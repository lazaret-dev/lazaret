#!/usr/bin/env python3
"""Bring a drop of tiny_https into the repository, or check the copy that is there (NET-1).

tiny_https is the HTTPS/TLS library Lazaret's network layer is built on (rust/crates/lazaret-net) and whose
pure verification part the engine may use (rust/crates/lazaret-verify): the standard library only, no
dependencies, Apache-2.0. It is kept in rust/crates/tiny_https as it was handed over, so that the next drop
replaces it whole and a reader can compare it with its source; nothing in it is edited by hand.

    python3 scripts/sync_tiny_https.py SOURCE      take SOURCE (the library's folder, or a .tgz / .tar.gz of it
                                                   with one top-level folder) into rust/crates/tiny_https
    python3 scripts/sync_tiny_https.py --verify    check rust/crates/tiny_https against the hashes recorded when it
                                                   was taken (CI): no file changed, none added, none missing

What is taken: Cargo.toml, LICENSE, README.md, BACKLOG.md and the folders src/, tests/ and examples/. What is
left out: the fuzzer and its corpus (fuzz/, 80 MB), the generators and oracles (tools/), the library's own
Cargo.lock (the workspace's is the one that counts), build output and caches. One change is made, to
Cargo.toml: its [profile.*] tables are dropped, since a workspace member's profiles are ignored (the
workspace's own, in rust/Cargo.toml, apply) and cargo warns about each one. Beside the files the script writes
LAZARET.md (where the drop came from and how to take the next one), vendored.sha256 (the hash of every file
taken, which --verify reads), .gitattributes (`* -text`: git keeps every byte as it is, on every system, so the
hashes hold and no DER fixture is ever treated as text) and .gitignore (the library's public certificates, *.pem,
and real npm tarballs, *.tgz, are committed here, where the repository's rule would leave them out).

A drop is data until it is checked: a member that is a link, a device, an absolute path or a path with `..`
stops the run before anything is written, as does a drop without src/lib.rs, a Cargo.toml that does not name
tiny_https, one that declares dependencies (the workspace takes no outside crate: scripts/check_rust_deps.py), a
file of a name the repository never commits (.env, .npmrc, a key file), or a private key in any file.

Standard library only."""

import argparse
import datetime
import hashlib
import io
import os
import pathlib
import re
import shutil
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEST = ROOT / "rust" / "crates" / "tiny_https"
KEEP_FILES = ("Cargo.toml", "LICENSE", "README.md", "BACKLOG.md")
KEEP_DIRS = ("src", "tests", "examples")
OURS = ("LAZARET.md", "vendored.sha256", ".gitattributes", ".gitignore")   # written here, not taken from the drop
# Names the repository never commits (.gitignore; scripts/make_bundle.py's CREDENTIAL_NAMES), refused in a drop. A
# .pem is let through when it holds no private key (the library's tests read public certificates), as is a .tgz (real
# npm tarballs its Sigstore tests check attestations against).
CREDENTIAL_NAMES = (".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", "*.key", "*.p12", "*.pfx",
                    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*")
_PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}-----END")
_SKIP_PART = re.compile(r"(?:__pycache__|target(?:[-_].*)?|\.git|\.DS_Store)")
_SKIP_NAME = re.compile(r".*\.(?:pyc|pyo|orig|rej|swp)")
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


class DropError(Exception):
    pass


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise (STRUCTURE.md, "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def _wanted(rel):
    """Is this path (relative to the library's top folder, `/`-separated) one the repository takes?"""
    parts = rel.split("/")
    if any(_SKIP_PART.fullmatch(p) for p in parts) or _SKIP_NAME.fullmatch(parts[-1]):
        return False
    if len(parts) == 1:
        return parts[0] in KEEP_FILES
    return parts[0] in KEEP_DIRS


def _check_rel(rel):
    if not rel or rel.startswith("/") or "\\" in rel or any(p in ("", ".", "..") for p in rel.split("/")):
        raise DropError(f"a member of the drop has a path that is not a plain relative one: {rel!r}")
    if re.match(r"^[A-Za-z]:", rel):
        raise DropError(f"a member of the drop has a drive in its path: {rel!r}")
    return rel


def read_drop(source):
    """{relative path: bytes} of the files the repository takes from `source` (a folder or a tarball)."""
    source = pathlib.Path(source)
    files, total = {}, 0
    if source.is_dir():
        top = source
        for path in sorted(top.rglob("*"), key=lambda p: p.as_posix()):
            rel = _check_rel(path.relative_to(top).as_posix())
            if path.is_symlink():
                if _wanted(rel):
                    raise DropError(f"the drop has a link where a file is taken: {rel}")
                continue
            if path.is_dir() or not _wanted(rel):
                continue
            if not path.is_file():
                raise DropError(f"the drop has something other than a file where a file is taken: {rel}")
            data = path.read_bytes()
            files[rel] = data
            total += len(data)
            if len(data) > MAX_FILE or total > MAX_TOTAL:
                raise DropError(f"the drop is larger than this script takes ({rel})")
        return files
    if not source.is_file():
        raise DropError(f"no such folder or file: {source}")
    with tarfile.open(source, "r:*") as tar:
        members = tar.getmembers()
        tops = {m.name.split("/", 1)[0] for m in members if m.name and m.name not in (".", "./")}
        if len(tops) != 1:
            raise DropError("a tarball of the library has one top-level folder; this one has "
                            f"{len(tops)} ({', '.join(sorted(tops)[:5])})")
        (top,) = tops
        for m in members:
            name = m.name[2:] if m.name.startswith("./") else m.name
            if name in (top, top + "/"):
                continue
            rel = _check_rel(name.split("/", 1)[1].rstrip("/") if "/" in name else "")
            if m.isdir():
                continue
            if not m.isfile():
                raise DropError(f"the drop has a link or a special file: {rel}")
            if not _wanted(rel):
                continue
            if m.size > MAX_FILE or total + m.size > MAX_TOTAL:
                raise DropError(f"the drop is larger than this script takes ({rel})")
            data = tar.extractfile(m).read()
            files[rel] = data
            total += len(data)
    return files


def check_no_credentials(files):
    """DropError for a file whose name the repository never commits, or whose bytes hold a private key."""
    import fnmatch
    for rel, data in sorted(files.items()):
        name = rel.rsplit("/", 1)[-1].lower()
        if name == ".env" or name.startswith(".env.") or any(fnmatch.fnmatchcase(name, p) for p in CREDENTIAL_NAMES):
            raise DropError(f"the drop has a file of a name the repository never commits: {rel}")
        if _PRIVATE_KEY_RE.search(data):
            raise DropError(f"the drop has a private key in {rel}: the repository commits none")


def edit_manifest(text):
    """Cargo.toml with its [profile.*] tables (header, keys, and the comments right above the header) taken out."""
    out, dropping = [], False
    pending = []                     # comment and blank lines not yet known to belong to a kept table
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            dropping = bool(re.match(r"^\[profile(?:\.|\])", stripped))
            if not dropping:
                out.extend(pending)
            pending = []
            if not dropping:
                out.append(line)
            continue
        if dropping and not stripped.startswith("#") and stripped:
            pending = []             # (a key of a dropped table: the comments above it go with it)
            continue
        if not stripped or stripped.startswith("#"):
            pending.append(line)
            continue
        out.extend(pending)
        pending = []
        out.append(line)
    if not dropping:
        out.extend(pending)
    edited = "".join(out).rstrip("\n") + "\n"
    return edited


def check_manifest(text):
    if not re.search(r'(?m)^name\s*=\s*"tiny_https"\s*$', text):
        raise DropError("the drop's Cargo.toml does not name the package tiny_https")
    section = None
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            section = m.group(1)
            continue
        if section and re.fullmatch(r"(?:target\..+\.)?(?:dev-|build-)?dependencies", section) and s:
            raise DropError(f"the drop's Cargo.toml declares a dependency ([{section}] {s}); the workspace takes no "
                            "outside crate")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "?"


def hashes_text(files):
    return "".join(f"{hashlib.sha256(files[rel]).hexdigest()}  {rel}\n" for rel in sorted(files))


def notes(source_name, source_sha, version, files):
    today = datetime.date.today().isoformat()
    size = sum(len(b) for b in files.values())
    return f"""# tiny_https in Lazaret

This folder is tiny_https {version}, the HTTPS/TLS library Lazaret's network layer is built on, as it was handed
over: nothing in it is edited by hand. `scripts/sync_tiny_https.py` took it on {today} from `{source_name}`
(SHA-256 `{source_sha}`): {len(files)} files, {size:,} bytes. Its licence is Apache-2.0 (`LICENSE`), as
Lazaret's is.

- **What is here:** `Cargo.toml`, `LICENSE`, `README.md`, `BACKLOG.md`, `src/`, `tests/` and `examples/`.
- **What was left out:** the fuzzer and its corpus (`fuzz/`), the generators and oracles (`tools/`), the
  library's own `Cargo.lock`, and build output. Two of the library's interoperability tests use files in
  `tools/` when Go or aioquic is installed (`tests/h2_client_interop.rs`, `tests/h3_client_interop.rs`); they
  skip without them, and Lazaret's CI does not run them.
- **The one change:** `Cargo.toml` without its `[profile.*]` tables. A workspace member's profiles are ignored
  (the workspace's, in `rust/Cargo.toml`, apply) and cargo warns about each one.
- **Lazaret's crates on it:** `lazaret-verify` (the pure part: `default-features = false`, no I/O, no `unsafe`;
  the engine and the WebAssembly build may use it) and `lazaret-net` (the network: Lazaret's host rule, URL
  limits, timeouts and byte budgets; linked into the native library only). `scripts/check_rust_deps.py` refuses
  the engine linking the network part.
- **The next drop:** `python3 scripts/sync_tiny_https.py PATH` (the library's folder or a tarball of it), then
  the gates. `python3 scripts/sync_tiny_https.py --verify` checks this folder against `vendored.sha256` (CI does).
- **Its tests in Lazaret's CI:** `cargo test --release -p tiny_https --lib` and the tests that need nothing
  installed (`go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic`, `rekor_real`).
"""


def take(source):
    source = pathlib.Path(source)
    if source.is_file():
        raw = source.read_bytes()
        source_sha = hashlib.sha256(raw).hexdigest()
    else:
        digest = hashlib.sha256()
        for path in sorted(source.rglob("*"), key=lambda p: p.as_posix()):
            if path.is_file() and not path.is_symlink():
                digest.update(path.relative_to(source).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
        source_sha = digest.hexdigest() + " (of the folder's files)"
    files = read_drop(source)
    if "src/lib.rs" not in files or "Cargo.toml" not in files or "LICENSE" not in files:
        raise DropError("the drop has no src/lib.rs, Cargo.toml or LICENSE: not the library")
    manifest = files["Cargo.toml"].decode("utf-8")
    version = check_manifest(manifest)
    files["Cargo.toml"] = edit_manifest(manifest).encode("utf-8")
    check_no_credentials(files)
    if re.search(r"(?m)^\[profile", files["Cargo.toml"].decode("utf-8")):
        raise DropError("the [profile.*] tables could not be taken out of Cargo.toml")
    if DEST.exists():
        shutil.rmtree(DEST)
    for rel, data in files.items():
        path = DEST / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (DEST / "vendored.sha256").write_text(hashes_text(files), encoding="utf-8", newline="\n")
    (DEST / "LAZARET.md").write_text(notes(source.name, source_sha, version, files), encoding="utf-8", newline="\n")
    (DEST / ".gitignore").write_text(
        "# The library's test fixtures as they were handed over: public certificates (*.pem) and real npm tarballs\n"
        "# (*.tgz), which its tests read. The repository's rule against committing those names does not apply in this\n"
        "# folder: scripts/sync_tiny_https.py refuses a drop with a private key or a credential file.\n"
        "!*.pem\n!*.tgz\n", encoding="utf-8", newline="\n")
    (DEST / ".gitattributes").write_text(
        "# The library's files as it was handed over, byte for byte on every system (scripts/sync_tiny_https.py):\n"
        "# no line-ending conversion, so vendored.sha256 holds and no DER fixture is ever treated as text.\n"
        "* -text\n", encoding="utf-8", newline="\n")
    return version, len(files)


def verify():
    """Problems of rust/crates/tiny_https against its vendored.sha256 ([] when it is as it was taken)."""
    record = DEST / "vendored.sha256"
    if not record.is_file():
        return ["rust/crates/tiny_https/vendored.sha256 is missing: take the library with this script"]
    want = {}
    for line in record.read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        if not m:
            return [f"vendored.sha256 has a line that is not a hash and a path: {line!r}"]
        want[m.group(2)] = m.group(1)
    problems = []
    have = set()
    for path in sorted(DEST.rglob("*"), key=lambda p: p.as_posix()):
        rel = path.relative_to(DEST).as_posix()
        if path.is_dir() or rel in OURS:
            continue
        have.add(rel)
        if rel not in want:
            problems.append(f"rust/crates/tiny_https/{rel}: not part of the drop (a file is added to the library "
                            "upstream, then taken with this script)")
            continue
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != want[rel]:
            problems.append(f"rust/crates/tiny_https/{rel}: changed since it was taken (change the library "
                            "upstream, then take it again with this script)")
    for rel in sorted(set(want) - have):
        problems.append(f"rust/crates/tiny_https/{rel}: missing")
    for name in OURS:
        if not (DEST / name).is_file():
            problems.append(f"rust/crates/tiny_https/{name}: missing")
    return problems


def main(argv=None):
    _configure_stdio()
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("source", nargs="?", help="the library's folder, or a .tgz / .tar.gz of it")
    parser.add_argument("--verify", action="store_true", help="check rust/crates/tiny_https against its recorded hashes")
    args = parser.parse_args(argv)
    if args.verify == bool(args.source):
        parser.error("give either SOURCE or --verify")
    if args.verify:
        problems = verify()
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        if problems:
            return 1
        count = len((DEST / "vendored.sha256").read_text(encoding="utf-8").splitlines())
        print(f"ok: rust/crates/tiny_https is the drop it was taken from ({count} files)")
        return 0
    try:
        version, count = take(args.source)
    except (DropError, OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ok: tiny_https {version} taken into rust/crates/tiny_https ({count} files); now run the gates")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
