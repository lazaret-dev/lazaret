#!/usr/bin/env python3
"""Bring pratique into the repository, or check the copy that is there (NET-1).

pratique (https://github.com/lazaret-dev/pratique; called tiny_https until October 2026) is the HTTPS/TLS library
Lazaret's network layer is built on (rust/crates/lazaret-net) and whose pure verification part the engine uses
(rust/crates/lazaret-verify): the standard library only, no dependencies, Apache-2.0. It is kept in
rust/crates/pratique as it is upstream, so that the next take replaces it whole and a reader can compare it with its
source; nothing in it is edited by hand.

    python3 scripts/sync_pratique.py CHECKOUT [--rev REV]
                                                take the library from a git checkout of it: the files of commit REV
                                                (HEAD if not given) as git holds them, whatever the working tree has;
                                                the commit is recorded in LAZARET.md
    python3 scripts/sync_pratique.py SOURCE      take a drop of it: the library's folder (not a checkout), or a .tgz /
                                                .tar.gz of it with one top-level folder
    python3 scripts/sync_pratique.py --verify    check rust/crates/pratique against the hashes recorded when it was
                                                taken (CI): no file changed, none added, none missing

What is taken: Cargo.toml, LICENSE, NOTICE (the notices the licences of what the library holds ask for, which its
Apache-2.0 licence has go with it), README.md, BACKLOG.md, SECURITY_REVIEW.md (the brief for its security review)
and the folders src/, tests/, examples/ and roots/ (the trust roots the library builds in: Sigstore's TUF root, which
src/tuf.rs includes, and Mozilla's root store for its `mozilla-roots` feature). What is left out: the fuzzer and its
corpus (fuzz/), the generators and oracles (tools/), the benchmarks against other libraries (bench/), the library's
own Cargo.lock (the workspace's is the one that counts), build output and caches. One change is made, to Cargo.toml:
its [profile.*] tables are dropped, since a workspace member's profiles are ignored (the workspace's own, in
rust/Cargo.toml, apply) and cargo warns about each one. Beside the files the script writes LAZARET.md (where the
library came from and how to take the next one), vendored.sha256 (the hash of every file taken, which --verify
reads), .gitattributes (`* -text`: git keeps every byte as it is, on every system, so the hashes hold and no DER
fixture is ever treated as text) and .gitignore (the library's public certificates, *.pem, and real npm tarballs,
*.tgz, are committed here, where the repository's rule would leave them out).

What is taken is data until it is checked: a member that is a link, a device, a submodule, an absolute path or a
path with `..` stops the run before anything is written, as does a source without src/lib.rs, a Cargo.toml that does
not name pratique, one that declares dependencies (the workspace takes no outside crate: scripts/check_rust_deps.py),
a file of a name the repository never commits (.env, .npmrc, a key file), or a private key in any file.

Standard library only, and git for a checkout."""

import argparse
import datetime
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEST = ROOT / "rust" / "crates" / "pratique"
UPSTREAM = "https://github.com/lazaret-dev/pratique"
KEEP_FILES = ("Cargo.toml", "LICENSE", "NOTICE", "README.md", "BACKLOG.md", "SECURITY_REVIEW.md")
KEEP_DIRS = ("src", "tests", "examples", "roots")
OURS = ("LAZARET.md", "vendored.sha256", ".gitattributes", ".gitignore")   # written here, not taken from the library
# Names the repository never commits (.gitignore; scripts/make_bundle.py's CREDENTIAL_NAMES), refused in a drop. A
# .pem is let through when it holds no private key (the library's tests read public certificates), as is a .tgz (real
# npm tarballs its Sigstore tests check attestations against).
CREDENTIAL_NAMES = (".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", "*.key", "*.p12", "*.pfx",
                    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*")
_PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}-----END")
_SKIP_PART = re.compile(r"(?:__pycache__|target(?:[-_].*)?|\.git|\.DS_Store)")
_SKIP_NAME = re.compile(r".*\.(?:pyc|pyo|orig|rej|swp)")
_COMMIT_RE = re.compile(r"commit `([0-9a-f]{40})`")
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
        raise DropError(f"a member of the source has a path that is not a plain relative one: {rel!r}")
    if re.match(r"^[A-Za-z]:", rel):
        raise DropError(f"a member of the source has a drive in its path: {rel!r}")
    return rel


class _Sizes:
    """The limits on one file and on all of them together."""

    def __init__(self):
        self.total = 0

    def add(self, rel, size):
        self.total += size
        if size > MAX_FILE or self.total > MAX_TOTAL:
            raise DropError(f"the source is larger than this script takes ({rel})")


def is_checkout(source):
    """A folder that is a git checkout (a .git folder, or the .git file of a worktree)."""
    source = pathlib.Path(source)
    return source.is_dir() and (source / ".git").exists()


def read_drop(source):
    """{relative path: bytes} of the files the repository takes from `source` (a folder or a tarball)."""
    source = pathlib.Path(source)
    files, sizes = {}, _Sizes()
    if source.is_dir():
        top = source
        for path in sorted(top.rglob("*"), key=lambda p: p.as_posix()):
            rel = _check_rel(path.relative_to(top).as_posix())
            if path.is_symlink():
                if _wanted(rel):
                    raise DropError(f"the source has a link where a file is taken: {rel}")
                continue
            if path.is_dir() or not _wanted(rel):
                continue
            if not path.is_file():
                raise DropError(f"the source has something other than a file where a file is taken: {rel}")
            data = path.read_bytes()
            sizes.add(rel, len(data))
            files[rel] = data
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
                raise DropError(f"the source has a link or a special file: {rel}")
            if not _wanted(rel):
                continue
            sizes.add(rel, m.size)
            files[rel] = tar.extractfile(m).read()
    return files


def _git(checkout, *args, data=None):
    """git's output for `args` in `checkout`, as bytes (DropError if git fails or is not there)."""
    try:
        done = subprocess.run(["git", "--no-optional-locks", "-C", str(checkout), *args], input=data,
                              capture_output=True, check=False)
    except OSError as exc:
        raise DropError(f"git could not be run: {exc}") from exc
    if done.returncode != 0:
        message = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise DropError(f"git {args[0]} failed in {checkout}: {message[-1] if message else done.returncode}")
    return done.stdout


def read_commit(checkout, rev="HEAD"):
    """(the commit's full hash, {relative path: bytes}) of the files the repository takes from commit `rev` of the
    checkout: what git holds for that commit, whatever the working tree has, with no .gitattributes applied."""
    if rev.startswith("-"):
        raise DropError(f"not a revision: {rev!r}")
    commit = _git(checkout, "rev-parse", "--verify", rev + "^{commit}").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise DropError(f"git did not name a commit for {rev!r}: {commit!r}")
    listing = _git(checkout, "ls-tree", "-r", "-z", "--full-tree", commit)
    wanted = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split()
        # what is not taken is not looked at further (a fuzz input may have any name)
        if not _wanted(raw_path.decode("utf-8", "surrogateescape")):
            continue
        try:
            rel = _check_rel(raw_path.decode("utf-8"))
        except UnicodeDecodeError:
            raise DropError(f"the commit has a path that is not UTF-8 where a file is taken: {raw_path!r}") from None
        if kind != "blob" or mode not in ("100644", "100755"):
            raise DropError(f"the commit has a link or a submodule where a file is taken: {rel}")
        wanted.append((rel, oid))
    out = _git(checkout, "cat-file", "--batch", data="".join(oid + "\n" for _, oid in wanted).encode("ascii"))
    files, sizes, pos = {}, _Sizes(), 0
    for rel, oid in wanted:
        try:
            end = out.index(b"\n", pos)
            got_oid, kind, size = out[pos:end].decode("ascii").split()
            size = int(size)
        except ValueError:
            raise DropError(f"git's answer for {rel} could not be read") from None
        if got_oid != oid or kind != "blob" or end + 1 + size > len(out):
            raise DropError(f"git gave something other than the file {rel}")
        sizes.add(rel, size)
        files[rel] = out[end + 1:end + 1 + size]
        pos = end + 1 + size + 1
    return commit, files


def check_no_credentials(files):
    """DropError for a file whose name the repository never commits, or whose bytes hold a private key."""
    import fnmatch
    for rel, data in sorted(files.items()):
        name = rel.rsplit("/", 1)[-1].lower()
        if name == ".env" or name.startswith(".env.") or any(fnmatch.fnmatchcase(name, p) for p in CREDENTIAL_NAMES):
            raise DropError(f"the source has a file of a name the repository never commits: {rel}")
        if _PRIVATE_KEY_RE.search(data):
            raise DropError(f"the source has a private key in {rel}: the repository commits none")


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
    if not re.search(r'(?m)^name\s*=\s*"pratique"\s*$', text):
        raise DropError("the source's Cargo.toml does not name the package pratique")
    section = None
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            section = m.group(1)
            continue
        if section and re.fullmatch(r"(?:target\..+\.)?(?:dev-|build-)?dependencies", section) and s:
            raise DropError(f"the source's Cargo.toml declares a dependency ([{section}] {s}); the workspace takes no "
                            "outside crate")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "?"


def hashes_text(files):
    return "".join(f"{hashlib.sha256(files[rel]).hexdigest()}  {rel}\n" for rel in sorted(files))


def notes(origin, version, files):
    today = datetime.date.today().isoformat()
    size = sum(len(b) for b in files.values())
    return f"""# pratique in Lazaret

This folder is pratique {version}, the HTTPS/TLS library Lazaret's network layer is built on, as it is upstream:
nothing in it is edited by hand. Its repository is {UPSTREAM}; it was called tiny_https until October 2026.

- **Taken** on {today} by `scripts/sync_pratique.py`, from {origin}: {len(files)} files, {size:,} bytes.
- **Licence:** Apache-2.0 (`LICENSE`), as Lazaret's is. `NOTICE` keeps the notices of what the library holds from
  elsewhere: Mozilla's root store (`roots/mozilla.pem`) is under the Mozilla Public License 2.0, as NSS is, and
  BearSSL's MIT notice goes with two of its crypto files.
- **What is here:** `Cargo.toml`, `LICENSE`, `NOTICE`, `README.md`, `BACKLOG.md`, `SECURITY_REVIEW.md` (the brief
  for the library's security review), `src/`, `tests/`, `examples/` and `roots/` (the trust roots it builds in:
  Sigstore's TUF root, always, and Mozilla's root store for the `mozilla-roots` feature, which Lazaret does not
  use and no package of Lazaret's carries).
- **What was left out:** the fuzzer and its corpus (`fuzz/`), the generators and oracles (`tools/`), the benchmarks
  against other libraries (`bench/`), the library's own `Cargo.lock`, and build output. Two of the library's
  interoperability tests use files in `tools/` when Go or aioquic is installed (`tests/h2_client_interop.rs`,
  `tests/h3_client_interop.rs`); they skip without them, and Lazaret's CI does not run them.
- **The one change:** `Cargo.toml` without its `[profile.*]` tables. A workspace member's profiles are ignored
  (the workspace's, in `rust/Cargo.toml`, apply) and cargo warns about each one.
- **Lazaret's crates on it:** `lazaret-verify` (the pure part: `default-features = false`, no I/O, no `unsafe`;
  the engine and the WebAssembly build use it) and `lazaret-net` (the network: Lazaret's host rule, URL
  limits, timeouts and byte budgets, and credentials given to each hop's own host through `Client::hop_headers`;
  linked into the native library only). `scripts/check_rust_deps.py` refuses the engine linking the network part.
- **The next take:** `python3 scripts/sync_pratique.py PATH [--rev REV]` (a checkout of {UPSTREAM}: the commit's
  files, with the commit recorded here; or a folder or tarball of the library), then the gates.
  `python3 scripts/sync_pratique.py --verify` checks this folder against `vendored.sha256` (CI does).
- **What Lazaret asks of it:** TLS 1.3, and TLS 1.2 with a server that speaks nothing newer (the library's
  default minimum: ECDHE with AEAD suites only, the extended master secret required, the downgrade check);
  HTTP/2 or HTTP/1.1; never the opt-in extras (`Content-Encoding` decoding, cookies, `Expect: 100-continue`) and
  never HTTP/3 (`rust/crates/lazaret-net`).
- **Its tests in Lazaret's CI:** `cargo test --release -p pratique --lib` and the tests that need nothing
  installed (`go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic`, `rekor_real`, `real_chains`,
  `inflate_vectors`; `real_chains` replays chains captured from real servers when `tests/data/real_chains/` is
  in the source, and skips without it).
"""


def take(source, rev=None):
    source = pathlib.Path(source)
    if is_checkout(source):
        commit, files = read_commit(source, rev or "HEAD")
        origin = f"commit `{commit}` (its files as git holds them)"
    elif rev is not None:
        raise DropError(f"--rev needs a git checkout of the library, and {source} is not one")
    else:
        if source.is_file():
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        else:
            digest = hashlib.sha256()
            for path in sorted(source.rglob("*"), key=lambda p: p.as_posix()):
                if path.is_file() and not path.is_symlink():
                    digest.update(path.relative_to(source).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
            source_sha = digest.hexdigest() + " (of the folder's files)"
        files = read_drop(source)
        origin = f"`{source.name}` (SHA-256 `{source_sha}`)"
    if "src/lib.rs" not in files or "Cargo.toml" not in files or "LICENSE" not in files:
        raise DropError("the source has no src/lib.rs, Cargo.toml or LICENSE: not the library")
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
    (DEST / "LAZARET.md").write_text(notes(origin, version, files), encoding="utf-8", newline="\n")
    (DEST / ".gitignore").write_text(
        "# The library's test fixtures as they are upstream: public certificates (*.pem) and real npm tarballs (*.tgz),\n"
        "# which its tests read. The repository's rule against committing those names does not apply in this folder:\n"
        "# scripts/sync_pratique.py refuses a source with a private key or a credential file.\n"
        "!*.pem\n!*.tgz\n", encoding="utf-8", newline="\n")
    (DEST / ".gitattributes").write_text(
        "# The library's files as they are upstream, byte for byte on every system (scripts/sync_pratique.py):\n"
        "# no line-ending conversion, so vendored.sha256 holds and no DER fixture is ever treated as text.\n"
        "* -text\n", encoding="utf-8", newline="\n")
    return version, len(files)


def recorded_commit():
    """The upstream commit LAZARET.md says the folder was taken from (None for a drop, or with no LAZARET.md)."""
    try:
        m = _COMMIT_RE.search((DEST / "LAZARET.md").read_text(encoding="utf-8"))
    except OSError:
        return None
    return m.group(1) if m else None


def verify():
    """Problems of rust/crates/pratique against its vendored.sha256 ([] when it is as it was taken)."""
    record = DEST / "vendored.sha256"
    if not record.is_file():
        return ["rust/crates/pratique/vendored.sha256 is missing: take the library with this script"]
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
            problems.append(f"rust/crates/pratique/{rel}: not part of what was taken (a file is added to the library "
                            "upstream, then taken with this script)")
            continue
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != want[rel]:
            problems.append(f"rust/crates/pratique/{rel}: changed since it was taken (change the library "
                            "upstream, then take it again with this script)")
    for rel in sorted(set(want) - have):
        problems.append(f"rust/crates/pratique/{rel}: missing")
    for name in OURS:
        if not (DEST / name).is_file():
            problems.append(f"rust/crates/pratique/{name}: missing")
    return problems


def main(argv=None):
    _configure_stdio()
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("source", nargs="?", help="a git checkout of the library, its folder, or a .tgz / .tar.gz of it")
    parser.add_argument("--rev", help="with a checkout: the commit to take (default HEAD)")
    parser.add_argument("--verify", action="store_true", help="check rust/crates/pratique against its recorded hashes")
    args = parser.parse_args(argv)
    if args.verify == bool(args.source):
        parser.error("give either SOURCE or --verify")
    if args.verify and args.rev:
        parser.error("--rev goes with SOURCE")
    if args.verify:
        problems = verify()
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        if problems:
            return 1
        count = len((DEST / "vendored.sha256").read_text(encoding="utf-8").splitlines())
        commit = recorded_commit()
        what = f"commit {commit[:12]} of pratique" if commit else "the drop it was taken from"
        print(f"ok: rust/crates/pratique is {what} ({count} files)")
        return 0
    try:
        version, count = take(args.source, args.rev)
    except (DropError, OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    commit = recorded_commit()
    at = f" at {commit[:12]}" if commit else ""
    print(f"ok: pratique {version}{at} taken into rust/crates/pratique ({count} files); now run the gates")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
