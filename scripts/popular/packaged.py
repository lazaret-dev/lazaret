#!/usr/bin/env python3
"""The Go and Rust benign sets of the release gate (0.1.9, N-2): what Ubuntu packages and what Go ships.

Go's module proxy can't be reached from everywhere this runs, and no Go registry publishes downloads, so the Go and
Rust code the release gate must hold quiet, besides the most-downloaded crates (popular.py's set), is what a
distribution packages and what Go itself ships: every golang-*-dev (Go modules) and librust-*-dev (crates) package
of Ubuntu 24.04's universe, and Go's standard library with the modules it vendors. Each module or crate is packed as
its registry serves it, a module zip (path@version/...) or a .crate (name-version/...), for scripts/bench.py:

    python3 scripts/popular/packaged.py ubuntu --debs DEBS --cache DIR --manifest DIR/ubuntu.jsonl
    python3 scripts/popular/packaged.py gostd [--goroot GOROOT] --cache DIR --manifest DIR/gostd.jsonl
    python3 scripts/bench.py run DIR/ubuntu.jsonl RUN.jsonl          (looped, as for the benchmark)

`ubuntu` reads noble's universe index (its Packages.xz, pinned by sha256: the release pocket never changes, and the
index holds each .deb's sha256), downloads into DEBS each package's .deb not there already (https from
archive.ubuntu.com; bytes with another sha256 than the index's are refused), and keeps a package only when every
licence its DEP-5 copyright file names (debian/ aside) is one Apache-2.0's terms can take in (MIT, Apache-2.0, the
BSD licences, ISC, Zlib, ...): the findings on this set are read, and code under other licences is not reviewed. A
.deb is read with dpkg-deb when there is one, else here (ar, then xz, gzip or bzip2; zstd, which Ubuntu uses, needs
Python 3.14 or the zstd command). A package's Go modules are its go.mod roots under /usr/share/gocode/src (or, with
none, its import paths' roots), each without the modules nested in it, packed as path@v0.0.0; its crates are the
directories of /usr/share/cargo/registry.

`gostd` packs GOROOT/src (the std module) without cmd/ and vendor/, src/cmd (cmd) without its vendor/, and each
module src/vendor/modules.txt and src/cmd/vendor/modules.txt name, at its version.

The packed files go into DIR named by their sha256 (packing is deterministic: sorted, dated 1980 or 0); the manifest
has one line per module or crate, in the category "benign", and --left-out FILE lists the packages left out and why.
Standard library only; nothing is built or run here.
"""
import argparse
import bz2
import contextlib
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

UBUNTU = "https://archive.ubuntu.com/ubuntu/"
INDEX_PATH = "dists/noble/universe/binary-amd64/Packages.xz"
#: the sha256 noble's InRelease (Apr 25, 2024) gives INDEX_PATH; the release pocket is frozen at the release
INDEX_SHA256 = "ba9057fa1b91438cc8a1d26808d00c85389fe101d0c1496254df97236405599a"
USER_AGENT = "lazaret-popular-set (https://lazaret.dev)"
FETCH_TIMEOUT = 90
MAX_DEB_BYTES = 200 << 20
MAX_UNIT_BYTES = 1 << 30           # a module or crate's files, unpacked
FORGES = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com", "git.sr.ht")
GO_SRC = "usr/share/gocode/src/"
CRATES_SRC = "usr/share/cargo/registry/"
#: a DEP-5 licence short name (lower case) Apache-2.0's terms can take in
LICENCE_RE = re.compile(r"^(?:apache-?2(?:\.0)?\+?|apache license,? version 2\.0|expat|mit(?:-0)?|mit/x11|x11|"
                        r"bsd|bsd-[23]-clause(?:-[a-z0-9-]+)?|0bsd|isc|zlib|unicode-3\.0|unicode-dfs-2016|"
                        r"bsl-1\.0|cc0(?:-1\.0)?|unlicense)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_1980 = (1980, 1, 1, 0, 0, 0)

EXIT_OK, EXIT_USAGE, EXIT_FAIL = 0, 2, 3


class SetError(Exception):
    """A package, a file or an index this set can't use."""


def _say(text):
    print(text, file=sys.stderr, flush=True)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest, expect, limit, opener=urllib.request.urlopen):
    """Download `url` to `dest` (https on archive.ubuntu.com only): SetError unless its sha256 is `expect`."""
    if not url.startswith(UBUNTU):
        raise SetError(f"only {UBUNTU} is fetched: {url}")
    part = dest + f".part-{os.getpid()}"
    h, size = hashlib.sha256(), 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with opener(req, timeout=FETCH_TIMEOUT) as resp, open(part, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise SetError(f"{url}: more than {limit >> 20} MiB")
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != expect:
            raise SetError(f"{url}: sha256 {h.hexdigest()}, the index says {expect}")
        os.replace(part, dest)
    except (OSError, ValueError) as exc:
        raise SetError(f"{url}: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.remove(part)
    return dest


# ---- the index
def read_index(data, expect=INDEX_SHA256):
    """-> the golang-*-dev and librust-*-dev packages of a Packages.xz whose sha256 is `expect`: [{"package",
    "version", "filename", "sha256", "size", "eco"}], by package name."""
    if sha256_bytes(data) != expect:
        raise SetError(f"the index's sha256 is {sha256_bytes(data)}, not the pinned {expect}")
    text = lzma.decompress(data).decode("utf-8", "replace")
    out = []
    for stanza in text.split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z0-9-]+):[ \t]*(.*)$", stanza, re.M))
        pkg = fields.get("Package", "")
        eco = ("go" if pkg.startswith("golang-") else "crates" if pkg.startswith("librust-") else None) \
            if pkg.endswith("-dev") else None
        filename, digest = fields.get("Filename", ""), fields.get("SHA256", "")
        if eco is None or not filename.startswith("pool/") or ".." in filename or not SHA256_RE.match(digest):
            continue
        out.append({"package": pkg, "version": fields.get("Version", ""), "filename": filename, "sha256": digest,
                    "size": int(fields.get("Size", "0") or 0), "eco": eco})
    return sorted(out, key=lambda r: r["package"])


def the_index(path, expect, opener=urllib.request.urlopen):
    """The index's bytes: `path` when it exists (its sha256 checked by read_index), else downloaded to it."""
    if not os.path.isfile(path):
        download(UBUNTU + INDEX_PATH, path, expect, 64 << 20, opener)
    with open(path, "rb") as fh:
        return fh.read()


# ---- a .deb
def _ar_members(data):
    """{name: bytes} of an ar archive (a .deb's outer layer)."""
    if not data.startswith(b"!<arch>\n"):
        raise SetError("not an ar archive")
    pos, out = 8, {}
    while pos + 60 <= len(data):
        head = data[pos:pos + 60]
        if head[58:60] != b"`\n":
            raise SetError("a damaged ar header")
        name = head[:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(head[48:58].decode("ascii").strip() or 0)
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
    return out


def _unzstd(data):
    try:
        from compression import zstd                   # Python 3.14
        return zstd.decompress(data)
    except ImportError:
        pass
    if shutil.which("zstd"):
        return subprocess.run(["zstd", "-dcq"], input=data, check=True, capture_output=True).stdout
    raise SetError("a zstd .deb needs dpkg-deb, the zstd command or Python 3.14")


def deb_tar(path, use_dpkg=True):
    """The .deb's data as the bytes of an uncompressed tar."""
    if use_dpkg and shutil.which("dpkg-deb"):
        try:
            return subprocess.run(["dpkg-deb", "--fsys-tarfile", path], check=True, capture_output=True).stdout
        except subprocess.CalledProcessError as exc:
            raise SetError(f"dpkg-deb: {exc.stderr.decode('utf-8', 'replace').strip()[:200]}") from None
    with open(path, "rb") as fh:
        members = _ar_members(fh.read())
    for name, data in members.items():
        if name == "data.tar":
            return data
        if name.startswith("data.tar."):
            ext = name[len("data.tar."):]
            if ext == "xz":
                return lzma.decompress(data)
            if ext == "gz":
                return gzip.decompress(data)
            if ext == "bz2":
                return bz2.decompress(data)
            if ext == "zst":
                return _unzstd(data)
            raise SetError(f"a .deb compressed with {ext}")
    raise SetError("no data.tar in the .deb")


def deb_files(path, use_dpkg=True):
    """{path: bytes} of the .deb's regular files, paths without "./" (a hard link is its target's bytes)."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(deb_tar(path, use_dpkg)), mode="r:") as tf:
        for m in tf:
            name = m.name[2:] if m.name.startswith("./") else m.name.lstrip("/")
            if m.isfile():
                files[name] = tf.extractfile(m).read()
            elif m.islnk():
                target = m.linkname[2:] if m.linkname.startswith("./") else m.linkname.lstrip("/")
                if target in files:
                    files[name] = files[target]
    return files


def dep5_licences(text):
    """-> (ok, licences): a DEP-5 copyright file's licences (each Files stanza's but debian/*'s), ok when every one
    can be taken under LICENCE_RE's alone ("a or b": one side; "a and b": both)."""
    if not text.startswith("Format:") and "copyright-format" not in text[:300]:
        return False, ["not DEP-5"]
    seen, ok = [], True
    for stanza in re.split(r"\n\s*\n", text):
        files = re.search(r"^Files:\s*(.*(?:\n[ \t]+.*)*)", stanza, re.M)
        lic = re.search(r"^License:\s*(.+)$", stanza, re.M)
        if not files or not lic:
            continue
        names = files.group(1).split()
        if names and all(n.startswith("debian/") for n in names):
            continue
        value = lic.group(1).strip().lower()
        seen.append(value)
        good = False
        for option in re.split(r"\s+or\s+|\s*\|\s*", value):
            parts = [p.strip(" ,") for p in re.split(r"\s+and\s+|,", option) if p.strip(" ,")]
            if parts and all(LICENCE_RE.match(p) for p in parts):
                good = True
        ok = ok and good
    return ok and bool(seen), seen


# ---- modules and crates
def _dirs_of(paths):
    """Every directory holding one of `paths` (relative, "/"-separated), with its ancestors; "" is the root."""
    out = {""}
    for p in paths:
        parts = p.split("/")[:-1]
        for n in range(1, len(parts) + 1):
            out.add("/".join(parts[:n]))
    return out


def _under(path, root):
    return root == "" or path.startswith(root + "/")


def go_units(files):
    """[(import path, {rel: bytes})] of the Go modules in `files` ({path under GO_SRC: bytes}): the directories with a
    go.mod, each without the ones nested in it; with no go.mod, the import paths' roots (host/owner/repository on a
    forge, else the first directory down with .go files)."""
    roots = sorted(p[:-len("/go.mod")] for p in files if p.endswith("/go.mod"))
    if not roots:
        with_go = {p.rsplit("/", 1)[0] for p in files if p.endswith(".go") and "/" in p}
        candidates = set()
        for d in _dirs_of(files) - {""}:
            parts = d.split("/")
            if parts[0] in FORGES and len(parts) == 3 or parts[0] not in FORGES and d in with_go:
                candidates.add(d)
        roots = sorted(d for d in candidates if not any(d != c and _under(d, c) for c in candidates))
    units = []
    for root in roots:
        nested = [r for r in roots if r != root and _under(r, root)]
        unit = {p[len(root) + 1:]: data for p, data in files.items()
                if _under(p, root) and not any(_under(p, n) for n in nested)}
        units.append((root, unit))
    return units


def crate_units(files):
    """[(name-version, {rel: bytes})] of the crates in `files` ({path under CRATES_SRC: bytes})."""
    by = {}
    for p, data in files.items():
        top, sep, rest = p.partition("/")
        if sep and rest:
            by.setdefault(top, {})[rest] = data
    return sorted(by.items())


def code_bytes(unit, eco):
    ext = (".go",) if eco == "go" else (".rs",)
    return sum(len(d) for p, d in unit.items() if p.endswith(ext))


def pack_zip(prefix, unit):
    """A module zip as the proxy serves one: every file under `prefix`, sorted, dated 1980."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for rel in sorted(unit):
            info = zipfile.ZipInfo(prefix + rel, DATE_1980)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, unit[rel])
    return buf.getvalue()


def pack_crate(prefix, unit):
    """A .crate as crates.io serves one: a gzipped tar of every file under `prefix`, sorted, dated 0."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=6) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for rel in sorted(unit):
                info = tarfile.TarInfo(prefix + rel)
                info.size, info.mode, info.mtime = len(unit[rel]), 0o644, 0
                tf.addfile(info, io.BytesIO(unit[rel]))
    return buf.getvalue()


def store(data, cache):
    """Write `data` into `cache` named by its sha256 (once): -> (sha256, path)."""
    digest = sha256_bytes(data)
    path = os.path.join(cache, digest)
    if not (os.path.isfile(path) and os.path.getsize(path) == len(data)):
        part = path + f".part-{os.getpid()}"
        with open(part, "wb") as fh:
            fh.write(data)
        os.replace(part, path)
    return digest, path


def manifest_line(rid, set_name, eco, name, version, path, digest, **extra):
    container, kind = ("zip", "gomod") if eco == "go" else ("tgz", "crate")
    line = {"id": rid, "cat": "benign", "set": set_name, "eco": eco, "name": name, "version": version,
            "artifact_path": path, "container": container, "kind": kind, "sha256": digest}
    line.update(extra)
    return line


def pack_units(eco, units, version_of, cache):
    """[(name, version, sha256, path)] for each unit with code; SetError for one over MAX_UNIT_BYTES."""
    out = []
    for name, unit in units:
        if not code_bytes(unit, eco):
            continue
        if sum(len(d) for d in unit.values()) > MAX_UNIT_BYTES:
            raise SetError(f"{name}: over {MAX_UNIT_BYTES >> 20} MiB unpacked")
        version = version_of(name)
        data = pack_zip(f"{name}@{version}/", unit) if eco == "go" else pack_crate(f"{name}/", unit)
        digest, path = store(data, cache)
        out.append((name, version, digest, path))
    return out


# ---- the sets
def ubuntu_package(row, debs, cache, use_dpkg=True, opener=urllib.request.urlopen):
    """-> (manifest lines, None) for one package of the index, or ([], why it is left out)."""
    deb = os.path.join(debs, os.path.basename(row["filename"]))
    if not (os.path.isfile(deb) and sha256_file(deb) == row["sha256"]):
        download(UBUNTU + row["filename"], deb, row["sha256"], MAX_DEB_BYTES, opener)
    files = deb_files(deb, use_dpkg)
    copyright = files.get(f"usr/share/doc/{row['package']}/copyright")
    if copyright is None:
        return [], "no copyright file"
    ok, licences = dep5_licences(copyright.decode("utf-8", "replace"))
    if not ok:
        return [], "licence: " + "; ".join(licences[:6])
    base = GO_SRC if row["eco"] == "go" else CRATES_SRC
    tree = {p[len(base):]: d for p, d in files.items() if p.startswith(base)}
    units = go_units(tree) if row["eco"] == "go" else crate_units(tree)
    packed = pack_units(row["eco"], units, lambda name: "v0.0.0", cache)
    return [manifest_line(f"ubuntu:{row['package']}:{name}", "ubuntu", row["eco"], name, row["version"], path, digest,
                          deb=os.path.basename(row["filename"]))
            for name, _version, digest, path in packed], None


def modules_txt(text):
    """[(module path, version)] of a vendor/modules.txt."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^# (\S+) (v\S+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _tree(root):
    """{rel: bytes} of the regular files under `root` (symbolic links left out)."""
    out = {}
    for dirpath, dirs, fs in os.walk(root):
        dirs.sort()
        for f in sorted(fs):
            full = os.path.join(dirpath, f)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root).replace(os.sep, "/")] = fh.read()
    return out


def gostd_units(goroot):
    """-> (Go's version, [(where, module, version, {rel: bytes})]): std, cmd and the modules they vendor (`where`:
    "std", "cmd", "vendor/<module>" or "cmd/vendor/<module>": both vendor some of golang.org/x/sys and x/text)."""
    src = os.path.join(goroot, "src")
    with open(os.path.join(goroot, "VERSION"), encoding="utf-8") as fh:
        version = fh.readline().strip()
    tree = _tree(src)
    units = [("std", "std", "v0.0.0", {p: d for p, d in tree.items() if not p.startswith(("cmd/", "vendor/"))}),
             ("cmd", "cmd", "v0.0.0", {p[4:]: d for p, d in tree.items()
                                       if p.startswith("cmd/") and not p.startswith("cmd/vendor/")})]
    for vendor in ("vendor", "cmd/vendor"):
        listing = tree.get(f"{vendor}/modules.txt")
        mods = modules_txt(listing.decode("utf-8", "replace")) if listing is not None else []
        roots = [f"{vendor}/{m}" for m, _v in mods]
        for (mod, ver), root in zip(mods, roots):
            nested = [r for r in roots if r != root and _under(r, root)]
            unit = {p[len(root) + 1:]: d for p, d in tree.items()
                    if _under(p, root) and not any(_under(p, n) for n in nested)}
            units.append((root, mod, ver, unit))
    return version, [u for u in units if u[3]]


# ---- the command line
def write_manifest(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def cmd_ubuntu(args, opener=urllib.request.urlopen):
    os.makedirs(args.debs, exist_ok=True)
    os.makedirs(args.cache, exist_ok=True)
    try:
        rows = read_index(the_index(args.index or os.path.join(args.debs, "Packages.xz"), args.index_sha256, opener),
                          args.index_sha256)
    except SetError as exc:
        _say(f"error: {exc}")
        return EXIT_FAIL
    if args.only:
        rows = [r for r in rows if args.only in r["package"]]
    lines, left, failed = [], [], 0
    for n, row in enumerate(rows, 1):
        try:
            got, why = ubuntu_package(row, args.debs, args.cache, not args.no_dpkg, opener)
        except (SetError, OSError, tarfile.TarError, lzma.LZMAError, EOFError, ValueError) as exc:
            failed += 1
            got, why = [], f"error: {exc}"[:300]
            _say(f"{row['package']}: {why}")
        lines.extend(got)
        if why:
            left.append({"package": row["package"], "eco": row["eco"], "why": why})
        if n % 200 == 0:
            _say(f"{n} of {len(rows)} packages")
    write_manifest(args.manifest, lines)
    if args.left_out:
        write_manifest(args.left_out, left)
    kept = len(rows) - len(left)
    by = {e: sum(1 for x in lines if x["eco"] == e) for e in ("go", "crates")}
    print(f"{len(rows)} packages, {kept} kept ({len(left) - failed} left out, {failed} failed); "
          f"Go modules {by['go']}, crates {by['crates']}: {args.manifest}")
    return EXIT_FAIL if failed else EXIT_OK


def cmd_gostd(args):
    goroot = args.goroot
    if not goroot:
        try:
            goroot = subprocess.run(["go", "env", "GOROOT"], check=True, capture_output=True, encoding="utf-8",
                                    errors="replace").stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            _say("error: no go command; give --goroot")
            return EXIT_USAGE
    os.makedirs(args.cache, exist_ok=True)
    try:
        goversion, units = gostd_units(goroot)
    except OSError as exc:
        _say(f"error: {exc}")
        return EXIT_USAGE
    lines = []
    for where, mod, ver, unit in units:
        for name, version, digest, path in pack_units("go", [(mod, unit)], lambda _n, v=ver: v, args.cache):
            lines.append(manifest_line(f"gostd:{goversion}:{where}@{version}", "gostd", "go", name, version, path,
                                       digest, go=goversion))
    write_manifest(args.manifest, lines)
    print(f"{goversion}: {len(lines)} modules in {args.manifest}")
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(prog="packaged.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("ubuntu", help="Ubuntu 24.04's golang-*-dev and librust-*-dev packages")
    u.add_argument("--debs", required=True, help="where the .debs are kept (and fetched to)")
    u.add_argument("--cache", required=True, help="where the packed modules and crates go, named by sha256")
    u.add_argument("--manifest", required=True, help="scripts/bench.py's manifest")
    u.add_argument("--left-out", help="write the packages left out, and why, here")
    u.add_argument("--index", help="noble's universe Packages.xz (default: DEBS/Packages.xz, fetched if missing)")
    u.add_argument("--index-sha256", default=INDEX_SHA256, help=argparse.SUPPRESS)
    u.add_argument("--only", help="the packages whose name holds this")
    u.add_argument("--no-dpkg", action="store_true", help="read the .debs here, not with dpkg-deb")
    u.set_defaults(func=cmd_ubuntu)
    g = sub.add_parser("gostd", help="Go's standard library, cmd and the modules they vendor")
    g.add_argument("--goroot", help="default: `go env GOROOT`")
    g.add_argument("--cache", required=True, help="where the packed modules go, named by sha256")
    g.add_argument("--manifest", required=True, help="scripts/bench.py's manifest")
    g.set_defaults(func=cmd_gostd)
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
