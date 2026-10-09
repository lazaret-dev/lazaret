"""Go modules (0.1.9, G-1): resolving a module version to its zip on the module proxy, checking it against the Go
checksum database's `h1:` hash, and saying which of its files are built into a program.

    names        a module path as `golang.org/x/mod/module.CheckPath` reads it: slash-separated elements of ASCII letters,
                 digits and `- . _ ~`, a first element with a dot and in lower case, no `..`, no leading or trailing dot,
                 no Windows device names, a `/vN` or `.vN` major-version suffix that is well formed. Case matters: two
                 spellings that differ only in case are two modules (`identity` keeps them apart). At most 255 characters.
    URLs         the proxy writes a capital letter as `!` and the lower-case letter (`Azure` -> `!azure`), in the path and
                 in the version; `escape` does that, and `segment` returns the escaped form of a checked name or version.
    versions     `vMAJOR.MINOR.PATCH`, a pre-release (pseudo-versions are pre-releases) and the build suffix
                 `+incompatible` and no other. A version has to agree with the path's major suffix (`CheckPathMajor`).
    the proxy    `/<module>/@latest` and `/<module>/@v/<version>.info` (JSON: Version, Time) and `/@v/<version>.zip`. Every
                 member of the zip is under `<module>@<version>/`.
    the digest   `h1:` is NOT a hash of the zip. It is the SHA-256 of a list with one line per member, sorted by name: the
                 hex SHA-256 of the member, two spaces and the name (`golang.org/x/mod/sumdb/dirhash`). `zip_h1` computes
                 it from the zip, and `verify` compares it with the line `sum.golang.org/lookup/<module>@<version>`
                 returns: a host other than the one that served the zip. The lookup is checked as the go command checks
                 it (`verify_lookup`, since 0.1.9: NET-1, the native library over pratique): the signed tree head it
                 carries has the signature of the key Go pins (`SUMDB_KEY`), it agrees with the newest head this process
                 accepted before, and the record is in that tree, proved by the database's tiles. So an answer the
                 database did not sign (forged or altered, whoever served it) is caught, not only a swapped download;
                 `info["sumdb"]` is "verified". Without the native library (or with one from before the check) the
                 lookup is as good as the TLS that brought it, and `info["sumdb"]` says "tls" so a report can say so.
    the archive  Go's `modzip.Unzip` extracts every member as a regular file, whatever its mode (so `links_extracted` is
                 False), and refuses the whole zip for a member outside the root or with a path `CheckFilePath` rejects.
                 `member_path` says which members that is. Case collisions between members are not checked here.
    what runs    nothing at download, and `go build` runs no generator. Code runs when a program is built and started:
                 `init` functions and package-level initializers of every imported package, and cgo's C compiler and
                 `pkg-config`. Which `.go` file declares `init` needs the file's text, and `run_targets` is given the
                 manifests and the names, so it marks by name: the programs a `go install` would build are `entries`; the
                 C, assembly and object files the Go tool hands to other tools are `install_scripts`. The engine's Go
                 rules (G-2, G-3) read the text.

Verified against Go's own code: `scripts/gooracle/` is a program over golang.org/x/mod v0.22.0 that answers for a name, a
version, a member path, a zip and a go.mod what Go answers, and `tests/registry/recorded/go/` holds its answers for a
long list, real module zips built by Go from their git tags with the `h1:` that the published go.sum files carry, and a
lookup response made by Go's own checksum database server. The module proxy itself was not reachable from where this
was written: its response formats are the documented protocol (`go help goproxy`), not recordings. The lookup's check
is tested on a capture of the real `sum.golang.org` (pratique's tests/data/sumdb: a lookup, a tree head kept from
before and the seven tiles Go's own client reads for them; `tests/registry/test_golang_sumdb.py`).

Standard library, `base`, and the native library for the lookup's check. No Go is run and nothing is built."""

import base64
import hashlib
import io
import re
import struct
import threading
import unicodedata
import urllib.parse
import zipfile
import zlib

from lazaret.registry.ecosystems import base
from lazaret.scanner import gomod

__all__ = ["Go", "ECOSYSTEM", "check_module_path", "split_path_version", "check_path_major", "escape", "file_path_problem",
           "unescape", "zip_h1", "file_h1", "parse_lookup", "verify_lookup", "parse_gomod", "is_pseudo_version", "canonical_version",
           "MAX_NAME", "MAX_ZIP_CONTENT", "SUMDB_KEY"]

PROXY_HOST = "proxy.golang.org"
SUMDB_HOST = "sum.golang.org"
MAX_NAME = 255
MAX_VERSION = gomod.MAX_VERSION
MAX_ZIP_CONTENT = 500 * 1024 * 1024        # zip.MaxZipFile: the total uncompressed size of a module
MAX_GOMOD = gomod.MAX_GOMOD                # zip.MaxGoMod
MAX_ENTRIES = 250_000                      # members of one zip (the biggest modules have tens of thousands)
MAX_REQUIRES = gomod.MAX_REQUIRES
MAX_LOOKUP_BYTES = 64 * 1024
#: the checksum database's verifier key, the one the go command pins (cmd/go/internal/modfetch, `knownGOSUMDB`)
SUMDB_KEY = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
MAX_SUMDB_TILES = 64                       # the most one check reads (lazaret-verify's gosum::MAX_TILES)
MAX_TILE_BYTES = 8192                      # a full tile: 2^8 hashes of 32 bytes
SUMDB_TILES_KEPT = 1024                    # tiles kept for the process (8 MiB at most)

_NUM, _PRE, _BUILD = gomod.NUM, gomod.PRE, gomod.BUILD
_SEMVER = rf"v{_NUM}\.{_NUM}\.{_NUM}(?:-{_PRE}(?:\.{_PRE})*)?"
VERSION_RE = re.compile(_SEMVER + r"(?:\+incompatible)?")
_SEMVER_RE = re.compile(_SEMVER + rf"(?:\+{_BUILD}(?:\.{_BUILD})*)?")
_PSEUDO_RE = re.compile(r"v[0-9]+\.(?:0\.0-|[0-9]+\.[0-9]+-(?:[^+]*\.)?0\.)[0-9]{14}-[A-Za-z0-9]+(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
_H1_RE = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,20}(?:Z|[+-][0-9]{2}:[0-9]{2})")
_WINDOWS_NAMES = frozenset({"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)})
_MODULE_CHARS = frozenset("-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_FIRST_CHARS = frozenset("-.0123456789abcdefghijklmnopqrstuvwxyz")
_FILE_PUNCTUATION = frozenset("!#$%&()+,-.=@[]^_{}~ ")
_ASCII_ALNUM = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


# ---------------------------------------------------------------- names (module.CheckPath, CheckFilePath, SplitPathVersion)
def _element_ok(ch, kind):
    if kind == "module":
        return ch in _MODULE_CHARS
    if ch.isascii():
        return ch in _ASCII_ALNUM or ch in _FILE_PUNCTUATION
    return unicodedata.category(ch).startswith("L")           # unicode.IsLetter


def _element_problem(elem, kind):
    if not elem:
        return "empty path element"
    if elem.count(".") == len(elem):
        return "a path element made of dots"
    if elem[0] == "." and kind == "module":
        return "leading dot in a path element"
    if elem[-1] == ".":
        return "trailing dot in a path element"
    if not all(_element_ok(ch, kind) for ch in elem):
        return "invalid character in a path element"
    short = elem.split(".", 1)[0]
    if short.isascii() and short.upper() in _WINDOWS_NAMES:
        return "a Windows device name as a path element"
    if kind == "file":
        return None
    tilde = short.rfind("~")
    if 0 <= tilde < len(short) - 1 and short[tilde + 1:].isascii() and short[tilde + 1:].isdigit():
        return "trailing tilde and digits in a path element"
    return None


def _path_problem(path, kind):
    """Why `path` is not a valid module path (`kind` "module") or file path in a module zip (`kind` "file"), as a fixed
    sentence that does not contain the path; None if it is valid. `module.checkPath`."""
    if not isinstance(path, str):
        return "not text"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "invalid UTF-8"
    if not path:
        return "empty"
    if path[0] == "-" and kind == "module":
        return "leading dash"
    if "//" in path:
        return "double slash"
    if path[-1] == "/":
        return "trailing slash"
    for elem in path.split("/"):
        problem = _element_problem(elem, kind)
        if problem:
            return problem
    return None


def file_path_problem(path):
    """Why `path` (a member of a module zip, relative to the module root) is refused by `module.CheckFilePath`, or None."""
    return _path_problem(path, "file")


def split_path_version(path):
    """-> (prefix, path_major, ok): `module.SplitPathVersion`. `path_major` is "" or "/vN" or ".vN" (gopkg.in)."""
    if path.startswith("gopkg.in/"):
        return _split_gopkg_in(path)
    i = len(path)
    dot = False
    while i > 0 and (path[i - 1].isascii() and path[i - 1].isdigit() or path[i - 1] == "."):
        if path[i - 1] == ".":
            dot = True
        i -= 1
    if i <= 1 or i == len(path) or path[i - 1] != "v" or path[i - 2] != "/":
        return path, "", True
    prefix, major = path[:i - 2], path[i - 2:]
    if dot or len(major) <= 2 or major[2] == "0" or major == "/v1":
        return path, "", False
    return prefix, major, True


def _split_gopkg_in(path):
    i = len(path)
    if path.endswith("-unstable"):
        i -= len("-unstable")
    while i > 0 and path[i - 1].isascii() and path[i - 1].isdigit():
        i -= 1
    if i <= 1 or path[i - 1] != "v" or path[i - 2] != ".":
        return path, "", False
    prefix, major = path[:i - 2], path[i - 2:]
    if len(major) <= 2 or major[2] == "0" and major != ".v0":
        return path, "", False
    return prefix, major, True


def check_module_path(path):
    """None if `path` is a module path `module.CheckPath` accepts; else a fixed sentence saying why not."""
    problem = _path_problem(path, "module")
    if problem:
        return problem
    first = path.split("/", 1)[0]                                 # (not empty and not led by a dash: `_path_problem` refused both)
    if "." not in first:
        return "missing dot in the first path element"
    if not all(ch in _FIRST_CHARS for ch in first):
        return "invalid character in the first path element"
    if not split_path_version(path)[2]:
        return "invalid major version suffix"
    return None


def _major(version):
    """semver.Major: "v1" for "v1.2.3-pre+build"."""
    return "v" + re.split(r"[.+-]", version[1:], maxsplit=1)[0]


def check_path_major(version, path_major):
    """True if a version fits the path's major-version suffix: `module.CheckPathMajor` (version already checked)."""
    if path_major.startswith(".v") and path_major.endswith("-unstable"):
        path_major = path_major[:-len("-unstable")]
    if version.startswith("v0.0.0-") and path_major == ".v1":
        return True
    major = _major(version)
    if path_major == "":
        return major in ("v0", "v1") or version.endswith("+incompatible")
    return major == path_major[1:]


def escape(text):
    """The proxy's case encoding of a checked name or version: each capital letter becomes `!` and its lower-case letter."""
    return "".join("!" + ch.lower() if "A" <= ch <= "Z" else ch for ch in text)


def unescape(text):
    """The name or version a proxy URL's `escape`d segment stands for (`module.UnescapePath`'s case decoding), or None when
    the text is not one: a capital letter, a `!` not followed by a lower-case letter, a trailing `!`, a non-ASCII character."""
    out, bang = [], False
    for ch in text:
        if ord(ch) >= 0x80:
            return None
        if bang:
            if not "a" <= ch <= "z":
                return None
            out.append(ch.upper())
            bang = False
        elif ch == "!":
            bang = True
        elif "A" <= ch <= "Z":
            return None
        else:
            out.append(ch)
    return None if bang else "".join(out)


canonical_version = gomod.canonical_version


def is_pseudo_version(version):
    """`module.IsPseudoVersion`: a SemVer pre-release of the shape `vX.Y.Z-yyyymmddhhmmss-abcdefabcdef`."""
    return version.count("-") >= 2 and bool(_SEMVER_RE.fullmatch(version)) and bool(_PSEUDO_RE.fullmatch(version))


# ---------------------------------------------------------------- the digest (sumdb/dirhash)
def _h1(lines):
    return "h1:" + base64.b64encode(hashlib.sha256(lines).digest()).decode("ascii")


def file_h1(data, name="go.mod"):
    """`dirhash.Hash1` over the one file `name`: the `/go.mod h1:` line of go.sum is this for the module's go.mod."""
    return _h1(hashlib.sha256(data).hexdigest().encode("ascii") + b"  " + name.encode("utf-8") + b"\n")


def zip_h1(data):
    """The `h1:` hash Go computes for a module zip (`dirhash.HashZip` with `Hash1`). DigestError for anything that is not
    a zip Go could have hashed: unreadable, an unsupported method, a bad checksum, two members of one name, a name with a
    newline, more files or more bytes than Go allows."""
    try:
        return _zip_h1(data)
    except base.DigestError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error, OSError,
            ValueError, OverflowError, struct.error, UnicodeError, MemoryError):
        raise base.DigestError("go: the download is not a zip that can be hashed") from None


def _zip_h1(data):
    # (the central directory is checked before zipfile parses it: it builds one record per entry the directory
    # declares, so a 200 MB download could hold millions; the Go/Rust review's RM-2)
    from lazaret.registry import repo                    # (here: repo is the registry's, and it does not import this module)
    refused = repo._zip_preflight(data, max_files=MAX_ENTRIES)
    if refused:
        raise base.DigestError(f"go: {refused}")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise base.DigestError("go: the zip has more members than a module can")
        if sum(i.file_size for i in infos) > MAX_ZIP_CONTENT:
            raise base.DigestError("go: the zip holds more than the 500 MiB a module can")
        if len({i.header_offset for i in infos}) != len(infos):          # (CPython warns on stderr when it reads such a zip: no module has one)
            raise base.DigestError("go: two members of the zip start at one place")
        rows, seen = [], set()
        for info in infos:
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise base.DigestError("go: a member of the zip uses a compression Go does not read")
            # The name as Go reads it: the bytes in the central directory, whatever the UTF-8 flag says.
            name = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
            if b"\n" in name:
                raise base.DigestError("go: a member of the zip has a newline in its name")
            if name in seen:
                raise base.DigestError("go: the zip has two members of one name")
            seen.add(name)
            digest = hashlib.sha256()
            if name.endswith(b"/"):                      # (a directory: Go reads it as empty, and refuses one that has data)
                if info.file_size:
                    raise base.DigestError("go: a directory in the zip has data")
            else:
                with z.open(info) as member:
                    while True:
                        chunk = member.read(1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
            rows.append((name, digest.hexdigest().encode("ascii")))
    rows.sort()
    return _h1(b"".join(hexdigest + b"  " + name + b"\n" for name, hexdigest in rows))


def _valid_record_text(text):
    """sumdb/tlog.isValidRecordText: no control characters but newline, no empty line, ends with a newline."""
    if not text.endswith("\n"):
        return False
    last = ""
    for ch in text:
        if ch < " " and ch != "\n" or ch == "\n" and last == "\n":
            return False
        last = ch
    return True


def parse_lookup(text, name, version):
    """A `sum.golang.org/lookup/<module>@<version>` response -> {"id": n, "h1": zip hash, "gomod_h1": go.mod hash or None}.
    The layout is `<id>\\n<record lines>\\n\\n<signed tree head>`; the record lines are `<module> <version> <hash>` and
    `<module> <version>/go.mod <hash>`. FetchError if it is not that, or does not speak of this module and version."""
    head, sep, note = text.partition("\n\n")
    first, nl, record = head.partition("\n")
    if not sep or not nl or not (first.isascii() and first.isdigit() and len(first) <= 18):
        raise base.FetchError("go: the checksum database sent a response in a layout it does not have")
    record += "\n"
    if not _valid_record_text(record):
        raise base.FetchError("go: the checksum database sent a record that is not valid")
    if not (note.startswith("go.sum database tree\n") and "\n\n— " in "\n" + note):
        raise base.FetchError("go: the checksum database response has no signed tree head")
    found = {}
    for line in record.splitlines():
        fields = line.split(" ")
        if len(fields) != 3 or not _H1_RE.fullmatch(fields[2]):
            raise base.FetchError("go: the checksum database sent a record line that is not valid")
        if fields[0] == name and fields[1] in (version, version + "/go.mod"):
            if fields[1] in found:
                raise base.FetchError("go: the checksum database sent two hashes for one file")
            found[fields[1]] = fields[2]
    if version not in found:
        raise base.FetchError("go: the checksum database has no hash for this module version")
    return {"id": int(first), "h1": found[version], "gomod_h1": found.get(version + "/go.mod")}


# ---------------------------------------------------------------- the checksum database's proof (NET-1)
_TILE_PATH_RE = re.compile(r"tile/8/[0-9]{1,2}/(?:x[0-9]{3}/){0,7}[0-9]{3}(?:\.p/[0-9]{1,3})?")


class _Sumdb:
    """What this process's checks keep: the newest signed tree head one has accepted, which the next check is given
    (so the database cannot show this process two histories: `Check::add_head`), and the tiles that passed. A tile's
    bytes never change, and each is checked again, against the signed tree, whenever it is used."""

    def __init__(self):
        self.lock = threading.Lock()
        self.latest = None                   # (tree size, the signed note)
        self.tiles = {}                      # tile path -> bytes

    def head(self):
        with self.lock:
            return None if self.latest is None else self.latest[1]

    def tile(self, path):
        with self.lock:
            return self.tiles.get(path)

    def keep(self, size, note, tiles):
        with self.lock:
            if self.latest is None or size > self.latest[0]:
                self.latest = (size, note)
            for path, data in tiles.items():
                if path not in self.tiles and len(self.tiles) >= SUMDB_TILES_KEPT:
                    self.tiles.pop(next(iter(self.tiles)))
                self.tiles[path] = data


_SUMDB = _Sumdb()


def _tile_ok(tile):
    return (isinstance(tile, dict) and all(isinstance(tile.get(k), str) and len(tile[k]) <= 64 and _TILE_PATH_RE.fullmatch(tile[k])
                                           for k in ("path", "full"))
            and all(type(tile.get(k)) is int for k in ("len", "full_len"))
            and 0 < tile["len"] <= tile["full_len"] <= MAX_TILE_BYTES)


def _fetch_tile(tile, fetch):
    """A tile from the database: the one named, or, when the database no longer serves that partial tile (it has filled
    since), the full one, whose first hashes are the same. The go command does the same (sumdb.Client.readTile)."""
    try:
        return fetch.bytes(f"https://{SUMDB_HOST}/{tile['path']}", max_bytes=tile["len"])
    except base.FetchError:
        if tile["full"] == tile["path"]:
            raise
    return fetch.bytes(f"https://{SUMDB_HOST}/{tile['full']}", max_bytes=tile["full_len"])


def _not_checked(name, version, exc):
    reason = "".join(c if c.isprintable() else "?" for c in str(exc).partition(": ")[2])[:200]
    return base.FetchError(f"go: the checksum database's answer for {base.show(name, 60)} {base.show(version)} does not check "
                           f"out ({reason})")


def verify_lookup(name, version, lookup, record, fetch):
    """The checksum database's answer for `name@version` (`lookup`, the response; `record`, what `parse_lookup` read of
    it) checked as the go command checks it, by the native library's `verify.go_sumdb` (pratique's sumdb and tlog):
    the signed tree head the lookup carries has the signature of the database's key (`SUMDB_KEY`), it is consistent
    with the newest head this process accepted before, and the record is in that tree, proved by the tiles the check
    names, which come from the database through `fetch` and are each checked against the signed root. The hashes
    `parse_lookup` read must be lines of that record. -> True when all of that holds; None when this install cannot
    check (no native library, or one from before the check): the lookup is then as good as the TLS that brought it.
    FetchError when the check fails or a tile cannot be had: fail closed, nothing the lookup says is used."""
    from lazaret.scanner import _native
    if not _native.available():
        return None
    args = {"module": name, "version": version, "key": SUMDB_KEY, "lookup": lookup, "head": _SUMDB.head()}
    try:
        needed = _native.call("verify.go_sumdb", args)
    except _native.NativeError as exc:
        if "unknown call" in str(exc):
            return None                                       # (a native library from before 0.1.9's check)
        raise _not_checked(name, version, exc) from None
    needed = needed.get("needed") if isinstance(needed, dict) else None
    if not isinstance(needed, list) or len(needed) > MAX_SUMDB_TILES or not all(_tile_ok(t) for t in needed):
        raise base.FetchError("go: the checksum database check named tiles it cannot have")
    tiles = {}
    for tile in needed:
        tiles[tile["path"]] = _SUMDB.tile(tile["path"]) or _fetch_tile(tile, fetch)
    args["tiles"] = {path: base64.b64encode(data).decode("ascii") for path, data in tiles.items()}
    try:
        got = _native.call("verify.go_sumdb", args)
    except _native.NativeError as exc:
        raise _not_checked(name, version, exc) from None
    if not (isinstance(got, dict) and got.get("verified") is True and isinstance(got.get("lines"), list)
            and isinstance(got.get("record"), str) and type(got.get("id")) is int and type(got.get("size")) is int
            and isinstance(got.get("latest"), str)):
        raise base.FetchError("go: the checksum database check gave an answer it does not give")
    signed = got["record"].split("\n")
    if (got["id"] != record["id"] or f"{name} {version} {record['h1']}" not in got["lines"]
            or (record["gomod_h1"] is not None and f"{name} {version}/go.mod {record['gomod_h1']}" not in signed)):
        raise base.FetchError("go: the checksum database's signed record is not the one its response reads as")
    _SUMDB.keep(got["size"], got["latest"], tiles)
    return True


# ---------------------------------------------------------------- go.mod
_tokens = gomod.tokens                                                # (the lexer is shared with the inventory: scanner/gomod.py)


def parse_gomod(text):
    """The parts of a go.mod that name things -> {"module": path or None, "go": version or None, "require": [(path,
    version, indirect), ...]}. It reads the way `modfile.Parse` does for what `Parse` accepts (the tests hold the two
    equal on a list of go.mod files) and goes on past a line it cannot read, since a hostile file is no reason to stop
    reading; it takes the paths as written and does not check them."""
    got = gomod.parse(text)
    return {"module": got["module"], "go": got["go"], "require": got["require"]}


# ---------------------------------------------------------------- source files that are handed to other tools
_FOREIGN_SOURCE = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".s", ".sx", ".syso", ".swig", ".swigcxx", ".f", ".f90",
                             ".for"})


class Go(base.Ecosystem):
    id = "go"
    title = "Go modules"
    hosts = frozenset({PROXY_HOST, SUMDB_HOST})
    artifact_kinds = ("gomod",)
    rate = {}
    manifest_names = frozenset({"go.mod"})

    # ---- names and versions
    def check_name(self, name):
        if not isinstance(name, str) or not name:
            raise base.SpecError("go: empty module path")
        if len(name) > MAX_NAME:
            raise base.SpecError(f"go: module path longer than {MAX_NAME} characters")
        problem = check_module_path(name)
        if problem:
            raise base.SpecError(f"go: invalid module path ({problem}): {base.show(name, 60)}")
        return name

    def check_version(self, version):
        if version is None:
            return None
        if not isinstance(version, str) or not version.strip():
            raise base.SpecError(f"go: invalid version {base.show(version)}")
        version = version.strip()
        if len(version) > MAX_VERSION or not VERSION_RE.fullmatch(version):
            raise base.SpecError(f"go: invalid version {base.show(version)}")
        return version

    def _name_ok(self, name):
        try:
            self.check_name(name)
        except base.SpecError:
            return False
        return True

    def segment(self, value):
        text = str(value)
        if check_module_path(text) is None and len(text) <= MAX_NAME:
            return escape(text)                                    # (a module path is several path segments)
        if len(text) <= MAX_VERSION and VERSION_RE.fullmatch(text):
            return escape(text)
        return urllib.parse.quote(text, safe="")

    # ---- the network
    def resolve(self, name, version, fetch):
        name = self.check_name(name)
        want = self.check_version(version)
        _, path_major, _ = split_path_version(name)
        if want is not None and not check_path_major(want, path_major):
            raise base.SpecError(f"go: version {base.show(want)} does not fit the major version of {base.show(name, 60)}")
        proxy = f"https://{PROXY_HOST}/{escape(name)}/"
        doc = fetch.json(proxy + ("@latest" if want is None else f"@v/{escape(want)}.info"))
        if not isinstance(doc, dict) or not isinstance(doc.get("Version"), str):
            raise base.FetchError("go: the proxy's answer has no version")
        try:
            found = self.check_version(doc["Version"])
        except base.SpecError:
            raise base.FetchError("go: the proxy sent a version that is not a module version") from None
        if (want is not None and found != want) or not check_path_major(found, path_major):
            raise base.FetchError("go: the proxy answered for another version than the one asked for")
        stamp = doc.get("Time")
        lookup = fetch.text(f"https://{SUMDB_HOST}/lookup/{escape(name)}@{escape(found)}", max_bytes=MAX_LOOKUP_BYTES)
        record = parse_lookup(lookup, name, found)
        checked = verify_lookup(name, found, lookup, record, fetch)
        entry = {"h1": record["h1"], "gomod_h1": record["gomod_h1"]}
        art = {"url": proxy + f"@v/{escape(found)}.zip", "container": "zip", "artifact": "gomod", "entry": entry,
               "filename": f"{name.rsplit('/', 1)[-1]}@{found}.zip"}
        return base.Resolution(found, [art], [], {
            "module": name, "root": f"{name}@{found}/", "pseudo": is_pseudo_version(found),
            "sumdb": "verified" if checked else "tls",
            "time": stamp if isinstance(stamp, str) and _TIME_RE.fullmatch(stamp) else None})

    def verify(self, data, entry, name, version):
        h1 = entry.get("h1") if isinstance(entry, dict) else None
        if not isinstance(h1, str) or not _H1_RE.fullmatch(h1):
            return None
        actual = zip_h1(data)
        if actual != h1:
            raise base.DigestError(f"go: the h1 hash of the download does not match the one the checksum database "
                                   f"published for {base.show(name, 60)} {base.show(version)}")
        return "h1", actual[3:]

    def dependencies(self, resolved, fetch):
        """The modules a release requires, from its `.mod` file on the proxy, checked against the go.mod hash the
        checksum database published."""
        try:
            name, version = resolved.info["module"], resolved[0]
            expect = resolved.artifacts[0]["entry"].get("gomod_h1")
        except (AttributeError, IndexError, KeyError, TypeError):
            return None
        if not (self._name_ok(name) and isinstance(version, str) and VERSION_RE.fullmatch(version)):
            return None
        raw = fetch.bytes(f"https://{PROXY_HOST}/{escape(name)}/@v/{escape(version)}.mod", max_bytes=MAX_GOMOD)
        if isinstance(expect, str) and _H1_RE.fullmatch(expect) and file_h1(raw) != expect:
            raise base.DigestError(f"go: the go.mod of {base.show(name, 60)} {base.show(version)} does not match the hash "
                                   f"the checksum database published")
        try:
            parsed = parse_gomod(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise base.FetchError("go: the go.mod is not UTF-8 text") from None
        return tuple(sorted({path for path, _, _ in parsed["require"] if self._name_ok(path)}))

    # ---- archives
    def container(self, filename):
        return "zip" if isinstance(filename, str) and filename.endswith(".zip") else None

    def archive_root(self, resolved, artifact):
        try:
            module = resolved.info["module"]
            version = resolved[0]
        except (AttributeError, KeyError, TypeError):
            return None
        return f"{module}@{version}/" if self._name_ok(module) and isinstance(version, str) else None

    def member_path(self, kind, name, root=None):
        path = name if isinstance(name, str) else str(name)
        if not root:
            parts = path.split("/")
            at = next((i for i, part in enumerate(parts[:-1]) if "@" in part), None)       # (the first `<name>@<version>` directory)
            root = "/".join(parts[:at + 1]) + "/" if at is not None else None
        if not root or not path.startswith(root):
            return None, "member outside the archive's root directory"
        rest = path[len(root):]
        if not rest:
            return None, None
        is_dir = rest.endswith("/")
        if is_dir:
            rest = rest[:-1]
        problem = file_path_problem(rest)
        if problem:
            return None, f"member path refused by Go ({problem})"
        if is_dir:
            return None, None
        if rest.rsplit("/", 1)[-1].lower() == "go.mod" and rest != "go.mod":
            return None, "go.mod not in the module root directory, or not spelled go.mod"
        return rest, None

    def links_extracted(self, kind):
        return False

    # ---- what is read in an archive, and what runs
    def run_targets(self, kind, manifests, members):
        entries, scripts = set(), set()
        for member in members or ():
            if not isinstance(member, str) or member.endswith("_test.go"):
                continue
            leaf = member.rsplit("/", 1)[-1]
            if leaf == "main.go" or member.startswith("cmd/") and leaf.endswith(".go") and "/internal/" not in member:
                entries.add(member)
            elif "." in leaf and "." + leaf.rsplit(".", 1)[-1].lower() in _FOREIGN_SOURCE and not leaf.startswith(("_", ".")):
                scripts.add(member)
        return base.RunTargets(entries=entries, install_scripts=scripts)

    def declared(self, kind, manifests, members):
        text = manifests.get("go.mod") if isinstance(manifests, dict) else None
        parsed = parse_gomod(text)
        specs = {}
        for path, version, _ in parsed["require"]:
            if self._name_ok(path) and path not in specs:
                specs[path] = version
        return base.Declared(parsed["module"] if parsed["module"] is not None and self._name_ok(parsed["module"]) else None,
                             sorted(specs), specs)


ECOSYSTEM = Go()
