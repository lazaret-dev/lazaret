"""npm's reading of a package tarball, to check the registry's reader against it (BR-4).

npm unpacks a package with node-tar (pacote's options: the first path part stripped, links dropped); the
registry reads it with Python's tarfile. The two parse tar headers differently, and where they disagree npm
writes what the scan did not read. Found by the differential fuzzer (scripts/fuzz, `archive-npm-diff`):

- a ustar prefix field whose first byte is NUL and whose 131st is not: node-tar reads `/name` (and writes
  `name` once the first part is stripped), tarfile reads `name` (a top-level file, which npm never writes, so
  the scan dropped it): the package's main file, never read;
- a pax global header's `path`: tarfile renames every later entry to it, node-tar takes none;
- a regular file whose name ends in `/`: a directory to node-tar, which reads the file's data as the next headers;
- a file's header with a link name, a pax record whose length is off or whose value holds a newline, an `N` or
  `X` header, a name whose bytes are not UTF-8 (U+FFFD in node-tar), a NUL before a newline in a name: each
  reads one way in npm and another in tarfile.

`NodeTar` is node-tar's parser (7.5, which npm 10 and 11 bundle) as npm runs it, fed the bytes of the tar stream
in order: for each entry npm writes, its path as node-tar reads it (before the first part is stripped), where
its data starts in the stream and its size, and node-tar's warnings. Two readers that take an entry's data from
the same place in the same stream, for the same size, read the same bytes: the comparison is of those. `repo._iter_tar` feeds it the
stream tarfile reads and compares the two (`disagreements`): an entry npm writes that tarfile reads at another
place, under another name or not at all, and a header node-tar finds invalid or a size it reads oddly, make the
archive corrupt (INCOMPLETE): the scan cannot vouch for what npm installs. Tarballs written by npm, yarn,
pnpm, bun and git read the same in both.

Written to match node-tar's behaviour (lib/parse.js, header.js, pax.js, read-entry.js, unpack.js and
large-numbers.js; BlueOak-1.0.0), JavaScript's semantics included (`parseInt`, `trim`, a regex `.` that stops
at a line terminator, UTF-8 decoded with U+FFFD for what is not UTF-8), and held to npm's own node-tar by the
fuzz target. Not modelled: a pax or long-name record whose UTF-8 is split where the stream's chunks break
(node-tar decodes chunk by chunk); npm on Windows (backslashes are separators there, as the registry's paths
already read them)."""

import re

BLOCK = 512
MAX_META = 1024 * 1024                  # node-tar's maxMetaEntrySize: a bigger meta entry is skipped, not applied

#: node-tar's types (lib/types.js), by their code
TYPES = {"0": "File", "": "OldFile", "1": "Link", "2": "SymbolicLink", "3": "CharacterDevice", "4": "BlockDevice",
         "5": "Directory", "6": "FIFO", "7": "ContiguousFile", "g": "GlobalExtendedHeader", "x": "ExtendedHeader",
         "A": "SolarisACL", "D": "GNUDumpDir", "I": "Inode", "K": "NextFileHasLongLinkpath",
         "L": "NextFileHasLongPath", "M": "ContinuationFile", "N": "OldGnuLongPath", "S": "SparseFile",
         "V": "TapeVolumeHeader", "X": "OldExtendedHeader"}
_META = {"NextFileHasLongLinkpath", "NextFileHasLongPath", "OldGnuLongPath", "GlobalExtendedHeader",
         "ExtendedHeader", "OldExtendedHeader"}
_WRITTEN = {"File", "OldFile", "ContiguousFile"}      # pacote's filter: /File$/ (a sparse file is ignored first)
#: the fields node-tar's Pax keeps (lib/pax.js's constructor)
_PAX_FIELDS = ("atime", "charset", "comment", "ctime", "dev", "gid", "gname", "ino", "linkpath", "mtime", "nlink",
               "path", "size", "uid", "uname")
_LINE_TERMINATORS = "\n\r\u2028\u2029"            # what a JavaScript regex's `.` does not match
_JS_SPACE = ("\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
             "\u2028\u2029\u202f\u205f\u3000\ufeff")
_SAFE = 2 ** 53 - 1
_TERMINATOR = re.compile("[\n\r\u2028\u2029]")
_OCTAL = re.compile(r"[+-]?[0-7]+")
_OCTAL_BYTES = re.compile(rb"[0-7]+")
_DECIMAL = re.compile(r"[+-]?[0-9]+")
_TIME_KEY = re.compile(r"([A-Z]+\.)?([mac]|birth|creation)time")
#: warnings that make the archive one the scan cannot vouch for: node-tar skipped a header there (and read what
#: followed as headers), or this reader met a size node-tar reads by JavaScript's arithmetic
AMBIGUOUS = ("TAR_ENTRY_INVALID", "TAR_BAD_ARCHIVE", "LAZARET_ODD_SIZE", "LAZARET_META_SKIPPED")


class _Invalid(Exception):
    """node-tar's Header threw: TAR_ENTRY_INVALID, and the block is skipped."""


def _utf8(raw):
    return bytes(raw).decode("utf-8", "replace")


def _cut_nul(s, to_end=False):
    """JavaScript's s.replace(/\\0.*/, '') (with `to_end`, /\\0.*$/): from the first NUL as far as `.` reaches;
    anchored to the end, from the first NUL after which no line terminator comes."""
    i = s.find("\x00")
    if i < 0:
        return s
    if not to_end:
        m = _TERMINATOR.search(s, i + 1)
        return s[:i] + s[m.start():] if m else s[:i]
    last = max(s.rfind(c) for c in _LINE_TERMINATORS)
    if last < i:
        return s[:i]
    j = s.find("\x00", last + 1)
    return s[:j] if j >= 0 else s


def _dec_string(raw):
    return _cut_nul(_utf8(raw))


def _js_trim(s):
    return s.strip(_JS_SPACE)


def _js_parse_int(s, radix):
    """JavaScript's parseInt(s, radix), radix 8 or 10: None for NaN."""
    m = (_OCTAL if radix == 8 else _DECIMAL).match(s.lstrip(_JS_SPACE))
    return int(m.group(0), radix) if m else None


def _large(raw):
    """lib/large-numbers.js: 0x80 then a big-endian positive number, 0xff a two's complement one."""
    if raw[0] == 0x80:
        value = int.from_bytes(bytes(raw[1:]), "big")
    elif raw[0] == 0xFF:
        value = int.from_bytes(bytes(raw), "big", signed=True)
    else:
        raise _Invalid("invalid base256 encoding")
    if abs(value) > _SAFE:
        raise _Invalid("parsed number outside of javascript safe integer range")
    return value


def _dec_number(raw):
    if raw[0] & 0x80:
        return _large(raw)
    raw = bytes(raw)
    if not raw.translate(None, b"01234567 \x00"):     # (octal digits, spaces and NULs, as tar writes them)
        m = _OCTAL_BYTES.match(raw.split(b"\x00", 1)[0].strip(b" "))
        return int(m.group(0), 8) if m else None
    return _js_parse_int(_js_trim(_cut_nul(_utf8(raw), to_end=True)), 8)


def _check(raw):
    """A field node-tar reads and this model does not need: only whether reading it throws (a base-256 number that
    is not 0x80 or 0xff, or out of JavaScript's safe range)."""
    if raw[0] & 0x80:
        _large(raw)


def _utf16_slice(s, k):
    """s.slice(k) in JavaScript (k counts UTF-16 code units)."""
    units = 0
    for i, c in enumerate(s):
        if units >= k:
            return s[i:]
        units += 2 if ord(c) > 0xFFFF else 1
    return ""


def _pax_parse(text, ex):
    """lib/pax.js's Pax.parse(text, ex): each line `N key=value` whose N is its length in bytes with its newline
    (a value with a newline in it breaks its record); the new values over `ex`'s; only the fields a Pax keeps."""
    found = {}
    body = text[:-1] if text.endswith("\n") else text
    for line in body.split("\n"):
        n = _js_parse_int(line, 10)
        if n is None or n != len(line.encode("utf-8", "surrogatepass")) + 1:
            continue
        key, _, value = _utf16_slice(line, len(str(n)) + 1).partition("=")
        if not key:
            continue
        key = re.sub(r"^SCHILY\.(dev|ino|nlink)", r"\1", key)
        if _TIME_KEY.fullmatch(key):
            found[key] = ("date", value)
        elif value and all("0" <= c <= "9" for c in value):
            found[key] = int(value)
        else:
            found[key] = value
    merged = dict(ex or {})
    merged.update(found)
    return {k: merged[k] for k in _PAX_FIELDS if merged.get(k) is not None}


class _Header:
    """lib/header.js's decode of one 512-byte block, with the extended headers in force."""

    def __init__(self, b, ex, gex):
        def check(name, off, size):                    # (read for whether it throws: its value is not needed)
            if name not in ex and name not in gex:
                _check(b[off:off + size])

        self.path = ex["path"] if "path" in ex else _dec_string(b[0:100])
        _check(b[100:108])                             # mode: never a pax field
        check("uid", 108, 8)
        check("gid", 116, 8)
        self.size = ex["size"] if "size" in ex else gex["size"] if "size" in gex else _dec_number(b[124:136])
        check("mtime", 136, 12)
        self.cksum = _dec_number(b[148:160])
        if "size" in gex:                              # the global header's fields, then the local one's
            self.size = gex["size"]
        if "size" in ex:
            self.size = ex["size"]
        t = _dec_string(b[156:157])
        self.code = (t or "0") if t in TYPES else None
        if self.code == "0":
            if not isinstance(self.path, str):
                raise _Invalid("this.path.slice is not a function")
            if self.path[-1:] == "/":
                self.code = "5"
        if self.code == "5":
            self.size = 0
        self.linkpath = _dec_string(b[157:257])
        if bytes(b[257:265]) == b"ustar\x0000":
            _check(b[329:337])                         # devmajor, devminor: never pax fields here
            _check(b[337:345])
            if b[475] != 0:
                self.path = _dec_string(b[345:500]) + "/" + _js_string(self.path)
            else:
                prefix = _dec_string(b[345:475])
                if prefix:
                    self.path = prefix + "/" + _js_string(self.path)
                check("atime", 476, 12)
                check("ctime", 488, 12)
        total = 8 * 0x20 + sum(b[0:148]) + sum(b[156:512])
        self.cksum_valid = total == self.cksum
        self.null_block = self.cksum is None and total == 8 * 0x20

    @property
    def type(self):
        return TYPES[self.code] if self.code is not None else "Unsupported"


def _js_string(v):
    return v if isinstance(v, str) else str(v)


class NodeTar:
    """node-tar's Parser as pacote runs it, fed the tar stream in order.

    `files`: (path, data offset, size) of each entry npm writes, its path as node-tar reads it (before the first part
    is stripped); `warnings`: node-tar's (code, message) along the way, and this reader's for what it leaves to
    JavaScript's arithmetic (LAZARET_*). `feed(bytes)` as the stream is read, then `finish()`."""

    def __init__(self):
        self.pending = bytearray()       # the end of the last feed that was not a whole block
        self.offset = 0                  # where `pending` starts in the stream
        self.ex, self.gex = None, None
        self.saw_null = self.eof = False
        self.entry = None                # [kind, path or type, size, data offset, blocks left, data left, meta]
        self.files, self.warnings = [], []
        self.dirs = []                   # the paths of the directory entries (the fuzzer's model of npm reads them)

    def feed(self, data):
        if self.eof or not data:
            return
        if self.pending:
            data = bytes(self.pending) + bytes(data)
            self.pending.clear()
        view = memoryview(data)
        n = len(view) // BLOCK * BLOCK
        at = 0
        while at < n and not self.eof:
            if self.entry is None:
                self._header(view[at:at + BLOCK], self.offset + at)
                at += BLOCK
            else:                                      # a body: as many of its blocks as are here, at once
                take = min(self.entry[4], n - at)
                self._body(view[at:at + take])
                at += take
        self.pending += view[n:]
        self.offset += n

    def finish(self):
        """The stream ended: an entry cut short is written as far as it got (TAR_BAD_ARCHIVE)."""
        if self.entry is not None and not self.eof:
            self.warnings.append(("TAR_BAD_ARCHIVE", "truncated input"))
            self._body(memoryview(bytes(self.pending)), final=True)
        return self

    def _body(self, b, final=False):
        e = self.entry
        take = min(e[5], len(b))
        if e[0] == "meta":
            e[6].append(bytes(b[:take]))
        e[4] = 0 if final else e[4] - len(b)
        e[5] -= take
        if e[4] <= 0:
            self.entry = None
            if e[0] == "file":
                self.files.append((e[1], e[3], e[2] - e[5]))
            elif e[0] == "meta":
                self._emit_meta(e[1], b"".join(e[6]))

    def _emit_meta(self, type_, raw):
        text = _utf8(raw)
        if type_ in ("ExtendedHeader", "OldExtendedHeader"):
            self.ex = _pax_parse(text, self.ex)
        elif type_ == "GlobalExtendedHeader":
            self.gex = _pax_parse(text, self.gex)
        elif type_ in ("NextFileHasLongPath", "OldGnuLongPath"):
            self.ex = dict(self.ex or {}, path=_cut_nul(text))
        else:                                          # NextFileHasLongLinkpath
            self.ex = dict(self.ex or {}, linkpath=_cut_nul(text))

    def _odd(self, *sizes):
        """A size node-tar reads by JavaScript's arithmetic (a pax value that is not digits, a negative number):
        not followed here, and the archive is ambiguous."""
        if any(not isinstance(s, int) or s < 0 for s in sizes):
            self.warnings.append(("LAZARET_ODD_SIZE", f"a size of {sizes!r}"))
            self.eof = True
            return True
        return False

    def _header(self, b, at):
        ex, gex = self.ex or {}, self.gex or {}
        try:
            h = _Header(b, ex, gex)
        except _Invalid as exc:
            self.warnings.append(("TAR_ENTRY_INVALID", str(exc)))
            return
        if h.null_block:
            self.eof = self.saw_null
            self.saw_null = True
            return
        self.saw_null = False
        if not h.cksum_valid:
            self.warnings.append(("TAR_ENTRY_INVALID", "checksum failure"))
            return
        if not h.path:
            self.warnings.append(("TAR_ENTRY_INVALID", "path is required"))
            return
        type_ = h.type
        link = type_ in ("Link", "SymbolicLink")
        if link and not h.linkpath:
            self.warnings.append(("TAR_ENTRY_INVALID", "linkpath required"))
            return
        if not link and type_ not in ("GlobalExtendedHeader", "ExtendedHeader") and h.linkpath:
            self.warnings.append(("TAR_ENTRY_INVALID", "linkpath forbidden"))
            return
        # ReadEntry: its path is the local extended header's, never a global one's; its size (what the meta
        # tests read) the global header's, then the local one's, then the header's; its body, the header's size
        path = ex["path"] if "path" in ex else h.path
        remain = h.size if h.size is not None else 0
        size = gex.get("size", ex.get("size", remain))
        if self._odd(remain, size):
            return
        blocks = -(-remain // BLOCK) * BLOCK if remain > 0 else 0
        if type_ in _META:
            if size > MAX_META:
                self.warnings.append(("LAZARET_META_SKIPPED", "a meta entry over 1 MiB, which node-tar skips"))
                self._start("skip", type_, remain, at, blocks)
            elif size > 0:
                self._start("meta", type_, remain, at, blocks)
            return                                     # (a meta entry of size 0: its body is read as headers)
        self.ex = None
        if type_ in ("Directory", "GNUDumpDir"):
            self.dirs.append(path)
        if type_ in _WRITTEN and isinstance(path, str):
            self._start("file", path, remain, at, blocks)
        elif not isinstance(path, str) and type_ in _WRITTEN:
            self.warnings.append(("TAR_ENTRY_INVALID", "a path that is a number"))   # pacote's filter throws
            self.eof = True
        elif blocks:
            self._start("skip", type_, remain, at, blocks)

    def _start(self, kind, path, remain, at, blocks):
        self.entry = [kind, path, remain, at + BLOCK, blocks, remain, [] if kind == "meta" else None]
        if not blocks:
            self.entry = None
            if kind == "file":
                self.files.append((path, at + BLOCK, 0))
            elif kind == "meta":
                self._emit_meta(path, b"")


def _sep(c):
    return c in "/\\"


def _win32_root(p):
    """Node's path.win32.parse(p).root: a drive (`C:`, `C:/`), a separator, a UNC root (`//server/share/`)."""
    n = len(p)
    if not n:
        return ""
    if n == 1:
        return p if _sep(p) else ""
    end = 0
    if _sep(p[0]):
        end = 1
        if _sep(p[1]):
            j = last = 2
            while j < n and not _sep(p[j]):
                j += 1
            if j < n and j != last:
                last = j
                while j < n and _sep(p[j]):
                    j += 1
                if j < n and j != last:
                    last = j
                    while j < n and not _sep(p[j]):
                        j += 1
                    if j == n:
                        end = j
                    elif j != last:
                        end = j + 1
    elif p[0].isascii() and p[0].isalpha() and p[1] == ":":
        if n <= 2:
            return p
        end = 2
        if _sep(p[2]):
            if n == 3:
                return p
            end = 3
    return p[:end]


def _win32_absolute(p):
    return bool(p) and (_sep(p[0]) or (len(p) > 2 and p[0].isascii() and p[0].isalpha() and p[1] == ":"
                                       and _sep(p[2])))


def strip_absolute(p):
    """node-tar's stripAbsolutePath (on every platform, by Windows' rules): (the roots taken off, the rest). A
    drive-relative `C:x` is `x`, a UNC root goes whole, a `/` one at a time."""
    taken = ""
    root = _win32_root(p)
    while _win32_absolute(p) or root:
        cut = "/" if p[:1] == "/" and p[:4] != "//?/" else root
        p, taken = p[len(cut):], taken + cut
        root = _win32_root(p)
    return taken, p


def written_path(path):
    """Where npm on Linux or macOS writes an entry of this path, relative to the package's folder, or None when it
    writes none: node-tar's Unpack with strip 1 (the first part dropped; a depth over 1,024 not written; the
    roots taken off what is left; a `..` part, by `/` or `\\`, not written; the folder itself not written)."""
    rest = path.split("/")[1:]
    if len(rest) > 1024:
        return None
    p = "/".join(rest)
    if p:
        _taken, p = strip_absolute(p)
        if ".." in p.replace("\\", "/").split("/"):
            return None
    parts = [x for x in p.split("/") if x not in ("", ".")]
    return "/".join(parts) or None


def disagreements(node, read):
    """node: a finished NodeTar; read: {data offset: (path or None, size)} of the regular files tarfile read, each
    path where the registry puts it (repo.canonical_member_path: None when it reads none there) -> what makes the
    archive one the scan cannot vouch for, as (where, detail), the first few."""
    out = []
    for code, message in node.warnings:
        if code in AMBIGUOUS:
            out.append(("(archive)", f"npm's tar reader (node-tar) {message} ({code}): it and this reader "
                                     f"disagree about what the archive holds"))
            break
    for path, start, size in node.files:
        npm = written_path(path)
        if npm is None:
            continue
        mine = read.get(start)
        theirs = "/".join(x for x in npm.replace("\\", "/").split("/") if x not in ("", "."))
        if mine is None:
            out.append((npm, f"npm writes {npm!r} from data at byte {start}, which this reader did not read as a file"))
        elif mine[0] != theirs:
            out.append((npm, f"npm writes the entry at byte {start} as {npm!r}, this reader read it as "
                             f"{mine[0]!r}" if mine[0] is not None else
                             f"npm writes the entry at byte {start} as {npm!r}, which this reader does not extract"))
        elif mine[1] != size:
            out.append((npm, f"npm reads {size} bytes for {npm!r} at byte {start}, this reader {mine[1]}"))
        if len(out) >= 3:
            break
    return out
