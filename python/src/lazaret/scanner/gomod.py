"""go.mod: the lines that name things (0.1.9, G-1).

One reader for the two places that need it: the Go module auditor (`registry/ecosystems/golang.py`, which reads a
dependency's go.mod and holds it to `golang.org/x/mod`'s `modfile.ParseLax`) and the dependency inventory of a project
(`scanner/sca.py`, which reads the project's own). It is in `scanner` because the layers go mcp, registry, scanner: the
registry may import this and the inventory may not import the registry.

The lexer is `modfile`'s: a line is words, a quoted string (`"`, read as `strconv.Unquote` reads it, or a raw string in
backticks) is one word, `(` `)` `[` `]` `{` `}` `,` are words of their own, `//` starts a comment, and a verb followed by a
lone `(` opens a block that a lone `)` closes. What is read of the lines is `module`, `go`, `require` (with `// indirect`),
`replace` and go.work's `use`; the rest (`exclude`, `retract`, `toolchain`, `godebug`, `tool`) is left, since none of it
names a module that is built.
It goes on past a line it cannot read, because a hostile file is no reason to stop reading, and it takes paths as written:
checking them is the caller's. Linear in the text, which is cut at `MAX_GOMOD`.

A version is read as `module.CanonicalVersion` reads it (`v1` is `v1.0.0`, build metadata goes except `+incompatible`);
a line whose version is not one is dropped, as Go refuses the file."""

import re

MAX_GOMOD = 16 * 1024 * 1024               # zip.MaxGoMod
MAX_REQUIRES = 20_000
MAX_REPLACES = 20_000
MAX_USES = 2_000
MAX_VERSION = 100

__all__ = ["MAX_GOMOD", "MAX_REQUIRES", "MAX_REPLACES", "MAX_USES", "MAX_VERSION", "NUM", "PRE", "BUILD", "SEMVER_PARTS",
           "tokens", "unquote", "parse", "is_directory_path", "canonical_version", "go_at_least"]

NUM = r"(?:0|[1-9][0-9]*)"
PRE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
BUILD = r"[0-9A-Za-z-]+"
SEMVER_PARTS = re.compile(rf"v({NUM})(?:\.({NUM})(?:\.({NUM})(?:-({PRE}(?:\.{PRE})*))?(?:\+({BUILD}(?:\.{BUILD})*))?)?)?")
_GO_VERSION = re.compile(r"([1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?(?:[a-z]+[0-9]+)?")      # modfile.GoVersionRE


def _ident_char(ch):
    return ch not in " ()[]{}," and ch.isprintable()


_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}
_HEX = frozenset("0123456789abcdefABCDEF")


def unquote(body):
    """The text of a double-quoted Go string whose inside is `body`, as `strconv.Unquote` reads it, or None where Go refuses
    it: `\\a` `\\b` `\\f` `\\n` `\\r` `\\t` `\\v` `\\\\` `\\"`, `\\x` and two hex digits or `\\` and three octal ones (a byte, up to
    0377), `\\u` and four or `\\U` and eight hex digits (a code point that is not a surrogate). The bytes are read as UTF-8.
    Only `\\"` and `\\\\` were read: `"a.example\\x2fb"`, which Go reads as a.example/b, dropped its line (the Go/Rust
    review's SCA-3)."""
    if "\\" not in body:
        return body
    out, i, n = bytearray(), 0, len(body)
    while i < n:
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8", "surrogatepass")
            i += 1
            continue
        c = body[i + 1] if i + 1 < n else ""
        if c in _ESCAPES and c:
            out += _ESCAPES[c].encode("ascii")
            i += 2
        elif c == "x" or c in "01234567" and c:
            digits = body[i + 2:i + 4] if c == "x" else body[i + 1:i + 4]
            if len(digits) != (2 if c == "x" else 3) or not all(d in (_HEX if c == "x" else "01234567") for d in digits):
                return None
            value = int(digits, 16 if c == "x" else 8)
            if value > 0xFF:
                return None
            out.append(value)
            i += 4
        elif c in ("u", "U"):
            k = 4 if c == "u" else 8
            digits = body[i + 2:i + 2 + k]
            if len(digits) != k or not all(d in _HEX for d in digits):
                return None
            value = int(digits, 16)
            if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                return None
            out += chr(value).encode("utf-8")
            i += 2 + k
        else:
            return None
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def tokens(line):
    """One line of a go.mod -> (tokens, comment). A token is text, or None for a string or a character that could not be
    read; `(` and `)` are tokens. `//` starts a comment, which is returned apart (without the slashes). The rules are
    those of `modfile`'s lexer."""
    out, i, n = [], 0, len(line)
    comment = None
    while i < n:
        ch = line[i]
        if ch in " \t\r":
            i += 1
        elif line.startswith("//", i):
            comment = line[i + 2:]
            break
        elif ch in "()[]{},":
            out.append(ch)
            i += 1
        elif ch in "\"`":
            j = i + 1
            while j < n and line[j] != ch:
                j += 2 if ch == '"' and line[j] == "\\" else 1          # (an escape is the backslash and the next character)
            if j >= n:
                out.append(None)                                    # (not closed on its line: Go refuses it)
            else:
                out.append(unquote(line[i + 1:j]) if ch == '"' else line[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and _ident_char(line[j]) and not line.startswith("//", j):
                j += 1
            out.append(line[i:j] if j > i else None)
            i = max(j, i + 1)
    return out, comment


def _indirect(comment):
    fields = (comment or "").split()
    return fields == ["indirect"] or len(fields) > 1 and fields[0] == "indirect;"


def is_directory_path(path):
    """`modfile.IsDirectoryPath`: a replacement that is a directory, not a module (checked for every syntax, since a go.mod
    moves between systems)."""
    return (path in (".", "..") or path.startswith(("./", ".\\", "../", "..\\", "/", "\\"))
            or len(path) >= 2 and path[0].isascii() and path[0].isalpha() and path[1] == ":")


def canonical_version(version):
    """`module.CanonicalVersion`: `v1` and `v1.2` are `v1.0.0` and `v1.2.0`, build metadata goes except `+incompatible`;
    "" if `version` is not SemVer."""
    m = SEMVER_PARTS.fullmatch(version) if isinstance(version, str) and len(version) <= MAX_VERSION else None
    if m is None:
        return ""
    major, minor, patch, pre, build = m.groups()
    if minor is None or patch is None:                               # (`v1` and `v1.2`; `v1-pre` and `v1+b` did not match: not SemVer)
        return f"v{major}.{minor or '0'}.{patch or '0'}"
    return f"v{major}.{minor}.{patch}" + (f"-{pre}" if pre is not None else "") + ("+incompatible" if build == "incompatible" else "")


def go_at_least(version, major, minor):
    """Is `version`, a `go` directive's (`1.21`, `1.21.3`, `1.21rc1`; `modfile.GoVersionRE`), at least `major.minor`?
    False when it is not a version. The numbers are compared as digit strings: a hostile file's are of any length."""
    m = _GO_VERSION.fullmatch(version) if isinstance(version, str) else None
    if m is None:
        return False
    return tuple((len(d), d) for d in m.groups()) >= tuple((len(str(n)), str(n)) for n in (major, minor))


def _replace(args, canonical):
    """The arguments of one replace line -> (old path, old version or "", new path, new version or ""), or None when
    `modfile.parseReplace` would refuse them: `old [version] => new [version]`, a directory without a version."""
    if not all(isinstance(a, str) for a in args):
        return None                                   # (a word that could not be read is in the line: Go refuses it)
    arrow = 1 if args[1:2] == ["=>"] else 2
    if len(args) < arrow + 2 or len(args) > arrow + 3 or args[arrow] != "=>":
        return None
    old, new = args[0], args[arrow + 1]
    old_version = ""
    if arrow == 2:
        old_version = canonical(args[1])
        if not old_version:
            return None
    new_version = ""
    if len(args) == arrow + 3:
        new_version = canonical(args[arrow + 2])
        if not new_version or is_directory_path(new):
            return None                               # (a directory cannot have a version)
    elif not is_directory_path(new):
        return None                                   # (a module without a version: Go refuses it)
    return old, old_version, new, new_version


def parse(text, canonical=canonical_version):
    """The parts of a go.mod (or a go.work) that name things -> {"module": path or None, "go": version or None, "require":
    [(path, version, indirect), ...], "replace": [(old path, old version, new path, new version), ...], "use": [directory,
    ...] (go.work's), "unversioned": [(path, indirect), ...], "dropped": n}. A version that is not one ("") drops its line
    (`canonical` is `canonical_version`; a caller may pass another), except one longer than MAX_VERSION, which Go reads
    and this reader does not: that requirement is in "unversioned", with no version. "dropped" counts the require,
    replace and use lines not read (a word that could not be read, a version that is not one, past the limits), so that
    nothing is left out unsaid (the Go/Rust review's SCA-3). A replacement without a version is a directory
    (`is_directory_path`)."""
    out = {"module": None, "go": None, "require": [], "replace": [], "use": [], "unversioned": [], "dropped": 0}
    if not isinstance(text, str):
        return out
    block = None
    requires, replaces, unversioned = out["require"], out["replace"], out["unversioned"]
    for raw in text[:MAX_GOMOD].split("\n"):
        words, comment = tokens(raw)
        if not words:
            continue
        if block is not None:
            if words[0] == ")":
                block = None
                continue
            verb, args = block, words
        else:
            verb, args = words[0], words[1:]
            if args == ["("]:
                block = verb if isinstance(verb, str) else ""
                continue
        if verb == "module" and out["module"] is None and len(args) == 1 and isinstance(args[0], str):
            out["module"] = args[0]
        elif (verb == "go" and block is None and out["go"] is None and len(args) == 1 and isinstance(args[0], str)
              and _GO_VERSION.fullmatch(args[0])):
            out["go"] = args[0]                                     # (a `go (` block is not read: Go refuses it or leaves it)
        elif verb == "require":
            version = None
            if len(args) == 2 and all(isinstance(a, str) for a in args) and len(requires) + len(unversioned) < MAX_REQUIRES:
                version = canonical(args[1])
                if not version and len(args[1]) > MAX_VERSION and args[1].startswith("v"):
                    unversioned.append((args[0], _indirect(comment)))
                    continue
            if version:
                requires.append((args[0], version, _indirect(comment)))
            else:
                out["dropped"] += 1
        elif verb == "replace":
            found = _replace(args, canonical) if len(replaces) < MAX_REPLACES else None
            if found:
                replaces.append(found)
            else:
                out["dropped"] += 1
        elif verb == "use":
            if len(args) == 1 and isinstance(args[0], str) and args[0] and len(out["use"]) < MAX_USES:
                out["use"].append(args[0])
            else:
                out["dropped"] += 1
    return out
