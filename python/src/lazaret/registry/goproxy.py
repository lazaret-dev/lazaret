"""The Go module proxy protocol and Go's settings for it: what `lazaret guard go` needs to relay a proxy and judge a request.

    parse_goproxy(text)        GOPROXY -> [Proxy], as `cmd/go` reads it (comma and bar, `direct`, `off`)
    glob_matches(globs, path)  GOPRIVATE / GONOPROXY: `module.MatchPrefixPatterns`
    parse_request(path)        a request path -> Request(kind, module, version), or None for anything the protocol does not name
    upstream_path(request)     the path of the same request at another proxy (names and versions escaped again from the checked text)
    newest_first(versions)     module versions, the highest first

The protocol is `go help goproxy`: GET $base/<escaped module>/@v/list, /@latest, /@v/<escaped version>.info, .mod and .zip, and
the checksum database's /sumdb/<name>/… when a proxy mirrors it. Nothing is fetched here. Names and versions are checked before a
path is made from them, so a request path cannot say anything but what a module proxy is asked.

Standard library, `ecosystems.golang` and `scanner.sca` (the version order)."""

import collections
import re

from lazaret.registry.ecosystems import golang
from lazaret.scanner import sca

__all__ = ["Proxy", "Request", "parse_goproxy", "glob_matches", "parse_request", "upstream_path", "newest_first",
           "MAX_QUERY"]

#: A `.info` request for a branch, a tag or a commit names it in a path segment this long at most
MAX_QUERY = 200
_QUERY_RE = re.compile(r"[A-Za-z0-9._+~-]+")
#: What the go command asks a proxy of the checksum database it mirrors (golang.org/x/mod/sumdb's client): whether it does, the
#: latest signed tree, a module version's record, and the tiles of the tree
_SUMDB_RE = re.compile(r"sumdb/(?P<name>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}))/(?:supported|latest|lookup/(?P<lookup>[^?#%]{1,400})|"
                       r"tile/[0-9]{1,2}/(?:[0-9]{1,2}|data)/(?:x[0-9]{3}/){0,8}[0-9]{3}(?:\.p/[0-9]{1,3})?)")

Proxy = collections.namedtuple("Proxy", "url fall_back")
Request = collections.namedtuple("Request", "kind module version rest")


def parse_goproxy(text):
    """GOPROXY -> [Proxy(url, fall_back)]. The list is cut where `cmd/go` cuts it: at the first `off` (every request then
    fails) or `direct` (the version control systems themselves), whose url is that word. fall_back says what happens when the
    proxy answers with an error other than 404 and 410 (those always go on to the next one): a bar after it (`a|b`) goes on, a comma
    does not."""
    out = []
    rest = text if isinstance(text, str) else ""
    while rest:
        cut = next((i for i, ch in enumerate(rest) if ch in ",|"), None)
        if cut is None:
            url, fall_back, rest = rest, False, ""
        else:
            url, fall_back, rest = rest[:cut], rest[cut] == "|", rest[cut + 1:]
        url = url.strip()
        if not url:
            continue
        if url in ("off", "direct"):
            out.append(Proxy(url, False))
            break
        out.append(Proxy(url, fall_back))
    return out


def _class_char(glob, i):
    """The character of a `[...]` class at glob[i] (a backslash makes the next one plain) and where the next starts; None for
    `-` and `]`, which a class does not take plain, and for a backslash at the end."""
    ch = glob[i]
    if ch in "-]":
        return None
    if ch == "\\":
        return (glob[i + 1], i + 2) if i + 1 < len(glob) else None
    return ch, i + 1


def _glob_regex(glob):
    """`path.Match`'s pattern as a regular expression: `*` and `?` stop at a slash, `[a-z]` and `[^a-z]` are classes, a backslash
    makes the next character plain. None for a pattern `path.Match` calls malformed (it matches nothing there either)."""
    out, i = [], 0
    while i < len(glob):
        ch = glob[i]
        i += 1
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "\\":
            if i >= len(glob):
                return None
            out.append(re.escape(glob[i]))
            i += 1
        elif ch == "[":
            negate = i < len(glob) and glob[i] == "^"
            i += 1 if negate else 0
            items = []
            while i < len(glob) and glob[i] != "]":
                lo = _class_char(glob, i)
                if lo is None:
                    return None
                i = lo[1]
                if i < len(glob) and glob[i] == "-":
                    hi = _class_char(glob, i + 1) if i + 1 < len(glob) else None
                    if hi is None or lo[0] > hi[0]:
                        return None
                    items.append(re.escape(lo[0]) + "-" + re.escape(hi[0]))
                    i = hi[1]
                else:
                    items.append(re.escape(lo[0]))
            if i >= len(glob) or not items:
                return None
            i += 1
            out.append("[" + ("^" if negate else "") + "".join(items) + "]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def glob_matches(globs, path):
    """Does a comma-separated list of module path patterns (GOPRIVATE, GONOPROXY) name `path`? Each pattern is matched against
    the first as many path elements of `path` as it has (`rsc.io/private` names rsc.io/private/quux), by the rules of
    `module.MatchPrefixPatterns`."""
    for glob in (globs if isinstance(globs, str) else "").split(","):
        if not glob:
            continue
        regex = _glob_regex(glob)
        if regex is not None and re.fullmatch(regex, "/".join(path.split("/")[:glob.count("/") + 1])):
            return True
    return False


def parse_request(path):
    """The module proxy request a URL path stands for -> Request(kind, module, version, rest), or None for any other.
    kind: "list", "latest", "info", "mod", "zip" (version is the version, or for "info" the query: a version, a branch, a
    commit), or "sumdb" (rest is the path below the proxy's root). The module and the version are the checked, unescaped
    names."""
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path or "\x00" in path:
        return None
    if path.startswith("/sumdb/"):
        # (only what go asks of a mirror of the checksum database, so that a request cannot say anything else to the proxy,
        # with the user's credentials for it: the Go/Rust review's GO-3)
        rest = path[1:]
        m = _SUMDB_RE.fullmatch(rest)
        if m is None or ".." in rest.split("/"):
            return None
        if m.group("lookup") is not None:
            escaped, at, version = m.group("lookup").rpartition("@")
            module, version = golang.unescape(escaped), golang.unescape(version)
            if not at or module is None or version is None or golang.check_module_path(module) is not None \
                    or not golang.VERSION_RE.fullmatch(version):
                return None
        return Request("sumdb", None, None, rest)
    escaped, _, tail = path[1:].partition("/@")
    module = golang.unescape(escaped)
    if module is None or len(module) > golang.MAX_NAME or golang.check_module_path(module) is not None:
        return None
    if tail == "latest":
        return Request("latest", module, None, None)
    if tail == "v/list":
        return Request("list", module, None, None)
    if not tail.startswith("v/"):
        return None
    name = tail[2:]
    for ext in (".info", ".mod", ".zip"):
        if not name.endswith(ext):
            continue
        version = golang.unescape(name[:-len(ext)])
        if version is None:
            return None
        if ext == ".info":
            ok = len(version) <= MAX_QUERY and bool(_QUERY_RE.fullmatch(version))
        else:
            ok = len(version) <= golang.MAX_VERSION and bool(golang.VERSION_RE.fullmatch(version))
        return Request(ext[1:], module, version, None) if ok else None
    return None


def upstream_path(request):
    """The request's path (no leading slash), made again from its checked names: what another proxy is asked."""
    if request.kind == "sumdb":
        return request.rest
    base = golang.escape(request.module) + "/@"
    if request.kind == "latest":
        return base + "latest"
    if request.kind == "list":
        return base + "v/list"
    return base + "v/" + golang.escape(request.version) + "." + request.kind


def newest_first(versions):
    """The versions, the highest (SemVer) first; those that are not versions at all first of all."""
    keys = {v: sca.version_key(v, "go") for v in versions}
    try:
        return sorted(versions, key=lambda v: (keys[v] is None, keys[v]), reverse=True)
    except TypeError:
        return list(versions)
