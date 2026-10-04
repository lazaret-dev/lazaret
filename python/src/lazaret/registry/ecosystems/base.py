"""What the registry modules share (0.1.9, wave 2): the errors, `Resolution`, the checked fetch seam and the
`Ecosystem` class that PyPI, npm, Go and crates.io each fill in.

Design: `specs/lazaret-registry-module-interface-2026-10-03.md`. This file is written ahead of `repo.py`'s part of X-2
(which is the 0.1.8 agent's): until `repo.py` re-exports `SpecError`, `FetchError`, `DigestError` and `Resolution`
from here, the classes below are separate classes from `repo.py`'s, with the same names and the same meaning, and
nothing in `repo.py` raises or catches these. `tests/registry/test_ecosystems_base.py` holds the copies to `repo.py`'s
constants and to `repo.Resolution`'s shape, so a drift shows up as a failing test and not as a surprise in X-2.

The rules every module keeps (the conformance tests, `tests/registry/ecosystem_contract.py`, check them for each):
https and the module's own hosts only, redirects included; names and versions validated before a URL is built and
never echoed raw in an error; everything bounded; a published digest checked before anything is scanned; nothing
executed; failures are `SpecError`, `FetchError`, `DigestError` or `ValueError`.

Standard library, and `scanner.core` for the bounded JSON reader. No import of `repo.py`."""

import collections
import http.client
import posixpath
import re
import threading
import time
import urllib.parse

from lazaret.scanner import core as lazaret

__all__ = ["SpecError", "FetchError", "DigestError", "Resolution", "RunTargets", "Declared", "Ecosystem", "Fetch", "DownloadBudget",
           "MAX_DOCUMENT_BYTES", "MAX_ARTIFACT_BYTES", "MAX_REDIRECTS", "METADATA_TIMEOUT", "DOWNLOAD_TIMEOUT",
           "VERSION_RE", "show", "ascii_name", "HOSTILE_NAMES", "HOSTILE_VERSIONS", "finish_member_path", "top_directory_stripped",
           "root_stripped"]

# The numbers `repo.py` has today (a test holds them equal).
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024        # repo.MAX_FEED_BYTES: a metadata document
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024      # repo.MAX_DOWNLOAD_BYTES: one archive
MAX_REDIRECTS = 3
METADATA_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 60
VERSION_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")          # repo.NAME_RE, which is what it calls versions
MAX_URL_LENGTH = 2048
MAX_LINE_BYTES = 1024 * 1024                                  # one JSON line of a line-delimited document


# ---------------------------------------------------------------- errors
class SpecError(ValueError):
    """Invalid ecosystem, package name or version."""


class FetchError(ValueError):
    """A fetch was refused (bad scheme or host) or exceeded a size budget. `status` is the HTTP status when the
    server answered with an error."""
    status = None


class DigestError(ValueError):
    """A downloaded artifact failed its registry-published integrity check. Fail closed: the scan stops and nothing
    is persisted for that package."""


def show(value, limit=120):
    """Text from outside, safe to put in a message: its `repr`, cut short. Control characters, bidi marks and the
    like come out as escapes, so a hostile name or URL cannot paint the terminal or the report."""
    text = value if isinstance(value, str) else repr(value)
    cut = text[:limit]
    shown = repr(cut)
    while len(shown) > limit + 2 and cut:                  # (an escape is longer than the character it stands for: \udcff, \U0010ffff)
        cut = cut[:len(cut) * (limit + 2) // len(shown)]                  # (always shorter: len(shown) > limit + 2)
        shown = repr(cut)
    return shown + ("…" if len(text) > len(cut) else "")


def ascii_name(value, what, allowed, limit, eco=""):
    """`value` if it is text of 1 to `limit` characters, all in `allowed` (a compiled pattern for one character
    class, e.g. `re.compile(r"[A-Za-z0-9_-]")`); SpecError otherwise, naming `what` and never the raw value."""
    prefix = f"{eco}: " if eco else ""
    if not isinstance(value, str) or not value:
        raise SpecError(f"{prefix}empty {what}")
    if len(value) > limit:
        raise SpecError(f"{prefix}{what} longer than {limit} characters")
    if not all(allowed.fullmatch(c) for c in value):
        raise SpecError(f"{prefix}invalid {what} {show(value)}")
    return value


# Names and versions every module must refuse (the contract's table; a module's own good names are not in it).
HOSTILE_NAMES = (
    "", " ", "\t", "\n", "a b", "a\tb", "a\nb", "a\rb", "..", ".", "../x", "x/..", "x/../y", "/", "/x", "x/", "//",
    "x//y", "\\", "x\\y", "..\\x", "a\x00b", "\x00", "a\x1bb", "\x1b[31m", "a\x7fb", "a\x85b", "a b",
    "a‮b", "‮", "a​b", "a⁦b", "﻿", "a%2fb", "%2e%2e", "%2E%2E%2F", "a%00b", "a%5cb",
    "a?b", "a#b", "a:b", "a;b", "a@@b", "a b c", "a∕b", "a․b", "．．", "／", "⁄",
    "a\ud800b", "x" * 5000, "x/" * 400, "a" * 300 + "/" + "b" * 300,
    "\x00" * 200, "\udcff" * 200, "a" + "\u202e" * 200, "\U0010ffff" * 200,       # (each is several characters in a message that quotes it)
)

# Versions every module must refuse. No `+` and no `v` prefix here: Go and semver versions may have them.
HOSTILE_VERSIONS = (
    "", " ", "\t", "\n", "..", ".", "1/2", "1\\2", "1 2", "1\n2", "1\x002", "1\x1b[0m", "1\x7f", "1\x852",
    "1\u202e2", "1\u200b2", "\ufeff1\ufeff", "1%2f2", "%2e%2e", "1?x", "1#x", "1;x", "1@2", "1:2", "1/../2", "../1",
    "1" * 101, "1\ud8002", "1\u22152", "\uff11\uff0e\uff12", "1\u20442", "1,2", "1\"2", "1'2", "1<2", "1>2", "1|2",
    "1*2", "1\\", "1$2", "1`2", "1(2)", "1{2}", "1[2]", "1&2", "1=2", "1!2", "1~2", "1^2",
    "\x00" * 200, "\udcff" * 200, "1" + "\u202e" * 200, "\U0010ffff" * 200,
)


# ---------------------------------------------------------------- archive member paths (the rules modules share)
_DRIVE_ROOT_RE = re.compile(r"^(?:[A-Za-z]:)?/+")                  # repo._DRIVE_ROOT_RE


def finish_member_path(rest):
    """The end every extractor rule shares: drive roots and leading slashes come off (as often as they repeat), a `..`
    element is a problem, the rest is normalized. -> (rel, None); (None, problem); (None, None) for "the package root
    itself", which is not extracted."""
    while True:
        stripped = _DRIVE_ROOT_RE.sub("", rest)
        if stripped == rest:
            break
        rest = stripped
    if ".." in rest.split("/"):
        return None, "path contains '..'"
    norm = posixpath.normpath(rest) if rest else ""
    if norm in ("", "."):
        return None, None
    return norm, None


def top_directory_stripped(name):
    """sdist rule (`repo.canonical_member_path` for anything but npm and wheels): backslashes are separators, `.` and
    empty elements are dropped, then the top directory comes off (a lone top-level file stays)."""
    parts = [x for x in str(name).replace("\\", "/").split("/") if x not in ("", ".")]
    return finish_member_path("/".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else ""))


def root_stripped(name, root):
    """An archive whose every member sits under one known directory `root` (Go's `<module>@<version>/`, a crate's
    `<name>-<version>/`): a member outside it is a problem, as it is for the tool that unpacks the archive."""
    path = str(name).replace("\\", "/")
    if not root or not path.startswith(root):
        return None, "member outside the archive's root directory"
    return finish_member_path(path[len(root):])


# ---------------------------------------------------------------- what a module returns
class Resolution(tuple):
    """(version, url, container_format, artifact_kind, meta_entry) — the primary artifact, unpackable as before —
    plus `.artifacts`: every artifact to scan, as dicts {url, container, artifact, entry, filename}, and
    `.skipped`: files of the release that are not scanned, as dicts {filename, packagetype, installable, size,
    reason}; `installable` means the package manager may install the file anyway (scan_package counts it as not
    scanned). The same shape as `repo.Resolution`."""

    def __new__(cls, version, artifacts, skipped=(), info=None):
        first = artifacts[0]
        self = super().__new__(cls, (version, first["url"], first["container"], first["artifact"], first["entry"]))
        self.artifacts = list(artifacts)
        self.skipped = list(skipped)
        self.info = info if isinstance(info, dict) else {}
        return self


class RunTargets(collections.namedtuple("RunTargets", "entries install_scripts startup")):
    """The three sets of member paths `_ArtifactScan` keeps today: what runs when the package is installed, built or
    loaded. `entries`: the package's entry points; `install_scripts`: what a build or install runs; `startup`: what
    runs when the interpreter or the runtime starts."""
    __slots__ = ()

    def __new__(cls, entries=(), install_scripts=(), startup=()):
        return super().__new__(cls, frozenset(entries), frozenset(install_scripts), frozenset(startup))


class Declared(collections.namedtuple("Declared", "name dependencies specs aliases")):
    """What a package says about itself: its own name and the names of the packages it depends on, as the
    ecosystem spells them (the look-alike and new-dependency checks read this).

    `specs` keeps each dependency's spec as written next to its name (`{name: text or None}`; npm's `^1.2` or
    `npm:other@1`, a crate's version requirement, a Go module's version), because what a spec says can change what
    the name means (an `npm:` alias names another package) and the unused-dependency check reads it. `aliases` is
    `{name: the name the code uses}` for a dependency the manifest renames (a crate's `package = "x"`): the check
    looks for the name the code uses, the registry for the name it is known by. Both hold only names in
    `dependencies`; a module that gives anything else has a bug, and it is a ValueError."""
    __slots__ = ()

    def __new__(cls, name=None, dependencies=(), specs=None, aliases=None):
        dependencies = tuple(dependencies)
        specs, aliases = dict(specs or {}), dict(aliases or {})
        known = set(dependencies)
        for table, kind in ((specs, "spec"), (aliases, "alias")):
            for key, value in table.items():
                if key not in known:
                    raise ValueError(f"a {kind} for {show(key)}, which is not a dependency")
                if not (value is None and kind == "spec") and not isinstance(value, str):
                    raise ValueError(f"the {kind} of {show(key)} is not text")
        return super().__new__(cls, name, dependencies, specs, aliases)


# ---------------------------------------------------------------- the fetch seam
class DownloadBudget:
    """The bytes a release may still download, shared by the threads that download its artifacts (P-9). Taking
    some is one step under a lock, so two threads cannot both take the last share: `reserve(n)` takes `n` bytes if
    that many are left and says whether it did; `give_back(n)` returns what a download did not use. `Fetch.bytes`
    reserves its `max_bytes` (the declared size of the artifact, or the limit) before it asks for anything, and gives
    back the difference once it has the body, or all of it when the request failed."""

    def __init__(self, total):
        if type(total) is not int or total < 0:
            raise ValueError("a download budget is a number of bytes, not less than 0")
        self.total = total
        self._left = total
        self._lock = threading.Lock()

    @property
    def left(self):
        with self._lock:
            return self._left

    def reserve(self, n):
        if type(n) is not int or n < 0:
            raise ValueError("a reservation is a number of bytes, not less than 0")
        with self._lock:
            if n > self._left:
                return False
            self._left -= n
            return True

    def give_back(self, n):
        if type(n) is not int or n < 0:
            raise ValueError("what is given back is a number of bytes, not less than 0")
        with self._lock:
            if self._left + n > self.total:
                raise ValueError("more was given back than was taken")
            self._left += n


class Fetch:
    """The only way a module reaches the network. It is bound to one ecosystem's `hosts`: https, one of those hosts,
    no credentials in the URL, a bounded length, or `FetchError` before any request; the transport's redirects go
    through the same check; each host's `rate` is kept (the interval between requests to it) from any number of
    threads. The bytes come from `transport(url, max_bytes=…, accept=…, timeout=…, check_redirect=…)`, which
    `repo.py` supplies in X-2 (its `_fetch`) and tests supply from recorded responses; it returns the body as bytes
    and raises `FetchError` for a failed or over-budget request.

    A document is decoded here: UTF-8 text, JSON with the bounded reader, JSON lines with a bound per line."""

    def __init__(self, eco, transport, *, clock=time.monotonic, sleep=time.sleep):
        self.eco = eco
        self.hosts = frozenset(h.lower() for h in eco.hosts)
        self.rate = {h.lower(): float(s) for h, s in eco.rate.items()}
        self._transport = transport
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._next = {}                                      # host -> the earliest time for its next request
        self.requests = []                                   # every URL asked for, in order (for tests and reports)

    # ---- the rules
    def check_url(self, url):
        """`url` if it may be fetched; FetchError otherwise. Never echoes the raw URL."""
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
            raise FetchError("registry URL is empty, not text, or too long")
        if any(not 0x21 <= ord(c) <= 0x7e for c in url):                    # (printable ASCII, no space)
            raise FetchError(f"registry URL has characters that do not belong in one: {show(url)}")
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            raise FetchError(f"unparseable registry URL {show(url)}") from None
        if parts.scheme != "https":
            raise FetchError(f"non-https registry URL blocked ({show(parts.scheme or 'no scheme')}): {show(url)}")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise FetchError(f"registry URL with credentials blocked: {show(url)}")
        host = (parts.hostname or "").lower()
        netloc = host if port in (None, 443) else f"{host}:{port}"
        if not host or netloc not in self.hosts:
            raise FetchError(f"registry host not allowlisted: {show(parts.netloc)}")
        return url

    def _wait_turn(self, url):
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        interval = self.rate.get(host)
        if not interval:
            return
        with self._lock:
            now = self._clock()
            start = max(now, self._next.get(host, 0.0))
            self._next[host] = start + interval
        if start > now:
            self._sleep(start - now)

    def _get(self, url, max_bytes, accept, timeout, budget=None):
        self.check_url(url)
        if budget is not None and not budget.reserve(max_bytes):           # (taken before any request, in one step)
            raise FetchError(f"the release's download budget is spent: {show(url)}")
        used = 0
        try:
            self._wait_turn(url)
            self.requests.append(url)
            try:
                body = self._transport(url, max_bytes=max_bytes, accept=accept, timeout=timeout,
                                       check_redirect=self.check_url)
            except FetchError:
                raise
            except (OSError, ValueError, http.client.HTTPException) as exc:    # (a transport that did not say it in our words)
                raise FetchError(f"fetch failed ({type(exc).__name__}): {show(url)}") from None
            if not isinstance(body, (bytes, bytearray)):
                raise FetchError(f"the transport gave no bytes for {show(url)}")
            used = min(len(body), max_bytes)
            if len(body) > max_bytes:
                raise FetchError(f"response exceeds {max_bytes // (1024 * 1024) or 1}MB budget: {show(url)}")
            return bytes(body)
        finally:
            if budget is not None:
                budget.give_back(max_bytes - used)

    # ---- what a module asks for
    def bytes(self, url, max_bytes=MAX_ARTIFACT_BYTES, accept=None, budget=None):
        """The body at `url`, at most `max_bytes`. With a `DownloadBudget`, `max_bytes` is reserved from it first (a
        spent budget is a `FetchError` and no request) and what the body did not use is given back."""
        return self._get(url, max_bytes, accept, DOWNLOAD_TIMEOUT, budget)

    def text(self, url, max_bytes=MAX_DOCUMENT_BYTES, accept=None):
        raw = self._get(url, max_bytes, accept, METADATA_TIMEOUT)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise FetchError(f"registry response is not UTF-8 text: {show(url)}") from None

    def json(self, url, max_bytes=MAX_DOCUMENT_BYTES, accept=None):
        raw = self._get(url, max_bytes, accept, METADATA_TIMEOUT)
        return self._loads(raw, url)

    def json_lines(self, url, max_bytes=MAX_DOCUMENT_BYTES, accept=None, select=None):
        """A line-delimited JSON document (crates.io's index) -> a list with one parsed value per non-empty line.
        A line that is not JSON, or is over `MAX_LINE_BYTES`, fails the whole document: a partial index is a wrong
        answer. `select(value)` turns each parsed line into what the caller keeps (None drops the line), so a document
        of many large lines costs the memory of what is kept and not of what was read."""
        raw = self._get(url, max_bytes, accept, METADATA_TIMEOUT)
        out, pos, end = [], 0, len(raw)
        while pos < end:
            stop = raw.find(b"\n", pos)
            if stop < 0:
                stop = end
            line, pos = raw[pos:stop], stop + 1
            if not line.strip():
                continue
            if len(line) > MAX_LINE_BYTES:
                raise FetchError(f"a line of the registry response is over {MAX_LINE_BYTES // 1024}KB: {show(url)}")
            value = self._loads(line, url)
            if select is not None:
                value = select(value)
                if value is None:
                    continue
            out.append(value)
        return out

    @staticmethod
    def _loads(raw, url):
        try:
            return lazaret.json_loads_bounded(raw)
        except lazaret.JsonTooDeep:
            raise FetchError(f"JSON registry response is too deeply nested to parse: {show(url)}") from None
        except (UnicodeDecodeError, ValueError):
            raise FetchError(f"invalid JSON registry response: {show(url)}") from None


# ---------------------------------------------------------------- the module
class Ecosystem:
    """What one registry's module provides. The attributes and methods are the interface in the design document;
    a module overrides what differs. Everything here that takes a name or a version is a pure function: no network,
    no files, and a bad value is a `SpecError` that does not echo the raw text."""

    id = ""                          # "pypi" | "npm" | "go" | "crates": the string in specs, store rows and reports
    title = ""                       # for messages and reports
    hosts = frozenset()              # lowercase host[:port]; https only
    artifact_kinds = ()              # what `Resolution` calls `artifact`
    rate = {}                        # host -> minimum seconds between requests (crates.io: 1.0)
    manifest_names = frozenset()     # members kept as text for `declared` and `run_targets`

    # ---- names and versions
    def check_name(self, name):
        raise NotImplementedError

    def check_version(self, version):
        """`version` stripped, or None for "latest"; SpecError for anything that is not a version."""
        if version is None:
            return None
        if not isinstance(version, str) or not version.strip():
            raise SpecError(f"{self.id}: invalid version {show(version)}")
        version = version.strip()
        if version in (".", "..") or not VERSION_RE.fullmatch(version):
            raise SpecError(f"{self.id}: invalid version {show(version)}")
        return version

    def identity(self, name):
        """The key for equality: the store, the watchlist and the look-alike checks compare these."""
        return self.check_name(name)

    def parse_spec(self, rest):
        """'name' or 'name@version' (what follows `id:` in a spec) -> (name, version or None), both checked."""
        if not isinstance(rest, str):
            raise SpecError(f"{self.id}: a spec is text")
        text = rest.strip()
        at = text.rfind("@")
        name, version = (text, None) if at <= 0 else (text[:at], text[at + 1:])        # ('@scope/x' has no version)
        return self.check_name(name), self.check_version(version)

    def segment(self, value):
        """A name or a version as one URL path segment."""
        return urllib.parse.quote(str(value), safe="")

    # ---- the network, only through `fetch`
    def resolve(self, name, version, fetch):
        raise NotImplementedError

    def verify(self, data, entry, name, version):
        """-> (algorithm, hex digest) when the registry published a digest and `data` matches it; None when it
        published none; `DigestError` when it did and `data` does not match."""
        return None

    # ---- archives
    def container(self, filename):
        """"zip" | "tgz" | …, or None for a file the package manager does not install."""
        return None

    def member_path(self, kind, name, root=None):
        """Where an extractor puts an archive member, relative to the package root -> (rel or None, problem or
        None). None for both: the member is the root itself and is not extracted."""
        raise NotImplementedError

    def archive_root(self, resolved, artifact):
        """The directory, with its trailing slash, that every member of `artifact` (one of `resolved.artifacts`) sits
        under, when the release says what it is (Go: `<module>@<version>/`; a crate: `<name>-<version>/`); None when
        the archive has no single known root. `repo.py` passes it on as `iter_archive(..., root=...)`, and a member
        outside it is an anomaly, as it is for the package manager's own extractor."""
        return None

    def links_extracted(self, kind):
        """Whether the package manager's extractor creates link members (npm's drops them; the others do not)."""
        return True

    # ---- what is read in an archive, and what runs
    def run_targets(self, kind, manifests, members):
        return RunTargets()

    def declared(self, kind, manifests, members):
        return Declared()

    # ---- optional: a module that does not have them says so by returning None
    def dependencies(self, resolved, fetch):
        return None

    def discover(self, cursor, limit, fetch):
        return None

    def popular_names(self):
        return None
