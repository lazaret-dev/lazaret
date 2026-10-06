"""lazaret guard — check what a package manager is about to install, before it runs.

    lazaret guard npm install express
    lazaret guard pnpm add react
    lazaret guard yarn add lodash         (yarn 1 and yarn 2+)
    lazaret guard bun add zod
    lazaret guard pip install requests
    lazaret guard uv add httpx            (also: uv sync, uv lock, uv run, uv pip install, uv pip sync)
    lazaret guard uvx ruff check .        (also: uv tool run, uv tool install)
    lazaret guard go get example.com/m    (also: go install, build, run, test, vet, list, mod download, mod tidy)
    lazaret guard cargo add serde         (also: cargo update, install, fetch, build, check, test, run, ...)
    lazaret-guard …                       (the same command under its own name)

npm, pnpm, yarn, Bun and uv's project commands: the tool resolves first,
installing nothing (npm --package-lock-only, pnpm --lockfile-only, yarn 2+
--mode=update-lockfile, bun --lockfile-only, uv add --no-sync, uv lock; yarn
1, which has no such mode, resolves in a temporary copy of the project with
scripts off). Every package the new lockfile installs on this machine that is
not installed yet is then fetched from where the tool will fetch it, checked
against the lockfile's digest (the bytes the tool will accept; yarn 2+ pins
its own zip's, so the registry's), and scanned in memory with the registry
auditor's tests (lazaret.registry.repo). Releases younger than --min-age are
held back where the tool can do it without writing the cutoff into the
lockfile (npm's `before`, pnpm's minimum-release-age, yarn's
npmMinimalAgeGate, bun's --minimum-release-age), and blocked where it can't.
A SUSPICIOUS package, one that could not be checked, or one younger than
--min-age blocks the install: the files the resolution changed (package.json,
the lockfile, pyproject.toml) are put back and nothing is installed.
Otherwise the command runs as given, and what it installed is compared with
what was checked.

pip, uv pip and uvx (uv tool run, uv tool install; what uv run installs
beside its project): the tool runs against an index on 127.0.0.1 that relays
the indexes the tool is set to use. Releases younger than --min-age are left
out of it, and every file the tool downloads is scanned before it is handed
over: a SUSPICIOUS one is refused, and pip and uv install nothing unless
every download succeeded (an sdist is scanned before pip or uv can build it,
which runs its code). The tool resolves first (a dry run, a compile) and the
files of its plan are scanned before anything is installed.

go: the go command runs against a Go module proxy of the guard's on 127.0.0.1 (GOPROXY), which relays the
proxies GOPROXY lists and scans each module zip before the command gets it: a SUSPICIOUS one is refused (go
then fails, and go.mod, go.sum and go.work.sum are put back), and so is one younger than --min-age (its
release time is the proxy's: the commit or tag time its author recorded, so a module author can backdate it).
go checks what it is handed against go.sum and the checksum database as ever, so what it accepts is what was
scanned. The proxy answers only the command's secret path and its own Host (LocalGate). Modules go takes without
asking the proxy (those already in its module cache, those GONOPROXY names, fetched from their repositories) are
listed with `go mod download -json` and scanned where go keeps them: before a command that builds a program, after
one that resolves; anything else that reaches the module cache unchecked fails the run. What the scan reads in a
module is what it reads in any archive (JavaScript and Python files, install hooks, binaries, the structure of the
zip); its Go rules read `.go` files once the engine routes them (0.1.9, S-4).

cargo: the resolution is made first (cargo add and update are that themselves; for the commands that build, `cargo update
--workspace`; for `cargo install`, a project of its own that needs only the crate, with the features asked for, or with
--locked the Cargo.lock the crate was published with), then Cargo.lock is read. Every crates.io crate in it, those cargo has
unpacked already too, is read from cargo's cache or fetched from where cargo fetches it (cargo's configuration as cargo merges
it: source replacement, [registries], include, --config), checked against the lockfile's checksum and scanned in memory as a
`.crate`; a SUSPICIOUS one, one that could not be checked or one younger than --min-age (the index's `pubtime`, else
crates.io's API) blocks the command and Cargo.toml and Cargo.lock are put back. Only then does cargo fetch and build, with
--locked (`cargo install NAME@=VERSION`), which is when build scripts and procedural macros run. Under --plan, the compiler
and the wrappers the project's configuration names, which cargo runs to learn the compiler's version while it
resolves, are set aside (CARGO_PLAN_CONFIG): a dry run runs none of the project's programs. Cargo.lock lists the crates
of every platform, so the guard checks those cargo would not build here too (a verdict is kept by checksum: once). A crate
from git, a vendor folder or a local registry, from a registry with a git index, or from one that wants credentials, is
INCOMPLETE, not checked. Not wrapped: `cargo install` of a git repository or a folder, --registry, --index, and the
credentials of registries. What the scan reads in a crate is what it reads in any archive; its Rust rules (build.rs,
procedural macros) read `.rs` files once the engine routes them (0.1.9, S-4).

The resolutions made outside the project (cargo install, yarn 1, npm install -g, go install pkg@version, --plan) are made
in a folder of the user's own (private_scratch), and the package manager is found in PATH's absolute folders only
(scanner/programs.py).

A private registry or index is used with the credentials the tool's own
settings give for it (lazaret.registry.pmsettings), sent to that host only.
Nothing is sent anywhere but the registries the packages come from. Verdicts
are kept in a local cache keyed by the artifact's digest (--no-cache to skip),
so a package is fetched and scanned once.
"""
import argparse
import base64
import collections
import concurrent.futures
import datetime
import email.utils
import fnmatch
import glob
import hashlib
import html
import html.parser
import http.client
import http.server
import ipaddress
import itertools
import json
import os
import platform
import re
import secrets
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from lazaret.scanner import core as lazaret
from lazaret.scanner import gomod, programs, sca, timings
from lazaret.registry import cargosrc, goproxy, keepalive as keepalive_, pmsettings, repo, scanpool
from lazaret.registry.ecosystems import crates, golang

#: Releases younger than this are held back or blocked (--min-age).
DEFAULT_MIN_AGE = 2 * 86400
EXIT_OK, EXIT_BLOCKED, EXIT_USAGE, EXIT_RESOLVE = 0, 1, 2, 3
NPM_REGISTRY = pmsettings.NPM_REGISTRY
PYPI_SIMPLE = pmsettings.PYPI_SIMPLE
PYPI_JSON = "https://pypi.org/pypi/"
#: Bytes of one registry document (a PyPI project page, an npm packument)
MAX_DOCUMENT = 64 * 1024 * 1024
#: Artifacts fetched at once
WORKERS = 6
#: Processes that scan at once (--jobs)
DEFAULT_JOBS = max(1, min(4, os.cpu_count() or 1))
#: Seconds a tool may wait on the local index while a file is scanned
TOOL_TIMEOUT = 600
USER_AGENT = "lazaret-guard/1.0"
TOOLS = ("npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "uvx", "go", "cargo")

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)
_UNITS = {"": 86400, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
_PEP503_RE = re.compile(r"[-_.]+")


class GuardError(Exception):
    """A usage or setup problem: the message says what to do (exit 2)."""


class ScanError(ValueError):
    """An artifact the scanner could not get through (the guard fails closed)."""


def parse_duration(text):
    """Seconds in a duration: '2d', '36h', '90m', '1w', '3600s', '0' (a bare
    number is days)."""
    m = _DURATION_RE.match(text or "")
    if m is None:
        raise GuardError(f"--min-age: expected a duration like 2d, 36h or 0, got {text!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def format_age(seconds):
    """'3 hours', '2 days' — how old a release is, roughly."""
    seconds = max(0, int(seconds))
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            return plural(seconds // size, unit)
    return plural(seconds, "second")


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def now():
    """The current time (UTC). Tests replace it."""
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(text):
    """An ISO 8601 time ('2026-09-28T08:33:55.944Z'), aware, or None."""
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)\.(\d+)(.*)$", t)
    if m:                                   # Python 3.10 reads 3 or 6 fraction digits only
        t = f"{m.group(1)}.{(m.group(2) + '000000')[:6]}{m.group(3)}"
    try:
        dt = datetime.datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def parse_http_date(text):
    """An HTTP date (Last-Modified), aware, or None."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        dt = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pep503(name):
    return _PEP503_RE.sub("-", name).lower()


# ---------------- Fetching ----------------
_is_loopback = pmsettings.is_loopback


def fetchable(url):
    """Can the guard fetch this URL at all: https, or http on this machine?"""
    try:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(parts.hostname))
    except ValueError:
        return False


def netloc(url):
    try:
        return urllib.parse.urlsplit(url).netloc.rpartition("@")[2].lower()
    except ValueError:
        return ""


class TooLarge(repo.FetchError):
    """A response over the bytes the guard reads: more than it scans, which is not a failure of the package's (a typed error, not
    a message: a message is text a server can choose)."""


class Fetcher:
    """Fetches from the named hosts only: https, or plain http to a loopback
    host (a registry served on this machine) or to a host the package
    manager's own settings name as a registry (http_hosts; what comes from
    there is checked against a digest). Redirects are held to the same rule;
    every response is read in chunks against a byte budget.

    `auth` (pmsettings.Credentials) holds the credentials the package
    manager's settings give for its registries: a request carries those of
    its own URL only — a redirect gets those of where it leads, if any — and
    none go over plain http to another machine. A URL's own user:password@
    is taken out of it and sent to its host alone; messages show URLs
    without it."""

    def __init__(self, hosts, http_hosts=(), auth=None, keepalive=False, https_redirects=False):
        self.hosts = {h.lower() for h in hosts if h}
        self.http_hosts = {h.lower() for h in http_hosts if h}
        self.https_redirects = https_redirects
        self.auth = auth if auth is not None else pmsettings.Credentials()
        self.lock = threading.Lock()
        self.pool = keepalive_.Pool() if keepalive else None

    def close(self):
        """Close the connections kept for reuse (a fetcher without them has none)."""
        if self.pool is not None:
            self.pool.close()

    def allow(self, url):
        """Let the fetcher reach url's host too."""
        host = netloc(url)
        if host:
            with self.lock:
                self.hosts.add(host)

    def check(self, url, redirect=False):
        """The url, or FetchError. redirect: it is where a response sent the fetcher; with `https_redirects` that may be any
        https host (a module proxy redirects to its storage; what is fetched there is checked against a digest)."""
        try:
            parts = urllib.parse.urlsplit(url)
            host, loc = (parts.hostname or "").lower(), parts.netloc.rpartition("@")[2].lower()
        except ValueError as exc:
            raise repo.FetchError(f"unparseable URL {pmsettings.shown(url)!r}") from exc
        plain_ok = parts.scheme == "http" and (_is_loopback(host) or loc in self.http_hosts or host in self.http_hosts)
        if parts.scheme != "https" and not plain_ok:
            raise repo.FetchError(f"only https is fetched (or http on this machine): {pmsettings.shown(url)}")
        with self.lock:
            known = loc in self.hosts or host in self.hosts
        if not known and not (redirect and self.https_redirects and parts.scheme == "https"):
            raise repo.FetchError(f"host not allowed for this install: {loc!r}")
        return url

    def request(self, url, accept=None):
        """-> (a Request for url, url as shown): the guard's User-Agent, the
        credentials for url (not carried over a redirect)."""
        clean, inline = pmsettings.split_userinfo(url)
        req = urllib.request.Request(clean, headers={"User-Agent": USER_AGENT, **({"Accept": accept} if accept else {})})
        header = pmsettings.basic(*inline) if inline and (clean.startswith("https:") or _is_loopback(
            urllib.parse.urlsplit(clean).hostname)) else self.auth.header(clean)
        if header:
            req.add_unredirected_header("Authorization", header)
        return req, clean

    def _opener(self, url):
        fetcher = self

        class Redirects(urllib.request.HTTPRedirectHandler):
            max_redirections = repo.MAX_REDIRECTS

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                try:
                    fetcher.check(newurl, redirect=True)
                except repo.FetchError as exc:
                    raise urllib.error.URLError(f"redirect blocked: {exc}")
                new = super().redirect_request(req, fp, code, msg, headers, newurl)
                header = fetcher.auth.header(newurl) if new is not None else None
                if header:                                  # (the request's own was not carried over)
                    new.add_unredirected_header("Authorization", header)
                return new

        handlers = [Redirects]
        if _is_loopback(urllib.parse.urlsplit(url).hostname):
            handlers.append(urllib.request.ProxyHandler({}))      # never through a proxy
        return urllib.request.build_opener(*handlers)

    def _http_error(self, code, clean, req):
        hint = ""
        if code in (401, 403):
            if self.auth.withheld(clean):
                hint = " (its credentials are sent over https only)"
            elif not req.has_header("Authorization"):
                hint = " (the package manager's settings give no credentials for this registry)"
        err = repo.FetchError(f"HTTP {code} fetching {clean}{hint}")
        err.status = code
        return err

    def open(self, url, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
        """The open response for url (the caller closes it); FetchError."""
        self.check(url)
        req, clean = self.request(url, accept)
        if self.pool is not None:
            try:
                return self._open_kept(req, clean, timeout)
            except keepalive_.Unsupported:
                pass                                        # a proxy or URL the pool does not carry: urllib, as before
        try:
            with timings.span("network", "request"):
                return self._opener(clean).open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise self._http_error(exc.code, clean, req) from None
        except urllib.error.URLError as exc:
            raise repo.FetchError(f"URL error fetching {clean}: {exc.reason}") from exc
        except OSError as exc:
            raise repo.FetchError(f"network error fetching {clean}: {exc}") from exc

    def _open_kept(self, req, clean, timeout):
        """The same request through the pool's connections. Redirects are followed here, by the rules of
        `_opener`: at most repo.MAX_REDIRECTS, each target checked by `check`, and a hop carries the headers
        but only the credentials of its own URL."""
        url, headers, visited = clean, dict(req.header_items()), {}
        while True:
            via = None if _is_loopback(urllib.parse.urlsplit(url).hostname) else keepalive_.proxy_for(url)
            try:
                with timings.span("network", "request"):
                    resp = self.pool.request(url, headers, timeout, via)
            except (OSError, http.client.HTTPException, UnicodeError) as exc:
                raise repo.FetchError(f"network error fetching {clean}: {exc}") from exc
            code = resp.status
            if 200 <= code < 300:
                return resp
            resp.drain()
            resp.close()
            location = resp.headers.get("Location") if code in (301, 302, 303, 307, 308) else None
            if not location:
                raise self._http_error(code, clean, req)
            target = urllib.parse.urlsplit(location)
            if not target.path and target.netloc:
                target = target._replace(path="/")
            target = urllib.parse.urldefrag(urllib.parse.urljoin(url, urllib.parse.urlunsplit(target)))[0]
            try:
                self.check(target, redirect=True)
            except repo.FetchError as exc:
                raise repo.FetchError(f"URL error fetching {clean}: redirect blocked: {exc}") from exc
            visited[target] = visited.get(target, 0) + 1
            if visited[target] > 4 or len(visited) > repo.MAX_REDIRECTS:
                raise self._http_error(code, clean, req)
            url, headers = target, dict(req.headers)        # (the first request's own credentials stay behind)
            header = self.auth.header(target)
            if header:
                headers["Authorization"] = header

    def fetch(self, url, max_bytes=repo.MAX_DOWNLOAD_BYTES, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
        """-> (body, response headers). TooLarge for a response over `max_bytes`."""
        clean = pmsettings.shown(url)
        too_big = f"response over {max_bytes // (1024 * 1024)}MB: {clean}"
        with self.open(url, accept, timeout) as r:
            try:
                length = r.headers.get("Content-Length")
                if length and length.isdigit() and int(length) > max_bytes:
                    raise TooLarge(too_big)
                buf = bytearray()
                with timings.span("network", "read"):
                    while True:
                        chunk = r.read(64 * 1024)
                        if not chunk:
                            break
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            raise TooLarge(too_big)
                if length and length.isdigit() and len(buf) != int(length):
                    raise repo.FetchError(f"incomplete response ({len(buf)} of {length} bytes): {clean}")
                return bytes(buf), r.headers
            except (OSError, http.client.HTTPException) as exc:
                raise repo.FetchError(f"network error fetching {clean}: {exc}") from exc

    def get(self, url, max_bytes=repo.MAX_DOWNLOAD_BYTES, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
        return self.fetch(url, max_bytes, accept, timeout)[0]

    def fetch_to_file(self, url, path, max_bytes, timeout=repo.DOWNLOAD_TIMEOUT):
        """Write the body of url to `path` (truncated first), as it comes -> (size, its SHA-256 hex). TooLarge past
        `max_bytes`."""
        clean = pmsettings.shown(url)
        too_big = f"response over {max_bytes // (1024 * 1024)}MB: {clean}"
        digest, size = hashlib.sha256(), 0
        with self.open(url, None, timeout) as r, open(path, "wb") as out:
            try:
                length = r.headers.get("Content-Length")
                if length and length.isdigit() and int(length) > max_bytes:
                    raise TooLarge(too_big)
                with timings.span("network", "read"):
                    while True:
                        chunk = r.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise TooLarge(too_big)
                        digest.update(chunk)
                        out.write(chunk)
                if length and length.isdigit() and size != int(length):
                    raise repo.FetchError(f"incomplete response ({size} of {length} bytes): {clean}")
            except (OSError, http.client.HTTPException) as exc:
                raise repo.FetchError(f"network error fetching {clean}: {exc}") from exc
        return size, digest.hexdigest()

    def json(self, url, accept="application/json"):
        return repo._deep_safe_loads(self.get(url, MAX_DOCUMENT, accept, repo.METADATA_TIMEOUT),
                                     f"from {pmsettings.shown(url)}")


# ---------------- Verdicts ----------------
class Check:
    """What the guard found for one artifact (or one package it could not
    check): its verdict, why it is blocked (empty: it is not), notes."""

    def __init__(self, eco, name, version, source=""):
        self.eco, self.name, self.version, self.source = eco, name, version, source
        self.verdict = None                 # OK / WARN / INCOMPLETE / SUSPICIOUS, None: not scanned
        self.reason = ""
        self.indicators = []                # the strongest findings' messages
        self.blocked = []                   # why it is blocked
        self.notes = []                     # what else to say
        self.trusted = False                # --trust let it through
        self.age = None                     # seconds since it was published, when known
        self.digest = None

    def label(self):
        return f"{self.name}@{self.version}" if self.version else self.name

    def to_json(self):
        return {"ecosystem": self.eco, "name": self.name, "version": self.version, "source": self.source,
                "verdict": self.verdict, "reason": self.reason, "indicators": self.indicators,
                "blocked": self.blocked, "notes": self.notes, "trusted": self.trusted,
                "ageSeconds": self.age, "digest": self.digest}


_SEV_RANK = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}


def summarize(result, limit=3):
    """The strongest supply-chain findings of a scan result, as messages."""
    found = [i for i in result.get("issues", []) if str(i.get("rule", "")).startswith("SC-") and i.get("sev") != "INFO"]
    found.sort(key=lambda i: (_SEV_RANK.get(i.get("sev"), 9), i.get("file", ""), i.get("line", 0)))
    return [f"{i['rule']} ({i['sev']}) {i.get('file', '')}: {i.get('msg', '')}"[:400] for i in found[:limit]]


class VerdictCache:
    """Verdicts by artifact (ecosystem, name, version, digest) and engine
    version, with the release's publish time, in a JSON file of the user's
    cache directory."""
    MAX_ENTRIES = 20_000

    def __init__(self, path):
        if path and os.path.exists(path) and not os.path.isfile(path):
            path = None                     # /dev/null, NUL, a folder: no cache, and never written over
        self.path = path
        self.data = {}
        self.lock = threading.Lock()
        self.dirty = False
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and loaded.get("engine") == repo.ENGINE_VERSION \
                        and isinstance(loaded.get("verdicts"), dict):
                    self.data = loaded["verdicts"]
            except (OSError, ValueError, RecursionError):
                self.data = {}

    @staticmethod
    def key(eco, name, version, digest):
        return f"{eco}:{name}@{version}#{digest}"

    def get(self, key):
        with self.lock:
            v = self.data.get(key)
        if not (isinstance(v, dict) and v.get("verdict") in ("OK", "WARN", "INCOMPLETE", "SUSPICIOUS")
                and isinstance(v.get("reason"), str) and isinstance(v.get("indicators"), list)):
            return None
        return v

    def put(self, key, hit, published):
        with self.lock:
            self.data.pop(key, None)                # most recent last: the oldest are dropped first
            self.data[key] = {"verdict": hit["verdict"], "reason": hit["reason"],
                              "indicators": [str(i) for i in hit["indicators"]][:3],
                              "published": iso(published) if published else None}
            self.dirty = True

    def save(self):
        if not self.path or not self.dirty:
            return
        with self.lock:
            items = list(self.data.items())[-self.MAX_ENTRIES:]
        folder = os.path.dirname(self.path) or "."
        try:
            os.makedirs(folder, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".guard-", dir=folder)
        except OSError:
            return                                  # a cache that can't be written is only slower
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"engine": repo.ENGINE_VERSION, "verdicts": dict(items)}, f)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)                      # no half-written file left beside it
            except OSError:
                pass


def default_cache_path():
    explicit = os.environ.get("LAZARET_GUARD_CACHE")
    if explicit:
        return explicit
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "lazaret", "guard-verdicts.json")


def _shared_above(path):
    """Is `path`, or a folder above it, one another user can write to (world-writable, as /tmp is on Linux)?"""
    if os.name == "nt":
        return False                    # (Windows' temporary folder is each user's own)
    here = os.path.abspath(path)
    while True:
        try:
            if os.stat(here).st_mode & stat.S_IWOTH:
                return True
        except OSError:
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def private_scratch(prefix):
    """A new folder (mode 0700) for a package manager to work in on the guard's behalf, where no folder above it is one
    another user can write to: LAZARET_GUARD_SCRATCH when it is set (taken as given), else the user's cache folder
    (XDG_CACHE_HOME or ~/.cache, lazaret/tmp), else the system's temporary folder when that is the user's own (macOS's,
    Windows'). cargo, rustup, yarn, npm and go read settings from every folder above the one they run in (cargo's
    configuration and workspace, rustup's toolchain file, yarn's `yarn-path`, npm's workspace root, go.work), so a file
    another user put in a shared /tmp could make the guard run their program or check nothing (the Go/Rust review's CG-1).
    GuardError when there is no such folder."""
    explicit = os.environ.get("LAZARET_GUARD_SCRATCH")
    if explicit:
        os.makedirs(explicit, mode=0o700, exist_ok=True)
        return tempfile.mkdtemp(prefix=prefix, dir=explicit)
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    for base in (os.path.join(cache, "lazaret", "tmp"), tempfile.gettempdir()):
        try:
            os.makedirs(base, mode=0o700, exist_ok=True)
        except OSError:
            continue
        if _shared_above(base):
            continue
        try:
            return tempfile.mkdtemp(prefix=prefix, dir=base)
        except OSError:
            continue
    raise GuardError("no folder of your own to work in: the cache folder cannot be made and the temporary folder is one other "
                     "users can write to; set LAZARET_GUARD_SCRATCH (or XDG_CACHE_HOME) to a folder only you can write to")


def _scan_one(data, container, kind, timeout, timed=False):
    """Scan one archive (in a worker process, or here) -> the verdict. `timed` (a worker, when the run
    keeps timings) adds the worker's own `timings` report to the answer, for the parent to merge."""
    budget = repo.Budget(deadline=time.monotonic() + timeout, deadline_detail="scan time budget exceeded")
    if not timed:
        with timings.span("scan", "artifact"):
            res = repo._scan_artifact(data, container, kind, False, budget)
        return {"verdict": res["verdict"], "reason": res["verdictReason"], "indicators": summarize(res)}
    here = timings.Timings()
    with timings.capture(here), here.run(), timings.span("scan", "artifact"):
        res = repo._scan_artifact(data, container, kind, False, budget)
    return {"verdict": res["verdict"], "reason": res["verdictReason"], "indicators": summarize(res),
            "timings": here.report()}


class Scanner:
    """Scans artifacts in memory (lazaret.registry.repo._scan_artifact), in worker processes
    (registry/scanpool.py): each with an address-space limit and its share of the cores, given the
    archive as a file, and replaced when it dies. `isolate` None is the old default, workers when
    `jobs` is over 1; True is workers for any `jobs`; False scans in this process, one at a time
    (`--no-isolate`). When workers cannot be started at all, it scans here too and says why (`note`)."""

    def __init__(self, cache, timeout=repo.SCAN_TIMEOUT, jobs=1, isolate=None, memory_mb=scanpool.DEFAULT_MEMORY_MB,
                 note=None):
        self.cache = cache
        self.timeout = timeout
        self.jobs = jobs
        self.isolate = (jobs > 1) if isolate is None else bool(isolate)
        self.memory_mb = memory_mb
        self._note = note
        self._pool = None
        self._no_pool = not self.isolate
        self._lock = threading.Lock()
        self._here = threading.Lock()

    def cached(self, key):
        return self.cache.get(key) if self.cache is not None and key else None

    def remember(self, key, hit, published):
        if self.cache is not None and key:
            self.cache.put(key, hit, published)

    def _get_pool(self):
        with self._lock:
            if self._pool is None and not self._no_pool:
                self._pool = scanpool.WorkerPool(self.jobs, _scan_one, memory_mb=self.memory_mb)
            return self._pool

    def _scan_here(self):
        """From now on, scan in this process (no worker could be started)."""
        with self._lock:
            first = not self._no_pool
            self._no_pool = True
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.close()
        if first and self._note is not None:
            self._note("lazaret guard: no scan worker could be started; scanning in this process")

    def scan(self, data, container, kind):
        """-> {verdict, reason, indicators}; ScanError when the scanner can't
        get through the artifact."""
        pool = self._get_pool()
        if pool is not None:
            kept = timings.current()                 # the run keeps timings: the worker's come back with its answer
            try:
                answer = pool.run(data, container, kind, self.timeout, kept is not None)
            except scanpool.Unavailable:
                self._scan_here()
            except scanpool.Hung:
                raise ScanError("the scan did not finish") from None
            except scanpool.Died as exc:
                raise ScanError(str(exc)) from None
            except Exception as exc:
                raise ScanError(f"the scan failed ({type(exc).__name__})") from None
            else:
                if kept is not None and isinstance(answer, dict):
                    kept.merge(answer.pop("timings", None))
                return answer
        with self._here:
            try:
                return _scan_one(data, container, kind, self.timeout)
            except Exception as exc:
                raise ScanError(f"the scan failed ({type(exc).__name__})") from None

    def close(self):
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.close()


# ---------------- Digests ----------------
_SRI_STRENGTH = ("sha512", "sha384", "sha256", "sha1")


def sri_best(sri):
    """(alg, base64 digest) of the strongest digest of an SRI string
    ('sha512-… sha1-…'), or None."""
    found = {}
    for token in sri.split() if isinstance(sri, str) else []:
        alg, _, digest = token.partition("-")
        if digest and alg.lower() in _SRI_STRENGTH:
            found.setdefault(alg.lower(), digest.split("?")[0])
    for alg in _SRI_STRENGTH:
        if alg in found:
            try:
                raw = base64.b64decode(found[alg], validate=True)
            except (ValueError, TypeError):
                continue
            if len(raw) == hashlib.new(alg).digest_size:
                return alg, base64.b64encode(raw).decode("ascii")
    return None


def sri_matches(data, want):
    alg, b64 = want
    return base64.b64encode(hashlib.new(alg, data).digest()).decode("ascii") == b64


def registry_digest(manifest):
    """(alg, base64) the registry publishes for a version (dist.integrity,
    else dist.shasum), or None."""
    dist = manifest.get("dist") if isinstance(manifest, dict) else None
    if not isinstance(dist, dict):
        return None
    got = sri_best(dist.get("integrity"))
    if got is None and isinstance(dist.get("shasum"), str) and re.fullmatch(r"[0-9a-fA-F]{40}", dist["shasum"]):
        got = ("sha1", base64.b64encode(bytes.fromhex(dist["shasum"])).decode("ascii"))
    return got


# ---------------- Lockfiles ----------------
def _strings(value):
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _str(meta, key):
    v = meta.get(key)
    return v if isinstance(v, str) else ""


def npm_lock_packages(text):
    """[{name, version, resolved, integrity, os, cpu, libc}] of a
    package-lock.json: the packages npm installs (lockfile v2/v3 `packages`,
    or v1's nested `dependencies`); the project, workspace folders, links and
    bundled dependencies (inside their parent's tarball) are left out."""
    try:
        doc = lazaret.json_loads_bounded(text)
    except (ValueError, lazaret.JsonTooDeep):
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if "node_modules/" not in path or not isinstance(meta, dict) or meta.get("link") or meta.get("inBundle"):
                continue
            out.append({"name": _str(meta, "name") or sca._npm_name_from_path(path), "version": _str(meta, "version"),
                        "resolved": _str(meta, "resolved"), "integrity": _str(meta, "integrity"),
                        "os": _strings(meta.get("os")), "cpu": _strings(meta.get("cpu")),
                        "libc": _strings(meta.get("libc"))})
        return out

    def walk(deps, depth):
        if depth > 64 or not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict) or meta.get("bundled"):
                continue
            version = _str(meta, "version")
            if version.startswith("npm:"):              # an alias: npm:real-name@1.0.0
                real, _, version = version[4:].rpartition("@")
                name = real or name
            if not version.startswith(("file:", "link:")):
                out.append({"name": name, "version": version if version[:1].isdigit() else "",
                            "resolved": _str(meta, "resolved"), "integrity": _str(meta, "integrity"),
                            "os": [], "cpu": [], "libc": []})
            walk(meta.get("dependencies"), depth + 1)
    walk(doc.get("dependencies"), 0)
    return out


_FLOW_PAIR_RE = re.compile(r"([A-Za-z]+):\s*('(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"|[^,{}]+)")
_FLOW_ITEM_RE = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"|[^,\[\]\s][^,\[\]]*")


def _yaml_scalar(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s


def pnpm_lock_packages(text):
    """{(name, version): {integrity, tarball, os, cpu, libc}} of the
    `packages:` section of a pnpm-lock.yaml (v5, v6, v9; line-based, no YAML
    dependency). A git or tarball package has version ''; local ones are left
    out (sca's key rules)."""
    out = {}
    section, cur, field = None, None, None
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            section, cur, field = stripped.rstrip(":").strip(), None, None
            continue
        if section != "packages":
            continue
        if indent == 2:
            cur, field = None, None
            key = stripped[:-1] if stripped.endswith(":") else stripped.split(": ", 1)[0]
            nv = sca._pnpm_key(key)
            if nv is not None:
                version = sca._npm_exact(nv[1])[0] if nv[1] else ""
                cur = out.setdefault((nv[0], version or ""), {"integrity": "", "tarball": "", "os": [],
                                                              "cpu": [], "libc": []})
            continue
        if cur is None:
            continue
        if indent == 4:
            field = None
            k, _, v = stripped.partition(":")
            k, v = k.strip(), v.strip()
            if k == "resolution":
                if v.startswith("{"):
                    for pk, pv in _FLOW_PAIR_RE.findall(v.strip("{} ")):
                        if pk in ("integrity", "tarball"):
                            cur[pk] = _yaml_scalar(pv)
                elif not v:
                    field = "resolution"
            elif k in ("os", "cpu", "libc"):
                if v.startswith("["):
                    cur[k] = [_yaml_scalar(i) for i in _FLOW_ITEM_RE.findall(v.strip("[] "))]
                elif not v:
                    field = k
            continue
        if field == "resolution":
            k, _, v = stripped.partition(":")
            if k.strip() in ("integrity", "tarball"):
                cur[k.strip()] = _yaml_scalar(v)
        elif field and stripped.startswith("- "):
            cur[field].append(_yaml_scalar(stripped[2:]))
    return out


def uv_lock_packages(text):
    """[{name, version, source, sdist, wheels}] of a uv.lock: source is
    registry / git / url / path / local (the project, its workspace members,
    directories); sdist and wheels are {url, hash, upload-time, filename}
    dicts."""
    try:
        doc = sca.load_toml(text)
    except ValueError:
        return []
    out = []
    for pkg in doc.get("package", []) if isinstance(doc.get("package"), list) else []:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            continue
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        if any(k in source for k in ("virtual", "editable", "directory")):
            kind = "local"
        else:
            kind = next((k for k in ("registry", "git", "url", "path") if k in source), "registry")

        def files(items):
            got = []
            for f in items if isinstance(items, list) else []:
                if isinstance(f, dict) and isinstance(f.get("url"), str):
                    got.append({"url": f["url"], "hash": _str(f, "hash"), "upload-time": _str(f, "upload-time"),
                                "filename": urllib.parse.unquote(f["url"].split("#")[0].rsplit("/", 1)[-1])})
            return got
        sdist = files([pkg["sdist"]] if isinstance(pkg.get("sdist"), dict) else [])
        out.append({"name": pkg["name"], "version": _str(pkg, "version"), "source": kind,
                    "sdist": sdist[0] if sdist else None, "wheels": files(pkg.get("wheels"))})
    return out


def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def installed_python(site_dirs):
    """{(pep503 name, version)} of the distributions installed in the given
    site-packages directories (their *.dist-info directories)."""
    out = set()
    for site in site_dirs:
        try:
            names = os.listdir(site)
        except OSError:
            continue
        for n in names:
            if n.endswith(".dist-info"):
                stem = n[:-len(".dist-info")]
                if "-" in stem:
                    name, version = stem.rsplit("-", 1)
                    out.add((pep503(name), version))
    return out


def venv_site_dirs(venv):
    """The site-packages directories of a virtual environment."""
    out = []
    for lib in ("lib", "lib64"):
        base = os.path.join(venv, lib)
        try:
            for d in sorted(os.listdir(base)):
                if d.startswith(("python", "pypy")):
                    out.append(os.path.join(base, d, "site-packages"))
        except OSError:
            pass
    out.append(os.path.join(venv, "Lib", "site-packages"))           # Windows
    return out


# ---------------- This machine ----------------
_NODE_ARCH = {"x86_64": "x64", "amd64": "x64", "x64": "x64", "aarch64": "arm64", "arm64": "arm64",
              "armv7l": "arm", "armv6l": "arm", "armv8l": "arm", "i386": "ia32", "i686": "ia32", "x86": "ia32",
              "ppc64le": "ppc64", "ppc64": "ppc64", "s390x": "s390x", "riscv64": "riscv64",
              "loongarch64": "loong64", "mips64": "mips64el"}


def node_platform(env=None):
    """(os, cpu, libc) as npm and pnpm see this machine: node's
    process.platform and process.arch; glibc or musl on Linux. None where it
    can't be told (a field then filters nothing)."""
    plat = arch = None
    node = programs.find("node", (env or os.environ).get("PATH"))
    if node:
        try:
            out = subprocess.run([node, "-p", "process.platform + ' ' + process.arch"], env=env,
                                 capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=30).stdout.split()
            if len(out) == 2:
                plat, arch = out
        except (OSError, subprocess.SubprocessError):
            pass
    if plat is None:
        plat = "win32" if sys.platform in ("win32", "cygwin") else re.sub(r"\d+$", "", sys.platform)
        machine = platform.machine().lower()
        arch = _NODE_ARCH.get(machine, machine or None)
    libc = None
    if plat == "linux":
        if platform.libc_ver()[0] == "glibc":
            libc = "glibc"
        elif glob.glob("/lib/ld-musl-*.so.1"):
            libc = "musl"
    return plat, arch, libc


def platform_ok(entry, here):
    """Would npm or pnpm install a package with these os / cpu / libc fields
    here (npm-install-checks' rules)?"""
    plat, arch, libc = here

    def ok(values, current):
        if not values or current is None or values == ["any"]:
            return True
        if "!" + current in values:
            return False
        positive = [v for v in values if not v.startswith("!")]
        return not positive or current in positive
    if not ok(entry.get("os"), plat) or not ok(entry.get("cpu"), arch):
        return False
    if entry.get("libc"):
        if plat is not None and plat != "linux":
            return False
        return ok(entry["libc"], libc)
    return True


_WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)(?:-(?P<build>\d[^-]*))?"
                       r"-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$", re.I)
_ARCH_ALIASES = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64", "i386": "i686", "x86": "i686"}


def interpreter_info(python=None):
    """(implementation, major, minor, os, arch) of a Python — the one given
    (a path; its answer is read from a short, fixed probe), else this one."""
    if python:
        try:
            out = subprocess.run([python, "-c", "import sys, platform; print(sys.implementation.name, "
                                  "sys.version_info[0], sys.version_info[1], sys.platform, platform.machine())"],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=30).stdout.split()
            if len(out) == 5:
                return out[0], int(out[1]), int(out[2]), out[3], out[4]
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return sys.implementation.name, sys.version_info[0], sys.version_info[1], sys.platform, platform.machine()


def wheel_fits(filename, info):
    """Can this machine's interpreter (interpreter_info) install the wheel?
    A generous reading of the wheel tags — the Python and ABI tag of this
    version, abi3 and pure wheels, and a platform tag of this system and
    architecture (not its glibc or macOS version) — so that the wheel the
    tool picks is among those that fit."""
    m = _WHEEL_RE.match(filename)
    if m is None:
        return False
    impl, major, minor, osname, arch = info
    arch = _ARCH_ALIASES.get(arch.lower(), arch.lower())
    short = {"cpython": "cp", "pypy": "pp"}.get(impl, impl[:2])
    pys = m.group("py").lower().split(".")
    abis = m.group("abi").lower().split(".")
    plats = m.group("plat").lower().split(".")

    def py_ok(tag):
        if tag in (f"py{major}", "py2.py3"):
            return True
        for pre in ("py", short):
            if tag.startswith(pre) and tag[len(pre):].isdigit():
                digits = tag[len(pre):]
                if digits == f"{major}{minor}":
                    return True
                if pre == "py" and digits.startswith(str(major)) and int(digits[1:] or 0) <= minor:
                    return True
                if pre == short and "abi3" in abis and digits.startswith(str(major)) \
                        and int(digits[1:] or 0) <= minor:
                    return True
        return False

    def plat_ok(tag):
        if tag == "any":
            return True
        if osname.startswith("linux"):
            return tag.startswith(("manylinux", "musllinux", "linux")) and tag.endswith(arch)
        if osname == "darwin":
            return tag.startswith("macosx") and (tag.endswith(arch) or tag.endswith(("universal2", "universal"))
                                                  or (arch == "aarch64" and tag.endswith("arm64")))
        if osname in ("win32", "cygwin"):
            return tag == {"x86_64": "win_amd64", "aarch64": "win_arm64", "i686": "win32"}.get(arch, "")
        return False
    abi_ok = any(a in ("none", "abi3") or a.startswith(f"{short}{major}{minor}") for a in abis)
    return any(py_ok(p) for p in pys) and abi_ok and any(plat_ok(p) for p in plats)


def pick_artifacts(files, info):
    """The files of one PyPI release the tool may install here: the wheels
    that fit, else the sdist, else every wheel. files: [{filename, …}]."""
    wheels = [f for f in files if f["filename"].lower().endswith(".whl")]
    fit = [w for w in wheels if wheel_fits(w["filename"], info)]
    if fit:
        return fit
    sdists = [f for f in files if not f["filename"].lower().endswith(".whl")]
    return sdists[:1] if sdists else wheels


# ---------------- One guard run ----------------
def _name_key(eco, name):
    if eco == "crates":
        return name.lower().replace("_", "-")                       # (crates.io holds one of `a-b` and `a_b`)
    return pep503(name) if eco == "pypi" else name.lower()


class Context:
    """One guard run: the options, the scanner, the policy, what was checked."""

    def __init__(self, opts, out=None):
        self.opts = opts
        self.keepalive = bool(getattr(opts, "keepalive", False))
        self.min_age = opts.min_age
        self.started = now()
        self.cutoff = self.started - datetime.timedelta(seconds=self.min_age) if self.min_age else None
        self.cache = None if opts.no_cache else VerdictCache(default_cache_path())
        self.scanner = Scanner(self.cache, timeout=opts.scan_timeout, jobs=opts.jobs, isolate=getattr(opts, "isolate", None),
                               memory_mb=getattr(opts, "worker_memory", scanpool.DEFAULT_MEMORY_MB), note=self.say)
        self.checks = []
        self.lock = threading.Lock()
        self.out = out or sys.stderr
        self.skipped_platform = 0           # lockfile packages for other platforms, left out
        self.expected = set()               # (name key, version) the tool may install: checked or noted
        self.unchecked = []                 # installed, but not checked (verify_installed)
        self.age_unknown = []               # releases whose publish time is not known (--min-age could not hold them)
        self.notes = []                     # what else the run has to say (one line each)
        self.unchecked_hint = "the registry changed while the guard checked; run it again, or remove them"

    def matches(self, patterns, eco, name):
        """Does a --allow-new / --trust pattern name this package ('@scope/*'
        and other shell patterns too)?"""
        key = _name_key(eco, name)
        return any(fnmatch.fnmatchcase(key, _name_key(eco, p)) for p in patterns)

    def add(self, check):
        with self.lock:
            self.checks.append(check)
        return check

    def block(self, check, reason):
        """Block the package — unless --trust names it: then it is installed
        and the reason is reported."""
        if self.matches(self.opts.trust, check.eco, check.name):
            check.trusted = True
            check.notes.append(f"installed anyway (--trust): {reason}")
        else:
            check.blocked.append(reason)

    def apply(self, check, hit):
        """A scan verdict, and what it means for the install."""
        check.verdict, check.reason, check.indicators = hit["verdict"], hit["reason"], list(hit["indicators"])
        if check.verdict == "SUSPICIOUS":
            self.block(check, f"SUSPICIOUS: {check.reason}")
        elif check.verdict in ("WARN", "INCOMPLETE") and self.opts.block_warn:
            self.block(check, f"{check.verdict} (--block-warn): {check.reason}")

    def age_check(self, check, published):
        """Block a release younger than --min-age (unless --allow-new names it). One whose publish time is not known (a
        mirror that does not say, an answer that failed) is said at the end of the run, and blocked under --block-warn: it
        used to pass with nothing said (the Go/Rust review's CG-4 and GO-9)."""
        if published is None:
            if self.cutoff is not None and not self.matches(self.opts.allow_new, check.eco, check.name):
                with self.lock:
                    self.age_unknown.append(check.label())
                if self.opts.block_warn:
                    self.block(check, "its publish time is not known, so --min-age cannot hold it (--block-warn)")
            return
        check.age = int((now() - published).total_seconds())
        if self.cutoff is None or published <= self.cutoff:
            return
        if self.matches(self.opts.allow_new, check.eco, check.name):
            check.notes.append(f"published {format_age(check.age)} ago; let through by --allow-new")
        else:
            self.block(check, f"published {format_age(check.age)} ago, under --min-age {format_age(self.min_age)} "
                              f"(--allow-new {check.name} lets it through)")

    def not_checked(self, check, exc):
        """A package that could not be fetched or scanned: blocked (the guard
        fails closed), except a file too large to scan, which is INCOMPLETE."""
        if isinstance(exc, TooLarge):
            self.apply(check, {"verdict": "INCOMPLETE", "indicators": [],
                               "reason": f"larger than the {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB the guard "
                                         f"scans, not scanned"})
        else:
            self.block(check, f"could not be checked: {exc}")

    def blocked(self):
        return [c for c in self.checks if c.blocked]

    def say(self, line=""):
        print(lazaret.sanitize_term_line(line) if line else "", file=self.out, flush=True)

    def close(self):
        self.scanner.close()


def run_all(jobs):
    """Run the zero-argument jobs a few at a time (fetching overlaps scanning)."""
    if not jobs:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for f in [pool.submit(job) for job in jobs]:
            f.result()


def verify_installed(ctx, new, eco):
    """new: {(name, version)} the tool installed that were not installed
    before. Those the guard neither checked nor noted (the registry changed
    while it checked, or the tool resolved differently) are reported, and the
    run fails."""
    expected = ctx.expected | {(_name_key(eco, c.name), c.version) for c in ctx.checks}
    ctx.unchecked = sorted(f"{n}@{v}" for n, v in new if (_name_key(eco, n), v) not in expected)


# ---------------- npm, pnpm, yarn and Bun packages ----------------
def tool_config(exe, env, cwd):
    """The package manager's settings (`<tool> config list --json`); {} when
    it can't say."""
    doc = pmsettings.run_json([exe, "config", "list", "--json"], env, cwd)
    return doc if isinstance(doc, dict) else {}


_registry_url = pmsettings.registry_url


class Registries(pmsettings.NpmSettings):
    """The default npm registry and the scoped ones (@scope:registry), from
    the package manager's settings, with the credentials those give
    (pmsettings)."""

    def for_name(self, name):
        if name.startswith("@"):
            return self.scoped.get(name.split("/", 1)[0], self.default)
        return self.default

    def tarball(self, name, version):
        return f"{self.for_name(name)}{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"

    def resolved(self, name, url):
        """Where npm fetches a lockfile's `resolved` URL (its
        replace-registry-host rule: registry.npmjs.org is the configured
        registry)."""
        base = self.for_name(name)
        if self.replace_npmjs and url.startswith(NPM_REGISTRY) and base != NPM_REGISTRY:
            return base + url[len(NPM_REGISTRY):]
        return url

    def all(self):
        return [self.default, *self.scoped.values()]

    def http_hosts(self):
        return {netloc(u) for u in self.all() if u.startswith("http://")}


def npm_publish_time(fetcher, registry, name, version):
    """When the registry says name@version was published (its packument's
    `time`), or None."""
    try:
        doc = fetcher.json(registry + urllib.parse.quote(name, safe="@"))
    except (repo.FetchError, ValueError):
        return None
    times = doc.get("time") if isinstance(doc, dict) else None
    return parse_time(times.get(version)) if isinstance(times, dict) else None


def check_npm_package(ctx, fetcher, pkg):
    """Check one npm package: pkg is {name, version, tarball, integrity,
    registry, lock_digest}. The tarball is fetched from where the package
    manager will fetch it and checked against the lockfile's integrity (the
    bytes the package manager will accept) — or the registry's, when the
    lockfile has none — then scanned. Its publish time comes from the
    download (Last-Modified), confirmed by the registry when it looks
    recent.

    yarn 2+ pins the checksum of the zip it makes of the tarball, not the
    tarball's: its lock_digest keys the verdict in the cache too, so a
    package checked once is known again without a download."""
    name, version = pkg["name"], pkg["version"]
    check = ctx.add(Check("npm", name, version, "registry"))
    try:
        repo._check_name("npm", name)
        alt = VerdictCache.key("npm", name, version, "yarn:" + pkg["lock_digest"]) if pkg.get("lock_digest") else None
        hit, key = ctx.scanner.cached(alt), None
        published = parse_time(hit.get("published")) if hit else None
        if hit is not None:
            check.digest = "yarn:" + pkg["lock_digest"]
        else:
            want, tarball = sri_best(pkg["integrity"]), pkg["tarball"]
            if want is None:
                manifest = fetcher.json(pkg["registry"] + urllib.parse.quote(name, safe="@") + "/"
                                        + urllib.parse.quote(version, safe=""))
                want = registry_digest(manifest)
                if want is None:
                    raise repo.FetchError("neither the lockfile nor the registry gives a digest to check it against")
            check.digest = f"{want[0]}-{want[1]}"
            key = VerdictCache.key("npm", name, version, check.digest)
            hit = ctx.scanner.cached(key)
            published = parse_time(hit.get("published")) if hit else None
            if hit is None:
                data, headers = fetcher.fetch(tarball)
                if not sri_matches(data, want):
                    ctx.block(check, f"its {want[0]} digest is not the "
                                     + ("lockfile's" if pkg["integrity"] else "registry's"))
                    return check
                published = parse_http_date(headers.get("Last-Modified"))
                hit = ctx.scanner.scan(data, "tgz", "npm")
        if ctx.cutoff is not None and (published is None or published > ctx.cutoff):
            published = npm_publish_time(fetcher, pkg["registry"], name, version) or published
        ctx.scanner.remember(key, hit, published)
        ctx.scanner.remember(alt, hit, published)
        ctx.apply(check, hit)
        ctx.age_check(check, published)
    except (repo.FetchError, repo.SpecError, ValueError) as exc:
        ctx.not_checked(check, exc)
    return check


def check_lock_entries(ctx, entries, registries, installed, label, env=None, rewrite=True):
    """Check what a lockfile adds on this machine. entries: [{name, version,
    resolved, integrity, os, cpu, libc, lock_digest}] (resolved: a URL, or
    '' for the registry's own). Other platforms and what is installed are
    left out; git, local and digest-less tarball sources are noted, not
    checked. rewrite: npm's replace-registry-host rule applies to resolved
    URLs (npm, pnpm). -> EXIT_BLOCKED, EXIT_OK (--plan), or None to go on."""
    here = node_platform(env)
    http_hosts = registries.http_hosts()
    todo = {}
    for e in entries:
        key = (e["name"], e["version"])
        if not platform_ok(e, here):
            ctx.skipped_platform += 1
            continue
        ctx.expected.add((_name_key("npm", e["name"]), e["version"]))
        if key in installed or key in todo:
            continue
        if e["resolved"]:
            url = registries.resolved(e["name"], e["resolved"]) if rewrite else e["resolved"]
        else:
            url = registries.tarball(e["name"], e["version"]) if e["version"] else ""
        if not url or not (fetchable(url) or (url.startswith("http://") and netloc(url) in http_hosts)):
            ctx.add(Check("npm", e["name"], e["version"], pmsettings.shown(e["resolved"]) or "unknown source")
                    ).notes.append("not from a registry (git, a local file or a link): not checked")
            continue
        if sri_best(e["integrity"]) is None and not e.get("lock_digest") \
                and (not e["version"] or "/-/" not in urllib.parse.urlsplit(url).path):
            ctx.add(Check("npm", e["name"], e["version"], pmsettings.shown(url))).notes.append(
                "a tarball URL with no digest in the lockfile (like a git dependency): not checked")
            continue
        todo[key] = {"name": e["name"], "version": e["version"], "tarball": url, "integrity": e["integrity"],
                     "registry": registries.for_name(e["name"]), "lock_digest": e.get("lock_digest")}
    fetcher = Fetcher({netloc(u) for u in registries.all()} | {netloc(p["tarball"]) for p in todo.values()},
                      http_hosts=http_hosts, auth=registries.creds, keepalive=ctx.keepalive)
    other = f"; {plural(ctx.skipped_platform, 'package')} for other platforms left out" \
        if ctx.skipped_platform else ""
    ctx.say(f"lazaret guard: {plural(len(todo), 'package')} to check ({label}{other})")
    try:
        run_all([lambda p=p: check_npm_package(ctx, fetcher, p) for p in todo.values()])
    finally:
        fetcher.close()
    if ctx.blocked():
        return EXIT_BLOCKED
    return EXIT_OK if ctx.opts.plan else None


# ---------------- PyPI files ----------------
def pypi_upload_time(fetcher, name, version, filename):
    """When PyPI says a file was uploaded (its JSON API), or None."""
    try:
        quote = urllib.parse.quote
        doc = fetcher.json(f"{PYPI_JSON}{quote(name, safe='')}/{quote(version, safe='')}/json")
    except (repo.FetchError, ValueError):
        return None
    for u in doc.get("urls", []) if isinstance(doc, dict) and isinstance(doc.get("urls"), list) else []:
        if isinstance(u, dict) and u.get("filename") == filename:
            return parse_time(u.get("upload_time_iso_8601"))
    return None


def check_file(ctx, fetcher, name, version, f):
    """Check one PyPI file of a lockfile (f: {url, hash, upload-time,
    filename}): verify its SHA-256 and scan it, once."""
    check = ctx.add(Check("pypi", name, version, f["filename"]))
    published = parse_time(f["upload-time"])
    try:
        sha = f["hash"][len("sha256:"):].lower() if f["hash"].startswith("sha256:") else ""
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise repo.FetchError("the lockfile gives no SHA-256 to check the file against")
        check.digest = f"sha256:{sha}"
        key = VerdictCache.key("pypi", pep503(name), version, check.digest)
        hit = ctx.scanner.cached(key)
        if hit is None:
            container = repo.pypi_container(f["filename"])
            if container is None:
                raise repo.FetchError("not an archive pip or uv installs")
            data = fetcher.get(f["url"])
            if hashlib.sha256(data).hexdigest() != sha:
                ctx.block(check, "its SHA-256 is not the lockfile's")
                return check
            hit = ctx.scanner.scan(data, container, "wheel" if f["filename"].lower().endswith(".whl") else "sdist")
        published = published or parse_time(hit.get("published"))
        if published is None and ctx.cutoff is not None and netloc(f["url"]) == "files.pythonhosted.org":
            published = pypi_upload_time(fetcher, name, version, f["filename"])
        ctx.scanner.remember(key, hit, published)
        ctx.apply(check, hit)
    except (repo.FetchError, ValueError) as exc:
        ctx.not_checked(check, exc)
    ctx.age_check(check, published)
    return check


# ---------------- A local index for pip and uv ----------------
_FILE_PATH_RE = re.compile(r"^/files/(\d{1,9})/([^/]{1,400})$")
_SIMPLE_PATH_RE = re.compile(r"^/simple/([A-Za-z0-9._-]{1,200})/?$")
_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


def pypi_upstream():
    """The simple index the local index relays (LAZARET_GUARD_PYPI_URL, else PyPI)."""
    url = os.environ.get("LAZARET_GUARD_PYPI_URL") or PYPI_SIMPLE
    return url if url.endswith("/") else url + "/"


_SIMPLE_ACCEPT = f"{_SIMPLE_JSON}, text/html;q=0.1"
#: Links read from one PEP 503 (HTML) project page
MAX_PAGE_LINKS = 100_000


class _SimpleLinks(html.parser.HTMLParser):
    """The files of a PEP 503 project page, as PEP 691 lists them: the
    link's text as the filename, its #sha256= fragment as the hash,
    data-requires-python, data-core-metadata (data-dist-info-metadata) and
    data-yanked."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.files, self._open = [], None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._open = (dict(attrs), [])

    def handle_data(self, data):
        if self._open is not None:
            self._open[1].append(data)

    def handle_endtag(self, tag):
        if tag != "a" or self._open is None:
            return
        attrs, text = self._open
        self._open = None
        href = attrs.get("href")
        if not href or len(self.files) >= MAX_PAGE_LINKS:
            return
        url, _, frag = href.partition("#")
        alg, _, digest = frag.partition("=")
        f = {"filename": "".join(text).strip() or urllib.parse.unquote(url.rsplit("/", 1)[-1]), "url": url,
             "hashes": {"sha256": digest.lower()} if alg == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
             else {}}
        if attrs.get("data-requires-python") is not None:
            f["requires-python"] = attrs["data-requires-python"]
        meta = attrs.get("data-core-metadata", attrs.get("data-dist-info-metadata"))
        if meta is not None:
            f["core-metadata"] = {"sha256": meta[7:]} if meta.startswith("sha256=") else True
        if "data-yanked" in attrs:
            f["yanked"] = attrs["data-yanked"] or True
        self.files.append(f)


def parse_simple_html(text, project):
    """A PEP 503 (HTML) project page as a PEP 691 (JSON) one."""
    parser = _SimpleLinks()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        pass
    return {"meta": {"api-version": "1.0"}, "name": project, "files": parser.files}


class PypiIndex:
    """What the local index knows: the project pages it served (their files,
    by a number) and the files it scanned, kept on disk (spool) until the
    tool has them.

    It relays the indexes the tool is set to use (0.1.8: the tool's own
    settings; LAZARET_GUARD_PYPI_URL names one instead; PyPI by default) —
    all of them at once (merge: pip's rule) or the first that has the
    project (uv's) — reading their JSON pages or their PEP 503 HTML ones.
    A project none of them has gets an empty page, not a 404, so that the
    tool never goes on to an index the guard does not relay."""

    def __init__(self, ctx, fetcher, spool, upstream=None, indexes=None, merge=False):
        self.ctx = ctx
        self.fetcher = fetcher
        self.spool = spool
        self.indexes = list(indexes) if indexes else [pmsettings.Index(upstream or pypi_upstream(), default=True)]
        self.simple = self.indexes[0].url
        self.merge = merge
        self.files = {}           # number -> {url, project, filename, version, sha256, published, size}
        self.numbers = {}         # upstream url -> number
        self.results = {}         # number -> (Check, spooled file or None)
        self.held_back = {}       # project -> {version: upload time}
        self.planned = None       # pip's plan: the numbers of its files, when every one came from this index
        self.prefix = ""          # the path its pages' links to files start with (the server's secret segment)
        self.errors = []          # what the index could not fetch (for the report, not the tool)
        self.lock = threading.Lock()
        self.number_locks = {}

    def note(self, message):
        with self.lock:
            if message not in self.errors and len(self.errors) < 20:
                self.errors.append(message)

    def _project_page(self, url, project):
        """An index's page for a project (JSON, or HTML read as JSON)."""
        body, headers = self.fetcher.fetch(url, MAX_DOCUMENT, _SIMPLE_ACCEPT, repo.METADATA_TIMEOUT)
        ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype.endswith("json"):
            doc = repo._deep_safe_loads(body, f"from {pmsettings.shown(url)}")
        else:
            doc = parse_simple_html(body.decode("utf-8", errors="replace"), project)
        if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
            raise repo.FetchError(f"no project page for {project} at {pmsettings.shown(url)}")
        return doc

    def _usable(self, url):
        return fetchable(url) or (url.startswith("http://") and netloc(url) in self.fetcher.http_hosts)

    def page(self, project):
        """The project page, as JSON, with the files younger than --min-age
        left out and the URLs pointing here."""
        docs = []
        for index in self.indexes:
            url = index.url + project + "/"
            try:
                doc = self._project_page(url, project)
            except repo.FetchError as exc:
                if getattr(exc, "status", None) == 404 or "HTTP 404" in str(exc):
                    continue                        # not on this index
                raise
            docs.append((url, doc))
            if not self.merge:
                break
        name = next((d["name"] for _, d in docs if isinstance(d.get("name"), str)), project)
        kept, dropped_versions, kept_versions, seen = [], set(), set(), set()
        undated = False
        for page_url, doc in docs:
            for f in doc["files"]:
                if not isinstance(f, dict) or not isinstance(f.get("url"), str) \
                        or not isinstance(f.get("filename"), str):
                    continue
                filename = f["filename"]
                upstream = urllib.parse.urljoin(page_url, f["url"]).split("#", 1)[0]
                if not self._usable(upstream) or "/" in filename or "\\" in filename \
                        or filename in (".", "..") or filename in seen:
                    continue
                seen.add(filename)
                version = file_version(filename)
                published = parse_time(f.get("upload-time"))
                undated = undated or published is None
                if (self.ctx.cutoff is not None and published is not None and published > self.ctx.cutoff
                        and not self.ctx.matches(self.ctx.opts.allow_new, "pypi", name)):
                    with self.lock:
                        self.held_back.setdefault(name, {})[version or filename] = published
                    dropped_versions.add(version)
                    continue
                kept_versions.add(version)
                hashes = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
                sha = hashes.get("sha256") if isinstance(hashes.get("sha256"), str) else ""
                with self.lock:
                    number = self.numbers.setdefault(upstream, str(len(self.numbers) + 1))
                    self.files[number] = {"url": upstream, "project": name, "filename": filename,
                                          "version": version, "sha256": sha.lower(), "published": published,
                                          "size": f.get("size") if isinstance(f.get("size"), int) else None}
                self.fetcher.allow(upstream)
                g = dict(f)
                g["url"] = f"{self.prefix}/files/{number}/{urllib.parse.quote(filename)}"
                kept.append(g)
        if undated and self.ctx.cutoff is not None:
            self.note(f"{project}: the index gives no upload times, so --min-age could not hold back its "
                      f"new releases")
        out = dict(docs[0][1]) if len(docs) == 1 else {"meta": {"api-version": "1.1"}}
        out["name"] = name
        out["files"] = kept
        versions = [v for _, d in docs for v in (d.get("versions") if isinstance(d.get("versions"), list) else [])]
        if versions:
            out["versions"] = [v for v in dict.fromkeys(versions) if v not in dropped_versions or v in kept_versions]
        return out

    def release_files(self, name, version):
        """The files the index served for name==version: [(number, info)]."""
        want = pep503(name)
        with self.lock:
            return [(n, i) for n, i in self.files.items()
                    if pep503(i["project"]) == want and _same_version(i["version"], version)]

    def scan(self, number):
        """(Check, spooled file) for a file the index served, fetched,
        verified and scanned once; the file is None when it is blocked, or
        too large to scan (it is then relayed as it comes, INCOMPLETE)."""
        with self.lock:
            lock = self.number_locks.setdefault(number, threading.Lock())
            info = self.files.get(number)
        if info is None:
            raise repo.FetchError("not a file of a page this index served")
        with lock:
            with self.lock:
                done = self.results.get(number)
            if done is not None:
                return done
            check = self.ctx.add(Check("pypi", info["project"], info["version"], info["filename"]))
            spooled = None
            try:
                container = repo.pypi_container(info["filename"])
                if container is None:
                    raise repo.FetchError("not an archive pip or uv installs")
                if info["size"] is not None and info["size"] > repo.MAX_DOWNLOAD_BYTES:
                    raise TooLarge(f"response over {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB: {info['filename']}")
                data = self.fetcher.get(info["url"])
                sha = hashlib.sha256(data).hexdigest()
                if info["sha256"] and sha != info["sha256"]:
                    self.ctx.block(check, "its SHA-256 is not the one the index publishes")
                else:
                    check.digest = f"sha256:{sha}"
                    key = VerdictCache.key("pypi", pep503(info["project"]), info["version"], check.digest)
                    hit = self.ctx.scanner.cached(key) or self.ctx.scanner.scan(
                        data, container, "wheel" if info["filename"].lower().endswith(".whl") else "sdist")
                    self.ctx.scanner.remember(key, hit, info["published"])
                    self.ctx.apply(check, hit)
                    self.ctx.age_check(check, info["published"])
                    if not check.blocked:
                        fd, spooled = tempfile.mkstemp(dir=self.spool)
                        with os.fdopen(fd, "wb") as f:
                            f.write(data)
            except (repo.FetchError, ValueError) as exc:
                self.ctx.not_checked(check, exc)
                self.ctx.age_check(check, info["published"])
            with self.lock:
                self.results[number] = (check, spooled)
            return check, spooled


_SDIST_EXTS = (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz", ".tar")


def file_version(filename):
    """The version in a PyPI file name (a wheel's second field; an sdist's
    last '-' part), or ''."""
    name = urllib.parse.unquote(filename)
    m = _WHEEL_RE.match(name)
    if m is not None:
        return m.group("ver")
    low = name.lower()
    for ext in _SDIST_EXTS:
        if low.endswith(ext):
            stem = name[:-len(ext)]
            return stem.rsplit("-", 1)[1] if "-" in stem else ""
    return ""


def _same_version(a, b):
    """Are two version strings the same release (lowercase, no leading 'v',
    '_' and '-' as '.', trailing '.0's ignored)?"""
    def norm(v):
        v = v.lower().lstrip("v").replace("_", ".").replace("-", ".")
        while v.endswith(".0") and v.count(".") > 1:
            v = v[:-2]
        return v
    return norm(a) == norm(b)


def _html_page(doc):
    """PEP 503 HTML of a project page, for a tool that asks for HTML."""
    rows = []
    for f in doc["files"]:
        hashes = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
        frag = f"#sha256={hashes['sha256']}" if isinstance(hashes.get("sha256"), str) else ""
        attrs = [f'href="{html.escape(f["url"] + frag)}"']
        if isinstance(f.get("requires-python"), str):
            attrs.append(f'data-requires-python="{html.escape(f["requires-python"])}"')
        meta = f.get("core-metadata", f.get("dist-info-metadata"))
        if isinstance(meta, dict) and isinstance(meta.get("sha256"), str):
            attrs.append(f'data-core-metadata="sha256={html.escape(meta["sha256"])}"')
            attrs.append(f'data-dist-info-metadata="sha256={html.escape(meta["sha256"])}"')
        elif meta is True:
            attrs.append('data-core-metadata="true"')
        if f.get("yanked"):
            attrs.append(f'data-yanked="{html.escape(f["yanked"] if isinstance(f["yanked"], str) else "")}"')
        rows.append(f"<a {' '.join(attrs)}>{html.escape(f['filename'])}</a><br/>")
    return ("<!DOCTYPE html><html><body>\n" + "\n".join(rows) + "\n</body></html>\n").encode("utf-8")


class LocalGate:
    """What lets a request through to one of the guard's servers on 127.0.0.1 (the Go proxy, the Python index): the run's
    secret first path segment, which only the tool the guard runs is told (GOPROXY, PIP_INDEX_URL, UV_INDEX), and a Host
    header naming the server as the tool was told it. Without them any process of the machine, another user's too, could ask
    the server for what it relays with the user's credentials for the upstream, and a page in a browser could, by pointing a
    name of its own at 127.0.0.1 (DNS rebinding: its own name is in the Host header) (the Go/Rust review's GO-3)."""

    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.host = None                    # "127.0.0.1:port", once the server has its port

    def bind(self, port):
        self.host = f"127.0.0.1:{port}"
        return f"http://{self.host}/{self.token}"

    def path(self, handler):
        """The request's path below the secret segment (with its leading slash), or None for a request to refuse."""
        if self.host is None or handler.headers.get("Host") != self.host:
            return None
        path = urllib.parse.urlsplit(handler.path).path
        prefix = "/" + self.token + "/"
        return path[len(prefix) - 1:] if path.startswith(prefix) else None


def make_index_server(index, gate=None):
    """A threaded HTTP server on 127.0.0.1 (a free port) serving `index`; with a LocalGate, only to the tool told its path."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _file(self, path):
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if self.command != "HEAD":
                with open(path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile, 1024 * 1024)

        def _relay(self, url):
            index.fetcher.check(url)
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with timings.span("network", "request"):
                response = index.fetcher._opener(url).open(req, timeout=repo.DOWNLOAD_TIMEOUT)
            with response as r:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                length = r.headers.get("Content-Length")
                if length and length.isdigit():
                    self.send_header("Content-Length", length)
                else:
                    self.close_connection = True
                self.end_headers()
                if self.command != "HEAD":
                    with timings.span("network", "relay"):
                        shutil.copyfileobj(r, self.wfile, 1024 * 1024)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path if gate is None else gate.path(self)
            if path is None:
                self._send(404, b"not found\n")
                return
            try:
                m = _SIMPLE_PATH_RE.match(path)
                if m is not None:
                    doc = index.page(pep503(m.group(1)))
                    if _SIMPLE_JSON in (self.headers.get("Accept") or ""):
                        self._send(200, json.dumps(doc).encode("utf-8"), _SIMPLE_JSON)
                    else:
                        self._send(200, _html_page(doc), "text/html; charset=utf-8")
                    return
                m = _FILE_PATH_RE.match(path)
                info = index.files.get(m.group(1)) if m is not None else None
                requested = urllib.parse.unquote(m.group(2)) if m is not None else ""
                if info is None or requested not in (info["filename"], info["filename"] + ".metadata"):
                    self._send(404, b"not found\n")
                    return
                if requested != info["filename"]:
                    self._send(200, index.fetcher.get(info["url"] + ".metadata", MAX_DOCUMENT),
                               "application/octet-stream")
                    return
                check, spooled = index.scan(m.group(1))
                if check.blocked:
                    self._send(403, b"blocked by lazaret guard (its report says why)\n")
                elif spooled is None:
                    self._relay(info["url"])                # too large to scan: INCOMPLETE
                else:
                    self._file(spooled)
            except repo.FetchError as exc:
                # fixed text for the tool; the reason goes in the guard's report
                index.note(str(exc))
                self._send(404 if getattr(exc, "status", None) == 404 else 502,
                           b"lazaret guard could not fetch this from the index it relays\n")
            except Exception:                              # never let one request kill the server
                self._send(500, b"lazaret guard: internal error\n")

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def handle_error(self, request, client_address):
            pass                            # a tool that hung up: nothing to print over its output

    return Server(("127.0.0.1", 0), Handler)


# ---------------- The tools ----------------
NPM_INSTALL = frozenset(("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
                         "isntall", "add", "update", "up", "upgrade", "udpate"))
NPM_CI = frozenset(("ci", "clean-install", "ic", "install-clean", "isntall-clean"))
PNPM_CMDS = frozenset(("add", "install", "i", "update", "up", "upgrade"))
UV_PROJECT = frozenset(("add", "sync", "lock"))
_GLOBAL_FLAGS = ("-g", "--global", "--location=global")
#: pip options that point it at another index or at local archives
PIP_INDEX_OPTIONS = ("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--no-index", "--index",
                     "--default-index")
_PIP_REQ_OPTION_RE = re.compile(r"^\s*(?:-i|--index-url|--extra-index-url|-f|--find-links|--no-index)(?:[\s=]|$)")
_PIP_REQ_INCLUDE_RE = re.compile(r"^\s*(?:-r|--requirement|-c|--constraint)[\s=]+(\S+)")
#: `uv lock` options `uv sync` takes too (they change the resolution): flags, then options with a value
_UV_LOCK_FLAGS = frozenset(("--no-index", "-U", "--upgrade", "--no-sources", "--no-build-isolation", "--no-build",
                            "--no-binary", "-n", "--no-cache", "--refresh", "--managed-python", "--no-managed-python",
                            "--no-python-downloads", "-q", "--quiet", "-v", "--verbose", "--native-tls", "--offline",
                            "--no-progress", "--no-config"))
_UV_LOCK_OPTIONS = frozenset(("--index", "--default-index", "-i", "--index-url", "--extra-index-url", "-f",
                              "--find-links", "--index-strategy", "--keyring-provider", "-P", "--upgrade-package",
                              "--resolution", "--prerelease", "--fork-strategy", "--exclude-newer",
                              "--exclude-newer-package", "-C", "--config-setting", "--config-settings-package",
                              "--no-build-isolation-package", "--no-build-package", "--no-binary-package",
                              "--cache-dir", "--refresh-package", "-p", "--python", "--color",
                              "--allow-insecure-host", "--directory", "--project", "--config-file"))
_UV_PLAN_LINE_RE = re.compile(r"^\s*\+\s+([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)")


class Snapshot:
    """Files a resolution may change, to put back when the install is blocked."""

    def __init__(self, paths):
        self.saved = {}
        for p in dict.fromkeys(os.path.abspath(p) for p in paths):
            try:
                with open(p, "rb") as f:
                    self.saved[p] = f.read()
            except FileNotFoundError:
                self.saved[p] = None
            except OSError as exc:
                raise GuardError(f"cannot read {p}: {exc.strerror}") from None

    def restore(self):
        """Put the files back; -> the names of those that had changed."""
        changed = []
        for p, data in self.saved.items():
            try:
                with open(p, "rb") as f:
                    now_data = f.read()
            except OSError:
                now_data = None
            if now_data == data:
                continue
            changed.append(os.path.basename(p))
            if data is None:
                try:
                    os.remove(p)
                except OSError:
                    pass
            else:
                with open(p, "wb") as f:
                    f.write(data)
        return changed


def find_tool(name):
    """The package manager's executable (after the command line was checked): the first in PATH's folders named by an absolute
    path, never one in the current folder (programs.find): shutil.which looked in the current folder first on Windows, so a
    project with a go.exe or an npm.cmd of its own ran it under the guard (the Go/Rust review's GO-8)."""
    exe = programs.find(name)
    if exe is None:
        raise GuardError(f"{name} is not on PATH (the guard looks in PATH's folders named by an absolute path, not in the "
                         f"current folder)")
    return exe


def run_tool(argv, env, cwd=None, capture=False):
    """Run the package manager; capture=True keeps its output (a resolution)."""
    try:
        with timings.span("tool", f"{os.path.basename(argv[0])} {'resolve' if capture else 'run'}"):
            return subprocess.run(argv, env=env, cwd=cwd, text=True, encoding="utf-8", errors="replace",
                                  stdout=subprocess.PIPE if capture else None,
                                  stderr=subprocess.STDOUT if capture else None)
    except OSError as exc:
        raise GuardError(f"could not run {argv[0]}: {exc.strerror or exc}") from None


def show_failure(ctx, what, proc, lines=40):
    ctx.say(f"lazaret guard: {what} failed (exit {proc.returncode}):")
    for line in (proc.stdout or "").splitlines()[-lines:]:
        ctx.say("  " + line)


def pnpm_age_setting(exe, env):
    """pnpm has minimum-release-age from 10.16 on."""
    try:
        out = subprocess.run([exe, "--version"], env=env, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=60).stdout.strip()
        major, minor = (int(x) for x in out.split(".")[:2])
        return (major, minor) >= (10, 16)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def _find_up(start, names, accept=None):
    d = os.path.abspath(start)
    while True:
        if any(os.path.exists(os.path.join(d, n)) for n in names) and (accept is None or accept(d)):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def _npm_workspace_of(root, cwd):
    """Is cwd one of the workspaces root's package.json lists?"""
    try:
        with open(os.path.join(root, "package.json"), encoding="utf-8") as f:
            spec = json.load(f).get("workspaces")
    except (OSError, ValueError, AttributeError):
        return False
    patterns = spec.get("packages") if isinstance(spec, dict) else spec
    rel = os.path.relpath(os.path.abspath(cwd), root).replace(os.sep, "/")
    return any(isinstance(p, str) and fnmatch.fnmatchcase(rel, p.strip("./").rstrip("/"))
               for p in (patterns if isinstance(patterns, list) else []))


def npm_prefix(exe, env, cwd, args=()):
    """The folder npm works in for a command run in cwd, as npm itself says
    (`npm prefix`, with the command's own --prefix): the nearest folder up
    from cwd with a package.json or a node_modules folder, or the root of
    the workspace that folder is one of. None when npm doesn't say.

    A folder with no package.json is not where npm writes: from a checkout
    whose package.json is in a subfolder, `npm install x` added x to the
    package.json of the nearest parent that had one (a home folder with a
    node_modules), and wrote its lockfile there — so the guard found no
    lockfile where it looked, and --plan left that parent changed."""
    given = _option_value(list(args), ("--prefix", "-C"))
    cmd = [exe, "prefix"] + ([f"--prefix={given}"] if given else [])
    try:
        proc = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = proc.stdout.strip().splitlines() if proc.returncode == 0 else []
    path = lines[-1].strip() if lines else ""
    return os.path.abspath(path) if path and os.path.isdir(path) else None


def _same_dir(a, b):
    """Are a and b the same folder (however each is spelled: a symlinked
    /var, a Windows short name)?"""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def npm_root(tool, cwd):
    """The folder whose lockfile a command run in cwd writes: pnpm's
    workspace root (pnpm-workspace.yaml), or the root of the npm workspace
    cwd is one of; else cwd."""
    if tool == "pnpm":
        return _find_up(cwd, ["pnpm-workspace.yaml"]) or cwd
    if any(os.path.exists(os.path.join(cwd, n)) for n in ("package-lock.json", "npm-shrinkwrap.json")):
        return cwd
    parent = os.path.dirname(os.path.abspath(cwd))
    return _find_up(parent, ["package.json"], lambda d: _npm_workspace_of(d, cwd)) or cwd


def installed_npm(tool, root):
    """{(name, version)} installed under root's node_modules (the hidden
    lockfile npm or pnpm keeps there), or None when there is none."""
    if tool == "npm":
        text = read_text(os.path.join(root, "node_modules", ".package-lock.json"))
        return None if text is None else {(e["name"], e["version"]) for e in npm_lock_packages(text)}
    text = read_text(os.path.join(root, "node_modules", ".pnpm", "lock.yaml"))
    return None if text is None else set(pnpm_lock_packages(text))


def _npm_age(ctx, tool, exe, env, config):
    """Give npm and pnpm the cutoff themselves (they then resolve to older
    releases): npm's `before` — always set, to the start of this run when
    there is no cutoff, so the install can't pick a release this run did not
    check (a stricter `before` of the user's own stays) — and pnpm's
    minimum-release-age (pnpm 10.16+)."""
    native = ctx.cutoff is not None and not ctx.opts.allow_new
    if tool == "npm":
        before = ctx.cutoff if native else ctx.started
        own = parse_time(config.get("before")) if isinstance(config.get("before"), str) else None
        env["npm_config_before"] = iso(min(before, own) if own else before)
        if native:
            ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are held back "
                    f"(npm --before {iso(before)})")
    elif native and pnpm_age_setting(exe, env):
        minutes = max(1, -(-ctx.min_age // 60))
        try:
            own = int(config.get("minimum-release-age") or 0)
        except (TypeError, ValueError):
            own = 0
        if own < minutes:
            env["npm_config_minimum_release_age"] = str(minutes)
        ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are held back "
                f"(pnpm minimum-release-age)")


def guard_npm(ctx, tool, args):
    """npm and pnpm: resolve to a lockfile, check what it adds, then install."""
    sub = args[0] if args else ""
    supported = (NPM_INSTALL | NPM_CI) if tool == "npm" else PNPM_CMDS
    if sub not in supported:
        raise GuardError(f"lazaret guard wraps {tool}'s install commands ({', '.join(sorted(supported))}); "
                         f"put the command first: lazaret guard {tool} install …")
    global_install = any(a in _GLOBAL_FLAGS for a in args)
    if global_install and tool == "pnpm":
        raise GuardError("lazaret guard does not wrap pnpm's global installs; install into a project instead")
    exe = find_tool(tool)
    cwd = os.getcwd()
    env = dict(os.environ)
    scratch = private_scratch("lazaret-guard-") if global_install else None
    try:
        if scratch:
            with open(os.path.join(scratch, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name": "lazaret-guard-plan", "version": "0.0.0", "private": true}\n')
        where = scratch or cwd
        root = scratch or (npm_prefix(exe, env, cwd, args) if tool == "npm" else None) or npm_root(tool, cwd)
        if not scratch and not _same_dir(root, cwd):
            ctx.say(f"lazaret guard: {tool} works in {root}")
        config = pmsettings.npm_tool_settings(tool, exe, env, cwd, root)
        registries = Registries(config)
        _npm_age(ctx, tool, exe, env, config)
        lock_names = ["npm-shrinkwrap.json", "package-lock.json"] if tool == "npm" else ["pnpm-lock.yaml"]
        snap = Snapshot([os.path.join(where, "package.json"), os.path.join(root, "package.json")]
                        + [os.path.join(root, n) for n in lock_names])
        fresh = sub in NPM_CI or global_install                 # nothing installed counts
        before_install = set() if fresh else (installed_npm(tool, root) or set())
        try:
            code = _check_npm(ctx, tool, exe, sub, args, env, where, root, lock_names, registries,
                              before_install, scratch=bool(scratch))
        except BaseException:
            snap.restore()
            raise
        if code is not None:
            return finish(ctx, installed=False, restored=[] if global_install else snap.restore(), code=code)
        proc = run_tool([exe] + list(args), env, cwd=cwd)
        if proc.returncode == 0 and not global_install:
            after = installed_npm(tool, root)
            if after is not None:
                verify_installed(ctx, after - before_install, "npm")
        return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)
    finally:
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def _check_npm(ctx, tool, exe, sub, args, env, where, root, lock_names, registries, installed, scratch=False):
    """Resolve, then check what the lockfile adds. -> None to go on and
    install, else the exit code (the resolution failed, something is blocked,
    or --plan). `scratch`: `where` is the guard's own folder (a global
    install's plan), which no project above it takes in as a workspace."""
    if sub not in NPM_CI:
        flags = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"] if tool == "npm" \
            else ["--lockfile-only", "--ignore-scripts"]
        if scratch and tool == "npm":
            flags.append("--workspaces=false")      # (npm looks above a project for a workspace root that names it)
        resolve = [exe] + [a for a in args if a not in _GLOBAL_FLAGS] + flags
        proc = run_tool(resolve, env, cwd=where, capture=True)
        if proc.returncode != 0:
            show_failure(ctx, f"resolving ({tool} {sub})", proc)
            return EXIT_RESOLVE
    lock_path = next((os.path.join(root, n) for n in lock_names if os.path.exists(os.path.join(root, n))), None)
    text = read_text(lock_path) if lock_path else None
    if text is None:
        raise GuardError(f"{tool} wrote no lockfile to check (looked in {root})")
    if tool == "npm":
        entries = npm_lock_packages(text)
    else:
        entries = [dict(e, name=n, version=v, resolved=e["tarball"]) for (n, v), e in pnpm_lock_packages(text).items()]
    return check_lock_entries(ctx, entries, registries, installed, os.path.basename(lock_path), env)


# ---------------- yarn and Bun (0.1.8) ----------------
YARN_CLASSIC_CMDS = frozenset(("install", "add", "upgrade", "remove"))
YARN_BERRY_CMDS = frozenset(("install", "add", "up", "remove", "dedupe"))
BUN_CMDS = frozenset(("install", "i", "add", "a", "update", "remove", "rm"))
_YARN_LOCAL = ("file:", "link:", "portal:", "workspace:")
_BERRY_NPM_RE = re.compile(r"^(@?[^@]+)@npm:([^:]+)(?:::(.*))?$")
_BERRY_CONDITION_RE = re.compile(r"\b(os|cpu|libc)=([!\w.-]+)")


def _lock_key_specs(line):
    key = line.rstrip()
    key = key[:-1] if key.endswith(":") else key
    return [p.strip().strip('"').strip("'") for p in key.split(",") if p.strip()]


def yarn_classic_lock(text):
    """{(name, version): {name, version, resolved, integrity}} of a yarn 1
    lockfile: one per package (an entry lists the ranges it satisfies; an
    alias is read as its real name). resolved is the URL yarn fetches; its
    #sha1 stands in for a missing integrity. Local folders, links and
    workspaces are left out."""
    out, cur = {}, None

    def flush():
        if cur and cur["name"] and cur["version"] and not cur["local"]:
            url, _, frag = cur["resolved"].partition("#")
            integrity = cur["integrity"]
            if not integrity and re.fullmatch(r"[0-9a-fA-F]{40}", frag):
                integrity = "sha1-" + base64.b64encode(bytes.fromhex(frag)).decode("ascii")
            out.setdefault((cur["name"], cur["version"]), {"name": cur["name"], "version": cur["version"],
                                                           "resolved": url, "integrity": integrity,
                                                           "os": [], "cpu": [], "libc": []})

    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            flush()
            specs = _lock_key_specs(raw)
            name, rest = sca._yarn_spec_name(specs[0]) if specs else ("", "")
            cur = {"name": name, "version": "", "resolved": "", "integrity": "", "local": rest.startswith(_YARN_LOCAL)}
            continue
        if cur is None or not raw.startswith("  ") or raw.startswith("   "):
            continue
        key, _, value = raw.strip().partition(" ")
        value = value.strip().strip('"')
        if key in ("version", "resolved", "integrity"):
            cur[key] = value
        if key == "resolved" and value.startswith(_YARN_LOCAL):
            cur["local"] = True
    flush()
    return out


def yarn_berry_lock(text):
    """[{name, version, resolved, integrity, lock_digest, os, cpu, libc}] of
    a yarn 2+ lockfile. An npm package (resolution `name@npm:version`) is
    fetched from its registry (resolved ''), or from the tarball URL yarn
    recorded when that is not the registry's usual one (`::__archiveUrl=`);
    yarn's checksum is of its own zip of the tarball, so it is lock_digest,
    not integrity. Its `conditions` give os / cpu / libc. Other sources (git,
    a tarball URL) come without a digest; workspaces, links, portals, local
    files and patches (whose package is an entry of its own) are left
    out."""
    out, cur = [], None

    def flush():
        if not cur or not cur.get("resolution"):
            return
        res = cur["resolution"]
        m = _BERRY_NPM_RE.match(res)
        conditions = {"os": [], "cpu": [], "libc": []}
        for k, v in _BERRY_CONDITION_RE.findall(cur.get("conditions", "")):
            conditions[k].append(v)
        if m is not None:
            params = urllib.parse.parse_qs(m.group(3) or "")
            archive = (params.get("__archiveUrl") or [""])[0]
            checksum = cur.get("checksum", "")
            out.append(dict(conditions, name=m.group(1), version=cur.get("version") or m.group(2), resolved=archive,
                            integrity="", lock_digest=checksum or None))
            return
        at = res.find("@", 1)
        name, source = (res[:at], res[at + 1:]) if at > 0 else (res, "")
        if source.startswith(_YARN_LOCAL + ("patch:", "exec:")):
            return
        out.append(dict(conditions, name=name, version=cur.get("version", ""), resolved=source, integrity="",
                        lock_digest=None))

    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            flush()
            cur = None if raw.startswith("__metadata") else {}
            continue
        if cur is None or not raw.startswith("  ") or raw.startswith("   "):
            continue
        key, _, value = raw.strip().partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if key in ("version", "resolution", "checksum", "conditions"):
            cur[key] = value
    flush()
    return out


def bun_lock_entries(text):
    """[{name, version, resolved, integrity, os, cpu, libc}] of a text
    bun.lock (Bun 1.2+): an npm package is ["name@version", its tarball URL
    or '' for the registry's own, {…, os, cpu}, integrity]; git, GitHub and
    tarball-URL packages come without a digest; workspaces, links and local
    folders are left out. ValueError when it is not a bun.lock."""
    doc = sca.jsonc_loads(text or "")
    pkgs = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(pkgs, dict):
        raise ValueError("not a bun.lock")
    out = []
    for entry in pkgs.values():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        at = entry[0].find("@", 1)
        if at <= 0:
            continue
        name, spec = entry[0][:at], entry[0][at + 1:]
        if spec.startswith(sca._BUN_LOCAL):
            continue
        info = next((x for x in entry[1:] if isinstance(x, dict)), {})
        platform = {k: _strings(info.get(k)) for k in ("os", "cpu", "libc")}
        if spec[:1].isdigit():
            url = entry[1] if len(entry) > 1 and isinstance(entry[1], str) else ""
            integrity = entry[3] if len(entry) > 3 and isinstance(entry[3], str) else ""
            out.append(dict(platform, name=name, version=spec, resolved=url, integrity=integrity))
        else:
            out.append(dict(platform, name=name, version="", resolved=spec, integrity=""))
    return out


def node_modules_installed(root):
    """{(name, version)} of the packages in root's node_modules and those
    nested in it (sca's walk; links and dot folders are not followed)."""
    return {(n, v) for _eco, n, v, _where in sca.scan_npm_installed(root) if v}


def verify_locked(ctx, entries, env):
    """After the install: the lockfile's packages for this machine the guard
    neither checked nor noted fail the run (verify_installed)."""
    here = node_platform(env)
    verify_installed(ctx, {(e["name"], e["version"]) for e in entries
                           if e["version"] and platform_ok(e, here)}, "npm")


def yarn_major(exe, env, cwd):
    """The major version of the yarn that runs in cwd (a project's yarnPath
    or packageManager field can make it yarn 2+)."""
    try:
        out = subprocess.run([exe, "--version"], env=env, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=120).stdout.strip()
        return int(out.split(".")[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        raise GuardError("could not tell which yarn runs here (yarn --version failed)") from None


def guard_yarn(ctx, args):
    """yarn 1 and yarn 2+: resolve, check what the lockfile adds, then
    install."""
    sub = args[0] if args and not args[0].startswith("-") else "install"
    if sub == "global":
        raise GuardError("lazaret guard does not wrap `yarn global`; install into a project instead")
    exe = find_tool("yarn")
    cwd = os.getcwd()
    env = dict(os.environ)
    if yarn_major(exe, env, cwd) < 2:
        return guard_yarn_classic(ctx, exe, env, cwd, sub, list(args))
    return guard_yarn_berry(ctx, exe, env, cwd, sub, list(args))


def _yarn_workspaces(root):
    """The workspace folders root's package.json lists (its patterns)."""
    try:
        with open(os.path.join(root, "package.json"), encoding="utf-8") as f:
            spec = json.load(f).get("workspaces")
    except (OSError, ValueError, AttributeError):
        return []
    patterns = spec.get("packages") if isinstance(spec, dict) else spec
    out = []
    for p in patterns if isinstance(patterns, list) else []:
        if isinstance(p, str) and not os.path.isabs(p) and ".." not in p.replace("\\", "/").split("/"):
            out += [d for d in sorted(glob.glob(os.path.join(root, p))) if os.path.isfile(os.path.join(d, "package.json"))]
    return out[:5000]


def _yarn_classic_root(cwd):
    """The workspace root cwd belongs to (a package.json up from it whose
    workspaces list it), else cwd."""
    d = os.path.dirname(os.path.abspath(cwd))
    while True:
        if os.path.isfile(os.path.join(d, "package.json")) and any(
                _same_dir(w, cwd) for w in _yarn_workspaces(d)):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return cwd
        d = parent


_YARNRC_PATH_KEYS = ("yarn-path", "yarn-offline-mirror", "cache-folder", "global-folder")


def _copy_yarn_project(root, cwd, dest):
    """The files yarn 1 resolves from, copied into dest: the package.json
    files (the root's, its workspaces'), yarn.lock, and the .npmrc and
    .yarnrc of the root and of cwd (a relative path in .yarnrc made
    absolute)."""
    dirs = [root] + [w for w in _yarn_workspaces(root) if not _same_dir(w, root)]
    for d in dirs:
        rel = os.path.relpath(d, root)
        os.makedirs(os.path.join(dest, rel), exist_ok=True)
        shutil.copyfile(os.path.join(d, "package.json"), os.path.join(dest, rel, "package.json"))
    for d in dict.fromkeys([root, cwd]):
        rel = os.path.relpath(d, root)
        os.makedirs(os.path.join(dest, rel), exist_ok=True)
        names = [".npmrc", ".yarnrc"] + (["yarn.lock"] if d == root else [])
        for name in names:
            src = os.path.join(d, name)
            if not os.path.isfile(src):
                continue
            if name != ".yarnrc":
                shutil.copyfile(src, os.path.join(dest, rel, name))
                continue
            lines = []
            for line in (read_text(src) or "").splitlines():
                key, _, value = line.strip().partition(" ")
                value = value.strip().strip('"')
                if key.strip('"') in _YARNRC_PATH_KEYS and value and not os.path.isabs(value):
                    line = f'{key} {json.dumps(os.path.normpath(os.path.join(d, value)))}'
                lines.append(line)
            with open(os.path.join(dest, rel, name), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")


def guard_yarn_classic(ctx, exe, env, cwd, sub, args):
    """yarn 1 has no lockfile-only mode: it resolves and installs in a
    temporary copy of the project with scripts off (nothing of a package
    runs), and what that copy installed is checked against its yarn.lock.
    Then the command runs as given."""
    if sub not in YARN_CLASSIC_CMDS:
        raise GuardError(f"lazaret guard wraps yarn 1's install commands ({', '.join(sorted(YARN_CLASSIC_CMDS))}); "
                         f"`yarn global` is not wrapped: install into a project")
    if not os.path.isfile(os.path.join(cwd, "package.json")):
        raise GuardError("no package.json here: run it in the project")
    root = _yarn_classic_root(cwd)
    if not _same_dir(root, cwd):
        ctx.say(f"lazaret guard: yarn works in {root}")
    registries = Registries(pmsettings.yarn_classic_settings(exe, env, cwd), default=pmsettings.YARN_REGISTRY,
                            replace_npmjs=False)
    if ctx.cutoff is not None:
        ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are blocked "
                f"(yarn 1 has no setting to hold them back)")
    before_install = node_modules_installed(root)
    scratch = private_scratch("lazaret-guard-yarn-")
    try:
        _copy_yarn_project(root, cwd, scratch)
        where = os.path.normpath(os.path.join(scratch, os.path.relpath(cwd, root)))
        resolve = [exe] + (args if args and not args[0].startswith("-") else ["install"] + args) \
            + ["--ignore-scripts", "--non-interactive"]
        proc = run_tool(resolve, dict(env, npm_config_ignore_scripts="true"), cwd=where, capture=True)
        if proc.returncode != 0:
            show_failure(ctx, f"resolving (yarn {sub}, in a copy of the project)", proc)
            code = EXIT_RESOLVE
        else:
            lock = yarn_classic_lock(read_text(os.path.join(scratch, "yarn.lock")) or "")
            planned = node_modules_installed(scratch)
            entries = [lock[k] for k in sorted(planned) if k in lock]
            # a package with no entry of its own came inside another's tarball (bundled): checked with it
            ctx.expected |= {(_name_key("npm", n), v) for n, v in planned}
            code = check_lock_entries(ctx, entries, registries, before_install, "yarn.lock", env, rewrite=False)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if code is not None:
        return finish(ctx, installed=False, code=code)
    proc = run_tool([exe] + args, env, cwd=cwd)
    if proc.returncode == 0:
        verify_installed(ctx, node_modules_installed(root) - before_install, "npm")
    return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)


def _berry_age_gate(exe, env, cwd):
    """yarn 2+'s npmMinimalAgeGate in minutes (yarn 4.10+), else None."""
    got = pmsettings.run_json([exe, "config", "get", "npmMinimalAgeGate", "--json"], env, cwd)
    return got if isinstance(got, int) and not isinstance(got, bool) else None


def guard_yarn_berry(ctx, exe, env, cwd, sub, args):
    """yarn 2+: `--mode=update-lockfile` resolves (fetching what it adds
    into yarn's cache, linking and building nothing); the lockfile's new
    packages are checked; then the command runs as given."""
    if sub not in YARN_BERRY_CMDS:
        raise GuardError(f"lazaret guard wraps yarn's install commands ({', '.join(sorted(YARN_BERRY_CMDS))})")
    root = _find_up(cwd, ["yarn.lock"]) or cwd
    settings, creds = pmsettings.berry_settings(exe, env, cwd)
    registries = Registries(settings, default=pmsettings.YARN_REGISTRY, creds=creds, replace_npmjs=False)
    if ctx.cutoff is not None and not ctx.opts.allow_new:
        own = _berry_age_gate(exe, env, cwd)
        if own is not None:
            minutes = max(1, -(-ctx.min_age // 60))
            if own < minutes:
                env["YARN_NPM_MINIMAL_AGE_GATE"] = str(minutes)
            ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are held back "
                    f"(yarn npmMinimalAgeGate)")
    lock = os.path.join(root, "yarn.lock")
    snap = Snapshot([os.path.join(cwd, "package.json"), os.path.join(root, "package.json"), lock,
                     os.path.join(root, ".yarn", "install-state.gz")])
    yarn_dir, cache = os.path.join(root, ".yarn"), os.path.join(root, ".yarn", "cache")
    had_yarn_dir = os.path.isdir(yarn_dir)
    cached_before = set(os.listdir(cache)) if os.path.isdir(cache) else set()
    before_install = node_modules_installed(root) \
        if os.path.exists(os.path.join(root, "node_modules", ".yarn-state.yml")) else set()
    try:
        resolve = [exe] + (args if args and not args[0].startswith("-") else ["install"] + args) \
            + ["--mode=update-lockfile"]
        proc = run_tool(resolve, dict(env, YARN_ENABLE_SCRIPTS="false"), cwd=cwd, capture=True)
        if proc.returncode != 0:
            show_failure(ctx, f"resolving (yarn {sub} --mode=update-lockfile)", proc)
            code = EXIT_RESOLVE
        else:
            entries = yarn_berry_lock(read_text(lock) or "")
            code = check_lock_entries(ctx, entries, registries, before_install, "yarn.lock", env, rewrite=False)
    except BaseException:
        snap.restore()
        raise
    if code is not None:
        restored = snap.restore()
        if not had_yarn_dir and os.path.isdir(yarn_dir):
            shutil.rmtree(yarn_dir, ignore_errors=True)         # all of it came from the resolution
            restored.append(".yarn")
        elif os.path.isdir(cache):
            added = sorted(set(os.listdir(cache)) - cached_before)
            for name in added:                     # what the resolution fetched into the project's cache
                try:
                    os.remove(os.path.join(cache, name))
                except OSError:
                    pass
            if added:
                restored.append(f".yarn/cache ({plural(len(added), 'file')})")
        return finish(ctx, installed=False, restored=restored, code=code)
    proc = run_tool([exe] + args, env, cwd=cwd)
    if proc.returncode == 0:
        verify_locked(ctx, yarn_berry_lock(read_text(lock) or ""), env)
    return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)


def _bun_age_flag(exe, env):
    """Does this bun take --minimum-release-age (Bun 1.3+)?"""
    try:
        out = subprocess.run([exe, "install", "--help"], env=env, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "--minimum-release-age" in out


def guard_bun(ctx, args):
    """Bun: `--lockfile-only` resolves (installing nothing, scripts off);
    what bun.lock adds is checked; then the command runs as given."""
    sub = args[0] if args and not args[0].startswith("-") else "install"
    if sub not in BUN_CMDS:
        raise GuardError(f"lazaret guard wraps bun's install commands ({', '.join(sorted(BUN_CMDS))})")
    if any(a in _GLOBAL_FLAGS for a in args):
        raise GuardError("lazaret guard does not wrap bun's global installs; install into a project instead")
    if "--no-verify" in args:
        raise GuardError("--no-verify: bun would not check the packages' digests, so the guard's check "
                         "would say nothing about what it installs")
    exe = find_tool("bun")
    cwd = os.getcwd()
    env = dict(os.environ)
    root = _find_up(cwd, ["bun.lock", "bun.lockb"]) or cwd
    lock = os.path.join(root, "bun.lock")
    if os.path.exists(os.path.join(root, "bun.lockb")) and not os.path.exists(lock):
        raise GuardError("the guard reads bun.lock (Bun 1.2+), not bun.lockb: convert it first with "
                         "`bun install --save-text-lockfile --lockfile-only`")
    settings, creds = pmsettings.bun_settings(env, cwd)
    registries = Registries(settings, creds=creds, replace_npmjs=False)
    args = list(args)
    if ctx.cutoff is not None and not ctx.opts.allow_new and sub in ("install", "i", "add", "a", "update") \
            and _bun_age_flag(exe, env):
        if not any(a.startswith("--minimum-release-age") for a in args):
            args.append(f"--minimum-release-age={ctx.min_age}")
        ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are held back "
                f"(bun --minimum-release-age)")
    snap = Snapshot([os.path.join(cwd, "package.json"), os.path.join(root, "package.json"), lock])
    before_install = node_modules_installed(root)
    try:
        resolve = [exe] + (args if args and not args[0].startswith("-") else ["install"] + args) \
            + ["--lockfile-only", "--ignore-scripts"]
        proc = run_tool(resolve, env, cwd=cwd, capture=True)
        if proc.returncode != 0:
            show_failure(ctx, f"resolving (bun {sub} --lockfile-only)", proc)
            code = EXIT_RESOLVE
        else:
            try:
                entries = bun_lock_entries(read_text(lock) or "")
            except ValueError:
                raise GuardError(f"bun wrote no bun.lock to check (looked in {root})") from None
            code = check_lock_entries(ctx, entries, registries, before_install, "bun.lock", env, rewrite=False)
    except BaseException:
        snap.restore()
        raise
    if code is not None:
        return finish(ctx, installed=False, restored=snap.restore(), code=code)
    proc = run_tool([exe] + args, env, cwd=cwd)
    if proc.returncode == 0:
        try:
            verify_locked(ctx, bun_lock_entries(read_text(lock) or ""), env)
        except ValueError:
            pass
    return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)


def uv_lock_args(args):
    """The options of a `uv sync` command line that `uv lock` takes too."""
    out, i = [], 1
    while i < len(args):
        a = args[i]
        if a in _UV_LOCK_FLAGS or re.fullmatch(r"-[qv]{2,}", a):
            out.append(a)
        elif a.split("=", 1)[0] in _UV_LOCK_OPTIONS:
            if "=" in a:
                out.append(a)
            elif i + 1 < len(args):
                out += [a, args[i + 1]]
                i += 1
        elif len(a) > 2 and a[:2] in ("-P", "-p", "-C", "-i", "-f"):
            out.append(a)
        i += 1
    return out


def strip_uv_upgrade(args):
    """A uv command line without --upgrade / --upgrade-package (the lockfile
    already has the upgrade, checked)."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in ("-P", "--upgrade-package"):
            skip = True
        elif not (a in ("-U", "--upgrade") or a.startswith("--upgrade-package=")
                  or (a.startswith("-P") and len(a) > 2)):
            out.append(a)
    return out


def _option_value(args, names):
    for k, a in enumerate(args):
        if a in names and k + 1 < len(args):
            return args[k + 1]
        for n in names:
            if n.startswith("--") and a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def uv_python(exe, args, env, cwd):
    """The interpreter uv installs for (`uv python find`, with --python when given)."""
    request = _option_value(args, ("-p", "--python"))
    cmd = [exe, "python", "find"] + ([request] if request else []) + (["--system"] if "--system" in args else [])
    try:
        found = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        found = ""
    return found or None


def _uv_workspace_root(d):
    text = read_text(os.path.join(d, "pyproject.toml")) or ""
    return "[tool.uv.workspace]" in text


def guard_uv_project(ctx, args):
    """uv add / sync / lock: lock first (uv.lock), check what it adds, then run."""
    sub = args[0]
    if "--script" in args or any(a.startswith("--script=") for a in args):
        raise GuardError("lazaret guard does not wrap uv's --script commands")
    exe = find_tool("uv")
    project = _option_value(args, ("--project", "--directory"))
    root = _find_up(os.path.abspath(project) if project else os.getcwd(), ["pyproject.toml"])
    if root is None:
        raise GuardError("no pyproject.toml here or above: run it in the project")
    lock_dir = root
    if not os.path.exists(os.path.join(root, "uv.lock")):
        lock_dir = _find_up(os.path.dirname(root), ["pyproject.toml"], _uv_workspace_root) or root
    env = dict(os.environ)
    lock = os.path.join(lock_dir, "uv.lock")
    venv = os.environ.get("UV_PROJECT_ENVIRONMENT") or ".venv"
    venv = venv if os.path.isabs(venv) else os.path.join(lock_dir, venv)
    snap = Snapshot([os.path.join(root, "pyproject.toml"), lock])
    before_install = installed_python(venv_site_dirs(venv))
    try:
        code, new = _check_uv(ctx, exe, sub, args, env, root, lock, before_install)
    except BaseException:
        snap.restore()
        raise
    if code is not None:
        return finish(ctx, installed=False, restored=snap.restore(), code=code)
    if sub == "lock":
        return finish(ctx, installed=False, code=EXIT_OK)
    final = strip_uv_upgrade(args) if sub == "sync" else list(args)
    proc = run_tool([exe] + final, env, cwd=os.getcwd())
    if proc.returncode == 0:
        local = {pep503(p["name"]) for p in new if p["source"] == "local"}
        verify_installed(ctx, {x for x in installed_python(venv_site_dirs(venv)) - before_install
                               if x[0] not in local}, "pypi")
    return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)


def _check_uv(ctx, exe, sub, args, env, root, lock, installed):
    """Resolve, then check what the lockfile adds. -> (None to go on, else
    the exit code; the new lockfile's packages)."""
    old = uv_lock_packages(read_text(lock) or "")
    frozen = any(a in ("--frozen", "--locked") for a in args)
    if ctx.cutoff is not None:
        ctx.say(f"lazaret guard: files uploaded less than {format_age(ctx.min_age)} ago are blocked "
                f"(uv's own exclude-newer would be written into uv.lock)")
    if not (sub == "sync" and frozen):
        if sub == "add":
            resolve = [exe] + list(args) + ([] if "--no-sync" in args else ["--no-sync"])
        elif sub == "sync":
            resolve = [exe, "lock"] + uv_lock_args(args)
        else:
            resolve = [exe] + list(args)
        proc = run_tool(resolve, env, cwd=os.getcwd(), capture=True)
        if proc.returncode != 0:
            show_failure(ctx, f"resolving (uv {sub})", proc)
            return EXIT_RESOLVE, []
    new = uv_lock_packages(read_text(lock) or "")
    baseline = {(pep503(p["name"]), p["version"]) for p in old} if sub == "lock" else installed
    info = interpreter_info(uv_python(exe, args, env, root))
    ctx.expected |= {(pep503(p["name"]), p["version"]) for p in new}
    todo = [p for p in new if p["source"] != "local" and (pep503(p["name"]), p["version"]) not in baseline]
    # the indexes of uv's settings give the credentials for their hosts (and .netrc for any)
    indexes = pmsettings.uv_indexes(env, root)
    urls = [f["url"] for p in todo for f in ([p["sdist"]] if p["sdist"] else []) + p["wheels"]]
    creds = pmsettings.index_credentials(indexes, env, hosts=urls)
    http_hosts = {netloc(i.url) for i in indexes if i.url.startswith("http://")}
    fetcher = Fetcher({"pypi.org"}, http_hosts=http_hosts, auth=creds, keepalive=ctx.keepalive)
    jobs = []
    for p in todo:
        if p["source"] != "registry":
            ctx.add(Check("pypi", p["name"], p["version"], f"{p['source']} source")).notes.append(
                "not from a registry (git, a URL or a local file): not checked")
            continue
        for f in pick_artifacts(([p["sdist"]] if p["sdist"] else []) + p["wheels"], info):
            if not (fetchable(f["url"]) or netloc(f["url"]) in http_hosts):
                ctx.block(ctx.add(Check("pypi", p["name"], p["version"], f["filename"])),
                          f"could not be checked: not fetched over https ({pmsettings.shown(f['url'])[:80]})")
                continue
            fetcher.allow(f["url"])
            jobs.append(lambda p=p, f=f: check_file(ctx, fetcher, p["name"], p["version"], f))
    ctx.say(f"lazaret guard: {plural(len(todo), 'package')} to check (uv.lock)")
    try:
        run_all(jobs)
    finally:
        fetcher.close()
    if ctx.blocked():
        return EXIT_BLOCKED, new
    return (EXIT_OK if ctx.opts.plan else None), new


def _requirement_files(args):
    """The requirement and constraint files named on a pip command line."""
    out = []
    for k, a in enumerate(args):
        if a in ("-r", "--requirement", "-c", "--constraint") and k + 1 < len(args):
            out.append(args[k + 1])
        elif a.startswith(("--requirement=", "--constraint=")):
            out.append(a.split("=", 1)[1])
        elif a.startswith(("-r", "-c")) and len(a) > 2 and not a.startswith("--"):
            out.append(a[2:])
    return out


def check_pip_arguments(args, base=None, depth=0):
    """Refuse options that point pip or uv at local archives or at no index
    (-f, --no-index), and index options inside the requirement files it
    names (and those they include): pip would use those itself, and packages
    from there would not pass the guard. (Index options on the command line
    are the guard's to relay: take_index_options.)"""
    for a in args:
        if a in PIP_INDEX_OPTIONS or a.startswith(tuple(o + "=" for o in PIP_INDEX_OPTIONS if o.startswith("--"))) \
                or (a.startswith(("-i", "-f")) and not a.startswith("--") and len(a) > 2):
            raise GuardError(f"{a.split('=')[0]}: lazaret guard serves the packages itself, from the indexes "
                             f"the tool is set to use; install without local archives")
    if depth > 5:
        return
    for req in _requirement_files(args):
        path = os.path.join(base or os.getcwd(), req)
        text = read_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            if _PIP_REQ_OPTION_RE.match(line):
                raise GuardError(f"{req}: {line.strip()[:80]} — lazaret guard serves the index itself; "
                                 f"move index options to the command line or the tool's settings")
            m = _PIP_REQ_INCLUDE_RE.match(line)
            if m:
                check_pip_arguments(["-r", m.group(1)], os.path.dirname(path), depth + 1)


#: Index options of the command line the guard relays: pip's, and uv's too
_PIP_TAKE = {"-i": "default", "--index-url": "default", "--extra-index-url": "extra"}
_UV_TAKE = dict(_PIP_TAKE, **{"--default-index": "default", "--index": "index", "--index-strategy": "strategy"})


def take_index_options(args, uv=False):
    """(args without their index options, the default index they name or
    None, the other indexes they name, uv's --index-strategy or None): the
    guard relays these indexes itself."""
    take = _UV_TAKE if uv else _PIP_TAKE
    out, default, extras, strategy = [], None, [], None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out += args[i:]
            break
        name, eq, value = a.partition("=") if a.startswith("--") else (a, "", "")
        if a.startswith("-i") and not a.startswith("--") and len(a) > 2:
            name, eq, value = "-i", "=", a[2:]
        kind = take.get(name)
        if kind is None or (not eq and i + 1 >= len(args)):
            out.append(a)
            i += 1
            continue
        if not eq:
            value = args[i + 1]
            i += 1
        i += 1
        if kind == "default":
            default = pmsettings.Index(value, default=True)
        elif kind == "extra":
            extras.append(pmsettings.Index(value))
        elif kind == "index":
            extras.append(pmsettings._uv_index_value(value))
        else:
            strategy = value
    return out, default, extras, strategy


def python_indexes(kind, exe, env, cwd, cli_default=None, cli_extras=(), cli_strategy=None):
    """(the indexes to relay, in the tool's order; merge them (pip's rule,
    or uv's unsafe strategies) or take the first that has a project (uv's
    first-index); their Credentials). kind: 'pip', 'uv-pip' or 'uv'. The
    command line's index options come first; LAZARET_GUARD_PYPI_URL stands
    for the tool's settings."""
    explicit = os.environ.get("LAZARET_GUARD_PYPI_URL")
    explicit = [pmsettings.Index(explicit, default=True)] if explicit else None
    if kind == "pip":
        found = explicit or pmsettings.pip_indexes(exe, env, cwd)
        indexes, merge = [cli_default or found[0]] + found[1:] + list(cli_extras), True
    else:
        found = explicit or pmsettings.uv_indexes(env, cwd, pip=kind == "uv-pip")
        indexes = list(cli_extras) + found[:-1] + [cli_default or found[-1]]
        strategy = cli_strategy or pmsettings.uv_index_strategy(env, cwd, pip=kind == "uv-pip")
        merge = strategy != "first-index"
    seen, unique = set(), []
    for index in indexes:
        key = pmsettings.shown(index.url)
        if key not in seen:
            seen.add(key)
            unique.append(index)
    creds = pmsettings.index_credentials(unique, env)
    for index in unique:
        if not (fetchable(index.url) or index.url.startswith("http://")):
            raise GuardError(f"{pmsettings.shown(index.url)}: lazaret guard relays https indexes "
                             f"(or http ones in the tool's settings)")
    return unique, merge, creds


class LocalIndex:
    """The local index (PypiIndex behind make_index_server) for one command:
    `with LocalIndex(ctx, indexes, merge, creds) as li:` — li.index,
    li.base (http://127.0.0.1:port/<the run's secret segment>), li.tool_env(env, uv)."""

    def __init__(self, ctx, indexes, merge, creds):
        self.spool = tempfile.mkdtemp(prefix="lazaret-guard-")
        http_hosts = {netloc(i.url) for i in indexes if i.url.startswith("http://")}
        fetcher = Fetcher({netloc(i.url) for i in indexes}, http_hosts=http_hosts, auth=creds, keepalive=ctx.keepalive)
        self.fetcher = fetcher
        self.index = PypiIndex(ctx, fetcher, self.spool, indexes=indexes, merge=merge)
        self.gate = LocalGate()
        self.index.prefix = "/" + self.gate.token
        self.server = make_index_server(self.index, self.gate)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.base = self.gate.bind(self.port)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.fetcher.close()
        shutil.rmtree(self.spool, ignore_errors=True)

    def tool_env(self, env, uv):
        """The tool's environment, pointed at this index alone. uv: as its
        first index (UV_INDEX, which comes before any in its settings files,
        and this index answers every project, so uv asks no other) and as its
        default; pip: its index-url (an extra-index-url in its settings files
        is still read by pip, and a file it takes from there blocks the
        install: _pip_plan)."""
        env = dict(env)
        if uv:
            for k in ("UV_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS", "UV_NO_INDEX", "UV_DEFAULT_INDEX",
                      "UV_INDEX_URL", "UV_INDEX_STRATEGY"):
                env.pop(k, None)
            env.update(UV_INDEX=f"lazaret-guard={self.base}/simple", UV_DEFAULT_INDEX=self.base + "/simple",
                       UV_INDEX_STRATEGY="first-index", UV_HTTP_TIMEOUT=str(TOOL_TIMEOUT))
        else:
            for k in ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX"):
                env.pop(k, None)
            env.update(PIP_INDEX_URL=self.base + "/simple/", PIP_TRUSTED_HOST=f"127.0.0.1:{self.port}",
                       PIP_DEFAULT_TIMEOUT=str(TOOL_TIMEOUT))
        return env


def _say_indexes(ctx, indexes):
    if len(indexes) > 1 or indexes[0].url != PYPI_SIMPLE:
        ctx.say("lazaret guard: relaying " + ", ".join(pmsettings.shown(i.url) for i in indexes))


def _pip_plan(ctx, index, base, exe, pip_args, env):
    """pip: resolve (--dry-run --report) and scan every file of the plan.
    -> an exit code, or None to go on."""
    report_path = os.path.join(index.spool, "plan.json")
    proc = run_tool([exe] + pip_args + ["--dry-run", "--quiet", "--report", report_path], env, capture=True)
    if proc.returncode != 0:
        if ctx.blocked():
            return EXIT_BLOCKED
        show_failure(ctx, "resolving (pip install --dry-run)", proc)
        return EXIT_RESOLVE
    try:
        with open(report_path, encoding="utf-8") as f:
            plan = json.load(f)
    except (OSError, ValueError) as exc:
        raise GuardError(f"pip wrote no plan to check ({exc})") from None
    items = plan.get("install") if isinstance(plan, dict) and isinstance(plan.get("install"), list) else []
    jobs, numbers, whole = [], [], True
    for item in items:
        info = item.get("download_info") if isinstance(item, dict) else None
        url = info.get("url") if isinstance(info, dict) and isinstance(info.get("url"), str) else ""
        meta = item.get("metadata") if isinstance(item, dict) and isinstance(item.get("metadata"), dict) else {}
        m = _FILE_PATH_RE.match(url[len(base):].split("?", 1)[0].split("#", 1)[0]) if url.startswith(base + "/files/") else None
        if m is not None and m.group(1) in index.files:
            jobs.append(lambda n=m.group(1): index.scan(n))
            numbers.append(m.group(1))
            continue
        whole = False
        c = ctx.add(Check("pypi", str(meta.get("name", url)), str(meta.get("version", "")), pmsettings.shown(url)))
        if isinstance(info, dict) and ("vcs_info" in info or "dir_info" in info or url.startswith("file:")):
            c.notes.append("a local or version-control source: not checked")
        else:
            ctx.block(c, "not downloaded through lazaret guard's index (an extra-index-url or find-links in "
                         "pip's configuration files?), so not checked")
    ctx.say(f"lazaret guard: {plural(len(items), 'package')} to check (pip's plan)")
    index.planned = numbers if whole and numbers else None
    run_all(jobs)
    return None


def _plan_folder(ctx, index):
    """--from-plan: the files of pip's plan, as the guard scanned them, in a
    folder of their own that pip installs from instead of resolving and
    downloading everything again. Each file is hashed once more and must still
    be the one that was scanned; one that is not is blocked. -> the folder, or
    None (and pip goes to the index as it always did) when the plan holds a
    file pip needs the index for: a source distribution builds with
    requirements the index serves, and a file too large to scan is relayed as
    it comes."""
    numbers = index.planned
    if not numbers:
        return None
    rows = []
    for n in numbers:
        info = index.files[n]
        with index.lock:
            check, spooled = index.results.get(n, (None, None))
        name = info["filename"]
        if not name.lower().endswith(".whl"):
            why = f"{name} is a source distribution, which builds with requirements the index serves"
        elif check is None or check.blocked or spooled is None or not check.digest.startswith("sha256:"):
            why = f"{name} was not scanned in full (too large, or not fetched)"
        elif any(name == r[0] for r in rows):
            why = f"{name} is in the plan twice"
        else:
            rows.append((name, spooled, check))
            continue
        ctx.say(f"lazaret guard: --from-plan: {why}, so pip installs through the index")
        return None
    folder = os.path.join(index.spool, "plan")
    try:
        os.mkdir(folder, 0o700)
        for name, spooled, check in rows:
            dest = os.path.join(folder, name)
            try:
                os.link(spooled, dest)
            except OSError:
                shutil.copyfile(spooled, dest)
            digest = hashlib.sha256()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            if "sha256:" + digest.hexdigest() != check.digest:
                # not ctx.block: --trust is for findings someone reviewed, not for a file that is not the one scanned
                check.blocked.append("the file changed between the plan and the install "
                                     "(its SHA-256 is no longer the one it was scanned with)")
    except OSError as exc:
        ctx.say(f"lazaret guard: --from-plan: could not set the folder up ({exc.strerror or exc}), so pip "
                f"installs through the index")
        return None
    if ctx.blocked():
        return None
    ctx.say(f"lazaret guard: installing the {plural(len(rows), 'file')} it checked, from a folder (--from-plan)")
    return folder


_UV_PLAN_URL_RE = re.compile(r"^\s*\+\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+@\s+(\S+)")


def _uv_plan_jobs(ctx, index, planned, urls, info):
    """Scan jobs for a uv plan: the files the index served for each
    name==version (those a uv here may install); a package it did not serve
    came from elsewhere and blocks; a URL, path or git source is noted."""
    jobs = []
    for name, version in planned:
        files = index.release_files(name, version)
        if not files:
            ctx.block(ctx.add(Check("pypi", name, version, "")),
                      "not served by lazaret guard's index, so not checked")
            continue
        picked = {f["filename"] for f in pick_artifacts([i for _, i in files], info)}
        jobs += [lambda n=n: index.scan(n) for n, i in files if i["filename"] in picked]
    for name, url in urls:
        ctx.add(Check("pypi", name, "", pmsettings.shown(url))).notes.append(
            "a local, URL or version-control source: not checked")
    return jobs


def _uv_pip_plan(ctx, index, exe, pip_args, env):
    """uv pip: resolve (--dry-run) and scan the files of the packages it
    would install. -> an exit code, or None to go on."""
    proc = run_tool([exe, "pip"] + pip_args + ["--dry-run"], env, capture=True)
    if proc.returncode != 0:
        if ctx.blocked():
            return EXIT_BLOCKED
        show_failure(ctx, f"resolving (uv pip {pip_args[0]} --dry-run)", proc)
        return EXIT_RESOLVE
    lines = (proc.stdout or "").splitlines()
    planned = [(m.group(1), m.group(2)) for m in map(_UV_PLAN_LINE_RE.match, lines) if m]
    urls = [(m.group(1), m.group(2)) for m in map(_UV_PLAN_URL_RE.match, lines) if m]
    info = interpreter_info(uv_python(exe, pip_args, env, os.getcwd()))
    jobs = _uv_plan_jobs(ctx, index, planned, urls, info)
    ctx.say(f"lazaret guard: {plural(len(planned), 'package')} to check (uv's plan)")
    run_all(jobs)
    return None


def guard_pip(ctx, tool, args):
    """pip install, uv pip install and uv pip sync, through the local index."""
    uv = tool == "uv"
    pip_args = args[1:] if uv else list(args)
    if not pip_args or pip_args[0] not in (("install", "sync") if uv else ("install",)):
        raise GuardError("lazaret guard wraps `pip install`, `uv pip install` and `uv pip sync`")
    rest, cli_default, cli_extras, cli_strategy = take_index_options(pip_args[1:], uv)
    check_pip_arguments(rest)
    pip_args = [pip_args[0]] + rest
    exe = find_tool("uv" if uv else tool)
    cwd = os.getcwd()
    env = dict(os.environ)
    indexes, merge, creds = python_indexes("uv-pip" if uv else "pip", exe, env, cwd, cli_default, cli_extras,
                                           cli_strategy)
    with LocalIndex(ctx, indexes, merge, creds) as li:
        _say_indexes(ctx, indexes)
        env = li.tool_env(env, uv)
        if ctx.cutoff is not None:
            ctx.say(f"lazaret guard: files uploaded less than {format_age(ctx.min_age)} ago are left out of "
                    f"the index")
        code = _uv_pip_plan(ctx, li.index, exe, pip_args, env) if uv \
            else _pip_plan(ctx, li.index, li.base, exe, pip_args, env)
        if code is None and ctx.blocked():
            code = EXIT_BLOCKED
        if code is None and ctx.opts.plan:
            code = EXIT_OK
        folder = None
        if code is None and not uv and getattr(ctx.opts, "from_plan", False):
            folder = _plan_folder(ctx, li.index)
            if ctx.blocked():
                code = EXIT_BLOCKED
        if code is not None:
            return finish(ctx, installed=False, index=li.index, code=code)
        if folder is None:
            argv = ([exe, "pip"] if uv else [exe]) + pip_args
        else:
            argv = [exe, pip_args[0], "--no-index", "--find-links", folder] + pip_args[1:]
            env = {k: v for k, v in env.items() if k not in ("PIP_INDEX_URL", "PIP_TRUSTED_HOST")}
        proc = run_tool(argv, env)
        blocked = bool(ctx.blocked())
        return finish(ctx, installed=proc.returncode == 0 and not blocked, index=li.index,
                      code=EXIT_BLOCKED if blocked else proc.returncode)


# ---------------- uvx, uv tool and uv run (0.1.8) ----------------
#: Options of `uv tool run` / `uv tool install` / `uv run` that take a value
_UV_VALUE_OPTIONS = frozenset((
    "--from", "-w", "--with", "--with-editable", "--with-requirements", "-c", "--constraints", "-b",
    "--build-constraints", "--overrides", "--env-file", "--python-platform", "--index", "--default-index", "-i",
    "--index-url", "--extra-index-url", "-f", "--find-links", "--index-strategy", "--keyring-provider", "-P",
    "--upgrade-package", "--resolution", "--prerelease", "--fork-strategy", "--exclude-newer",
    "--exclude-newer-package", "--reinstall-package", "--link-mode", "-C", "--config-setting",
    "--config-settings-package", "--no-build-isolation-package", "--no-build-package", "--no-binary-package",
    "--cache-dir", "--refresh-package", "-p", "--python", "--color", "--allow-insecure-host", "--directory",
    "--project", "--config-file", "--torch-backend", "--with-executables-from", "--extra", "--group",
    "--only-group", "--no-group", "--package", "--no-extra", "--python-preference", "-e", "--editable",
    "--no-dev", "--script",
))
#: ... of these, the flags (no value): --no-dev, --script and -e/--editable take none in some commands
_UV_FLAG_LIKE = frozenset(("--no-dev", "--script", "-e", "--editable"))
_UV_SHORT_VALUE = ("-w", "-c", "-b", "-i", "-f", "-P", "-C", "-p")
_PYTHON_COMMAND_RE = re.compile(r"^python(?:\d+(?:\.\d+)*)?(?:\.exe)?$")


def split_uv_args(args, flags=_UV_FLAG_LIKE):
    """(options before the first positional argument, the positional, what
    follows it) of a uv command line (clap's trailing arguments)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[:i], (args[i + 1] if i + 1 < len(args) else None), args[i + 2:]
        if not a.startswith("-") or a == "-":
            return args[:i], a, args[i + 1:]
        if a in _UV_VALUE_OPTIONS and a not in flags:
            i += 2
            continue
        i += 1
    return args, None, []


def _option_values(opts, names):
    """Every value the options `names` take in opts."""
    out = []
    for k, a in enumerate(opts):
        if a in names and k + 1 < len(opts):
            out.append(opts[k + 1])
        for n in names:
            if n.startswith("--") and a.startswith(n + "="):
                out.append(a.split("=", 1)[1])
            elif not n.startswith("--") and a.startswith(n) and len(a) > len(n) and a not in _UV_VALUE_OPTIONS:
                out.append(a[len(n):])
    return out


def _split_with(value):
    """uv's --with a,b (not the commas inside an extras list)."""
    parts, depth, cur = [], 0, ""
    for ch in value:
        depth += ch == "["
        depth -= ch == "]"
        if ch == "," and depth <= 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return [p for p in parts if p]


# a requirement that is a path, a URL or a git source (PEP 508's `name @ url` too, not uvx's `name@1.2`)
_REQ_LOCAL_RE = re.compile(r"(?:^[.~/\\]|^[A-Za-z]:[\\/]|://|^git\+|@\s*(?:[A-Za-z][A-Za-z0-9+.-]*:|[.~/\\]))")


def _tool_requirements(opts, command, install):
    """(registry requirements, local / URL / git ones) of a uv tool command:
    --from, or the command itself (`name@version` pins it; `python` is no
    package), --with (commas), --with-requirements files."""
    reqs = []
    source = _option_values(opts, ("--from",))
    if source:
        reqs.append(source[-1])
    elif command and (install or not _PYTHON_COMMAND_RE.match(command)):
        name, at, version = command.partition("@")
        if _REQ_LOCAL_RE.search(command) or not at:
            reqs.append(command)
        else:
            reqs.append(name if version == "latest" else f"{name}=={version}")
    for value in _option_values(opts, ("-w", "--with")):
        reqs += _split_with(value)
    for path in _option_values(opts, ("--with-requirements",)):
        check_pip_arguments(["-r", path])
        for line in (read_text(path) or "").splitlines():
            line = line.split(" #", 1)[0].strip()
            if line and not line.startswith(("#", "-")):
                reqs.append(line)
    local = [r for r in reqs if _REQ_LOCAL_RE.search(r)] + _option_values(opts, ("--with-editable",))
    return [r for r in reqs if not _REQ_LOCAL_RE.search(r)], local


_UV_COMPILE_PASS = ("-c", "--constraints", "--overrides", "-b", "--build-constraints", "--prerelease",
                    "--resolution", "--fork-strategy", "--exclude-newer", "--exclude-newer-package",
                    "--python-platform", "--no-build-package", "--no-binary-package", "-C", "--config-setting")
_UV_COMPILE_FLAGS = ("--no-build", "--no-binary", "--no-sources", "--pre")


def _uv_tool_plan(ctx, li, exe, env, opts, reqs, python):
    """Resolve the tool's requirements through the local index (`uv pip
    compile`: metadata only, and every file it downloads is scanned first)
    and scan the files of the plan. -> an exit code, or None to go on."""
    work = tempfile.mkdtemp(prefix="lazaret-guard-plan-", dir=li.spool)
    req_path, out_path = os.path.join(work, "requirements.in"), os.path.join(work, "plan.txt")
    with open(req_path, "w", encoding="utf-8") as f:
        f.write("\n".join(reqs) + "\n")
    passed = []
    for k, a in enumerate(opts):
        if a in _UV_COMPILE_PASS and k + 1 < len(opts):
            passed += [a, opts[k + 1]]
        elif a.split("=", 1)[0] in _UV_COMPILE_PASS and "=" in a or a in _UV_COMPILE_FLAGS:
            passed.append(a)
    cmd = [exe, "pip", "compile", req_path, "-o", out_path, "--quiet", "--no-header", "--no-annotate"] + passed \
        + (["--python", python] if python else [])
    proc = run_tool(cmd, env, capture=True)
    if proc.returncode != 0:
        if ctx.blocked():
            return EXIT_BLOCKED
        show_failure(ctx, "resolving (uv pip compile)", proc)
        return EXIT_RESOLVE
    lines = (read_text(out_path) or "").splitlines()
    planned = [(m.group(1), m.group(2)) for m in (re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", ln)
                                                  for ln in lines) if m]
    jobs = _uv_plan_jobs(ctx, li.index, planned, [], interpreter_info(python))
    ctx.say(f"lazaret guard: {plural(len(planned), 'package')} to check (uv's plan)")
    run_all(jobs)
    return None


def guard_uv_tool(ctx, args, via_uvx):
    """uvx / uv tool run / uv tool install, through the local index: the
    tool's requirements are resolved and their files scanned first (a
    plan), then the command runs as given with every download served —
    scanned — by the guard's index. `uvx python` and a tool installed
    already download nothing."""
    install = not via_uvx and args[1] == "install"
    rest = list(args if via_uvx else args[2:])
    opts, command, trailing = split_uv_args(rest)
    if install:
        opts, trailing = opts + trailing, []                   # (install: options may follow the package)
    kept, cli_default, cli_extras, cli_strategy = take_index_options(opts, uv=True)
    check_pip_arguments(kept)
    exe = find_tool("uv")
    cwd = os.getcwd()
    env = dict(os.environ)
    if command is None:
        raise GuardError("name the tool to run or install: lazaret guard uvx ruff …")
    reqs, local = _tool_requirements(kept, command, install)
    indexes, merge, creds = python_indexes("uv", exe, env, cwd, cli_default, cli_extras, cli_strategy)
    with LocalIndex(ctx, indexes, merge, creds) as li:
        _say_indexes(ctx, indexes)
        env = li.tool_env(env, uv=True)
        for r in local:
            ctx.add(Check("pypi", r, "", r)).notes.append("a local, URL or version-control source: not checked")
        code = None
        if reqs:
            python = uv_python(exe, kept, env, cwd)
            code = _uv_tool_plan(ctx, li, exe, env, kept, reqs, python)
        if code is None and ctx.blocked():
            code = EXIT_BLOCKED
        if code is None and ctx.opts.plan:
            code = EXIT_OK
        if code is not None:
            return finish(ctx, installed=False, index=li.index, code=code)
        head = ["tool", "install"] if install else ["tool", "run"]
        proc = run_tool([exe] + head + kept + [command] + trailing, env, cwd=cwd)
        blocked = bool(ctx.blocked())
        return finish(ctx, installed=proc.returncode == 0 and not blocked, index=li.index,
                      code=EXIT_BLOCKED if blocked else proc.returncode)


def guard_uv_run(ctx, args):
    """uv run: in a project, its environment is synced from uv.lock first —
    checked as `uv sync` is — and the command then runs with --frozen (the
    lockfile just checked); what else it installs (--with, a script's own
    dependencies) comes through the local index, scanned before uv gets it."""
    opts, command, trailing = split_uv_args(list(args[1:]))
    kept, cli_default, cli_extras, cli_strategy = take_index_options(opts, uv=True)
    check_pip_arguments(kept)
    exe = find_tool("uv")
    cwd = os.getcwd()
    env = dict(os.environ)
    project_dir = _option_value(kept, ("--project", "--directory"))
    script = "--script" in kept or ((command or "").endswith(".py") and "# /// script" in (read_text(command) or ""))
    found = _find_up(os.path.abspath(project_dir) if project_dir else cwd, ["pyproject.toml"])
    in_project = not script and "--no-project" not in kept and "--isolated" not in kept and found is not None \
        and re.search(r"(?m)^\[(?:project|tool\.uv\.workspace)\]", read_text(os.path.join(found, "pyproject.toml"))
                      or "") is not None
    frozen = any(a in ("--frozen", "--locked") for a in kept)
    run_opts = list(kept)
    if in_project and "--no-sync" not in kept:
        root = found
        lock_dir = root if os.path.exists(os.path.join(root, "uv.lock")) else \
            (_find_up(os.path.dirname(root), ["pyproject.toml"], _uv_workspace_root) or root)
        lock = os.path.join(lock_dir, "uv.lock")
        venv = os.environ.get("UV_PROJECT_ENVIRONMENT") or ".venv"
        venv = venv if os.path.isabs(venv) else os.path.join(lock_dir, venv)
        snap = Snapshot([os.path.join(root, "pyproject.toml"), lock])
        try:
            code, _new = _check_uv(ctx, exe, "sync", ["sync"] + kept, env, root, lock,
                                   installed_python(venv_site_dirs(venv)))
        except BaseException:
            snap.restore()
            raise
        if code is not None:
            return finish(ctx, installed=False, restored=snap.restore(), code=code)
        if not frozen:
            run_opts.append("--frozen")
    indexes, merge, creds = python_indexes("uv", exe, env, cwd, cli_default, cli_extras, cli_strategy)
    with LocalIndex(ctx, indexes, merge, creds) as li:
        env = li.tool_env(env, uv=True)
        if ctx.opts.plan:
            return finish(ctx, installed=False, index=li.index, code=EXIT_OK)
        proc = run_tool([exe, "run"] + run_opts + ([command] if command else []) + trailing, env, cwd=cwd)
        blocked = bool(ctx.blocked())
        return finish(ctx, installed=proc.returncode == 0 and not blocked, index=li.index,
                      code=EXIT_BLOCKED if blocked else proc.returncode)


# ---------------- Go modules (0.1.9) ----------------
GO_COMMANDS = ("get", "install", "build", "run", "test", "vet", "list", "mod")
GO_MOD_COMMANDS = ("download", "tidy")
#: The commands that build a program (test and run then run it): go takes the modules it has in its module cache already
#: without asking the proxy, so the guard checks those before the command runs. (vet and list build nothing that runs: what
#: they fetch is checked as it comes through the proxy.)
GO_BUILDS = ("install", "build", "run", "test")
#: The module the go command downloads a Go toolchain as (GOTOOLCHAIN): go checks it against the checksum database itself
GO_TOOLCHAIN = "golang.org/toolchain"
#: The newest versions of a module whose release time is looked up when the proxy lists its versions
GO_PROBES = 24
GO_ENV_KEYS = ("GOPROXY", "GONOPROXY", "GOPRIVATE", "GOMODCACHE", "GOMOD", "GOWORK", "GO111MODULE", "GOFLAGS")
#: go's flags that take their value as the next argument (`-flag value`): the build flags and those of the commands the guard
#: wraps (cmd/go 1.24's flag sets); a reading of the command line skips their values. The others are true or false.
GO_VALUE_FLAGS = frozenset((
    "C", "p", "asmflags", "buildmode", "compiler", "covermode", "coverpkg", "coverprofile", "debug-actiongraph",
    "debug-runtime-trace", "debug-trace", "exec", "f", "gccgoflags", "gcflags", "go", "compat", "installsuffix", "ldflags",
    "mod", "modfile", "o", "overlay", "pgo", "pkgdir", "reuse", "tags", "toolexec", "vettool", "bench", "benchtime",
    "blockprofile", "blockprofilerate", "count", "cpu", "cpuprofile", "fuzz", "fuzztime", "fuzzminimizetime", "list",
    "memprofile", "memprofilerate", "mutexprofile", "mutexprofilefraction", "outputdir", "parallel", "run", "shuffle", "skip",
    "timeout", "trace", "vet"))
#: Modules read from one `go mod download -json` list
MAX_GO_LISTED = 20_000
#: Bytes of an `.info` record in go's module cache
MAX_GO_INFO = 64 * 1024
#: Bytes of a go.mod, a list of versions, an `.info` record (zip.MaxGoMod is 16 MiB)
MAX_GO_ANSWER = 16 * 1024 * 1024
#: The largest module zip go takes (zip.MaxZipFile): the relay keeps a zip this large on disk, scanned when it is no larger than
#: the guard scans (repo.MAX_DOWNLOAD_BYTES), and hands go those bytes
MAX_GO_ZIP = 500 * 1024 * 1024
_TEXT = "text/plain; charset=utf-8"

GoReply = collections.namedtuple("GoReply", "code body ctype file stream")


def _not_found(message="not found"):
    exc = repo.FetchError(message)
    exc.status = 404
    return exc


class GoRelay:
    """What the local Go proxy knows for one go command: the proxies GOPROXY lists, relayed in the order and by the rules of the go
    command (a 404 or 410 goes on to the next, any other error only after a bar), the release times it looked up, the module
    zips it scanned, kept on disk (spool) until the tool has them.

    A module version is the guard's to judge when go asks for its zip: the proxy fetches it, scans it, and hands it over only when
    it is not blocked (go then checks the bytes against go.sum or the checksum database, so what it accepts is what was scanned).
    --min-age holds versions back at the proxy: a module's list leaves out those younger than the age (the newest
    GO_PROBES are looked up), and an `.info` or a zip of one is refused. The time is the one the proxy gives (the commit or the
    tag, as its author recorded it)."""

    def __init__(self, ctx, fetcher, proxies, spool, source=""):
        self.ctx = ctx
        self.fetcher = fetcher
        self.proxies = [goproxy.Proxy(p.url if p.url in ("off", "direct") or p.url.endswith("/") else p.url + "/", p.fall_back)
                        for p in proxies]
        self.spool = spool
        self.source = source
        self.results = {}         # (module, version) -> (Check, spooled file or None)
        self.times = {}           # (module, version) -> (release time or None, .info body or None)
        self.held_back = {}       # module -> {version: release time}
        self.errors = []          # what the proxy could not fetch (for the report, not the tool)
        self.lock = threading.Lock()
        self.key_locks = {}

    def note(self, message):
        with self.lock:
            if message not in self.errors and len(self.errors) < 20:
                self.errors.append(message)

    # ---- the proxies GOPROXY lists
    def _each(self, path, op):
        """op(url) at each proxy in turn, as the go command goes through its list."""
        last = None
        for proxy in self.proxies:
            if proxy.url == "off":
                raise repo.FetchError("GOPROXY is off")
            if proxy.url == "direct":
                break
            try:
                return op(proxy.url + path)
            except repo.FetchError as exc:
                if getattr(exc, "status", None) in (404, 410) or proxy.fall_back:
                    last = exc
                    continue
                raise
        if last is not None and getattr(last, "status", None) not in (404, 410):
            raise last
        raise _not_found()

    def _get(self, path, max_bytes=MAX_GO_ANSWER):
        return self._each(path, lambda url: self.fetcher.fetch(url, max_bytes, None, repo.METADATA_TIMEOUT))[0]

    # ---- release times
    def _info(self, module, version):
        """(release time or None, the proxy's .info body or None) of one version, looked up once."""
        key = (module, version)
        with self.lock:
            if key in self.times:
                return self.times[key]
        try:
            body = self._get(goproxy.upstream_path(goproxy.Request("info", module, version, None)))
            doc = repo._deep_safe_loads(body, "from the Go proxy")
            if not isinstance(doc, dict):
                raise ValueError("not a JSON object")
            found = (parse_time(doc.get("Time")), body)
        except (repo.FetchError, ValueError) as exc:
            self.note(f"{module}@{version}: no release time ({exc})")
            found = (None, None)
        with self.lock:
            self.times[key] = found
        return found

    def _holds(self, module):
        """Does --min-age hold this module's new releases back?"""
        return self.ctx.cutoff is not None and module != GO_TOOLCHAIN \
            and not self.ctx.matches(self.ctx.opts.allow_new, "go", module)

    def _too_new(self, module, published):
        return published is not None and self._holds(module) and published > self.ctx.cutoff

    def _held_message(self, module, version, published):
        return (f"lazaret guard: {module}@{version} was published {format_age((now() - published).total_seconds())} ago, "
                f"under --min-age {format_age(self.ctx.min_age)}\n").encode("utf-8")

    # ---- the requests
    def handle(self, req):
        """The reply to one request of the protocol (a goproxy.Request)."""
        try:
            if req.kind == "list":
                return self._list(req)
            if req.kind in ("info", "latest"):
                return self._info_reply(req)
            if req.kind == "zip":
                return self._zip(req)
            return GoReply(200, self._get(goproxy.upstream_path(req)), _TEXT, None, None)       # .mod, the checksum database
        except (repo.FetchError, ValueError) as exc:
            if getattr(exc, "status", None) in (404, 410):
                return GoReply(404, b"not found\n", _TEXT, None, None)
            self.note(str(exc))                                    # (fixed text for the tool; the reason goes in the report)
            return GoReply(502, b"lazaret guard could not fetch this from the proxy it relays\n", _TEXT, None, None)

    def _list(self, req):
        body = self._get(goproxy.upstream_path(req))
        versions = [v for v in body.decode("utf-8", "replace").split() if golang.VERSION_RE.fullmatch(v)]
        late = {}
        if self._holds(req.module):
            probes = goproxy.newest_first(versions)[:GO_PROBES]
            run_all([lambda v=v: self._info(req.module, v) for v in probes])
            late = {v: t for v in probes for t in [self._info(req.module, v)[0]] if self._too_new(req.module, t)}
        if late:
            with self.lock:
                self.held_back.setdefault(req.module, {}).update(late)
        return GoReply(200, "".join(v + "\n" for v in versions if v not in late).encode("utf-8"), _TEXT, None, None)

    def _info_reply(self, req):
        with self.lock:
            kept = self.times.get((req.module, req.version)) if req.kind == "info" else None
        body = kept[1] if kept is not None and kept[1] is not None else self._get(goproxy.upstream_path(req))
        doc = repo._deep_safe_loads(body, "from the Go proxy")
        version = doc.get("Version") if isinstance(doc, dict) else None
        if not isinstance(version, str) or not golang.VERSION_RE.fullmatch(version):
            raise repo.FetchError("the proxy's answer has no version")
        published = parse_time(doc.get("Time"))
        if self._too_new(req.module, published):
            with self.lock:
                self.held_back.setdefault(req.module, {})[version] = published
            return GoReply(403, self._held_message(req.module, version, published), _TEXT, None, None)
        with self.lock:
            self.times.setdefault((req.module, version), (published, body))
        return GoReply(200, body, "application/json", None, None)

    def _zip(self, req):
        key = (req.module, req.version)
        with self.lock:
            lock = self.key_locks.setdefault(key, threading.Lock())
        with lock:
            with self.lock:
                done = self.results.get(key)
            if done is None:
                done = self._scan(req)
                with self.lock:
                    self.results[key] = done
        check, spooled = done
        if check is None:
            return GoReply(404, b"not found\n", _TEXT, None, None)
        if check.blocked:
            reason = "; ".join(check.blocked)[:300].replace("\n", " ")
            return GoReply(403, f"blocked by lazaret guard: {reason}\n".encode("utf-8", "replace"), _TEXT, None, None)
        if spooled is not None:
            return GoReply(200, None, "application/zip", spooled, None)
        if req.module == GO_TOOLCHAIN:
            # (handed over as it comes: go checks a toolchain against the checksum database whatever GOSUMDB says)
            stream = self._each(goproxy.upstream_path(req), lambda url: self.fetcher.open(url, None, repo.DOWNLOAD_TIMEOUT))
            return GoReply(200, None, "application/zip", None, stream)
        # (no bytes kept that were fetched: never a second download that nothing scanned: the Go/Rust review's GO-2)
        return GoReply(502, b"lazaret guard could not fetch this from the proxy it relays\n", _TEXT, None, None)

    def _scan(self, req):
        """(Check, spooled file) for one module zip, fetched once (to the spool, as it comes) and scanned: the Check is None when
        the proxy has no such zip, the file None when it is blocked. A zip larger than the guard scans is INCOMPLETE, and its
        bytes, the ones fetched, are what go gets (go checks them against go.sum or the checksum database)."""
        module, version = req.module, req.version
        check = Check("go", module, version, self.source)
        if module == GO_TOOLCHAIN:
            check.notes.append("a Go toolchain: go checks it against the checksum database itself; not scanned")
            return self.ctx.add(check), None
        published = self._info(module, version)[0] if self.ctx.cutoff is not None else None
        self.ctx.age_check(check, published)
        if check.blocked:
            return self.ctx.add(check), None
        fd, spooled = tempfile.mkstemp(dir=self.spool)
        os.close(fd)
        try:
            size, sha = self._each(goproxy.upstream_path(req),
                                   lambda url: self.fetcher.fetch_to_file(url, spooled, MAX_GO_ZIP, repo.DOWNLOAD_TIMEOUT))
            check.digest = "sha256:" + sha
            if size > repo.MAX_DOWNLOAD_BYTES:
                self.ctx.not_checked(check, TooLarge(f"response over {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB: "
                                                     f"{module}@{version}"))
            else:
                with open(spooled, "rb") as f:
                    data = f.read()
                key = VerdictCache.key("go", module, version, check.digest)
                hit = self.ctx.scanner.cached(key) or self.ctx.scanner.scan(data, "zip", "gomod")
                del data
                self.ctx.scanner.remember(key, hit, published)
                self.ctx.apply(check, hit)
        except (repo.FetchError, ValueError) as exc:
            os.remove(spooled)
            if getattr(exc, "status", None) in (404, 410):
                return None, None
            if isinstance(exc, TooLarge):
                self.ctx.block(check, f"larger than the {MAX_GO_ZIP // (1024 * 1024)}MB a module zip can be")
            else:
                self.ctx.not_checked(check, exc)
            return self.ctx.add(check), None
        if check.blocked:
            os.remove(spooled)
            spooled = None
        return self.ctx.add(check), spooled


def make_go_server(relay, gate=None):
    """A threaded HTTP server on 127.0.0.1 (a free port) answering the Go module proxy protocol from `relay`; with a LocalGate,
    only to the go command told its path."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype=_TEXT):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _file(self, path, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(os.path.getsize(path)))
            self.end_headers()
            if self.command != "HEAD":
                with open(path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile, 1024 * 1024)

        def _stream(self, response, ctype):
            with response as r:
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                length = r.headers.get("Content-Length")
                if length and length.isdigit():
                    self.send_header("Content-Length", length)
                else:
                    self.close_connection = True
                self.end_headers()
                if self.command != "HEAD":
                    with timings.span("network", "relay"):
                        shutil.copyfileobj(r, self.wfile, 1024 * 1024)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path if gate is None else gate.path(self)
            req = goproxy.parse_request(urllib.parse.unquote(path)) if path is not None else None
            if req is None:
                self._send(404, b"not found\n")
                return
            try:
                reply = relay.handle(req)
                if reply.file is not None:
                    self._file(reply.file, reply.ctype)
                elif reply.stream is not None:
                    self._stream(reply.stream, reply.ctype)
                else:
                    self._send(reply.code, reply.body, reply.ctype)
            except Exception:                              # never let one request kill the server
                self._send(500, b"lazaret guard: internal error\n")

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def handle_error(self, request, client_address):
            pass                            # a tool that hung up: nothing to print over its output

    return Server(("127.0.0.1", 0), Handler)


class LocalGoProxy:
    """The local Go proxy (GoRelay behind make_go_server) for one command: `with LocalGoProxy(ctx, proxies, creds) as lp:` —
    lp.relay, lp.base (http://127.0.0.1:port/<the run's secret segment>)."""

    def __init__(self, ctx, proxies, creds):
        self.spool = tempfile.mkdtemp(prefix="lazaret-guard-")
        urls = [p.url for p in proxies if p.url not in ("off", "direct")]
        fetcher = Fetcher({netloc(u) for u in urls}, http_hosts={netloc(u) for u in urls if u.startswith("http://")},
                          auth=creds, keepalive=ctx.keepalive, https_redirects=True)
        self.fetcher = fetcher
        self.relay = GoRelay(ctx, fetcher, proxies, self.spool, source=pmsettings.shown(urls[0]) if urls else "")
        self.gate = LocalGate()
        self.server = make_go_server(self.relay, self.gate)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.base = self.gate.bind(self.server.server_address[1])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.fetcher.close()
        shutil.rmtree(self.spool, ignore_errors=True)


def remove_tree(path):
    """Remove a folder and what is in it, though go's module cache keeps its folders read-only."""
    for folder, dirs, _files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(folder, d), 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


def go_settings(exe, env, cwd):
    """What `go env` says of the settings the guard reads (GO_ENV_KEYS), as strings; GuardError when go does not say. go runs
    with GOTOOLCHAIN=local: a go.mod whose go line is newer than this go made `go env` download that toolchain from GOPROXY
    before the guard's proxy was there (the Go/Rust review's GO-5). The command itself switches as it would."""
    doc = pmsettings.run_json([exe, "env", "-json", *GO_ENV_KEYS], dict(env, GOTOOLCHAIN="local"), cwd)
    if not isinstance(doc, dict) or "GOPROXY" not in doc:
        raise GuardError("could not read go's settings (`go env` failed)")
    return {k: v for k, v in doc.items() if isinstance(v, str)}


def _go_words(args):
    """How many of go's arguments are the command's words: two for `mod download`, one for `get`."""
    return 2 if args[:1] == ["mod"] and len(args) > 1 and not args[1].startswith("-") else 1


def _go_scan(args):
    """go's command line `args` (the command's words first) read as cmd/go reads it -> ({flag: [value, ...]}, [the other
    arguments]): `-flag value` (GO_VALUE_FLAGS), `-flag=value`, a flag that is true or false (value None), one dash or two.
    Flags end at `--` and at the first argument that is not one (a package: what follows `go run`'s is the program's), but
    go test's flags may follow its packages, up to -args (the Go/Rust review's GO-6: `go run . -modfile=x` was read as go's)."""
    sub = args[0] if args else ""
    rest = list(args[_go_words(args):]) if args else []
    flags, other, k = {}, [], 0
    while k < len(rest):
        a = rest[k]
        if sub == "test" and a in ("-args", "--args"):
            break
        if a == "--":
            other.extend(rest[k + 1:])
            break
        if a.startswith("-") and a != "-":
            name, eq, value = (a[2:] if a.startswith("--") else a[1:]).partition("=")
            if eq:
                flags.setdefault(name, []).append(value)
                k += 1
            elif name in GO_VALUE_FLAGS:
                if k + 1 < len(rest):
                    flags.setdefault(name, []).append(rest[k + 1])
                k += 2
            else:
                flags.setdefault(name, []).append(None)
                k += 1
            continue
        if sub != "test":
            other.extend(rest[k:])
            break
        other.append(a)
        k += 1
    return flags, other


def _go_flag(args, name):
    """The value of go's flag -name on its command line `args` (the command's words first; _go_scan), or None: the last one
    given, as go takes it."""
    values = [v for v in _go_scan(args)[0].get(name, []) if v is not None]
    return values[-1] if values else None


def _go_chdir(args):
    """The folder of go's -C flag, or None: cmd/go reads it only as the first argument after the command's words (`go build
    -C dir`, `go mod download -C dir`: the Go/Rust review's GO-6)."""
    k = _go_words(args) if args else 1
    first = args[k] if len(args) > k else ""
    if first in ("-C", "--C"):
        return args[k + 1] if len(args) > k + 1 else None
    for prefix in ("-C=", "--C="):
        if first.startswith(prefix):
            return first[len(prefix):]
    return None


def _goflags(text):
    """GOFLAGS as go splits it (cmd/internal/quoted.Split: fields between spaces; a field in single or double quotes is what
    is between them, nothing unescaped) -> [field, ...]; [] for one go refuses (a quote not closed)."""
    s, fields, k = text or "", [], 0
    while True:
        while k < len(s) and s[k] in " \t\r\n":
            k += 1
        if k >= len(s):
            return fields
        if s[k] in "\"'":
            end = s.find(s[k], k + 1)
            if end < 0:
                return []
            fields.append(s[k + 1:end])
            k = end + 1
            continue
        j = k
        while j < len(s) and s[j] not in " \t\r\n":
            j += 1
        fields.append(s[k:j])
        k = j


def _goflags_value(text, name):
    """The value GOFLAGS gives go's flag -name (`-name=value`, the last one), or None. The command line's own wins over it."""
    found = None
    for field in _goflags(text):
        if not field.startswith("-") or field.startswith("---"):
            continue
        flag, eq, value = (field[2:] if field.startswith("--") else field[1:]).partition("=")
        if flag == name and eq:
            found = value
    return found


def _go_setting(settings, args, name):
    """go's flag -name as the command takes it: from its command line, else from GOFLAGS (`go env GOFLAGS`)."""
    return _go_flag(args, name) or _goflags_value(settings.get("GOFLAGS", ""), name)


def go_packages(args):
    """The packages of an install or a run (the arguments that are not go's flags): `go run`'s first only (or its .go files),
    what follows it being the program's arguments."""
    other = _go_scan(args)[1]
    if args[:1] == ["run"]:
        files = list(itertools.takewhile(lambda a: a.endswith(".go"), other))
        return files or other[:1]
    return other


def cached_zips(modcache):
    """{(module, version): the zip's path} of the modules in go's module cache (GOMODCACHE/cache/download)."""
    root = os.path.join(modcache, "cache", "download") if modcache else ""
    found = {}
    for folder, dirs, files in os.walk(root):
        if folder == root:
            dirs[:] = [d for d in dirs if d != "sumdb"]
        if os.path.basename(folder) != "@v":
            continue
        dirs[:] = []
        module = golang.unescape(os.path.relpath(os.path.dirname(folder), root).replace(os.sep, "/"))
        for name in files:
            version = golang.unescape(name[:-4]) if name.endswith(".zip") else None
            if module is not None and version is not None:
                found[(module, version)] = os.path.join(folder, name)
    return found


def cached_modules(modcache):
    """{(module, version)} whose zip is in the module cache (GOMODCACHE/cache/download)."""
    return set(cached_zips(modcache))


def go_module_files(settings, args, cwd):
    """The files a go command may change that tell what the project depends on: go.mod and go.sum (or the -modfile and
    the .sum beside it: on the command line or in GOFLAGS), the workspace's go.work and go.work.sum."""
    files = []
    main = settings.get("GOMOD", "")
    if main and main not in (os.devnull, "NUL"):
        files += [main, os.path.join(os.path.dirname(main), "go.sum")]
    alt = _go_setting(settings, args, "modfile")
    if alt:
        alt = os.path.abspath(os.path.join(cwd, alt))
        files += [alt, (alt[:-4] if alt.endswith(".mod") else alt) + ".sum"]
    work = settings.get("GOWORK", "")
    if work and work not in ("off", os.devnull, "NUL"):
        files += [work, work + ".sum"]
    return files


def go_vendored(settings, args, cwd):
    """Does go build from a vendor folder here (cmd/go's rule): -mod=vendor (the command line, else GOFLAGS); with no -mod, a
    vendor folder beside go.work whose go line is 1.22 or later, or (no workspace) beside go.mod whose go line (the
    -modfile's, when there is one) is 1.14 or later."""
    mode = _go_setting(settings, args, "mod")
    if mode:
        return mode == "vendor"
    work = settings.get("GOWORK", "")
    gomod_path = settings.get("GOMOD", "")
    if work and work not in ("off", os.devnull, "NUL"):
        root, version_file, least = os.path.dirname(work), work, (1, 22)
    elif gomod_path and gomod_path not in (os.devnull, "NUL"):
        alt = _go_setting(settings, args, "modfile")
        root, least = os.path.dirname(gomod_path), (1, 14)
        version_file = os.path.abspath(os.path.join(cwd, alt)) if alt else gomod_path
    else:
        return False
    if not os.path.isdir(os.path.join(root, "vendor")):
        return False
    version = gomod.parse(read_text(version_file) or "")["go"]
    return bool(version) and gomod.go_at_least(version, *least)


def go_listing(exe, env, cwd, args=()):
    """What `go mod download -json` (args: -C and -modfile, or the modules to list) says of the modules it fetches, those go
    has in its module cache already included -> ([{"Path", "Version", "Zip", "Info", ...}, ...], why the list may be short
    (go's error) or None). No module's code runs: go fetches (through the guard's proxy; a module GONOPROXY names, from its
    repository) and checks zips."""
    chdir = list(args[:2]) if args[:1] == ["-C"] else []
    argv = [exe, "mod", "download", *chdir, "-json", *args[len(chdir):]]
    try:
        with timings.span("tool", "go mod download -json"):
            proc = subprocess.run(argv, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"go could not be run ({exc.strerror or exc})"
    records, text, k = [], proc.stdout or "", 0
    decoder = json.JSONDecoder()
    while len(records) < MAX_GO_LISTED:
        while k < len(text) and text[k] in " \t\r\n":
            k += 1
        if k >= len(text):
            break
        try:
            doc, k = decoder.raw_decode(text, k)
        except (ValueError, RecursionError):
            return records, "go's list could not be read"
        if isinstance(doc, dict) and isinstance(doc.get("Path"), str) and isinstance(doc.get("Version"), str):
            records.append(doc)
    if proc.returncode == 0:
        return records, None
    errors = [d["Error"].splitlines()[0] for d in records if isinstance(d.get("Error"), str) and d["Error"].strip()]
    lines = errors or [line.strip() for line in (proc.stderr or "").splitlines() if line.strip()]
    return records, (lines[0] if lines else f"exit {proc.returncode}")[:300]


def _cached_time(path):
    """The release time an `.info` record of go's module cache gives (go keeps the proxy's answer beside the zip), or None."""
    try:
        with open(path, "rb") as f:
            body = f.read(MAX_GO_INFO + 1)
        doc = repo._deep_safe_loads(body, "from go's module cache") if len(body) <= MAX_GO_INFO else None
    except (OSError, TypeError, ValueError, repo.FetchError):
        return None
    return parse_time(doc.get("Time")) if isinstance(doc, dict) else None


def _check_cached_zip(ctx, check, path, info):
    """Scan one zip of go's module cache as the proxy scans one it fetches: the release time (--min-age) from the `.info`
    beside it, the verdict cache by its SHA-256; one too large to scan is INCOMPLETE, one that cannot be read is blocked."""
    published = _cached_time(info) if ctx.cutoff is not None and isinstance(info, str) else None
    ctx.age_check(check, published)
    if not check.blocked:
        try:
            if os.path.getsize(path) > repo.MAX_DOWNLOAD_BYTES:
                ctx.not_checked(check, TooLarge(f"response over {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB: {check.label()}"))
            else:
                with open(path, "rb") as f:
                    data = f.read(repo.MAX_DOWNLOAD_BYTES + 1)
                check.digest = "sha256:" + hashlib.sha256(data).hexdigest()
                key = VerdictCache.key("go", check.name, check.version, check.digest)
                hit = ctx.scanner.cached(key) or ctx.scanner.scan(data, "zip", "gomod")
                del data
                ctx.scanner.remember(key, hit, published)
                ctx.apply(check, hit)
        except (OSError, ValueError, repo.FetchError) as exc:
            ctx.not_checked(check, repo.FetchError(f"go's module cache could not be read ({getattr(exc, 'strerror', None) or exc})"))
    ctx.add(check)


def check_cached(ctx, relay, records, private):
    """Check the modules of a list of zips (go_listing's records) that did not come through the guard's proxy in this run:
    those go had in its module cache already (an earlier command the guard did not see, a --trust), and those it fetched
    from their repository (GONOPROXY, `private`). Each is read from where go keeps it, scanned as the proxy scans a zip (the
    Go/Rust review's GO-4: they used to pass unchecked, with nothing said). -> the Checks made."""
    with relay.lock:
        done = set(relay.results)
    done |= {(c.name, c.version) for c in list(ctx.checks) if c.eco == "go"}
    jobs, made = [], []
    for rec in records:
        module, version, path = rec.get("Path"), rec.get("Version"), rec.get("Zip")
        if (module, version) in done or module == GO_TOOLCHAIN or not isinstance(path, str) or not os.path.isfile(path):
            continue
        if golang.check_module_path(module) is not None or not golang.VERSION_RE.fullmatch(version):
            continue
        done.add((module, version))
        check = Check("go", module, version, "version control" if goproxy.glob_matches(private, module) else "module cache")
        made.append(check)
        jobs.append(lambda c=check, p=path, i=rec.get("Info"): _check_cached_zip(ctx, c, p, i))
    run_all(jobs)
    return made


def _zip_records(zips):
    """cached_zips' {(module, version): path} as go_listing's records."""
    return [{"Path": m, "Version": v, "Zip": p, "Info": p[:-4] + ".info"} for (m, v), p in sorted(zips.items())]


def _plan_module(folder):
    """An empty module of the guard's own, in `folder` (made), where an install or a run of pkg@version is a `go get`."""
    os.makedirs(folder)
    with open(os.path.join(folder, "go.mod"), "w", encoding="utf-8") as f:
        f.write("module lazaret.guard/plan\n\ngo 1.21\n")
    return folder


def go_plan(args, scratch):
    """-> (the go command that fetches what `args` would, the folder it runs in or None for the current one). get and mod download
    or tidy are that themselves (they run no code); an install or run of pkg@version is `go get` of it in an empty module of
    its own; the others (build, test, vet, list, run of a local package) would compile and run: `go mod download` instead."""
    sub = args[0]
    if sub in ("get", "mod"):
        return list(args), None
    given = [a for a in go_packages(args) if "@" in a] if sub in ("install", "run") else []
    if given:
        return ["get"] + given, scratch
    chdir = _go_chdir(args)
    modfile = _go_flag(args, "modfile")
    return ["mod", "download"] + (["-C", chdir] if chdir else []) + ([f"-modfile={modfile}"] if modfile else []), None


def _listing_args(args, chdir):
    """The arguments of the guard's `go mod download -json` for a command: its -C and -modfile, and for a `go mod download`
    the modules it names."""
    modfile = _go_flag(args, "modfile")
    named = _go_scan(args)[1] if args[:2] == ["mod", "download"] else []
    return (["-C", chdir] if chdir else []) + ([f"-modfile={modfile}"] if modfile else []) + named


def guard_go(ctx, args):
    """go get, install, build, run, test, vet, list, mod download and mod tidy: the go command runs against a Go proxy of the
    guard's on this machine (GOPROXY), which relays the proxies GOPROXY lists and scans each module zip before the command gets it.
    The modules go takes from its module cache or from their repositories (GONOPROXY) without asking the proxy are read from
    the cache and scanned too: before a command that builds a program (GO_BUILDS), after get, mod download and mod tidy
    (`go mod download -json` lists them). go.mod, go.sum and go.work.sum are put back when anything was blocked."""
    sub = args[0] if args else ""
    if sub not in GO_COMMANDS or (sub == "mod" and args[1:2] and args[1] not in GO_MOD_COMMANDS) or (sub == "mod" and len(args) < 2):
        raise GuardError("lazaret guard wraps go's commands that fetch modules (get, install, build, run, test, vet, list, "
                         "mod download, mod tidy); put the command first: lazaret guard go get …")
    exe = find_tool("go")
    env = dict(os.environ)
    cwd = os.getcwd()
    chdir = _go_chdir(args)
    work = os.path.abspath(os.path.join(cwd, chdir)) if chdir else cwd
    settings = go_settings(exe, env, work)
    if settings.get("GO111MODULE") == "off":
        raise GuardError("GO111MODULE=off: go then fetches packages from version control, not through a module proxy, and "
                         "the guard has nothing to check; use modules")
    proxies = goproxy.parse_goproxy(settings.get("GOPROXY"))
    relayed = [p for p in proxies if p.url not in ("off", "direct")]
    if not relayed:
        raise GuardError("GOPROXY names no module proxy (off, or direct from version control): there is nothing for the guard "
                         "to relay; set GOPROXY to a proxy, such as https://proxy.golang.org")
    indexes = [pmsettings.Index(p.url) for p in relayed]
    creds = pmsettings.index_credentials(indexes, env)
    relayed = [goproxy.Proxy(i.url, p.fall_back) for i, p in zip(indexes, relayed)]
    bad = [p.url for p in relayed if not (fetchable(p.url) or p.url.startswith("http://"))]
    if bad:
        raise GuardError(f"GOPROXY lists {', '.join(pmsettings.shown(u) for u in bad)}: the guard relays https and http "
                         f"proxies, not other kinds (a file:// folder, say)")
    # (go goes to a module's repository when GONOPROXY names it, and `go env` gives GONOPROXY as go takes it: GOPRIVATE when
    # it is not set. GOPRIVATE alone named modules that came through the proxy: the Go/Rust review's GO-7)
    private = settings.get("GONOPROXY", "")
    modcache = settings.get("GOMODCACHE", "")
    ctx.say("lazaret guard: relaying " + ", ".join(pmsettings.shown(p.url) for p in relayed)
            + (" (the guard does not fetch from version control: a module the proxy lacks is not fetched, unless GONOPROXY or "
               "GOPRIVATE names it)" if any(p.url == "direct" for p in proxies) else ""))
    if ctx.cutoff is not None:
        ctx.say(f"lazaret guard: releases younger than {format_age(ctx.min_age)} are held back at the proxy "
                f"(a Go module's age is the commit or tag time its author recorded)")
    ctx.unchecked_hint = ("go did not fetch them through the guard's proxy (GOFLAGS, a module in a version control repository, "
                          "a vendor folder); look at what go downloaded, or run the command again")
    plan = ctx.opts.plan
    builds = sub in GO_BUILDS
    at_version = [a for a in go_packages(args) if "@" in a] if sub in ("install", "run") else []
    vendored = builds and not at_version and go_vendored(settings, args, work)
    scratch = private_scratch("lazaret-guard-") if plan or at_version else None
    files = go_module_files(settings, args, work)
    snap = Snapshot(files)
    before = None if plan else cached_modules(modcache)
    restored, proc = [], None
    try:
        with LocalGoProxy(ctx, relayed, creds) as lp:
            tool_env = dict(env, GOPROXY=lp.base)
            if plan:
                tool_env["GOMODCACHE"] = os.path.join(scratch, "modcache")
                argv, where = go_plan(args, os.path.join(scratch, "module"))
                if where is not None:
                    _plan_module(where)
                    tool_env["GOWORK"] = "off"          # (the plan's module alone: no go.work from a folder above it)
                proc = run_tool([exe] + argv, tool_env, cwd=where or cwd, capture=True)
                if proc.returncode == 0 and not ctx.blocked():
                    # (what go fetched from repositories, GONOPROXY, is in the plan's cache: read from there)
                    check_cached(ctx, lp.relay, _zip_records(cached_zips(tool_env["GOMODCACHE"])), private)
            else:
                if builds and not vendored:
                    if at_version:
                        _check_install(ctx, lp.relay, exe, tool_env, os.path.join(scratch, "module"), at_version, private)
                    else:
                        records, error = go_listing(exe, tool_env, cwd, _listing_args(args, chdir))
                        check_cached(ctx, lp.relay, records, private)
                        if error is not None:
                            _short_list(ctx, error)
                    snap.restore()        # (go mod download may have added to go.sum: the command runs on the files as they were)
                if vendored:
                    ctx.notes.append("go builds this project's dependencies from its vendor folder: they are the project's "
                                     "own files, which go does not fetch and the guard did not check")
                if not ctx.blocked():
                    proc = run_tool([exe] + list(args), tool_env, cwd=cwd)
                    if proc.returncode == 0 and not ctx.blocked() and sub in ("get", "mod"):
                        after = Snapshot(files)
                        records, error = go_listing(exe, tool_env, cwd, _listing_args(args, chdir))
                        check_cached(ctx, lp.relay, records, private)
                        after.restore()   # (the list leaves the files as the command left them)
                        if error is not None:
                            _short_list(ctx, error)
        blocked = bool(ctx.blocked())
        if blocked or plan:
            restored = snap.restore()
    except BaseException:
        snap.restore()
        raise
    finally:
        if scratch:
            remove_tree(scratch)
    relay = lp.relay
    if plan and proc.returncode != 0 and not blocked:
        show_failure(ctx, f"resolving (go {args[0]})", proc)
        return finish(ctx, installed=False, restored=restored, index=relay, code=EXIT_RESOLVE)
    if before is not None and not blocked and proc is not None and proc.returncode == 0:
        new = {k: p for k, p in cached_zips(modcache).items() if k not in before}
        check_cached(ctx, relay, _zip_records({k: p for k, p in new.items() if goproxy.glob_matches(private, k[0])}), private)
        verify_installed(ctx, set(new), "go")
        if ctx.blocked():
            restored = snap.restore()
    blocked = bool(ctx.blocked())
    cached = sorted(c.label() for c in ctx.checks if c.blocked and c.source in ("module cache", "version control"))
    if cached:
        ctx.notes.append(f"{_and(cached)} {'was' if len(cached) == 1 else 'were'} in go's module cache already, from a command "
                         f"the guard did not check or from version control (`go clean -modcache` empties the cache)")
    if blocked and not plan and len(cached) < len(ctx.blocked()):
        ctx.say("lazaret guard: modules that passed are in go's module cache; a blocked one was not handed over to go")
    code = EXIT_BLOCKED if blocked else (EXIT_OK if plan else (proc.returncode if proc is not None else EXIT_OK))
    return finish(ctx, installed=proc is not None and proc.returncode == 0 and not blocked and not plan, restored=restored,
                  index=relay, code=code)


def _short_list(ctx, error):
    ctx.notes.append(f"go could not list every module the command uses ({error}): those in go's module cache already may not "
                     f"have been checked")


def _check_install(ctx, relay, exe, env, folder, packages, private):
    """Before `go install pkg@version` or `go run pkg@version`: check the modules it builds that go has in its module cache
    already, listed by `go get` of the packages in an empty module of the guard's (go_plan's reading of an install) and that
    module's `go mod download -json`."""
    env = dict(env, GOWORK="off")
    proc = run_tool([exe, "get", *packages], env, cwd=_plan_module(folder), capture=True)
    if proc.returncode != 0:
        if not ctx.blocked():
            lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            _short_list(ctx, lines[-1][:300] if lines else f"go get: exit {proc.returncode}")
        return
    records, error = go_listing(exe, env, folder)
    check_cached(ctx, relay, records, private)
    if error is not None:
        _short_list(ctx, error)


# ---------------- Cargo crates (0.1.9) ----------------
#: commands that are the resolution themselves (they edit Cargo.toml or Cargo.lock and run no crate's code, though cargo runs
#: the compiler, or a wrapper, the project's own configuration names to learn its version: not under --plan,
#: CARGO_PLAN_CONFIG); every other command the guard wraps first resolves, with `cargo update --workspace`, then checks,
#: then runs
CARGO_RESOLVES = frozenset(("add", "update", "generate-lockfile"))
#: what --plan gives every cargo command it runs (GR-1): while it resolves, cargo asks the compiler its version (`rustc -vV`)
#: through the project's `build.rustc-wrapper`, `build.rustc-workspace-wrapper` and `build.rustc` (checked with cargo 1.95,
#: editions 2021 and 2024), programs the project's configuration names; a dry run runs none of them, and the compiler cargo
#: finds by itself (PATH's rustc, rustup's) answers. Without --plan the command runs as the project configures it.
CARGO_PLAN_CONFIG = ("--config", 'build.rustc-wrapper=""', "--config", 'build.rustc-workspace-wrapper=""',
                     "--config", 'build.rustc="rustc"')
CARGO_BUILDS = frozenset(("build", "b", "check", "c", "clippy", "doc", "d", "test", "t", "bench", "run", "r", "fix", "fetch",
                          "vendor", "rustc", "rustdoc", "package"))
CRATES_API = "https://crates.io/api/v1/crates/"
#: crates.io's rule for its API is one request a second
CRATES_API_INTERVAL = 1.0
MAX_CRATE_INDEX = 16 * 1024 * 1024
MAX_MEMBERS = 2000
_api_lock = threading.Lock()


def cargo_toolchain(args):
    """(["+nightly"] or [], the rest): rustup's toolchain choice comes before the command and goes before every command the
    guard runs."""
    return ([args[0]], list(args[1:])) if args and args[0].startswith("+") else ([], list(args))


def cargo_plan_config(ctx):
    """The `--config` options of the cargo commands the guard runs: CARGO_PLAN_CONFIG under --plan, else none."""
    return list(CARGO_PLAN_CONFIG) if ctx.opts.plan else []


def cargo_workspace(exe, tc, env, cwd, manifest):
    """-> (the workspace root's folder, [the manifests of its members]) from `cargo metadata --no-deps` (no network, no crate's
    code runs); GuardError when cargo cannot read the project."""
    argv = [exe, *tc, "metadata", "--no-deps", "--format-version", "1", "--offline"] + (["--manifest-path", manifest] if manifest else [])
    doc = pmsettings.run_json(argv, env, cwd)
    root = doc.get("workspace_root") if isinstance(doc, dict) else None
    if not isinstance(root, str) or not root:
        raise GuardError("cargo cannot read the project here (`cargo metadata` failed): is there a Cargo.toml in this folder or "
                         "above it?")
    members = [p.get("manifest_path") for p in (doc.get("packages") or [])[:MAX_MEMBERS] if isinstance(p, dict)]
    return root, [m for m in members if isinstance(m, str)]


class CrateRegistry:
    """One registry's index as the guard reads it: `base` (the sparse index's URL), `dl` (the download URL pattern its
    config.json gives; None, with `error`, when that could not be read), and whether it is crates.io's own index."""

    def __init__(self, fetcher, base):
        self.base, self.dl, self.error = base, None, None
        self.default = base == cargosrc.DEFAULT_INDEX
        try:
            doc = fetcher.json(base + "config.json")
            dl = doc.get("dl") if isinstance(doc, dict) else None
            if not isinstance(dl, str) or not dl or len(dl) > 512:
                raise repo.FetchError("the registry's config.json has no download URL")
            self.dl = dl
            fetcher.allow(dl)
        except (repo.FetchError, ValueError) as exc:
            self.error = exc


def crate_index_record(fetcher, registry, pkg):
    """What the registry's index says of one release (cargosrc.index_record), or None when it lists none."""
    text = fetcher.get(cargosrc.index_url(registry.base, pkg.name), MAX_CRATE_INDEX).decode("utf-8", "replace")
    return cargosrc.index_record(text, pkg.version)


def crate_publish_time(fetcher, registry, pkg, record):
    """When the registry says a release was published: the index's `pubtime` (optional), else crates.io's API for crates.io's own
    index (one request a second); None when neither says. -> (the time or None, the index record or None)."""
    if record is None:
        try:
            record = crate_index_record(fetcher, registry, pkg)
        except repo.FetchError:
            record = None
    if record is not None and record["pubtime"]:
        return parse_time(record["pubtime"]), record
    if not registry.default:
        return None, record
    with _api_lock:
        try:
            doc = fetcher.json(f"{CRATES_API}{pkg.name}/{pkg.version}")
        except (repo.FetchError, ValueError):
            doc = None
        time.sleep(CRATES_API_INTERVAL)
    version = doc.get("version") if isinstance(doc, dict) else None
    return (parse_time(version.get("created_at")) if isinstance(version, dict) else None), record


def check_crate(ctx, fetcher, registry, pkg, home, offline, keep=None):
    """Check one crate: pkg is a cargosrc.Package. Its `.crate` is read from cargo's own cache or fetched from where cargo
    fetches it, checked against the lockfile's checksum (or, with none, the index's), and scanned. A verdict that is already
    known by the checksum is not fetched again. Its publish time is the index's `pubtime`, else crates.io's API. `keep`, a dict:
    the bytes are kept in it by (name, version)."""
    check = ctx.add(Check("crates", pkg.name, pkg.version, "registry"))
    try:
        if not cargosrc.crate_ok(pkg.name, pkg.version):
            raise repo.SpecError("not a crate name and version the guard fetches")
        if registry.error is not None:
            raise registry.error
        record, digest = None, pkg.checksum
        if digest is None and offline:
            raise repo.FetchError("offline, and the lockfile gives no checksum to check it against")
        if digest is None:
            record = crate_index_record(fetcher, registry, pkg)
            digest = record["cksum"] if record else None
            if digest is None:
                raise repo.FetchError("neither the lockfile nor the registry's index gives a checksum to check it against")
        check.digest = "sha256:" + digest
        key = VerdictCache.key("crates", pkg.name, pkg.version, check.digest)
        hit = ctx.scanner.cached(key)
        published = parse_time(hit.get("published")) if hit else None
        if hit is None or keep is not None:
            data = cargosrc.cached_crate(home, pkg.name, pkg.version, digest)
            if data is None:
                if offline:
                    raise repo.FetchError("offline, and cargo's cache does not hold it")
                data = fetcher.get(cargosrc.download_url(registry.dl, pkg.name, pkg.version, digest))
                if hashlib.sha256(data).hexdigest() != digest:
                    ctx.block(check, "its sha256 is not the " + ("lockfile's" if pkg.checksum else "index's"))
                    return check
            if keep is not None:
                keep[(pkg.name, pkg.version)] = data
            if hit is None:
                hit = ctx.scanner.scan(data, "tgz", "crate")
        if ctx.cutoff is not None and published is None and not offline:
            published, record = crate_publish_time(fetcher, registry, pkg, record)
        if record is not None and record["yanked"]:
            check.notes.append("yanked on the registry")
        ctx.scanner.remember(key, hit, published)
        ctx.apply(check, hit)
        ctx.age_check(check, published)
    except (repo.FetchError, repo.SpecError, ValueError) as exc:
        if not registry.default and getattr(exc, "status", None) in (401, 403):
            unchecked(ctx, check, "the registry asked for credentials the guard does not read: not checked")
        else:
            ctx.not_checked(check, exc)
    return check


def unchecked(ctx, check, reason):
    """A package the guard cannot check (a git source, a registry it cannot read): INCOMPLETE with the reason, so it is
    counted and --block-warn blocks it, where it used to be a note only."""
    ctx.apply(check, {"verdict": "INCOMPLETE", "reason": reason, "indicators": []})


def check_cargo_packages(ctx, packages, registry, home, offline, label, skip=(), keep=None):
    """Check the registry crates among `packages` (cargosrc.Package), those cargo has unpacked already included: cargo builds
    an unpacked crate without fetching it again, and another tool (an editor, `cargo tree`, `cargo metadata`) may have unpacked
    it (a verdict the cache holds for its checksum is not scanned again). Those in `skip` (name-version) are left out. A crate
    from git or another source the guard does not read is INCOMPLETE, not checked. -> the names (`name-version`) of every
    crate the lock lists that cargo may unpack."""
    listed, todo = set(), {}
    for pkg in packages:
        src = cargosrc.classify(pkg.source)
        if src.kind == "path":
            continue
        dirname = f"{pkg.name}-{pkg.version}"
        if dirname in skip:
            listed.add(dirname)
            continue
        if src.kind == "git":
            unchecked(ctx, ctx.add(Check("crates", pkg.name, pkg.version, "git")), "from a git repository: not checked")
            listed.add(dirname)
            continue
        if src.kind in ("git-index", "other"):
            unchecked(ctx, ctx.add(Check("crates", pkg.name, pkg.version, src.kind)),
                      "from a registry the guard cannot read (a git index, or a source it does not know): not checked")
            listed.add(dirname)
            continue
        listed.add(dirname)
        if src.kind == "crates-io" and registry.kind != "sparse":
            unchecked(ctx, ctx.add(Check("crates", pkg.name, pkg.version, registry.kind)),
                      f"cargo reads crates.io from a {registry.kind.replace('-', ' ')} source "
                      f"({pmsettings.shown(registry.url)}): not checked")
            continue
        base = registry.url if src.kind == "crates-io" else src.url
        todo[(pkg.name, pkg.version, base)] = pkg
    if len(todo) > cargosrc.MAX_PACKAGES:
        raise GuardError(f"more than {cargosrc.MAX_PACKAGES} crates to check")
    bases = sorted({k[2] for k in todo})
    http_hosts = {netloc(b) for b in bases if b.startswith("http://")}
    hosts = {netloc(b) for b in bases} | ({netloc(CRATES_API)} if cargosrc.DEFAULT_INDEX in bases else set())
    fetcher = Fetcher(hosts, http_hosts=http_hosts, keepalive=ctx.keepalive)
    ctx.say(f"lazaret guard: {plural(len(todo), 'crate')} to check ({label})")
    try:
        registries = {b: CrateRegistry(fetcher, b) for b in bases} if not offline else {}
        if offline:
            registries = {b: _offline_registry(b) for b in bases}
        run_all([lambda k=k, p=p: check_crate(ctx, fetcher, registries[k[2]], p, home, offline, keep)
                 for k, p in todo.items()])
    finally:
        fetcher.close()
    return listed


def _offline_registry(base):
    """The registry of a run that does not use the network: only cargo's cache is read, and no download URL is wanted."""
    reg = CrateRegistry.__new__(CrateRegistry)
    reg.base, reg.dl, reg.error, reg.default = base, "", None, base == cargosrc.DEFAULT_INDEX
    return reg


def read_cargo_lock(path, strict=True):
    """-> [cargosrc.Package] of a Cargo.lock file, or [] when there is none; GuardError when it is not a lockfile (strict), else []."""
    text = read_text(path)
    if text is None:
        return []
    try:
        return cargosrc.parse_lock(text)
    except ValueError as exc:
        if not strict:
            return []
        raise GuardError(f"{os.path.basename(path)} cannot be read: {exc}") from None


def guard_cargo(ctx, args):
    """cargo add, update, generate-lockfile, install and the commands that build (build, check, test, run, fetch, ...): the
    resolution is made first, Cargo.lock is read, every crate in it is checked (against its checksum, then scanned; one cargo
    has unpacked already too, and a verdict cached for its checksum is not scanned again), and only then does cargo fetch and
    build, with --locked, so that it builds the lock that was checked. Cargo.toml and Cargo.lock are put back when anything was
    blocked."""
    tc, rest = cargo_toolchain(args)
    sub = rest[0] if rest else ""
    if sub == "install":
        return guard_cargo_install(ctx, tc, rest[1:])
    if sub not in CARGO_RESOLVES and sub not in CARGO_BUILDS:
        raise GuardError("lazaret guard wraps cargo's commands that fetch crates (add, update, generate-lockfile, install, fetch, "
                         "build, check, clippy, doc, test, bench, run, fix, vendor, package); put the command first: "
                         "lazaret guard cargo build …")
    exe = find_tool("cargo")
    env = dict(os.environ)
    cwd = os.getcwd()
    project = cargosrc.parse_project(rest[1:])
    root, members = cargo_workspace(exe, tc, env, cwd, project.manifest_path)
    lock_path = os.path.join(root, "Cargo.lock")
    snap = Snapshot([lock_path, os.path.join(root, "Cargo.toml"), *members])
    home = cargosrc.cargo_home(env)
    conf = cargosrc.config(cwd, env, project.configs)
    registry = cargosrc.registry_of(conf["source"], conf["registries"], env)
    before_lock = read_cargo_lock(lock_path, strict=False)             # (one cargo cannot read is for cargo to say: all count as new)
    before_unpacked = cargosrc.crate_dirs(home)
    ctx.unchecked_hint = ("cargo got them from somewhere the guard did not look (a git source, a registry the lockfile does not "
                          "name); look at what cargo unpacked, or run the command again")
    restored, proc = [], None
    try:
        if sub in CARGO_RESOLVES:
            proc = run_tool([exe, *tc, sub, *cargo_plan_config(ctx), *rest[1:]], env, cwd=cwd)
            if proc.returncode != 0:
                return finish(ctx, installed=False, restored=snap.restore(), code=proc.returncode)
        elif not project.locked:
            resolve = [exe, *tc, "update", *cargo_plan_config(ctx), "--workspace"] \
                + (["--manifest-path", project.manifest_path] if project.manifest_path else []) + (["--offline"] if project.offline else [])
            proc = run_tool(resolve, env, cwd=cwd, capture=True)
            if proc.returncode != 0:
                show_failure(ctx, f"resolving (cargo {sub})", proc)
                return finish(ctx, installed=False, restored=snap.restore(), code=EXIT_RESOLVE)
        after = read_cargo_lock(lock_path)
        if sub in CARGO_RESOLVES:                     # (what the command changed is what it adds)
            was = {(p.name, p.version, p.source, p.checksum) for p in before_lock}
            fetched = [p for p in after if (p.name, p.version, p.source, p.checksum) not in was]
            label = "what the command added to Cargo.lock"
        else:
            fetched, label = after, "Cargo.lock"
        listed = check_cargo_packages(ctx, fetched, registry, home, project.offline, label)
        if sub not in CARGO_RESOLVES:
            listed |= {f"{p.name}-{p.version}" for p in after if cargosrc.classify(p.source).kind != "path"}
        blocked = bool(ctx.blocked())
        if blocked or ctx.opts.plan:
            restored = snap.restore()
            return finish(ctx, installed=False, restored=restored, code=EXIT_OK)
        if sub in CARGO_RESOLVES:
            return finish(ctx, installed=True, code=proc.returncode)
        # (the lock just checked, kept as it is: cargo stops rather than resolve to crates the guard did not check)
        locked = [] if project.locked else ["--locked"]
        proc = run_tool([exe, *tc, sub, *locked, *rest[1:]], env, cwd=cwd)
        ctx.unchecked = sorted(cargosrc.crate_dirs(home) - before_unpacked - listed)     # (a build script that fails still ran)
        return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)
    except BaseException:
        snap.restore()
        raise


def cargo_scratch_lock(ctx, exe, tc, env, scratch, name, req, offline, cwd):
    """The lock cargo makes for a project that needs crate `name` at `req` (None: the newest) and nothing else, which is the
    resolution `cargo install` makes for it: -> [cargosrc.Package], or None when cargo could not resolve it. The project is
    its own workspace (`[workspace]`: no Cargo.toml above it joins it), and cargo runs from `cwd`, the user's folder, so its
    configuration and rustup's toolchain are the ones `cargo install` run there reads, not a folder's above the scratch."""
    os.makedirs(os.path.join(scratch, "src"))
    with open(os.path.join(scratch, "Cargo.toml"), "w", encoding="utf-8") as f:
        f.write('[package]\nname = "lazaret-guard-plan"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n\n'
                f'[dependencies]\n{name} = {json.dumps(req or "*")}\n')
    with open(os.path.join(scratch, "src", "lib.rs"), "w", encoding="utf-8") as f:
        f.write("")
    argv = [exe, *tc, "generate-lockfile", *cargo_plan_config(ctx), "--manifest-path", os.path.join(scratch, "Cargo.toml")] \
        + (["--offline"] if offline else [])
    proc = run_tool(argv, env, cwd=cwd, capture=True)
    if proc.returncode != 0:
        show_failure(ctx, f"resolving (cargo install {name})", proc)
        return None
    return read_cargo_lock(os.path.join(scratch, "Cargo.lock"))


def _install_root(packages, name):
    """The crate `cargo install name` builds in a lock made for a project that needs only it: the one registry crate of that
    name (crates.io folds case and `_` as `-`), the highest when the lock holds more than one."""
    want = name.lower().replace("_", "-")
    named = [p for p in packages if p.name.lower().replace("_", "-") == want and cargosrc.classify(p.source).kind != "path"]
    return max(named, key=lambda p: crates.semver_key(p.version) or ()) if named else None


def guard_cargo_install(ctx, tc, rest):
    """cargo install <crate>…: for each crate, the version cargo picks (the lock of a project that needs only it), that release
    checked, and then the lock cargo makes for it as the root of a workspace of its own with every feature on (which is how
    `cargo install` resolves an installed crate, whatever features are asked); with --locked, the Cargo.lock the crate was
    published with. Every crate in it is checked, and cargo then installs the release checked (`name@=version`), not one
    published in the meantime."""
    try:
        want = cargosrc.parse_install(rest)
    except ValueError as exc:
        raise GuardError(str(exc)) from None
    exe = find_tool("cargo")
    env = dict(os.environ)
    cwd = os.getcwd()
    home = cargosrc.cargo_home(env)
    conf = cargosrc.config(cwd, env, want.configs)
    registry = cargosrc.registry_of(conf["source"], conf["registries"], env)
    before_unpacked = cargosrc.crate_dirs(home)
    ctx.unchecked_hint = ("cargo got them from somewhere the guard did not look; look at what cargo unpacked, or run the "
                          "command again")
    scratch = private_scratch("lazaret-guard-")
    listed, pinned = set(), []                      # (every crate any of the lockfiles names: checked, or noted, once)
    try:
        for k, (name, req) in enumerate(want.crates):
            here = os.path.join(scratch, str(k))
            packages = cargo_scratch_lock(ctx, exe, tc, env, os.path.join(here, "dependent"), name, req, want.offline, cwd)
            if packages is None:
                return finish(ctx, installed=False, code=EXIT_RESOLVE)
            root = _install_root(packages, name)
            if root is None:
                ctx.say(f"lazaret guard: cargo's resolution for {name} does not hold it, so what cargo install builds is not "
                        f"known: nothing installed")
                return finish(ctx, installed=False, code=EXIT_RESOLVE)
            pinned.append((root.name, root.version))
            kept = {}
            listed |= check_cargo_packages(ctx, [root], registry, home, want.offline, f"{name}, the crate cargo install builds",
                                           keep=kept)
            data = kept.get((root.name, root.version))
            built = None
            if data is not None and want.locked:
                built = _published_lock(ctx, data, root)
            if data is not None and built is None and not ctx.blocked():
                built = cargo_crate_lock(ctx, exe, tc, env, os.path.join(here, "crate"), data, root, want.offline, cwd)
                if built is None:
                    return finish(ctx, installed=False, code=EXIT_RESOLVE)
            if built is None:                       # (its bytes are not to be had: the crates a dependent of it resolves)
                built = packages
            listed |= check_cargo_packages(ctx, built, registry, home, want.offline, f"what cargo install {name} builds",
                                           skip=listed)
        if ctx.blocked() or ctx.opts.plan:
            return finish(ctx, installed=False, code=EXIT_OK)
    finally:
        remove_tree(scratch)
    proc = run_tool([exe, *tc, "install", *cargosrc.pinned_install(rest, want, pinned)], env, cwd=cwd)
    # (whether cargo succeeded or not: a build script that fails still ran)
    ctx.unchecked = sorted(cargosrc.crate_dirs(home) - before_unpacked - listed)
    return finish(ctx, installed=proc.returncode == 0, code=proc.returncode)


def cargo_crate_lock(ctx, exe, tc, env, folder, data, root, offline, cwd):
    """The lock `cargo install` makes for crate `root`: the crate's files (its bytes as the guard checked them) as the root of
    a workspace of its own, resolved with every feature of it on, as cargo resolves an installed crate's lock, the Cargo.lock it
    was published with left out (cargo install reads it only with --locked). cargo runs from `cwd`, the user's folder, and
    only resolves: no code of the crate's runs. -> [cargosrc.Package], or None when cargo could not resolve it."""
    os.makedirs(folder)
    real = os.path.realpath(folder)
    for rel, _size, raw, reason in repo.iter_archive(data, "tgz", "crate"):
        if reason is not None or rel in ("Cargo.lock", ".cargo-ok"):
            continue
        path = os.path.realpath(os.path.join(folder, *rel.split("/")))
        if not path.startswith(real + os.sep):
            continue                                # (iter_archive's paths stay inside: this holds whatever it says)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(raw)
    manifest = os.path.join(folder, "Cargo.toml")
    text = read_text(manifest)
    if text is None:
        ctx.say(f"lazaret guard: {root.name}@{root.version} has no Cargo.toml: what cargo install builds is not known")
        return None
    try:
        own_workspace = isinstance(sca.load_toml(text).get("workspace"), dict)
    except ValueError:
        own_workspace = False                       # (cargo will say what it cannot read)
    if not own_workspace:
        with open(manifest, "a", encoding="utf-8") as f:
            f.write("\n[workspace]\n")
    argv = [exe, *tc, "generate-lockfile", *cargo_plan_config(ctx), "--manifest-path", manifest] + (["--offline"] if offline else [])
    proc = run_tool(argv, env, cwd=cwd, capture=True)
    if proc.returncode != 0:
        show_failure(ctx, f"resolving (cargo install {root.name}, the crate's own lock)", proc)
        return None
    return read_cargo_lock(os.path.join(folder, "Cargo.lock"))


def _published_lock(ctx, data, root):
    """The crates in the Cargo.lock a crate was published with (`cargo install --locked` builds with them), or None when the
    crate has none (cargo then resolves it as without --locked). A lock the guard cannot be sure of is blocked: two of them in
    the archive (cargo unpacks the last), one too large to read, or one that is not a lockfile."""
    if data is None:
        return None
    found, reasons = [], []
    for rel, _size, raw, reason in repo.iter_archive(data, "tgz", "crate"):
        if rel == "Cargo.lock":
            found.append(raw)
            reasons.append(reason)
    if not found:
        return None
    problem = None
    if len(found) > 1:
        problem = "its archive holds two Cargo.lock files (cargo unpacks the last one)"
    elif reasons[0] is not None:
        problem = "its Cargo.lock is too large to read"
    else:
        try:
            return cargosrc.parse_lock(bytes(found[0]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            problem = "its Cargo.lock is not a lockfile the guard can read"
    ctx.block(ctx.add(Check("crates", root.name, root.version, "registry")),
              f"{problem}: cargo install --locked would build crates the guard has not seen")
    return []


# ---------------- Reporting ----------------
_VERDICT_ORDER = {"SUSPICIOUS": 0, "INCOMPLETE": 1, "WARN": 2, None: 3, "OK": 4}
#: Packages to review listed one per line; the rest are counted (--json lists them all)
SHOW_REVIEW = 15


def _and(items):
    """'a', 'a and b', 'a, b and c'."""
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def finish(ctx, installed, restored=(), code=None, index=None):
    """Print what was checked and why anything was blocked; write --json.
    -> the exit code."""
    checks = sorted(ctx.checks, key=lambda c: (not c.blocked, _VERDICT_ORDER.get(c.verdict, 3), c.name, c.version))
    blocked = [c for c in checks if c.blocked]
    counts = {}
    for c in checks:
        counts[c.verdict or "not checked"] = counts.get(c.verdict or "not checked", 0) + 1
    if checks:
        ctx.say("lazaret guard: checked " + ", ".join(f"{n} {v}" for v, n in sorted(
            counts.items(), key=lambda kv: _VERDICT_ORDER.get(kv[0] if kv[0] != "not checked" else None, 3))))
    for c in blocked:
        what = c.label() + (f" ({c.source})" if c.source and c.eco == "pypi" else "")
        ctx.say(f"  BLOCKED    {what}: " + "; ".join(c.blocked))
        for msg in c.indicators[:3]:
            ctx.say(f"             {msg}")
    review = [c for c in checks if not c.blocked and (c.notes or c.verdict in ("WARN", "INCOMPLETE", "SUSPICIOUS"))]
    for c in review[:SHOW_REVIEW]:
        head = "TRUSTED" if c.trusted else (c.verdict or "NOTE")
        ctx.say(f"  {head:<10} {c.label()}: " + "; ".join(c.notes or [c.reason]))
    if len(review) > SHOW_REVIEW:
        ctx.say(f"  … and {len(review) - SHOW_REVIEW} more to review"
                + ("" if ctx.opts.json else " (--json PATH lists them all)"))
    held = index.held_back if index is not None else {}
    for message in (index.errors[:5] if index is not None else []):
        ctx.say(f"  index      {message}")
    for project, versions in sorted(held.items()):
        newest = max(versions.values())
        ctx.say(f"  held back  {project}: {plural(len(versions), 'release')} younger than {format_age(ctx.min_age)} "
                f"(newest {format_age((now() - newest).total_seconds())} old; --allow-new {project} lets them in)")
    if ctx.age_unknown:
        names = sorted(set(ctx.age_unknown))
        ctx.say(f"lazaret guard: the publish time of {plural(len(names), 'release')} is not known, so --min-age could not hold "
                f"{'it' if len(names) == 1 else 'them'}: {', '.join(names[:10])}" + (f", … (+{len(names) - 10})" if len(names) > 10 else "")
                + " (--block-warn blocks them)")
    for line in ctx.notes:
        ctx.say("lazaret guard: " + line)
    if ctx.unchecked:
        what = "installed but not checked" if installed else "fetched but not checked (the command then failed)"
        ctx.say(f"lazaret guard: {what}: {', '.join(ctx.unchecked[:10])}"
                + (f", … (+{len(ctx.unchecked) - 10})" if len(ctx.unchecked) > 10 else "")
                + f" — {ctx.unchecked_hint}")
    exit_code = EXIT_OK if code is None else code
    if blocked:
        tail = f"; {_and(restored)} put back" if restored else ""
        ctx.say(f"lazaret guard: {len(blocked)} blocked — nothing was installed{tail}")
        exit_code = EXIT_BLOCKED
    elif ctx.opts.plan and not installed and exit_code == EXIT_OK:
        ctx.say("lazaret guard: nothing blocked (--plan: nothing was installed"
                + (f"; {_and(restored)} put back" if restored else "") + ")")
    elif ctx.unchecked and exit_code == EXIT_OK:
        exit_code = EXIT_BLOCKED
    if ctx.cache is not None:
        ctx.cache.save()
    if ctx.opts.json:
        doc = {"generatedBy": "lazaret-guard-1", "tool": ctx.opts.tool, "command": ctx.opts.args,
               "minAgeSeconds": ctx.min_age, "cutoff": iso(ctx.cutoff) if ctx.cutoff else None,
               "installed": bool(installed and not blocked), "blocked": len(blocked), "exitCode": exit_code,
               "leftOutForOtherPlatforms": ctx.skipped_platform, "installedUnchecked": ctx.unchecked,
               "ageUnknown": sorted(set(ctx.age_unknown)),
               "notes": list(ctx.notes),
               "packages": [c.to_json() for c in checks],
               "heldBack": {p: sorted(v) for p, v in held.items()}}
        if timings.current() is not None:
            doc["timings"] = timings.current().report()
        try:
            with open(ctx.opts.json, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
        except OSError as exc:
            ctx.say(f"lazaret guard: could not write {ctx.opts.json}: {exc.strerror}")
    return exit_code


# ---------------- Command line ----------------
def build_parser():
    ap = argparse.ArgumentParser(
        prog="lazaret guard",
        description="Check what npm, pnpm, yarn, Bun, pip, uv, go or cargo is about to install — resolve, fetch, scan in "
                    "memory — and block it before it runs when a package is SUSPICIOUS or too new.",
        epilog="Examples: lazaret guard npm install express · lazaret guard pip install -r requirements.txt · "
               "lazaret guard uv add httpx · lazaret guard yarn add lodash · lazaret guard uvx ruff check . · "
               "lazaret guard go get example.com/m@v1.2.3 · lazaret guard cargo install --locked ripgrep · "
               "lazaret guard --min-age 7d pnpm add react")
    ap.add_argument("--version", action="version", version=f"lazaret guard {lazaret.VERSION}")
    ap.add_argument("--min-age", default="2d", metavar="AGE",
                    help="hold back or block releases younger than this (default 2d; s, m, h, d, w; 0 turns it off)")
    ap.add_argument("--allow-new", action="append", default=[], metavar="NAME",
                    help="let NAME's new releases through the --min-age check; they are still scanned "
                         "(repeatable; patterns like '@types/*' work)")
    ap.add_argument("--trust", action="append", default=[], metavar="NAME",
                    help="install NAME whatever the guard finds or can't check — a finding you reviewed, a "
                         "package it can't fetch; it is still reported (repeatable; patterns work)")
    ap.add_argument("--block-warn", action="store_true",
                    help="block packages judged WARN or INCOMPLETE too (default: SUSPICIOUS only)")
    ap.add_argument("--plan", action="store_true",
                    help="resolve, fetch and scan, then stop: install nothing (a dry run)")
    ap.add_argument("--from-plan", action="store_true",
                    help="pip: install the files that were scanned, from a folder, instead of resolving and "
                         "downloading again (needs wheels only; otherwise pip goes through the index as usual)")
    ap.add_argument("--json", metavar="PATH", help="write what was checked, as JSON")
    ap.add_argument("--keepalive", action="store_true",
                    help="reuse connections between the guard's requests (experimental: with --timings, compare "
                         "the network lines with and without it)")
    ap.add_argument("--timings", action="store_true",
                    help="say on stderr (and in --json) where the time went: the network, the scans, the package "
                         "manager, the rest")
    ap.add_argument("--no-cache", action="store_true", help="scan every artifact again (no verdict cache)")
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS, metavar="N",
                    help=f"scan workers that run at once (default {DEFAULT_JOBS}); each is a process of its own, "
                         "with the cores shared out among them")
    ap.add_argument("--no-isolate", dest="isolate", action="store_false",
                    help="scan in this process, one archive at a time, instead of in worker processes (for a "
                         "platform where workers cannot start; a scan that grows too large then grows this process)")
    ap.add_argument("--worker-memory", type=int, default=scanpool.DEFAULT_MEMORY_MB, metavar="MB",
                    help="address space one scan worker may use, on platforms that have such a limit "
                         f"(default {scanpool.DEFAULT_MEMORY_MB}; 0 for none); a scan over it is not cleared")
    ap.add_argument("--scan-timeout", type=float, default=repo.SCAN_TIMEOUT, metavar="SEC",
                    help=f"seconds to scan one artifact (default {repo.SCAN_TIMEOUT:g})")
    ap.add_argument("tool", choices=TOOLS, help="the package manager")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="its command, as you would type it")
    return ap


def main(argv=None):
    """`lazaret guard` / `lazaret-guard`. -> exit code (0 installed or
    nothing to do; 1 blocked, or installed something it did not check; 2
    usage; 3 the resolution failed; else the package manager's own exit
    code)."""
    lazaret.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    first_tool = next((k for k, a in enumerate(argv) if a in TOOLS), len(argv))
    if "--" in argv[:first_tool]:
        argv.remove("--")
    opts = build_parser().parse_args(argv)
    if not getattr(opts, "timings", False):
        return _run(opts)
    kept = timings.Timings()
    with timings.capture(kept), kept.run():
        code = _run(opts)
    report = kept.report()
    if code != EXIT_USAGE or report["phases"]:             # (a command line that was refused took no time worth telling)
        for line in timings.render(report):
            print(line, file=sys.stderr)
    return code


def _run(opts):
    ctx = None
    try:
        opts.min_age = parse_duration(opts.min_age)
        if opts.jobs < 1:
            raise GuardError("--jobs: at least 1")
        if opts.worker_memory < 0:
            raise GuardError("--worker-memory: MB, or 0 for no limit")
        ctx = Context(opts)
        tool, args = opts.tool, list(opts.args)
        ctx.say(f"lazaret guard: {tool} {' '.join(args)}".rstrip())
        if opts.from_plan and tool != "pip":
            ctx.say(f"lazaret guard: --from-plan is for pip; {tool} goes through the index as usual")
        if tool in ("npm", "pnpm"):
            return guard_npm(ctx, tool, args)
        if tool == "yarn":
            return guard_yarn(ctx, args)
        if tool == "bun":
            return guard_bun(ctx, args)
        if tool == "go":
            return guard_go(ctx, args)
        if tool == "cargo":
            return guard_cargo(ctx, args)
        if tool == "uv" and args[:1] and args[0] in UV_PROJECT:
            return guard_uv_project(ctx, args)
        if tool == "uvx" or (tool == "uv" and args[:1] == ["tool"] and args[1:2] in (["run"], ["install"])):
            return guard_uv_tool(ctx, args, via_uvx=tool == "uvx")
        if tool == "uv" and args[:1] == ["run"]:
            return guard_uv_run(ctx, args)
        if tool == "uv" and args[:1] != ["pip"]:
            raise GuardError("lazaret guard wraps uv add, uv sync, uv lock, uv run, uv tool run, uv tool install, "
                             "uv pip install and uv pip sync (and uvx)")
        return guard_pip(ctx, tool, args)
    except GuardError as exc:
        print(f"lazaret guard: {lazaret.sanitize_term_line(str(exc))}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("lazaret guard: interrupted — nothing more was installed", file=sys.stderr)
        return 130
    finally:
        if ctx is not None:
            ctx.close()


def console_main():
    sys.exit(main())


if __name__ == "__main__":
    console_main()
