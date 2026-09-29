"""lazaret guard — check what a package manager is about to install, before it runs.

    lazaret guard npm install express
    lazaret guard pnpm add react
    lazaret guard pip install requests
    lazaret guard uv add httpx            (also: uv sync, uv lock, uv pip install, uv pip sync)
    lazaret-guard …                       (the same command under its own name)

npm, pnpm and uv's project commands: the tool resolves first, installing
nothing (npm --package-lock-only, pnpm --lockfile-only, uv add --no-sync,
uv lock). Every package the new lockfile installs on this machine that is not
installed yet is then fetched from where the tool will fetch it, checked
against the lockfile's digest (the bytes the tool will accept), and scanned in
memory with the registry auditor's tests (lazaret.registry.repo). Releases
younger than --min-age are held back where the tool can do it without writing
the cutoff into the lockfile (npm's `before`, pnpm's minimum-release-age), and
blocked where it can't. A SUSPICIOUS package, one that could not be checked,
or one younger than --min-age blocks the install: the files the resolution
changed (package.json, the lockfile, pyproject.toml) are put back and nothing
is installed. Otherwise the command runs as given, and what it installed is
compared with what was checked.

pip and uv pip: the tool runs against an index on 127.0.0.1 that relays PyPI.
Releases younger than --min-age are left out of it, and every file the tool
downloads is scanned before it is handed over: a SUSPICIOUS one is refused,
and pip and uv install nothing unless every download succeeded (an sdist is
scanned before pip or uv can build it, which runs its code). The tool resolves
first (a dry run) and the files of its plan are scanned before anything is
installed.

Nothing is sent anywhere but the registries the packages come from. Verdicts
are kept in a local cache keyed by the artifact's digest (--no-cache to skip),
so a package is fetched and scanned once.
"""
import argparse
import base64
import concurrent.futures
import datetime
import email.utils
import fnmatch
import glob
import hashlib
import html
import http.server
import ipaddress
import json
import multiprocessing
import os
import platform
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from lazaret.scanner import core as lazaret
from lazaret.scanner import sca
from lazaret.registry import repo

#: Releases younger than this are held back or blocked (--min-age).
DEFAULT_MIN_AGE = 2 * 86400
EXIT_OK, EXIT_BLOCKED, EXIT_USAGE, EXIT_RESOLVE = 0, 1, 2, 3
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_SIMPLE = "https://pypi.org/simple/"
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
TOOLS = ("npm", "pnpm", "pip", "pip3", "uv")

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
def _is_loopback(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def fetchable(url):
    """Can the guard fetch this URL at all: https, or http on this machine?"""
    try:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(parts.hostname))
    except ValueError:
        return False


def netloc(url):
    try:
        return urllib.parse.urlsplit(url).netloc.lower()
    except ValueError:
        return ""


class Fetcher:
    """Fetches from the named hosts only: https, or plain http to a loopback
    host (a registry served on this machine) or to a host the package
    manager's own settings name as a registry (http_hosts; what comes from
    there is checked against a digest). Redirects are held to the same rule;
    every response is read in chunks against a byte budget."""

    def __init__(self, hosts, http_hosts=()):
        self.hosts = {h.lower() for h in hosts if h}
        self.http_hosts = {h.lower() for h in http_hosts if h}
        self.lock = threading.Lock()

    def allow(self, url):
        """Let the fetcher reach url's host too."""
        host = netloc(url)
        if host:
            with self.lock:
                self.hosts.add(host)

    def check(self, url):
        try:
            parts = urllib.parse.urlsplit(url)
            host, loc = (parts.hostname or "").lower(), parts.netloc.lower()
        except ValueError as exc:
            raise repo.FetchError(f"unparseable URL {url!r}") from exc
        plain_ok = parts.scheme == "http" and (_is_loopback(host) or loc in self.http_hosts or host in self.http_hosts)
        if parts.scheme != "https" and not plain_ok:
            raise repo.FetchError(f"only https is fetched (or http on this machine): {url}")
        with self.lock:
            known = loc in self.hosts or host in self.hosts
        if not known:
            raise repo.FetchError(f"host not allowed for this install: {loc!r}")
        return url

    def _opener(self, url):
        fetcher = self

        class Redirects(urllib.request.HTTPRedirectHandler):
            max_redirections = repo.MAX_REDIRECTS

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                try:
                    fetcher.check(newurl)
                except repo.FetchError as exc:
                    raise urllib.error.URLError(f"redirect blocked: {exc}")
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        handlers = [Redirects]
        if _is_loopback(urllib.parse.urlsplit(url).hostname):
            handlers.append(urllib.request.ProxyHandler({}))      # never through a proxy
        return urllib.request.build_opener(*handlers)

    def fetch(self, url, max_bytes=repo.MAX_DOWNLOAD_BYTES, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
        """-> (body, response headers)."""
        self.check(url)
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(url, headers=headers)
        too_big = f"response over {max_bytes // (1024 * 1024)}MB: {url}"
        try:
            with self._opener(url).open(req, timeout=timeout) as r:
                length = r.headers.get("Content-Length")
                if length and length.isdigit() and int(length) > max_bytes:
                    raise repo.FetchError(too_big)
                buf = bytearray()
                while True:
                    chunk = r.read(64 * 1024)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise repo.FetchError(too_big)
                return bytes(buf), r.headers
        except urllib.error.HTTPError as exc:
            exc.close()
            err = repo.FetchError(f"HTTP {exc.code} fetching {url}")
            err.status = exc.code
            raise err from None
        except urllib.error.URLError as exc:
            raise repo.FetchError(f"URL error fetching {url}: {exc.reason}") from exc
        except OSError as exc:
            raise repo.FetchError(f"network error fetching {url}: {exc}") from exc

    def get(self, url, max_bytes=repo.MAX_DOWNLOAD_BYTES, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
        return self.fetch(url, max_bytes, accept, timeout)[0]

    def json(self, url, accept="application/json"):
        return repo._deep_safe_loads(self.get(url, MAX_DOCUMENT, accept, repo.METADATA_TIMEOUT), f"from {url}")


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
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"engine": repo.ENGINE_VERSION, "verdicts": dict(items)}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass                                    # a cache that can't be written is only slower


def default_cache_path():
    explicit = os.environ.get("LAZARET_GUARD_CACHE")
    if explicit:
        return explicit
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "lazaret", "guard-verdicts.json")


def _scan_one(data, container, kind, timeout):
    """Scan one archive (in a worker process, or here) -> the verdict."""
    budget = repo.Budget(deadline=time.monotonic() + timeout, deadline_detail="scan time budget exceeded")
    res = repo._scan_artifact(data, container, kind, False, budget)
    return {"verdict": res["verdict"], "reason": res["verdictReason"], "indicators": summarize(res)}


class Scanner:
    """Scans artifacts in memory (lazaret.registry.repo._scan_artifact),
    several at a time in worker processes (--jobs: scanning is CPU-bound);
    here, one at a time, when --jobs is 1 or the workers can't run."""

    def __init__(self, cache, timeout=repo.SCAN_TIMEOUT, jobs=1):
        self.cache = cache
        self.timeout = timeout
        self.jobs = jobs
        self._pool = None
        self._no_pool = jobs <= 1
        self._stuck = False
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
                try:
                    self._pool = concurrent.futures.ProcessPoolExecutor(
                        max_workers=self.jobs, mp_context=multiprocessing.get_context("spawn"))
                except (OSError, ValueError, ImportError, NotImplementedError):
                    self._no_pool = True
            return self._pool

    def scan(self, data, container, kind):
        """-> {verdict, reason, indicators}; ScanError when the scanner can't
        get through the artifact."""
        pool = self._get_pool()
        if pool is not None:
            try:
                future = pool.submit(_scan_one, data, container, kind, self.timeout)
            except (RuntimeError, OSError):
                future = None
            if future is not None:
                try:
                    return future.result(timeout=2 * self.timeout + 60)
                except concurrent.futures.TimeoutError:
                    self._stuck = True
                    raise ScanError("the scan did not finish") from None
                except concurrent.futures.process.BrokenProcessPool:
                    with self._lock:
                        self._no_pool = True        # scan here from now on
                except Exception as exc:
                    raise ScanError(f"the scan failed ({type(exc).__name__})") from None
        with self._here:
            try:
                return _scan_one(data, container, kind, self.timeout)
            except Exception as exc:
                raise ScanError(f"the scan failed ({type(exc).__name__})") from None

    def close(self):
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is None:
            return
        if self._stuck:                             # a worker that never finished: stop it
            for proc in list(getattr(pool, "_processes", {}).values()):
                try:
                    proc.terminate()
                except (OSError, AttributeError):
                    pass
        pool.shutdown(wait=not self._stuck, cancel_futures=True)


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
    node = shutil.which("node", path=(env or os.environ).get("PATH"))
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
    return pep503(name) if eco == "pypi" else name.lower()


class Context:
    """One guard run: the options, the scanner, the policy, what was checked."""

    def __init__(self, opts, out=None):
        self.opts = opts
        self.min_age = opts.min_age
        self.started = now()
        self.cutoff = self.started - datetime.timedelta(seconds=self.min_age) if self.min_age else None
        self.cache = None if opts.no_cache else VerdictCache(default_cache_path())
        self.scanner = Scanner(self.cache, timeout=opts.scan_timeout, jobs=opts.jobs)
        self.checks = []
        self.lock = threading.Lock()
        self.out = out or sys.stderr
        self.skipped_platform = 0           # lockfile packages for other platforms, left out
        self.expected = set()               # (name key, version) the tool may install: checked or noted
        self.unchecked = []                 # installed, but not checked (verify_installed)

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
        """Block a release younger than --min-age (unless --allow-new names it)."""
        if published is None:
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
        if "response over" in str(exc):
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


# ---------------- npm and pnpm packages ----------------
def tool_config(exe, env, cwd):
    """The package manager's settings (`<tool> config list --json`); {} when
    it can't say."""
    try:
        out = subprocess.run([exe, "config", "list", "--json"], env=env, cwd=cwd, capture_output=True,
                             text=True, encoding="utf-8", errors="replace", timeout=60).stdout
        doc = json.loads(out)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _registry_url(value):
    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        return None
    return value if value.endswith("/") else value + "/"


class Registries:
    """The default npm registry and the scoped ones (@scope:registry), from
    the package manager's settings."""

    def __init__(self, config):
        self.default = _registry_url(config.get("registry")) or NPM_REGISTRY
        self.scoped = {}
        for k, v in config.items():
            url = _registry_url(v)
            if url and isinstance(k, str) and k.startswith("@") and k.endswith(":registry"):
                self.scoped[k[:-len(":registry")]] = url
        self.replace_npmjs = config.get("replace-registry-host") != "never"

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
    registry}. The tarball is fetched from where the package manager will
    fetch it and checked against the lockfile's integrity (the bytes the
    package manager will accept) — or the registry's, when the lockfile has
    none — then scanned. Its publish time comes from the download
    (Last-Modified), confirmed by the registry when it looks recent."""
    name, version = pkg["name"], pkg["version"]
    check = ctx.add(Check("npm", name, version, "registry"))
    try:
        repo._check_name("npm", name)
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
                ctx.block(check, f"its {want[0]} digest is not the lockfile's")
                return check
            published = parse_http_date(headers.get("Last-Modified"))
            hit = ctx.scanner.scan(data, "tgz", "npm")
        if ctx.cutoff is not None and (published is None or published > ctx.cutoff):
            published = npm_publish_time(fetcher, pkg["registry"], name, version) or published
        ctx.scanner.remember(key, hit, published)
        ctx.apply(check, hit)
        ctx.age_check(check, published)
    except (repo.FetchError, repo.SpecError, ValueError) as exc:
        ctx.not_checked(check, exc)
    return check


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


class PypiIndex:
    """What the local index knows: the project pages it served (their files,
    by a number) and the files it scanned, kept on disk (spool) until the
    tool has them."""

    def __init__(self, ctx, fetcher, spool, upstream=None):
        self.ctx = ctx
        self.fetcher = fetcher
        self.spool = spool
        self.simple = upstream or pypi_upstream()
        self.files = {}           # number -> {url, project, filename, version, sha256, published, size}
        self.numbers = {}         # upstream url -> number
        self.results = {}         # number -> (Check, spooled file or None)
        self.held_back = {}       # project -> {version: upload time}
        self.lock = threading.Lock()
        self.number_locks = {}

    def page(self, project):
        """The project page, as JSON, with the files younger than --min-age
        left out and the URLs pointing here."""
        doc = self.fetcher.json(self.simple + project + "/", accept=_SIMPLE_JSON)
        if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
            raise repo.FetchError(f"no project page for {project}")
        name = doc.get("name") if isinstance(doc.get("name"), str) else project
        kept, dropped_versions, kept_versions = [], set(), set()
        for f in doc["files"]:
            if not isinstance(f, dict) or not isinstance(f.get("url"), str) or not isinstance(f.get("filename"), str):
                continue
            filename = f["filename"]
            upstream = urllib.parse.urljoin(self.simple + project + "/", f["url"]).split("#", 1)[0]
            if not fetchable(upstream) or "/" in filename or "\\" in filename or filename in (".", ".."):
                continue
            version = file_version(filename)
            published = parse_time(f.get("upload-time"))
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
                self.files[number] = {"url": upstream, "project": name, "filename": filename, "version": version,
                                      "sha256": sha.lower(), "published": published,
                                      "size": f.get("size") if isinstance(f.get("size"), int) else None}
            self.fetcher.allow(upstream)
            g = dict(f)
            g["url"] = f"/files/{number}/{urllib.parse.quote(filename)}"
            kept.append(g)
        out = dict(doc)
        out["files"] = kept
        if isinstance(doc.get("versions"), list):
            out["versions"] = [v for v in doc["versions"] if v not in dropped_versions or v in kept_versions]
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
                    raise repo.FetchError(f"response over {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB: "
                                          f"{info['filename']}")
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


def make_index_server(index):
    """A threaded HTTP server on 127.0.0.1 (a free port) serving `index`."""

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
            with index.fetcher._opener(url).open(req, timeout=repo.DOWNLOAD_TIMEOUT) as r:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                length = r.headers.get("Content-Length")
                if length and length.isdigit():
                    self.send_header("Content-Length", length)
                else:
                    self.close_connection = True
                self.end_headers()
                if self.command != "HEAD":
                    shutil.copyfileobj(r, self.wfile, 1024 * 1024)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
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
                    self._send(403, ("blocked by lazaret guard: " + "; ".join(check.blocked) + "\n").encode("utf-8"))
                elif spooled is None:
                    self._relay(info["url"])                # too large to scan: INCOMPLETE
                else:
                    self._file(spooled)
            except repo.FetchError as exc:
                status = getattr(exc, "status", None)
                self._send(404 if status == 404 else 502, (str(exc) + "\n").encode("utf-8"))
            except Exception as exc:                       # never let one request kill the server
                self._send(500, f"lazaret guard: internal error ({type(exc).__name__})\n".encode("utf-8"))

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


def run_tool(argv, env, cwd=None, capture=False):
    """Run the package manager; capture=True keeps its output (a resolution)."""
    try:
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


def guard_npm(ctx, tool, args):
    """npm and pnpm: resolve to a lockfile, check what it adds, then install."""
    sub = args[0] if args else ""
    supported = (NPM_INSTALL | NPM_CI) if tool == "npm" else PNPM_CMDS
    if sub not in supported:
        raise GuardError(f"lazaret guard wraps {tool}'s install commands ({', '.join(sorted(supported))}); "
                         f"put the command first: lazaret guard {tool} install …")
    exe = shutil.which(tool)
    if exe is None:
        raise GuardError(f"{tool} is not on PATH")
    global_install = any(a in _GLOBAL_FLAGS for a in args)
    if global_install and tool == "pnpm":
        raise GuardError("lazaret guard does not wrap pnpm's global installs; install into a project instead")
    cwd = os.getcwd()
    env = dict(os.environ)
    config = tool_config(exe, env, cwd)
    registries = Registries(config)
    native = ctx.cutoff is not None and not ctx.opts.allow_new
    if tool == "npm":
        # npm resolves nothing published after `before`: the cutoff, or the
        # start of this run, so that the install can't pick a release this
        # run did not check. A stricter `before` of the user's own stays.
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
    scratch = tempfile.mkdtemp(prefix="lazaret-guard-") if global_install else None
    try:
        if scratch:
            with open(os.path.join(scratch, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name": "lazaret-guard-plan", "version": "0.0.0", "private": true}\n')
        where = scratch or cwd
        root = scratch or npm_root(tool, cwd)
        lock_names = ["npm-shrinkwrap.json", "package-lock.json"] if tool == "npm" else ["pnpm-lock.yaml"]
        snap = Snapshot([os.path.join(where, "package.json"), os.path.join(root, "package.json")]
                        + [os.path.join(root, n) for n in lock_names])
        fresh = sub in NPM_CI or global_install                 # nothing installed counts
        before_install = set() if fresh else (installed_npm(tool, root) or set())
        try:
            code = _check_npm(ctx, tool, exe, sub, args, env, where, root, lock_names, registries,
                              before_install)
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


def _check_npm(ctx, tool, exe, sub, args, env, where, root, lock_names, registries, installed):
    """Resolve, then check what the lockfile adds. -> None to go on and
    install, else the exit code (the resolution failed, something is blocked,
    or --plan)."""
    if sub not in NPM_CI:
        flags = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"] if tool == "npm" \
            else ["--lockfile-only", "--ignore-scripts"]
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
            url = registries.resolved(e["name"], e["resolved"])
        else:
            url = registries.tarball(e["name"], e["version"]) if e["version"] else ""
        if not url or not (fetchable(url) or (url.startswith("http://") and netloc(url) in http_hosts)):
            ctx.add(Check("npm", e["name"], e["version"], e["resolved"] or "unknown source")).notes.append(
                "not from a registry (git, a local file or a link): not checked")
            continue
        if not e["version"] and sri_best(e["integrity"]) is None:
            ctx.add(Check("npm", e["name"], "", url)).notes.append(
                "a tarball URL with no digest in the lockfile (like a git dependency): not checked")
            continue
        todo[key] = {"name": e["name"], "version": e["version"], "tarball": url, "integrity": e["integrity"],
                     "registry": registries.for_name(e["name"])}
    fetcher = Fetcher({netloc(u) for u in registries.all()} | {netloc(p["tarball"]) for p in todo.values()},
                      http_hosts=http_hosts)
    other = f"; {plural(ctx.skipped_platform, 'package')} for other platforms left out" \
        if ctx.skipped_platform else ""
    ctx.say(f"lazaret guard: {plural(len(todo), 'package')} to check ({os.path.basename(lock_path)}{other})")
    run_all([lambda p=p: check_npm_package(ctx, fetcher, p) for p in todo.values()])
    if ctx.blocked():
        return EXIT_BLOCKED
    return EXIT_OK if ctx.opts.plan else None


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


def guard_uv_project(ctx, exe, args):
    """uv add / sync / lock: lock first (uv.lock), check what it adds, then run."""
    sub = args[0]
    if "--script" in args or any(a.startswith("--script=") for a in args):
        raise GuardError("lazaret guard does not wrap uv's --script commands")
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
    fetcher = Fetcher({"pypi.org"})
    jobs = []
    for p in todo:
        if p["source"] != "registry":
            ctx.add(Check("pypi", p["name"], p["version"], f"{p['source']} source")).notes.append(
                "not from a registry (git, a URL or a local file): not checked")
            continue
        for f in pick_artifacts(([p["sdist"]] if p["sdist"] else []) + p["wheels"], info):
            if not fetchable(f["url"]):
                ctx.block(ctx.add(Check("pypi", p["name"], p["version"], f["filename"])),
                          f"could not be checked: not fetched over https ({f['url'][:80]})")
                continue
            fetcher.allow(f["url"])
            jobs.append(lambda p=p, f=f: check_file(ctx, fetcher, p["name"], p["version"], f))
    ctx.say(f"lazaret guard: {plural(len(todo), 'package')} to check (uv.lock)")
    run_all(jobs)
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
    """Refuse options that point pip or uv at another index or at local
    archives — packages from there would not pass the guard — on the command
    line and in the requirement files it names (and those they include)."""
    for a in args:
        if a in PIP_INDEX_OPTIONS or a.startswith(tuple(o + "=" for o in PIP_INDEX_OPTIONS if o.startswith("--"))) \
                or (a.startswith(("-i", "-f")) and not a.startswith("--") and len(a) > 2):
            raise GuardError(f"{a.split('=')[0]}: lazaret guard serves the index itself (PyPI, checked); "
                             f"install without another index or local archives")
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
                                 f"remove index options from the requirements")
            m = _PIP_REQ_INCLUDE_RE.match(line)
            if m:
                check_pip_arguments(["-r", m.group(1)], os.path.dirname(path), depth + 1)


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
    jobs = []
    for item in items:
        info = item.get("download_info") if isinstance(item, dict) else None
        url = info.get("url") if isinstance(info, dict) and isinstance(info.get("url"), str) else ""
        meta = item.get("metadata") if isinstance(item, dict) and isinstance(item.get("metadata"), dict) else {}
        m = _FILE_PATH_RE.match(urllib.parse.urlsplit(url).path) if url.startswith(base + "/files/") else None
        if m is not None and m.group(1) in index.files:
            jobs.append(lambda n=m.group(1): index.scan(n))
            continue
        c = ctx.add(Check("pypi", str(meta.get("name", url)), str(meta.get("version", "")), url))
        if isinstance(info, dict) and ("vcs_info" in info or "dir_info" in info or url.startswith("file:")):
            c.notes.append("a local or version-control source: not checked")
        else:
            ctx.block(c, "not downloaded through lazaret guard's index, so not checked")
    ctx.say(f"lazaret guard: {plural(len(items), 'package')} to check (pip's plan)")
    run_all(jobs)
    return None


def _uv_pip_plan(ctx, index, exe, pip_args, env):
    """uv pip: resolve (--dry-run) and scan the files of the packages it
    would install. -> an exit code, or None to go on."""
    proc = run_tool([exe, "pip"] + pip_args + ["--dry-run"], env, capture=True)
    if proc.returncode != 0:
        if ctx.blocked():
            return EXIT_BLOCKED
        show_failure(ctx, f"resolving (uv pip {pip_args[0]} --dry-run)", proc)
        return EXIT_RESOLVE
    planned = [(m.group(1), m.group(2)) for m in map(_UV_PLAN_LINE_RE.match, (proc.stdout or "").splitlines()) if m]
    info = interpreter_info(uv_python(exe, pip_args, env, os.getcwd()))
    jobs = []
    for name, version in planned:
        files = index.release_files(name, version)
        picked = {f["filename"] for f in pick_artifacts([i for _, i in files], info)}
        jobs += [lambda n=n: index.scan(n) for n, i in files if i["filename"] in picked]
    ctx.say(f"lazaret guard: {plural(len(planned), 'package')} to check (uv's plan)")
    run_all(jobs)
    return None


def guard_pip(ctx, tool, args):
    """pip install, uv pip install and uv pip sync, through the local index."""
    uv = tool == "uv"
    pip_args = args[1:] if uv else list(args)
    if not pip_args or pip_args[0] not in (("install", "sync") if uv else ("install",)):
        raise GuardError("lazaret guard wraps `pip install`, `uv pip install` and `uv pip sync`")
    exe = shutil.which("uv" if uv else tool)
    if exe is None:
        raise GuardError(f"{'uv' if uv else tool} is not on PATH")
    check_pip_arguments(pip_args[1:])
    upstream = pypi_upstream()
    if not fetchable(upstream):
        raise GuardError(f"LAZARET_GUARD_PYPI_URL must be https (or http on this machine): {upstream}")
    spool = tempfile.mkdtemp(prefix="lazaret-guard-")
    fetcher = Fetcher({netloc(upstream), "pypi.org", "files.pythonhosted.org"})
    index = PypiIndex(ctx, fetcher, spool, upstream)
    server = make_index_server(index)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    env = dict(os.environ)
    if uv:
        for k in ("UV_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS", "UV_NO_INDEX"):
            env.pop(k, None)
        env.update(UV_DEFAULT_INDEX=base + "/simple", UV_INDEX_URL=base + "/simple", UV_HTTP_TIMEOUT=str(TOOL_TIMEOUT))
    else:
        for k in ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX"):
            env.pop(k, None)
        env.update(PIP_INDEX_URL=base + "/simple/", PIP_TRUSTED_HOST=f"127.0.0.1:{server.server_address[1]}",
                   PIP_DEFAULT_TIMEOUT=str(TOOL_TIMEOUT))
    if ctx.cutoff is not None:
        ctx.say(f"lazaret guard: files uploaded less than {format_age(ctx.min_age)} ago are left out of the index")
    try:
        code = _uv_pip_plan(ctx, index, exe, pip_args, env) if uv else _pip_plan(ctx, index, base, exe, pip_args, env)
        if code is None and ctx.blocked():
            code = EXIT_BLOCKED
        if code is None and ctx.opts.plan:
            code = EXIT_OK
        if code is not None:
            return finish(ctx, installed=False, index=index, code=code)
        proc = run_tool(([exe, "pip"] if uv else [exe]) + pip_args, env)
        blocked = bool(ctx.blocked())
        return finish(ctx, installed=proc.returncode == 0 and not blocked, index=index,
                      code=EXIT_BLOCKED if blocked else proc.returncode)
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(spool, ignore_errors=True)


# ---------------- Reporting ----------------
_VERDICT_ORDER = {"SUSPICIOUS": 0, "INCOMPLETE": 1, "WARN": 2, None: 3, "OK": 4}
#: Packages to review listed one per line; the rest are counted (--json lists them all)
SHOW_REVIEW = 15


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
    for project, versions in sorted(held.items()):
        newest = max(versions.values())
        ctx.say(f"  held back  {project}: {plural(len(versions), 'release')} younger than {format_age(ctx.min_age)} "
                f"(newest {format_age((now() - newest).total_seconds())} old; --allow-new {project} lets them in)")
    if ctx.unchecked:
        ctx.say(f"lazaret guard: installed but not checked: {', '.join(ctx.unchecked[:10])}"
                + (f", … (+{len(ctx.unchecked) - 10})" if len(ctx.unchecked) > 10 else "")
                + " — the registry changed while the guard checked; run it again, or remove them")
    exit_code = EXIT_OK if code is None else code
    if blocked:
        tail = f"; {' and '.join(restored)} put back" if restored else ""
        ctx.say(f"lazaret guard: {len(blocked)} blocked — nothing was installed{tail}")
        exit_code = EXIT_BLOCKED
    elif ctx.opts.plan and not installed and exit_code == EXIT_OK:
        ctx.say("lazaret guard: nothing blocked (--plan: nothing was installed"
                + (f"; {' and '.join(restored)} put back" if restored else "") + ")")
    elif ctx.unchecked and exit_code == EXIT_OK:
        exit_code = EXIT_BLOCKED
    if ctx.cache is not None:
        ctx.cache.save()
    if ctx.opts.json:
        doc = {"generatedBy": "lazaret-guard-1", "tool": ctx.opts.tool, "command": ctx.opts.args,
               "minAgeSeconds": ctx.min_age, "cutoff": iso(ctx.cutoff) if ctx.cutoff else None,
               "installed": bool(installed and not blocked), "blocked": len(blocked), "exitCode": exit_code,
               "leftOutForOtherPlatforms": ctx.skipped_platform, "installedUnchecked": ctx.unchecked,
               "packages": [c.to_json() for c in checks],
               "heldBack": {p: sorted(v) for p, v in held.items()}}
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
        description="Check what npm, pnpm, pip or uv is about to install — resolve, fetch, scan in memory — "
                    "and block it before it runs when a package is SUSPICIOUS or too new.",
        epilog="Examples: lazaret guard npm install express · lazaret guard pip install -r requirements.txt · "
               "lazaret guard uv add httpx · lazaret guard --min-age 7d pnpm add react")
    ap.add_argument("--min-age", default="2d", metavar="AGE",
                    help="hold back or block releases younger than this (default 2d; s, m, h, d, w; 0 turns it off)")
    ap.add_argument("--allow-new", action="append", default=[], metavar="NAME",
                    help="let NAME's new releases through the --min-age check; they are still scanned "
                         "(repeatable; patterns like '@types/*' work)")
    ap.add_argument("--trust", action="append", default=[], metavar="NAME",
                    help="install NAME whatever the guard finds or can't check — a package from a private "
                         "registry, a finding you reviewed; it is still reported (repeatable; patterns work)")
    ap.add_argument("--block-warn", action="store_true",
                    help="block packages judged WARN or INCOMPLETE too (default: SUSPICIOUS only)")
    ap.add_argument("--plan", action="store_true",
                    help="resolve, fetch and scan, then stop: install nothing (a dry run)")
    ap.add_argument("--json", metavar="PATH", help="write what was checked, as JSON")
    ap.add_argument("--no-cache", action="store_true", help="scan every artifact again (no verdict cache)")
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS, metavar="N",
                    help=f"processes that scan at once (default {DEFAULT_JOBS}; 1 scans in this process)")
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
    ctx = None
    try:
        opts.min_age = parse_duration(opts.min_age)
        if opts.jobs < 1:
            raise GuardError("--jobs: at least 1")
        ctx = Context(opts)
        tool, args = opts.tool, list(opts.args)
        ctx.say(f"lazaret guard: {tool} {' '.join(args)}".rstrip())
        if tool in ("npm", "pnpm"):
            return guard_npm(ctx, tool, args)
        if tool == "uv" and args[:1] and args[0] in UV_PROJECT:
            exe = shutil.which("uv")
            if exe is None:
                raise GuardError("uv is not on PATH")
            return guard_uv_project(ctx, exe, args)
        if tool == "uv" and args[:1] != ["pip"]:
            raise GuardError("lazaret guard wraps uv add, uv sync, uv lock, uv pip install and uv pip sync")
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
