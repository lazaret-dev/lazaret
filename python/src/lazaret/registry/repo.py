#!/usr/bin/env python3
"""Lazaret registry scanner — audit npm / PyPI packages for supply-chain compromise.

Fetches package archives from registry.npmjs.org / pypi.org, scans them
in memory (never extracted to disk — immune to tar-slip), and tracks scan
state in a database so you can do full or incremental sweeps.

Usage:
    lazaret-registry add npm:express pypi:requests      # track packages
    lazaret-registry scan npm:left-pad                  # scan latest version
    lazaret-registry scan npm:left-pad@1.3.0            # scan specific version
    lazaret-registry scan pypi:six --full               # full ruleset, not just supply-chain
    lazaret-registry scan-all                           # scan latest of every tracked package
    lazaret-registry list                               # tracked packages + last verdicts
    lazaret-registry report npm:left-pad@1.3.0          # stored findings for a scan

State backends (--db or LAZARET_DB env):
    default            SQLite file lazaret-registry.db (no dependencies);
                       also `sqlite:PATH` / `sqlite:///PATH`
    postgres://…       PostgreSQL via the internal wire-protocol client
                       (lazaret.pg — pure stdlib, SCRAM-SHA-256 + TLS; nothing
                       to pip-install). A libpq keyword string
                       ("host=db user=… dbname=lazaret") works too.
                       Point the DSN at a dedicated database on your server, e.g.
                       postgres://user:pass@host:5432/lazaret — see registry/schema.sql
                       for one-time setup. Don't reuse an existing application DB.

Package specs: npm:<name>[@version]  |  pypi:<name>[@version or ==version]
Scoped npm packages work: npm:@scope/pkg@1.0.0
PyPI releases are judged on every file pip may install: the sdist and each
distinct wheel (up to --max-artifacts files and --max-download-bytes in
total); the verdict is the worst of them.
"""
import argparse
import base64
import bz2
import datetime
import hashlib
import importlib
import io
import json
import lzma
import os
import posixpath
import re
import struct
import sys
import tarfile
import time
import zipfile
import zlib
import urllib.error
import urllib.parse
import urllib.request

from lazaret.scanner import core as lazaret  # noqa: E402

from lazaret import safexml as _safexml                 # noqa: E402
from lazaret.safexml import ElementTree as _safe_ET     # noqa: E402


def _env_number(var, default, kind=int):
    try:
        value = kind(os.environ.get(var, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


USER_AGENT = "Lazaret-registry-scanner/1.0"
MAX_MEMBER = 1_000_000     # bytes of a text file we will scan as source
MAX_FILES = 20_000         # files per package (numpy's sdist alone has >4,000)
SAMPLE = 8192              # header/entropy sample read from oversized files
# 2.4: every PyPI artifact, decode/cookie handling, archive structure checks,
#      entry points and hook targets, Python install scripts
ENGINE_VERSION = "2.4.0"   # 2.3: verdict tiers, decoded hex, install-script inspection; 2.2: verdict-integrity; 2.1: binary-artifact awareness

# ---------------- Trust-chain limits (F9/G14/F10) ----------------
# Only these hosts may ever be fetched, over https only, and redirects to any
# other scheme/host are refused. Everything else fails closed.
REGISTRY_HOSTS = {"registry.npmjs.org", "replicate.npmjs.com",
                  "pypi.org", "files.pythonhosted.org"}
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024     # one artifact archive (F9a)
MAX_FEED_BYTES = 5 * 1024 * 1024           # registry metadata / RSS / _changes feed
FEED_MAX_BYTES = MAX_FEED_BYTES            # XML parser cap: never above the fetch cap
# Every byte the decompressor produces counts, including member data that is
# skipped rather than read (F9b): a 2 MB gzip that inflates to 2 GiB stops here.
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024
MAX_REDIRECTS = 3                          # no redirect loops / long hop chains
FETCH_CHUNK = 64 * 1024
METADATA_TIMEOUT = 30                      # seconds for registry metadata / feeds
DOWNLOAD_TIMEOUT = 60                      # seconds for artifact archives
# Wall-clock budget for reading and scanning ONE artifact archive; past it the
# scan stops and the verdict is INCOMPLETE. Env LAZARET_SCAN_TIMEOUT / --scan-timeout.
SCAN_TIMEOUT = _env_number("LAZARET_SCAN_TIMEOUT", 120.0, float)
# PyPI: artifacts scanned per release (sdist + distinct wheels). More than
# this makes the verdict INCOMPLETE. Env LAZARET_MAX_ARTIFACTS / --max-artifacts.
# Popular binary packages publish 60-90 files per release (numpy, grpcio,
# pillow); 50 made every one of them permanently INCOMPLETE.
MAX_ARTIFACTS = _env_number("LAZARET_MAX_ARTIFACTS", 200)
# Total bytes downloaded for ONE package (all its release files together);
# checked BEFORE each download against the sizes PyPI's metadata declares, so
# a release that cannot fit is not fetched at all. Files that don't fit are
# not scanned and the verdict is INCOMPLETE. Env LAZARET_MAX_DOWNLOAD_BYTES /
# --max-download-bytes. (MAX_DOWNLOAD_BYTES above is the per-file limit.)
MAX_PACKAGE_DOWNLOAD_BYTES = _env_number("LAZARET_MAX_DOWNLOAD_BYTES", 2 * 1024 ** 3)
# Non-source text members kept in memory until package.json says whether
# they are entry points (main/bin/exports) or hook targets.
DEFERRED_TEXT_BUDGET = 64 * 1024 * 1024
# Package names come from user input AND from registry feeds, and end up in URLs
# and the watchlist — validate before either.
NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")          # versions
NAME_MAX = 214                                           # npm's limit; PyPI has none
_NPM_NAME_PART_RE = re.compile(r"^[a-zA-Z0-9~-][a-zA-Z0-9._~-]*$")
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")   # PEP 508


class SpecError(ValueError):
    """Invalid ecosystem / package name / version."""


class FetchError(ValueError):
    """A fetch was refused (bad scheme/host) or exceeded a size budget."""


class DigestError(ValueError):
    """A downloaded artifact failed its registry-published integrity check.

    Fail-closed: the scan stops and nothing is persisted for that package.
    """


class FeedError(ValueError):
    """A registry change feed was rejected as unsafe (DTD / entity declaration)."""


class StoreConfigError(RuntimeError):
    """--db / LAZARET_DB is not a usable SQLite path or Postgres DSN."""


class ScanCancelled(Exception):
    """The caller asked a running scan to stop (MCP notifications/cancelled)."""


# ---------------- Package spec parsing ----------------
def _check_npm_name(name):
    """npm's naming rules (validate-npm-package-name), restricted to URL-safe
    ASCII: an optional @scope/, at most 214 characters, no leading '.' or
    '_', nothing that could escape the registry API path."""
    if len(name) > NAME_MAX:
        raise SpecError(f"npm: package name longer than {NAME_MAX} characters")
    if name.startswith("@"):
        scope, sep, pkg = name[1:].partition("/")
        if not sep or not scope or not pkg or "/" in pkg:
            raise SpecError(f"npm: scoped name must be @scope/pkg, got {name!r}")
        parts = (scope, pkg)
    else:
        parts = (name,)
    for part in parts:
        if part in (".", "..") or not _NPM_NAME_PART_RE.fullmatch(part):
            raise SpecError(f"npm: invalid package name {name!r}")
    if name.lower() in ("node_modules", "favicon.ico"):
        raise SpecError(f"npm: reserved package name {name!r}")
    return name


def _check_name(eco, name):
    """Reject names that could escape the registry API path or poison the DB (F10).

    Names arrive from the CLI, the watchlist *and* registry discovery feeds, and
    end up interpolated into URLs and persisted — so traversal segments, path
    separators and control characters must never be accepted.
    """
    if not isinstance(name, str) or not name:
        raise SpecError(f"{eco}: empty package name")
    if eco == "npm":
        return _check_npm_name(name)
    if len(name) > NAME_MAX or not _PYPI_NAME_RE.fullmatch(name):
        raise SpecError(f"{eco}: invalid package name {name!r}")
    return name


def valid_name(eco, name):
    try:
        _check_name(eco, name)
        return True
    except SpecError:
        return False


def _check_version(eco, version):
    """Same guarantee for pinned versions; None (== latest) passes through."""
    if version is None:
        return None
    if not isinstance(version, str) or not version.strip():
        raise SpecError(f"{eco}: invalid version {version!r}")
    version = version.strip()
    if version in (".", "..") or not NAME_RE.fullmatch(version):
        raise SpecError(f"{eco}: invalid version {version!r}")
    return version


def parse_spec(spec):
    """'npm:@scope/pkg@1.2.3' -> ('npm', '@scope/pkg', '1.2.3'); version may be None."""
    if not isinstance(spec, str) or ":" not in spec:
        raise SpecError(f"Spec must be npm:<name> or pypi:<name> — got {spec!r}")
    eco, rest = spec.split(":", 1)
    eco = eco.strip().lower()
    if eco not in ("npm", "pypi"):
        raise SpecError(f"Unknown ecosystem {eco!r} (use npm or pypi)")
    rest = rest.strip().replace("==", "@")
    if rest.startswith("@"):                      # scoped npm package
        if eco != "npm":
            raise SpecError(f"{eco}: invalid package name {rest!r}")
        at = rest.find("@", 1)
        name, ver = (rest[:at], rest[at + 1:]) if at != -1 else (rest, None)
    elif "@" in rest:
        name, ver = rest.split("@", 1)
    else:
        name, ver = rest, None
    return eco, _check_name(eco, name), _check_version(eco, ver)


def _validated_url(url):
    """F10: registry fetches must be https to a known registry host.

    urlopen() honors ANY scheme by default — file:// would read local disk
    (local file disclosure), ftp://, data://… likewise. Validate before we
    ever hand a URL to the opener."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"unparseable registry URL {url!r}") from exc
    if parts.scheme != "https":
        raise FetchError(
            f"non-https registry URL blocked ({parts.scheme or 'no scheme'}): {url}")
    if parts.netloc.lower() not in REGISTRY_HOSTS:
        raise FetchError(f"registry host not allowlisted: {parts.netloc!r}")
    return url


class _RegistryOpener(urllib.request.HTTPRedirectHandler):
    """G15: urllib follows redirects to ANY host/scheme by default — a
    Location: header must not turn a registry fetch into an arbitrary
    network read. Keep redirects on https + allowlisted registry hosts,
    and cap the hop count."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _validated_url(newurl)
        except FetchError as exc:
            raise urllib.error.URLError(f"redirect blocked: {exc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_RegistryOpener)


def _fetch(url, max_bytes=MAX_DOWNLOAD_BYTES, timeout=DOWNLOAD_TIMEOUT):
    """Validated, byte-budgeted fetch (F10 + F9a). Reads in bounded chunks so
    a hostile server cannot OOM the scanner with an unbounded stream (a 300MB
    response previously pinned ~714MB RSS via bare r.read())."""
    _validated_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            buf = bytearray()
            while True:
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise FetchError(
                        f"response exceeds {max_bytes // (1024 * 1024)}MB budget: {url}")
            return bytes(buf)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"URL error fetching {url}: {exc.reason}") from exc
    except OSError as exc:                     # includes socket timeouts
        raise FetchError(f"network error fetching {url}: {exc}") from exc


def http_json(url):
    raw = _fetch(url, max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT)
    return _deep_safe_loads(raw, f"registry response from {url}")


def _deep_safe_loads(raw, what):
    """json.loads for registry-published JSON with a deep-nesting guard
    (card 1149e3e5, the primitive proven by card 48033f94's scan_manifest PoC:
    ~60KB of '[' parses a 60k-deep document and blows CPython's recursion
    limit). Applies wherever scanned-repo/registry content is consumed:
    registry metadata (resolve_npm/resolve_pypi), discovery feeds, and
    scan-all loops. A hostile response must neither kill the sweep
    (uncaught RecursionError — exit 1, every later package lost) nor silently
    vanish; we raise a FetchError naming the reason so callers treat it like
    any other network failure: warn-and-skip in the non-critical paths,
    'error scanning <spec>' + continuing in cmd_scan (nothing persisted under
    a wrong verdict, remaining work still reported)."""
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:     # JSONDecodeError, int digits
        raise FetchError(f"invalid JSON {what}: {exc}") from exc
    except RecursionError as exc:
        raise FetchError(
            f"JSON {what} is too deeply nested to parse (recursion limit "
            f"hit) — treated as a fetch failure, not a crash") from exc


def http_bytes(url):
    """Budget-limited artifact/attachment fetch (F9a): keeps reading until EOF
    but aborts as soon as the byte budget is exceeded."""
    return _fetch(url)


# ---------------- Registry metadata ----------------
class Resolution(tuple):
    """(version, url, container_format, artifact_kind, meta_entry) — the
    primary artifact, unpackable as before — plus .artifacts: every artifact
    to scan, as dicts {url, container, artifact, entry, filename}, and
    .skipped: files of the release that are not scanned (with the reason)."""

    def __new__(cls, version, artifacts, skipped=()):
        first = artifacts[0]
        self = super().__new__(cls, (version, first["url"], first["container"],
                                     first["artifact"], first["entry"]))
        self.artifacts = list(artifacts)
        self.skipped = list(skipped)
        return self


def resolve_npm(name, version):
    """-> (version, url, container_format, artifact_kind, meta_entry).
    meta_entry is the version metadata (dist.integrity digest lives there),
    consumed by scan_package for artifact verification (G15)."""
    _check_name("npm", name)
    version = _check_version("npm", version)
    # Ask for one version's manifest (/<name>/latest or /<name>/<version>), not
    # the full packument: that lists every version ever published and runs to
    # tens of MB for packages like typescript. A scoped name keeps its '@' and
    # encodes the '/' (registry.npmjs.org/@babel%2Fcore/latest).
    url = ("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@") + "/"
           + (_quote_seg(version) if version else "latest"))
    v = http_json(url)
    if not isinstance(v, dict) or not isinstance(v.get("dist"), dict) \
            or not isinstance(v["dist"].get("tarball"), str):
        raise ValueError(f"npm:{name}@{version or 'latest'} not found")
    if version is not None and v.get("version") != version:
        raise ValueError(f"npm:{name}@{version} not found")
    found = v.get("version") if isinstance(v.get("version"), str) else version
    return found or version, v["dist"]["tarball"], "tgz", "npm", v


def pypi_container(filename):
    """Archive format of a PyPI file, from its name (pip decides the same
    way); None for formats pip does not install."""
    f = (filename or "").lower()
    if f.endswith((".whl", ".zip")):
        return "zip"
    if f.endswith((".tar.gz", ".tgz")):
        return "tgz"
    if f.endswith((".tar.bz2", ".tbz", ".tbz2")):
        return "tbz2"
    if f.endswith((".tar.xz", ".txz")):
        return "txz"
    if f.endswith(".tar"):
        return "tar"
    return None


def resolve_pypi(name, version):
    """-> Resolution: (version, url, container_format, artifact_kind,
    meta_entry) of the primary file, and .artifacts = EVERY file pip may
    install for that release: the sdist and each distinct wheel (pip picks a
    compatible wheel when one exists, so scanning only the sdist judged a
    file that is usually never installed). Duplicate files (same sha256) are
    scanned once. URL path segments are quoted (F10); each entry carries its
    digests.sha256 for G15 verification."""
    _check_name("pypi", name)
    version = _check_version("pypi", version)
    url = (f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(version)}/json" if version
           else f"https://pypi.org/pypi/{_quote_seg(name)}/json")
    try:
        meta = http_json(url)
    except FetchError as exc:
        # The unversioned document lists every release's files (9 MB for
        # grpcio). Find the latest stable version from the release feed
        # instead, then fetch just that version's document.
        if version is not None or "budget" not in str(exc):
            raise
        version = pypi_latest_from_feed(name)
        meta = http_json(f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(version)}/json")
    info = meta.get("info") if isinstance(meta, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("version"), str):
        raise ValueError(f"pypi:{name}@{version or 'latest'} not found")
    version = info["version"]
    urls = meta.get("urls") if isinstance(meta.get("urls"), list) else []
    artifacts, skipped, seen = [], [], set()
    for entry in urls:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        filename = entry.get("filename") if isinstance(entry.get("filename"), str) \
            else entry["url"].rsplit("/", 1)[-1]
        kind = entry.get("packagetype")
        container = pypi_container(filename)
        if kind not in ("sdist", "bdist_wheel") or container is None:
            skipped.append({"filename": filename, "reason": f"{kind or 'unknown'} is not installed by pip"})
            continue
        digest = expected_digest(entry)
        key = digest or entry["url"]
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({"url": entry["url"], "container": container,
                          "artifact": "sdist" if kind == "sdist" else "wheel",
                          "entry": entry, "filename": filename})
    if not artifacts:
        raise ValueError(f"pypi:{name}@{version} has no downloadable archive")
    artifacts.sort(key=lambda a: (a["artifact"] != "sdist", a["filename"]))
    return Resolution(version, artifacts, skipped)


_PEP440_FINAL_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:\.post(\d+))?$")


def _final_release_key(v):
    """Sort key for a final (non-pre/dev) PEP 440 version, or None otherwise."""
    m = _PEP440_FINAL_RE.match(v.strip())
    if not m:
        return None
    release = tuple(int(x) for x in m.group(1).split("."))
    return release + (0,) * (10 - len(release)), int(m.group(2) or 0)


def pypi_latest_from_feed(name):
    """Latest final release of a PyPI project, from its release RSS feed
    (parsed with lazaret.safexml). The feed is ordered by upload time, and a
    backport can be uploaded after a newer release, so pick the highest
    version, not the first item."""
    raw = _fetch(f"https://pypi.org/rss/project/{_quote_seg(name)}/releases.xml",
                 max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT)
    try:
        root = _safe_ET.fromstring(raw, forbid_dtd=True, max_bytes=FEED_MAX_BYTES)
    except (_safexml.SafeXMLError, _safe_ET.ParseError) as exc:
        raise FeedError(f"pypi:{name}: unreadable release feed: {exc}") from None
    titles = [(item.findtext("title") or "").strip() for item in root.iter("item")]
    finals = [(key, t) for t in titles if (key := _final_release_key(t)) is not None]
    if finals:
        return max(finals)[1]
    if titles:
        return titles[0]
    raise ValueError(f"pypi:{name} has no releases")


def resolve(eco, name, version):
    """Registry metadata for one package version (network seam: tests patch
    resolve_npm / resolve_pypi)."""
    return (resolve_npm if eco == "npm" else resolve_pypi)(name, version)


# ---------------- Artifact integrity (G15) ----------------
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _quote_seg(value):
    """Percent-encode one URL path segment (package name / version)."""
    return urllib.parse.quote(str(value), safe="")


def expected_digest(meta_entry):
    """Digest published by the registry for one artifact, from its metadata
    entry. npm: dist.integrity ("sha512-<base64>"); PyPI: digests.sha256 (hex).
    -> (alg, hexdigest) or None when the registry published no digest."""
    if not isinstance(meta_entry, dict):
        return None
    dist = meta_entry.get("dist") or {}
    if isinstance(dist, dict):
        integrity = dist.get("integrity")
        if isinstance(integrity, str) and "-" in integrity:
            alg, b64 = integrity.split("-", 1)
            if alg in ("sha256", "sha512"):
                try:
                    digest = base64.b64decode(b64, validate=True)
                except (ValueError, TypeError):
                    return None
                if digest and len(digest) == hashlib.new(alg).digest_size:
                    return alg, digest.hex()
    digests = meta_entry.get("digests") or {}
    if isinstance(digests, dict):
        sha = digests.get("sha256")
        if isinstance(sha, str) and _HEX64_RE.fullmatch(sha.strip().lower()):
            return "sha256", sha.strip().lower()
    return None


def verify_digest(data, meta_entry, eco, name, version):
    """Fail closed (SC-DIGEST-MISMATCH) when the downloaded artifact does not
    match the registry-published digest (G15). Any CDN/mirror compromise or
    host-hopping redirect then yields an error instead of an unverified blob
    whose verdict is persisted under the real name/version. Returns (alg,
    hexdigest) for the result dict, or None if no digest was published."""
    expected = expected_digest(meta_entry)
    if expected is None:
        return None
    alg, want = expected
    got = hashlib.new(alg, data).hexdigest()
    if got != want:
        raise DigestError(
            f"{eco}:{name}@{version} SC-DIGEST-MISMATCH: registry metadata says "
            f"{alg}={want[:16]}… but the downloaded artifact hashes to {got[:16]}… — "
            f"refusing to scan an unverified artifact (possible CDN/mirror "
            f"compromise or man-in-the-middle)")
    return alg, want


# ---------------- In-memory archive reading ----------------
class ArchiveLimit(Exception):
    """Internal: reading stopped (reason 'total' | 'time' | 'corrupt')."""

    def __init__(self, reason, detail=""):
        super().__init__(detail or reason)
        self.reason, self.detail = reason, detail


class Budget:
    """Decompression and time budget for reading one archive. Every
    decompressed byte is charged — including member data tarfile skips over
    rather than returns — and the deadline / cancellation hook is checked
    between chunks and between members."""

    def __init__(self, total=None, deadline=None, cancel=None):
        self.limit = MAX_ARCHIVE_TOTAL if total is None else total
        self.used = 0
        self.deadline = deadline
        self.cancel = cancel

    def charge(self, n):
        self.used += n
        if self.used > self.limit:
            raise ArchiveLimit("total")

    def check(self):
        if self.cancel is not None and self.cancel():
            raise ScanCancelled("scan cancelled")
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ArchiveLimit("time")


_GZIP_MAGIC, _BZ2_MAGIC, _XZ_MAGIC = b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"
_CODEC_MAGIC = {"gz": _GZIP_MAGIC, "bz2": _BZ2_MAGIC, "xz": _XZ_MAGIC}
_INPUT_CHUNK = 64 * 1024
_OUTPUT_CHUNK = 1024 * 1024


class _Inflater:
    """Read-only, forward-only file object over one compressed tar stream.

    Decompresses in bounded chunks with the container's REAL codec (gzip for
    npm and .tar.gz, bzip2/xz only for .tar.bz2/.tar.xz files), charges every
    produced byte to the budget, follows concatenated streams (gzip allows
    several members; node-tar reads them all), and keeps the last bytes it
    produced for the end-of-archive check. Data after the last stream that
    is not zero padding, or a stream cut short, raises ArchiveLimit('corrupt')."""

    def __init__(self, data, codec, budget):
        self.data, self.pos, self.codec, self.budget = memoryview(data), 0, codec, budget
        self.dec = self._decompressor() if codec != "tar" else None
        self.buf, self.tail = bytearray(), bytearray()
        self.produced, self.eof = 0, False

    def _decompressor(self):
        if self.codec == "gz":
            return zlib.decompressobj(31)
        if self.codec == "bz2":
            return bz2.BZ2Decompressor()
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = _OUTPUT_CHUNK
        while len(self.buf) < n and not self.eof:
            self.budget.check()
            self._fill(n - len(self.buf))
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def _emit(self, out):
        if out:
            self.budget.charge(len(out))
            self.produced += len(out)
            self.buf += out
            self.tail += out[-1024:]
            del self.tail[:-1024]

    def _next_input(self):
        chunk = self.data[self.pos:self.pos + _INPUT_CHUNK]
        self.pos += len(chunk)
        return bytes(chunk)

    def _fill(self, want):
        want = min(max(want, _INPUT_CHUNK), _OUTPUT_CHUNK)
        if self.dec is None:                                   # plain tar
            chunk = self.data[self.pos:self.pos + want]
            self.pos += len(chunk)
            if not chunk:
                self.eof = True
            self._emit(bytes(chunk))
            return
        try:
            if self.codec == "gz":
                inp = self.dec.unconsumed_tail or self._next_input()
                if not inp and not self.dec.eof:
                    raise ArchiveLimit("corrupt", "compressed stream is truncated")
                out = self.dec.decompress(inp, want)
            else:
                inp = self._next_input() if self.dec.needs_input else b""
                if not inp and self.dec.needs_input and not self.dec.eof:
                    raise ArchiveLimit("corrupt", "compressed stream is truncated")
                out = self.dec.decompress(inp, want)
        except (zlib.error, OSError, lzma.LZMAError, EOFError, ValueError) as exc:
            raise ArchiveLimit("corrupt", f"decompression failed ({type(exc).__name__})") from None
        self._emit(out)
        if self.dec.eof:
            rest = bytes(self.dec.unused_data) + bytes(self.data[self.pos:])
            self.data, self.pos = memoryview(rest), 0
            if not rest or not rest.strip(b"\x00"):
                self.eof = True
            elif rest.startswith(_CODEC_MAGIC[self.codec]):
                self.dec = self._decompressor()             # concatenated stream
            else:
                raise ArchiveLimit("corrupt", "data after the end of the compressed stream")


class _TarReader(tarfile.TarFile):
    """Records the blocks tarfile skips with ignore_zeros=True: zero blocks
    (end-of-archive markers) and invalid headers (a bad checksum). Python's
    tarfile used to STOP at either, while npm's node-tar skips a bad header
    and reads on — so what npm installed was never scanned."""

    def _dbg(self, level, msg):
        if level == 2 and isinstance(msg, str) and msg.startswith("0x") and ": " in msg:
            offset, _, what = msg.partition(": ")
            try:
                offset = int(offset, 16)
            except ValueError:
                offset = -1
            key = "_lazaret_zero_blocks" if what == "end of file header" else "_lazaret_bad_blocks"
            self.__dict__.setdefault(key, []).append(offset)
        super()._dbg(level, msg)


class Member(tuple):
    """(relative_path, real_size, raw_bytes, reason) with a .detail text for
    reasons that need one ('corrupt')."""

    def __new__(cls, rel, size, raw, reason, detail=""):
        self = super().__new__(cls, (rel, size, raw, reason))
        self.detail = detail
        return self


_DRIVE_ROOT_RE = re.compile(r"^(?:[A-Za-z]:)?/+")


def canonical_member_path(name, artifact=None):
    """Where an extractor puts an archive member, relative to the package
    root. -> (rel or None, problem or None).

    npm: exactly pacote's node-tar strip:1 — drop the FIRST path component
    whatever it is ('./decoy/setup.js' -> 'decoy/setup.js', never
    'setup.js'), strip absolute roots, refuse '..'; a member that ends up as
    the package root itself (a top-level file) is not extracted.
    wheel: paths are install paths, nothing stripped.
    sdist (and the legacy default): '.' / empty segments dropped, then the
    top directory. Backslashes count as separators (npm on Windows)."""
    p = str(name).replace("\\", "/")
    if artifact == "npm":
        rest = "/".join(p.split("/")[1:])
    elif artifact == "wheel":
        rest = p
    else:
        parts = [x for x in p.split("/") if x not in ("", ".")]
        rest = "/".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else "")
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


def strip_root(path):
    """Legacy helper: canonical_member_path() without artifact semantics."""
    rel, _problem = canonical_member_path(path)
    return rel if rel is not None else str(path).replace("\\", "/")


def _tar_codec(data, container, artifact):
    """The only codec a container may use -> 'gz' | 'bz2' | 'xz' | 'tar'.
    Raises ArchiveLimit('corrupt') on a mismatch: a bzip2 or xz stream served
    as an npm .tgz is rejected, not decompressed (pip opens .tar.gz with
    r:gz; npm auto-detects gzip and otherwise reads plain tar)."""
    head = bytes(data[:6])
    is_tar = len(data) >= 262 and bytes(data[257:262]) == b"ustar"
    want = {"tgz": "gz", "tbz2": "bz2", "txz": "xz", "tar": "tar"}.get(container, "gz")
    if want == "gz" and head.startswith(_GZIP_MAGIC):
        return "gz"
    if want == "gz" and artifact in (None, "npm") and (is_tar or not head.startswith(
            (_BZ2_MAGIC, _XZ_MAGIC, b"PK", b"(\xb5/\xfd"))):
        return "tar"                   # node-tar reads uncompressed tarballs too
    if want in ("bz2", "xz") and head.startswith(_CODEC_MAGIC[want]):
        return want
    if want == "tar":
        return "tar"
    found = next((k for k, magic in _CODEC_MAGIC.items() if head.startswith(magic)), "unknown")
    raise ArchiveLimit("corrupt", f"{container} artifact is {found}-compressed; "
                                  f"only {want} is accepted for this format")


def _note_member(seen, rel, anomalies):
    if rel in seen:
        if seen[rel] == 1:
            anomalies.append(("dup", rel, "two archive entries extract to this path; "
                                          "the later one wins"))
        seen[rel] += 1
    else:
        seen[rel] = 1


def iter_archive(data, container, artifact=None, *, budget=None, anomalies=None):
    """Yield Member(relative_path, real_size, raw_bytes, reason) for every file
    an installer would extract from the archive.

    Verdict-integrity fix (audit C2/G16): sizes are REAL decompressed byte
    counts, never the archive-declared file_size/tar m.size — a hostile
    archive used to declare >MAX_MEMBER and skip scanning entirely with zero
    signal. Reading is bounded at MAX_MEMBER+1 per member, and every
    decompressed byte (skipped member data included) is charged to the
    budget, so neither a lying header nor a decompression bomb can exhaust
    memory or time.

    Paths are canonicalized like the installer does it (canonical_member_path).
    In-archive links in sdists and wheels are resolved and their target's
    content is yielded under the link's name (pip extracts them); npm drops
    links (pacote), so they are skipped there. Structural problems that do
    not stop the scan — duplicate paths, links out of the archive, '..'
    entries — are appended to `anomalies` as (kind, path, detail).

    reason is None for a fully-read member, or:
      "member"  — more than MAX_MEMBER bytes; only the first SAMPLE bytes are
                  returned, so the caller can classify but not scan it.
      "files"   — more than MAX_FILES entries; iteration stops.
      "total"   — the decompression budget is spent; iteration stops.
      "time"    — the scan deadline passed; iteration stops.
      "corrupt" — the archive is damaged or ambiguous (bad header block,
                  entries after an end-of-archive block, trailing data, a
                  truncated or wrongly compressed stream); .detail says what."""
    budget = budget if budget is not None else Budget()
    anomalies = anomalies if anomalies is not None else []
    if container == "zip":
        yield from _iter_zip(data, artifact, budget, anomalies)
    else:
        yield from _iter_tar(data, container, artifact, budget, anomalies)


def _iter_tar(data, container, artifact, budget, anomalies):
    last = "(archive)"
    try:
        codec = _tar_codec(data, container, artifact)
        reader = _Inflater(data, codec, budget)
        tf = _TarReader.open(fileobj=reader, mode="r|", ignore_zeros=True)
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
        return
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt", f"not a readable tar archive ({type(exc).__name__})")
        return
    seen, links, offsets, count = {}, [], [], 0
    try:
        for m in tf:
            budget.check()
            offsets.append(m.offset)
            if m.isdir():
                continue
            rel, problem = canonical_member_path(m.name, artifact)
            if m.issym() or m.islnk():
                if artifact != "npm":                  # pacote drops links
                    links.append((m.name, m.linkname, m.issym(), rel, problem))
                continue
            if not m.isfile():
                continue
            if problem:
                anomalies.append(("path", m.name, problem))
                continue
            if rel is None:
                continue                               # the extractor drops it
            count += 1
            if count > MAX_FILES:
                yield Member(rel, 0, b"", "files")
                return
            _note_member(seen, rel, anomalies)
            last = rel
            f = tf.extractfile(m)
            raw = f.read(MAX_MEMBER + 1) if f is not None else b""
            if len(raw) > MAX_MEMBER:
                yield Member(rel, SAMPLE, raw[:SAMPLE], "member")
                continue
            yield Member(rel, len(raw), raw, None)
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
        return
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt",
                     f"archive could not be read past {last} ({type(exc).__name__})")
        return
    bad = tf.__dict__.get("_lazaret_bad_blocks", [])
    zeros = tf.__dict__.get("_lazaret_zero_blocks", [])
    if bad:
        yield Member("(archive)", 0, b"", "corrupt",
                     f"{len(bad)} invalid tar header block(s) skipped (first at byte "
                     f"{bad[0]:#x}); tar readers disagree about what follows")
    if zeros and offsets and max(offsets) > min(zeros):
        yield Member("(archive)", 0, b"", "corrupt",
                     "entries follow an end-of-archive block; pip stops reading there "
                     "while npm reads on")
    leftover = reader.produced - tf.offset
    if 0 < leftover <= len(reader.tail) and reader.tail[-leftover:].strip(b"\x00"):
        yield Member("(archive)", 0, b"", "corrupt", "data after the last tar entry")
    if links:
        yield from _resolve_tar_links(data, codec, artifact, links, seen, budget, anomalies, count)


def _link_target(member_name, linkname, symbolic):
    """Archive path a link points to, or None when it leaves the archive."""
    linkname = str(linkname).replace("\\", "/")
    if linkname.startswith("/") or _DRIVE_ROOT_RE.match(linkname):
        return None
    base = posixpath.dirname(str(member_name).replace("\\", "/")) if symbolic else ""
    target = posixpath.normpath(posixpath.join(base, linkname))
    if target == ".." or target.startswith("../"):
        return None
    return target


def _link_plan(links, artifact, anomalies):
    """{target rel: [link rel, ...]} with link chains followed (8 hops)."""
    by_rel = {}
    for name, linkname, symbolic, rel, problem in links:
        if problem or rel is None:
            if problem:
                anomalies.append(("path", name, problem))
            continue
        target = _link_target(name, linkname, symbolic)
        if target is None:
            anomalies.append(("link", rel, f"link to {linkname!r} points outside the archive"))
            continue
        # tar link targets are archive paths: canonicalize them like members
        trel, tproblem = canonical_member_path(target, artifact)
        if tproblem or trel is None:
            anomalies.append(("link", rel, f"link to {linkname!r} points outside the archive"))
            continue
        by_rel[rel] = trel
    plan = {}
    for rel, trel in by_rel.items():
        hops = 0
        while trel in by_rel and hops < 8:
            trel, hops = by_rel[trel], hops + 1
        plan.setdefault(trel, []).append(rel)
    return plan


def _resolve_tar_links(data, codec, artifact, links, seen, budget, anomalies, count):
    plan = _link_plan(links, artifact, anomalies)
    if not plan:
        return
    last = "(archive)"
    try:
        reader = _Inflater(data, codec, budget)
        tf = tarfile.open(fileobj=reader, mode="r|", ignore_zeros=True)
        for m in tf:
            budget.check()
            if not m.isfile():
                continue
            rel, _problem = canonical_member_path(m.name, artifact)
            if rel not in plan:
                continue
            f = tf.extractfile(m)
            raw = f.read(MAX_MEMBER + 1) if f is not None else b""
            for link_rel in plan.pop(rel):
                count += 1
                if count > MAX_FILES:
                    yield Member(link_rel, 0, b"", "files")
                    return
                _note_member(seen, link_rel, anomalies)
                last = link_rel
                if len(raw) > MAX_MEMBER:
                    yield Member(link_rel, SAMPLE, raw[:SAMPLE], "member")
                else:
                    yield Member(link_rel, len(raw), raw, None)
            if not plan:
                return
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt", f"links could not be resolved ({type(exc).__name__})")


def _zip_is_symlink(info):
    return (info.external_attr >> 16) & 0o170000 == 0o120000


_ZIP_EOCD_SIG, _ZIP64_LOC_SIG, _ZIP64_EOCD_SIG = b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"
_ZIP_CD_SIG = b"PK\x01\x02"
_ZIP_EOCD = struct.Struct("<4s4H2LH")            # 22 bytes
_ZIP64_LOC = struct.Struct("<4sLQL")             # 20 bytes
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")        # 56 bytes
# Largest central directory read (bytes). zipfile reads it whole and builds
# one ZipInfo per record before any file cap can apply; MAX_FILES records
# with long names fit easily in this.
MAX_ZIP_CENTRAL_DIR = 64 * 1024 * 1024


def _zip_preflight(data):
    """Refuse a zip whose central directory is too big to parse, BEFORE
    zipfile.ZipFile() reads it -> None (fine) or the reason.

    zipfile parses the whole central directory — ~340 MB and 4 s for a
    million records — before MAX_FILES can apply. Read the End Of Central
    Directory record (and the ZIP64 one) the same way zipfile finds it,
    and refuse when the declared entry count exceeds MAX_FILES, the
    declared directory size is implausible, or the directory region holds
    more than MAX_FILES record signatures (a count field can lie; zipfile
    parses records until the declared SIZE is consumed). Anything this
    reader can't make sense of is left to zipfile, which reports it."""
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    n = len(data)
    if n >= _ZIP_EOCD.size and data[n - 22:n - 18] == _ZIP_EOCD_SIG and data[n - 2:] == b"\0\0":
        pos = n - 22
    else:                                       # an archive comment follows the EOCD
        pos = data.rfind(_ZIP_EOCD_SIG, max(0, n - 65535 - _ZIP_EOCD.size))
        if pos < 0 or pos + _ZIP_EOCD.size > n:
            return None
    (_sig, _disk, _cd_disk, count_disk, count, cd_size, _cd_offset,
     _comment) = _ZIP_EOCD.unpack_from(data, pos)
    counts, sizes, records = [], [], [pos]
    loc = pos - _ZIP64_LOC.size
    if loc >= 0 and data[loc:loc + 4] == _ZIP64_LOC_SIG:
        _sig, _disk, reloff, _disks = _ZIP64_LOC.unpack_from(data, loc)
        # zipfile reads the record at the offset the locator names or,
        # depending on the version, right before the locator: check both
        for rec in {reloff, loc - _ZIP64_EOCD.size}:
            if 0 <= rec <= n - _ZIP64_EOCD.size and data[rec:rec + 4] == _ZIP64_EOCD_SIG:
                fields = _ZIP64_EOCD.unpack_from(data, rec)
                counts += [fields[6], fields[7]]
                sizes.append(fields[8])
                records.append(rec)
    if not sizes:          # no ZIP64 record: the classic fields are the real ones
        counts, sizes = [count_disk, count], [cd_size]
    declared = max(counts)
    if declared > MAX_FILES:
        return (f"zip central directory declares {declared:,} entries — more than the "
                f"{MAX_FILES:,}-file limit; the archive was not opened")
    size = max(sizes)
    if size > MAX_ZIP_CENTRAL_DIR:
        return (f"zip central directory declares {size:,} bytes — more than the "
                f"{MAX_ZIP_CENTRAL_DIR:,}-byte limit; the archive was not opened")
    # the records zipfile will parse lie in the `size` bytes before the
    # (ZIP64) end record; count their signatures without copying
    start = max(0, min(records) - size)
    found = data.count(_ZIP_CD_SIG, start, pos)
    if found > MAX_FILES:
        return (f"zip central directory holds more than {MAX_FILES:,} entries "
                f"({found:,} records, {declared:,} declared); the archive was not opened")
    return None


# What reading one zip member can raise (bad CRC, broken deflate/bz2/lzma
# stream, an encrypted or unsupported entry, a bad local header).
_ZIP_READ_ERRORS = (zipfile.BadZipFile, OSError, EOFError, ValueError, zlib.error,
                    lzma.LZMAError, NotImplementedError, RuntimeError)


def _iter_zip(data, artifact, budget, anomalies):
    refused = _zip_preflight(data)
    if refused:
        yield Member("(archive)", 0, b"", "files", refused)
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, ValueError,
            NotImplementedError, RuntimeError) as exc:
        yield Member("(archive)", 0, b"", "corrupt", f"not a readable zip archive ({type(exc).__name__})")
        return
    seen, by_rel, links, count, last = {}, {}, [], 0, "(archive)"

    def read(info, limit):
        with zf.open(info) as fh:
            raw = fh.read(limit)
        budget.charge(len(raw))
        return raw

    with zf:
        try:
            for info in infos:
                budget.check()
                if info.is_dir():
                    continue
                rel, problem = canonical_member_path(info.filename, artifact)
                if problem:
                    anomalies.append(("path", info.filename, problem))
                    continue
                if rel is None:
                    continue
                count += 1
                if count > MAX_FILES:
                    yield Member(rel, 0, b"", "files")
                    return
                if _zip_is_symlink(info):
                    links.append((info, rel))
                    continue
                by_rel[rel] = info
                _note_member(seen, rel, anomalies)
                last = rel
                try:
                    raw = read(info, MAX_MEMBER + 1)          # bounded, real bytes
                except _ZIP_READ_ERRORS as exc:
                    yield Member(rel, 0, b"", "corrupt",
                                 f"member {rel} could not be read ({type(exc).__name__})")
                    continue
                if len(raw) > MAX_MEMBER:
                    yield Member(rel, SAMPLE, raw[:SAMPLE], "member")
                    continue
                yield Member(rel, len(raw), raw, None)
            for info, rel in links:
                budget.check()
                try:
                    linkname = read(info, 4096).decode("utf-8", "replace")
                except _ZIP_READ_ERRORS as exc:
                    # where it points is unknown, so what it installs was not
                    # scanned: INCOMPLETE, not an "outside the archive" WARN
                    yield Member(rel, 0, b"", "corrupt",
                                 f"link {rel} could not be read ({type(exc).__name__})")
                    continue
                target = _link_target(info.filename, linkname, True) if linkname else None
                trel = canonical_member_path(target, artifact)[0] if target else None
                if trel is None:
                    anomalies.append(("link", rel, f"link to {linkname!r} points outside the archive"))
                    continue
                tinfo = by_rel.get(trel)
                if tinfo is None:
                    continue                                   # dangling inside the archive
                _note_member(seen, rel, anomalies)
                last = rel
                try:
                    raw = read(tinfo, MAX_MEMBER + 1)
                except _ZIP_READ_ERRORS as exc:
                    yield Member(rel, 0, b"", "corrupt",
                                 f"link target {trel} of {rel} could not be read "
                                 f"({type(exc).__name__})")
                    continue
                if len(raw) > MAX_MEMBER:
                    yield Member(rel, SAMPLE, raw[:SAMPLE], "member")
                else:
                    yield Member(rel, len(raw), raw, None)
        except ArchiveLimit as lim:
            yield Member(last, 0, b"", lim.reason, lim.detail)


# Detail text for each truncation reason (verdict integrity, audit C2/G16).
_TRUNC_DETAILS = {
    "member": lambda rel, size: (
        f"member {rel} decompresses to more than the {MAX_MEMBER:,}-byte "
        f"source-scan limit ({size:,} real decompressed bytes available)"),
    "files": lambda rel, size: (
        f"archive holds more than {MAX_FILES:,} file entries — entry order is "
        f"attacker-controlled (stopped at {rel})"),
    "total": lambda rel, size: (
        f"cumulative decompressed archive size exceeds {MAX_ARCHIVE_TOTAL:,} "
        f"bytes (stopped at {rel})"),
    "time": lambda rel, size: (
        f"scan time budget of {SCAN_TIMEOUT:g} s exceeded (stopped at {rel})"),
}
# Hard cap on SC-TRUNCATED findings per package so a hostile archive with
# thousands of oversize members cannot flood the report; the `truncated`
# count in the result always reflects the true number.
TRUNCATED_FINDING_CAP = 20


# ---------------- Verdicts ----------------
# The registry verdict answers one question: does this package look malicious?
#   SUSPICIOUS  a strong supply-chain indicator (CRITICAL/BLOCKER SC-* finding):
#               decode-then-execute, packed code, an install script that ships
#               data off the machine, hidden code in hex escapes, ...
#   INCOMPLETE  part of the package could not be scanned, so it cannot be
#               cleared; nothing strong was found in the part that was.
#   WARN        weaker indicators or capabilities worth a look: install hooks,
#               shipped binaries, opaque blobs.
#   OK          none of the above.
# Secrets and code-quality findings are reported but never decide the verdict:
# a test key inside someone else's package is not a threat to you.
STRONG_SEVERITIES = ("BLOCKER", "CRITICAL")
VERDICT_RANK = {"OK": 0, "WARN": 1, "INCOMPLETE": 2, "SUSPICIOUS": 3}
# Rules that mean "not fully scanned": they make a scan INCOMPLETE instead
# of counting as indicators.
TRUNCATION_RULES = ("SC-TRUNCATED", "SC-MANIFEST-UNPARSEABLE")
# Directory names that hold tests / fixtures (exact names, case-insensitive).
# Weaker findings in them are listed as INFO unless the file is reachable from
# an entry point (main/bin/exports, an install hook, setup.py).
TEST_DIR_NAMES = {"test", "tests", "testing", "__tests__", "spec", "specs", "fixtures",
                  "__fixtures__", "testdata", "test_data", "test-data", "test-fixtures",
                  "unittests", "test cases"}
_TEST_FILE_RE = re.compile(r"(?:^test_.*\.py|.*_test\.py|.*\.(?:test|spec)\.[cm]?[jt]sx?)$", re.I)


def is_test_path(rel):
    parts = rel.replace("\\", "/").split("/")
    return (any(_is_test_dir(part.lower()) for part in parts[:-1])
            or bool(_TEST_FILE_RE.match(parts[-1])))


def _is_test_dir(name):
    # exact names only: testkit/, testutils/, attestation/ are code, not tests
    return name in TEST_DIR_NAMES


def _demote_test_findings(issues, reachable=frozenset()):
    """Weaker supply-chain findings inside test code become inventory (INFO):
    test fixtures legitimately contain binaries, blobs and escaped bytes, and
    tests are neither imported nor run when the package is installed. Strong
    findings are never demoted: hiding a payload in tests/ doesn't make it safe.
    Nor is anything reachable from an entry point: a main that points into
    test/ makes that code the package."""
    for issue in issues:
        if (issue["rule"].startswith("SC-") and issue["rule"] not in TRUNCATION_RULES
                and issue["sev"] not in STRONG_SEVERITIES + ("INFO",)
                and issue["file"] not in reachable
                and is_test_path(issue["file"])):
            issue["sev"] = "INFO"
            issue["msg"] = issue["msg"].rstrip() + " (in test code: listed, not counted)"


def decide_verdict(issues, truncated):
    """-> (verdict, reason, strong_count, weak_count)."""
    indicators = [i for i in issues if i["rule"].startswith("SC-")
                  and i["rule"] not in TRUNCATION_RULES and i["sev"] != "INFO"]
    strong = sum(1 for i in indicators if i["sev"] in STRONG_SEVERITIES)
    weak = len(indicators) - strong
    plural = lambda n, word: f"{n} {word}{'' if n == 1 else 's'}"
    if strong:
        return "SUSPICIOUS", plural(strong, "strong supply-chain indicator"), strong, weak
    if truncated:
        return ("INCOMPLETE", f"scan incomplete: {plural(truncated, 'part')} not fully scanned, "
                "so the package can't be cleared", strong, weak)
    if weak:
        return "WARN", plural(weak, "weaker supply-chain indicator") + " to review", strong, weak
    return "OK", "no supply-chain indicators", strong, weak


# ---------------- Install-script inspection ----------------
# An install hook is a capability; what makes it hostile is what the script it
# runs does. Escalate only on the patterns malicious install scripts share:
# shipping environment/credential data over the network, or talking to
# throwaway exfiltration endpoints. Downloading a platform binary from the
# registry (esbuild, puppeteer) is not either. The same test applies to the
# Python code pip runs at install time (an sdist's setup.py, an in-tree PEP 517
# backend) and to shell scripts a hook runs.
_NETWORK_RE = re.compile(
    r"""\b(?:https?\.(?:get|request)|fetch\s*\(|axios|XMLHttpRequest|net\.connect|dns\.resolve|"""
    r"""require\(\s*["'](?:node:)?(?:https?|net|dgram|tls)["']\s*\)|"""
    r"""from\s+["'](?:node:)?(?:https?|net|dgram|tls)["'])"""
    # Python
    r"""|\burllib\.request\b|\burlopen\s*\(|\burlretrieve\s*\(|\bhttp\.client\b|"""
    r"""\bHTTPS?Connection\s*\(|\bsocket\.(?:socket|create_connection)\s*\(|"""
    r"""\brequests\.(?:get|post|put|patch|request|Session)\b|\bimport\s+(?:requests|httpx|aiohttp|urllib3)\b|"""
    r"""\bfrom\s+(?:requests|httpx|aiohttp|urllib3|urllib\.request|http\.client)\s+import\b|"""
    r"""\bhttpx\.\w+\s*\(|\baiohttp\.ClientSession\b|\bsmtplib\b|\bftplib\b"""
    # shell: a download tool pointed at a URL, netcat to a host and port, bash's /dev/tcp
    r"""|\b(?:curl|wget)\s+(?:-{1,2}[\w-]+(?:[ =](?!https?:)\S+)?\s+)*["']?https?://"""
    r"""|\b(?:nc|ncat|netcat)\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b|/dev/tcp/""", re.M)
_SECRET_SOURCE_RE = re.compile(
    r"""JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries|values)\(\s*process\.env|"""
    r"""\.npmrc|[/\\]\.ssh\b|~/\.ssh\b|id_rsa|id_ed25519|\.aws[/\\]|~/\.aws\b|\.git-credentials|"""
    r"""\.docker[/\\]config\.json|\.kube[/\\]config|Local Storage[/\\]leveldb|\.pypirc|\.netrc\b|"""
    # Python: the whole environment, not one variable
    r"""\bdict\(\s*os\.environ\s*\)|\bos\.environ\.(?:items|keys|values|copy)\(\s*\)|"""
    r"""json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\b(?:str|repr)\(\s*os\.environ\s*\)|"""
    r"""\{\s*\*\*\s*os\.environ|\burlencode\(\s*(?:dict\(\s*)?os\.environ|\bos\.environb\b"""
    # shell: the whole environment piped or redirected somewhere
    r"""|(?:^|[\s;&(`])(?:env|printenv|set)\s*(?:\|(?!\|)|>)|\$\(\s*(?:env|printenv)\s*\)|`\s*(?:env|printenv)\s*`""",
    re.I | re.M)
_EXFIL_DEST_RE = re.compile(
    r"""https?://(?:\d{1,3}\.){3}\d{1,3}\b|pastebin\.com|\bngrok|webhook\.site|"""
    r"""discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|"""
    r"""\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin|pipedream\.net|"""
    r"""transfer\.sh|\.onion\b""", re.I)
_PIPE_TO_SHELL_RE = re.compile(r"""\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b""")


def install_script_risk(text):
    """Reasons an install-time script looks hostile ([] if none)."""
    reasons = []
    network = bool(_NETWORK_RE.search(text))
    if network and _SECRET_SOURCE_RE.search(text):
        reasons.append("reads environment variables or credential files and sends data over the network")
    dest = _EXFIL_DEST_RE.search(text)
    if dest:
        reasons.append(f"contacts an address typical of data exfiltration ({dest.group(0)[:40]})")
    if _PIPE_TO_SHELL_RE.search(text):
        reasons.append("pipes a download into a shell")
    return reasons


def _node_candidates(rel):
    """Files Node tries for a path it is asked to run or load."""
    rel = rel.rstrip("/")
    return [rel, rel + ".js", rel + ".cjs", rel + ".mjs", rel + ".json", rel + ".node",
            rel + "/index.js", rel + "/index.cjs", rel + "/index.mjs", rel + "/index.json"]


def _rel_join(base, target):
    target = str(target).replace("\\", "/")
    if target.startswith("/"):
        target = target.lstrip("/")
    joined = posixpath.normpath(posixpath.join(base or ".", target))
    return "" if joined in (".", "") else joined


# Entry points declared in package.json: what `require(pkg)`, `import pkg`
# and the installed command run.
def _package_entry_targets(data):
    targets = []
    main = data.get("main")
    # no main: require(pkg) loads index.js
    targets.append(main if isinstance(main, str) and main.strip() else "index.js")
    bins = data.get("bin")
    if isinstance(bins, str):
        targets.append(bins)
    elif isinstance(bins, dict):
        targets += [v for v in bins.values() if isinstance(v, str)]
    stack, nodes = [data.get("exports")], 0
    while stack and nodes < 10_000:
        node = stack.pop()
        nodes += 1
        if isinstance(node, str):
            if node.startswith("./") and "*" not in node:
                targets.append(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return targets


_JS_LOCAL_DEP_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+|\bexport\s+[^'"\n;]*?\bfrom\s+)"""
    r"""(['"])(\.{1,2}/[^'"\n]+)\1""", re.M)
_SHEBANG_RE = re.compile(r"^#!\s*(\S+)(?:\s+(?:-\S+\s+)*(\S+))?")
_MANIFEST_NAMES = ("package.json", "binding.gyp", "pyproject.toml")


def _shebang_lang(text):
    """'js' | 'py' | 'sh' | None from a script's #! line."""
    m = _SHEBANG_RE.match(text)
    if not m:
        return None
    prog = m.group(1).rsplit("/", 1)[-1].lower()
    if prog == "env" and m.group(2):
        prog = m.group(2).rsplit("/", 1)[-1].lower()
    if prog in ("node", "nodejs"):
        return "js"
    if lazaret._PYTHON_NAME_RE.match(prog):
        return "py"
    if prog in lazaret._SHELL_NAMES:
        return "sh"
    return None


# SC-PTH-EXEC lives in the scanner (project and --deps scans check .pth files
# too); the registry uses the same function, so the two can't drift.
_PTH_EXEC_RE = lazaret._PTH_EXEC_RE
pth_issues = lazaret.pth_issues


def _archive_issue(kind, path, detail):
    rules = {
        "dup": ("SC-ARCHIVE-DUP", "Duplicate archive path",
                "Two entries in the archive extract to the same path, so what a reviewer "
                "(or a scanner reading the first) sees is not what gets installed."),
        "link": ("SC-ARCHIVE-LINK", "Archive link leaves the package",
                 "A symlink or hardlink pointing outside the extraction directory can make "
                 "the installer read or overwrite files elsewhere on the machine."),
        "path": ("SC-ARCHIVE-PATH", "Unsafe archive path",
                 "An entry with '..' in its path tries to escape the extraction directory; "
                 "installers refuse it, and no legitimate package tool produces one."),
    }
    rid, name, why = rules[kind]
    return {"rule": rid, "name": name, "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"{name}: {path} — {detail}.", "why": why,
            "fix": "Inspect the archive listing (tar -tvf / unzip -l) before installing.",
            "ref": "CWE-506 · Supply chain", "file": str(path), "line": 1,
            "snippet": [], "snipStart": 1}


class _ArtifactScan:
    """Scan state for one archive: classify members as they stream by, then
    resolve what package.json / setup.py say runs (entry points, install
    hooks, build backends) once every member is known."""

    def __init__(self, artifact, full):
        self.artifact, self.full = artifact, full
        self.issues, self.files_scanned, self.binaries = [], 0, 0
        self.truncated, self.truncated_emitted = 0, 0
        self.sources = {}          # rel -> (text, lang) scanned as source
        self.deferred = {}         # rel -> raw bytes (text, not scanned yet)
        self.deferred_bytes = 0
        self.dropped = set()       # text members not kept (budget)
        self.shell = {}            # rel -> text of shell scripts
        self.binary = set()        # classified as binary
        self.oversize = set()
        self.members = set()
        self.manifests = {}        # rel -> text (package.json, binding.gyp, pyproject.toml)
        self.entries = set()       # rels that run when installed / imported

    # ---- bookkeeping ----
    def truncate(self, rel, detail):
        self.truncated += 1
        if self.truncated_emitted < TRUNCATED_FINDING_CAP:
            self.issues.append(lazaret.truncated_issue(rel, detail))
            self.truncated_emitted += 1

    def add_decode_issues(self, extra, keep_encoding=True):
        for i in extra:
            if i["rule"] == "SC-TRUNCATED":
                self.truncate(i["file"], i["msg"].removeprefix("File not fully scanned: ").rstrip("."))
            elif keep_encoding or i["rule"] != "Q-ENCODING":
                self.issues.append(i)

    def classify(self, rel, raw, size):
        bi = lazaret.classify_binary(rel, raw, size, self.artifact)
        if bi:
            self.binaries += 1
            self.issues.append(bi)

    def scan_source(self, rel, text, lang):
        self.files_scanned += 1
        self.issues.extend(lazaret.scan_file(rel, text, lang, dep=not self.full))
        self.sources[rel] = (text, lang)

    # ---- pass 1: members ----
    def member(self, m):
        rel, size, raw, reason = m
        if reason in ("files", "total", "time", "corrupt"):
            detail = getattr(m, "detail", "") or _TRUNC_DETAILS.get(
                reason, lambda r, s: f"archive not fully read ({reason})")(rel, size)
            self.truncate(rel, detail)
            return
        self.members.add(rel)
        base = os.path.basename(rel)
        ext = os.path.splitext(base)[1].lower()
        wants_text = (base in _MANIFEST_NAMES or ext in lazaret.EXTS
                      or ext in (".pth", ".gyp", ".gypi"))
        if reason == "member":
            self.oversize.add(rel)
            if wants_text and not (ext == ".ts" and lazaret._mpeg_ts(raw[:512])):
                # Verdict integrity (audit C2/G16): a cut-short scan is a
                # signal, not a clean verdict — whatever the first bytes look like.
                self.truncate(rel, _TRUNC_DETAILS["member"](rel, size))
            # still classifiable by magic/entropy from the decompressed prefix
            self.classify(rel, raw, size)
            return
        if base == "package.json":
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra, keep_encoding=False)
            self.manifests[rel] = text
            for i in lazaret.scan_manifest(rel, text, registry=True):
                if i["rule"] == "SC-MANIFEST-UNPARSEABLE":
                    self.truncated += 1
                self.issues.append(i)
            return
        if base in ("binding.gyp",) or ext in (".gyp", ".gypi"):
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra, keep_encoding=False)
            self.manifests[rel] = text
            for i in lazaret.scan_gyp(rel, text):
                if i["rule"] == "SC-MANIFEST-UNPARSEABLE":
                    self.truncated += 1
                self.issues.append(i)
            return
        if base == "pyproject.toml":
            self.manifests[rel] = raw.decode("utf-8", "replace")
            return
        if ext == ".pth":
            text = raw.decode("utf-8-sig", "replace")
            self.issues.extend(pth_issues(rel, text))
            self.scan_source(rel, text, "py")
            return
        lang = lazaret.EXTS.get(ext)
        if lang is not None:
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra)
            if any(i["rule"] == "SC-TRUNCATED" for i in extra):
                self.classify(rel, raw, size)   # an ELF named index.js is still an ELF
            self.scan_source(rel, text, lang)
            return
        if lazaret.looks_binary(raw[:2048]):
            self.binary.add(rel)
            self.classify(rel, raw, size)
            return
        # Text without a source extension: a script by its #! line, or kept
        # until package.json says whether it runs (main -> lib/core.dat).
        if raw.startswith(b"#!"):
            text = raw.decode("utf-8", "replace")
            kind = _shebang_lang(text)
            if kind in ("js", "py"):
                self.scan_source(rel, text, kind)
                return
            if kind == "sh":
                self.shell[rel] = text
                return
        if self.deferred_bytes + len(raw) <= DEFERRED_TEXT_BUDGET:
            self.deferred[rel] = raw
            self.deferred_bytes += len(raw)
        else:
            self.dropped.add(rel)

    # ---- pass 2: what runs ----
    def _find(self, candidates):
        return next((c for c in candidates if c in self.members), None)

    def _text_of(self, rel, as_lang="js"):
        """Text of a member that is run as code, scanning it as `as_lang`
        first when it has not been scanned (non-source extension). None when
        it cannot be read as text — that is counted as INCOMPLETE."""
        if rel in self.sources:
            return self.sources[rel][0]
        if rel in self.shell:
            return self.shell[rel]
        if os.path.splitext(rel)[1].lower() in (".json", ".node", ".wasm"):
            return None          # loaded as data / native code, not run as script text
        if rel in self.deferred:
            raw = self.deferred.pop(rel)
            if as_lang == "sh" or _shebang_lang(raw[:256].decode("utf-8", "replace")) == "sh":
                text = raw.decode("utf-8", "replace")
                self.shell[rel] = text
                return text
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra)
            self.scan_source(rel, text, as_lang)
            return text
        if rel in self.dropped:
            self.truncate(rel, f"{rel} runs at install/import time but was not kept for "
                               f"scanning (text budget exhausted)")
        elif rel in self.oversize:
            self.truncate(rel, f"{rel} runs at install/import time but exceeds the "
                               f"{MAX_MEMBER:,}-byte scan limit")
        elif rel in self.binary and os.path.splitext(rel)[1].lower() not in (".node", ".wasm", ".json"):
            self.truncate(rel, f"{rel} runs at install/import time but is not text, so it "
                               f"could not be scanned")
        return None

    def _entry_points(self, manifest_rel, data):
        base = posixpath.dirname(manifest_rel)
        for target in _package_entry_targets(data):
            rel = self._find(_node_candidates(_rel_join(base, target)))
            if rel:
                self.entries.add(rel)
                self._text_of(rel, "js")

    def _implicit_gyp_hook(self, manifest_rel, data):
        """npm runs `node-gyp rebuild` for a root binding.gyp when the package
        defines no install/preinstall script (and gypfile isn't false)."""
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        if "binding.gyp" not in self.members or data.get("gypfile") is False:
            return
        if any(isinstance(scripts.get(h), str) and scripts[h].strip() for h in ("install", "preinstall")):
            return
        self.issues.append(lazaret._sc_install_hook_issue(
            "binding.gyp", 1, [], "install (implicit)", "node-gyp rebuild", False))

    def _follow_hooks(self):
        """Follow each install hook to the scripts it runs; escalate the hook
        when one looks hostile (see install_script_risk)."""
        for issue in list(self.issues):
            if issue["rule"] != "SC-INSTALL-HOOK" or not issue.get("cmd"):
                continue
            base = posixpath.dirname(issue["file"])
            for target in lazaret.hook_script_targets(issue["cmd"]):
                rel = self._find(_node_candidates(_rel_join(base, target)))
                if rel is None:
                    continue
                self.entries.add(rel)
                lang = "sh" if rel.endswith(".sh") else "js"
                text = self._text_of(rel, lang)
                reasons = install_script_risk(text) if text else []
                if reasons and issue["sev"] not in STRONG_SEVERITIES:
                    issue["sev"] = "CRITICAL"
                    issue["msg"] = f"Install hook runs {target}, which {'; and '.join(reasons)}."

    def _python_install_scripts(self):
        """Python code pip runs to build/install an sdist: setup.py and an
        in-tree PEP 517 backend (build-system.backend-path)."""
        scripts = []
        if "setup.py" in self.sources:
            scripts.append("setup.py")
        backend, paths = _pep517_backend(self.manifests.get("pyproject.toml", ""))
        if backend and paths:
            mod = backend.split(":", 1)[0].replace(".", "/")
            for p in paths:
                root = _rel_join("", p)
                rel = self._find([_rel_join(root, mod + ".py"), _rel_join(root, mod + "/__init__.py")])
                if rel:
                    scripts.append(rel)
        # modules they import from the sdist itself run at install time too
        queue, seen = list(scripts), set(scripts)
        while queue and len(seen) < 200:
            text, lang = self.sources.get(queue.pop(), ("", None))
            if lang != "py":
                continue
            for m in _PY_LOCAL_IMPORT_RE.finditer(text):
                mod = (m.group(1) or m.group(2)).replace(".", "/")
                rel = self._find([mod + ".py", mod + "/__init__.py"])
                if rel and rel not in seen:
                    seen.add(rel)
                    scripts.append(rel)
                    queue.append(rel)
        for rel in scripts:
            self.entries.add(rel)
            text = self.sources.get(rel, ("", "py"))[0]
            reasons = install_script_risk(text)
            if reasons:
                lines = lazaret.normalize_newlines(text).split("\n")
                self.issues.append(lazaret.mk_issue(
                    {"id": "SC-INSTALL-HOOK", "name": "Install hook", "type": "HOTSPOT",
                     "sev": "CRITICAL",
                     "msg": f"{rel} runs when pip builds or installs this sdist, and it "
                            f"{'; and '.join(reasons)}.",
                     "why": ("pip executes an sdist's setup.py (or its in-tree build "
                             "backend) with the user's privileges before anything is "
                             "reviewed — the Python twin of an npm install hook."),
                     "fix": "Do not install this sdist; report it to the index.",
                     "ref": "CWE-506 · Supply chain"}, rel, 1, lines))

    def _reachable(self):
        """Entry files plus local files they require/import (JS), transitively."""
        seen, queue = set(self.entries), list(self.entries)
        while queue and len(seen) < 10_000:
            rel = queue.pop()
            text, lang = self.sources.get(rel, (None, None))
            if not text or lang != "js":
                continue
            base = posixpath.dirname(rel)
            for _q, target in _JS_LOCAL_DEP_RE.findall(text):
                dep = self._find(_node_candidates(_rel_join(base, target)))
                if dep and dep not in seen:
                    seen.add(dep)
                    queue.append(dep)
        return seen

    def finish(self, anomalies):
        for kind, path, detail in anomalies:
            self.issues.append(_archive_issue(kind, path, detail))
        for rel, text in list(self.manifests.items()):
            if os.path.basename(rel) != "package.json":
                continue
            data, _problems = lazaret.load_manifest(rel, text)
            if data is None:
                continue
            if rel == "package.json":
                self._entry_points(rel, data)
                self._implicit_gyp_hook(rel, data)
        self._follow_hooks()
        if self.artifact == "sdist":
            self._python_install_scripts()
        reachable = self._reachable()
        # interprocedural / cross-file taint (full profile only — needs whole source)
        if self.full and getattr(lazaret, "lazaret_flow", None) is not None:
            records = [{"path": r, "content": t, "lang": lang}
                       for r, (t, lang) in self.sources.items()]
            try:
                self.issues.extend(lazaret.lazaret_flow.analyze(records))
            except Exception as exc:                            # noqa: BLE001
                print(f"warning: interprocedural taint analysis skipped "
                      f"({type(exc).__name__})", file=sys.stderr)
        _demote_test_findings(self.issues, reachable)
        # F9b: the decompressed sources are no longer needed
        self.sources, self.deferred, self.shell = {}, {}, {}


_PY_LOCAL_IMPORT_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*))", re.M)
_PEP517_SECTION_RE = re.compile(r"^\s*\[build-system\]\s*$(.*?)(?=^\s*\[|\Z)", re.M | re.S)


def _pep517_backend(pyproject):
    """(build-backend, backend-path list) from pyproject.toml text; tomllib
    where available (3.11+), a narrow regex reader on 3.10."""
    if not pyproject:
        return None, []
    try:
        # stdlib from Python 3.11; loaded by name so the 3.10 stdlib guard
        # (tests/architecture) does not see an import it cannot resolve
        tomllib = importlib.import_module("tomllib")
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            section = tomllib.loads(pyproject).get("build-system") or {}
        except (ValueError, RecursionError):       # TOMLDecodeError is a ValueError
            section = None
        if isinstance(section, dict):
            backend = section.get("build-backend")
            paths = section.get("backend-path")
            return (backend if isinstance(backend, str) else None,
                    [p for p in paths if isinstance(p, str)] if isinstance(paths, list) else [])
    m = _PEP517_SECTION_RE.search(pyproject)
    if not m:
        return None, []
    body = m.group(1)
    backend = re.search(r"""^\s*build-backend\s*=\s*["']([^"']+)["']""", body, re.M)
    paths = re.search(r"""^\s*backend-path\s*=\s*\[([^\]]*)\]""", body, re.M | re.S)
    return (backend.group(1) if backend else None,
            re.findall(r"""["']([^"']+)["']""", paths.group(1)) if paths else [])


def _scan_artifact(data, container, artifact, full, budget):
    """Scan one archive -> per-artifact result fields (issues, counts, verdict)."""
    st = _ArtifactScan(artifact, full)
    anomalies = []
    try:
        for m in iter_archive(data, container, artifact, budget=budget, anomalies=anomalies):
            st.member(m)
            budget.check()
    except ArchiveLimit as lim:          # deadline hit between members
        st.truncate("(archive)", lim.detail or _TRUNC_DETAILS.get(
            lim.reason, lambda r, s: lim.reason)("(archive)", 0))
    st.finish(anomalies)
    issues = st.issues
    verdict, reason, strong, weak = decide_verdict(issues, st.truncated)
    return {"issues": issues, "filesScanned": st.files_scanned, "binaryArtifacts": st.binaries,
            "truncated": st.truncated, "verdict": verdict, "verdictReason": reason,
            "strongIndicators": strong, "weakIndicators": weak}


def _fmt_bytes(n):
    """1536 -> '1.5 KiB' (binary units, one decimal)."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"  # pragma: no cover


def declared_size(meta_entry):
    """Byte size a registry declares for one artifact (PyPI's `size`), or
    None when it declares none. Used to refuse a download BEFORE it starts."""
    size = meta_entry.get("size") if isinstance(meta_entry, dict) else None
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        return size
    return None


def _skipped_summary(skipped, byte_budget, limit):
    """SC-TRUNCATED issues + a short verdict-reason phrase for release files
    that were not scanned. skipped: [(filename, kind, size)] with kind
    'artifacts' | 'budget' | 'filesize' | 'time'."""
    issues, labels = [], []
    groups = {}
    for filename, kind, size in skipped:
        groups.setdefault(kind, []).append((filename, size))

    def names(items):
        shown = ", ".join(str(f) for f, _ in items[:3])
        return shown + (f", … (+{len(items) - 3})" if len(items) > 3 else "")

    if "artifacts" in groups:
        items = groups["artifacts"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} more release file(s) not scanned (limit {limit} "
                         f"artifacts per release; raise --max-artifacts)"))
        labels.append(f"more than {limit} files (--max-artifacts)")
    if "filesize" in groups:
        items = groups["filesize"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: each is larger than "
                         f"the {_fmt_bytes(MAX_DOWNLOAD_BYTES)} per-file download limit "
                         f"({names(items)})"))
        labels.append(f"over the {_fmt_bytes(MAX_DOWNLOAD_BYTES)} per-file limit")
    if "budget" in groups:
        items = groups["budget"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: they would take the "
                         f"package past its {_fmt_bytes(byte_budget)} download budget "
                         f"({names(items)}; raise --max-download-bytes / "
                         f"LAZARET_MAX_DOWNLOAD_BYTES)"))
        labels.append(f"over the {_fmt_bytes(byte_budget)} download budget (--max-download-bytes)")
    if "time" in groups:
        items = groups["time"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: the scan's time "
                         f"budget ran out ({names(items)})"))
        labels.append("time budget exhausted")
    return issues, "; ".join(labels)


def scan_package(eco, name, version=None, full=False, *, resolved=None, deadline=None,
                 cancel=None, max_artifacts=None, max_download_bytes=None):
    """Fetch and scan one package version. Returns a result dict.

    Every archive member is classified as source or binary. Source files (by
    extension, by #! line, or because package.json runs them) are run through
    the normal ruleset; binary/compiled artifacts through classify_binary,
    which flags smuggled executables, nested archives, and opaque
    high-entropy blobs — with severity that depends on whether they belong
    (sdist/npm vs wheel).

    PyPI: every file of the release pip may install is scanned (sdist and
    each distinct wheel, at most max_artifacts files and max_download_bytes
    bytes in total); the verdict is the worst one, and result["artifacts"]
    keeps the per-file detail. A file that does not fit — past the artifact
    limit, over the per-file download limit or the package's download budget
    by its DECLARED size (checked before downloading), or reached after the
    deadline — is not downloaded; it is listed in result["skippedArtifacts"],
    an SC-TRUNCATED finding names it, and the verdict is INCOMPLETE at best.

    resolved: a resolve_npm/resolve_pypi result already fetched (scan-all
    checks the version before downloading). deadline: absolute
    time.monotonic() bound for the whole package (MCP budget); each archive
    also gets SCAN_TIMEOUT. cancel: callable; True stops the scan with
    ScanCancelled."""
    if resolved is None:
        resolved = resolve(eco, name, version)
    version, url, container, artifact, meta_entry = resolved
    refs = getattr(resolved, "artifacts", None) or [
        {"url": url, "container": container, "artifact": artifact, "entry": meta_entry,
         "filename": url.rsplit("/", 1)[-1] if isinstance(url, str) else None}]
    limit = max_artifacts or MAX_ARTIFACTS
    byte_budget = max_download_bytes or MAX_PACKAGE_DOWNLOAD_BYTES
    over, refs = refs[limit:], refs[:limit]
    skipped = [(r.get("filename"), "artifacts", declared_size(r.get("entry"))) for r in over]
    per, all_issues, truncated = [], [], 0
    multi = len(refs) > 1
    downloaded = 0
    for ref in refs:
        size = declared_size(ref.get("entry"))
        if cancel is not None and cancel():
            raise ScanCancelled("scan cancelled")
        if deadline is not None and time.monotonic() > deadline:
            skipped.append((ref.get("filename"), "time", size))
            continue
        if size is not None and size > MAX_DOWNLOAD_BYTES:
            skipped.append((ref.get("filename"), "filesize", size))
            continue
        if downloaded >= byte_budget or (size is not None and downloaded + size > byte_budget):
            skipped.append((ref.get("filename"), "budget", size))
            continue
        data = http_bytes(ref["url"])
        downloaded += max(len(data), size or 0)
        # G15: verify the artifact against the registry-published digest BEFORE
        # scanning anything — a mismatch raises and nothing is persisted under
        # this name/version.
        digest = verify_digest(data, ref["entry"], eco, name, version)
        stop = time.monotonic() + SCAN_TIMEOUT
        budget = Budget(deadline=min(stop, deadline) if deadline else stop, cancel=cancel)
        r = _scan_artifact(data, ref["container"], ref["artifact"], full, budget)
        prefix = f"{ref['filename']}/" if multi and ref.get("filename") else ""
        for issue in r["issues"]:
            if prefix:
                issue["file"] = prefix + issue["file"]
                issue["artifact"] = ref["filename"]
            all_issues.append(issue)
        truncated += r["truncated"]
        per.append({"filename": ref.get("filename"), "kind": ref["artifact"], "url": ref["url"],
                    "archiveBytes": len(data), "digest": digest,
                    **{k: r[k] for k in ("verdict", "verdictReason", "filesScanned",
                                         "binaryArtifacts", "truncated",
                                         "strongIndicators", "weakIndicators")}})
    skip_issues, skip_label = _skipped_summary(skipped, byte_budget, limit)
    truncated += len(skip_issues)
    all_issues.extend(skip_issues)
    all_issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["file"], i["line"]))
    sev_counts = {s: 0 for s in lazaret.SEV_ORDER}
    for i in all_issues:
        sev_counts[i["sev"]] += 1
    # Only supply-chain indicators decide the verdict (see "Verdicts" above).
    # Verdict integrity: a truncated scan can never be cleared, because the
    # unscanned members are attacker-chosen: it is INCOMPLETE at best.
    verdict, reason, strong, weak = decide_verdict(all_issues, truncated)
    if multi and per:
        worst = max(per, key=lambda p: VERDICT_RANK.get(p["verdict"], 0))
        if VERDICT_RANK.get(worst["verdict"], 0) == VERDICT_RANK.get(verdict, 0) \
                and verdict != "OK":
            reason += f" (worst: {worst['filename']}; {len(per)} release files scanned)"
        else:
            reason += f" ({len(per)} release files scanned)"
    if skipped:
        reason += (f"; {len(skipped)} of {len(per) + len(skipped)} release files not "
                   f"scanned: {skip_label}")
    # L1 (artifact hygiene): redaction is default-on, so the issues this
    # result carries — including the ones persisted as the Store blob via
    # save_scan — already have placeholder/scrubbed snippets from mk_issue.
    # This defensive sweep exists so the registry path cannot regress.
    all_issues = lazaret.redact_result({"issues": list(all_issues)})["issues"]
    kinds = [p["kind"] for p in per]
    artifact_label = kinds[0] if len(kinds) == 1 else (
        "+".join(filter(None, ["sdist" if "sdist" in kinds else "",
                               f"{kinds.count('wheel')} wheel{'s' if kinds.count('wheel') != 1 else ''}"
                               if "wheel" in kinds else ""])))
    return {"ecosystem": eco, "name": name, "version": version, "artifact": artifact_label,
            "archiveBytes": sum(p["archiveBytes"] for p in per),
            "filesScanned": sum(p["filesScanned"] for p in per),
            "binaryArtifacts": sum(p["binaryArtifacts"] for p in per),
            "profile": "full" if full else "supply-chain",
            "sevCounts": sev_counts, "supplyChain": strong + weak, "strongIndicators": strong,
            "weakIndicators": weak, "truncated": truncated,
            "verdict": verdict, "verdictReason": reason, "issues": all_issues,
            "digest": per[0]["digest"] if per else None, "artifacts": per,
            "skippedArtifacts": [{"filename": f, "reason": kind, "declaredBytes": size}
                                 for f, kind, size in skipped],
            "scannedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


# ---------------- State store (SQLite / Postgres) ----------------
_PG_KEYWORD_RE = re.compile(
    r"^\s*(?:host|hostaddr|port|dbname|database|user|password|passfile|sslmode|sslrootcert|"
    r"sslcert|sslkey|connect_timeout|application_name|channel_binding|require_auth|options|"
    r"service|target_session_attrs)\s*=", re.I)
_PG_SCHEME_RE = re.compile(r"^\s*(postgres(?:ql)?)://", re.I)


def classify_dsn(dsn):
    """--db / LAZARET_DB -> ('pg', dsn) or ('sqlite', path).

    postgres:// and postgresql:// in any letter case, and libpq keyword
    strings ("host=db user=app dbname=lazaret"), select Postgres; `sqlite:`
    / `sqlite:///` prefixes and plain paths select SQLite. A plain path
    containing '=' is refused: it is almost certainly a mistyped connection
    string, and SQLite would create a FILE named after it — password
    included. Error messages never echo the value."""
    if not isinstance(dsn, str) or not dsn.strip():
        raise StoreConfigError("empty database location (--db / LAZARET_DB)")
    m = _PG_SCHEME_RE.match(dsn)
    if m:
        return "pg", m.group(1).lower() + dsn[m.end(1):].lstrip()
    if _PG_KEYWORD_RE.match(dsn):
        return "pg", dsn.strip()
    if dsn.lower().startswith("sqlite:"):
        path = dsn[len("sqlite:"):]
        if path.startswith("///"):
            path = path[3:]
        elif path.startswith("//"):
            path = path[2:]
        if not path:
            raise StoreConfigError("sqlite: needs a path (sqlite:PATH or sqlite:///PATH)")
        return "sqlite", path
    if "=" in dsn:
        raise StoreConfigError(
            "database location contains '=' but is not a recognized Postgres connection "
            "string; refusing to create a SQLite file with that name (use postgres://…, "
            "a libpq 'host=… dbname=…' string, or sqlite:PATH)")
    if "://" in dsn:
        raise StoreConfigError("unsupported database URL scheme (use postgres:// or sqlite:)")
    return "sqlite", dsn


def _db_text(value):
    """Text a Postgres TEXT/JSONB value can hold: no NUL, no lone surrogate
    (a hook command with \\u0000, an archive member name that is not UTF-8)."""
    if not isinstance(value, str):
        return value
    if "\x00" in value:
        value = value.replace("\x00", "\\x00")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = value.encode("utf-8", "backslashreplace").decode("utf-8")
    return value


def _db_clean(obj, depth=0):
    """_db_text over a JSON-shaped structure (bounded depth)."""
    if isinstance(obj, str):
        return _db_text(obj)
    if depth > 64:
        return None
    if isinstance(obj, dict):
        return {_db_text(str(k)): _db_clean(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_db_clean(v, depth + 1) for v in obj]
    return obj


def db_json(obj):
    """JSON text for the issues/artifacts columns. Non-ASCII stays literal
    UTF-8 (a \\uXXXX escape above U+007F is refused by a JSONB column in a
    non-UTF8 database), NUL and lone surrogates are made storable first."""
    return json.dumps(_db_clean(obj), ensure_ascii=False)


# Insecure escape hatches for a Postgres state DB that still authenticates
# with MD5 or a cleartext password. lazaret.pg refuses both over TLS whose
# certificate is not verified (sslmode=prefer/require, the default is
# prefer): a man-in-the-middle terminating TLS could relay the MD5 response
# or read the password. Its opt-outs are keyword arguments of pg.connect(),
# not libpq parameters — the DSN parser rejects them as unknown — so a
# LAZARET_DB DSN cannot carry them. Set one of these variables to "1" to
# opt in; prefer sslmode=verify-full or a SCRAM-SHA-256 role instead.
PG_INSECURE_AUTH_ENV = {
    "LAZARET_PG_ALLOW_MD5_OVER_UNVERIFIED_TLS": "allow_md5_over_unverified_tls",
    "LAZARET_PG_ALLOW_CLEARTEXT_PASSWORD": "allow_cleartext_password",
}


def pg_insecure_auth_options(environ=None):
    """pg.connect() keyword arguments enabled by PG_INSECURE_AUTH_ENV
    (exactly "1" enables one; anything else leaves lazaret.pg's refusal)."""
    env = os.environ if environ is None else environ
    return {kw: True for var, kw in PG_INSECURE_AUTH_ENV.items() if env.get(var) == "1"}


class Store:
    def __init__(self, dsn):
        kind, target = classify_dsn(dsn)
        self.pg = kind == "pg"
        if self.pg:
            from lazaret import pg as lazaret_pg
            # audit H2 (=F3/F4): Store is LIBRARY code — the MCP server
            # constructs it inside tool dispatch (scan_package /
            # registry_status / discover_packages), where sys.exit()
            # bypasses every `except Exception` and kills the whole
            # server with no error reply. RuntimeError propagates to the
            # tool boundary normally; the CLI boundary (main) converts
            # it back to the identical sys.exit() message and exit code.
            # (License note: the backend is the internal stdlib-only
            # lazaret_pg client — no external driver, nothing to pip-install.)
            try:
                self.conn = lazaret_pg.connect(   # DSN should target a dedicated lazaret DB
                    target, timeout=30, application_name="lazaret",
                    **pg_insecure_auth_options())
            except (lazaret_pg.Error, OSError) as exc:
                raise RuntimeError(f"Postgres backend unreachable: {exc}") from exc
            self._pg_errors = lazaret_pg
            self.ph, self.t = "$1", ""
        else:
            import sqlite3
            # G20 (artifact hygiene): registry state is shared by concurrent
            # writers (a `scan-all` sweep while the MCP server answers
            # tool calls against the same LAZARET_DB). Plain connect()
            # gave us the 5s default lock timeout and no WAL, so writers
            # crashed with "database is locked" mid-sweep. 30s busy timeout
            # + WAL (readers never block writers) is the standard remedy.
            try:
                self.conn = sqlite3.connect(target, timeout=30)
            except sqlite3.Error as exc:
                raise StoreConfigError(f"cannot open SQLite database: {exc}") from exc
            self._configure_sqlite()
            self.ph, self.t = "?", ""
        try:
            self._init_schema()
        except BaseException:
            self.close()
            raise

    def close(self):
        """Close the database connection (idempotent). Every caller closes
        what it opens: a long-running MCP server must not keep a handle per
        tool call, and Windows can't delete a database file that is still
        open (STRUCTURE.md, "Cross-platform rules", rule 3)."""
        conn = getattr(self, "conn", None)
        if conn is not None and not getattr(self, "_closed", False):
            self._closed = True
            try:
                conn.close()
            except Exception:                                  # noqa: BLE001
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def _phs(self, n):
        """n positional placeholders for the ACTIVE backend, in order.

        sqlite wants `?` for every parameter; the Postgres wire protocol
        requires each parameter to have its OWN $k number ($1, $2, ...).
        SQL shared by both branches must interpolate this list, never a
        single repeated self.ph (which would send every value as $1)."""
        if self.pg:
            return [f"${i}" for i in range(1, n + 1)]
        return ["?"] * n

    def _configure_sqlite(self):
        """Best-effort pragmas for shared use; failures (exotic filesystems,
        immutable VFS, …) must not make the store unusable."""
        import sqlite3
        for pragma in ("PRAGMA journal_mode=WAL",
                       "PRAGMA synchronous=NORMAL",
                       "PRAGMA busy_timeout=30000"):
            try:
                self.conn.execute(pragma)
            except sqlite3.Error:
                pass

    def _init_schema(self):
        """Create the tables, and migrate older ones in place (idempotent):
        scans.artifacts holds the per-file detail of multi-artifact scans."""
        if self.pg:
            # Postgres DDL (SERIAL / JSONB): execute_script runs the whole
            # script as ONE implicit transaction via the simple protocol.
            self.conn.execute_script(f"""CREATE TABLE IF NOT EXISTS {self.t}packages (
                id SERIAL PRIMARY KEY, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
                added_at TEXT NOT NULL, UNIQUE (ecosystem, name));
                CREATE TABLE IF NOT EXISTS {self.t}scans (
                id SERIAL PRIMARY KEY, package_id INTEGER NOT NULL REFERENCES {self.t}packages(id),
                version TEXT NOT NULL, profile TEXT NOT NULL, scanned_at TEXT NOT NULL,
                engine_version TEXT NOT NULL, files_scanned INTEGER, archive_bytes INTEGER,
                blockers INTEGER, criticals INTEGER, majors INTEGER,
                supply_chain INTEGER, issue_count INTEGER, verdict TEXT,
                issues JSONB, artifacts JSONB,
                UNIQUE (package_id, version, profile, engine_version));
                ALTER TABLE {self.t}scans ADD COLUMN IF NOT EXISTS artifacts JSONB;
                CREATE INDEX IF NOT EXISTS idx_scans_package
                ON {self.t}scans(package_id, scanned_at DESC)""")
            return
        cur = self.conn.cursor()
        serial, jsontype = "INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"
        cur.execute(f"""CREATE TABLE IF NOT EXISTS {self.t}packages (
            id {serial}, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
            added_at TEXT NOT NULL, UNIQUE (ecosystem, name))""")
        cur.execute(f"""CREATE TABLE IF NOT EXISTS {self.t}scans (
            id {serial}, package_id INTEGER NOT NULL REFERENCES {self.t}packages(id),
            version TEXT NOT NULL, profile TEXT NOT NULL, scanned_at TEXT NOT NULL,
            engine_version TEXT NOT NULL, files_scanned INTEGER, archive_bytes INTEGER,
            blockers INTEGER, criticals INTEGER, majors INTEGER,
            supply_chain INTEGER, issue_count INTEGER, verdict TEXT,
            issues {jsontype}, artifacts {jsontype},
            UNIQUE (package_id, version, profile, engine_version))""")
        columns = {row[1] for row in cur.execute(f"PRAGMA table_info({self.t}scans)")}
        if "artifacts" not in columns:
            cur.execute(f"ALTER TABLE {self.t}scans ADD COLUMN artifacts {jsontype}")
        # G20: WAL already set at connect; index for the status() lateral join
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_scans_package "
                    f"ON {self.t}scans(package_id, scanned_at DESC)")
        self.conn.commit()

    def _pg_call(self, run):
        """Run one self-contained Postgres operation, run() -> result, and
        survive a dropped session. The MCP server and scan-all keep a Store
        open for a long time; an admin shutdown or pg_terminate_backend
        (57P01), idle_session_timeout (57P05) or a network blip ends the
        session, and every later call used to fail with "connection is
        closed" until the process restarted.

        A connection already found closed (lost during an earlier call) is
        reopened first. An OperationalError from run() is followed by ONE
        conn.reconnect() and ONE retry; a second failure, or a failed
        reconnect (server still down), propagates. Never inside a
        transaction: when the caller has a transaction open, run() is not
        retried (a lone retried statement would silently drop the ones
        before it), and reconnect() itself refuses inside a transaction()
        block. run() may be a whole transaction() block of Store's own
        (save_scan): it is retried only as a whole, after the block has
        been left and rolled back. Every Store write is an idempotent
        upsert, so a retry after a lost COMMIT acknowledgement is safe
        (add_package's `created` flag may then read False)."""
        conn = self.conn
        if conn.closed:
            conn.reconnect()
        elif conn.in_transaction:
            return run()                  # the caller's transaction: never retried
        try:
            return run()
        except self._pg_errors.OperationalError:
            conn.reconnect()
            return run()

    def _one(self, sql, args=()):
        if self.pg:
            # wire client: fetchrow(sql, *args) with $n placeholders already
            # written into the SQL by the caller
            return self._pg_call(lambda: self.conn.fetchrow(sql, *args))
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return cur.fetchone()

    def add_package(self, eco, name):
        """Idempotent package upsert, race-free (audit G20).

        The old SELECT-then-INSERT raced between a CLI `scan-all` sweep and
        the MCP server both adding the same (eco, name): one process hit the
        UNIQUE(ecosystem, name) constraint and the sweep died mid-run. The
        SQLite branch uses INSERT OR IGNORE followed by a SELECT inside one
        transaction (last-writer-wins; `added_at` keeps the first timestamp
        because the ignored row stays); the Postgres branch upserts with
        RETURNING so both writers converge on the same id.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        if self.pg:
            # race-free upsert: ON CONFLICT DO UPDATE converges both concurrent
            # writers on the same id; (xmax = 0) reports whether THIS call
            # created the row (False when it already existed, exactly like the
            # old DO NOTHING + SELECT fallback).
            row = self._pg_call(lambda: self.conn.fetchrow(
                f"INSERT INTO {self.t}packages (ecosystem,name,added_at) "
                f"VALUES ($1,$2,$3) "
                f"ON CONFLICT (ecosystem,name) DO UPDATE "
                f"SET added_at={self.t}packages.added_at "
                f"RETURNING id, (xmax = 0) AS created",
                eco, _db_text(name), now))
            return row[0], row[1]
        cur = self.conn.cursor()
        # SQLite: single write that is a no-op if the row exists (keeps the
        # original added_at), then read the id — committed atomically.
        created = False
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cur.execute(f"INSERT OR IGNORE INTO {self.t}packages "
                        f"(ecosystem,name,added_at) VALUES (?,?,?)",
                        (eco, name, now))
            created = cur.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        row = self._one(f"SELECT id FROM {self.t}packages "
                        f"WHERE ecosystem={self.ph} AND name={self.ph}",
                        (eco, name))
        return (row[0], created) if row else (None, created)

    def packages(self):
        sql = (f"SELECT id, ecosystem, name FROM {self.t}packages "
               f"ORDER BY ecosystem, name")
        if self.pg:
            # wire client: fetch() rows are tuple-subclass Rows — positional
            # unpacking (id, eco, name) works unchanged
            return self._pg_call(lambda: self.conn.fetch(sql))
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def has_scan(self, pid, version, profile, engine_version=ENGINE_VERSION):
        """Verdict-integrity fix (audit C2/G16): the cache match is keyed on the
        ENGINE_VERSION that produced the stored scan. A package last scanned
        by an older engine no longer reports OK forever: with UNIQUE
        (package_id, version, profile) and no --rescan, a stale-clean verdict
        used to shadow every future re-scan."""
        p1, p2, p3, p4 = self._phs(4)
        return self._one(
            f"SELECT id FROM {self.t}scans WHERE package_id={p1} AND version={p2} "
            f"AND profile={p3} AND engine_version={p4}",
            (pid, _db_text(version), profile, engine_version)) is not None

    def stored_verdict(self, pid, version, profile, engine_version=ENGINE_VERSION):
        """Verdict of the stored scan has_scan() matches, or None. A sweep
        that skips an already-scanned version reports this one, so a known
        SUSPICIOUS / INCOMPLETE package still fails --ci."""
        p1, p2, p3, p4 = self._phs(4)
        row = self._one(
            f"SELECT verdict FROM {self.t}scans WHERE package_id={p1} AND version={p2} "
            f"AND profile={p3} AND engine_version={p4}",
            (pid, _db_text(version), profile, engine_version))
        return row[0] if row else None

    def save_scan(self, pid, res):
        """Persist one scan result as a SINGLE atomic statement (audit G20).

        The old implementation ran DELETE then INSERT as two separate
        autocommitted statements: a crash between them (kill, disk full,
        exception) left the version with NO row, which has_scan then
        reported as never-scanned — a completed scan silently vanishing
        from the record. Now one INSERT … ON CONFLICT DO UPDATE keyed on
        the same UNIQUE (package_id, version, profile, engine_version) the
        schema already declares, inside one transaction: there is no window
        in which the version has no row.

        Text is made storable first (_db_clean): Postgres rejects NUL and
        lone surrogates in TEXT/JSONB, and an issue that quotes a hostile
        hook command or a non-UTF-8 member name must not cost the verdict.
        """
        sc = res["sevCounts"]
        conflict_key = ("ON CONFLICT (package_id, version, profile, engine_version) "
                        "DO UPDATE SET "
                        "scanned_at=excluded.scanned_at, "
                        "engine_version=excluded.engine_version, "
                        "files_scanned=excluded.files_scanned, "
                        "archive_bytes=excluded.archive_bytes, "
                        "blockers=excluded.blockers, criticals=excluded.criticals, "
                        "majors=excluded.majors, supply_chain=excluded.supply_chain, "
                        "issue_count=excluded.issue_count, verdict=excluded.verdict, "
                        "issues=excluded.issues, artifacts=excluded.artifacts")
        values = (pid, _db_text(res["version"]), res["profile"], res["scannedAt"], ENGINE_VERSION,
                  res["filesScanned"], res["archiveBytes"], sc["BLOCKER"], sc["CRITICAL"],
                  sc["MAJOR"], res["supplyChain"], len(res["issues"]), _db_text(res["verdict"]),
                  db_json(res["issues"]), db_json(res.get("artifacts") or []))
        columns = ("INSERT INTO {t}scans (package_id,version,profile,scanned_at,"
                   "engine_version,files_scanned,archive_bytes,blockers,criticals,majors,"
                   "supply_chain,issue_count,verdict,issues,artifacts) ").format(t=self.t)
        if self.pg:
            # The wire client's transaction() gives the single-atomic-statement
            # guarantee (commit on success, rollback on exception). ::jsonb
            # casts the dumps'd text into the JSONB columns (sqlite stores TEXT).
            # _pg_call retries the WHOLE block once after a dropped session
            # (the upsert is idempotent), never a statement inside it.
            def upsert():
                with self.conn.transaction():
                    self.conn.execute(
                        columns + "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,"
                                  f"$14::jsonb,$15::jsonb) {conflict_key}",
                        *values)
            self._pg_call(upsert)
            return
        cur = self.conn.cursor()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cur.execute(columns + f"VALUES ({','.join([self.ph] * 15)}) {conflict_key}", values)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def status(self):
        sql = (f"""
            SELECT p.ecosystem, p.name, s.version, s.profile, s.scanned_at,
                   s.verdict, s.issue_count, s.supply_chain
            FROM {self.t}packages p
            LEFT JOIN {self.t}scans s ON s.id = (
              SELECT id FROM {self.t}scans WHERE package_id = p.id
              ORDER BY scanned_at DESC, id DESC LIMIT 1)
            ORDER BY p.ecosystem, p.name""")
        if self.pg:
            return self._pg_call(lambda: self.conn.fetch(sql))
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def report(self, eco, name, version=None):
        p1, p2 = self._phs(2)
        q = (f"SELECT s.version, s.profile, s.scanned_at, s.verdict, s.issues, s.artifacts "
             f"FROM {self.t}scans s JOIN {self.t}packages p ON p.id = s.package_id "
             f"WHERE p.ecosystem={p1} AND p.name={p2}")
        args = [eco, name]
        if version:
            p3 = self._phs(3)[2]
            q += f" AND s.version={p3}"
            args.append(version)
        q += " ORDER BY s.scanned_at DESC LIMIT 1"
        row = self._one(q, args)
        if not row:
            return None
        if isinstance(row[4], list):          # JSONB backend already parsed it
            issues = row[4]
        else:
            # Card 1149e3e5: a scan result — user-supplied repo content at
            # write time — round-trips through json.loads here. Nothing stops
            # a hostile entry from being nested 60k deep: ~60KB of '[' will
            # RecursionError, killing 'report' and MCP registry_status with a
            # traceback. Guard it: parse failure (any cause) degrades to a
            # named issue instead of crashing the query; verdict + metrics
            # (rows the JSON blob doesn't feed) stay intact.
            try:
                issues = json.loads(row[4])
            except (json.JSONDecodeError, RecursionError, TypeError) as exc:
                what = f"stored scan issues for {eco}:{name}@{row[0]}"
                # audit H1: `what` interpolates the stored name/version — a
                # registry-supplied value that never passed NAME_RE on the
                # stored-blob path. Neutralize its control bytes before it
                # reaches a terminal.
                print(f"warning: {lazaret.sanitize_term(what)}: could not parse "
                      f"({exc.__class__.__name__})", file=sys.stderr)
                issues = [lazaret.mk_issue(
                    {"id": "SC-STORED-DEPTH", "type": "HOTSPOT",
                     "sev": "CRITICAL",
                     "name": "Hostile nesting depth in stored scan result",
                     "msg": (f"Stored scan result could not be parsed "
                             f"({exc.__class__.__name__}) — likely nested "
                             f"beyond CPython's recursion limit."),
                     "why": ("A stored issues blob this shape cannot come from "
                             "a normal scan: a 60k-deep document is exactly "
                             "the primitive that crashes or blinds scanners "
                             "(card 48033f94). The record's verdict and "
                             "counts stand; only the issue list is unreadable."),
                     "fix": ("Inspect this DB row directly; re-scan the package "
                             "with --rescan to rebuild a sane stored result."),
                     "ref": "CWE-506 · Supply chain"},
                    row[0] or "<stored>", 1, [])]
        artifacts = row[5] if len(row) > 5 else None
        if isinstance(artifacts, str):
            try:
                artifacts = json.loads(artifacts)
            except (ValueError, RecursionError):
                artifacts = None
        return {"version": row[0], "profile": row[1], "scannedAt": row[2],
                "verdict": row[3], "issues": issues,
                "artifacts": artifacts if isinstance(artifacts, list) else []}


# ---------------- CLI ----------------
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else str(s)

VERDICT_COLOR = {"OK": "42;30", "WARN": "43;30", "INCOMPLETE": "44;97", "SUSPICIOUS": "41;97"}

def print_scan(res, top=15):
    # audit H1: the verdict badge is wrapped in its own SGR sequence by c(),
    # so the sanitized value must be the ARGUMENT of c() — sanitizing the
    # result would strip Lazaret's own color codes and leave the span open.
    v = c(VERDICT_COLOR.get(res["verdict"], "7"), f" {lazaret.sanitize_term(res['verdict'])} ")
    sc = res["sevCounts"]
    # audit H1: ecosystem/name/version come from registry metadata; `version`
    # in particular is re-read from the feed (after _check_version), so it is
    # never NAME_RE-gated. Neutralize before printing.
    print(f"\n{lazaret.sanitize_term(res['ecosystem'])}:"
          f"{lazaret.sanitize_term(res['name'])}@"
          f"{lazaret.sanitize_term(res['version'])}  {v}")
    if res.get("verdictReason"):
        print(f"  {lazaret.sanitize_term(res['verdictReason'])}")
    print(f"  {res['filesScanned']} source files · {res.get('binaryArtifacts', 0)} binary "
          f"artifacts · {res['archiveBytes']//1024} KB {res.get('artifact','')} "
          f"· profile: {res['profile']}")
    arts = res.get("artifacts") or []
    if len(arts) > 1:
        for a in arts:
            print(f"    {lazaret.sanitize_term(a.get('verdict'))!s:<10} "
                  f"{lazaret.sanitize_term(a.get('filename'))}")
    print(f"  blockers {sc['BLOCKER']} · criticals {sc['CRITICAL']} · majors {sc['MAJOR']} "
          f"· supply-chain indicators {res['supplyChain']}")
    for i in res["issues"][:top]:
        prefix = f"    {i['sev']:<8} [{i['rule']}] "
        # audit H1: i['file'] is an archive member name (hostile tarball) and
        # i['msg'] embeds scanned content (install-hook cmd, X-FLOW paths).
        print(f"{prefix}{lazaret.sanitize_term(i['file'])}:{i['line']} — "
              f"{lazaret.sanitize_term(i['msg'])}")
        ex = lazaret.issue_excerpt(i)
        if ex:
            print(" " * len(prefix) + c('2', '» ' + ex))   # aligned under the file path
    if len(res["issues"]) > top:
        print(f"    … {len(res['issues']) - top} more (see 'report')")


# ---------------- Discovery: recently published/updated packages ----------------
def parse_since(s):
    """'7d' / '2w' / '24h' / an ISO date -> a timezone-aware UTC cutoff datetime."""
    s = (s or "").strip().lower()
    now = datetime.datetime.now(datetime.timezone.utc)
    m = re.fullmatch(r"(\d+)\s*([hdw])", s)
    if m:
        hours = int(m.group(1)) * {"h": 1, "d": 24, "w": 168}[m.group(2)]
        try:
            return now - datetime.timedelta(hours=hours)
        except OverflowError:
            raise ValueError(f"bad --since {s!r}; use e.g. 7d, 2w, 24h, or 2026-06-25") from None
    try:
        d = datetime.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        # audit H2 (=F3): this module is LIBRARY code — parse_since is called
        # from the MCP server's tool dispatch (tool_discover_packages), where
        # a raised SystemExit bypasses every `except Exception` and kills the
        # whole server with no error reply (PoC: one discover_packages call
        # with since:"garbage!!" → exit 1, subsequent ping never answered).
        # ValueError propagates normally; the CLI boundary (main → cmd_discover)
        # converts it back to the exact same sys.exit() message and exit code.
        raise ValueError(f"bad --since {s!r}; use e.g. 7d, 2w, 24h, or 2026-06-25")


def _to_utc(dt):
    """G13: force a datetime to UTC-aware so comparisons against aware cutoffs
    never raise naive-vs-aware TypeErrors, and stored timestamps compare
    correctly across DST/timezones."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _parse_xml(raw):
    """G14: parse a registry feed defensively with lazaret.safexml. Any
    DOCTYPE is rejected (forbid_dtd), which also rules out every entity
    declaration, so external-entity resolution and entity-expansion bombs are
    impossible on feed-derived XML that feeds the watchlist. Nesting depth and
    size are bounded too. Returns the parsed root or raises FeedError."""
    try:
        return _safe_ET.fromstring(raw, forbid_dtd=True, max_bytes=FEED_MAX_BYTES)
    except _safexml.SafeXMLError as exc:
        raise FeedError(f"feed rejected by the XML hardening layer: {exc}") from None
    except (_safe_ET.ParseError, ValueError, RecursionError) as exc:
        raise FeedError(f"feed is not well-formed XML ({type(exc).__name__})") from None


def _feed_token_ok(value):
    """A token lifted from an RSS title (name or version) must survive the same
    name validation as CLI specs before it can enter the watchlist and drive a
    download (G14 + F10)."""
    return value is not None and NAME_RE.fullmatch(value) is not None


def discover_pypi(cutoff, limit):
    """Recently created + updated PyPI projects via the RSS feeds (timestamped,
    bounded to the most recent ~100 entries per feed)."""
    import email.utils
    found = {}
    for feed in ("https://pypi.org/rss/packages.xml", "https://pypi.org/rss/updates.xml"):
        try:
            # metadata budget (5 MB) and timeout, not the 200 MB artifact budget
            raw = _fetch(feed, max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT)
        except Exception as exc:                                   # noqa: BLE001
            # audit H1: FetchError/_fetch messages can embed text derived from
            # the network response; `feed` is a constant URL.
            print(f"warning: PyPI feed {feed} failed: "
                  f"{lazaret.sanitize_term(exc)}", file=sys.stderr)
            continue
        try:
            root = _parse_xml(raw)
        except Exception as exc:                                   # noqa: BLE001
            # audit H1: an XML ParseError echoes bytes from the hostile feed.
            print(f"warning: PyPI feed {feed} rejected "
                  f"({lazaret.sanitize_term(exc)}).", file=sys.stderr)
            continue
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            pub = item.findtext("pubDate")
            if not title or not pub:
                continue
            try:
                when = email.utils.parsedate_to_datetime(pub)
            except (TypeError, ValueError, IndexError, OverflowError):
                continue
            when = _to_utc(when)
            if when < cutoff:
                continue
            parts = title.split()
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
            # G14/F10: feed-derived names drive downloads — validate them
            # against the same rules as CLI specs.
            if not valid_name("pypi", name):
                continue
            if version is not None and not _feed_token_ok(version):
                version = None
            if name not in found or when > found[name][3]:
                found[name] = ("pypi", name, version, when)
    out = sorted(found.values(), key=lambda x: x[3], reverse=True)
    return out[:limit] if limit else out


def discover_npm(cutoff, limit):
    """Recently updated npm packages via the replication _changes feed. Best-effort:
    the feed requires network access to replicate.npmjs.com; on failure npm
    discovery is skipped with a warning rather than aborting the run. Rows of
    an unexpected shape, and names npm itself would not accept, are skipped."""
    want = (limit or 100) * 3
    url = (f"https://replicate.npmjs.com/_changes?descending=true"
           f"&include_docs=true&limit={want}")
    try:
        data = http_json(url)
    except Exception as exc:                                       # noqa: BLE001
        # audit H1: the npm _changes feed is network-controlled; the exception
        # text can echo bytes of the hostile response (URLError reason, JSON
        # parse position). Sanitize before it reaches a terminal/CI log.
        print(f"warning: npm changes feed unavailable "
              f"({lazaret.sanitize_term(exc)}); npm discovery skipped "
              f"(needs access to replicate.npmjs.com).", file=sys.stderr)
        return []
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        print("warning: npm changes feed has an unexpected shape; npm discovery skipped.",
              file=sys.stderr)
        return []
    out, rejected = {}, 0
    for row in results:
        if not isinstance(row, dict):
            continue
        doc = row.get("doc") if isinstance(row.get("doc"), dict) else {}
        name = doc.get("name") if isinstance(doc.get("name"), str) else row.get("id")
        if not isinstance(name, str) or not name or name.startswith("_"):
            continue
        if not valid_name("npm", name):
            rejected += 1
            continue
        times = doc.get("time") if isinstance(doc.get("time"), dict) else {}
        modified = times.get("modified")
        when = None
        if isinstance(modified, str):
            try:
                # G13: 'Z' suffix makes fromisoformat produce aware datetimes on
                # Python < 3.11; force every parse to UTC-aware either way so
                # the cutoff comparison never hits naive-vs-aware TypeError.
                when = _to_utc(datetime.datetime.fromisoformat(
                    modified.replace("Z", "+00:00")))
            except ValueError:
                when = None
        if when is None or when < cutoff:
            continue
        tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
        version = tags.get("latest") if isinstance(tags.get("latest"), str) else None
        if version is not None and not _feed_token_ok(version):
            version = None
        if name not in out or when > out[name][3]:
            out[name] = ("npm", name, version, when)
    if rejected:
        print(f"warning: skipped {rejected} npm feed name(s) that are not valid package names.",
              file=sys.stderr)
    res = sorted(out.values(), key=lambda x: x[3], reverse=True)
    return res[:limit] if limit else res


def cmd_discover(store, args):
    cutoff = parse_since(args.since)
    ecos = args.ecosystem or ["pypi", "npm"]
    discovered = []
    if "pypi" in ecos:
        discovered += discover_pypi(cutoff, args.limit)
    if "npm" in ecos:
        discovered += discover_npm(cutoff, args.limit)
    discovered.sort(key=lambda x: x[3], reverse=True)
    if args.limit:
        discovered = discovered[:args.limit]
    if not discovered:
        print(f"No packages published/updated since {cutoff.isoformat()} in {', '.join(ecos)}.")
        return False
    print(f"\nDiscovered {len(discovered)} package(s) since {cutoff.strftime('%Y-%m-%d %H:%M')} UTC:")
    for eco, name, ver, when in discovered:
        # audit H1: discovery-feed name/version are raw feed text. Sanitize
        # before the width-free print (the strftime timestamp is engine-controlled).
        print(f"  {when.strftime('%Y-%m-%d %H:%M')}  "
              f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}"
              f"{('@' + lazaret.sanitize_term(ver)) if ver else ''}")
    errors = getattr(args, "_errors", None)
    if args.add or args.scan:
        for eco, name, _ver, _when in discovered:
            if not valid_name(eco, name):
                continue
            try:
                store.add_package(eco, name)
            except Exception as exc:                                # noqa: BLE001
                # one package the DB refuses must not end the run (cmd_scan
                # below reports it again when --scan is set)
                spec = f"{eco}:{name}"
                print(f"error adding {lazaret.sanitize_term(spec)} to the watchlist: "
                      f"{type(exc).__name__}: {lazaret.sanitize_term(exc)}", file=sys.stderr)
                if errors is not None and not args.scan:
                    errors.append(spec)
    if args.scan:
        specs = [f"{eco}:{name}" + (f"@{ver}" if ver else "")
                 for eco, name, ver, _ in discovered]
        print(f"\nScanning {len(specs)} discovered package(s)…")
        return cmd_scan(store, specs, args.full, args.rescan, errors=errors)
    return False


BAD_VERDICTS = ("SUSPICIOUS", "INCOMPLETE")


def cmd_scan(store, specs, full, rescan, errors=None):
    """Scan each spec; returns True when any result is SUSPICIOUS/INCOMPLETE
    — including the STORED verdict of a version skipped as already scanned —
    or any spec failed. One package's failure (bad name in the watchlist,
    network, digest mismatch, a store error) never stops the sweep.
    `errors`, when given, collects every spec that failed to scan or to be
    stored (the CLI exits 1 for them at the end of the sweep)."""
    exit_bad = False
    profile = "full" if full else "supply-chain"
    for spec in specs:
        try:
            eco, name, ver = parse_spec(spec)
            pid, _ = store.add_package(eco, name)
            resolved = None
            if not rescan:
                if ver is None:
                    # scan-all specs carry no version: ask the registry which
                    # version is current BEFORE downloading, so an already
                    # scanned version is skipped instead of re-scanned.
                    resolved = resolve(eco, name, None)
                    ver = resolved[0]
                if ver and store.has_scan(pid, ver, profile):
                    # A skipped version keeps its stored verdict: a sweep
                    # without --rescan must not turn a known SUSPICIOUS or
                    # INCOMPLETE package into a passing --ci run.
                    stored = store.stored_verdict(pid, ver, profile)
                    # audit H1: name/version echo registry- or feed-derived text.
                    print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                          f"{lazaret.sanitize_term(ver)} already scanned ({profile}"
                          f"{', ' + lazaret.sanitize_term(stored) if stored else ''}); "
                          f"use --rescan to redo")
                    exit_bad |= stored in BAD_VERDICTS
                    continue
            res = scan_package(eco, name, ver, full, resolved=resolved)
        except Exception as exc:
            # audit H1: {spec} is echoed verbatim and {exc} embeds registry
            # response text (FetchError URL/reason, JSON parse position) —
            # both are network-controlled on the failure path.
            print(f"error scanning {lazaret.sanitize_term(spec)}: "
                  f"{lazaret.sanitize_term(exc)}", file=sys.stderr)
            exit_bad = True
            if errors is not None:
                errors.append(spec)
            continue
        try:
            if not rescan and store.has_scan(pid, res["version"], profile):
                # audit H1: res['version'] is re-read from registry metadata.
                print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                      f"{lazaret.sanitize_term(res['version'])} already scanned "
                      f"({profile}); skipping store")
            else:
                store.save_scan(pid, res)
        except Exception as exc:
            # The verdict is printed below all the same; the failure to record
            # it is an error of its own and fails the run at the end.
            print(f"error storing the scan of {lazaret.sanitize_term(spec)}: "
                  f"{type(exc).__name__}: {lazaret.sanitize_term(exc)}", file=sys.stderr)
            exit_bad = True
            if errors is not None:
                errors.append(spec)
        print_scan(res)
        exit_bad |= res["verdict"] in BAD_VERDICTS  # a partial scan never passes
    return exit_bad


def _finish_sweep(errors, bad, ci):
    """CLI exit for scan / scan-all / discover: every package was attempted;
    any that failed to scan or store makes the run exit 1 (with or without
    --ci), after a one-line summary on stderr. --ci also fails on
    SUSPICIOUS / INCOMPLETE."""
    if errors:
        shown = ", ".join(lazaret.sanitize_term(s) for s in errors[:20])
        more = f", … (+{len(errors) - 20} more)" if len(errors) > 20 else ""
        print(f"error: {len(errors)} package(s) failed to scan or store: {shown}{more}",
              file=sys.stderr)
    if errors or (ci and bad):
        sys.exit(1)


def main():
    global SCAN_TIMEOUT, MAX_ARTIFACTS, MAX_PACKAGE_DOWNLOAD_BYTES
    lazaret.configure_stdio()
    ap = argparse.ArgumentParser(prog="lazaret-registry", description="Lazaret npm/PyPI registry scanner")
    ap.add_argument("command", choices=["add", "scan", "scan-all", "list", "report", "discover"])
    ap.add_argument("specs", nargs="*", help="npm:<name>[@ver] or pypi:<name>[@ver]")
    ap.add_argument("--db", default=os.environ.get("LAZARET_DB", "lazaret-registry.db"),
                    help="SQLite path (or sqlite:PATH), postgres:// URL or libpq "
                         "'host=… dbname=…' string (env LAZARET_DB)")
    ap.add_argument("--full", action="store_true",
                    help="Run the full ruleset, not just supply-chain/secret rules")
    ap.add_argument("--rescan", action="store_true", help="Re-scan already-scanned versions")
    ap.add_argument("--ci", action="store_true",
                    help="Exit 1 if any package is SUSPICIOUS or INCOMPLETE")
    ap.add_argument("--no-redact-secrets", action="store_true",
                    help="Opt OUT of secret redaction: keep the matched line for "
                         "credential findings (default: redacted in every artifact, "
                         "including the DB blob)")
    ap.add_argument("--excerpt-width", type=int, metavar="N",
                    help="Chars of the matched line to show under each finding (default 100)")
    ap.add_argument("--scan-timeout", type=float, metavar="SECONDS",
                    help=f"Time budget per archive (default {SCAN_TIMEOUT:g}, env "
                         f"LAZARET_SCAN_TIMEOUT); past it the verdict is INCOMPLETE")
    ap.add_argument("--max-artifacts", type=int, metavar="N",
                    help=f"PyPI files scanned per release (default {MAX_ARTIFACTS}, env "
                         f"LAZARET_MAX_ARTIFACTS); more makes the verdict INCOMPLETE")
    ap.add_argument("--max-download-bytes", type=int, metavar="BYTES",
                    help=f"Total bytes downloaded per package, all release files together "
                         f"(default {MAX_PACKAGE_DOWNLOAD_BYTES} = "
                         f"{_fmt_bytes(MAX_PACKAGE_DOWNLOAD_BYTES)}, env "
                         f"LAZARET_MAX_DOWNLOAD_BYTES); checked against the registry's "
                         f"declared sizes before downloading — files that don't fit "
                         f"are not scanned and the verdict is INCOMPLETE")
    # discover options
    ap.add_argument("--since", default="7d",
                    help="discover: time window — 7d, 2w, 24h, or an ISO date (default 7d)")
    ap.add_argument("--limit", type=int, default=50,
                    help="discover: max packages to return (default 50)")
    ap.add_argument("--ecosystem", action="append", choices=["pypi", "npm"],
                    help="discover: restrict to pypi and/or npm (default both)")
    ap.add_argument("--scan", action="store_true",
                    help="discover: scan the discovered packages (and track them)")
    ap.add_argument("--add", action="store_true",
                    help="discover: add discovered packages to the watchlist")
    args = ap.parse_args()
    lazaret.REDACT_SECRETS = not args.no_redact_secrets
    if args.excerpt_width:
        lazaret.EXCERPT_WIDTH = args.excerpt_width
    if args.scan_timeout and args.scan_timeout > 0:
        SCAN_TIMEOUT = args.scan_timeout
    if args.max_artifacts and args.max_artifacts > 0:
        MAX_ARTIFACTS = args.max_artifacts
    if args.max_download_bytes and args.max_download_bytes > 0:
        MAX_PACKAGE_DOWNLOAD_BYTES = args.max_download_bytes
    try:
        store = Store(args.db)
    except RuntimeError as exc:
        # CLI boundary: Store.__init__ raises RuntimeError when the Postgres
        # backend is unreachable or --db is unusable (library code must not
        # sys.exit — the MCP server dispatches it); here the CLI keeps the
        # exact legacy behavior.
        sys.exit(str(exc))
    try:
        errors = []
        args._errors = errors

        if args.command == "add":
            for spec in args.specs:
                try:
                    eco, name, _ = parse_spec(spec)
                except SpecError as exc:
                    sys.exit(f"error: {lazaret.sanitize_term(exc)}")
                _, created = store.add_package(eco, name)
                # audit H1: operator CLI arg; sanitize is a no-op for clean names.
                print(f"{'added' if created else 'already tracked'}: "
                      f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}")

        elif args.command == "scan":
            if not args.specs:
                sys.exit("scan needs at least one package spec")
            bad = cmd_scan(store, args.specs, args.full, args.rescan, errors=errors)
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "scan-all":
            specs = [f"{eco}:{name}" for _, eco, name in store.packages()]
            if not specs:
                sys.exit("no tracked packages — use 'add' first")
            print(f"Scanning latest versions of {len(specs)} tracked package(s)…")
            bad = cmd_scan(store, specs, args.full, args.rescan, errors=errors)
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "discover":
            try:
                bad = cmd_discover(store, args)
            except ValueError as exc:
                # CLI boundary: parse_since raises ValueError for a bad --since
                # (library code must not raise SystemExit — the MCP server
                # dispatches discover_packages); the CLI keeps the exact legacy
                # behavior: message on stderr, exit 1.
                sys.exit(str(exc))
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "list":
            rows = store.status()
            if not rows:
                print("no tracked packages")
                return
            print(f"\n{'package':<40} {'last scan':<22} {'version':<12} {'verdict':<11} issues")
            for eco, name, ver, profile, at, verdict, n, supply in rows:
                # audit H1: eco/name/ver come from the stored DB blob (registry
                # data). Sanitize BEFORE the <40/<12 width padding so the column
                # alignment is computed on the string that is actually printed
                # ('·' is one char, so widths stay correct).
                pkg = lazaret.sanitize_term(f"{eco}:{name}")
                if ver is None:
                    print(f"{pkg:<40} {'— never scanned':<22}")
                else:
                    # sanitize the ARGUMENT of c(), never its result.
                    vc = c(VERDICT_COLOR.get(verdict, "0"), lazaret.sanitize_term(verdict))
                    extra = f" ({supply} supply-chain)" if supply else ""
                    print(f"{pkg:<40} {at:<22} "
                          f"{lazaret.sanitize_term(ver):<12} {vc:<11} {n}{extra}")

        elif args.command == "report":
            if not args.specs:
                sys.exit("report needs a package spec")
            try:
                eco, name, ver = parse_spec(args.specs[0])
            except SpecError as exc:
                sys.exit(f"error: {lazaret.sanitize_term(exc)}")
            rep = store.report(eco, name, ver)
            if not rep:
                # audit H1: args.specs[0] is echoed before any validation applies
                # to it on this path (parse_spec accepts a scoped name; a hostile
                # discovery-fed spec reaches here verbatim).
                sys.exit(f"no stored scan for {lazaret.sanitize_term(args.specs[0])}")
            # audit H1: rep[] fields are read back from the stored DB blob, which
            # was built from registry metadata + package content.
            print(f"\n{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                  f"{lazaret.sanitize_term(rep['version'])} — "
                  f"{lazaret.sanitize_term(rep['verdict'])} "
                  f"(profile {rep['profile']}, scanned {rep['scannedAt']})")
            for a in rep.get("artifacts") or []:
                if isinstance(a, dict) and len(rep["artifacts"]) > 1:
                    print(f"  {lazaret.sanitize_term(a.get('verdict'))!s:<10} "
                          f"{lazaret.sanitize_term(a.get('filename'))}")
            for i in rep["issues"]:
                prefix = f"  {i['sev']:<8} [{i['rule']}] "
                # audit H1: stored archive member names + rule messages that embed
                # package content (SC-INSTALL-HOOK cmd, SCA advisory titles).
                print(f"{prefix}{lazaret.sanitize_term(i['file'])}:{i['line']} — "
                      f"{lazaret.sanitize_term(i['msg'])}")
                ex = lazaret.issue_excerpt(i)
                if ex:
                    print(" " * len(prefix) + c('2', '» ' + ex))
            if not rep["issues"]:
                print("  no findings")

    finally:
        store.close()


if __name__ == "__main__":
    main()
