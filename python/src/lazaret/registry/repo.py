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
    default            SQLite file lazaret-registry.db (no dependencies)
    postgres://…       PostgreSQL via the internal wire-protocol client
                       (lazaret.pg — pure stdlib, SCRAM-SHA-256 + TLS; nothing
                       to pip-install).
                       Point the DSN at a dedicated database on your server, e.g.
                       postgres://user:pass@host:5432/lazaret — see registry/schema.sql
                       for one-time setup. Don't reuse an existing application DB.

Package specs: npm:<name>[@version]  |  pypi:<name>[@version or ==version]
Scoped npm packages work: npm:@scope/pkg@1.0.0
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zipfile
import urllib.error
import urllib.parse
import urllib.request

from lazaret.scanner import core as lazaret  # noqa: E402

from lazaret import safexml as _safexml                 # noqa: E402
from lazaret.safexml import ElementTree as _safe_ET     # noqa: E402

FEED_MAX_BYTES = 16 * 1024 * 1024   # a registry RSS feed is ~100 entries; far below this

USER_AGENT = "Lazaret-registry-scanner/1.0"
MAX_MEMBER = 1_000_000     # bytes of a text file we will scan as source
MAX_FILES = 4000           # files per package
SAMPLE = 8192              # header/entropy sample read from oversized files
ENGINE_VERSION = "2.2.0"   # 2.2: verdict-integrity (suppression/size/cache); 2.1: binary-artifact awareness

# ---------------- Trust-chain limits (F9/G14/F10) ----------------
# Only these hosts may ever be fetched, over https only, and redirects to any
# other scheme/host are refused. Everything else fails closed.
REGISTRY_HOSTS = {"registry.npmjs.org", "replicate.npmjs.com",
                  "pypi.org", "files.pythonhosted.org"}
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024     # one artifact archive (F9a)
MAX_FEED_BYTES = 5 * 1024 * 1024           # registry metadata / RSS / _changes feed
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024      # cumulative *decompressed* bytes per archive (F9b)
MAX_REDIRECTS = 3                          # no redirect loops / long hop chains
FETCH_CHUNK = 64 * 1024
METADATA_TIMEOUT = 30                      # seconds for registry metadata / feeds
DOWNLOAD_TIMEOUT = 60                      # seconds for artifact archives
# Package names come from user input AND from registry feeds, and end up in URLs
# and the watchlist — validate before either.
NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")


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

# ---------------- Package spec parsing ----------------
def _check_name(eco, name):
    """Reject names that could escape the registry API path or poison the DB (F10).

    Names arrive from the CLI, the watchlist *and* registry discovery feeds, and
    end up interpolated into URLs and persisted — so traversal segments, path
    separators and control characters must never be accepted.
    """
    if not name:
        raise SpecError(f"{eco}: empty package name")
    if name in (".", "..") or not NAME_RE.fullmatch(name):
        raise SpecError(f"{eco}: invalid package name {name!r}")
    return name


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
    if ":" not in spec:
        raise ValueError(f"Spec must be npm:<name> or pypi:<name> — got {spec!r}")
    eco, rest = spec.split(":", 1)
    eco = eco.lower()
    if eco not in ("npm", "pypi"):
        raise ValueError(f"Unknown ecosystem {eco!r} (use npm or pypi)")
    rest = rest.strip().replace("==", "@")
    if rest.startswith("@"):                      # scoped npm package
        if "@" in rest[1:]:
            name, ver = rest[1:].split("@", 1)
        else:
            name, ver = rest[1:], None
        scope, _, tail = name.partition("/")
        if not tail or "/" in tail:
            raise SpecError(f"npm: scoped name must be @scope/pkg, got {rest!r}")
        _check_name(eco, scope)
        _check_name(eco, tail)
        return eco, "@" + name, _check_version(eco, ver)
    if "@" in rest:
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
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
def resolve_npm(name, version):
    """-> (version, url, container_format, artifact_kind, meta_entry).
    meta_entry is the version metadata (dist.integrity digest lives there),
    consumed by scan_package for artifact verification (G15)."""
    _check_name("npm", name)
    version = _check_version("npm", version)
    meta = http_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    if version is None:
        version = meta.get("dist-tags", {}).get("latest")
    v = (meta.get("versions") or {}).get(version)
    if not v:
        raise ValueError(f"npm:{name}@{version} not found")
    return version, v["dist"]["tarball"], "tgz", "npm", v


def resolve_pypi(name, version):
    """-> (version, url, container_format, artifact_kind, meta_entry).
    Prefers the sdist (buildable source) over a wheel so binaries stand out
    as unexpected. URL path segments are quoted (F10) and the chosen files
    entry (digests.sha256 lives there) is returned for G15 verification."""
    _check_name("pypi", name)
    version = _check_version("pypi", version)
    url = (f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(version)}/json" if version
           else f"https://pypi.org/pypi/{_quote_seg(name)}/json")
    meta = http_json(url)
    version = meta["info"]["version"]
    urls = meta.get("urls") or []
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    wheel = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    pick = sdist or wheel
    if not pick:
        raise ValueError(f"pypi:{name}@{version} has no downloadable archive")
    container = "zip" if pick["filename"].endswith((".whl", ".zip")) else "tgz"
    artifact = "sdist" if pick is sdist else "wheel"
    return version, pick["url"], container, artifact, pick


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


# ---------------- In-memory archive scanning ----------------
def iter_archive(data, container):
    """Yield (relative_path, real_size, raw_bytes, reason) for every file in
    the archive.

    Verdict-integrity fix (audit C2/G16): sizes are now REAL decompressed byte
    counts, never the archive-declared file_size/tar m.size — a hostile
    archive used to declare >MAX_MEMBER and skip scanning entirely with zero
    signal. Reading is bounded at MAX_MEMBER+1 per member, so neither a lying
    header nor a decompression bomb can exhaust memory.

    reason is None for a fully-scanned member, or:
      "member" — the member decompresses to more than MAX_MEMBER bytes; only
                 the first SAMPLE bytes are returned (real_size is the length
                 of that decompressed prefix, not the declared size), so the
                 caller can still classify by magic/entropy but must not scan
                 it as source.
      "files"  — the archive has more than MAX_FILES entries (attacker
                 controls entry order; the member that tripped the cap is
                 yielded with b"" so the cutoff is attributable). Iteration
                 stops after this yield.
      "total"  — the cumulative REAL decompressed size of members yielded so
                 far exceeds MAX_ARCHIVE_TOTAL (F9b); iteration stops after
                 this yield. The budget is charged from measured bytes, not
                 declared ones, so a lying header cannot stop the scan early
                 either."""
    count = 0
    total = 0
    if container == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                count += 1
                if count > MAX_FILES:
                    yield strip_root(info.filename), 0, b"", "files"
                    return
                # real decompressed bytes read for the yielded member
                with zf.open(info) as fh:
                    raw = fh.read(MAX_MEMBER + 1)  # bounded, real bytes
                if len(raw) > MAX_MEMBER:
                    raw = raw[:SAMPLE]
                    yield strip_root(info.filename), len(raw), raw, "member"
                    continue
                total += len(raw)
                if total > MAX_ARCHIVE_TOTAL:
                    yield strip_root(info.filename), len(raw), raw, "total"
                    return
                yield strip_root(info.filename), len(raw), raw, None
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                count += 1
                if count > MAX_FILES:
                    yield strip_root(m.name), 0, b"", "files"
                    return
                if total > MAX_ARCHIVE_TOTAL:
                    yield strip_root(m.name), 0, b"", "total"
                    return
                f = tf.extractfile(m)
                if f is None:
                    continue
                raw = f.read(MAX_MEMBER + 1)           # bounded, real bytes
                if len(raw) > MAX_MEMBER:
                    raw = raw[:SAMPLE]
                    yield strip_root(m.name), len(raw), raw, "member"
                    continue
                total += len(raw)
                if total > MAX_ARCHIVE_TOTAL:
                    yield strip_root(m.name), len(raw), raw, "total"
                    return
                yield strip_root(m.name), len(raw), raw, None


def strip_root(path):
    parts = path.replace("\\", "/").lstrip("./").split("/")
    return "/".join(parts[1:]) if len(parts) > 1 else parts[0]


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
}
# Hard cap on SC-TRUNCATED findings per package so a hostile archive with
# thousands of oversize members cannot flood the report; the `truncated`
# count in the result always reflects the true number.
TRUNCATED_FINDING_CAP = 20


def scan_package(eco, name, version=None, full=False):
    """Fetch and scan one package version. Returns a result dict.

    Every archive member is classified as source or binary. Source files (by
    extension) are run through the normal ruleset; binary/compiled artifacts
    are run through classify_binary, which flags smuggled executables, nested
    archives, and opaque high-entropy blobs — with severity that depends on
    whether they belong (sdist/npm vs wheel)."""
    version, url, container, artifact, meta_entry = (
        resolve_npm if eco == "npm" else resolve_pypi)(name, version)
    data = http_bytes(url)
    # G15: verify the artifact against the registry-published digest BEFORE
    # scanning anything — a mismatch raises and nothing is persisted under
    # this name/version.
    digest = verify_digest(data, meta_entry, eco, name, version)
    issues, files_scanned, binaries = [], 0, 0
    source_records = []
    truncated = 0
    truncated_emitted = 0
    for rel, size, raw, reason in iter_archive(data, container):
        if reason:
            # Verdict integrity (audit C2/G16): a cut-short scan is a signal,
            # not a clean verdict. Every cutoff reason — an oversize member,
            # the file-count cap, the cumulative budget — becomes an
            # SC-TRUNCATED finding (capped per-package; the count is exact)
            # and forces verdict=SUSPICIOUS.
            truncated += 1
            if truncated_emitted < TRUNCATED_FINDING_CAP:
                issues.append(lazaret.truncated_issue(
                    rel, _TRUNC_DETAILS[reason](rel, size)))
                truncated_emitted += 1
            if reason == "member":
                # still classifiable by magic/entropy from the decompressed
                # prefix — real size, no declared-size trust.
                bi = lazaret.classify_binary(rel, raw, size, artifact)
                if bi:
                    binaries += 1
                    issues.append(bi)
            continue
        base = os.path.basename(rel)
        if not lazaret.looks_binary(raw[:2048]):
            text = raw.decode("utf-8", "replace")
            if base == "package.json":
                issues.extend(lazaret.scan_manifest(rel, text))
                continue
            ext = os.path.splitext(base)[1].lower()
            lang = lazaret.EXTS.get(ext)
            if lang is None:
                continue
            files_scanned += 1
            issues.extend(lazaret.scan_file(rel, text, lang, dep=not full))
            source_records.append({"path": rel, "content": text, "lang": lang})
        else:
            bi = lazaret.classify_binary(rel, raw, size, artifact)
            if bi:
                binaries += 1
                issues.append(bi)
    # interprocedural / cross-file taint (full profile only — needs whole source)
    if full and getattr(lazaret, "lazaret_flow", None) is not None:
        issues.extend(lazaret.lazaret_flow.analyze(source_records))
    # F9b: the decompressed sources are no longer needed — drop the reference
    # before building the result so cumulative archive contents don't stay
    # pinned in RSS until the next scan.
    source_records = None
    issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["file"], i["line"]))
    sev_counts = {s: 0 for s in lazaret.SEV_ORDER}
    for i in issues:
        sev_counts[i["sev"]] += 1
    # supply-chain indicators drive the verdict; INFO-level inventory (expected
    # binaries in a wheel) is surfaced but does not count against the package.
    supply = sum(1 for i in issues if i["rule"].startswith("SC-") and i["sev"] != "INFO")
    # Verdict integrity: a truncated scan can never yield a clean verdict —
    # the unscanned members are attacker-chosen.
    if supply or sev_counts["BLOCKER"] or truncated:
        verdict = "SUSPICIOUS"
    elif sev_counts["CRITICAL"]:
        verdict = "WARN"
    else:
        verdict = "OK"
    # L1 (artifact hygiene): redaction is default-on, so the issues this
    # result carries — including the ones persisted as the Store blob via
    # save_scan — already have placeholder/scrubbed snippets from mk_issue.
    # This defensive sweep exists so the registry path cannot regress: an
    # issue entering from any unpatched engine path gets its context lines
    # scrubbed before the blob is written.
    issues = lazaret.redact_result({"issues": list(issues)})["issues"]
    return {"ecosystem": eco, "name": name, "version": version, "artifact": artifact,
            "archiveBytes": len(data), "filesScanned": files_scanned,
            "binaryArtifacts": binaries, "profile": "full" if full else "supply-chain",
            "sevCounts": sev_counts, "supplyChain": supply, "truncated": truncated,
            "verdict": verdict, "issues": issues, "digest": digest,
            "scannedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


# ---------------- State store (SQLite / Postgres) ----------------
class Store:
    def __init__(self, dsn):
        self.pg = dsn.startswith(("postgres://", "postgresql://"))
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
                    dsn, timeout=30, application_name="lazaret")
            except lazaret_pg.Error as exc:
                raise RuntimeError(f"Postgres backend unreachable: {exc}") from exc
            self.ph, self.t = "$1", ""
        else:
            import sqlite3
            # G20 (artifact hygiene): registry state is shared by concurrent
            # writers (a `scan-all` sweep while the MCP server answers
            # tool calls against the same LAZARET_DB). Plain connect()
            # gave us the 5s default lock timeout and no WAL, so writers
            # crashed with "database is locked" mid-sweep. 30s busy timeout
            # + WAL (readers never block writers) is the standard remedy.
            self.conn = sqlite3.connect(dsn, timeout=30)
            self._configure_sqlite()
            self.ph, self.t = "?", ""
        self._init_schema()

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
                issues JSONB, UNIQUE (package_id, version, profile, engine_version));
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
            issues {jsontype}, UNIQUE (package_id, version, profile, engine_version))""")
        # G20: WAL already set at connect; index for the status() lateral join
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_scans_package "
                    f"ON {self.t}scans(package_id, scanned_at DESC)")
        self.conn.commit()

    def _one(self, sql, args=()):
        if self.pg:
            # wire client: fetchrow(sql, *args) with $n placeholders already
            # written into the SQL by the caller
            return self.conn.fetchrow(sql, *args)
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
            row = self.conn.fetchrow(
                f"INSERT INTO {self.t}packages (ecosystem,name,added_at) "
                f"VALUES ($1,$2,$3) "
                f"ON CONFLICT (ecosystem,name) DO UPDATE "
                f"SET added_at={self.t}packages.added_at "
                f"RETURNING id, (xmax = 0) AS created",
                eco, name, now)
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
            return self.conn.fetch(sql)
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
            (pid, version, profile, engine_version)) is not None

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
                        "issues=excluded.issues")
        if self.pg:
            # (external-driver removal) the old code called
            # self.conn.execute("BEGIN IMMEDIATE") — external-driver
            # connections had no .execute method, so this path raised
            # AttributeError before it could ever persist anything (latent
            # bug: never exercised on a real server). The wire client's
            # transaction() context gives the
            # same single-atomic-statement guarantee (commit on success,
            # rollback on exception). $14::jsonb casts the dumps'd issues text
            # into the JSONB column (sqlite stores TEXT identically).
            with self.conn.transaction():
                self.conn.execute(
                    f"INSERT INTO {self.t}scans (package_id,version,profile,scanned_at,"
                    f"engine_version,files_scanned,archive_bytes,blockers,criticals,majors,"
                    f"supply_chain,issue_count,verdict,issues) "
                    f"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) "
                    f"{conflict_key}",
                    pid, res["version"], res["profile"], res["scannedAt"], ENGINE_VERSION,
                    res["filesScanned"], res["archiveBytes"], sc["BLOCKER"], sc["CRITICAL"],
                    sc["MAJOR"], res["supplyChain"], len(res["issues"]), res["verdict"],
                    json.dumps(res["issues"]))
            return
        cur = self.conn.cursor()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cur.execute(
                f"INSERT INTO {self.t}scans (package_id,version,profile,scanned_at,"
                f"engine_version,files_scanned,archive_bytes,blockers,criticals,majors,"
                f"supply_chain,issue_count,verdict,issues) "
                f"VALUES ({','.join([self.ph]*14)}) {conflict_key}",
                (pid, res["version"], res["profile"], res["scannedAt"], ENGINE_VERSION,
                 res["filesScanned"], res["archiveBytes"], sc["BLOCKER"], sc["CRITICAL"],
                 sc["MAJOR"], res["supplyChain"], len(res["issues"]), res["verdict"],
                 json.dumps(res["issues"])))
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
            return self.conn.fetch(sql)
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def report(self, eco, name, version=None):
        p1, p2 = self._phs(2)
        q = (f"SELECT s.version, s.profile, s.scanned_at, s.verdict, s.issues "
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
        return {"version": row[0], "profile": row[1], "scannedAt": row[2],
                "verdict": row[3], "issues": issues}


# ---------------- CLI ----------------
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else str(s)

VERDICT_COLOR = {"OK": "42;30", "WARN": "43;30", "SUSPICIOUS": "41;97"}

def print_scan(res, top=15):
    # audit H1: the verdict badge is wrapped in its own SGR sequence by c(),
    # so the sanitized value must be the ARGUMENT of c() — sanitizing the
    # result would strip Lazaret's own color codes and leave the span open.
    v = c(VERDICT_COLOR[res["verdict"]], f" {lazaret.sanitize_term(res['verdict'])} ")
    sc = res["sevCounts"]
    # audit H1: ecosystem/name/version come from registry metadata; `version`
    # in particular is re-read from the feed (after _check_version), so it is
    # never NAME_RE-gated. Neutralize before printing.
    print(f"\n{lazaret.sanitize_term(res['ecosystem'])}:"
          f"{lazaret.sanitize_term(res['name'])}@"
          f"{lazaret.sanitize_term(res['version'])}  {v}")
    print(f"  {res['filesScanned']} source files · {res.get('binaryArtifacts', 0)} binary "
          f"artifacts · {res['archiveBytes']//1024} KB {res.get('artifact','')} "
          f"· profile: {res['profile']}")
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
        return now - datetime.timedelta(hours=hours)
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
            raw = http_bytes(feed)
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
            except (TypeError, ValueError):
                continue
            when = _to_utc(when)
            if when < cutoff:
                continue
            parts = title.split()
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
            # G14/F10: feed-derived names drive downloads — validate them
            # against the same allowlist as CLI specs.
            if not _feed_token_ok(name):
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
    discovery is skipped with a warning rather than aborting the run."""
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
    out = {}
    for row in data.get("results", []):
        doc = row.get("doc") or {}
        name = doc.get("name") or row.get("id")
        if not name or name.startswith("_"):
            continue
        modified = (doc.get("time") or {}).get("modified")
        when = None
        if modified:
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
        version = (doc.get("dist-tags") or {}).get("latest")
        if name not in out or when > out[name][3]:
            out[name] = ("npm", name, version, when)
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
        # audit H1: discovery-feed name/version — the npm branch does NOT
        # run _feed_token_ok, so both are raw feed text. Sanitize before the
        # width-free print (the strftime timestamp is engine-controlled).
        print(f"  {when.strftime('%Y-%m-%d %H:%M')}  "
              f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}"
              f"{('@' + lazaret.sanitize_term(ver)) if ver else ''}")
    if args.add or args.scan:
        for eco, name, _ver, _when in discovered:
            store.add_package(eco, name)
    if args.scan:
        specs = [f"{eco}:{name}" + (f"@{ver}" if ver else "")
                 for eco, name, ver, _ in discovered]
        print(f"\nScanning {len(specs)} discovered package(s)…")
        return cmd_scan(store, specs, args.full, args.rescan)
    return False


def cmd_scan(store, specs, full, rescan):
    exit_bad = False
    for spec in specs:
        eco, name, ver = parse_spec(spec)
        pid, _ = store.add_package(eco, name)
        profile = "full" if full else "supply-chain"
        if ver and not rescan and store.has_scan(pid, ver, profile):
            # audit H1: name/version echo registry- or feed-derived text.
            print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                  f"{lazaret.sanitize_term(ver)} already scanned ({profile}); "
                  f"use --rescan to redo")
            continue
        try:
            res = scan_package(eco, name, ver, full)
        except Exception as exc:
            # audit H1: {spec} is echoed verbatim and {exc} embeds registry
            # response text (FetchError URL/reason, JSON parse position) —
            # both are network-controlled on the failure path.
            print(f"error scanning {lazaret.sanitize_term(spec)}: "
                  f"{lazaret.sanitize_term(exc)}", file=sys.stderr)
            exit_bad = True
            continue
        if not rescan and store.has_scan(pid, res["version"], profile):
            # audit H1: res['version'] is re-read from registry metadata and
            # is NOT NAME_RE/version-gated at this point.
            print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                  f"{lazaret.sanitize_term(res['version'])} already scanned "
                  f"({profile}); skipping store")
        else:
            store.save_scan(pid, res)
        print_scan(res)
        exit_bad |= res["verdict"] == "SUSPICIOUS"
    return exit_bad


def main():
    lazaret.configure_stdio()
    ap = argparse.ArgumentParser(prog="lazaret-registry", description="Lazaret npm/PyPI registry scanner")
    ap.add_argument("command", choices=["add", "scan", "scan-all", "list", "report", "discover"])
    ap.add_argument("specs", nargs="*", help="npm:<name>[@ver] or pypi:<name>[@ver]")
    ap.add_argument("--db", default=os.environ.get("LAZARET_DB", "lazaret-registry.db"),
                    help="SQLite path or postgres:// DSN (env LAZARET_DB)")
    ap.add_argument("--full", action="store_true",
                    help="Run the full ruleset, not just supply-chain/secret rules")
    ap.add_argument("--rescan", action="store_true", help="Re-scan already-scanned versions")
    ap.add_argument("--ci", action="store_true", help="Exit 1 if any package is SUSPICIOUS")
    ap.add_argument("--no-redact-secrets", action="store_true",
                    help="Opt OUT of secret redaction: keep the matched line for "
                         "credential findings (default: redacted in every artifact, "
                         "including the DB blob)")
    ap.add_argument("--excerpt-width", type=int, metavar="N",
                    help="Chars of the matched line to show under each finding (default 100)")
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
    try:
        store = Store(args.db)
    except RuntimeError as exc:
        # CLI boundary: Store.__init__ raises RuntimeError when the Postgres
        # backend is unreachable (library code must not sys.exit — the MCP
        # server dispatches it); here the CLI keeps the exact legacy behavior.
        sys.exit(str(exc))

    if args.command == "add":
        for spec in args.specs:
            eco, name, _ = parse_spec(spec)
            _, created = store.add_package(eco, name)
            # audit H1: operator CLI arg; sanitize is a no-op for clean names.
            print(f"{'added' if created else 'already tracked'}: "
                  f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}")

    elif args.command == "scan":
        if not args.specs:
            sys.exit("scan needs at least one package spec")
        bad = cmd_scan(store, args.specs, args.full, args.rescan)
        if args.ci and bad:
            sys.exit(1)

    elif args.command == "scan-all":
        specs = [f"{eco}:{name}" for _, eco, name in store.packages()]
        if not specs:
            sys.exit("no tracked packages — use 'add' first")
        print(f"Scanning latest versions of {len(specs)} tracked package(s)…")
        bad = cmd_scan(store, specs, args.full, args.rescan)
        if args.ci and bad:
            sys.exit(1)

    elif args.command == "discover":
        try:
            bad = cmd_discover(store, args)
        except ValueError as exc:
            # CLI boundary: parse_since raises ValueError for a bad --since
            # (library code must not raise SystemExit — the MCP server
            # dispatches discover_packages); the CLI keeps the exact legacy
            # behavior: message on stderr, exit 1.
            sys.exit(str(exc))
        if args.ci and bad:
            sys.exit(1)

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
        eco, name, ver = parse_spec(args.specs[0])
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


if __name__ == "__main__":
    main()
