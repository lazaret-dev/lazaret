"""Build the CVE bundle `lazaret-sca` matches against, from public feeds.

    lazaret-sca --update-bundle                        # writes ./cve-bundle.json
    lazaret-sca --update-bundle --bundle path/cve-bundle.json
    lazaret-sca . --bundle cve-bundle.json --update-bundle --ci   # refresh, then scan

Three public sources, no account or API key:

  OSV   the Open Source Vulnerabilities database's per-ecosystem exports
        (storage.googleapis.com/osv-vulnerabilities/{npm,PyPI,Go,crates.io}/all.zip):
        GitHub Security Advisories, the PyPA advisory database, the Go
        vulnerability database, RustSec and OpenSSF malicious-package
        reports, with exact package names and affected-version ranges.
  KEV   CISA's Known Exploited Vulnerabilities catalog (its JSON feed, or
        CISA's GitHub mirror of it when the feed can't be reached).
  EPSS  FIRST's Exploit Prediction Scoring System, the daily scores file.

OSV supplies the advisories; KEV and EPSS are joined to them by CVE id.
Records that OSV lists as aliases of one another (a GHSA advisory and the
PYSEC record for the same CVE, a MAL report and GitHub's advisory for the
same malware) become one advisory, named by its CVE when it has one.

Ranges come from each `affected` entry's SEMVER and ECOSYSTEM ranges (GIT
ranges name commits, not versions, and are skipped). The events are put in
version order and read as intervals: `introduced` opens one ("0" means no
lower bound), `fixed` and `limit` close it before that version,
`last_affected` closes it after, and an interval that is never closed has
no upper bound. A version in `affected[].versions` that no interval covers
is added as an exact version. A package with neither is kept without
ranges, which lazaret-sca reports as SCA-CVE-UNKNOWN, never as clear.

Every package entry is marked "exact": OSV names are package-manager names,
so an entry only matches its own ecosystem and its own name (PEP 503
normalized for PyPI, as written for npm and for a Go module path, lowercase
with `_` as `-` for a crate). Entries without the mark (CPE product names
from other bundle producers) keep lazaret-sca's looser name matching; a Go
module or a crate is never matched that way.

Three kinds of OSV entry name no dependency and are left out, counted as
notes: the Go standard library and toolchain (`stdlib`, `toolchain`: go.mod
does not pin them) and RustSec's informational advisories that are not
vulnerabilities (`unmaintained`, `notice`; `unsound` ones stay). Go and
RustSec entries are module- and crate-level, as the other ecosystems' are:
an advisory that is about one function reports every use of the version.

Severity: the CVSS 3.x base score computed from the advisory's vector (4.0
and 2.0 vectors are not scored) and GitHub's severity label, the higher of
the two. A malicious-package report (OpenSSF's MAL- records) is marked
"malicious": lazaret-sca reports it as SCA-MALICIOUS, BLOCKER, as it does a
KEV-listed CVE. EPSS is shown with each finding and changes no severity.

An update is all or nothing. Every feed is checked before anything is
written (a KEV catalog with no CVEs, or an export with no advisories for
its ecosystem, is refused), and the bundle goes to a temporary file that is
renamed over the old one only when complete, so a failed update leaves the
previous bundle as it was, and the freshness condition ages it.

URLs are https only, redirects stay on https, and every download has a
byte budget. A file: URL or a plain path reads a local mirror instead (the
OSV location takes an {ecosystem} placeholder: npm, PyPI, Go, crates.io).
Standard library only.
"""
import csv
import datetime as _dt
import gzip
import http.client
import io
import json
import os
import re
import stat
import struct
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

import lazaret as _lazaret_pkg          # __version__ (the package root imports nothing)
from lazaret.scanner import core as lazaret
from lazaret.scanner import reports as lazaret_report
from lazaret.scanner import sca

OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"
OSV_ECOSYSTEMS = (("npm", "npm"), ("PyPI", "pypi"), ("Go", "go"), ("crates.io", "crates"))   # OSV's directory name, the bundle's name
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own mirror, updated with the feed (github.com/cisagov/kev-data)
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ATTRIBUTION = [
    "Advisories from OSV (https://osv.dev): GitHub Advisory Database (CC-BY 4.0), "
    "PyPA Advisory Database (CC-BY 4.0), Go Vulnerability Database (CC-BY 4.0), "
    "RustSec Advisory Database (public domain; the advisories it imports from the GitHub Advisory Database CC-BY 4.0), "
    "OpenSSF Malicious Packages (Apache-2.0)",
    "CISA Known Exploited Vulnerabilities Catalog (public domain), "
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
]
EPSS_ATTRIBUTION = "EPSS scores: see EPSS at https://www.first.org/epss"
DEFAULT_BUNDLE = sca.DEFAULT_BUNDLE
USER_AGENT = "lazaret-sca/%s" % _lazaret_pkg.__version__

# Budgets. The OSV exports and the EPSS file are streamed to temporary files,
# never held in memory; the KEV catalog (under 2 MB today) is read whole.
# What a feed decompresses to is budgeted too, not just what was downloaded:
# a small gzip can expand a thousandfold, so the EPSS reader charges every
# decompressed byte and caps the length of a line, and an OSV export's zip
# central directory is checked before zipfile parses it.
MAX_OSV_ZIP_BYTES = 4 << 30
MAX_OSV_RECORDS = 5_000_000
MAX_OSV_RECORD_BYTES = 8 << 20
MAX_OSV_CENTRAL_DIR = 1 << 30       # declared bytes of an export's zip central directory
MAX_KEV_BYTES = 64 << 20
MAX_EPSS_BYTES = 512 << 20
MAX_EPSS_CSV_BYTES = 256 << 20      # decompressed (the real file is about 15 MB)
MAX_EPSS_LINE = 64 << 10            # one CSV line (a real one is about 40 bytes)
MAX_EPSS_ROWS = 20_000_000
READ_TIMEOUT = 60           # seconds a download may go without receiving data
MAX_REDIRECTS = 5
STALE_FEED_DAYS = 7         # warn when a feed's own date is older than this

EXIT_OUTPUT = lazaret_report.EXIT_OUTPUT     # 3: the bundle can't be written
EXIT_FEED = sca.EXIT_BUNDLE                  # 4: a feed can't be downloaded or read


class FeedError(Exception):
    """A feed could not be downloaded or read. Nothing is written."""


class BundleOutputError(Exception):
    """The bundle cannot be written to the requested path."""


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------

class _HttpsRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a few redirects (feeds move: EPSS has changed hosts before), https
    only: a feed is never downgraded to http or sent to another scheme."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise urllib.error.URLError("redirect to a non-https URL refused: %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsRedirects)


def local_path(location):
    """The filesystem path a file: URL or plain path names, or None for a
    remote URL. A file: URL must name this machine (no host part)."""
    parts = urllib.parse.urlsplit(location)
    if parts.scheme.lower() == "file":
        if parts.netloc not in ("", "localhost"):
            raise FeedError("%s: a file: URL must name a local path (pass a network share "
                            "as a plain path)" % location)
        return urllib.request.url2pathname(parts.path)
    if "://" in location:
        return None
    return location                       # a path (C:\\... included: no "://")


def _copy(src, dst, max_bytes, location):
    total = 0
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            return total
        total += len(chunk)
        if total > max_bytes:
            raise FeedError("%s is larger than the %d MiB budget for this feed"
                            % (location, max_bytes >> 20))
        dst.write(chunk)


def fetch(location, dst, max_bytes):
    """Copy the resource at `location` (an https URL, a file: URL or a local
    path) into binary file object `dst`; returns the byte count. Any failure
    is a FeedError naming the location."""
    try:
        path = local_path(location)
        if path is not None:
            with open(path, "rb") as src:
                return _copy(src, dst, max_bytes, location)
        if urllib.parse.urlsplit(location).scheme.lower() != "https":
            raise FeedError("%s: only https URLs, file: URLs and local paths are accepted"
                            % location)
        req = urllib.request.Request(location, headers={"User-Agent": USER_AGENT})
        with _OPENER.open(req, timeout=READ_TIMEOUT) as resp:
            return _copy(resp, dst, max_bytes, location)
    except FeedError:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise FeedError("HTTP %s from %s" % (exc.code, location)) from None
    except urllib.error.URLError as exc:
        raise FeedError("cannot fetch %s: %s" % (location, exc.reason)) from None
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise FeedError("cannot fetch %s: %s" % (location, exc)) from None


# ---------------------------------------------------------------------------
# CVSS 3.x base score (FIRST's specification, 3.1 rounding)
# ---------------------------------------------------------------------------

_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS3_HEAD_RE = re.compile(r"\ACVSS:3\.[01]\Z")
_NUMERIC_SCORE_RE = re.compile(r"\A(?:10(?:\.0)?|\d(?:\.\d)?)\Z")


def _roundup(x):
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def cvss3_base_score(vector):
    """Base score of a CVSS 3.0/3.1 vector string, or None if it isn't one.
    Temporal and environmental metrics in the vector are ignored."""
    if not isinstance(vector, str) or len(vector) > 256:
        return None
    parts = vector.strip().split("/")
    if not _CVSS3_HEAD_RE.match(parts[0]):
        return None
    m = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep or key in m:
            return None
        m[key] = val
    try:
        scope = m["S"]
        if scope not in ("U", "C"):
            return None
        pr = {"N": 0.85, "L": 0.68 if scope == "C" else 0.62,
              "H": 0.5 if scope == "C" else 0.27}[m["PR"]]
        exploitability = 8.22 * _CVSS3_AV[m["AV"]] * _CVSS3_AC[m["AC"]] * pr * _CVSS3_UI[m["UI"]]
        c, i, a = (_CVSS3_CIA[m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def _cvss_of(severities):
    """Highest CVSS 3.x base score in an OSV `severity` list, or None."""
    best = None
    for s in severities if isinstance(severities, list) else []:
        if not isinstance(s, dict) or s.get("type") != "CVSS_V3":
            continue
        score = s.get("score")
        if isinstance(score, str) and _NUMERIC_SCORE_RE.match(score.strip()):
            n = float(score)
        else:
            n = cvss3_base_score(score)
        if n is not None and (best is None or n > best):
            best = n
    return best


# ---------------------------------------------------------------------------
# OSV records -> bundle fragments
# ---------------------------------------------------------------------------

_ECOSYSTEM = {"npm": "npm", "pypi": "pypi", "go": "go", "crates.io": "crates"}      # OSV ecosystem (lowercased) -> bundle
_ID_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._:-]{0,99}\Z")
_CVE_RE = re.compile(r"\ACVE-(\d{4})-(\d{4,9})\Z")
_CWE_RE = re.compile(r"\ACWE-\d{1,6}\Z")
_DATE_RE = re.compile(r"\A(\d{4}-\d{2}-\d{2})")
_PYPI_NAME_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_NPM_NAME_RE = re.compile(r"\A(?:@[^\s/@]+/)?[^\s/@][^\s/]*\Z")
_GO_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._~+/-]*\Z")       # a module path, or a package's (a GitHub advisory names those)
_CRATE_NAME_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_-]*\Z")
_NAME_RE = {"pypi": _PYPI_NAME_RE, "go": _GO_NAME_RE, "crates": _CRATE_NAME_RE}
_NOT_MODULES = frozenset({"stdlib", "toolchain"})               # Go's own: OSV names the standard library and the go command
_NOT_VULNERABILITIES = frozenset({"unmaintained", "notice"})    # RustSec's `informational` values that are no flaw in a version
_MAX_NAME = 214
_MAX_VERSION = 128
_LABELS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
           "low": "low"}
_LABEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_REF_ORDER = {"ADVISORY": 0, "REPORT": 1, "FIX": 2, "PACKAGE": 3, "EVIDENCE": 4, "WEB": 5,
              "ARTICLE": 6, "DETECTION": 7, "DISCUSSION": 8}
_MAX_REFS = 6
_MAX_ALIASES = 20
_MAX_CWES = 10
_MAX_TITLE = 200


class Counts(dict):
    """Named counters of skipped input, reported after an update: problems
    as warnings, and (in .notes) oddities that lose nothing."""

    def __init__(self):
        super().__init__()
        self.notes = {}

    def add(self, what, n=1):
        self[what] = self.get(what, 0) + n

    def note(self, what, n=1):
        self.notes[what] = self.notes.get(what, 0) + n


name_key = sca.exact_name_key          # what an exact entry matches on (one definition)


def _package_name(value, ecosystem):
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME or not name.isprintable():
        return None
    return name if _NAME_RE.get(ecosystem, _NPM_NAME_RE).match(name) else None


def _event_order(evs, ecosystem):
    """Indices of `evs` in version order ("introduced 0" first), or None
    when one versioning scheme can't order every event's version."""
    versions = [v for k, v in evs if (k, v) != ("introduced", "0")]
    for keyf in sca._schemes(ecosystem, *versions):
        keys = {}
        for v in versions:
            k = keyf(v)
            if k is None:
                break
            keys[v] = k
        else:
            return sorted(range(len(evs)),
                          key=lambda i: (0,) if evs[i] == ("introduced", "0")
                          else (1, keys[evs[i][1]]))
    return None


def _interval(start, end, end_inclusive, ecosystem):
    r = {}
    if start is not None:
        r["fromVersion"], r["fromInclusive"] = start, True
    if end is not None:
        r["toVersion"], r["toInclusive"] = end, end_inclusive
    if start is not None and end is not None:
        c = sca._cmp_keys(start, end, ecosystem)
        if c is not None and (c > 0 or (c == 0 and not end_inclusive)):
            return None                   # an empty interval affects nothing
    return r


def osv_intervals(events, ecosystem):
    """Bundle ranges for one OSV SEMVER/ECOSYSTEM range (its `events`)."""
    evs = []
    for e in events if isinstance(events, list) else []:
        if not isinstance(e, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            v = e.get(kind)
            if isinstance(v, str) and v.strip() and len(v.strip()) <= _MAX_VERSION:
                evs.append((kind, v.strip()))
                break
    order = _event_order(evs, ecosystem)
    if order is not None:
        evs = [evs[i] for i in order]
    out, start, is_open = [], None, False
    for kind, v in evs:
        if kind == "introduced":
            if not is_open:
                is_open, start = True, (None if v == "0" else v)
        elif is_open:
            out.append(_interval(start, v, kind == "last_affected", ecosystem))
            is_open = False
    if is_open:
        out.append(_interval(start, None, True, ecosystem))
    return [r for r in out if r is not None]


def affected_ranges(aff, ecosystem, counts=None):
    """Bundle ranges for one OSV `affected` entry: its SEMVER/ECOSYSTEM
    intervals, plus every listed version no interval covers."""
    counts = counts if counts is not None else Counts()
    intervals = []
    ranges = aff.get("ranges")
    for rng in ranges if isinstance(ranges, list) else []:
        if isinstance(rng, dict) and rng.get("type") in ("SEMVER", "ECOSYSTEM"):
            intervals.extend(osv_intervals(rng.get("events"), ecosystem))
    points, seen = [], set()
    versions = aff.get("versions")
    if any(sca._all_versions(r) for r in intervals):
        versions = None                   # every version is already covered
    for v in versions if isinstance(versions, list) else []:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if not v or v in seen or len(v) > _MAX_VERSION:
            continue
        seen.add(v)
        if not sca.is_comparable_version(v, ecosystem):
            # a legacy version ('2004d'): installed, it is SCA-CVE-UNKNOWN anyway
            counts.note("listed versions that can't be compared (skipped)")
            continue
        if any(sca.version_in_range(v, r, ecosystem) is True for r in intervals):
            continue
        points.append({"fromVersion": v, "fromInclusive": True,
                       "toVersion": v, "toInclusive": True})
    return intervals + points


def _text(value, limit=_MAX_TITLE):
    if not isinstance(value, str):
        return None
    s = " ".join(value.split())
    if not s:
        return None
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


def _first_line(value, limit=_MAX_TITLE):
    if not isinstance(value, str):
        return None
    for line in value.splitlines():
        s = _text(line.strip("#* \t"), limit)
        if s:
            return s
    return None


def _date(value):
    m = _DATE_RE.match(value) if isinstance(value, str) else None
    return m.group(1) if m else None


def _refs(references):
    """The record's https reference URLs, advisories first (never another
    scheme: they end up as links in the HTML report)."""
    found = []
    for n, ref in enumerate(references if isinstance(references, list) else []):
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if (isinstance(url, str) and url.startswith("https://") and len(url) <= 500
                and url.isprintable() and not any(ch.isspace() for ch in url)):
            found.append((_REF_ORDER.get(ref.get("type"), 9), n, url))
    out = []
    for _, _, url in sorted(found):
        if url not in out:
            out.append(url)
    return out[:_MAX_REFS]


def _dedupe_ranges(ranges):
    out, seen = [], set()
    for r in ranges:
        key = tuple(sorted(r.items()))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def osv_record(raw, counts=None):
    """The parts of one OSV record the bundle uses, or None when it names
    no package of an ecosystem it reads, is withdrawn, or isn't an OSV record."""
    counts = counts if counts is not None else Counts()
    if not isinstance(raw, dict):
        counts.add("OSV files that are not records (skipped)")
        return None
    rid = raw.get("id")
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        counts.add("OSV records without a valid id (skipped)")
        return None
    if raw.get("withdrawn"):
        return None
    packages = {}
    affected = raw.get("affected") if isinstance(raw.get("affected"), list) else []
    for aff in affected:
        if not isinstance(aff, dict) or not isinstance(aff.get("package"), dict):
            continue
        pkg = aff["package"]
        eco_raw = pkg.get("ecosystem")
        eco = _ECOSYSTEM.get(eco_raw.split(":")[0].strip().lower()) \
            if isinstance(eco_raw, str) else None
        if eco is None:
            continue
        name = _package_name(pkg.get("name"), eco)
        if name is None:
            counts.add("affected packages with an unusable name (skipped)")
            continue
        if eco == "go" and name in _NOT_MODULES:
            counts.note("Go standard library and toolchain entries (not modules; skipped)")
            continue
        aff_ds = aff.get("database_specific") if isinstance(aff.get("database_specific"), dict) else {}
        informational = aff_ds.get("informational")
        if eco == "crates" and isinstance(informational, str) and informational in _NOT_VULNERABILITIES:
            counts.note("RustSec informational entries (unmaintained or notice; not vulnerabilities; skipped)")
            continue
        entry = packages.setdefault((eco, name_key(name, eco)), [name, []])
        entry[1].extend(affected_ranges(aff, eco, counts))
    if not packages:
        return None
    aliases = []
    for a in raw.get("aliases") if isinstance(raw.get("aliases"), list) else []:
        if not isinstance(a, str):
            continue
        a = a.strip()
        if _CVE_RE.match(a.upper()):
            a = a.upper()
        if _ID_RE.match(a) and a != rid and a not in aliases:
            aliases.append(a)
    ds = raw.get("database_specific") if isinstance(raw.get("database_specific"), dict) else {}
    label = _LABELS.get(str(ds.get("severity") or "").strip().lower())
    cvss = _cvss_of(raw.get("severity"))
    for aff in affected:
        if isinstance(aff, dict):
            n = _cvss_of(aff.get("severity"))
            if n is not None and (cvss is None or n > cvss):
                cvss = n
    cwe_ids = ds.get("cwe_ids") if isinstance(ds.get("cwe_ids"), list) else []
    modified = raw.get("modified")
    return {
        "id": rid,
        "aliases": aliases,
        "title": _text(raw.get("summary")) or _first_line(raw.get("details")),
        "published": _date(raw.get("published")),
        "modified": modified if isinstance(modified, str) and _DATE_RE.match(modified) else None,
        "label": label,
        "cvss": cvss,
        "cwes": sorted({c for c in cwe_ids if isinstance(c, str) and _CWE_RE.match(c)}),
        "refs": _refs(raw.get("references")),
        "malicious": rid.startswith("MAL-"),
        "packages": [(eco, name, _dedupe_ranges(ranges))
                     for (eco, _key), (name, ranges) in packages.items()],
    }


_ZIP_EOCD_SIG, _ZIP64_LOC_SIG, _ZIP64_EOCD_SIG = b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"
_ZIP_CD_SIG = b"PK\x01\x02"
_ZIP_EOCD = struct.Struct("<4s4H2LH")            # 22 bytes
_ZIP64_LOC = struct.Struct("<4sLQL")             # 20 bytes
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")        # 56 bytes


def _read_at(fileobj, offset, size):
    fileobj.seek(offset)
    return fileobj.read(size)


def osv_zip_preflight(fileobj, max_records=MAX_OSV_RECORDS, max_cd_bytes=MAX_OSV_CENTRAL_DIR):
    """Refuse an export whose zip central directory is too big to parse,
    BEFORE zipfile.ZipFile() reads it (it parses the whole directory, a few
    hundred bytes of memory per record, before max_records can apply).

    The file-backed twin of the registry's in-memory `_zip_preflight`: find
    the End Of Central Directory record (and the ZIP64 one) the way zipfile
    does, then raise FeedError when the declared record count exceeds
    `max_records`, the declared directory size exceeds `max_cd_bytes`, or
    the directory region holds more than `max_records` record signatures (a
    count field can lie; zipfile parses records until the declared size is
    used up). Anything it can't make sense of is left to zipfile, which
    reports it. The file position is restored to the start."""
    try:
        fileobj.seek(0, os.SEEK_END)
        n = fileobj.tell()
    except (AttributeError, OSError, ValueError):
        return                                  # not seekable: zipfile will say so
    try:
        tail_len = min(n, 65535 + _ZIP_EOCD.size)
        base = n - tail_len
        tail = _read_at(fileobj, base, tail_len)
        t = len(tail)
        if t >= _ZIP_EOCD.size and tail[t - 22:t - 18] == _ZIP_EOCD_SIG and tail[t - 2:] == b"\0\0":
            pos = t - 22
        else:                                   # an archive comment follows the EOCD
            pos = tail.rfind(_ZIP_EOCD_SIG)
            if pos < 0 or pos + _ZIP_EOCD.size > t:
                return
        (_sig, _disk, _cd_disk, count_disk, count, cd_size, _cd_offset,
         _comment) = _ZIP_EOCD.unpack_from(tail, pos)
        eocd = base + pos
        counts, sizes, records = [], [], [eocd]
        loc = eocd - _ZIP64_LOC.size
        raw = _read_at(fileobj, loc, _ZIP64_LOC.size) if loc >= 0 else b""
        if len(raw) == _ZIP64_LOC.size and raw[:4] == _ZIP64_LOC_SIG:
            _sig, _disk, reloff, _disks = _ZIP64_LOC.unpack(raw)
            # zipfile reads the record at the offset the locator names or,
            # depending on the version, right before the locator: check both
            for rec in {reloff, loc - _ZIP64_EOCD.size}:
                if 0 <= rec <= n - _ZIP64_EOCD.size:
                    data = _read_at(fileobj, rec, _ZIP64_EOCD.size)
                    if len(data) == _ZIP64_EOCD.size and data[:4] == _ZIP64_EOCD_SIG:
                        fields = _ZIP64_EOCD.unpack(data)
                        counts += [fields[6], fields[7]]
                        sizes.append(fields[8])
                        records.append(rec)
        if not sizes:          # no ZIP64 record: the classic fields are the real ones
            counts, sizes = [count_disk, count], [cd_size]
        declared, size = max(counts), max(sizes)
        if declared > max_records:
            raise FeedError("the archive declares %d records, more than the %d budget"
                            % (declared, max_records))
        if size > max_cd_bytes:
            raise FeedError("the archive's central directory declares %d bytes, more than the "
                            "%d MiB budget" % (size, max_cd_bytes >> 20))
        # count the record signatures zipfile will parse, in the `size` bytes
        # before the (ZIP64) end record, a chunk at a time
        start = max(0, min(records) - size)
        fileobj.seek(start)
        left, carry, found = eocd - start, b"", 0
        while left > 0:
            chunk = fileobj.read(min(left, 1 << 20))
            if not chunk:
                break
            left -= len(chunk)
            found += (carry + chunk).count(_ZIP_CD_SIG)
            carry = chunk[-(len(_ZIP_CD_SIG) - 1):]  # a signature split across two chunks
            if found > max_records:
                raise FeedError("the archive's central directory holds more than %d records "
                                "(%d declared)" % (max_records, declared))
    finally:
        fileobj.seek(0)


def read_osv_zip(fileobj, counts=None, max_records=MAX_OSV_RECORDS):
    """Yield (member name, OSV record dict) for every record in an OSV export
    zip. A corrupt archive is a FeedError (a damaged download must not
    become a bundle with advisories missing); an unparseable record is
    skipped and counted. The central directory is checked against the
    record budget before zipfile parses it (osv_zip_preflight)."""
    counts = counts if counts is not None else Counts()
    osv_zip_preflight(fileobj, max_records)
    try:
        zf = zipfile.ZipFile(fileobj)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        raise FeedError("not a readable zip archive (%s)" % exc) from None
    with zf:
        members = [i for i in zf.infolist() if not i.is_dir() and i.filename.endswith(".json")]
        if len(members) > max_records:
            raise FeedError("the archive holds %d records, more than the %d budget"
                            % (len(members), max_records))
        for info in members:
            if info.file_size > MAX_OSV_RECORD_BYTES:
                counts.add("OSV records over %d MiB (skipped)" % (MAX_OSV_RECORD_BYTES >> 20))
                continue
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_OSV_RECORD_BYTES + 1)
            except (zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError,
                    NotImplementedError, ValueError) as exc:
                raise FeedError("damaged archive member %s (%s)" % (info.filename, exc)) from None
            if len(data) > MAX_OSV_RECORD_BYTES:
                counts.add("OSV records over %d MiB (skipped)" % (MAX_OSV_RECORD_BYTES >> 20))
                continue
            try:
                rec = lazaret.json_loads_bounded(data)
            except (ValueError, UnicodeDecodeError):
                counts.add("OSV records that are not valid JSON (skipped)")
                continue
            yield info.filename, rec


# ---------------------------------------------------------------------------
# KEV and EPSS
# ---------------------------------------------------------------------------

def read_kev(data):
    """{CVE: {"dueDate", "ransomware", "dateAdded"}} and the catalog's
    metadata from the KEV JSON feed. FeedError if it isn't the catalog or
    lists no CVEs (an empty catalog would silently clear every KEV entry)."""
    try:
        doc = lazaret.json_loads_bounded(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise FeedError("the KEV catalog is not valid JSON (%s)" % exc) from None
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        raise FeedError("not the KEV catalog (no 'vulnerabilities' list)")
    kev = {}
    for v in vulns:
        if not isinstance(v, dict) or not isinstance(v.get("cveID"), str):
            continue
        cve = v["cveID"].strip().upper()
        if not _CVE_RE.match(cve):
            continue
        due = _date(v.get("dueDate"))
        entry = kev.setdefault(cve, {"dueDate": None, "ransomware": False,
                                     "dateAdded": _date(v.get("dateAdded"))})
        if due and (entry["dueDate"] is None or due < entry["dueDate"]):
            entry["dueDate"] = due
        use = v.get("knownRansomwareCampaignUse")
        if isinstance(use, str) and use.strip().lower() == "known":
            entry["ransomware"] = True
    if not kev:
        raise FeedError("the KEV catalog lists no CVEs")
    meta = {"entries": len(kev)}
    for key in ("catalogVersion", "dateReleased"):
        if isinstance(doc.get(key), str):
            meta[key] = doc[key][:40]
    return kev, meta


def _unit_float(text):
    try:
        x = float(text)
    except (TypeError, ValueError):
        return None
    return x if 0.0 <= x <= 1.0 else None


def bounded_lines(stream, max_bytes, max_line, what):
    """Yield the lines of binary stream `stream` (a decompressing reader)
    as text, without their line ends, charging every byte that comes out of
    it. FeedError past `max_bytes` in all, or `max_line` in one line: a
    TextIOWrapper would buffer a line with no newline whole, however big,
    before csv's field limit ever saw it (a 600 KB gzip can hold one 600 MB
    line). Invalid UTF-8 raises UnicodeDecodeError, as TextIOWrapper did."""
    total, pending = 0, b""
    while True:
        chunk = stream.read(1 << 16)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FeedError("%s decompresses to more than the %d MiB budget"
                            % (what, max_bytes >> 20))
        pending += chunk
        start = 0
        while True:
            end = pending.find(b"\n", start)
            if end < 0:
                break
            if end - start > max_line:
                break
            yield pending[start:end].decode("utf-8")
            start = end + 1
        pending = pending[start:]
        if len(pending) > max_line:
            raise FeedError("%s has a line longer than %d KiB" % (what, max_line >> 10))
    if pending:
        yield pending.decode("utf-8")


def read_epss(fileobj, wanted=None, max_rows=MAX_EPSS_ROWS):
    """{CVE: (epss, percentile)} for the CVEs in `wanted` (every CVE when
    None) and the file's metadata, from the gzipped EPSS scores CSV:
    `#model_version:…,score_date:…`, then `cve,epss,percentile` rows.
    Decompressed bytes and line length are budgeted (bounded_lines)."""
    meta, scores, header, rows = {}, {}, None, 0
    try:
        # closing this leaves `fileobj` open: GzipFile only closes files it opened
        with gzip.GzipFile(fileobj=fileobj, mode="rb") as gz:
            lines = bounded_lines(gz, MAX_EPSS_CSV_BYTES, MAX_EPSS_LINE, "the EPSS file")
            for row in csv.reader(lines):
                if not row:
                    continue
                if row[0].startswith("#"):
                    for part in row:
                        key, sep, val = part.lstrip("#").partition(":")
                        if sep:
                            meta[key.strip()] = val.strip()[:40]
                    continue
                if header is None:
                    header = [c.strip().lower() for c in row]
                    if not {"cve", "epss", "percentile"} <= set(header):
                        raise FeedError("the EPSS file has no cve,epss,percentile header")
                    i_cve, i_epss, i_pct = (header.index(c) for c in ("cve", "epss", "percentile"))
                    continue
                rows += 1
                if rows > max_rows:
                    raise FeedError("the EPSS file has more than %d rows" % max_rows)
                if len(row) != len(header):
                    continue
                cve = row[i_cve].strip().upper()
                if wanted is not None and cve not in wanted:
                    continue
                epss, pct = _unit_float(row[i_epss]), _unit_float(row[i_pct])
                if epss is not None and pct is not None and _CVE_RE.match(cve):
                    scores[cve] = (epss, pct)
    except FeedError:
        raise
    except (OSError, EOFError, zlib.error, UnicodeDecodeError, csv.Error) as exc:
        raise FeedError("the EPSS file is unreadable (%s)" % exc) from None
    if header is None or rows == 0:
        raise FeedError("the EPSS file has no scores")
    out = {"rows": rows}
    if meta.get("model_version"):
        out["modelVersion"] = meta["model_version"]
    if meta.get("score_date"):
        out["scoreDate"] = meta["score_date"]
    return scores, out


# ---------------------------------------------------------------------------
# Merging records into advisories
# ---------------------------------------------------------------------------

def _id_rank(i):
    """Sort key of a vulnerability id: CVEs first (by year and number),
    then GHSA, PYSEC, MAL, GO, RUSTSEC and anything else."""
    m = _CVE_RE.match(i)
    if m:
        return (0, int(m.group(1)), int(m.group(2)), i)
    for n, prefix in enumerate(("GHSA-", "PYSEC-", "MAL-", "GO-", "RUSTSEC-"), 1):
        if i.startswith(prefix):
            return (n, 0, 0, i)
    return (9, 0, 0, i)


def group_records(records):
    """Lists of records that are one vulnerability: connected through their
    ids and aliases (union-find, so the result doesn't depend on order)."""
    parent = {}

    def find(x):
        root = x
        while parent.get(root, root) != root:
            root = parent[root]
        while parent.get(x, x) != root:
            parent[x], x = root, parent[x]
        return root

    for rec in records:
        for alias in rec["aliases"]:
            a, b = find(rec["id"]), find(alias)
            if a != b:
                parent[max(a, b)] = min(a, b)
    groups = {}
    for rec in records:
        groups.setdefault(find(rec["id"]), []).append(rec)
    return list(groups.values())


def _label_of_cvss(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else None


def advisory(members, kev, epss):
    """One bundle advisory from a group of OSV records."""
    members = sorted(members, key=lambda r: _id_rank(r["id"]))
    ids = set()
    for r in members:
        ids.add(r["id"])
        ids.update(r["aliases"])
    primary = min(ids, key=_id_rank)
    cves = sorted((i for i in ids if _CVE_RE.match(i)), key=_id_rank)
    malicious = any(r["malicious"] for r in members)
    cvss = max((r["cvss"] for r in members if r["cvss"] is not None), default=None)
    labels = [r["label"] for r in members if r["label"]]
    if malicious:
        labels.append("critical")
    if cvss is not None and _label_of_cvss(cvss):
        labels.append(_label_of_cvss(cvss))
    refs = ["https://osv.dev/vulnerability/" + members[0]["id"]]
    for r in members:
        for url in r["refs"]:
            if url not in refs:
                refs.append(url)
    packages = {}
    for r in members:
        for eco, name, ranges in r["packages"]:
            entry = packages.setdefault((eco, name_key(name, eco)), [name, []])
            entry[1].extend(ranges)
    kev_hits = [kev[c] for c in cves if c in kev]
    epss_hits = [epss[c] for c in cves if c in epss]
    adv = {"cve": primary}
    aliases = sorted(ids - {primary}, key=_id_rank)[:_MAX_ALIASES]
    if aliases:
        adv["aliases"] = aliases
    title = next((r["title"] for r in members if r["title"]), None)
    if title:
        adv["title"] = title
    if labels:
        adv["severity"] = max(labels, key=_LABEL_RANK.__getitem__)
    if cvss is not None:
        adv["cvss"] = cvss
    cwes = sorted(set().union(*(r["cwes"] for r in members)))[:_MAX_CWES]
    if cwes:
        adv["cwes"] = cwes
    if kev_hits:
        adv["knownExploited"] = True
        if any(k["ransomware"] for k in kev_hits):
            adv["ransomware"] = True
        dues = [k["dueDate"] for k in kev_hits if k["dueDate"]]
        if dues:
            adv["dueDate"] = min(dues)
    if epss_hits:
        adv["epss"], adv["epssPercentile"] = max(epss_hits)
    if malicious:
        adv["malicious"] = True
    published = min((r["published"] for r in members if r["published"]), default=None)
    if published:
        adv["published"] = published
    adv["refs"] = refs[:_MAX_REFS]
    sources = sorted({"osv:" + (r["id"].split("-", 1)[0].lower()) for r in members})
    if kev_hits:
        sources.append("cisa-kev")
    if epss_hits:
        sources.append("epss")
    adv["sources"] = sources
    adv["packages"] = [{"name": name, "ecosystem": eco, "exact": True,
                        "ranges": _dedupe_ranges(ranges)}
                       for (eco, _key), (name, ranges) in sorted(packages.items())]
    return adv


# ---------------------------------------------------------------------------
# Building and writing the bundle
# ---------------------------------------------------------------------------

def _utc_now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(value, now):
    ts = sca.parse_generated_at(value)
    return None if ts is None else (now - ts).days


def _mib(n):
    return "%.1f MiB" % (n / (1 << 20))


def _load_kev(kev_urls, fetch_fn, log):
    failures = []
    for url in kev_urls:
        try:
            buf = io.BytesIO()
            size = fetch_fn(url, buf, MAX_KEV_BYTES)
            kev, meta = read_kev(buf.getvalue())
        except FeedError as exc:
            failures.append(str(exc))
            if url != kev_urls[-1]:
                log("  CISA KEV:  %s — trying the next source" % exc)
            continue
        meta["url"] = url
        log("  CISA KEV:  %s CVEs (catalog %s, %s) from %s"
            % (format(meta["entries"], ","), meta.get("catalogVersion", "?"), _mib(size), url))
        return kev, meta
    raise FeedError("the KEV catalog could not be read: " + "; ".join(failures))


def osv_locations(osv_url):
    """[(location, [OSV ecosystem names it is read for])]: one download per
    distinct location (a template without {ecosystem} is one archive)."""
    out = {}
    for osv_name, _eco in OSV_ECOSYSTEMS:
        out.setdefault(osv_url.replace("{ecosystem}", osv_name), []).append(osv_name)
    return list(out.items())


def build_bundle(osv_url=OSV_URL, kev_urls=KEV_URLS, epss_url=EPSS_URL, *,
                 fetch_fn=None, now=None, log=None):
    """Download and read the feeds; returns (bundle document, Counts of
    skipped input). FeedError if any feed fails its checks."""
    fetch_fn = fetch_fn or fetch
    log = log or (lambda msg: None)
    now = now or _utc_now()
    counts = Counts()
    feeds = {}
    kev_urls = tuple(kev_urls)
    kev, feeds["cisa-kev"] = _load_kev(kev_urls, fetch_fn, log)
    with tempfile.TemporaryFile() as epss_file:
        if epss_url:
            size = fetch_fn(epss_url, epss_file, MAX_EPSS_BYTES)
            log("  EPSS:      %s from %s" % (_mib(size), epss_url))
        records = {}
        newest = None
        exports = []
        for location, names in osv_locations(osv_url):
            with tempfile.TemporaryFile() as zfile:
                size = fetch_fn(location, zfile, MAX_OSV_ZIP_BYTES)
                zfile.seek(0)
                n_read = n_kept = 0
                seen = set()                      # ecosystems this export has advisories for
                for _member, raw in read_osv_zip(zfile, counts):
                    n_read += 1
                    rec = osv_record(raw, counts)
                    if rec is None:
                        continue
                    n_kept += 1
                    seen.update(p[0] for p in rec["packages"])
                    if rec["modified"] and (newest is None or rec["modified"] > newest):
                        newest = rec["modified"]
                    old = records.get(rec["id"])
                    if old is None or (rec["modified"] or "") > (old["modified"] or ""):
                        records[rec["id"]] = rec
            # Each export must hold advisories for what it was read for: an
            # empty or wrong file would otherwise clear every dependency of
            # that ecosystem (a record in the other export naming it is no
            # substitute).
            missing = [eco for osv_name, eco in OSV_ECOSYSTEMS if osv_name in names and eco not in seen]
            if missing:
                raise FeedError("the OSV export %s has no %s advisories — refusing to write a "
                                "bundle that would clear every %s dependency"
                                % (location, " or ".join(missing), " and ".join(missing)))
            exports.append({"url": location, "ecosystems": names, "records": n_read,
                            "keptRecords": n_kept})
            log("  OSV:       %s records (%s kept, %s) from %s"
                % (format(n_read, ","), format(n_kept, ","), _mib(size), location))
        feeds["osv"] = {"exports": exports, "newestModified": newest}
        groups = group_records(list(records.values()))
        cves = set()
        for g in groups:
            for r in g:
                cves.update(i for i in [r["id"]] + r["aliases"] if _CVE_RE.match(i))
        epss = {}
        if epss_url:
            epss_file.seek(0)
            epss, meta = read_epss(epss_file, cves)
            meta["url"] = epss_url
            feeds["epss"] = meta
            log("  EPSS:      scores for %s of %s CVEs (model %s, scored %s)"
                % (format(len(epss), ","), format(len(cves), ","),
                   meta.get("modelVersion", "?"), meta.get("scoreDate", "?")))
    advisories = sorted((advisory(g, kev, epss) for g in groups),
                        key=lambda a: _id_rank(a["cve"]))
    packages = [p for a in advisories for p in a["packages"]]
    doc = {
        "bundleVersion": 1,
        "generator": "lazaret-sca %s" % _lazaret_pkg.__version__,
        "generatedAt": _iso(now),
        "sources": ["osv:" + eco for _osv_name, eco in OSV_ECOSYSTEMS] + ["cisa-kev"] + (["epss"] if epss_url else []),
        # the data's own terms travel with it (a bundle is often shared)
        "attribution": ATTRIBUTION + ([EPSS_ATTRIBUTION] if epss_url else []),
        "feeds": feeds,
        "counts": {
            "advisories": len(advisories),
            "packages": len(packages),
            "withRanges": sum(1 for p in packages if p["ranges"]),
            "knownExploited": sum(1 for a in advisories if a.get("knownExploited")),
            "malicious": sum(1 for a in advisories if a.get("malicious")),
        },
        "advisories": advisories,
    }
    return doc, counts


def stale_feed_warnings(doc, now=None):
    """Feeds whose own dates are older than STALE_FEED_DAYS (a stale local
    mirror would otherwise pass as a fresh bundle)."""
    now = now or _utc_now()
    feeds = doc.get("feeds") or {}
    out = []
    for label, value in (("OSV (newest record)", (feeds.get("osv") or {}).get("newestModified")),
                         ("EPSS (score date)", (feeds.get("epss") or {}).get("scoreDate"))):
        age = _age_days(value, now) if value else None
        if age is not None and age > STALE_FEED_DAYS:
            out.append("%s is %d days old — is this a stale mirror?" % (label, age))
    return out


def dump_bundle(doc, fh):
    """Write the bundle as JSON with one advisory per line (diffable, and
    grep finds a package's advisories)."""
    fh.write("{\n")
    for key, value in doc.items():
        if key != "advisories":
            fh.write("%s: %s,\n" % (json.dumps(key), json.dumps(value)))
    fh.write('"advisories": [\n')
    advisories = doc.get("advisories") or []
    for n, adv in enumerate(advisories):
        fh.write(json.dumps(adv, separators=(",", ":")))
        fh.write(",\n" if n + 1 < len(advisories) else "\n")
    fh.write("]\n}\n")


def _looks_like_bundle(path):
    head = lazaret_report._read_head(path)       # regular files only; never blocks on a FIFO
    return head is not None and ('"bundleVersion"' in head or head.startswith(sca.INDEX_MAGIC.decode("ascii")))


def check_output_path(path, force=False):
    """Refuse a destination the bundle must not replace, before anything is
    downloaded: a device, a symlink (never written through), a directory or
    special file, a missing or unwritable directory, or (without
    --force-overwrite) an existing file that isn't a CVE bundle."""
    if path.startswith("/dev/"):
        raise BundleOutputError("%s is a device file" % path)
    if os.path.lexists(path):
        if os.path.islink(path):
            raise BundleOutputError("%s is a symlink — refusing to write through it" % path)
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            raise BundleOutputError("%s is a directory" % path)
        if not stat.S_ISREG(st.st_mode):
            raise BundleOutputError("%s is not a regular file" % path)
        if not force and not _looks_like_bundle(path):
            raise BundleOutputError("refusing to overwrite %s: it is not a CVE bundle. Move it, "
                                    "pick another path, or pass --force-overwrite" % path)
    reason = lazaret_report.writability_error(path)
    if reason:
        raise BundleOutputError(reason)


BUNDLE_FORMATS = ("json", "index")


def write_bundle(doc, path, force=False, fmt="json", warn=None):
    """Write `doc` to `path` atomically (temporary file, fsync, rename);
    returns the size in bytes. The destination is checked again at write
    time; an existing bundle keeps its permissions. `fmt` is "json" (one
    document) or "index" (sca_index.py: the same bundle as a file a scan reads
    parts of); an indexed bundle is read back whole and checked before it
    replaces anything; `warn(line)` is called for each thing the bundle had
    that the scanner would drop or coerce (an indexed bundle's self-check)."""
    if fmt not in BUNDLE_FORMATS:
        raise ValueError("unknown bundle format %r" % (fmt,))
    check_output_path(path, force)
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    mode = 0o666 & ~lazaret_report._umask()
    try:
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode):
            mode = stat.S_IMODE(st.st_mode) & 0o777
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".cve-bundle-", suffix=".tmp")
    try:
        if fmt == "index":
            from lazaret.scanner import sca_index
            with os.fdopen(fd, "wb") as fh:
                summary = sca_index.dump_index(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
            sca_index.verify_path(tmp)           # what was written reads back as the document
            for msg in summary["warnings"]:
                if warn is not None:
                    warn(msg)
        else:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                dump_bundle(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        size = os.path.getsize(tmp)
        os.replace(tmp, path)
        tmp = None
    except (OSError, ValueError) as exc:
        raise BundleOutputError("cannot write %s: %s" % (path, exc)) from None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return size


# ---------------------------------------------------------------------------
# lazaret-sca --update-bundle
# ---------------------------------------------------------------------------

def run_update(args, out=None, err=None, fetch_fn=None):
    """The --update-bundle step of lazaret-sca; returns an exit code (0,
    EXIT_OUTPUT when the bundle can't be written, EXIT_FEED when a feed
    can't be read)."""
    out = out or sys.stdout
    err = err or sys.stderr
    line = lazaret.sanitize_term_line
    path = args.bundle

    def log(msg):
        if not args.quiet:
            print(line(msg), file=out)

    try:
        check_output_path(path, args.force_overwrite)
    except BundleOutputError as exc:
        print("error: %s" % line(exc), file=err)
        return EXIT_OUTPUT
    log("Lazaret SCA — updating the CVE bundle %s" % os.path.abspath(path))
    try:
        doc, counts = build_bundle(
            osv_url=args.osv_url or OSV_URL,
            kev_urls=(args.kev_url,) if args.kev_url else KEV_URLS,
            epss_url=None if args.no_epss else (args.epss_url or EPSS_URL),
            fetch_fn=fetch_fn, log=log)
    except FeedError as exc:
        print("error: %s" % line(exc), file=err)
        print("  the bundle was not changed", file=err)
        return EXIT_FEED
    for what, n in sorted(counts.notes.items()):
        log("  note: %s: %s" % (what, format(n, ",")))
    for what, n in sorted(counts.items()):
        print("  warning: %s: %s" % (line(what), format(n, ",")), file=err)
    fmt = getattr(args, "bundle_format", None) or "json"
    if fmt == "json":
        check = sca.CveBundle(doc)                   # the scanner must read what we write
        for msg in check.warnings.lines():
            print("  warning: bundle self-check: %s" % line(msg), file=err)
    for msg in stale_feed_warnings(doc):
        print("  warning: %s" % line(msg), file=err)
    try:
        size = write_bundle(doc, path, args.force_overwrite, fmt,
                            warn=lambda msg: print("  warning: bundle self-check: %s" % line(msg), file=err))
    except BundleOutputError as exc:
        print("error: %s" % line(exc), file=err)
        return EXIT_OUTPUT
    c = doc["counts"]
    print(line("  bundle:    %s advisories · %s packages · %s known-exploited · "
               "%s malicious-package reports" % (
                   format(c["advisories"], ","), format(c["packages"], ","),
                   format(c["knownExploited"], ","), format(c["malicious"], ","))), file=out)
    print(line("  wrote %s (%s)" % (os.path.abspath(path), _mib(size))), file=out)
    return 0
