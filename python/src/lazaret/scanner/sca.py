#!/usr/bin/env python3
"""Lazaret SCA — dependency CVE scanner (card "Identify CVE Scanning Features").

Given an installed code base (a project directory), inventory the npm and PyPI
modules that are actually installed/declared there, then match each module@version
against a CVE bundle exported from the Redline vulnerability knowledge base
(`export-bundle.ts` on the Redline side: KEV + NVD + Wordfence + EPSS, with
affected-version ranges) and emit Lazaret-shaped VULN findings.

    lazaret-sca <project-dir> --bundle cve-bundle.json [options]

What "inventory" means (both ecosystems, both direct evidence and declared pins):
  npm   - node_modules/**/package.json (nested node_modules too; the INSTALLED truth)
          package-lock.json / npm-shrinkwrap.json (v1 nested dependencies,
          v2/v3 packages incl. node_modules/a/node_modules/b), yarn.lock (v1
          and berry), pnpm-lock.yaml                   (the LOCKED truth)
          package.json dependencies/devDependencies/optionalDependencies,
          incl. workspaces                             (the DECLARED truth)
  pypi  - <venv>/lib/pythonX.Y/site-packages/<pkg>.dist-info/METADATA
          (the INSTALLED truth — also scanned when site-packages lives under
           the project dir, e.g. .venv, venv, or a passed --site-packages)
          requirements*.txt and requirements/*.txt (following -r/-c),
          pyproject.toml ([project], [dependency-groups], [tool.poetry]),
          poetry.lock, Pipfile.lock, setup.py
  Several versions of one package are all kept (a nested lodash@4.17.11 is
  not hidden by a top-level lodash@4.17.21). A package whose version cannot
  be read (a range or wildcard specifier, a git/url/file dependency) is kept
  with an empty version, so a matching advisory reports SCA-CVE-UNKNOWN.

Matching (the Redline A06 engine, ported and hardened):
  - Version comparison is ecosystem-aware (compare_versions):
      pypi: PEP 440 — epoch, release with zero padding (1.0 == 1.0.0),
            pre-releases a < b < rc, post-releases, dev releases
            (1.0.dev1 < 1.0a1 < 1.0 < 1.0.post1), local versions last
            (1.0 < 1.0+local).
      npm:  semver 2.0 §11 — build metadata ignored, pre-release identifiers
            compared numerically when numeric, numeric < alphanumeric,
            a shorter identifier list sorts first.
      No ecosystem: semver when a version contains '-', else PEP 440.
  - Range membership: inclusive/exclusive bounds, '*' or '' = unbounded.
    For PEP 440, a bound without a local label ignores the candidate's local
    label (pip's specifier rule: 1.2.3+cu118 is inside "<=1.2.3" and
    ">=1.2.3"); pre-releases use plain ordering (2.0rc1 < 2.0, so a fix in
    2.0 leaves 2.0rc1 affected — the safe direction).
  - Verdicts: affected / not-affected / unknown. NO RANGE DATA, a version
    or bound that cannot be compared ('*', '2.*', git refs), or a malformed
    range => UNKNOWN, never a false clear — the same discipline as Redline's
    version-range.ts ("we never wrongly clear a component as patched").
  - Name normalization: lowercase, PEP 503 separator folding ('_', '.', '-'
    runs), '@scope/name' folds to 'scope-name' (never to the bare 'name': an
    @types/lodash is not lodash), 'python-' / 'py-' prefixes and '-python'
    suffixes stripped for pypi.
  - Ecosystem hint from the bundle is advisory only: we match on the normalized
    package NAME, because CPE product names (cryptography, requests, ws,
    lodash) are how NVD records npm/pypi packages. A pypi 'python-foo' alias
    normalizes to the same key as an npm 'foo'.

Severity mapping (VULN, per Lazaret's BLOCKER..INFO):
  KEV known-exploited  -> BLOCKER   (a registered, actively exploited CVE on an
                                     installed version — the exact case the card asks for)
  cvss >= 9.0          -> CRITICAL
  cvss >= 7.0          -> MAJOR
  cvss >= 4.0          -> MINOR
  everything else      -> MINOR (a CVE match is never 'INFO': the operator must see it)

Output: the standard Lazaret result dict (quality gate, conditions, metrics,
counts, issues) written with the same report writers as the lazaret CLI
(JSON with the provenance marker, optional HTML and SARIF), with the same
baseline handling. Issue dicts carry the same keys as lazaret.mk_issue plus
'cve' extras under i['detail'] (cve, package, installed, range, fix hint,
epss, kev).

Exit codes (mirror the lazaret CLI): 0 ok / 1 gate failed (--ci) / 2 usage /
3 report output error / 4 bundle problem (invalid, unreadable, no
advisories) / 5 internal error.

No third-party dependencies — stock python3, same contract as the lazaret CLI.
"""
import argparse
import collections
import datetime as _dt
import importlib
import json
import os
import re
import stat
import sys

# audit H1: lazaret.sanitize_term() is the canonical terminal-control
# neutralizer; sca output interpolates inventory names/versions and CVE-bundle
# fields, so it needs the helper.
from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.scanner import reports as lazaret_report  # noqa: E402

EXIT_BUNDLE = 4
EXIT_INTERNAL = 5
SCA_REPORT_NAME = "lazaret-sca.json"

# ---------------------------------------------------------------------------
# Version engine — PEP 440 and semver 2.0 (ported from Redline's
# version-range.ts and corrected: that port compared everything after the
# numeric head as a string, so 1.0.post1 < 1.0 and beta.10 < beta.9)
# ---------------------------------------------------------------------------

_PEP440_RE = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.X | re.I)
_SEMVER_RE = re.compile(
    r"^\s*[v=]?\s*(?P<nums>[0-9]+(?:\.[0-9]+)*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\s*$")
_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_NEG, _POS = (0,), (2,)
_MAX_VERSION_LEN = 128


def _release(nums):
    rel = tuple(int(x) for x in nums.split("."))
    while len(rel) > 1 and rel[-1] == 0:          # 1.0 == 1.0.0
        rel = rel[:-1]
    return rel


def _pep440_key(v, ignore_local=False):
    """Sort key of a PEP 440 version (None if it is not one)."""
    s = str(v)
    if len(s) > _MAX_VERSION_LEN:
        return None
    m = _PEP440_RE.match(s)
    if m is None:
        return None
    pre = post = dev = None
    if m.group("pre_l"):
        pre = (_PRE_ORDER[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    if m.group("post"):
        post = int(m.group("post_n1") or m.group("post_n2") or 0)
    if m.group("dev_l"):
        dev = int(m.group("dev_n") or 0)
    if pre is None and post is None and dev is not None:
        pre_k = _NEG                                # 1.0.dev1 < 1.0a1
    elif pre is None:
        pre_k = _POS                                # final > pre-releases
    else:
        pre_k = (1, pre)
    post_k = _NEG if post is None else (1, post)
    dev_k = _POS if dev is None else (1, dev)
    local = m.group("local")
    if local is None or ignore_local:
        local_k = _NEG
    else:
        local_k = (1, tuple((1, int(p), "") if p.isdigit() else (0, 0, p.lower())
                            for p in re.split(r"[-_.]", local)))
    return (int(m.group("epoch") or 0), _release(m.group("release")),
            pre_k, post_k, dev_k, local_k)


def _semver_key(v, ignore_local=False):
    """Sort key of a semver version (None if it is not one). Build metadata
    never takes part in precedence (semver §10)."""
    s = str(v)
    if len(s) > _MAX_VERSION_LEN:
        return None
    m = _SEMVER_RE.match(s)
    if m is None:
        return None
    pre = m.group("pre")
    if pre is None:
        pre_k = (1,)                                # release > any pre-release
    else:
        pre_k = (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                          for p in pre.split(".")))
    return (_release(m.group("nums")), pre_k)


def _schemes(ecosystem, *versions):
    if ecosystem == "pypi":
        return (_pep440_key, _semver_key)
    if ecosystem == "npm":
        return (_semver_key, _pep440_key)
    if any("-" in str(v) for v in versions):
        return (_semver_key, _pep440_key)
    return (_pep440_key, _semver_key)


def version_key(version, ecosystem=None):
    """Comparable key of one version, or None when it is not comparable
    ('*', '2.*', 'latest', git refs, …)."""
    if not isinstance(version, (str, int, float)) or isinstance(version, bool):
        return None
    for keyf in _schemes(ecosystem, version):
        k = keyf(version)
        if k is not None:
            return k
    return None


def _cmp_keys(a, b, ecosystem, ignore_local_of_a=False):
    """-1/0/1 comparing versions a and b with the first scheme that parses
    both, or None if none does."""
    for keyf in _schemes(ecosystem, a, b):
        kb = keyf(b)
        if kb is None:
            continue
        ka = keyf(a, ignore_local=ignore_local_of_a)
        if ka is None:
            continue
        return (ka > kb) - (ka < kb)
    return None


# Legacy total order (the old port), only as a last resort so compare_versions
# stays total for callers; range membership never relies on it.
_NUM_HEAD = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def split_ver(v):
    """'1.2.3-beta' -> ([1,2,3], 'beta'); '*' -> ([], '*')."""
    s = str(v or "").strip().lower()
    if s.startswith("v"):
        s = s[1:]
    m = _NUM_HEAD.match(s)
    if not m:
        return [], s
    nums = [int(x) if x.isdigit() else 0 for x in m.group(1).split(".")]
    pre = re.sub(r"^[-._+]+", "", m.group(2)).strip()
    return nums, pre


def _legacy_compare(a, b):
    pa, pb = split_ver(a), split_ver(b)
    n = max(len(pa[0]), len(pb[0]))
    for i in range(n):
        x = pa[0][i] if i < len(pa[0]) else 0
        y = pb[0][i] if i < len(pb[0]) else 0
        if x != y:
            return -1 if x < y else 1
    prea, preb = pa[1], pb[1]
    if not prea and preb:
        return 1
    if prea and not preb:
        return -1
    if prea == preb:
        return 0
    return -1 if prea < preb else 1


def compare_versions(a, b, ecosystem=None):
    """-1/0/1. PEP 440 for pypi, semver 2.0 for npm, and without an ecosystem
    semver when either version contains '-', else PEP 440 (see the module
    docstring). Falls back to the legacy order only when neither scheme
    parses both versions."""
    c = _cmp_keys(a, b, ecosystem)
    return c if c is not None else _legacy_compare(a, b)


def is_comparable_version(version, ecosystem=None):
    """True for a concrete version under PEP 440 or semver — single-segment
    versions ('5') included; wildcards ('*', '2.*'), tags and git refs are
    not comparable."""
    return version_key(version, ecosystem) is not None


def unbounded(b):
    return b is None or b == "" or b == "*"


def _has_local(v):
    return "+" in str(v)


def version_in_range(version, r, ecosystem=None):
    """Is `version` inside affected range `r` (a dict with from/to + inclusivity)?

    True / False, or None when it cannot be decided (a non-comparable
    version or bound, or a malformed range) — callers report None as
    SCA-CVE-UNKNOWN, never as "not affected"."""
    if not isinstance(r, dict) or version_key(version, ecosystem) is None:
        return None
    lo, hi = r.get("fromVersion", "*"), r.get("toVersion", "*")
    lo_inc = r.get("fromInclusive", True) is not False
    hi_inc = r.get("toInclusive", True) is not False
    for bound, is_lo, inc in ((lo, True, lo_inc), (hi, False, hi_inc)):
        if unbounded(bound):
            continue
        if not isinstance(bound, (str, int, float)) or isinstance(bound, bool):
            return None
        bound = str(bound)
        # pip: a bound without a local label ignores the candidate's label
        c = _cmp_keys(version, bound, ecosystem,
                      ignore_local_of_a=not _has_local(bound))
        if c is None:
            return None
        if is_lo and ((c < 0) if inc else (c <= 0)):
            return False
        if not is_lo and ((c > 0) if inc else (c >= 0)):
            return False
    return True


def format_range(r):
    if not isinstance(r, dict):
        return "unparseable range"
    lo = None if unbounded(r.get("fromVersion", "*")) else \
        (">=" if r.get("fromInclusive", True) is not False else ">") + str(r.get("fromVersion"))
    hi = None if unbounded(r.get("toVersion", "*")) else \
        ("<=" if r.get("toInclusive", True) is not False else "<") + str(r.get("toVersion"))
    if not lo and not hi:
        return "all versions"
    return " ".join(x for x in (lo, hi) if x)


# ---------------------------------------------------------------------------
# Name normalization — one namespace across npm and pypi
# ---------------------------------------------------------------------------

def normalize_pkg(name, ecosystem=None):
    """Fold an npm/pypi/CPE product name into one comparison key.

    npm scoped packages fold '@scope/pkg' to 'scope-pkg' (never to the bare
    'pkg'); separators fold PEP 503 style (runs of '-', '_', '.' become one
    '-'); pypi's python- prefix / -python suffix aliases fold together.
    """
    n = str(name or "").strip().lower()
    if n.startswith("@") and "/" in n:
        scope, tail = n[1:].split("/", 1)
        n = scope + "-" + tail.replace("/", "-")     # '@babel/core' -> 'babel-core'
    n = re.sub(r"[-_.\s]+", "-", n)
    if ecosystem == "pypi" or ecosystem is None:
        if n.startswith("python-"):
            n = n[len("python-"):]
        elif n.startswith("py-"):
            n = n[len("py-"):]
        if n.endswith("-python"):
            n = n[: -len("-python")]
    return n


def name_variants(name, ecosystem):
    """All lookup keys an installed/pinned dependency name can be indexed under.

    The bundle's product names come from CPE records ('python-' prefixes
    sometimes present); the inventory's names are what the package manager
    recorded. A pypi name is also looked up under its 'python-'/'py-' alias
    keys, so 'urllib3' finds a CPE 'python-urllib3' entry. A scoped npm name
    is NOT looked up under its unscoped tail: @types/lodash (type
    definitions) must not match lodash CVEs.
    """
    n = str(name or "").strip().lower()
    out = {normalize_pkg(n, ecosystem)}
    if ecosystem == "pypi":
        base = normalize_pkg(n)
        out.add("python-" + base)                      # raw alias key, NOT prefix-stripped
        out.add("py-" + base)
    out.discard("")
    return out


# ---------------------------------------------------------------------------
# Dependency inventory
# ---------------------------------------------------------------------------

class Inventory(list):
    """[(ecosystem, name, version, where)] — every module we can see installed or pinned."""

    def dedup(self):
        """One entry per (ecosystem, name, version) — several versions of a
        package are all kept. An unknown-version entry ('' — a range, a
        wildcard, a git dependency) is dropped when a concrete version of
        the same package is known from elsewhere."""
        known = {(e, normalize_pkg(n, e)) for e, n, v, w in self if v}
        seen, out = set(), Inventory()
        for e, n, v, w in self:
            key = (e, normalize_pkg(n, e), v)
            if key in seen or (not v and (e, key[1]) in known):
                continue
            seen.add(key)
            out.append((e, n, v, w))
        return out


class _Warnings:
    """Counts malformed inventory/bundle entries per kind (printed once)."""

    def __init__(self):
        self.counts = {}

    def __call__(self, kind, n=1):
        self.counts[kind] = self.counts.get(kind, 0) + n

    def lines(self):
        return ["%d %s" % (n, k) for k, n in sorted(self.counts.items())]


def _warn_fn(warn):
    return warn if callable(warn) else (lambda kind, n=1: None)


def _regular_file(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _read_text(path, cap=20 * 1024 * 1024):
    """Text of a regular (non-symlink) file up to cap bytes, else None."""
    if not _regular_file(path):
        return None
    try:
        if os.path.getsize(path) > cap:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(cap + 1)
    except OSError:
        return None


def _read_json(path, cap=20 * 1024 * 1024):
    text = _read_text(path, cap)
    if text is None:
        return None
    try:
        return lazaret.json_loads_bounded(text)
    except (ValueError, MemoryError):   # incl. JsonTooDeep
        return None


def _rel(path, root):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path


# ----- npm -----

_NPM_UNRESOLVABLE_PREFIXES = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:",
                              "gist:", "http:", "https:", "file:", "link:", "workspace:",
                              "portal:", "patch:")


def _npm_exact(spec, full=False):
    """(version, alias_name) for an exact npm version spec, ('', alias_name)
    for anything else (range, tag, wildcard, git/url/file). full=True (a
    package.json dependency spec) requires major.minor.patch: '1' and '1.2'
    are x-ranges there, not versions."""
    if not isinstance(spec, str):
        return "", None
    s = spec.strip()
    alias = None
    if s.startswith("npm:"):                       # "npm:real@1.2.3" alias
        rest = s[4:]
        at = rest.find("@", 1)
        if at < 0:
            return "", rest or None
        alias, s = rest[:at], rest[at + 1:]
    if s.startswith(_NPM_UNRESOLVABLE_PREFIXES) or "/" in s:
        return "", alias
    nums = r"\d+\.\d+\.\d+" if full else r"\d+(?:\.\d+)*"
    m = re.match(r"^[=v]?\s*(" + nums + r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$", s)
    return (m.group(1) if m else ""), alias


def _npm_locked_version(meta_version, resolved=None):
    """Version from a lock entry: '' for git/url/file entries."""
    v, alias = _npm_exact(meta_version) if isinstance(meta_version, str) else ("", None)
    return v, alias


def _npm_name_from_path(key):
    """'node_modules/foo/node_modules/@s/bar' -> '@s/bar'."""
    return key.rsplit("node_modules/", 1)[1].strip("/")


def scan_npm_installed(root, warn=None, max_depth=32, max_packages=100_000):
    """node_modules/**/package.json — the installed truth (incl. @scoped and
    nested node_modules). Symlinks (workspace/pnpm links) are not followed."""
    warn = _warn_fn(warn)
    out = Inventory()
    queue = collections.deque([(os.path.join(root, "node_modules"), 0)])
    count = 0
    while queue:
        nm, depth = queue.popleft()
        if depth > max_depth or not os.path.isdir(nm) or os.path.islink(nm):
            continue
        try:
            entries = sorted(os.listdir(nm))
        except OSError:
            continue
        pkg_dirs = []
        for entry in entries:
            if entry.startswith("."):
                continue
            p = os.path.join(nm, entry)
            if os.path.islink(p) or not os.path.isdir(p):
                continue
            if entry.startswith("@"):               # scope dir: node_modules/@scope/pkg
                try:
                    subs = sorted(os.listdir(p))
                except OSError:
                    continue
                for sub in subs:
                    sp = os.path.join(p, sub)
                    if not sub.startswith(".") and not os.path.islink(sp) and os.path.isdir(sp):
                        pkg_dirs.append((sp, "%s/%s" % (entry, sub)))
            else:
                pkg_dirs.append((p, entry))
        for pkg_dir, dir_name in pkg_dirs:
            count += 1
            if count > max_packages:
                warn("installed npm packages beyond the %d-package limit skipped" % max_packages)
                return out
            _add_npm_pkg(out, pkg_dir, dir_name, root, warn)
            queue.append((os.path.join(pkg_dir, "node_modules"), depth + 1))
    return out


def _add_npm_pkg(out, pkg_dir, dir_name, root, warn=None):
    warn = _warn_fn(warn)
    pj_path = os.path.join(pkg_dir, "package.json")
    if not os.path.lexists(pj_path):
        return
    pj = _read_json(pj_path, cap=2 * 1024 * 1024)
    if not isinstance(pj, dict):
        warn("unreadable node_modules package.json file(s)")
        return
    name = pj.get("name") if isinstance(pj.get("name"), str) and pj.get("name") else dir_name
    version = pj.get("version")
    version = version.strip() if isinstance(version, str) else ""
    # 'where' is the path of this package.json relative to the SCAN ROOT, so
    # findings point at a real file the operator can open.
    out.append(("npm", name, version, _rel(pj_path, root)))


def scan_npm_lock(root, warn=None):
    """package-lock.json / npm-shrinkwrap.json (v1, 2, 3) — the locked truth.
    Nested entries (v2/v3 'node_modules/a/node_modules/b', v1 nested
    'dependencies') are kept with their own versions; workspace links and
    first-party workspace entries are skipped; git/url/file entries get an
    unknown version."""
    warn = _warn_fn(warn)
    out = Inventory()
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lock = _read_json(os.path.join(root, lock_name))
        if lock is None:
            continue
        if not isinstance(lock, dict):
            warn("malformed npm lockfile(s)")
            continue
        packages = lock.get("packages")
        if isinstance(packages, dict):        # lock v2/v3: {"node_modules/x": {...}}
            for k, meta in packages.items():
                if not isinstance(k, str) or "node_modules/" not in k:
                    continue                  # "" is the root; "packages/a" a workspace
                if not isinstance(meta, dict):
                    warn("malformed npm lockfile entries")
                    continue
                if meta.get("link"):
                    continue                  # workspace link (first-party)
                tail = _npm_name_from_path(k)
                name = meta.get("name") if isinstance(meta.get("name"), str) and meta.get("name") else tail
                v, alias = _npm_locked_version(meta.get("version"))
                name = alias or name
                where = lock_name if k == "node_modules/" + tail else "%s (%s)" % (lock_name, k)
                if name:
                    out.append(("npm", name, v, where))
        deps = lock.get("dependencies")        # lock v1: {"name": {version, dependencies}}
        if isinstance(deps, dict):
            stack = [(deps, "", 0)]
            seen = 0
            while stack:
                cur, parent, depth = stack.pop()
                if depth > 64:
                    warn("npm lockfile nesting beyond 64 levels skipped")
                    continue
                for name, meta in cur.items():
                    seen += 1
                    if seen > 500_000:
                        break
                    if not isinstance(name, str) or not name:
                        continue
                    where = lock_name if not parent else "%s (%s)" % (lock_name, parent)
                    if not isinstance(meta, dict):
                        # e.g. "weird": "1.0.0" — malformed; keep the name so a
                        # matching advisory reports version-unknown
                        warn("malformed npm lockfile entries")
                        out.append(("npm", name, "", where))
                        continue
                    v, alias = _npm_locked_version(meta.get("version"))
                    out.append(("npm", alias or name, v, where))
                    sub = meta.get("dependencies")
                    if isinstance(sub, dict):
                        stack.append((sub, (parent + "/" if parent else "") + name, depth + 1))
    return out


def _yarn_spec_name(spec):
    """Package name of a yarn.lock key entry ('lodash@^4', '@b/c@npm:^7',
    'alias@npm:real@^1' -> 'real')."""
    at = spec.find("@", 1)
    if at <= 0:
        return spec, ""
    name, rest = spec[:at], spec[at + 1:]
    if rest.startswith("npm:"):
        r = rest[4:]
        j = r.find("@", 1)
        if j > 0:
            return r[:j], r[j + 1:]
    return name, rest


def parse_yarn_lock(text):
    """[(name, version)] from a yarn.lock (v1 and berry). Workspace, link,
    portal and file entries (first-party) are skipped."""
    out = []
    cur = None

    def flush():
        if cur and cur["names"] and not cur["local"]:
            names = cur["names"]
            if cur["resolution"]:
                rname, rver = _yarn_spec_name(cur["resolution"])
                if rname:
                    names = {rname}
                if rver.startswith(("workspace:", "link:", "portal:", "file:")):
                    return
            ver = cur["version"] or ""
            v, _ = _npm_exact(ver)
            for n in sorted(names):
                out.append((n, v))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            flush()
            key = raw.rstrip()
            key = key[:-1] if key.endswith(":") else key
            specs = [s.strip().strip('"').strip("'") for s in key.split(",")]
            specs = [s for s in specs if s and s != "__metadata"]
            names = set()
            local = False
            for s in specs:
                n, rest = _yarn_spec_name(s)
                if rest.startswith(("workspace:", "link:", "portal:", "file:")):
                    local = True
                if n:
                    names.add(n)
            cur = {"names": names, "version": None, "resolution": None, "local": local}
            continue
        if cur is None or not raw.startswith("  ") or raw.startswith("   "):
            continue
        line = raw.strip()
        m = re.match(r'^version:?\s+"?([^"\s]+)"?\s*$', line)
        if m:
            cur["version"] = m.group(1)
            continue
        m = re.match(r'^resolution:\s+"?([^"]+?)"?\s*$', line)
        if m:
            cur["resolution"] = m.group(1)
    flush()
    return out


_PNPM_V5_RE = re.compile(r"^(@[^@/]+/[^@/]+|[^@/]+)/(\d[^/_]*)(?:_.*)?$")
_PNPM_V6_RE = re.compile(r"^(@?[^@]+)@([^@]+)$")


def _pnpm_key(key):
    k = key.strip().strip("'\"")
    if k.startswith("/"):
        k = k[1:]
    m = _PNPM_V5_RE.match(k)
    if m:
        return m.group(1), m.group(2)
    k = k.split("(", 1)[0]                         # v6/v9 peer suffix
    m = _PNPM_V6_RE.match(k)
    if m and m.group(2)[:1].isdigit():
        return m.group(1), m.group(2)
    return None


def parse_pnpm_lock(text):
    """[(name, version)] from pnpm-lock.yaml (lockfile v5, v6 and v9): the
    package keys of the 'packages:' and 'snapshots:' sections
    ('/name/1.0.0', '/name@1.0.0(peer@2)', 'name@1.0.0'). Line-based, no
    YAML dependency; link:/file:/git keys are skipped."""
    out = []
    section = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            section = raw.strip().rstrip(":").strip()
            continue
        if section not in ("packages", "snapshots") or indent != 2:
            continue
        key = raw.strip()
        if not key.endswith(":"):
            continue
        nv = _pnpm_key(key[:-1])
        if nv is not None:
            v, _ = _npm_exact(nv[1])
            out.append((nv[0], v))
    return out


def scan_npm_other_locks(root, warn=None):
    """yarn.lock (v1/berry) and pnpm-lock.yaml."""
    out = Inventory()
    for fname, parser in (("yarn.lock", parse_yarn_lock), ("pnpm-lock.yaml", parse_pnpm_lock)):
        text = _read_text(os.path.join(root, fname))
        if text is None:
            continue
        for name, v in parser(text):
            out.append(("npm", name, v, fname))
    return out


def _declared_npm(pj, where_prefix, out):
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = pj.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str) or not name:
                continue
            v, alias = _npm_exact(spec, full=True)
            name = alias or name
            if v:
                out.append(("npm", name, v, "%s(%s)" % (where_prefix, section)))
            else:
                # a ^/~/>= range, a tag, '*', or a git/url/file dependency:
                # NOT a version — record it unresolvable so a matching
                # advisory yields version-unknown, never a silent clear
                out.append(("npm", name, "", "%s(%s) unresolvable:%s" % (
                    where_prefix, section, str(spec)[:40])))


def scan_npm_declared(root, warn=None):
    """package.json dependencies/devDependencies (+ workspaces) — the declared truth."""
    out = Inventory()
    pj = _read_json(os.path.join(root, "package.json"))
    if not isinstance(pj, dict):
        return out
    _declared_npm(pj, "package.json", out)
    ws = pj.get("workspaces")
    if isinstance(ws, dict):
        ws = ws.get("packages")
    if isinstance(ws, list):
        for pat in ws[:200]:
            for d in _workspace_dirs(root, pat):
                wpj = _read_json(os.path.join(d, "package.json"))
                if isinstance(wpj, dict):
                    _declared_npm(wpj, _rel(os.path.join(d, "package.json"), root), out)
    return out


def _workspace_dirs(root, pat):
    """Directories a workspace pattern ('packages/*', 'apps/web') names,
    confined to the project root."""
    if not isinstance(pat, str) or not pat or os.path.isabs(pat) or ".." in pat.split("/"):
        return []
    pat = pat.rstrip("/")
    if pat.endswith("/**") or pat.endswith("/*"):
        base = os.path.join(root, pat.rsplit("/", 1)[0])
        try:
            return [os.path.join(base, d) for d in sorted(os.listdir(base))
                    if os.path.isdir(os.path.join(base, d))
                    and not os.path.islink(os.path.join(base, d))]
        except OSError:
            return []
    d = os.path.join(root, pat)
    return [d] if os.path.isdir(d) and not os.path.islink(d) else []


# ----- pypi -----

def scan_pypi_installed(root, extra_site_packages=None, warn=None):
    """*.dist-info/METADATA (and egg-info/PKG-INFO) under any site-packages we can find.

    Sources: a venv-style lib dir inside the project (.venv/venv/env →
    lib/pythonX.Y/site-packages — covers Linux/macOS layouts; a Windows-style
    Lib\\site-packages is picked up too), plus any --site-packages the operator
    passes (the actual interpreter environment when the project has no venv of
    its own). Finally the project dir itself may BE a site-packages target
    (pip install --target / vendored wheels).
    """
    out = Inventory()
    roots = []
    if os.path.isdir(root):
        for sub in (".venv", "venv", "env"):
            for libname in ("lib", "Lib"):
                cand = os.path.join(root, sub, libname)
                if os.path.isdir(cand):
                    roots.append(cand)
                    break
    for sp in (extra_site_packages or []):
        if sp and os.path.isdir(sp):
            roots.append(sp)
    for libdir in roots:
        try:
            entries = os.listdir(libdir)
        except OSError:
            continue
        for entry in entries:
            if not entry.startswith("python"):
                continue
            site = os.path.join(libdir, entry, "site-packages")
            if os.path.isdir(site):
                out.extend(_scan_site_packages(site, site))
    # Windows venv layout: <root>/<venv>/Lib/site-packages has no pythonX.Y level
    if os.path.isdir(root):
        for sub in (".venv", "venv", "env"):
            site_win = os.path.join(root, sub, "Lib", "site-packages")
            if os.path.isdir(site_win):
                out.extend(_scan_site_packages(site_win, site_win))
    # a site-packages dir passed directly via --site-packages
    for sp in (extra_site_packages or []):
        if sp and os.path.isdir(sp) and os.path.basename(os.path.normpath(sp)) == "site-packages":
            out.extend(_scan_site_packages(sp, sp))
    # project dir itself may contain vendored dist-infos (pip install --target style)
    out.extend(_scan_site_packages(root, root, shallow=True))
    return out


def _scan_site_packages(site, display_root, shallow=False):
    out = Inventory()
    try:
        entries = os.listdir(site)
    except OSError:
        return out
    for entry in entries:
        if not entry.endswith((".dist-info", ".egg-info")):
            continue
        d = os.path.join(site, entry)
        meta_file = os.path.join(d, "METADATA") if entry.endswith(".dist-info") else os.path.join(d, "PKG-INFO")
        name = version = None
        try:
            with open(meta_file, "r", encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f):
                    if n > 200 or not line.strip():
                        break                          # headers end at the first blank line
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                    if name and version:
                        break
        except OSError:
            continue
        if name and version:
            where = os.path.relpath(d, display_root) if display_root != d else entry
            out.append(("pypi", name, version, where))
    return out


# ---- PEP 508 requirement strings ----
_PEP508_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*(?P<rest>.*)$", re.S)
_SPEC_RE = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*(\S+)$")


def parse_pep508(req):
    """(name, pinned_version or '', spec text) for a PEP 508 requirement
    ('requests[security]==2.19.0; python_version>"3"', 'Django',
    'flask[async] >= 1.0', 'pkg @ https://…'), or None if it is not one.
    A version counts as pinned only for a single exact '==' / '===' without
    a wildcard; anything else is unknown (''), never a guessed version."""
    if not isinstance(req, str):
        return None
    m = _PEP508_RE.match(req.split(";", 1)[0])
    if m is None:
        return None
    name, rest = m.group("name"), m.group("rest").strip()
    if rest.startswith("@"):
        return name, "", rest[:60]                 # direct URL reference
    rest = rest.strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1]
    pins = set()
    for part in (p.strip() for p in rest.split(",")):
        if not part:
            continue
        sm = _SPEC_RE.match(part)
        if sm is None:
            return name, "", rest[:60]
        op, ver = sm.groups()
        if op in ("==", "===") and "*" not in ver:
            pins.add(ver)
    return name, (pins.pop() if len(pins) == 1 else ""), rest[:60]


def _add_req(out, req, where):
    parsed = parse_pep508(req)
    if parsed is None:
        return
    name, ver, spec = parsed
    if ver:
        out.append(("pypi", name, ver, where))
    else:
        out.append(("pypi", name, "", "%s (range: %s)" % (where, spec) if spec else where))


_REQ_INCLUDE_RE = re.compile(r"^(-r|--requirement|-c|--constraint)(?:\s*=\s*|\s+)(\S+)")


def _req_lines(text):
    """Logical lines of a requirements file: continuations joined, comments
    stripped."""
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line = buf + line
        buf = ""
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if line:
            yield line
    if buf.strip():
        yield buf.strip()


def _scan_requirements(path, root, out, warn, seen, depth=0):
    real = os.path.realpath(path)
    if real in seen:
        return
    seen.add(real)
    if depth > 5:
        warn("requirements includes nested deeper than 5 levels skipped")
        return
    if not lazaret_report.path_is_inside(path, root):
        warn("requirements includes outside the project skipped")
        return
    text = _read_text(path, cap=5 * 1024 * 1024)
    if text is None:
        return
    rel = _rel(path, root)
    for line in _req_lines(text):
        inc = _REQ_INCLUDE_RE.match(line)
        if inc:
            target = os.path.join(os.path.dirname(path), inc.group(2))
            _scan_requirements(target, root, out, warn, seen, depth + 1)
            continue
        if line.startswith(("-e", "--editable")):
            egg = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            if egg:
                out.append(("pypi", egg.group(1), "", "%s (editable)" % rel))
            continue
        if line.startswith("-"):
            continue                                # -i/--index-url/--hash/…
        if "://" in line.split("@", 1)[0] or line.startswith(("git+", "hg+", "svn+", "bzr+")):
            egg = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            if egg:
                out.append(("pypi", egg.group(1), "", "%s (url)" % rel))
            continue
        # a requirement may carry trailing options (--hash=…)
        req = re.split(r"\s--?[A-Za-z]", line, 1)[0].strip()
        _add_req(out, req, rel)


# ---- TOML ----
def _tomllib():
    try:
        return importlib.import_module("tomllib")      # Python 3.11+
    except ImportError:
        return None


def load_toml(text):
    """Parse TOML: tomllib on 3.11+, else the conservative subset parser
    below (Python 3.10). Raises ValueError on invalid input."""
    lib = _tomllib()
    if lib is not None:
        try:
            return lib.loads(text)
        except lib.TOMLDecodeError as exc:
            raise ValueError(str(exc)) from None
    return toml_subset_loads(text)


class _TomlSubset:
    """A small TOML reader for Python 3.10 (no tomllib): tables, arrays of
    tables, dotted/quoted keys, basic/literal/multi-line strings, integers,
    floats, booleans, dates (kept as text), arrays and inline tables — enough
    for poetry.lock and pyproject.toml. Anything else raises ValueError."""

    _BARE = re.compile(r"[A-Za-z0-9_-]+")
    _NUM = re.compile(r"[+-]?(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|inf|nan|"
                      r"[0-9_]+(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)")
    _DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
                       r"(?:Z|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}:\d{2}(?:\.\d+)?")

    def __init__(self, text):
        self.s = text.replace("\r\n", "\n")
        self.i = 0
        self.n = len(self.s)

    def err(self, what):
        line = self.s.count("\n", 0, self.i) + 1
        raise ValueError(f"TOML: {what} at line {line}")

    def ws(self, newlines=False):
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#":
                j = self.s.find("\n", self.i)
                self.i = self.n if j < 0 else j
            else:
                break

    def key(self):
        parts = []
        while True:
            self.ws()
            c = self.s[self.i:self.i + 1]
            if c in ('"', "'"):
                parts.append(self.string())
            else:
                m = self._BARE.match(self.s, self.i)
                if not m:
                    self.err("expected a key")
                parts.append(m.group())
                self.i = m.end()
            self.ws()
            if self.s[self.i:self.i + 1] == ".":
                self.i += 1
                continue
            return parts

    def string(self):
        s, i = self.s, self.i
        if s.startswith('"""', i) or s.startswith("'''", i):
            q = s[i:i + 3]
            j = s.find(q, i + 3)
            if j < 0:
                self.err("unterminated multi-line string")
            while s.startswith(q[0], j + 3):       # up to two extra quotes
                j += 1
            body = s[i + 3:j]
            self.i = j + 3
            if body.startswith("\n"):
                body = body[1:]
            if q == '"""':
                body = re.sub(r"\\\s*\n\s*", "", body)
                return self._unescape(body)
            return body
        q = s[i]
        j = i + 1
        buf = []
        while j < self.n:
            c = s[j]
            if c == "\n":
                break
            if q == '"' and c == "\\":
                buf.append(s[j:j + 2])
                if s[j + 1:j + 2] in ("u", "U"):
                    width = 4 if s[j + 1] == "u" else 8
                    buf.append(s[j + 2:j + 2 + width])
                    j += 2 + width
                else:
                    j += 2
                continue
            if c == q:
                self.i = j + 1
                raw = "".join(buf)
                return self._unescape(raw) if q == '"' else raw
            buf.append(c)
            j += 1
        self.err("unterminated string")

    def _unescape(self, raw):
        def rep(m):
            e = m.group(1)
            simple = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r",
                      '"': '"', "\\": "\\", "e": "\x1b"}
            if e in simple:
                return simple[e]
            try:
                return chr(int(e[1:], 16))
            except ValueError:
                self.err("bad unicode escape")
        return re.sub(r"\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", rep, raw)

    def value(self, depth=0):
        if depth > 64:
            self.err("nesting too deep")
        self.ws()
        s, i = self.s, self.i
        c = s[i:i + 1]
        if c in ('"', "'"):
            return self.string()
        if c == "[":
            self.i += 1
            out = []
            while True:
                self.ws(newlines=True)
                if self.s[self.i:self.i + 1] == "]":
                    self.i += 1
                    return out
                out.append(self.value(depth + 1))
                self.ws(newlines=True)
                c = self.s[self.i:self.i + 1]
                if c == ",":
                    self.i += 1
                elif c == "]":
                    self.i += 1
                    return out
                else:
                    self.err("expected ',' or ']'")
        if c == "{":
            self.i += 1
            tbl = {}
            self.ws()
            if self.s[self.i:self.i + 1] == "}":
                self.i += 1
                return tbl
            while True:
                k = self.key()
                if self.s[self.i:self.i + 1] != "=":
                    self.err("expected '='")
                self.i += 1
                self._set(tbl, k, self.value(depth + 1))
                self.ws()
                c = self.s[self.i:self.i + 1]
                if c == ",":
                    self.i += 1
                elif c == "}":
                    self.i += 1
                    return tbl
                else:
                    self.err("expected ',' or '}'")
        if s.startswith("true", i):
            self.i += 4
            return True
        if s.startswith("false", i):
            self.i += 5
            return False
        m = self._DATE.match(s, i)
        if m:
            self.i = m.end()
            return m.group()
        m = self._NUM.match(s, i)
        if m and m.end() > i:
            self.i = m.end()
            t = m.group().replace("_", "").lower()
            body = t.lstrip("+-")
            try:
                if body[:2] in ("0x", "0o", "0b"):
                    return int(t, 0)
                if body in ("inf", "nan") or "." in body or "e" in body:
                    return float(t)
                return int(t)
            except ValueError:
                self.err("bad number")
        self.err("unsupported value")

    @staticmethod
    def _set(tbl, keys, val):
        for k in keys[:-1]:
            nxt = tbl.setdefault(k, {})
            if not isinstance(nxt, dict):
                raise ValueError(f"TOML: key {k!r} is not a table")
            tbl = nxt
        if keys[-1] in tbl:
            raise ValueError(f"TOML: duplicate key {keys[-1]!r}")
        tbl[keys[-1]] = val

    def parse(self):
        root = {}
        cur = root
        while True:
            self.ws(newlines=True)
            if self.i >= self.n:
                return root
            if self.s.startswith("[[", self.i):
                self.i += 2
                keys = self.key()
                if not self.s.startswith("]]", self.i):
                    self.err("expected ']]'")
                self.i += 2
                tbl = root
                for k in keys[:-1]:
                    tbl = tbl.setdefault(k, {})
                    if isinstance(tbl, list):
                        tbl = tbl[-1]
                arr = tbl.setdefault(keys[-1], [])
                if not isinstance(arr, list):
                    self.err("array of tables redefines a key")
                cur = {}
                arr.append(cur)
            elif self.s[self.i] == "[":
                self.i += 1
                keys = self.key()
                if self.s[self.i:self.i + 1] != "]":
                    self.err("expected ']'")
                self.i += 1
                cur = root
                for k in keys:
                    cur = cur.setdefault(k, {})
                    if isinstance(cur, list):
                        cur = cur[-1]
                    if not isinstance(cur, dict):
                        self.err("table redefines a value")
            else:
                keys = self.key()
                if self.s[self.i:self.i + 1] != "=":
                    self.err("expected '='")
                self.i += 1
                self._set(cur, keys, self.value())
            self.ws()
            if self.i < self.n and self.s[self.i] != "\n":
                self.err("expected end of line")


def toml_subset_loads(text):
    try:
        return _TomlSubset(text).parse()
    except (IndexError, RecursionError) as exc:
        raise ValueError(f"TOML: {type(exc).__name__}") from None


def _poetry_spec(spec):
    """Exact version of a Poetry constraint ('1.2.3', '==1.2.3'), else ''."""
    if isinstance(spec, dict):
        spec = spec.get("version")
    if not isinstance(spec, str):
        return ""
    s = spec.strip()
    if s.startswith("=="):
        s = s[2:].strip()
    elif s.startswith("="):
        s = s[1:].strip()
    if re.match(r"^\d+(?:\.\d+)*(?:[-._+a-zA-Z0-9]*)$", s) and "*" not in s:
        return s
    return ""


def _scan_pyproject(root, out, warn):
    path = os.path.join(root, "pyproject.toml")
    text = _read_text(path, cap=5 * 1024 * 1024)
    if text is None:
        return
    try:
        doc = load_toml(text)
    except ValueError:
        warn("unparseable pyproject.toml file(s)")
        return
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    lists = [project.get("dependencies")]
    opt = project.get("optional-dependencies")
    if isinstance(opt, dict):
        lists.extend(opt.values())
    groups = doc.get("dependency-groups")
    if isinstance(groups, dict):
        lists.extend(groups.values())
    for lst in lists:
        if isinstance(lst, list):
            for req in lst:
                if isinstance(req, str):
                    _add_req(out, req, "pyproject.toml")
    tool = doc.get("tool") if isinstance(doc.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    pgroups = poetry.get("group")
    if isinstance(pgroups, dict):
        tables.extend(g.get("dependencies") for g in pgroups.values() if isinstance(g, dict))
    for tbl in tables:
        if not isinstance(tbl, dict):
            continue
        for name, spec in tbl.items():
            if not isinstance(name, str) or name.lower() == "python":
                continue
            v = _poetry_spec(spec)
            if v:
                out.append(("pypi", name, v, "pyproject.toml"))
            else:
                out.append(("pypi", name, "", "pyproject.toml (range: %s)" % str(
                    spec if not isinstance(spec, dict) else spec.get("version", "…"))[:40]))


def _scan_poetry_lock(root, out, warn):
    text = _read_text(os.path.join(root, "poetry.lock"))
    if text is None:
        return
    try:
        doc = load_toml(text)
    except ValueError:
        warn("unparseable poetry.lock file(s)")
        return
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        return
    for pkg in pkgs:
        if not isinstance(pkg, dict):
            continue
        name, v = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and name:
            out.append(("pypi", name, v if isinstance(v, str) else "", "poetry.lock"))


def _scan_pipfile_lock(root, out, warn):
    pl = _read_json(os.path.join(root, "Pipfile.lock"))
    if not isinstance(pl, dict):
        return
    for section in ("default", "develop"):
        entries = pl.get(section)
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            if not isinstance(name, str) or not name:
                continue
            where = "Pipfile.lock(%s)" % section
            if not isinstance(meta, dict):
                # "django": "==2.2" — malformed; keep the name, unknown version
                warn("malformed Pipfile.lock entries")
                out.append(("pypi", name, "", where))
                continue
            v = meta.get("version")
            v = v.strip() if isinstance(v, str) else ""
            if v.startswith("==="):
                v = v[3:]
            elif v.startswith("=="):
                v = v[2:]
            else:
                v = ""                                # git/path/editable entries
            out.append(("pypi", name, v.strip(), where))


def _scan_setup_py(root, out, warn):
    text = _read_text(os.path.join(root, "setup.py"), cap=5 * 1024 * 1024)
    if text is None:
        return
    m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        for entry in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            _add_req(out, entry.strip(), "setup.py")


def scan_pypi_declared(root, warn=None):
    """requirements*.txt and requirements/*.txt (following -r/-c),
    pyproject.toml ([project], [dependency-groups], [tool.poetry]),
    poetry.lock, Pipfile.lock, setup.py. Unpinned names are recorded with
    version '' (reported as unknown, never cleared)."""
    warn = _warn_fn(warn)
    out = Inventory()
    if not os.path.isdir(root):
        return out
    req_files = []
    try:
        for fn in sorted(os.listdir(root)):
            if re.match(r"^requirements.*\.txt$", fn):
                req_files.append(os.path.join(root, fn))
    except OSError:
        pass
    req_dir = os.path.join(root, "requirements")
    if os.path.isdir(req_dir) and not os.path.islink(req_dir):
        try:
            req_files.extend(os.path.join(req_dir, fn) for fn in sorted(os.listdir(req_dir))
                             if fn.endswith(".txt"))
        except OSError:
            pass
    seen = set()
    for path in req_files:
        _scan_requirements(path, root, out, warn, seen)
    _scan_pyproject(root, out, warn)
    _scan_pipfile_lock(root, out, warn)
    _scan_poetry_lock(root, out, warn)
    _scan_setup_py(root, out, warn)
    return out


# ---------------------------------------------------------------------------
# CVE bundle (the Redline export) — loading, validation + index
# ---------------------------------------------------------------------------

def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _strs(v):
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


class CveBundle:
    """Advisories indexed by normalized package name for O(inventory) matching.

    Every level of the bundle is type-checked: a malformed advisory or
    package entry is skipped and counted (self.warnings), a malformed range
    list makes that package's verdicts UNKNOWN (never a silent clear), and
    field types are normalized (cvss/epss numbers, lists of strings) so
    nothing downstream can crash on a hostile bundle. Structural problems
    (not an object, wrong bundleVersion, 'advisories' not a list) raise
    ValueError — the CLI exits 4.
    """

    def __init__(self, doc):
        if not isinstance(doc, dict) or doc.get("bundleVersion") != 1:
            raise ValueError("not a Lazaret CVE bundle (bundleVersion != 1)")
        advisories = doc.get("advisories")
        if advisories is None:
            advisories = []
        if not isinstance(advisories, list):
            raise ValueError("CVE bundle 'advisories' is %s, not a list"
                             % type(advisories).__name__)
        self.warnings = _Warnings()
        gen = doc.get("generatedAt")
        self.generated_at = gen if isinstance(gen, str) else None
        if gen is not None and not isinstance(gen, str):
            self.warnings("non-text generatedAt values")
        sources = doc.get("sources")
        self.sources = _strs(sources)
        if sources is not None and (not isinstance(sources, list) or len(self.sources) != len(sources)):
            self.warnings("non-text bundle source entries")
        counts = doc.get("counts")
        self.counts = counts if isinstance(counts, dict) else {}
        self.advisories = []
        self._index = {}
        for raw in advisories:
            adv = self._advisory(raw)
            if adv is None:
                continue
            self.advisories.append(adv)
            for pkg in adv["packages"]:
                for key in name_variants(pkg["name"], pkg["ecosystem"]):
                    self._index.setdefault(key, []).append((adv, pkg))

    def _advisory(self, raw):
        w = self.warnings
        if not isinstance(raw, dict):
            w("malformed advisory entries skipped")
            return None
        cve = raw.get("cve") or raw.get("id")
        if not isinstance(cve, str) or not cve:
            w("advisory entries without a 'cve' id (kept as 'advisory#N')")
            cve = "advisory#%d" % (len(self.advisories) + 1)
        adv = {
            "cve": cve,
            "title": raw.get("title") if isinstance(raw.get("title"), str) else None,
            "severity": raw.get("severity") if isinstance(raw.get("severity"), str) else None,
            "cvss": _num(raw.get("cvss")),
            "epss": _num(raw.get("epss")),
            "epssPercentile": _num(raw.get("epssPercentile")),
            "knownExploited": raw.get("knownExploited") is True,
            "ransomware": raw.get("ransomware") is True,
            "dueDate": raw.get("dueDate") if isinstance(raw.get("dueDate"), str) else None,
            "published": raw.get("published") if isinstance(raw.get("published"), str) else None,
            "cwes": _strs(raw.get("cwes")),
            "refs": _strs(raw.get("refs")),
            "sources": _strs(raw.get("sources")),
            "packages": [],
        }
        for f in ("cvss", "epss", "epssPercentile"):
            if raw.get(f) is not None and adv[f] is None:
                w("non-numeric %s values ignored" % f)
        pkgs = raw.get("packages")
        if not isinstance(pkgs, list):
            if pkgs is not None:
                w("advisories with a malformed 'packages' list skipped")
            return adv
        for p in pkgs:
            if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"].strip():
                w("malformed advisory package entries skipped")
                continue
            eco = p.get("ecosystem") if p.get("ecosystem") in ("npm", "pypi") else None
            ranges = p.get("ranges")
            if ranges is None:
                ranges = []
            if not isinstance(ranges, list) or not all(isinstance(r, dict) for r in ranges):
                w("malformed affected-version ranges (verdict: unknown)")
                ranges = None                      # -> SCA-CVE-UNKNOWN on a name match
            adv["packages"].append({"name": p["name"], "ecosystem": eco, "ranges": ranges,
                                    "vendor": p.get("vendor") if isinstance(p.get("vendor"), str) else None})
        return adv

    def advisories_for(self, name, ecosystem=None):
        out = []
        seen = set()
        for key in name_variants(name, ecosystem):
            for pair in self._index.get(key, []):
                k = (id(pair[0]), id(pair[1]))
                if k not in seen:
                    seen.add(k)
                    out.append(pair)
        return out

    @classmethod
    def load(cls, path):
        try:
            with open(path, "rb") as f:
                doc = lazaret.json_loads_bounded(f.read().decode("utf-8"))
        except (OSError, ValueError, MemoryError) as e:
            # ValueError covers a deeply nested bundle (JsonTooDeep), bad
            # UTF-8 and the int-digit limit.
            raise ValueError("cannot read CVE bundle %s: %s" % (path, e)) from None
        return cls(doc)


_ISO_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?\s*$", re.I)


def parse_generated_at(generated_at):
    """Aware datetime for an ISO-8601 timestamp (a naive one is taken as
    UTC), or None when missing/unparseable."""
    if not isinstance(generated_at, str):
        return None
    m = _ISO_RE.match(generated_at)
    if m is None:
        return None
    y, mo, d, hh, mm, ss, tz = m.groups()
    try:
        tzinfo = _dt.timezone.utc
        if tz and tz.upper() != "Z":
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            tzinfo = _dt.timezone(sign * _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
        return _dt.datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0),
                            int(ss or 0), tzinfo=tzinfo)
    except ValueError:
        return None


def bundle_age_days(generated_at):
    """Age of the bundle in days (None when unknown/unparseable)."""
    gen = parse_generated_at(generated_at)
    if gen is None:
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - gen).days


def bundle_is_fresh(generated_at, max_age):
    """Freshness gate: FAILS for a missing, unparseable or future (> 1 day)
    timestamp — an unknown age must not pass as fresh. max_age <= 0 disables
    the gate."""
    if max_age <= 0:
        return True
    age = bundle_age_days(generated_at)
    return age is not None and -1 <= age <= max_age


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def severity_of(adv):
    """KEV first, then CVSS, then the KB severity label. Never INFO — see module docstring."""
    if adv.get("knownExploited") is True:
        return "BLOCKER"
    cvss = _num(adv.get("cvss"))
    if cvss is not None:
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "MAJOR"
    sev = str(adv.get("severity") or "").lower()
    return {"critical": "CRITICAL", "high": "MAJOR"}.get(sev, "MINOR")


def fix_hint(adv, pkg, ecosystem=None):
    """Best-effort patched-version hint: the upper bound of any exclusive range."""
    best = None
    for r in pkg.get("ranges") or []:
        if not isinstance(r, dict):
            continue
        hi = r.get("toVersion")
        if not isinstance(hi, str) or unbounded(hi) or r.get("toInclusive") is not False:
            continue
        if not is_comparable_version(hi, ecosystem):
            continue
        if best is None or compare_versions(hi, best, ecosystem) > 0:
            best = hi
    if best:
        return "Upgrade to >= %s" % best
    return "See the advisory references for patched versions"


def match_inventory(inventory, bundle):
    """-> (matches, unknown). A match = (adv, pkg, dep, matched_range); an
    unknown = (dep, adv, pkg, reason). Unknown covers: no version known for
    the dependency, an advisory without range data, a malformed range, and a
    version or bound that cannot be compared — never a silent clear."""
    matches = []
    unknown = []
    seen = set()
    for dep in inventory:
        e, name, version, _where = dep
        for adv, pkg in bundle.advisories_for(name, e):
            mkey = (adv.get("cve"), normalize_pkg(pkg.get("name"), pkg.get("ecosystem")),
                    str(version), e)
            if mkey in seen:
                continue
            seen.add(mkey)
            ranges = pkg.get("ranges")
            if not version:
                unknown.append((dep, adv, pkg, "no concrete version (range, wildcard "
                                                "or unpinned dependency)"))
                continue
            if ranges is None:
                unknown.append((dep, adv, pkg, "the advisory's version ranges are malformed"))
                continue
            if not ranges:
                unknown.append((dep, adv, pkg, "the advisory has no affected-version ranges"))
                continue
            hit, undecided = None, False
            for r in ranges:
                verdict = version_in_range(version, r, e)
                if verdict is True:
                    hit = r
                    break
                if verdict is None:
                    undecided = True
            if hit is not None:
                matches.append((adv, pkg, dep, hit))
            elif undecided:
                unknown.append((dep, adv, pkg, "version %r cannot be compared with the "
                                               "advisory's range bounds" % str(version)[:40]))
            # else: version falls outside every range -> not affected, stay silent
    return matches, unknown


# ---------------------------------------------------------------------------
# Findings — Lazaret issue shape (mirrors lazaret.mk_issue keys)
# ---------------------------------------------------------------------------

# A CVE verdict is only as current as the bundle it came from. KEV is updated
# continuously and EPSS daily, so an export older than this fails a quality-gate
# freshness condition (override or disable with --max-age).
BUNDLE_MAX_AGE_DAYS = 7

SCA_RULES = {
    "SCA-CVE-KEV": {
        "id": "SCA-CVE-KEV", "name": "Known-exploited vulnerable dependency (KEV)",
        "type": "VULN", "sev": "BLOCKER",
        "msg": None, "why": "CISA's KEV catalog lists this CVE as exploited in the wild. An "
                            "installed module version inside the affected range with an active "
                            "KEV entry is the highest-confidence supply-chain exposure there is.",
        "fix": "Upgrade the dependency out of the affected range; if that is impossible this " "release, plan a compensating control and an exception with an expiry.",
        "ref": "OWASP A06:2021 — Vulnerable & Outdated Components; CISA KEV",
    },
    "SCA-CVE": {
        "id": "SCA-CVE", "name": "Vulnerable dependency (CVE in affected range)",
        "type": "VULN", "sev": "MAJOR",
        "msg": None, "why": "The installed version falls inside a published affected range for "
                            "this CVE. Range matching is advisory-data driven — verify "
                            "exploitability in context before treating it as critical.",
        "fix": "Upgrade the dependency out of the affected range.",
        "ref": "OWASP A06:2021 — Vulnerable & Outdated Components",
    },
    "SCA-CVE-UNKNOWN": {
        "id": "SCA-CVE-UNKNOWN", "name": "Dependency matches a CVE advisory (version unresolvable)",
        "type": "VULN", "sev": "MINOR",
        "msg": None, "why": "The advisory is registered for this module but no affected version "
                            "range could be evaluated against the installed/pinned version. "
                            "Unknown is reported rather than clear — the Redline KB discipline: "
                            "never wrongly clear a component as patched.",
        "fix": "Pin an exact version and re-scan, or check the advisory manually.",
        "ref": "OWASP A06:2021 — Vulnerable & Outdated Components",
    },
}


def mk_sca_issue(rule, dep, adv, pkg, matched_range=None, fix=None, reason=None):
    e, name, version, where = dep
    cve = adv.get("cve")
    title = adv.get("title") or cve
    sev = "BLOCKER" if adv.get("knownExploited") is True else severity_of(adv)
    if rule["id"] == "SCA-CVE-UNKNOWN":
        sev = "MINOR"
        msg = "%s in %s: installed version could not be range-checked against this advisory" % (cve, name)
        if reason:
            msg += " (%s)" % reason
    elif adv.get("knownExploited") is True:
        msg = "%s (%s) affects %s %s — KEV: exploited in the wild%s" % (
            cve, title, name, version,
            " (ransomware use known)" if adv.get("ransomware") is True else "")
    else:
        msg = "%s (%s) affects %s %s" % (cve, title, name, version)
    issue = {
        "rule": rule["id"], "name": rule["name"], "type": "VULN", "sev": sev,
        "msg": msg, "why": rule["why"], "fix": fix or rule["fix"], "ref": rule["ref"],
        "file": where, "line": 1,
        "snippet": [], "snipStart": 0,
        "detail": {
            "ecosystem": e, "package": name, "installed": version,
            "cve": cve, "cvss": _num(adv.get("cvss")), "severity": adv.get("severity"),
            "cwes": adv.get("cwes") or [], "knownExploited": adv.get("knownExploited") is True,
            "ransomware": adv.get("ransomware") is True, "dueDate": adv.get("dueDate"),
            "epss": _num(adv.get("epss")), "epssPercentile": _num(adv.get("epssPercentile")),
            "published": adv.get("published"),
            "matchedRange": format_range(matched_range) if matched_range else None,
            "advisoryRefs": (adv.get("refs") or [])[:4],
            "kbSources": adv.get("sources") or [],
            "unknownReason": reason,
        },
    }
    return issue


def build_sca_result(root, bundle, issues, inventory, stats, out_dir=None, max_age=BUNDLE_MAX_AGE_DAYS):
    """Lazaret result dict — same keys lazaret.build_result emits, so the
    report renderers, quality gate semantics, baseline diffing and MCP slim()
    all work on an SCA result unchanged. Includes the bundle-freshness gate:
    a CVE verdict is only as trustworthy as the export it came from — a
    missing or unparseable export date FAILS it."""
    age_days = bundle_age_days(bundle.generated_at)
    counts = {"VULN": 0, "HOTSPOT": 0, "BUG": 0, "SMELL": 0}
    for i in issues:
        counts[i["type"]] = counts.get(i["type"], 0) + 1
    conds = [
        {"label": "No known-exploited (KEV) dependencies",
         "ok": not any(i["rule"] == "SCA-CVE-KEV" for i in issues)},
        {"label": "No critical vulnerable dependencies",
         "ok": not any(i["type"] == "VULN" and i["sev"] in ("CRITICAL", "BLOCKER") for i in issues)},
        {"label": "No vulnerable dependencies",
         "ok": not any(i["rule"] == "SCA-CVE" for i in issues)},
        {"label": "CVE bundle fresh (age ≤ %d days)" % max_age,
         "ok": bundle_is_fresh(bundle.generated_at, max_age)},
        {"label": "All dependency versions resolvable",
         "ok": not any(i["rule"] == "SCA-CVE-UNKNOWN" for i in issues)},
        {"label": "Dependency inventory non-empty",
         "ok": len(inventory) > 0},
    ]
    per_file = {}
    for i in issues:
        per_file[i["file"]] = per_file.get(i["file"], 0) + 1
    metrics = {
        "files": 1, "depFiles": 0, "ncloc": 0, "comments": 0, "dupPct": 0.0,
        "npmDeps": stats.get("npm", 0), "pypiDeps": stats.get("pypi", 0),
        "advisories": len(bundle.advisories),
        "bundleGeneratedAt": bundle.generated_at,
        "bundleAgeDays": age_days,
        "bundleSources": bundle.sources,
    }
    return {
        "project": os.path.abspath(root),
        "scannedAt": _dt.datetime.now().isoformat(timespec="seconds"),
        "pass": all(c["ok"] for c in conds),
        "conditions": conds,
        "metrics": metrics, "counts": counts,
        "ratings": {"security": "A" if not any(i["type"] == "VULN" for i in issues) else
                    ("E" if any(i["sev"] in ("CRITICAL", "BLOCKER") for i in issues) else
                     ("C" if counts["VULN"] else "B")),
                    "reliability": "A", "maintainability": "A"},
        "supplyChain": 0, "crossFile": 0, "sca": True,
        "perFile": per_file, "issues": issues,
        "inventory": [{"ecosystem": e, "name": n, "version": v, "where": w} for e, n, v, w in inventory],
        "inventoryStats": stats,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="lazaret-sca",
        description="Lazaret SCA — inventory npm/pypi dependencies of an installed code "
                    "base and match them against a Redline-exported CVE bundle.")
    ap.add_argument("directory", help="project directory (the installed code base)")
    ap.add_argument("--bundle", required=True, help="path to cve-bundle.json (Redline export)")
    ap.add_argument("--site-packages", action="append", default=[],
                    help="extra site-packages dir to scan for installed pypi modules (repeatable)")
    ap.add_argument("--max-age", type=int, default=BUNDLE_MAX_AGE_DAYS, dest="max_age",
                    help="max acceptable CVE-bundle age in days before the quality gate flags it "
                         "stale (default %d; 0 disables the freshness gate)" % BUNDLE_MAX_AGE_DAYS)
    ap.add_argument("--out-dir", metavar="DIR",
                    help="directory for the default report (default: the project dir). "
                         "Must already exist and be writable.")
    ap.add_argument("--json", dest="json_out", default=None, metavar="PATH",
                    help="write JSON report to PATH (default <out-dir>/%s)" % SCA_REPORT_NAME)
    ap.add_argument("--no-json", action="store_true", help="skip the JSON report")
    ap.add_argument("--html", default=None, metavar="PATH", help="also write an HTML report")
    ap.add_argument("--sarif", default=None, metavar="PATH", help="also write a SARIF 2.1.0 report")
    ap.add_argument("--force-overwrite", action="store_true",
                    help="overwrite an existing report file even if it was not produced by "
                         "Lazaret (still refuses directories, symlinks and special files)")
    ap.add_argument("--baseline", metavar="PATH",
                    help="previous JSON report; findings not in it are marked new")
    ap.add_argument("--ci", action="store_true", help="exit 1 if the quality gate fails")
    ap.add_argument("-q", "--quiet", action="store_true", help="summary only")
    ap.add_argument("--inventory-only", action="store_true",
                    help="print the dependency inventory and exit (no matching)")
    return ap.parse_args(argv)


def scan_all(root, extra_site_packages=None, warn=None):
    inv = Inventory()
    inv.extend(scan_npm_installed(root, warn))
    inv.extend(scan_npm_lock(root, warn))
    inv.extend(scan_npm_other_locks(root, warn))
    inv.extend(scan_npm_declared(root, warn))
    inv.extend(scan_pypi_installed(root, extra_site_packages, warn))
    inv.extend(scan_pypi_declared(root, warn))
    return inv.dedup()


def _report_paths(args):
    """Final report paths, resolved like the lazaret CLI: relative paths are
    taken relative to --out-dir (default: the project dir)."""
    base = os.path.abspath(args.out_dir or args.directory)

    def resolve(p):
        return p if os.path.isabs(p) else os.path.join(base, p)
    paths = {}
    if not args.no_json:
        paths["json"] = resolve(args.json_out or SCA_REPORT_NAME)
    if args.html:
        paths["html"] = resolve(args.html)
    if args.sarif:
        paths["sarif"] = resolve(args.sarif)
    return paths


def main(argv=None):
    """lazaret-sca entry point; returns the exit code. An unexpected error is
    printed as `error: internal: …` with exit 5 — never a traceback that
    could be mistaken for a failed gate."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:                        # pragma: no cover (defensive)
        print("error: internal: %s: %s" % (type(exc).__name__, lazaret.sanitize_term(exc)),
              file=sys.stderr)
        return EXIT_INTERNAL


def _main(argv=None):
    lazaret.configure_stdio()
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not os.path.isdir(args.directory):
        # audit H1: sanitize the CLI value — no-op for clean paths, uniformity.
        print("error: %s is not a directory" % lazaret.sanitize_term(args.directory),
              file=sys.stderr)
        return 2

    paths = {}
    if not args.inventory_only:
        # Report destinations are validated BEFORE the scan (writability, no
        # symlinks/special files, no clobbering a file that is not one of our
        # reports) — the old plain open() followed a committed
        # `lazaret-sca.json -> ~/.bashrc` symlink and overwrote the target.
        try:
            if args.out_dir:
                lazaret_report.validate_out_dir(args.out_dir)
            paths = _report_paths(args)
            if paths:
                lazaret_report.validate_report_paths(paths, strict=args.force_overwrite)
        except lazaret_report.ReportPathError as exc:
            print("error: %s" % lazaret.sanitize_term(exc), file=sys.stderr)
            return lazaret_report.EXIT_OUTPUT

    warn = _Warnings()
    inv = scan_all(args.directory, args.site_packages, warn)
    stats = {"npm": sum(1 for d in inv if d[0] == "npm"),
             "pypi": sum(1 for d in inv if d[0] == "pypi")}
    print("Lazaret SCA — %s" % lazaret.sanitize_term(os.path.abspath(args.directory)))
    print("  inventory: %d npm · %d pypi modules" % (stats["npm"], stats["pypi"]))
    for line in warn.lines():
        print("  warning: inventory: %s" % lazaret.sanitize_term(line), file=sys.stderr)
    if args.inventory_only:
        for e, n, v, w in sorted(inv):
            # audit H1: inventory names/versions come from hostile
            # package.json / METADATA / lockfiles; sanitize BEFORE the width
            # padding so the columns stay aligned ('·' is 1 char).
            print("  %-5s %-40s %-16s %s" % (
                e, lazaret.sanitize_term(n), lazaret.sanitize_term(v),
                lazaret.sanitize_term(w)))
        return 0

    try:
        bundle = CveBundle.load(args.bundle)
    except ValueError as e:
        # audit H1: the ValueError text can echo bundle-file content.
        print("error: %s" % lazaret.sanitize_term(e), file=sys.stderr)
        return EXIT_BUNDLE
    if not bundle.advisories:
        print("error: bundle %s contains no advisories — export one from Redline first "
              "(packages/vulndb/src/export-bundle.ts)" % lazaret.sanitize_term(args.bundle),
              file=sys.stderr)
        return EXIT_BUNDLE
    for line in bundle.warnings.lines():
        print("  warning: CVE bundle: %s" % lazaret.sanitize_term(line), file=sys.stderr)

    matches, unknown = match_inventory(inv, bundle)
    issues = []
    for adv, pkg, dep, hit in sorted(matches, key=lambda m: (m[0].get("cve") or "")):
        rule = SCA_RULES["SCA-CVE-KEV" if adv.get("knownExploited") is True else "SCA-CVE"]
        issues.append(mk_sca_issue(rule, dep, adv, pkg, hit, fix=fix_hint(adv, pkg, dep[0])))
    for dep, adv, pkg, reason in sorted(unknown, key=lambda u: (u[1].get("cve") or "",
                                                                 u[2].get("name") or "")):
        issues.append(mk_sca_issue(SCA_RULES["SCA-CVE-UNKNOWN"], dep, adv, pkg, reason=reason))

    res = build_sca_result(args.directory, bundle, issues, inv, stats, max_age=args.max_age)
    if args.baseline:
        lazaret.apply_baseline(res, args.baseline, scan_root=args.directory)

    # audit H1: bundle.sources and generated_at are arbitrary strings in the
    # bundle JSON — sanitize both.
    print("\n  CVE bundle: %d advisories (%s) generated %s" % (
        len(bundle.advisories),
        lazaret.sanitize_term(", ".join(bundle.sources)),
        lazaret.sanitize_term(bundle.generated_at)))
    age = bundle_age_days(bundle.generated_at)
    if args.max_age > 0 and age is None:
        print("  WARNING: the bundle's generatedAt is missing or unparseable — its "
              "freshness cannot be established, so the freshness gate fails.",
              file=sys.stderr)
    elif age is not None and args.max_age > 0 and not bundle_is_fresh(bundle.generated_at, args.max_age):
        print("  WARNING: bundle is %d days old (max %d) — new CVEs/KEV entries since the "
              "export are invisible to this scan. Re-export from Redline "
              "(packages/vulndb/src/export-bundle.ts)." % (age, args.max_age), file=sys.stderr)
    print("  matches:    %d affected · %d unknown-version" % (len(matches), len(unknown)))
    if "newIssues" in res:
        print("  New issues vs baseline: %d" % res["newIssues"])
    gate = " PASSED " if res["pass"] else " FAILED "
    print("\n  Quality gate: %s" % gate)
    for cond in res["conditions"]:
        print("    %s %s" % ("✓" if cond["ok"] else "✗", cond["label"]))

    try:
        if "json" in paths:
            p = lazaret_report.write_report(
                paths["json"], lambda: lazaret_report.json_renderer(res), "json",
                strict=args.force_overwrite)
            print("\n  JSON report: %s" % lazaret.sanitize_term(p))
        if "html" in paths:
            p = lazaret_report.write_report(
                paths["html"], lambda: lazaret._html_report_marked(res), "html",
                strict=args.force_overwrite)
            print("  HTML report: %s" % lazaret.sanitize_term(p))
        if "sarif" in paths:
            p = lazaret_report.write_report(
                paths["sarif"], lambda: lazaret_report.sarif_renderer(lazaret.sarif_report(res)),
                "sarif", strict=args.force_overwrite)
            print("  SARIF report: %s" % lazaret.sanitize_term(p))
    except (lazaret_report.ReportPathError, OSError) as exc:
        print("error: %s" % lazaret.sanitize_term(exc), file=sys.stderr)
        return lazaret_report.EXIT_OUTPUT

    if not args.quiet and res["issues"]:
        print("\n  Issues")
        for i in sorted(res["issues"], key=lambda i: (i["sev"] != "BLOCKER", i["detail"]["cve"] or "")):
            # audit H1: i['msg'] embeds advisory titles and inventory
            # name/version; i['fix'] embeds the bundle's toVersion hint.
            print("    %-8s [%s] %s" % (i["sev"], i["rule"],
                                        lazaret.sanitize_term(i["msg"])))
            d = i["detail"]
            extra = []
            if d.get("cvss") is not None:
                extra.append("cvss %s" % d["cvss"])
            if d.get("matchedRange"):
                extra.append("range %s" % d["matchedRange"])
            if isinstance(d.get("epss"), (int, float)):
                extra.append("epss %.3f" % d["epss"])
            if extra:
                # matchedRange is derived from bundle data — sanitize the join.
                print("             %s" % lazaret.sanitize_term(" · ".join(extra)))
            print("             fix: %s" % lazaret.sanitize_term(i["fix"]))

    if args.ci and not res["pass"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
