#!/usr/bin/env python3
"""Lazaret SCA — dependency CVE scanner (card "Identify CVE Scanning Features").

Given an installed code base (a project directory), inventory the npm and PyPI
modules that are actually installed/declared there, then match each module@version
against a CVE bundle exported from the Redline vulnerability knowledge base
(`export-bundle.ts` on the Redline side: KEV + NVD + Wordfence + EPSS, with
affected-version ranges) and emit Lazaret-shaped VULN findings.

    lazaret-sca <project-dir> --bundle cve-bundle.json [options]

What "inventory" means (both ecosystems, both direct evidence and declared pins):
  npm   - node_modules/<pkg>/package.json            (the INSTALLED truth)
          package-lock.json / npm-shrinkwrap.json    (the LOCKED truth)
          package.json dependencies/devDependencies  (the DECLARED truth)
  pypi  - <venv>/lib/pythonX.Y/site-packages/<pkg>.dist-info/METADATA
          (the INSTALLED truth — also scanned when site-packages lives under
           the project dir, e.g. .venv, venv, or a passed --site-packages)
          requirements*.txt, pyproject.toml, Pipfile.lock, poetry.lock, setup.py

Matching (the Redline A06 engine, ported):
  - Version comparison: numeric segments, missing trailing segments = 0,
    pre-release sorts BELOW release (semver). See compare_versions().
  - Range membership: inclusive/exclusive bounds, '*' or '' = unbounded.
  - Verdicts: affected / not-affected / unknown. NO RANGE DATA => UNKNOWN,
    never a false clear — the same discipline as Redline's version-range.ts
    ("we never wrongly clear a component as patched").
  - Name normalization: lowercase, '_' vs '-', '@scope/name' unscoped for npm,
    'python-' / 'py-' prefixes and '-python' suffixes stripped for pypi.
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
counts, issues) so the report renderers, baseline diffing and MCP slim() work
unchanged. Issue dicts carry the same keys as lazaret.mk_issue plus 'cve'
extras under i['detail'] (cve, package, installed, range, fix hint, epss, kev).

Exit codes (mirror the lazaret CLI): 0 ok / 1 gate failed (--ci) / 2 usage /
3 unwritable output / 4 bundle problem (invalid, unreadable, no advisories).

No third-party dependencies — stock python3, same contract as the lazaret CLI.
"""
import argparse
import json
import os
import re
import sys

# audit H1: lazaret.sanitize_term() is the canonical terminal-control
# neutralizer; sca output interpolates inventory names/versions and CVE-bundle
# fields, so it needs the helper. Same sys.path bootstrap lazaret_repo uses.
from lazaret.scanner import core as lazaret  # noqa: E402

# ---------------------------------------------------------------------------
# Version engine — faithful port of redline/packages/core/src/version-range.ts
# ---------------------------------------------------------------------------

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


def compare_versions(a, b):
    """-1/0/1 like the TS compareVersions: trailing zeros equal, pre < release."""
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


def is_comparable_version(version):
    return bool(re.match(r"^\s*v?\d+\.\d+", str(version or "")))


def unbounded(b):
    return b is None or b == "" or b == "*"


def version_in_range(version, r):
    """Is `version` inside affected range `r` (a dict with from/to + inclusivity)?"""
    if not is_comparable_version(version):
        return False
    lo, lo_inc = r.get("fromVersion", "*"), r.get("fromInclusive", True)
    hi, hi_inc = r.get("toVersion", "*"), r.get("toInclusive", True)
    if not unbounded(lo):
        if not is_comparable_version(lo):
            return False
        c = compare_versions(version, lo)
        if (c < 0) if lo_inc else (c <= 0):
            return False
    if not unbounded(hi):
        if not is_comparable_version(hi):
            return False
        c = compare_versions(version, hi)
        if (c > 0) if hi_inc else (c >= 0):
            return False
    return True


def format_range(r):
    lo = None if unbounded(r.get("fromVersion", "*")) else \
        (">=" if r.get("fromInclusive", True) else ">") + str(r.get("fromVersion"))
    hi = None if unbounded(r.get("toVersion", "*")) else \
        ("<=" if r.get("toInclusive", True) else "<") + str(r.get("toVersion"))
    if not lo and not hi:
        return "all versions"
    return " ".join(x for x in (lo, hi) if x)


# ---------------------------------------------------------------------------
# Name normalization — one namespace across npm and pypi
# ---------------------------------------------------------------------------

def normalize_pkg(name, ecosystem=None):
    """Fold an npm/pypi/CPE product name into one comparison key.

    npm scoped packages drop the scope (NVD records them unscoped); pypi's
    python- prefix / -python suffix aliases fold together; separators unify.
    Returns a single key: the scoped name itself when scoped (so @scope/pkg
    never collides with a plain 'pkg' — matching is variant-aware instead).
    """
    n = str(name or "").strip().lower()
    if n.startswith("@") and "/" in n:
        scope, tail = n[1:].split("/", 1)
        n = scope + "-" + tail.replace("/", "-")     # '@babel/core' -> 'babel-core'
    n = n.replace(" ", "-").replace("_", "-").replace(".", "-")
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

    The bundle's product names come from CPE records (unscoped, 'python-'
    prefixes sometimes present); the inventory's names are what the package
    manager recorded. We look an inventory name up under BOTH its own fold AND
    the alias-fold, so npm '@babel/core' finds a CPE 'babel' entry and pypi
    'urllib3' finds a CPE 'python-urllib3' entry.
    """
    n = str(name or "").strip().lower()
    out = {normalize_pkg(n, ecosystem)}
    if "/" in n:                                       # scoped npm: also try unscoped
        out.add(normalize_pkg(n.split("/", 1)[1], "npm"))
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
        seen = {}
        for e, n, v, w in self:
            k = (e, n)
            if k not in seen:
                seen[k] = (e, n, v, w)
        return Inventory(seen[k] for k in seen)


def _read_json(path, cap=20 * 1024 * 1024):
    try:
        if os.path.getsize(path) > cap:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ----- npm -----

def scan_npm_installed(root):
    """node_modules/<pkg>/package.json — the installed truth (incl. @scoped)."""
    out = Inventory()
    nm = os.path.join(root, "node_modules")
    if not os.path.isdir(nm):
        return out
    try:
        entries = sorted(os.listdir(nm))
    except OSError:
        return out
    for entry in entries:
        if entry.startswith("."):
            continue
        if entry.startswith("@"):               # scope dir: node_modules/@scope/pkg
            scope_dir = os.path.join(nm, entry)
            try:
                subs = sorted(os.listdir(scope_dir))
            except OSError:
                continue
            for sub in subs:
                if sub.startswith("."):
                    continue
                _add_npm_pkg(out, os.path.join(scope_dir, sub), "%s/%s" % (entry, sub), nm)
        else:
            _add_npm_pkg(out, os.path.join(nm, entry), entry, nm)
    return out


def _add_npm_pkg(out, pkg_dir, rel, nm):
    pj = _read_json(os.path.join(pkg_dir, "package.json"), cap=2 * 1024 * 1024)
    if not isinstance(pj, dict) or not pj.get("name"):
        return
    name = str(pj.get("name"))
    version = str(pj.get("version") or "").strip()
    if not version:
        return
    # 'where' is the path of this package.json relative to the SCAN ROOT (the dir
    # containing node_modules/), so findings point at a real file the operator can open.
    root_dir = os.path.dirname(nm)            # the project dir that holds node_modules
    where = os.path.relpath(os.path.join(pkg_dir, "package.json"), root_dir)
    out.append(("npm", name, version, where.replace(os.sep, "/")))


def scan_npm_lock(root):
    """package-lock.json / npm-shrinkwrap.json (v1, 2, 3) — the locked truth."""
    out = Inventory()
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lock = _read_json(os.path.join(root, lock_name))
        if not isinstance(lock, dict):
            continue
        found = {}
        packages = lock.get("packages")
        if isinstance(packages, dict):        # lock v2/v3: {"node_modules/x": {...}}
            for k, meta in packages.items():
                if not isinstance(meta, dict) or not k.startswith("node_modules/"):
                    continue
                name = meta.get("name") or k[len("node_modules/"):]
                v = str(meta.get("version") or "").strip()
                if name and v:
                    found[str(name)] = v
        deps = lock.get("dependencies")        # lock v1: {"name": {version, dependencies}}
        if isinstance(deps, dict):
            for name, meta in deps.items():
                v = str((meta or {}).get("version") or "").strip()
                if name and v and str(name) not in found:
                    found[str(name)] = v
        for name, v in found.items():
            out.append(("npm", name, v, lock_name))
    return out


def scan_npm_declared(root):
    """package.json dependencies/devDependencies — the declared truth."""
    out = Inventory()
    pj = _read_json(os.path.join(root, "package.json"))
    if not isinstance(pj, dict):
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = pj.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            v = str(spec or "").strip()
            m = re.match(r"^(\d+(?:\.\d+)+)", v)          # ignore ^ ~ >= ranges — pin only
            if m:
                out.append(("npm", str(name), m.group(1), "package.json(%s)" % section))
            elif v.startswith(("git+", "http", "file:")):
                out.append(("npm", str(name), "", "package.json(%s) unresolvable:%s" % (section, v[:40])))
            elif v and v not in ("*", "latest"):
                # a ^/~/>= range or tag: NOT a version — record it unresolvable so a matching
                # advisory yields version-unknown, never a silent clear
                out.append(("npm", str(name), "", "package.json(%s) unresolvable:%s" % (section, v[:40])))
    return out


# ----- pypi -----

def scan_pypi_installed(root, extra_site_packages=None):
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
                for line in f:
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


_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9_.+\-]*)")      # == is a pin
_REQ_BOUND = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(>=|<=|~=|!=|>|<|===)\s*([0-9][A-Za-z0-9_.+\-]*)")


def scan_pypi_declared(root):
    """requirements*.txt (== pins), pyproject.toml (PEP 508 + lock sections), Pipfile.lock, poetry.lock, setup.py."""
    out = Inventory()

    for fn in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        if re.match(r"^requirements.*\.txt$", fn):
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        m = _REQ_PIN.match(line)
                        if m:
                            out.append(("pypi", m.group(1), m.group(2), fn))
                        elif _REQ_BOUND.match(line):
                            # a >=/~/!= bound is a RANGE, not a version — record the module
                            # with an empty version so the matcher reports it as
                            # version-unknown against matching advisories rather than
                            # silently clearing it (the Redline no-false-clear discipline).
                            out.append(("pypi", _REQ_BOUND.match(line).group(1), "", "%s (range: %s)" % (fn, line[:60])))
            except OSError:
                pass

    pp = os.path.join(root, "pyproject.toml")
    if os.path.isfile(pp):
        try:
            with open(pp, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            text = ""
        for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*\"([^\"#=]+)\"", text, re.M):
            name, spec = m.group(1).strip(), m.group(2).strip()
            if name in ("requires-python", "python", "version", "description", "name", "readme", "license"):
                continue
            vm = re.match(r"^(\d+(?:\.\d+)+)", spec)
            if vm:
                out.append(("pypi", name, vm.group(1), "pyproject.toml"))
            elif spec and not spec.startswith(("<", ">", "~", "!", "^")):
                out.append(("pypi", name, spec.strip(), "pyproject.toml"))
            elif spec:
                out.append(("pypi", name, "", "pyproject.toml (range: %s)" % spec[:40]))

    pl = _read_json(os.path.join(root, "Pipfile.lock"))
    if isinstance(pl, dict):
        for section in ("default", "develop"):
            for name, meta in (pl.get(section) or {}).items():
                v = str((meta or {}).get("version") or "").lstrip("=v").strip()
                if v:
                    out.append(("pypi", str(name), v, "Pipfile.lock(%s)" % section))

    po = _read_json(os.path.join(root, "poetry.lock"))
    if isinstance(po, dict):
        for pkg in po.get("package") or []:
            name, v = pkg.get("name"), pkg.get("version")
            if name and v:
                out.append(("pypi", str(name), str(v), "poetry.lock"))

    su = os.path.join(root, "setup.py")
    if os.path.isfile(su):
        try:
            with open(su, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
            if m:
                for entry in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                    em = _REQ_PIN.match(entry.strip())
                    if em:
                        out.append(("pypi", em.group(1), em.group(2), "setup.py"))
        except OSError:
            pass
    return out


# ---------------------------------------------------------------------------
# CVE bundle (the Redline export) — loading + index
# ---------------------------------------------------------------------------

class CveBundle:
    """Advisories indexed by normalized package name for O(inventory) matching.

    The index keys on every variant of each advisory package name (folded and
    alias-folded), so an inventory lookup under ANY of the same variants finds
    it. ``advisories_for`` then does the same variant expansion on the
    inventory side — the two sides never need to agree on a single spelling.
    """

    def __init__(self, doc):
        if not isinstance(doc, dict) or doc.get("bundleVersion") != 1:
            raise ValueError("not a Lazaret CVE bundle (bundleVersion != 1)")
        advisories = doc.get("advisories") or []
        self.generated_at = doc.get("generatedAt")
        self.sources = doc.get("sources") or []
        self.counts = doc.get("counts") or {}
        self.advisories = advisories
        self._index = {}
        for adv in advisories:
            for pkg in adv.get("packages") or []:
                eco = pkg.get("ecosystem")
                for key in name_variants(str(pkg.get("name") or ""), eco):
                    self._index.setdefault(key, []).append((adv, pkg))

    def advisories_for(self, name, ecosystem=None):
        out = []
        seen = set()
        for key in name_variants(name, ecosystem):
            for pair in self._index.get(key, []):
                k = id(pair[0])
                if k not in seen:
                    seen.add(k)
                    out.append(pair)
        return out

    @classmethod
    def load(cls, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            raise ValueError("cannot read CVE bundle %s: %s" % (path, e))
        return cls(doc)


def bundle_age_days(generated_at):
    """Age of the bundle in days (None when unknown/unparseable)."""
    if not generated_at:
        return None
    import datetime as _dt
    try:
        gen = _dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - gen).days


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def severity_of(adv):
    """KEV first, then CVSS, then the KB severity label. Never INFO — see module docstring."""
    if adv.get("knownExploited"):
        return "BLOCKER"
    cvss = adv.get("cvss")
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "MAJOR"
    sev = str(adv.get("severity") or "").lower()
    return {"critical": "CRITICAL", "high": "MAJOR"}.get(sev, "MINOR")


def fix_hint(adv, pkg):
    """Best-effort patched-version hint: the upper bound of any exclusive range."""
    best = None
    for r in pkg.get("ranges") or []:
        hi = r.get("toVersion")
        if not unbounded(hi) and r.get("toInclusive") is False:
            if best is None or compare_versions(hi, best) > 0:
                best = hi
    if best:
        return "Upgrade to >= %s" % best
    return "See the advisory references for patched versions"


def match_inventory(inventory, bundle):
    """-> (matches, unknown_version_pkgs). A match = (adv, pkg, dep, matched_range)."""
    matches = []
    unknown = []
    seen = set()
    for dep in inventory:
        e, name, version, _where = dep
        for adv, pkg in bundle.advisories_for(name, e):
            mkey = (adv.get("cve"), normalize_pkg(pkg.get("name"), pkg.get("ecosystem")), str(version))
            if mkey in seen:
                continue
            ranges = pkg.get("ranges") or []
            if not version:
                unknown.append((dep, adv, pkg))
                seen.add(mkey)
                continue
            hit = None
            for r in ranges:
                if version_in_range(version, r):
                    hit = r
                    break
            if hit is not None:
                matches.append((adv, pkg, dep, hit))
                seen.add(mkey)
            elif not ranges:
                unknown.append((dep, adv, pkg))
                seen.add(mkey)
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


def mk_sca_issue(rule, dep, adv, pkg, matched_range=None, fix=None):
    e, name, version, where = dep
    cve = adv.get("cve")
    title = adv.get("title") or cve
    sev = "BLOCKER" if adv.get("knownExploited") else severity_of(adv)
    if rule["id"] == "SCA-CVE-UNKNOWN":
        sev = "MINOR"
        msg = "%s in %s: installed version could not be range-checked against this advisory" % (cve, name)
    elif adv.get("knownExploited"):
        msg = "%s (%s) affects %s %s — KEV: exploited in the wild%s" % (
            cve, title, name, version,
            " (ransomware use known)" if adv.get("ransomware") else "")
    else:
        msg = "%s (%s) affects %s %s" % (cve, title, name, version)
    issue = {
        "rule": rule["id"], "name": rule["name"], "type": "VULN", "sev": sev,
        "msg": msg, "why": rule["why"], "fix": fix or rule["fix"], "ref": rule["ref"],
        "file": where, "line": 1,
        "snippet": [], "snipStart": 0,
        "detail": {
            "ecosystem": e, "package": name, "installed": version,
            "cve": cve, "cvss": adv.get("cvss"), "severity": adv.get("severity"),
            "cwes": adv.get("cwes") or [], "knownExploited": bool(adv.get("knownExploited")),
            "ransomware": bool(adv.get("ransomware")), "dueDate": adv.get("dueDate"),
            "epss": adv.get("epss"), "epssPercentile": adv.get("epssPercentile"),
            "published": adv.get("published"),
            "matchedRange": format_range(matched_range) if matched_range else None,
            "advisoryRefs": (adv.get("refs") or [])[:4],
            "kbSources": adv.get("sources") or [],
        },
    }
    return issue


def build_sca_result(root, bundle, issues, inventory, stats, out_dir=None, max_age=BUNDLE_MAX_AGE_DAYS):
    """Lazaret result dict — same keys lazaret.build_result emits, so the
    report renderers, quality gate semantics, baseline diffing and MCP slim()
    all work on an SCA result unchanged. Includes the bundle-freshness gate:
    a CVE verdict is only as trustworthy as the export it came from."""
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
         "ok": max_age <= 0 or age_days is None or age_days <= max_age},
        {"label": "All dependency versions resolvable",
         "ok": not any(i["rule"] == "SCA-CVE-UNKNOWN" for i in issues)},
        {"label": "Dependency inventory non-empty",
         "ok": len(inventory) > 0},
    ]
    per_file = {}
    for i in issues:
        per_file[i["file"]] = per_file.get(i["file"], 0) + 1
    import datetime as _dt
    metrics = {
        "files": 1, "depFiles": 0, "ncloc": 0, "comments": 0, "dupPct": 0.0,
        "npmDeps": stats.get("npm", 0), "pypiDeps": stats.get("pypi", 0),
        "advisories": bundle.counts.get("advisories", 0),
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
    ap.add_argument("--json", dest="json_out", default=None,
                    help="write JSON report to PATH (default <dir>/lazaret-sca.json)")
    ap.add_argument("--no-json", action="store_true", help="skip the JSON report")
    ap.add_argument("--ci", action="store_true", help="exit 1 if the quality gate fails")
    ap.add_argument("-q", "--quiet", action="store_true", help="summary only")
    ap.add_argument("--inventory-only", action="store_true",
                    help="print the dependency inventory and exit (no matching)")
    return ap.parse_args(argv)


def scan_all(root, extra_site_packages=None):
    inv = Inventory()
    inv.extend(scan_npm_installed(root))
    inv.extend(scan_npm_lock(root))
    inv.extend(scan_npm_declared(root))
    inv.extend(scan_pypi_installed(root, extra_site_packages))
    inv.extend(scan_pypi_declared(root))
    return inv.dedup()


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not os.path.isdir(args.directory):
        # audit H1: sanitize the CLI value — no-op for clean paths, uniformity.
        print("error: %s is not a directory" % lazaret.sanitize_term(args.directory),
              file=sys.stderr)
        return 2

    inv = scan_all(args.directory, args.site_packages)
    stats = {"npm": sum(1 for d in inv if d[0] == "npm"),
             "pypi": sum(1 for d in inv if d[0] == "pypi")}
    print("Lazaret SCA — %s" % lazaret.sanitize_term(os.path.abspath(args.directory)))
    print("  inventory: %d npm · %d pypi modules" % (stats["npm"], stats["pypi"]))
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
        return 4
    if not bundle.advisories:
        print("error: bundle %s contains no advisories — export one from Redline first "
              "(packages/vulndb/src/export-bundle.ts)" % lazaret.sanitize_term(args.bundle),
              file=sys.stderr)
        return 4

    matches, unknown = match_inventory(inv, bundle)
    issues = []
    for adv, pkg, dep, hit in sorted(matches, key=lambda m: (m[0].get("cve") or "")):
        rule = SCA_RULES["SCA-CVE-KEV" if adv.get("knownExploited") else "SCA-CVE"]
        issues.append(mk_sca_issue(rule, dep, adv, pkg, hit, fix=fix_hint(adv, pkg)))
    for dep, adv, pkg in sorted(unknown, key=lambda u: (u[1].get("cve") or "", u[2].get("name") or "")):
        issues.append(mk_sca_issue(SCA_RULES["SCA-CVE-UNKNOWN"], dep, adv, pkg))

    res = build_sca_result(args.directory, bundle, issues, inv, stats, max_age=args.max_age)

    json_path = None
    if not args.no_json:
        json_path = args.json_out or os.path.join(args.directory, "lazaret-sca.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
        except OSError as e:
            print("error: cannot write %s: %s" % (lazaret.sanitize_term(json_path),
                  lazaret.sanitize_term(e)), file=sys.stderr)
            return 3

    # audit H1: bundle.sources and generated_at are arbitrary strings in the
    # bundle JSON — sanitize both (the error text at OSError can carry the
    # same hostile path fragments).
    print("\n  CVE bundle: %d advisories (%s) generated %s" % (
        bundle.counts.get("advisories", 0),
        lazaret.sanitize_term(", ".join(bundle.sources)),
        lazaret.sanitize_term(bundle.generated_at)))
    age = bundle_age_days(bundle.generated_at)
    if age is not None and args.max_age > 0 and age > args.max_age:
        print("  WARNING: bundle is %d days old (max %d) — new CVEs/KEV entries since the "
              "export are invisible to this scan. Re-export from Redline "
              "(packages/vulndb/src/export-bundle.ts)." % (age, args.max_age), file=sys.stderr)
    print("  matches:    %d affected · %d unknown-version" % (len(matches), len(unknown)))
    gate = " PASSED " if res["pass"] else " FAILED "
    print("\n  Quality gate: %s" % gate)
    for cond in res["conditions"]:
        print("    %s %s" % ("✓" if cond["ok"] else "✗", cond["label"]))
    if json_path:
        print("\n  JSON report: %s" % lazaret.sanitize_term(json_path))
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
            if d.get("epss") is not None:
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
