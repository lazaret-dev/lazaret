#!/usr/bin/env python3
"""Unit tests — Lazaret SCA dependency CVE scanner (card "Identify CVE Scanning
Features"). Pure-function tests for the version engine (ported from Redline
version-range.ts), name normalization, the bundle index, the inventory scanners
and the match/severity machinery — plus an end-to-end scan of a fixture project
against a synthetic CVE bundle.

Run:  python3 lazaret/test_sca.py [unittest-args]

Fixtures:
    testproj_sca/           a tiny installed code base (npm + pypi)
    cve-bundle.test.json    a synthetic Redline export (bundleVersion 1)

Acceptance covered:
    - npm + pypi inventory from node_modules, locks, manifests, dist-info
    - version range membership incl. pre-release and exclusive bounds
    - affected / not-affected / unknown verdicts (no false clear)
    - KEV => BLOCKER; CVSS tiers; SCA issue dict matches lazaret.mk_issue keys
    - quality-gate conditions and the result dict shape
"""
import datetime
import json
import os

from tests import _support  # noqa: E402
import shutil
import sys
import tempfile
import unittest


from lazaret.scanner import sca as sca  # noqa: E402

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Version engine — parity with redline/packages/core/src/version-range.ts
# ---------------------------------------------------------------------------

class TestVersionEngine(unittest.TestCase):
    def test_compare_basic(self):
        self.assertEqual(sca.compare_versions("1.2.3", "1.2.4"), -1)
        self.assertEqual(sca.compare_versions("1.2.4", "1.2.3"), 1)
        self.assertEqual(sca.compare_versions("1.2", "1.2.0"), 0)

    def test_compare_trailing_zero(self):
        self.assertEqual(sca.compare_versions("6.9", "6.9.0"), 0)
        self.assertEqual(sca.compare_versions("6.9", "6.9.1"), -1)

    def test_compare_prerelease_below_release(self):
        self.assertEqual(sca.compare_versions("1.2.3-beta", "1.2.3"), -1)
        self.assertEqual(sca.compare_versions("1.2.3", "1.2.3-beta"), 1)

    def test_compare_prerelease_lexical(self):
        self.assertEqual(sca.compare_versions("1.2.3-alpha", "1.2.3-beta"), -1)
        self.assertEqual(sca.compare_versions("1.2.3-beta", "1.2.3-alpha"), 1)

    def test_compare_v_prefix_and_case(self):
        self.assertEqual(sca.compare_versions("v2.0.0", "2.0.0"), 0)
        self.assertEqual(sca.compare_versions("V2.0.0", "2.0.0"), 0)

    def test_is_comparable(self):
        self.assertTrue(sca.is_comparable_version("1.2.3"))
        self.assertTrue(sca.is_comparable_version("v1.2"))
        self.assertFalse(sca.is_comparable_version("beta"))
        self.assertFalse(sca.is_comparable_version("*"))
        self.assertFalse(sca.is_comparable_version("1"))       # needs a dot — parity with TS

    def test_unbounded(self):
        for b in (None, "", "*"):
            self.assertTrue(sca.unbounded(b))
        self.assertFalse(sca.unbounded("1.0.0"))

    def test_range_membership_inclusive(self):
        r = {"fromVersion": "1.0.0", "fromInclusive": True, "toVersion": "2.0.0", "toInclusive": True}
        self.assertTrue(sca.version_in_range("1.0.0", r))
        self.assertTrue(sca.version_in_range("1.5.0", r))
        self.assertTrue(sca.version_in_range("2.0.0", r))
        self.assertFalse(sca.version_in_range("2.0.1", r))
        self.assertFalse(sca.version_in_range("0.9.9", r))

    def test_range_membership_exclusive(self):
        r = {"fromVersion": "8.14.2", "fromInclusive": True, "toVersion": "8.17.1", "toInclusive": False}
        self.assertTrue(sca.version_in_range("8.17.0", r))
        self.assertFalse(sca.version_in_range("8.17.1", r))
        self.assertTrue(sca.version_in_range("8.14.2", r))

    def test_range_membership_unbounded_sides(self):
        r = {"fromVersion": "*", "fromInclusive": True, "toVersion": "0.11.0", "toInclusive": False}
        self.assertTrue(sca.version_in_range("0.10.1", r))
        self.assertFalse(sca.version_in_range("0.11.0", r))
        r2 = {"fromVersion": "4.0.0", "fromInclusive": False, "toVersion": "*", "toInclusive": True}
        self.assertTrue(sca.version_in_range("4.0.1", r2))
        self.assertFalse(sca.version_in_range("4.0.0", r2))

    def test_range_membership_rejects_non_comparable_version(self):
        r = {"fromVersion": "*", "fromInclusive": True, "toVersion": "2.0.0", "toInclusive": True}
        self.assertFalse(sca.version_in_range("latest", r))
        self.assertFalse(sca.version_in_range("", r))

    def test_format_range(self):
        r = {"fromVersion": "1.0.0", "fromInclusive": True, "toVersion": "2.0.0", "toInclusive": False}
        self.assertEqual(sca.format_range(r), ">=1.0.0 <2.0.0")
        self.assertEqual(sca.format_range({"fromVersion": "*", "toVersion": "*"}), "all versions")


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------

class TestNormalize(unittest.TestCase):
    def test_scoped_npm_folds_to_scope_name(self):
        # '@babel/core' -> 'babel-core' (scoped names never collide with a plain 'core')
        self.assertEqual(sca.normalize_pkg("@babel/core", "npm"), "babel-core")
        self.assertEqual(sca.normalize_pkg("@babel/core"), "babel-core")

    def test_separators_fold(self):
        self.assertEqual(sca.normalize_pkg("Foo_Bar"), "foo-bar")
        self.assertEqual(sca.normalize_pkg("foo.bar"), "foo-bar")

    def test_pypi_prefixes(self):
        self.assertEqual(sca.normalize_pkg("python-requests", "pypi"), "requests")
        self.assertEqual(sca.normalize_pkg("py-zbar", "pypi"), "zbar")
        self.assertEqual(sca.normalize_pkg("mysql-python", "pypi"), "mysql")

    def test_name_variants_cover_both_spellings(self):
        # an npm scoped dep finds a CPE entry recorded unscoped
        v = sca.name_variants("@babel/core", "npm")
        self.assertIn("babel-core", v)
        self.assertIn("core", v)
        # a pypi dep finds a CPE entry recorded 'python-<name>'
        v2 = sca.name_variants("urllib3", "pypi")
        self.assertIn("urllib3", v2)
        self.assertIn("python-urllib3", v2)

    def test_bundle_index_finds_scoped_entry_from_cpe_product(self):
        bundle = sca.CveBundle({"bundleVersion": 1, "advisories": [{
            "cve": "CVE-1", "packages": [
                {"name": "babel-core", "ecosystem": "npm", "ranges": []}]}]})
        self.assertEqual(len(bundle.advisories_for("babel-core", "npm")), 1)
        self.assertEqual(len(bundle.advisories_for("@babel/core", "npm")), 1)


# ---------------------------------------------------------------------------
# Bundle loading + index
# ---------------------------------------------------------------------------

BUNDLE_DOC = {
    "bundleVersion": 1,
    "generator": "redline-vulndb-export",
    "generatedAt": None,  # set to "now" at module import (see below) so the
                          # freshness fixture never goes stale with the calendar
    "sources": ["nvd", "cisa-kev"],
    "counts": {"advisories": 3, "packages": 3, "withRanges": 3, "knownExploited": 1},
    "advisories": [
        {
            "cve": "CVE-2024-48888", "title": "ws Denial of Service", "description": "d",
            "severity": "high", "cvss": 7.5, "cwes": ["CWE-400"], "knownExploited": False,
            "ransomware": False, "dueDate": None, "epss": 0.1, "epssPercentile": 0.55,
            "published": "2024-10-14", "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-48888"],
            "sources": ["nvd"], "packages": [
                {"name": "ws", "vendor": "wsjs", "ecosystem": "npm", "ranges": [
                    {"fromVersion": "8.0.0", "fromInclusive": True, "toVersion": "8.17.1", "toInclusive": False}]},
            ],
        },
        {
            "cve": "CVE-2023-36188", "title": "Ada URL parser", "description": "d",
            "severity": "critical", "cvss": 9.8, "cwes": ["CWE-125"], "knownExploited": True,
            "ransomware": True, "dueDate": "2023-09-01", "epss": 0.9, "epssPercentile": 0.96,
            "published": "2023-07-01", "refs": ["https://kev"], "sources": ["nvd", "cisa-kev"],
            "packages": [
                {"name": "ada-url", "vendor": "ada", "ecosystem": "npm", "ranges": [
                    {"fromVersion": "2.0.0", "fromInclusive": True, "toVersion": "2.9.0", "toInclusive": False}]},
            ],
        },
        {
            "cve": "CVE-2023-43804", "title": "urllib3 header leakage", "description": "d",
            "severity": "high", "cvss": 7.5, "cwes": ["CWE-200"], "knownExploited": False,
            "ransomware": False, "dueDate": None, "epss": None, "epssPercentile": None,
            "published": "2023-10-10", "refs": [], "sources": ["nvd"],
            "packages": [
                {"name": "python-urllib3", "vendor": "python", "ecosystem": "pypi", "ranges": [
                    {"fromVersion": "2.0.0", "fromInclusive": True, "toVersion": "2.0.7", "toInclusive": False}]},
                {"name": "requests", "vendor": "python", "ecosystem": "pypi", "ranges": []},
            ],
        },
    ],
}

# generatedAt "now" (in UTC, same wire format the real bundles use) so the
# freshness fixture is deterministic regardless of when the suite runs.
BUNDLE_DOC["generatedAt"] = datetime.datetime.now(datetime.timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ")


class TestBundle(unittest.TestCase):
    def setUp(self):
        self.bundle = sca.CveBundle(BUNDLE_DOC)

    def test_load_rejects_wrong_shape(self):
        with self.assertRaises(ValueError):
            sca.CveBundle({"bundleVersion": 2})
        with self.assertRaises(ValueError):
            sca.CveBundle([])

    def test_index_normalizes_names(self):
        found = self.bundle.advisories_for("python-urllib3", "pypi")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0]["cve"], "CVE-2023-43804")
        # the pypi prefix strip means a pypi 'urllib3' install also matches the same entry
        found2 = self.bundle.advisories_for("urllib3", "pypi")
        self.assertEqual(len(found2), 1)

    def test_missing_name_is_empty(self):
        self.assertEqual(self.bundle.advisories_for("no-such-package"), [])


# ---------------------------------------------------------------------------
# Fixtures — a tiny installed code base
# ---------------------------------------------------------------------------

FIXTURE = "testproj_sca"


def make_fixture(tmp):
    root = os.path.join(tmp, FIXTURE)
    # npm installed: ws@8.14.2 (vulnerable), lodash@4.17.21 (patched, no advisory)
    write(os.path.join(root, "node_modules", "ws", "package.json"),
          json.dumps({"name": "ws", "version": "8.14.2"}))
    write(os.path.join(root, "node_modules", "lodash", "package.json"),
          json.dumps({"name": "lodash", "version": "4.17.21"}))
    # npm scoped package installed
    write(os.path.join(root, "node_modules", "@types", "node", "package.json"),
          json.dumps({"name": "@types/node", "version": "20.1.0"}))
    # package.json declared with a range spec (^) — recorded unresolvable
    write(os.path.join(root, "package.json"),
          json.dumps({"name": "app", "dependencies": {"ws": "^8.14.2", "lodash": "4.17.21"}}))
    # lock pins ws@8.14.2
    write(os.path.join(root, "package-lock.json"),
          json.dumps({"lockfileVersion": 3, "packages": {
              "node_modules/ws": {"name": "ws", "version": "8.14.2"},
              "node_modules/lodash": {"name": "lodash", "version": "4.17.21"}}}))
    # pypi installed: urllib3@2.0.6 (vulnerable), requests@2.31.0 (unknown-version row)
    write(os.path.join(root, "venv", "lib", "python3.10", "site-packages", "urllib3-2.0.6.dist-info", "METADATA"),
          "Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.6\n")
    write(os.path.join(root, "venv", "lib", "python3.10", "site-packages", "requests-2.31.0.dist-info", "METADATA"),
          "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
    # declared pypi pins
    write(os.path.join(root, "requirements.txt"),
          "requests==2.31.0\nurllib3==2.0.6\n# comment\nflask>=1.0\n")
    return root


class TestInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cg_sca_")
        cls.root = make_fixture(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_npm_installed_found(self):
        inv = sca.scan_npm_installed(self.root)
        names = {(n, v) for e, n, v, w in inv}
        self.assertIn(("ws", "8.14.2"), names)
        self.assertIn(("lodash", "4.17.21"), names)
        self.assertIn(("@types/node", "20.1.0"), names)

    def test_npm_lock_found(self):
        inv = sca.scan_npm_lock(self.root)
        names = {(n, v) for e, n, v, w in inv}
        self.assertIn(("ws", "8.14.2"), names)
        self.assertIn(("lodash", "4.17.21"), names)

    def test_npm_declared_range_is_unresolvable(self):
        inv = sca.scan_npm_declared(self.root)
        ws = [(n, v, w) for e, n, v, w in inv if n == "ws"]
        # '^8.14.2' is a range: recorded with an empty version so matching reports
        # version-unknown rather than silently clearing
        self.assertEqual(ws, [("ws", "", "package.json(dependencies) unresolvable:^8.14.2")])

    def test_pypi_installed_from_venv(self):
        inv = sca.scan_pypi_installed(self.root)
        names = {(n, v) for e, n, v, w in inv}
        self.assertIn(("urllib3", "2.0.6"), names)
        self.assertIn(("requests", "2.31.0"), names)

    def test_pypi_declared_requirements_pins(self):
        inv = sca.scan_pypi_declared(self.root)
        names = {(n, v) for e, n, v, w in inv}
        self.assertIn(("requests", "2.31.0"), names)
        self.assertIn(("urllib3", "2.0.6"), names)
        self.assertNotIn(("flask", "1.0"), names)     # >= spec is not a pin
        flask = [(n, v) for e, n, v, w in inv if n == "flask"]
        self.assertEqual(flask, [("flask", "")])       # recorded unresolvable, not version 1.0

    def test_dedup_keeps_first_where(self):
        inv = sca.scan_all(self.root)
        seen = [x for x in inv if x[1] == "ws"]
        self.assertEqual(len(seen), 1)                # node_modules wins (scanned first)
        self.assertTrue(seen[0][3].startswith("node_modules"))


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

class TestMatch(unittest.TestCase):
    def setUp(self):
        self.bundle = sca.CveBundle(BUNDLE_DOC)

    def test_affected_match(self):
        inv = sca.Inventory([("npm", "ws", "8.14.2", "node_modules/ws")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        self.assertEqual(len(matches), 1)
        adv, pkg, dep, hit = matches[0]
        self.assertEqual(adv["cve"], "CVE-2024-48888")
        self.assertEqual(hit["toVersion"], "8.17.1")

    def test_not_affected_silent(self):
        inv = sca.Inventory([("npm", "ws", "8.17.1", "node_modules/ws")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        self.assertEqual(len(matches), 0)
        self.assertEqual(len(unknown), 0)

    def test_no_ranges_yields_unknown_not_clear(self):
        inv = sca.Inventory([("pypi", "requests", "2.31.0", "requirements.txt")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        self.assertEqual(len(matches), 0)
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0][1]["cve"], "CVE-2023-43804")

    def test_pypi_prefix_advisory_matches_pypi_install(self):
        inv = sca.Inventory([("pypi", "urllib3", "2.0.6", "site-packages")])
        matches, _ = sca.match_inventory(inv, self.bundle)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0]["cve"], "CVE-2023-43804")

    def test_kev_match(self):
        inv = sca.Inventory([("npm", "ada-url", "2.7.4", "node_modules/ada-url")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0]["knownExploited"], True)

    def test_same_cve_different_package_not_duplicated(self):
        inv = sca.Inventory([("pypi", "urllib3", "2.0.6", "a"), ("pypi", "urllib3", "2.0.6", "b")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        # dedup by (cve, pkg, version): one match reported, not two
        self.assertEqual(len(matches), 1)


# ---------------------------------------------------------------------------
# Findings + result shape
# ---------------------------------------------------------------------------

class TestFindings(unittest.TestCase):
    def setUp(self):
        self.bundle = sca.CveBundle(BUNDLE_DOC)

    def mk_issue_for(self, rule_key, dep, adv, pkg, hit=None):
        rule = sca.SCA_RULES[rule_key]
        return sca.mk_sca_issue(rule, dep, adv, pkg, matched_range=hit)

    def test_issue_has_lazaret_shape(self):
        inv = sca.Inventory([("npm", "ws", "8.14.2", "node_modules/ws")])
        matches, _ = sca.match_inventory(inv, self.bundle)
        adv, pkg, dep, hit = matches[0]
        i = self.mk_issue_for("SCA-CVE", dep, adv, pkg, hit)
        for key in ("rule", "name", "type", "sev", "msg", "why", "fix", "ref", "file", "line", "snippet", "snipStart"):
            self.assertIn(key, i, "issue dict missing lazaret key %s" % key)
        self.assertEqual(i["type"], "VULN")
        self.assertEqual(i["detail"]["cve"], "CVE-2024-48888")
        self.assertEqual(i["detail"]["package"], "ws")
        self.assertEqual(i["detail"]["installed"], "8.14.2")
        self.assertEqual(i["detail"]["matchedRange"], ">=8.0.0 <8.17.1")

    def test_severity_kev_blocker(self):
        inv = sca.Inventory([("npm", "ada-url", "2.7.4", "node_modules/ada-url")])
        matches, _ = sca.match_inventory(inv, self.bundle)
        adv, pkg, dep, hit = matches[0]
        i = self.mk_issue_for("SCA-CVE-KEV" if adv["knownExploited"] else "SCA-CVE", dep, adv, pkg, hit)
        self.assertEqual(i["sev"], "BLOCKER")

    def test_severity_cvss_critical_major_minor(self):
        self.assertEqual(sca.severity_of({"cvss": 9.8}), "CRITICAL")
        self.assertEqual(sca.severity_of({"cvss": 7.5}), "MAJOR")
        self.assertEqual(sca.severity_of({"cvss": 3.1}), "MINOR")
        self.assertEqual(sca.severity_of({"severity": "high"}), "MAJOR")
        self.assertEqual(sca.severity_of({}), "MINOR")
        self.assertEqual(sca.severity_of({"knownExploited": True}), "BLOCKER")

    def test_fix_hint_exclusive_upper_bound(self):
        adv = {"knownExploited": False}
        pkg = {"ranges": [{"fromVersion": "8.0.0", "fromInclusive": True,
                           "toVersion": "8.17.1", "toInclusive": False}]}
        self.assertEqual(sca.fix_hint(adv, pkg), "Upgrade to >= 8.17.1")

    def test_fix_hint_inclusive_only_falls_back_to_refs(self):
        adv = {"knownExploited": False, "refs": ["https://x"]}
        pkg = {"ranges": [{"fromVersion": "1.0.0", "fromInclusive": True,
                           "toVersion": "2.0.0", "toInclusive": True}]}
        self.assertIn("advisory references", sca.fix_hint(adv, pkg))

    def test_result_dict_shape(self):
        inv = sca.Inventory([("npm", "ws", "8.14.2", "node_modules/ws")])
        matches, unknown = sca.match_inventory(inv, self.bundle)
        issues = [self.mk_issue_for("SCA-CVE", dep, adv, pkg, hit) for adv, pkg, dep, hit in matches]
        res = sca.build_sca_result("/tmp/proj", self.bundle, issues, inv, {"npm": 1, "pypi": 0})
        for key in ("project", "scannedAt", "pass", "conditions", "metrics", "counts", "ratings", "perFile", "issues"):
            self.assertIn(key, res)
        self.assertEqual(res["metrics"]["npmDeps"], 1)
        self.assertTrue(any(c["label"] == "No vulnerable dependencies" for c in res["conditions"]))
        self.assertFalse(res["pass"])       # the ws match fails the gate
        # freshness: fixture bundle is generated "now" so it passes by default
        self.assertTrue(any(c["label"].startswith("CVE bundle fresh") and c["ok"] for c in res["conditions"]))
        self.assertEqual(res["metrics"]["bundleAgeDays"], 0)

    def test_stale_bundle_fails_freshness_gate(self):
        stale = sca.CveBundle({**BUNDLE_DOC, "generatedAt": "2020-01-01T00:00:00Z"})
        res = sca.build_sca_result("/tmp/proj", stale, [], sca.Inventory(), {}, max_age=7)
        fresh = [c for c in res["conditions"] if c["label"].startswith("CVE bundle fresh")]
        self.assertEqual(len(fresh), 1)
        self.assertFalse(fresh[0]["ok"])
        self.assertGreaterEqual(res["metrics"]["bundleAgeDays"], 2000)

    def test_max_age_zero_disables_freshness_gate(self):
        stale = sca.CveBundle({**BUNDLE_DOC, "generatedAt": "2020-01-01T00:00:00Z"})
        res = sca.build_sca_result("/tmp/proj", stale, [], sca.Inventory(), {}, max_age=0)
        fresh = [c for c in res["conditions"] if c["label"].startswith("CVE bundle fresh")]
        self.assertTrue(fresh[0]["ok"])

    def test_missing_generated_at_is_not_a_failure(self):
        undated = sca.CveBundle({**BUNDLE_DOC, "generatedAt": None})
        res = sca.build_sca_result("/tmp/proj", undated, [], sca.Inventory(), {})
        fresh = [c for c in res["conditions"] if c["label"].startswith("CVE bundle fresh")]
        self.assertTrue(fresh[0]["ok"])     # unknown age does not fail the gate

    def test_bundle_age_days_parses_iso_z(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.assertEqual(sca.bundle_age_days(now), 0)
        self.assertIsNone(sca.bundle_age_days(None))
        self.assertIsNone(sca.bundle_age_days("not a date"))


# ---------------------------------------------------------------------------
# End-to-end — fixture project + synthetic bundle through main()
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cg_sca_e2e_")
        cls.root = make_fixture(cls.tmp)
        cls.bundle_path = os.path.join(cls.tmp, "cve-bundle.test.json")
        with open(cls.bundle_path, "w", encoding="utf-8") as f:
            json.dump(BUNDLE_DOC, f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, extra=None):
        argv = [self.root, "--bundle", self.bundle_path, "--no-json", "-q"] + (extra or [])
        rc = sca.main(argv)
        return rc

    def test_scan_finds_installed_vulnerable_deps(self):
        # ws@8.14.2 affected; urllib3@2.0.6 affected; requests has an advisory with NO
        # ranges -> unknown; lodash patched + absent from bundle -> silent
        inv = sca.scan_all(self.root)
        matches, unknown = sca.match_inventory(inv, sca.CveBundle(BUNDLE_DOC))
        self.assertEqual({m[0]["cve"] for m in matches}, {"CVE-2024-48888", "CVE-2023-43804"})
        self.assertEqual({u[1]["cve"] for u in unknown}, {"CVE-2023-43804"})
        rc = self._run()
        self.assertEqual(rc, 0)        # gate fails but --ci not passed -> 0
        # the JSON report default write also happens without --no-json; we used --no-json

    def test_ci_exit_code_when_gate_fails(self):
        rc = self._run(["--ci"])
        self.assertEqual(rc, 1)

    def test_json_report_written(self):
        out = os.path.join(self.tmp, "out.json")
        rc = sca.main([self.root, "--bundle", self.bundle_path, "--json", out, "-q"])
        self.assertEqual(rc, 0)
        with open(out, "r", encoding="utf-8") as f:
            res = json.load(f)
        self.assertTrue(res["sca"])
        rules = {i["rule"] for i in res["issues"]}
        self.assertIn("SCA-CVE", rules)
        # ws and urllib3 both matched; requests unknown
        self.assertEqual(len(res["issues"]), 3)
        cves = {i["detail"]["cve"] for i in res["issues"]}
        self.assertEqual(cves, {"CVE-2024-48888", "CVE-2023-43804"})

    def test_inventory_only_lists_modules(self):
        rc = sca.main([self.root, "--bundle", self.bundle_path, "--inventory-only"])
        self.assertEqual(rc, 0)

    def test_missing_directory_is_usage_error(self):
        rc = sca.main(["/no/such/dir", "--bundle", self.bundle_path])
        self.assertEqual(rc, 2)

    def test_bad_bundle_is_exit_4(self):
        bad = os.path.join(self.tmp, "bad.json")
        write(bad, "not json")
        rc = sca.main([self.root, "--bundle", bad, "-q"])
        self.assertEqual(rc, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
