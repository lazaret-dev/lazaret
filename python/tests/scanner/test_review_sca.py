"""Review findings 3 and 14-20 — lazaret-sca.

 3  the JSON report was written with plain open(): a committed
    `lazaret-sca.json -> ../victim_home/.bashrc` symlink got .bashrc
    overwritten.
14  version comparison treated everything after the numeric head as a string
    (1.0.post1 < 1.0, beta.10 < beta.9, 2.0.1+cu118 < 2.0.1, epochs ignored).
15  non-comparable versions/bounds ('*', '2.*', single-segment '5', git refs)
    were silently "not affected".
16  nested npm versions were lost (lock v2/v3 and v1, nested node_modules,
    one version per name).
17  PyPI inventory missed poetry.lock (read as JSON), PEP 621 arrays, extras,
    bare names, -r/-c includes and requirements/*.txt.
18  @types/lodash matched lodash CVEs; no PEP 503 normalization.
19  malformed lockfiles/bundles crashed; freshness failed OPEN.
20  CLI parity: --baseline/--html/--sarif, the provenance marker, yarn.lock
    and pnpm-lock.yaml.

All fixtures are inert manifest/lock text and synthetic CVE ids.
"""
import datetime
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from lazaret.scanner import reports, sca

NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def adv(cve, name, eco, to, cvss=9.8, frm="*", to_inc=False):
    return {"cve": cve, "title": cve.lower(), "cvss": cvss, "packages": [
        {"name": name, "ecosystem": eco, "ranges": [
            {"fromVersion": frm, "fromInclusive": True, "toVersion": to, "toInclusive": to_inc}]}]}


BUNDLE = {"bundleVersion": 1, "generatedAt": NOW, "sources": ["test"], "advisories": [
    adv("CVE-TEST-REQ", "requests", "pypi", "2.20.0"),
    adv("CVE-TEST-DJ", "django", "pypi", "3.2.0"),
    adv("CVE-TEST-FLASK", "flask", "pypi", "2.0.0"),
    adv("CVE-TEST-LODASH", "lodash", "npm", "4.17.21"),
    adv("CVE-TEST-ZZZ", "zzz", "npm", "1.0.0", cvss=5),
]}


class Tmp(unittest.TestCase):
    def mk(self, files, bundle=None):
        root = tempfile.mkdtemp(prefix="lz-review-sca-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, content in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content if isinstance(content, str) else json.dumps(content))
        return root

    def bundle_file(self, doc=None, text=None):
        d = tempfile.mkdtemp(prefix="lz-review-bundle-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "b.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if text is not None else json.dumps(doc or BUNDLE))
        return path

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sca.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def inv(self, root):
        return sorted((e, n, v) for e, n, v, w in sca.scan_all(root))

    def verdicts(self, root, doc=None):
        inv = sca.scan_all(root)
        matches, unknown = sca.match_inventory(inv, sca.CveBundle(doc or BUNDLE))
        return (sorted((m[2][1], m[2][2], m[0]["cve"]) for m in matches),
                sorted((u[0][1], u[1]["cve"]) for u in unknown))


# ---------------------------------------------------------------------------
# 14. version semantics
# ---------------------------------------------------------------------------
PEP440_ORDER = [
    "0!0.9", "1.0.dev0", "1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0b2.post1",
    "1.0rc1", "1.0rc9", "1.0rc10", "1.0", "1.0+local", "1.0+local.2", "1.0.post1.dev1",
    "1.0.post1", "1.0.post2", "1.0.1", "1.1a1", "1.1", "2.0.1", "2.0.1+cu118", "10.0", "1!0.5",
]
SEMVER_ORDER = [
    "0.9.9", "1.0.0-0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
    "1.0.0-beta.2", "1.0.0-beta.9", "1.0.0-beta.10", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
    "1.0.1", "1.2.0", "1.10.0", "2.0.0-rc.1", "2.0.0",
]


class VersionSemantics(unittest.TestCase):
    def check_order(self, order, eco):
        for i, a in enumerate(order):
            for j, b in enumerate(order):
                want = (i > j) - (i < j)
                self.assertEqual(sca.compare_versions(a, b, eco), want, f"{a} vs {b} ({eco})")

    def test_pep440_total_order(self):
        self.check_order(PEP440_ORDER, "pypi")

    def test_semver_total_order(self):
        self.check_order(SEMVER_ORDER, "npm")

    def test_equalities(self):
        for a, b, eco in (("1.0", "1.0.0", "pypi"), ("V1.2", "1.2", "pypi"), ("1.0.0+build.5", "1.0.0", "npm"),
                          ("v2.0.0", "2.0.0", "npm"), ("1.0-1", "1.0.post1", "pypi"),
                          ("1.0.0-alpha", "1.0.0alpha", "pypi"), ("1.0RC1", "1.0rc1", "pypi")):
            with self.subTest(a=a, b=b):
                self.assertEqual(sca.compare_versions(a, b, eco), 0)

    def test_reviewer_table_with_ecosystems(self):
        """t_ver.py rows, each under its own ecosystem's rules."""
        rows = [("1.0", "1.0.0", 0, "pypi"), ("1.0.post1", "1.0", 1, "pypi"),
                ("1.0.dev1", "1.0a1", -1, "pypi"), ("1.0rc10", "1.0rc9", 1, "pypi"),
                ("1!0.5", "2.0", 1, "pypi"), ("1.0+local", "1.0", 1, "pypi"),
                ("2.0.1+cu118", "2.0.1", 1, "pypi"), ("1.0.0-beta.10", "1.0.0-beta.9", 1, "npm"),
                ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1, "npm"), ("1.0.0+build.5", "1.0.0", 0, "npm"),
                ("1.0.0-rc.1", "1.0.0", -1, "npm"), ("1.0a1", "1.0b1", -1, "pypi"),
                ("1.0b1", "1.0rc1", -1, "pypi"), ("1.0.0", "1.0.0-0", 1, "npm"), ("V1.2", "1.2", 0, "pypi")]
        for a, b, want, eco in rows:
            with self.subTest(a=a, b=b):
                self.assertEqual(sca.compare_versions(a, b, eco), want)

    def test_default_scheme_without_ecosystem(self):
        self.assertEqual(sca.compare_versions("1.0.0-beta.10", "1.0.0-beta.9"), 1)   # '-': semver
        self.assertEqual(sca.compare_versions("1.0.post1", "1.0"), 1)               # else PEP 440
        self.assertEqual(sca.compare_versions("1.0.0", "1.0.0-0"), 1)

    def test_range_membership(self):
        R = lambda lo, hi, hi_inc=False: {"fromVersion": lo, "fromInclusive": True,
                                          "toVersion": hi, "toInclusive": hi_inc}
        rows = [("2.0.0-rc.9", R("*", "2.0.0-rc.10"), True, "npm"),
                ("1.2.3", R("*", "1.2.3.post1"), True, "pypi"),
                ("1.2.3+cu118", R("1.2.3", "1.2.5"), True, "pypi"),
                ("1.2.3+cu118", R("*", "1.2.3", hi_inc=True), True, "pypi"),   # pip: <=1.2.3
                ("1.2.3+build", R("1.2.3", "1.2.5"), True, "npm"),
                ("5", R("*", "6"), True, "pypi"), ("4.2", R("*", "5"), True, "npm"),
                ("1!1.0", R("*", "1!2.0"), True, "pypi"), ("2.0rc1", R("*", "2.0"), True, "pypi"),
                ("2.0", R("*", "2.0"), False, "pypi"), ("1.0.post1", R("*", "1.0", True), False, "pypi")]
        for v, r, want, eco in rows:
            with self.subTest(v=v, r=r):
                self.assertIs(sca.version_in_range(v, r, eco), want)


# ---------------------------------------------------------------------------
# 15. non-comparable -> unknown, never "not affected"
# ---------------------------------------------------------------------------
class NonComparable(Tmp):
    def test_wildcards_are_unknown(self):
        """Reviewer repro p_star: requests="*", django="2.*" -> PASSED."""
        root = self.mk({"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.10"\n'
                                          'requests = "*"\ndjango = "2.*"\n'})
        rc, out, _ = self.main(root, "--bundle", self.bundle_file(), "--no-json", "--ci")
        self.assertEqual(rc, 1)
        self.assertIn("2 unknown-version", out)
        self.assertIn("FAILED", out)

    def test_single_segment_git_ref_and_wildcard_bound(self):
        self.assertIs(sca.version_in_range("5", {"toVersion": "6", "toInclusive": False}, "pypi"), True)
        self.assertIsNone(sca.version_in_range("a1b2c3d", {"toVersion": "6"}, "npm"))
        self.assertIsNone(sca.version_in_range("1.0", {"toVersion": "2.*"}, "pypi"))
        self.assertIsNone(sca.version_in_range("1.0", "not-a-dict", "pypi"))
        doc = {"bundleVersion": 1, "generatedAt": NOW, "advisories": [
            adv("CVE-W", "lodash", "npm", "4.x")]}
        root = self.mk({"node_modules/lodash/package.json": {"name": "lodash", "version": "4.17.11"}})
        matches, unknown = self.verdicts(root, doc)
        self.assertEqual((matches, unknown), ([], [("lodash", "CVE-W")]))


# ---------------------------------------------------------------------------
# 16. nested npm versions
# ---------------------------------------------------------------------------
class NpmInventory(Tmp):
    def test_lock_v3_nested(self):
        root = self.mk({"package-lock.json": {"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/foo/node_modules/lodash": {"version": "4.17.11"},
            "node_modules/@s/bar/node_modules/@s/baz": {"version": "2.0.0"},
            "node_modules/aliased": {"name": "zzz", "version": "0.9.0"},
            "node_modules/linked": {"resolved": "packages/linked", "link": True},
            "packages/linked": {"name": "linked", "version": "0.0.1"},
            "node_modules/gitdep": {"version": "git+https://example.invalid/x.git#abc"}}}})
        inv = self.inv(root)
        self.assertIn(("npm", "lodash", "4.17.11"), inv)
        self.assertIn(("npm", "lodash", "4.17.21"), inv)
        self.assertIn(("npm", "@s/baz", "2.0.0"), inv)
        self.assertIn(("npm", "zzz", "0.9.0"), inv)             # alias -> real package
        self.assertIn(("npm", "gitdep", ""), inv)               # git: unknown version
        self.assertNotIn("linked", [n for _, n, _ in inv])      # workspace link: first-party
        matches, unknown = self.verdicts(root)
        self.assertEqual(matches, [("lodash", "4.17.11", "CVE-TEST-LODASH"), ("zzz", "0.9.0", "CVE-TEST-ZZZ")])

    def test_lock_v1_nested_and_malformed(self):
        root = self.mk({"package-lock.json": {"lockfileVersion": 1, "dependencies": {
            "lodash": {"version": "4.17.21"},
            "foo": {"version": "1.0.0", "dependencies": {"lodash": {"version": "4.17.11"}}},
            "weird": "1.0.0",
            "al": {"version": "npm:zzz@0.5.0"}}}})
        inv = self.inv(root)
        self.assertIn(("npm", "lodash", "4.17.11"), inv)
        self.assertIn(("npm", "weird", ""), inv)
        self.assertIn(("npm", "zzz", "0.5.0"), inv)
        w = sca._Warnings()
        sca.scan_npm_lock(root, w)
        self.assertEqual(w.counts, {"malformed npm lockfile entries": 1})

    def test_nested_node_modules_dirs(self):
        root = self.mk({"node_modules/lodash/package.json": {"name": "lodash", "version": "4.17.21"},
                        "node_modules/foo/package.json": {"name": "foo", "version": "1.0.0"},
                        "node_modules/foo/node_modules/lodash/package.json": {"name": "lodash", "version": "4.17.11"},
                        "node_modules/@s/p/node_modules/q/package.json": {"name": "q", "version": "1.0.0"},
                        "node_modules/@s/p/package.json": {"name": "@s/p", "version": "1.0.0"}})
        found = {(n, v, w) for e, n, v, w in sca.scan_npm_installed(root)}
        self.assertIn(("lodash", "4.17.11", "node_modules/foo/node_modules/lodash/package.json"), found)
        self.assertIn(("q", "1.0.0", "node_modules/@s/p/node_modules/q/package.json"), found)
        self.assertEqual(self.verdicts(root)[0], [("lodash", "4.17.11", "CVE-TEST-LODASH")])

    def test_declared_specs(self):
        root = self.mk({"package.json": {"dependencies": {
            "lodash": "4.17.11", "a": "^1.0.0", "b": "*", "c": "latest", "d": "1.2",
            "zz": "npm:zzz@0.1.0", "g": "github:user/repo", "f": "file:../x"},
            "workspaces": ["packages/*"]},
            "packages/w/package.json": {"name": "w", "dependencies": {"lodash": "4.17.10"}}})
        got = {(n, v) for e, n, v, w in sca.scan_npm_declared(root)}
        for want in (("lodash", "4.17.11"), ("a", ""), ("b", ""), ("c", ""), ("d", ""),
                     ("zzz", "0.1.0"), ("g", ""), ("f", ""), ("lodash", "4.17.10")):
            self.assertIn(want, got)

    def test_dedup_keeps_versions_and_drops_redundant_unknowns(self):
        inv = sca.Inventory([("npm", "lodash", "4.17.21", "a"), ("npm", "lodash", "4.17.11", "b"),
                             ("npm", "lodash", "", "c"), ("npm", "lodash", "4.17.21", "d"),
                             ("npm", "only-range", "", "e")])
        self.assertEqual(inv.dedup(), [("npm", "lodash", "4.17.21", "a"), ("npm", "lodash", "4.17.11", "b"),
                                       ("npm", "only-range", "", "e")])


# ---------------------------------------------------------------------------
# 17. PyPI inventory
# ---------------------------------------------------------------------------
POETRY_LOCK = ('[[package]]\nname = "requests"\nversion = "2.19.0"\ndescription = "HTTP"\n'
               'optional = false\npython-versions = "*"\n\n[package.dependencies]\n'
               'urllib3 = ">=1.21.1"\n\n[[package]]\nname = "django"\nversion = "2.2.0"\n\n'
               '[metadata]\nlock-version = "2.0"\ncontent-hash = "abc"\n\n[metadata.files]\n'
               'requests = [\n    {file = "requests-2.19.0.tar.gz", hash = "sha256:00"},\n]\n')
PYPROJECT = ('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = [\n'
             '    "requests==2.19.0",  # pinned\n    "django>=2.0,<3",\n    \'flask[async]==1.1.0 ; python_version > "3"\',\n]\n'
             '[project.optional-dependencies]\ndev = ["pytest"]\n'
             '[dependency-groups]\ntest = ["coverage==7.0", {include-group = "dev"}]\n'
             '[tool.poetry.dependencies]\npython = "^3.10"\nurllib3 = {version = "1.26.0", extras = ["socks"]}\n'
             'six = "^1.16"\n[tool.poetry.group.lint.dependencies]\nblack = "==23.1.0"\n')


class PypiInventory(Tmp):
    def test_poetry_lock_and_pep621(self):
        root = self.mk({"poetry.lock": POETRY_LOCK, "pyproject.toml": PYPROJECT})
        got = {(n, v) for e, n, v, w in sca.scan_pypi_declared(root)}
        for want in (("requests", "2.19.0"), ("django", "2.2.0"), ("django", ""), ("flask", "1.1.0"),
                     ("pytest", ""), ("coverage", "7.0"), ("urllib3", "1.26.0"), ("six", ""),
                     ("black", "23.1.0")):
            self.assertIn(want, got)
        self.assertNotIn("python", {n for n, _ in got})

    def test_toml_fallback_parser_on_every_version(self):
        with mock.patch.object(sca, "_tomllib", return_value=None):
            root = self.mk({"poetry.lock": POETRY_LOCK, "pyproject.toml": PYPROJECT})
            got = {(n, v) for e, n, v, w in sca.scan_pypi_declared(root)}
        self.assertIn(("requests", "2.19.0"), got)
        self.assertIn(("urllib3", "1.26.0"), got)
        lib = sca._tomllib()
        if lib is not None:        # the subset parser agrees with tomllib
            for text in (POETRY_LOCK, PYPROJECT):
                self.assertEqual(sca.toml_subset_loads(text), lib.loads(text))
        for bad in ("a = ", "[x\n", "a = [1,", "a = 'x\n", "a = 1\na = 2\n", "a = {b = }"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sca.toml_subset_loads(bad)

    def test_requirements_forms_and_includes(self):
        root = self.mk({
            "requirements.txt": ("requests[security]==2.19.0\nDjango\nflask[async] >= 1.0\n"
                                 "-r base.txt\n--constraint=cons.txt\n-r loop.txt\n"
                                 "-r ../../outside.txt\nnumpy==1.* \\\n  --hash=sha256:00\n"
                                 "-e git+https://example.invalid/r.git#egg=editpkg\n"
                                 "pkg @ https://example.invalid/pkg.whl\n"),
            "base.txt": "six==1.16.0  # comment\n",
            "cons.txt": "urllib3==1.26.0\n",
            "loop.txt": "-r requirements.txt\nidna==3.4\n",
            "requirements/prod.txt": "gunicorn==20.0.0\n"})
        got = {(n, v) for e, n, v, w in sca.scan_pypi_declared(root)}
        for want in (("requests", "2.19.0"), ("Django", ""), ("flask", ""), ("six", "1.16.0"),
                     ("urllib3", "1.26.0"), ("idna", "3.4"), ("numpy", ""), ("editpkg", ""),
                     ("pkg", ""), ("gunicorn", "20.0.0")):
            self.assertIn(want, got)

    def test_reviewer_fixtures(self):
        cases = {
            "requirements.txt": ("requests[security]==2.19.0\nDjango\nflask[async] >= 1.0\n",
                                 [("requests", "2.19.0", "CVE-TEST-REQ")],
                                 [("Django", "CVE-TEST-DJ"), ("flask", "CVE-TEST-FLASK")]),
            "requirements/prod.txt": ("requests==2.19.0\n", [("requests", "2.19.0", "CVE-TEST-REQ")], []),
        }
        for rel, (text, m, u) in cases.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.verdicts(self.mk({rel: text})), (m, u))

    def test_pep508_parser(self):
        P = sca.parse_pep508
        self.assertEqual(P("requests[security]==2.19.0")[:2], ("requests", "2.19.0"))
        self.assertEqual(P("Django")[:2], ("Django", ""))
        self.assertEqual(P("flask[async] >= 1.0")[:2], ("flask", ""))
        self.assertEqual(P('x==1.0; python_version < "3.8"')[:2], ("x", "1.0"))
        self.assertEqual(P("x==1.0,!=1.0.1")[:2], ("x", "1.0"))
        self.assertEqual(P("x (==1.0)")[:2], ("x", "1.0"))
        self.assertEqual(P("x==1.*")[:2], ("x", ""))
        self.assertIsNone(P("==1.0"))


# ---------------------------------------------------------------------------
# 18. names
# ---------------------------------------------------------------------------
class Names(Tmp):
    def test_types_package_does_not_match(self):
        root = self.mk({"node_modules/@types/lodash/package.json": {"name": "@types/lodash",
                                                                     "version": "4.14.195"}})
        self.assertEqual(self.verdicts(root), ([], []))

    def test_pep503_normalization(self):
        self.assertEqual(sca.normalize_pkg("Foo__Bar..baz", "pypi"), "foo-bar-baz")
        doc = {"bundleVersion": 1, "generatedAt": NOW, "advisories": [adv("CVE-N", "zope.interface", "pypi", "6.0")]}
        b = sca.CveBundle(doc)
        self.assertEqual(len(b.advisories_for("Zope_Interface", "pypi")), 1)


# ---------------------------------------------------------------------------
# 19. malformed input
# ---------------------------------------------------------------------------
class Malformed(Tmp):
    def run_bundle(self, doc=None, text=None, project=None):
        root = self.mk(project or {"requirements.txt": "requests==2.19.0\n"})
        return self.main(root, "--bundle", self.bundle_file(doc, text), "--no-json")

    def test_structural_bundle_problems_exit_4(self):
        for text in ('{"bundleVersion":1,"advisories":{"a":1}}', "[" * 100000, "{", '"x"',
                     '{"bundleVersion": 2}', '{"bundleVersion":1,"advisories":[' + "9" * 5000 + "]}"):
            with self.subTest(text=text[:30]):
                rc, _, err = self.run_bundle(text=text)
                self.assertEqual(rc, 4, err)
                self.assertNotIn("Traceback", err)

    def test_entry_problems_are_counted_not_fatal(self):
        base = adv("CVE-B", "requests", "pypi", "2.20.0")
        docs = {
            "epss_str": dict(base, epss="0.9"),
            "sources_int": dict(base, sources=[1], cwes="x", refs=5),
            "ranges_dict": dict(base, packages=[{"name": "requests", "ranges": {"toVersion": "2.20.0"}}]),
            "range_entry_str": dict(base, packages=[{"name": "requests", "ranges": ["<2.20"]}]),
            "cvss_str": dict(base, cvss="9.8"),
        }
        for name, a in docs.items():
            with self.subTest(case=name):
                doc = {"bundleVersion": 1, "generatedAt": NOW, "sources": [1, "ok"],
                       "advisories": [a, 5, {"cve": 7}, {"cve": "X", "packages": [5, {"name": 3}]}]}
                rc, out, err = self.run_bundle(doc)
                self.assertEqual(rc, 0, err)
                self.assertIn("warning: CVE bundle:", err)
                self.assertNotIn("Traceback", err)
                self.assertTrue("1 affected" in out or "1 unknown-version" in out, out)

    def test_malformed_lockfiles(self):
        project = {"package-lock.json": '{"lockfileVersion":1,"dependencies":{"weird":"1.0.0","x":[1]}}',
                   "Pipfile.lock": '{"default":{"requests":{"version":"==2.19.0"},"django":"==2.2"},'
                                   '"develop":[1]}',
                   "poetry.lock": "[[package]\nname=", "pyproject.toml": "not = [toml",
                   "yarn.lock": "\x00garbage\n  version\n", "pnpm-lock.yaml": "packages:\n  /:\n"}
        rc, out, err = self.run_bundle(project=project)
        self.assertEqual(rc, 0, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("malformed Pipfile.lock entries", err)
        self.assertIn("1 affected", out)            # requests from Pipfile.lock

    def test_freshness_fails_closed(self):
        for gen, ok in ((NOW, True), (None, False), ("last tuesday", False), (5, False),
                        ("2019-01-01", False), (NOW.rstrip("Z"), True), ("2999-01-01T00:00:00Z", False)):
            with self.subTest(gen=gen):
                b = sca.CveBundle({"bundleVersion": 1, "generatedAt": gen, "advisories": []})
                res = sca.build_sca_result("/p", b, [], sca.Inventory(), {})
                fresh = [c["ok"] for c in res["conditions"] if c["label"].startswith("CVE bundle fresh")]
                self.assertEqual(fresh, [ok])

    def test_naive_timestamp_is_utc(self):
        naive = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        self.assertEqual(sca.bundle_age_days(naive), 0)
        self.assertEqual(sca.parse_generated_at("2026-01-02T03:04:05+02:00").utcoffset(),
                         datetime.timedelta(hours=2))


# ---------------------------------------------------------------------------
# 3 + 20. CLI: safe report writing, parity flags, other lockfiles
# ---------------------------------------------------------------------------
class Cli(Tmp):
    def project(self):
        return self.mk({"requirements.txt": "requests==2.19.0\n"})

    @unittest.skipUnless(hasattr(os, "symlink"), "no symlinks")
    def test_symlinked_report_is_refused(self):
        """Reviewer repro: lazaret-sca.json -> ../victim_home/.bashrc."""
        base = tempfile.mkdtemp(prefix="lz-review-sym-")
        self.addCleanup(shutil.rmtree, base, True)
        victim = os.path.join(base, "victim_home", ".bashrc")
        os.makedirs(os.path.dirname(victim))
        with open(victim, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# inert victim file\n")
        repo = os.path.join(base, "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, "requirements.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("requests==2.31.0\n")
        try:
            os.symlink("../victim_home/.bashrc", os.path.join(repo, "lazaret-sca.json"))
        except OSError:
            self.skipTest("cannot create symlinks here")
        rc, _, err = self.main(repo, "--bundle", self.bundle_file())
        self.assertEqual(rc, 3)
        self.assertIn("symlink", err)
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "# inert victim file\n")
        rc, _, _ = self.main(repo, "--bundle", self.bundle_file(), "--force-overwrite")
        self.assertEqual(rc, 3)                       # --force-overwrite never follows links

    def test_marker_rescan_and_foreign_file(self):
        root = self.project()
        rc, _, err = self.main(root, "--bundle", self.bundle_file(), "-q")
        self.assertEqual(rc, 0, err)
        path = os.path.join(root, sca.SCA_REPORT_NAME)
        self.assertTrue(reports.is_our_report(path, "json"))
        self.assertEqual(self.main(root, "--bundle", self.bundle_file(), "-q")[0], 0)   # re-scan
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"not": "ours"}')
        rc, _, err = self.main(root, "--bundle", self.bundle_file(), "-q")
        self.assertEqual(rc, 3)
        self.assertIn("refusing to overwrite", err)
        self.assertEqual(self.main(root, "--bundle", self.bundle_file(), "-q", "--force-overwrite")[0], 0)

    def test_out_dir_html_sarif(self):
        root, out = self.project(), self.mk({})
        rc, stdout, err = self.main(root, "--bundle", self.bundle_file(), "-q", "--out-dir", out,
                                    "--html", "r.html", "--sarif", "r.sarif")
        self.assertEqual(rc, 0, err)
        for name, kind in ((sca.SCA_REPORT_NAME, "json"), ("r.html", "html"), ("r.sarif", "sarif")):
            self.assertTrue(reports.is_our_report(os.path.join(out, name), kind), name)
        with open(os.path.join(out, "r.sarif"), encoding="utf-8") as fh:
            sarif = json.load(fh)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "SCA-CVE")
        self.assertFalse(os.path.exists(os.path.join(root, sca.SCA_REPORT_NAME)))
        self.assertEqual(self.main(root, "--bundle", self.bundle_file(), "--out-dir",
                                   os.path.join(out, "missing"))[0], 3)

    def test_baseline(self):
        root, out = self.project(), self.mk({})
        base = os.path.join(out, "base.json")
        self.assertEqual(self.main(root, "--bundle", self.bundle_file(), "--json", base, "-q")[0], 0)
        rc, stdout, err = self.main(root, "--bundle", self.bundle_file(), "--no-json", "--baseline", base)
        self.assertIn("New issues vs baseline: 0", stdout)
        forged = os.path.join(root, "forged.json")
        with open(forged, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"generatedBy": "lazaret-cli-1", "issues": []}')
        rc, stdout, err = self.main(root, "--bundle", self.bundle_file(), "--no-json", "--baseline", forged)
        self.assertIn("New issues vs baseline: 1", stdout)
        self.assertIn("untrusted", err)

    def test_yarn_and_pnpm_locks(self):
        yarn_v1 = ('# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.5:\n  version "4.17.11"\n'
                   '  resolved "https://registry.example.invalid/lodash-4.17.11.tgz"\n  dependencies:\n'
                   '    zzz "^0.1.0"\n\n"@s/p@^1.0.0":\n  version "1.2.3"\n\nalias@npm:zzz@^0.1:\n'
                   '  version "0.1.5"\n')
        berry = ('__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.11\n'
                 '  resolution: "lodash@npm:4.17.11"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n'
                 '  resolution: "app@workspace:."\n')
        pnpm5 = "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.11:\n    resolution: {integrity: x}\n" \
                "  /@s/p/1.2.3_react@18.0.0:\n    dev: false\n"
        pnpm6 = "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.11:\n    resolution: {integrity: x}\n" \
                "  /@s/p@1.2.3(react@18.0.0):\n    dev: false\n"
        pnpm9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n" \
                "packages:\n  lodash@4.17.11:\n    resolution: {integrity: x}\n  '@s/p@1.2.3':\n" \
                "    resolution: {integrity: y}\n  foo@link:../foo:\n    x: 1\nsnapshots:\n" \
                "  '@s/p@1.2.3(react@18.0.0)':\n    dependencies: {}\n"
        self.assertEqual(sorted(sca.parse_yarn_lock(yarn_v1)),
                         [("@s/p", "1.2.3"), ("lodash", "4.17.11"), ("zzz", "0.1.5")])
        self.assertEqual(sca.parse_yarn_lock(berry), [("lodash", "4.17.11")])
        for text in (pnpm5, pnpm6, pnpm9):
            with self.subTest(text=text[:20]):
                self.assertEqual(sorted(set(sca.parse_pnpm_lock(text))),
                                 [("@s/p", "1.2.3"), ("lodash", "4.17.11")])
        lodash = ("lodash", "4.17.11", "CVE-TEST-LODASH")
        for fname, text, want in (("yarn.lock", yarn_v1, [lodash, ("zzz", "0.1.5", "CVE-TEST-ZZZ")]),
                                  ("pnpm-lock.yaml", pnpm6, [lodash])):
            with self.subTest(fname=fname):
                root = self.mk({fname: text})
                self.assertEqual(self.verdicts(root)[0], want)

    def test_usage_errors(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                sca.main(["--nope"])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(self.main("/nonexistent.invalid", "--bundle", "x")[0], 2)


if __name__ == "__main__":
    unittest.main()
