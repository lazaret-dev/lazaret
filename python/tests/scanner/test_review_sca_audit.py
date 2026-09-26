"""Audit findings — lazaret-sca matching.

1  match_inventory deduplicated on (CVE, advisory package name, version)
   BEFORE checking ranges: when one advisory lists the same product twice
   (a 'python-urllib3' and a 'urllib3' entry, or an npm and a pypi protobuf)
   only the first entry was checked. urllib3 1.24.1 was always cleared, and
   pypi protobuf 4.21.1 was reported or cleared depending on PYTHONHASHSEED.
4  Manifests were read as plain UTF-8: a BOM-prefixed package-lock.json,
   package.json, Pipfile.lock or pyproject.toml was silently ignored, a BOM
   in requirements.txt dropped its first requirement, and a UTF-16
   requirements.txt (PowerShell `pip freeze >`) yielded nothing. A manifest
   that was present but unusable left no warning.
5  setup.py's install_requires was matched with a regex that stopped at the
   first ']': ["requests[security]==2.19.0", "django==1.11.0"] gave an
   empty inventory and no warning.

All fixtures are inert manifest/lock text and synthetic CVE ids.
"""
import atexit
import datetime
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

from lazaret.scanner import sca
from tests import _support

NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry(name, eco, frm, to, to_inc=False):
    return {"name": name, "ecosystem": eco,
            "ranges": [{"fromVersion": frm, "toVersion": to, "toInclusive": to_inc}]}


def bundle(*advisories):
    return sca.CveBundle({"bundleVersion": 1, "generatedAt": NOW, "advisories": list(advisories)})


def verdicts(inv, b):
    matches, unknown = sca.match_inventory(sca.Inventory(inv), b)
    return (sorted((a["cve"], d[1], d[2]) for a, p, d, r in matches),
            sorted((a["cve"], d[1], d[2]) for d, a, p, why in unknown))


# ---------------------------------------------------------------------------
# 1. every (advisory, package entry) pair is checked before deduplication
# ---------------------------------------------------------------------------
class EveryEntryIsChecked(unittest.TestCase):
    URLLIB3 = [("pypi", "urllib3", "1.24.1", "requirements.txt")]

    def test_second_entry_for_the_same_product(self):
        alias = {"cve": "CVE-0000-0001", "cvss": 9.8, "packages": [
            entry("python-urllib3", "pypi", "1.0", "1.20"),       # does not cover 1.24.1
            entry("urllib3", "pypi", "1.24", "1.24.2")]}          # covers it
        twice = {"cve": "CVE-0000-0002", "cvss": 9.8, "packages": [
            entry("urllib3", "pypi", "1.0", "1.20"),
            entry("urllib3", "pypi", "1.24", "1.24.2")]}
        want = ([("CVE-0000-0001", "urllib3", "1.24.1"), ("CVE-0000-0002", "urllib3", "1.24.1")], [])
        self.assertEqual(verdicts(self.URLLIB3, bundle(alias, twice)), want)
        for adv in (alias, twice):                                # either order
            adv["packages"].reverse()
        self.assertEqual(verdicts(self.URLLIB3, bundle(alias, twice)), want)

    def test_npm_and_pypi_entries_under_every_hash_seed(self):
        # The lookup keys of a pypi name are a set; which entry came first
        # used to depend on PYTHONHASHSEED. Each run is a fresh interpreter.
        code = textwrap.dedent("""
            from lazaret.scanner import sca
            b = sca.CveBundle({"bundleVersion": 1, "advisories": [{"cve": "CVE-0000-0003",
                "packages": [
                    {"name": "protobuf", "ecosystem": "npm",
                     "ranges": [{"fromVersion": "3.0.0", "toVersion": "3.4.0", "toInclusive": False}]},
                    {"name": "protobuf", "ecosystem": "pypi",
                     "ranges": [{"fromVersion": "4.21.0", "toVersion": "4.21.6", "toInclusive": False}]}]}]})
            m, u = sca.match_inventory(sca.Inventory([("pypi", "protobuf", "4.21.1", "r.txt")]), b)
            print(len(m), len(u), m[0][1]["ecosystem"] if m else "-")
        """)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            p for p in (_support.SRC, os.environ.get("PYTHONPATH")) if p))
        seen = {}
        for seed in range(8):
            env["PYTHONHASHSEED"] = str(seed)
            p = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env,
                               encoding="utf-8", errors="replace", timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            seen[seed] = p.stdout.strip()
        self.assertEqual(set(seen.values()), {"1 0 pypi"}, seen)

    def test_affected_over_unknown_over_clear(self):
        no_ranges = {"name": "foo", "ecosystem": "pypi", "ranges": []}
        malformed = {"name": "foo", "ecosystem": "pypi", "ranges": {"toVersion": "2.0"}}
        dep = [("pypi", "foo", "1.5", "requirements.txt")]
        cases = {
            "unknown entry first, affected second": ([no_ranges, entry("foo", "pypi", "1.0", "2.0")],
                                                     ([("CVE-0000-0004", "foo", "1.5")], [])),
            "clear entry first, unknown second": ([entry("foo", "pypi", "3.0", "4.0"), malformed],
                                                  ([], [("CVE-0000-0004", "foo", "1.5")])),
            "clear only": ([entry("foo", "pypi", "3.0", "4.0"), entry("foo", "pypi", "0.1", "1.0")],
                           ([], [])),
        }
        for label, (packages, want) in cases.items():
            with self.subTest(label):
                b = bundle({"cve": "CVE-0000-0004", "cvss": 7.5, "packages": packages})
                self.assertEqual(verdicts(dep, b), want)

    def test_one_result_per_cve_and_dependency_in_bundle_order(self):
        adv = {"cve": "CVE-0000-0005", "cvss": 7.5, "packages": [
            entry("python-foo", "pypi", "1.0", "1.9"), entry("foo", "pypi", "1.0", "2.0")]}
        inv = [("pypi", "foo", "1.5", "a"), ("pypi", "foo", "1.5", "b"), ("pypi", "foo", "2.5", "c")]
        matches, unknown = sca.match_inventory(sca.Inventory(inv), bundle(adv))
        self.assertEqual(unknown, [])
        self.assertEqual([(d[3], sca.format_range(r)) for a, p, d, r in matches], [("a", ">=1.0 <1.9")])


# ---------------------------------------------------------------------------
# 4. manifests are decoded like source files; unusable ones are warned about
# ---------------------------------------------------------------------------
BOM = b"\xef\xbb\xbf"


def project(files):
    """A temp project from {relpath: bytes}."""
    root = tempfile.mkdtemp(prefix="lz-sca-audit-")
    atexit.register(shutil.rmtree, root, True)
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    return root


def inventory(root):
    w = sca._Warnings()
    return sorted((e, n, v) for e, n, v, where in sca.scan_all(root, None, w)), w.counts


class ManifestDecoding(unittest.TestCase):
    LOCK = (b'{"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"},'
            b' "node_modules/lodash": {"version": "4.17.11"}}}')

    def test_bom_prefixed_manifests(self):
        cases = {
            "package-lock.json": (self.LOCK, ("npm", "lodash", "4.17.11")),
            "package.json": (b'{"dependencies": {"lodash": "4.17.11"}}', ("npm", "lodash", "4.17.11")),
            "Pipfile.lock": (b'{"default": {"urllib3": {"version": "==1.24.1"}}}',
                             ("pypi", "urllib3", "1.24.1")),
            "pyproject.toml": (b'[project]\nname = "x"\ndependencies = ["django==1.11.0"]\n',
                               ("pypi", "django", "1.11.0")),
            "poetry.lock": (b'[[package]]\nname = "pyyaml"\nversion = "5.1"\n', ("pypi", "pyyaml", "5.1")),
            "requirements.txt": (b"urllib3==1.24.1\nrequests==2.19.0\n", ("pypi", "urllib3", "1.24.1")),
        }
        for name, (data, want) in cases.items():
            with self.subTest(name):
                inv, warnings = inventory(project({name: BOM + data}))
                self.assertIn(want, inv)
                self.assertEqual(warnings, {})

    def test_utf16_requirements(self):
        text = "urllib3==1.24.1\r\nrequests==2.19.0\r\n"          # PowerShell 5 `pip freeze >`
        for codec in ("utf-16", "utf-16-be"):
            data = text.encode(codec) if codec == "utf-16" else b"\xfe\xff" + text.encode(codec)
            with self.subTest(codec):
                inv, _ = inventory(project({"requirements.txt": data}))
                self.assertEqual(inv, [("pypi", "requests", "2.19.0"), ("pypi", "urllib3", "1.24.1")])

    def test_present_but_unusable_files_are_warned(self):
        root = project({"package-lock.json": b"{not json", "Pipfile.lock": b"[1]",
                        "package.json": b'"just a string"', "real.json": b"{}"})
        want = {"unparseable package-lock.json file(s)": 1, "malformed Pipfile.lock file(s)": 1,
                "malformed package.json file(s)": 1}
        if hasattr(os, "mkfifo"):
            os.mkfifo(os.path.join(root, "yarn.lock"))
            want["unreadable yarn.lock file(s)"] = 1
        try:
            os.symlink("real.json", os.path.join(root, "npm-shrinkwrap.json"))
            want["unreadable npm-shrinkwrap.json file(s)"] = 1
        except (OSError, NotImplementedError):
            pass                            # Windows without the symlink privilege
        self.assertEqual(inventory(root), ([], want))


# ---------------------------------------------------------------------------
# 5. setup.py install_requires is parsed, not matched up to the first ']'
# ---------------------------------------------------------------------------
class SetupPy(unittest.TestCase):
    def declared(self, text):
        w = sca._Warnings()
        inv = sca.scan_pypi_declared(project({"setup.py": text.encode("utf-8")}), w)
        return sorted((n, v) for e, n, v, where in inv), w.counts

    def test_extras_in_a_literal_list(self):
        text = ('from setuptools import setup\nsetup(name="demo", install_requires=[\n'
                '    "requests[security]==2.19.0",\n    "django==1.11.0",\n    "pyyaml==5.1",\n])\n')
        self.assertEqual(self.declared(text),
                         ([("django", "1.11.0"), ("pyyaml", "5.1"), ("requests", "2.19.0")], {}))

    def test_names_concatenation_and_kwargs_dicts(self):
        text = ('BASE = ["six==1.10.0"]\nREQS = BASE + ["idna==2.5"]\nREQS += ["chardet==3.0.4"]\n'
                'EXTRA = {"install_requires": ["attrs==19.1.0"]}\nsetup(install_requires=REQS)\n'
                'setup(**EXTRA)\n')
        self.assertEqual(self.declared(text)[0], [("attrs", "19.1.0"), ("chardet", "3.0.4"),
                                                  ("idna", "2.5"), ("six", "1.10.0")])

    def test_python2_setup_py(self):
        text = ('print "building"\nsetup(name="old",\n      install_requires=[\'requests[socks]==2.19.0\',\n'
                '                        "django==1.11.0"],  # pinned\n)\n')
        self.assertEqual(self.declared(text),
                         ([("django", "1.11.0"), ("requests", "2.19.0")], {}))

    def test_a_computed_value_is_warned_about(self):
        text = ('import io\nsetup(install_requires=io.open("requirements.txt").read().splitlines())\n')
        inv, warnings = self.declared(text)
        self.assertEqual(inv, [])
        self.assertEqual(list(warnings), ["setup.py install_requires computed at run time "
                                          "(that part not inventoried)"])


if __name__ == "__main__":
    unittest.main()
