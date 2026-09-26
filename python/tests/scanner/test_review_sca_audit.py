"""Audit findings — lazaret-sca matching.

1  match_inventory deduplicated on (CVE, advisory package name, version)
   BEFORE checking ranges: when one advisory lists the same product twice
   (a 'python-urllib3' and a 'urllib3' entry, or an npm and a pypi protobuf)
   only the first entry was checked. urllib3 1.24.1 was always cleared, and
   pypi protobuf 4.21.1 was reported or cleared depending on PYTHONHASHSEED.

All fixtures are inert manifest/lock text and synthetic CVE ids.
"""
import datetime
import os
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
