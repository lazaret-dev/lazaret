"""Review: the per-file finding cap flipped the maintainability gate.

cap_issues runs inside scan_file, before build_result rates the project, so
the rating counted what was left: 2000 over-long lines in one file were
listed as 200 Q-LONGLINE findings plus one Q-CAPPED note, 201 smells over
2000 lines of code, rating C and a passing gate; the real density (2000
smells) is rating E. A Q-CAPPED note now records how many findings it
replaces ("omitted") and their type ("omittedType"), and the rating counts
those findings instead of the note, when they are smells (a capped bug rule
adds none). The rating no longer depends on the cap; both engines and the
dashboard count the same way.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import core, engine
from tests import _support
from tests.scanner import _dashboard_vm as dash

TABLE = "".join(f'value_{n:04d} = "' + f"segment-{n:04d} " * 14 + '"\n' for n in range(2000))
CATCHES = "try { f() } catch (e) {}\n" * 300 + "// TODO later\n" * 15


def scan(tree):
    with tempfile.TemporaryDirectory() as root:
        for rel, text in tree.items():
            with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
                f.write(text)
        return core.scan_project(root)


def uncapped_calls(items):
    """engine.scan_calls asking for the rules part alone (scan_rules: no markers, no cap): these trees' findings are
    all the rules', so it is their scan uncapped (the cap is the engine's since Q-1, 0.1.9, as the passes are)."""
    calls = REAL_SCAN_CALLS(items)
    return [None if c is None else ("scan_rules", {k: v for k, v in c[1].items() if k not in ("dep", "taint")})
            for c in calls]


REAL_SCAN_CALLS = engine.scan_calls


class RatingTests(unittest.TestCase):
    def test_capped_long_lines_rate_e(self):
        res = scan({"table.py": TABLE})
        rules = [i["rule"] for i in res["issues"]]
        self.assertEqual((rules.count("Q-LONGLINE"), rules.count("Q-CAPPED")), (200, 1))
        (note,) = [i for i in res["issues"] if i["rule"] == "Q-CAPPED"]
        self.assertEqual((note["omitted"], note["omittedType"], note["msg"]),
                         (1800, "SMELL", "1800 more Q-LONGLINE findings omitted"))
        self.assertEqual(res["ratings"]["maintainability"], "E")                  # was C
        self.assertEqual(res["conditions"][3], {"label": "Maintainability ≥ C", "ok": False})
        self.assertFalse(res["pass"])

    def test_rating_is_the_uncapped_rating(self):
        trees = [{"table.py": TABLE}, {"c.js": CATCHES}, {"table.py": TABLE, "c.js": CATCHES},
                 {"t.py": "# TODO x\n" * 260 + "x = 1\n" * 3000}]
        for tree in trees:
            with self.subTest(files=sorted(tree)):
                capped = scan(tree)
                with mock.patch.object(engine, "scan_calls", uncapped_calls):
                    uncapped = scan(tree)
                self.assertIn("Q-CAPPED", {i["rule"] for i in capped["issues"]})
                self.assertNotIn("Q-CAPPED", {i["rule"] for i in uncapped["issues"]})
                self.assertEqual(capped["ratings"], uncapped["ratings"])
                self.assertEqual(capped["pass"], uncapped["pass"])

    def test_a_capped_bug_rule_adds_no_smells(self):
        res = scan({"c.js": CATCHES})
        (note,) = [i for i in res["issues"] if i["rule"] == "Q-CAPPED"]
        self.assertEqual((note["omitted"], note["omittedType"]), (100, "BUG"))
        # 15 TODO smells over 300 lines of code: 5.0 per 100, A (the note counted
        # as a smell made it B; its 100 bugs counted as smells would make it D)
        self.assertEqual(res["ratings"]["maintainability"], "A")

    def test_a_note_without_a_count_is_one_smell(self):
        note = {"rule": "Q-CAPPED", "type": "SMELL"}
        self.assertEqual(core.maintainability_rating([note] * 6, 100), "B")

    def test_cli_gate(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            with open(os.path.join(root, "table.py"), "w", encoding="utf-8") as f:
                f.write(TABLE)
            p = subprocess.run([sys.executable, _support.CLI, root, "--ci", "--out-dir", out, "--quiet"],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=40)
            self.assertEqual(p.returncode, 1, p.stdout[-500:])                    # was 0
            with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["ratings"]["maintainability"], "E")


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_report_rates_like_the_cli(self):
        files = [("table.py", "py", TABLE), ("c.js", "js", CATCHES)]
        (page,) = dash.run([{"op": "runScan", "files": [
            {"name": n, "lang": lang, "content": c} for n, lang, c in files]}])
        issues = []
        for n, lang, c in files:
            issues += core.scan_file(n, c, lang)
        cli = core.build_result(".", [{"path": n, "lang": lang, "content": c} for n, lang, c in files], issues)
        for key in ("ratings", "pass", "counts", "metrics"):
            self.assertEqual(page[key], cli[key], key)
        self.assertEqual(page["ratings"]["maintainability"], "E")
        notes = lambda r: sorted(json.dumps(i, sort_keys=True) for i in r["issues"] if i["rule"] == "Q-CAPPED")
        self.assertEqual(notes(page), notes(cli))


if __name__ == "__main__":
    unittest.main()
