"""Review fix: bounded snippets and a per-(file, rule) cap on low-value findings.

Each finding copied its ±2 context lines whole, so a 22.5 KB one-line file
produced a 34 MB JSON and a 34 MB HTML report. Snippet lines are now clipped
to 240 characters, the flagged line windowed around the match; INFO/MINOR/
SMELL findings are capped at 200 per (file, rule) with one Q-CAPPED summary.
"""
import json
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

E = core.ELLIPSIS


class ClipTests(unittest.TestCase):
    def test_short_lines_untouched(self):
        self.assertEqual(core.clip_snippet_line("x" * 240, 5), "x" * 240)
        self.assertIsNone(core.clip_snippet_line(None))

    def test_long_line_without_column_keeps_its_start(self):
        s = "".join(chr(65 + k % 26) for k in range(1000))
        out = core.clip_snippet_line(s)
        self.assertEqual(len(out), 240)
        self.assertEqual(out, s[:239] + E)

    def test_window_starts_60_chars_before_the_match(self):
        s = "a" * 5000 + "eval(x)" + "b" * 5000
        out = core.clip_snippet_line(s, 5000)
        self.assertEqual(len(out), 240)
        self.assertTrue(out.startswith(E) and out.endswith(E))
        self.assertEqual(out.index("eval("), 61)       # 1 marker + 60 lead chars

    def test_window_near_the_end(self):
        s = "a" * 1000 + "eval(x)"
        out = core.clip_snippet_line(s, 1000)
        self.assertEqual(len(out), 240)
        self.assertTrue(out.startswith(E) and out.endswith("eval(x)"))

    def test_window_near_the_start(self):
        s = "eval(x)" + "b" * 1000
        out = core.clip_snippet_line(s, 0)
        self.assertEqual(out, s[:239] + E)


class ScanSnippetTests(unittest.TestCase):
    def test_one_line_file_report_is_bounded(self):
        src = "try{}catch(e){}" * 1500 + "\n"          # the review's 22.5 KB repro
        issues = core.scan_file("m.js", src, "js")
        self.assertGreaterEqual(len(issues), 1500)
        for i in issues:
            for l in i["snippet"]:
                self.assertLessEqual(len(l), 240)
        self.assertLess(len(json.dumps(issues)), 3_000_000)

    def test_flagged_line_windowed_on_the_match(self):
        src = "var pad = '" + "x" * 3000 + "'; eval(process.argv[2]);\n"
        issue = next(i for i in core.scan_file("w.js", src, "js") if i["rule"] == "S-EVAL-JS")
        line = issue["snippet"][issue["line"] - issue["snipStart"]]
        self.assertTrue(line.startswith(E))
        self.assertIn("eval(process.argv[2])", line)

    def test_context_lines_clipped(self):
        src = "x = '" + "y" * 1000 + "'\nimport os\nos.system(input())\n"
        issue = next(i for i in core.scan_file("c.py", src, "py") if i["rule"] == "S-OSCMD-PY")
        self.assertEqual(len(issue["snippet"][0]), 240)
        self.assertTrue(issue["snippet"][0].endswith(E))

    def test_redact_result_clips_foreign_issues(self):
        res = {"issues": [{"rule": "X-SQL", "line": 1, "snipStart": 1, "msg": "m",
                           "snippet": ["z" * 5000]}]}
        core.redact_result(res)
        self.assertEqual(len(res["issues"][0]["snippet"][0]), 240)


class CapTests(unittest.TestCase):
    def test_info_rule_capped_with_one_summary(self):
        src = "# TODO: x\n" * 500
        issues = core.scan_file("t.py", src, "py")
        todo = [i for i in issues if i["rule"] == "Q-TODO"]
        capped = [i for i in issues if i["rule"] == "Q-CAPPED"]
        self.assertEqual(len(todo), 200)
        self.assertEqual([i["line"] for i in todo], list(range(1, 201)))
        self.assertEqual(len(capped), 1)
        self.assertEqual(capped[0]["msg"], "300 more Q-TODO findings omitted")
        self.assertEqual((capped[0]["sev"], capped[0]["type"], capped[0]["line"]),
                         ("INFO", "SMELL", 201))

    def test_minor_bug_rule_capped(self):
        src = "if (a == b) f();\n" * 250
        issues = core.scan_file("q.js", src, "js")
        self.assertEqual(sum(i["rule"] == "B-EQEQ" for i in issues), 200)
        self.assertIn("50 more B-EQEQ findings omitted", {i["msg"] for i in issues})

    def test_security_rules_never_capped(self):
        src = "eval(process.argv[2]);\n" * 300 + "u = 'http://example.invalid';\n" * 250
        issues = core.scan_file("s.js", src, "js")
        self.assertEqual(sum(i["rule"] == "S-EVAL-JS" for i in issues), 300)
        self.assertEqual(sum(i["rule"] == "S-HTTP" for i in issues), 250)   # MINOR, but S-*
        self.assertFalse(any(i["rule"] == "Q-CAPPED" and "S-" in i["msg"] for i in issues))

    def test_sql_smell_never_capped(self):
        issues = core.scan_file("s.sql", "SELECT * FROM t;\n" * 250, "sql")
        self.assertEqual(sum(i["rule"] == "SQL-SELECT-STAR" for i in issues), 250)

    def test_cappable_predicate(self):
        self.assertTrue(core._cappable({"rule": "Q-FN-LONG", "sev": "MAJOR", "type": "SMELL"}))
        self.assertTrue(core._cappable({"rule": "B-EQEQ", "sev": "MINOR", "type": "BUG"}))
        self.assertFalse(core._cappable({"rule": "B-EMPTY-CATCH", "sev": "MAJOR", "type": "BUG"}))
        for rid in ("S-HTTP", "T-CMD", "SC-B64", "X-SQL", "SQL-NOLOCK"):
            self.assertFalse(core._cappable({"rule": rid, "sev": "MINOR", "type": "SMELL"}))


if __name__ == "__main__":
    unittest.main()
