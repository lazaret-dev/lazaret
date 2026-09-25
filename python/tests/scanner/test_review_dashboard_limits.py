"""The dashboard's limits match the CLI's (FIX-SPEC items 7 and 9).

Before: the page stopped recording issues after 500 per file (a SCAN-BUDGET
notice, and everything after it unreported, security findings included) and
had no size limit, so a 25 MB upload froze the tab while the CLI reports
SC-TRUNCATED for anything over 2,000,000 bytes. Now: no per-file budget;
at most 200 findings per (file, rule) for INFO/MINOR rules and code smells,
then one Q-CAPPED; security findings never capped; snippet lines clipped to
240 characters around the match; the 2 MB limit with SC-TRUNCATED."""

import time
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash


def rules(issues):
    counts = {}
    for i in issues:
        counts[i["rule"]] = counts.get(i["rule"], 0) + 1
    return counts


@dash.requires_node
class SizeLimitTests(unittest.TestCase):
    def test_over_the_limit_is_one_sc_truncated_like_the_cli(self):
        (issue,) = dash.scan("big.js", "x" * 2_000_001, lang="js")
        cli = core.truncated_issue("big.js", "2,000,001 bytes exceeds the 2,000,000-byte file limit")
        for key in ("rule", "name", "type", "sev", "msg", "why", "fix", "ref", "file", "line", "snippet"):
            self.assertEqual(issue[key], cli[key], key)

    def test_the_limit_counts_utf8_bytes(self):
        at_limit = dash.scan("ok.js", "x" * 2_000_000, lang="js")         # exactly 2,000,000: scanned
        self.assertEqual([i["rule"] for i in at_limit], ["Q-LONGLINE"])
        (issue,) = dash.scan("wide.py", "é" * 1_000_001, lang="py")      # 2,000,002 bytes
        self.assertEqual(issue["rule"], "SC-TRUNCATED")
        self.assertIn("2,000,002 bytes", issue["msg"])

    def test_an_oversize_upload_is_not_read_and_fails_the_gate(self):
        accepted, result = dash.run([
            {"op": "upload", "files": [{"name": "huge.js", "content": "eval(x)\n", "size": 25_000_000},
                                       {"name": "small.js", "content": "eval(x)\n"}]},
            {"op": "runScan", "files": [{"name": "huge.js", "content": "", "size": 25_000_000},
                                        {"name": "small.js", "content": "eval(x)\n"}]},
        ])
        self.assertEqual([(f["name"], f["contentLength"], f["size"]) for f in accepted],
                         [("huge.js", 0, 25_000_000), ("small.js", 8, 8)])
        self.assertEqual(rules(result["issues"]).get("SC-TRUNCATED"), 1)
        self.assertFalse(result["pass"])
        self.assertEqual(result["metrics"]["ncloc"], 1)                  # only small.js measured


@dash.requires_node
class CapTests(unittest.TestCase):
    def test_no_per_file_budget_for_security_findings(self):
        issues = dash.scan("many.js", "eval(x);\n" * 600, lang="js")
        counts = rules(issues)
        self.assertEqual(counts.get("S-EVAL-JS"), 600)
        self.assertNotIn("SCAN-BUDGET", counts)
        self.assertNotIn("Q-CAPPED", counts)

    def test_quality_findings_are_capped_with_a_note(self):
        issues = dash.scan("vars.js", "".join(f"var a{n} = 1;\n" for n in range(250)), lang="js")
        counts = rules(issues)
        self.assertEqual(counts["Q-VAR"], 200)
        (capped,) = [i for i in issues if i["rule"] == "Q-CAPPED"]
        self.assertEqual(capped["msg"], "50 more Q-VAR findings omitted")
        self.assertEqual((capped["sev"], capped["line"]), ("INFO", 201))

    def test_minor_security_rules_are_never_capped(self):
        issues = dash.scan("urls.py", 'u = "http://example.invalid/x"\n' * 250, lang="py")
        self.assertEqual(rules(issues).get("S-HTTP"), 250)                # MINOR, but S-*
        self.assertNotIn("Q-CAPPED", rules(issues))

    def test_issue_dense_file_is_fast(self):
        # the reviewer's tab-freeze input, cut to 2,000 lines to stay under the 2 MB limit
        line = "var a" + "=1;if(x){y()}else{z()};" * 40 + "\n"
        started = time.monotonic()
        issues = dash.scan("dense.js", line * 2000, lang="js")
        self.assertLess(time.monotonic() - started, 30)
        counts = rules(issues)
        self.assertEqual(counts["Q-LONGLINE"], 200)
        self.assertIn("Q-CAPPED", counts)


@dash.requires_node
class SnippetTests(unittest.TestCase):
    def test_lines_are_clipped_and_windowed_around_the_match(self):
        long_line = "a = 1; " * 70 + "eval(payload); " + "b = 2; " * 70
        src = "x = 1\n" + ("y" * 500) + "\n" + long_line + "\nz = 2\n"
        (issue,) = [i for i in dash.scan("w.js", src, lang="js") if i["rule"] == "S-EVAL-JS"]
        for text in issue["snippet"]:
            self.assertLessEqual(len(text), 240)
        flagged = issue["snippet"][issue["line"] - issue["snipStart"]]
        self.assertTrue(flagged.startswith("…") and flagged.endswith("…"), flagged)
        self.assertIn("eval(payload)", flagged)
        self.assertEqual(flagged.index("eval(payload)"), 61)                # 60 chars of lead-in after "…"
        self.assertTrue(issue["snippet"][0 if issue["snipStart"] == 2 else 1].endswith("…"))

    def test_short_lines_are_untouched(self):
        (issue,) = [i for i in dash.scan("s.js", "eval(x)\n", lang="js") if i["rule"] == "S-EVAL-JS"]
        self.assertEqual(issue["snippet"][0], "eval(x)")


if __name__ == "__main__":
    unittest.main()
