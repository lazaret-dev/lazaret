"""The dashboard scans adversarial input in linear time, with the CLI's
per-file time backstop (FIX-SPEC 14).

Before: the page still had the backtracking forms of SQL-DYNAMIC,
B-EXCEPT-PASS, B-EMPTY-CATCH, the S-TOKEN JWT alternative, the SQL-sink
assignment regex and the method-header scan — each took over 4 s on the
inputs below (the tab froze; the *-NOWHERE rules took 2 s) — and nothing
stopped a slow file. The inputs are the npm engine's review-perf cases,
built inside the page; each now takes well under a second (the bound is
generous), and none may hit the backstop. The backstop itself is checked
with a zero budget: one SC-TRUNCATED finding, the same one core.scan_file
reports."""

import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

LIMIT_MS = 4000
# label -> (lang, JavaScript expression building the content inside the page)
CASES = {
    "SQL-DELETE-NOWHERE unterminated": ("sql", '"DELETE FROM x ".repeat(20000)'),
    "SQL-UPDATE-NOWHERE unterminated": ("sql", '"UPDATE x SET ".repeat(20000)'),
    "SQL-*-NOWHERE with WHERE": ("sql", '"DELETE FROM t WHERE a = 1 AND b IN (SELECT c FROM d);\\n".repeat(10000)'),
    "SQL-DYNAMIC quotes": ("sql", "\"SET @a = '\".repeat(20000)"),
    "SQL-DYNAMIC EXEC(": ("sql", '\'EXEC("\'.repeat(20000)'),
    "SQL-GRANT-PUBLIC": ("sql", '"GRANT ".repeat(20000)'),
    "B-EXCEPT-PASS newlines": ("py", '"except:" + "\\n".repeat(200000)'),
    "B-EXCEPT-PASS repeated": ("py", '"except ".repeat(100000)'),
    "S-YAML repeated": ("py", '"yaml.load(".repeat(20000) + "SafeLoader"'),
    "S-CHMOD repeated": ("py", '"chmod(".repeat(20000)'),
    "B-EMPTY-CATCH repeated": ("js", '"catch(".repeat(50000)'),
    "function header a( repeated": ("js", '"a(".repeat(100000)'),
    "function header long word": ("js", '"a".repeat(300000)'),
    "S-TOKEN eyJ run": ("js", "\"x = '\" + \"eyJ\".repeat(100000) + \"'\""),
    "SQL sink assignment whitespace": ("py", "\"q = 'x'\" + \" \".repeat(300000) + \"+\""),
    "taint: many assignments": ("js", 'Array.from({length: 20000}, (_, i) => `const v${i} = req.query.a${i};`).join("\\n")'
                                      ' + "\\neval(v1);\\n"'),
}


def timed(name, lang, content_expr):
    return (f"(() => {{ const content = {content_expr}; const t0 = Date.now();"
            f" const issues = scanFile({{name: {json.dumps(name)}, lang: {json.dumps(lang)}, content}});"
            f" return {{ms: Date.now() - t0, truncated: issues.some((i) => i.rule === 'SC-TRUNCATED'),"
            f" n: issues.length}}; }})()")


@dash.requires_node
class DashboardPerfTests(unittest.TestCase):
    def test_adversarial_inputs_are_linear(self):
        results = dash.run([{"op": "eval", "expr": timed(f"t.{lang}", lang, expr)}
                            for lang, expr in CASES.values()])
        for label, r in zip(CASES, results):
            with self.subTest(case=label):
                self.assertLess(r["ms"], LIMIT_MS, f"{label}: {r['ms']} ms")
                self.assertFalse(r["truncated"], f"{label} hit the time backstop")

    def test_time_backstop_stops_a_file_with_sc_truncated(self):
        content = "eval(a)\n" * 5000
        (stopped, normal) = dash.run([
            {"op": "eval", "expr": "(() => { setScanTimeBudget(0); try { return scanFile({name: 't.js', lang: 'js',"
                                   " content: 'eval(a)\\n'.repeat(5000)}); } finally { setScanTimeBudget(); } })()"},
            {"op": "scanFile", "file": {"name": "t.js", "lang": "js", "content": "eval(a)\n"}},
        ])
        (issue,) = [i for i in stopped if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(issue, core.truncated_issue("t.js", "scan time budget exceeded"))
        self.assertLess(len(stopped), content.count("\n") + 1)       # it did stop early
        self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in normal})  # the budget is back to 30 s


if __name__ == "__main__":
    unittest.main()
