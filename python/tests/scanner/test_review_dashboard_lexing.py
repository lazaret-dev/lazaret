"""The dashboard's side of the lexing / encoding review fixes.

Runs the page's script in node:vm (_dashboard_vm.py): its copy of the npm
engine must be as fast as the CLIs on the inputs that used to be quadratic,
and report exactly what lazaret.scanner.core reports on the new inputs
(test_review_lexing.py and friends hold the expectations themselves). All
input is inert: nothing is executed, hosts are TEST-NET or .invalid.
"""
import collections
import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash
from tests.scanner.test_review_dashboard_parity import issue_key, short

# Generous (machines differ); before the fix the page took ~20 s per case.
LIMIT_MS = 4000

TIMED = """(() => {
  const content = %s;
  const t0 = Date.now();
  const issues = scanFile({name: "a.js", lang: "js", content});
  return [Date.now() - t0, issues.map((i) => i.rule + "@" + i.line)];
})()"""


@dash.requires_node
class DashboardLexingTests(unittest.TestCase):
    def assert_same_findings(self, name, cli, page):
        a, b = collections.Counter(map(issue_key, cli)), collections.Counter(map(issue_key, page))
        if a != b:
            self.fail(f"{name}: findings differ\n  only in the CLI:\n    "
                      + "\n    ".join(short(json.loads(k)) for k in (a - b).elements())
                      + "\n  only in the dashboard:\n    "
                      + "\n    ".join(short(json.loads(k)) for k in (b - a).elements()))

    def compare(self, cases):
        """cases: [(name, lang, content)] -> the page's findings, checked against core."""
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": lang, "content": c}}
                         for n, lang, c in cases])
        for (name, lang, content), page_issues in zip(cases, page):
            with self.subTest(file=name):
                self.assert_same_findings(name, core.scan_file(name, content, lang), page_issues)
        return page

    def test_comment_checks_are_linear(self):
        """jsText and the suppression check tested every comment span of a
        line per escape / per marker: O(n²), ~20 s for these lines."""
        exprs = ['"x=1;" + "/**/\\\\u0061".repeat(60000) + "\\n"',
                 '"x=1;" + "\'// nosec\'/**/".repeat(60000) + "eval(a)\\n"']
        for expr, (ms, rules) in zip(exprs, dash.run([{"op": "eval", "expr": TIMED % e} for e in exprs])):
            with self.subTest(content=expr):
                self.assertLess(ms, LIMIT_MS)
                self.assertNotIn("SC-TRUNCATED@1", rules)
        self.assertIn("S-EVAL-JS@1", rules)


if __name__ == "__main__":
    unittest.main()
