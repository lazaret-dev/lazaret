"""The dashboard's rule table has the linear S-JWT-NONE and B-EMPTY-CATCH
patterns (see test_review_perf_regex).

Before: the page compiled S-JWT-NONE's `\\s*\\[?\\s*` form, so 'algorithm:'
followed by 200,000 spaces froze the tab for ~20 s in one regex call, which
the per-file time backstop cannot interrupt. B-EMPTY-CATCH runs through the
page's linear scan and is kept as a guard. Each input now takes milliseconds
(the bound is generous) and the page still reports what core reports. The
page's linear token matcher (findSecretToken) and core's (_TokenPattern,
new with this fix) redact the same text."""

import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash
from tests.scanner.test_review_dashboard_perf import timed

LIMIT_MS = 4000
CASES = {
    "S-JWT-NONE 'algorithm:' + 200,000 spaces": ("js", '"opts = {algorithm:" + " ".repeat(200000)'),
    "S-JWT-NONE 'algorithm=' + 200,000 spaces (py)": ("py", '"opts = dict(algorithm=" + " ".repeat(200000)'),
    "B-EMPTY-CATCH 'catch' + 150,000 newlines": ("js", '"try { f() } catch" + "\\n".repeat(150000)'),
    "SC-OFFSCREEN-CODE 'x;' + 200,000 spaces": ("js", '"x;" + " ".repeat(200000)'),
    "SC-SELF-PUBLISH needles + 'a' x 200,000": ("js", '"exec(\'npm publish\'); w(\'package.json\'); " + "a".repeat(200000) + ".nam = 1"'),
}
SAMPLES = [
    ("a.js", "try { f() } catch (e) {}\ntry { g() } catch\n{\n}\njwt.verify(t, k, {algorithms: [ 'none' ]})\n"),
    ("b.py", "jwt.decode(t, algorithms=['none'])\nopts = dict(algorithm =  [  'none'\n"),
]


@dash.requires_node
class DashboardLinearPatternTests(unittest.TestCase):
    def test_adversarial_inputs_are_linear(self):
        results = dash.run([{"op": "eval", "expr": timed(f"t.{lang}", lang, expr)}
                            for lang, expr in CASES.values()])
        for label, r in zip(CASES, results):
            with self.subTest(case=label):
                self.assertLess(r["ms"], LIMIT_MS, f"{label}: {r['ms']} ms")
                self.assertFalse(r["truncated"], f"{label} hit the time backstop")

    def test_same_findings_as_core(self):
        pages = dash.run([{"op": "scanFile", "file": {"name": name, "content": text}} for name, text in SAMPLES])
        for (name, text), page in zip(SAMPLES, pages):
            with self.subTest(file=name):
                cli = core.scan_file(name, text, name.rsplit(".", 1)[1])
                self.assertEqual(sorted((i["rule"], i["line"], i["msg"]) for i in page),
                                 sorted((i["rule"], i["line"], i["msg"]) for i in cli))
                self.assertIn("S-JWT-NONE", {i["rule"] for i in page})

    def test_token_redaction_matches_core(self):
        """core's linear token matcher (test_review_perf_regex) redacts what the
        page's findSecretToken redacts, glued tokens included."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        lines = ["x" + jwt, "AKIA" + "Q" * 16 + jwt + ".sig", "ghp_" + "a1B2" * 9 + jwt,
                 "a.eyJ" + "b" * 10 + " eyJ" * 3, "-" * 20 + "eyJ" + "c" * 10 + ".eyJ" + "d" * 10,
                 "//" + "eyJ" * 5000]
        (page,) = dash.run([{"op": "eval", "expr": f"{json.dumps(lines)}.map(redactContextLine)"}])
        self.assertEqual(page, [core._redact_context_line(line) for line in lines])


if __name__ == "__main__":
    unittest.main()
