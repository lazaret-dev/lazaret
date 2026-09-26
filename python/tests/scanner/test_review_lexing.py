"""Review fixes: the comment lexer and what is built on it.

Each case failed before its fix; the npm engine's side is in
js/test/review-lexing.test.js, the dashboard's in
test_review_dashboard_lexing.py, and both CLIs are compared on the same
inputs in tests/architecture/test_js_parity_lexing.py. All input is inert.
"""
import time
import unittest

from tests import _support  # noqa: F401  (puts src/ on sys.path)
from lazaret.scanner import core

# Loose on purpose (STRUCTURE.md rule 7): the fixed code takes well under a
# second per case; before the fix each took 20 s or more.
PER_CASE_LIMIT = 8.0


def rules_at(issues):
    return sorted((i["rule"], i["line"]) for i in issues)


class LinearCommentChecksTests(unittest.TestCase):
    """_js_text tested every comment span of a line for each \\u escape, and
    _find_marker every span for each suppression-marker match: O(n²) on one
    line (`x=1;` + `/**/\\u0061` x 10,000: 4.9 s, x 20,000: 20 s), beyond
    the reach of the per-file time budget. Both now walk the sorted spans once."""

    def scan_timed(self, content):
        t = time.monotonic()
        issues = core.scan_file("a.js", content, "js")
        elapsed = time.monotonic() - t
        self.assertLess(elapsed, PER_CASE_LIMIT, f"{elapsed:.1f}s")
        self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})
        return issues

    def test_escapes_between_comments(self):
        self.scan_timed("x=1;" + "/**/\\u0061" * 20000 + "\n")

    def test_marker_lookalikes_between_comments(self):
        # every "// nosec" sits in a string: none suppresses the eval
        issues = self.scan_timed("x=1;" + "'// nosec'/**/" * 20000 + "eval(a)\n")
        self.assertIn(("S-EVAL-JS", 1), rules_at(issues))

    def test_results_unchanged(self):
        src = "a = 1; /* c */ \\u0065val(x) /* d */ \\u0065val(y) // nosec\n/**/\\u0065val(z)\n"
        self.assertEqual(rules_at(core.scan_file("a.js", src, "js")), [("S-EVAL-JS", 2)])


if __name__ == "__main__":
    unittest.main()
