"""Review: a decoded source kept lone surrogates, and the HTML report crashed.

A PEP 263 cookie naming UTF-7 or unicode_escape can decode to surrogate code
points that are not text: `x = "+2AA-"` under `# coding: utf-7` is U+D800
alone, `"\\udc80"` under unicode_escape is U+DC80. decode_source kept them,
so the JSON report was written (json.dumps escapes them) and then the HTML
writer's `rendered.encode("utf-8")` raised: `error: internal:
UnicodeEncodeError`, exit 5 instead of 1 with --ci, no HTML report. The flow
engine could not parse the file either (Q-FLOW-SKIPPED). The npm engine's
decoders already write U+FFFD for them; decode_source now does the same, and
write_report encodes one it still meets as U+FFFD instead of raising.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from lazaret.scanner import core
from lazaret.scanner import reports
from tests import _support

HIGH, LOW = chr(0xD800), chr(0xDC80)
UTF7 = b'# -*- coding: utf-7 -*-\nx = "+2AA-"  # TODO marker\n'
UNICODE_ESCAPE = b'# coding: unicode_escape\nlabel = "\\udc80"\npair = "\\ud83d\\ude00"\n'


def has_surrogate(text):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


class DecodeTests(unittest.TestCase):
    def test_utf7_lone_surrogate_becomes_replacement_character(self):
        text, info = core.decode_source(UTF7, "py")
        self.assertTrue(info["utf7"])
        self.assertEqual(text.split("\n")[1], 'x = "\ufffd"  # TODO marker')

    def test_unicode_escape_surrogates(self):
        text, info = core.decode_source(UNICODE_ESCAPE, "py")
        self.assertEqual(info["encoding"], "unicode-escape")
        self.assertEqual(text.split("\n")[1:3], ['label = "\ufffd"', 'pair = "\ufffd\ufffd"'])

    def test_decoded_text_is_always_utf8(self):
        cases = [UTF7, UNICODE_ESCAPE, b"# coding: raw_unicode_escape\ns = '\\ud800'\n",
                 b"# coding: utf-7\n+2D3eAA- +3gA- +2D3YPQ-\n", b"# coding: utf-7\n+2ADYAA-\n"]
        for data in cases:
            with self.subTest(data=data):
                text, _ = core.decode_source(data, "py")
                self.assertFalse(has_surrogate(text))
                text.encode("utf-8")
        text, _ = core.decode_source(b"# coding: utf-7\n+2D3eAA-\n", "py")
        self.assertEqual(text, "# coding: utf-7\n\U0001F600\n")          # a valid pair is one character

    def test_the_write_backstop(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            reports.write_report(path, lambda: f"<p>a{HIGH}b{LOW}</p>", kind="html")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), "<p>a\ufffdb\ufffd</p>".encode("utf-8"))


class CliTests(unittest.TestCase):
    def test_review_tree_writes_both_reports_and_exits_1(self):
        for name, data in (("a.py", UTF7), ("b.py", UNICODE_ESCAPE)):
            with self.subTest(file=name), tempfile.TemporaryDirectory() as root, \
                    tempfile.TemporaryDirectory() as out:
                with open(os.path.join(root, name), "wb") as f:
                    f.write(data)
                p = subprocess.run([sys.executable, _support.CLI, root, "--ci", "--out-dir", out, "--quiet"],
                                   capture_output=True, encoding="utf-8", errors="replace", timeout=40)
                self.assertEqual(p.returncode, 1, p.stderr)                # was 5
                self.assertNotIn("internal", p.stderr)
                with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as f:
                    rules = {i["rule"] for i in json.load(f)["issues"]}
                self.assertIn("Q-ENCODING", rules)
                self.assertNotIn("Q-FLOW-SKIPPED", rules)                  # the flow engine parses it
                with open(os.path.join(out, "lazaret-report.html"), encoding="utf-8") as f:
                    self.assertIn("\ufffd", f.read())


if __name__ == "__main__":
    unittest.main()
