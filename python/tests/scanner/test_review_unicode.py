"""Review fix: Unicode spellings of code no longer evade ASCII rules; S-BIDI.

Repros (review uni/, ws/, bidi/, verify/u1): Python runs NFKC-folded
identifiers (`ｅｘｅｃ(base64.b64decode(…))`, `os.ｓｙｓｔｅｍ(input())`), JS runs
identifier escapes (`\\u0065val(atob(…))`) and treats U+FEFF as whitespace
(`eval<U+FEFF>(atob(…))`) — all scanned clean. Trojan Source bidi controls
were not reported at all. Fixtures are inert strings; nothing is executed.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

B64 = '"cHJpbnQoJ2hpJyk="'           # base64 of print('hi')


def found(src, lang, dep=False):
    return {(i["rule"], i["line"]) for i in core.scan_file("x." + lang, src, lang, dep=dep)}


class PythonNFKCTests(unittest.TestCase):
    def test_fullwidth_exec_and_system(self):
        src = ("import base64, os\n"
               "\uff45\uff58\uff45\uff43(base64.b64decode(" + B64 + "))\n"
               "os.\uff53\uff59\uff53\uff54\uff45\uff4d(input())\n")
        got = found(src, "py")
        for rule, line in (("SC-EVAL-DECODE", 2), ("S-EVAL-PY", 2), ("S-OSCMD-PY", 3),
                           ("T-CMD", 3)):
            self.assertIn((rule, line), got)
        self.assertIn(("SC-EVAL-DECODE", 2), found(src, "py", dep=True))

    def test_snippet_keeps_original_text(self):
        src = "import os\nos.\uff53\uff59\uff53\uff54\uff45\uff4d(input())\n"
        issue = next(i for i in core.scan_file("x.py", src, "py") if i["rule"] == "S-OSCMD-PY")
        self.assertIn("\uff53\uff59\uff53", issue["snippet"][1])

    def test_ascii_lines_are_not_copied(self):
        lines = ["x = 1", "y = 2"]
        ctx = core._FileCtx(lines, "py")
        self.assertIs(ctx.mlines[0], lines[0])


class JavaScriptEscapeTests(unittest.TestCase):
    def test_identifier_escape(self):
        for esc in ("\\u0065val", "\\u{65}val", "ev\\u0061l"):
            with self.subTest(esc=esc):
                src = esc + '(atob("Y29uc29sZS5sb2coMSk="));\n'
                self.assertIn(("SC-EVAL-DECODE", 1), found(src, "js"))
                self.assertIn(("S-EVAL-JS", 1), found(src, "js"))
                self.assertIn(("SC-EVAL-DECODE", 1), found(src, "js", dep=True))

    def test_bom_as_whitespace(self):
        src = ('eval\ufeff(atob("Y29uc29sZS5sb2coMSk="));\n'
               'require("child_process").exec\ufeff(process.argv[2] + "");\n')
        got = found(src, "js")
        self.assertIn(("SC-EVAL-DECODE", 1), got)
        self.assertIn(("T-CMD", 2), got)

    def test_escapes_inside_string_literals_are_not_decoded(self):
        ctx = core._FileCtx(['var s = "\\u0065val(x)"; t = \'\\u0065\'; \\u0065val(y);'], "js")
        self.assertEqual(ctx.mlines[0], 'var s = "\\u0065val(x)"; t = \'\\u0065\'; eval(y);')

    def test_quote_inside_regex_literal_does_not_hide_escape(self):
        ctx = core._FileCtx(["x = /'/; \\u0065val(y);"], "js")
        self.assertEqual(ctx.mlines[0], "x = /'/; eval(y);")

    def test_non_identifier_escapes_left_alone(self):
        ctx = core._FileCtx(["a\\u0028b\\u{110000}c"], "js")
        self.assertEqual(ctx.mlines[0], "a\\u0028b\\u{110000}c")


class BidiTests(unittest.TestCase):
    def test_trojan_source_comment(self):
        src = ("var isAdmin = false;\n"
               "/*\u202e } \u2066if (isAdmin)\u2069 \u2066 begin admins only */\n"
               "console.info('ok');\n"
               "/* end admins only \u202e { \u2066*/\n")
        got = found(src, "js")
        self.assertIn(("S-BIDI", 2), got)
        self.assertIn(("S-BIDI", 4), got)
        issue = next(i for i in core.scan_file("t.js", src, "js") if i["rule"] == "S-BIDI")
        self.assertEqual((issue["sev"], issue["type"]), ("CRITICAL", "VULN"))
        self.assertEqual(issue["msg"], "Bidirectional control character in source (Trojan Source)")

    def test_every_control_and_language(self):
        for cp in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)):
            for lang, line in (("py", "x = 1  # %s\n"), ("js", "s = '%s';\n"),
                               ("sql", "SELECT '%s';\n")):
                with self.subTest(cp=hex(cp), lang=lang):
                    self.assertIn(("S-BIDI", 1), found(line % chr(cp), lang))

    def test_other_format_chars_not_flagged(self):
        self.assertNotIn(("S-BIDI", 1), found("s = '\u200f\u200e\u200d'\n", "py"))


if __name__ == "__main__":
    unittest.main()
