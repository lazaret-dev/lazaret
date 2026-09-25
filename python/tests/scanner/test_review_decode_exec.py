"""Review fix: decode-then-execute across lines, statements and member prefixes.

With --deps, `eval(\\n atob(…))`, `eval(globalThis.atob(…))`,
`const d = atob(…); eval(d)` and `execSync(Buffer.from(…, "base64").toString())`
gave zero findings; in project mode `exec(  # nosec\\n base64.b64decode(…))`
split the call so SC-EVAL-DECODE never fired (defeating "SC-* is
unsuppressible"). Fixtures are inert strings (base64 of console.log / print).
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

JS_B64 = '"Y29uc29sZS5sb2coMSk="'
PY_B64 = '"cHJpbnQoJ2hpJyk="'


def sc_lines(src, lang, dep):
    return sorted(i["line"] for i in core.scan_file("x." + lang, src, lang, dep=dep)
                  if i["rule"] == "SC-EVAL-DECODE")


class SingleStatementTests(unittest.TestCase):
    def test_member_prefixed_decoders_and_new_sinks(self):
        cases = ["eval(globalThis.atob(%s));" % JS_B64,
                 "eval(window.atob(%s));" % JS_B64,
                 'require("child_process").execSync(Buffer.from("ZWNobyBoaQ==", "base64").toString());',
                 "vm.runInThisContext(atob(%s));" % JS_B64,
                 "new Function(atob(%s))();" % JS_B64]
        for src in cases:
            for dep in (False, True):
                with self.subTest(src=src, dep=dep):
                    self.assertEqual(sc_lines(src + "\n", "js", dep), [1])

    def test_python_hex_decoders(self):
        for src in ("exec(bytes.fromhex('7072696e74283129'))",
                    "exec(binascii.unhexlify('7072696e74283129'))"):
            with self.subTest(src=src):
                self.assertEqual(sc_lines(src + "\n", "py", True), [1])

    def test_non_decoders_not_flagged(self):
        self.assertEqual(sc_lines("eval(JSON.parse(x));\n", "js", True), [])
        self.assertEqual(sc_lines("exec(open(f).read())\n", "py", True), [])


class MultiLineStatementTests(unittest.TestCase):
    def test_call_split_across_lines(self):
        src = "eval(\n  atob(%s));\n" % JS_B64
        self.assertEqual(sc_lines(src, "js", True), [1])
        self.assertEqual(sc_lines(src, "js", False), [1])
        src = "eval\n(atob(%s));\n" % JS_B64
        self.assertEqual(sc_lines(src, "js", True), [1])

    def test_comment_inside_split_call_cannot_suppress(self):
        src = "import base64\nexec(  # nosec\n    base64.b64decode(%s))\n" % PY_B64
        self.assertEqual(sc_lines(src, "py", False), [2])
        src = "eval( // nosec\n  /* x */ atob(%s));\n" % JS_B64
        self.assertEqual(sc_lines(src, "js", False), [1])

    def test_join_is_bounded(self):
        src = "eval(\n" + "\n" * 20 + "atob(%s));\n" % JS_B64
        self.assertEqual(sc_lines(src, "js", True), [])
        src = "eval(x);\natob(%s);\n" % JS_B64          # balanced: no join
        self.assertEqual(sc_lines(src, "js", True), [])


class DependencyFlowTests(unittest.TestCase):
    def test_decoded_variable_reaches_sink_same_line(self):
        src = "const d = atob(%s); eval(d);\n" % JS_B64
        self.assertEqual(sc_lines(src, "js", True), [1])

    def test_decoded_variable_through_copies(self):
        src = ('const raw = Buffer.from(p, "base64");\n'
               "const s = raw.toString();\n"
               "require('child_process').execSync(s);\n")
        self.assertEqual(sc_lines(src, "js", True), [3])
        issue = next(i for i in core.scan_file("x.js", src, "js", dep=True)
                     if i["rule"] == "SC-EVAL-DECODE")
        self.assertIn("assigned at line 1", issue["msg"])

    def test_python_flow(self):
        src = ("import base64, zlib\n"
               "blob = base64.b64decode(%s)\n"
               "code = zlib.decompress(blob)\n"
               "exec(code)\n" % PY_B64)
        self.assertEqual(sc_lines(src, "py", True), [4])

    def test_sink_before_assignment_or_unrelated_name(self):
        self.assertEqual(sc_lines("eval(d); const d = atob(%s);\n" % JS_B64, "js", True), [])
        self.assertEqual(sc_lines("const d = atob(%s);\neval(e);\n" % JS_B64, "js", True), [])
        self.assertEqual(sc_lines('const d = atob(p);\nconsole.log("eval(d)");\n', "js", True), [])

    def test_buffer_from_without_base64_is_not_a_decode(self):
        self.assertEqual(sc_lines("const d = Buffer.from(p);\neval(d);\n", "js", True), [])

    def test_project_mode_uses_taint_instead(self):
        src = "const d = atob(%s);\neval(d);\n" % JS_B64
        rules = {(i["rule"], i["line"]) for i in core.scan_file("x.js", src, "js")}
        self.assertIn(("T-CODE", 2), rules)
        self.assertNotIn(("SC-EVAL-DECODE", 2), rules)


if __name__ == "__main__":
    unittest.main()
