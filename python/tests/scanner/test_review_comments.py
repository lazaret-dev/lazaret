"""Review fix: comment detection is a per-file lexer, not a line prefix test.

is_comment() used to treat any JS/SQL line starting with "/*" or "*" as a
comment, so every rule skipped `/**/eval(atob(…))`, a `  * eval(…)`
continuation line, a minified bundle opening with a `/*! … */` banner and
`/* x */ GRANT ALL … TO PUBLIC;` — in project and --deps mode alike. JS also
ends lines at U+2028/U+2029, which hid `// note<U+2028>eval(…)`.

All fixtures are inert strings (base64 of `console.log(1)`); nothing runs.
"""
import unittest

from tests import _support  # noqa: F401  (puts src/ on sys.path)
from lazaret.scanner import core

PAYLOAD = 'eval(atob("Y29uc29sZS5sb2coMSk="));'


def rules_at(issues, line):
    return {i["rule"] for i in issues if i["line"] == line}


class CommentEvasionTests(unittest.TestCase):
    def assert_flagged(self, src, line, lang="js", dep=False):
        issues = core.scan_file("x." + lang, src, lang, dep=dep)
        self.assertIn("SC-EVAL-DECODE", rules_at(issues, line), issues)
        return issues

    def test_empty_block_comment_prefix(self):
        for dep in (False, True):
            with self.subTest(dep=dep):
                issues = self.assert_flagged("/**/" + PAYLOAD + "\n", 1, dep=dep)
                if not dep:
                    self.assertIn("S-EVAL-JS", rules_at(issues, 1))

    def test_star_continuation_line_outside_block_comment(self):
        self.assert_flagged("const x = 1\n  * " + PAYLOAD + "\n", 2)
        self.assert_flagged("const x = 1\n  * " + PAYLOAD + "\n", 2, dep=True)

    def test_unicode_line_separator_ends_js_line_comment(self):
        for sep in ("\u2028", "\u2029"):
            with self.subTest(sep=hex(ord(sep))):
                self.assert_flagged("// note" + sep + PAYLOAD + "\n", 2)
                self.assert_flagged("// note" + sep + PAYLOAD + "\n", 2, dep=True)

    def test_minified_bundle_with_license_banner(self):
        src = ('/*! lib v1 | MIT */!function(){var k="A";' + PAYLOAD
               + 'require("child_process").exec(process.argv[2]);}();\n')
        issues = self.assert_flagged(src, 1)
        self.assertIn("T-CMD", rules_at(issues, 1))
        self.assert_flagged(src, 1, dep=True)

    def test_sql_block_comment_prefix(self):
        issues = core.scan_file("g.sql", "/* x */ GRANT ALL ON db.* TO PUBLIC;\n", "sql")
        self.assertTrue({"SQL-GRANT-ALL", "SQL-GRANT-PUBLIC"} <= rules_at(issues, 1))

    def test_real_block_comment_lines_still_skipped(self):
        src = "/**\n * example: " + PAYLOAD + "\n */\nfoo();\n"
        issues = core.scan_file("x.js", src, "js")
        self.assertNotIn("SC-EVAL-DECODE", {i["rule"] for i in issues})
        issues = core.scan_file("g.sql", "/*\n GRANT ALL ON t TO PUBLIC;\n*/\n", "sql")
        self.assertNotIn("SQL-GRANT-ALL", {i["rule"] for i in issues})

    def test_regex_literal_does_not_open_a_comment(self):
        # a lexer without regex literals would read /[/*]/ as a comment
        # opener and hide line 2 until the "*/" on line 3
        src = "var r = /[/*]/;\n" + PAYLOAD + "\n// */\n"
        self.assert_flagged(src, 2)

    def test_taint_and_entropy_no_longer_gated_by_block_prefix(self):
        src = ('/**/const d = req.query.cmd;\n'
               '/**/require("child_process").exec(d);\n'
               '/**/const k = "Zk3q9XvB2mT7pL4wR8sY1nC6hJ0dF5gA";\n')
        issues = core.scan_file("x.js", src, "js")
        self.assertIn("T-CMD", rules_at(issues, 2))
        self.assertIn("S-ENTROPY", rules_at(issues, 3))


class CommentMaskTests(unittest.TestCase):
    def mask(self, src, lang):
        return core.comment_mask(src.split("\n"), lang)

    def test_js(self):
        self.assertEqual(self.mask("/**\n * doc\n */\ncode();", "js"),
                         [True, True, True, False])
        self.assertEqual(self.mask("a(); // c\n// only\n/* x */ b();", "js"),
                         [False, True, False])
        # template literal spans lines: its content is string, not comment
        self.assertEqual(self.mask("const t = `\n// NOSONAR`; x();", "js"), [False, False])

    def test_sql(self):
        self.assertEqual(self.mask("-- c\nSELECT 1; -- c\n/* a\n b */", "sql"),
                         [True, False, True, True])
        # SQL strings span lines, so a "/*" inside one opens nothing
        self.assertEqual(self.mask("SELECT 'a\n/* not';\nGRANT x;", "sql"),
                         [False, False, False])

    def test_python_uses_the_tokenizer(self):
        src = 'HELP = """Usage:\n# not a comment"""\nx = 1  # trailing\n  # full'
        self.assertEqual(self.mask(src, "py"), [False, False, False, True])

    def test_python_fallback_lexer_when_file_does_not_tokenize(self):
        src = 'def f(:\n    HELP = """\n# in string\n"""\n  # real'
        self.assertIsNone(core._py_tokenize_comment_spans(src))
        self.assertEqual(self.mask(src, "py"), [False, False, False, False, True])

    def test_is_comment_is_line_local(self):
        self.assertTrue(core.is_comment("  // x", "js"))
        self.assertTrue(core.is_comment("/* x */", "js"))
        self.assertFalse(core.is_comment("/**/eval(x)", "js"))
        self.assertFalse(core.is_comment("  * foo", "js"))
        self.assertTrue(core.is_comment("-- x", "sql"))
        self.assertFalse(core.is_comment("/* x */ GRANT ALL", "sql"))
        self.assertTrue(core.is_comment("   # x", "py"))
        self.assertFalse(core.is_comment("", "py"))

    def test_source_lines_splits_js_line_terminators_only(self):
        self.assertEqual(core.source_lines("a\u2028b\u2029c\r\nd", "js"), ["a", "b", "c", "d"])
        self.assertEqual(core.source_lines("a\u2028b", "py"), ["a\u2028b"])

    def test_metrics_count_jsdoc_as_comments(self):
        files = [{"path": "a.js", "lang": "js", "dep": False,
                  "content": "/**\n * doc\n */\nfoo();\n/**/bar();\n"}]
        m = core.compute_metrics(files)
        self.assertEqual((m["comments"], m["ncloc"]), (3, 2))


if __name__ == "__main__":
    unittest.main()
