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


# The review's mysqldump case: MySQL reads O\'Brien as one string, the
# standard-SQL lexer ended the string at \' and took the /* in 'src/*.js' for
# a comment that hid every later line.
DUMP = ("INSERT INTO people VALUES (1,'O\\'Brien','src/*.js');\n"
        "GRANT ALL PRIVILEGES ON appdb.* TO 'marker_user'@'%';\n"
        "SELECT * FROM people;\n")


class MaskingFailsClosedTests(unittest.TestCase):
    """A comment only where both readings of the text agree (see the lexer
    notes in core): nothing some runtime executes is hidden, and no string
    passes for a comment holding a suppression marker."""

    def scan(self, name, src):
        return rules_at(core.scan_file(name, src, name.rsplit(".", 1)[1].replace("tsx", "js")
                                       .replace("jsx", "js").replace("ts", "js")))

    def test_mysql_escaped_quote_opens_no_comment(self):
        want = [("SQL-GRANT-ALL", 2), ("SQL-SELECT-STAR", 3)]
        self.assertEqual(self.scan("dump.sql", DUMP), want)
        self.assertEqual(self.scan("control.sql", DUMP.replace("O\\'Brien", "OBrien")), want)
        self.assertEqual(core.comment_mask(DUMP.split("\n"), "sql"), [False] * 4)

    def test_marker_in_a_mysql_string_suppresses_nothing(self):
        self.assertEqual(self.scan("m.sql", "SELECT 'it\\'s -- nosec'; GRANT ALL ON t TO u;\n"),
                         [("SQL-GRANT-ALL", 1)])

    def test_mysql_executes_bang_comments_and_quotes_names(self):
        src = ("/*!50000 GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' */;\n"
               "SELECT `a/*b` FROM t;\nGRANT ALL ON t TO u;\n"
               "/* GRANT ALL ON y TO z */\n-- nosec\nGRANT ALL ON v TO w;\n")
        self.assertEqual(self.scan("x.sql", src), [("SQL-GRANT-ALL", 1), ("SQL-GRANT-ALL", 3)])

    def test_jsx_text_opens_no_comment(self):
        src = "const a = <p>Docs at /api/* and https://example.invalid/x</p>;\neval(input)\n// */\n"
        self.assertEqual(self.scan("a.jsx", src), [("S-EVAL-JS", 2)])
        self.assertEqual(self.scan("b.js", "export default <p>/api/*</p>;\neval(input)\n"),
                         [("S-EVAL-JS", 2)])
        self.assertEqual(self.scan("c.tsx", "if (x) <a title='/*'>{y}/*</a>;\neval(input)\n"),
                         [("S-EVAL-JS", 2)])

    def test_marker_in_jsx_text_suppresses_nothing(self):
        self.assertEqual(self.scan("a.jsx", "const a = <p>// nosec</p>; eval(x)\n"), [("S-EVAL-JS", 1)])

    def test_comments_in_jsx_code_are_comments(self):
        src = ("const a = (\n  <div id=\"x\"\n    // eval(p)\n    title={\n      /* eval(q) */\n      t}>\n"
               "    {\n      // eval(s)\n    }\n    <br/>\n  </div>\n);\n// eval(u)\n")
        self.assertEqual(self.scan("a.jsx", src), [])
        self.assertEqual([i for i, c in enumerate(core.comment_mask(src.split("\n"), "js")) if c],
                         [2, 4, 7, 12])

    def test_typescript_generics_and_assertions_keep_their_comments(self):
        for name, src in (("a.tsx", "const id = <T,>(x: T) => x;\n// eval(z)\n"),
                          ("b.ts", "const id = <T>(x: T) => x;\n// eval(z)\n"),
                          ("c.ts", "const el = <HTMLInputElement>document.body;\n// eval(z)\n"),
                          ("d.js", "if (a[0] < b) { f() }\n// eval(z)\nif (g(x) < h) {}\n// eval(w)\n")):
            with self.subTest(file=name):
                self.assertEqual(self.scan(name, src), [])

    def test_jsx_in_a_ts_file_is_not_read(self):
        # TypeScript parses no JSX in .ts: `<p>` there is a type assertion
        src = "const a = <p>x /* </p>;\neval(input)\n*/\n"
        self.assertEqual(self.scan("a.ts", src), [])
        self.assertEqual(self.scan("a.tsx", src), [("S-EVAL-JS", 2)])


class PythonCommentsAreVersionIndependentTests(unittest.TestCase):
    """Python comments came from the running interpreter's tokenizer, which
    reads f-strings differently from 3.12 on (PEP 701) and fails on some
    files there that 3.10/3.11 tokenize. The same file had other metrics and
    other suppressions on different Pythons, and the npm engine agreed with
    only some of them. Both engines now lex Python the same way on every
    version: a comment only where the pre-3.12 and the PEP 701 readings agree."""

    FSTRING = 'x = f"""{\n    # a note\n    1\n}"""\ny = 2\n'

    def test_comment_line_in_an_fstring_field(self):
        # 3.12+ tokenizer: a COMMENT (ncloc 4, comments 1); 3.10/3.11: string
        self.assertEqual(core.comment_mask(self.FSTRING.split("\n"), "py"), [False] * 6)
        m = core.compute_metrics([{"path": "f.py", "lang": "py", "content": self.FSTRING}])
        self.assertEqual((m["ncloc"], m["comments"]), (5, 0))

    def test_marker_after_an_unterminated_string(self):
        # 3.10/3.11 tokenizer: ERRORTOKEN, then a COMMENT that suppressed the eval
        self.assertEqual(rules_at(core.scan_file("e.py", "z = eval(x) + 'unterminated  # nosec\n", "py")),
                         [("S-EVAL-PY", 1)])

    def test_marker_in_a_string_inside_an_fstring(self):
        # 3.12+: the '#' is in a string in the field; the pre-3.12 reading
        # alone would take it for a comment (and forge the suppression)
        for src in ('x = f"{d["# nosec"]}" + eval(y)\n', "x = t'{d['# nosec']}' + eval(y)\n",
                    'x = f"{v:# nosec}"; eval(y)\n', 'x = f"""{d["""# nosec"""]}""" + eval(y)\n'):
            with self.subTest(src=src):
                self.assertEqual(rules_at(core.scan_file("f.py", src, "py")), [("S-EVAL-PY", 1)])

    def test_ordinary_comments(self):
        src = ('s = f"{a!r:>{w}}"  # nosec\nt = f"{{# not a field}}"  # c\n  # full\n'
               'u = rf"\\{x}" "#"  # c\nv = f"\\N{BULLET} {x}"\n# eval(z)\n')
        self.assertEqual(core.comment_mask(src.split("\n"), "py"),
                         [False, False, True, False, False, True, False])
        self.assertEqual(rules_at(core.scan_file("o.py", src, "py")), [])


if __name__ == "__main__":
    unittest.main()
