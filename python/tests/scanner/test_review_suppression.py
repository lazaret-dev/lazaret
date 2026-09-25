"""Review fix: suppression markers are parsed from real comments only.

Defects (review repros sup/, sup2/):
  * a `# nosec` + triple-quote line that closes a docstring suppressed the
    next line;
  * `` `\\n// NOSONAR`; eval(...) `` (marker inside a template literal);
  * Python `os.system(input()) --nosec` (an expression, not a comment);
  * `# nosec   ` (trailing spaces) and `# nosec - reviewed by bob` were
    NOT honored, and a SQL `-- nosec` on the line above was ignored.
Invariants that held up and must stay: SC-*/X-* never suppressible, dep
mode ignores markers, suppression never crosses files.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core


def rules(src, lang, dep=False, name=None):
    return {(i["rule"], i["line"]) for i in core.scan_file(name or "x." + lang, src, lang, dep=dep)}


class ForgedMarkerTests(unittest.TestCase):
    def test_docstring_closing_line_is_not_a_comment(self):
        src = 'import os\nHELP = """Usage:\n# nosec"""\nos.system(input())\n'
        self.assertIn(("S-OSCMD-PY", 4), rules(src, "py"))

    def test_marker_inside_template_literal(self):
        src = "const banner = `\n// NOSONAR`; eval(process.argv[2]);\n"
        self.assertIn(("S-EVAL-JS", 2), rules(src, "js"))

    def test_python_decrement_expression_is_not_a_comment(self):
        src = "import os\nnosec = 0\nos.system(input()) --nosec\n"
        self.assertIn(("S-OSCMD-PY", 3), rules(src, "py"))

    def test_js_private_field_named_nosec(self):
        src = "class A {\n  #nosec = eval(process.argv[2]);\n}\n"
        self.assertIn(("S-EVAL-JS", 2), rules(src, "js"))

    def test_sql_dash_marker_does_not_count_in_python_or_js(self):
        self.assertIn(("S-OSCMD-PY", 2), rules("import os\nos.system(x) -- nosec\n", "py"))
        self.assertIn(("S-EVAL-JS", 1), rules("eval(x) -- nosec\n", "js"))

    def test_line_above_must_be_a_standalone_comment(self):
        src = "x = 1  # nosec\nos.system(input())\n"
        self.assertIn(("S-OSCMD-PY", 2), rules(src, "py"))


class HonoredMarkerTests(unittest.TestCase):
    def test_trailing_whitespace_and_free_text_reason(self):
        for tail in ("# nosec   ", "# nosec - reviewed by bob", "# nosec", "# NOSEC: reviewed",
                     "#nosec\t"):
            with self.subTest(tail=tail):
                src = "import os\nos.system(input())  " + tail + "\n"
                self.assertNotIn(("S-OSCMD-PY", 2), rules(src, "py"))

    def test_js_reason_after_colon(self):
        self.assertNotIn(("S-EVAL-JS", 1), rules("eval(x); // nosec: reviewed\n", "js"))
        self.assertNotIn(("S-EVAL-JS", 2), rules("// NOSONAR\neval(x);\n", "js"))

    def test_sql_marker_on_line_above_and_trailing(self):
        src = "-- nosec\nGRANT ALL ON db.* TO bob;\nGRANT ALL ON db.* TO carl; -- nosec\n"
        self.assertFalse({r for r in rules(src, "sql") if r[0] == "SQL-GRANT-ALL"})

    def test_scoped_marker_names_rules(self):
        src = "import os\nos.system(input())  # nosec: S-OSCMD-PY\n"
        found = rules(src, "py")
        self.assertNotIn(("S-OSCMD-PY", 2), found)
        self.assertIn(("T-CMD", 2), found)
        src = "import os\nos.system(input())  # lazaret-ignore: s-oscmd-py, T-CMD\n"
        self.assertFalse({r for r in rules(src, "py") if r[1] == 2})

    def test_scoped_marker_for_other_rule_does_not_suppress(self):
        src = "import os\nos.system(input())  # nosec: S-EVAL-PY\n"
        self.assertIn(("S-OSCMD-PY", 2), rules(src, "py"))

    def test_marker_parse(self):
        m = core.marker_in_comment("x()  # nosec: S-A, T-B  because", "py")
        self.assertEqual(core._marker_rules(m), frozenset({"S-A", "T-B"}))
        self.assertIsNone(core._marker_rules(core.marker_in_comment("x()  # nosec   ", "py")))
        self.assertIsNone(core.marker_in_comment("x()  # nosecret", "py"))


class InvariantTests(unittest.TestCase):
    def test_sc_rules_unsuppressible(self):
        src = 'eval(atob("Y29uc29sZS5sb2coMSk=")); // nosec\n'
        self.assertIn(("SC-EVAL-DECODE", 1), rules(src, "js"))

    def test_dep_mode_ignores_markers(self):
        src = 'k = "AKIA' + "A" * 16 + '"  # nosec\n'
        self.assertIn(("S-TOKEN", 1), rules(src, "py", dep=True))
        self.assertNotIn(("S-TOKEN", 1), rules(src, "py"))

    def test_marker_does_not_cross_files(self):
        issue = {"rule": "S-OSCMD-PY", "line": 1}
        other_file = ["# nosec", "x = 1"]
        self.assertFalse(core.is_suppressed(issue, ["os.system(x)"], lang="py"))
        self.assertTrue(core.is_suppressed({"rule": "S-OSCMD-PY", "line": 2}, other_file, lang="py"))
        # a marker in file A never reaches a finding in file B
        a = core.scan_file("a.py", "# nosec\n", "py")
        b = core.scan_file("b.py", "import os\nos.system(input())\n", "py")
        self.assertEqual(a, [])
        self.assertIn("S-OSCMD-PY", {i["rule"] for i in b})

    def test_crlf_marker(self):
        src = "import os\r\nos.system(input())  # nosec\r\n"
        self.assertNotIn(("S-OSCMD-PY", 2), rules(src, "py"))


if __name__ == "__main__":
    unittest.main()
