"""Review fix: annotated assignments and JS destructuring carry taint.

`target: str = request.args.get("next"); return redirect(target)` and
`const { file } = req.query; res.sendFile(file)` gave no findings, while the
plain-assignment forms did (review repro taintfn/).
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core


def found(src, lang):
    return {(i["rule"], i["line"]) for i in core.scan_file("x." + lang, src, lang)}


class PythonAnnotationTests(unittest.TestCase):
    def test_annotated_assignment(self):
        src = ("from flask import request, redirect\n"
               "def a():\n"
               "    target: str = request.args.get('next')\n"
               "    return redirect(target)\n")
        self.assertIn(("T-REDIR", 4), found(src, "py"))

    def test_complex_annotation(self):
        src = ("import os\n"
               "cmd: Optional[Dict[str, int]] = input()\n"
               "os.system(cmd)\n")
        self.assertIn(("T-CMD", 3), found(src, "py"))

    def test_keywords_are_not_names(self):
        self.assertEqual(core._assignment("else: x = request.args['a']", "py"), (None, None))
        self.assertEqual(core._assignment("case y: z = input()", "py"), (None, None))
        self.assertEqual(core._assignment("match = input()", "py"), (["match"], "input()"))
        src = ("import os\n"
               "if a:\n    pass\n"
               "else: x = input()\n"
               "else_ = 1\n"
               "os.system('ls')  # else\n")
        self.assertNotIn(("T-CMD", 6), found(src, "py"))

    def test_comparison_is_not_assignment(self):
        self.assertEqual(core._assignment("x == input()", "py"), (None, None))


class JavaScriptDestructuringTests(unittest.TestCase):
    def test_object_pattern(self):
        src = ("app.get('/a', (req, res) => {\n"
               "  const { file } = req.query;\n"
               "  res.sendFile(file);\n"
               "});\n")
        self.assertIn(("T-PATH", 3), found(src, "js"))

    def test_renamed_default_and_rest_bindings(self):
        self.assertEqual(core._destructured_names("{ a, b: c, d = 1, ...e }"), ["a", "c", "d", "e"])
        self.assertEqual(core._destructured_names("[a, , b = 2, ...c]"), ["a", "b", "c"])
        src = ("const { id, path: p } = req.params;\n"
               "require('child_process').exec(p);\n")
        self.assertIn(("T-CMD", 2), found(src, "js"))
        src = ("let [first] = process.argv.slice(2);\n"
               "eval(first);\n")
        self.assertIn(("T-CODE", 2), found(src, "js"))

    def test_untainted_destructuring(self):
        src = ("const { file } = config;\n"
               "res.sendFile(file);\n")
        self.assertNotIn(("T-PATH", 2), found(src, "js"))


if __name__ == "__main__":
    unittest.main()
