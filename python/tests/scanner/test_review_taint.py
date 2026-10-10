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
        # (the engine's own tests hold the assignments a line makes: taint_tests.rs)
        self.assertIn(("T-CMD", 3), found("import os\nmatch = input()\nos.system(match)\n", "py"))
        src = ("import os\n"
               "if a:\n    pass\n"
               "else: x = input()\n"
               "else_ = 1\n"
               "os.system('ls')  # else\n")
        self.assertNotIn(("T-CMD", 6), found(src, "py"))

    def test_comparison_is_not_assignment(self):
        self.assertNotIn(("T-CMD", 3), found("import os\nx == input()\nos.system(x)\n", "py"))


class JavaScriptDestructuringTests(unittest.TestCase):
    def test_object_pattern(self):
        src = ("app.get('/a', (req, res) => {\n"
               "  const { file } = req.query;\n"
               "  res.sendFile(file);\n"
               "});\n")
        self.assertIn(("T-PATH", 3), found(src, "js"))

    def test_renamed_default_and_rest_bindings(self):
        for name, n in (("a", 1), ("c", 2), ("d", 3), ("e", 4)):
            src = "const { a, b: c, d = 1, ...e } = req.query;\n" + "\n" * (n - 1) + f"eval({name});\n"
            self.assertIn(("T-CODE", n + 1), found(src, "js"))
        self.assertIn(("T-CODE", 2), found("let [a, , b = 2, ...c] = process.argv;\neval(c);\n", "js"))
        self.assertNotIn(("T-CODE", 2), found("const { b: c } = req.query;\neval(b);\n", "js"))
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
