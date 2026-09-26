"""Engine parity for the lexing / encoding review fixes: the Python CLI and
the npm CLI report the same findings (rule, file, line, severity, message),
metrics, gate and exit code on a tree exercising each of them (findings
only the Python engine has, its cross-file flow engine's, set aside as in
test_js_parity). The
expectations themselves are in tests/scanner/test_review_lexing.py and
js/test/review-lexing.test.js; this only holds the engines to each other.
All content is inert (nothing is executed; hosts are .invalid). Skipped
where node is missing.
"""
import collections
import os
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NODE, _python_only, both, issue_key

TREE = {
    # comment masking fails closed (a comment only where both readings agree)
    "mask/dump.sql": ("INSERT INTO people VALUES (1,'O\\'Brien','src/*.js');\n"
                      "GRANT ALL PRIVILEGES ON appdb.* TO 'marker_user'@'%';\nSELECT * FROM people;\n"),
    "mask/marker.sql": "SELECT 'it\\'s -- nosec'; GRANT ALL ON t TO u;\n",
    "mask/mysql.sql": ("/*!50000 GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' */;\nSELECT `a/*b` FROM t;\n"
                       "GRANT ALL ON t TO u;\n/* GRANT ALL ON y TO z */\n-- nosec\nGRANT ALL ON v TO w;\n"),
    "mask/text.jsx": "const a = <p>Docs at /api/* and https://example.invalid/x</p>;\neval(input)\n// */\n",
    "mask/attr.tsx": "if (x) <a title='/*'>{y}/*</a>;\neval(input)\n",
    "mask/marker.jsx": "const a = <p>// nosec</p>; eval(x)\n",
    "mask/code.jsx": ("const a = (\n  <div id=\"x\"\n    // eval(p)\n    title={\n      /* eval(q) */\n      t}>\n"
                      "    {\n      // eval(s)\n    }\n    <br/>\n  </div>\n);\n// eval(u)\n"),
    "mask/generic.tsx": "const id = <T,>(x: T) => x;\n// eval(z)\n",
    "mask/assert.ts": "const el = <HTMLInputElement>document.body;\n// eval(z)\n",
    "mask/jsx.ts": "const a = <p>x /* </p>;\neval(input)\n*/\n",
    "mask/jsx.tsx": "const a = <p>x /* </p>;\neval(input)\n*/\n",
    # Python comments do not depend on the interpreter's tokenizer
    "py/fstring.py": 'x = f"""{\n    # a note\n    1\n}"""\ny = 2\n',
    "py/nested.py": ('x = f"{d["# nosec"]}" + eval(y)\nx = t\'{d[\'# nosec\']}\' + eval(y)\n'
                     'x = f"{v:# nosec}"; eval(y)\n'),
    "py/unterminated.py": "z = eval(x) + 'unterminated  # nosec\n",
    # a coding cookie on line 2 of a CRLF / CR file
    "enc/crlf7.py": b"#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1 # +AAo-eval(x)\r\n",
    "enc/crlf_latin1.py": b"#!/usr/bin/env python\r\n# coding: latin-1\r\ns = '\xe9'\r\neval(s)\r\n",
    "enc/cr_latin1.py": b"#!/usr/bin/env python\r# coding: latin-1\rs = '\xe9'\r",
    # codecs: Python's tables for single-byte ones; SC-TRUNCATED for the rest
    "enc/ebcdic.py": "# coding: cp037\nprint(1)\nx = eval(input())\n",
    "enc/dos.py": b"# coding: cp437\nx = eval(y)  # \x82t\x82\n",
    "enc/iso16.py": b"# coding: iso8859_16\ns = '\xa1\xa4'\neval(s)\n",
    "enc/cp1252.py": b"# coding: cp1252\ns = '\x80\x81\x9f'\n",
    "enc/win874.py": b"# coding: windows-874\ns = '\x80'\n",
    "enc/palmos.py": b"# coding: palmos\ns = '\x9b'\n",
    "enc/u32.py": "# coding: utf-32\nx = eval(y)\n",
    "enc/uesc.py": "# coding: unicode_escape\n# \\x0aeval(z)\n",
    # extensions as os.path.splitext reads them: leading dots are no extension
    "ext/..js": "var a = 1;\nconsole.log(a);\n",
    "ext/...py": 'import os\nos.system("echo hi")\n',
    "ext/..so": b"",
    "ext/.x.js": "var b = 2;\n",
    # S-CHMOD's \s* is unbounded
    "misc/chmod.py": "os.chmod(p," + " " * 80 + "0o777)\n",
    # the quadratic comment checks, at a size both engines finish quickly
    "perf/escapes.js": "x=1;" + "/**/\\u0061" * 20000 + "\n",
}


def write_tree(root, tree):
    for rel, data in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


@unittest.skipUnless(NODE, "node is not installed")
class LexingParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, tree, extra=(), label="lexing"):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root, extra=extra)
        self.assertIsNotNone(js, f"{label}: JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"{label}: Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        py_only = [i for i in py["issues"] if _python_only(i)]
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"] if not _python_only(i))
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []},
                         f"{label}: the engines disagree")
        self.assertEqual(js["metrics"], py["metrics"], f"{label}: metrics")
        if not py_only:        # otherwise the Python-only findings legitimately move these
            for field in DERIVED:
                self.assertEqual(js[field], py[field], f"{label}: {field}")
            self.assertEqual(js_exit, py_exit, f"{label}: exit code")
        return py

    def test_lexing_tree(self):
        report = self.assert_same(TREE)
        found = {(i["rule"], i["file"].replace("\\", "/"), i["line"]) for i in report["issues"]}
        for want in (("SQL-GRANT-ALL", "mask/dump.sql", 2), ("S-EVAL-JS", "mask/text.jsx", 2),
                     ("S-EVAL-JS", "mask/marker.jsx", 1), ("S-EVAL-PY", "py/unterminated.py", 1),
                     ("SC-UTF7", "enc/crlf7.py", 2), ("Q-ENCODING", "enc/cr_latin1.py", 1),
                     ("SC-TRUNCATED", "enc/u32.py", 1), ("SC-TRUNCATED", "enc/uesc.py", 1),
                     ("S-CHMOD", "misc/chmod.py", 1)):
            self.assertIn(want, found)
        self.assertNotIn(("S-EVAL-PY", "enc/ebcdic.py", 3), found)     # decoded as EBCDIC, as Python reads it
        self.assertEqual({f for _, f, _ in found if f.startswith("ext/")}, {"ext/.x.js"})


if __name__ == "__main__":
    unittest.main()
