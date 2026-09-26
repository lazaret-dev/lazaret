"""The dashboard's side of the lexing / encoding review fixes.

Runs the page's script in node:vm (_dashboard_vm.py): its copy of the npm
engine must be as fast as the CLIs on the inputs that used to be quadratic,
and report exactly what lazaret.scanner.core reports on the new inputs
(test_review_lexing.py and friends hold the expectations themselves). All
input is inert: nothing is executed, hosts are TEST-NET or .invalid.
"""
import base64
import collections
import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash
from tests.scanner.test_review_dashboard_parity import cli_upload, issue_key, short

# Generous (machines differ); before the fix the page took ~20 s per case.
LIMIT_MS = 4000

TIMED = """(() => {
  const content = %s;
  const t0 = Date.now();
  const issues = scanFile({name: "a.js", lang: "js", content});
  return [Date.now() - t0, issues.map((i) => i.rule + "@" + i.line)];
})()"""


# Comment masking fails closed (a comment only where both readings of the
# text agree) and Python comments no longer depend on the interpreter.
MASKING = [
    ("dump.sql", "sql", "INSERT INTO people VALUES (1,'O\\'Brien','src/*.js');\n"
     "GRANT ALL PRIVILEGES ON appdb.* TO 'marker_user'@'%';\nSELECT * FROM people;\n"),
    ("marker.sql", "sql", "SELECT 'it\\'s -- nosec'; GRANT ALL ON t TO u;\n"),
    ("mysql.sql", "sql", "/*!50000 GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' */;\nSELECT `a/*b` FROM t;\n"
     "GRANT ALL ON t TO u;\n/* GRANT ALL ON y TO z */\n-- nosec\nGRANT ALL ON v TO w;\n"),
    ("text.jsx", "js", "const a = <p>Docs at /api/* and https://example.invalid/x</p>;\neval(input)\n// */\n"),
    ("default.js", "js", "export default <p>/api/*</p>;\neval(input)\n"),
    ("attr.tsx", "js", "if (x) <a title='/*'>{y}/*</a>;\neval(input)\n"),
    ("marker.jsx", "js", "const a = <p>// nosec</p>; eval(x)\n"),
    ("code.jsx", "js", "const a = (\n  <div id=\"x\"\n    // eval(p)\n    title={\n      /* eval(q) */\n      t}>\n"
     "    {\n      // eval(s)\n    }\n    <br/>\n  </div>\n);\n// eval(u)\n"),
    ("generic.tsx", "js", "const id = <T,>(x: T) => x;\n// eval(z)\n"),
    ("generic.ts", "js", "const id = <T>(x: T) => x;\n// eval(z)\n"),
    ("assert.ts", "js", "const el = <HTMLInputElement>document.body;\n// eval(z)\n"),
    ("compare.js", "js", "if (a[0] < b) { f() }\n// eval(z)\nif (g(x) < h) {}\n// eval(w)\n"),
    ("jsx.ts", "js", "const a = <p>x /* </p>;\neval(input)\n*/\n"),
    ("jsx.tsx", "js", "const a = <p>x /* </p>;\neval(input)\n*/\n"),
    ("fstring.py", "py", 'x = f"""{\n    # a note\n    1\n}"""\ny = 2\n'),
    ("nested.py", "py", 'x = f"{d["# nosec"]}" + eval(y)\nx = t\'{d[\'# nosec\']}\' + eval(y)\n'
     'x = f"{v:# nosec}"; eval(y)\nx = f"""{d["""# nosec"""]}""" + eval(y)\n'),
    ("unterminated.py", "py", "z = eval(x) + 'unterminated  # nosec\n"),
    ("ordinary.py", "py", 's = f"{a!r:>{w}}"  # nosec\nt = f"{{# not a field}}"  # c\n  # full\n'
     'u = rf"\\{x}" "#"  # c\nv = f"\\N{BULLET} {x}"\n# eval(z)\n'),
]


# Other places the page read input differently from core.
MISC = [
    ("chmod.py", "py", "os.chmod(p," + " " * 80 + "0o777)\nos.chmod(q,\t\t0o644)\n"),
    # re.I folding (İ, ı are i; ſ is s) and ASCII-only markers
    ("fold.sql", "sql", "SELECT a FROM t WİTH (NOLOCK);\nſET @q = 'SELECT 1 ' + @x;\nEXECUTE İMMEDIATE 'x' || y;\n"),
    ("marker.js", "js", "eval(a) // noſec\neval(b) // lazaret-ıgnore\neval(c) // NOSONAR\n"
     "eval(d) // nosec: S-EVAL-JS, ſ-X\neval(e) // nosec: S-EVAL-JS\n"),
]

# Uploads: raw bytes through the page's decoder, against core.decode_source.
UPLOADS = [
    # a cookie on line 2 of a CRLF (or CR) file: the page counted \r\n twice
    ("crlf7.py", b"#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1 # +AAo-eval(x)\r\n"),
    ("crlf_latin1.py", b"#!/usr/bin/env python\r\n# coding: latin-1\r\ns = '\xe9'\r\neval(s)\r\n"),
    ("cr_latin1.py", b"#!/usr/bin/env python\r# coding: latin-1\rs = '\xe9'\r"),
]


@dash.requires_node
class DashboardLexingTests(unittest.TestCase):
    def assert_same_findings(self, name, cli, page):
        a, b = collections.Counter(map(issue_key, cli)), collections.Counter(map(issue_key, page))
        if a != b:
            self.fail(f"{name}: findings differ\n  only in the CLI:\n    "
                      + "\n    ".join(short(json.loads(k)) for k in (a - b).elements())
                      + "\n  only in the dashboard:\n    "
                      + "\n    ".join(short(json.loads(k)) for k in (b - a).elements()))

    def compare(self, cases):
        """cases: [(name, lang, content)] -> the page's findings, checked against core."""
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": lang, "content": c}}
                         for n, lang, c in cases])
        for (name, lang, content), page_issues in zip(cases, page):
            with self.subTest(file=name):
                self.assert_same_findings(name, core.scan_file(name, content, lang), page_issues)
        return page

    def test_comment_checks_are_linear(self):
        """jsText and the suppression check tested every comment span of a
        line per escape / per marker: O(n²), ~20 s for these lines."""
        exprs = ['"x=1;" + "/**/\\\\u0061".repeat(60000) + "\\n"',
                 '"x=1;" + "\'// nosec\'/**/".repeat(60000) + "eval(a)\\n"']
        for expr, (ms, rules) in zip(exprs, dash.run([{"op": "eval", "expr": TIMED % e} for e in exprs])):
            with self.subTest(content=expr):
                self.assertLess(ms, LIMIT_MS)
                self.assertNotIn("SC-TRUNCATED@1", rules)
        self.assertIn("S-EVAL-JS@1", rules)

    def test_masking_fails_closed(self):
        page = self.compare(MASKING)
        found = {(name, i["rule"], i["line"]) for (name, _, _), issues in zip(MASKING, page) for i in issues}
        # not vacuous: the cases that used to be masked are reported
        for want in (("dump.sql", "SQL-GRANT-ALL", 2), ("text.jsx", "S-EVAL-JS", 2),
                     ("marker.jsx", "S-EVAL-JS", 1), ("unterminated.py", "S-EVAL-PY", 1)):
            self.assertIn(want, found)

    def test_misc(self):
        page = self.compare(MISC)
        self.assertIn("S-CHMOD", {i["rule"] for i in page[0]})
        self.assertEqual(sorted(i["rule"] for i in page[1]), ["SQL-DYNAMIC", "SQL-DYNAMIC", "SQL-NOLOCK"])

    def test_uploads(self):
        (page,) = dash.run([{"op": "uploadScan", "files": [
            {"name": n, "b64": base64.b64encode(data).decode("ascii")} for n, data in UPLOADS]}])
        self.assertEqual(len(page), len(UPLOADS))
        for (name, data), page_issues in zip(UPLOADS, page):
            with self.subTest(file=name):
                self.assert_same_findings(name, cli_upload(name, data), page_issues)
        self.assertIn("SC-UTF7", {i["rule"] for i in page[0]})

    def test_metrics_match(self):
        files = [{"name": n, "lang": lang, "content": c} for n, lang, c in MASKING]
        (page,) = dash.run([{"op": "runScan", "files": files}])
        cli = core.compute_metrics([{"path": f["name"], "lang": f["lang"], "content": f["content"]} for f in files])
        self.assertEqual(page["metrics"], cli)


if __name__ == "__main__":
    unittest.main()
