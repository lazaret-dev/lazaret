"""Review finding 12 — the JavaScript brace heuristic in flow.py.

The brace pass counted braces inside strings, comments, regex and template
literals (`const b = "}"; exec(cmd);` closed the function early and hid the
sink; `console.log("{" + cmd)` made a function swallow the next one), and the
200-character window after a sink matched a parameter used in a LATER
statement. flow._js_mask() now blanks literal/comment content before any
brace or regex pass, and sink arguments are the sink call's balanced
argument list. Inert fixtures only.
"""
import time
import unittest

from lazaret.scanner import flow

APP = "app.get('/x', (req, res) => { const q = req.query.q; CALL; });\n"


def js_findings(helper, call="runIt(q)"):
    files = [{"path": "h.js", "content": helper, "lang": "js"},
             {"path": "app.js", "content": APP.replace("CALL", call), "lang": "js"}]
    return sorted((f["rule"], f["file"]) for f in flow.analyze(files) if f["rule"].startswith("X-"))


HIT = [("X-CMD", "app.js")]


class BraceCounting(unittest.TestCase):
    def test_control(self):
        self.assertEqual(js_findings("function runIt(cmd) {\n  exec(cmd);\n}\n"), HIT)

    def test_close_brace_in_string(self):
        self.assertEqual(js_findings(
            'function runIt(cmd) {\n  const banner = "}";\n  exec(cmd);\n}\n'), HIT)

    def test_close_brace_in_comment_regex_template(self):
        for line in ("// closing } here", "/* } */", "const r = /}/g;",
                     "const t = `}`;", "const t = `${'}'}`;", "const s = '\\'}';"):
            with self.subTest(line=line):
                self.assertEqual(js_findings(
                    "function runIt(cmd) {\n  " + line + "\n  exec(cmd);\n}\n"), HIT)

    def test_open_brace_in_string_does_not_swallow_next_function(self):
        helper = ('function logIt(cmd) {\n  console.log("{" + cmd);\n}\n'
                  'function other(cmd) {\n  exec(cmd);\n}\n')
        self.assertEqual(js_findings(helper, "logIt(q)"), [])
        self.assertEqual(js_findings(helper, "other(q)"), HIT)

    def test_sink_text_in_strings_and_comments_ignored(self):
        helper = ('function logIt(cmd) {\n  // exec(cmd) would be bad\n'
                  '  console.log("exec(" + cmd + ")");\n}\n')
        self.assertEqual(js_findings(helper, "logIt(q)"), [])


class SinkArgumentScope(unittest.TestCase):
    def test_param_in_later_statement_is_not_a_sink_argument(self):
        helper = 'function audit(msg) {\n  exec("uptime");\n  console.log(msg);\n}\n'
        self.assertEqual(js_findings(helper, "audit(q)"), [])

    def test_param_inside_argument_list_still_counts(self):
        helper = 'function audit(msg) {\n  exec("echo " + wrap(msg, ")"));\n}\n'
        self.assertEqual(js_findings(helper, "audit(q)"), HIT)

    def test_innerhtml_assignment_statement(self):
        helper = ("function show(html) {\n  el.innerHTML = '<b>' + html + '</b>';\n"
                  "  log(html);\n}\nfunction safe(t) {\n  el.innerHTML = 'x';\n  log(t);\n}\n")
        files = [{"path": "h.js", "content": helper, "lang": "js"},
                 {"path": "app.js", "lang": "js", "content":
                  "app.get('/x', (req, res) => { const q = req.query.q; show(q); safe(q); });\n"}]
        rules = [(f["rule"], f["line"]) for f in flow.analyze(files) if f["rule"].startswith("X-")]
        self.assertEqual(rules, [("X-XSS", 1)])
        self.assertEqual(len(rules), 1)

    def test_sql_template_interpolation_still_detected(self):
        helper = "function find(id) {\n  return db.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n"
        self.assertEqual(js_findings(helper, "find(q)"), [("X-SQL", "app.js")])
        safe = "function find(id) {\n  return db.query('SELECT * FROM t WHERE id = ?', [id]);\n}\n"
        self.assertEqual(js_findings(safe, "find(q)"), [])


class Lexer(unittest.TestCase):
    CASES = {
        'const b = "}"; exec(cmd);': 'const b = " "; exec(cmd);',
        "a = b / c / d;": "a = b / c / d;",
        "x = /}[/]\\//g.test(s);": "x = /      /g.test(s);",
        "return /ab+c/i.exec(s)": "return /    /i.exec(s)",
        "y = `t ${ {a:1}.a + `in ${z}` } }` + q;": "y = `  ${ {a:1}.a + `   ${z}` }  ` + q;",
        "// c }\n/* { \n } */ f(x)": "      \n     \n      f(x)",
        "s = 'it\\'s {';": "s = '       ';",
        "arr[i] / 2 / x": "arr[i] / 2 / x",
    }

    def test_mask(self):
        for src, want in self.CASES.items():
            with self.subTest(src=src):
                got = flow._js_mask(src)
                self.assertEqual(got, want)
                self.assertEqual(len(got), len(src))

    def test_unterminated_and_hostile_inputs_are_linear(self):
        for src in ("`" + "${" * 50000 + "x", "'" * 300000, "/" * 300000,
                    "/*" + "x" * 300000, "`" * 300001):
            t = time.time()
            self.assertEqual(len(flow._js_mask(src)), len(src))
            self.assertLess(time.time() - t, 5)


if __name__ == "__main__":
    unittest.main()
