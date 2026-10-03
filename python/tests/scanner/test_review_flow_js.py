"""Review finding 12 — the JavaScript brace heuristic in flow.py.

The brace pass counted braces inside strings, comments, regex and template
literals (`const b = "}"; exec(cmd);` closed the function early and hid the
sink; `console.log("{" + cmd)` made a function swallow the next one), and the
200-character window after a sink matched a parameter used in a LATER
statement. The pass first blanked literals and comments; since 0.1.7 it
reads parsed trees (the engine's parser since the Rust-first refactor),
where a sink's arguments are its call's own arguments and a brace in a
literal is part of the literal.
These cases stay as regression tests. Inert fixtures only.
"""
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


if __name__ == "__main__":
    unittest.main()
