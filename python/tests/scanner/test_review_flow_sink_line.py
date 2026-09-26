"""Final-review item 5: JavaScript cross-file X-* findings named the wrong
sink location. The Python engine reports the line of the sink call, but the
JS engine reported the line of the FUNCTION that contains it: "reaches a
sink at h.js:3 (in runIt())" for an exec() on line 6, and h.js:2 instead of
3 in the reviewer's t5 cases. It also took the file from the last function
of that name anywhere in the project, not from the one that has the sink.
The message now names the sink call's own file and line, numbered like the
rest of flow.py (U+2028 / U+2029 end a line). The finding's line and
snippet stay at the call site in the caller's file, as for Python.

Fixtures are inert text; nothing is executed.
"""
import textwrap
import unittest

from lazaret.scanner import flow

LS, PS = chr(0x2028), chr(0x2029)
APP = "app.get('/x', (req, res) => { const q = req.query.q; runIt(q); });\n"


def x_findings(files):
    recs = [{"path": p, "content": textwrap.dedent(c), "lang": "js"} for p, c in files.items()]
    return [f for f in flow.analyze(recs) if f["rule"].startswith("X-")]


class SinkLineTests(unittest.TestCase):
    def sink_of(self, helper, app=APP, **more):
        found = x_findings({"h.js": helper, "app.js": app, **more})
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_reviewer_t5_j0(self):
        f = self.sink_of("""
            function runIt(cmd) {
              exec(cmd);
            }
            """)
        self.assertIn("reaches a sink at h.js:3 (in runIt())", f["msg"])
        self.assertEqual((f["file"], f["line"]), ("app.js", 1))     # still the call site

    def test_reviewer_t5_j1_brace_in_string_and_comment(self):
        for filler in ('const banner = "}";', "// closing } here"):
            with self.subTest(filler=filler):
                f = self.sink_of(f"""
                    function runIt(cmd) {{
                      {filler}
                      exec(cmd);
                    }}
                    """)
                self.assertIn("reaches a sink at h.js:4 (in runIt())", f["msg"])

    def test_verifier_case_sink_far_below_the_header(self):
        f = self.sink_of("// l1\n// l2\nfunction runIt(cmd) {\n  const a = 1;\n  const b = 2;\n"
                         "  exec(cmd);\n}\nmodule.exports = runIt;\n",
                         app="// l1\nconst runIt = require('./h');\n" + APP)
        self.assertIn("reaches a sink at h.js:6 (in runIt())", f["msg"])
        self.assertEqual(f["line"], 3)

    def test_line_separators_count_as_line_ends(self):
        helper = ("function runIt(cmd) {" + LS + "  const a = 1;" + PS
                  + "  exec(cmd);\n}\n")
        f = self.sink_of(helper)
        self.assertIn("reaches a sink at h.js:3 (in runIt())", f["msg"])

    def test_first_sink_of_the_category_is_named(self):
        f = self.sink_of("function runIt(cmd) {\n  log(cmd);\n  exec(cmd);\n"
                         "  execSync(cmd);\n}\n")
        self.assertIn("reaches a sink at h.js:3 (in runIt())", f["msg"])

    def test_sink_in_a_multiline_function_header(self):
        f = self.sink_of("function runIt(\n  cmd,\n  opts\n) {\n  return exec(\n    cmd);\n}\n")
        self.assertIn("reaches a sink at h.js:5 (in runIt())", f["msg"])

    def test_the_file_that_holds_the_sink_is_named(self):
        # a sink-free function of the same name in another file must not
        # take over the location
        found = x_findings({"h.js": "function runIt(cmd) {\n\n  exec(cmd);\n}\n",
                            "z.js": "function runIt(cmd) {\n  return cmd;\n}\n",
                            "app.js": APP})
        self.assertEqual(len(found), 1, found)
        self.assertIn("reaches a sink at h.js:3 (in runIt())", found[0]["msg"])


if __name__ == "__main__":
    unittest.main()
