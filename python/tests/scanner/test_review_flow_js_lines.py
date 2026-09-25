"""Review follow-up: X-* line numbers for JavaScript agree with the rest of
the engine when a file contains U+2028 / U+2029.

The pattern engine (core.source_lines, shared semantics 1) treats U+2028
LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR as JavaScript line
terminators, but flow.py split JS source on "\\n" only: an interprocedural
X-* finding after such a character reported a line one lower than core's
findings on the same statement (and the function-definition line in its
message was off the same way). flow._js_text now maps them to "\\n" before
masking, function extraction and line splitting. Inert fixtures only.
"""
import os
import tempfile
import unittest

from lazaret.scanner import core
from lazaret.scanner import flow

LS, PS = chr(0x2028), chr(0x2029)

HELPER = "/* helper */" + LS + "function runIt(cmd) {\n  exec(cmd);\n}\n"
APP = ("// header" + LS + "const x = 1;" + PS + "const y = 2;\n"
       "app.get('/x', (req, res) => { const q = req.query.q; runIt(q); eval(q); });\n")


class FlowLinesMatchCore(unittest.TestCase):
    def test_js_text_is_same_length(self):
        self.assertEqual(flow._js_text("a" + LS + "b" + PS + "c"), "a\nb\nc")
        self.assertEqual(flow._js_text("plain\n"), "plain\n")

    def test_x_finding_line_matches_core(self):
        with tempfile.TemporaryDirectory() as root:
            for name, text in (("h.js", HELPER), ("app.js", APP)):
                with open(os.path.join(root, name), "w", encoding="utf-8") as f:
                    f.write(text)
            res = core.scan_project(root)
        by_rule = {}
        for i in res["issues"]:
            by_rule.setdefault((i["rule"], i["file"]), []).append(i)
        core_line = by_rule[("S-EVAL-JS", "app.js")][0]["line"]
        self.assertEqual(core_line, 4)          # LS and PS each end a line
        x = by_rule[("X-CMD", "app.js")]
        self.assertEqual([i["line"] for i in x], [core_line])
        # the sink's function is named at the line core reports its exec() on,
        # minus one (the definition line)
        exec_line = next(i["line"] for i in res["issues"]
                         if i["file"] == "h.js" and i["rule"].startswith(("S-", "T-")))
        self.assertEqual(exec_line, 3)
        self.assertIn("h.js:2 (in runIt())", x[0]["msg"])
        # the snippet is the same text core shows for that line
        self.assertEqual(x[0]["snippet"][core_line - x[0]["snipStart"]],
                         core.source_lines(APP, "js")[core_line - 1])

    def test_flow_analyze_directly(self):
        files = [{"path": "h.js", "content": HELPER, "lang": "js"},
                 {"path": "app.js", "content": APP, "lang": "js"}]
        found = [(f["rule"], f["line"]) for f in flow.analyze(files) if f["rule"].startswith("X-")]
        self.assertEqual(found, [("X-CMD", 4)])


if __name__ == "__main__":
    unittest.main()
