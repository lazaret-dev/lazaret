"""The dashboard's engine has the review fixes (explicit expectations).

The page's scan engine predated the review fixes the CLI and the npm engine
got; test_review_dashboard_parity compares it with the CLI on many inputs.
This file pins the fixed behavior itself, so a regression both engines
shared would still fail here. Each case failed on the unported page:

1  comments: `/**/eval(y)` was skipped as a comment line, a block
   comment's body was scanned as code, U+2028 did not end a JS line;
2  suppression: `# nosec - reviewed` was ignored, `# nosec` inside a string
   suppressed, and so did a marker on an SC-* (supply-chain) finding;
4, 15  uploads were read as UTF-8 text: a UTF-16 eval() scanned clean, a
   UTF-7 cookie went unnoticed (no SC-UTF7), no Q-ENCODING notes;
5  no S-BIDI; `\\u0065val(x)` and fullwidth `ｅval(x)` scanned clean;
7  Q-CAPPED carried its own why/fix text, not the CLI's;
12 destructuring and annotated assignments did not taint;
and pasted code was trimmed, so its line numbers were off by its leading
blank lines. Runs the page's script in node:vm (see _dashboard_vm.py); all
input is inert."""

import base64
import json
import unittest

from tests.scanner import _dashboard_vm as dash


def at(issues):
    return sorted((i["rule"], i["line"]) for i in issues)


def rules(issues):
    return {i["rule"] for i in issues}


@dash.requires_node
class CommentTests(unittest.TestCase):
    def test_block_comments_span_lines_and_empty_ones_hide_nothing(self):
        issues = dash.scan("b.js", "/*\n eval(x)\n*/\n/**/eval(y)\n", lang="js")
        self.assertEqual(at(issues), [("S-EVAL-JS", 4)])

    def test_star_line_outside_a_block_comment_is_code(self):
        self.assertIn(("S-EVAL-JS", 2), at(dash.scan("s.js", "const x = 1\n  * eval(y)\n", lang="js")))

    def test_js_line_separators_end_a_line_comment(self):
        for sep in ("\u2028", "\u2029"):
            with self.subTest(sep=hex(ord(sep))):
                self.assertEqual(at(dash.scan("u.js", f"// note{sep}eval(z)\n", lang="js")), [("S-EVAL-JS", 2)])


@dash.requires_node
class SuppressionTests(unittest.TestCase):
    def test_marker_with_a_reason(self):
        self.assertEqual(dash.scan("r.py", "import os\nos.system(cmd)  # nosec - reviewed\n", lang="py"), [])

    def test_marker_inside_a_string_or_code_does_not_suppress(self):
        issues = dash.scan("s.py", 'x = "# nosec"; eval(y)\nos.system(a) --nosec\n', lang="py")
        self.assertEqual(at(issues), [("S-EVAL-PY", 1), ("S-OSCMD-PY", 2)])

    def test_line_above_counts_only_as_a_standalone_comment(self):
        issues = dash.scan("a.js", "eval(a); // nosec\neval(b)\n// nosec\neval(c)\n", lang="js")
        self.assertEqual(at(issues), [("S-EVAL-JS", 2)])

    def test_supply_chain_findings_are_never_suppressed(self):
        issues = dash.scan("d.js", "eval(atob(p)); // nosec\n", lang="js")
        self.assertEqual(at(issues), [("SC-EVAL-DECODE", 1)])

    def test_sql_comment_marker(self):
        issues = dash.scan("g.sql", "-- nosec\nGRANT ALL ON t TO PUBLIC;\nGRANT SELECT ON t TO PUBLIC;\n", lang="sql")
        self.assertEqual(at(issues), [("SQL-GRANT-PUBLIC", 3)])


def upload(files):
    (out,) = dash.run([{"op": "uploadScan", "files": [
        {"name": n, "b64": base64.b64encode(data).decode("ascii")} for n, data in files]}])
    return out


@dash.requires_node
class UploadEncodingTests(unittest.TestCase):
    def test_utf16_with_and_without_bom(self):
        le, be, bare = upload([("le.js", b"\xff\xfe" + "eval(a)\n".encode("utf-16-le")),
                               ("be.js", b"\xfe\xff" + "eval(b)\n".encode("utf-16-be")),
                               ("bare.js", "eval(c)\n".encode("utf-16-le"))])
        for issues, enc in ((le, "utf-16-le"), (be, "utf-16-be"), (bare, "utf-16-le")):
            self.assertEqual(at(issues), [("Q-ENCODING", 1), ("S-EVAL-JS", 1)])
            (note,) = [i for i in issues if i["rule"] == "Q-ENCODING"]
            self.assertEqual(note["msg"], f"Source file is not UTF-8 (detected {enc}); decoded explicitly.")

    def test_nul_near_the_top_of_utf8_is_not_utf16(self):
        (issues,) = upload([("nul.js", b"/*\x00*/eval(x)\n")])
        self.assertEqual(at(issues), [("S-EVAL-JS", 1)])

    def test_utf7_cookie(self):
        (issues,) = upload([("u7.py", b"# -*- coding: utf-7 -*-\n# harmless comment +AAo-eval(e)\n")])
        self.assertEqual(at(issues), [("Q-ENCODING", 1), ("S-EVAL-PY", 3), ("SC-UTF7", 1)])
        (sc,) = [i for i in issues if i["rule"] == "SC-UTF7"]
        self.assertEqual((sc["sev"], sc["msg"]), ("CRITICAL", "Python source declares UTF-7; code can hide in comments."))

    def test_other_cookies(self):
        latin1, unknown, js = upload([("l.py", b"# coding: latin-1\ns = '\xe9'\neval(f)\n"),
                                      ("n.py", b"# coding: no-such-codec\neval(g)\n"),
                                      ("c.js", b"// coding: latin-1\neval(h)\n")])
        self.assertIn("detected iso8859-1", [i for i in latin1 if i["rule"] == "Q-ENCODING"][0]["msg"])
        self.assertIn("é", [i for i in latin1 if i["rule"] == "S-EVAL-PY"][0]["snippet"][1])
        self.assertIn("detected no-such-codec", [i for i in unknown if i["rule"] == "Q-ENCODING"][0]["msg"])
        self.assertEqual(at(js), [("S-EVAL-JS", 2)])                  # cookies are Python-only

    def test_crlf_upload(self):
        (issues,) = upload([("w.py", b"eval(a)  # nosec\r\neval(b)\r\n")])
        self.assertEqual(at(issues), [("S-EVAL-PY", 2)])


@dash.requires_node
class UnicodeTests(unittest.TestCase):
    def test_bidi_controls(self):
        issues = dash.scan("b.js", 'const s = "\u202e";\n// \u2066 note\n', lang="js")
        self.assertEqual(at(issues), [("S-BIDI", 1), ("S-BIDI", 2)])
        self.assertEqual({(i["sev"], i["type"]) for i in issues}, {("CRITICAL", "VULN")})

    def test_escaped_and_fullwidth_identifiers(self):
        self.assertIn(("S-EVAL-JS", 1), at(dash.scan("e.js", "\\u0065val(x)\n", lang="js")))
        self.assertNotIn("S-EVAL-JS", rules(dash.scan("s.js", "'\\u0065val(x)'\n", lang="js")))
        self.assertIn(("S-EVAL-PY", 1), at(dash.scan("f.py", "\uff45val(x)\n", lang="py")))


@dash.requires_node
class CapAndTaintTests(unittest.TestCase):
    def test_q_capped_is_the_clis(self):
        issues = dash.scan("c.js", "x(); // TODO\n" * 210, lang="js")
        self.assertEqual(len([i for i in issues if i["rule"] == "Q-TODO"]), 200)
        (capped,) = [i for i in issues if i["rule"] == "Q-CAPPED"]
        self.assertEqual({k: capped[k] for k in ("line", "sev", "type", "msg", "why", "fix", "ref")}, {
            "line": 201, "sev": "INFO", "type": "SMELL", "msg": "10 more Q-TODO findings omitted",
            "why": "Low-severity findings that repeat hundreds of times in one file are capped so reports "
                   "stay readable; security findings are never capped.",
            "fix": "Fix or deliberately suppress the Q-TODO pattern in this file, then re-scan to see the "
                   "remaining occurrences.",
            "ref": "Maintainability"})

    def test_destructuring_and_annotated_assignments_taint(self):
        js = dash.scan("t.js", "const { a, b: c } = req.query;\nexec(c);\nconst [d] = req.body;\nexec(d);\n", lang="js")
        self.assertEqual([i["line"] for i in js if i["rule"] == "T-CMD"], [2, 4])
        py = dash.scan("t.py", "import os\ntarget: str = request.args['x']\nos.system(target)\n", lang="py")
        self.assertEqual([i["line"] for i in py if i["rule"] == "T-CMD"], [3])


@dash.requires_node
class PasteTests(unittest.TestCase):
    def test_pasted_code_keeps_its_line_numbers(self):
        expr = ("(() => { document.querySelector('#code').value = %s; document.querySelector('#lang').value = 'js';"
                " for (const fn of document.querySelector('#scanBtn').listeners.click) fn();"
                " return lastResult.issues.map((i) => [i.rule, i.file, i.line]); })()") % json.dumps("\n\n  eval(x)\n")
        (issues,) = dash.run([{"op": "eval", "expr": expr}])
        self.assertEqual(issues, [["S-EVAL-JS", "pasted-code.js", 3]])


if __name__ == "__main__":
    unittest.main()
