"""Look-alike identifiers (SC-HOMOGLYPH; analyst gap: the homoglyph case).

`const \\u0435val = eval; \\u0435val(x)` (a Cyrillic e) ran eval where no rule,
and no reviewer, saw eval called: \\u0435val is a different name that only looks
like eval. Now a name whose skeleton (look-alike letters mapped to the Latin
ones they are drawn like, invisible U+200C / U+200D dropped, and in
JavaScript NFKC's compatibility forms read as the letters they stand for) is
an ASCII name it is not is SC-HOMOGLYPH: CRITICAL when it reads as a
code-execution or network name, or as another name in the file; MAJOR when
it mixes ASCII letters with look-alikes. Names are read where the lexer
reads code: not in comments, strings (a docstring, a template, an f-string)
or regex literals, whose escapes are not names either. A Cyrillic word and
Greek alpha in scientific code are left alone. On 38,752 real files (a real
node_modules, npm's own packages, date and language libraries with Cyrillic
and Greek locales, the standard library and installed Python packages) it
finds nothing. Reading strings line by line and regex literals as code, it
found 13 names there: ajv's /http[s\\u017F]?/ read as "s\\u017f", date-fns's
locale patterns (/^\\u0441e[\\u0439]/i, /^(\\d+)[\\u00ba\\u00aao]?/i), and a
string in a minified bundle whose quotes a line-by-line reading paired
wrongly.

The npm engine's twin: js/test/review-lookalike-names.test.js;
tests/architecture/test_js_parity_lookalike.py compares the two. Every such
character in this file is written as an escape; payloads are inert text.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core
from tests.registry._review_support import issues, scan_npm


def found(text, lang="js", dep=False, path=None):
    return [(i["sev"], i["line"], i["msg"]) for i in core.scan_file(path or "x." + lang, text, lang, dep=dep)
            if i["rule"] == "SC-HOMOGLYPH"]


EVAL_MSG = "'\u0435val' reads as 'eval' but is spelled with U+0435 for 'e'."


class LookalikeTests(unittest.TestCase):
    def test_a_second_eval(self):
        for lang, text in (("js", "const \u0435val = eval;\n\u0435val(x);\n"),
                           ("py", "\u0435val = eval\n\u0435val(input())\n")):
            for dep in (False, True):
                with self.subTest(lang=lang, dep=dep):
                    self.assertEqual(found(text, lang, dep), [("CRITICAL", 1, EVAL_MSG), ("CRITICAL", 2, EVAL_MSG)])

    def test_another_name_in_the_file(self):
        self.assertEqual(found("if (isAdm\u0456n) { go(); }\nconst isAdmin = false;\n"), [(
            "CRITICAL", 1, "'isAdm\u0456n' reads as 'isAdmin', another name in this file, but is spelled with "
                           "U+0456 for 'i'.")])

    def test_a_name_that_only_mixes_alphabets(self):
        self.assertEqual(found("const v\u0430lue = 1;\n"),
                         [("MAJOR", 1, "'v\u0430lue' reads as 'value' but is spelled with U+0430 for 'a'.")])
        self.assertEqual(found("\u0435\u0445\u0435\u0441(c)\n", "py"), [(
            "CRITICAL", 1, "'\u0435\u0445\u0435\u0441' reads as 'exec' but is spelled with U+0435 for 'e', "
                           "U+0445 for 'x', U+0441 for 'c'.")])

    def test_javascript_forms(self):
        self.assertEqual(found("eva\u200dl(x);\n"),
                         [("CRITICAL", 1, "'eva\\u200dl' reads as 'eval' but is spelled with an invisible U+200D.")])
        self.assertEqual(found("\uff45val(x);\n"),
                         [("CRITICAL", 1, "'\uff45val' reads as 'eval' but is spelled with U+FF45 for 'e'.")])
        self.assertEqual(found("\\u0435val(x);\n"), [("CRITICAL", 1, EVAL_MSG)])           # an identifier escape
        # Python reads fullwidth e as e: that is eval itself (S-EVAL-PY), not a second one
        self.assertEqual(found("\uff45val(x)\n", "py"), [])
        self.assertIn("S-EVAL-PY", {i["rule"] for i in core.scan_file("x.py", "\uff45val(x)\n", "py")})

    def test_what_is_not_a_lookalike_name(self):
        for lang, text in [
            ("js", "const s = '\u0435val';\n"), ("js", "// \u0435val(x)\n"), ("js", "/[\u0430-\u044f]/.test(s);\n"),
            ("js", "const \u043f\u0440\u0438\u0432\u0435\u0442 = 1;\n"), ("py", "\u03b1 = 0.05\n"), ("py", "\u039f = 1\n"),
            ("js", "const re = /[\\uFF07\\uFF10]/;\n"), ("js", "x = /[\\u2105\\u210A]/;\n"), ("py", "t = '\u0435val'  # \u0435val\n"),
            ("js", "const caf\u00e9 = 1;\n"), ("js", "const \u0430 = 1;\n"),
        ]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [])

    def test_a_regex_literal_holds_no_names(self):
        for text in [
            "var re = /^(?:(?:http[s\\u017F]?|ftp):\\/\\/)/i;\n",                     # ajv
            "const ok = /^[a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u0401]+$/.test(s);\n",
            "const m = s.match(/^(\\d+)[\u00ba\u00aao]?/i);\n",                         # date-fns pt-BR
            "if (ok) {}\n/[a\u0441]/.test(s);\n",
        ]:
            with self.subTest(text=text):
                self.assertEqual(found(text), [])
        # a '/' the lexer reads as division starts no regex literal
        self.assertEqual(found("const r = a / v\u0430lue / 2;\n"),
                         [("MAJOR", 1, "'v\u0430lue' reads as 'value' but is spelled with U+0430 for 'a'.")])

    def test_a_string_is_read_by_the_lexer(self):
        # a string's other lines (a docstring, a template's text, a string
        # continued with a backslash)
        for lang, text in [("py", 'def f():\n    """\n    v\u0430lue \u0435val(x)\n    """\n'),
                           ("js", "const t = `\n  v\u0430lue \u0435val(x)\n`;\n"),
                           ("js", 'const s = "a\\\n\u0435val";\n')]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [])
        # a template's or an f-string's fields are code: a call there runs
        for lang, text, line in [("js", "const t = `\n  v\u0430lue ${\u0435val(x)}\n`;\n", 2),
                                 ("py", "x = f'{\u0435val(p)}'\n", 1)]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [("CRITICAL", line, EVAL_MSG)])
        # a quote escaped in a string ends nothing
        for lang, text in [("js", "const s = 'it\\'s' + \u0435val(x) + 'y';\n"),
                           ("py", "s = 'it\\'s' + \u0435val(x) + 'y'\n")]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [("CRITICAL", 1, EVAL_MSG)])

    def test_never_suppressed(self):
        self.assertEqual(found("\u0435val(x); // nosec\n"), [("CRITICAL", 1, EVAL_MSG)])


class ProjectAndRegistryTests(unittest.TestCase):
    def test_a_project_and_its_dependencies(self):
        root = tempfile.mkdtemp(prefix="lz-lookalike-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in {"src/a.js": "const \u0435val = eval;\n", "node_modules/p/index.js": "\u0435val(atob(p));\n",
                          "node_modules/p/package.json": json.dumps({"name": "p", "version": "1.0.0"})}.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        res = core.scan_project(root, include_deps=True)
        self.assertEqual(sorted((i["file"].replace(os.sep, "/"), i["sev"]) for i in res["issues"]
                                if i["rule"] == "SC-HOMOGLYPH"),
                         [("node_modules/p/index.js", "CRITICAL"), ("src/a.js", "CRITICAL")])
        self.assertFalse(res["pass"])

    def test_a_package(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"}),
                        "index.js": "const \u0435val = eval;\nmodule.exports = (s) => \u0435val(s);\n"})
        self.assertEqual([i["line"] for i in issues(res, "SC-HOMOGLYPH")], [1, 2])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
