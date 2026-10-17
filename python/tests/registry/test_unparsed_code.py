"""JS-PARSE-STRICT (0.1.9): a package's JavaScript that the engine's parser refuses is said in the report.

The supply-chain tests that read a file's syntax tree (code written into another package's folder, a program carved
out of another file, D-13's loads, the cross-file pass) have only the text followers for a file the parser refuses,
and the report said nothing of it. Most such files are broken and Node refuses them too: on Oct 9 the parser refused
11 of the 37,490 JavaScript files of the popular set's and the benchmark's npm releases, and V8 refused each of them.
Since JS-PARSE-STRICT the parser reads what V8 compiles but past its nesting bound (jsparse's MAX_DEPTH; V8 compiles
far deeper nesting). Each file one of those tests read and the parser refused (an install script's too, whose test
reads its tree) is now listed in one SC-UNPARSED-CODE finding, INFO (the verdict does not move), with its line and the
parser's reason; a TypeScript declaration, which nothing runs, is not.

Payloads are inert: nothing is installed or run.
"""
import unittest

from lazaret.registry import repo
from tests.registry._review_support import issues, manifest, scan_npm

# what Node runs and the parser refuses: arrays nested past its bound (V8 compiles 1,000; the parser stops at 127)
NESTED = "module.exports = " + "[" * 200 + "]" * 200 + ";\n"
BROKEN = "const a = 1;\nconst b = 2;\nconst = 3;\n"         # Node refuses it too
PLAIN = "module.exports = { a: 1 };\n"


def unparsed(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues(res, "SC-UNPARSED-CODE")]


class UnparsedCodeTests(unittest.TestCase):
    def test_a_file_node_runs_nested_past_the_parsers_bound(self):
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": NESTED})
        ((file, line, sev, msg),) = unparsed(res)
        self.assertEqual((file, line, sev), ("index.js", 1, "INFO"))
        self.assertIn("1 JavaScript file the parser could not read (index.js (line 1: nesting too deep))", msg)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_a_broken_file_with_its_line_and_the_parsers_reason(self):
        # (one nothing loads: SC-USE-RISK's step reads the package's other code)
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/broken.js": BROKEN})
        ((file, line, _sev, msg),) = unparsed(res)
        self.assertEqual((file, line), ("lib/broken.js", 3))
        self.assertIn("(lib/broken.js (line 3: unexpected token '='))", msg)

    def test_an_install_script(self):
        # (its test reads the tree too: the parse alone says so, js_refusal)
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node src/postinstall.js"}),
                        "src/postinstall.js": "const a = 1;\nconst b = 'x;\n"})
        ((file, line, _sev, msg),) = unparsed(res)
        self.assertEqual((file, line), ("src/postinstall.js", 2))
        self.assertIn("(src/postinstall.js (line 2: unterminated string))", msg)

    def test_one_finding_for_the_package_the_first_three_named(self):
        files = {"package.json": manifest(main="index.js"), "index.js": NESTED}
        files.update({f"lib/b{k}.js": BROKEN for k in range(4)})
        ((file, _line, _sev, msg),) = unparsed(scan_npm(files))
        self.assertEqual(file, "index.js")
        self.assertTrue(msg.startswith("5 JavaScript files the parser could not read (index.js (line 1: nesting too "
                                       "deep), lib/b0.js (line 3: unexpected token '='), lib/b1.js (line 3: "
                                       "unexpected token '='), …): "), msg)

    def test_none_where_the_parser_reads_every_file(self):
        # an assignment to a call and `let` as a name, which V8 compiles (a ReferenceError when the line runs), and
        # a TypeScript declaration the parser does not read, which nothing runs
        text = "function f() {}\nif (0) { f() = 1; f()++; }\nvar let = 1;\nfor (let in {}) ;\n" + PLAIN
        res = scan_npm({"package.json": manifest(main="index.js", types="index.d.ts"), "index.js": text,
                        "index.d.ts": "export declare const x: number = ;\n", "lib/t.d.cts": "declare const = ;\n"})
        self.assertEqual(unparsed(res), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_the_finding(self):
        # D-13's read of a module the parser refuses gives no reason: the file is named alone
        issue = repo._unparsed_code_issue({"b.js": (3, "unexpected token '='"), "a.js": None})
        self.assertEqual((issue["rule"], issue["sev"], issue["type"], issue["file"], issue["line"]),
                         ("SC-UNPARSED-CODE", "INFO", "HOTSPOT", "a.js", 1))
        self.assertTrue(issue["msg"].startswith("2 JavaScript files the parser could not read (a.js, b.js (line 3: "
                                                "unexpected token '=')): "), issue["msg"])
        self.assertNotIn(repo.UNPARSED_CODE_RULE, repo.TRUNCATION_RULES)


if __name__ == "__main__":
    unittest.main()
