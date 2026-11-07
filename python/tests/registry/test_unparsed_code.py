"""JS-PARSE-STRICT (0.1.9): a package's JavaScript that the engine's parser refuses is said in the report.

The supply-chain tests that read a file's syntax tree (code written into another package's folder, a program carved
out of another file, D-13's loads, the cross-file pass) have only the text followers for a file the parser refuses,
and the report said nothing of it. Most such files are broken and Node refuses them too: on Oct 9 the parser refused
11 of the 37,490 JavaScript files of the popular set's and the benchmark's npm releases, and V8 refused each of them.
Since JS-PARSE-STRICT the parser reads what V8 compiles but past its nesting bound (jsparse's MAX_DEPTH; V8 compiles
far deeper nesting). Each broken file one of those tests read and the parser refused is listed in one
SC-UNPARSED-CODE finding, INFO (the verdict does not move), with its line and the parser's reason; a TypeScript
declaration, which nothing runs, is not.

JS-NEST (0.1.9) raised MAX_DEPTH by half (256 to 384) and split off the one shape V8 compiles that the parser still
refuses, where the code runs: a file refused *only* because it nests past the bound, by the install-script test or
the import-time test (code that runs when the package is installed or loaded), is SC-NESTED-CODE (MAJOR, an
indicator). Refused for nesting where the code may never run (the use-time test's files, which nothing the entry
points load reaches; D-13's read), it stays in the INFO inventory with its reason: generated code nests that deep too
(a minifier's ternary chains, a deep data literal). A file several passes refused is judged by the strongest.

BIG-BUNDLE-TAIL (the external review of Oct 20, H3): a file whose code runs and which the supply-chain tree did not read
whole is SC-TRUNCATED (CRITICAL) in the tree's words ("the supply-chain tree did not read it whole: the parser refused
it at line 1 (nesting too deep); …") beside what the text follower found, and a quiet follower never clears it, so
such a package's scan is INCOMPLETE; the SC-NESTED-CODE indicator stays beside it.

Payloads are inert: nothing is installed or run.
"""
import unittest

from lazaret.registry import repo
from tests.registry._review_support import issues, manifest, scan_npm

# what Node runs and the parser refuses: arrays nested past its bound (V8 compiles 1,000; the parser reads 191)
NESTED = "module.exports = " + "[" * 400 + "]" * 400 + ";\n"
# a minifier's if-return chain (terser: `return c === 0 ? 0 : c === 1 ? 1 : …`), 378 deep: the parser reads 377
TERNARY_CHAIN = ("module.exports = function (c) { return " + "".join(f"c === {k} ? {k} : " for k in range(378))
                 + "-1; };\n")
BROKEN = "const a = 1;\nconst b = 2;\nconst = 3;\n"         # Node refuses it too
PLAIN = "module.exports = { a: 1 };\n"


def unparsed(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues(res, "SC-UNPARSED-CODE")]


def nested(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues(res, "SC-NESTED-CODE")]


def truncated(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues(res, "SC-TRUNCATED")]


# the tree's words for a file it did not read (signs::local_data_sent's TREE_UNREAD, the parser's refusal)
NOT_READ = ("the supply-chain tree did not read it whole: the parser refused it at line 1 (nesting too deep); "
            "its text alone was read for what it sends")


class UnparsedCodeTests(unittest.TestCase):
    def test_a_file_node_runs_nested_past_the_parsers_bound_is_an_indicator(self):
        # reached at import time (the package's main): its code runs when the package is loaded
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": NESTED})
        ((file, line, sev, msg),) = nested(res)
        self.assertEqual((file, line, sev), ("index.js", 1, "MAJOR"))
        self.assertIn("1 JavaScript file nested past the parser's bound (index.js (line 1: nesting too deep))", msg)
        self.assertEqual(unparsed(res), [])
        # H3 (BIG-BUNDLE-TAIL, the review of Oct 20): code that runs and the tree did not read is SC-TRUNCATED beside
        # the follower's answer, never cleared by a quiet follower, so the verdict is INCOMPLETE (WARN before: the
        # MAJOR indicator alone)
        ((file, line, sev, msg),) = truncated(res)
        self.assertEqual((file, line, sev), ("index.js", 1, "CRITICAL"))
        self.assertIn(NOT_READ, msg)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])

    def test_nesting_in_an_install_script_is_an_indicator(self):
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node install.js"}), "install.js": NESTED})
        ((file, line, sev, _msg),) = nested(res)
        self.assertEqual((file, line, sev), ("install.js", 1, "MAJOR"))
        self.assertEqual(unparsed(res), [])
        # (H3: the install script runs, the tree did not read it)
        ((file, line, sev, msg),) = truncated(res)
        self.assertEqual((file, line, sev), ("install.js", 1, "CRITICAL"))
        self.assertIn(NOT_READ, msg)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])

    def test_nesting_where_nothing_loads_the_file_is_inventory(self):
        # the same file, but the entry points do not reach it: only the use-time test reads it, so it is listed
        # (INFO, with its reason) and the verdict does not move
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/deep.js": NESTED})
        ((file, line, sev, msg),) = unparsed(res)
        self.assertEqual((file, line, sev), ("lib/deep.js", 1, "INFO"))
        self.assertIn("(lib/deep.js (line 1: nesting too deep))", msg)
        self.assertEqual(nested(res), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_a_minifiers_ternary_chain_in_a_data_file_nothing_loads_is_inventory(self):
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN,
                        "lib/lookup-table.js": TERNARY_CHAIN})
        ((file, _line, sev, msg),) = unparsed(res)
        self.assertEqual((file, sev), ("lib/lookup-table.js", "INFO"))
        self.assertIn("(lib/lookup-table.js (line 1: nesting too deep))", msg)
        self.assertEqual(nested(res), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        # one level shallower, the parser reads it: nothing to list
        shallower = TERNARY_CHAIN.replace("c === 377 ? 377 : ", "")
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/lookup-table.js": shallower})
        self.assertEqual((unparsed(res), nested(res)), ([], []))

    def test_a_broken_file_with_its_line_and_the_parsers_reason(self):
        # (one nothing loads: SC-USE-RISK's step reads the package's other code)
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/broken.js": BROKEN})
        ((file, line, sev, msg),) = unparsed(res)
        self.assertEqual((file, line, sev), ("lib/broken.js", 3, "INFO"))
        self.assertIn("(lib/broken.js (line 3: unexpected token '='))", msg)
        self.assertEqual(nested(res), [])

    def test_an_install_script(self):
        # (its test reads the tree too: the parse alone says so, js_refusal)
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node src/postinstall.js"}),
                        "src/postinstall.js": "const a = 1;\nconst b = 'x;\n"})
        ((file, line, _sev, msg),) = unparsed(res)
        self.assertEqual((file, line), ("src/postinstall.js", 2))
        self.assertIn("(src/postinstall.js (line 2: unterminated string))", msg)

    def test_nesting_and_broken_files_are_separate_findings(self):
        files = {"package.json": manifest(main="index.js"), "index.js": NESTED}
        files.update({f"lib/b{k}.js": BROKEN for k in range(4)})
        res = scan_npm(files)
        ((nfile, _nl, nsev, nmsg),) = nested(res)
        self.assertEqual((nfile, nsev), ("index.js", "MAJOR"))
        self.assertIn("1 JavaScript file nested past the parser's bound", nmsg)
        ((ufile, _ul, usev, umsg),) = unparsed(res)
        self.assertEqual((ufile, usev), ("lib/b0.js", "INFO"))
        self.assertTrue(umsg.startswith("4 JavaScript files the parser could not read (lib/b0.js (line 3: "
                                        "unexpected token '='), lib/b1.js (line 3: unexpected token '='), "
                                        "lib/b2.js (line 3: unexpected token '='), …): "), umsg)

    def test_none_where_the_parser_reads_every_file(self):
        # an assignment to a call and `let` as a name, which V8 compiles (a ReferenceError when the line runs), and
        # a TypeScript declaration the parser does not read, which nothing runs
        text = "function f() {}\nif (0) { f() = 1; f()++; }\nvar let = 1;\nfor (let in {}) ;\n" + PLAIN
        res = scan_npm({"package.json": manifest(main="index.js", types="index.d.ts"), "index.js": text,
                        "index.d.ts": "export declare const x: number = ;\n", "lib/t.d.cts": "declare const = ;\n"})
        self.assertEqual(unparsed(res), [])
        self.assertEqual(nested(res), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_the_findings(self):
        # D-13's read of a module the parser refuses gives no reason: the file is named alone (INFO inventory). A
        # nesting refusal where the code runs (the install or import-time pass) is split off as SC-NESTED-CODE
        # (MAJOR); elsewhere (the use-time pass) it is inventory with its reason; the strongest pass decides.
        deep = (1, "nesting too deep")
        out = repo._unparsed_code_issues({"b.js": {"import": (3, "unexpected token '='")}, "a.js": {"loads": None},
                                          "deep.js": {"import": deep}, "hook.js": {"loads": None, "install": deep},
                                          "unused.js": {"use": deep}})
        by = {i["rule"]: i for i in out}
        self.assertEqual(set(by), {"SC-NESTED-CODE", "SC-UNPARSED-CODE"})
        self.assertEqual((by["SC-NESTED-CODE"]["sev"], by["SC-NESTED-CODE"]["file"]), ("MAJOR", "deep.js"))
        self.assertTrue(by["SC-NESTED-CODE"]["msg"].startswith(
            "2 JavaScript files nested past the parser's bound (deep.js (line 1: nesting too deep), hook.js (line 1: "
            "nesting too deep)): "), by["SC-NESTED-CODE"]["msg"])
        self.assertEqual((by["SC-UNPARSED-CODE"]["sev"], by["SC-UNPARSED-CODE"]["file"]), ("INFO", "a.js"))
        self.assertTrue(by["SC-UNPARSED-CODE"]["msg"].startswith(
            "3 JavaScript files the parser could not read (a.js, b.js (line 3: unexpected token '='), unused.js (line "
            "1: nesting too deep)): "), by["SC-UNPARSED-CODE"]["msg"])
        self.assertEqual(repo._unparsed_code_issues({"unused.js": {"use": deep}})[0]["rule"], "SC-UNPARSED-CODE")
        self.assertEqual(repo._unparsed_code_issues({}), [])
        self.assertNotIn(repo.UNPARSED_CODE_RULE, repo.TRUNCATION_RULES)
        self.assertNotIn(repo.NESTED_CODE_RULE, repo.TRUNCATION_RULES)


class TypeScriptTests(unittest.TestCase):
    """TS-STRIP (0.1.9): a TypeScript member is read, and refused, in its own dialect, and the findings name its
    language: Node does not run a .tsx file, so `node --check` is no advice for one."""

    def test_a_typescript_files_refusal_is_its_dialects(self):
        # JSX is no TypeScript in a .ts file: JavaScript's reading, the first tried before, read it
        view = "const a = 1;\nexport const el = <div>hi</div>;\n"
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/view.ts": view})
        ((file, line, sev, msg),) = unparsed(res)
        self.assertEqual((file, line, sev), ("lib/view.ts", 2, "INFO"))
        self.assertTrue(msg.startswith("1 TypeScript file the parser could not read (lib/view.ts (line 2: "), msg)
        # and the same text in a .tsx file is read
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": PLAIN, "lib/view.tsx": view})
        self.assertEqual(unparsed(res), [])

    def test_an_install_script_in_its_dialect(self):
        # (js_refusal, the parse alone, is asked in the script's dialect)
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node src/postinstall.ts"}),
                        "src/postinstall.ts": "const a = 1;\nconst el = <div>hi</div>;\n"})
        ((file, line, _sev, msg),) = unparsed(res)
        self.assertEqual((file, line), ("src/postinstall.ts", 2))
        self.assertTrue(msg.startswith("1 TypeScript file the parser could not read"), msg)

    def test_the_words(self):
        def one(found):
            # each file refused by the import-time pass (its code runs: a nesting refusal there is SC-NESTED-CODE)
            (issue,) = repo._unparsed_code_issues({rel: {"import": why} for rel, why in found.items()})
            return issue

        broken = (3, "unexpected token '='")
        ts = one({"a.ts": broken, "b.tsx": broken})
        self.assertEqual(ts["name"], "TypeScript the parser could not read")
        self.assertTrue(ts["msg"].startswith("2 TypeScript files the parser could not read (a.ts (line 3: "), ts["msg"])
        self.assertIn("tsc --noEmit --jsx preserve FILE", ts["fix"])
        self.assertNotIn("node --check", ts["fix"])
        self.assertIn("tsc refuses them too", ts["why"])
        self.assertNotIn("V8", ts["why"])
        mixed = one({"a.js": broken, "b.mts": broken})
        self.assertEqual(mixed["name"], "JavaScript or TypeScript the parser could not read")
        self.assertTrue(mixed["msg"].startswith("2 JavaScript or TypeScript files the parser could not read"))
        self.assertIn("node --check FILE", mixed["fix"])
        self.assertIn("tsc --noEmit --jsx preserve FILE", mixed["fix"])
        js = one({"a.js": broken, "b.cjs": broken})
        self.assertEqual(js["name"], "JavaScript the parser could not read")
        self.assertEqual(js["fix"], "Check that the file is one Node would refuse (`node --check FILE`); if Node runs "
                                    "it, review it.")
        self.assertNotIn("tsc", js["why"])
        # SC-NESTED-CODE names the language too
        deep = (1, "nesting too deep")
        nested_ts = one({"a.cts": deep})
        self.assertEqual(nested_ts["name"], "TypeScript nested too deep for the parser")
        self.assertTrue(nested_ts["msg"].startswith("1 TypeScript file nested past the parser's bound"))
        self.assertIn("V8 and tsc compile", nested_ts["why"])
        nested_js = one({"a.js": deep})
        self.assertEqual(nested_js["name"], "JavaScript nested too deep for the parser")
        self.assertIn("deep nesting is the one kind of source V8 compiles", nested_js["why"])
        # (a .d.ts declaration is never listed: _note_unparsed leaves it out)


if __name__ == "__main__":
    unittest.main()
