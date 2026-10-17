"""The engine's JavaScript parser (`js_parse`) against V8, on a curated set:
every source here V8 compiles — as a script (Node's CommonJS: a `.cjs`, and a
`.js` whose package.json does not say `"type": "module"`) or as a module —
the parser must parse. Where it does not, the supply-chain tests have only
the text followers for the file: the answers only its tree gives (another
package's code rewritten, a program carved out of another file, D-13's
loads, the cross-file pass) are lost. The oracle is
`scripts/fuzz/js_v8_compile.cjs` (a node subprocess; V8 compiles only,
nothing is run).

A fixed list, not a fuzzer: `js-parse` in `scripts/fuzz` fuzzes the parser
for robustness. The list is constructs a package's script uses, Annex B's
HTML-like comments among them (F-12: `<!--` and `-->` were syntax errors, so
a file that opened with `<!-- a banner` did not parse), and what the parser
refused before JS-PARSE-STRICT (Oct 9): an assignment or an update to a call,
which V8 compiles and leaves to a ReferenceError when the line runs, and
`let` as a name in sloppy code. What V8 refuses, the parser refuses too (the
forms next to those). The one place left where the parser is stricter is
nesting: it stops past MAX_DEPTH (jsparse), well short of V8, and a
registry scan says which of a package's files it could not read
(SC-UNPARSED-CODE). Skipped where node is missing.
"""
import json
import os
import shutil
import subprocess
import unittest

from tests import _support
from lazaret.scanner import _native

NODE = shutil.which("node")
V8 = os.path.join(_support.REPO_ROOT, "scripts", "fuzz", "js_v8_compile.cjs")

# Sources a script (or a module) runs that the parser must read. Annex B's HTML-like comments are the F-12 cases.
VALID = [
    # Annex B (ECMA-262 B.1.1): `<!--` opens a line comment anywhere; `-->` opens one where a line begins.
    "<!-- a banner a script runs\nmodule.exports = 1;\n",
    "0;\n--> a close comment at a line's start\nmodule.exports = 1;\n",
    "<!-- open\nx = 1;\n--> close\n",
    "/* a\nb */ --> close after a block comment with a line break\ny = 2;\n",
    "#!/usr/bin/env node\n<!-- after a hashbang\nz = 3;\n",
    "   --> blanks then a close comment, the input's first line\nx = 1;\n",
    "var html = a <!-- b;\n",
    "x<!--y\nz = 1;\n",
    "i-->0;\n",
    "x = i-- > 0;\n",
    # modern syntax a package's code uses
    "a ??= b; c ||= d; e &&= f; g = h?.i?.[j]?.(k);\n",
    "x = 1_000n + 0xffn + 0o7n + 0b1n;\n",
    "async function* f() { for await (const x of y) yield* z; }\n",
    "class C { #p = 1; static { this.q = 2; } m() { return #p in this; } get #g() { return 1; } }\n",
    "const { [a]: b, ...c } = d; [e, , ...f] = g;\n",
    "x = (a) => (b) => ({ c: d }); let h = async (e, f) => e;\n",
    "import.meta.url; p = import(x); export default function () {}\n",
    "const a = 1; export { a as b }; export * as ns from 'm'; import y, * as z from 'w';\n",
    "s = `x${`y${z}`}` + tag`a${b}`;\n",
    "for (var a in b); for (const c of d); for (let e = (f in g); ;) break;\n",
    "r = /[a-z/]/gimsuy; t = a / b / c; u = /=/; v = x++ / 2;\n",
    "function f(a = 1, { b } = {}, ...rest) { return new.target; }\n",
    "label: for (;;) { break label; } do x(); while (0);\n",
    "with (o) { x = 1; } var yield = 2, await = 3; async = 4;\n",       # script-only forms
    # JS-PARSE-STRICT: an assignment or an update to a call (a ReferenceError when it runs; in modules too), `let`
    # as a name before `in` and `instanceof` (scripts)
    "function f() {}\nif (0) { f() = 1; f() += 1; f() **= 2; f()++; --f(); (f()) = 1; f() = g() = 1; }\n",
    "if (0) { for (f() in x); for (f() of x); for ((f()) in x); }\n",
    "var let = 1; for (let in {}); if (0) { let in x; let instanceof X; for (let.x in y); }\n",
]

# What V8 refuses, as scripts and as modules, next to what JS-PARSE-STRICT made the parser read: a call as the target
# of a logical assignment or inside a pattern, `new`, an optional chain, a tagged template, `import()`, a sequence,
# `for (let of x)`
REFUSED = ["f() &&= 1;", "f() ||= 1;", "f() ??= 1;", "[f()] = [];", "({a: f()} = {});", "[a, f()] = [1, 2];",
           "new f() = 1;", "a?.b = 1;", "a?.b() = 1;", "f()?.x = 1;", "f`x` = 1;", "import(x) = 1;", "(a, f()) = 1;",
           "for (let of x);"]


@unittest.skipUnless(NODE, "node is not installed")
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JsParseVsV8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen([NODE, "--experimental-vm-modules", "--no-warnings", V8],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        for pipe in (cls.proc.stdin, cls.proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
        cls.proc.kill()
        cls.proc.wait()

    def v8(self, src):
        self.proc.stdin.write(json.dumps({"src": src}) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def parses(self, src):
        for args in ({"ts": False, "jsx": True}, {"ts": False, "jsx": False}):
            status, answer = _native.call_raw("js_parse", args, src)
            if status == 0 and answer.startswith('{"type":"Program"'):
                return True
        return False

    def test_the_oracle_runs(self):
        self.assertEqual(self.v8("x = 1;\n"), {"script": True, "module": True})
        self.assertEqual(self.v8("]["), {"script": False, "module": False})

    def test_v8_compiles_the_curated_list(self):
        # (so the comparison below is comparing what it means to: sources a runtime runs)
        for src in VALID:
            got = self.v8(src)
            self.assertTrue(got["script"] or got["module"], f"V8 compiles neither: {src!r}")

    def test_the_parser_reads_every_source_v8_runs(self):
        for src in VALID:
            with self.subTest(src=src[:50]):
                self.assertTrue(self.parses(src), f"V8 runs it, js_parse does not: {src!r}")

    def test_what_v8_refuses_the_parser_refuses(self):
        for src in REFUSED:
            with self.subTest(src=src):
                self.assertEqual(self.v8(src), {"script": False, "module": False})
                self.assertFalse(self.parses(src))

    def test_nesting_past_the_bound_is_the_one_place_left(self):
        # V8 compiles 1,000 nested arrays; the parser reads 127 (MAX_DEPTH, 256, counts two for each): such a file
        # keeps only the text followers, and a registry scan says so (SC-UNPARSED-CODE)
        deep = "x = " + "[" * 200 + "]" * 200 + ";\n"
        self.assertTrue(self.v8(deep)["script"])
        self.assertFalse(self.parses(deep))
        self.assertTrue(self.parses("x = " + "[" * 120 + "]" * 120 + ";\n"))

    def test_an_html_comment_hides_nothing_a_module_runs(self):
        # V8 refuses a module that holds an HTML-like comment (Node: "HTML comments are not allowed in modules"),
        # even where the standard reads `<!--` as `<` `!` `--` (`x <!--y` is `x < !--y` in a module), so reading it as
        # a comment in a `.mjs` hides nothing V8 runs. (tsc reads it so too; TypeScript is read as tsc reads it.)
        self.assertFalse(self.v8("import x from 'y';\n<!-- c\nx();\n")["module"])
        self.assertFalse(self.v8("let y = 1; export const x = 5 <!--y;\n")["module"])
        self.assertEqual(self.v8("x = 5 <!--y, f();\n")["script"], True)


if __name__ == "__main__":
    unittest.main()
