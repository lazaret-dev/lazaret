"""Decode-then-run through an indirect call of eval or Function (review of
the adversarial analysis).

SC-EVAL-DECODE knew `eval(atob(p))` and `globalThis.eval(atob(p))`, and the
dependency decode flow `const d = atob(p); eval(d)`, but not the ways
JavaScript calls eval without writing `eval(`: the comma operator's
`(0, eval)(…)`, `eval.call(null, …)`, `eval.apply(this, […])`,
`eval.bind(null)(…)`, `Reflect.apply(eval, null, […])`, and a computed member
named by a string literal, whole or cut into pieces (`window['eval'](…)`,
`globalThis["ev" + "al"](…)`); the same for Function. Each ran a decoded
payload unseen. Now both the rule and the flow take them as sinks (core
_INDIRECT_EVAL, _INDIRECT_SINK_RE), a global object may name them (`(0,
window.eval)`) but no other receiver: TypeScript's CommonJS output calls
every imported function as `(0, module_1.name)(…)`, and typebox exports one
named Function.

The npm engine's twins are in js/src/scanner/rules.js and scan.js
(js/test/review-indirect-eval.test.js; tests/architecture/
test_js_parity_eval.py compares the engines). Payloads are inert text.
"""
import unittest

from lazaret.scanner import core

DECODE = "atob('Y29uc29sZS5sb2coMSk=')"


def eval_decode(text, dep=False, lang="js"):
    return [(i["line"], i["msg"]) for i in core.scan_file("x." + lang, text, lang, dep=dep)
            if i["rule"] == "SC-EVAL-DECODE"]


RUN = "Code decoded (base64/escape) and immediately executed."
FLOW = "Decoded payload (assigned at line 1) reaches a code-execution sink."


class IndirectEvalTests(unittest.TestCase):
    CALLS = ["(0, eval)(%s)", "(0,eval)(%s)", "(void 0, eval)(%s)", "(1, window.eval)(%s)",
             "(0, globalThis.Function)(%s)()", "eval.call(null, %s)", "eval.call(void 0, %s)",
             "eval.call(this,%s)", "eval.apply(this, [%s])", "Function.apply(null, [%s])()",
             "eval.bind(null)(%s)", "Function.bind(this, 'a')(%s)", "Reflect.apply(eval, null, [%s])",
             "Reflect.apply(globalThis.eval, undefined, [%s])", "window['eval'](%s)", 'self["Function"](%s)()',
             "globalThis[`eval`](%s)", "window['ev' + 'al'](%s)", 'this["e"+"v"+"a"+"l"](%s)',
             "window['Func' +\t'tion'](%s)()", "top[ 'eval' ]( %s )"]

    def test_decoded_payload_run_indirectly(self):
        for call in self.CALLS:
            for dep in (False, True):
                with self.subTest(call=call, dep=dep):
                    self.assertEqual(eval_decode(call % DECODE + ";\n", dep=dep), [(1, RUN)])

    def test_through_a_variable_in_a_dependency(self):
        for call in self.CALLS:
            with self.subTest(call=call):
                text = f"const d = {DECODE};\n" + call % "d" + ";\n"
                self.assertEqual(eval_decode(text, dep=True), [(2, FLOW)])
                self.assertEqual(eval_decode(text), [])            # the project scan has T-CODE for this

    def test_split_across_lines(self):
        for text in ("(0, eval)(\n  %s);\n", "window['eval'](\n  %s);\n", "globalThis['ev' + 'al'](\n  %s);\n",
                     "eval.call(null,\n  %s);\n"):
            with self.subTest(text=text):
                self.assertEqual(eval_decode(text % DECODE), [(1, RUN)])

    def test_what_is_not_an_indirect_eval(self):
        cases = [
            "(0, eval)('this');\n",                                       # webpack: the global object
            "(0, eval)(x);\n",
            f"(0, index_9.Function)({DECODE});\n",                        # TypeScript: an imported function
            f"(0, util_1.eval)({DECODE});\n",
            f"Reflect.apply(api.eval, null, [{DECODE}]);\n",
            f"x['get' + 'Item']({DECODE});\n",
            f"x['evaluate']({DECODE});\n",
            f"// (0, eval)({DECODE})\n",
            f"Function.prototype.apply.call(f, null, [{DECODE}]);\n",
        ]
        for text in cases:
            for dep in (False, True):
                with self.subTest(text=text, dep=dep):
                    self.assertEqual(eval_decode(text, dep=dep), [])
        flow_cases = [
            "const d = atob(p);\nconst s = \"(0, eval)(d)\";\n",
            "const d = atob(p);\n(0, index_9.Function)(d);\n",
            "const d = atob(p);\nx['get' + 'Item'](d);\n",
            "const d = atob(p);\nwindow['eval'](e);\n",
        ]
        for text in flow_cases:
            with self.subTest(text=text):
                self.assertEqual(eval_decode(text, dep=True), [])

    def test_python_is_unchanged(self):
        self.assertEqual(eval_decode("exec(__import__('base64').b64decode(p))\n", lang="py"), [(1, RUN)])
        self.assertEqual(eval_decode("x = (0, eval)(b64decode(p))\n", lang="py"), [(1, RUN)])


if __name__ == "__main__":
    unittest.main()
