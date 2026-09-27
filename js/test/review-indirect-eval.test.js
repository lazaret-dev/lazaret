// Decode-then-run through an indirect call of eval or Function (twin of
// python/tests/scanner/test_review_indirect_eval.py): `(0, eval)(…)`,
// `eval.call(null, …)`, `eval.apply(this, […])`, `eval.bind(null)(…)`,
// `Reflect.apply(eval, null, […])`, `window['eval'](…)` and
// `globalThis["ev" + "al"](…)` — the same for Function — are sinks of
// SC-EVAL-DECODE and of the dependency decode flow. A global object may name
// them, no other receiver (TypeScript's `(0, module_1.name)(…)`). Payloads are
// inert text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const DECODE = "atob('Y29uc29sZS5sb2coMSk=')";
const RUN = "Code decoded (base64/escape) and immediately executed.";
const FLOW = "Decoded payload (assigned at line 1) reaches a code-execution sink.";
const evalDecode = (content, dep = false, lang = "js") =>
  scanFile({ path: "x." + lang, content, lang, dep }).filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => [i.line, i.msg]);
const fill = (call, arg) => call.replace("%s", arg);

const CALLS = ["(0, eval)(%s)", "(0,eval)(%s)", "(void 0, eval)(%s)", "(1, window.eval)(%s)",
  "(0, globalThis.Function)(%s)()", "eval.call(null, %s)", "eval.call(void 0, %s)",
  "eval.call(this,%s)", "eval.apply(this, [%s])", "Function.apply(null, [%s])()",
  "eval.bind(null)(%s)", "Function.bind(this, 'a')(%s)", "Reflect.apply(eval, null, [%s])",
  "Reflect.apply(globalThis.eval, undefined, [%s])", "window['eval'](%s)", 'self["Function"](%s)()',
  "globalThis[`eval`](%s)", "window['ev' + 'al'](%s)", 'this["e"+"v"+"a"+"l"](%s)',
  "window['Func' +\t'tion'](%s)()", "top[ 'eval' ]( %s )"];

test("a decoded payload run through an indirect eval", () => {
  for (const call of CALLS) {
    for (const dep of [false, true]) assert.deepEqual(evalDecode(fill(call, DECODE) + ";\n", dep), [[1, RUN]], `${call} dep=${dep}`);
    const flow = `const d = ${DECODE};\n` + fill(call, "d") + ";\n";
    assert.deepEqual(evalDecode(flow, true), [[2, FLOW]], `flow: ${call}`);
    assert.deepEqual(evalDecode(flow), [], `project: ${call}`);
  }
  for (const text of ["(0, eval)(\n  %s);\n", "window['eval'](\n  %s);\n", "globalThis['ev' + 'al'](\n  %s);\n",
    "eval.call(null,\n  %s);\n"]) assert.deepEqual(evalDecode(fill(text, DECODE)), [[1, RUN]], text);
});

test("what is not an indirect eval", () => {
  for (const text of ["(0, eval)('this');\n", "(0, eval)(x);\n", `(0, index_9.Function)(${DECODE});\n`,
    `(0, util_1.eval)(${DECODE});\n`, `Reflect.apply(api.eval, null, [${DECODE}]);\n`, `x['get' + 'Item'](${DECODE});\n`,
    `x['evaluate'](${DECODE});\n`, `// (0, eval)(${DECODE})\n`,
    `Function.prototype.apply.call(f, null, [${DECODE}]);\n`]) {
    for (const dep of [false, true]) assert.deepEqual(evalDecode(text, dep), [], `${text} dep=${dep}`);
  }
  for (const text of ["const d = atob(p);\nconst s = \"(0, eval)(d)\";\n", "const d = atob(p);\n(0, index_9.Function)(d);\n",
    "const d = atob(p);\nx['get' + 'Item'](d);\n", "const d = atob(p);\nwindow['eval'](e);\n"]) {
    assert.deepEqual(evalDecode(text, true), [], text);
  }
  assert.deepEqual(evalDecode("exec(__import__('base64').b64decode(p))\n", false, "py"), [[1, RUN]]);
});
