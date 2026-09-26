// False positives from real registry scans (twin of
// tests/scanner/test_review_false_positives.py; the Python suite also runs
// both engines on the same trees). Inert strings; nothing is executed.
//  - the dependency-mode decode flow took RegExp.prototype.exec for a sink;
//  - SC-MARSHAL flagged exec(compile(<source>)), and was the only rule that
//    caught exec(compile(b64decode(…)));
//  - SC-CHARCODE counted numbers anywhere on a long minified line, and any
//    array of printable codes on it;
//  - the scope-less decode flow reached every sink in a large bundle, and
//    took `function exec(…) {` for a call.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const B64 = '"Y29uc29sZS5sb2coMSk="';
const lines = (content, lang, rule, dep = true) =>
  scanFile({ path: `x.${lang}`, content, lang, dep }).filter((i) => i.rule === rule).map((i) => i.line);

test("decode flow: RegExp and other .exec/.eval methods are not code execution", () => {
  const prefix = `var t = atob(${B64});\n`;
  for (const line of ["for (ya.lastIndex = 0; (r = ya.exec(t)) !== null;) { g(r) }",
    "let q = /[^=]*/.exec(t)[0];", "db.exec(t);", "model.eval(t);", "foo().exec(t);"])
    assert.deepEqual(lines(prefix + line + "\n", "js", "SC-EVAL-DECODE"), [], line);
  for (const line of ["eval(t);", "window.eval(t);", "new Function(t);", 'require("child_process").exec(t);',
    "exec(t);", "worker.spawn(t);"])
    assert.deepEqual(lines(prefix + line + "\n", "js", "SC-EVAL-DECODE"), [2], line);
  assert.deepEqual(lines(prefix + 'import * as cp from "node:child_process";\ncp.exec(t);\n', "js", "SC-EVAL-DECODE"), [3]);
  const inline = scanFile({ path: "x.js", lang: "js", dep: true,
    content: `const cp = require("child_process");\ncp.exec(wrap(atob(${B64})));\n` })
    .filter((i) => i.rule === "SC-EVAL-DECODE");
  assert.deepEqual(inline.map((i) => [i.line, i.msg]),
    [[2, "Decoded payload reaches a code-execution sink in the same call."]]);
});

test("decode flow: a decode reaches sinks within 10,000 characters; definitions are not calls", () => {
  const decode = `var t = atob(${B64});\n`;
  const pad = (n) => `var pad = [${"0,".repeat(n >> 1)}];\n`;
  assert.deepEqual(lines(decode + pad(10500) + "eval(t);\n", "js", "SC-EVAL-DECODE"), []);
  assert.deepEqual(lines(decode + pad(2000) + "eval(t);\n", "js", "SC-EVAL-DECODE"), [3]);
  assert.deepEqual(lines(decode + pad(6666) + "var u = t;\n" + pad(6666) + "eval(u);\n", "js", "SC-EVAL-DECODE"), []);
  // astral characters count once, as in the Python engine
  assert.deepEqual(lines(decode + `var s = "${"\u{1F600}".repeat(9000)}";\n` + "eval(t);\n", "js", "SC-EVAL-DECODE"), [3]);
  for (const line of ["function exec(t, e) { return run(t, e); }", "function* exec(t) { yield t; }",
    "var o = { exec(t) { return t; } };", "class A { exec(t, e) { return 1; } }", "class B { async eval(t) {} }"])
    assert.deepEqual(lines(decode + line + "\n", "js", "SC-EVAL-DECODE"), [], line);
  assert.deepEqual(lines(decode + "function run(x) { return x; } exec(t);\n", "js", "SC-EVAL-DECODE"), [2]);
  assert.deepEqual(lines("d = base64.b64decode(p)\ndef exec(d):\n    return d\n", "py", "SC-EVAL-DECODE"), []);
});

test("exec(compile(source)) is not bytecode; decode -> compile -> exec still is", () => {
  const rules = (src, dep = true) => new Set(scanFile({ path: "x.py", content: src + "\n", lang: "py", dep }).map((i) => i.rule));
  assert.deepEqual([...rules('exec(compile(path.read_bytes(), str(path), "exec"), ns)')], []);
  assert.ok(rules('exec(compile(base64.b64decode(x), "<s>", "exec"))').has("SC-EVAL-DECODE"));
  for (const src of ["code = marshal.load(fh)", 'exec(__import__("marshal").loads(b))', "c = types.CodeType(0)",
    'm = imp.load_compiled("x", "x.pyc")'])
    assert.ok(rules(src).has("SC-MARSHAL"), src);
});

test("SC-CHARCODE counts the codes inside the call", () => {
  const numbers = "x=12,y=34,z=56,w=78,v=90,u=11,q=22,r=33,s=44,t=55,o=66;";
  for (const line of ["n+=String.fromCharCode(255&e),e>>>=8;", "t+=String.fromCharCode(e>>>10&1023|55296);",
    "return String.fromCharCode(...n.subarray(0,r));", "catch(r){r=String.fromCharCode.apply(null,n)}"])
    assert.deepEqual(lines(line + numbers + "\n", "js", "SC-CHARCODE"), [], line);
  const codes = "104,116,116,112,115,58,47,47,101,120,97";
  for (const line of [`var s=String.fromCharCode(${codes});`, `x=String.fromCharCode.apply(null,[${codes}]);`,
    `var k=[${codes}];eval(String.fromCharCode(...k));`])
    assert.deepEqual(lines(line + "\n", "js", "SC-CHARCODE"), [1], line);
  for (const line of [`var T=[${codes}];s+=String.fromCharCode(e>>>10&1023|55296);`,
    `var k=[${codes}];x=String.fromCharCode(o.k);`, `o.k=[${codes}];x=String.fromCharCode(...k);`])
    assert.deepEqual(lines(line + numbers + "\n", "js", "SC-CHARCODE"), [], line);
  assert.deepEqual(lines(`s=String.fromCharCode.apply(null,k);var k=[${codes}];\n`, "js", "SC-CHARCODE"), [1]);
  // the argument window is counted in code points, as in the Python engine
  assert.deepEqual(lines(`x=String.fromCharCode(f("${"\u{1F600}".repeat(3000)}"),${codes});\n`, "js", "SC-CHARCODE"), [1]);
});
