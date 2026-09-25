// Review regressions: rule drift between the engines (review findings 15,
// 16 and 17; shared semantics 5, 12, 13). Every expectation equals the
// Python engine's scan_file result (rule, line) on the same input. Inputs
// are inert strings; credentials are dummies.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile, RULES } from "../src/index.js";

const rules = (content, lang, { dep = false, name = `t.${lang}` } = {}) =>
  scanFile({ name, content, lang, dep }).map((i) => `${i.rule}@${i.line}`).sort();

test("S-SECRET: markup lines and `example_*` words no longer hide a credential", () => {
  // was: any `<…>` on the line and substring `example` skipped the rule
  assert.deepEqual(rules('<Input password="hunter2hunter2" />\n', "js", { name: "t.jsx" }), ["S-SECRET@1"]);
  assert.deepEqual(rules('api_key = "Zq8vN3pL0wX7rT2mK9sB"  # example_user\n', "py"), ["S-SECRET@1"]);
  assert.deepEqual(rules('api_key = "Zq8vN3pL0wX7rT2mK9sB"  # example\n', "py"), []);
});

test("S-ENTROPY: `latest`/`test` comments do not suppress; identifiers are not secrets", () => {
  assert.deepEqual(rules('tok = "Zq8vN3pL0wX7rT2mK9sB4hF6"  # latest\n', "py"), ["S-ENTROPY@1"]);
  assert.deepEqual(rules('tok = "Zq8vN3pL0wX7rT2mK9sB4hF6"  # test\n', "py"), ["S-ENTROPY@1"]);
  assert.deepEqual(rules('x = "ThisIsAVeryLongCamelCaseIdentifierName"\n', "py"), []);   // entropy_secretish
});

test("Unicode identifiers keep their taint (\\w is Unicode, as in Python)", () => {
  assert.deepEqual(rules("café = request.args['x']\nos.system(café)\n", "py"), ["S-OSCMD-PY@2", "T-CMD@2"]);
  assert.deepEqual(rules("const naïve = req.query.q;\nexec(naïve);\n", "js"), ["S-EXEC-JS@2", "T-CMD@2"]);
});

test("taint idioms: annotated assignment and destructuring (spec 12)", () => {
  assert.deepEqual(rules("x: str = request.args['q']\nos.system(x)\n", "py"), ["S-OSCMD-PY@2", "T-CMD@2"]);
  assert.deepEqual(rules("const { a, b: c } = req.query;\nexec(c);\n", "js"), ["S-EXEC-JS@2", "T-CMD@2"]);
  assert.deepEqual(rules("const [first] = req.body.items;\neval(first);\n", "js"), ["S-EVAL-JS@2", "T-CODE@2"]);
});

test("SQL rules: SQL-CRED skip list; Q-LONGLINE on .sql, counted in code points", () => {
  assert.deepEqual(rules("CREATE USER app IDENTIFIED BY 'example';\n", "sql"), []);
  assert.deepEqual(rules("CREATE USER app IDENTIFIED BY 'hunter2hunter2';\n", "sql"), ["SQL-CRED@1"]);
  assert.deepEqual(rules("SELECT " + "a, ".repeat(100) + "b FROM t;\n", "sql"), ["Q-LONGLINE@1"]);
  assert.deepEqual(rules("const s = '" + "\u{1F600}".repeat(130) + "';\n", "js"), []);   // 143 code points
  assert.deepEqual(rules("const s = '" + "\u{1F600}".repeat(150) + "';\n", "js"), ["Q-LONGLINE@1"]);
});

test("SQL sink map has no prototype: execute(constructor) is not a finding", () => {
  assert.deepEqual(rules("cur.execute(constructor)\ncur.execute(toString)\n", "py"), []);
});

test("dependency files: no quality/bug text rules, no SQL sink analysis", () => {
  const src = "try { f() } catch (e) {}\n";
  assert.deepEqual(rules(src, "js"), ["B-EMPTY-CATCH@1"]);
  assert.deepEqual(rules(src, "js", { dep: true, name: "node_modules/x/a.js" }), []);
  assert.deepEqual(rules('cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n', "py",
    { dep: true, name: "site-packages/x/a.py" }), []);
});

test("Unicode evasion (spec 5): JS identifier escapes, U+FEFF, NFKC, bidi controls", () => {
  assert.deepEqual(rules("\\u0065val(x)\n", "js"), ["S-EVAL-JS@1"]);
  assert.deepEqual(rules("\\u{65}val(x)\n", "js"), ["S-EVAL-JS@1"]);
  assert.deepEqual(rules("const s = '\\u0065val(x)';\n", "js"), []);          // inside a string: data
  assert.deepEqual(rules("eval\ufeff(x)\n", "js"), ["S-EVAL-JS@1"]);
  assert.deepEqual(rules("\uff45val(x)\n", "py"), ["S-EVAL-PY@1"]);            // fullwidth e → NFKC
  assert.deepEqual(rules("const ok = 1; // \u202e }\n", "js"), ["S-BIDI@1"]);
  const bidi = scanFile({ name: "t.js", content: "// \u2066x\n", lang: "js" })[0];
  assert.deepEqual([bidi.rule, bidi.sev, bidi.type], ["S-BIDI", "CRITICAL", "VULN"]);
});

test("decode → execute across lines and statements (spec 13)", () => {
  assert.deepEqual(rules("eval(\n  atob(x))\n", "js"), ["S-EVAL-JS@1", "SC-EVAL-DECODE@1"]);
  assert.deepEqual(rules("eval(globalThis.atob(x))\n", "js"), ["S-EVAL-JS@1", "SC-EVAL-DECODE@1", "T-CODE@1"]);
  const dep = scanFile({ name: "node_modules/x/a.js", content: "const p = atob(s);\nconst q = 1;\neval(p);\n", lang: "js", dep: true });
  assert.deepEqual(dep.map((i) => [i.rule, i.line, i.msg]),
    [["SC-EVAL-DECODE", 3, "Decoded payload (assigned at line 1) reaches a code-execution sink."]]);
  assert.deepEqual(rules("import base64\nblob = base64.b64decode(s)\nexec(blob)\n", "py",
    { dep: true, name: "site-packages/x/a.py" }), ["SC-EVAL-DECODE@3"]);
});

test("message and name text is the Python engine's", () => {
  const hex = scanFile({ name: "t.py", content: 's = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x21\\x21"\n', lang: "py" });
  assert.deepEqual(hex.map((i) => i.rule), ["SC-HEXSTR"]);
  const rule = (id) => RULES.find((r) => r.id === id);
  assert.equal(rule("S-EVAL-JS").msg, "Use of eval enables arbitrary code execution.");
  assert.equal(rule("S-XML").name, "XML parsing without a hardened parser");
});
