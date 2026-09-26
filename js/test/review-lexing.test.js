// Review regressions: the comment lexer and what is built on it. Every
// expectation here was checked against the Python engine
// (lazaret.scanner.core.scan_file) on the same input; the CLIs are compared in
// python/tests/architecture/test_js_parity_lexing.py. Fixtures are inert
// strings — nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const LIMIT_MS = 4000;
const rules = (content, lang, { dep = false, name = `t.${lang}` } = {}) =>
  scanFile({ name, content, lang, dep }).map((i) => `${i.rule}@${i.line}`).sort();

// jsText tested every comment span of a line for each \u escape, and the
// suppression check every span for each marker match: O(n²) on one line
// (`x=1;` + `/**/a` x 20,000: 2.2 s, x 60,000: ~20 s), beyond the reach
// of the per-file time budget. Both now walk the sorted spans once.
function timed(content) {
  const t0 = performance.now();
  const issues = scanFile({ name: "a.js", content, lang: "js" });
  const ms = performance.now() - t0;
  assert.ok(ms < LIMIT_MS, `${ms.toFixed(0)} ms`);
  assert.ok(!issues.some((i) => i.rule === "SC-TRUNCATED"), "hit the time backstop");
  return issues.map((i) => `${i.rule}@${i.line}`).sort();
}

test("linear: \\u escapes between comments on one line", () => {
  timed("x=1;" + "/**/\\u0061".repeat(60000) + "\n");
});

test("linear: marker look-alikes in strings between comments", () => {
  // every "// nosec" sits in a string: none suppresses the eval
  assert.ok(timed("x=1;" + "'// nosec'/**/".repeat(60000) + "eval(a)\n").includes("S-EVAL-JS@1"));
});

test("comment and escape handling is unchanged", () => {
  const src = "a = 1; /* c */ \\u0065val(x) /* d */ \\u0065val(y) // nosec\n/**/\\u0065val(z)\n";
  assert.deepEqual(rules(src, "js"), ["S-EVAL-JS@2"]);
});

// ---- comment masking fails closed: a comment only where both readings agree
const langOf = (name) => (/\.sql$/.test(name) ? "sql" : /\.py$/.test(name) ? "py" : "js");
const scan = (name, content) => rules(content, langOf(name), { name });
const DUMP = "INSERT INTO people VALUES (1,'O\\'Brien','src/*.js');\n"
  + "GRANT ALL PRIVILEGES ON appdb.* TO 'marker_user'@'%';\nSELECT * FROM people;\n";

test("SQL: a MySQL \\' escape opens no comment", () => {
  const want = ["SQL-GRANT-ALL@2", "SQL-SELECT-STAR@3"];
  assert.deepEqual(scan("dump.sql", DUMP), want);
  assert.deepEqual(scan("control.sql", DUMP.replace("O\\'Brien", "OBrien")), want);
});

test("SQL: a marker in a MySQL string suppresses nothing", () => {
  assert.deepEqual(scan("m.sql", "SELECT 'it\\'s -- nosec'; GRANT ALL ON t TO u;\n"), ["SQL-GRANT-ALL@1"]);
});

test("SQL: MySQL runs /*! … */ and quotes names in backticks", () => {
  const src = "/*!50000 GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' */;\nSELECT `a/*b` FROM t;\nGRANT ALL ON t TO u;\n"
    + "/* GRANT ALL ON y TO z */\n-- nosec\nGRANT ALL ON v TO w;\n";
  assert.deepEqual(scan("x.sql", src), ["SQL-GRANT-ALL@1", "SQL-GRANT-ALL@3"]);
});

test("JSX text opens no comment and holds no marker", () => {
  const src = "const a = <p>Docs at /api/* and https://example.invalid/x</p>;\neval(input)\n// */\n";
  assert.deepEqual(scan("a.jsx", src), ["S-EVAL-JS@2"]);
  assert.deepEqual(scan("b.js", "export default <p>/api/*</p>;\neval(input)\n"), ["S-EVAL-JS@2"]);
  assert.deepEqual(scan("c.tsx", "if (x) <a title='/*'>{y}/*</a>;\neval(input)\n"), ["S-EVAL-JS@2"]);
  assert.deepEqual(scan("d.jsx", "const a = <p>// nosec</p>; eval(x)\n"), ["S-EVAL-JS@1"]);
});

test("comments in JSX code, TypeScript generics and assertions stay comments", () => {
  const jsx = "const a = (\n  <div id=\"x\"\n    // eval(p)\n    title={\n      /* eval(q) */\n      t}>\n"
    + "    {\n      // eval(s)\n    }\n    <br/>\n  </div>\n);\n// eval(u)\n";
  assert.deepEqual(scan("a.jsx", jsx), []);
  assert.deepEqual(scan("a.tsx", "const id = <T,>(x: T) => x;\n// eval(z)\n"), []);
  assert.deepEqual(scan("b.ts", "const id = <T>(x: T) => x;\n// eval(z)\n"), []);
  assert.deepEqual(scan("c.ts", "const el = <HTMLInputElement>document.body;\n// eval(z)\n"), []);
  assert.deepEqual(scan("d.js", "if (a[0] < b) { f() }\n// eval(z)\nif (g(x) < h) {}\n// eval(w)\n"), []);
  // TypeScript parses no JSX in .ts: `<p>` there is a type assertion
  const src = "const a = <p>x /* </p>;\neval(input)\n*/\n";
  assert.deepEqual(scan("a.ts", src), []);
  assert.deepEqual(scan("a.tsx", src), ["S-EVAL-JS@2"]);
});

test("Python: f-strings read as 3.12+ reads them hide no comment and forge no marker", () => {
  for (const src of ['x = f"{d["# nosec"]}" + eval(y)\n', "x = t'{d['# nosec']}' + eval(y)\n",
    'x = f"{v:# nosec}"; eval(y)\n', 'x = f"""{d["""# nosec"""]}""" + eval(y)\n',
    "z = eval(x) + 'unterminated  # nosec\n"]) {
    assert.deepEqual(scan("f.py", src), ["S-EVAL-PY@1"], src);
  }
  const ordinary = 's = f"{a!r:>{w}}"  # nosec\nt = f"{{# not a field}}"  # c\n  # full\n'
    + 'u = rf"\\{x}" "#"  # c\nv = f"\\N{BULLET} {x}"\n# eval(z)\n';
  assert.deepEqual(scan("o.py", ordinary), []);
});
