// The cross-file flow engine's JavaScript half (src/scanner/flow.js), twin of
// lazaret.scanner.flow's: a request value passed into a function whose
// parameter reaches a sink (command, code, SQL, XSS, SSRF, redirect) is an
// X-* finding at the call site that names the sink's own file and line.
// Mirrors tests/scanner/test_review_flow_js.py, test_review_flow_js_lines.py
// and test_review_flow_sink_line.py on the Python side;
// tests/architecture/test_js_parity_flow.py compares the two engines.
// Inert text only: nothing is executed, the credential is a dummy.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { analyzeFlows, jsMask, jsText } from "../src/scanner/flow.js";
import { run } from "../src/index.js";

const LS = "\u2028", PS = "\u2029";
const SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9";
const APP = "app.get('/x', (req, res) => { const q = req.query.q; CALL; });\n";
const js = (...pairs) => pairs.map(([path, content]) => ({ path, content, lang: "js" }));
const xFindings = (files) => analyzeFlows(files).filter((f) => f.rule.startsWith("X-"));
const found = (helper, call = "runIt(q)") =>
  xFindings(js(["h.js", helper], ["app.js", APP.replace("CALL", call)])).map((f) => [f.rule, f.file]).sort();
const HIT = [["X-CMD", "app.js"]];

test("braces in strings, comments, regex and template text don't end a function", () => {
  assert.deepEqual(found("function runIt(cmd) {\n  exec(cmd);\n}\n"), HIT);
  assert.deepEqual(found('function runIt(cmd) {\n  const banner = "}";\n  exec(cmd);\n}\n'), HIT);
  for (const line of ["// closing } here", "/* } */", "const r = /}/g;", "const t = `}`;",
    "const t = `${'}'}`;", "const s = '\\'}';"]) {
    assert.deepEqual(found(`function runIt(cmd) {\n  ${line}\n  exec(cmd);\n}\n`), HIT, line);
  }
});

test("an open brace in a string doesn't make one function swallow the next", () => {
  const helper = 'function logIt(cmd) {\n  console.log("{" + cmd);\n}\nfunction other(cmd) {\n  exec(cmd);\n}\n';
  assert.deepEqual(found(helper, "logIt(q)"), []);
  assert.deepEqual(found(helper, "other(q)"), HIT);
  assert.deepEqual(found('function logIt(cmd) {\n  // exec(cmd) would be bad\n  console.log("exec(" + cmd + ")");\n}\n',
    "logIt(q)"), []);
});

test("a sink's arguments are its own: not a later statement's", () => {
  assert.deepEqual(found('function audit(msg) {\n  exec("uptime");\n  console.log(msg);\n}\n', "audit(q)"), []);
  assert.deepEqual(found('function audit(msg) {\n  exec("echo " + wrap(msg, ")"));\n}\n', "audit(q)"), HIT);
  const helper = "function show(html) {\n  el.innerHTML = '<b>' + html + '</b>';\n  log(html);\n}\n" +
    "function safe(t) {\n  el.innerHTML = 'x';\n  log(t);\n}\n";
  const got = xFindings(js(["h.js", helper],
    ["app.js", "app.get('/x', (req, res) => { const q = req.query.q; show(q); safe(q); });\n"]));
  assert.deepEqual(got.map((f) => [f.rule, f.line]), [["X-XSS", 1]]);
});

test("SQL: interpolated into the query is a flow, a placeholder argument is not", () => {
  assert.deepEqual(found("function find(id) {\n  return db.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n", "find(q)"),
    [["X-SQL", "app.js"]]);
  assert.deepEqual(found("function find(id) {\n  return db.query('SELECT * FROM t WHERE id = ?', [id]);\n}\n", "find(q)"), []);
});

test("sanitizers: numeric coercion clears every category, a category's sanitizer only its own", () => {
  const helper = "function runIt(cmd) {\n  exec(cmd);\n}\nfunction show(h) {\n  el.innerHTML = h;\n}\n";
  assert.deepEqual(found(helper, "const n = Number(q); runIt(n)"), []);
  assert.deepEqual(found(helper, "const n = parseInt(q, 10); runIt(n)"), []);
  assert.deepEqual(found(helper, "const s = q.trim(); runIt(s)"), HIT);
  assert.deepEqual(found(helper, "runIt(Number(q))"), []);
  assert.deepEqual(found(helper, "runIt(shellQuote(q))"), []);
  assert.deepEqual(found(helper, "runIt(escapeHtml(q))"), HIT);            // the wrong sanitizer for a shell
  assert.deepEqual(found(helper, "show(escapeHtml(q))"), []);
  assert.deepEqual(found(helper, "show(shellQuote(q))"), [["X-XSS", "app.js"]]);
});

test("the lexer blanks literal and comment content, keeping length, newlines and ${} code", () => {
  const cases = {
    'const b = "}"; exec(cmd);': 'const b = " "; exec(cmd);',
    "a = b / c / d;": "a = b / c / d;",
    "x = /}[/]\\//g.test(s);": "x = /      /g.test(s);",
    "return /ab+c/i.exec(s)": "return /    /i.exec(s)",
    "y = `t ${ {a:1}.a + `in ${z}` } }` + q;": "y = `  ${ {a:1}.a + `   ${z}` }  ` + q;",
    "// c }\n/* { \n } */ f(x)": "      \n     \n      f(x)",
    "s = 'it\\'s {';": "s = '       ';",
    "arr[i] / 2 / x": "arr[i] / 2 / x",
  };
  for (const [src, want] of Object.entries(cases)) assert.equal(jsMask(src), want, src);
  // one space per code point, as Python counts characters
  assert.equal(jsMask("s = '\u{1F600}';"), "s = ' ';");
});

test("hostile inputs are linear", () => {
  for (const src of ["`" + "${".repeat(50000) + "x", "'".repeat(300000), "/".repeat(300000),
    "/*" + "x".repeat(300000), "`".repeat(300001)]) {
    const t = Date.now();
    assert.equal(jsMask(src).length, src.length);
    assert.ok(Date.now() - t < 5000);
  }
});

test("U+2028 / U+2029 end a line: the finding's line, the sink's line", () => {
  assert.equal(jsText("a" + LS + "b" + PS + "c"), "a\nb\nc");
  const files = js(["h.js", "/* helper */" + LS + "function runIt(cmd) {\n  exec(cmd);\n}\n"],
    ["app.js", "// header" + LS + "const x = 1;" + PS + "const y = 2;\n" +
      "app.get('/x', (req, res) => { const q = req.query.q; runIt(q); eval(q); });\n"]);
  const [f] = xFindings(files);
  assert.deepEqual([f.rule, f.file, f.line], ["X-CMD", "app.js", 4]);
  assert.match(f.msg, /reaches a sink at h\.js:3 \(in runIt\(\)\) \(cross-file\)\.$/);
  assert.equal(f.snippet[4 - f.snipStart], "app.get('/x', (req, res) => { const q = req.query.q; runIt(q); eval(q); });");
});

test("the message names the sink call's own file and line", () => {
  const sinkAt = (files) => {
    const got = xFindings(files);
    assert.equal(got.length, 1, JSON.stringify(got));
    return got[0].msg.match(/reaches a sink at (\S+)/)[1];
  };
  const app = ["app.js", APP.replace("CALL", "runIt(q)")];
  assert.equal(sinkAt(js(["h.js", "\nfunction runIt(cmd) {\n  exec(cmd);\n}\n"], app)), "h.js:3");
  assert.equal(sinkAt(js(["h.js", "function runIt(cmd) {\n  log(cmd);\n  exec(cmd);\n  execSync(cmd);\n}\n"], app)), "h.js:3");
  assert.equal(sinkAt(js(["h.js", "function runIt(\n  cmd,\n  opts\n) {\n  return exec(\n    cmd);\n}\n"], app)), "h.js:5");
  // a sink-free function of the same name elsewhere doesn't take over the location
  assert.equal(sinkAt(js(["h.js", "function runIt(cmd) {\n\n  exec(cmd);\n}\n"],
    ["z.js", "function runIt(cmd) {\n  return cmd;\n}\n"], app)), "h.js:3");
});

test("every sink category, arrow functions and function expressions", () => {
  const helper = "const go = (u) => { res.redirect(u); };\nconst ev = async function (s) { eval(s); };\n" +
    "function net(u) { fetch(u); }\nfunction tpl(s) { return new Function(s); }\n";
  assert.deepEqual(found(helper, "go(q); ev(q); net(q); tpl(q)"),
    [["X-CODE", "app.js"], ["X-CODE", "app.js"], ["X-REDIR", "app.js"], ["X-SSRF", "app.js"]]);
});

test("dependencies are not analyzed; above 2,000,000 code points a file is skipped with a note", () => {
  const dep = [{ path: "node_modules/d/h.js", content: "function runIt(c) {\n  exec(c);\n}\n", lang: "js", dep: true },
    { path: "app.js", content: APP.replace("CALL", "runIt(q)"), lang: "js" }];
  assert.deepEqual(analyzeFlows(dep), []);
  const head = "function runIt(c) { exec(c); }\n//";
  const at = (n) => analyzeFlows(js(["big.js", head + "a".repeat(n - head.length)], ["app.js", APP.replace("CALL", "runIt(q)")]))
    .map((f) => [f.rule, f.file]);
  assert.deepEqual(at(2_000_000), HIT);
  assert.deepEqual(at(2_000_001), [["X-FLOW-SKIPPED", "big.js"]]);
  // astral characters count once, as in Python: 1,000,001 of them are analyzed
  assert.deepEqual(analyzeFlows(js(["big.js", head + "\u{1F600}".repeat(1_000_001)],
    ["app.js", APP.replace("CALL", "runIt(q)")])).map((f) => f.rule), ["X-CMD"]);
});

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-flow-"));
  for (const [rel, text] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return d;
}

test("the CLI reports the flow, redacts its snippet, and the gate says Python was not analyzed", () => {
  const d = tree({
    "lib/h.js": "const { exec } = require('child_process');\nfunction runIt(cmd) {\n  exec('ls ' + cmd);\n}\nmodule.exports = { runIt };\n",
    "app.js": `const { runIt } = require('./lib/h');\napp.get('/x', (req, res) => {\n  const seed = "${SEED}";\n  runIt(req.query.q);\n});\n`,
    "tool.py": "def add(a, b):\n    return a + b\n",
  });
  try {
    const report = (extra) => {
      const err = [];
      assert.equal(run(["check", d, "-q", "--no-html", "--force-overwrite", ...extra],
        { out: () => {}, err: (s) => err.push(s), env: {} }), 0, err.join("\n"));
      return JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    };
    const rep = report([]);
    const flows = rep.issues.filter((i) => i.rule.startsWith("X-"));
    assert.deepEqual(flows.map((i) => [i.rule, i.file, i.line]), [["X-CMD", "app.js", 4]]);
    // the sink path uses the OS separator (native on Windows, like the finding's
    // `file` field and the Python engine), so normalize it before matching
    assert.match(flows[0].msg.replaceAll("\\", "/"), /reaches a sink at lib\/h\.js:3 \(in runIt\(\)\) \(cross-file\)/);
    assert.equal(flows[0].snippet[3 - flows[0].snipStart], '  const seed = "[redacted]";');
    assert.ok(!JSON.stringify(rep).includes(SEED));
    assert.equal(rep.crossFile, 1);
    assert.deepEqual(rep.conditions.at(-1),
      { label: "No cross-file taint flows (JavaScript only: 1 Python file not analyzed)", ok: false });
    assert.equal(rep.pass, false);
    // --no-redact-secrets still works for a project scan
    assert.ok(JSON.stringify(report(["--no-redact-secrets"]).issues.filter((i) => i.rule === "X-CMD")).includes(SEED));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("without Python files the gate label is the Python engine's", () => {
  const d = tree({ "app.js": "const a = 1;\n" });
  try {
    assert.equal(run(["check", d, "-q", "--no-html"], { out: () => {}, err: () => {}, env: {} }), 0);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.conditions.at(-1), { label: "No cross-file taint flows", ok: true });
  } finally { rmSync(d, { recursive: true, force: true }); }
});
