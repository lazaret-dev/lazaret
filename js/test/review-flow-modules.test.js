// The JavaScript cross-file pass follows modules and returned values (twin of
// tests/scanner/test_review_flow_js_modules.py; the two engines are compared
// by tests/architecture/test_js_parity_flow.py). Since 0.1.7 it reads parsed
// trees; it is the engine's pass (rust/crates/lazaret-engine/src/jsflow/,
// through src/scanner/flow.js). A call binds to what its
// file names — a visible definition, else what a relative require() / import
// brings in; where the binding can't be resolved (a package, a path alias,
// `obj.f()`) the call may reach every project function of that name, and
// only positive evidence binds nothing (a Node built-in, a global object's
// member, a built-in method on an unknown receiver, a declared parameter or
// variable). A definite call reads as what its function returns; a project
// function shadows a sanitizer of its name; the fixpoint, the pass's work and
// one function's reading are bounded, each noting itself; a file nested
// deeper than the reader follows is skipped with a note. Inert text only:
// nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { FLOW_OPTIONS, analyzeFlows } from "../src/scanner/flow.js";

const dedent = (s) => {
  const lines = s.replace(/^\n/, "").split("\n");
  const pad = Math.min(...lines.filter((l) => l.trim()).map((l) => l.match(/^ */)[0].length));
  return lines.map((l) => l.slice(pad)).join("\n");
};
const analyze = (files) => analyzeFlows(Object.entries(files).map(([path, c]) => ({ path, content: dedent(c), lang: "js" })));
const flows = (files) => analyze(files).filter((i) => i.rule.startsWith("X-")).map((i) => [i.rule, i.file, i.line]);

const INPUT = `
    function getCmd(req) {
      return req.query.cmd;
    }
    const getName = (req) => req.body.name;
    function getSafe(req) { return escapeHtml(req.query.n); }
    module.exports = { getCmd, getName, getSafe };
    `;

test("a source returned by a helper reaches a sink in another file", () => {
  const got = analyze({ "lib/input.js": INPUT, "app.js": `
    const { getCmd, getName, getSafe } = require('./lib/input');
    app.get('/x', (req, res) => {
      exec(getCmd(req));
      const c = getCmd(req);
      execSync(c);
      el.innerHTML = getName(req);
      el.innerHTML = getSafe(req);
      exec(getSafe(req));
      db.query('SELECT * FROM t WHERE id = ?', [getName(req)]);
      db.query('SELECT * FROM t WHERE id = ' + getName(req));
      exec(Number(getCmd(req)));
      exec(shellQuote(getCmd(req)));
    });
    ` });
  assert.deepEqual(got.map((i) => [i.rule, i.line]), [["X-CMD", 3], ["X-CMD", 5], ["X-XSS", 6], ["X-CMD", 8], ["X-SQL", 10]]);
  assert.equal(got[0].msg, "Possible command injection: untrusted data from lib/input.js:2 (in getCmd()) reaches a sink at app.js:3 (cross-file).");
  assert.match(got[0].why, /the value returned by getCmd\(\)/);
  assert.equal(got[0].snippet[got[0].line - got[0].snipStart], "  exec(getCmd(req));");
});

test("returned parameters carry taint; a clean return clears it", () => {
  const helpers = `
    function runIt(cmd) { exec(cmd); }
    function wrap(x) { return "ls " + x; }
    function yes(x) { log(x); return true; }
    function clean(x) { return Number(x); }
    function escape(x) { return escapeHtml(x); }
    function show(h) { el.innerHTML = h; }
    module.exports = { runIt, wrap, yes, clean, escape, show };
    `;
  assert.deepEqual(flows({ "h.js": helpers, "app.js": `
    const { runIt, wrap, yes, clean, escape, show } = require('./h');
    app.get('/x', (req, res) => {
      const q = req.query.q;
      runIt(wrap(q));
      runIt(yes(q));
      runIt(clean(q));
      const w = wrap(q); runIt(w);
      const v = yes(q); runIt(v);
      show(escape(q));
      runIt(escape(q));
    });
    ` }), [["X-CMD", "app.js", 4], ["X-CMD", "app.js", 7], ["X-CMD", "app.js", 10]]);
});

test("a chain of returns; a return inside a callback is the callback's", () => {
  const got = analyze({
    "a.js": "function inner(req) { return req.query.c; }\nfunction outer(req) { const v = inner(req); return v.trim(); }\n" +
      "function cb(cmd) {\n  run(function () { return cmd; });\n  return 'ok';\n}\nmodule.exports = { outer, cb };\n",
    "app.js": "const { outer, cb } = require('./a');\nexec(outer(req));\nexec(cb(req.query.q));\n",
  });
  assert.deepEqual(got.map((i) => [i.rule, i.line]), [["X-CMD", 2]]);
  assert.match(got[0].msg, /from a\.js:1 \(in inner\(\)\)/);
  assert.match(got[0].why, /the value returned by outer\(\)/);
  // request data read in the sink's own function is the intra-file engine's finding
  assert.deepEqual(flows({ "a.js": "function wrap(x) { return x; }\napp.get('/', (req) => { exec(wrap(req.query.q)); });\n" }), []);
});

test("a call binds to what its file imports; what it can't resolve reaches every namesake", () => {
  assert.deepEqual(flows({
    "safe.js": "function runIt(cmd) { log(cmd); }\nmodule.exports = { runIt };\n",
    "danger.js": "function runIt(cmd) { exec(cmd); }\nmodule.exports = { runIt };\n",
    "a.js": "const { runIt } = require('./safe');\napp.get('/', (req) => { runIt(req.query.q); });\n",
    "b.js": "app.get('/', (req) => { runIt(req.query.q); });\n",
    "c.js": "const { runIt } = require('some-pkg');\napp.get('/', (req) => { runIt(req.query.q); });\n",
    "d.js": "const d = require('./danger');\napp.get('/', (req) => { d.runIt(req.query.q); });\n" +
      "app.get('/', (req) => { obj.runIt(req.query.q); this.runIt(req.query.q); });\n",
    "e.js": "const { runIt } = require('fs');\napp.get('/', (req) => { runIt(req.query.q); });\n",
  }), [["X-CMD", "b.js", 1], ["X-CMD", "c.js", 2], ["X-CMD", "d.js", 2], ["X-CMD", "d.js", 3]]);
});

const LIB = "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\nmodule.exports = { runIt };\n";
const route = (call, head = "") => head + "app.get('/x', (req, res) => {\n  " + call + ";\n});\n";

test("unresolved imports and receivers keep the name-based coverage", () => {
  const hops = { "lib/run.js": LIB, "b1.js": "export * from './lib/run';\n", "app.js": route("runIt(req.query.q)", "import { runIt } from './b5';\n") };
  for (let i = 2; i <= 5; i++) hops[`b${i}.js`] = `export * from './b${i - 1}';\n`;
  const cases = {
    "inline require": { "lib/run.js": LIB, "app.js": route("require('./lib/run').runIt(req.query.q)") },
    "module copied": { "lib/run.js": LIB, "app.js": route("o.runIt(req.query.q)", "const lib = require('./lib/run');\nconst o = lib;\n") },
    "path alias": { "src/lib/run.js": LIB, "src/app.js": route("runIt(req.query.q)", "import { runIt } from '@/lib/run';\n") },
    "workspace package": { "packages/util/index.js": LIB, "packages/web/app.js": route("runIt(req.query.q)", "const { runIt } = require('@acme/util');\n") },
    "five re-export hops": hops,
    "default export called inline": { "run.js": "module.exports = function runIt(cmd) { exec(cmd); };\n", "app.js": route("require('./run')(req.query.q)") },
    "const copy of an import": { "lib.js": LIB, "app.js": route("const go = runIt; go(req.query.q)", "const { runIt } = require('./lib');\n") },
    "this.method": { "h.js": "module.exports = {\n  runIt(cmd) { exec(cmd); },\n  handle(req) { this.runIt(req.query.q); },\n};\nfunction runIt(cmd) { exec(cmd); }\n" },
    "a namesake in another scope": { "h.js": LIB, "app.js": "const { runIt: go } = require('./h');\nfunction unrelated() {\n  function go(x) { log(x); }\n}\n" + route("go(req.query.q)") },
    "module rebound": { "a.js": "function runIt(cmd) { return 'ok'; }\nmodule.exports = { runIt };\n", "b.js": LIB,
      "app.js": route("m.runIt(req.query.q)", "let m = require('./a');\nm = require('./b');\n") },
    "function rebound": { "lib.js": LIB, "app.js": route("tidy(req.query.q)", "const { runIt } = require('./lib');\nfunction tidy(x) { return 'x'; }\ntidy = runIt;\n") },
    "function values": { "lib.js": "function runIt(cmd) {\n  exec(cmd());\n}\nmodule.exports = { runIt };\n", "app.js": route("runIt(x => req.query.q)", "const { runIt } = require('./lib');\n") },
  };
  for (const [label, files] of Object.entries(cases)) {
    assert.deepEqual([...new Set(flows(files).map(([r]) => r))], ["X-CMD"], label);
  }
});

test("positive evidence binds nothing", () => {
  const cases = {
    "JSON.parse": { "lib.js": "function parse(cmd) { exec(cmd); }\nmodule.exports = { parse };\n", "app.js": route("JSON.parse(req.query.q)") },
    "a Node built-in": { "lib.js": "function readFile(p) { exec('cat ' + p); }\nmodule.exports = { readFile };\n",
      "app.js": route("readFile(req.query.q)", "const { readFile } = require('node:fs');\n") },
    "a visible local function": { "lib.js": LIB, "app.js": route("function runIt(x) { log(x); }\n  runIt(req.query.q)") },
    "a parameter": { "lib.js": LIB, "app.js": "function apply(runIt, q) {\n  runIt(q);\n}\n" + route("apply(log, req.query.q)") },
    "a built-in method": { "lib.js": "function replace(s) { exec(s); }\nmodule.exports = { replace };\n",
      "app.js": route("const s = req.query.q; s.replace(/a/g, 'b')") },
  };
  for (const [label, files] of Object.entries(cases)) assert.deepEqual(flows(files), [], label);
});

const H = "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\n";
const hroute = (call, head) => head + "app.get('/x', (req, res) => {\n  " + call + ";\n});\n";

test("a helper's value keeps its arguments unless no return of it can hold them", () => {
  const cases = {
    "copied to a local": "function tidy(x) {\n  const y = x.trim();\n  return y;\n}\n",
    "built with +=": "function tidy(x) {\n  let s = 'ls ';\n  s += x;\n  return s;\n}\n",
    "pushed into an array": "function tidy(x) {\n  const a = [];\n  a.push(x);\n  return a.join(' ');\n}\n",
    "a constructor": "function tidy(x) {\n  this.v = x;\n}\n",
  };
  for (const [label, helper] of Object.entries(cases)) {
    const call = label === "a constructor" ? "const v = new tidy(req.query.q); runIt(v)" : "const v = tidy(req.query.q); runIt(v)";
    assert.deepEqual(flows({ "h.js": H + helper + "module.exports = { runIt, tidy };\n",
      "app.js": hroute(call, "const { runIt, tidy } = require('./h');\n") }), [["X-CMD", "app.js", 3]], label);
  }
  assert.deepEqual(flows({ "h.js": H + "function ok(s) {\n  if (s.length > 3) return true;\n  return false;\n}\nmodule.exports = { runIt, ok };\n",
    "app.js": hroute("const v = ok(req.query.q); runIt(v)", "const { runIt, ok } = require('./h');\n") }), []);
});

test("returned values through closures, compound assignments and ASI", () => {
  const got = analyze({
    "get.js": "function viaClosure(req) {\n  let c;\n  [1].forEach(i => { c = req.query.cmd; });\n  return c;\n}\n" +
      "function viaPlus(req) {\n  let s = 'ls ';\n  s += req.query.cmd;\n  return s;\n}\nmodule.exports = { viaClosure, viaPlus };\n",
    "app.js": "const { viaClosure, viaPlus } = require('./get')\nexec(viaClosure(req))\nexec(viaPlus(req))\n",
  });
  assert.deepEqual(got.map((i) => [i.rule, i.line]), [["X-CMD", 2], ["X-CMD", 3]]);
  assert.deepEqual(flows({ "lib.js": H + "module.exports = { runIt };\n",
    "app.js": "const { runIt } = require('./lib')\napp.get('/x', (req, res) => {\n  let c\n  c = req.query.q\n  runIt(c)\n})\n" }),
  [["X-CMD", "app.js", 5]]);
});

test("a project function shadows a sanitizer name", () => {
  assert.deepEqual(flows({
    "lib.js": "function escapeHtml(s) { return s; }\nfunction show(h) { el.innerHTML = h; }\n" +
      "function getName(req) { return escapeHtml(req.query.n); }\nmodule.exports = { escapeHtml, show, getName };\n",
    "app.js": "const { escapeHtml, show, getName } = require('./lib');\napp.get('/', (req) => {\n  show(escapeHtml(req.query.q));\n});\n" +
      "app.get('/', (req) => {\n  el.innerHTML = getName(req);\n});\n",
  }), [["X-XSS", "app.js", 3], ["X-XSS", "app.js", 6]]);
});

test("ESM: default, namespace, barrels, and ./x.js naming x.ts", () => {
  const got = analyze({
    "src/input.ts": "export function getCmd(req: any): string {\n  return req.query.cmd;\n}\n" +
      "export default function getDef(req) { return req.body.x; }\n",
    "src/index.ts": "export * from './input.js';\nexport { getDef as other } from './input.js';\n",
    "src/app.ts": "import { getCmd } from './input.js';\nimport * as inp from './input';\nimport g from './input';\n" +
      "import { getCmd as gc2, other } from './index';\nimport type { Nothing } from './input';\n" +
      "exec(getCmd(req));\nexec(inp.getCmd(req));\nexec(g(req));\nexec(gc2(req));\nexec(other(req));\n",
  });
  assert.deepEqual(got.map((i) => [i.line, i.msg.split("from ")[1].split(" reaches")[0]]), [
    [6, "src/input.ts:2 (in getCmd())"], [7, "src/input.ts:2 (in getCmd())"], [8, "src/input.ts:4 (in getDef())"],
    [9, "src/input.ts:2 (in getCmd())"], [10, "src/input.ts:4 (in getDef())"]]);
});

test("CommonJS default exports", () => {
  assert.deepEqual(flows({
    "a.js": "module.exports = function getCmd(req) { return req.query.c; };\n",
    "b.js": "function helper(req) { return req.query.c; }\nmodule.exports = helper;\n",
    "c.js": "exports.getIt = function getIt(req) { return req.query.c; };\n",
    "d.js": "module.exports = require('./b');\n",
    "app.js": "const x = require('./a');\nconst y = require('./b');\nconst { getIt } = require('./c');\n" +
      "const z = require('./d');\nexec(x(req));\nexec(y(req));\nexec(getIt(req));\nexec(z(req));\n",
  }), [["X-CMD", "app.js", 5], ["X-CMD", "app.js", 6], ["X-CMD", "app.js", 7], ["X-CMD", "app.js", 8]]);
});

test("a header is not a call; an arrow function spans its expression", () => {
  assert.deepEqual(flows({ "h.js": "const cmd = req.query.c;\nfunction runIt(cmd) { exec(cmd); }\n" }), []);
  assert.deepEqual(flows({ "h.js": "const id = (cmd) => cmd;\nfunction runIt(cmd) { exec(cmd); }\n",
    "app.js": "app.get('/', (req) => { id(req.query.q); runIt(req.query.q); });\n" }), [["X-CMD", "app.js", 1]]);
  assert.deepEqual(flows({ "h.js": "const run = (c) => exec(c);\n",
    "app.js": "app.get('/', (req) => { run(req.query.q); });\n" }), [["X-CMD", "app.js", 1]]);
});

test("TypeScript and rest parameters; nested call arguments", () => {
  assert.deepEqual(flows({
    "h.ts": "function runIt(cmd: string, opts?: object) { exec(cmd); }\nfunction all(...parts) { exec(parts.join(' ')); }\n",
    "app.ts": "app.get('/', (req) => {\n  runIt(req.query.q);\n  all(req.query.q);\n});\n",
  }), [["X-CMD", "app.ts", 2], ["X-CMD", "app.ts", 3]]);
  assert.deepEqual(flows({
    "h.js": "function runIt(cmd) {\n  exec(cmd);\n}\n",
    "app.js": "app.get('/', (req) => {\n  runIt(format(req.query.q));\n  runIt(Number(req.query.q));\n" +
      "  runIt(function () { log(req.query.q); });\n  runIt([req.query.a, 1].join(','));\n});\n",
  }), [["X-CMD", "app.js", 2], ["X-CMD", "app.js", 5]]);
});

test("a name tainted in one function doesn't taint its namesake; closures see their outer variables", () => {
  assert.deepEqual(flows({ "a.js": "function probe() { var result = typeof win.location.href; return 1; }\n" +
    "function make() { var result = compute(); return result; }\nfunction use() { el.innerHTML = make(); }\n" }), []);
  assert.deepEqual(flows({ "a.js": "function getQ() { return req.query.q; }\napp.get('/', function (req, res) {\n" +
    "  const c = getQ();\n  db.run(sql, function (err) { exec(c); });\n});\n" }), [["X-CMD", "a.js", 4]]);
});

test("long chains of returns: callees first; through module variables, the cap notes itself", () => {
  let src = "";
  for (let i = 0; i < 40; i++) src += `function c${i}(a) { return c${i + 1}(a); }\n`;
  assert.deepEqual(flows({ "a.js": src + "function c40(a) { return req.query.q; }\nexec(c0(1));\n" }), [["X-CMD", "a.js", 42]]);
  const chain = (n) => {
    let out = "";
    for (let i = 0; i < n; i++) out += `function c${i}() { return v${i + 1}; }\nvar v${i + 1} = c${i + 1}();\n`;
    return out + `function c${n}() { return req.query.q; }\nexec(c0());\n`;
  };
  assert.deepEqual(flows({ "a.js": chain(40) }), [["X-CMD", "a.js", 82]]);
  const [note, ...rest] = analyze({ "a.js": chain(60) });
  assert.deepEqual([note.rule, note.name, note.sev, rest.length], ["Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)", "INFO", 0]);
  assert.match(note.msg, /did not converge within 50 re-analyses \(first: the module's own code in 'a\.js'\)/);
});

test("the work budget notes itself", () => {
  let src = "";
  for (let i = 0; i < 60; i++) src += `function c${i}() { return v${i + 1}; }\nvar v${i + 1} = c${i + 1}();\n`;
  src += "function c60() { return req.query.q; }\n" + "x = y + z;\n".repeat(6000) + "exec(c0());\n";
  const t = Date.now();
  const got = analyzeFlows([{ path: "a.js", content: src, lang: "js" }]);
  assert.ok(Date.now() - t < 20000);
  assert.deepEqual(got.map((i) => [i.rule, i.name, i.file, i.line]),
    [["Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", "a.js", 1]]);
  assert.match(got[0].msg, /stopped following values at the module's own code in 'a\.js'/);
});

test("one reading's limit notes itself", () => {
  const files = { "lib.js": "function runIt(list) {\n  for (const c of list) {\n    if (c) exec(c);\n  }\n}\nmodule.exports = { runIt };\n",
    "app.js": "const { runIt } = require('./lib');\napp.get('/', (req) => {\n  runIt(req.query.q);\n});\n" };
  assert.deepEqual(flows(files), [["X-CMD", "app.js", 3]]);
  try {
    FLOW_OPTIONS.runLimit = [0, 1];                     // (the engine's limit, lowered)
    const got = analyze(files);
    assert.deepEqual(got.map((i) => [i.rule, i.file, i.line]), [["Q-FLOW-INCOMPLETE", "lib.js", 1]]);
    assert.match(got[0].msg, /stopped reading runIt\(\) in 'lib\.js' at its limit/);
  } finally {
    FLOW_OPTIONS.runLimit = null;
  }
});

test("nesting deeper than the reader follows skips that file", () => {
  const nest = "function pad(a){return g(function(){".repeat(2500) + "}})".repeat(2500) + "\n";
  const got = analyze({ "lib.js": "function runIt(cmd) {\n  exec(cmd);\n}\nmodule.exports = { runIt };\n", "gen.js": nest,
    "app.js": "const { runIt } = require('./lib');\napp.get('/', (req) => {\n  runIt(req.query.q);\n});\n" });
  assert.deepEqual(got.map((i) => [i.rule, i.file, i.line]), [["X-CMD", "app.js", 3], ["Q-FLOW-SKIPPED", "gen.js", 1]]);
  assert.equal(got[1].msg, "Cross-file taint analysis skipped 'gen.js': it could not be read as JavaScript (line 1: nesting too deep).");
});

test("nested code is linear and bounded", () => {
  const cases = {
    returns: "function f(a){return g(function(){".repeat(30000),
    sinks: "function g(req){return req.query.q}\n" + "exec(".repeat(200000) + "g(req)" + ")".repeat(200000) + "\n",
    html: "function g(req){return req.query.q}\n" + "el.innerHTML = (".repeat(100000) + "g(req)" + ")".repeat(100000) + ";\n",
    calls: "function runIt(c){exec(c)}\n" + "runIt(".repeat(200000) + "req.query.q" + ")".repeat(200000) + "\n",
  };
  for (const [label, src] of Object.entries(cases)) {
    const t = Date.now();
    const got = analyzeFlows([{ path: "a.js", content: src, lang: "js" }]);
    assert.ok(Date.now() - t < 20000, label);
    assert.deepEqual(got.map((i) => [i.rule, i.msg.includes("nesting too deep")]), [["Q-FLOW-SKIPPED", true]], label);
  }
});
