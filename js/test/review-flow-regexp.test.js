// A RegExp's exec() is not a command sink (twin of
// tests/scanner/test_review_flow_js_regexp.py; the engines are compared by
// tests/architecture/test_js_parity_flow.py). A call leaves the command sinks
// only when its receiver is proven to be a RegExp — a /…/ literal, `new
// RegExp(…)` / `RegExp(…)` with RegExp never rebound in the file, or a name
// declared once in the file as one and otherwise used only for RegExp members,
// called inside that declaration's block; or (0.1.9) a property of a variable
// of the file whose every definition there is a regex (convert-source-map's
// `exports.commentRegex` getter, vite's CRITICAL X-CMD). Every other exec( stays
// a sink. Inert text only: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFlows } from "../src/scanner/flow.js";

const APP = "const { f } = require('./lib');\napp.post('/x', (req, res) => {\n  f(req.query.q);\n});\n";
const lib = (body, head = "") => head + "function f(p) {\n" + body + "\n}\nmodule.exports = { f };\n";
const analyze = (src) => analyzeFlows([{ path: "lib.js", content: src, lang: "js" }, { path: "app.js", content: APP, lang: "js" }]);
const flows = (src) => {
  const out = analyze(src);
  // a pass that failed reports no flow: never an answer here
  assert.deepEqual(out.filter((i) => i.rule === "Q-FLOW-INCOMPLETE"), [], "the pass did not finish");
  return out.filter((i) => i.rule.startsWith("X-")).map((i) => [i.rule, i.file, i.line]);
};

test("a RegExp's exec runs no command", () => {
  const cases = {
    "a literal": lib("  return /^(\\w+)=(.*)$/.exec(p);"),
    "a literal with flags": lib("  return /x/gi.exec(p);"),
    "a literal, exec on the next line": lib("  return /^(\\w+)$/\n    .exec(p);"),
    "a module const": lib("  return RE.exec(p);", "const RE = /^([^:]*):(.*)$/;\n"),
    "a const in the function": lib("  const re = /a(b)/;\n  const m = re.exec(p);\n  return m;"),
    "a module var (basic-auth)": lib("  var m = CRED.exec(p)\n  return m", "var CRED = /^ *(?:[Bb]asic) +(\\S+) *$/\n"),
    "a let in a block": lib("  if (p) {\n    let re = /x/;\n    return re.exec(p);\n  }"),
    "new RegExp(…)": lib("  return new RegExp('^a').exec(p);"),
    "RegExp(…)": lib("  return RegExp('^a').exec(p);"),
    "a const new RegExp": lib("  return re.exec(p);", "const re = new RegExp('^' + prefix, 'i');\n"),
    "lastIndex, test and source": lib("  RE.lastIndex = 0;\n  let m;\n  while ((m = RE.exec(p))) {}\n  return RE.test(p) && RE.source;",
      "const RE = /x/g;\n"),
    "a TypeScript annotation": lib("  return re.exec(p);", "const re: RegExp = /x/;\n"),
    "instanceof RegExp": lib("  if (p instanceof RegExp) return 1;\n  return new RegExp('x').exec(p);"),
    "no semicolon": lib("  const re = /x/\n  return re.exec(p)"),
  };
  for (const [label, src] of Object.entries(cases)) assert.deepEqual(flows(src), [], label);
});

test("every other exec stays a sink", () => {
  const cp = "const cp = require('child_process');\n";
  const cases = {
    child_process: lib("  cp.exec(p);", cp),
    "a destructured exec": lib("  exec('ls ' + p);", "const { exec } = require('child_process');\n"),
    shelljs: lib("  shell.exec('ls ' + p);", "const shell = require('shelljs');\n"),
    "an inline require": lib("  require('child_process').exec(p);"),
    "a call's result": lib("  getRunner().exec(p);"),
    "this.re": lib("  this.re.exec(p);"),
    "optional chaining": lib("  re?.exec(p);", "const re = /x/;\n"),
    reassigned: lib("  re.exec(p);", "let re = /x/;\nre = require('child_process');\n"),
    "redeclared in the function": lib("  const re = require('child_process');\n  re.exec(p);", "const re = /x/;\n"),
    "redeclared in a block": lib("  const re = /x/;\n  {\n    const re = require('child_process');\n    re.exec(p);\n  }"),
    "a parameter of that name": "const re = /x/;\nfunction f(p, re) {\n  re.exec(p);\n}\nmodule.exports = { f };\n",
    "an arrow parameter": lib("  [cp].forEach(re => re.exec(p));", "const re = /x/;\n" + cp),
    "a catch parameter": lib("  try { throw cp; } catch (re) { re.exec(p); }", "const re = /x/;\n" + cp),
    "a destructuring assignment": lib("  re.exec(p);", "let re = /x/;\n[re] = [require('child_process')];\n"),
    "passed to a function": lib("  re.exec(p);", "const re = /x/;\npatch(re);\n"),
    "exec assigned on it": lib("  re.exec(p);", "const re = /x/;\nre.exec = require('child_process').exec;\n"),
    "RegExp.prototype patched": lib("  return /x/.exec(p);", "RegExp.prototype.exec = function (c) { return run(c); };\n"),
    "a with statement": lib("  with (env) { re.exec(p); }", "const re = /x/;\n"),
    "a direct eval": lib("  eval(code);\n  re.exec(p);", "const re = /x/;\n"),
    "RegExp redefined": lib("  new RegExp('x').exec(p);", "const RegExp = function () { return require('child_process'); };\n"),
    "the global RegExp replaced": lib("  new RegExp('x').exec(p);", "globalThis.RegExp = function () { return require('child_process'); };\n"),
    "declared in another function": "function g() {\n  const re = /x/;\n}\n" + lib("  re.exec(p);"),
    "a value that goes on": lib("  re.exec(p);", "const re = /x/ && require('child_process');\n"),
    "a second declarator": lib("  re.exec(p);", "let a = 1, re = require('child_process');\n"),
    "var redeclared elsewhere": "var re = /x/;\nfunction f(p) {\n  var re = require('child_process');\n  re.exec(p);\n}\nmodule.exports = { f };\n",
  };
  for (const [label, src] of Object.entries(cases)) assert.deepEqual(flows(src).map(([r]) => r), ["X-CMD"], label);
});

// RUN stands for exec, so that Lazaret's scan of its own sources does not read these strings as calls
const run = (src) => flows(src.replaceAll("RUN", "exec"));

test("a property that holds only a regex", () => {
  const cases = {
    "an object literal": lib("  return o.re.RUN(p);", "const o = { re: /x/ };\n"),
    assigned: lib("  return o.re.RUN(p);", "const o = {};\no.re = new RegExp('^a', 'g');\n"),
    "a getter": lib("  return o.re.RUN(p);", "const o = {};\nObject.defineProperty(o, 're', { get() { return /x/g; } });\n"),
    "an arrow getter, other keys": lib("  return o.re.RUN(p);", "const o = {};\nObject.defineProperty(o, 're', "
      + "{ enumerable: true, get: () => /x/ });\nObject.defineProperty(o, 'n', { value: 2 });\n"),
    "a value": lib("  return o.re.RUN(p);", "let o = {};\nObject.defineProperty(o, 're', { value: /x/ });\n"),
    "a parameter's": "function f(p) {\n  return g(p, {});\n}\nfunction g(p, o) {\n  o.re = /x/;\n  o.other = p;\n"
      + "  return o.re.RUN(p);\n}\nmodule.exports = { f };\n",
    "convert-source-map's exports.commentRegex": "const conv = {};\n((exports) => {\n"
      + "  Object.defineProperty(exports, 'commentRegex', { get: function getCommentRegex() {\n"
      + "    return /^\\s*?\\/[\\/\\*][@#]\\s+?sourceMappingURL=data:(.*?)$/mg;\n  } });\n"
      + "  exports.fromComment = function (c) {\n    const m = exports.commentRegex.RUN(c);\n    return m;\n  };\n})(conv);\n"
      + "function f(p) {\n  return conv.fromComment(p);\n}\nmodule.exports = { f };\n",
  };
  for (const [label, src] of Object.entries(cases)) assert.deepEqual(run(src), [], label);
});

test("a property that may hold something else", () => {
  const cp = "require('child_' + 'process')";
  const cases = {
    "also assigned something else": lib("  o.re.RUN(p);", `const o = { re: /x/ };\no.re = ${cp};\n`),
    "assigned with another operator": lib("  o.re.RUN(p);", `const o = { re: /x/ };\no.re ||= ${cp};\n`),
    "written by a computed key": lib("  o.re.RUN(p);", `const o = { re: /x/ };\no[k] = ${cp};\n`),
    "an object passed on": lib("  o.re.RUN(p);", "const o = { re: /x/ };\npatch(o);\n"),
    "Object.assign onto it": lib("  o.re.RUN(p);", "const o = { re: /x/ };\nObject.assign(o, mods);\n"),
    aliased: lib("  o.re.RUN(p);", `const o = { re: /x/ };\nconst o2 = o;\no2.re = ${cp};\n`),
    "a getter that returns something else": lib("  o.re.RUN(p);", `const o = {};\nObject.defineProperty(o, 're', { get() { return ${cp}; } });\n`),
    "a getter that does more": lib("  o.re.RUN(p);", "const o = {};\nObject.defineProperty(o, 're', { get() { log(); return /x/; } });\n"),
    "a name not written out": lib("  o.re.RUN(p);", "const o = {};\nObject.defineProperty(o, name, { value: /x/ });\n"),
    "a spread in the literal": lib("  o.re.RUN(p);", "const o = { re: /x/, ...base };\n"),
    "an object from elsewhere": lib("  o.re.RUN(p);", "const o = require('./conf');\no.re = /x/;\n"),
    "never defined": lib("  o.re.RUN(p);", "const o = {};\n"),
    "a member of a member": lib("  a.o.re.RUN(p);", "const a = { o: { re: /x/ } };\n"),
    "this.re": lib("  this.re = /x/;\n  this.re.RUN(p);"),
  };
  for (const [label, src] of Object.entries(cases)) assert.deepEqual(run(src).map(([r]) => r), ["X-CMD"], label);
});

test("a regexp call next to a command in the same function", () => {
  const src = lib("  const m = /^(\\w+)$/.exec(p);\n  cp.exec('ls ' + p);", "const cp = require('child_process');\n");
  assert.deepEqual(flows(src), [["X-CMD", "app.js", 3]]);
  assert.match(analyze(src)[0].msg, /lib\.js:4 \(in f\(\)\)/);
});
