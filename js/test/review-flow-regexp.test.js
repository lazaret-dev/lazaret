// A RegExp's exec() is not a command sink (twin of
// tests/scanner/test_review_flow_js_regexp.py; the engines are compared by
// tests/architecture/test_js_parity_flow.py). A call leaves the command sinks
// only when its receiver is proven to be a RegExp — a /…/ literal, `new
// RegExp(…)` / `RegExp(…)` with RegExp never rebound in the file, or a name
// declared once in the file as one and otherwise used only for RegExp members,
// called inside that declaration's block. Every other exec( stays a sink.
// Inert text only: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFlows } from "../src/scanner/flow.js";

const APP = "const { f } = require('./lib');\napp.post('/x', (req, res) => {\n  f(req.query.q);\n});\n";
const lib = (body, head = "") => head + "function f(p) {\n" + body + "\n}\nmodule.exports = { f };\n";
const analyze = (src) => analyzeFlows([{ path: "lib.js", content: src, lang: "js" }, { path: "app.js", content: APP, lang: "js" }]);
const flows = (src) => analyze(src).filter((i) => i.rule.startsWith("X-")).map((i) => [i.rule, i.file, i.line]);

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
    "a property holding a regex": lib("  o.re.exec(p);", "const o = { re: /x/ };\n"),
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

test("a regexp call next to a command in the same function", () => {
  const src = lib("  const m = /^(\\w+)$/.exec(p);\n  cp.exec('ls ' + p);", "const cp = require('child_process');\n");
  assert.deepEqual(flows(src), [["X-CMD", "app.js", 3]]);
  assert.match(analyze(src)[0].msg, /lib\.js:4 \(in f\(\)\)/);
});
