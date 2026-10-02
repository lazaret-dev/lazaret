// Review B3 (adversarial analysis): V8's backtracking regex engine keeps one
// stack entry per repetition of an alternation (and of a class repeated
// {N,} times, N > 2), so a single line of a few million characters threw
// "Maximum call stack size exceeded". In the scan, the file's findings were
// dropped for an INFO Q-SCAN-ERROR note and the gate PASSED (a 6.5 MB base64
// string next to eval(atob(…)) and execSync(…) hid both); in the metrics,
// the whole run died (exit 5). The 16,000,000-byte source limit (0.1.1) let
// such files through; at 2,000,000 they were SC-TRUNCATED. Now:
//   * the comment lexer is the native engine's (lex_comment_spans), which
//     reads a literal without a regular expression;
//   * pyRe writes a class repeated {N,} times as {N} then *;
//   * a file whose scan still throws is SC-TRUNCATED (CRITICAL; the gate
//     fails), and the metrics count its lines as code instead of dying.
// The native engine is the reference for findings.
// All payloads are inert text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, scanFile, scanManifest } from "../src/index.js";
import { pyRe } from "../src/lib/pycompat.js";

test("pyRe writes a class repeated {N,} times as {N} then *: same matches, no overflow", () => {
  assert.equal(pyRe("[ab]{20,}c").source, "[ab]{20}[ab]*c");
  assert.equal(pyRe(String.raw`\d{3,}?x`).source, String.raw`\p{Nd}{3}\p{Nd}*?x`);
  assert.equal(pyRe("a{3,}").source, "a{3,}");                        // a literal: left as written
  for (const [py, js] of [["[ab]{3,}c", "[ab]{3,}c"], ["[ab]{2,}?b", "[ab]{2,}?b"], [".{3,}b", "[^\\n]{3,}b"]]) {
    const fast = pyRe(py, "g"), ref = new RegExp(js, "gu");
    for (const s of ["", "abc", "aaab", "ababababc", "ab\nabab", "cabbbbc", "aaaaaaaaaaab", "bbb"])
      assert.deepEqual([...s.matchAll(fast)].map((m) => [m.index, m[0]]), [...s.matchAll(ref)].map((m) => [m.index, m[0]]), `${py} on ${s}`);
  }
  const blob = '"' + "QUJD".repeat(4_000_000) + '"';
  assert.doesNotThrow(() => pyRe(String.raw`[\"'][A-Za-z0-9+/]{200,}={0,2}[\"']`).exec(blob));
});

// a hostile file: its dangerous lines, then one huge line
const HEAD = 'const cp = require("child_process");\neval(atob("ZWNobyBoaQ=="));\n';
function scanRules(content, lang = "js") {
  return new Set(scanFile({ path: "f." + lang, content, lang }).map((i) => i.rule));
}

test("a file with a huge string or blob line keeps its findings", () => {
  const cases = [
    ["js", HEAD + 'const s = "' + "QUJD".repeat(1_700_000) + '";\n'],               // 6.8 MB base64
    ["js", HEAD + "const s = '" + "a b ".repeat(2_300_000) + "';\n"],               // 9.2 MB string
    ["js", HEAD + "var x = 1;\n".repeat(1000) + "const s = `" + "z".repeat(9_000_000) + "`;\n"],
    ["py", 'import os\neval(input())\nx = """' + "a".repeat(9_000_000) + '"""\n'],
    ["sql", "EXEC xp_cmdshell 'dir';\nSELECT '" + "a".repeat(9_000_000) + "';\n"],
  ];
  const want = { js: ["S-EVAL-JS", "SC-EVAL-DECODE"], py: ["S-EVAL-PY"], sql: ["SQL-XPCMD"] };
  for (const [lang, content] of cases) {
    const rules = scanRules(content, lang);
    for (const r of want[lang]) assert.ok(rules.has(r), `${lang}: ${r} in ${[...rules]}`);
  }
});

test("a file whose scan throws is SC-TRUNCATED, fails the gate, and the report is still written", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-b3-"));
  const exec = RegExp.prototype.exec;
  RegExp.prototype.exec = function (s) {              // lexing this one file overflows, as in the review
    if (typeof s === "string" && s.includes("B3-OVERFLOW") && new Error().stack.includes("commentSpans"))
      throw new RangeError("Maximum call stack size exceeded");
    return exec.call(this, s);
  };
  try {
    mkdirSync(join(d, "src"));
    writeFileSync(join(d, "src", "evil.js"), HEAD + "// B3-OVERFLOW\n");
    writeFileSync(join(d, "src", "ok.js"), "eval(x);\n");
    const code = run(["check", d, "--no-html", "--ci", "--quiet"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    const evil = rep.issues.filter((i) => i.file.replaceAll("\\", "/") === "src/evil.js");
    assert.deepEqual(evil.map((i) => [i.rule, i.sev, i.msg]), [["SC-TRUNCATED", "CRITICAL",
      "File not fully scanned: its scan failed (RangeError), so its findings are missing."]]);
    assert.ok(rep.issues.some((i) => i.rule === "S-EVAL-JS" && i.file.endsWith("ok.js")));   // the rest was scanned
    assert.equal(rep.pass, false);
    assert.equal(code, 1);
    assert.ok(rep.metrics.ncloc >= 4);                 // the metrics counted it as code instead of dying
  } finally {
    RegExp.prototype.exec = exec;
    rmSync(d, { recursive: true, force: true });
  }
});

test("a manifest with a string of millions of characters: its hook is found at its key", () => {
  const text = `{\n  "name": "x",\n  "scripts": {\n    "postinstall": ${JSON.stringify("node x.js ".repeat(900_000))}\n  }\n}\n`;
  const found = scanManifest("package.json", text, { registry: true });
  assert.deepEqual(found.map((i) => [i.rule, i.line]), [["SC-INSTALL-HOOK", 4]]);
});
