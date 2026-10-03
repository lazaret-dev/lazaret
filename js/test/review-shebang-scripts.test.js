// Scripts with no source extension, read by their #! line (twin of
// python/tests/scanner/test_review_shebang_scripts.py). The walk read only
// files with a source extension, so a package's bin/cli or the ./setup an
// install hook runs was classified by magic bytes and never read. Now a file
// whose #! line names Node (or bun, deno, ts-node, tsx) or Python is scanned
// as JavaScript or Python; shell scripts are not, and a file that is not
// text is still a binary to classify. shebangLang (the native engine's,
// lib/native.js) is core's shebang_lang, scriptSourceLang (lib/fs.js) core's
// script_source_lang.
// Fixtures are inert text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { shebangLang } from "../src/lib/native.js";
import { scriptSourceLang, collectFiles } from "../src/lib/fs.js";

test("the language a #! line names (the first line only)", () => {
  const cases = [
    ["#!/usr/bin/env node\n", "js"], ["#!/usr/bin/node --harmony\n", "js"], ["#!/usr/bin/nodejs", "js"],
    ["#! /usr/bin/env -S deno run --allow-read\n", "js"], ["#!/usr/bin/env bun\n", "js"],
    ["#!/usr/local/bin/ts-node\n", "js"], ["#!/usr/bin/env tsx\r\n", "js"], ["#!/usr/bin/env NODE\n", "js"],
    ["#!/usr/bin/python3.11 -u\n", "py"], ["#!/usr/bin/env python\n", "py"], ["#!/usr/bin/env -S python3 -X dev\n", "py"],
    ["#!/bin/sh\n", "sh"], ["#!/usr/bin/env bash\n", "sh"], ["#!/bin/zsh -f\n", "sh"],
    ["#!/usr/bin/perl -w\n", null], ["#!/usr/bin/env ruby\n", null], ["#!\n", null], ["#!/usr/bin/env\n", null],
    ["#!/usr/bin/env\nnode x\n", null], ["#!\n/usr/bin/node\n", null], ["#!/usr/bin/env \npython\n", null],
    ["", null], ["node\n", null], [" #!/usr/bin/node\n", null], ["\ufeff#!/usr/bin/node\n", null],
  ];
  for (const [text, want] of cases) assert.equal(shebangLang(text), want, JSON.stringify(text));
  const bytes = (s) => Buffer.from(s, "latin1");
  assert.equal(scriptSourceLang(bytes("#!/usr/bin/env node\nx()\n")), "js");
  assert.equal(scriptSourceLang(bytes("#!/usr/bin/python3\n")), "py");
  assert.equal(scriptSourceLang(bytes("#!/bin/sh\nls\n")), null);
  assert.equal(scriptSourceLang(Buffer.concat([bytes("#!/usr/bin/node\n"), Buffer.from([...Array(32).keys()].flatMap((b) => Array(12).fill(b)))])), null);
  assert.equal(scriptSourceLang(bytes("\x7fELF#!/usr/bin/node\n")), null);
  assert.equal(scriptSourceLang(Buffer.alloc(0)), null);
});

const FILES = {
  "index.js": "console.log(1);\n",
  "bin/cli": "#!/usr/bin/env node\nconst cp = require('child_process');\ncp.exec(process.argv[2]);\neval(atob(p));\n",
  "bin/tool": Buffer.from("#!/usr/bin/python3\n# -*- coding: utf-7 -*-\n# harmless +AAo-eval(e)\n", "latin1"),
  "bin/dtool": "#!/usr/bin/env -S deno run\neval(x)\n",
  "bin/run": "#!/bin/sh\neval \"$1\"\n",
  "bin/next-line": "#!/usr/bin/env\nnode\neval(x)\n",
  "bin/blob": Buffer.from([0x23, 0x21, 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15]),
  "node_modules/dep/package.json": JSON.stringify({ name: "dep", version: "1.0.0" }),
  "node_modules/dep/bin/setup": "#!/usr/bin/env node\neval(atob('Y29uc29sZS5sb2coMSk='));\n",
};

function tree() {
  const root = mkdtempSync(join(tmpdir(), "lz-shebang-"));
  for (const [rel, data] of Object.entries(FILES)) {
    const path = join(root, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, data);
  }
  return root;
}

function scan(root, ...extra) {
  const out = mkdtempSync(join(tmpdir(), "lz-shebang-out-"));
  try {
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...extra], { out: () => {}, err: () => {}, env: {} });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
const found = (rep) => new Set(rep.issues.map((i) => `${i.rule} ${i.file.replaceAll("\\", "/")}`));

test("node and python scripts are scanned; shell, a later line and binaries are not", () => {
  const root = tree();
  try {
    const col = collectFiles(root);
    assert.deepEqual(col.files.map((f) => [f.path.replaceAll("\\", "/"), f.lang]).sort(),
      [["bin/cli", "js"], ["bin/dtool", "js"], ["bin/tool", "py"], ["index.js", "js"]]);
    const rep = scan(root);
    const got = found(rep);
    for (const want of ["S-EVAL-JS bin/cli", "SC-EVAL-DECODE bin/cli", "T-CMD bin/cli", "S-EVAL-JS bin/dtool",
      "SC-UTF7 bin/tool", "S-EVAL-PY bin/tool"]) assert.ok(got.has(want), want);
    assert.ok(![...got].some((k) => /bin\/(run|next-line|blob)$/.test(k)), [...got].join("; "));
    assert.equal(rep.metrics.files, 4);
    assert.ok(!got.has("SC-EVAL-DECODE node_modules/dep/bin/setup"));        // pruned without --deps
    const deps = scan(root, "--deps");
    assert.ok(found(deps).has("SC-EVAL-DECODE node_modules/dep/bin/setup"));
    assert.equal(deps.metrics.depFiles, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an oversize script is SC-TRUNCATED", () => {
  const root = tree();
  try {
    writeFileSync(join(root, "bin", "big"), "#!/usr/bin/env node\n" + "var x = 1;\n".repeat(2000));
    const rep = scan(root, "--max-source-bytes", "10000");
    const trunc = rep.issues.filter((i) => i.rule === "SC-TRUNCATED");
    assert.deepEqual(trunc.map((i) => i.file.replaceAll("\\", "/")), ["bin/big"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
