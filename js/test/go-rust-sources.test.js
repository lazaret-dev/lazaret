// S-4: a project's Go and Rust files are read (.go, .rs), as the Python
// package reads them (tests/scanner/test_go_rust_sources.py): their comments
// and literals as each language's lexer reads them, the rules that list the
// two languages (S-SECRET, S-TOKEN, S-BIDI, Q-TODO) and the families every
// text gets. A dependency tree's Go and Rust files are read only in a Go or cargo vendor tree (twin of
// core.DEP_LANGS; test/vendored-code.test.js), and duplication is measured on Python, JavaScript and SQL
// (twin of core.DUP_LANGS). Fake credentials built by concatenation; inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { collectFiles, detectLang, scanFile, computeMetrics } from "../src/index.js";
import { EXTS, DEP_LANGS } from "../src/lib/fs.js";
import { DUP_LANGS } from "../src/scanner/metrics.js";
import { commentSpans } from "../src/lib/lexer.js";

const AWS = "AKIA" + "ABCDEFGHIJKLMNOP";

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-gors-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}

test("the extension tables", () => {
  assert.equal(EXTS[".go"], "go");
  assert.equal(EXTS[".rs"], "rs");
  assert.deepEqual([...DEP_LANGS].sort(), ["js", "py", "sql"]);
  assert.deepEqual([...DUP_LANGS].sort(), ["js", "py", "sql"]);
  assert.equal(detectLang("cmd/main.go", "package main\n"), "go");
  assert.equal(detectLang("src/LIB.RS", "fn main() {}\n"), "rs");
});

test("a project's Go and Rust files are collected; a dependency tree's are not read", () => {
  const d = tree({
    "m.go": "package m\n", "src/lib.rs": "fn f() {}\n",
    "node_modules/dep/package.json": JSON.stringify({ name: "dep", version: "1.0.0" }),
    "node_modules/dep/x.go": `package x\nvar k = "${AWS}"\n`,
  });
  try {
    const col = collectFiles(d, { includeDeps: true });
    assert.deepEqual(col.files.map((f) => [f.path.replaceAll("\\", "/"), f.lang, Boolean(f.dep)]).sort(),
      [["m.go", "go", false], ["src/lib.rs", "rs", false]]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("each language's comments", () => {
  const rs = "let a = 1; /* x /* y */ still */ let b = 'q'; // z\n";
  assert.deepEqual(commentSpans(rs, "rs").map(([s, e]) => rs.slice(s, e)), ["/* x /* y */ still */", "// z"]);
  const go = "s := `/* not a comment */` // yes\nr := '\"'; t := \"// no\"\n";
  assert.deepEqual(commentSpans(go, "go").map(([s, e]) => go.slice(s, e)), ["// yes"]);
});

test("the rules that list Go and Rust, outside comments where they say so", () => {
  const go = `package m\n\nvar password = "hunter22hunter"\n// password = "in a comment"\n// ${AWS}\nvar k = "${AWS}" // nosec\n`;
  const found = scanFile({ path: "m.go", content: go, lang: "go" }).map((i) => [i.rule, i.line]);
  assert.deepEqual(found.sort(), [["S-SECRET", 3], ["S-TOKEN", 5]]);
  const rs = `/* outer /* nested */ let password = "x1y2z3w4"; */\nlet password = "hunter22hunter";\n`;
  assert.deepEqual(scanFile({ path: "l.rs", content: rs }).map((i) => [i.rule, i.line]), [["S-SECRET", 2]]);
});

test("duplication is measured on Python, JavaScript and SQL lines", () => {
  let block = "";
  for (let k = 0; k < 8; k++) block += `    let v${k} = compute(${k}, "step ${k}");\n`;
  const rs = [{ path: "a.rs", lang: "rs", content: "fn a() {\n" + block + "}\n" },
    { path: "b.rs", lang: "rs", content: "fn b() {\n" + block + "}\n" }];
  let m = computeMetrics(rs);
  assert.deepEqual([m.ncloc, m.dupPct], [20, 0]);
  let py = "";
  for (let k = 0; k < 8; k++) py += `v${k} = compute(${k}, 'step ${k}')\n`;
  m = computeMetrics([...rs, { path: "a.py", lang: "py", content: py }, { path: "b.py", lang: "py", content: py }]);
  assert.deepEqual([m.ncloc, m.dupPct], [36, 100]);
  // (a file given without its language is measured, as before)
  m = computeMetrics([{ path: "a", content: py }, { path: "b", content: py }]);
  assert.equal(m.dupPct, 100);
});
