// Architecture rules about the package itself (STRUCTURE.md §5), mirroring
// the Python side's tests/architecture/ folder:
//   1. src/lib/ never imports from src/scanner/  (leaf libraries)
//   2. the public export surface stays importable and stable
//   3. shipped files are inert — nothing executes at import time
//   4. the native engine (native/lazaret.wasm) is a module that imports
//      nothing: it reads the text it is handed and answers, no host access

import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { available, loadError } from "../src/lib/native.js";

const PKG_ROOT = fileURLToPath(new URL("..", import.meta.url));
const SRC = join(PKG_ROOT, "src");

function walk(dir) {
  let out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    out = statSync(full).isDirectory() ? out.concat(walk(full)) : [...out, full];
  }
  return out;
}

const importRe = /(?:^|\n)\s*(?:import\s[^;]*?from\s*|export\s[^;]*?from\s*)(["'])([^"']+)\1/g;

test("architecture: src/lib/** imports nothing from src/scanner/", () => {
  // lib is a zero-dependency leaf layer; the scanner may depend on it, never
  // the other way around (STRUCTURE.md §5). Regression guard for the
  // supplychain.js → engine.js violation found in integration.
  const violations = [];
  for (const path of walk(join(SRC, "lib"))) {
    if (!path.endsWith(".js")) continue;
    const text = readFileSync(path, "utf8");
    let m;
    while ((m = importRe.exec(text))) {
      const spec = m[2];
      const rel = spec.startsWith(".") ? join(dirname(path), spec) : spec;
      if (rel.includes(join(SRC, "scanner"))) {
        violations.push(`${path.replace(PKG_ROOT, "")} imports ${spec}`);
      }
    }
  }
  assert.deepEqual(violations, []);
});

test("architecture: scanner may import lib (allowed direction), all modules resolve", async () => {
  // Import every source module once: catches broken re-export chains and
  // module cycles that only blow up at runtime, not at analysis time.
  for (const path of walk(SRC)) {
    if (!path.endsWith(".js") || path.endsWith("cli.js")) continue;
    await assert.doesNotReject(
      import(pathToFileURL(path).href),   // a bare "D:\\..." path is not an import specifier on Windows
      `${path} failed to import`,
    );
  }
});

test("architecture: public export surface (index.js) is importable and has the contract members", async () => {
  const api = await import(pathToFileURL(join(SRC, "index.js")).href);
  for (const name of [
    "version", "TAGLINE", "run", "scanFile", "detectLang",
    "SEV_ORDER", "TYPES", "computeMetrics", "worstSevRating", "maintainabilityRating",
    "buildResult", "jsonRenderer", "printReport", "scanManifest", "scanGyp",
    "redactResult", "collectFiles", "reportPaths", "writeReport", "ReportPathError",
    "EXIT_OUTPUT",
  ]) {
    assert.ok(api[name] !== undefined, `index.js must export ${name}`);
  }
});


test("architecture: zero dependencies, shipped files only, its licenses", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  // nothing runs when the package is installed (no preinstall, install, postinstall or prepare): `build` and
  // `test` are run by hand, and `prepack` only when a maintainer packs or publishes from a checkout
  assert.deepEqual(pkg.scripts, { build: "node scripts/build-wasm.js", prepack: "node scripts/build-wasm.js --check",
    test: "node --test" });
  assert.deepEqual(pkg.files, ["bin/", "src/", "native/lazaret.wasm", "native/NOTICE", "README.md", "LICENSE",
    "LICENSE-PYTHON", "LICENSE-UNICODE", "NOTICE",
    "!**/.*", "!**/*.pem", "!**/*.key", "!**/id_rsa*", "!**/id_ed25519*"]);   // never pack dotfiles (.env*, ._*, .DS_Store) or keys
  // the native engine (native/lazaret.wasm, its notices in native/NOTICE) holds translations of CPython code (shlex,
  // the Final_Sigma rule, re's case equivalences) and Unicode 13.0 data, and lib/unicode13.js and lib/codecs.js hold Unicode data (NOTICE):
  // the package carries both licenses and declares them
  assert.equal(pkg.license, "Apache-2.0 AND Python-2.0.1 AND Unicode-3.0");
});

test("architecture: the native engine imports nothing from its host", () => {
  const bytes = readFileSync(new URL("../native/lazaret.wasm", import.meta.url));
  const mod = new WebAssembly.Module(bytes);
  assert.deepEqual(WebAssembly.Module.imports(mod), []);
  const exports = WebAssembly.Module.exports(mod).map((e) => `${e.kind} ${e.name}`).sort();
  for (const want of ["function lazaret_alloc", "function lazaret_call", "function lazaret_free", "memory memory"]) {
    assert.ok(exports.includes(want), want);
  }
});

test("architecture: the native engine loads; without it the CLI says what is missing", () => {
  assert.equal(loadError(), null);
  assert.equal(available(), true);
  // a copy of the package without native/ (a checkout without `npm run build`): exit 2, before any scan
  const tmp = mkdtempSync(join(tmpdir(), "lazaret-nowasm-"));
  try {
    for (const name of ["bin", "src"]) cpSync(join(PKG_ROOT, name), join(tmp, name), { recursive: true });
    cpSync(join(PKG_ROOT, "package.json"), join(tmp, "package.json"));
    mkdirSync(join(tmp, "project"));
    writeFileSync(join(tmp, "project", "a.js"), "eval(x);\n");
    const p = spawnSync(process.execPath, [join(tmp, "bin", "lazaret.js"), join(tmp, "project"), "--no-json", "--no-html"],
      { encoding: "utf8", timeout: 20000 });
    assert.equal(p.status, 2, p.stderr);
    assert.match(p.stderr, /^error: the native engine is missing \(.*lazaret\.wasm: ENOENT\); build it with `npm run build`/);
    assert.equal(p.stdout, "");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
