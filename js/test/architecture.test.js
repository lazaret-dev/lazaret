// Architecture rules about the package itself (STRUCTURE.md §5), mirroring
// the Python side's tests/architecture/ folder:
//   1. src/lib/ never imports from src/scanner/  (leaf libraries)
//   2. the public export surface stays importable and stable
//   3. shipped files are inert — nothing executes at import time

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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
    "version", "TAGLINE", "run", "scanFile", "detectLang", "RULES", "TEXT_RULES",
    "SEV_ORDER", "TYPES", "computeMetrics", "worstSevRating", "maintainabilityRating",
    "buildResult", "jsonRenderer", "printReport", "scanManifest", "scanGyp",
    "redactResult", "collectFiles", "reportPaths", "writeReport", "ReportPathError",
    "EXIT_OUTPUT",
  ]) {
    assert.ok(api[name] !== undefined, `index.js must export ${name}`);
  }
});


test("architecture: zero dependencies, shipped files only, Apache-2.0", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.deepEqual(pkg.files, ["bin/", "src/", "README.md", "LICENSE",
    "!**/.*", "!**/*.pem", "!**/*.key", "!**/id_rsa*", "!**/id_ed25519*"]);   // never pack dotfiles (.env*, ._*, .DS_Store) or keys
  assert.equal(pkg.license, "Apache-2.0");
});
