// Layering (STRUCTURE.md, section 5) and ship policy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("src/lib never imports src/scanner", () => {
  const libDir = join(ROOT, "src", "lib");
  for (const f of readdirSync(libDir).filter((n) => n.endsWith(".js"))) {
    const src = readFileSync(join(libDir, f), "utf8");
    assert.doesNotMatch(src, /from\s+["']\.\.\/scanner\//, `${f} imports the scanner`);
  }
});

test("zero dependencies, shipped files only, Apache-2.0", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.deepEqual(pkg.files, ["bin/", "src/", "README.md", "LICENSE"]);
  assert.equal(pkg.license, "Apache-2.0");
});
