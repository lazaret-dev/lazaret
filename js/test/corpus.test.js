import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, relative, resolve, sep } from "node:path";

// Corpus test against the private lazaret-samples repo (STRUCTURE.md, section 6).
// The samples contain offensive fixtures (real typosquat names,
// working-looking install hooks) and live OUTSIDE the public repo, so
// scanners watching this repo never see them.
//
// Enable with: LAZARET_SAMPLES_DIR=../lazaret-samples npm test
// The first test (fixtures policy) always runs; the checkout tests are
// skipped automatically when LAZARET_SAMPLES_DIR is unset.

const SAMPLES_DIR = process.env.LAZARET_SAMPLES_DIR;
const fixturesDir = fileURLToPath(new URL("./fixtures", import.meta.url));

function exists(p) {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

function walk(dir) {
  let out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    out = statSync(full).isDirectory() ? out.concat(walk(full)) : [...out, full];
  }
  return out;
}

test("fixtures policy: the public repo ships only inert, data-only fixtures", () => {
  // test/fixtures/ may hold .json/.txt/.md only (STRUCTURE.md §5): nothing
  // executable, so nothing an automated scanner could treat as a live
  // payload. Anything offensive belongs in the private lazaret-samples repo.
  if (!exists(fixturesDir)) return; // empty is fine
  const ALLOWED = [".json", ".txt", ".md"];
  for (const path of walk(fixturesDir)) {
    assert.ok(ALLOWED.includes(path.slice(path.lastIndexOf("."))),
      `${path}: not an allowed inert fixture type (${ALLOWED.join("/")})`);
    if (path.endsWith(".json")) {
      assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")), `${path}: unparseable JSON`);
    }
  }
});

// --- corpus tests (env-gated) ------------------------------------------
// manifest.json is shared with the Python engine's corpus test
// (python/tests/scanner/test_detection_corpus.py): JSON rather than TOML,
// because neither Node nor Python 3.10 can read TOML without a dependency.

const gated = { skip: !SAMPLES_DIR && "LAZARET_SAMPLES_DIR not set" };
const REQUIRED = ["id", "path", "sha256", "lang", "category", "source", "defanged", "expect"];
const CATEGORIES = new Set(["typosquat", "install-hook", "obfuscation", "secrets",
                            "taint-sql", "taint-command", "exfiltration"]);

function loadManifest() {
  return JSON.parse(readFileSync(join(SAMPLES_DIR, "manifest.json"), "utf8")).samples;
}

test("corpus: checkout is a lazaret-samples repo", gated, () => {
  assert.ok(exists(join(SAMPLES_DIR, "manifest.json")), "expected manifest.json at the samples root");
  const readme = readFileSync(join(SAMPLES_DIR, "README.md"), "utf8");
  assert.match(readme, /lazaret-samples/);
});

test("corpus: samples checkout matches its manifest", gated, () => {
  const entries = loadManifest();
  assert.ok(entries.length >= 1, "manifest lists no samples");
  const root = resolve(SAMPLES_DIR);
  const seen = new Set();
  for (const e of entries) {
    for (const key of REQUIRED) assert.ok(e[key] !== undefined, `${e.id ?? e.path ?? "?"}: missing ${key}`);
    assert.ok(CATEGORIES.has(e.category), `${e.id}: unknown category ${e.category}`);
    assert.equal(e.defanged, true, `${e.id}: every sample must be defanged`);
    const full = resolve(root, e.path);
    assert.ok(full.startsWith(root + sep), `${e.id}: path escapes the samples checkout`);
    const digest = createHash("sha256").update(readFileSync(full)).digest("hex");
    assert.equal(digest, e.sha256, `${e.id}: sha256 mismatch`);
    seen.add(relative(root, full).split(sep).join("/"));
  }
  const onDisk = ["synthetic", "real"].map((d) => join(root, d)).filter(exists).flatMap(walk)
    .map((p) => relative(root, p).split(sep).join("/"))
    .filter((p) => !/(^|\/)(\.gitkeep|README[^/]*)$/.test(p));
  assert.deepEqual(onDisk.filter((p) => !seen.has(p)), [], "samples on disk but not in manifest.json");
});

test("corpus: every sample is detected by the JS engine", gated, async () => {
  const { scanFile } = await import("../src/scanner/scan.js");
  for (const e of loadManifest().filter((x) => ["py", "js", "sql"].includes(x.lang))) {
    const content = readFileSync(join(SAMPLES_DIR, e.path), "utf8");
    const found = new Set(scanFile({ name: e.path, path: e.path, content, lang: e.lang }).map((i) => i.rule));
    const missing = e.expect.filter((rule) => !found.has(rule));
    assert.deepEqual(missing, [], `${e.id}: not flagged for ${missing.join(", ")}`);
  }
});
