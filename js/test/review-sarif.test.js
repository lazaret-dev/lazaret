// Review regression: --sarif (review finding 3). The document matches the
// Python engine's SARIF writer byte-for-byte in structure: provenance
// marker first, %SRCROOT% base URI, percent-encoded artifact URIs, ruleIndex,
// the package version and https://lazaret.dev as informationUri.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { run, version } from "../src/index.js";

test("SARIF 2.1.0 report: tool identity, %SRCROOT%, encoded URIs, ruleIndex", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret sarif "));
  const out = mkdtempSync(join(tmpdir(), "lazaret-sarif-out-"));
  try {
    mkdirSync(join(d, "sub dir"));
    writeFileSync(join(d, "sub dir", "a b%.js"), "eval(y)\n");
    writeFileSync(join(d, "café.py"), "eval(x)\n");
    writeFileSync(join(d, "t.py"), "x = 1  # TODO\n");
    const code = run(["check", d, "--no-html", "--no-json", "--sarif", join(out, "r.sarif"), "-q"],
      { out: () => {}, err: () => {}, env: {} });
    assert.equal(code, 0);
    const text = readFileSync(join(out, "r.sarif"), "utf8");
    const s = JSON.parse(text);
    assert.deepEqual(Object.keys(s), ["properties", "$schema", "version", "runs"]);
    assert.deepEqual(s.properties, { generatedBy: "lazaret-cli-1" });       // provenance marker first
    assert.equal(s.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
    assert.equal(s.version, "2.1.0");
    const [runObj] = s.runs;
    assert.deepEqual([runObj.tool.driver.name, runObj.tool.driver.version, runObj.tool.driver.informationUri],
      ["Lazaret", version, "https://lazaret.dev"]);
    let base = pathToFileURL(d).href;
    if (!base.endsWith("/")) base += "/";
    assert.equal(runObj.originalUriBaseIds["%SRCROOT%"].uri, base);
    const rules = runObj.tool.driver.rules.map((r) => r.id);
    const got = runObj.results.map((r) => {
      const loc = r.locations[0].physicalLocation;
      assert.equal(loc.artifactLocation.uriBaseId, "%SRCROOT%");
      assert.equal(rules[r.ruleIndex], r.ruleId);
      return [r.ruleId, r.level, loc.artifactLocation.uri, loc.region.startLine];
    });
    assert.deepEqual(got, [
      ["S-EVAL-PY", "error", "caf%C3%A9.py", 1],
      ["S-EVAL-JS", "error", "sub%20dir/a%20b%25.js", 1],
      ["Q-TODO", "note", "t.py", 1],
    ]);
    // re-running over our own SARIF file is allowed (it carries the marker)
    assert.equal(run(["check", d, "--no-html", "--no-json", "--sarif", join(out, "r.sarif"), "-q"],
      { out: () => {}, err: () => {}, env: {} }), 0);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
