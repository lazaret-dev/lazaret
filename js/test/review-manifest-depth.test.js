// Review follow-up: the manifest nesting limit is explicit and shared. Both
// engines measure a manifest's depth (brackets outside JSON strings) before
// parsing it and report SC-MANIFEST-DEPTH above MAX_JSON_DEPTH = 500
// (core.MAX_MANIFEST_DEPTH), with the same message. The Python engine used
// to depend on its interpreter's recursion limit (~995 levels on 3.10/3.11,
// ~10,000 on 3.12+), so depths in between disagreed. Inert text only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanManifest, scanGyp } from "../src/index.js";
import { loadManifest, MANIFEST_DEPTH_MSG } from "../src/lib/supplychain.js";
import { MAX_JSON_DEPTH, jsonDepthExceeds } from "../src/lib/pycompat.js";

const nested = (depth) => '{"name": "x", "a": ' + "[".repeat(depth - 1) + "]".repeat(depth - 1) + "}";
const rules = (issues) => issues.map((i) => i.rule);

test("the limit is 500 and the message names it", () => {
  assert.equal(MAX_JSON_DEPTH, 500);
  assert.equal(MANIFEST_DEPTH_MSG, "Manifest is too deeply nested to parse (more than 500 levels).");
});

test("500 levels parse; 501, 700 and deeper are SC-MANIFEST-DEPTH", () => {
  const [data, issues] = loadManifest("package.json", nested(500));
  assert.equal(data.name, "x");
  assert.deepEqual(issues, []);
  for (const depth of [501, 700, 2000, 12000]) {
    const [d, found] = loadManifest("package.json", nested(depth));
    assert.equal(d, null);
    assert.deepEqual(found.map((i) => [i.rule, i.sev, i.line, i.msg]),
      [["SC-MANIFEST-DEPTH", "CRITICAL", 1, MANIFEST_DEPTH_MSG]]);
  }
  assert.deepEqual(rules(scanManifest("sub/package.json", nested(700))), ["SC-MANIFEST-DEPTH"]);
  assert.deepEqual(rules(scanManifest("node_modules/x/package.json", nested(700))), ["SC-MANIFEST-DEPTH"]);
  assert.deepEqual(rules(scanGyp("binding.gyp", nested(700))), ["SC-MANIFEST-DEPTH"]);
});

test("brackets inside strings do not count; a syntax error does not hide the depth", () => {
  const text = JSON.stringify({ name: "x", description: "[".repeat(1000) + "{".repeat(1000), note: '"' + "[".repeat(800) });
  assert.deepEqual(loadManifest("package.json", text)[1], []);
  const late = '{"a": x, "b": ' + "[".repeat(700) + "]".repeat(700) + "}";
  assert.deepEqual(rules(scanManifest("package.json", late)), ["SC-MANIFEST-DEPTH"]);
});

test("jsonDepthExceeds (same cases as core.json_depth_exceeds)", () => {
  assert.equal(jsonDepthExceeds("[".repeat(500)), false);
  assert.equal(jsonDepthExceeds("[".repeat(501)), true);
  assert.equal(jsonDepthExceeds("{".repeat(250) + "[".repeat(251)), true);
  assert.equal(jsonDepthExceeds('"' + "[".repeat(1000)), false);
  assert.equal(jsonDepthExceeds('["\\\\", "' + "[".repeat(1000) + '"]'), false);
  assert.equal(jsonDepthExceeds('["\\\\"' + "[".repeat(600)), true);
  assert.equal(jsonDepthExceeds("[]".repeat(10000)), false);
  assert.equal(jsonDepthExceeds("[[[", 2), true);
});
