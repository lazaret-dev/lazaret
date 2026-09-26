// Final review: .pth files were never checked in project or --deps scans (a
// directory holding only evil.pth exited 2, "nothing to scan"). site.py
// executes every `import` line of a .pth file in site-packages at every
// interpreter start. The walker now runs SC-PTH-EXEC (twin of
// core.pth_issues / the registry's check) on each .pth file: CRITICAL when
// the import line also executes or decodes code, MAJOR otherwise. A .pth
// file is not source (no other rule, not in the metrics); the size cap
// applies; a directory with only a .pth file is a valid target. Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, pthIssues, collectFiles } from "../src/index.js";

const EVIL = 'import os, base64; exec(base64.b64decode("cHJpbnQoMSk="))\n';
const SHIM = "import _distutils_hack; _distutils_hack.do()\n";

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-pth-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}
function scan(d, extra = []) {
  const err = [];
  const code = run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: (s) => err.push(s) });
  let issues = null;
  try { issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues; } catch { /* no report */ }
  return { code, err: err.join("\n"), issues };
}
const pth = (issues) => issues.filter((i) => i.rule === "SC-PTH-EXEC").map((i) => [i.file.replaceAll("\\", "/"), i.line, i.sev]).sort();

test("a directory holding only evil.pth is scanned, not 'nothing to scan'", () => {
  const d = tree({ "evil.pth": EVIL });
  try {
    const r = scan(d);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(pth(r.issues), [["evil.pth", 1, "CRITICAL"]]);
    assert.equal(r.issues.find((i) => i.rule === "SC-PTH-EXEC").msg, ".pth line runs code at every Python start and executes or decodes a payload.");
    assert.equal(scan(d, ["--ci"]).code, 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a .pth file without import lines is still a valid target", () => {
  const d = tree({ "paths.pth": "./src\n../lib\n" });
  try {
    const r = scan(d);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(pth(r.issues), []);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test(".pth files are not source files; BOM and CRLF are handled", () => {
  const d = tree({ "sub/boot.pth": "import os; os.system(cmd)\n", "app.py": "x = 1\n",
    "a.pth": Buffer.from("\ufeffimport sys\r\n./x\r\nimport os; exec(s)\r\n") });
  try {
    const col = collectFiles(d);
    assert.deepEqual(col.files.map((f) => f.path), ["app.py"]);
    assert.deepEqual(col.pth.map((p) => p.replaceAll("\\", "/")).sort(), ["a.pth", "sub/boot.pth"]);
    const r = scan(d);
    assert.deepEqual(pth(r.issues), [["a.pth", 1, "MAJOR"], ["a.pth", 3, "CRITICAL"], ["sub/boot.pth", 1, "MAJOR"]]);
    assert.deepEqual([...new Set(r.issues.map((i) => i.rule))], ["SC-PTH-EXEC"]);   // no S-OSCMD-PY on it
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("site-packages .pth files are checked with --deps", () => {
  const d = tree({ "app.py": "x = 1\n", "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/python3.11/site-packages/ns.pth": SHIM, "venv/lib/python3.11/site-packages/evil.pth": EVIL });
  try {
    assert.deepEqual(pth(scan(d).issues), []);
    assert.deepEqual(pth(scan(d, ["--deps"]).issues), [
      ["venv/lib/python3.11/site-packages/evil.pth", 1, "CRITICAL"],
      ["venv/lib/python3.11/site-packages/ns.pth", 1, "MAJOR"]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("the size cap applies to .pth files", () => {
  const d = tree({ "big.pth": EVIL + "#".repeat(2_000_001) });
  try {
    const r = scan(d);
    assert.deepEqual(pth(r.issues), []);
    assert.deepEqual(r.issues.filter((i) => i.rule === "SC-TRUNCATED").map((i) => i.file), ["big.pth"]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("pthIssues: CRITICAL only when the import line executes or decodes", () => {
  const got = pthIssues("m.pth", "import\tsite\n./a\n  import os\nimport x; y = s.decode('rot13')\nimport os; os.system('\\x69d')\nimport zlib, marshal; marshal.loads(z)\n");
  assert.deepEqual(got.map((i) => [i.line, i.sev]), [[1, "MAJOR"], [4, "CRITICAL"], [5, "CRITICAL"], [6, "CRITICAL"]]);
});
