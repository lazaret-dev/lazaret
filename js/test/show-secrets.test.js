// --show-secrets (tests/scanner/test_show_secrets.py's twin for this package): a finding's flagged line unredacted on
// the terminal, and nowhere else. The findings stay redacted where they are made (the engine's one redactor); the
// flag keeps each finding's flagged line as it was read, apart from the result (flaggedLines), and the terminal's
// excerpt prints it. The JSON and HTML reports and the baseline stay redacted. It works only when the output is a
// terminal: asked for elsewhere, a note says the credentials stay redacted. Made-up credentials, built in pieces.

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { run } from "../src/index.js";
import { check } from "../src/hook.js";
import { flaggedLines, issueExcerpt, showSecretsOn, SHOW_SECRETS_NOT_A_TERMINAL } from "../src/report.js";
import { findProgram } from "../src/lib/programs.js";

const TOKEN = "gh" + "p_" + "a1B2".repeat(9);
const LINE = `const token = "${TOKEN}";`;
const GIT = findProgram("git");
const GIT_HOME = mkdtempSync(join(tmpdir(), "lz-show-git-"));
const NO_SETTINGS = join(GIT_HOME, "gitconfig");
writeFileSync(NO_SETTINGS, "");
after(() => rmSync(GIT_HOME, { recursive: true, force: true, maxRetries: 3 }));
const ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: NO_SETTINGS };

function tree(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "lz-show-")));
  for (const [rel, text] of Object.entries(files)) {
    const path = join(root, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
  }
  return root;
}

test("only on a terminal", () => {
  const err = [];
  assert.equal(showSecretsOn(false, true, (s) => err.push(s)), false);
  assert.equal(showSecretsOn(true, true, (s) => err.push(s)), true);
  assert.deepEqual(err, []);
  assert.equal(showSecretsOn(true, false, (s) => err.push(s)), false);
  assert.deepEqual(err, [SHOW_SECRETS_NOT_A_TERMINAL]);
});

test("flaggedLines: each finding's line as read", () => {
  const entries = [{ path: "a.js", content: "x\r\ny\u2028z", lang: "js" }, { path: "b", content: "p\nq" },
    { path: "c", content: null }];
  const issues = [{ file: "a.js", line: 3 }, { file: "a.js", line: 4 }, { file: "b", line: 2 }, { file: "c", line: 1 },
    { file: "d", line: 1 }, { file: "b", line: 0 }, { file: "b" }];
  const shown = flaggedLines(issues, entries);
  assert.equal(shown.size, 2);
  assert.equal(issueExcerpt({ file: "a.js", line: 3, snippet: ["[redacted]"], snipStart: 3 }, undefined, shown), "z");
  assert.equal(issueExcerpt({ file: "b", line: 2, snippet: ["[redacted]"], snipStart: 2 }, undefined, shown), "q");
  assert.equal(issueExcerpt({ file: "b", line: 1, snippet: ["[redacted]"], snipStart: 1 }, undefined, shown), "[redacted]");
});

function scan(root, args, isTTY) {
  const out = [], err = [];
  const code = run(["check", root, "--force-overwrite", ...args], { out: (s) => out.push(s), err: (s) => err.push(s),
    env: {}, isTTY });
  const reports = readFileSync(join(root, "lazaret-report.json"), "utf8") + readFileSync(join(root, "lazaret-report.html"), "utf8");
  return { code, out: out.join("\n"), err: err.join("\n"), reports };
}

test("the CLI: the terminal shows the line, the reports never do", () => {
  const root = tree({ "app.js": `// settings\n${LINE}\n` });
  try {
    let got = scan(root, ["--show-secrets"], true);
    assert.ok(got.out.includes(TOKEN), got.out);
    assert.ok(!got.reports.includes(TOKEN));
    assert.ok(!got.err.includes(SHOW_SECRETS_NOT_A_TERMINAL));
    got = scan(root, ["--show-secrets"], false);
    assert.ok(!(got.out + got.reports).includes(TOKEN));
    assert.ok(got.err.includes(SHOW_SECRETS_NOT_A_TERMINAL));
    got = scan(root, [], true);
    assert.ok(!(got.out + got.reports).includes(TOKEN));
  } finally { rmSync(root, { recursive: true, force: true, maxRetries: 3 }); }
});

test("the hook: the staged line", { skip: GIT ? false : "git is not installed" }, async () => {
  const root = tree({ "app.js": `${LINE}\n` });
  try {
    for (const args of [["init", "-q"], ["config", "user.email", "t@x.invalid"], ["config", "user.name", "t"], ["add", "app.js"]]) {
      const p = spawnSync(GIT, ["-C", root, ...args], { env: ENV });
      assert.equal(p.status, 0, String(p.stderr));
    }
    for (const showSecrets of [true, false]) {
      const lines = [];
      const code = await check([], { cwd: root, env: ENV, out: (s) => lines.push(s), showSecrets });
      assert.equal(code, 1);
      assert.ok(lines.join("\n").includes("[S-TOKEN]"));
      assert.equal(lines.join("\n").includes(TOKEN), showSecrets);
    }
  } finally { rmSync(root, { recursive: true, force: true, maxRetries: 3 }); }
});
