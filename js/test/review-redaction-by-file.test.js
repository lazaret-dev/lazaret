// Review: the walker's Q-ENCODING / SC-UTF7 findings leaked the file's
// secrets. mkIssue redacts a snippet with the file's own entropy literals and
// PEM blocks only for lines registered by scanFile; the walker built these
// two findings from its own lines, so a UTF-8-BOM settings.py showed the
// `SEED = "q8Zr…"` literal its S-ENTROPY finding redacted. The walker now
// registers the file's lines first (twin of core.encoding_issues), in the
// CLI and in the library API (collectFiles). Dummy credentials only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, collectFiles } from "../src/index.js";

const SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9";
const PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
const SETTINGS = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]),
  Buffer.from(`# service settings\nSEED = "${SEED}"\nDEBUG_LEVEL = 1\n`)]);
const UTF7 = Buffer.from(`# -*- coding: utf-7 -*-\nSEED = "${SEED}"\nx = 1\n`);
// a UTF-16 file whose PEM block starts above line 1's snippet window end
const KEYS = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(
  `const k = "-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----";\n`, "utf16le")]);

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-redact-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}

test("the walker's Q-ENCODING / SC-UTF7 snippets redact the file's own literals and PEM lines", () => {
  const d = tree({ "settings.py": SETTINGS, "u7.py": UTF7, "keys.js": KEYS });
  try {
    const { binaryIssues } = collectFiles(d);
    const at = (file, rule) => binaryIssues.find((i) => i.file === file && i.rule === rule);
    assert.deepEqual(at("settings.py", "Q-ENCODING").snippet, ["# service settings", 'SEED = "[redacted]"', "DEBUG_LEVEL = 1"]);
    assert.equal(at("u7.py", "Q-ENCODING").snippet[1], 'SEED = "[redacted]"');
    assert.equal(at("u7.py", "SC-UTF7").snippet[1], 'SEED = "[redacted]"');
    assert.deepEqual(at("keys.js", "Q-ENCODING").snippet, ['const k = "[redacted]', "[redacted]", "[redacted]"]);
    assert.ok(!JSON.stringify(binaryIssues).includes(SEED));
    assert.ok(!JSON.stringify(binaryIssues).includes(PEM_BODY));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("the JSON and HTML reports carry no literal", () => {
  const d = tree({ "settings.py": SETTINGS });
  try {
    const err = [];
    assert.equal(run(["check", d, "-q"], { out: () => {}, err: (s) => err.push(s), env: {} }), 0, err.join("\n"));
    for (const name of ["lazaret-report.json", "lazaret-report.html"]) {
      const text = readFileSync(join(d, name), "utf8");
      assert.ok(text.includes("Q-ENCODING"), name);
      assert.ok(!text.includes(SEED), name);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("--no-redact-secrets keeps the literal", () => {
  const d = tree({ "settings.py": SETTINGS });
  try {
    assert.equal(run(["check", d, "-q", "--no-html", "--no-redact-secrets"], { out: () => {}, err: () => {}, env: {} }), 0);
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    assert.ok(issues.find((i) => i.rule === "Q-ENCODING").snippet[1].includes(SEED));
  } finally { rmSync(d, { recursive: true, force: true }); }
});
