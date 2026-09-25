// Review regressions: --baseline with trust rules (review finding 3; twin
// of the Python engine's apply_baseline / sign_fingerprints). A baseline is
// report-shaped input that CI gates on, and the engine marker is public, so:
// with $LAZARET_BASELINE_KEY set a baseline must carry a valid HMAC-SHA256
// signature; without a key, a baseline inside the scanned tree is untrusted.
// An untrusted baseline counts every finding as new (fail closed).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, baselineSignature, fingerprint } from "../src/index.js";
import { signFingerprints } from "../src/baseline.js";

const KEY = "test-key-not-a-secret";

function setup() {
  const d = mkdtempSync(join(tmpdir(), "lazaret-bl-"));
  mkdirSync(join(d, "src"));
  mkdirSync(join(d, "out"));
  writeFileSync(join(d, "src", "a.js"), "eval(y)\n");
  return d;
}
function scan(d, argv, env = {}) {
  const out = [], err = [];
  const code = run(["check", join(d, "src"), "--no-html", "-q", ...argv],
    { out: (s) => out.push(s), err: (s) => err.push(s), env });
  return { code, out: out.join("\n"), err: err.join("\n") };
}
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));

test("a baseline outside the tree marks only new findings as new", () => {
  const d = setup();
  try {
    assert.equal(scan(d, ["--json", join(d, "out", "base.json")]).code, 0);
    writeFileSync(join(d, "src", "b.js"), "eval(z)\n");
    const r = scan(d, ["--json", join(d, "out", "now.json"), "--baseline", join(d, "out", "base.json")]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.err, "");
    assert.match(r.out, /New issues vs baseline: 1/);
    const rep = readJson(join(d, "out", "now.json"));
    assert.equal(rep.newIssues, 1);
    assert.deepEqual(rep.issues.map((i) => [i.file, i.new]), [["a.js", false], ["b.js", true]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("without a key, a baseline inside the scanned tree is untrusted (it could be planted)", () => {
  const d = setup();
  try {
    assert.equal(scan(d, []).code, 0);                                   // report inside src/
    const r = scan(d, ["--baseline", join(d, "src", "lazaret-report.json")]);
    assert.match(r.err, /is inside the scanned tree and \$LAZARET_BASELINE_KEY is not set/);
    assert.match(r.err, /all current findings are counted as new/);
    const rep = readJson(join(d, "src", "lazaret-report.json"));
    assert.equal(rep.newIssues, 1);
    assert.equal(rep.baselineUntrusted, true);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a foreign file is not a baseline; a malformed one is ignored with a warning", () => {
  const d = setup();
  try {
    writeFileSync(join(d, "out", "foreign.json"), '{"issues": []}');
    let r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", join(d, "out", "foreign.json")]);
    assert.match(r.err, /is not a report produced by this engine/);
    assert.equal(readJson(join(d, "out", "r.json")).newIssues, 1);
    writeFileSync(join(d, "out", "bad.json"), '{"generatedBy": "lazaret-cli-1", "issues": "nope"}');
    r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", join(d, "out", "bad.json")]);
    assert.equal(r.code, 0);
    assert.match(r.err, /'issues' is str, not a list — baseline ignored/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("with $LAZARET_BASELINE_KEY: reports are signed; only a verifying baseline is trusted", () => {
  const d = setup();
  const env = { LAZARET_BASELINE_KEY: KEY };
  try {
    assert.equal(scan(d, [], env).code, 0);
    const base = join(d, "src", "lazaret-report.json");
    const signed = readJson(base);
    assert.deepEqual(Object.keys(signed).slice(0, 2), ["generatedBy", "baselineSignature"]);
    assert.equal(signed.baselineSignature.alg, "HMAC-SHA256");
    assert.equal(signed.baselineSignature.value, baselineSignature(signed.issues, KEY));
    // signed + key: trusted even inside the tree
    let r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", base], env);
    assert.equal(r.err, "");
    assert.equal(readJson(join(d, "out", "r.json")).newIssues, 0);
    // an edited baseline no longer verifies
    signed.issues[0].snippet = ["eval(somethingElse)"];
    writeFileSync(join(d, "out", "edited.json"), JSON.stringify(signed));
    r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", join(d, "out", "edited.json")], env);
    assert.match(r.err, /signature does not verify/);
    assert.equal(readJson(join(d, "out", "r.json")).baselineUntrusted, true);
    // a hand-written marker file (no signature) is refused once a key is set
    writeFileSync(join(d, "out", "forged.json"),
      JSON.stringify({ generatedBy: "lazaret-cli-1", issues: signed.issues.map((i) => ({ ...i, snippet: ["eval(y)"], snipStart: 1 })) }));
    r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", join(d, "out", "forged.json")], env);
    assert.match(r.err, /carries no baseline signature/);
    // … and a report signed with another key is refused as well
    r = scan(d, ["--json", join(d, "out", "r.json"), "--baseline", base], { LAZARET_BASELINE_KEY: "another-key" });
    assert.match(r.err, /signature does not verify/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("signature serialization is shared with the Python engine", () => {
  // HMAC-SHA256(UTF-8 key, b"lazaret-baseline-v1\n" + json.dumps(sorted(set(fps)),
  // ensure_ascii=True, separators=(",", ":"))) — this hex was produced by
  // lazaret.scanner.reports.sign_fingerprints on the same input.
  const fps = ["S-EVAL-JS|src/a.js|eval(y)", 'S-EVAL-PY|café.py|eval("é\u{1F600}")',
    "S-EVAL-JS|src/a.js|eval(y)", 'Q-TODO|b.js|// TODO \\ "q"\t'];
  assert.equal(signFingerprints(fps, "test-key-é"),
    "98eb9a02086a38114576d43088eef92cf35471c29c6a9696ba6c099560041a44");
  // fingerprint: rule | path with forward slashes | stripped flagged line
  assert.equal(fingerprint({ rule: "R", file: "a\\b.js", line: 3, snipStart: 2, snippet: ["x", "  eval(q)  ", "z"] }),
    "R|a/b.js|eval(q)");
});
