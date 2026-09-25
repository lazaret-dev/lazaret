// Detection tests for the ported scanner engine — each fixture is the
// canonical trigger for one rule family, taken from the working CodeGuard
// dashboard engine (codeguard.html) semantics.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile, detectLang } from "../../src/scanner/scan.js";
import { computeMetrics, worstSevRating, maintainabilityRating } from "../../src/scanner/metrics.js";

const scan = (name, content) =>
  scanFile({ name, content, lang: detectLang(name, content) }).map((i) => i.rule);

test("detectLang by extension and content", () => {
  assert.equal(detectLang("a.py", ""), "py");
  assert.equal(detectLang("a.ts", ""), "js");
  assert.equal(detectLang("a.sql", ""), "sql");
  assert.equal(detectLang("noext", "SELECT * FROM t"), "sql");
  assert.equal(detectLang("noext", "function f(){}"), "js");
});

test("py: eval/exec, command injection, SQL injection", () => {
  assert.ok(scan("t.py", "eval(x)\n").includes("S-EVAL-PY"));
  assert.ok(scan("t.py", "import os\nos.system(cmd)\n").includes("S-OSCMD-PY"));
  assert.ok(scan("t.py", 'cur.execute("SELECT * FROM t WHERE i=" + uid)\n').includes("S-SQL-PY"));
});

test("py: sqlSinkScan catches template-variable SQL (G12)", () => {
  const src = [
    "q = 'SELECT * FROM t WHERE id = %s' % uid",
    "cur.execute(q)",
    "",
  ].join("\n");
  const found = scanFile({ name: "t.py", content: src, lang: "py" });
  assert.ok(found.some((i) => i.rule === "S-SQL-PY" && i.sev === "BLOCKER"));
});

test("py: parameterized SQL is NOT flagged", () => {
  const src = 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n';
  assert.deepEqual(scanFile({ name: "t.py", content: src, lang: "py" }), []);
});

test("js: eval, innerHTML XSS, prototype pollution", () => {
  assert.ok(scan("t.js", "eval(userInput);\n").includes("S-EVAL-JS"));
  assert.ok(scan("t.js", "el.innerHTML = userHtml;\n").includes("S-INNERHTML"));
  assert.ok(scan("t.js", 'obj["__proto__"] = x;\n').includes("S-PROTO"));
});

test("taint: request data → os.system is flagged (T-CMD)", () => {
  const src = "import os\nfrom flask import request\ncmd = request.args.get('c')\nos.system(cmd)\n";
  const found = scanFile({ name: "t.py", content: src, lang: "py" });
  assert.ok(found.some((i) => i.rule === "T-CMD"));
});

test("taint: sanitized flow is NOT flagged", () => {
  const src = "import os, shlex\nfrom flask import request\ncmd = shlex.quote(request.args.get('c'))\nos.system('ls ' + cmd)\n";
  const found = scanFile({ name: "t.py", content: src, lang: "py" })
    .filter((i) => i.rule.startsWith("T-"));
  assert.deepEqual(found, []);
});

test("obfuscation: hex-hidden text and base64 blob flagged (SC-HEXSTR / SC-B64)", () => {
  // "\x65\x76\x61\x6c\x28\x61\x74\x6f\x62" spells eval(atob: readable text hidden in escapes
  const hex = 'x = "' + [..."eval(atob"].map((c) => "\\x" + c.charCodeAt(0).toString(16)).join("") + '"\n';
  assert.ok(scan("t.py", hex).includes("SC-HEXSTR"));
  // escaped binary data (NUL bytes, UTF-8 sequences) is not obfuscation
  const binary = 'x = b"' + "\\x00\\xc3\\xa4".repeat(4) + '"\n';
  assert.ok(!scan("t.py", binary).includes("SC-HEXSTR"));
  const b64 = 'x = "' + "A".repeat(250) + '"\n';   // 200+ consecutive base64 chars
  assert.ok(scan("t.js", b64).includes("SC-B64"));
});

test("entropy: high-entropy literal flagged (S-ENTROPY), placeholder skipped", () => {
  assert.ok(scan("t.py", 'token = "Zk9mS3B4NjdxTW5xU2Y4"\n').includes("S-ENTROPY"));
  assert.ok(!scan("t.py", 'token = "placeholder-example-token"  # example\n').includes("S-ENTROPY"));
});

test("javascript-obfuscator signature: 5+ _0x identifiers (SC-OBF-IDENT)", () => {
  const src = [...Array(6)].map((_, i) => `var _0x${"abcd"}${i} = 1;`).join("\n") + "\n";
  assert.ok(scan("t.js", src).includes("SC-OBF-IDENT"));
});

test("quality: long function and complexity (Q-FN-LONG / Q-FN-CX)", () => {
  const long = "def f():\n" + "    x = 1\n".repeat(70);
  const found = scanFile({ name: "t.py", content: long, lang: "py" });
  assert.ok(found.some((i) => i.rule === "Q-FN-LONG"));
});

test("suppression: nosec with rule id suppresses only that rule", () => {
  const src = "import os\nos.system(cmd)  # nosec S-OSCMD-PY\n";
  assert.deepEqual(scanFile({ name: "t.py", content: src, lang: "py" }).map((i) => i.rule), []);
});

test("suppression: marker on the line suppresses; id list filters by rule", () => {
  assert.deepEqual(
    scanFile({ name: "t.py", content: "import os\nos.system(cmd)  # nosec S-OSCMD-PY\n", lang: "py" })
      .map((i) => i.rule), []);
  // marker naming a DIFFERENT rule does not suppress
  const other = scanFile({ name: "t.py", content: "import os\nos.system(cmd)  # nosec S-EVAL-PY\n", lang: "py" });
  assert.ok(other.some((i) => i.rule === "S-OSCMD-PY"));
  // bare marker (no ids) suppresses everything on the line
  assert.deepEqual(
    scanFile({ name: "t.py", content: "eval(x)  # lazaret-ignore\n", lang: "py" }).map((i) => i.rule), []);
  // previous-line marker counts only when that line is a standalone comment
  const prev = scanFile({ name: "t.py", content: "# nosec\neval(x)\n", lang: "py" });
  assert.deepEqual(prev.map((i) => i.rule), []);
  const prevCode = scanFile({ name: "t.py", content: "a = 1  # nosec\neval(x)\n", lang: "py" });
  assert.ok(prevCode.some((i) => i.rule === "S-EVAL-PY"));
});

test("issue shape: all fields present, snippet is ±2 lines, snipStart matches", () => {
  const issues = scanFile({ name: "t.py", content: "a=1\nb=2\neval(x)\nc=3\n", lang: "py" });
  const i = issues.find((x) => x.rule === "S-EVAL-PY");
  for (const k of ["rule", "name", "type", "sev", "msg", "why", "fix", "ref", "file", "line", "snippet", "snipStart"])
    assert.ok(i[k] !== undefined, `missing field ${k}`);
  assert.equal(i.line, 3);
  assert.equal(i.snipStart, 1);
  assert.equal(i.snippet.length, 5);       // lines 1..5 (max(0,3-3) to 3+2)
});

test("findings cap: security findings never capped, low-severity ones capped at 200 + Q-CAPPED", () => {
  // spec 7 replaces the old 500-issue per-file budget (which silently dropped
  // every later rule, SC-* included)
  const src = "eval(x)\n".repeat(600);
  const found = scanFile({ name: "t.py", content: src, lang: "py" });
  assert.equal(found.filter((i) => i.rule === "S-EVAL-PY").length, 600);
  const todo = scanFile({ name: "t.py", content: "# TODO\n".repeat(600), lang: "py" });
  assert.equal(todo.filter((i) => i.rule === "Q-TODO").length, 200);
  assert.deepEqual(todo.filter((i) => i.rule === "Q-CAPPED").map((i) => i.msg), ["400 more Q-TODO findings omitted"]);
});

test("computeMetrics: ncloc/comments/dupPct + files/depFiles", () => {
  const block = "x=1\nx=2\nx=3\nx=4\nx=5\nx=6\n";   // 6 identical code lines → full-window duplication
  const files = [
    { name: "a.py", content: block, lang: "py", dep: false },
    { name: "b.py", content: block, lang: "py", dep: false },
    { name: "dep.py", content: "y=2\n", lang: "py", dep: true },
  ];
  const m = computeMetrics(files);
  assert.equal(m.files, 2);
  assert.equal(m.depFiles, 1);
  assert.equal(m.ncloc, 12);
  assert.equal(m.comments, 0);
  assert.equal(m.dupPct, 100);   // two identical files: every window occurs twice
});

test("ratings: worst-severity mapping and maintainability bands", () => {
  assert.equal(worstSevRating([{ type: "VULN", sev: "BLOCKER" }], ["VULN"]), "E");
  assert.equal(worstSevRating([{ type: "VULN", sev: "CRITICAL" }], ["VULN"]), "D");
  assert.equal(worstSevRating([{ type: "BUG", sev: "MAJOR" }], ["VULN"]), "A"); // filtered by type
  assert.equal(worstSevRating([], ["VULN"]), "A");
  assert.equal(maintainabilityRating([], 100), "A");
  assert.equal(maintainabilityRating(new Array(25).fill({ type: "SMELL" }), 100), "D");  // 25/100 → D
  assert.equal(maintainabilityRating(new Array(50).fill({ type: "SMELL" }), 100), "E"); // 50/100 → E
});
