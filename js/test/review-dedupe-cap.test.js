// Final review: report blowup. The per-(file, rule) cap covered only
// INFO/MINOR/SMELL rules, so the MAJOR B-EMPTY-CATCH gave 130,001 findings
// (an 87.7 MB JSON report) for a 1.95 MB one-line file of
// `try{}catch(e){}` x 130,000. Shared semantics (twin of core.cap_issues):
// findings identical on (rule, file, line, msg) are reported once (every
// rule, security rules too, before the cap); every non-security rule
// (not S-, T-, SC-, X-, SQL-) is capped at 200 per file with one Q-CAPPED.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanFile, run } from "../src/index.js";
import { dedupeIssues } from "../src/scanner/scan.js";

const count = (issues, rule) => issues.filter((i) => i.rule === rule).length;
const cappedMsgs = (issues) => issues.filter((i) => i.rule === "Q-CAPPED").map((i) => i.msg).sort();

test("a 1.95 MB one-line file gives one finding per rule and a small report", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-oneline-"));
  try {
    writeFileSync(join(d, "one.js"), "try{}catch(e){}".repeat(130_000));
    const code = run(["check", d, "-q", "--no-html"], { out: () => {}, err: () => {} });
    assert.equal(code, 0);
    const report = join(d, "lazaret-report.json");
    const issues = JSON.parse(readFileSync(report, "utf8")).issues;
    assert.equal(count(issues, "B-EMPTY-CATCH"), 1);
    assert.ok(statSync(report).size < 50_000, `report is ${statSync(report).size} bytes`);   // was 87.7 MB
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("a MAJOR bug rule is capped at 200 with one Q-CAPPED", () => {
  const r = scanFile({ name: "many.js", lang: "js", content: "try{}catch(e){}\n".repeat(1000) });
  assert.equal(count(r, "B-EMPTY-CATCH"), 200);
  assert.deepEqual(cappedMsgs(r), ["800 more B-EMPTY-CATCH findings omitted"]);
  const cap = r.find((i) => i.rule === "Q-CAPPED");
  assert.equal(cap.line, 201);
  assert.equal(cap.why, "Findings of one rule that repeat hundreds of times in one file are capped so reports stay readable; security findings are never capped.");
  const py = scanFile({ name: "e.py", lang: "py", content: "try:\n    f()\nexcept:\n    pass\n".repeat(250) });
  assert.equal(count(py, "B-EXCEPT-PASS"), 200);
  assert.deepEqual(cappedMsgs(py), ["50 more B-BARE-EXCEPT findings omitted", "50 more B-EXCEPT-PASS findings omitted"]);
});

test("the 120,000-line variant: 200 findings and one Q-CAPPED", () => {
  const r = scanFile({ name: "lines.js", lang: "js", content: "try{}catch(e){}\n".repeat(120_000) });
  assert.equal(count(r, "B-EMPTY-CATCH"), 200);
  assert.deepEqual(cappedMsgs(r), ["119800 more B-EMPTY-CATCH findings omitted"]);
  assert.ok(JSON.stringify(r).length < 200_000);
});

test("security rules are deduplicated but never capped", () => {
  const sql = scanFile({ name: "d.sql", lang: "sql", content: "DELETE FROM a; DELETE FROM b; DELETE FROM c;\n".repeat(3) + "DELETE FROM t;\n".repeat(250) });
  assert.equal(count(sql, "SQL-DELETE-NOWHERE"), 253);
  assert.deepEqual(sql.filter((i) => i.rule === "SQL-DELETE-NOWHERE").slice(0, 3).map((i) => i.line), [1, 2, 3]);
  assert.deepEqual(cappedMsgs(sql), []);
  assert.equal(count(scanFile({ name: "s.js", lang: "js", content: "eval(a); eval(b)\n".repeat(300) }), "S-EVAL-JS"), 300);
});

test("findings with different messages on one line are kept", () => {
  const r = scanFile({ name: "s.py", lang: "py",
    content: "cur.execute(sql % x); cur.execute(tpl.format(y))\ncur.execute(a % x); cur.execute(b % y)\n" });
  assert.deepEqual(r.filter((i) => i.rule === "S-SQL-PY").map((i) => [i.line, i.msg]).sort(), [
    [1, "SQL query built with %-interpolation into execute()."],
    [1, "SQL query built with .format()/f-string into execute()."],
    [2, "SQL query built with %-interpolation into execute()."],
  ]);
});

test("dedupeIssues keys on (rule, file, line, msg) and keeps the first", () => {
  const issue = (o = {}) => ({ rule: "T-CMD", file: "a.py", line: 3, msg: "m1", snippet: ["x"], ...o });
  const first = issue({ snippet: ["first"] });
  const kept = dedupeIssues([first, issue({ snippet: ["second"] }), issue({ msg: "m2" }), issue({ line: 4 }),
    issue({ file: "b.py" }), issue({ rule: "T-CODE" }), issue({ msg: "m2" })]);
  assert.equal(kept[0], first);
  assert.deepEqual(kept.map((i) => [i.rule, i.file, i.line, i.msg]), [
    ["T-CMD", "a.py", 3, "m1"], ["T-CMD", "a.py", 3, "m2"], ["T-CMD", "a.py", 4, "m1"],
    ["T-CMD", "b.py", 3, "m1"], ["T-CODE", "a.py", 3, "m1"]]);
});
