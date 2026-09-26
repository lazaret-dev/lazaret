// Review: the per-file finding cap flipped the maintainability gate. The cap
// runs inside scanFile, before buildResult rates the project: 2000 over-long
// lines were listed as 200 Q-LONGLINE findings plus one Q-CAPPED note, 201
// smells over 2000 lines of code, rating C and a passing gate (the real
// density is E). Q-CAPPED now records `omitted` (how many findings it
// replaces) and `omittedType`, and the rating counts those findings instead
// of the note when they are smells (twin of core._rated_smells).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, scanFile, buildResult, maintainabilityRating } from "../src/index.js";

const TABLE = Array.from({ length: 2000 }, (_, n) => {
  const k = String(n).padStart(4, "0");
  return `value_${k} = "${`segment-${k} `.repeat(14)}"\n`;
}).join("");
const CATCHES = "try { f() } catch (e) {}\n".repeat(300) + "// TODO later\n".repeat(15);

test("capped long lines rate E and fail the gate", () => {
  const issues = scanFile({ name: "table.py", content: TABLE, lang: "py" });
  const note = issues.find((i) => i.rule === "Q-CAPPED");
  assert.deepEqual([note.omitted, note.omittedType, note.msg], [1800, "SMELL", "1800 more Q-LONGLINE findings omitted"]);
  const res = buildResult(".", [{ path: "table.py", lang: "py", content: TABLE }], issues);
  assert.equal(res.ratings.maintainability, "E");                              // was C
  assert.equal(res.pass, false);
});

test("a capped bug rule adds no smells; a note without a count is one", () => {
  const issues = scanFile({ name: "c.js", content: CATCHES, lang: "js" });
  const note = issues.find((i) => i.rule === "Q-CAPPED");
  assert.deepEqual([note.omitted, note.omittedType], [100, "BUG"]);
  // 15 TODO smells over 300 lines of code: 5.0 per 100 is A
  assert.equal(buildResult(".", [{ path: "c.js", lang: "js", content: CATCHES }], issues).ratings.maintainability, "A");
  assert.equal(maintainabilityRating(Array(6).fill({ rule: "Q-CAPPED", type: "SMELL" }), 100), "B");
});

test("the CLI exits 1 with --ci", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-cap-"));
  try {
    writeFileSync(join(d, "table.py"), TABLE);
    assert.equal(run(["check", d, "-q", "--no-html", "--ci"], { out: () => {}, err: () => {}, env: {} }), 1);   // was 0
    assert.equal(JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).ratings.maintainability, "E");
  } finally { rmSync(d, { recursive: true, force: true }); }
});
