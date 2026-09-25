// Review regressions: quadratic regexes (review finding 8; shared semantics
// 14). Each input below took seconds to minutes before the fix (e.g. a
// 547 KB .sql: 15.7 s in SQL-*-NOWHERE alone); now every one is linear and
// finishes in well under a second. The bound is generous (machines differ)
// but far below the old cost at these sizes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile, setScanTimeBudget } from "../src/index.js";

const LIMIT_MS = 4000;
const CASES = {
  "SQL-DELETE-NOWHERE unterminated": ["sql", "DELETE FROM x ".repeat(20000)],
  "SQL-UPDATE-NOWHERE unterminated": ["sql", "UPDATE x SET ".repeat(20000)],
  "SQL-*-NOWHERE with WHERE": ["sql", "DELETE FROM t WHERE a = 1 AND b IN (SELECT c FROM d);\n".repeat(10000)],
  "SQL-DYNAMIC quotes": ["sql", "SET @a = '".repeat(20000)],
  "SQL-DYNAMIC EXEC(": ["sql", 'EXEC("'.repeat(20000)],
  "SQL-GRANT-PUBLIC": ["sql", "GRANT ".repeat(20000)],
  "B-EXCEPT-PASS newlines": ["py", "except:" + "\n".repeat(200000)],
  "B-EXCEPT-PASS repeated": ["py", "except ".repeat(100000)],
  "S-YAML repeated": ["py", "yaml.load(".repeat(20000) + "SafeLoader"],
  "S-CHMOD repeated": ["py", "chmod(".repeat(20000)],
  "B-EMPTY-CATCH repeated": ["js", "catch(".repeat(50000)],
  "function header a( repeated": ["js", "a(".repeat(100000)],
  "function header long word": ["js", "a".repeat(300000)],
  "S-TOKEN eyJ run": ["js", "x = '" + "eyJ".repeat(100000) + "'"],
  "SQL sink assignment whitespace": ["py", "q = 'x'" + " ".repeat(300000) + "+"],
  "taint: many assignments": ["js", Array.from({ length: 20000 }, (_, i) => `const v${i} = req.query.a${i};`).join("\n") + "\neval(v1);\n"],
};

for (const [label, [lang, content]] of Object.entries(CASES)) {
  test(`linear: ${label}`, () => {
    const t0 = performance.now();
    const issues = scanFile({ name: `t.${lang}`, content, lang });
    const ms = performance.now() - t0;
    assert.ok(ms < LIMIT_MS, `${label}: ${ms.toFixed(0)} ms`);
    assert.ok(!issues.some((i) => i.rule === "SC-TRUNCATED"), `${label} hit the time backstop`);
  });
}

test("the per-file time backstop stops a file with SC-TRUNCATED", () => {
  setScanTimeBudget(0);
  try {
    const issues = scanFile({ name: "t.js", content: "eval(a)\n".repeat(5000), lang: "js" });
    const t = issues.filter((i) => i.rule === "SC-TRUNCATED");
    assert.equal(t.length, 1);
    assert.equal(t[0].sev, "CRITICAL");
    assert.equal(t[0].msg, "File not fully scanned: scan time budget exceeded.");
  } finally {
    setScanTimeBudget();                      // back to the 30 s default
  }
  assert.ok(!scanFile({ name: "t.js", content: "eval(a)\n", lang: "js" }).some((i) => i.rule === "SC-TRUNCATED"));
});
