// Look-alike identifiers (SC-HOMOGLYPH; twin of
// python/tests/scanner/test_review_lookalike_names.py): a name spelled with
// letters from another alphabet that look like Latin ones (or with an
// invisible U+200C / U+200D, or with NFKC compatibility forms) reads as a name
// it is not: CRITICAL when that is a code-execution or network name, or
// another name in the file; MAJOR when it mixes ASCII letters with
// look-alikes. Every such character here is written as an escape.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const found = (content, lang = "js", dep = false) =>
  scanFile({ path: "x." + lang, content, lang, dep }).filter((i) => i.rule === "SC-HOMOGLYPH").map((i) => [i.sev, i.line, i.msg]);
const EVAL_MSG = "'\u0435val' reads as 'eval' but is spelled with U+0435 for 'e'.";

test("a second eval, another name in the file, a mixed name", () => {
  for (const [lang, text] of [["js", "const \u0435val = eval;\n\u0435val(x);\n"], ["py", "\u0435val = eval\n\u0435val(input())\n"]]) {
    for (const dep of [false, true]) assert.deepEqual(found(text, lang, dep), [["CRITICAL", 1, EVAL_MSG], ["CRITICAL", 2, EVAL_MSG]]);
  }
  assert.deepEqual(found("if (isAdm\u0456n) { go(); }\nconst isAdmin = false;\n"), [["CRITICAL", 1,
    "'isAdm\u0456n' reads as 'isAdmin', another name in this file, but is spelled with U+0456 for 'i'."]]);
  assert.deepEqual(found("const v\u0430lue = 1;\n"), [["MAJOR", 1, "'v\u0430lue' reads as 'value' but is spelled with U+0430 for 'a'."]]);
  assert.deepEqual(found("\u0435\u0445\u0435\u0441(c)\n", "py"), [["CRITICAL", 1,
    "'\u0435\u0445\u0435\u0441' reads as 'exec' but is spelled with U+0435 for 'e', U+0445 for 'x', U+0441 for 'c'."]]);
});

test("JavaScript's forms: invisible characters, fullwidth letters, identifier escapes", () => {
  assert.deepEqual(found("eva\u200dl(x);\n"), [["CRITICAL", 1, "'eva\\u200dl' reads as 'eval' but is spelled with an invisible U+200D."]]);
  assert.deepEqual(found("\uff45val(x);\n"), [["CRITICAL", 1, "'\uff45val' reads as 'eval' but is spelled with U+FF45 for 'e'."]]);
  assert.deepEqual(found("\\u0435val(x);\n"), [["CRITICAL", 1, EVAL_MSG]]);
  assert.deepEqual(found("\uff45val(x)\n", "py"), []);                    // Python reads it as eval itself
});

test("what is not a look-alike name", () => {
  for (const [lang, text] of [
    ["js", "const s = '\u0435val';\n"], ["js", "// \u0435val(x)\n"], ["js", "/[\u0430-\u044f]/.test(s);\n"],
    ["js", "const \u043f\u0440\u0438\u0432\u0435\u0442 = 1;\n"], ["py", "\u03b1 = 0.05\n"], ["py", "\u039f = 1\n"],
    ["js", "const re = /[\\uFF07\\uFF10]/;\n"], ["js", "x = /[\\u2105\\u210A]/;\n"], ["py", "t = '\u0435val'  # \u0435val\n"],
    ["js", "const caf\u00e9 = 1;\n"], ["js", "const \u0430 = 1;\n"],
  ]) assert.deepEqual(found(text, lang), [], text);
  assert.deepEqual(found("\u0435val(x); // nosec\n"), [["CRITICAL", 1, EVAL_MSG]]);   // never suppressed
});
