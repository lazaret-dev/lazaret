// Invisible-character payload (SC-HIDDEN-UNICODE; twin of
// python/tests/scanner/test_review_hidden_unicode.py). GlassWorm hid its
// payload in a run of variation selectors decoded into eval; tag characters
// smuggle data past review. A flag emoji and a lone emoji variation selector
// are left alone. The invisible characters are built at run time so this file
// stays ASCII.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const vs = (bytes) => Array.from(bytes, (b) => String.fromCodePoint(0xFE00 + (b % 16))).join("");
const tagChars = (s) => Array.from(s, (c) => String.fromCodePoint(0xE0000 + c.codePointAt(0))).join("");
const bytesOf = (s) => Array.from(s, (c) => c.charCodeAt(0));
const flagEmoji = () => String.fromCodePoint(0x1F3F4) + tagChars("gbsct") + String.fromCodePoint(0xE007F);

const found = (content, lang = "js") => scanFile({ path: "x." + lang, content, lang })
  .filter((i) => i.rule === "SC-HIDDEN-UNICODE").map((i) => [i.sev, i.line, i.msg]);

test("the GlassWorm shape is CRITICAL, a bare carrier MAJOR", () => {
  const glass = "const s = v => [...v].map(w => w.codePointAt(0));\n" +
    "eval(Buffer.from(s(`" + vs(bytesOf("payload")) + "`)).toString());\n";
  assert.deepEqual(found(glass), [["CRITICAL", 2,
    "A run of 7 invisible variation selectors carries hidden data in the code, and the file runs code from a string."]]);
  assert.deepEqual(found("const x = `" + vs(bytesOf("hi")) + "`;\n"),
    [["MAJOR", 1, "A run of 2 invisible variation selectors carries hidden data in the code."]]);
});

test("tag characters smuggle; astral runs are counted in code points", () => {
  assert.deepEqual(found("x = '" + tagChars("run") + "'\n", "py"),
    [["MAJOR", 1, "A run of 3 invisible tag characters carries hidden data in the code."]]);
  const run = Array.from({ length: 5 }, (_, i) => String.fromCodePoint(0xE0100 + i)).join("");   // 5 astral VS
  assert.match(found("const x = `" + run + "`;\n")[0][2], /run of 5 invisible/);
});

test("a flag emoji, a lone variation selector and plain text are left alone", () => {
  for (const [text, lang] of [
    ["const label = '" + flagEmoji() + "';\n", "js"],
    ["x = 'a" + String.fromCodePoint(0xFE0F) + "';\n", "js"],
    ["const re = /[a-z]/;\n", "js"],
    ["s = '" + String.fromCodePoint(0x0435) + "val'\n", "py"],           // a Cyrillic letter is not a carrier
  ]) assert.deepEqual(found(text, lang), [], text);
});

test("it runs on dependencies and is never suppressed", () => {
  const text = "eval(s(`" + vs(bytesOf("xy")) + "`)); // nosec\n";
  assert.deepEqual(scanFile({ path: "x.js", content: text, lang: "js", dep: true })
    .filter((i) => i.rule === "SC-HIDDEN-UNICODE").map((i) => i.sev), ["CRITICAL"]);
});
