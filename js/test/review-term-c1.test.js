// Review follow-up: terminal sanitizing is identical in both engines. The
// npm engine always mapped the C1 controls (U+0080-U+009F; 0x9b is a
// one-byte CSI introducer on many terminals) and the bidi controls
// (U+202A-U+202E, U+2066-U+2069) to '·'; the Python engine's sanitize_term
// now maps the same set, and python/tests/scanner/test_review_term_c1.py
// compares the two engines over every code point up to U+2FFF.

import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeTerm, safeExcerpt } from "../src/index.js";

const CSI = "\x9b", OSC = "\x9d", ST = "\x9c";
const RLO = "\u202e", LRI = "\u2066", PDI = "\u2069", LRE = "\u202a", PDF = "\u202c";

test("sanitizeTerm maps C1 controls and bidi controls, keeps TAB/LF and printable text", () => {
  assert.equal(sanitizeTerm(`a${CSI}2Jb${OSC}0;PWNED${ST}c`), "a·2Jb·0;PWNED·c");
  assert.equal(sanitizeTerm("\x80\x85\x9f\xa0\xa9"), "···\xa0\xa9");
  assert.equal(sanitizeTerm(`x${RLO}y${LRI}z${PDI}${LRE}${PDF}`), "x·y·z···");
  // neighbours of the bidi ranges are not mapped
  const outside = "\u2029\u200f\u202f\u2065\u206a";
  assert.equal(sanitizeTerm(outside), outside);
  assert.equal(sanitizeTerm("a\nb\tc caf\u00e9 \u4e2d"), "a\nb\tc caf\u00e9 \u4e2d");
});

test("safeExcerpt maps C1 controls and bidi controls", () => {
  assert.equal(safeExcerpt(`eval("${CSI}31m") // ${RLO} } ${LRI}`), 'eval("·31m") // · } ·');
  assert.equal(safeExcerpt("a\xa0caf\u00e9\x85b\x9b"), "a·caf\u00e9·b·");
});
