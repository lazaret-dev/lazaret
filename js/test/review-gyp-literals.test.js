// Review regressions: the npm engine's binding.gyp literal parser and value
// rendering differed from core's ast.literal_eval and str(). Every
// expectation equals core.scan_gyp's result on the same text
// (test_review_gyp_literals; test_js_parity_gyp compares the two CLIs).
//
// Numbers: JSON and literal numbers were JS doubles, so the kind and the
// digits were lost ("echo 1 12345678901234567000 0" for ['echo', 1.0,
// 12345678901234567890, -0.0]); `--1` parsed (literal_eval refuses a sign on
// a signed operand) while `1+2j` did not, `2j` was the number 2, and number
// tokens longer than 400 characters or written `1.e5` failed.
//
// Strings and containers: `\N{NAME}` was refused (so a gyp file using one
// was unparseable, and unscanned, here only); a bytes literal was a str (a
// b'action' key made an action, b'…' printed without its b and quotes, bytes
// and str concatenated); a tuple printed as a list; a non-str dict key was
// String(key) (the tuple key ('action',) became "action", 1 and '1' one
// key); \r did not end a comment or a line as it does for Python's
// tokenizer; \v counted as whitespace and a NUL was accepted. Inert input.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanGyp } from "../src/index.js";

const cmd = (args) => {
  const issues = scanGyp("binding.gyp", `{'action': [${args}]}`);
  return issues.map((i) => (i.rule === "SC-INSTALL-HOOK" ? i.cmd : i.rule));
};
const UNPARSEABLE = ["SC-MANIFEST-UNPARSEABLE"];

test("numbers keep Python's kind and digits", () => {
  assert.deepEqual(cmd("'echo', 1.0, 12345678901234567890, -0.0"), ["echo 1.0 12345678901234567890 -0.0"]);
  assert.deepEqual(cmd("1.e5, 01.5, .5, 5., 0_0, 0x_1F, 0o17, 0b101, 1e400, 5e-324"),
    ["100000.0 1.5 0.5 5.0 0 31 15 5 inf 5e-324"]);
  assert.deepEqual(cmd("9999999999999998.0, 1e16, 1e-5, 0.0001"), ["9999999999999998.0 1e+16 1e-05 0.0001"]);
  // JSON: an integer literal of up to 1000 characters is an int, a longer one a float
  const json = scanGyp("binding.gyp", '{"action": [1, -0, 1.0, 2.50, 1E400, ' + "1".repeat(1200) + "]}");
  assert.deepEqual(json.map((i) => i.cmd), ["1 0 1.0 2.5 inf inf"]);
});

test("a long int is exact, and past 4300 digits (where str() refuses) shown in hex", () => {
  assert.deepEqual(cmd("1".repeat(4300)), ["1".repeat(4300)]);
  assert.deepEqual(cmd("-0x" + "f".repeat(5000)), ["-0x" + "f".repeat(5000)]);
  assert.deepEqual(cmd("1".repeat(4301)), UNPARSEABLE);                // Python's parser refuses it
});

test("signs and complex literals as literal_eval takes them", () => {
  assert.deepEqual(cmd("2j, -2j, 1+2j, 1.5-2.5j, -1+2j, (1)+2j, 1+(2j), 0x10+1j, -(1), +1, 1e400+1j"),
    ["2j (-0-2j) (1+2j) (1.5-2.5j) (-1+2j) (1+2j) (1+2j) (16+1j) -1 1 (inf+1j)"]);
  for (const bad of ["--1", "-(-1)", "-+1", "-True", "-(1,)", "1+-2j", "1+2j+3j", "1+2", "2j+1", "True+1j",
    "9".repeat(400) + "+1j", "0_1", "1__0", "1_", "0x", "1e"]) {
    assert.deepEqual(cmd(bad), UNPARSEABLE, bad);
  }
});

const gyp = (text) => scanGyp("binding.gyp", text).map((i) => (i.rule === "SC-INSTALL-HOOK" ? [i.sev, i.cmd] : i.rule));

test("\\N{…} escapes, by name or alias, in any case", () => {
  assert.deepEqual(cmd("'caf\\N{LATIN SMALL LETTER E WITH ACUTE}', '\\N{latin small letter a}', 'x\\N{SP}y', '\\N{NBSP}', '\\N{KELVIN SIGN}'"),
    ["caf\u00e9 a x y \u00a0 \u212a"]);
  assert.deepEqual(gyp("{'action': ['\\N{LATIN SMALL LETTER C}url', 'x']}"), [["CRITICAL", "curl x"]]);
  assert.deepEqual(gyp("{'action': ['ba\\N{LATIN SMALL LETTER LONG S}e64']}"), [["CRITICAL", "ba\u017fe64"]]);
  for (const bad of ["'\\N{}'", "'\\N{ A}'", "'\\N{LATIN  SMALL LETTER A}'", "'\\N'", "'\\N{A'"]) assert.deepEqual(cmd(bad), UNPARSEABLE, bad);
  // a well-formed name outside pynames.js's table is accepted (it may be valid for Python), as U+FFFD
  assert.deepEqual(cmd("'\\N{GREEK SMALL LETTER ALPHA}'"), ["\ufffd"]);
});

test("line breaks, whitespace and NUL as Python's tokenizer reads them", () => {
  assert.deepEqual(cmd("'echo', # c\r 'x'"), ["echo x"]);                    // \r ends a comment
  assert.deepEqual(cmd("'echo',\\\r\n 'x'"), ["echo x"]);                    // continuation over \r\n
  assert.deepEqual(cmd("'''a\r\nb\rc'''"), ["a\nb\nc"]);
  assert.deepEqual(cmd("'a\\\r\nb', r'a\\\r\nb'"), ["ab a\\\nb"]);
  for (const bad of ["'a\rb'", "1,\x0b2", "'a\x00b'"]) assert.deepEqual(cmd(bad), UNPARSEABLE, JSON.stringify(bad));
});

test("bytes, tuples, sets and non-str keys keep their Python kind", () => {
  assert.deepEqual(cmd("b'x', b'a\\'b\"', b'\\777', b'\\t', b'a' rb'\\d'"), ["b'x' b'a\\'b\"' b'\\xff' b'\\t' b'a\\\\d'"]);
  for (const bad of ["b'a' 'b'", "'a' b'b'", "b'\u00e9'", "{[1]: 2}", "{1, [2]}"]) assert.deepEqual(cmd(bad), UNPARSEABLE, bad);
  assert.deepEqual(cmd("(1,), (), {1, 2}, set(), ('a', 'b'), {1: 'a', (2,): b'x'}"),
    ["(1,) () {1, 2} set() ('a', 'b') {1: 'a', (2,): b'x'}"]);
  assert.deepEqual(cmd("{1: 'a', 1.0: 'b', True: 'c'}, {1, 1.0, True, 2}, {-0.0: 1, 0: 2}, {'b': 1, '1': 2, 1: 3}"),
    ["{1: 'c'} {1, 2} {-0.0: 2} {'b': 1, '1': 2, 1: 3}"]);
  assert.deepEqual(gyp("{b'action': ['curl x']}"), []);
  assert.deepEqual(gyp("{('action',): ['curl x']}"), []);
  assert.deepEqual(gyp("{b'<!(curl -s http://192.0.2.1/x)': 1}"), []);
  assert.deepEqual(gyp("{('<!(curl -s http://192.0.2.1/x)',): 1}"), [["CRITICAL", "curl -s http://192.0.2.1/x"]]);
  assert.deepEqual(gyp("{1: {'action': ['echo', 'one']}, '1': {'action': ['echo', 'two']}}"),
    [["MAJOR", "echo one"], ["MAJOR", "echo two"]]);
  assert.deepEqual(gyp('{"b": {"action": ["echo", "b"]}, "1": {"action": ["echo", "1"]}}'), [["MAJOR", "echo b"], ["MAJOR", "echo 1"]]);
});
