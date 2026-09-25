// Review regressions: terminal escape-sequence injection (review finding
// 13). File names, messages and excerpts come from the scanned tree; every
// one of them is printed through sanitizeTerm/safeExcerpt ('·' for control
// characters, as the Python engine's sanitize_term / safe_excerpt).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, sanitizeTerm, safeExcerpt } from "../src/index.js";

const ESC = "\x1b", BEL = "\x07";
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;   // everything but TAB/LF

test("sanitizeTerm / safeExcerpt map control characters to '·'", () => {
  assert.equal(sanitizeTerm(`a${ESC}]0;PWNED${BEL}b${ESC}[2J\r\n\tz`), "a·]0;PWNED·b·[2J·\n\tz");
  assert.equal(sanitizeTerm("x\x7fy\x00z"), "x·y·z");
  assert.equal(safeExcerpt(`\t eval("${ESC}[31m") \t`), 'eval("·[31m")');
  assert.equal(safeExcerpt("abcdef", 3), "abc…");
});

test("hostile file names, messages and excerpts never reach the terminal raw", { skip: process.platform === "win32" }, () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-term-"));
  try {
    writeFileSync(join(d, `a${ESC}]0;PWNED${BEL}${ESC}[2Jb.js`), `eval("${ESC}[31mred")\n`);
    writeFileSync(join(d, "package.json"),
      JSON.stringify({ scripts: { postinstall: `node x.js ${ESC}]0;title${BEL}` } }));
    const out = [], err = [];
    const code = run(["check", d, "--no-json", "--no-html"], { out: (s) => out.push(s), err: (s) => err.push(s), env: {} });
    assert.equal(code, 0, err.join("\n"));
    const text = out.join("\n");
    assert.doesNotMatch(text, CONTROL);
    assert.match(text, /a·\]0;PWNED··\[2Jb\.js:1/);                        // the file name
    assert.match(text, /eval\("·\[31mred"\)/);                            // the excerpt
    assert.ok(text.includes(String.raw`'node x.js \x1b]0;title\x07'`));      // the hook message (Python repr)
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("error messages that echo user input are sanitized too", () => {
  const err = [];
  const code = run([`no-such-${ESC}[2J-dir`], { out: () => {}, err: (s) => err.push(s), env: {} });
  assert.equal(code, 2);
  assert.doesNotMatch(err.join("\n"), CONTROL);
  assert.match(err.join("\n"), /no-such-·\[2J-dir/);
});
