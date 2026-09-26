// pyRe() translates Python's Unicode `\b` into lookarounds. Before a literal
// word character (or a group whose every alternative starts with one) the
// boundary can only be a word start, so it is now one lookbehind: the same
// matches, and V8 no longer runs two lookarounds at every position. On a
// string with any non-ASCII character that was the npm engine's main cost:
// npm:pullfrog's 8 MB dist/cli.mjs took 23.7 s in dependency mode (the
// per-file budget is 30 s), now 3.6 s.

import { test } from "node:test";
import assert from "node:assert/strict";
import { pyRe } from "../src/lib/pycompat.js";
import { scanFile } from "../src/index.js";

// The same Python pattern with every \b spelled out, so pyRe() keeps the full
// two-sided boundary: the reference the optimised translation must match.
const PY_BOUNDARY = String.raw`(?:(?<=\w)(?!\w)|(?<!\w)(?=\w))`;
const reference = (src, flags) => pyRe(src.replaceAll(String.raw`\b`, PY_BOUNDARY), flags);

const PATTERNS = [
  String.raw`environ|process\.env|getenv|\bplaceholder\b|\bexample\b|\bdummy\b|\bsample\b|\bmock\b|\bredacted\b|\bxxxx+\b`,
  String.raw`(?:\batob|\bb64decode|\.\s*fromhex|\bunhexlify|\b(?:codecs|__import__\(\s*['"]codecs['"]\s*\))\s*\.\s*decode)\s*\(`,
  String.raw`\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\s*\(`,
  String.raw`\bab`, String.raw`\ba?b`, String.raw`\ba*b`, String.raw`\ba{0,2}b`, String.raw`\b(?:a|b)?c`,
  String.raw`\b(?:a|)b`, String.raw`\b(?:ab|\wc)`, String.raw`\b(?:a[)|]|b)c`, String.raw`\b(?:a|b)+`,
  String.raw`x\b`, String.raw`\b1\b`, String.raw`(?<=\bab)c`, String.raw`\b_x`,
];
const ALPHABET = ["a", "b", "c", "x", "A", "B", "1", "_", "é", "ß", "٣", "→", "😀", " ", ".", "(", ")", "'", "=",
  "atob", "exec", "eval", "mock", "example", "codecs", "Function", "process.env", "xxxxx"];

function* strings() {
  let seed = 7;
  const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31);
  for (let n = 0; n < 400; n++) {
    let s = "";
    for (let k = next() % 12; k >= 0; k--) s += ALPHABET[next() % ALPHABET.length];
    yield s;
  }
}
const matches = (re, s) => [...s.matchAll(re)].map((m) => [m.index, ...m]);

test("the one-lookbehind \\b matches exactly what the two-sided one does", () => {
  for (const src of PATTERNS)
    for (const flags of ["g", "gi"]) {
      const fast = pyRe(src, flags), ref = reference(src, flags);
      for (const s of strings()) assert.deepEqual(matches(fast, s), matches(ref, s), `${src} /${flags} on ${JSON.stringify(s)}`);
    }
});

test("a leading \\b that may match zero characters keeps both sides", () => {
  for (const src of [String.raw`\ba?b`, String.raw`\ba*b`, String.raw`\ba{0,2}b`, String.raw`\b(?:a|b)?c`, String.raw`\b(?:a|)b`, String.raw`\b\w`])
    assert.match(pyRe(src).source, /\(\?=\[/, src);
  for (const src of [String.raw`\batob`, String.raw`\b(?:eval|exec)\s*\(`, String.raw`\b(?:a|b)+`])
    assert.ok(pyRe(src).source.startsWith(String.raw`(?<![\p{L}\p{N}_])` + src.slice(2, 5)), src);
});

test("a 2 MB minified bundle with one non-ASCII character scans quickly", () => {
  const unit = 'var e=function(t,n){return t.exec(n)||o.get(n,"key→")},r=a.b.c;';
  const content = unit.repeat(Math.ceil(2e6 / unit.length)) + "\n";
  const t = Date.now();
  scanFile({ path: "bundle.js", content, lang: "js", dep: true });
  assert.ok(Date.now() - t < 2000, `${Date.now() - t} ms (was about 4,000)`);
});
