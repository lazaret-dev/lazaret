// The analyst's smaller gaps (twin of python/tests/scanner/test_review_small_gaps.py):
// .mts / .cts TypeScript sources (read without JSX; a camera's .mts video is
// media), .jsc V8 bytecode is a compiled artifact, __import__("os").system is
// S-OSCMD-PY, and a dangerous name hidden in fewer than eight escapes is
// SC-HEXSTR. Fixtures are inert text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, scanFile } from "../src/index.js";
import { jsxReading } from "../src/lib/lexer.js";
import { EXTS } from "../src/lib/fs.js";

/** The name SC-HEXSTR says a line's escapes hide, else null (core.hex_hidden_name, as its message shows it). */
const hexHiddenName = (line) => {
  const found = scanFile({ name: "f.py", content: line + "\n", lang: "py" })
    .find((i) => i.rule === "SC-HEXSTR" && i.msg.startsWith("Escape sequences hide a name: "));
  return found ? found.msg.slice("Escape sequences hide a name: ".length + 1, -2) : null;
};

// an MPEG transport stream: a sync byte (0x47) every 188 bytes
const VIDEO = Buffer.concat(Array.from({ length: 40 }, (_, k) =>
  Buffer.from([0x47, ...Array.from({ length: 187 }, (_, n) => (k * 7 + n) % 256)])));
const FILES = {
  "src/a.mts": "const el = <HTMLInputElement>document.body;\n// eval(z)\neval(atob(p));\n",
  "src/b.cts": "const cp = require('child_process');\ncp.exec(process.argv[2]);\n",
  "media/clip.mts": VIDEO,
  "media/clip.ts": VIDEO,
  "dist/app.jsc": Buffer.from("\x00\x01bytenode\x02".repeat(10), "latin1"),
  "tool.py": "__import__('os').system(input())\nimportlib.import_module('os').popen(cmd)\n",
  "hide.js": 'var m = global["\\x72\\x65\\x71\\x75\\x69\\x72\\x65"]("child_process");\n' +
    'var u = "https:\\u002F\\u002Fexample.invalid";\n' + 'var b = "\\x00\\x01\\x65val";\n',
};

function scan(...extra) {
  const root = mkdtempSync(join(tmpdir(), "lz-gaps-"));
  const out = mkdtempSync(join(tmpdir(), "lz-gaps-out-"));
  try {
    for (const [rel, data] of Object.entries(FILES)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    }
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...extra], { out: () => {}, err: () => {}, env: {} });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
}
const key = (i) => `${i.rule} ${i.file.replaceAll("\\", "/")} ${i.line}`;

test("project: .mts/.cts sources, videos, .jsc, inline os import, hidden names", () => {
  const rep = scan();
  const found = new Set(rep.issues.map(key));
  for (const want of ["S-EVAL-JS src/a.mts 3", "SC-EVAL-DECODE src/a.mts 3", "T-CMD src/b.cts 2",
    "S-OSCMD-PY tool.py 1", "S-OSCMD-PY tool.py 2", "SC-BINARY dist/app.jsc 1", "SC-HEXSTR hide.js 1"]) {
    assert.ok(found.has(want), want);
  }
  assert.ok(!found.has("S-EVAL-JS src/a.mts 2"));                       // a comment, read without JSX
  assert.ok(![...found].some((k) => k.includes("media/")), [...found].join("; "));
  assert.equal(rep.metrics.files, 4);
  const hex = rep.issues.filter((i) => i.rule === "SC-HEXSTR");
  assert.deepEqual(hex.map((i) => [i.line, i.sev, i.msg]), [[1, "CRITICAL", "Escape sequences hide a name: 'require'."]]);
  const jsc = rep.issues.find((i) => i.file.replaceAll("\\", "/") === "dist/app.jsc");
  assert.equal(jsc.msg, "Executable/compiled binary in the source tree: compiled artifact (.jsc).");
  const small = scan("--max-source-bytes", "1000");                     // a big video is not SC-TRUNCATED
  assert.ok(!small.issues.some((i) => i.file.replaceAll("\\", "/").startsWith("media/")));
});

test("the tables", () => {
  assert.equal(EXTS[".mts"], "js");
  assert.equal(EXTS[".cts"], "js");
  assert.equal(jsxReading("x.MTS") || jsxReading("x.cts"), false);
});

test("names hidden in a few escapes", () => {
  const cases = [
    [String.raw`x = "\x65val"`, ["eval", 5]], [String.raw`x = "sy\x73tem"`, ["system", 7]], [String.raw`s = '\145val'`, ["eval", 5]],
    [String.raw`w["\u{65}v\u0061l"](x)`, ["eval", 3]], [String.raw`p = "\U00000065xec"`, ["exec", 5]],
    [String.raw`k = "\x5f_import__"`, ["__import__", 5]], [String.raw`x = "\\\x65val"`, ["eval", 7]],
    [String.raw`a = '\x00\x00\x00'; b = '\x65val'`, ["eval", 25]],
    [String.raw`x = "\\x65val"`, null], [String.raw`u = "https:\u002F\u002Fexample.invalid"`, null], [String.raw`u = "\u0068ttps://example.invalid"`, ["https://", 5]],
    [String.raw`b = b"\x00\x01\x65val"`, null], [String.raw`x = "\x41PI system"`, null], [String.raw`x = "e\x76al_thing"`, null],
    [String.raw`x = "\x65"; y = "val"`, null], [String.raw`x = "a\x2fb"`, null], [String.raw`\x65val`, null],
  ];
  for (const [line, want] of cases) assert.deepEqual(hexHiddenName(line), want && want[0], line);
  const eight = String.raw`x = "\x65\x76\x61\x6c\x28\x61\x74\x6f"`;
  const hex = scanFile({ path: "x.js", content: eight + "\n", lang: "js" }).filter((i) => i.rule === "SC-HEXSTR");
  assert.deepEqual(hex.map((i) => i.msg), ["Hex escapes hide readable text: 'eval(ato'."]);
});
