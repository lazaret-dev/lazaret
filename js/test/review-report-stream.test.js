// Review regression: a report too big for one string. V8 caps a string at
// about 2^29 characters and the engine rendered each report with a single
// JSON.stringify, so a scan with about a million findings (an 8 MB file of
// `eval(a)` lines) ended with "could not write a report: Invalid string
// length", exit 3 and no report, where the Python engine wrote it. Reports
// are rendered and written in pieces now; the text is exactly what
// JSON.stringify(…, null, 2) gave before.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, openSync, readSync, closeSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanFile } from "../src/scanner/scan.js";
import {
  buildResult, jsonChunks, jsonRenderer, jsonReportChunks, htmlRenderer, htmlReportChunks,
  sarifReport, sarifRenderer, sarifChunks,
} from "../src/report.js";
import { writeReport, HTML_ENGINE_MARKER } from "../src/lib/fs.js";

function withDir(fn) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-stream-"));
  try { return fn(d); } finally { rmSync(d, { recursive: true, force: true }); }
}
function edges(path, n) {
  const size = statSync(path).size, fd = openSync(path, "r");
  try {
    const head = Buffer.alloc(n), tail = Buffer.alloc(n);
    readSync(fd, head, 0, n, 0);
    readSync(fd, tail, 0, n, size - n);
    return { size, head: head.toString("utf8"), tail: tail.toString("utf8") };
  } finally { closeSync(fd); }
}
function sampleResult() {
  const files = [
    ["a.py", "import os\nos.system(cmd)\nx = eval(input())  # café \u{1f600}\n"],
    ["b.js", "eval(a)\nconst s = '<b>\"&amp;\\'</b>';\neval(s)\n"],
    ["c.sql", "GRANT ALL ON t TO u;\n"],
  ];
  const issues = files.flatMap(([name, content]) =>
    scanFile({ name, path: name, content, lang: name.split(".").pop() === "py" ? "py" : name.endsWith(".sql") ? "sql" : "js" }));
  return buildResult("/proj", files.map(([name, content]) => ({ name, path: name, content, lang: "py" })), issues);
}

test("jsonChunks is JSON.stringify(value, null, 2), in pieces", () => {
  let seed = 7;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const leaf = () => pick([undefined, () => 1, Symbol("s"), null, true, false, 0, -0, 1.5, 1e21, NaN, -Infinity,
    new Date(0), new Number(5), new String("x\ny"), JSON.rawJSON("0.0"), "", "a\nb", " ", "\ud800", "é😀", '"\\', "\x00"]);
  const gen = (d) => {
    if (d <= 0 || rnd() < 0.3) return leaf();
    if (rnd() < 0.5) {
      const a = Array.from({ length: Math.floor(rnd() * 4) }, () => gen(d - 1));
      if (rnd() < 0.1) a.length += 2;                                   // holes
      return a;
    }
    const o = rnd() < 0.2 ? Object.create(null) : {};
    for (let k = Math.floor(rnd() * 4); k > 0; k--) o[pick(["a", "1", "0", "b c", "é", "10", "k" + k])] = gen(d - 1);
    if (rnd() < 0.1) Object.defineProperty(o, "__proto__", { value: gen(d - 1), enumerable: true, writable: true, configurable: true });
    if (rnd() < 0.1) Object.defineProperty(o, "hidden", { value: 1, enumerable: false });
    return o;
  };
  for (let t = 0; t < 3000; t++) {
    const v = gen(5);
    const want = JSON.stringify(v, null, 2) ?? "";
    for (const depth of [0, 1, 2, 3, 6]) assert.equal([...jsonChunks(v, depth)].join(""), want);
  }
});

test("the report renderers' text is what JSON.stringify gave", () => {
  const res = sampleResult();
  assert.ok(res.issues.length >= 4);
  // dupPct is written as the Python float it is there (review-parity-misc)
  const metrics = { ...res.metrics, dupPct: JSON.rawJSON(res.metrics.dupPct.toFixed(1)) };
  const out = (extra = {}) => ({ generatedBy: "lazaret-cli-1", ...extra, ...res, metrics });
  assert.equal(jsonRenderer(res), JSON.stringify(out(), null, 2));
  const signed = jsonRenderer(res, { key: "k" });
  const sig = JSON.parse(signed).baselineSignature;
  assert.equal(signed, JSON.stringify(out({ baselineSignature: sig }), null, 2));
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  assert.equal(htmlRenderer(res), `<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n${HTML_ENGINE_MARKER}\n` +
    `<title>Lazaret report</title></head>\n<body><pre>${esc(JSON.stringify(out(), null, 2))}</pre></body></html>\n`);
  const sarif = sarifReport(res, "/proj");
  assert.equal(sarifRenderer(sarif), JSON.stringify({ properties: { generatedBy: "lazaret-cli-1" }, ...sarif }, null, 2));
  // one piece per finding (plus a few): nothing is rendered as one big string
  for (const pieces of [[...jsonReportChunks(res)], [...htmlReportChunks(res)], [...sarifChunks(sarif)]]) {
    assert.ok(pieces.length > res.issues.length);
    assert.ok(Math.max(...pieces.map((p) => p.length)) < 4096);
  }
});

test("writeReport writes an iterable of strings, a surrogate pair split across pieces intact", () => withDir((d) => {
  const pieces = ["a".repeat((1 << 20) - 1) + "\ud83d", "\ude00", "b", "é"];
  writeReport(join(d, "r.json"), () => pieces[Symbol.iterator](), { kind: "json" });
  assert.deepEqual(readFileSync(join(d, "r.json")), Buffer.from(pieces.join(""), "utf8"));
}));

test("a report too big for one string is written", () => withDir((d) => {
  const [one] = scanFile({ name: "a.js", path: "a.js", content: "eval(a)\n", lang: "js" });
  const res = buildResult("/p", [], [one]);
  res.issues = new Array(2100).fill({ ...one, msg: "m".repeat(1 << 18) });   // ~550M characters of JSON
  writeReport(join(d, "lazaret-report.json"), () => jsonReportChunks(res), { kind: "json" });
  const { size, head, tail } = edges(join(d, "lazaret-report.json"), 40);
  assert.ok(size > 2 ** 29, String(size));
  assert.equal(head, '{\n  "generatedBy": "lazaret-cli-1",\n  "p');
  assert.equal(tail, '     ],\n      "snipStart": 1\n    }\n  ]\n}');
}));
