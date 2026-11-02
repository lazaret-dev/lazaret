// Review regression: a report too big for one string. V8 caps a string at
// about 2^29 characters and the engine rendered each report with a single
// JSON.stringify, so a scan with about a million findings (an 8 MB file of
// `eval(a)` lines) ended with "could not write a report: Invalid string
// length", exit 3 and no report, where the Python engine wrote it. Reports
// are made and written in pieces: the engine's frame, then the findings a
// batch at a time (report.rs; the forms are held to the Python package's,
// byte for byte, by tests/architecture/test_report_engine.py).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, openSync, readSync, closeSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanFile } from "../src/scanner/scan.js";
import {
  buildResult, jsonRenderer, jsonReportChunks, htmlRenderer, htmlReportChunks, sarifReport, sarifRenderer, sarifChunks,
  reportTextChunks,
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

test("each form is made in pieces: a frame, then the findings a batch at a time", () => {
  const [one] = scanFile({ name: "a.js", path: "a.js", content: "eval(a)\n", lang: "js" });
  const res = buildResult("/proj", [], [one]);
  res.issues = Array.from({ length: 4500 }, (_, k) => ({ ...one, line: k + 1 }));
  for (const [chunks, whole] of [[jsonReportChunks(res), jsonRenderer(res)], [htmlReportChunks(res), htmlRenderer(res)],
    [sarifChunks(res, "/proj"), sarifRenderer(res, "/proj")], [reportTextChunks(res), null]]) {
    const pieces = [...chunks];
    assert.ok(pieces.length >= 5, String(pieces.length));                        // a frame's two, three batches
    assert.ok(Math.max(...pieces.map((p) => p.length)) < pieces.join("").length / 2);
    if (whole !== null) assert.equal(pieces.join(""), whole);
  }
  const json = JSON.parse(jsonRenderer(res, { key: "k" }));
  assert.deepEqual(Object.keys(json).slice(0, 3), ["generatedBy", "baselineSignature", "project"]);
  assert.equal(json.issues.length, 4500);
  assert.ok(htmlRenderer(res).includes(`\n${HTML_ENGINE_MARKER}\n<meta name="viewport"`));
  assert.equal(sarifReport(res, "/proj").runs[0].results.length, 4500);
  assert.ok(!("properties" in sarifReport(res, "/proj")));
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
