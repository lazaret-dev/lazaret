// FP-OPAQUE-MEDIA: a near-random file is a sound, video, image or font when its bytes are that format from start to
// end, and a keystore is a credential file, in the npm package's project scan and --deps, as the Python package reads
// them (python/tests/scanner/test_review_opaque_media.py; the engine's media/, through collect_file and, for a file
// too large to read whole, media_stream). The files the real encoders wrote (tests/fixtures/media), the shapes of
// John's tally (an MP3 that starts at its first frame, Pillow's IM Tools test image, a debug keystore) and keystores
// laid out as keytool writes them, each part in its shape, with random bytes for their keys; the review's bounds of
// Oct 27 (a file cut short as it is read, a payload in a part that walks, a keystore holding more than one does).
// Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/index.js";

const MEDIA = fileURLToPath(new URL("../../tests/fixtures/media/", import.meta.url));
const fixture = (name) => readFileSync(join(MEDIA, name));

/** Seeded bytes, none of them zero. */
function noise(seed, n) {
  let x = (seed * 2654435761) >>> 0 || 1;
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; out[i] = (x % 255) + 1; }
  return out;
}
const appended = (data) => Buffer.concat([data, noise(21, 2048)]);
const glued = (data, n = 6000) => Buffer.concat([data.subarray(0, 64), noise(22, n)]);

/** MPEG-1 Layer III frames from the first byte, no ID3v2 tag (music1.mp3's shape). */
function rawMp3(frames, seed = 1) {
  const parts = [];
  for (let k = 0; k < frames; k++) {
    const pad = k % 3 === 0 ? 1 : 0;
    parts.push(Buffer.from([0xff, 0xfb, 0x90 | (pad << 1), 0x64]), noise(seed + k, 413 + pad));
  }
  return Buffer.concat(parts);
}
const IMT = Buffer.concat([Buffer.from("*comment\nwidth 256\nheight 10\npixel n8\n\x0c", "latin1"),
  Buffer.from(Array.from({ length: 2560 }, (_, i) => i % 256))]);

function der(tag, body) {
  const n = body.length;
  const head = n < 0x80 ? [tag, n] : n < 0x100 ? [tag, 0x81, n] : [tag, 0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from(head), body]);
}
const hex = (h) => Buffer.from(h, "hex");
const seq = (...parts) => der(0x30, Buffer.concat(parts));
const DATA = hex("2a864886f70d010701");
const ENCRYPTED = hex("2a864886f70d010706");
const PBE = hex("2a864886f70d010c0103");
const RSA = seq(der(0x06, hex("2a864886f70d010101")), der(0x05, Buffer.alloc(0)));
const bag = (kind, body) => seq(der(0x06, hex(`2a864886f70d010c0a01${kind.toString(16).padStart(2, "0")}`)), der(0xa0, body));
const pbe = (seed) => seq(der(0x06, PBE), seq(der(0x04, noise(seed, 20)), der(0x02, Buffer.from([8, 0]))));
/** A DER Certificate's shape, its key and signature random bytes. */
function certificate(seed) {
  const name = seq(der(0x31, seq(der(0x06, hex("550403")), der(0x0c, Buffer.from("Lazaret")))));
  const validity = seq(der(0x17, Buffer.from("261021000000Z")), der(0x17, Buffer.from("361021000000Z")));
  const spki = seq(RSA, der(0x03, Buffer.concat([Buffer.from([0]), noise(seed, 270)])));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, noise(seed + 1, 16)), RSA, name, validity, name, spki);
  return seq(tbs, RSA, der(0x03, Buffer.concat([Buffer.from([0]), noise(seed + 2, 256)])));
}
/** An EncryptedPrivateKeyInfo of `n` random bytes. */
const epki = (seed, n) => seq(pbe(seed), der(0x04, noise(seed + 1, n)));
/** A PFX as keytool -genkeypair writes one: a shrouded key bag in the clear part, the certificates encrypted. */
function pkcs12(key = true) {
  const infos = [];
  if (key) infos.push(seq(der(0x06, DATA), der(0xa0, der(0x04, seq(bag(2, epki(7, 1217)))))));
  infos.push(seq(der(0x06, ENCRYPTED), der(0xa0, seq(der(0x02, Buffer.from([0])),
    seq(der(0x06, DATA), pbe(9), der(0x80, noise(10, 900)))))));
  const ci = seq(der(0x06, DATA), der(0xa0, der(0x04, seq(...infos))));
  return seq(der(0x02, Buffer.from([3])), ci, der(0x30, noise(11, 75)));
}
const utf = (s) => { const b = Buffer.from(s); const n = Buffer.alloc(2); n.writeUInt16BE(b.length); return Buffer.concat([n, b]); };
const int = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
const blob = (b) => Buffer.concat([int(b.length), b]);
const cert = (seed) => Buffer.concat([utf("X.509"), blob(certificate(seed))]);
/** A JKS keystore: a private key entry (its protected key `n` bytes) and a trusted certificate, then the digest. */
function jks(withKey = true, n = 1230) {
  const entries = [];
  if (withKey) entries.push(Buffer.concat([int(1), utf("key"), Buffer.alloc(8), blob(epki(12, n)), int(1), cert(13)]));
  entries.push(Buffer.concat([int(2), utf("ca"), Buffer.alloc(8), cert(14)]));
  return Buffer.concat([hex("feedfeed"), int(2), int(entries.length), ...entries, noise(15, 20)]);
}

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-media-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, ...rel.split("/"));
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}
function scan(files, extra = []) {
  const d = tree({ "app.js": "1;\n", ...files });     // (a tree of media alone is nothing to scan)
  try {
    const err = [];
    const code = run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: (s) => err.push(s) });
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    return { code, err: err.join("\n"), issues };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const found = (issues) => issues.filter((i) => i.rule.startsWith("SC-") || i.rule === "S-SECRET")
  .map((i) => [i.file.replaceAll("\\", "/"), i.rule, i.sev]).sort();

test("the tally's three files: audio, an image, a credential file", () => {
  const r = scan({ "music/music1.mp3": rawMp3(60), "Tests/images/bw_gradient.imt": IMT,
    "signing/tiles-foss-debug.pkcs12": pkcs12() });
  assert.deepEqual(found(r.issues), [["signing/tiles-foss-debug.pkcs12", "S-SECRET", "BLOCKER"]]);
});

test("the encoders' files are quiet, whatever their names", () => {
  const files = {};
  readdirSync(MEDIA).filter((n) => n !== "MANIFEST" && n !== "README.md").forEach((n, k) => {
    files[`assets/${n}`] = fixture(n);
    files[`blobs/b${k}.bin`] = fixture(n);
  });
  assert.deepEqual(found(scan(files).issues), []);
});

test("bytes the structure does not hold keep a file opaque", () => {
  const files = {};
  for (const n of ["noise.png", "noise.jpg", "noise-raw.mp3", "noise.m4a", "signal.wav", "noise.woff2"]) {
    // (a JPEG's first 512 bytes, its tables, are not near-random: the project scan's sample, so a payload after one
    // is not looked at, before as now)
    if (n !== "noise.jpg") files[`a/${n}`] = appended(fixture(n));
    files[`g/${n}`] = glued(fixture(n));
  }
  files["a/keystore.p12"] = appended(pkcs12());
  const r = scan(files);
  assert.deepEqual(found(r.issues), Object.keys(files).sort().map((f) => [f, "SC-OPAQUE-BLOB", "MAJOR"]));
  assert.ok(r.issues.some((i) => i.file.endsWith("noise.png") && i.msg.includes("read as PNG image, it is not one to its end")));
});

test("keystores by what they hold", () => {
  const r = scan({ "k/release.jks": jks(), "k/cacerts": jks(false), "k/trust.p12": pkcs12(false) });
  assert.deepEqual(found(r.issues), [["k/cacerts", "S-SECRET", "INFO"], ["k/release.jks", "S-SECRET", "BLOCKER"],
    ["k/trust.p12", "S-SECRET", "MAJOR"]]);
});

test("a file over the size limit is walked as it is read", () => {
  const big = rawMp3(60);
  const r = scan({ "m/long.mp3": big, "m/long.m4a": fixture("noise.m4a"), "m/bad.mp3": appended(big),
    "m/glued.mp3": glued(big, 20000) }, ["--max-source-bytes", "4096"]);
  assert.deepEqual(found(r.issues), [["m/bad.mp3", "SC-OPAQUE-BLOB", "MAJOR"], ["m/glued.mp3", "SC-OPAQUE-BLOB", "MAJOR"]]);
});

test("the review's bounds: cut short as it is read, a payload in a part that walks, a keystore too large", () => {
  const ftyp = Buffer.concat([int(24), Buffer.from("ftypisom"), hex("00000200"), Buffer.from("isomiso2")]);
  const claims = Buffer.concat([ftyp, int(1 << 30), Buffer.from("mdat"), noise(30, 20000)]);
  const pnm = Buffer.concat([Buffer.from("P5\n100 100\n255\n"), noise(33, 10000)]);
  const free = Buffer.concat([int(8), Buffer.from("free"), int(0), Buffer.from("mdat"), noise(34, 16000)]);
  const files = { "v/claims.mp4": claims, "p/pnm.bin": pnm, "p/free.mp4": free, "k/big.jks": jks(true, 20000) };
  for (const extra of [[], ["--max-source-bytes", "4096"]]) {
    const r = scan(files, extra);
    // (a keystore over the size limit is not read whole: judged by its first bytes, an opaque blob)
    const keystore = extra.length ? [] : [["k/big.jks", "S-SECRET", "BLOCKER"]];
    assert.deepEqual(found(r.issues), [...keystore, ["k/big.jks", "SC-OPAQUE-BLOB", "MAJOR"],
      ["p/free.mp4", "SC-OPAQUE-BLOB", "MAJOR"], ["p/pnm.bin", "SC-OPAQUE-BLOB", "MAJOR"],
      ["v/claims.mp4", "SC-OPAQUE-BLOB", "MAJOR"]], extra.join(" "));
    assert.ok(r.issues.some((i) => i.file.endsWith("claims.mp4") && i.msg.includes("cut short")));
  }
});

test("--deps: a dependency's media, keystore and payload", () => {
  const files = { "app.js": "require('pkg')\n", "package.json": '{"dependencies": {"pkg": "1.0.0"}}',
    "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}', "node_modules/pkg/index.js": "module.exports = 1\n",
    "node_modules/pkg/sounds/beep.mp3": rawMp3(20), "node_modules/pkg/fonts/icons.woff2": fixture("noise.woff2"),
    "node_modules/pkg/android/debug.keystore": jks(), "node_modules/pkg/data/payload.png": glued(fixture("noise.png")) };
  assert.deepEqual(found(scan(files, ["--deps"]).issues), [
    ["node_modules/pkg/android/debug.keystore", "S-SECRET", "BLOCKER"],
    ["node_modules/pkg/data/payload.png", "SC-OPAQUE-BLOB", "MAJOR"]]);
});
