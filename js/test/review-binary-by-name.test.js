// FP-BINARY-BY-NAME: a file is a compiled binary by its bytes, not its name, in the npm package's project scan and
// --deps, as the Python package reads it (python/tests/scanner/test_review_binary_by_name.py). John's corrected
// fp-tally: a text Dockerfile named `Dockerfile.node` was SC-BINARY, "compiled artifact (.node)". Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";

const DOCKERFILE = 'FROM node:22-slim\nWORKDIR /sandbox\nCOPY . .\nUSER node\nCMD ["node", "index.js"]\n';
const filler = (n, seed = 7) => {
  let x = seed;
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; out[i] = (x >> 16) & 0xff; }
  return out;
};
const u32le = (...v) => { const b = Buffer.alloc(4 * v.length); v.forEach((x, k) => b.writeUInt32LE(x >>> 0, 4 * k)); return b; };
const u32be = (...v) => { const b = Buffer.alloc(4 * v.length); v.forEach((x, k) => b.writeUInt32BE(x >>> 0, 4 * k)); return b; };
const elf = Buffer.concat([Buffer.from("7f454c46020101", "hex"), Buffer.alloc(9), Buffer.from([3, 0, 62, 0]), filler(2000)]);
const machoObject = Buffer.concat([u32le(0xfeedfacf, 0x0100000c, 0, 1, 0, 0, 0, 0), filler(2000, 8)]);
const machoFat = Buffer.concat([u32be(0xcafebabe, 2, 0x01000007, 3, 4096, 2000, 12), Buffer.alloc(40), filler(2000, 9)]);
const javaClass = Buffer.concat([Buffer.from("cafebabe0000003d0014", "hex"), filler(600, 10)]);

function scan(files, extra = []) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-binname-"));
  try {
    for (const [rel, data] of Object.entries({ "app.js": "1;\n", ...files })) {
      const p = join(d, ...rel.split("/"));
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    }
    run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: () => {} });
    return JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const binaries = (r) => r.issues.filter((i) => i.rule === "SC-BINARY")
  .map((i) => [i.file.replaceAll("\\", "/"), i.sev, i.msg.split(": ").slice(1).join(": ")]).sort();

test("a Dockerfile named .node is a Dockerfile; text under a compiled name is text", () => {
  const r = scan({ "examples/sandbox/Dockerfile.node": DOCKERFILE, "lib/libc.so": "/* GNU ld script */\nGROUP ( libc.so.6 )\n",
    "x/mod.dex": "dex\nnot a dex file\n", "src/Main.class": "class Main {}\n" });
  assert.deepEqual(binaries(r), []);
  assert.equal(r.metrics.configFiles, 1);
});

test("compiled code by its bytes, whatever its name", () => {
  const files = { "build/addon.node": elf, "out/CFNetwork-2ABC.pcm": machoObject, "bin/tool": machoFat,
    "classes/Main.class": javaClass, "data/blob.node": filler(3000, 3) };
  assert.deepEqual(binaries(scan(files)), [
    ["bin/tool", "MAJOR", "Mach-O universal binary (macOS)."],
    ["build/addon.node", "MAJOR", "ELF binary (Linux/Unix executable or shared object)."],
    ["classes/Main.class", "MAJOR", "Java .class bytecode."],
    ["data/blob.node", "MAJOR", "compiled artifact (.node)."],
    ["out/CFNetwork-2ABC.pcm", "MAJOR", "Mach-O 64-bit binary (macOS)."]]);
});

test("the whole file: a jar after a launch script keeps SC-BINARY; a document by its container's bytes", () => {
  const launcher = Buffer.from(Array.from({ length: 60 }, (_, k) => `# line ${k}: a launch script\n`).join(""));
  const zip = Buffer.concat([Buffer.from("504b0304140000000000", "hex"), filler(600, 12)]);   // (a local header: NULs)
  const r = scan({ "app/app.jar": Buffer.concat([launcher, zip]), "lib/mod.node": Buffer.concat([launcher, elf]),
    "doc/random.docx": filler(8000, 21) });
  assert.deepEqual(binaries(r), [["app/app.jar", "MAJOR", "compiled artifact (.jar)."],
    ["lib/mod.node", "MAJOR", "compiled artifact (.node)."]]);
  assert.ok(r.issues.some((i) => i.file.endsWith("random.docx") && i.rule === "SC-OPAQUE-BLOB"));
});

test("--deps: a dependency's", () => {
  const files = { "package.json": '{"dependencies": {"pkg": "1.0.0"}}', "app.js": "require('pkg')\n",
    "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}', "node_modules/pkg/index.js": "module.exports = 1\n",
    "node_modules/pkg/Dockerfile.node": DOCKERFILE, "node_modules/pkg/build/addon.node": elf };
  assert.deepEqual(binaries(scan(files, ["--deps"])).map((x) => x[0]), ["node_modules/pkg/build/addon.node"]);
});
