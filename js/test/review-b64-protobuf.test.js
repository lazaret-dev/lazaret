// FP-B64-PROTOBUF: a protobuf file's descriptor that protoc-gen-es embeds as base64 and hands to its runtime's loader
// (`fileDesc("…")` from @bufbuild/protobuf/codegenv2 or codegenv1) is not SC-B64 in the npm package's project scan and
// --deps when generated code alone uses it, as in the Python package's (python/tests/scanner/
// test_review_b64_protobuf.py; the engine's protodesc/usage.rs, asked over the whole scan: scancollection.js
// b64DescriptorPass). Base64 that is not such a descriptor, a descriptor that carries free text, one anything else
// could read back, or one handed to a loader the project remaps, is SC-B64 as before (the review of Oct 27, B-1 to
// B-3: its shapes, each with its control). The generated files are python/tests/fixtures/protobuf_es's
// (scripts/make_protobuf_fixtures.py); the other descriptors are made here, and every payload stand-in is inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/index.js";

const GEN = fileURLToPath(new URL("../../python/tests/fixtures/protobuf_es/gen/", import.meta.url));
const read = (rel) => readFileSync(join(GEN, ...rel.split("/")), "utf8");
const LT = read("ts/listentogether/v1/listentogether_pb.ts");
const DESC = /fileDesc\("([A-Za-z0-9+/]+)"/.exec(LT)[1];
const IMPORT = 'import { fileDesc } from "@bufbuild/protobuf/codegenv2";\n';
const CODE = Buffer.from([...Array(8).keys()].map((k) => `console.log('a stand-in for a payload, inert: ${k}');\n`).join(""))
  .toString("base64");
const PKG = '{"name": "x", "version": "1.0.0", "main": "index.js"}\n';

function walk(dir) {
  const out = {};
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) Object.assign(out, walk(p));
    else out[relative(GEN, p).replaceAll("\\", "/")] = readFileSync(p, "utf8");
  }
  return out;
}

function scan(files, extra = []) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-pb-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const p = join(d, ...rel.split("/"));
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    }
    const code = run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: () => {} });
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    return { code, issues };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const b64 = (issues) => issues.filter((i) => i.rule === "SC-B64").map((i) => [i.file.replaceAll("\\", "/"), i.line]).sort();

test("the tally case and every form protoc-gen-es writes are quiet", () => {
  const gen = walk(GEN);
  assert.equal(Object.keys(gen).length, 21);
  const files = { "package.json": PKG, "worker/src/gen/listentogether_pb.ts": LT };
  for (const [rel, text] of Object.entries(gen)) files[`gen/${rel}`] = text;
  const r = scan(files);
  assert.deepEqual(b64(r.issues), []);
  assert.equal(r.code, 0);
});

test("base64 that is not a descriptor, or goes anywhere else, keeps SC-B64", () => {
  const r = scan({
    "package.json": PKG,
    "gen/a_pb.ts": IMPORT + `export const f = fileDesc("${CODE}");\n`,
    "gen/b.js": `eval(atob("${DESC}"));\n`,
    "gen/c_pb.js": `function fileDesc(s) { return eval(atob(s)); }\nexport const f = fileDesc("${DESC}");\n`,
    "gen/d_pb.ts": `import { fileDesc } from "./codegenv2";\nexport const f = fileDesc("${DESC}");\n`,
    "gen/e_pb.js": 'const cg = require("@bufbuild/protobuf/codegenv2");\ncg.fileDesc = (s) => eval(atob(s));\n'
      + `exports.f = (0, cg.fileDesc)("${DESC}");\n`,
    "gen/f_pb.ts": IMPORT + `export const f = fileDesc("${DESC}" + tail);\n`,
  });
  assert.deepEqual(b64(r.issues), [["gen/a_pb.ts", 2], ["gen/b.js", 1], ["gen/c_pb.js", 2], ["gen/d_pb.ts", 2],
    ["gen/e_pb.js", 3], ["gen/f_pb.ts", 2]]);
});

test("--deps: a dependency's generated files are quiet, its other base64 is not", () => {
  const r = scan({
    "package.json": PKG, "index.js": "1;\n",
    "node_modules/pb/package.json": '{"name": "pb", "version": "1.0.0"}\n',
    "node_modules/pb/gen/listentogether_pb.js": read("js/listentogether/v1/listentogether_pb.js"),
    "node_modules/pb/gen/settings_pb.js": read("cjs/legacy/settings_pb.js"),
    "node_modules/pb/gen/bad_pb.js": IMPORT + `export const f = fileDesc("${CODE}");\n`,
  }, ["--deps"]);
  assert.deepEqual(b64(r.issues), [["node_modules/pb/gen/bad_pb.js", 2]]);
});

// ---- the review of Oct 27: a protobuf writer (made-up descriptors), and its shapes with their controls ----

const varint = (n) => { const out = []; for (;;) { const b = n & 0x7f; n = Math.floor(n / 128); if (n) out.push(b | 0x80); else { out.push(b); return out; } } };
const fld = (num, data) => [...varint(num * 8 + 2), ...varint(data.length), ...data];
const ifld = (num, v) => [...varint(num * 8), ...varint(v)];
const utf = (s) => [...Buffer.from(s, "utf8")];
const fieldDesc = (name, number, extra = []) => [...fld(1, utf(name)), ...ifld(3, number), ...ifld(4, 1), ...ifld(5, 5), ...extra];
const message = (name, fields) => [...fld(1, utf(name)), ...fields.flatMap((f) => fld(2, f))];
const msgs4 = (extra = () => []) => [0, 1, 2, 3].map((k) => message(`M${k}`, [0, 1, 2, 3, 4, 5].map((j) => fieldDesc(`field_${j}`, j + 1, extra(j)))));
function fileDesc({ name = "app/v1/app.proto", msgs = msgs4(), options = null, sourceInfo = null } = {}) {
  let out = [...fld(1, utf(name)), ...fld(2, utf("app.v1")), ...msgs.flatMap((m) => fld(4, m))];
  if (options) out = [...out, ...fld(8, options)];
  if (sourceInfo) out = [...out, ...fld(9, sourceInfo)];
  return [...out, ...fld(12, utf("proto3"))];
}
const enc = (bytes) => Buffer.from(bytes).toString("base64").replace(/=+$/, "");
const MARKER = "INERT-MARKER-TEXT ".repeat(40);
const PLAIN = enc(fileDesc());
const WITH_TEXT = enc(fileDesc({ sourceInfo: fld(1, fld(3, utf(MARKER))) }));
const WITH_OPT = enc(fileDesc({ options: fld(50000, [...Array(1024).keys()].map((i) => i % 256)) }));
const WITH_JSON_NAME = enc(fileDesc({ msgs: msgs4((j) => fld(10, utf(`f${j}`))) }));
const GEN_IMPORT = 'import { fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv2";\n';
const app = (desc = PLAIN, tail = "") => GEN_IMPORT + `export const file_app = /*@__PURE__*/\n  fileDesc("${desc}");\n`
  + "export const M0Schema = /*@__PURE__*/\n  messageDesc(file_app, 0);\n" + tail;
const USER = 'import { create } from "@bufbuild/protobuf";\nimport { M0Schema } from "../gen/app_pb";\nexport const m = create(M0Schema);\n';
const kept = (files, path = "gen/app_pb.ts", extra = []) => b64(scan(files, extra).issues).some(([f]) => f === path);

test("B-1: what a descriptor carries; its control", () => {
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_OPT), "src/use.ts": USER }), false);
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_TEXT) }), true);
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_JSON_NAME) }), true);
});

test("B-1: the descriptor read back, in its file or another; their controls", () => {
  const back = "const text = file_app.proto.sourceCodeInfo.location[0].leadingComments;\n";
  for (const tail of ["console.log(file_app.proto);\n", `${back}eval(text);\n`, `${back}new Function(text)();\n`,
    `import { execSync } from "node:child_process";\n${back}execSync(text);\n`,
    `import vm from "node:vm";\n${back}vm.runInThisContext(text);\n`]) {
    assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_OPT, tail) }), true, tail);
  }
  const other = 'import { file_app } from "../gen/app_pb";\nimport { writeFileSync } from "node:fs";\n'
    + 'writeFileSync("/tmp/out.bin", file_app.proto.options.$unknown[0].data);\n';
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_OPT), "src/use.ts": other }), true);
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_OPT),
    "src/App.vue": '<template><pre>{{ file_app.proto }}</pre></template>\n<script setup>import { file_app } from "../gen/app_pb";</script>\n' }), true);
  assert.equal(kept({ "package.json": PKG, "gen/app_pb.ts": app(WITH_OPT),
    "src/App.vue": '<template><p>{{ m.name }}</p></template>\n<script setup>import { M0Schema } from "../gen/app_pb";</script>\n' }), false);
  // the same string twice: the other use keeps it
  assert.deepEqual(b64(scan({ "package.json": PKG, "gen/app_pb.ts": app(), "src/other.ts": `export const again = atob("${PLAIN}");\n` }).issues),
    [["src/other.ts", 1]]);
});

test("B-3: the loader remapped by the project; its control", () => {
  assert.equal(kept({ "package.json": JSON.stringify({ name: "x", dependencies: { "@bufbuild/protobuf": "^2.2.0" } }),
    "gen/app_pb.ts": app() }), false);
  for (const spec of ["npm:some-other-package@1.0.0", "file:../loader", "link:./loader", "workspace:*", "github:a/b"]) {
    assert.equal(kept({ "package.json": JSON.stringify({ name: "x", dependencies: { "@bufbuild/protobuf": spec } }),
      "gen/app_pb.ts": app() }), true, spec);
  }
  for (const paths of [{ "@bufbuild/protobuf/codegenv2": ["src/loader.ts"] }, { "*": ["types/*"] }]) {
    assert.equal(kept({ "package.json": PKG, "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths } }),
      "src/loader.ts": "export function fileDesc(s: string) { return s.length; }\n", "gen/app_pb.ts": app() }), true);
  }
  assert.equal(kept({ "package.json": PKG, "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["src/*"] } } }),
    "gen/app_pb.ts": app() }), false);
});

test("B-1, the cross-file rule: the module read whole by any road keeps SC-B64; read for its members it does not", () => {
  const base = { "package.json": PKG, "gen/app_pb.ts": app() };
  assert.equal(kept({ ...base, "src/use.js": 'const pb = require("../gen/app_pb");\nexports.m = pb.M0Schema;\n' }), false);
  const cfg = JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@pb": ["gen/app_pb.ts"] } } });
  assert.equal(kept({ ...base, "tsconfig.json": cfg, "src/f.ts": 'import * as pb from "@pb";\nexport const m = pb.M0Schema;\n' }), false);
  for (const [path, text] of [
    ["src/a.js", 'const v = require("../gen/app_pb")[getKey()];\n'],
    ["src/b.js", 'const { [getKey()]: v } = require("../gen/app_pb");\n'],
    ["src/c.js", 'const pb = __importStar(require("../gen/app_pb"));\n'],
    ["src/d.ts", 'export * as ns from "../gen/app_pb";\n'],
    ["src/e.js", 'console.log(Object.keys(require("../GEN/App_PB")));\n'],
    ["src/g.ts", 'import * as pb from "@gen";\nconsole.log(Object.values(pb));\n'],
    ["src/h.ts", 'import src from "../gen/app_pb.ts?raw";\nconsole.log(src);\n'],
    ["src/i.js", 'console.log(require("fs").readFileSync("gen/app_pb.ts", "utf8"));\n'],
    ["src/j.js", "console.log(require.cache);\n"],
    ["src/k.mjs", 'import { execSync } from "node:child_process";\nexecSync(getText());\n'],
    ["src/l.js", "(() => {}).constructor(getText())();\n"],
    ["src/m.js", "globalThis[getName()](getText());\n"],
  ]) {
    assert.equal(kept({ ...base, [path]: text }), true, path);
  }
  assert.equal(kept({ ...base, "tsconfig.json": cfg, "src/f.ts": 'import * as pb from "@pb";\nconsole.log(Object.values(pb));\n' }), true);
  // the generated file's own scope (TypeScript's CommonJS) read by a name made at run time
  const tsc = '"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nexports.file_a = void 0;\n'
    + 'const codegenv2_1 = require("@bufbuild/protobuf/codegenv2");\n' + `exports.file_a = (0, codegenv2_1.fileDesc)("${PLAIN}");\n`;
  assert.equal(kept({ "package.json": PKG, "gen/a_pb.js": tsc }, "gen/a_pb.js"), false);
  for (const tail of ["console.log(exports[getKey()]);\n", "console.log(module.exports);\n", "console.log(this[getKey()]);\n"]) {
    assert.equal(kept({ "package.json": PKG, "gen/a_pb.js": tsc + tail }, "gen/a_pb.js"), true, tail);
  }
  // B-3: a remap by a key that names the runtime otherwise; a { find } alias
  assert.equal(kept({ ...base, "package.json": JSON.stringify({ name: "x", resolutions: { "**/@bufbuild/protobuf": "file:./loader" } }) }), true);
  assert.equal(kept({ ...base, "rollup.config.js": 'export default { plugins: [alias({ entries: [{ find: "@bufbuild/protobuf", replacement: "/x.js" }] })] };\n' }), true);
});

test("B-1 and B-3 under --deps", () => {
  const dep = { "node_modules/pb/package.json": '{"name": "pb", "version": "1.0.0"}\n' };
  const base = { "package.json": PKG, "index.js": "1;\n" };
  assert.equal(kept({ ...base, ...dep, "node_modules/pb/gen/app_pb.ts": app(WITH_OPT) }, "node_modules/pb/gen/app_pb.ts", ["--deps"]), false);
  assert.equal(kept({ ...base, ...dep, "node_modules/pb/gen/app_pb.ts": app(WITH_OPT),
    "node_modules/pb/use.js": 'const pb = require("./gen/app_pb");\nmodule.exports = pb.file_app.proto;\n' },
  "node_modules/pb/gen/app_pb.ts", ["--deps"]), true);
});

test("B-2: many descriptors in one file cost about what one does each", () => {
  const secs = (k) => {
    let body = IMPORT;
    for (let j = 0; j < k; j++) body += `export const f${j} = fileDesc("${enc(fileDesc({ name: `a/p${j}.proto` }))}");\n`;
    const t = performance.now();
    const r = scan({ "package.json": PKG, "gen/all_pb.ts": body });
    assert.deepEqual(b64(r.issues), []);
    return (performance.now() - t) / 1000;
  };
  const small = secs(150), large = secs(600);
  assert.ok(large < 8 * small + 1.5, `${small} s for 150, ${large} s for 600`);
});
