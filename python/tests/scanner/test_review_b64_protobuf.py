"""FP-B64-PROTOBUF: a protobuf file's descriptor that protoc-gen-es embeds, as base64, and hands to its runtime's
loader is not SC-B64 when generated code alone uses it; base64 that is anything else, a descriptor that carries free
text, or one anything else could read back, still is.

The false positive: John's fp-tally over 261 GitHub scans (Oct 21) found SC-B64 ("Base64 blob (200+ chars) embedded
in code", MAJOR, WARN) on worker/src/gen/listentogether_pb.ts:13. protoc-gen-es (protobuf-es 2.x) embeds each .proto
file's serialized FileDescriptorProto as base64 and hands it to `fileDesc("…")`, imported from
@bufbuild/protobuf/codegenv2 (codegenv1 in 2.0 to 2.2).

The file scan keeps reporting SC-B64; the scan of a project, a --deps tree or a package decides, over all of it,
which findings to drop (core.b64_descriptor_pass, the engine's protodesc/usage.rs): every run of the line a
descriptor with no source information, JSON name or long default value, the whole first argument of the runtime's
fileDesc bound as generated code binds it, the descriptor used only as generated code uses it in every file of the
scan, nothing of the scan running text or loading a module by a name made at run time, the loader not remapped
(package.json, tsconfig/jsconfig paths), and nothing left unread. The review of Oct 27 (B-1 to B-3) is why; its
shapes are here, each with its benign control.

The generated files are fixtures (tests/fixtures/protobuf_es: protoc-gen-es 2.16.0 and 2.0.0's output for made-up
.proto files, in each form it writes, compiled to CommonJS by tsc and laid out by prettier:
scripts/make_protobuf_fixtures.py); the other descriptors are built here by a minimal protobuf writer, and every
stand-in for a payload is an inert marker: nothing is run.
"""
import base64
import json
import os
import re
import shutil
import tempfile
import time
import unittest

from lazaret.scanner import core
from tests.registry._review_support import scan_npm

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "protobuf_es", "gen")
PKG = '{"name": "x", "version": "1.0.0", "main": "index.js"}\n'
IMPORT = 'import { fileDesc } from "@bufbuild/protobuf/codegenv2";\n'


def generated():
    """{form/path: text} of every generated file of the fixture."""
    out = {}
    for root, _dirs, names in os.walk(FIXTURES):
        for n in sorted(names):
            path = os.path.join(root, n)
            with open(path, encoding="utf-8") as fh:
                out[os.path.relpath(path, FIXTURES).replace(os.sep, "/")] = fh.read()
    return out


def gen(rel):
    with open(os.path.join(FIXTURES, *rel.split("/")), encoding="utf-8") as fh:
        return fh.read()


LT = gen("ts/listentogether/v1/listentogether_pb.ts")
DESC = re.search(r'fileDesc\("([A-Za-z0-9+/]+)"', LT).group(1)
RAW = base64.b64decode(DESC + "=" * (-len(DESC) % 4))
# an inert stand-in for a payload: JavaScript that only logs
CODE = base64.b64encode("".join(f"console.log('a stand-in for a payload, inert: {k}');\n" for k in range(8)).encode()).decode()
TRAILING = base64.b64encode(RAW + b"\nconsole.log('x');\n").decode()
NOT_PROTO = base64.b64encode(b"\n\x0apayload.js" + RAW[2 + RAW[1]:]).decode()


# ---- the review's protobuf writer (descriptors made up here) ----

def varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def fld(num, data):
    return varint(num << 3 | 2) + varint(len(data)) + data


def ifld(num, v):
    return varint(num << 3) + varint(v)


def field_desc(name, number, extra=b""):
    return fld(1, name.encode()) + ifld(3, number) + ifld(4, 1) + ifld(5, 5) + extra


def message(name, fields):
    return fld(1, name.encode()) + b"".join(fld(2, f) for f in fields)


def file_desc(name="app/v1/app.proto", msgs=None, options=b"", source_info=b""):
    msgs = msgs if msgs is not None else [message(f"M{k}", [field_desc(f"field_{j}", j + 1) for j in range(6)])
                                          for k in range(4)]
    out = fld(1, name.encode()) + fld(2, b"app.v1") + b"".join(fld(4, m) for m in msgs)
    if options:
        out += fld(8, options)
    if source_info:
        out += fld(9, source_info)
    return out + fld(12, b"proto3")


def b64(raw):
    return base64.b64encode(raw).decode().rstrip("=")


MARKER = "INERT-MARKER-TEXT " * 40
PLAIN = b64(file_desc())
WITH_TEXT = b64(file_desc(source_info=fld(1, fld(3, MARKER.encode()))))
WITH_OPT = b64(file_desc(options=fld(50000, bytes(range(256)) * 4)))
WITH_DEFAULT = b64(file_desc(msgs=[message("M", [field_desc("x", 1, fld(7, MARKER.encode()))])]))
WITH_JSON_NAME = b64(file_desc(msgs=[message(f"M{k}", [field_desc(f"field_{j}", j + 1, fld(10, f"f{j}".encode()))
                                                       for j in range(6)]) for k in range(4)]))
SHORT_DEFAULT = b64(file_desc(msgs=[message(f"M{k}", [field_desc(f"field_{j}", j + 1, fld(7, b"42"))
                                                      for j in range(6)]) for k in range(4)]))
GEN_IMPORT = 'import { fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv2";\n'


def app(desc=PLAIN, tail=""):
    """protoc-gen-es's shape: the descriptor bound, a schema made of it; `tail` after it."""
    return (GEN_IMPORT + f'export const file_app = /*@__PURE__*/\n  fileDesc("{desc}");\n'
            "export const M0Schema = /*@__PURE__*/\n  messageDesc(file_app, 0);\n" + tail)


USER = 'import { create } from "@bufbuild/protobuf";\nimport { M0Schema } from "../gen/app_pb";\nexport const m = create(M0Schema);\n'


def hostile():
    """{name: (path, text, line)}: shapes SC-B64 keeps, at that line (each in a project of its own)."""
    return {
        "code handed to the loader": ("gen/a_pb.ts", IMPORT + f'export const f = fileDesc("{CODE}");\n', 2),
        "a descriptor with bytes after it": ("gen/b_pb.ts", IMPORT + f'export const f = fileDesc("{TRAILING}");\n', 2),
        "not a .proto file's descriptor": ("gen/c_pb.ts", IMPORT + f'export const f = fileDesc("{NOT_PROTO}");\n', 2),
        "a descriptor into eval": ("gen/d.js", f'eval(atob("{DESC}"));\n', 1),
        "a descriptor into Function": ("gen/e.js", f'new Function(Buffer.from("{DESC}", "base64").toString())();\n', 1),
        "a descriptor written to a file": ("gen/f.js", 'const fs = require("fs");\n'
                                           f'fs.writeFileSync("x.bin", Buffer.from("{DESC}", "base64"));\n', 2),
        "the file's own fileDesc": ("gen/g_pb.js", "function fileDesc(s) { return eval(atob(s)); }\n"
                                    f'export const f = fileDesc("{DESC}");\n', 2),
        "a local module": ("gen/h_pb.ts", 'import { fileDesc } from "./codegenv2";\n'
                           f'export const f = fileDesc("{DESC}");\n', 2),
        "a look-alike module": ("gen/i_pb.ts", 'import { fileDesc } from "@bufbuild/protobuf-codegenv2";\n'
                                f'export const f = fileDesc("{DESC}");\n', 2),
        "fileDesc bound again inside": ("gen/j_pb.ts", IMPORT + "export function g() {\n  const fileDesc = (s) => eval(atob(s));\n"
                                        f'  return fileDesc("{DESC}");\n}}\n', 4),
        "the module object written to": ("gen/k_pb.js", 'const cg = require("@bufbuild/protobuf/codegenv2");\n'
                                         "cg.fileDesc = (s) => eval(atob(s));\n"
                                         f'exports.f = (0, cg.fileDesc)("{DESC}");\n', 3),
        "require rebound": ("gen/l_pb.js", "const require = (m) => ({ fileDesc: (s) => eval(atob(s)) });\n"
                            'const { fileDesc } = require("@bufbuild/protobuf/codegenv2");\n'
                            f'exports.f = fileDesc("{DESC}");\n', 3),
        "not the whole argument": ("gen/m_pb.ts", IMPORT + f'export const f = fileDesc("{DESC}" + tail);\n', 2),
        "an aliased import": ("gen/n_pb.ts", 'import { boot as fileDesc } from "@bufbuild/protobuf/codegenv2";\n'
                              f'export const f = fileDesc("{DESC}");\n', 2),
        "a type-only import": ("gen/o_pb.ts", 'import type { fileDesc } from "@bufbuild/protobuf/codegenv2";\n'
                               f'export const f = fileDesc("{DESC}");\n', 2),
        "a variable, not the literal": ("gen/p_pb.ts", IMPORT + f'const s = "{DESC}";\nexport const f = fileDesc(s);\n', 2),
    }


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-pb-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
    return root


def scan(files, **kw):
    root = tree(files)
    try:
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def b64_of(res):
    return sorted((i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"] if i["rule"] == "SC-B64")


def kept(files, path="gen/app_pb.ts", **kw):
    """Does SC-B64 stay at `path` in the project scan of `files`?"""
    return any(f == path for f, _line in b64_of(scan(files, **kw)))


def b64_lines(path, text):
    return [i["line"] for i in core.scan_file(path, text, "js") if i["rule"] == "SC-B64"]


class TheFalsePositive(unittest.TestCase):
    def test_the_tally_case(self):
        # the shape fp-tally found: worker/src/gen/listentogether_pb.ts, protoc-gen-es's target=ts
        res = scan({"package.json": PKG, "worker/src/gen/listentogether_pb.ts": LT})
        self.assertEqual(b64_of(res), [])
        self.assertTrue(res["pass"])
        self.assertEqual(res["supplyChain"], 0)

    def test_every_form_the_generator_writes(self):
        # target=ts, js (ESM), legacy_commonjs, 2.0's codegenv1, tsc's CommonJS, prettier's layout, in their tree
        files = generated()
        self.assertEqual(len(files), 21)
        res = scan({"package.json": PKG, **{f"gen/{rel}": text for rel, text in files.items()}})
        self.assertEqual(b64_of(res), [])

    def test_the_file_scan_still_reports_it(self):
        # the decision is the whole scan's: a file read alone keeps its finding
        self.assertEqual(b64_lines("gen/listentogether_pb.ts", LT), [17])

    def test_no_path_or_name_plays_a_part(self):
        for path in ("src/schema.ts", "a.js", "gen/x_pb.ts", "lib/index.mjs", "listentogether_pb.cts"):
            with self.subTest(path=path):
                self.assertEqual(b64_of(scan({"package.json": PKG, path: LT})), [])
        res = scan({"package.json": PKG, "gen/listentogether_pb.ts": IMPORT + f'export const f = fileDesc("{CODE}");\n'})
        self.assertEqual(b64_of(res), [("gen/listentogether_pb.ts", 2)])


class HostileShapes(unittest.TestCase):
    def test_each_keeps_sc_b64(self):
        for name, (path, text, line) in hostile().items():
            with self.subTest(name=name):
                self.assertIn((path, line), b64_of(scan({"package.json": PKG, path: text})))

    def test_code_that_runs_text_keeps_the_generated_files_too(self):
        # eval of a variable anywhere in the scan could run what a descriptor carries: nothing is dropped
        files = {"package.json": PKG, "gen/listentogether_pb.ts": LT,
                 **{path: text for path, text, _line in hostile().values()}}
        want = sorted([(path, line) for path, _text, line in hostile().values()] + [("gen/listentogether_pb.ts", 17)])
        self.assertEqual(b64_of(scan(files)), want)


class WhatADescriptorCarries(unittest.TestCase):
    """B-1: a descriptor with free text keeps SC-B64; options (custom options) stay passed over."""

    def test_control(self):
        self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app()}))
        self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app(SHORT_DEFAULT)}))
        self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app(WITH_OPT)}))

    def test_comments_json_names_long_defaults(self):
        for name, desc in (("source information", WITH_TEXT), ("a JSON name", WITH_JSON_NAME),
                           ("a long default value", WITH_DEFAULT)):
            with self.subTest(name=name):
                self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(desc)}))


class ReadBack(unittest.TestCase):
    """B-1: the descriptor read, in its file or in another, keeps SC-B64 (the stand-ins only read a field)."""
    BACK = "const text = file_app.proto.sourceCodeInfo.location[0].leadingComments;\n"

    def test_control(self):
        self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app(WITH_OPT), "src/use.ts": USER}))

    def test_in_its_file(self):
        for name, tail in (("log", "console.log(file_app.proto);\n"),
                           ("eval", self.BACK + "eval(text);\n"),
                           ("new Function", self.BACK + "new Function(text)();\n"),
                           ("exec", 'import { execSync } from "node:child_process";\n' + self.BACK + "execSync(text);\n"),
                           ("vm", 'import vm from "node:vm";\n' + self.BACK + "vm.runInThisContext(text);\n"),
                           ("handed on", "register(file_app);\n"),
                           ("exported again", "export default file_app;\n"),
                           ("a computed read", 'export const p = file_app["proto"];\n')):
            with self.subTest(name=name):
                self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(WITH_OPT, tail)}))

    def test_in_another_file(self):
        for name, path, text in (
                ("readback-other-file", "src/use.ts", 'import { file_app } from "../gen/app_pb";\n'
                 'import { writeFileSync } from "node:fs";\nwriteFileSync("/tmp/out.bin", file_app.proto.options.$unknown[0].data);\n'),
                ("an alias", "src/use.ts", 'import { file_app as f } from "../gen/app_pb";\nconsole.log(f);\n'),
                ("the module whole", "src/use.ts", 'import * as pb from "../gen/app_pb";\nconsole.log(Object.values(pb));\n'),
                ("its name in a string", "src/use.js", 'const pb = require("../gen/app_pb");\nconsole.log(pb["file_app"]);\n'),
                ("a dynamic import", "src/use.js", 'import("../gen/app_pb.js").then((m) => console.log(m));\n'),
                ("a module named at run time", "src/use.js", "const m = require(process.env.MOD);\n"),
                ("a component's template", "src/App.vue", '<template><pre>{{ file_app.proto }}</pre></template>\n'
                 '<script setup>import { file_app } from "../gen/app_pb";</script>\n'),
                ("a page's handler", "index.html", '<button onclick="eval(window.payload)">x</button>\n')):
            with self.subTest(name=name):
                self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(WITH_OPT), path: text}))

    def test_the_same_string_twice(self):
        res = scan({"package.json": PKG, "gen/app_pb.ts": app() + f'export const again = atob("{PLAIN}");\n'})
        self.assertEqual(b64_of(res), [("gen/app_pb.ts", 6)])
        res = scan({"package.json": PKG, "gen/app_pb.ts": app(), "src/other.ts": f'export const again = atob("{PLAIN}");\n'})
        self.assertEqual(b64_of(res), [("src/other.ts", 1)])


class TheModuleReadWhole(unittest.TestCase):
    """B-1, the cross-file rule: the descriptor's module (its exports) read by a name made at run time, by any road the
    scan can see, keeps SC-B64; read for its members, or a path that leads elsewhere, does not."""

    def test_controls(self):
        for path, text in (("src/use.js", 'const pb = require("../gen/app_pb");\nexports.m = pb.M0Schema;\n'),
                           ("src/use.ts", 'import * as pb from "../gen/app_pb";\nexport const m = pb.M0Schema;\n')):
            with self.subTest(path=path):
                self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app(), path: text}))
        cfg = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@pb": ["gen/app_pb.ts"], "@/*": ["src/*"]}}})
        pkg = json.dumps({"name": "x", "dependencies": {"express": "^4.19.0"}})
        self.assertFalse(kept({"package.json": pkg, "tsconfig.json": cfg, "gen/app_pb.ts": app(),
                               "src/App.ts": "export default 1;\n",
                               "src/main.ts": 'import express from "express";\nimport App from "@/App";\n'
                                              'import * as pb from "@pb";\nexport const s = express();\n'
                                              "export const c = App;\nexport const m = pb.M0Schema;\n"}))

    def test_each_road(self):
        cfg = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@pb": ["gen/app_pb.ts"]}}})
        for name, extra in (
                ("a computed read after require", {"src/a.js": 'const v = require("../gen/app_pb")[getKey()];\n'}),
                ("a computed destructuring", {"src/b.js": 'const { [getKey()]: v } = require("../gen/app_pb");\n'}),
                ("a helper", {"src/c.js": 'const pb = __importStar(require("../gen/app_pb"));\n'}),
                ("a namespace exported", {"src/d.ts": 'export * as ns from "../gen/app_pb";\n'}),
                ("another case", {"src/e.js": 'console.log(Object.keys(require("../GEN/App_PB")));\n'}),
                ("a tsconfig alias", {"tsconfig.json": cfg, "src/f.ts": 'import * as pb from "@pb";\nconsole.log(Object.values(pb));\n'}),
                ("an undeclared name", {"src/g.ts": 'import * as pb from "@gen";\nconsole.log(Object.values(pb));\n'}),
                ("its text, ?raw", {"src/h.ts": 'import src from "../gen/app_pb.ts?raw";\nconsole.log(src);\n'}),
                ("its text, a path", {"src/i.js": 'console.log(require("fs").readFileSync("gen/app_pb.ts", "utf8"));\n'}),
                ("the module registry", {"src/j.js": "console.log(require.cache);\n"}),
                ("child_process", {"src/k.mjs": 'import { execSync } from "node:child_process";\nexecSync(getText());\n'}),
                ("a constructor called on text", {"src/l.js": "(() => {}).constructor(getText())();\n"}),
                ("a global by a name made at run time", {"src/m.js": "globalThis[getName()](getText());\n"})):
            with self.subTest(name=name):
                self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(), **extra}))

    def test_its_own_scope(self):
        # TypeScript's CommonJS of the generated file, and its exports read by a name made at run time
        tsc = ('"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nexports.file_a = void 0;\n'
               'const codegenv2_1 = require("@bufbuild/protobuf/codegenv2");\n'
               f'exports.file_a = (0, codegenv2_1.fileDesc)("{PLAIN}");\n')
        self.assertFalse(kept({"package.json": PKG, "gen/a_pb.js": tsc}, "gen/a_pb.js"))
        for tail in ("console.log(exports[getKey()]);\n", "console.log(module.exports);\n", "console.log(this[getKey()]);\n"):
            with self.subTest(tail=tail):
                self.assertTrue(kept({"package.json": PKG, "gen/a_pb.js": tsc + tail}, "gen/a_pb.js"))


class TheLoader(unittest.TestCase):
    """B-3: the loader's module remapped by the project keeps SC-B64; a version of it does not."""

    def test_control(self):
        pkg = json.dumps({"name": "x", "dependencies": {"@bufbuild/protobuf": "^2.2.0"}})
        cfg = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}})
        self.assertFalse(kept({"package.json": pkg, "tsconfig.json": cfg, "gen/app_pb.ts": app()}))

    def test_package_json(self):
        for spec in ("npm:some-other-package@1.0.0", "file:../loader", "link:./loader", "workspace:*",
                     "github:someone/loader", "git+https://example.invalid/x.git", "https://example.invalid/x.tgz"):
            with self.subTest(spec=spec):
                pkg = json.dumps({"name": "x", "dependencies": {"@bufbuild/protobuf": spec}})
                self.assertTrue(kept({"package.json": pkg, "gen/app_pb.ts": app()}))
        pkg = json.dumps({"name": "x", "browser": {"@bufbuild/protobuf/codegenv2": "./loader.js"}})
        self.assertTrue(kept({"package.json": pkg, "gen/app_pb.ts": app()}))
        for pkg in ({"name": "x", "resolutions": {"**/@bufbuild/protobuf": "file:./loader"}},
                    {"name": "x", "pnpm": {"overrides": {"@bufbuild/protobuf@2": "link:./loader"}}}):
            with self.subTest(pkg=pkg):
                self.assertTrue(kept({"package.json": json.dumps(pkg), "gen/app_pb.ts": app()}))

    def test_tsconfig_paths(self):
        for paths in ({"@bufbuild/protobuf/codegenv2": ["src/loader.ts"]}, {"@bufbuild/*": ["vendor/*"]}, {"*": ["types/*"]}):
            with self.subTest(paths=paths):
                cfg = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": paths}})
                self.assertTrue(kept({"package.json": PKG, "tsconfig.json": cfg, "gen/app_pb.ts": app(),
                                      "src/loader.ts": "export function fileDesc(s: string) { return s.length; }\n"}))
        cfg = json.dumps({"compilerOptions": {"baseUrl": "src"}})
        self.assertTrue(kept({"package.json": PKG, "jsconfig.json": cfg, "gen/app_pb.ts": app(),
                              "src/@bufbuild/protobuf/codegenv2.ts": "export function fileDesc(s) { return s; }\n"}))
        # a config it extends that the scan did not read
        cfg = json.dumps({"extends": "@tsconfig/node20/tsconfig.json"})
        self.assertTrue(kept({"package.json": PKG, "tsconfig.json": cfg, "gen/app_pb.ts": app()}))

    def test_aliases(self):
        for path, text in (("vite.config.ts", 'export default { resolve: { alias: { "@bufbuild/protobuf/codegenv2": "/src/x.ts" } } };\n'),
                           ("rollup.config.js", 'export default { plugins: [alias({ entries: [{ find: "@bufbuild/protobuf", replacement: "/x.js" }] })] };\n'),
                           ("deno.json", '{"imports": {"@bufbuild/protobuf/codegenv2": "./src/x.ts"}}\n')):
            with self.subTest(path=path):
                self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(), path: text}))

    def test_the_review_shapes(self):
        # loader-local-reexport, loader-shadow-param, loader-concat, loader-cjs-written, loader-cjs-bracket-write,
        # loader-var-require-redef: kept; loader-cjs, loader-import-ns: quiet (an ES module's namespace is not written)
        for name, path, text, quiet in (
                ("local re-export", "gen/app_pb.ts", 'import { fileDesc } from "../src/loader";\n'
                 f'export const f = fileDesc("{PLAIN}");\n', False),
                ("shadowing parameter", "gen/app_pb.ts", IMPORT + "function g(fileDesc) { return fileDesc; }\n"
                 f'export const f = fileDesc("{PLAIN}");\n', False),
                ("concat", "gen/app_pb.ts", IMPORT + f'export const f = fileDesc("{PLAIN}" + "");\n', False),
                ("cjs written", "gen/app_pb.js", 'const codegenv2_1 = require("@bufbuild/protobuf/codegenv2");\n'
                 f'Object.assign(codegenv2_1, {{}});\nexports.f = (0, codegenv2_1.fileDesc)("{PLAIN}");\n', False),
                ("cjs bracket write", "gen/app_pb.js", 'const codegenv2_1 = require("@bufbuild/protobuf/codegenv2");\n'
                 'codegenv2_1["fileDesc"] = function (s) { return s; };\n'
                 f'exports.f = (0, codegenv2_1.fileDesc)("{PLAIN}");\n', False),
                ("var redeclared", "gen/app_pb.js", 'var cg = require("@bufbuild/protobuf/codegenv2");\nvar cg;\n'
                 f'exports.f = cg.fileDesc("{PLAIN}");\n', False),
                ("cjs", "gen/app_pb.js", 'const codegenv2_1 = require("@bufbuild/protobuf/codegenv2");\n'
                 f'exports.f = (0, codegenv2_1.fileDesc)("{PLAIN}");\n', True),
                ("import ns", "gen/app_pb.ts", 'import * as cg from "@bufbuild/protobuf/codegenv2";\n'
                 'import * as m from "@bufbuild/protobuf/codegenv2";\n'
                 f'export const f = cg.fileDesc("{PLAIN}");\n', True),
                (".mjs", "gen/app_pb.mjs", IMPORT + f'export const f = fileDesc("{PLAIN}");\n', True),
                (".cjs", "gen/app_pb.cjs", 'const { fileDesc } = require("@bufbuild/protobuf/codegenv2");\n'
                 f'exports.f = fileDesc("{PLAIN}");\n', True)):
            with self.subTest(name=name):
                files = {"package.json": PKG, path: text,
                         "src/loader.ts": "export function fileDesc(s: string) { return s.length; }\n"}
                self.assertEqual(kept(files, path), not quiet)


class WhatTheScanDidNotRead(unittest.TestCase):
    def test_a_component_read_and_one_not(self):
        vue = '<template><p>{{ m.name }}</p></template>\n<script setup lang="ts">\nimport { M0Schema } from "../gen/app_pb";\n</script>\n'
        self.assertFalse(kept({"package.json": PKG, "gen/app_pb.ts": app(), "src/App.vue": vue}))
        # larger than the cap: not read whole
        big = vue + "<!--" + "x" * (core.SOURCE_SIZE_CAP + 1) + "-->\n"
        self.assertTrue(kept({"package.json": PKG, "gen/app_pb.ts": app(), "src/App.vue": big}))


class Routes(unittest.TestCase):
    def test_deps(self):
        files = {"package.json": PKG, "index.js": "1;\n",
                 "node_modules/pb/package.json": '{"name": "pb", "version": "1.0.0"}\n',
                 "node_modules/pb/gen/listentogether_pb.js": gen("js/listentogether/v1/listentogether_pb.js"),
                 "node_modules/pb/gen/cjs_pb.js": gen("cjs/legacy/settings_pb.js"),
                 "node_modules/pb/gen/bad_pb.js": IMPORT + f'export const f = fileDesc("{CODE}");\n'}
        res = scan(files, include_deps=True)
        self.assertEqual(b64_of(res), [("node_modules/pb/gen/bad_pb.js", 2)])
        # a dependency that runs text it builds: nothing is dropped
        files["node_modules/other/package.json"] = '{"name": "other", "version": "1.0.0"}\n'
        files["node_modules/other/index.js"] = "module.exports = (s) => eval(s);\n"
        res = scan(files, include_deps=True)
        self.assertIn("node_modules/pb/gen/listentogether_pb.js", [f for f, _line in b64_of(res)])

    def test_registry(self):
        res = scan_npm({"package.json": PKG, "index.js": "1;\n", "gen/listentogether_pb.js": gen("tsc/listentogether/v1/listentogether_pb.js"),
                        "gen/common_pb.js": gen("js/common/common_pb.js")})
        self.assertEqual([i for i in res["issues"] if i["rule"] == "SC-B64"], [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        res = scan_npm({"package.json": PKG, "index.js": "1;\n", "gen/a_pb.js": IMPORT + f'export const f = fileDesc("{CODE}");\n'})
        self.assertEqual([(i["file"], i["line"]) for i in res["issues"] if i["rule"] == "SC-B64"], [("gen/a_pb.js", 2)])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        # the read-back in another file of the package, and the package's own copy of the runtime
        for name, extra in (("read back", {"lib/use.js": 'const pb = require("../gen/app_pb.js");\n'
                                                         "module.exports = pb.file_app.proto;\n"}),
                            ("its own runtime", {"node_modules/@bufbuild/protobuf/dist/cjs/codegenv2/index.js":
                                                 "exports.fileDesc = (s) => s;\n"})):
            with self.subTest(name=name):
                res = scan_npm({"package.json": PKG, "index.js": "1;\n", "gen/app_pb.js": app(), **extra})
                self.assertIn("gen/app_pb.js", [i["file"] for i in res["issues"] if i["rule"] == "SC-B64"])
        res = scan_npm({"package.json": PKG, "index.js": "1;\n", "gen/app_pb.js": app()})
        self.assertEqual([i for i in res["issues"] if i["rule"] == "SC-B64"], [])


class Cost(unittest.TestCase):
    def test_linear_in_the_descriptors_of_a_file(self):
        # B-2: K lines `export const f<k> = fileDesc("<descriptor>")` in one file of a package
        def secs(k):
            body = "".join(f'export const f{j} = fileDesc("{b64(file_desc(name=f"a/p{j}.proto"))}");\n' for j in range(k))
            t = time.perf_counter()
            res = scan_npm({"package.json": PKG, "gen/all_pb.ts": IMPORT + body})
            took = time.perf_counter() - t
            self.assertEqual([i for i in res["issues"] if i["rule"] == "SC-B64"], [])
            return took
        small, large = secs(250), secs(1000)
        self.assertLess(large, 8 * small + 1.0, (small, large))


if __name__ == "__main__":
    unittest.main()
