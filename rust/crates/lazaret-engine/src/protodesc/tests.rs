//! FP-B64-PROTOBUF: the descriptor reader, and the scan's pass over SC-B64 (usage.rs) on the shapes the generators
//! write and the review of Oct 27 (B-1 to B-3). Every stand-in for a payload is inert text: nothing is run.

use super::usage::{decide, Input};
use super::*;
use crate::json::Value;
use crate::scanfile::{scan_file, Options};

#[path = "samples.rs"]
mod samples;
use samples::*;

fn bytes(b64: &str) -> Vec<u8> {
    let mut s: Vec<u32> = b64.chars().map(|c| c as u32).collect();
    while s.len() % 4 != 0 {
        s.push('=' as u32);
    }
    crate::signs::b64decode_strict(&s).expect("base64")
}

fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
        }
    }
    out
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let x = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(x);
            return out;
        }
        out.push(x | 0x80);
    }
}

/// A length-delimited field.
fn ld(num: u64, data: &[u8]) -> Vec<u8> {
    let mut out = varint(num << 3 | 2);
    out.extend(varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

/// A varint field.
fn vi(num: u64, v: u64) -> Vec<u8> {
    [varint(num << 3), varint(v)].concat()
}

/// The first field (a file's name) of `b` replaced by `name`.
fn renamed(b: &[u8], name: &[u8]) -> Vec<u8> {
    let first = 2 + b[1] as usize;
    let mut out = ld(1, name);
    out.extend_from_slice(&b[first..]);
    out
}

/// A made-up descriptor (the review's writer): a file `name`, four messages of six fields, `extra` after them.
fn made(name: &str, extra: &[u8]) -> Vec<u8> {
    let field = |n: &str, k: u64| [ld(1, n.as_bytes()), vi(3, k), vi(4, 1), vi(5, 5)].concat();
    let msg = |k: usize| [ld(1, format!("M{k}").as_bytes()), (0..6).flat_map(|j| ld(2, &field(&format!("field_{j}"), j + 1))).collect()].concat();
    let mut out = [ld(1, name.as_bytes()), ld(2, b"app.v1")].concat();
    for k in 0..4 {
        out.extend(ld(4, &msg(k)));
    }
    out.extend_from_slice(extra);
    out.extend(ld(12, b"proto3"));
    out
}

#[test]
fn the_generators_descriptors_are_read_to_their_end() {
    for d in [PROTO3, PROTO2, EDITION, OPTIONS, FILE_OPTIONS] {
        assert!(file_descriptor(&bytes(d)), "{}", &d[..40]);
    }
    let mut f = ld(1, b"a/b.proto");
    f.extend(ld(2, b"a.b"));
    f.extend(ld(4, &ld(1, b"Thing")));
    assert!(file_descriptor(&f));
    assert!(file_descriptor(&made("app/v1/app.proto", b"")));
    // a custom option of any number, as protovalidate's and googleapis' carry: options are well-formed fields
    assert!(file_descriptor(&made("app/v1/app.proto", &ld(8, &ld(50000, &[7u8; 300])))));
    // the JSON name protoc derives from a field's name (protoc-gen-es writes it for an extension)
    let ext = [ld(1, b"note_text"), vi(3, 100), vi(4, 1), vi(5, 9), ld(2, b".a.M"), ld(10, b"noteText")].concat();
    assert!(file_descriptor(&[ld(1, b"a.proto"), ld(4, &ld(1, b"M")), ld(7, &ext)].concat()));
    // a default value up to MAX_DEFAULT characters
    let field = [ld(1, b"x"), vi(3, 1), vi(4, 1), vi(5, 9), ld(7, "y".repeat(MAX_DEFAULT).as_bytes())].concat();
    assert!(file_descriptor(&[ld(1, b"a.proto"), ld(4, &[ld(1, b"M"), ld(2, &field)].concat())].concat()));
}

#[test]
fn anything_else_is_not_a_descriptor() {
    let real = bytes(PROTO3);
    let not = |b: &[u8], why: &str| assert!(!file_descriptor(b), "{why}");
    not(b"", "empty");
    not(b"console.log('a stand-in for a payload');\n", "text");
    let mut after = real.clone();
    after.extend_from_slice(b"\nconsole.log(1);");
    not(&after, "bytes after the descriptor");
    let mut cut = real.clone();
    cut.truncate(real.len() - 3);
    not(&cut, "cut short");
    not(&renamed(&real, b"payload.js"), "a name that is not a .proto path");
    not(&renamed(&real, b"../x.proto"), "a parent path");
    not(&renamed(&real, b"a b.proto"), "a blank in the path");
    let mut unknown = real.clone();
    unknown.extend(ld(99, b"x"));
    not(&unknown, "an unknown field");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(4, &[ld(1, b"M"), ld(42, b"x")].concat()));
    not(&f, "an unknown field of a message");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(4, &ld(1, b"M;eval")));
    not(&f, "a message's name");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(2, b"a..b"));
    not(&f, "a package");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(4, &[ld(1, b"M"), ld(2, &[ld(1, b"f"), ld(7, b"\xff\xfe")].concat())].concat()));
    not(&f, "a default value that is not UTF-8");
    let mut f = ld(1, b"a.proto");
    f.extend_from_slice(&[0x20, 0x01]);
    not(&f, "a message as a varint");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(1, b"b.proto"));
    not(&f, "two names");
    not(&ld(2, b"pkg"), "no name");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(12, b"proto4"));
    not(&f, "a syntax");
    let mut f = ld(1, b"a.proto");
    f.extend(ld(8, &[0x0a, 0x05, b'a']));
    not(&f, "options cut short");
    let mut m = ld(1, b"M");
    for _ in 0..80 {
        m = [ld(1, b"M"), ld(3, &m)].concat();
    }
    not(&[ld(1, b"a.proto"), ld(4, &m)].concat(), "nested past the bound");
    // the review's carriers of free text (B-1): source information (comments), a JSON name, a long default value
    let marker = "INERT-MARKER-TEXT ".repeat(40);
    not(&made("app/v1/app.proto", &ld(9, &ld(1, &ld(3, marker.as_bytes())))), "source information");
    not(&made("app/v1/app.proto", &ld(9, &[])), "empty source information");
    let field = |extra: Vec<u8>| [ld(1, b"x"), vi(3, 1), vi(4, 1), vi(5, 9), extra].concat();
    let with = |f: Vec<u8>| [ld(1, b"a.proto"), ld(4, &[ld(1, b"M"), ld(2, &f)].concat())].concat();
    not(&with(field(ld(10, b"jsonName"))), "a JSON name of its own");
    not(&with(field([ld(10, b"payload"), ld(10, b"x")].concat())), "two JSON names, one free");
    let named = |n: &[u8], j: &[u8]| [ld(1, b"a.proto"), ld(4, &[ld(1, b"M"), ld(2, &[ld(1, n), vi(3, 1), ld(10, j)].concat())].concat())].concat();
    assert!(file_descriptor(&named(b"field_one", b"fieldOne")));
    not(&named(b"field_one", b"field_one"), "a JSON name not the derived one");
    not(&with(field(ld(7, marker.as_bytes()))), "a default value past MAX_DEFAULT");
    not(&with(field(ld(7, "y".repeat(MAX_DEFAULT + 1).as_bytes()))), "a default value one past");
}

// ---- the scan's pass ----------------------------------------------------------------------------------------------

const IMP: &str = "import { enumDesc, fileDesc, messageDesc } from \"@bufbuild/protobuf/codegenv2\";\n";
const PKG: &str = "{\"name\": \"x\", \"version\": \"1.0.0\"}";

fn u(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

/// The SC-B64 lines scan_file reports in `src`.
fn b64_lines(src: &str, lang: &str) -> Vec<usize> {
    let p = crate::pack::current();
    let opts = Options { dep: false, redact: true, neumaier: false };
    scan_file(&p, &u(src), Some(lang), true, &opts)
        .iter()
        .filter_map(|i| match i {
            Value::Arr(a) if a.first().and_then(|r| r.as_str()) == Some(u("SC-B64").as_slice()) => {
                a.get(8).and_then(|l| if let Value::Int(n) = l { Some(*n as usize) } else { None })
            }
            _ => None,
        })
        .collect()
}

#[derive(Default)]
struct Scan {
    files: Vec<(String, String)>,
    unread: Vec<String>,
    unreadable: Vec<String>,
    stopped: bool,
    package: bool,
}

impl Scan {
    fn of(files: &[(&str, &str)]) -> Scan {
        Scan { files: files.iter().map(|(p, t)| (p.to_string(), t.to_string())).collect(), ..Scan::default() }
    }

    /// The pass over the scan's SC-B64 findings: (path, line, why it stays).
    fn decide(&self) -> Vec<(String, usize, Option<String>)> {
        let p = crate::pack::current();
        let ext = |f: &str| f.rsplit('.').next().unwrap_or("").to_string();
        let code = |f: &str| ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"].contains(&ext(f).as_str());
        let holder = |f: &str| ["vue", "svelte", "html", "astro", "mdx"].contains(&ext(f).as_str());
        let mut input = Input {
            files: Vec::new(),
            holders: Vec::new(),
            manifests: Vec::new(),
            configs: Vec::new(),
            findings: Vec::new(),
            unread: self.unread.clone(),
            stopped: self.stopped,
            package: self.package,
        };
        for (path, text) in &self.files {
            let base = path.rsplit('/').next().unwrap();
            if base == "package.json" {
                input.manifests.push((path.clone(), u(text)));
            } else if base.starts_with("tsconfig") || base.starts_with("jsconfig") || ["deno.json", ".babelrc", ".swcrc"].contains(&base) {
                input.configs.push((path.clone(), (!self.unreadable.contains(path)).then(|| u(text))));
            } else if code(path) {
                input.findings.extend(b64_lines(text, "js").into_iter().map(|l| (path.clone(), l)));
                input.files.push((path.clone(), u(text)));
            } else if holder(path) {
                input.holders.push((path.clone(), (!self.unreadable.contains(path)).then(|| u(text))));
            }
        }
        decide(&p, &input)
    }

    /// Is every SC-B64 finding of the scan dropped (and was there one)?
    fn quiet(&self) -> bool {
        let d = self.decide();
        !d.is_empty() && d.iter().all(|(_, _, why)| why.is_none())
    }

    /// Does a finding stay at `path`?
    fn kept(&self, path: &str) -> bool {
        self.decide().iter().any(|(f, _, why)| f == path && why.is_some())
    }
}

fn gen(name: &str, d: &str) -> String {
    format!("{IMP}export const {name}: GenFile = /*@__PURE__*/\n  fileDesc(\"{d}\", [file_google_protobuf_timestamp]);\n\nexport const RoomSchema: GenMessage<Room> = /*@__PURE__*/\n  messageDesc({name}, 0);\nexport const RoleSchema = /*@__PURE__*/ enumDesc({name}, 0);\n")
}

#[test]
fn the_generators_files_are_passed_over() {
    let d = PROTO3;
    let user = "import { create } from \"@bufbuild/protobuf\";\nimport { RoomSchema } from \"../gen/app_pb\";\nexport const r = create(RoomSchema);\n";
    // protoc-gen-es's TypeScript, with a user of its schemas and a declaration file
    let s = Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &gen("file_app", d)), ("src/use.ts", user),
        ("gen/app_pb.d.ts", "export declare const file_app: GenFile;\n")]);
    assert!(s.quiet(), "{:?}", s.decide());
    // the scan_file finding is there (the pass drops it, not the file scan)
    assert_eq!(b64_lines(&gen("file_app", d), "js"), vec![3]);
    // codegenv1, prettier's layout, ASI
    for src in [
        format!("import {{ fileDesc, messageDesc }} from '@bufbuild/protobuf/codegenv1';\nexport const file_a = fileDesc(\"{d}\");\nexport const M = messageDesc(file_a, 0);\n"),
        format!("import {{\n  enumDesc,\n  fileDesc,\n}} from \"@bufbuild/protobuf/codegenv2\";\nexport const file_a =\n  /*@__PURE__*/\n  fileDesc(\n    \"{d}\",\n    [a, b],\n  );\nexport const E = enumDesc(file_a, 0)\n"),
        format!("import {{ fileDesc }} from \"@bufbuild/protobuf/codegenv2\"\nexport const file_a = fileDesc(\"{d}\")\nexport const other = 1\n"),
        // an ES module's namespace cannot be written
        format!("import * as cg from \"@bufbuild/protobuf/codegenv2\";\nimport * as m from \"@bufbuild/protobuf/codegenv2\";\nexport const file_a = cg.fileDesc(\"{d}\");\n"),
        format!("import {{ fileDesc }} from \"@bufbuild/protobuf/codegenv2\";\nexport const file_a = fileDesc(\"{d}\");\n"),
    ] {
        assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.ts", &src)]).quiet(), "{}", &src[..90]);
    }
    // protoc-gen-es's CommonJS
    let cjs = format!("\"use strict\";\nconst {{ fileDesc, messageDesc }} = require(\"@bufbuild/protobuf/codegenv2\");\nconst file_a = /*@__PURE__*/\n  fileDesc(\"{d}\");\nconst M = /*@__PURE__*/\n  messageDesc(file_a, 0);\nexports.M = M;\nexports.file_a = file_a;\n");
    assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.js", &cjs)]).quiet());
    // TypeScript's CommonJS, used from another file through its module object and by the runtime's registry
    let tsc = format!("\"use strict\";\nObject.defineProperty(exports, \"__esModule\", {{ value: true }});\nexports.M = exports.file_a = void 0;\nconst codegenv2_1 = require(\"@bufbuild/protobuf/codegenv2\");\nconst wkt_1 = require(\"@bufbuild/protobuf/wkt\");\nexports.file_a = (0, codegenv2_1.fileDesc)(\"{d}\", [wkt_1.file_google_protobuf_duration]);\nexports.M = (0, codegenv2_1.messageDesc)(exports.file_a, 0);\n");
    let validator = "\"use strict\";\nconst protobuf_1 = require(\"@bufbuild/protobuf\");\nconst a_pb_js_1 = require(\"./gen/a_pb.js\");\nfunction make(opt) {\n  return opt.registry ? (0, protobuf_1.createMutableRegistry)(opt.registry, a_pb_js_1.file_a) : (0, protobuf_1.createMutableRegistry)(a_pb_js_1.file_a);\n}\nexports.make = make;\nexports.M = a_pb_js_1.M;\n";
    let s = Scan::of(&[("package.json", PKG), ("dist/gen/a_pb.js", &tsc), ("dist/validator.js", validator)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // the same package in ESM beside it (protovalidate's dist/esm and dist/cjs define the same name)
    let esm = format!("{IMP}import {{ file_google_protobuf_duration }} from \"@bufbuild/protobuf/wkt\";\nexport const file_a = /*@__PURE__*/ fileDesc(\"{d}\", [file_google_protobuf_duration]);\nexport const M = /*@__PURE__*/ messageDesc(file_a, 0);\n");
    let esm_user = "import { createMutableRegistry } from \"@bufbuild/protobuf\";\nimport { file_a } from \"./gen/a_pb.js\";\nexport const reg = createMutableRegistry(file_a);\nexport * from \"./gen/a_pb.js\";\n";
    let s = Scan::of(&[("package.json", PKG), ("dist/cjs/gen/a_pb.js", &tsc), ("dist/esm/gen/a_pb.js", &esm),
        ("dist/esm/validator.js", esm_user), ("dist/cjs/validator.js", validator)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // another descriptor's dependency list, a re-export, a namespace read for its members
    let dep = format!("{IMP}import {{ file_a }} from \"./a_pb\";\nexport const file_b = fileDesc(\"{}\", [file_a]);\n", b64(&made("b.proto", b"")));
    let ns = "import * as pb from \"../gen/index\";\nexport const s = pb.M;\n";
    let s = Scan::of(&[("package.json", PKG), ("gen/a_pb.ts", &gen("file_a", d)), ("gen/b_pb.ts", &dep),
        ("gen/index.ts", "export * from \"./a_pb\";\nexport * from \"./b_pb\";\n"), ("src/ns.ts", ns)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // a Vue component and an HTML page beside it
    let vue = "<template><p>{{ room.name }}</p></template>\n<script setup lang=\"ts\">\nimport { RoomSchema } from \"../gen/app_pb\";\nconst room = create(RoomSchema);\n</script>\n";
    let html = "<!doctype html><html><body><div id=\"app\"></div><script type=\"module\" src=\"/src/main.ts\"></script></body></html>\n";
    let s = Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &gen("file_app", d)), ("src/App.vue", vue), ("index.html", html)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // a version range is the registry's package
    let pkg = "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"^2.2.0\"}, \"devDependencies\": {\"@bufbuild/protoc-gen-es\": \"2.16.0\"}}";
    assert!(Scan::of(&[("package.json", pkg), ("gen/app_pb.ts", &gen("file_app", d))]).quiet());
    // a --deps tree: the app's node_modules/@bufbuild/protobuf is the one npm installed
    let s = Scan::of(&[("package.json", PKG), ("node_modules/x/package.json", PKG), ("node_modules/x/gen/a_pb.js", &tsc),
        ("node_modules/@bufbuild/protobuf/package.json", "{\"name\": \"@bufbuild/protobuf\"}"),
        ("node_modules/@bufbuild/protobuf/dist/cjs/codegenv2/file.js", "exports.fileDesc = function () {};\n")]);
    assert!(s.quiet(), "{:?}", s.decide());
}

#[test]
fn a_descriptor_read_back_keeps_sc_b64() {
    let marker = "INERT-MARKER-TEXT ".repeat(40);
    let plain = b64(&made("app/v1/app.proto", b""));
    let head = |d: &str| format!("{IMP}export const file_app = fileDesc(\"{d}\");\n");
    // what a descriptor can carry: comments, a JSON name, a long default value
    let comment = b64(&made("app/v1/app.proto", &ld(9, &ld(1, &ld(3, marker.as_bytes())))));
    let field = [ld(1, b"x"), vi(3, 1), vi(4, 1), vi(5, 9), ld(7, marker.as_bytes())].concat();
    let default = b64(&[ld(1, b"a/a.proto"), ld(4, &[ld(1, b"M"), ld(2, &field)].concat())].concat());
    for d in [&comment, &default] {
        assert!(Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &head(d))]).kept("gen/app_pb.ts"));
    }
    // the review's read-backs (inert: the stand-in reads a field), in the file and in another
    let back = "const text = file_app.proto.sourceCodeInfo.location[0].leadingComments;\n";
    for tail in [
        format!("{back}eval(text);\n"),
        format!("{back}new Function(text)();\n"),
        format!("import {{ execSync }} from \"node:child_process\";\n{back}execSync(text);\n"),
        format!("import vm from \"node:vm\";\n{back}vm.runInThisContext(text);\n"),
        "console.log(file_app.proto);\n".to_string(),
        "export const x = file_app;\n".to_string(),
        "export const x = file_app[\"proto\"];\n".to_string(),
        "use(file_app);\n".to_string(),
        "export default file_app;\n".to_string(),
    ] {
        let src = format!("{}{tail}", head(&plain));
        assert!(Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &src)]).kept("gen/app_pb.ts"), "{tail}");
    }
    // the loader's value read on the spot
    let chained = format!("{IMP}export const file_app = fileDesc(\"{plain}\").proto;\n");
    assert!(Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &chained)]).kept("gen/app_pb.ts"));
    let gen_file = head(&plain);
    for (path, other) in [
        ("src/use.ts", "import { file_app } from \"../gen/app_pb\";\nimport { writeFileSync } from \"node:fs\";\nwriteFileSync(\"out.bin\", file_app.proto.options.$unknown[0].data);\n"),
        ("src/alias.ts", "import { file_app as f } from \"../gen/app_pb\";\nconsole.log(f);\n"),
        ("src/ns.ts", "import * as pb from \"../gen/app_pb\";\nfor (const v of Object.values(pb)) console.log(v);\n"),
        ("src/req.js", "const pb = require(\"../gen/app_pb\");\nconst k = \"file_\" + \"app\";\nconsole.log(pb[k]);\n"),
        ("src/str.js", "const pb = require(\"../gen/app_pb\");\nconsole.log(pb[\"file_app\"]);\n"),
        ("src/dyn.js", "import(\"../gen/app_pb.js\").then((m) => console.log(m));\n"),
        ("src/glob.ts", "const all = import.meta.glob(\"../gen/*_pb.ts\", { eager: true });\nconsole.log(all);\n"),
        ("src/load.js", "const name = process.env.MOD;\nconst m = require(name);\n"),
        ("src/run.js", "const code = getText();\neval(code);\n"),
        ("src/rest.js", "const { RoomSchema, ...rest } = require(\"../gen/app_pb\");\nconsole.log(rest);\n"),
        ("src/index.ts", "export * from \"../gen/app_pb\";\n"),
        ("src/read.vue", "<template><pre>{{ file_app.proto }}</pre></template>\n<script setup>import { file_app } from \"../gen/app_pb\";</script>\n"),
        ("page.html", "<button onclick=\"eval(window.payload)\">x</button>\n"),
    ] {
        let mut files = vec![("package.json", PKG), ("gen/app_pb.ts", gen_file.as_str()), (path, other)];
        if path == "src/index.ts" {
            files.push(("src/all.ts", "import * as all from \"./index\";\nconsole.log(Object.keys(all));\n"));
        }
        assert!(Scan::of(&files).kept("gen/app_pb.ts"), "{path}");
    }
}

#[test]
fn the_module_read_whole_by_any_road_keeps_sc_b64() {
    // the descriptor's module (and its exports) reached by a name made at run time, through every road the scan can
    // see; and the controls each road has (the module read for its members, a path that leads elsewhere)
    let gen_file = gen("file_app", PROTO3);
    let kept = |extra: &[(&str, &str)]| {
        let mut files = vec![("package.json", PKG), ("gen/app_pb.ts", gen_file.as_str())];
        files.extend_from_slice(extra);
        Scan::of(&files).kept("gen/app_pb.ts")
    };
    for (path, other) in [
        // a require followed by a computed read, a call, a computed or nested destructuring
        ("src/a.js", "const k = \"file_\" + \"app\";\nconst v = require(\"../gen/app_pb\")[k];\nconsole.log(v);\n"),
        ("src/b.js", "const k = getKey();\nconst { [k]: v } = require(\"../gen/app_pb\");\nconsole.log(v);\n"),
        ("src/c.js", "const { RoomSchema: { file } } = require(\"../gen/app_pb\");\nconsole.log(file);\n"),
        // a helper handed the module (TypeScript's esModuleInterop, tslib), a namespace exported under a name
        ("src/e.js", "const pb = __importStar(require(\"../gen/app_pb\"));\nexports.s = pb.RoomSchema;\n"),
        ("src/f.js", "__exportStar(require(\"../gen/app_pb\"), exports);\n"),
        ("src/g.ts", "export * as ns from \"../gen/app_pb\";\n"),
        // a path by another spelling: case, a folder, an alias of tsconfig's, an undeclared name, a `#` import
        ("src/h.js", "const pb = require(\"../GEN/App_PB\");\nconsole.log(Object.keys(pb));\n"),
        ("src/i.js", "const pb = require(\"../gen\");\nconsole.log(Object.keys(pb));\n"),
        ("src/j.ts", "import * as pb from \"@gen\";\nconsole.log(Object.values(pb));\n"),
        ("src/k.ts", "import * as pb from \"#pb\";\nconsole.log(Object.values(pb));\n"),
        ("src/l.ts", "import src from \"../gen/app_pb.ts?raw\";\nconsole.log(src);\n"),
        // the file read as text: a path in a string, not a module specifier
        ("src/m.js", "const fs = require(\"fs\");\nconsole.log(fs.readFileSync(\"gen/app_pb.ts\", \"utf8\"));\n"),
        ("src/n.mjs", "console.log(new URL(\"../gen/app_pb.js\", import.meta.url));\n"),
        ("src/o.js", "console.log(require.resolve(\"../gen/app_pb\"));\n"),
        // the module registry, Node's modules that run code
        ("src/p.js", "for (const m of Object.values(require.cache)) console.log(m.exports);\n"),
        ("src/q.js", "console.log(module.children);\n"),
        ("src/r.js", "console.log(process.mainModule);\n"),
        ("src/s.mjs", "import { execSync } from \"node:child_process\";\nexecSync(getText());\n"),
        ("src/t.js", "const { Worker } = require(\"worker_threads\");\nnew Worker(getText(), { eval: true });\n"),
        ("src/u.js", "const run = (() => {}).constructor(getText());\nrun();\n"),
        ("src/v.js", "globalThis[getName()](getText());\n"),
    ] {
        let mut extra = vec![(path, other)];
        if path == "src/i.js" {
            extra.push(("gen/package.json", "{\"main\": \"app_pb.js\"}"));
        }
        assert!(kept(&extra), "{path}");
    }
    // a tsconfig alias that leads to the file, read whole; the same alias read for its members
    let cfg = "{\"compilerOptions\": {\"baseUrl\": \".\", \"paths\": {\"@pb\": [\"gen/app_pb.ts\"], \"@/*\": [\"src/*\"]}}}";
    assert!(kept(&[("tsconfig.json", cfg), ("src/w.ts", "import * as pb from \"@pb\";\nconsole.log(Object.values(pb));\n")]));
    assert!(!kept(&[("tsconfig.json", cfg), ("src/w.ts", "import * as pb from \"@pb\";\nexport const s = pb.RoomSchema;\n")]));
    // an alias that leads elsewhere, read whole (a component used as a value), and a declared package's default
    // import called: the descriptor's module is not among them
    let pkg = "{\"name\": \"x\", \"dependencies\": {\"express\": \"^4.19.0\"}}";
    let app = "import express from \"express\";\nimport App from \"@/App\";\nexport const s = express();\nexport const c = App;\n";
    let s = Scan::of(&[("package.json", pkg), ("tsconfig.json", cfg), ("gen/app_pb.ts", &gen_file), ("src/App.ts", "export default 1;\n"), ("src/main.ts", app)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // the generated file's own scope read by a name made at run time (CommonJS: its exports, `this`, `arguments`)
    let tsc = format!("\"use strict\";\nObject.defineProperty(exports, \"__esModule\", {{ value: true }});\nexports.file_a = void 0;\nconst codegenv2_1 = require(\"@bufbuild/protobuf/codegenv2\");\nexports.file_a = (0, codegenv2_1.fileDesc)(\"{PROTO3}\");\n");
    assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.js", &tsc)]).quiet());
    for tail in ["console.log(exports[getKey()]);\n", "console.log(module.exports);\n", "console.log(this[getKey()]);\n", "console.log(arguments[0]);\n", "Object.keys(exports);\n"] {
        let src = format!("{tsc}{tail}");
        assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.js", &src)]).kept("gen/a_pb.js"), "{tail}");
    }
    // a module that re-exports it (CommonJS: module.exports = require(…)) and reads its own exports
    let reexp = "module.exports = require(\"./gen/app_pb\");\nconsole.log(module.exports[getKey()]);\n";
    assert!(kept(&[("index.js", reexp)]));
    // B-3: a remap by a key that names the runtime otherwise, rollup's and vite's { find } aliases
    for pkg in [
        "{\"name\": \"x\", \"resolutions\": {\"**/@bufbuild/protobuf\": \"file:./loader\"}}",
        "{\"name\": \"x\", \"pnpm\": {\"overrides\": {\"@bufbuild/protobuf@2\": \"link:./loader\"}}}",
    ] {
        assert!(Scan::of(&[("package.json", pkg), ("gen/app_pb.ts", &gen_file)]).kept("gen/app_pb.ts"), "{pkg}");
    }
    for cfg in [
        "export default { resolve: { alias: [{ find: \"@bufbuild/protobuf/codegenv2\", replacement: \"/src/x.ts\" }] } };\n",
        "export default { resolve: { alias: [{ find: /^@bufbuild\\/protobuf/, replacement: \"/src/x.ts\" }] } };\n",
    ] {
        assert!(kept(&[("vite.config.ts", cfg)]), "{cfg}");
    }
}

#[test]
fn a_member_named_eval_is_not_eval() {
    // protovalidate's evaluators (`eval(val, cursor) {`), googleapis' conformance service (`eval: {` in a type), a
    // key or a method named require, import or with: definitions, not references; and the references beside them
    let gen_file = gen("file_app", PROTO3);
    let with = |src: &str| Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", gen_file.as_str()), ("src/x.ts", src)]);
    for src in [
        "export class E {\n  constructor(c) {\n    this.c = c;\n  }\n  eval(val, cursor) {\n    return val === this.c;\n  }\n}\n",
        "export type S = {\n  parse: { kind: 1 },\n  eval: { kind: 2 },\n};\n",
        "export const o = { eval: 1, require: 2, import: 3, with: 4, Function: 5 };\n",
        "export const p = {\n  eval(x) { return x; },\n  require(id) { return id; },\n  import(s) { return s; },\n  with(o) { return o; },\n};\n",
        "export interface I {\n  eval(x: string): boolean;\n  get eval2(): number;\n}\n",
    ] {
        assert!(with(src).quiet(), "{src}: {:?}", with(src).decide());
    }
    for src in [
        "export const r = c ? eval : null;\n",
        "export const r = run(eval);\n",
        "export const r = (0, eval)(getText());\n",
        "eval(getText())\n{ }\n",
        "export const r = c ? (b, eval(getText())) : d;\n",
        "export const o = { eval };\n",
    ] {
        assert!(with(src).kept("gen/app_pb.ts"), "{src}");
    }
}

#[test]
fn the_loader_must_be_the_runtimes() {
    let d = PROTO3;
    let gen_file = gen("file_app", d);
    // bound another way (B-1's controls before the review, kept)
    for src in [
        format!("export const file_a = fileDesc(\"{d}\");\n"),
        format!("function fileDesc(s) {{ return eval(atob(s)); }}\nexport const file_a = fileDesc(\"{d}\");\n"),
        format!("{IMP}function fileDesc(s) {{ return s; }}\nexport const file_a = fileDesc(\"{d}\");\n"),
        format!("import {{ fileDesc }} from \"./codegenv2\";\nexport const file_a = fileDesc(\"{d}\");\n"),
        format!("import type {{ fileDesc }} from \"@bufbuild/protobuf/codegenv2\";\nexport const file_a = fileDesc(\"{d}\");\n"),
        format!("import {{ boot as fileDesc }} from \"@bufbuild/protobuf/codegenv2\";\nexport const file_a = fileDesc(\"{d}\");\n"),
        format!("{IMP}export const g = (fileDesc) => fileDesc(\"{d}\");\n"),
        format!("{IMP}{IMP}export const file_a = fileDesc(\"{d}\");\n"),
        format!("{IMP}export const file_a = fileDesc(\"{d}\" + tail);\n"),
        format!("{IMP}export const file_a = other.fileDesc(\"{d}\");\n"),
        format!("{IMP}let file_a = fileDesc(\"{d}\");\n"),
        format!("{IMP}export const file_a = fileDesc(\"{d}\"), b = 1;\n"),
        format!("var cg = require(\"@bufbuild/protobuf/codegenv2\");\nvar cg;\nexports.file_a = cg.fileDesc(\"{d}\");\n"),
        format!("const cg = require(\"@bufbuild/protobuf/codegenv2\");\nObject.assign(cg, {{}});\nexports.file_a = (0, cg.fileDesc)(\"{d}\");\n"),
        format!("const cg = require(\"@bufbuild/protobuf/codegenv2\");\ncg[\"fileDesc\"] = function (s) {{ return s; }};\nexports.file_a = cg.fileDesc(\"{d}\");\n"),
        format!("function require(m) {{ return {{ fileDesc: eval }}; }}\nconst cg = require(\"@bufbuild/protobuf/codegenv2\");\nexports.file_a = (0, cg.fileDesc)(\"{d}\");\n"),
    ] {
        assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.js", &src)]).kept("gen/a_pb.js"), "{}", src.lines().take(2).collect::<Vec<_>>().join(" | "));
    }
    // B-3: the module remapped by the project
    for pkg in [
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"npm:some-other-package@1.0.0\"}}",
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"file:../loader\"}}",
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"link:./loader\"}}",
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"github:someone/loader\"}}",
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"git+https://example.invalid/x.git\"}}",
        "{\"name\": \"x\", \"dependencies\": {\"@bufbuild/protobuf\": \"workspace:*\"}}",
        "{\"name\": \"x\", \"overrides\": {\"@bufbuild/protobuf\": \"npm:other@1\"}}",
        "{\"name\": \"x\", \"pnpm\": {\"overrides\": {\"a>@bufbuild/protobuf\": \"link:../x\"}}}",
        "{\"name\": \"x\", \"resolutions\": {\"@bufbuild/protobuf@^2\": \"file:./x.tgz\"}}",
        "{ not json",
    ] {
        assert!(Scan::of(&[("package.json", pkg), ("gen/app_pb.ts", &gen_file)]).kept("gen/app_pb.ts"), "{pkg}");
    }
    for cfg in [
        "{\"compilerOptions\": {\"baseUrl\": \".\", \"paths\": {\"@bufbuild/protobuf/codegenv2\": [\"src/loader.ts\"]}}}",
        "{\"compilerOptions\": {\"paths\": {\"@bufbuild/*\": [\"vendor/*\"]}}}",
        "{\"compilerOptions\": {\"paths\": {\"*\": [\"types/*\"]}}}",
        "{\n  // a comment\n  \"compilerOptions\": {\"paths\": {\"@bufbuild/protobuf\": [\"x\"],},},\n}",
    ] {
        let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", cfg), ("gen/app_pb.ts", &gen_file)]);
        assert!(s.kept("gen/app_pb.ts"), "{cfg}");
    }
    // the runtime's module written to from another file (CommonJS's exports are an object)
    for other in [
        "require(\"@bufbuild/protobuf/codegenv2\").fileDesc = (s) => s;\n",
        "const cg = require(\"@bufbuild/protobuf/codegenv2\");\ncg.fileDesc = (s) => s;\n",
        "const pb = require(\"@bufbuild/protobuf\");\npatch(pb);\n",
    ] {
        let s = Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &gen_file), ("src/patch.js", other)]);
        assert!(s.kept("gen/app_pb.ts"), "{other}");
    }
    let reads = "const cg = require(\"@bufbuild/protobuf/codegenv2\");\nconst pb = require(\"@bufbuild/protobuf\");\nexports.m = pb.create(cg.messageDesc);\n";
    assert!(Scan::of(&[("package.json", PKG), ("gen/app_pb.ts", &gen_file), ("src/read.js", reads)]).quiet());
    // a config extended: read (quiet), a package's the scan did not read (kept), one of a --deps tree's (read)
    let base_cfg = "{\"compilerOptions\": {\"strict\": true}}";
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", "{\"extends\": \"./tsconfig.base.json\"}"),
        ("tsconfig.base.json", base_cfg), ("gen/app_pb.ts", &gen_file)]);
    assert!(s.quiet(), "{:?}", s.decide());
    let pkg_ext = "{\"extends\": [\"@tsconfig/node20/tsconfig.json\", \"./tsconfig.base.json\"]}";
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", pkg_ext), ("tsconfig.base.json", base_cfg), ("gen/app_pb.ts", &gen_file)]);
    assert!(s.kept("gen/app_pb.ts"));
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", pkg_ext), ("tsconfig.base.json", base_cfg), ("gen/app_pb.ts", &gen_file),
        ("node_modules/@tsconfig/node20/tsconfig.json", base_cfg)]);
    assert!(s.quiet(), "{:?}", s.decide());
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", "{\"extends\": \"./missing.json\"}"), ("gen/app_pb.ts", &gen_file)]);
    assert!(s.kept("gen/app_pb.ts"));
    let mut s = Scan::of(&[("package.json", PKG), ("tsconfig.json", base_cfg), ("gen/app_pb.ts", &gen_file)]);
    assert!(s.quiet());
    s.unreadable = vec!["tsconfig.json".to_string()];
    assert!(s.kept("gen/app_pb.ts"));
    // the other files that say where modules are, a bundler's alias, an import map, a package's browser field
    for (path, text) in [
        ("deno.json", "{\"imports\": {\"@bufbuild/protobuf/codegenv2\": \"./src/loader.ts\"}}"),
        (".babelrc", "{\"plugins\": [[\"module-resolver\", {\"alias\": {\"@bufbuild/protobuf\": \"./src\"}}]]}"),
        ("vite.config.ts", "export default { resolve: { alias: { \"@bufbuild/protobuf/codegenv2\": \"/src/loader.ts\" } } };\n"),
        ("index.html", "<script type=\"importmap\">{\"imports\": {\"@bufbuild/protobuf/codegenv2\": \"/loader.js\"}}</script>\n"),
        ("package.json", "{\"name\": \"x\", \"browser\": {\"@bufbuild/protobuf/codegenv2\": \"./loader.js\"}}"),
    ] {
        let mut files = vec![("gen/app_pb.ts", gen_file.as_str()), (path, text)];
        if path != "package.json" {
            files.push(("package.json", PKG));
        }
        assert!(Scan::of(&files).kept("gen/app_pb.ts"), "{path}");
    }
    // a bundler's configuration that names the runtime otherwise
    let vite = "import { defineConfig } from \"vite\";\nexport default defineConfig({ optimizeDeps: { include: [\"@bufbuild/protobuf\"] } });\n";
    assert!(Scan::of(&[("package.json", PKG), ("vite.config.ts", vite), ("gen/app_pb.ts", &gen_file)]).quiet());
    // baseUrl with an @bufbuild folder under it
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", "{\"compilerOptions\": {\"baseUrl\": \"src\"}}"),
        ("src/@bufbuild/protobuf/codegenv2.ts", "export function fileDesc(s) { return s; }\n"), ("gen/app_pb.ts", &gen_file)]);
    assert!(s.kept("gen/app_pb.ts"));
    // other paths are the project's own business
    let s = Scan::of(&[("package.json", PKG), ("tsconfig.json", "{\"compilerOptions\": {\"baseUrl\": \".\", \"paths\": {\"@/*\": [\"src/*\"]}}}"),
        ("gen/app_pb.ts", &gen_file)]);
    assert!(s.quiet(), "{:?}", s.decide());
    // a package's own copy of the runtime (its scan), not a checkout's installed one
    let files = [("package.json", PKG), ("gen/app_pb.ts", gen_file.as_str()),
        ("node_modules/@bufbuild/protobuf/dist/cjs/codegenv2/file.js", "exports.fileDesc = (s) => s;\n")];
    let mut s = Scan::of(&files);
    assert!(s.quiet());
    s.package = true;
    assert!(s.kept("gen/app_pb.ts"));
}

#[test]
fn what_the_scan_did_not_read_keeps_it() {
    let gen_file = gen("file_app", PROTO3);
    let base = [("package.json", PKG), ("gen/app_pb.ts", gen_file.as_str())];
    let mut s = Scan::of(&base);
    assert!(s.quiet());
    s.stopped = true;
    assert!(s.kept("gen/app_pb.ts"));
    for unread in ["src/big.js", "src/link.ts", ".", "vendor", "page.vue"] {
        let mut s = Scan::of(&base);
        s.unread = vec![unread.to_string()];
        assert!(s.kept("gen/app_pb.ts"), "{unread}");
    }
    // a data file not read is not code
    let mut s = Scan::of(&base);
    s.unread = vec!["data/big.csv".to_string()];
    assert!(s.quiet());
    let mut files = base.to_vec();
    files.push(("src/App.vue", "<script>x</script>"));
    let mut s = Scan::of(&files);
    s.unreadable = vec!["src/App.vue".to_string()];
    assert!(s.kept("gen/app_pb.ts"));
    // a line with a second blob of another kind
    let two = format!("{IMP}export const file_a = fileDesc(\"{}\"); const z = \"{}\";\n", PROTO3, b64(&b"console.log('inert');\n".repeat(12)));
    assert!(Scan::of(&[("package.json", PKG), ("gen/a_pb.ts", &two)]).kept("gen/a_pb.ts"));
}

#[test]
fn many_descriptors_in_one_file_cost_what_one_does_each() {
    // the review's cost case (B-2): K lines `export const f<k> = fileDesc("<descriptor>")`
    let time = |k: usize| {
        let mut src = String::from(IMP);
        for j in 0..k {
            src.push_str(&format!("export const f{j} = fileDesc(\"{}\");\n", b64(&made(&format!("a/p{j}.proto"), b""))));
        }
        let s = Scan::of(&[("package.json", PKG), ("gen/all_pb.ts", &src)]);
        let t = std::time::Instant::now();
        let d = s.decide();
        let secs = t.elapsed().as_secs_f64();
        assert_eq!(d.len(), k);
        assert!(d.iter().all(|(_, _, why)| why.is_none()), "{:?}", d.iter().find(|x| x.2.is_some()));
        secs
    };
    let (small, large) = (time(250), time(1000));
    // four times the literals: about four times the work, never sixteen
    assert!(large < 8.0 * small + 0.5, "{small:.3}s for 250, {large:.3}s for 1000");
}

// The external hostile review's adversarial tests (Oct 28: SOUND, no bypass; its 9 adopted as they were, at
// stacking)

/// Deeply nested messages at MAX_DEPTH boundary
fn deeply_nested(depth: usize) -> Vec<u8> {
    let mut inner = ld(1, b"Inner");
    for i in (0..depth).rev() {
        let name = format!("M{}", i);
        inner = [ld(1, name.as_bytes()), ld(3, &inner)].concat();
    }
    let mut out = ld(1, b"deep.proto");
    out.extend(ld(2, b"test"));
    out.extend(ld(4, &inner));
    out.extend(ld(12, b"proto3"));
    out
}

#[test]
fn adversarial_depth_boundary() {
    // At depth 64 (MAX_DEPTH): should still parse
    assert!(file_descriptor(&deeply_nested(63)), "depth 63 should pass");
    // At depth 65: should fail (depth > MAX_DEPTH check is depth > 64)
    assert!(!file_descriptor(&deeply_nested(64)), "depth 64 should fail (depth > MAX_DEPTH)");
    // Way beyond: should fail fast
    assert!(!file_descriptor(&deeply_nested(200)), "depth 200 should fail");
}

#[test]
fn adversarial_default_value_boundary() {
    // Exactly MAX_DEFAULT (64) chars: should pass
    let field = [ld(1, b"x"), vi(3, 1), vi(4, 1), vi(5, 9), ld(7, "A".repeat(MAX_DEFAULT).as_bytes())].concat();
    let msg = [ld(1, b"M"), ld(2, &field)].concat();
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(12, b"proto3")].concat();
    assert!(file_descriptor(&desc), "64-char default should pass");

    // One over: should fail
    let field = [ld(1, b"x"), vi(3, 1), vi(4, 1), vi(5, 9), ld(7, "A".repeat(MAX_DEFAULT + 1).as_bytes())].concat();
    let msg = [ld(1, b"M"), ld(2, &field)].concat();
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(12, b"proto3")].concat();
    assert!(!file_descriptor(&desc), "65-char default should fail");
}

#[test]
fn adversarial_source_code_info_rejected() {
    // Field 9 (source_code_info) must cause rejection
    let msg = ld(1, b"M");
    let source_info = ld(1, b"comment text here");
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(9, &source_info), ld(12, b"proto3")].concat();
    assert!(!file_descriptor(&desc), "source_code_info must be rejected");
}

#[test]
fn adversarial_trailing_bytes_rejected() {
    let msg = ld(1, b"M");
    let mut desc = [ld(1, b"a.proto"), ld(4, &msg), ld(12, b"proto3")].concat();
    desc.extend(b"\x00\x00\x00");
    assert!(!file_descriptor(&desc), "trailing bytes must be rejected");
}

#[test]
fn adversarial_empty_rejected() {
    assert!(!file_descriptor(&[]), "empty must be rejected");
}

#[test]
fn adversarial_json_name_mismatch_rejected() {
    // Field "my_field" should derive json_name "myField", not "wrong"
    let field = [ld(1, b"my_field"), vi(3, 1), vi(4, 1), vi(5, 9), ld(10, b"wrong")].concat();
    let msg = [ld(1, b"M"), ld(2, &field)].concat();
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(12, b"proto3")].concat();
    assert!(!file_descriptor(&desc), "mismatched json_name must be rejected");

    // Correct derived name should pass
    let field = [ld(1, b"my_field"), vi(3, 1), vi(4, 1), vi(5, 9), ld(10, b"myField")].concat();
    let msg = [ld(1, b"M"), ld(2, &field)].concat();
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(12, b"proto3")].concat();
    assert!(file_descriptor(&desc), "correct json_name should pass");
}

// (large custom option test removed - covered by existing the_generators_descriptors_are_read_to_their_end)

#[test]
fn adversarial_many_fields_linear_cost() {
    use std::time::Instant;
    let build = |count: usize| {
        let mut fields = vec![];
        for i in 0..count {
            let name = format!("f{}", i);
            let field = [ld(1, name.as_bytes()), vi(3, (i+1) as u64), vi(4, 1), vi(5, 5)].concat();
            fields.extend(ld(2, &field));
        }
        let msg = [ld(1, b"M"), fields].concat();
        [ld(1, b"big.proto"), ld(2, b"t"), ld(4, &msg), ld(12, b"proto3")].concat()
    };

    let d100 = build(100);
    let t1 = Instant::now();
    assert!(file_descriptor(&d100));
    let e1 = t1.elapsed();

    let d1000 = build(1000);
    let t2 = Instant::now();
    assert!(file_descriptor(&d1000));
    let e2 = t2.elapsed();

    // 10x more fields should take roughly 10x longer (linear), not quadratic
    // Allow generous margin: 50x would still be acceptable
    let ratio = e2.as_nanos() as f64 / e1.as_nanos().max(1) as f64;
    assert!(ratio < 50.0, "cost should be linear: 1000/100 fields took {:.1}x (limit 50x)", ratio);
}

#[test]
fn adversarial_unknown_field_number_rejected() {
    // A field number not in descriptor.proto should be rejected
    let msg = ld(1, b"M");
    let unknown = ld(999, b"unknown field data"); // field 999 doesn't exist
    let desc = [ld(1, b"a.proto"), ld(4, &msg), ld(999, &unknown), ld(12, b"proto3")].concat();
    assert!(!file_descriptor(&desc), "unknown field number must be rejected");
}

#[test]
fn adversarial_wrong_wire_type_rejected() {
    // Field 1 (name) should be length-delimited (wire type 2), not varint (wire type 0)
    let wrong = vi(1, 42); // varint instead of string
    let desc = [wrong, ld(2, b"pkg"), ld(12, b"proto3")].concat();
    assert!(!file_descriptor(&desc), "wrong wire type must be rejected");
}
