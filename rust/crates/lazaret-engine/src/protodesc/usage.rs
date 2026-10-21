//! FP-B64-PROTOBUF over the whole scan (the engine's `b64_descriptors`; the review of Oct 27, B-1 to B-3).
//!
//! A descriptor is data the runtime keeps and the program can read back (`file_x.proto…`): one that only
//! generated code touches is passed over, one that anything else could read is not. So the file scan keeps
//! reporting SC-B64, and a scan that has read a project, a `--deps` tree or a package whole asks this pass which
//! findings to drop. A finding is dropped when every run of its line that SC-B64 counts is a descriptor
//! ([`super::file_descriptor`]) and all of these hold, else it stays (fail closed):
//!
//! - **the scan read everything**: it did not stop, no JavaScript file (nor a folder, nor a file of a kind that
//!   holds script: `_SCRIPT_HOLDER_EXTS`) is SC-TRUNCATED, unreadable or a link (`_B64_DESCRIPTOR_UNREAD`), and each
//!   such holder (.vue, .svelte, .html …) was read: its text, its script blocks and its handlers are read with the
//!   files;
//! - **the literal is the whole first argument of the loader**, bound as generated code binds it (`fileDesc` of the
//!   pack's `_B64_DESCRIPTOR_LOADERS` modules imported or required once and only called; `x.fileDesc`, `(0,
//!   x.fileDesc)` with `x` bound once to that module and never written; `require` not rebound), the call followed
//!   by nothing but its dependency list, and its value bound and nothing else: `export const file_x = fileDesc(…)`,
//!   `const file_x = …` (protoc-gen-es's CommonJS), `exports.file_x = (0, x.fileDesc)(…)` (TypeScript's);
//! - **the descriptor is used only as generated code uses it, in every file of the scan**: `file_x` (or `m.file_x`)
//!   is the first argument of the loader's `messageDesc`, `enumDesc`, `serviceDesc` or `extDesc`, an element of
//!   another `fileDesc`'s dependency list, an argument of the runtime's registry constructors
//!   (`_B64_DESCRIPTOR_CONSUMERS`: protovalidate builds its registry so), a name in an import's, an export's or a
//!   destructured require's list (not renamed), and in its own file `exports.file_x = file_x` or TypeScript's
//!   `exports.… = exports.file_x = … = void 0`; nothing else names it, no string holds the name, and no string but a
//!   module specifier names its file (a path handed to `fs`, `new URL`, `require.resolve`);
//! - **its module is read for its members alone, wherever it may be loaded** (`modules`): every specifier of the
//!   scan is resolved as far as the scan can tell (a relative path; a tsconfig's or jsconfig's `paths` and
//!   `baseUrl`; a package the scan holds, by its name, any of its files; a package the manifests declare by a version
//!   range, or one of Node's, names none of the scan's files; anything else — undeclared, a `#` import, a name a
//!   manifest maps elsewhere or the code aliases — may name any), its file name read as a name too (case aside), and
//!   each module object that may be it is read only for its members (`m.y`, never written, never loaded whole:
//!   `import(…)`, a `require(…)` handed on, followed by anything but its statement's end, a rest or computed
//!   destructuring, `export * as`, a helper such as `__importStar`, a `?raw` or loader-prefixed import,
//!   `import.meta.glob`); a module that re-exports it is held to the same, and so is the module's own scope: no
//!   `exports`, `module`, `this` or `arguments` but `exports.y`, `this.y`, `this && …` and
//!   `Object.defineProperty(exports, "__esModule", …)` (they would read its exports by a name made at run time);
//! - **no code of the scan runs text or reaches the module registry**: no `eval`, `Function`, vm call or `with` but
//!   with literals alone, no `.constructor(…)` call of text, no global looked up by a name made at run time
//!   (`globalThis[x]`), no module loaded by a name made at run time (`require(x)`, `import(x)`, `createRequire`,
//!   `require.context`), no `require.cache`, `require.main`, `module.children`, `module.parent`,
//!   `process.mainModule`, `process.binding`, and no module of `_B64_RUNNER_MODULES` loaded (`child_process`,
//!   `worker_threads`, `vm`, `module` …);
//! - **the loader is the runtime's** (B-3): no package.json from the descriptor's folder up maps
//!   `@bufbuild/protobuf` or a module of it to another package or a file (an `npm:`, `file:`, `link:`, git or URL
//!   spec, `workspace:`: anything but a version range; in its dependencies, overrides, resolutions, `browser` …,
//!   under any key that names it); a package does not carry its own copy in its node_modules (a package's scan); no
//!   tsconfig or jsconfig of the scan has a `paths` entry that matches the runtime's modules (`*` patterns too), a
//!   `baseUrl` that holds an `@bufbuild` folder, or an `extends` the scan did not read; no other file that tells a
//!   tool where modules are (`_B64_RESOLVER_CONFIGS`: Babel's, SWC's, Deno's, Bun's, an import map) names
//!   `@bufbuild/protobuf`; no code (a bundler's configuration, an import map in a page) has `"@bufbuild/protobuf…"`
//!   as an object's key or a `find:`; and no code uses a module of the runtime whole.
//!
//! Cost: each unit is lexed once (twice with JSX); each reading's names, brackets and `void 0` chains are indexed
//! once (`Index`), so every question asked of a token is answered without a walk; each specifier is resolved once,
//! and a module's readers are found through an index of the keys a specifier may name a file by.

use crate::autorun::{parse_jsonc, JKind, JNode};
use crate::filectx::{pin, source_text, Lang};
use crate::lex::{Kind, Token};
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The pass's input: the scan's files and what it knows of what it did not read. Paths are '/'-separated.
pub struct Input {
    /// every JavaScript-family file the scan read whole (lang "js"): path, text
    pub files: Vec<(String, PyStr)>,
    /// every file of a kind that holds script the file scan does not read (`_SCRIPT_HOLDER_EXTS`): its text, None
    /// when it could not be read whole
    pub holders: Vec<(String, Option<PyStr>)>,
    /// every package.json the scan read
    pub manifests: Vec<(String, PyStr)>,
    /// the scan's files that may tell a bundler or a compiler where a module is (tsconfig*.json, jsconfig*.json,
    /// `_B64_RESOLVER_CONFIGS`): its text, None when it could not be read whole
    pub configs: Vec<(String, Option<PyStr>)>,
    /// the SC-B64 findings to decide: path, line
    pub findings: Vec<(String, usize)>,
    /// the paths of the scan's SC-TRUNCATED, Q-UNREADABLE and Q-SYMLINK findings ("." for the scan itself)
    pub unread: Vec<String>,
    /// did the scan stop before its end?
    pub stopped: bool,
    /// a package's scan (its own node_modules is what it carries), not a checkout's
    pub package: bool,
}

/// Each finding's decision: None when it is dropped, else why it stays.
pub type Decision = (String, usize, Option<String>);

type Table<'p> = &'p [(Vec<u32>, Vec<Vec<u32>>)];

/// The extensions of the files the scan reads as JavaScript.
const CODE_EXTS: [&str; 8] = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];

/// The extensions a module specifier may leave out (or name for another: TypeScript's "./x.js" is x.ts).
const STEM_EXTS: [&str; 16] = [
    ".d.ts", ".d.mts", ".d.cts", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json", ".vue", ".svelte",
    ".astro", ".mdx",
];

/// Node's own modules: a bare specifier of one (or of a path under one, `fs/promises`) names no file of the scan,
/// unless the scan's code or manifests alias it.
const NODE_BUILTINS: [&str; 43] = [
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os",
    "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
    "test", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
];

fn ext_of(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    base.rfind('.').map_or(String::new(), |k| base[k..].to_string())
}

fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |k| &path[..k])
}

fn base_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn stem(path: &str) -> &str {
    let low = path.to_ascii_lowercase();
    for e in STEM_EXTS {
        if low.ends_with(e) && path.len() > e.len() {
            return &path[..path.len() - e.len()];
        }
    }
    path
}

/// `rel` joined to the folder `dir` ("/x": from the scan's root), "." and ".." read; None when it leaves the scan.
fn join(dir: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = if rel.starts_with('/') || dir.is_empty() { Vec::new() } else { dir.split('/').collect() };
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            x => parts.push(x),
        }
    }
    Some(parts.join("/"))
}

/// Is `a` the folder `b` or one above it?
fn at_or_above(a: &str, b: &str) -> bool {
    a.is_empty() || a == b || (b.starts_with(a) && b.as_bytes().get(a.len()) == Some(&b'/'))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    /// a JavaScript-family file the scan read
    File,
    /// a holder's whole text: its words (a descriptor's name anywhere in it is a use no pass can follow)
    Whole,
    /// a holder's script: a script block, front matter, an event handler, a template's expression
    Block,
}

struct Unit {
    path: String,
    part: Part,
    /// a declaration file (types alone: nothing of it runs)
    dts: bool,
    content: Vec<u32>,
    /// the tokens of each reading (with JSX and without for a file that may hold it), comments left out (none for a
    /// holder's whole text: its words are read as they are)
    readings: Vec<Vec<Token>>,
    starts: OnceCell<Vec<usize>>,
}

impl Unit {
    /// Where each line begins.
    fn starts(&self) -> &[usize] {
        self.starts.get_or_init(|| {
            let mut s = vec![0usize];
            s.extend(self.content.iter().enumerate().filter(|(_, &c)| c == '\n' as u32).map(|(i, _)| i + 1));
            s
        })
    }

    /// The 1-based line of the offset `at`.
    fn line_at(&self, at: usize) -> usize {
        self.starts().partition_point(|&s| s <= at)
    }
}

/// The text as scan_file reads it (filectx: its newlines normalized, pinned).
fn read_text(text: &[u32]) -> Vec<u32> {
    let mut content = source_text(text, Lang::Js);
    if !pystr::is_ascii(&content) {
        pin(&mut content);
    }
    content
}

fn unit(path: &str, part: Part, content: Vec<u32>, jsx_too: bool) -> Unit {
    let readings = if part == Part::Whole {
        Vec::new()
    } else if jsx_too {
        vec![false, true]
    } else {
        vec![false]
    };
    let readings = readings
        .into_iter()
        .map(|j| crate::lex::js::tokens(&content, j).iter().filter(|t| t.kind != Kind::Comment).copied().collect())
        .collect();
    let low = path.to_ascii_lowercase();
    let dts = part == Part::File && [".d.ts", ".d.mts", ".d.cts"].iter().any(|e| low.ends_with(e));
    Unit { path: path.to_string(), part, dts, content, readings, starts: OnceCell::new() }
}

/// An attribute's name is looked for this far back from its `=` (a longer one is taken for one that holds code).
const ATTR_NAME_MAX: usize = 256;

/// The script a holder carries: its `<script>` blocks, an Astro file's front matter, its event handlers' and
/// `javascript:` URLs' code (`on…="…"`, `@click="…"`, `v-on:…="…"`, `:x="…"`), and in a component's or an MDX
/// file's markup (`expressions`) each `{…}` and `import`/`export` line.
fn holder_blocks(text: &[u32], expressions: bool) -> Vec<Vec<u32>> {
    let low: Vec<u32> = text.iter().map(|&c| if (0x41..=0x5a).contains(&c) { c + 32 } else { c }).collect();
    let find = |from: usize, w: &str| -> Option<usize> {
        let w = pystr::u(w);
        (from..low.len().saturating_sub(w.len() - 1)).find(|&i| low[i..i + w.len()] == w[..])
    };
    let mut out = Vec::new();
    // <script …>…</script>
    let mut i = 0;
    while let Some(a) = find(i, "<script") {
        let Some(open_end) = find(a, ">") else { break };
        let end = find(open_end, "</script").unwrap_or(text.len());
        out.push(text[open_end + 1..end].to_vec());
        i = end;
    }
    // ---\n…\n--- (front matter)
    if pystr::starts_with(text, "---") {
        if let Some(e) = find(3, "\n---") {
            out.push(text[3..e].to_vec());
        }
    }
    // attributes that hold code: on…, @…, v-on:…, and javascript: URLs
    let mut k = 0;
    while k < text.len() {
        if text[k] == '=' as u32 && k + 1 < text.len() && (text[k + 1] == '"' as u32 || text[k + 1] == '\'' as u32) {
            let q = text[k + 1];
            let mut a = k;
            let floor = k.saturating_sub(ATTR_NAME_MAX);
            while a > floor && !(text[a - 1] == ' ' as u32 || text[a - 1] == '\n' as u32 || text[a - 1] == '\t' as u32 || text[a - 1] == '<' as u32) {
                a -= 1;
            }
            // (a name longer than the bound, or none found: read the value as code)
            let unbounded = a == floor && floor > 0;
            let name: String = low[a..k].iter().filter_map(|&c| char::from_u32(c)).collect();
            let close = (k + 2..text.len()).find(|&j| text[j] == q).unwrap_or(text.len());
            let value = &text[k + 2..close];
            let vlow: String = value.iter().take(16).filter_map(|&c| char::from_u32(c)).collect::<String>().to_ascii_lowercase();
            if unbounded
                || (name.starts_with("on") && name.len() > 2)
                || name.starts_with('@')
                || name.starts_with("v-on:")
                || name.starts_with(':')
                || name.starts_with("v-bind:")
                || vlow.trim_start().starts_with("javascript:")
            {
                out.push(value.to_vec());
            }
            k = close;
        }
        k += 1;
    }
    if expressions {
        // {…} (outermost), and the lines that begin with import or export
        let mut depth = 0usize;
        let mut open = 0usize;
        for (i, &c) in text.iter().enumerate() {
            if c == '{' as u32 {
                if depth == 0 {
                    open = i + 1;
                }
                depth += 1;
            } else if c == '}' as u32 && depth > 0 {
                depth -= 1;
                if depth == 0 {
                    out.push(text[open..i].to_vec());
                }
            }
        }
        let mut lines: Vec<u32> = Vec::new();
        for l in text.split(|&c| c == '\n' as u32) {
            let t: Vec<u32> = l.iter().copied().skip_while(|&c| c == ' ' as u32 || c == '\t' as u32).collect();
            if pystr::starts_with(&t, "import ") || pystr::starts_with(&t, "export ") {
                lines.extend_from_slice(l);
                lines.push('\n' as u32);
            }
        }
        if !lines.is_empty() {
            out.push(lines);
        }
    }
    out
}

// ---- one reading of a unit -------------------------------------------------------------------------------------

/// No token (an index's empty slot).
const NONE: u32 = u32::MAX;
// What an open bracket holds directly (Index::content's bits).
/// every token directly inside is a name, `.` or `,`
const PLAIN: u8 = 1;
/// a `.` directly inside
const DOT: u8 = 2;
/// an `as` directly inside
const AS: u8 = 4;
/// a `...` directly inside
const REST: u8 = 8;
/// a bracket inside
const NESTED: u8 = 16;

/// A reading's tokens indexed once, so that no question asked of a token walks the reading (B-2).
struct Index {
    /// each name's tokens, by its text
    occ: HashMap<Vec<u32>, Vec<u32>>,
    /// the innermost open bracket around each token (a closing bracket's: the one it closes; NONE: none)
    open: Vec<u32>,
    /// an open bracket's closing one (NONE: not closed), by its token
    close: Vec<u32>,
    /// an open bracket's content (PLAIN, DOT, AS, REST, NESTED), by its token
    content: Vec<u8>,
    /// the `=` tokens from which `exports.a = exports.b = … = void 0` runs to its `void 0`
    voided: Vec<bool>,
}

struct R<'a> {
    s: &'a [u32],
    t: &'a [Token],
    bound: RefCell<HashMap<Vec<u32>, bool>>,
    objects: RefCell<HashMap<(usize, Vec<u32>), bool>>,
    req: OnceCell<bool>,
    ix: OnceCell<Index>,
}

/// What made a reading's code unsafe to pass a descriptor in: code run from text, a module loaded by a name made at
/// run time, the module registry reached.
struct Hit {
    at: usize,
    what: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RefKind {
    /// a module object: `import * as m`, a default import, `m = require(…)` (its binding token)
    Object(usize),
    /// re-exported: `export * from`, `export { … } from`, `module.exports = require(…)`
    ReExport,
    /// `import("…")`
    Dynamic,
    /// a module required and handed on whole (`f(require("…"))`, `x = require("…")`, `require("…")[k]`, a
    /// destructuring with a rest or a computed key, `export * as ns`, a helper's `__importStar(require("…"))`, a
    /// `?raw` or loader-prefixed import)
    Loose,
    /// `import.meta.glob("…")` and `import(`…${x}`)`: the modules under a folder
    Glob,
    /// a static import of names alone, or of the module's side effects: its members are named, and checked by name
    Named,
}

struct Ref {
    spec: Vec<u32>,
    kind: RefKind,
}

impl<'a> R<'a> {
    fn new(s: &'a [u32], t: &'a [Token]) -> R<'a> {
        R {
            s,
            t,
            bound: RefCell::new(HashMap::new()),
            objects: RefCell::new(HashMap::new()),
            req: OnceCell::new(),
            ix: OnceCell::new(),
        }
    }

    fn len(&self) -> usize {
        self.t.len()
    }

    fn text(&self, k: usize) -> &'a [u32] {
        let t = &self.t[k];
        &self.s[t.start as usize..t.end as usize]
    }

    fn kind(&self, k: usize) -> Option<Kind> {
        self.t.get(k).map(|t| t.kind)
    }

    fn is(&self, k: usize, w: &str) -> bool {
        k < self.t.len() && pystr::eq(self.text(k), w)
    }

    /// Is token k the punctuator `w`?
    fn punct(&self, k: usize, w: &str) -> bool {
        self.kind(k) == Some(Kind::Punct) && pystr::eq(self.text(k), w)
    }

    /// Is token `k - n` the word `w`?
    fn back(&self, k: usize, n: usize, w: &str) -> bool {
        k >= n && self.is(k - n, w)
    }

    fn name(&self, k: usize, w: &[u32]) -> bool {
        k < self.t.len() && self.t[k].kind == Kind::Name && self.text(k) == w
    }

    fn is_name(&self, k: usize) -> bool {
        self.kind(k) == Some(Kind::Name)
    }

    /// Is token k a property access's name (after `.` or `?.`)?
    fn member(&self, k: usize) -> bool {
        k > 0 && (self.is(k - 1, ".") || self.is(k - 1, "?."))
    }

    /// Is there a line's end between tokens a and b (a < b)?
    fn newline_between(&self, a: usize, b: usize) -> bool {
        let (x, y) = (self.t[a].end as usize, self.t[b].start as usize);
        x < y && self.s[x..y].contains(&('\n' as u32))
    }

    /// Does token k begin a statement?
    fn stmt_start(&self, k: usize) -> bool {
        k == 0 || self.is(k - 1, ";") || self.is(k - 1, "}") || self.is(k - 1, "{") || self.newline_between(k - 1, k)
    }

    /// The reading's index, made at its first question.
    fn ix(&self) -> &Index {
        self.ix.get_or_init(|| {
            let n = self.len();
            let mut occ: HashMap<Vec<u32>, Vec<u32>> = HashMap::new();
            let mut open = vec![NONE; n];
            let mut close = vec![NONE; n];
            let mut content = vec![0u8; n];
            let mut stack: Vec<usize> = Vec::new();
            for k in 0..n {
                open[k] = stack.last().map_or(NONE, |&o| o as u32);
                if self.is_name(k) {
                    occ.entry(self.text(k).to_vec()).or_default().push(k as u32);
                }
                if self.punct(k, "(") || self.punct(k, "[") || self.punct(k, "{") {
                    if let Some(&o) = stack.last() {
                        content[o] = (content[o] & !PLAIN) | NESTED;
                    }
                    stack.push(k);
                    content[k] = PLAIN;
                } else if self.punct(k, ")") || self.punct(k, "]") || self.punct(k, "}") {
                    if let Some(o) = stack.pop() {
                        close[o] = k as u32;
                    }
                } else if let Some(&o) = stack.last() {
                    if !(self.is_name(k) || self.punct(k, ".") || self.punct(k, ",")) {
                        content[o] &= !PLAIN;
                    }
                    if self.punct(k, ".") {
                        content[o] |= DOT;
                    }
                    if self.is_name(k) && self.is(k, "as") {
                        content[o] |= AS;
                    }
                    if self.punct(k, "...") {
                        content[o] |= REST;
                    }
                }
            }
            let mut voided = vec![false; n];
            for eq in (0..n).rev() {
                if !self.punct(eq, "=") {
                    continue;
                }
                voided[eq] = (self.is(eq + 1, "void") && self.is(eq + 2, "0"))
                    || (self.is(eq + 1, "exports")
                        && self.is(eq + 2, ".")
                        && self.is_name(eq + 3)
                        && self.punct(eq + 4, "=")
                        && voided.get(eq + 4) == Some(&true));
            }
            Index { occ, open, close, content, voided }
        })
    }

    /// The tokens of the name `w` (member or not).
    fn occurrences(&self, w: &[u32]) -> &[u32] {
        self.ix().occ.get(w).map_or(&[], |v| v.as_slice())
    }

    /// The innermost open bracket around token k.
    fn open_of(&self, k: usize) -> Option<usize> {
        self.ix().open.get(k).copied().filter(|&o| o != NONE).map(|o| o as usize)
    }

    /// The closing bracket of the open one at k.
    fn close_of(&self, k: usize) -> Option<usize> {
        self.ix().close.get(k).copied().filter(|&c| c != NONE).map(|c| c as usize)
    }

    fn content(&self, k: usize) -> u8 {
        self.ix().content.get(k).copied().unwrap_or(0)
    }

    /// Token k's text when it is a literal string: '…' or "…" with no escape, or a template with no hole.
    fn literal(&self, k: usize) -> Option<&'a [u32]> {
        let kind = self.kind(k)?;
        let x = self.text(k);
        if x.len() < 2 || x.contains(&('\\' as u32)) {
            return None;
        }
        let q = x[0];
        match kind {
            Kind::Str if x[x.len() - 1] == q => Some(&x[1..x.len() - 1]),
            Kind::Template if q == '`' as u32 && x[x.len() - 1] == '`' as u32 && !pystr::contains(x, "${") => Some(&x[1..x.len() - 1]),
            _ => None,
        }
    }

    /// The static text a template with holes begins with (`./pages/${x}` → "./pages/").
    fn template_prefix(&self, k: usize) -> Option<&'a [u32]> {
        let x = self.text(k);
        (self.kind(k) == Some(Kind::Template) && x.first() == Some(&('`' as u32)) && pystr::ends_with(x, "${"))
            .then(|| &x[1..x.len() - 2])
    }

    /// Is token k a string literal naming one of `modules` ('…' or "…", no escapes)?
    fn module(&self, k: usize, modules: &[Vec<u32>]) -> bool {
        if self.kind(k) != Some(Kind::Str) {
            return false;
        }
        self.literal(k).is_some_and(|x| modules.iter().any(|m| x == &m[..]))
    }

    /// Is token k an assignment's operator (`=`, `+=`, `??=` …; not a comparison or an arrow)?
    fn assigned(&self, k: usize) -> bool {
        if self.kind(k) != Some(Kind::Punct) {
            return false;
        }
        let p = self.text(k);
        p.last() == Some(&('=' as u32)) && !["==", "===", "!=", "!==", "<=", ">=", "=>"].iter().any(|w| pystr::eq(p, w))
            || pystr::eq(p, "++")
            || pystr::eq(p, "--")
    }

    /// Does the call opened at `open` take literals alone (or nothing)?
    fn literal_args(&self, open: usize) -> bool {
        let mut m = open + 1;
        loop {
            if self.is(m, ")") {
                return true;
            }
            if self.literal(m).is_none() {
                return false;
            }
            if self.is(m + 1, ",") {
                m += 2;
            } else {
                return self.is(m + 1, ")");
            }
        }
    }

    // -- the loader's names (as the file scan read them before the review: one binding, calls alone)

    /// The token indices of the names `import { … } from "<module>"` (a value import: not `import type`, no `type`
    /// before the name, no `as`) and `const|let|var { … } = require("<module>")` bind, for `modules`.
    fn import_bindings(&self, modules: &[Vec<u32>]) -> Vec<usize> {
        let mut out = Vec::new();
        let n = self.len();
        for k in 0..n {
            let list = (self.is(k, "import") && !self.member(k) && self.is(k + 1, "{"))
                || ((self.is(k, "const") || self.is(k, "let") || self.is(k, "var")) && self.is(k + 1, "{"));
            if !list {
                continue;
            }
            let Some(j) = self.close_of(k + 1) else { continue };
            if self.content(k + 1) & (PLAIN | NESTED) != PLAIN {
                // (not a plain list of names: `:` renames, a default value, a nested pattern)
                let ok_colon = (k + 2..j).all(|m| self.is_name(m) || self.is(m, ",") || self.is(m, ":"));
                if !ok_colon {
                    continue;
                }
            }
            let plain: Vec<usize> = (k + 2..j)
                .filter(|&m| self.is_name(m) && (self.is(m - 1, "{") || self.is(m - 1, ",")) && (self.is(m + 1, ",") || self.is(m + 1, "}")))
                .collect();
            let ok = if self.is(k, "import") {
                self.is(j + 1, "from") && self.module(j + 2, modules)
            } else {
                self.is(j + 1, "=")
                    && self.is(j + 2, "require")
                    && !self.member(j + 2)
                    && self.is(j + 3, "(")
                    && self.module(j + 4, modules)
                    && self.is(j + 5, ")")
            };
            if ok {
                out.extend(plain);
            }
        }
        out
    }

    /// Is `name` bound once, by a value import (or a destructured `require`) of one of `modules`, and used nowhere
    /// else but in calls (`name(…)`, not after `function`)?
    fn bound(&self, name: &[u32], modules: &[Vec<u32>]) -> bool {
        if let Some(&b) = self.bound.borrow().get(name) {
            return b;
        }
        let bound = self.import_bindings(modules);
        let mut bindings = 0;
        let mut ok = true;
        for &k in self.occurrences(name) {
            let k = k as usize;
            if self.member(k) {
                continue;
            }
            if bound.contains(&k) {
                bindings += 1;
            } else if !(self.is(k + 1, "(") && !self.back(k, 1, "function") && !(self.back(k, 1, "*") && self.back(k, 2, "function"))) {
                ok = false; // bound or used another way: a declaration, a parameter, an assignment, a key …
                break;
            }
        }
        let b = ok && bindings == 1;
        self.bound.borrow_mut().insert(name.to_vec(), b);
        b
    }

    /// Is the name at token `x` bound once, to one of `modules` (`const|let|var x = require("<module>")`, `import *
    /// as x from "<module>"`), and everywhere else read for a property (`x.y`) that is not written to? (`table`:
    /// which modules, for the cache.)
    fn module_object(&self, x: usize, modules: &[Vec<u32>], table: usize) -> bool {
        let name = self.text(x).to_vec();
        if let Some(&b) = self.objects.borrow().get(&(table, name.clone())) {
            return b;
        }
        let mut bindings = 0;
        let mut ok = true;
        for &k in self.occurrences(&name) {
            let k = k as usize;
            if self.member(k) {
                continue;
            }
            let required = (self.back(k, 1, "const") || self.back(k, 1, "let") || self.back(k, 1, "var"))
                && self.is(k + 1, "=")
                && self.is(k + 2, "require")
                && self.is(k + 3, "(")
                && self.module(k + 4, modules)
                && self.is(k + 5, ")")
                && self.ends_statement_or_comma(k + 5);
            let imported = self.back(k, 1, "as")
                && self.back(k, 2, "*")
                && self.back(k, 3, "import")
                && self.is(k + 1, "from")
                && self.module(k + 2, modules);
            if required || imported {
                bindings += 1;
            } else if !(self.is(k + 1, ".") && self.is_name(k + 2) && !self.assigned(k + 3)) {
                ok = false;
                break;
            }
        }
        let b = ok && bindings == 1;
        self.objects.borrow_mut().insert((table, name), b);
        b
    }

    /// Is every `require` of the reading the runtime's: called, never declared, assigned or passed?
    fn require_intact(&self) -> bool {
        *self.req.get_or_init(|| {
            self.occurrences(&pystr::u("require")).iter().all(|&k| {
                let k = k as usize;
                self.member(k) || (self.is(k + 1, "(") && !self.back(k, 1, "function"))
            })
        })
    }

    /// The function of `table` the call opened at `open` calls, bound as the loader's names are bound (see the
    /// module's documentation): (its index in `table`, where the callee begins).
    fn callee(&self, open: usize, table: Table, tid: usize) -> Option<(usize, usize)> {
        if open == 0 || !self.is(open, "(") {
            return None;
        }
        let c = open - 1;
        for (i, (name, modules)) in table.iter().enumerate() {
            if self.name(c, name) && !self.member(c) {
                // fileDesc("…")
                return (self.bound(name, modules) && self.require_intact()).then_some((i, c));
            }
            if self.name(c, name) && c >= 2 && self.is(c - 1, ".") && self.is_name(c - 2) && !self.member(c - 2) {
                // x.fileDesc("…")
                return (self.module_object(c - 2, modules, tid) && self.require_intact()).then_some((i, c - 2));
            }
            if self.is(c, ")")
                && c >= 6
                && self.name(c - 1, name)
                && self.is(c - 2, ".")
                && self.is_name(c - 3)
                && !self.member(c - 3)
                && self.is(c - 4, ",")
                && self.is(c - 5, "0")
                && self.is(c - 6, "(")
            {
                // (0, x.fileDesc)("…"): TypeScript's (and Babel's) CommonJS
                return (self.module_object(c - 3, modules, tid) && self.require_intact()).then_some((i, c - 6));
            }
        }
        None
    }

    // -- the descriptor's binding

    /// A dependency list from token j (`[a, b.c, …]`): the index of its `]`.
    fn dep_list(&self, j: usize) -> Option<usize> {
        if !self.is(j, "[") {
            return None;
        }
        let mut m = j + 1;
        loop {
            if self.is(m, "]") {
                return Some(m);
            }
            if !self.is_name(m) {
                return None;
            }
            m += 1;
            while self.is(m, ".") && self.is_name(m + 1) {
                m += 2;
            }
            if self.is(m, ",") {
                m += 1;
            } else if !self.is(m, "]") {
                return None;
            }
        }
    }

    /// Does the call that ends at `close` end its statement (`;`, the end, or a line's end before what cannot go on
    /// with it)?
    fn ends_statement(&self, close: usize) -> bool {
        let j = close + 1;
        if j >= self.len() || self.is(j, ";") {
            return true;
        }
        self.newline_between(close, j)
            && (self.is(j, "}")
                || (self.is_name(j) && !["instanceof", "in", "as", "satisfies", "of"].iter().any(|w| self.is(j, w))))
    }

    /// ends_statement, or a declaration list's `,` after it (`const a = require("x"), b = …`).
    fn ends_statement_or_comma(&self, close: usize) -> bool {
        self.is(close + 1, ",") || self.ends_statement(close)
    }

    /// The name before a type annotation that ends at token `last` (`file_x: GenFile<…>`), when `const` comes
    /// before it.
    fn annotated(&self, last: usize) -> Option<usize> {
        let mut k = last;
        for _ in 0..64 {
            if self.is(k, ":") && k >= 2 && self.is_name(k - 1) && self.is(k - 2, "const") {
                return Some(k - 1);
            }
            if k == 0 {
                return None;
            }
            k -= 1;
        }
        None
    }

    /// The descriptor the Str token k makes, if it is the whole first argument of the loader's `fileDesc` and the
    /// call's value is bound as generated code binds it: (the name, its token, whether `exports.name`).
    fn descriptor_def(&self, k: usize, loaders: Table) -> Option<(Vec<u32>, usize, bool)> {
        if !(self.back(k, 1, "(") && (self.is(k + 1, ")") || self.is(k + 1, ","))) {
            return None;
        }
        let (i, start) = self.callee(k - 1, loaders, 0)?;
        if !pystr::eq(&loaders[i].0, "fileDesc") {
            return None;
        }
        let close = if self.is(k + 1, ")") {
            k + 1
        } else {
            let end = self.dep_list(k + 2)?;
            if self.is(end + 1, ")") {
                end + 1
            } else if self.is(end + 1, ",") && self.is(end + 2, ")") {
                end + 2
            } else {
                return None;
            }
        };
        if !self.ends_statement(close) || !self.back(start, 1, "=") || start < 2 {
            return None;
        }
        let n = start - 2;
        // exports.file_x = (0, x.fileDesc)(…);
        if self.is_name(n) && self.member(n) && self.back(n, 2, "exports") && !self.member(n - 2) && self.stmt_start(n - 2) {
            return Some((self.text(n).to_vec(), n, true));
        }
        // [export] const file_x[: GenFile] = fileDesc(…);
        let n = if self.is_name(n) && self.back(n, 1, "const") { n } else { self.annotated(n)? };
        let ok = if self.back(n, 2, "export") { self.stmt_start(n - 2) } else { self.stmt_start(n - 1) };
        (ok && !self.member(n)).then(|| (self.text(n).to_vec(), n, false))
    }

    // -- the uses of a descriptor's name

    /// Is the name at token k one of an import's, an export's or a destructured require's plain list of names?
    fn specifier(&self, k: usize) -> bool {
        if !((self.back(k, 1, "{") || self.back(k, 1, ",")) && (self.is(k + 1, ",") || self.is(k + 1, "}"))) {
            return false;
        }
        let Some(b) = self.open_of(k) else { return false };
        if !self.punct(b, "{") || self.content(b) & (PLAIN | DOT | AS | NESTED) != PLAIN {
            return false;
        }
        let Some(e) = self.close_of(b) else { return false };
        let import = self.back(b, 1, "import")
            || (self.back(b, 1, "type") && self.back(b, 2, "import"))
            || (self.back(b, 1, ",") && b >= 2 && self.is_name(b - 2) && self.back(b, 3, "import"));
        if import {
            return self.is(e + 1, "from") && self.kind(e + 2) == Some(Kind::Str);
        }
        if self.back(b, 1, "export") || (self.back(b, 1, "type") && self.back(b, 2, "export")) {
            return true;
        }
        (self.back(b, 1, "const") || self.back(b, 1, "let") || self.back(b, 1, "var"))
            && self.is(e + 1, "=")
            && self.is(e + 2, "require")
            && !self.member(e + 2)
            && self.is(e + 3, "(")
            && self.kind(e + 4) == Some(Kind::Str)
            && self.is(e + 5, ")")
    }

    /// Is the descriptor's name at token k used as generated code uses it (see the module's documentation)?
    /// `defines`: this reading binds the name to a descriptor (its definitions' tokens in `defs`).
    fn use_ok(&self, k: usize, name: &[u32], defs: &[usize], defines: bool, loaders: Table, consumers: Table) -> bool {
        if defs.contains(&k) {
            return true;
        }
        let member = self.member(k);
        let a0 = if member {
            if !(k >= 2 && self.is_name(k - 2) && !self.member(k - 2)) {
                return false;
            }
            k - 2
        } else {
            k
        };
        if defines {
            // exports.file_x = file_x;   (protoc-gen-es's CommonJS)
            if member && self.is(a0, "exports") && self.is(k + 1, "=") && self.name(k + 2, name) && !self.member(k + 2) {
                return true;
            }
            if !member && self.back(k, 1, "=") && k >= 4 && self.name(k - 2, name) && self.is(k - 3, ".") && self.is(k - 4, "exports") {
                return true;
            }
            // exports.a = exports.file_x = … = void 0;   (TypeScript's CommonJS)
            if member && self.is(a0, "exports") && self.punct(k + 1, "=") && self.ix().voided.get(k + 1) == Some(&true) {
                return true;
            }
        }
        // the first argument of the loader's messageDesc, enumDesc, serviceDesc, extDesc
        if self.back(a0, 1, "(") && self.is(k + 1, ",") {
            if let Some((i, _)) = self.callee(a0 - 1, loaders, 0) {
                if !pystr::eq(&loaders[i].0, "fileDesc") {
                    return true;
                }
            }
        }
        // an argument of the runtime's registry constructors
        if (self.back(a0, 1, "(") || self.back(a0, 1, ",")) && (self.is(k + 1, ",") || self.is(k + 1, ")")) {
            if let Some(open) = self.open_of(a0).filter(|&o| self.punct(o, "(")) {
                if self.callee(open, consumers, 1).is_some() {
                    return true;
                }
            }
        }
        // an element of another descriptor's dependency list
        if (self.back(a0, 1, "[") || self.back(a0, 1, ",")) && (self.is(k + 1, ",") || self.is(k + 1, "]")) {
            if let Some(open) = self.open_of(a0).filter(|&o| self.punct(o, "[") && self.content(o) & PLAIN != 0) {
                if open >= 3 && self.is(open - 1, ",") && self.kind(open - 2) == Some(Kind::Str) && self.is(open - 3, "(") {
                    if let Some((i, _)) = self.callee(open - 3, loaders, 0) {
                        if pystr::eq(&loaders[i].0, "fileDesc") {
                            return true;
                        }
                    }
                }
            }
        }
        !member && self.specifier(k)
    }

    /// Is the Str token k a module specifier (`from "…"`, `require("…")`, `import("…")`, `import "…"`,
    /// `import.meta.glob("…")`)?
    fn specifier_string(&self, k: usize) -> bool {
        self.back(k, 1, "from")
            || (self.back(k, 1, "(") && (self.back(k, 2, "require") || self.back(k, 2, "import") || self.back(k, 2, "glob")))
            || (self.back(k, 1, "import") && !self.member(k - 1))
    }

    // -- what the reading loads, and code it runs from text

    /// Every module the reading names (with how it uses it), and what it does that no pass can follow.
    fn refs(&self, full: bool) -> (Vec<Ref>, Vec<Hit>) {
        let mut refs = Vec::new();
        let mut hits = Vec::new();
        let n = self.len();
        let decl = |k: usize| self.is(k, "const") || self.is(k, "let") || self.is(k, "var");
        for k in 0..n {
            if self.kind(k) == Some(Kind::Str) && self.is(k + 1, ":") {
                // "@bufbuild/protobuf/codegenv2": … (a bundler's alias, an import map)
                if self.literal(k).is_some_and(|x| pystr::eq(x, "@bufbuild/protobuf") || pystr::starts_with(x, "@bufbuild/protobuf/")) {
                    hits.push(Hit { at: k, what: "an alias of @bufbuild/protobuf" });
                }
                continue;
            }
            if self.kind(k) == Some(Kind::Str) && self.back(k, 1, ":") && self.back(k, 2, "find") {
                // { find: "@bufbuild/protobuf", replacement: … } (rollup's and vite's aliases)
                if self.literal(k).is_none_or(|x| pystr::contains(x, "@bufbuild")) {
                    hits.push(Hit { at: k, what: "an alias of @bufbuild/protobuf" });
                }
                continue;
            }
            if self.kind(k) == Some(Kind::Regex) && pystr::contains(self.text(k), "bufbuild") {
                hits.push(Hit { at: k, what: "a pattern that may alias @bufbuild/protobuf" });
                continue;
            }
            if !self.is_name(k) {
                continue;
            }
            let w = self.text(k);
            let member = self.member(k);
            if pystr::eq(w, "import") && !member && !self.defines_member(k) {
                if self.is(k + 1, "(") {
                    match self.literal(k + 2) {
                        Some(x) if self.is(k + 3, ")") || self.is(k + 3, ",") => refs.push(Ref { spec: x.to_vec(), kind: RefKind::Dynamic }),
                        _ => match self.template_prefix(k + 2) {
                            Some(x) => refs.push(Ref { spec: x.to_vec(), kind: RefKind::Glob }),
                            None if full => hits.push(Hit { at: k, what: "a module imported by a name made at run time" }),
                            None => {}
                        },
                    }
                } else if self.is(k + 1, ".") && self.is(k + 2, "meta") {
                    if self.is(k + 3, ".") && self.is(k + 4, "glob") && self.is(k + 5, "(") {
                        match self.literal(k + 6) {
                            Some(x) => refs.push(Ref { spec: x.to_vec(), kind: RefKind::Glob }),
                            None if full => hits.push(Hit { at: k, what: "import.meta.glob of a pattern made at run time" }),
                            None => {}
                        }
                    }
                } else if let Some(r) = self.static_import(k) {
                    refs.extend(r);
                }
            } else if pystr::eq(w, "export") && !member {
                // export * from "…", export * as ns from "…", export { … } from "…", export type { … } from "…"
                let (from, kind) = if self.is(k + 1, "*") && self.is(k + 2, "from") {
                    (Some(k + 2), RefKind::ReExport)
                } else if self.is(k + 1, "*") && self.is(k + 2, "as") && self.is(k + 4, "from") {
                    (Some(k + 4), RefKind::Loose) // (a namespace object handed out under a name)
                } else if self.punct(k + 1, "{") || (self.is(k + 1, "type") && self.punct(k + 2, "{")) {
                    let o = if self.punct(k + 1, "{") { k + 1 } else { k + 2 };
                    (self.close_of(o).filter(|&c| self.is(c + 1, "from")).map(|c| c + 1), RefKind::ReExport)
                } else {
                    (None, RefKind::ReExport)
                };
                if let Some(x) = from.and_then(|f| self.literal(f + 1)) {
                    refs.push(Ref { spec: x.to_vec(), kind });
                }
            } else if pystr::eq(w, "require") && (!member || (k >= 2 && (self.is(k - 2, "module") || self.is(k - 2, "mainModule")))) {
                if !member && self.defines_member(k) {
                    continue; // (a key or a method named require)
                }
                if !self.is(k + 1, "(") {
                    if self.is(k + 1, ".") && self.is(k + 2, "resolve") {
                        // (a path)
                    } else if self.is(k + 1, ".") || self.is(k + 1, "?.") || self.is(k + 1, "[") {
                        // (`require.main === module`, a CLI's test: compared, nothing of it read)
                        if full && !(self.is(k + 2, "main") && self.only_compared(k, k + 2)) {
                            hits.push(Hit { at: k, what: "the module registry (require.cache, require.main, require.context …)" });
                        }
                    } else if !self.back(k, 1, "typeof") && full && !member {
                        hits.push(Hit { at: k, what: "require handed on" });
                    }
                    continue;
                }
                let Some(x) = self.literal(k + 2).filter(|_| self.is(k + 3, ")")) else {
                    if full {
                        hits.push(Hit { at: k, what: "a module required by a name made at run time" });
                    }
                    continue;
                };
                let spec = x.to_vec();
                let start = if member { k - 2 } else { k };
                let close = k + 3;
                let after = k + 4;
                let kind = if self.back(start, 1, "=") && start >= 3 && self.is_name(start - 2) && decl(start - 3) && self.ends_statement_or_comma(close) {
                    RefKind::Object(start - 2)
                } else if self.back(start, 1, "=") && start >= 2 && self.punct(start - 2, "}") {
                    // const { … } = require("…"): names, unless a rest, a computed key or a nested pattern takes more
                    let o = self.open_of(start - 2).filter(|&o| self.punct(o, "{"));
                    match o {
                        Some(o) if o >= 1 && decl(o - 1) && self.ends_statement_or_comma(close) && self.content(o) & (REST | NESTED) == 0 => RefKind::Named,
                        _ => RefKind::Loose,
                    }
                } else if (self.is(after, ".") || self.is(after, "?.")) && self.is_name(after + 1) && !self.assigned(after + 2) {
                    RefKind::Named // require("…").y (read; y is checked by its name)
                } else if self.back(start, 1, "=")
                    && self.back(start, 2, "exports")
                    && self.back(start, 3, ".")
                    && self.back(start, 4, "module")
                    && self.ends_statement(close)
                {
                    RefKind::ReExport
                } else {
                    RefKind::Loose // handed to a function (a helper's __importStar, __exportStar), read by `[…]`, called …
                };
                refs.push(Ref { spec, kind });
            } else if !member && pystr::eq(w, "createRequire") && !self.defines_member(k) {
                if full {
                    hits.push(Hit { at: k, what: "createRequire" });
                }
            } else if pystr::eq(w, "eval") {
                let global = !member || (k >= 2 && ["globalThis", "window", "self", "global"].iter().any(|g| self.is(k - 2, g)));
                if global && !(self.is(k + 1, "(") && self.literal_args(k + 1)) && !(!member && self.defines_member(k)) {
                    hits.push(Hit { at: k, what: "eval" });
                }
            } else if pystr::eq(w, "Function") && !member && self.is(k + 1, "(") && !self.literal_args(k + 1) && !self.defines_member(k) {
                hits.push(Hit { at: k, what: "Function" });
            } else if ["runInThisContext", "runInNewContext", "runInContext", "compileFunction"].iter().any(|v| pystr::eq(w, v))
                && self.is(k + 1, "(")
                && !self.literal_args(k + 1)
                && !(!member && self.defines_member(k))
            {
                hits.push(Hit { at: k, what: "a vm call" });
            } else if pystr::eq(w, "Script")
                && self.is(k + 1, "(")
                && (self.back(k, 1, "new") || (member && self.back(k, 3, "new")))
                && !self.literal_args(k + 1)
            {
                hits.push(Hit { at: k, what: "vm.Script" });
            } else if full && !member && pystr::eq(w, "with") && self.is(k + 1, "(") && !self.defines_member(k) {
                hits.push(Hit { at: k, what: "with" });
            } else if member && pystr::eq(w, "constructor") && self.is(k + 1, "(") && !self.literal_args(k + 1) {
                // x.constructor.constructor(text): the Function constructor reached through an object
                let mut j = k;
                while j >= 2 && self.is(j - 1, ".") && self.is_name(j - 2) {
                    j -= 2;
                }
                if !self.back(j, 1, "new") {
                    hits.push(Hit { at: k, what: "a constructor called on text" });
                }
            } else if !member && ["globalThis", "global", "window"].iter().any(|g| pystr::eq(w, g)) && self.punct(k + 1, "[") {
                let lit = self.literal(k + 2).is_some() && self.is(k + 3, "]");
                if !lit {
                    hits.push(Hit { at: k, what: "a global looked up by a name made at run time" });
                }
            } else if full
                && !member
                && pystr::eq(w, "module")
                && self.is(k + 1, ".")
                && ["children", "parent", "constructor"].iter().any(|x| self.is(k + 2, x))
                && !(self.is(k + 2, "parent") && self.only_compared(k, k + 2))
            {
                // (`!module.parent`, `module.parent === x`: a CLI's test, nothing of it read)
                hits.push(Hit { at: k, what: "the module registry (module.children, module.parent …)" });
            } else if full
                && !member
                && pystr::eq(w, "process")
                && self.is(k + 1, ".")
                && ["mainModule", "binding", "_linkedBinding", "dlopen"].iter().any(|x| self.is(k + 2, x))
            {
                hits.push(Hit { at: k, what: "the module registry or a native module (process.mainModule, process.binding …)" });
            }
        }
        (refs, hits)
    }

    /// Is the name at token k a member's key or definition, not a reference to what it names: a key (`eval: …` in an
    /// object or a type, after `{`, `,`, `;` or `}`), or a method's definition (`eval(x) {` on one line, a class's or
    /// an object's, after `{`, `}`, `;`, `,` or a modifier; `eval(x): T` after `{`, `}`, `;` or a modifier)?
    /// `c ? eval : x`, `f(eval)`, `eval(x)` and `eval(x)\n{ … }` are references.
    fn defines_member(&self, k: usize) -> bool {
        let modifier = |j: usize| {
            self.punct(j, "*")
                || ["static", "async", "get", "set", "public", "private", "protected", "override", "readonly", "abstract", "declare", "accessor"]
                    .iter()
                    .any(|w| self.is_name(j) && self.is(j, w))
        };
        let after = |commas: bool| {
            k == 0
                || self.punct(k - 1, "{")
                || self.punct(k - 1, "}")
                || self.punct(k - 1, ";")
                || (commas && self.punct(k - 1, ","))
                || modifier(k - 1)
        };
        if self.punct(k + 1, ":") {
            return after(true);
        }
        if self.punct(k + 1, "(") {
            if let Some(c) = self.close_of(k + 1) {
                if self.punct(c + 1, "{") && !self.newline_between(c, c + 1) {
                    return after(true);
                }
                if self.punct(c + 1, ":") {
                    return after(false);
                }
            }
        }
        false
    }

    /// Is the expression of tokens `[a, last]` (`require.main`, `module.parent`) only compared or negated, nothing of it
    /// read (not followed by `.`, `?.`, `[` or `(`)?
    fn only_compared(&self, a: usize, last: usize) -> bool {
        let cmp = |j: usize| ["===", "==", "!==", "!="].iter().any(|w| self.punct(j, w));
        let read = self.is(last + 1, ".") || self.is(last + 1, "?.") || self.is(last + 1, "[") || self.is(last + 1, "(");
        !read && (cmp(last + 1) || (a >= 1 && (cmp(a - 1) || self.punct(a - 1, "!"))))
    }

    /// `import a, * as b, { … } from "…"` and `import "…"` at token k: its refs (None: not a static import read
    /// here, `import type …`).
    fn static_import(&self, k: usize) -> Option<Vec<Ref>> {
        let mut j = k + 1;
        if self.kind(j) == Some(Kind::Str) {
            return Some(vec![Ref { spec: self.literal(j)?.to_vec(), kind: RefKind::Named }]);
        }
        if self.is(j, "type") && !(self.is(j + 1, "from") || self.is(j + 1, ",") || self.is(j + 1, "=")) {
            return None; // import type … (nothing of it runs)
        }
        let mut bindings = Vec::new();
        if self.is_name(j) && !self.is(j, "from") || (self.is(j, "from") && self.is(j + 1, "from")) {
            bindings.push(j);
            j += 1;
            if self.is(j, ",") {
                j += 1;
            }
        }
        if self.is(j, "*") && self.is(j + 1, "as") && self.is_name(j + 2) {
            bindings.push(j + 2);
            j += 3;
        } else if self.punct(j, "{") {
            j = self.close_of(j)? + 1;
        }
        if !self.is(j, "from") {
            return None;
        }
        let spec = self.literal(j + 1)?.to_vec();
        let mut out: Vec<Ref> = bindings.into_iter().map(|b| Ref { spec: spec.clone(), kind: RefKind::Object(b) }).collect();
        out.push(Ref { spec, kind: RefKind::Named });
        Some(out)
    }

    /// Is the module object bound at token b used for its members alone (`m.y`, not written)?
    fn object_static(&self, b: usize) -> bool {
        let name = self.text(b);
        self.occurrences(name).iter().all(|&k| {
            let k = k as usize;
            k == b || self.member(k) || ((self.is(k + 1, ".") || self.is(k + 1, "?.")) && self.is_name(k + 2) && !self.assigned(k + 3))
        })
    }

    /// The first use of the module's own scope that could read its exports by a name made at run time: `exports`,
    /// `module`, `this` or `arguments` other than `exports.y`, `this.y`, `this && …` and
    /// `Object.defineProperty(exports, "__esModule", …)`.
    fn scope_reader(&self) -> Option<usize> {
        // (`this` and `arguments` at a module's top are its exports and its wrapper's arguments only in CommonJS: a
        // reading that names `require`, `exports` or `module`)
        let cjs = ["require", "exports", "module"].iter().any(|w| self.occurrences(&pystr::u(w)).iter().any(|&k| !self.member(k as usize)));
        for w in ["exports", "module", "this", "arguments"] {
            if !cjs && (w == "this" || w == "arguments") {
                continue;
            }
            for &k in self.occurrences(&pystr::u(w)) {
                let k = k as usize;
                if self.member(k) {
                    continue;
                }
                let ok = match w {
                    "exports" => {
                        (self.is(k + 1, ".") && self.is_name(k + 2))
                            || (self.back(k, 1, "(")
                                && self.back(k, 2, "defineProperty")
                                && self.back(k, 3, ".")
                                && self.back(k, 4, "Object")
                                && self.is(k + 1, ",")
                                && self.literal(k + 2).is_some_and(|x| pystr::eq(x, "__esModule")))
                    }
                    "this" => (self.is(k + 1, ".") && self.is_name(k + 2)) || self.is(k + 1, "&&"),
                    _ => false,
                };
                if !ok {
                    return Some(k);
                }
            }
        }
        None
    }
}

// ---- where a specifier may lead ---------------------------------------------------------------------------------

/// What the scan can tell of where a module specifier leads, as keys a file may be named by (lower case: a file
/// system that ignores case reads `./X_PB` as x_pb).
#[derive(Default)]
struct Leads {
    /// the paths, extensions off, it may be (a relative specifier; a tsconfig's paths and baseUrl)
    exact: Vec<String>,
    /// its last part, extension off: a file of that name anywhere may be it (an alias that keeps the name)
    base: Option<String>,
    /// folders any file under which may be it (a package the scan holds, by its name; a glob's folder)
    roots: Vec<String>,
    /// it may be any file of the scan
    any: bool,
}

/// What the scan's manifests, configs and code say about where bare specifiers lead.
struct Resolver {
    /// package name -> its root folders in the scan (package.json's name; node_modules/<name>)
    roots: BTreeMap<String, Vec<String>>,
    /// package names a manifest declares with a version range
    declared: HashSet<String>,
    /// package names a manifest maps elsewhere (file:, link:, npm:, workspace:, git …) or a `browser` field remaps,
    /// and names the code uses as an object's key or a `find:` (a bundler's alias)
    aliased: HashSet<String>,
    /// the code has an alias whose name cannot be read (a pattern)
    alias_any: bool,
    /// the names (extension off) of the files a `browser` field sends elsewhere by a relative key
    remapped: HashSet<String>,
    /// tsconfig/jsconfig `paths`: (pattern, targets, the folder they are read from)
    paths: Vec<(String, Vec<String>, String)>,
    /// tsconfig/jsconfig `baseUrl` folders
    base_urls: Vec<String>,
    /// the scan's files' paths (lower case, extension off), and a folder's for its index: what a path may be
    files: HashSet<String>,
}

impl Resolver {
    fn leads(&self, spec: &str, from: &str, kind: &RefKind) -> Leads {
        let mut l = Leads::default();
        // a loader prefix (`raw-loader!./x`) and a query (`./x?raw`) are read past
        let spec = spec.rsplit('!').next().unwrap_or(spec);
        let spec = spec.split(['?', '#']).next().unwrap_or(spec);
        let low = spec.to_ascii_lowercase();
        let last = stem(low.trim_end_matches('/').rsplit('/').next().unwrap_or(&low)).to_string();
        if !last.is_empty() && last != "." && last != ".." {
            l.base = Some(last);
        }
        let relative = low.starts_with("./") || low.starts_with("../") || low == "." || low == ".." || low.starts_with('/');
        if *kind == RefKind::Glob {
            // the folder its pattern begins with: anything under it
            let fixed = low.split(['*', '{', '[', '?']).next().unwrap_or("");
            let folder = if fixed.ends_with('/') { fixed.trim_end_matches('/') } else { dir_of(fixed) };
            match join(&dir_of(from).to_ascii_lowercase(), if relative { folder } else { "" }) {
                Some(r) if relative => l.roots.push(r),
                _ => l.any = true,
            }
            return l;
        }
        if relative {
            match join(&dir_of(from).to_ascii_lowercase(), &low) {
                Some(p) => {
                    // (a folder: its index, or what its package.json's main names, anything under it)
                    l.roots.push(p.clone());
                    l.exact.push(stem(&p).to_string());
                }
                None => l.any = true,
            }
            // a `browser` field or an alias that sends this file elsewhere
            if self.aliased.contains(&low) || l.base.as_ref().is_some_and(|b| self.remapped.contains(b)) {
                l.any = true;
            }
            return l;
        }
        if low.starts_with('#') || low.is_empty() {
            l.any = true; // a package's own imports map: any file of it
            return l;
        }
        if let Some((scheme, _)) = low.split_once(':') {
            if !scheme.contains('/') {
                // node:fs, a URL, cloudflare:workers, virtual:…: no file of the scan, but a data: or file: URL
                l.any = matches!(scheme, "data" | "file") || self.alias_any || self.aliased.contains(&low);
                return l;
            }
        }
        let mut segs = low.splitn(if low.starts_with('@') { 3 } else { 2 }, '/');
        let pkg = if low.starts_with('@') {
            format!("{}/{}", segs.next().unwrap_or(""), segs.next().unwrap_or(""))
        } else {
            segs.next().unwrap_or("").to_string()
        };
        if self.alias_any || self.aliased.contains(&pkg) || self.aliased.contains(&low) {
            l.any = true;
            return l;
        }
        let mut known = false;
        let before = l.exact.len();
        for (pattern, targets, at) in &self.paths {
            let hit = match pattern.split_once('*') {
                None => (pattern == &low).then_some(""),
                Some((a, b)) => (low.len() >= a.len() + b.len() && low.starts_with(a) && low.ends_with(b)).then(|| &low[a.len()..low.len() - b.len()]),
            };
            if let Some(star) = hit {
                for t in targets {
                    match join(at, &t.replacen('*', star, 1)) {
                        Some(p) => l.exact.push(stem(&p).to_string()),
                        None => l.any = true,
                    }
                }
            }
        }
        for b in &self.base_urls {
            if let Some(p) = join(b, &low) {
                l.exact.push(stem(&p).to_string());
            }
        }
        // (a paths entry or the baseUrl that leads to a file of the scan: the compiler and the bundlers that read
        // the config take it, before node_modules)
        if l.exact[before..].iter().any(|e| self.files.contains(e)) {
            known = true;
        }
        if let Some(rs) = self.roots.get(&pkg) {
            l.roots.extend(rs.iter().cloned());
            known = true;
        }
        let builtin = NODE_BUILTINS.contains(&pkg.as_str());
        if !(known || builtin || self.declared.contains(&pkg)) {
            l.any = true; // undeclared: an alias, a phantom dependency … it may be any file
        }
        l
    }
}

/// The keys of the file at `path` that a specifier's leads may hold: (exact stems, base names, folders above it).
fn keys_of(path: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let low = path.to_ascii_lowercase();
    let s = stem(&low).to_string();
    let b = base_of(&s).to_string();
    let mut exact = vec![s.clone()];
    let mut base = vec![b.clone()];
    if b == "index" {
        exact.push(dir_of(&s).to_string());
        base.push(base_of(dir_of(&s)).to_string());
    }
    let mut roots = vec![String::new()];
    let mut d = dir_of(&low);
    let mut above = Vec::new();
    while !d.is_empty() {
        above.push(d.to_string());
        d = dir_of(d);
    }
    roots.extend(above);
    // (the file itself: a glob's folder may be the file's own path when it names one file)
    roots.push(low.clone());
    (exact, base, roots)
}

// ---- the decision -------------------------------------------------------------------------------------------------

/// Is `body` (the characters of a B64_BLOB_RE run, its quotes and `=` taken off) the base64 of one protobuf
/// FileDescriptorProto, read to its end (file_descriptor)? protoc-gen-es writes it unpadded.
pub fn b64_descriptor(body: &[u32]) -> bool {
    if body.len() % 4 == 1 {
        return false;
    }
    let mut padded = body.to_vec();
    while padded.len() % 4 != 0 {
        padded.push('=' as u32);
    }
    crate::signs::b64decode_strict(&padded).is_some_and(|b| super::file_descriptor(&b))
}

/// A descriptor run to decide: where it is bound, in each reading of its file.
struct Candidate {
    unit: usize,
    name: Vec<u32>,
    /// its definition's token in each reading
    defs: Vec<usize>,
}

/// Is a dependency spec a version range (or tag), naming the registry's package and nothing else?
fn plain_spec(v: &[u32]) -> bool {
    v.iter().all(|&c| char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || " .*^~<>=|+-_".contains(ch)))
}

/// Does a package.json map `@bufbuild/protobuf` to something other than a version of it (under any key that names
/// it: `@bufbuild/protobuf`, `a>@bufbuild/protobuf`, `**/@bufbuild/protobuf`, `@bufbuild/protobuf@^2`, a module of
/// it)?
fn remaps_runtime(node: &JNode, depth: usize) -> bool {
    if depth > 64 {
        return true;
    }
    let runtime = |k: &[u32]| pystr::contains(k, "@bufbuild/protobuf");
    let any_string = |n: &JNode| -> bool {
        let mut stack = vec![n];
        let mut steps = 0;
        while let Some(x) = stack.pop() {
            steps += 1;
            if steps > 100_000 {
                return true;
            }
            match &x.kind {
                JKind::Str(v) if !plain_spec(v) => return true,
                JKind::Object(m) => stack.extend(m.iter().map(|(_, y)| y)),
                JKind::Array(a) => stack.extend(a.iter()),
                _ => {}
            }
        }
        false
    };
    match &node.kind {
        JKind::Object(members) => members.iter().any(|(k, v)| (runtime(k) && any_string(v)) || remaps_runtime(v, depth + 1)),
        JKind::Array(items) => items.iter().any(|v| remaps_runtime(v, depth + 1)),
        _ => false,
    }
}

/// The JSON at `path` of a node, by keys.
fn at_key<'n>(node: &'n JNode, key: &str) -> Option<&'n JNode> {
    match &node.kind {
        JKind::Object(m) => m.iter().rev().find(|(k, _)| pystr::eq(k, key)).map(|(_, v)| v),
        _ => None,
    }
}

/// Does a tsconfig's or jsconfig's `paths` entry match `spec` (one `*` at most, as TypeScript reads it)?
fn path_pattern_matches(pattern: &str, spec: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == spec,
        Some((a, b)) => spec.len() >= a.len() + b.len() && spec.starts_with(a) && spec.ends_with(b),
    }
}

/// The package names a manifest declares: (with a version range, mapped elsewhere). Its `browser` field's keys are
/// mapped elsewhere too.
fn declared_names(node: &JNode) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::new();
    let mut odd = Vec::new();
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(JNode { kind: JKind::Object(m), .. }) = at_key(node, section) {
            for (k, v) in m {
                let name = pystr::to_string(k).to_ascii_lowercase();
                match &v.kind {
                    JKind::Str(s) if plain_spec(s) => plain.push(name),
                    _ => odd.push(name),
                }
            }
        }
    }
    for section in ["overrides", "resolutions", "pnpm"] {
        if let Some(v) = at_key(node, section) {
            collect_odd(v, &mut odd, 0);
        }
    }
    match at_key(node, "browser").map(|n| &n.kind) {
        Some(JKind::Object(m)) => odd.extend(m.iter().map(|(k, _)| pystr::to_string(k).to_ascii_lowercase())),
        Some(JKind::Str(_)) | None => {}
        Some(_) => {}
    }
    (plain, odd)
}

/// The keys of an overrides/resolutions object whose value is not a version range (their last package name).
fn collect_odd(node: &JNode, out: &mut Vec<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    if let JKind::Object(m) = &node.kind {
        for (k, v) in m {
            let key = pystr::to_string(k).to_ascii_lowercase();
            let last = key.rsplit('>').next().unwrap_or(&key).trim_start_matches("**/").to_string();
            let name = match last.strip_prefix('@') {
                Some(rest) => match rest.find('@') {
                    Some(i) => last[..i + 1].to_string(),
                    None => last.clone(),
                },
                None => last.split('@').next().unwrap_or(&last).to_string(),
            };
            match &v.kind {
                JKind::Str(s) if plain_spec(s) => {}
                JKind::Object(_) => collect_odd(v, out, depth + 1),
                _ => out.push(name),
            }
        }
    }
}

/// What the pass keeps of a unit once it has read it (its tokens are dropped: the scan's units are read one at a
/// time, so memory holds one unit's readings, and the candidates', at once).
struct Seen {
    path: String,
    part: Part,
    /// what it loads: (specifier, the kind, whether it reads the module whole)
    refs: Vec<(String, RefKind, bool)>,
    /// its module scope read by a name made at run time
    scope: Option<String>,
}

/// What the units' readings add up to across the scan.
#[derive(Default)]
struct Acc {
    /// the first unit that runs code it builds, reaches the module registry, loads a runner module or uses the
    /// runtime whole: why every finding stays
    stop: Option<String>,
    /// names the code aliases (an object's string key, a `find:`), and whether one cannot be read
    aliased: HashSet<String>,
    alias_any: bool,
    /// a name's misuse, the first found: name -> why
    misused: HashMap<Vec<u32>, String>,
    /// a defining file named in a string: unit -> why
    unit_why: HashMap<usize, String>,
}

/// The pass's view of one unit's readings, read once (see `decide`).
#[allow(clippy::too_many_arguments)]
fn read_unit(
    ui: usize,
    u: &Unit,
    rs: &[R],
    runners: &[String],
    names: &HashSet<Vec<u32>>,
    defined: &HashMap<(usize, Vec<u32>), Vec<Vec<usize>>>,
    file_names: &HashMap<String, Vec<usize>>,
    loaders: Table,
    consumers: Table,
    acc: &mut Acc,
) -> Seen {
    let mut seen = Seen { path: u.path.clone(), part: u.part, refs: Vec::new(), scope: None };
    let word = |c: u32| char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$');
    let path_char = |c: u32| char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || "_$.-@".contains(ch));
    // a descriptor's name in a string or in markup: a computed access, code to run
    let words_of = |x: &[u32], at: usize, how: &str, misused: &mut HashMap<Vec<u32>, String>| {
        let mut i = 0;
        while i < x.len() {
            if !word(x[i]) {
                i += 1;
                continue;
            }
            let j = (i..x.len()).find(|&j| !word(x[j])).unwrap_or(x.len());
            let w = &x[i..j];
            if names.contains(w) && !misused.contains_key(w) {
                misused.insert(w.to_vec(), format!("{}:{} names it {how}", u.path, u.line_at(at + i)));
            }
            i = j;
        }
    };
    // a defining file's name in a string (but a module specifier): a path to its text
    let paths_of = |x: &[u32], at: usize, unit_why: &mut HashMap<usize, String>| {
        let mut i = 0;
        while i < x.len() {
            if !path_char(x[i]) {
                i += 1;
                continue;
            }
            let j = (i..x.len()).find(|&j| !path_char(x[j])).unwrap_or(x.len());
            let w: String = x[i..j].iter().filter_map(|&c| char::from_u32(c)).collect::<String>().to_ascii_lowercase();
            for cand in [w.as_str(), stem(&w)] {
                if let Some(list) = file_names.get(cand) {
                    for &d in list {
                        unit_why.entry(d).or_insert_with(|| format!("{}:{} names its file in a string", u.path, u.line_at(at + i)));
                    }
                }
            }
            i = j;
        }
    };
    if u.dts {
        return seen;
    }
    if u.part == Part::Whole {
        words_of(&u.content, 0, "in its markup", &mut acc.misused);
        return seen;
    }
    for (ri, r) in rs.iter().enumerate() {
        // what it loads and runs
        let (found, hits) = r.refs(true);
        if let Some(h) = hits.first() {
            if acc.stop.is_none() {
                acc.stop = Some(format!("{}:{} runs code it builds or reaches the module registry ({})", u.path, u.line_at(r.t[h.at].start as usize), h.what));
            }
            return seen;
        }
        for x in found {
            let spec = pystr::to_string(&x.spec);
            let bare = spec.strip_prefix("node:").unwrap_or(&spec);
            let head = bare.split('/').next().unwrap_or(bare);
            if runners.iter().any(|m| m == bare || m == head) {
                if acc.stop.is_none() {
                    acc.stop = Some(format!("{} loads {spec}, which runs code or loads modules", u.path));
                }
                return seen;
            }
            let whole = match x.kind {
                RefKind::Object(b) => !r.object_static(b),
                RefKind::Loose | RefKind::Dynamic | RefKind::Glob => true,
                RefKind::ReExport | RefKind::Named => false,
            };
            if whole && x.kind != RefKind::Glob && (spec == "@bufbuild/protobuf" || spec.starts_with("@bufbuild/protobuf/")) {
                // the runtime's own module written to or handed on (`require("@bufbuild/protobuf/codegenv2").fileDesc = …`)
                if acc.stop.is_none() {
                    acc.stop = Some(format!("{} uses {spec} as a whole", u.path));
                }
                return seen;
            }
            let raw = spec.contains('?') || spec.contains('!');
            if whole || raw || x.kind == RefKind::ReExport {
                seen.refs.push((spec, x.kind.clone(), whole || raw));
            }
        }
        // the code's aliases: an object's string key, a `find:` (a bundler's configuration)
        for k in 0..r.len() {
            if r.kind(k) == Some(Kind::Str) && r.is(k + 1, ":") {
                if let Some(x) = r.literal(k) {
                    acc.aliased.insert(pystr::to_string(x).to_ascii_lowercase());
                }
            } else if r.is(k, "find") && r.is(k + 1, ":") {
                match r.literal(k + 2) {
                    Some(x) => {
                        acc.aliased.insert(pystr::to_string(x).to_ascii_lowercase());
                    }
                    None => acc.alias_any = true,
                }
            }
        }
        // the descriptors' names, and the strings that name one or its file
        let t = r.t;
        for k in 0..t.len() {
            let kind = t[k].kind;
            if kind == Kind::Name {
                let w = r.text(k);
                if !names.contains(w) || acc.misused.contains_key(w) {
                    continue;
                }
                let defs = defined.get(&(ui, w.to_vec())).map(|d| d[ri].clone());
                if !r.use_ok(k, w, defs.as_deref().unwrap_or(&[]), defs.is_some(), loaders, consumers) {
                    acc.misused.insert(w.to_vec(), format!("{}:{} uses it as generated code does not", u.path, u.line_at(t[k].start as usize)));
                }
            } else if matches!(kind, Kind::Str | Kind::Template | Kind::JsxStr) {
                words_of(r.text(k), t[k].start as usize, "in a string", &mut acc.misused);
                if !(kind == Kind::Str && r.specifier_string(k)) && !file_names.is_empty() {
                    paths_of(r.text(k), t[k].start as usize, &mut acc.unit_why);
                }
            }
        }
        // its module scope (a file's): its own exports read by a name made at run time
        if u.part == Part::File && seen.scope.is_none() {
            if let Some(k) = r.scope_reader() {
                seen.scope = Some(format!("{}:{} reads its module's own exports ({})", u.path, u.line_at(r.t[k].start as usize), pystr::to_string(r.text(k))));
            }
        }
    }
    seen
}

/// Decide each of `input.findings` (see the module's documentation).
pub fn decide(p: &Pack, input: &Input) -> Vec<Decision> {
    let keep_all = |why: String| -> Vec<Decision> { input.findings.iter().map(|(f, l)| (f.clone(), *l, Some(why.clone()))).collect() };
    if input.findings.is_empty() {
        return Vec::new();
    }
    if input.stopped {
        return keep_all("the scan stopped before its end".into());
    }
    let holder_exts: Vec<String> = p.strs("_SCRIPT_HOLDER_EXTS").iter().map(|x| pystr::to_string(x)).collect();
    let relevant = |path: &str| {
        let e = ext_of(path);
        path == "." || e.is_empty() || CODE_EXTS.contains(&e.as_str()) || holder_exts.contains(&e)
    };
    if let Some(u) = input.unread.iter().find(|x| relevant(x)) {
        return keep_all(format!("{u} was not read whole"));
    }
    if let Some((h, _)) = input.holders.iter().find(|(_, t)| t.is_none()) {
        return keep_all(format!("{h} (it may hold script) was not read"));
    }
    let loaders: Table = if p.has("_B64_DESCRIPTOR_LOADERS") { p.map_strs("_B64_DESCRIPTOR_LOADERS") } else { &[] };
    let consumers: Table = if p.has("_B64_DESCRIPTOR_CONSUMERS") { p.map_strs("_B64_DESCRIPTOR_CONSUMERS") } else { &[] };
    if loaders.is_empty() {
        return keep_all("no loader is known".into());
    }
    let runners: Vec<String> = if p.has("_B64_RUNNER_MODULES") {
        p.strs("_B64_RUNNER_MODULES").iter().map(|x| pystr::to_string(x)).collect()
    } else {
        return keep_all("no module that runs code is known".into());
    };
    let file_jsx = |path: &str| {
        let low = path.to_ascii_lowercase();
        !(low.ends_with(".ts") || low.ends_with(".mts") || low.ends_with(".cts"))
    };

    // the files the findings are in, read first (kept to the end): the candidates, each finding's runs
    let by_path: HashMap<&str, usize> = input.files.iter().enumerate().map(|(i, (p, _))| (p.as_str(), i)).collect();
    let mut cand_ids: Vec<usize> = input.findings.iter().filter_map(|(f, _)| by_path.get(f.as_str()).copied()).collect();
    cand_ids.sort_unstable();
    cand_ids.dedup();
    let cand_units: Vec<Unit> = cand_ids.iter().map(|&i| unit(&input.files[i].0, Part::File, read_text(&input.files[i].1), file_jsx(&input.files[i].0))).collect();
    let cand_rs: Vec<Vec<R>> = cand_units.iter().map(|u| u.readings.iter().map(|t| R::new(&u.content, t)).collect()).collect();
    let slot = |ui: usize| cand_ids.binary_search(&ui).ok();
    let b64_re = p.re("B64_BLOB_RE");
    let plain_max = p.usize("_B64_PLAIN_MAX");
    let period_max = p.usize("_B64_PERIOD_MAX");
    let mut cands: Vec<Candidate> = Vec::new();
    let mut finding_cands: Vec<Result<Vec<usize>, String>> = Vec::new();
    for (path, line) in &input.findings {
        let Some((ui, s)) = by_path.get(path.as_str()).and_then(|&ui| slot(ui).map(|s| (ui, s))) else {
            finding_cands.push(Err("its file is not one the pass was given".into()));
            continue;
        };
        let u = &cand_units[s];
        let starts = u.starts();
        if *line == 0 || *line > starts.len() {
            finding_cands.push(Err("no such line".into()));
            continue;
        }
        let base = starts[line - 1];
        let end = starts.get(*line).map_or(u.content.len(), |&e| e - 1);
        let text = &u.content[base..end];
        let mut mine = Vec::new();
        let mut why = None;
        for m in b64_re.finditer(text) {
            let run = m.group0();
            let mut body = &run[1..run.len() - 1];
            while body.last() == Some(&('=' as u32)) {
                body = &body[..body.len() - 1];
            }
            if crate::scanfile::b64_plain(body, plain_max, period_max) || crate::scanfile::b64_data(body) {
                continue;
            }
            if !b64_descriptor(body) {
                why = Some("a run of the line is not a protobuf descriptor (one with no comments, no JSON name but the derived one, no long default value)".to_string());
                break;
            }
            let (q, e) = ((base + m.start()) as u32, (base + m.end()) as u32);
            let mut defs = Vec::new();
            let mut name: Option<Vec<u32>> = None;
            for r in &cand_rs[s] {
                let t = r.t;
                let k = t.partition_point(|x| x.start < q);
                let def = (k < t.len() && t[k].start == q && t[k].end == e && t[k].kind == Kind::Str).then(|| r.descriptor_def(k, loaders)).flatten();
                match def {
                    Some((n, tok, _)) if name.as_ref().is_none_or(|x| *x == n) => {
                        name = Some(n);
                        defs.push(tok);
                    }
                    _ => {
                        name = None;
                        break;
                    }
                }
            }
            match name {
                Some(n) => {
                    mine.push(cands.len());
                    cands.push(Candidate { unit: ui, name: n, defs });
                }
                None => {
                    why = Some("a descriptor of the line is not handed, whole, to the protobuf runtime's loader and bound as generated code binds it".to_string());
                    break;
                }
            }
        }
        finding_cands.push(match why {
            Some(w) => Err(w),
            None if mine.is_empty() => Err("no run of the line is a protobuf descriptor".into()),
            None => Ok(mine),
        });
    }
    // the descriptors' names; their definitions' tokens per reading; their files' names (lower case, extension off)
    let names: HashSet<Vec<u32>> = cands.iter().map(|c| c.name.clone()).collect();
    let mut defined: HashMap<(usize, Vec<u32>), Vec<Vec<usize>>> = HashMap::new();
    for c in &cands {
        let n = cand_units[slot(c.unit).unwrap_or(0)].readings.len();
        let e = defined.entry((c.unit, c.name.clone())).or_insert_with(|| vec![Vec::new(); n]);
        for (ri, &d) in c.defs.iter().enumerate() {
            e[ri].push(d);
        }
    }
    let def_units: HashSet<usize> = cands.iter().map(|c| c.unit).collect();
    let mut file_names: HashMap<String, Vec<usize>> = HashMap::new();
    for &ui in &def_units {
        file_names.entry(base_of(stem(&input.files[ui].0.to_ascii_lowercase())).to_string()).or_default().push(ui);
    }

    // every unit of the scan read once, in turn: the files (index = their place in input.files), then each holder's
    // blocks and its whole text; what each loads, runs and names kept, its tokens dropped
    let mut acc = Acc::default();
    let mut seen: Vec<Seen> = Vec::with_capacity(input.files.len() + 2 * input.holders.len());
    for (ui, (path, text)) in input.files.iter().enumerate() {
        let got = match slot(ui) {
            Some(s) => read_unit(ui, &cand_units[s], &cand_rs[s], &runners, &names, &defined, &file_names, loaders, consumers, &mut acc),
            None => {
                let u = unit(path, Part::File, read_text(text), file_jsx(path));
                let rs: Vec<R> = u.readings.iter().map(|t| R::new(&u.content, t)).collect();
                read_unit(ui, &u, &rs, &runners, &names, &defined, &file_names, loaders, consumers, &mut acc)
            }
        };
        seen.push(got);
        if let Some(w) = acc.stop.take() {
            return keep_all(w);
        }
    }
    for (path, text) in &input.holders {
        let text = read_text(text.as_deref().unwrap_or(&[]));
        let component = [".vue", ".svelte", ".astro", ".mdx", ".marko", ".riot"].contains(&ext_of(path).as_str());
        for b in holder_blocks(&text, component).into_iter().map(Some).chain(std::iter::once(None)) {
            let u = match b {
                Some(b) => unit(path, Part::Block, b, true),
                None => unit(path, Part::Whole, text.clone(), true),
            };
            let rs: Vec<R> = u.readings.iter().map(|t| R::new(&u.content, t)).collect();
            let ui = seen.len();
            let got = read_unit(ui, &u, &rs, &runners, &names, &defined, &file_names, loaders, consumers, &mut acc);
            seen.push(got);
            if let Some(w) = acc.stop.take() {
                return keep_all(w);
            }
        }
    }
    drop(cand_rs);
    drop(cand_units);
    let Acc { aliased: code_aliases, alias_any: code_alias_any, misused, unit_why, .. } = acc;

    // the package roots by name (package.json's name; node_modules/<name>), what the manifests declare
    let mut roots: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut manifests: Vec<(&str, Option<JNode>)> = Vec::new();
    let mut declared: HashSet<String> = HashSet::new();
    let mut aliased: HashSet<String> = code_aliases;
    let mut alias_any = code_alias_any;
    let mut remapped: HashSet<String> = HashSet::new();
    for (path, text) in &input.manifests {
        let node = parse_jsonc(text).ok();
        if let Some(n) = node.as_ref() {
            if let Some(JKind::Str(s)) = at_key(n, "name").map(|x| &x.kind) {
                roots.entry(pystr::to_string(s).to_ascii_lowercase()).or_default().push(dir_of(path).to_ascii_lowercase());
            }
            let (plain, odd) = declared_names(n);
            declared.extend(plain);
            for x in odd {
                if x.starts_with('.') || x.starts_with('/') {
                    remapped.insert(base_of(stem(x.trim_end_matches('/'))).to_string());
                }
                aliased.insert(x);
            }
        }
        manifests.push((path.as_str(), node));
    }
    let known: Vec<&str> = seen.iter().map(|u| u.path.as_str()).chain(input.manifests.iter().map(|(p, _)| p.as_str())).collect();
    for k in &known {
        let low = k.to_ascii_lowercase();
        let mut rest: &str = &low;
        let mut prefix = String::new();
        while let Some(i) = rest.find("node_modules/") {
            let after = &rest[i + "node_modules/".len()..];
            let mut segs = after.split('/');
            let pkg = match segs.next() {
                Some(s) if s.starts_with('@') => format!("{}/{}", s, segs.next().unwrap_or("")),
                Some(s) => s.to_string(),
                None => break,
            };
            let root = format!("{}{}node_modules/{}", prefix, &rest[..i], pkg);
            let list = roots.entry(pkg.clone()).or_default();
            if !list.contains(&root) {
                list.push(root.clone());
            }
            prefix = format!("{}/", root);
            rest = &after[pkg.len().min(after.len())..];
            rest = rest.trim_start_matches('/');
        }
    }

    // the loader's own module remapped (B-3): tsconfig and jsconfig; their paths and baseUrl kept for resolving
    let mut runtime_modules: Vec<String> = loaders.iter().flat_map(|(_, m)| m.iter().map(|x| pystr::to_string(x))).collect();
    runtime_modules.extend(consumers.iter().flat_map(|(_, m)| m.iter().map(|x| pystr::to_string(x))));
    let config_paths: HashSet<&str> = input.configs.iter().map(|(c, _)| c.as_str()).collect();
    let mut ts_paths: Vec<(String, Vec<String>, String)> = Vec::new();
    let mut base_urls: Vec<String> = Vec::new();
    for (path, text) in &input.configs {
        let Some(text) = text else {
            return keep_all(format!("{path} (it may say where modules are) was not read"));
        };
        let low = base_of(path).to_ascii_lowercase();
        if !((low.starts_with("tsconfig") || low.starts_with("jsconfig")) && low.ends_with(".json")) {
            if pystr::contains(text, "@bufbuild/protobuf") {
                return keep_all(format!("{path} names @bufbuild/protobuf"));
            }
            // (Babel's, SWC's, Deno's, Bun's module maps: any name they map may lead anywhere)
            if let Ok(node) = parse_jsonc(text) {
                collect_keys(&node, &mut aliased, 0);
            } else {
                alias_any = true;
            }
            continue;
        }
        let Ok(node) = parse_jsonc(text) else {
            return keep_all(format!("{path} cannot be read"));
        };
        // extends: a config of the scan, else what it says is not known
        let extends: Vec<String> = match at_key(&node, "extends").map(|n| &n.kind) {
            None => Vec::new(),
            Some(JKind::Str(x)) => vec![pystr::to_string(x)],
            Some(JKind::Array(items)) if items.iter().all(|i| matches!(i.kind, JKind::Str(_))) => items
                .iter()
                .filter_map(|i| if let JKind::Str(x) = &i.kind { Some(pystr::to_string(x)) } else { None })
                .collect(),
            Some(_) => return keep_all(format!("{path}'s extends cannot be read")),
        };
        for x in &extends {
            let read = if x.starts_with("./") || x.starts_with("../") || x.starts_with('/') || x == "." || x == ".." {
                join(dir_of(path), x).is_some_and(|j| {
                    [j.clone(), format!("{j}.json"), format!("{j}/tsconfig.json")].iter().any(|c| config_paths.contains(c.as_str()))
                })
            } else {
                let tails = [format!("node_modules/{x}"), format!("node_modules/{x}.json"), format!("node_modules/{x}/tsconfig.json")];
                config_paths.iter().any(|c| tails.iter().any(|t| *c == t.as_str() || c.ends_with(&format!("/{t}"))))
            };
            if !read {
                return keep_all(format!("{path} extends {x}, which the scan did not read"));
            }
        }
        let Some(options) = at_key(&node, "compilerOptions") else { continue };
        let at = match at_key(options, "baseUrl") {
            Some(JNode { kind: JKind::Str(base), .. }) => {
                let Some(b) = join(dir_of(path), &pystr::to_string(base)) else {
                    return keep_all(format!("{path}'s baseUrl leaves the scan"));
                };
                let under = if b.is_empty() { "@bufbuild/".to_string() } else { format!("{b}/@bufbuild/") };
                if known.iter().any(|k| k.starts_with(&under)) {
                    return keep_all(format!("{path}'s baseUrl holds an @bufbuild folder"));
                }
                base_urls.push(b.to_ascii_lowercase());
                b
            }
            Some(_) => return keep_all(format!("{path}'s baseUrl cannot be read")),
            None => dir_of(path).to_string(),
        };
        match at_key(options, "paths") {
            None => {}
            Some(JNode { kind: JKind::Object(entries), .. }) => {
                if let Some((k, _)) = entries.iter().find(|(k, _)| runtime_modules.iter().any(|m| path_pattern_matches(&pystr::to_string(k), m))) {
                    return keep_all(format!("{path} maps {} to its own files", pystr::to_string(k)));
                }
                for (k, v) in entries {
                    let targets: Vec<String> = match &v.kind {
                        JKind::Array(items) => items.iter().filter_map(|i| if let JKind::Str(x) = &i.kind { Some(pystr::to_string(x).to_ascii_lowercase()) } else { None }).collect(),
                        _ => Vec::new(),
                    };
                    if targets.is_empty() {
                        alias_any = true;
                    }
                    ts_paths.push((pystr::to_string(k).to_ascii_lowercase(), targets, at.to_ascii_lowercase()));
                }
            }
            Some(_) => return keep_all(format!("{path}'s paths cannot be read")),
        }
    }

    // where each module object, re-export and load leads; which files they may read whole (bad), and which they
    // re-export (each a key a file may be named by)
    let files: HashSet<String> = seen.iter().filter(|u| u.part != Part::Whole).flat_map(|u| keys_of(&u.path).0).collect();
    let resolver = Resolver { roots, declared, aliased, alias_any, remapped, paths: ts_paths, base_urls, files };
    #[derive(Clone, Hash, PartialEq, Eq)]
    enum Key {
        Exact(String),
        Base(String),
        Root(String),
        Any,
    }
    let keys_of_leads = |l: &Leads| -> Vec<Key> {
        let mut out: Vec<Key> = l.exact.iter().map(|e| Key::Exact(e.clone())).collect();
        out.extend(l.base.iter().map(|b| Key::Base(b.clone())));
        out.extend(l.roots.iter().map(|r| Key::Root(r.clone())));
        if l.any {
            out.push(Key::Any);
        }
        out
    };
    // the files each key names
    let mut files_by_key: HashMap<Key, Vec<usize>> = HashMap::new();
    let mut file_units: Vec<usize> = Vec::new();
    for (ui, u) in seen.iter().enumerate() {
        if u.part == Part::Whole {
            continue;
        }
        file_units.push(ui);
        let (exact, base, above) = keys_of(&u.path);
        for k in exact.into_iter().map(Key::Exact).chain(base.into_iter().map(Key::Base)).chain(above.into_iter().map(Key::Root)) {
            files_by_key.entry(k).or_default().push(ui);
        }
    }
    files_by_key.insert(Key::Any, file_units);
    // a key reached by a module read whole (with why), and the keys each file re-exports
    let mut bad_keys: HashMap<Key, String> = HashMap::new();
    let mut reexports: Vec<Vec<Key>> = vec![Vec::new(); seen.len()];
    for (ui, u) in seen.iter().enumerate() {
        for (spec, kind, whole) in &u.refs {
            let keys = keys_of_leads(&resolver.leads(spec, &u.path, kind));
            if *whole {
                for k in keys {
                    bad_keys.entry(k).or_insert_with(|| format!("{} loads a module that may hold it as a whole ({spec})", u.path));
                }
            } else if *kind == RefKind::ReExport {
                // (a component's script re-exports for whoever imports the component)
                reexports[ui].extend(keys);
            }
        }
    }
    // the files read whole: those a bad key names, those that read their own exports so, and those a file read whole
    // re-exports, to a fixed point (each key and each file once)
    let mut bad: Vec<Option<String>> = vec![None; seen.len()];
    let mut queue: Vec<usize> = Vec::new();
    for (ui, u) in seen.iter().enumerate() {
        if let Some(w) = &u.scope {
            bad[ui] = Some(w.clone());
            queue.push(ui);
        }
    }
    let mut done_keys: HashSet<Key> = HashSet::new();
    let mut key_queue: Vec<(Key, String)> = bad_keys.into_iter().collect();
    loop {
        while let Some((k, why)) = key_queue.pop() {
            if !done_keys.insert(k.clone()) {
                continue;
            }
            for &ui in files_by_key.get(&k).map(|v| v.as_slice()).unwrap_or(&[]) {
                if bad[ui].is_none() {
                    bad[ui] = Some(why.clone());
                    queue.push(ui);
                }
            }
        }
        let Some(ui) = queue.pop() else { break };
        let why = bad[ui].clone().unwrap_or_default();
        for k in &reexports[ui] {
            if !done_keys.contains(k) {
                key_queue.push((k.clone(), format!("{} (it re-exports the module)", why)));
            }
        }
    }

    // the loader remapped by a manifest above the descriptor (B-3), or carried in the package
    let mut bad_manifest: HashMap<String, String> = HashMap::new();
    for (path, node) in &manifests {
        let why = match node {
            None => Some(format!("{path} cannot be read")),
            Some(n) if remaps_runtime(n, 0) => Some(format!("{path} maps @bufbuild/protobuf to another package")),
            _ => None,
        };
        if let Some(w) = why {
            bad_manifest.entry(dir_of(path).to_string()).or_insert(w);
        }
    }
    let own_copies: Vec<&str> = known.iter().copied().filter(|k| k.contains("node_modules/@bufbuild/protobuf/")).collect();
    let loader_why = |ui: usize| -> Option<String> {
        let d = dir_of(&seen[ui].path).to_string();
        let mut a: &str = &d;
        loop {
            if let Some(w) = bad_manifest.get(a) {
                return Some(w.clone());
            }
            if a.is_empty() {
                break;
            }
            a = dir_of(a);
        }
        if input.package {
            let root = manifests.iter().map(|(p, _)| dir_of(p)).filter(|r| at_or_above(r, &d)).max_by_key(|r| r.len()).unwrap_or("");
            for k in &own_copies {
                if let Some(i) = k.find("node_modules/@bufbuild/protobuf/") {
                    let a = k[..i].trim_end_matches('/');
                    if at_or_above(a, &d) && at_or_above(root, a) {
                        return Some(format!("the package carries its own @bufbuild/protobuf ({k})"));
                    }
                }
            }
        }
        None
    };
    let mut loader_cache: HashMap<usize, Option<String>> = HashMap::new();
    for &ui in &def_units {
        loader_cache.insert(ui, loader_why(ui));
    }

    input
        .findings
        .iter()
        .zip(finding_cands)
        .map(|((path, line), fc)| {
            let why = match fc {
                Err(w) => Some(w),
                Ok(list) => list.iter().find_map(|&ci| {
                    let c = &cands[ci];
                    let name = pystr::to_string(&c.name);
                    misused
                        .get(&c.name)
                        .map(|w| format!("{name}: {w}"))
                        .or_else(|| unit_why.get(&c.unit).map(|w| format!("{name}: {w}")))
                        .or_else(|| bad[c.unit].as_ref().map(|w| format!("{name}: {w}")))
                        .or_else(|| loader_cache[&c.unit].as_ref().map(|w| format!("{name}: {w}")))
                }),
            };
            (path.clone(), *line, why)
        })
        .collect()
}

/// Every key of a module map (an import map's, Babel's module-resolver's `alias` …), lower case: names it may send
/// elsewhere.
fn collect_keys(node: &JNode, out: &mut HashSet<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    match &node.kind {
        JKind::Object(m) => {
            for (k, v) in m {
                out.insert(pystr::to_string(k).to_ascii_lowercase());
                collect_keys(v, out, depth + 1);
            }
        }
        JKind::Array(a) => {
            for v in a {
                collect_keys(v, out, depth + 1);
            }
        }
        _ => {}
    }
}
