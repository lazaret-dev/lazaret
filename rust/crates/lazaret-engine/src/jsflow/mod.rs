//! Cross-file taint for JavaScript and TypeScript, on parsed trees: a port
//! of `lazaret.scanner.jsflow` (jsflow.py), function for function, which
//! both packages ask since phase 3 of the Rust-first refactor retired
//! jsflow.py and its npm twin (docs/RUST_ENGINE.md §8, §16).
//!
//! The model is jsflow.py's: each function gets a summary — which of its
//! parameters reach which sinks, what its return value carries — computed
//! to a fixpoint over the call graph, callees first; findings come from a
//! last pass over every function. Names are resolved with scopes (var and
//! function hoisting, block-scoped let, const and class, parameters, catch
//! clauses, imports) and values with a flow-insensitive points-to for
//! functions, modules, objects and classes (`descs.rs`); values are
//! followed through a function flow-sensitively (`eval.rs`); the driver
//! (`driver.rs`) reads the files, runs the fixpoint and the reporting pass
//! and returns the findings as data, for the host to build its issues from
//! (flow._issue, flow._flow_note, flow._skipped_size; flow.js's twins).
//!
//! Deterministic: no wall clock — a work budget (steps per tree node), a cap
//! on one function's reading and a per-function re-analysis cap bound the
//! pass, as in jsflow.py. Where jsflow.py kept a dict's insertion order or
//! deduped with `dict.fromkeys`, so does this: the order of a call's
//! targets decides which of them a finding names.

pub mod descs;
pub mod driver;
pub mod eval;
pub mod supply;
#[cfg(test)]
mod tests;

use crate::jsparse::tree::{self as jt, Kind, NodeId, Tree, NONE};
use crate::pystr::PyStr;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

pub use driver::{analyze, Config, Out};

pub const MAX_FILE: usize = 2_000_000;
pub const MAX_TOTAL: usize = 8_000_000;
pub const MAX_OPEN: usize = 4;
pub const MAX_ITERS: u32 = 50;
pub const MAX_PARAMS: usize = 64;
pub const PARAM_BASE: u64 = 1 << 20;
/// A parameter's key, set on a value read through a member of the parameter whose name is not the environment's
/// (the supply-chain model, D-16: `env.platform`, `env.readConfig()`): what a call gives such a parameter is,
/// there, its value without the whole environment.
pub const MEMBER_KEY: u64 = 1 << 63;

/// The function a parameter's key is of.
pub fn key_owner(key: u64) -> FnId {
    ((key & !MEMBER_KEY) / PARAM_BASE) as FnId
}

/// A parameter's key's index among its function's parameters.
pub fn key_index(key: u64) -> usize {
    ((key & !MEMBER_KEY) % PARAM_BASE) as usize
}
pub const EXPORT_HOPS: u32 = 8;
pub const ALIAS_DEPTH: u32 = 16;
pub const WORK_BASE: u64 = 200_000;
pub const WORK_PER_NODE: u64 = 24;
pub const EMIT_PER_NODE: u64 = 8;
pub const RUN_BASE: u64 = 2_000;
pub const RUN_PER_NODE: u64 = 64;
pub const TEXT_MAX: usize = 400;

/// The sink categories, in jsflow.py's order (a value's `clean` is a bit
/// set over them).
pub const CATS: [&str; 8] = [
    "SQL injection",
    "command injection",
    "code injection",
    "template injection",
    "path traversal",
    "server-side request forgery",
    "open redirect",
    "cross-site scripting",
];
pub const SQL: u8 = 0;
pub const CMD: u8 = 1;
pub const CODE: u8 = 2;
pub const TEMPLATE: u8 = 3;
pub const PATH: u8 = 4;
pub const SSRF: u8 = 5;
pub const REDIRECT: u8 = 6;
pub const XSS: u8 = 7;
pub const ALL: u8 = 0xFF;
pub const FIXED_HOST: u8 = (1 << SSRF) | (1 << REDIRECT);

/// A category's bit.
pub const fn bit(cat: u8) -> u8 {
    1 << cat
}

/// A category by its name.
pub fn cat_of(name: &str) -> Option<u8> {
    CATS.iter().position(|c| *c == name).map(|k| k as u8)
}

pub(crate) const EXTS: [&str; 8] = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"];

pub(crate) fn ts_sources(ext: &str) -> &'static [&'static str] {
    match ext {
        ".js" => &[".ts", ".tsx"],
        ".jsx" => &[".tsx"],
        ".mjs" => &[".mts"],
        ".cjs" => &[".cts"],
        _ => &[],
    }
}

pub(crate) const NODE_BUILTINS: &[&str] = &[
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder",
    "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
];

pub(crate) const GLOBAL_OBJECTS: &[&str] = &[
    "JSON", "Math", "Object", "Array", "Number", "String", "Boolean", "Symbol", "BigInt", "Date", "RegExp", "Error",
    "Promise", "Reflect", "Proxy", "Intl", "Atomics", "WebAssembly", "console", "Buffer", "process", "globalThis",
    "window", "document", "navigator", "Map", "Set", "WeakMap", "WeakSet", "$", "jQuery", "_",
];

pub(crate) const COMMON_METHODS: &[&str] = &[
    "at", "charAt", "charCodeAt", "codePointAt", "concat", "endsWith", "includes", "indexOf", "lastIndexOf",
    "localeCompare", "match", "matchAll", "normalize", "padEnd", "padStart", "repeat", "replace", "replaceAll",
    "search", "slice", "split", "startsWith", "substr", "substring", "toLowerCase", "toUpperCase",
    "toLocaleLowerCase", "toLocaleUpperCase", "toString", "toLocaleString", "trim", "trimStart", "trimEnd",
    "trimLeft", "trimRight", "valueOf", "copyWithin", "entries", "every", "fill", "filter", "find", "findIndex",
    "findLast", "findLastIndex", "flat", "flatMap", "forEach", "join", "keys", "map", "pop", "push", "reduce",
    "reduceRight", "reverse", "shift", "some", "sort", "splice", "unshift", "values", "hasOwnProperty",
    "isPrototypeOf", "propertyIsEnumerable", "apply", "bind", "call", "then", "catch", "finally", "get", "set", "has",
    "delete", "clear", "add", "exec", "test", "getTime", "toISOString", "toJSON", "parse", "stringify", "on", "once",
    "off", "emit", "addListener", "removeListener", "removeAllListeners", "addEventListener", "removeEventListener",
    "dispatchEvent", "pipe", "write", "end", "read", "destroy", "resume", "pause", "log", "debug", "info", "warn",
    "error", "trace", "send", "json", "status", "render", "sendFile", "sendStatus", "cookie", "header", "type",
];

pub(crate) const CLEAN_RESULT: &[&str] = &[
    "test", "includes", "startsWith", "endsWith", "indexOf", "lastIndexOf", "findIndex", "findLastIndex",
    "localeCompare", "some", "every", "has", "isArray", "isNaN", "isFinite", "isInteger", "isSafeInteger",
    "hasOwnProperty", "getTime", "charCodeAt", "codePointAt", "search",
];

pub(crate) const REGEXP_MEMBERS: &[&str] = &[
    "exec", "test", "lastIndex", "source", "flags", "global", "ignoreCase", "multiline", "sticky", "unicode",
    "dotAll", "hasIndices", "toString",
];

pub(crate) const ROUTE_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "del", "all", "options", "head", "use"];
pub(crate) const REQUEST_PROPS: &[&str] = &[
    "query", "body", "params", "headers", "cookies", "signedCookies", "files", "file", "originalUrl", "url", "path",
    "hostname",
];
pub(crate) const REQUEST_CALLS: &[&str] = &["get", "header", "param"];
pub(crate) const REQUEST_WRAPPERS: &[&str] = &["request", "req"];
pub(crate) const REQUEST_OBJECTS: &[&str] = &["query", "body", "params", "headers", "cookies", "signedCookies"];

/// Is `s` one of `set`'s words?
pub(crate) fn is_in(set: &[&str], s: &[u32]) -> bool {
    set.iter().any(|w| eq(s, w))
}

/// Does the code-point string `s` equal `w`?
pub(crate) fn eq(s: &[u32], w: &str) -> bool {
    s.len() == w.len() && s.iter().zip(w.bytes()).all(|(&a, b)| a == b as u32)
}

pub(crate) fn u(s: &str) -> PyStr {
    s.chars().map(|c| c as u32).collect()
}

/// ASCII letters lowered (the same in both engines, whatever the Unicode
/// tables).
pub(crate) fn lower(s: &[u32]) -> PyStr {
    s.iter().map(|&c| if (0x41..=0x5A).contains(&c) { c + 32 } else { c }).collect()
}

/// base/rel with its "." and ".." segments resolved (empty segments
/// dropped); None when it climbs above the root.
pub(crate) fn join(base: &[u32], rel: &[u32]) -> Option<PyStr> {
    let mut parts: Vec<&[u32]> = Vec::new();
    for seg in base.split(|&c| c == 0x2F).chain(rel.split(|&c| c == 0x2F)) {
        if seg.is_empty() || eq(seg, ".") {
            continue;
        }
        if eq(seg, "..") {
            parts.pop()?;
        } else {
            parts.push(seg);
        }
    }
    let mut out = Vec::new();
    for (k, p) in parts.iter().enumerate() {
        if k > 0 {
            out.push(0x2F);
        }
        out.extend_from_slice(p);
    }
    Some(out)
}

// ------------------------------------------------------------------ values --

/// What a value carries (jsflow.py's _V): request data (`src`, read at
/// `origin` in function `fname`; `via`: the chain it arrived by — a
/// returned value, an imported variable), the parameters of the function
/// being read or of functions around it (`params`: keys), the sink
/// categories it is sanitized for (`clean`, a bit set), whether it was
/// joined into a string (`built`), and `kind`: bit 1 a request object, bit
/// 2 a response object (the supply-chain model's marks: `supply::OBJ_*`).
/// With the supply-chain model (`supply.rs`) the source is local data, and
/// `sc` says which kinds the value holds and which read came first; project
/// mode never sets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V {
    pub src: bool,
    /// (module, line) of the read
    pub origin: Option<(u32, u32)>,
    pub fname: Option<Rc<PyStr>>,
    pub via: Option<Rc<PyStr>>,
    /// sorted, unique
    pub params: Rc<[u64]>,
    pub clean: u8,
    pub built: bool,
    pub kind: u8,
    pub sc: Option<Rc<Sc>>,
}

/// The supply-chain model's source facts of a value: the first read (by its
/// offset in the text) of each kind of local data it holds — (the kind's
/// index in `supply::KIND_NAMES`, what it read: an environment variable's
/// name, a path, a command; the offset) — in the kinds' order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sc {
    pub kinds: u16,
    pub firsts: Vec<(u8, Rc<PyStr>, u32)>,
}

/// Both values' source facts: the kinds of both, each kind's earlier read.
pub fn sc_union(a: &Option<Rc<Sc>>, b: &Option<Rc<Sc>>) -> Option<Rc<Sc>> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) => Some(x.clone()),
        (None, Some(y)) => Some(y.clone()),
        (Some(x), Some(y)) => {
            if Rc::ptr_eq(x, y) || x == y {
                return Some(x.clone());
            }
            let mut firsts: Vec<(u8, Rc<PyStr>, u32)> = Vec::with_capacity(x.firsts.len() + y.firsts.len());
            let (mut i, mut j) = (0, 0);
            while i < x.firsts.len() || j < y.firsts.len() {
                let take_x = j >= y.firsts.len() || (i < x.firsts.len() && x.firsts[i].0 < y.firsts[j].0);
                let take_y = i >= x.firsts.len() || (j < y.firsts.len() && y.firsts[j].0 < x.firsts[i].0);
                if take_x {
                    firsts.push(x.firsts[i].clone());
                    i += 1;
                } else if take_y {
                    firsts.push(y.firsts[j].clone());
                    j += 1;
                } else {
                    // the same kind in both: the earlier read
                    firsts.push(if y.firsts[j].2 < x.firsts[i].2 { y.firsts[j].clone() } else { x.firsts[i].clone() });
                    i += 1;
                    j += 1;
                }
            }
            let out = Sc { kinds: x.kinds | y.kinds, firsts };
            if out == **x {
                return Some(x.clone());
            }
            if out == **y {
                return Some(y.clone());
            }
            Some(Rc::new(out))
        }
    }
}

thread_local! {
    static NO_PARAMS: Rc<[u64]> = Rc::from(Vec::new());
}

fn no_params() -> Rc<[u64]> {
    NO_PARAMS.with(|p| p.clone())
}

impl V {
    /// jsflow.py's _V(…): the read's fields kept only for request data.
    pub fn new(
        src: bool,
        origin: Option<(u32, u32)>,
        fname: Option<Rc<PyStr>>,
        via: Option<Rc<PyStr>>,
        params: Rc<[u64]>,
        clean: u8,
        built: bool,
        kind: u8,
    ) -> V {
        V {
            src,
            origin: if src { origin } else { None },
            fname: if src { fname } else { None },
            via: if src { via } else { None },
            params,
            clean,
            built,
            kind,
            sc: None,
        }
    }

    /// The value with the supply-chain model's source facts (kept only for
    /// a source's value, like `origin`).
    pub fn with_sc(mut self, sc: Option<Rc<Sc>>) -> V {
        self.sc = if self.src { sc } else { None };
        self
    }

    /// EMPTY: nothing, clean for every category.
    pub fn empty() -> V {
        V { src: false, origin: None, fname: None, via: None, params: no_params(), clean: ALL, built: false, kind: 0, sc: None }
    }

    /// A value holding one parameter key.
    pub fn param(key: u64, clean: u8, built: bool, kind: u8) -> V {
        V::new(false, None, None, None, Rc::from(vec![key]), clean, built, kind)
    }

    pub fn is_empty(&self) -> bool {
        !self.src && self.params.is_empty() && self.clean == ALL && !self.built && self.kind == 0
    }

    pub fn tainted(&self) -> bool {
        self.src || !self.params.is_empty()
    }

    pub fn union(&self, o: &V) -> V {
        if o.is_empty() {
            return self.clone();
        }
        if self.is_empty() {
            return o.clone();
        }
        let s = if self.src { self } else { o };
        let params: Rc<[u64]> = if o.params.is_empty() {
            self.params.clone()
        } else if self.params.is_empty() {
            o.params.clone()
        } else {
            let mut all: Vec<u64> = Vec::with_capacity(self.params.len() + o.params.len());
            let (a, b) = (&self.params, &o.params);
            let (mut i, mut j) = (0, 0);
            while i < a.len() || j < b.len() {
                let x = if j >= b.len() || (i < a.len() && a[i] <= b[j]) {
                    let x = a[i];
                    if j < b.len() && b[j] == x {
                        j += 1;
                    }
                    i += 1;
                    x
                } else {
                    let x = b[j];
                    j += 1;
                    x
                };
                all.push(x);
            }
            all.truncate(MAX_PARAMS);
            Rc::from(all)
        };
        V::new(self.src || o.src, s.origin, s.fname.clone(), s.via.clone(), params, self.clean & o.clean, self.built || o.built, self.kind | o.kind)
            .with_sc(sc_union(&self.sc, &o.sc))
    }

    pub fn sanitize(&self, bits: u8) -> V {
        if !self.tainted() {
            return V::empty();
        }
        V::new(self.src, self.origin, self.fname.clone(), self.via.clone(), self.params.clone(), self.clean | bits, self.built, 0)
            .with_sc(self.sc.clone())
    }

    pub fn with_built(&self) -> V {
        if !self.tainted() || self.built {
            return self.clone();
        }
        V::new(self.src, self.origin, self.fname.clone(), self.via.clone(), self.params.clone(), self.clean, true, self.kind)
            .with_sc(self.sc.clone())
    }

    pub fn with_via(&self, via: Rc<PyStr>) -> V {
        V::new(self.src, self.origin, self.fname.clone(), Some(via), self.params.clone(), self.clean, self.built, self.kind)
            .with_sc(self.sc.clone())
    }

    /// The value with only the parameters of functions `fids`.
    pub fn within(&self, fids: &BTreeSet<u32>) -> V {
        if self.params.is_empty() {
            return self.clone();
        }
        let params: Vec<u64> = self.params.iter().copied().filter(|&k| fids.contains(&key_owner(k))).collect();
        if params.len() == self.params.len() {
            return self.clone();
        }
        if !self.src && params.is_empty() {
            return V::empty();
        }
        V::new(self.src, self.origin, self.fname.clone(), self.via.clone(), Rc::from(params), self.clean, self.built, self.kind)
            .with_sc(self.sc.clone())
    }

    /// The value read through a member of a name that is not the environment's: its parameters' keys with
    /// MEMBER_KEY set (D-16).
    pub fn through_member(&self) -> V {
        if self.params.iter().all(|&k| k & MEMBER_KEY != 0) {
            return self.clone();
        }
        let mut keys: Vec<u64> = self.params.iter().map(|&k| k | MEMBER_KEY).collect();
        keys.sort_unstable();
        keys.dedup();
        V::new(self.src, self.origin, self.fname.clone(), self.via.clone(), Rc::from(keys), self.clean, self.built, self.kind)
            .with_sc(self.sc.clone())
    }

    /// The value without a request or response object's mark.
    pub fn plain(&self) -> V {
        if self.kind == 0 {
            return self.clone();
        }
        if !self.tainted() {
            return V::empty();
        }
        V::new(self.src, self.origin, self.fname.clone(), self.via.clone(), self.params.clone(), self.clean, self.built, 0)
            .with_sc(self.sc.clone())
    }
}

pub fn union_all<'a>(vals: impl IntoIterator<Item = &'a V>) -> V {
    let mut out = V::empty();
    for v in vals {
        out = out.union(v);
    }
    out
}

// ------------------------------------------------------------------- model --

pub type ScopeId = u32;
pub type BindId = u32;
pub type FnId = u32;
pub type ClassId = u32;
pub type ObjId = u32;
pub type ModId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    /// a var scope: functions and the module
    Function,
    Block,
}

pub struct Scope {
    pub kind: ScopeKind,
    pub parent: Option<ScopeId>,
    pub names: HashMap<PyStr, BindId>,
    /// the function the scope's code belongs to
    pub fid: FnId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindKind {
    Var,
    Let,
    Const,
    Using,
    AwaitUsing,
    Param,
    Function,
    Class,
    Import,
    Catch,
    Enum,
}

impl BindKind {
    fn of_var(op: u8) -> BindKind {
        match op {
            jt::VAR => BindKind::Var,
            jt::LET => BindKind::Let,
            jt::CONST => BindKind::Const,
            jt::USING => BindKind::Using,
            _ => BindKind::AwaitUsing,
        }
    }
}

/// A property path a pattern reads on the way to a name: a name, or None
/// for an element, a rest or a computed key.
pub type Path = Vec<Option<PyStr>>;

/// What is written to a binding (its module's nodes).
#[derive(Clone, Debug)]
pub enum Write {
    Fn { node: NodeId, scope: ScopeId, fid: FnId },
    Param { node: NodeId, scope: ScopeId, index: usize },
    Init { node: NodeId, scope: ScopeId, path: Path },
    Assign { node: NodeId, scope: ScopeId, path: Path },
    Nothing { scope: ScopeId },
    Import { spec: PyStr, scope: ScopeId, name: PyStr },
    Class { node: NodeId, scope: ScopeId, cid: ClassId },
    Opaque { node: NodeId, scope: ScopeId },
}

pub struct Bind {
    pub bid: BindId,
    pub name: PyStr,
    pub kind: BindKind,
    /// the function whose code declares it
    pub fid: FnId,
    pub writes: Vec<Write>,
    /// read or written by another function (closures, module variables)
    pub shared: bool,
    pub module: ModId,
    /// (identifier node, parent node) of every reference
    pub refs: Vec<(NodeId, NodeId)>,
    /// an import: the bindings it reads in the modules it names
    pub targets: Option<Vec<BindId>>,
}

/// A sink a parameter reaches: (file, line, the function's label, whether
/// the value must be joined into the query text).
pub type Entry = (u32, u32, Rc<PyStr>, bool);

pub struct Func {
    pub fid: FnId,
    pub module: ModId,
    /// its node (the Program for the module's own code)
    pub node: NodeId,
    pub name: Option<PyStr>,
    pub params: Vec<NodeId>,
    pub scope: ScopeId,
    /// the enclosing function (None: the module's own code)
    pub parent: Option<FnId>,
    pub line: u32,
    /// the class of a method
    pub cls: Option<ClassId>,
    /// the object literal of a method
    pub obj: Option<ObjId>,
    /// the module's own code
    pub is_module: bool,
    /// a route handler: 1 (request, response), 2 (error, request, response)
    pub route: u8,
    /// param index -> category -> the sink it reaches
    pub reach: BTreeMap<usize, BTreeMap<u8, Entry>>,
    /// (param index, category) -> whether it reaches the sink through a member alone (MEMBER_KEY, D-16)
    pub reach_member: BTreeMap<(usize, u8), bool>,
    /// param index -> (clean, built, through a member alone: MEMBER_KEY) of the value it returns
    pub ret_params: BTreeMap<usize, (u8, bool, bool)>,
    /// request data it returns
    pub ret_src: Option<V>,
    /// key of an enclosing function's parameter it returns -> (clean, built)
    pub ret_outer: BTreeMap<u64, (u8, bool)>,
    /// param index -> the closure variables it is written to (the
    /// supply-chain model's: `res.on('data', d => body += d)`)
    pub param_writes: BTreeMap<usize, BTreeSet<BindId>>,
    /// param index -> the files it is written to: (the keys of the path, where), the supply-chain model's (D-2:
    /// `request.get(u, (e, r, body) => fs.writeFileSync(p, body))`, a callback given a download)
    pub param_files: BTreeMap<usize, BTreeSet<(Vec<PyStr>, u32)>>,
    /// fid -> the parameters it passed tainted values in its last reading
    pub callers: BTreeMap<FnId, BTreeSet<usize>>,
    pub runs: u32,
    /// (call node, scope) of its call sites
    pub calls: Vec<(NodeId, ScopeId)>,
    pub size: u64,
}

impl Func {
    pub fn label(&self) -> PyStr {
        if self.is_module {
            return u("(module level)");
        }
        match &self.name {
            Some(n) if !n.is_empty() => {
                let mut out = u("(in ");
                out.extend_from_slice(n);
                out.extend(u("())"));
                out
            }
            _ => u("(in an anonymous function)"),
        }
    }

    pub fn display(&self) -> PyStr {
        if self.is_module {
            return u("the module's own code");
        }
        match &self.name {
            Some(n) if !n.is_empty() => {
                let mut out = n.clone();
                out.extend(u("()"));
                out
            }
            _ => u("an anonymous function"),
        }
    }
}

pub struct Class {
    pub cid: ClassId,
    pub name: Option<PyStr>,
    /// prototype method name -> fid
    pub methods: HashMap<PyStr, FnId>,
    /// static member name -> fid
    pub statics: HashMap<PyStr, FnId>,
    /// the superclass expression: (module, node, scope)
    pub sup: Option<(ModId, NodeId, ScopeId)>,
}

pub struct Obj {
    pub oid: ObjId,
    pub module: ModId,
    /// key -> [(value node, scope)]
    pub props: HashMap<PyStr, Vec<(NodeId, ScopeId)>>,
}

/// An export of a module.
#[derive(Clone, Debug)]
pub enum Export {
    /// a name of the module (looked up in `scope`)
    Binding { name: PyStr, scope: ScopeId },
    /// `export { x } from 'm'`
    Reexport { spec: PyStr, name: PyStr },
    /// `export default <node>`
    Expr { node: NodeId, scope: ScopeId },
    /// `export * as ns from 'm'`
    Namespace { spec: PyStr },
}

/// Not resolved yet / a global (no binding).
pub const UNSET: u32 = u32::MAX;
pub const GLOBAL: u32 = u32::MAX - 1;

pub struct Mod {
    pub idx: ModId,
    pub path: PyStr,
    /// the index of its file in the pass's input
    pub file: u32,
    pub dir: PyStr,
    pub tree: Tree,
    pub scope: ScopeId,
    /// fid of the module's own code
    pub fn_: FnId,
    /// ESM export name -> [entry]
    pub named: HashMap<PyStr, Vec<Export>>,
    /// `export * from` specifiers
    pub stars: Vec<PyStr>,
    /// module.exports = … : [(node, scope)]
    pub cjs: Vec<(NodeId, ScopeId)>,
    /// exports.x = … : name -> [(node, scope)]
    pub cjs_props: HashMap<PyStr, Vec<(NodeId, ScopeId)>>,
    /// a direct eval() or a with statement
    pub eval_with: bool,
    /// RegExp.prototype touched
    pub regexp_proto: bool,
    /// the global RegExp assigned
    pub regexp_rebound: bool,
    pub nodes: u64,
    // the per-node annotations jsflow.py keeps on its dicts
    pub scope_at: Vec<u32>,
    pub fid_at: Vec<u32>,
    pub cid_at: Vec<u32>,
    pub oid_at: Vec<u32>,
    pub bind_at: Vec<u32>,
    pub asg: Vec<bool>,
    pub text_memo: HashMap<NodeId, Rc<PyStr>>,
}

impl Mod {
    pub fn t(&self) -> &Tree {
        &self.tree
    }
}

// ------------------------------------------------------------- tree access --

/// Node field access by slot (the kinds' fields, jsparse/tree.rs `fields`).
pub(crate) struct Ast<'t>(pub &'t Tree);

impl<'t> Ast<'t> {
    #[inline]
    pub fn kind(&self, id: NodeId) -> Kind {
        self.0.nodes[id as usize].kind
    }
    #[inline]
    pub fn line(&self, id: NodeId) -> u32 {
        self.0.nodes[id as usize].line
    }
    #[inline]
    pub fn op(&self, id: NodeId) -> u8 {
        self.0.nodes[id as usize].op
    }
    #[inline]
    pub fn flag(&self, id: NodeId, f: u16) -> bool {
        self.0.nodes[id as usize].flags & f != 0
    }
    /// A child slot (NONE when null).
    #[inline]
    pub fn at(&self, id: NodeId, slot: u8) -> NodeId {
        self.0.nodes[id as usize].f[slot as usize]
    }
    #[inline]
    pub fn opt(&self, id: NodeId, slot: u8) -> Option<NodeId> {
        let c = self.at(id, slot);
        if c == NONE {
            None
        } else {
            Some(c)
        }
    }
    #[inline]
    pub fn list(&self, id: NodeId, slot: u8) -> &'t [NodeId] {
        self.0.list(self.0.nodes[id as usize].f[slot as usize])
    }
    /// A string slot's text.
    #[inline]
    pub fn s(&self, id: NodeId, slot: u8) -> &'t [u32] {
        self.0.str(self.0.nodes[id as usize].f[slot as usize])
    }
    /// An Identifier's (PrivateIdentifier's, JSXIdentifier's) name.
    #[inline]
    pub fn name(&self, id: NodeId) -> &'t [u32] {
        self.s(id, jt::A)
    }
    pub fn is_ident(&self, id: NodeId) -> bool {
        self.kind(id) == Kind::Identifier
    }
    pub fn is_ident_named(&self, id: NodeId, n: &str) -> bool {
        self.kind(id) == Kind::Identifier && eq(self.name(id), n)
    }
    pub fn is_function(&self, id: NodeId) -> bool {
        matches!(self.kind(id), Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression)
    }
    pub fn is_string(&self, id: NodeId) -> bool {
        self.kind(id) == Kind::Literal && self.op(id) == jt::L_STRING
    }
    /// A string Literal's value.
    pub fn str_value(&self, id: NodeId) -> Option<&'t [u32]> {
        if self.is_string(id) {
            Some(self.s(id, jt::A))
        } else {
            None
        }
    }
    /// An operator node's operator text.
    pub fn operator(&self, id: NodeId) -> &'static str {
        self.0.operator(id)
    }
    pub fn computed(&self, id: NodeId) -> bool {
        self.flag(id, jt::COMPUTED)
    }

    /// jsflow.py's _kids: the child nodes in source order (its own table).
    pub fn kids(&self, id: NodeId) -> Vec<NodeId> {
        use jt::{A, B, C, D};
        use Kind::*;
        let mut out = Vec::new();
        let one = |out: &mut Vec<NodeId>, c: NodeId| {
            if c != NONE {
                out.push(c);
            }
        };
        let n = &self.0.nodes[id as usize];
        let lst = |s: u8| self.0.list(n.f[s as usize]);
        match n.kind {
            Program | BlockStatement | StaticBlock | ClassBody => out.extend(lst(A).iter().copied().filter(|&c| c != NONE)),
            ExpressionStatement | TSExportAssignment | ChainExpression | JSXExpressionContainer | JSXSpreadChild => {
                one(&mut out, n.f[A as usize])
            }
            WithStatement => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize])
            }
            ReturnStatement | ThrowStatement | UpdateExpression | UnaryExpression | AwaitExpression | YieldExpression
            | SpreadElement | RestElement | JSXSpreadAttribute => one(&mut out, n.f[A as usize]),
            LabeledStatement => one(&mut out, n.f[B as usize]),
            IfStatement | ConditionalExpression => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize]);
                one(&mut out, n.f[C as usize])
            }
            SwitchStatement | SwitchCase => {
                one(&mut out, n.f[A as usize]);
                out.extend(lst(B).iter().copied().filter(|&c| c != NONE))
            }
            TryStatement => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize]);
                one(&mut out, n.f[C as usize])
            }
            CatchClause | WhileStatement | DoWhileStatement | VariableDeclarator | Property | MemberExpression
            | BinaryExpression | LogicalExpression | AssignmentExpression | AssignmentPattern | TaggedTemplateExpression => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize])
            }
            ForStatement => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize]);
                one(&mut out, n.f[C as usize]);
                one(&mut out, n.f[D as usize])
            }
            ForInStatement | ForOfStatement => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize]);
                one(&mut out, n.f[C as usize])
            }
            FunctionDeclaration | FunctionExpression | ArrowFunctionExpression => {
                out.extend(lst(B).iter().copied().filter(|&c| c != NONE));
                one(&mut out, n.f[C as usize])
            }
            VariableDeclaration | SequenceExpression | ObjectPattern | ObjectExpression | TemplateLiteral => {
                let s = if n.kind == TemplateLiteral { B } else { A };
                out.extend(lst(s).iter().copied().filter(|&c| c != NONE))
            }
            ClassDeclaration | ClassExpression => {
                if n.f[D as usize] != NONE {
                    out.extend(lst(D).iter().copied());
                }
                one(&mut out, n.f[B as usize]);
                one(&mut out, n.f[C as usize])
            }
            MethodDefinition | PropertyDefinition => {
                if n.f[D as usize] != NONE {
                    out.extend(lst(D).iter().copied());
                }
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize])
            }
            ExportNamedDeclaration => {
                one(&mut out, n.f[A as usize]);
                out.extend(lst(B).iter().copied().filter(|&c| c != NONE))
            }
            ExportDefaultDeclaration | ExportSpecifier => one(&mut out, n.f[A as usize]),
            ArrayExpression | ArrayPattern => out.extend(lst(A).iter().copied().filter(|&c| c != NONE)),
            CallExpression | NewExpression => {
                one(&mut out, n.f[A as usize]);
                out.extend(lst(B).iter().copied().filter(|&c| c != NONE))
            }
            ImportExpression => {
                one(&mut out, n.f[A as usize]);
                one(&mut out, n.f[B as usize])
            }
            JSXElement => {
                one(&mut out, n.f[A as usize]);
                out.extend(lst(C).iter().copied().filter(|&c| c != NONE))
            }
            JSXOpeningElement => out.extend(lst(B).iter().copied().filter(|&c| c != NONE)),
            JSXAttribute => one(&mut out, n.f[B as usize]),
            JSXFragment => out.extend(lst(A).iter().copied().filter(|&c| c != NONE)),
            TSEnumDeclaration => out.extend(lst(B).iter().copied().filter(|&c| c != NONE)),
            TSEnumMember => one(&mut out, n.f[B as usize]),
            TSModuleDeclaration => one(&mut out, n.f[B as usize]),
            _ => {}
        }
        out
    }

    /// jsflow.py's _pattern_names: (identifier node, property path) of each
    /// name a pattern binds, in source order.
    pub fn pattern_names(&self, pat: NodeId) -> Vec<(NodeId, Path)> {
        use jt::{A, B};
        let mut out = Vec::new();
        let mut stack: Vec<(NodeId, Path)> = vec![(pat, Vec::new())];
        while let Some((p, pth)) = stack.pop() {
            if p == NONE {
                continue;
            }
            match self.kind(p) {
                Kind::Identifier => out.push((p, pth)),
                Kind::ObjectPattern => {
                    for &prop in self.list(p, A).iter().rev() {
                        if self.kind(prop) == Kind::RestElement {
                            let mut q = pth.clone();
                            q.push(None);
                            stack.push((self.at(prop, A), q));
                        } else {
                            let mut name = None;
                            if !self.computed(prop) {
                                let key = self.at(prop, A);
                                name = if self.is_ident(key) {
                                    Some(self.name(key).to_vec())
                                } else {
                                    self.str_value(key).map(|v| v.to_vec())
                                };
                            }
                            let mut q = pth.clone();
                            q.push(name);
                            stack.push((self.at(prop, B), q));
                        }
                    }
                }
                Kind::ArrayPattern => {
                    for &el in self.list(p, A).iter().rev() {
                        let mut q = pth.clone();
                        q.push(None);
                        stack.push((el, q));
                    }
                }
                Kind::RestElement => {
                    let mut q = pth.clone();
                    q.push(None);
                    stack.push((self.at(p, A), q));
                }
                Kind::AssignmentPattern => stack.push((self.at(p, A), pth)),
                _ => {}
            }
        }
        out
    }

    /// jsflow.py's _pattern_members: the member expressions a pattern
    /// assigns to (`[a.b] = …`).
    pub fn pattern_members(&self, pat: NodeId) -> Vec<NodeId> {
        use jt::{A, B};
        let mut out = Vec::new();
        let mut stack = vec![pat];
        while let Some(p) = stack.pop() {
            if p == NONE {
                continue;
            }
            match self.kind(p) {
                Kind::MemberExpression => out.push(p),
                Kind::ObjectPattern => {
                    for &prop in self.list(p, A) {
                        stack.push(if self.kind(prop) == Kind::RestElement { self.at(prop, A) } else { self.at(prop, B) });
                    }
                }
                Kind::ArrayPattern => stack.extend(self.list(p, A).iter().copied()),
                Kind::RestElement | Kind::AssignmentPattern => stack.push(self.at(p, A)),
                _ => {}
            }
        }
        out
    }

    /// A member expression's property name, or None (computed, not a
    /// literal).
    pub fn prop_name(&self, member: NodeId) -> Option<PyStr> {
        let prop = self.at(member, jt::B);
        if !self.computed(member) {
            if self.kind(prop) == Kind::PrivateIdentifier {
                let mut out = vec![0x23];
                out.extend_from_slice(self.name(prop));
                return Some(out);
            }
            return Some(self.name(prop).to_vec());
        }
        if self.kind(prop) == Kind::Literal && matches!(self.op(prop), jt::L_STRING | jt::L_NUMBER) {
            return Some(self.s(prop, jt::A).to_vec());
        }
        // (a list of one string is that string as a key: `o[['post']]`)
        if self.kind(prop) == Kind::ArrayExpression {
            if let [only] = self.list(prop, jt::A) {
                if *only != NONE && self.kind(*only) == Kind::Literal && self.op(*only) == jt::L_STRING {
                    return Some(self.s(*only, jt::A).to_vec());
                }
            }
        }
        None
    }

    /// An object's or a class's member name, or None (computed).
    pub fn key_name(&self, prop: NodeId) -> Option<PyStr> {
        let key = self.at(prop, jt::A);
        if self.computed(prop) {
            return self.str_value(key).map(|v| v.to_vec());
        }
        match self.kind(key) {
            Kind::Identifier => Some(self.name(key).to_vec()),
            Kind::PrivateIdentifier => {
                let mut out = vec![0x23];
                out.extend_from_slice(self.name(key));
                Some(out)
            }
            Kind::Literal => match self.op(key) {
                jt::L_STRING | jt::L_NUMBER | jt::L_BIGINT | jt::L_REGEX => Some(self.s(key, jt::A).to_vec()),
                // (a boolean or null key: jsparse never gives one)
                _ => None,
            },
            _ => None,
        }
    }

    pub fn unwrap(&self, mut node: NodeId) -> NodeId {
        while self.kind(node) == Kind::ChainExpression {
            node = self.at(node, jt::A);
        }
        node
    }

    /// A route's path: '/…' or '*', a `/…` template, a regex literal, or an
    /// array of those.
    pub fn route_path(&self, node: NodeId) -> bool {
        match self.kind(node) {
            Kind::Literal => {
                if self.op(node) == jt::L_REGEX {
                    return true;
                }
                match self.str_value(node) {
                    Some(v) => v.first() == Some(&0x2F) || eq(v, "*"),
                    None => false,
                }
            }
            Kind::TemplateLiteral => {
                let q = self.list(node, jt::A);
                !q.is_empty() && self.s(q[0], jt::A).first() == Some(&0x2F)
            }
            Kind::ArrayExpression => {
                let els = self.list(node, jt::A);
                !els.is_empty()
                    && els.iter().all(|&e| e != NONE && self.kind(e) != Kind::ArrayExpression && self.route_path(e))
            }
            _ => false,
        }
    }

    /// The text a string expression starts with, when it starts with a
    /// literal: a string, a template's first part, the left end of a `+`
    /// chain; else None.
    pub fn leftmost_text(&self, mut node: NodeId) -> Option<&'t [u32]> {
        let mut seen = 0;
        while seen < ALIAS_DEPTH {
            seen += 1;
            match self.kind(node) {
                Kind::Literal => return self.str_value(node),
                Kind::TemplateLiteral => {
                    let q = self.list(node, jt::A);
                    return q.first().map(|&e| self.s(e, jt::A));
                }
                Kind::BinaryExpression if self.operator(node) == "+" => {
                    node = self.at(node, jt::A);
                    continue;
                }
                _ => return None,
            }
        }
        None
    }
}

pub(crate) fn html_type(value: &[u32]) -> bool {
    let v = lower(value);
    let has = |w: &str| {
        let w: Vec<u32> = w.chars().map(|c| c as u32).collect();
        v.windows(w.len()).any(|x| x == w.as_slice())
    };
    has("html") || has("xml") || has("svg")
}

// ------------------------------------------------------------------ program --

pub struct Program {
    pub mods: Vec<Mod>,
    pub by_path: HashMap<PyStr, ModId>,
    pub fns: Vec<Func>,
    pub classes: Vec<Class>,
    pub objs: Vec<Obj>,
    pub binds: Vec<Bind>,
    pub scopes: Vec<Scope>,
    /// function name -> [fid], every project function of that name
    pub by_name: HashMap<PyStr, Vec<FnId>>,
    /// bid -> everything written to a shared binding
    pub shared: HashMap<BindId, V>,
    /// bid -> who reads a shared binding (in the order they first did)
    pub readers: HashMap<BindId, Vec<FnId>>,
    pub desc_memo: HashMap<BindId, Rc<Vec<descs::D>>>,
    pub tg_memo: HashMap<(ModId, NodeId), Rc<(Vec<FnId>, descs::How)>>,
    pub cfg: Rc<Config>,
    pub work: u64,
    pub budget: u64,
    pub nodes: u64,
    pub anc: HashMap<FnId, Rc<BTreeSet<FnId>>>,
    /// (the supply-chain model) a member of `this` — (class or object
    /// literal, its id, the member's name) — as a binding of its own
    pub sc_props: HashMap<(u8, u32, PyStr), BindId>,
    /// (the supply-chain model) the classes whose instances are made in more
    /// than one place (`new C(…)` of them or of a subclass): made when first
    /// asked (descs::Program::sc_made_widely)
    pub sc_wide: Option<HashSet<ClassId>>,
    /// (the supply-chain model) a class's `this.x` binding -> the class
    pub sc_this_class: HashMap<BindId, ClassId>,
    /// (the supply-chain model) a module -> the names of the members of a name it puts anything into
    /// (`o.list.push(…)`, `Object.assign(o.opts, …)`): made when first asked (supply::collected_members, D-3b)
    pub sc_collected: HashMap<ModId, HashSet<PyStr>>,
}

impl Program {
    pub fn new(cfg: Rc<Config>) -> Program {
        Program {
            mods: Vec::new(),
            by_path: HashMap::new(),
            fns: Vec::new(),
            classes: Vec::new(),
            objs: Vec::new(),
            binds: Vec::new(),
            scopes: Vec::new(),
            by_name: HashMap::new(),
            shared: HashMap::new(),
            readers: HashMap::new(),
            desc_memo: HashMap::new(),
            tg_memo: HashMap::new(),
            cfg,
            work: 0,
            budget: WORK_BASE,
            nodes: 0,
            anc: HashMap::new(),
            sc_props: HashMap::new(),
            sc_wide: None,
            sc_this_class: HashMap::new(),
            sc_collected: HashMap::new(),
        }
    }

    /// fid and the functions around it (memoized).
    pub fn scope_fns(&mut self, fid: FnId) -> Rc<BTreeSet<FnId>> {
        if let Some(got) = self.anc.get(&fid) {
            return got.clone();
        }
        let mut out = BTreeSet::new();
        let mut f = fid;
        loop {
            out.insert(f);
            match self.fns[f as usize].parent {
                Some(p) => f = p,
                None => break,
            }
        }
        let got = Rc::new(out);
        self.anc.insert(fid, got.clone());
        got
    }

    fn new_scope(&mut self, kind: ScopeKind, parent: Option<ScopeId>, fid: FnId) -> ScopeId {
        let id = self.scopes.len() as ScopeId;
        self.scopes.push(Scope { kind, parent, names: HashMap::new(), fid });
        id
    }

    pub fn var_scope(&self, mut s: ScopeId) -> ScopeId {
        while self.scopes[s as usize].kind != ScopeKind::Function {
            s = self.scopes[s as usize].parent.expect("a block scope has a parent");
        }
        s
    }

    pub fn mod_scope(&self, mut s: ScopeId) -> ScopeId {
        while let Some(p) = self.scopes[s as usize].parent {
            s = p;
        }
        s
    }

    pub fn lookup(&self, scope: ScopeId, name: &[u32]) -> Option<BindId> {
        let mut s = Some(scope);
        while let Some(id) = s {
            let sc = &self.scopes[id as usize];
            if let Some(&b) = sc.names.get(name) {
                return Some(b);
            }
            s = sc.parent;
        }
        None
    }

    // ---- indexing ----
    pub fn add_module(&mut self, path: &[u32], tree: Tree, file: u32) -> ModId {
        let norm0: PyStr = path.iter().map(|&c| if c == 0x5C { 0x2F } else { c }).collect();
        let norm = join(&[], &norm0).unwrap_or(norm0);
        let idx = self.mods.len() as ModId;
        let dir = match norm.iter().rposition(|&c| c == 0x2F) {
            Some(k) => norm[..k].to_vec(),
            None => Vec::new(),
        };
        let n = tree.nodes.len();
        let fid = self.fns.len() as FnId;
        let scope = self.new_scope(ScopeKind::Function, None, fid);
        self.fns.push(Func {
            fid,
            module: idx,
            node: tree.root,
            name: None,
            params: Vec::new(),
            scope,
            parent: None,
            line: 1,
            cls: None,
            obj: None,
            is_module: true,
            route: 0,
            reach: BTreeMap::new(),
            reach_member: BTreeMap::new(),
            ret_params: BTreeMap::new(),
            ret_src: None,
            ret_outer: BTreeMap::new(),
            param_writes: BTreeMap::new(),
            param_files: BTreeMap::new(),
            callers: BTreeMap::new(),
            runs: 0,
            calls: Vec::new(),
            size: 0,
        });
        let root = tree.root;
        self.mods.push(Mod {
            idx,
            path: path.to_vec(),
            file,
            dir,
            tree,
            scope,
            fn_: fid,
            named: HashMap::new(),
            stars: Vec::new(),
            cjs: Vec::new(),
            cjs_props: HashMap::new(),
            eval_with: false,
            regexp_proto: false,
            regexp_rebound: false,
            nodes: 0,
            scope_at: vec![NONE; n],
            fid_at: vec![NONE; n],
            cid_at: vec![NONE; n],
            oid_at: vec![NONE; n],
            bind_at: vec![UNSET; n],
            asg: vec![false; n],
            text_memo: HashMap::new(),
        });
        self.by_path.entry(norm).or_insert(idx);
        if root != NONE {
            self.mods[idx as usize].scope_at[root as usize] = scope;
            self.declare(idx, root, scope, fid);
        }
        self.nodes += self.mods[idx as usize].nodes;
        idx
    }

    fn new_bind(&mut self, name: &[u32], kind: BindKind, scope: ScopeId, module: ModId) -> BindId {
        let bid = self.binds.len() as BindId;
        let fid = self.scopes[scope as usize].fid;
        self.binds.push(Bind {
            bid,
            name: name.to_vec(),
            kind,
            fid,
            writes: Vec::new(),
            shared: false,
            module,
            refs: Vec::new(),
            targets: None,
        });
        self.scopes[scope as usize].names.insert(name.to_vec(), bid);
        bid
    }

    /// Scopes and bindings: every name declared under `root` (a Program),
    /// and the functions, classes and object literals in it.
    fn declare(&mut self, m: ModId, root: NodeId, root_scope: ScopeId, root_fn: FnId) {
        use jt::{A, B, C, D};
        // (node, scope, the function whose code it is, name hint)
        let mut stack: Vec<(NodeId, ScopeId, FnId, Hint)> = Vec::new();
        {
            let a = Ast(&self.mods[m as usize].tree);
            for &st in a.list(root, A).iter().rev() {
                stack.push((st, root_scope, root_fn, Hint::None));
            }
        }
        self.mods[m as usize].nodes += 1;
        self.fns[root_fn as usize].size += 1;
        while let Some((node, scope, fn_, hint)) = stack.pop() {
            self.mods[m as usize].nodes += 1;
            self.fns[fn_ as usize].size += 1;
            let t = self.mods[m as usize].tree.nodes[node as usize].kind;
            if matches!(t, Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression) {
                let inner = self.new_function(m, node, scope, fn_, &hint);
                let fscope = self.fns[inner as usize].scope;
                self.mods[m as usize].scope_at[node as usize] = fscope;
                let (id, params, body) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.opt(node, A), a.list(node, B).to_vec(), a.at(node, C))
                };
                if t == Kind::FunctionExpression {
                    if let Some(id) = id {
                        let name = self.mods[m as usize].tree.str(self.mods[m as usize].tree.nodes[id as usize].f[A as usize]).to_vec();
                        let fb = self.new_bind(&name, BindKind::Function, fscope, m);
                        self.binds[fb as usize].writes.push(Write::Fn { node, scope: fscope, fid: inner });
                    }
                }
                for (i, &p) in params.iter().enumerate() {
                    let names = Ast(&self.mods[m as usize].tree).pattern_names(p);
                    for (ident, _) in names {
                        let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                        let b = self.new_bind(&name, BindKind::Param, fscope, m);
                        self.binds[b as usize].writes.push(Write::Param { node: p, scope: fscope, index: i });
                    }
                }
                if self.mods[m as usize].tree.nodes[body as usize].kind == Kind::BlockStatement {
                    self.mods[m as usize].scope_at[body as usize] = fscope;
                    let sts = Ast(&self.mods[m as usize].tree).list(body, A).to_vec();
                    for &st in sts.iter().rev() {
                        stack.push((st, fscope, inner, Hint::None));
                    }
                } else {
                    stack.push((body, fscope, inner, Hint::None));
                }
                for &p in params.iter().rev() {
                    self.push_pattern_parts(m, p, fscope, inner, &mut stack);
                }
                if t == Kind::FunctionDeclaration {
                    if let Some(id) = id {
                        let name = Ast(&self.mods[m as usize].tree).name(id).to_vec();
                        let b = match self.scopes[scope as usize].names.get(&name) {
                            Some(&b) if matches!(self.binds[b as usize].kind, BindKind::Var | BindKind::Function) => b,
                            _ => self.new_bind(&name, BindKind::Function, scope, m),
                        };
                        self.binds[b as usize].writes.push(Write::Fn { node, scope, fid: inner });
                    }
                }
                continue;
            }
            if matches!(t, Kind::ClassDeclaration | Kind::ClassExpression) {
                let c = self.new_class(m, node, &hint);
                let cscope = self.new_scope(ScopeKind::Block, Some(scope), fn_);
                self.mods[m as usize].scope_at[node as usize] = cscope;
                let (id, sup, body, decorators) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    let d = if a.at(node, D) != NONE { a.list(node, D).to_vec() } else { Vec::new() };
                    (a.opt(node, A), a.opt(node, B), a.at(node, C), d)
                };
                if let Some(id) = id {
                    let name = Ast(&self.mods[m as usize].tree).name(id).to_vec();
                    let target = if t == Kind::ClassDeclaration { scope } else { cscope };
                    let b = self.new_bind(&name, BindKind::Class, target, m);
                    self.binds[b as usize].writes.push(Write::Class { node, scope, cid: c });
                }
                let members = Ast(&self.mods[m as usize].tree).list(body, A).to_vec();
                for &member in members.iter().rev() {
                    let a = Ast(&self.mods[m as usize].tree);
                    let mt = a.kind(member);
                    if mt == Kind::StaticBlock {
                        let sts = a.list(member, A).to_vec();
                        let sscope = self.new_scope(ScopeKind::Function, Some(cscope), fn_);
                        self.mods[m as usize].scope_at[member as usize] = sscope;
                        for &st in sts.iter().rev() {
                            stack.push((st, sscope, fn_, Hint::None));
                        }
                        continue;
                    }
                    let name = a.key_name(member);
                    let v = a.opt(member, B);
                    let computed = a.computed(member);
                    let key = a.at(member, A);
                    let is_static = a.flag(member, jt::STATIC);
                    let mdecos = if a.at(member, D) != NONE { a.list(member, D).to_vec() } else { Vec::new() };
                    if let Some(v) = v {
                        if mt == Kind::MethodDefinition {
                            let kind = a.op(member);
                            stack.push((v, cscope, fn_, Hint::Method { cid: c, name: name.clone(), is_static, kind }));
                        } else if a.is_function(v) {
                            stack.push((v, cscope, fn_, Hint::Method { cid: c, name: name.clone(), is_static, kind: jt::M_METHOD }));
                        } else {
                            stack.push((v, cscope, fn_, Hint::None));
                        }
                    }
                    if computed {
                        stack.push((key, scope, fn_, Hint::None));
                    }
                    for &d in mdecos.iter().rev() {
                        stack.push((d, scope, fn_, Hint::None));
                    }
                }
                if let Some(sup) = sup {
                    self.classes[c as usize].sup = Some((m, sup, scope));
                    stack.push((sup, scope, fn_, Hint::None));
                }
                for &d in decorators.iter().rev() {
                    stack.push((d, scope, fn_, Hint::None));
                }
                continue;
            }
            if t == Kind::ObjectExpression {
                let o = self.new_object(m, node);
                let props = Ast(&self.mods[m as usize].tree).list(node, A).to_vec();
                for &prop in props.iter().rev() {
                    let a = Ast(&self.mods[m as usize].tree);
                    if a.kind(prop) == Kind::SpreadElement {
                        stack.push((a.at(prop, A), scope, fn_, Hint::None));
                        continue;
                    }
                    let name = a.key_name(prop);
                    let v = a.at(prop, B);
                    let is_fn = a.is_function(v);
                    let computed = a.computed(prop);
                    let key = a.at(prop, A);
                    if let Some(name) = &name {
                        self.objs[o as usize].props.entry(name.clone()).or_default().insert(0, (v, scope));
                    }
                    stack.push((v, scope, fn_, if is_fn { Hint::ObjProp { oid: o, name: name.clone() } } else { Hint::None }));
                    if computed {
                        stack.push((key, scope, fn_, Hint::None));
                    }
                }
                continue;
            }
            if t == Kind::VariableDeclaration {
                let (op, decls) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.op(node), a.list(node, A).to_vec())
                };
                let kind = BindKind::of_var(op);
                let target = if kind == BindKind::Var { self.var_scope(scope) } else { scope };
                for &d in &decls {
                    let (id, init) = {
                        let a = Ast(&self.mods[m as usize].tree);
                        (a.at(d, A), a.opt(d, B))
                    };
                    let names = Ast(&self.mods[m as usize].tree).pattern_names(id);
                    for (ident, path) in names {
                        let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                        let existing = if kind == BindKind::Var { self.scopes[target as usize].names.get(&name).copied() } else { None };
                        let b = match existing {
                            Some(b) if matches!(self.binds[b as usize].kind, BindKind::Var | BindKind::Function | BindKind::Param) => b,
                            _ => self.new_bind(&name, kind, target, m),
                        };
                        match init {
                            Some(init) => self.binds[b as usize].writes.push(Write::Init { node: init, scope, path }),
                            None if kind != BindKind::Var => self.binds[b as usize].writes.push(Write::Nothing { scope }),
                            None => {}
                        }
                    }
                }
                for &d in decls.iter().rev() {
                    let (id, init) = {
                        let a = Ast(&self.mods[m as usize].tree);
                        (a.at(d, A), a.opt(d, B))
                    };
                    if let Some(init) = init {
                        let a = Ast(&self.mods[m as usize].tree);
                        let it = a.kind(init);
                        let hint2 = if a.is_ident(id) && (a.is_function(init) || it == Kind::ClassExpression) {
                            Hint::Var(Some(a.name(id).to_vec()))
                        } else {
                            Hint::None
                        };
                        stack.push((init, scope, fn_, hint2));
                    }
                    self.push_pattern_parts(m, id, scope, fn_, &mut stack);
                }
                continue;
            }
            if t == Kind::BlockStatement {
                let bscope = self.new_scope(ScopeKind::Block, Some(scope), fn_);
                self.mods[m as usize].scope_at[node as usize] = bscope;
                let sts = Ast(&self.mods[m as usize].tree).list(node, A).to_vec();
                for &st in sts.iter().rev() {
                    stack.push((st, bscope, fn_, Hint::None));
                }
                continue;
            }
            if matches!(t, Kind::ForStatement | Kind::ForInStatement | Kind::ForOfStatement | Kind::SwitchStatement) {
                let lscope = self.new_scope(ScopeKind::Block, Some(scope), fn_);
                self.mods[m as usize].scope_at[node as usize] = lscope;
                let kids = Ast(&self.mods[m as usize].tree).kids(node);
                for &k in kids.iter().rev() {
                    stack.push((k, lscope, fn_, Hint::None));
                }
                continue;
            }
            if t == Kind::CatchClause {
                let cscope = self.new_scope(ScopeKind::Block, Some(scope), fn_);
                self.mods[m as usize].scope_at[node as usize] = cscope;
                let (param, body) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.opt(node, A), a.at(node, B))
                };
                if let Some(param) = param {
                    let names = Ast(&self.mods[m as usize].tree).pattern_names(param);
                    for (ident, _) in names {
                        let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                        let b = self.new_bind(&name, BindKind::Catch, cscope, m);
                        self.binds[b as usize].writes.push(Write::Nothing { scope: cscope });
                    }
                    self.push_pattern_parts(m, param, cscope, fn_, &mut stack);
                }
                self.mods[m as usize].scope_at[body as usize] = cscope;
                let sts = Ast(&self.mods[m as usize].tree).list(body, A).to_vec();
                for &st in sts.iter().rev() {
                    stack.push((st, cscope, fn_, Hint::None));
                }
                continue;
            }
            if t == Kind::ImportDeclaration {
                let (specs, src) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.list(node, A).to_vec(), a.str_value(a.at(node, B)).map(|v| v.to_vec()).unwrap_or_default())
                };
                let ms = self.mod_scope(scope);
                for spec in specs {
                    let (name, local) = {
                        let a = Ast(&self.mods[m as usize].tree);
                        match a.kind(spec) {
                            Kind::ImportDefaultSpecifier => (u("default"), a.name(a.at(spec, A)).to_vec()),
                            Kind::ImportNamespaceSpecifier => (u("*"), a.name(a.at(spec, A)).to_vec()),
                            _ => {
                                let imp = a.at(spec, A);
                                let n = if a.is_ident(imp) { a.name(imp).to_vec() } else { a.str_value(imp).unwrap_or(&[]).to_vec() };
                                (n, a.name(a.at(spec, B)).to_vec())
                            }
                        }
                    };
                    let b = self.new_bind(&local, BindKind::Import, ms, m);
                    self.binds[b as usize].writes.push(Write::Import { spec: src.clone(), scope, name });
                }
                continue;
            }
            if t == Kind::TSImportEquals {
                let (id, module, entity) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.at(node, A), a.opt(node, B), a.opt(node, C))
                };
                let name = Ast(&self.mods[m as usize].tree).name(id).to_vec();
                let b = self.new_bind(&name, BindKind::Import, scope, m);
                match module {
                    Some(md) => {
                        let spec = Ast(&self.mods[m as usize].tree).str_value(md).unwrap_or(&[]).to_vec();
                        self.binds[b as usize].writes.push(Write::Import { spec, scope, name: u("=") });
                    }
                    None => {
                        if let Some(entity) = entity {
                            self.binds[b as usize].writes.push(Write::Init { node: entity, scope, path: Vec::new() });
                        }
                    }
                }
                continue;
            }
            if matches!(t, Kind::TSEnumDeclaration | Kind::TSModuleDeclaration) {
                let (name, kids) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    let id = a.at(node, A);
                    (if a.is_ident(id) { Some((a.name(id).to_vec(), id)) } else { None }, a.kids(node))
                };
                if let Some((name, _)) = name {
                    if !self.scopes[scope as usize].names.contains_key(&name) {
                        let b = self.new_bind(&name, BindKind::Enum, scope, m);
                        self.binds[b as usize].writes.push(Write::Nothing { scope });
                    }
                }
                for &k in kids.iter().rev() {
                    stack.push((k, scope, fn_, Hint::None));
                }
                continue;
            }
            if t == Kind::WithStatement {
                self.mods[m as usize].eval_with = true;
            } else if t == Kind::AssignmentExpression {
                let (left, right) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.at(node, A), a.at(node, B))
                };
                let a = Ast(&self.mods[m as usize].tree);
                let mut hint2 = Hint::None;
                if a.is_function(right) || a.kind(right) == Kind::ClassExpression {
                    if a.is_ident(left) {
                        hint2 = Hint::Var(Some(a.name(left).to_vec()));
                    } else if a.kind(left) == Kind::MemberExpression {
                        hint2 = Hint::Var(a.prop_name(left));
                    }
                }
                stack.push((right, scope, fn_, hint2));
                stack.push((left, scope, fn_, Hint::None));
                continue;
            } else if t == Kind::ExportDefaultDeclaration {
                let d = Ast(&self.mods[m as usize].tree).at(node, A);
                stack.push((d, scope, fn_, Hint::None));
                continue;
            }
            let kids = Ast(&self.mods[m as usize].tree).kids(node);
            for &k in kids.iter().rev() {
                stack.push((k, scope, fn_, Hint::None));
            }
        }
    }

    /// A pattern's default values and computed keys, read in scope.
    fn push_pattern_parts(&self, m: ModId, pat: NodeId, scope: ScopeId, fn_: FnId, stack: &mut Vec<(NodeId, ScopeId, FnId, Hint)>) {
        use jt::{A, B};
        let a = Ast(&self.mods[m as usize].tree);
        let mut todo = vec![pat];
        while let Some(p) = todo.pop() {
            if p == NONE {
                continue;
            }
            match a.kind(p) {
                Kind::AssignmentPattern => {
                    let (left, right) = (a.at(p, A), a.at(p, B));
                    let hint = if a.is_ident(left) && a.is_function(right) { Hint::Var(Some(a.name(left).to_vec())) } else { Hint::None };
                    stack.push((right, scope, fn_, hint));
                    todo.push(left);
                }
                Kind::ObjectPattern => {
                    for &prop in a.list(p, A) {
                        if a.kind(prop) == Kind::RestElement {
                            todo.push(a.at(prop, A));
                        } else {
                            if a.computed(prop) {
                                stack.push((a.at(prop, A), scope, fn_, Hint::None));
                            }
                            todo.push(a.at(prop, B));
                        }
                    }
                }
                Kind::ArrayPattern => todo.extend(a.list(p, A).iter().copied()),
                Kind::RestElement => todo.push(a.at(p, A)),
                Kind::MemberExpression => stack.push((p, scope, fn_, Hint::None)),
                _ => {}
            }
        }
    }

    fn new_function(&mut self, m: ModId, node: NodeId, scope: ScopeId, parent_fn: FnId, hint: &Hint) -> FnId {
        let (mut name, params, line) = {
            let a = Ast(&self.mods[m as usize].tree);
            let name = if a.kind(node) != Kind::ArrowFunctionExpression {
                a.opt(node, jt::A).map(|id| a.name(id).to_vec())
            } else {
                None
            };
            (name, a.list(node, jt::B).to_vec(), a.line(node))
        };
        let fid = self.fns.len() as FnId;
        let (mut cls, mut obj) = (None, None);
        let or = |name: &mut Option<PyStr>, alt: &Option<PyStr>| {
            if name.as_ref().map_or(true, |n| n.is_empty()) {
                if alt.is_some() {
                    *name = alt.clone();
                }
            }
        };
        match hint {
            Hint::Method { cid, name: mname, is_static, kind } => {
                or(&mut name, mname);
                if matches!(*kind, jt::M_METHOD | jt::M_CONSTRUCTOR) {
                    if let Some(mn) = mname {
                        let c = &mut self.classes[*cid as usize];
                        let table = if *is_static { &mut c.statics } else { &mut c.methods };
                        table.insert(mn.clone(), fid);
                    }
                }
                cls = Some(*cid);
            }
            Hint::ObjProp { oid, name: pname } => {
                or(&mut name, pname);
                obj = Some(*oid);
            }
            Hint::Var(v) => or(&mut name, v),
            Hint::None => {}
        }
        let fscope = self.new_scope(ScopeKind::Function, Some(scope), fid);
        self.fns.push(Func {
            fid,
            module: m,
            node,
            name: name.clone(),
            params,
            scope: fscope,
            parent: Some(parent_fn),
            line,
            cls,
            obj,
            is_module: false,
            route: 0,
            reach: BTreeMap::new(),
            reach_member: BTreeMap::new(),
            ret_params: BTreeMap::new(),
            ret_src: None,
            ret_outer: BTreeMap::new(),
            param_writes: BTreeMap::new(),
            param_files: BTreeMap::new(),
            callers: BTreeMap::new(),
            runs: 0,
            calls: Vec::new(),
            size: 0,
        });
        self.mods[m as usize].fid_at[node as usize] = fid;
        if let Some(n) = name {
            if !n.is_empty() {
                self.by_name.entry(n).or_default().push(fid);
            }
        }
        fid
    }

    fn new_class(&mut self, m: ModId, node: NodeId, hint: &Hint) -> ClassId {
        let name = {
            let a = Ast(&self.mods[m as usize].tree);
            match a.opt(node, jt::A) {
                Some(id) => Some(a.name(id).to_vec()),
                None => match hint {
                    Hint::Var(v) => v.clone(),
                    _ => None,
                },
            }
        };
        let cid = self.classes.len() as ClassId;
        self.classes.push(Class { cid, name, methods: HashMap::new(), statics: HashMap::new(), sup: None });
        self.mods[m as usize].cid_at[node as usize] = cid;
        cid
    }

    fn new_object(&mut self, m: ModId, node: NodeId) -> ObjId {
        let oid = self.objs.len() as ObjId;
        self.objs.push(Obj { oid, module: m, props: HashMap::new() });
        self.mods[m as usize].oid_at[node as usize] = oid;
        oid
    }

    // ---- references ----

    /// Every identifier resolved to its binding (`bind_at`, GLOBAL: none);
    /// the writes of assignments, the call sites of each function, the
    /// members a program assigns to (`asg`), exports, module.exports and the
    /// file's eval / with / RegExp facts.
    pub fn resolve_module(&mut self, m: ModId) {
        use jt::{A, B, C, D};
        let root = self.mods[m as usize].tree.root;
        if root == NONE {
            return;
        }
        let (mscope, mfn) = (self.mods[m as usize].scope, self.mods[m as usize].fn_);
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum F {
            Ref,
            Decl,
        }
        // (node, scope, fid, parent, field)
        let mut stack: Vec<(NodeId, ScopeId, FnId, NodeId, F)> = vec![(root, mscope, mfn, NONE, F::Ref)];
        while let Some((node, mut scope, mut fid, parent, field)) = stack.pop() {
            let t = self.mods[m as usize].tree.nodes[node as usize].kind;
            let s = self.mods[m as usize].scope_at[node as usize];
            if s != NONE {
                scope = s;
                if matches!(t, Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression) {
                    fid = self.mods[m as usize].fid_at[node as usize];
                }
            }
            if t == Kind::Identifier {
                let name = Ast(&self.mods[m as usize].tree).name(node).to_vec();
                let b = self.lookup(scope, &name);
                self.mods[m as usize].bind_at[node as usize] = b.unwrap_or(GLOBAL);
                if field == F::Ref {
                    if let Some(b) = b {
                        self.binds[b as usize].refs.push((node, parent));
                        if self.binds[b as usize].fid != fid {
                            self.binds[b as usize].shared = true;
                        }
                    }
                }
                continue;
            }
            if t == Kind::MemberExpression {
                let (obj, prop, computed, name) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.at(node, A), a.at(node, B), a.computed(node), a.prop_name(node))
                };
                {
                    let a = Ast(&self.mods[m as usize].tree);
                    if name.as_deref().is_some_and(|n| eq(n, "prototype")) && a.is_ident_named(obj, "RegExp") {
                        self.mods[m as usize].regexp_proto = true;
                    }
                    let a = Ast(&self.mods[m as usize].tree);
                    if name.as_deref().is_some_and(|n| eq(n, "RegExp"))
                        && a.is_ident(obj)
                        && is_in(&["globalThis", "window", "global", "self"], a.name(obj))
                        && self.mods[m as usize].asg[node as usize]
                    {
                        self.mods[m as usize].regexp_rebound = true;
                    }
                }
                stack.push((obj, scope, fid, node, F::Ref));
                if computed {
                    stack.push((prop, scope, fid, node, F::Ref));
                }
                continue;
            }
            match t {
                Kind::CallExpression | Kind::NewExpression | Kind::TaggedTemplateExpression => {
                    let a = Ast(&self.mods[m as usize].tree);
                    let callee = a.at(node, A);
                    if t == Kind::CallExpression && a.is_ident_named(callee, "eval") {
                        self.mods[m as usize].eval_with = true;
                    }
                    self.fns[fid as usize].calls.push((node, scope));
                }
                Kind::AssignmentExpression => self.record_assignment(m, node, scope, fid),
                Kind::UpdateExpression | Kind::UnaryExpression => {
                    let a = Ast(&self.mods[m as usize].tree);
                    if t == Kind::UpdateExpression || a.operator(node) == "delete" {
                        let arg = a.at(node, A);
                        if a.kind(arg) == Kind::MemberExpression {
                            self.mods[m as usize].asg[arg as usize] = true;
                        } else if t == Kind::UpdateExpression && a.is_ident(arg) {
                            let name = a.name(arg).to_vec();
                            if let Some(b) = self.lookup(scope, &name) {
                                self.binds[b as usize].writes.push(Write::Opaque { node, scope });
                                if self.binds[b as usize].fid != fid {
                                    self.binds[b as usize].shared = true;
                                }
                            }
                        }
                    }
                }
                Kind::ExportNamedDeclaration => self.record_export(m, node, scope),
                Kind::ExportDefaultDeclaration => {
                    let d = Ast(&self.mods[m as usize].tree).at(node, A);
                    self.mods[m as usize].named.entry(u("default")).or_default().push(Export::Expr { node: d, scope });
                }
                Kind::ExportAllDeclaration => {
                    let a = Ast(&self.mods[m as usize].tree);
                    let src = a.str_value(a.at(node, B)).unwrap_or(&[]).to_vec();
                    match a.opt(node, A) {
                        None => self.mods[m as usize].stars.push(src),
                        Some(ex) => {
                            let name = if a.is_ident(ex) { a.name(ex).to_vec() } else { a.str_value(ex).unwrap_or(&[]).to_vec() };
                            self.mods[m as usize].named.entry(name).or_default().push(Export::Namespace { spec: src });
                        }
                    }
                }
                Kind::TSExportAssignment => {
                    let e = Ast(&self.mods[m as usize].tree).at(node, A);
                    self.mods[m as usize].cjs.push((e, scope));
                }
                Kind::ForInStatement | Kind::ForOfStatement => {
                    let left = Ast(&self.mods[m as usize].tree).at(node, A);
                    if Ast(&self.mods[m as usize].tree).kind(left) == Kind::VariableDeclaration {
                        let decls = Ast(&self.mods[m as usize].tree).list(left, A).to_vec();
                        for d in decls {
                            let id = Ast(&self.mods[m as usize].tree).at(d, A);
                            let names = Ast(&self.mods[m as usize].tree).pattern_names(id);
                            for (ident, _) in names {
                                let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                                if let Some(b) = self.lookup(scope, &name) {
                                    self.binds[b as usize].writes.push(Write::Opaque { node, scope });
                                }
                            }
                        }
                    } else {
                        let members = Ast(&self.mods[m as usize].tree).pattern_members(left);
                        for mem in members {
                            self.mods[m as usize].asg[mem as usize] = true;
                        }
                        let names = Ast(&self.mods[m as usize].tree).pattern_names(left);
                        for (ident, _) in names {
                            let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                            if let Some(b) = self.lookup(scope, &name) {
                                self.binds[b as usize].writes.push(Write::Opaque { node, scope });
                                if self.binds[b as usize].fid != fid {
                                    self.binds[b as usize].shared = true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            // children: references and declared names
            let a = Ast(&self.mods[m as usize].tree);
            match t {
                Kind::Property => {
                    if a.computed(node) {
                        stack.push((a.at(node, A), scope, fid, node, F::Ref));
                    }
                    let in_pattern = parent != NONE && a.kind(parent) == Kind::ObjectPattern;
                    stack.push((a.at(node, B), scope, fid, node, if in_pattern { field } else { F::Ref }));
                    continue;
                }
                Kind::MethodDefinition | Kind::PropertyDefinition => {
                    if let Some(v) = a.opt(node, B) {
                        stack.push((v, scope, fid, node, F::Ref));
                    }
                    let outer = self.scopes[scope as usize].parent.unwrap_or(scope);
                    if a.computed(node) {
                        stack.push((a.at(node, A), outer, fid, node, F::Ref));
                    }
                    if a.at(node, D) != NONE {
                        for &d in a.list(node, D).iter().rev() {
                            stack.push((d, outer, fid, node, F::Ref));
                        }
                    }
                    continue;
                }
                Kind::LabeledStatement => {
                    stack.push((a.at(node, B), scope, fid, node, F::Ref));
                    continue;
                }
                Kind::ExportSpecifier | Kind::ImportDeclaration | Kind::ExportAllDeclaration | Kind::TSImportEquals
                | Kind::MetaProperty => {
                    if t == Kind::TSImportEquals {
                        if let Some(e) = a.opt(node, C) {
                            stack.push((e, scope, fid, node, F::Ref));
                        }
                    }
                    continue;
                }
                Kind::ExportNamedDeclaration => {
                    if let Some(d) = a.opt(node, A) {
                        stack.push((d, scope, fid, node, F::Ref));
                    }
                    continue;
                }
                Kind::ClassDeclaration | Kind::ClassExpression => {
                    // the class's own scope holds its name (expressions)
                    let outer = self.scopes[scope as usize].parent.unwrap_or(scope);
                    let body = a.at(node, C);
                    for &member in a.list(body, A).iter().rev() {
                        if a.kind(member) == Kind::StaticBlock {
                            let sscope = self.mods[m as usize].scope_at[member as usize];
                            for &st in a.list(member, A).iter().rev() {
                                stack.push((st, sscope, fid, member, F::Ref));
                            }
                        } else {
                            stack.push((member, scope, fid, node, F::Ref));
                        }
                    }
                    if let Some(sup) = a.opt(node, B) {
                        stack.push((sup, outer, fid, node, F::Ref));
                    }
                    if a.at(node, D) != NONE {
                        for &d in a.list(node, D).iter().rev() {
                            stack.push((d, outer, fid, node, F::Ref));
                        }
                    }
                    continue;
                }
                Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression => {
                    stack.push((a.at(node, C), scope, fid, node, F::Ref));
                    for &p in a.list(node, B).iter().rev() {
                        stack.push((p, scope, fid, node, F::Decl));
                    }
                    continue;
                }
                Kind::VariableDeclarator => {
                    if let Some(init) = a.opt(node, B) {
                        stack.push((init, scope, fid, node, F::Ref));
                    }
                    stack.push((a.at(node, A), scope, fid, node, F::Decl));
                    continue;
                }
                Kind::ObjectPattern | Kind::ArrayPattern | Kind::RestElement | Kind::AssignmentPattern => {
                    let kids = a.kids(node);
                    let right = if t == Kind::AssignmentPattern { a.at(node, B) } else { NONE };
                    for &k in kids.iter().rev() {
                        let kf = if t == Kind::AssignmentPattern && k == right { F::Ref } else { field };
                        stack.push((k, scope, fid, node, kf));
                    }
                    continue;
                }
                Kind::CatchClause => {
                    stack.push((a.at(node, B), scope, fid, node, F::Ref));
                    if let Some(p) = a.opt(node, A) {
                        stack.push((p, scope, fid, node, F::Decl));
                    }
                    continue;
                }
                Kind::JSXOpeningElement | Kind::JSXClosingElement => {
                    if t == Kind::JSXOpeningElement {
                        for &at in a.list(node, B).iter().rev() {
                            stack.push((at, scope, fid, node, F::Ref));
                        }
                    }
                    continue;
                }
                Kind::JSXAttribute => {
                    if let Some(v) = a.opt(node, B) {
                        stack.push((v, scope, fid, node, F::Ref));
                    }
                    continue;
                }
                _ => {}
            }
            for &k in a.kids(node).iter().rev() {
                stack.push((k, scope, fid, node, F::Ref));
            }
        }
    }

    fn record_assignment(&mut self, m: ModId, node: NodeId, scope: ScopeId, fid: FnId) {
        use jt::{A, B};
        let (left, right, op_eq) = {
            let a = Ast(&self.mods[m as usize].tree);
            (a.at(node, A), a.at(node, B), a.operator(node) == "=")
        };
        let lk = Ast(&self.mods[m as usize].tree).kind(left);
        if lk == Kind::Identifier {
            let name = Ast(&self.mods[m as usize].tree).name(left).to_vec();
            match self.lookup(scope, &name) {
                Some(b) => {
                    let w = if op_eq {
                        Write::Assign { node: right, scope, path: Vec::new() }
                    } else {
                        Write::Opaque { node: right, scope }
                    };
                    self.binds[b as usize].writes.push(w);
                    if self.binds[b as usize].fid != fid {
                        self.binds[b as usize].shared = true;
                    }
                }
                None => {
                    if eq(&name, "RegExp") {
                        self.mods[m as usize].regexp_rebound = true;
                    }
                }
            }
            return;
        }
        if lk == Kind::ObjectPattern || lk == Kind::ArrayPattern {
            let members = Ast(&self.mods[m as usize].tree).pattern_members(left);
            for mem in members {
                self.mods[m as usize].asg[mem as usize] = true;
            }
            let names = Ast(&self.mods[m as usize].tree).pattern_names(left);
            for (ident, path) in names {
                let name = Ast(&self.mods[m as usize].tree).name(ident).to_vec();
                match self.lookup(scope, &name) {
                    Some(b) => {
                        self.binds[b as usize].writes.push(Write::Assign { node: right, scope, path });
                        if self.binds[b as usize].fid != fid {
                            self.binds[b as usize].shared = true;
                        }
                    }
                    None => {
                        if eq(&name, "RegExp") {
                            self.mods[m as usize].regexp_rebound = true;
                        }
                    }
                }
            }
            return;
        }
        if lk != Kind::MemberExpression {
            return;
        }
        self.mods[m as usize].asg[left as usize] = true;
        let (name, obj) = {
            let a = Ast(&self.mods[m as usize].tree);
            (a.prop_name(left), a.at(left, A))
        };
        let a = Ast(&self.mods[m as usize].tree);
        let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
        if named("RegExp") && a.is_ident(obj) && is_in(&["globalThis", "window", "global", "self"], a.name(obj)) {
            self.mods[m as usize].regexp_rebound = true;
        }
        let a = Ast(&self.mods[m as usize].tree);
        // module.exports = … / module.exports.x = … / exports.x = …
        if a.is_ident_named(obj, "module") && named("exports") && self.lookup(scope, &u("module")).is_none() {
            self.mods[m as usize].cjs.push((right, scope));
            return;
        }
        if let Some(name) = &name {
            if a.is_ident_named(obj, "exports") && self.lookup(scope, &u("exports")).is_none() {
                self.mods[m as usize].cjs_props.entry(name.clone()).or_default().push((right, scope));
                return;
            }
            if a.kind(obj) == Kind::MemberExpression
                && !a.computed(obj)
                && a.prop_name(obj).as_deref().is_some_and(|x| eq(x, "exports"))
                && a.is_ident_named(a.at(obj, A), "module")
                && self.lookup(scope, &u("module")).is_none()
            {
                self.mods[m as usize].cjs_props.entry(name.clone()).or_default().push((right, scope));
            }
        }
    }

    fn record_export(&mut self, m: ModId, node: NodeId, scope: ScopeId) {
        use jt::{A, B, C};
        let a = Ast(&self.mods[m as usize].tree);
        if let Some(decl) = a.opt(node, A) {
            let mut names: Vec<PyStr> = Vec::new();
            if a.kind(decl) == Kind::VariableDeclaration {
                for &d in a.list(decl, A) {
                    for (ident, _) in a.pattern_names(a.at(d, A)) {
                        names.push(a.name(ident).to_vec());
                    }
                }
            } else {
                // (a function, a class, an enum, a namespace: its id)
                let has_id = matches!(
                    a.kind(decl),
                    Kind::FunctionDeclaration
                        | Kind::FunctionExpression
                        | Kind::ClassDeclaration
                        | Kind::ClassExpression
                        | Kind::TSEnumDeclaration
                        | Kind::TSModuleDeclaration
                        | Kind::TSImportEquals
                );
                if has_id {
                    if let Some(id) = a.opt(decl, A) {
                        if a.is_ident(id) {
                            names.push(a.name(id).to_vec());
                        }
                    }
                }
            }
            for n in names {
                self.mods[m as usize].named.entry(n.clone()).or_default().push(Export::Binding { name: n, scope });
            }
            return;
        }
        let src = a.opt(node, C).map(|s| a.str_value(s).unwrap_or(&[]).to_vec());
        let specs = a.list(node, B).to_vec();
        for spec in specs {
            let a = Ast(&self.mods[m as usize].tree);
            let (local, exported) = (a.at(spec, A), a.at(spec, B));
            let lname = if a.is_ident(local) { a.name(local).to_vec() } else { a.str_value(local).unwrap_or(&[]).to_vec() };
            let ename = if a.is_ident(exported) { a.name(exported).to_vec() } else { a.str_value(exported).unwrap_or(&[]).to_vec() };
            let entry = match &src {
                Some(s) => Export::Reexport { spec: s.clone(), name: lname },
                None => Export::Binding { name: lname, scope },
            };
            self.mods[m as usize].named.entry(ename).or_default().push(entry);
        }
    }

    // ---- modules ----

    /// A module specifier from module `m`.
    pub fn resolve_spec(&self, m: ModId, spec: &[u32]) -> descs::D {
        use descs::D;
        if spec.len() >= 5 && eq(&spec[..5], "node:") {
            return D::Builtin(spec[5..].to_vec());
        }
        let starts = |p: &str| spec.len() >= p.len() && eq(&spec[..p.len()], p);
        if !(starts("./") || starts("../") || eq(spec, ".") || eq(spec, "..")) {
            let head: &[u32] = spec.split(|&c| c == 0x2F).next().unwrap_or(&[]);
            if is_in(NODE_BUILTINS, head) {
                return D::Builtin(head.to_vec());
            }
            return D::Pkg(spec.to_vec());
        }
        let base = match join(&self.mods[m as usize].dir, spec) {
            Some(b) => b,
            None => return D::Pkg(spec.to_vec()),
        };
        let last_start = base.iter().rposition(|&c| c == 0x2F).map_or(0, |k| k + 1);
        let last = &base[last_start..];
        let ext: PyStr = match last.iter().rposition(|&c| c == 0x2E) {
            Some(dot) if dot > 0 => last[dot..].to_vec(),
            _ => Vec::new(),
        };
        let mut cands: Vec<PyStr> = Vec::new();
        let ext_s: String = ext.iter().map(|&c| char::from_u32(c).unwrap_or('\u{FFFD}')).collect();
        if EXTS.contains(&ext_s.as_str()) {
            cands.push(base.clone());
            for alt in ts_sources(&ext_s) {
                let mut c = base[..base.len() - ext.len()].to_vec();
                c.extend(u(alt));
                cands.push(c);
            }
        } else {
            for e in EXTS {
                let mut c = base.clone();
                c.extend(u(e));
                cands.push(c);
            }
            for e in EXTS {
                let mut c = base.clone();
                if !base.is_empty() {
                    c.push(0x2F);
                }
                c.extend(u("index"));
                c.extend(u(e));
                cands.push(c);
            }
        }
        for c in cands {
            if let Some(&idx) = self.by_path.get(&c) {
                return D::Mod(idx);
            }
        }
        D::Pkg(spec.to_vec())
    }
}

/// A function's or class's name hint, from where it is defined.
#[derive(Clone, Debug)]
enum Hint {
    None,
    /// a class member: its class, name, whether static, its kind (jt::M_*)
    Method { cid: ClassId, name: Option<PyStr>, is_static: bool, kind: u8 },
    /// an object literal's property
    ObjProp { oid: ObjId, name: Option<PyStr> },
    /// a variable's or a member's name
    Var(Option<PyStr>),
}
