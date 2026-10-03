//! Cross-file taint for Python, on the engine's Python parser's trees: a
//! port of flow.py's Python half (`_PyProject`, `_Analyzer`,
//! `_analyze_python`), function for function.
//!
//! Every function, method, nested def and each module's top-level code (a
//! pseudo-function) gets a summary — which parameters reach which sinks
//! (`param_to_sink`), which reach the return value and what they are clean
//! for there (`param_to_return`), a request source it returns
//! (`ret_source`) — computed to a fixpoint over the call graph, callees
//! first; a last pass over every function reports a source passed into a
//! function whose parameter reaches a sink, or reaching a sink as the value
//! another function returned. Calls are matched only to what they can name
//! (flow.py's resolution model): a module-level function defined in or
//! imported into the module (imports, re-exports, star imports), a nested
//! def, a class's constructor; `self.m()` and `super().m()` through the
//! class and its project bases; `C().m()`, `x.m()` with `x = C(…)`,
//! `C.m()`; an unknown receiver's method by name when at most four project
//! methods have it and it is no common library method name. Route handlers
//! (Flask, FastAPI, Django: `frameworks.rs`) get request data in the
//! parameters their framework fills. Guards (a path check, an allowlist)
//! clear a value in the branch where it passed.
//!
//! Deterministic: where flow.py iterates a set (a function's callees and
//! callers, the functions read again, a value's parameters) the port keeps
//! the order things were added in (a value's parameters: their order in
//! the function's signature), and a work budget (steps per tree node) and a
//! limit on one function's reading bound the pass where flow.py had a
//! time budget. A step is a node read; following a long chain of links (a
//! callee's or an attribute's, `dotted`) and the texts that makes are more
//! steps past FREE_WORK (`charge`), so code that would cost its length
//! squared is bounded by the budgets too. Python's recursion limit, where
//! flow.py's recursive reading and collecting stop on deeply nested code
//! (a Q-FLOW-RECURSION note), is kept as a count of the frames flow.py
//! would hold (`frames`), as from the `lazaret` command (FRAMES).

pub mod driver;
pub mod eval;
pub mod frameworks;
pub mod supply;
pub mod unparse;
#[cfg(test)]
mod tests;

pub use crate::jsflow::Out;
pub use driver::{analyze, Config};

use crate::jsflow::{bit, ALL};
use crate::pyparse::tree::{self as pt, Kind, NodeId, Tree, NONE};
use crate::pystr::{self, PyStr};
use crate::quickhash::{QuickMap, QuickSet};
use std::collections::HashMap;
use std::rc::Rc;

pub type FnId = u32;
pub type ModId = u32;
pub type ClsId = u32;
pub type NameId = u32;

/// re-analyses of one function before cutoff
pub const MAX_ITERS: u32 = 50;
/// Python files analyzed per run
pub const MAX_FILES: usize = 20_000;
/// Python source characters analyzed per run
pub const MAX_BYTES: usize = 64_000_000;
/// obj.m() with an unknown receiver: at most this many project methods
pub const MAX_DUCK: usize = 4;
pub const IMPORT_HOPS: u32 = 5;
/// The steps the summaries' fixpoint may take: WORK_BASE + WORK_PER_NODE
/// per syntax tree node; the reporting pass EMIT_PER_NODE more; one reading
/// of one function RUN_BASE + RUN_PER_NODE per node of it.
pub const WORK_BASE: u64 = 1_000_000;
pub const WORK_PER_NODE: u64 = 48;
pub const EMIT_PER_NODE: u64 = 16;
pub const RUN_BASE: u64 = 20_000;
pub const RUN_PER_NODE: u64 = 256;
/// Work a step does past its node: following a callee's or an attribute's
/// chain of links, and the texts that makes, is part of the step up to
/// FREE_WORK links and characters, then one more step for each
/// WORK_PER_STEP (only pathological code has chains that long: read at
/// every link of a chain, they would cost its length squared, which the
/// budgets now bound).
pub const FREE_WORK: u64 = 64;
pub const WORK_PER_STEP: u64 = 16;
/// The callee texts a call's classification is kept for (raw and canonical
/// together, in characters): longer ones are classified at each call.
pub const MEMO_TEXT: usize = 256;
/// The frames flow.py's recursive reading could hold before Python's
/// recursion limit (1000) stopped it, entered from the `lazaret` command:
/// so the same nesting stops both (a chain of 986 binary operators is read,
/// one of 987 is not; `bench/pyflow_frames.py` measured each construct).
pub const FRAMES: u32 = 991;

pub const SQL: u8 = 0;
pub const CMD: u8 = 1;
pub const CODE: u8 = 2;
pub const TEMPLATE: u8 = 3;
pub const PATH: u8 = 4;
pub const SSRF: u8 = 5;
pub const REDIRECT: u8 = 6;
pub const XSS: u8 = 7;

// ---------------- the model's vocabulary (flow.py's tables) ----------------

/// full sanitizers: numeric coercion, strict validation
pub const FULL_SANITIZERS: &[&str] = &["int", "float", "bool", "complex", "uuid.UUID", "UUID", "ipaddress.ip_address", "ip_address"];
/// partial sanitizers: the categories each clears
pub const PARTIAL_SANITIZERS: &[(&str, u8)] = &[
    ("shlex.quote", bit(CMD)),
    ("pipes.quote", bit(CMD)),
    ("html.escape", bit(XSS)),
    ("cgi.escape", bit(XSS)),
    ("markupsafe.escape", bit(XSS)),
    ("escape", bit(XSS)),
    ("bleach.clean", bit(XSS)),
    ("os.path.basename", bit(PATH)),
    ("basename", bit(PATH)),
    ("secure_filename", bit(PATH)),
    ("safe_join", bit(PATH)),
    ("conditional_escape", bit(XSS)),
    ("format_html", bit(XSS)),
    ("render_template", bit(XSS)),
    ("render_to_string", bit(XSS)),
    ("TemplateResponse", bit(XSS)),
    ("jsonify", bit(XSS)),
    ("url_for", bit(XSS) | bit(REDIRECT)),
    ("reverse", bit(REDIRECT)),
    ("reverse_lazy", bit(REDIRECT)),
];
/// what a call returns that is not request data though its arguments may be
pub const FULL_RESULT: &[&str] = &["get_object_or_404", "get_list_or_404", "open", "builtins.open", "io.open", "codecs.open"];
/// … and a query's result (searched in "." + the callee's text)
pub const ORM_RESULT_RE: &str = r"\.objects\.|\.query\.|\bsession\.(?:query|get|scalars?|execute)\b";
pub const SOURCE_RE: &str = concat!(
    r"\brequest\.(args|form|values|json|data|cookies|headers|files|query_string|stream|full_path",
    r"|GET|POST|COOKIES|META|FILES|body|query_params|path_params)\b",
    r"|\brequest\.(?:get_json|get_data)\b|\bsys\.argv\b|\bflask\.request\b",
    r"|\b(?:websocket|ws)\.receive_(?:text|json|bytes)\b",
);
/// A Python 2 source (flow._parse_py), matched with re.M.
pub const PY2_PRINT_RE: &str = r#"^\s*print\s+["'\w]"#;

/// dir(builtins) on Python 3.13 (flow._BUILTIN_NAMES)
pub const BUILTIN_NAMES: &[&str] = &[
    "ArithmeticError", "AssertionError", "AttributeError", "BaseException", "BaseExceptionGroup",
    "BlockingIOError", "BrokenPipeError", "BufferError", "BytesWarning", "ChildProcessError",
    "ConnectionAbortedError", "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
    "DeprecationWarning", "EOFError", "Ellipsis", "EncodingWarning", "EnvironmentError", "Exception",
    "ExceptionGroup", "False", "FileExistsError", "FileNotFoundError", "FloatingPointError", "FutureWarning",
    "GeneratorExit", "IOError", "ImportError", "ImportWarning", "IndentationError", "IndexError",
    "InterruptedError", "IsADirectoryError", "KeyError", "KeyboardInterrupt", "LookupError", "MemoryError",
    "ModuleNotFoundError", "NameError", "None", "NotADirectoryError", "NotImplemented", "NotImplementedError",
    "OSError", "OverflowError", "PendingDeprecationWarning", "PermissionError", "ProcessLookupError",
    "PythonFinalizationError", "RecursionError", "ReferenceError", "ResourceWarning", "RuntimeError",
    "RuntimeWarning", "StopAsyncIteration", "StopIteration", "SyntaxError", "SyntaxWarning", "SystemError",
    "SystemExit", "TabError", "TimeoutError", "True", "TypeError", "UnboundLocalError", "UnicodeDecodeError",
    "UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError", "UnicodeWarning", "UserWarning", "ValueError",
    "Warning", "ZeroDivisionError", "_IncompleteInputError", "__build_class__", "__debug__", "__doc__",
    "__import__", "__loader__", "__name__", "__package__", "__spec__", "abs", "aiter", "all", "anext", "any",
    "ascii", "bin", "bool", "breakpoint", "bytearray", "bytes", "callable", "chr", "classmethod", "compile",
    "complex", "copyright", "credits", "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec", "exit",
    "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash", "help", "hex", "id",
    "input", "int", "isinstance", "issubclass", "iter", "len", "license", "list", "locals", "map", "max",
    "memoryview", "min", "next", "object", "oct", "open", "ord", "pow", "print", "property", "quit", "range",
    "repr", "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
    "tuple", "type", "vars", "zip",
];

/// Method names never resolved by duck typing when the receiver is unknown.
pub const COMMON_METHODS: &str = "
get set setdefault pop popitem update keys values items copy clear append
extend insert remove index count sort reverse add discard union intersection
difference issubset issuperset open close read readline readlines write
writelines seek tell flush truncate fileno run start stop join split rsplit
strip lstrip rstrip replace format format_map encode decode lower upper title
capitalize casefold startswith endswith find rfind partition rpartition
splitlines expandtabs zfill center ljust rjust send recv sendall sendto
connect bind listen accept execute executemany fetchone fetchall fetchmany
commit rollback cursor call apply map filter reduce next iter throw match
search sub subn fullmatch findall finditer group groups groupdict compile
load loads dump dumps parse render process handle dispatch emit log debug
info warning warn error exception critical submit result cancel wait put
get_nowait put_nowait acquire release lock notify notify_all is_set
setattr getattr delattr register unregister exists makedirs mkdir unlink
delete create save merge destroy upsert get_one get_all get_by_id get_many
find find_one find_all first last bulk_create bulk_update refresh
";
/// An ORM's query builders: what they build binds its values (no SQL injection).
pub const SQL_BUILDER_FUNCS: &[&str] =
    &["select", "insert", "update", "delete", "sqlalchemy.select", "sqlalchemy.insert", "sqlalchemy.update", "sqlalchemy.delete"];
pub const SQL_BUILDER_METHODS: &[&str] = &[
    "where", "filter", "filter_by", "values", "order_by", "group_by", "having", "join", "outerjoin", "options", "limit",
    "offset", "returning", "on_conflict_do_update", "on_conflict_do_nothing", "exclude", "annotate", "select_related",
    "prefetch_related", "values_list", "distinct",
];
/// External calls whose result carries no attacker-controlled text.
pub const CLEAN_RESULT: &str = "
len bool isinstance issubclass hasattr callable id hash type ord abs round sum
any all divmod exists isfile isdir islink ismount isabs getsize getmtime
getatime getctime startswith endswith isdigit isalpha isalnum isspace
isnumeric isdecimal isidentifier islower isupper istitle isascii isprintable
count find rfind index rindex hexdigest digest compare_digest time monotonic
perf_counter
";
/// path checks and the calls that leave (guards)
pub const PATH_CHECKS: &[&str] = &["is_relative_to", "startswith"];
pub const EXIT_CALLS: &[&str] = &["abort", "flask.abort", "sys.exit", "exit"];

pub fn is_in(s: &[u32], list: &[&str]) -> bool {
    list.iter().any(|w| pystr::eq(s, w))
}

pub fn in_words(s: &[u32], words: &str) -> bool {
    words.split_whitespace().any(|w| pystr::eq(s, w))
}

fn cp(s: &str) -> PyStr {
    s.chars().map(|c| c as u32).collect()
}

/// The text after the last ".": `callee.split(".")[-1]`.
pub fn last_part(s: &[u32]) -> &[u32] {
    match s.iter().rposition(|&c| c == 0x2E) {
        Some(k) => &s[k + 1..],
        None => s,
    }
}

// ---------------- values ----------------

/// A value's parameters: indices into the analyzed function's parameter
/// names (`Func::pnames`), ascending.
pub type Params = Rc<[u16]>;

thread_local! {
    static NO_PARAMS: Params = Rc::from(Vec::<u16>::new());
}

pub fn no_params() -> Params {
    NO_PARAMS.with(|p| p.clone())
}

fn merge_params(a: &Params, b: &Params) -> Params {
    if b.is_empty() || Rc::ptr_eq(a, b) {
        return a.clone();
    }
    if a.is_empty() {
        return b.clone();
    }
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if j >= b.len() || (i < a.len() && a[i] < b[j]) {
            out.push(a[i]);
            i += 1;
        } else if i >= a.len() || b[j] < a[i] {
            out.push(b[j]);
            j += 1;
        } else {
            out.push(a[i]);
            i += 1;
            j += 1;
        }
    }
    if out.len() == a.len() {
        return a.clone();
    }
    Rc::from(out)
}

/// flow._Taint: tainted by a concrete source and/or by parameters of the
/// function being read; `clean`: the categories it is sanitized for;
/// `origin`: where the source was read (a module and line); `via`: the
/// function whose return value delivered it. A value with neither is
/// flow.py's EMPTY (clean for everything).
///
/// With the supply-chain model (`supply.rs`) the source is local data or
/// data received over the network: `sc` says which kinds the value holds
/// and which read came first (jsflow's `Sc`), and `marks` what the value is
/// (a connection, an HTTP client, os.environ itself: `supply::OBJ_*`).
/// Project mode never sets them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taint {
    pub source: bool,
    pub params: Params,
    pub clean: u8,
    pub origin: Option<(ModId, u32)>,
    pub via: Option<FnId>,
    pub sc: Option<Rc<crate::jsflow::Sc>>,
    pub marks: u8,
}

impl Taint {
    pub fn empty() -> Taint {
        Taint { source: false, params: no_params(), clean: ALL, origin: None, via: None, sc: None, marks: 0 }
    }

    /// A value read from function parameter `k` (its index in pnames).
    pub fn param(k: u16) -> Taint {
        Taint { source: false, params: Rc::from(vec![k]), clean: 0, origin: None, via: None, sc: None, marks: 0 }
    }

    /// Request data (or, with the supply-chain model, local data) read at `origin`.
    pub fn src(clean: u8, origin: Option<(ModId, u32)>, via: Option<FnId>) -> Taint {
        Taint { source: true, params: no_params(), clean, origin, via, sc: None, marks: 0 }
    }

    pub fn tainted(&self) -> bool {
        self.source || !self.params.is_empty()
    }

    /// Concatenation: safe for a category only where both parts are.
    pub fn union(&self, other: &Taint) -> Taint {
        if !other.tainted() && other.marks & !self.marks == 0 {
            return self.clone();
        }
        if !self.tainted() && self.marks & !other.marks == 0 {
            return other.clone();
        }
        let src = if self.source { self } else { other };
        let source = self.source || other.source;
        Taint {
            source,
            params: merge_params(&self.params, &other.params),
            clean: if !other.tainted() {
                self.clean
            } else if !self.tainted() {
                other.clean
            } else {
                self.clean & other.clean
            },
            origin: if source { src.origin } else { None },
            via: if source { src.via } else { None },
            sc: crate::jsflow::sc_union(&self.sc, &other.sc),
            marks: self.marks | other.marks,
        }
    }

    pub fn sanitize(&self, cats: u8) -> Taint {
        if !self.tainted() {
            return Taint::empty();
        }
        Taint { clean: self.clean | cats, ..self.clone() }
    }

    /// The value without what it is (`marks`, but `supply::FETCHED`, which
    /// says what its parameters are): what a call it is given to makes of it.
    pub fn plain(&self) -> Taint {
        if self.marks & !supply::FETCHED == 0 {
            return self.clone();
        }
        if !self.tainted() {
            return Taint::empty();
        }
        Taint { marks: self.marks & supply::FETCHED, ..self.clone() }
    }

    /// The value as a summary keeps it (a source, or with the supply-chain
    /// model what a value is): no parameters, its facts.
    pub fn as_source(&self) -> Taint {
        Taint {
            source: self.source,
            params: no_params(),
            clean: self.clean,
            origin: self.origin,
            via: self.via,
            sc: self.sc.clone(),
            marks: self.marks,
        }
    }
}

pub fn union_all<'a>(vals: impl IntoIterator<Item = &'a Taint>) -> Taint {
    let mut t = Taint::empty();
    for v in vals {
        t = t.union(v);
    }
    t
}

// ---------------- the model ----------------

#[derive(Clone, Debug)]
pub enum Import {
    /// `import a.b` (a's name bound: a; with `as`: a.b)
    Module(PyStr),
    /// `from base import attr` (level: leading dots)
    From { base: PyStr, attr: PyStr, level: u32 },
}

pub struct Module {
    pub idx: ModId,
    /// the index of its file in the pass's input
    pub file: u32,
    pub path: PyStr,
    pub content: PyStr,
    pub tree: Tree,
    /// the tree's string ids -> project names (NONE until asked)
    pub sid: Vec<u32>,
    pub key: PyStr,
    pub dir: PyStr,
    pub funcs: QuickMap<NameId, FnId>,
    pub classes: QuickMap<NameId, ClsId>,
    pub nested: QuickMap<NameId, Vec<FnId>>,
    pub imports: QuickMap<NameId, Import>,
    pub stars: Vec<(PyStr, u32)>,
    pub all_funcs: Vec<FnId>,
    pub globals: QuickMap<NameId, Taint>,
    pub body_fn: FnId,
    pub frameworks: Option<u8>,
    pub dep_aliases: Option<Rc<Vec<PyStr>>>,
    pub nodes: u64,
}

pub const FW_FLASK: u8 = 1;
pub const FW_FASTAPI: u8 = 2;
pub const FW_DJANGO: u8 = 4;

pub struct Class {
    pub name: NameId,
    pub module: ModId,
    pub node: NodeId,
    /// method name -> method, in the order first defined (a later def replaces the value)
    pub methods: Vec<(NameId, FnId)>,
    pub attr_taint: QuickMap<NameId, Taint>,
    pub bases: Option<Vec<ClsId>>,
    pub subclasses: Vec<ClsId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnKind {
    Function,
    Method,
    Static,
    Class,
}

/// A place a parameter reaches a sink: the function and line (written as
/// "path:line (in qual())" or "(module level)").
pub type SinkLoc = (FnId, u32);

pub struct Func {
    pub id: FnId,
    pub name: NameId,
    pub module: ModId,
    /// the FunctionDef (the Module for the pseudo-function)
    pub node: NodeId,
    pub cls: Option<ClsId>,
    pub pseudo: bool,
    pub line: u32,
    pub kind: FnKind,
    pub posonly: Vec<NameId>,
    pub args: Vec<NameId>,
    pub kwonly: Vec<NameId>,
    pub vararg: Option<NameId>,
    pub kwarg: Option<NameId>,
    pub receiver: Option<NameId>,
    /// flow.py's params (the receiver left out), in order
    pub params: Vec<NameId>,
    /// the parameters' names once each: a value's params index this
    pub pnames: Vec<NameId>,
    pub param_to_sink: Vec<(NameId, Vec<(u8, SinkLoc)>)>,
    pub param_to_return: Vec<(NameId, u8)>,
    pub ret_source: Option<Taint>,
    pub local_names: QuickSet<NameId>,
    pub types: QuickMap<NameId, ClsId>,
    pub callees: Vec<FnId>,
    pub callee_set: QuickSet<FnId>,
    pub callers: Vec<FnId>,
    pub caller_set: QuickSet<FnId>,
    pub runs: u32,
    pub request_params: Option<Rc<Vec<NameId>>>,
    pub size: u64,
    /// the function a nested def is defined in (the supply-chain model reads
    /// its variables there)
    pub parent: Option<FnId>,
}

/// What a name or an expression may be (flow.py's (kind, target)).
#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    Func(FnId),
    Class(ClsId),
    Module(ModId),
    Ext(Rc<[u32]>),
}

/// A call's resolution (flow._CallRes): (function, the first parameter
/// skipped) targets, the class it constructs, the import-canonical callee
/// text, resolved through names (not duck typing).
#[derive(Clone, Debug)]
pub struct CallRes {
    pub targets: Vec<(FnId, bool)>,
    pub ctor: Option<ClsId>,
    pub precise: bool,
    /// what its callee's texts make the call
    pub class: CallClass,
}

/// What a call is on the pass's model from its callee's texts alone (its
/// dotted text, and with an import alias at its head replaced), whether
/// its resolution is precise and whether it calls an attribute: worked out
/// when the call is resolved (`Project::class_of`), so neither text is
/// kept, and the same for every call with those (eval.rs `classify`).
#[derive(Clone, Copy, Debug)]
pub struct CallClass {
    /// 1) a source (`request.args.get(…)`, `input()`, …)
    pub source: bool,
    /// 2) a sink's category (a configured sink's first)
    pub sink: Option<u8>,
    /// 4) a configured sanitizer, then a built-in one
    pub config_san: Option<eval::San>,
    pub builtin_san: Option<eval::San>,
    /// a call whose result is clean (`get_object_or_404`, an ORM query, …)
    pub full_result: bool,
    /// an SQL query builder (its value is SQL-clean)
    pub sql_builder: bool,
    /// `len()`, `isinstance()`, `hexdigest()`, …: no text of its arguments
    pub clean_result: bool,
}

/// What a method call's receiver is (flow._PyProject._receiver).
#[derive(Clone, Debug)]
pub enum Recv {
    Instance(ClsId),
    Super(ClsId),
    ClassRef(ClsId),
    Module(Vec<ModId>),
    Ext,
}

/// Why a reading stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// Python's recursion limit (flow.py's RecursionError)
    Overflow,
    /// the reading's own limit
    Cut,
    /// the pass's budget
    Stop,
}

/// Project-wide names (identifiers), interned.
#[derive(Default)]
pub struct Names {
    map: HashMap<PyStr, NameId>,
    list: Vec<PyStr>,
}

impl Names {
    pub fn id(&mut self, s: &[u32]) -> NameId {
        if let Some(&k) = self.map.get(s) {
            return k;
        }
        let k = self.list.len() as NameId;
        self.list.push(s.to_vec());
        self.map.insert(s.to_vec(), k);
        k
    }

    pub fn find(&self, s: &[u32]) -> Option<NameId> {
        self.map.get(s).copied()
    }

    pub fn get(&self, k: NameId) -> &[u32] {
        self.list.get(k as usize).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ---------------- paths (posixpath) ----------------

pub fn basename(p: &[u32]) -> &[u32] {
    match p.iter().rposition(|&c| c == 0x2F) {
        Some(k) => &p[k + 1..],
        None => p,
    }
}

pub fn dirname(p: &[u32]) -> PyStr {
    let i = p.iter().rposition(|&c| c == 0x2F).map(|k| k + 1).unwrap_or(0);
    let head = &p[..i];
    if !head.is_empty() && head.iter().any(|&c| c != 0x2F) {
        let end = head.iter().rposition(|&c| c != 0x2F).map(|k| k + 1).unwrap_or(0);
        return head[..end].to_vec();
    }
    head.to_vec()
}

/// posixpath.join(a, *parts)
pub fn join(a: &[u32], parts: &[&[u32]]) -> PyStr {
    let mut path = a.to_vec();
    for b in parts {
        if b.first() == Some(&0x2F) {
            path = b.to_vec();
        } else if path.is_empty() || path.last() == Some(&0x2F) {
            path.extend_from_slice(b);
        } else {
            path.push(0x2F);
            path.extend_from_slice(b);
        }
    }
    path
}

fn split_on(s: &[u32], c: u32) -> Vec<&[u32]> {
    s.split(|&x| x == c).collect()
}

// ---------------- the tree ----------------

#[inline]
pub fn slot(t: &Tree, n: NodeId, s: u8) -> u32 {
    t.node(n).f[s as usize]
}

#[inline]
pub fn a_(t: &Tree, n: NodeId) -> u32 {
    slot(t, n, pt::A)
}
#[inline]
pub fn b_(t: &Tree, n: NodeId) -> u32 {
    slot(t, n, pt::B)
}
#[inline]
pub fn c_(t: &Tree, n: NodeId) -> u32 {
    slot(t, n, pt::C)
}
#[inline]
pub fn d_(t: &Tree, n: NodeId) -> u32 {
    slot(t, n, pt::D)
}

/// An item of a node's extension list.
#[inline]
pub fn ext(t: &Tree, n: NodeId, i: u8) -> u32 {
    t.raw(t.node(n), pt::At::Ext(i))
}

/// A function's or a class's decorators.
pub fn decorators(t: &Tree, n: NodeId) -> &[u32] {
    match t.kind(n) {
        Kind::FunctionDef | Kind::AsyncFunctionDef => t.list(ext(t, n, 0)),
        Kind::ClassDef => t.list(ext(t, n, 1)),
        _ => &[],
    }
}

/// A statement's body (FunctionDef, ClassDef: slot C; Module: A).
pub fn body_of(t: &Tree, n: NodeId) -> &[u32] {
    match t.kind(n) {
        Kind::Module => t.list(a_(t, n)),
        Kind::FunctionDef | Kind::AsyncFunctionDef | Kind::ClassDef => t.list(c_(t, n)),
        _ => &[],
    }
}

/// Is `n` a str Constant?
pub fn is_str_const(t: &Tree, n: NodeId) -> bool {
    n != NONE && t.kind(n) == Kind::Constant && t.node(n).op == pt::V_STR
}

/// flow._own_nodes: every node of these statements, pre-order, without
/// descending into nested function or class bodies or lambdas (their
/// decorators, defaults and bases belong to the enclosing scope).
pub fn own_nodes(t: &Tree, stmts: &[u32]) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut stack: Vec<NodeId> = stmts.iter().rev().copied().collect();
    let mut kids: Vec<NodeId> = Vec::new();
    while let Some(n) = stack.pop() {
        out.push(n);
        match t.kind(n) {
            Kind::FunctionDef | Kind::AsyncFunctionDef | Kind::ClassDef => {
                stack.extend_from_slice(decorators(t, n));
                if t.kind(n) == Kind::ClassDef {
                    stack.extend_from_slice(t.list(b_(t, n)));
                } else {
                    let args = b_(t, n);
                    if args != NONE {
                        stack.extend(t.list(ext(t, args, 3)).iter().copied().filter(|&d| d != NONE));
                        stack.extend(t.list(ext(t, args, 1)).iter().copied().filter(|&d| d != NONE));
                    }
                }
            }
            Kind::Lambda => {}
            _ => {
                kids.clear();
                t.each_child(n, |c| kids.push(c));
                stack.extend(kids.iter().rev().copied());
            }
        }
    }
    out
}

/// flow._dotted: a best-effort dotted text for a Name / Attribute / Call /
/// Subscript expression.
pub fn dotted(t: &Tree, node: NodeId) -> PyStr {
    dotted_links(t, node).0
}

/// `dotted`, and the links of the chain it followed.
pub fn dotted_links(t: &Tree, node: NodeId) -> (PyStr, u64) {
    let mut parts: Vec<&[u32]> = Vec::new();
    let mut n = node;
    let mut links = 0u64;
    loop {
        links += 1;
        if n == NONE {
            parts.push(&[]);
            break;
        }
        match t.kind(n) {
            Kind::Name => {
                parts.push(t.str(a_(t, n)));
                break;
            }
            Kind::Attribute => {
                parts.push(t.str(b_(t, n)));
                n = a_(t, n);
            }
            Kind::Call => {
                let func = a_(t, n);
                let args = t.list(b_(t, n));
                if t.kind(func) == Kind::Name
                    && pystr::eq(t.str(a_(t, func)), "__import__")
                    && !args.is_empty()
                    && is_str_const(t, args[0])
                {
                    parts.push(t.str(a_(t, args[0])));
                    break;
                }
                n = func;
            }
            Kind::Subscript => n = a_(t, n),
            _ => {
                parts.push(&[]);
                break;
            }
        }
    }
    let mut out = Vec::new();
    for (k, p) in parts.iter().rev().enumerate() {
        if k > 0 {
            out.push(0x2E);
        }
        out.extend_from_slice(p);
    }
    (out, links)
}

/// flow._guard_of: (the name, the categories, positive, the collection an
/// allowlist checks against) of a guard `test`.
pub fn guard_of(t: &Tree, test: NodeId) -> Option<(NodeId, u8, bool, NodeId)> {
    let mut positive = true;
    let mut test = test;
    if t.kind(test) == Kind::UnaryOp && t.node(test).op == pt::NOT {
        positive = false;
        test = a_(t, test);
    }
    if t.kind(test) == Kind::Call {
        let func = a_(t, test);
        let args = t.list(b_(t, test));
        if t.kind(func) == Kind::Attribute && is_in(t.str(b_(t, func)), PATH_CHECKS) && !args.is_empty() {
            let mut target = a_(t, func);
            if t.kind(target) == Kind::Call {
                let tf = a_(t, target);
                let targs = t.list(b_(t, target));
                let last = dotted(t, tf);
                if is_in(last_part(&last), &["realpath", "abspath", "normpath", "resolve"])
                    && (!targs.is_empty() || t.kind(tf) == Kind::Attribute)
                {
                    target = if !targs.is_empty() { targs[0] } else { a_(t, tf) };
                }
            }
            if t.kind(target) == Kind::Name {
                return Some((target, bit(PATH), positive, NONE));
            }
            return None;
        }
    }
    if t.kind(test) == Kind::Compare {
        let ops = t.list(b_(t, test));
        if ops.len() == 1 && (ops[0] as u8 == pt::IN || ops[0] as u8 == pt::NOTIN) {
            let left = a_(t, test);
            let right = t.list(c_(t, test))[0];
            let negated = (ops[0] as u8 == pt::NOTIN) != !positive;
            if is_str_const(t, left) && pystr::starts_with(t.str(a_(t, left)), "..") && t.kind(right) == Kind::Name {
                return Some((right, bit(PATH), negated, NONE));
            }
            if t.kind(left) == Kind::Name && !is_str_const(t, right) {
                return Some((left, ALL, !negated, right));
            }
        }
    }
    None
}

/// flow._leaves: does a block always leave its function or loop at its end?
pub fn leaves(t: &Tree, body: &[u32]) -> bool {
    let last = match body.last() {
        Some(&l) => l,
        None => return false,
    };
    match t.kind(last) {
        Kind::Return | Kind::Raise | Kind::Continue | Kind::Break => true,
        Kind::Expr => {
            let v = a_(t, last);
            t.kind(v) == Kind::Call && is_in(&dotted(t, a_(t, v)), EXIT_CALLS)
        }
        _ => false,
    }
}

// ---------------- the project ----------------

pub struct Project {
    pub mods: Vec<Module>,
    pub fns: Vec<Func>,
    pub classes: Vec<Class>,
    pub names: Names,
    pub by_key: HashMap<PyStr, ModId>,
    pub by_dotted: HashMap<PyStr, Vec<ModId>>,
    pub funcs_by_name: QuickMap<NameId, Vec<FnId>>,
    pub methods_by_name: QuickMap<NameId, Vec<FnId>>,
    name_cache: QuickMap<(ModId, NameId), Rc<Vec<Target>>>,
    call_cache: QuickMap<(FnId, NodeId), Rc<CallRes>>,
    /// is an attribute's or a subscript's dotted text a source (eval.rs)
    pub src_memo: QuickMap<(ModId, NodeId), bool>,
    /// what a call is, by its callee's texts (raw, canonical: up to
    /// MEMO_TEXT characters), whether its resolution is precise and whether
    /// it calls an attribute (texts an input chooses: the keyed hash)
    class_memo: HashMap<PyStr, CallClass>,
    pub cfg: Rc<Config>,
    builtins: QuickSet<NameId>,
    common: QuickSet<NameId>,
    pub frames: u32,
    pub frame_limit: u32,
    /// steps taken, and the budget they may reach
    pub work: u64,
    pub budget: u64,
    pub nodes: u64,
    pub n_self: NameId,
    pub n_request: NameId,
    pub n_init: NameId,
    pub n_super: NameId,
    /// (the supply-chain model) the variables a function gives the defs
    /// nested in it, and the names each function declares `global`
    pub closure: QuickMap<FnId, QuickMap<NameId, Taint>>,
    /// (the supply-chain model) what nested functions give a function's
    /// variables: `nonlocal x` assigned, or a container of its filled
    pub closure_back: QuickMap<FnId, QuickMap<NameId, Taint>>,
    pub global_decls: QuickMap<FnId, Vec<NameId>>,
    pub nonlocal_decls: QuickMap<FnId, Vec<NameId>>,
}

impl Project {
    pub fn new(cfg: Rc<Config>) -> Project {
        let mut names = Names::default();
        let builtins = BUILTIN_NAMES.iter().map(|w| names.id(&cp(w))).collect();
        let common = COMMON_METHODS.split_whitespace().map(|w| names.id(&cp(w))).collect();
        let n_self = names.id(&cp("self"));
        let n_request = names.id(&cp("request"));
        let n_init = names.id(&cp("__init__"));
        let n_super = names.id(&cp("super"));
        Project {
            mods: Vec::new(),
            fns: Vec::new(),
            classes: Vec::new(),
            names,
            by_key: HashMap::new(),
            by_dotted: HashMap::new(),
            funcs_by_name: QuickMap::default(),
            methods_by_name: QuickMap::default(),
            name_cache: QuickMap::default(),
            call_cache: QuickMap::default(),
            src_memo: QuickMap::default(),
            class_memo: HashMap::new(),
            cfg,
            builtins,
            common,
            frames: 0,
            frame_limit: FRAMES,
            work: 0,
            budget: u64::MAX,
            nodes: 0,
            n_self,
            n_request,
            n_init,
            n_super,
            closure: QuickMap::default(),
            closure_back: QuickMap::default(),
            global_decls: QuickMap::default(),
            nonlocal_decls: QuickMap::default(),
        }
    }

    /// The project name of string `sid` of module `m`'s tree.
    pub fn name(&mut self, m: ModId, sid: u32) -> NameId {
        let md = &mut self.mods[m as usize];
        if let Some(&k) = md.sid.get(sid as usize) {
            if k != NONE {
                return k;
            }
        }
        let k = self.names.id(md.tree.str(sid));
        if let Some(slot) = self.mods[m as usize].sid.get_mut(sid as usize) {
            *slot = k;
        }
        k
    }

    pub fn name_text(&self, k: NameId) -> &[u32] {
        self.names.get(k)
    }

    pub fn is_builtin(&self, k: NameId) -> bool {
        self.builtins.contains(&k)
    }

    pub fn is_common_method(&self, k: NameId) -> bool {
        self.common.contains(&k)
    }

    pub fn tree(&self, m: ModId) -> &Tree {
        &self.mods[m as usize].tree
    }

    pub fn qualname(&self, f: FnId) -> PyStr {
        let func = &self.fns[f as usize];
        if func.pseudo {
            return cp("<module>");
        }
        let mut out = Vec::new();
        if let Some(c) = func.cls {
            out.extend_from_slice(self.names.get(self.classes[c as usize].name));
            out.push(0x2E);
        }
        out.extend_from_slice(self.names.get(func.name));
        out
    }

    /// "path:line" of a source.
    pub fn origin_text(&self, o: (ModId, u32)) -> PyStr {
        let mut s = self.mods[o.0 as usize].path.clone();
        s.push(0x3A);
        s.extend(cp(&o.1.to_string()));
        s
    }

    /// A sink's place as flow.py writes it.
    pub fn sink_text(&self, loc: SinkLoc) -> PyStr {
        let f = &self.fns[loc.0 as usize];
        let mut s = self.mods[f.module as usize].path.clone();
        s.push(0x3A);
        s.extend(cp(&loc.1.to_string()));
        if f.pseudo {
            s.extend(cp(" (module level)"));
        } else {
            s.extend(cp(" (in "));
            s.extend(self.qualname(loc.0));
            s.extend(cp("())"));
        }
        s
    }

    // ---------- collection ----------

    /// flow._PyModule + _PyProject.add_module.
    /// flow._PyProject.add_module: false when collecting its definitions
    /// held more frames than Python's recursion limit allows (a RecursionError
    /// out of add_module there: what was collected stays, its top-level code
    /// and imports are not added; flow._analyze_python notes the file).
    pub fn add_module(&mut self, file: u32, path: &[u32], content: &[u32], tree: Tree) -> bool {
        let idx = self.mods.len() as ModId;
        let mut norm: PyStr = path.iter().map(|&c| if c == 0x5C { 0x2F } else { c }).collect();
        while norm.starts_with(&[0x2E, 0x2F]) {
            norm.drain(..2);
        }
        let mut stem: PyStr = if pystr::ends_with(&norm, ".py") { norm[..norm.len() - 3].to_vec() } else { norm.clone() };
        if pystr::eq(basename(&stem), "__init__") {
            stem = dirname(&stem);
        }
        let dir = dirname(&norm);
        let nstr = tree.strings.len();
        let nodes = tree.nodes.len() as u64;
        self.mods.push(Module {
            idx,
            file,
            path: path.to_vec(),
            content: content.to_vec(),
            tree,
            sid: vec![NONE; nstr],
            key: stem.clone(),
            dir,
            funcs: QuickMap::default(),
            classes: QuickMap::default(),
            nested: QuickMap::default(),
            imports: QuickMap::default(),
            stars: Vec::new(),
            all_funcs: Vec::new(),
            globals: QuickMap::default(),
            body_fn: NONE,
            frameworks: None,
            dep_aliases: None,
            nodes,
        });
        self.nodes += nodes;
        self.by_key.insert(stem.clone(), idx);
        let parts: Vec<&[u32]> = split_on(&stem, 0x2F).into_iter().filter(|p| !p.is_empty() && *p != [0x2E]).collect();
        for k in 1..=parts.len().min(8) {
            let tail = &parts[parts.len() - k..];
            let mut key = Vec::new();
            for (i, p) in tail.iter().enumerate() {
                if i > 0 {
                    key.push(0x2E);
                }
                key.extend_from_slice(p);
            }
            self.by_dotted.entry(key).or_default().push(idx);
        }
        let root = self.mods[idx as usize].tree.root;
        let body: Vec<u32> = body_of(self.tree(idx), root).to_vec();
        // (the frames: flow.py's from add_module's first _collect, frame 0
        // here; its definitions are collected a frame shallower than its
        // readings run, so their limit is one more: a chain of 991 `elif`s
        // is collected, one of 992 is not, as from the `lazaret` command)
        self.frames = 0;
        let limit = self.frame_limit;
        self.frame_limit = limit + 1;
        let collected = self.collect_items(&body, idx, None, false, None);
        self.frame_limit = limit;
        self.frames = 0;
        if collected.is_err() {
            return false;
        }
        let body_fn = self.new_func(idx, root, None, true, None);
        self.mods[idx as usize].body_fn = body_fn;
        self.mods[idx as usize].all_funcs.push(body_fn);
        for n in own_nodes(self.tree(idx), &body) {
            self.record_import(idx, n);
        }
        true
    }

    fn new_func(&mut self, m: ModId, node: NodeId, cls: Option<ClsId>, pseudo: bool, parent: Option<FnId>) -> FnId {
        let id = self.fns.len() as FnId;
        let (name, line, mut posonly, mut args, mut kwonly, mut vararg, mut kwarg) =
            (NONE, 1u32, Vec::new(), Vec::new(), Vec::new(), None, None);
        let mut kind = FnKind::Function;
        let mut name_id = name;
        let mut fline = line;
        if !pseudo {
            let (sname, a, start) = {
                let t = self.tree(m);
                (a_(t, node), b_(t, node), t.node(node).start)
            };
            name_id = self.name(m, sname);
            fline = self.tree(m).line_of(start);
            let (po, ar, kw, va, ka) = {
                let t = self.tree(m);
                (
                    t.list(a_(t, a)).to_vec(),
                    t.list(b_(t, a)).to_vec(),
                    t.list(ext(t, a, 0)).to_vec(),
                    c_(t, a),
                    ext(t, a, 2),
                )
            };
            for x in po {
                let s = a_(self.tree(m), x);
                posonly.push(self.name(m, s));
            }
            for x in ar {
                let s = a_(self.tree(m), x);
                args.push(self.name(m, s));
            }
            for x in kw {
                let s = a_(self.tree(m), x);
                kwonly.push(self.name(m, s));
            }
            if va != NONE {
                let s = a_(self.tree(m), va);
                vararg = Some(self.name(m, s));
            }
            if ka != NONE {
                let s = a_(self.tree(m), ka);
                kwarg = Some(self.name(m, s));
            }
            if cls.is_some() {
                kind = FnKind::Method;
                let decs: Vec<u32> = decorators(self.tree(m), node).to_vec();
                for d in decs {
                    let dn = dotted(self.tree(m), d);
                    if pystr::eq(&dn, "staticmethod") || pystr::eq(&dn, "builtins.staticmethod") {
                        kind = FnKind::Static;
                    } else if pystr::eq(&dn, "classmethod") || pystr::eq(&dn, "builtins.classmethod") {
                        kind = FnKind::Class;
                    }
                }
            }
        }
        let positional: Vec<NameId> = posonly.iter().chain(args.iter()).copied().collect();
        let receiver = if matches!(kind, FnKind::Method | FnKind::Class) { positional.first().copied() } else { None };
        let mut params: Vec<NameId> = positional.clone();
        params.extend(vararg);
        params.extend(kwonly.iter().copied());
        params.extend(kwarg);
        params.retain(|&p| Some(p) != receiver);
        let mut pnames: Vec<NameId> = Vec::new();
        for &p in &params {
            if !pnames.contains(&p) {
                pnames.push(p);
            }
        }
        let size = if pseudo { 0 } else { 0 };
        self.fns.push(Func {
            id,
            name: name_id,
            module: m,
            node,
            cls,
            pseudo,
            line: fline,
            kind,
            posonly,
            args,
            kwonly,
            vararg,
            kwarg,
            receiver,
            params,
            pnames,
            param_to_sink: Vec::new(),
            param_to_return: Vec::new(),
            ret_source: None,
            local_names: QuickSet::default(),
            types: QuickMap::default(),
            callees: Vec::new(),
            callee_set: QuickSet::default(),
            callers: Vec::new(),
            caller_set: QuickSet::default(),
            runs: 0,
            request_params: None,
            size,
            parent,
        });
        id
    }

    fn record_import(&mut self, m: ModId, node: NodeId) {
        match self.tree(m).kind(node) {
            Kind::Import => {
                let aliases: Vec<u32> = self.tree(m).list(a_(self.tree(m), node)).to_vec();
                for al in aliases {
                    let (nm, asn) = {
                        let t = self.tree(m);
                        (t.str(a_(t, al)).to_vec(), b_(t, al))
                    };
                    if asn != NONE {
                        let k = self.name(m, asn);
                        self.mods[m as usize].imports.insert(k, Import::Module(nm));
                    } else {
                        let head = split_on(&nm, 0x2E)[0].to_vec();
                        let k = self.names.id(&head);
                        self.mods[m as usize].imports.entry(k).or_insert(Import::Module(head));
                    }
                }
            }
            Kind::ImportFrom => {
                let (base, aliases, level) = {
                    let t = self.tree(m);
                    let ms = a_(t, node);
                    let base = if ms == NONE { Vec::new() } else { t.str(ms).to_vec() };
                    (base, t.list(b_(t, node)).to_vec(), c_(t, node))
                };
                let level = if level == NONE { 0 } else { level };
                for al in aliases {
                    let (nm, asn) = {
                        let t = self.tree(m);
                        (t.str(a_(t, al)).to_vec(), b_(t, al))
                    };
                    if pystr::eq(&nm, "*") {
                        self.mods[m as usize].stars.push((base.clone(), level));
                    } else {
                        let k = if asn != NONE { self.name(m, asn) } else { self.names.id(&nm) };
                        self.mods[m as usize].imports.insert(k, Import::From { base: base.clone(), attr: nm, level });
                    }
                }
            }
            _ => {}
        }
    }

    /// flow._PyProject._collect, one frame deeper (`parent`: the function
    /// the body is in, if any).
    fn collect(&mut self, body: &[u32], m: ModId, cls: Option<ClsId>, in_func: bool, parent: Option<FnId>) -> Result<(), Halt> {
        self.enter()?;
        let r = self.collect_items(body, m, cls, in_func, parent);
        self.leave();
        r
    }

    fn collect_items(&mut self, body: &[u32], m: ModId, cls: Option<ClsId>, in_func: bool, parent: Option<FnId>) -> Result<(), Halt> {
        for &node in body {
            let kind = self.tree(m).kind(node);
            match kind {
                Kind::FunctionDef | Kind::AsyncFunctionDef => {
                    let fid = self.new_func(m, node, if in_func { None } else { cls }, false, if in_func { parent } else { None });
                    let name = self.fns[fid as usize].name;
                    self.mods[m as usize].all_funcs.push(fid);
                    if in_func {
                        self.mods[m as usize].nested.entry(name).or_default().push(fid);
                    } else if let Some(c) = cls {
                        let methods = &mut self.classes[c as usize].methods;
                        match methods.iter_mut().find(|(k, _)| *k == name) {
                            Some(e) => e.1 = fid,
                            None => methods.push((name, fid)),
                        }
                        self.methods_by_name.entry(name).or_default().push(fid);
                    } else {
                        self.mods[m as usize].funcs.insert(name, fid);
                        self.funcs_by_name.entry(name).or_default().push(fid);
                    }
                    let fbody: Vec<u32> = body_of(self.tree(m), node).to_vec();
                    self.collect(&fbody, m, None, true, Some(fid))?;
                    for n in own_nodes(self.tree(m), &fbody) {
                        self.record_import(m, n);
                    }
                }
                Kind::ClassDef => {
                    let sname = a_(self.tree(m), node);
                    let name = self.name(m, sname);
                    let c = self.classes.len() as ClsId;
                    self.classes.push(Class {
                        name,
                        module: m,
                        node,
                        methods: Vec::new(),
                        attr_taint: QuickMap::default(),
                        bases: None,
                        subclasses: Vec::new(),
                    });
                    if !in_func && cls.is_none() {
                        self.mods[m as usize].classes.insert(name, c);
                    }
                    let cbody: Vec<u32> = body_of(self.tree(m), node).to_vec();
                    self.collect(&cbody, m, Some(c), false, None)?;
                }
                _ => {
                    for field in ["body", "orelse", "finalbody", "handlers", "cases"] {
                        let sub: Vec<u32> = self.tree(m).children_of(node, field).to_vec();
                        if sub.is_empty() {
                            continue;
                        }
                        let mut stmts = Vec::new();
                        for s in sub {
                            let k = self.tree(m).kind(s);
                            if k == Kind::ExceptHandler || k == Kind::match_case {
                                stmts.extend_from_slice(self.tree(m).children_of(s, "body"));
                            } else if k.is_stmt() {
                                stmts.push(s);
                            }
                        }
                        self.collect(&stmts, m, cls, in_func, parent)?;
                    }
                }
            }
        }
        Ok(())
    }

    // ---------- name resolution ----------

    pub fn resolve_module(&self, dotted: &[u32], frm: ModId, level: u32) -> Vec<ModId> {
        let fm = &self.mods[frm as usize];
        if level > 0 {
            let mut base = fm.dir.clone();
            for _ in 0..level - 1 {
                base = dirname(&base);
            }
            let key = if !dotted.is_empty() { join(&base, &split_on(dotted, 0x2E)) } else { base };
            return self.by_key.get(&key).map(|&m| vec![m]).unwrap_or_default();
        }
        let cands = match self.by_dotted.get(dotted) {
            Some(c) => c,
            None => return Vec::new(),
        };
        if cands.len() <= 1 {
            return cands.clone();
        }
        let fparts = split_on(&fm.dir, 0x2F);
        let score = |m: ModId| -> usize {
            let mut n = 0;
            for (a, b) in split_on(&self.mods[m as usize].dir, 0x2F).iter().zip(fparts.iter()) {
                if a != b {
                    break;
                }
                n += 1;
            }
            n
        };
        let best = cands.iter().map(|&m| score(m)).max().unwrap_or(0);
        cands.iter().copied().filter(|&m| score(m) == best).collect()
    }

    /// flow._PyProject.resolve_name: [(kind, target)], cached by (module,
    /// name) (the first answer stands, whatever its hops).
    pub fn resolve_name(&mut self, m: ModId, name: NameId, hops: u32) -> Result<Rc<Vec<Target>>, Halt> {
        if let Some(hit) = self.name_cache.get(&(m, name)) {
            return Ok(hit.clone());
        }
        self.name_cache.insert((m, name), Rc::new(Vec::new()));
        self.enter()?;
        let r = self.resolve_name_inner(m, name, hops);
        self.leave();
        let out = Rc::new(r?);
        self.name_cache.insert((m, name), out.clone());
        Ok(out)
    }

    fn resolve_name_inner(&mut self, m: ModId, name: NameId, hops: u32) -> Result<Vec<Target>, Halt> {
        let md = &self.mods[m as usize];
        if let Some(&f) = md.funcs.get(&name) {
            return Ok(vec![Target::Func(f)]);
        }
        if let Some(&c) = md.classes.get(&name) {
            return Ok(vec![Target::Class(c)]);
        }
        if let Some(imp) = md.imports.get(&name).cloned() {
            match imp {
                Import::Module(d) => {
                    let ms = self.resolve_module(&d, m, 0);
                    if ms.is_empty() {
                        return Ok(vec![Target::Ext(Rc::from(d))]);
                    }
                    return Ok(ms.into_iter().map(Target::Module).collect());
                }
                Import::From { base, attr, level } => {
                    let full: PyStr = if !base.is_empty() {
                        let mut s = base.clone();
                        s.push(0x2E);
                        s.extend_from_slice(&attr);
                        s
                    } else {
                        attr.clone()
                    };
                    let sub = self.resolve_module(&full, m, level);
                    if !sub.is_empty() {
                        return Ok(sub.into_iter().map(Target::Module).collect());
                    }
                    let mut out: Vec<Target> = Vec::new();
                    if hops < IMPORT_HOPS && (!base.is_empty() || level > 0) {
                        let attr_id = self.names.id(&attr);
                        for bm in self.resolve_module(&base, m, level) {
                            let r = self.resolve_name(bm, attr_id, hops + 1)?;
                            out.extend(r.iter().cloned());
                        }
                    }
                    let internal: Vec<Target> = out.iter().filter(|t| !matches!(t, Target::Ext(_))).cloned().collect();
                    if !internal.is_empty() {
                        return Ok(internal);
                    }
                    if !out.is_empty() {
                        return Ok(out);
                    }
                    let ext: PyStr = if !base.is_empty() && level == 0 { full } else { attr };
                    return Ok(vec![Target::Ext(Rc::from(ext))]);
                }
            }
        }
        if let Some(fs) = md.nested.get(&name) {
            return Ok(fs.iter().map(|&f| Target::Func(f)).collect());
        }
        if hops < IMPORT_HOPS {
            let stars = md.stars.clone();
            for (base, level) in stars {
                for sm in self.resolve_module(&base, m, level) {
                    let r = self.resolve_name(sm, name, hops + 1)?;
                    let r: Vec<Target> = r.iter().filter(|t| !matches!(t, Target::Ext(_))).cloned().collect();
                    if !r.is_empty() {
                        return Ok(r);
                    }
                }
            }
        }
        Ok(Vec::new())
    }

    /// flow._PyProject.canonical: an import alias at the head of a dotted
    /// name replaced with what it imports.
    pub fn canonical(&mut self, m: ModId, dotted: &[u32]) -> PyStr {
        let (head, rest) = match dotted.iter().position(|&c| c == 0x2E) {
            Some(k) => (&dotted[..k], Some(&dotted[k + 1..])),
            None => (dotted, None),
        };
        let k = match self.names.find(head) {
            Some(k) => k,
            None => return dotted.to_vec(),
        };
        let base: PyStr = match self.mods[m as usize].imports.get(&k) {
            None => return dotted.to_vec(),
            Some(Import::Module(d)) => d.clone(),
            Some(Import::From { base, attr, level }) => {
                if !base.is_empty() && *level == 0 {
                    let mut s = base.clone();
                    s.push(0x2E);
                    s.extend_from_slice(attr);
                    s
                } else {
                    attr.clone()
                }
            }
        };
        let mut out = base;
        if let Some(r) = rest {
            if !r.is_empty() {
                out.push(0x2E);
                out.extend_from_slice(r);
            }
        }
        out
    }

    pub fn bases(&mut self, c: ClsId) -> Result<Vec<ClsId>, Halt> {
        if let Some(b) = &self.classes[c as usize].bases {
            return Ok(b.clone());
        }
        self.classes[c as usize].bases = Some(Vec::new());
        let (m, node) = (self.classes[c as usize].module, self.classes[c as usize].node);
        let bases: Vec<u32> = self.tree(m).list(b_(self.tree(m), node)).to_vec();
        for b in bases {
            for t in self.expr_targets(m, b)?.iter() {
                if let Target::Class(tc) = *t {
                    let has = self.classes[c as usize].bases.as_ref().map(|v| v.contains(&tc)).unwrap_or(false);
                    if tc != c && !has {
                        if let Some(v) = self.classes[c as usize].bases.as_mut() {
                            v.push(tc);
                        }
                        self.classes[tc as usize].subclasses.push(c);
                    }
                }
            }
        }
        Ok(self.classes[c as usize].bases.clone().unwrap_or_default())
    }

    pub fn expr_targets(&mut self, m: ModId, node: NodeId) -> Result<Rc<Vec<Target>>, Halt> {
        let kind = self.tree(m).kind(node);
        match kind {
            Kind::Name => {
                let s = a_(self.tree(m), node);
                let k = self.name(m, s);
                self.resolve_name(m, k, 0)
            }
            Kind::Attribute => {
                self.enter()?;
                let (v, attr) = {
                    let t = self.tree(m);
                    (a_(t, node), b_(t, node))
                };
                let inner = self.expr_targets(m, v);
                let inner = match inner {
                    Ok(x) => x,
                    Err(e) => {
                        self.leave();
                        return Err(e);
                    }
                };
                let attr = self.name(m, attr);
                let mut out = Vec::new();
                for t in inner.iter() {
                    if let Target::Module(tm) = *t {
                        match self.resolve_name(tm, attr, 0) {
                            Ok(r) => out.extend(r.iter().cloned()),
                            Err(e) => {
                                self.leave();
                                return Err(e);
                            }
                        }
                    }
                }
                self.leave();
                Ok(Rc::new(out))
            }
            _ => Ok(Rc::new(Vec::new())),
        }
    }

    /// The first method `name` of the class or its bases, breadth first.
    pub fn lookup_method(&mut self, c: ClsId, name: NameId) -> Result<Vec<FnId>, Halt> {
        let mut seen: QuickSet<ClsId> = QuickSet::default();
        let mut queue: std::collections::VecDeque<ClsId> = std::collections::VecDeque::new();
        queue.push_back(c);
        while let Some(x) = queue.pop_front() {
            if !seen.insert(x) {
                continue;
            }
            if let Some(&(_, f)) = self.classes[x as usize].methods.iter().find(|(k, _)| *k == name) {
                self.charge(seen.len() as u64);
                return Ok(vec![f]);
            }
            for b in self.bases(x)? {
                queue.push_back(b);
            }
        }
        self.charge(seen.len() as u64);
        Ok(Vec::new())
    }

    /// The source taint of self.<attr> written by any method of the class
    /// or its bases (depth first, unioned in that order).
    pub fn mro_attr_taint(&mut self, c: ClsId, attr: NameId) -> Result<Option<Taint>, Halt> {
        let mut seen: QuickSet<ClsId> = QuickSet::default();
        let mut stack = vec![c];
        let mut t: Option<Taint> = None;
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some(v) = self.classes[x as usize].attr_taint.get(&attr) {
                t = Some(match t {
                    None => v.clone(),
                    Some(t0) => t0.union(v),
                });
            }
            stack.extend(self.bases(x)?);
        }
        self.charge(seen.len() as u64);
        Ok(t)
    }

    // ---------- call resolution ----------

    pub fn receiver(&mut self, f: FnId, val: NodeId) -> Result<Option<Recv>, Halt> {
        let m = self.fns[f as usize].module;
        let kind = self.tree(m).kind(val);
        match kind {
            Kind::Name => {
                let s = a_(self.tree(m), val);
                let id = self.name(m, s);
                let func = &self.fns[f as usize];
                if let (Some(c), Some(r)) = (func.cls, func.receiver) {
                    if id == r {
                        return Ok(Some(Recv::Instance(c)));
                    }
                }
                if let Some(&c) = func.types.get(&id) {
                    return Ok(Some(Recv::Instance(c)));
                }
                if func.local_names.contains(&id) {
                    return Ok(None);
                }
                let tl = self.resolve_name(m, id, 0)?;
                let mods: Vec<ModId> =
                    tl.iter().filter_map(|t| if let Target::Module(x) = t { Some(*x) } else { None }).collect();
                if !mods.is_empty() {
                    return Ok(Some(Recv::Module(mods)));
                }
                if let Some(c) = tl.iter().find_map(|t| if let Target::Class(x) = t { Some(*x) } else { None }) {
                    return Ok(Some(Recv::ClassRef(c)));
                }
                if tl.iter().any(|t| matches!(t, Target::Ext(_))) {
                    return Ok(Some(Recv::Ext));
                }
                Ok(None)
            }
            Kind::Call => {
                let func_node = a_(self.tree(m), val);
                if self.tree(m).kind(func_node) == Kind::Name {
                    let s = a_(self.tree(m), func_node);
                    if self.name(m, s) == self.n_super {
                        if let Some(c) = self.fns[f as usize].cls {
                            return Ok(Some(Recv::Super(c)));
                        }
                    }
                }
                let tl = self.expr_targets(m, func_node)?;
                if let Some(c) = tl.iter().find_map(|t| if let Target::Class(x) = t { Some(*x) } else { None }) {
                    return Ok(Some(Recv::Instance(c)));
                }
                Ok(None)
            }
            Kind::Attribute => {
                let tl = self.expr_targets(m, val)?;
                let mods: Vec<ModId> =
                    tl.iter().filter_map(|t| if let Target::Module(x) = t { Some(*x) } else { None }).collect();
                if !mods.is_empty() {
                    return Ok(Some(Recv::Module(mods)));
                }
                if let Some(c) = tl.iter().find_map(|t| if let Target::Class(x) = t { Some(*x) } else { None }) {
                    return Ok(Some(Recv::ClassRef(c)));
                }
                let mut root = val;
                while self.tree(m).kind(root) == Kind::Attribute {
                    root = a_(self.tree(m), root);
                }
                if self.tree(m).kind(root) == Kind::Name {
                    let s = a_(self.tree(m), root);
                    let id = self.name(m, s);
                    let func = &self.fns[f as usize];
                    if !func.local_names.contains(&id) && func.receiver != Some(id) {
                        let tl = self.resolve_name(m, id, 0)?;
                        if tl.iter().any(|t| matches!(t, Target::Ext(_))) {
                            return Ok(Some(Recv::Ext));
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub fn resolve_call(&mut self, f: FnId, call: NodeId) -> Result<Rc<CallRes>, Halt> {
        if let Some(r) = self.call_cache.get(&(f, call)) {
            return Ok(r.clone());
        }
        let r = Rc::new(self.resolve_call_inner(f, call)?);
        self.call_cache.insert((f, call), r.clone());
        Ok(r)
    }

    fn resolve_call_inner(&mut self, f: FnId, call: NodeId) -> Result<CallRes, Halt> {
        let m = self.fns[f as usize].module;
        let func = a_(self.tree(m), call);
        let (d, links) = dotted_links(self.tree(m), func);
        let canon = self.canonical(m, &d);
        self.charge(links + (d.len() + canon.len()) as u64);
        let mut targets: Vec<(FnId, bool)> = Vec::new();
        let mut ctor: Option<ClsId> = None;
        let mut precise = true;
        let fkind = self.tree(m).kind(func);
        if fkind == Kind::Name {
            let s = a_(self.tree(m), func);
            let id = self.name(m, s);
            let mut tl: Vec<Target> = self.resolve_name(m, id, 0)?.as_ref().clone();
            if tl.is_empty() && !self.is_builtin(id) && !self.fns[f as usize].local_names.contains(&id) {
                if let Some(c) = self.funcs_by_name.get(&id) {
                    if c.len() == 1 {
                        tl = vec![Target::Func(c[0])];
                    }
                }
            }
            for t in tl {
                match t {
                    Target::Func(g) => targets.push((g, false)),
                    Target::Class(c) => {
                        ctor = Some(c);
                        let init = self.n_init;
                        for g in self.lookup_method(c, init)? {
                            targets.push((g, true));
                        }
                    }
                    _ => {}
                }
            }
        } else if fkind == Kind::Attribute {
            let (v, attr_s) = {
                let t = self.tree(m);
                (a_(t, func), b_(t, func))
            };
            let attr = self.name(m, attr_s);
            let recv = self.receiver(f, v)?;
            match recv {
                None => {
                    let text = self.names.get(attr);
                    if !pystr::starts_with(text, "__") && !self.is_common_method(attr) {
                        let cands = self.methods_by_name.get(&attr).cloned().unwrap_or_default();
                        if !cands.is_empty() && cands.len() <= MAX_DUCK {
                            precise = false;
                            targets = cands.iter().map(|&g| (g, self.fns[g as usize].kind != FnKind::Static)).collect();
                        }
                    }
                }
                Some(Recv::Instance(c)) => {
                    targets = self
                        .lookup_method(c, attr)?
                        .into_iter()
                        .map(|g| (g, self.fns[g as usize].kind != FnKind::Static))
                        .collect();
                }
                Some(Recv::Super(c)) => {
                    for b in self.bases(c)? {
                        for g in self.lookup_method(b, attr)? {
                            targets.push((g, self.fns[g as usize].kind != FnKind::Static));
                        }
                    }
                }
                Some(Recv::ClassRef(c)) => {
                    targets = self
                        .lookup_method(c, attr)?
                        .into_iter()
                        .map(|g| (g, self.fns[g as usize].kind == FnKind::Class))
                        .collect();
                }
                Some(Recv::Module(ms)) => {
                    for tm in ms {
                        let r = self.resolve_name(tm, attr, 0)?;
                        for t in r.iter() {
                            match *t {
                                Target::Func(g) => targets.push((g, false)),
                                Target::Class(c) => {
                                    ctor = Some(c);
                                    let init = self.n_init;
                                    for g in self.lookup_method(c, init)? {
                                        targets.push((g, true));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Some(Recv::Ext) => {}
            }
        }
        let precise = precise && (!targets.is_empty() || ctor.is_some());
        let class = self.class_of(&d, &canon, precise, fkind == Kind::Attribute);
        Ok(CallRes { targets, ctor, precise, class })
    }

    /// What a call with these callee texts is (`CallClass`): worked out once
    /// for each pair of texts up to MEMO_TEXT long, each time for longer.
    fn class_of(&mut self, raw: &[u32], canon: &[u32], precise: bool, attr: bool) -> CallClass {
        let key: Option<PyStr> = (raw.len() + canon.len() <= MEMO_TEXT).then(|| {
            let mut k = Vec::with_capacity(raw.len() + canon.len() + 3);
            k.extend_from_slice(raw);
            k.push(0x11_0000); // (past Unicode: a separator no text holds)
            k.extend_from_slice(canon);
            k.push(precise as u32);
            k.push(attr as u32);
            k
        });
        if let Some(c) = key.as_ref().and_then(|k| self.class_memo.get(k)) {
            return *c;
        }
        let c = eval::classify(&self.cfg, raw, canon, precise, attr);
        self.charge(4 * (raw.len() + canon.len()) as u64);
        if let Some(k) = key {
            self.class_memo.insert(k, c);
        }
        c
    }

    // ---------- pre-pass ----------

    pub fn prepass(&mut self, f: FnId) -> Result<(), Halt> {
        let (m, node, pseudo) = {
            let func = &self.fns[f as usize];
            (func.module, func.node, func.pseudo)
        };
        let body: Vec<u32> = body_of(self.tree(m), node).to_vec();
        let nodes = own_nodes(self.tree(m), &body);
        let func = &self.fns[f as usize];
        let mut names: QuickSet<NameId> = func.posonly.iter().chain(func.args.iter()).chain(func.kwonly.iter()).copied().collect();
        names.extend(func.vararg);
        names.extend(func.kwarg);
        for &n in &nodes {
            let t = self.tree(m);
            if t.kind(n) == Kind::Name && t.node(n).op == pt::STORE {
                let s = a_(t, n);
                let k = self.name(m, s);
                names.insert(k);
            }
        }
        if !pseudo {
            self.fns[f as usize].local_names = names;
        }
        self.fns[f as usize].size = nodes.len() as u64;
        for &n in &nodes {
            let (is_assign, target, value) = {
                let t = self.tree(m);
                if t.kind(n) == Kind::Assign {
                    let targets = t.list(a_(t, n));
                    let v = b_(t, n);
                    if targets.len() == 1 && t.kind(targets[0]) == Kind::Name && t.kind(v) == Kind::Call {
                        (true, targets[0], v)
                    } else {
                        (false, NONE, NONE)
                    }
                } else {
                    (false, NONE, NONE)
                }
            };
            if is_assign {
                let fnode = a_(self.tree(m), value);
                let tl = self.expr_targets(m, fnode)?;
                if let Some(c) = tl.iter().find_map(|t| if let Target::Class(x) = t { Some(*x) } else { None }) {
                    let s = a_(self.tree(m), target);
                    let k = self.name(m, s);
                    self.fns[f as usize].types.insert(k, c);
                }
            }
        }
        for &n in &nodes {
            if self.tree(m).kind(n) == Kind::Call {
                if self.work > self.budget {
                    return Err(Halt::Stop);
                }
                let res = self.resolve_call(f, n)?;
                for &(g, _) in &res.targets {
                    if self.fns[f as usize].callee_set.insert(g) {
                        self.fns[f as usize].callees.push(g);
                    }
                    if self.fns[g as usize].caller_set.insert(f) {
                        self.fns[g as usize].callers.push(f);
                    }
                }
            }
        }
        Ok(())
    }

    // ---------- work past a step's own ----------

    /// `n` links or characters of work past a step's own (FREE_WORK).
    #[inline]
    pub fn charge(&mut self, n: u64) {
        if n > FREE_WORK {
            self.work += (n - FREE_WORK) / WORK_PER_STEP;
        }
    }

    // ---------- frames (Python's recursion limit) ----------

    /// One more frame of flow.py's recursive reading (RecursionError past
    /// the limit).
    #[inline]
    pub fn enter(&mut self) -> Result<(), Halt> {
        self.frames += 1;
        if self.frames > self.frame_limit {
            self.frames -= 1;
            return Err(Halt::Overflow);
        }
        Ok(())
    }

    #[inline]
    pub fn leave(&mut self) {
        self.frames = self.frames.saturating_sub(1);
    }

    // ---------- route handlers ----------

    /// The frameworks module `m` imports (flow._frameworks_of).
    pub fn frameworks_of(&mut self, m: ModId) -> u8 {
        if let Some(fw) = self.mods[m as usize].frameworks {
            return fw;
        }
        let mut got = 0u8;
        for rec in self.mods[m as usize].imports.values() {
            let base: &[u32] = match rec {
                Import::Module(d) => d,
                Import::From { base, level, .. } => {
                    if *level == 0 {
                        base
                    } else {
                        &[]
                    }
                }
            };
            let head = split_on(base, 0x2E)[0];
            if pystr::eq(head, "flask") || pystr::eq(head, "quart") {
                got |= FW_FLASK;
            } else if pystr::eq(head, "fastapi") {
                got |= FW_FASTAPI;
            } else if pystr::eq(head, "django") {
                got |= FW_DJANGO;
            }
        }
        self.mods[m as usize].frameworks = Some(got);
        got
    }

    /// The parameters of `f` a web framework fills from the request, if it
    /// is a route handler (flow._request_params).
    pub fn request_params(&mut self, f: FnId) -> Rc<Vec<NameId>> {
        if let Some(r) = &self.fns[f as usize].request_params {
            return r.clone();
        }
        let mut got: Vec<NameId> = Vec::new();
        let (m, node, pseudo) = {
            let func = &self.fns[f as usize];
            (func.module, func.node, func.pseudo)
        };
        if !pseudo {
            let fws = self.frameworks_of(m);
            let a = b_(self.tree(m), node);
            let (positional, defaults, kwonly, kw_defaults, vararg, kwarg) = {
                let t = self.tree(m);
                let mut pos: Vec<u32> = t.list(a_(t, a)).to_vec();
                pos.extend_from_slice(t.list(b_(t, a)));
                (pos, t.list(ext(t, a, 3)).to_vec(), t.list(ext(t, a, 0)).to_vec(), t.list(ext(t, a, 1)).to_vec(), c_(t, a), ext(t, a, 2))
            };
            let mut dflt: Vec<u32> = vec![NONE; positional.len().saturating_sub(defaults.len())];
            dflt.extend(defaults.iter().copied());
            // (name, annotation node, default node): the texts are written when asked
            let mut params: Vec<(NameId, NodeId, NodeId)> = Vec::new();
            for (k, &x) in positional.iter().enumerate() {
                let (s, ann) = (a_(self.tree(m), x), b_(self.tree(m), x));
                let id = self.name(m, s);
                params.push((id, ann, dflt.get(k).copied().unwrap_or(NONE)));
            }
            for (k, &x) in kwonly.iter().enumerate() {
                let (s, ann) = (a_(self.tree(m), x), b_(self.tree(m), x));
                let id = self.name(m, s);
                params.push((id, ann, kw_defaults.get(k).copied().unwrap_or(NONE)));
            }
            let text = |p: &Project, n: NodeId| -> PyStr {
                if n == NONE {
                    return Vec::new();
                }
                unparse::unparse(p.tree(m), n).unwrap_or_default()
            };
            let mut routed = false;
            let decs: Vec<u32> = decorators(self.tree(m), node).to_vec();
            for d in decs {
                let (is_call, func) = {
                    let t = self.tree(m);
                    let ok = t.kind(d) == Kind::Call && t.kind(a_(t, d)) == Kind::Attribute;
                    (ok, if ok { a_(t, d) } else { NONE })
                };
                if !is_call {
                    continue;
                }
                let method = self.tree(m).str(b_(self.tree(m), func)).to_vec();
                if pystr::eq(&method, "route") || (fws & FW_FLASK != 0 && frameworks::is_in(&method, frameworks::FLASK_ROUTE_METHODS)) {
                    routed = true;
                    let rule: PyStr = {
                        let t = self.tree(m);
                        let args = t.list(b_(t, d));
                        let first = args.first().copied().filter(|&x| is_str_const(t, x)).map(|x| t.str(a_(t, x)).to_vec());
                        match first {
                            Some(r) => r,
                            None => {
                                let mut r = None;
                                for &k in t.list(c_(t, d)) {
                                    let karg = a_(t, k);
                                    let v = b_(t, k);
                                    if karg != NONE && pystr::eq(t.str(karg), "rule") && is_str_const(t, v) {
                                        r = Some(t.str(a_(t, v)).to_vec());
                                        break;
                                    }
                                }
                                r.unwrap_or_default()
                            }
                        }
                    };
                    let free = frameworks::flask_free_vars(&rule);
                    for &(name, _, _) in &params {
                        if free.iter().any(|v| v.as_slice() == self.names.get(name)) {
                            got.push(name);
                        }
                    }
                } else if fws & FW_FASTAPI != 0 && frameworks::is_in(&method, frameworks::FASTAPI_ROUTE_METHODS) {
                    routed = true;
                    let aliases = match &self.mods[m as usize].dep_aliases {
                        Some(a) => a.clone(),
                        None => {
                            let a = Rc::new(frameworks::dep_aliases(&self.mods[m as usize].content));
                            self.mods[m as usize].dep_aliases = Some(a.clone());
                            a
                        }
                    };
                    for &(name, ann, dn) in &params {
                        let (at, dt) = (text(self, ann), text(self, dn));
                        if frameworks::fastapi_param(self.names.get(name), &at, &dt, &aliases) {
                            got.push(name);
                        }
                    }
                }
            }
            if !routed && fws & FW_DJANGO != 0 {
                let first = if params.len() >= 2 && params[0].0 == self.n_self && params[1].0 == self.n_request {
                    2
                } else if !params.is_empty() && params[0].0 == self.n_request {
                    1
                } else {
                    0
                };
                if first > 0 {
                    for &(name, ann, _) in &params[first..] {
                        let at = text(self, ann);
                        if frameworks::django_param(self.names.get(name), &at) {
                            got.push(name);
                        }
                    }
                    if vararg != NONE {
                        let s = a_(self.tree(m), vararg);
                        let k = self.name(m, s);
                        got.push(k);
                    }
                    if kwarg != NONE {
                        let s = a_(self.tree(m), kwarg);
                        let k = self.name(m, s);
                        got.push(k);
                    }
                }
            }
            let mut uniq: Vec<NameId> = Vec::new();
            for g in got {
                if !uniq.contains(&g) {
                    uniq.push(g);
                }
            }
            got = uniq;
        }
        let r = Rc::new(got);
        self.fns[f as usize].request_params = Some(r.clone());
        r
    }
}
