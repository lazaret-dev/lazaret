//! The reader's evaluation of Go code: what a function's statements do, followed into the package's own functions,
//! methods and closures and the module's other packages, recorded as events (0.1.9, G-1).
//!
//! It evaluates the way Rust's reader does (`rsread::eval`), on the tree `goparse` builds: each expression is a
//! [`Val`] (the text it builds, the data it carries, the handle it is), each statement updates the function's names,
//! and the calls that matter are recorded: a process started ([`Ev::Run`]), data sent ([`Ev::Send`]), a file written
//! ([`Ev::Write`]), a name looked up ([`Ev::Lookup`]), a library or plugin loaded ([`Ev::Load`]). Both branches of an
//! `if` and every case of a `switch` are read; a loop is read once, or once for each item of a list it knows (a few,
//! or all of them, up to a bound, when its body only computes: the loops that decode a string); a goroutine and a
//! deferred call are read where they are written. Package-level variables are read when they are first used,
//! constants with their `iota`. Work is bounded by steps, nesting, events and closures; a reading that reaches a
//! bound says so ([`Model::cut`]).
//!
//! The APIs it knows are the standard library's (`os/exec`, `os`, `os/user`, `io`, `bufio`, `net`, `net/http`,
//! `crypto/tls`, `syscall`, `plugin`, `path/filepath`, `strings`, `bytes`, `strconv`, `fmt`, `encoding/base64`,
//! `encoding/hex`, `compress/*`, `net/url`) and `golang.org/x/sys/windows`. A name is resolved through the file's
//! imports: `exec.Command` is `os/exec`'s whatever the import's name.

use super::lit;
use crate::goparse::scan::Tok;
use crate::goparse::tree::{Kind as K, Node, NodeId, Tree, ELLIPSIS, NONE};
use crate::jsflow::supply::{K_BYTES, K_DECODED, K_IDENTITY, K_PATH, K_WHOLE_ENV};
use crate::model::events::{self, derived, path_join, text_of_bytes, CmdState, ConnState, Ev, ReqState, WState};
use crate::model::val::{self, Obj, Val, UNKNOWN};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// The deepest nesting of the evaluator's own calls (a statement within a statement, an expression within an
/// expression, a call's body within its call): past it a value is unknown and the reading is cut short. Chains
/// (`a + b + …`, `else if`) are walked, not nested.
pub const MAX_NEST: u32 = 400;
/// The most events one reading records; past it the reading is cut short.
pub const MAX_EVENTS: usize = 2_000;
/// The most closures one reading makes (each holds a copy of its function's names).
pub const MAX_CLOSURES: usize = 4_096;
/// The items of a list a loop whose body does more than compute is read for.
const LOOP_ITEMS: usize = 8;
/// The items a loop whose body only computes is read for (a decoder's loop: every byte).
const COMPUTE_ITEMS: usize = 4_096;

/// A file of the module, as the evaluator reads it.
pub struct FileRef<'a> {
    pub path: PyStr,
    pub src: &'a [u32],
    pub tree: Tree,
    /// Its package: an index into [`Module::pkgs`].
    pub pkg: u32,
    /// The names its imports bring in -> the import path (`exec` -> `os/exec`; an alias's name for an alias).
    pub imports: HashMap<PyStr, PyStr>,
}

/// A package-level name: what gives it its value.
#[derive(Clone, Copy, Debug)]
pub struct Global {
    pub file: u16,
    /// The ValueSpec that names it, and its place among the spec's names.
    pub spec: NodeId,
    pub index: u32,
    /// The ValueSpec whose values give it: its own, or for a constant written with none, the last of its group
    /// with some (NONE: a variable's zero value).
    pub values: NodeId,
    /// A constant's place in its group (`iota`); -1 for a variable.
    pub iota: i64,
    /// `//go:embed`: the build puts files' bytes in it.
    pub embed: bool,
}

/// A package: one folder's files, built together.
#[derive(Default)]
pub struct Pkg {
    pub dir: PyStr,
    pub files: Vec<u16>,
    /// Its functions (no receiver) by name.
    pub funcs: HashMap<PyStr, Vec<(u16, NodeId)>>,
    /// Its methods by name.
    pub methods: HashMap<PyStr, Vec<(u16, NodeId)>>,
    /// Its package-level variables and constants by name.
    pub globals: HashMap<PyStr, Global>,
    /// Its type names (a call of one is a conversion).
    pub types: HashSet<PyStr>,
}

pub struct Module<'a> {
    pub files: Vec<FileRef<'a>>,
    pub pkgs: Vec<Pkg>,
    /// The module's own packages by import path.
    pub by_path: HashMap<PyStr, u32>,
    /// Functions whose body holds base64's alphabet: a decoder written out.
    pub b64_fns: HashSet<(u16, NodeId)>,
}

pub struct ClosureState {
    pub file: u16,
    pub pkg: u32,
    /// A FuncLit, or the FuncDecl a function's name gives as a value (`decl`).
    pub node: NodeId,
    pub decl: bool,
    pub env: HashMap<PyStr, Val>,
    /// The function that made it: called from there, it sees and changes that function's names.
    pub creator: Option<(u16, NodeId)>,
}

struct Frame {
    file: u16,
    pkg: u32,
    vars: HashMap<PyStr, Val>,
    ret: Option<Val>,
}

pub struct Model<'k, 'a> {
    pub k: &'k Module<'a>,
    pub p: &'k Pack,
    pub cmds: Vec<CmdState>,
    pub reqs: Vec<ReqState>,
    pub conns: Vec<ConnState>,
    pub wfiles: Vec<WState>,
    pub closures: Vec<ClosureState>,
    pub events: Vec<Ev>,
    /// The function declarations a reading reached.
    pub reached: HashSet<(u16, NodeId)>,
    globals: HashMap<(u32, PyStr), Val>,
    global_stack: Vec<(u32, PyStr)>,
    /// Package-level variables whose initializers are another moment's (they ran when the package was loaded):
    /// their values are not known here.
    pub no_init: HashSet<(u32, PyStr)>,
    stack: Vec<(u16, NodeId)>,
    steps: u64,
    pub max_steps: u64,
    pub max_depth: usize,
    next_id: u32,
    /// The functions not to follow (another moment's): their values are not known here.
    pub not_follow: HashSet<(u16, NodeId)>,
    nest: u32,
    /// The reading was cut short (steps, nesting, events, closures): what it did not read may hold what it looks
    /// for. The caller resets it.
    pub cut: bool,
    /// The code called a function of its cgo preamble (`C.f(…)`).
    pub calls_c: bool,
}

fn eqs(a: &[u32], b: &str) -> bool {
    pystr::eq(a, b)
}

fn args_kinds(args: &[Val]) -> Val {
    let mut v = Val::unknown();
    for a in args {
        v.add_kinds(a);
    }
    v
}

/// The basic types a call of which is a conversion.
const BASIC: &[&str] = &[
    "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8",
    "uint16", "uint32", "uint64", "uintptr", "any",
];

/// Methods of the standard library's types a package's own method may share a name with: never followed into the
/// package when the receiver is not known.
fn is_std_method(n: &str) -> bool {
    matches!(
        n,
        "String" | "Error" | "Close" | "Read" | "Write" | "Len" | "Less" | "Swap" | "Get" | "Set" | "Add" | "Del" | "Lock" | "Unlock" | "Wait" | "Done"
            | "Next" | "Reset" | "Bytes" | "Format" | "Scan" | "Err" | "Value" | "Load" | "Store" | "Do" | "Run" | "Start" | "Stop" | "Init" | "New"
    )
}

/// [`is_std_method`], for the module's reading of what init code calls.
pub fn is_std_method_pub(n: &str) -> bool {
    is_std_method(n)
}

/// The binary operator a compound assignment applies (`+=` -> `+`).
fn compound(op: u8) -> u8 {
    let t = |x: Tok| x as u8;
    match op {
        x if x == t(Tok::AddAssign) => t(Tok::Add),
        x if x == t(Tok::SubAssign) => t(Tok::Sub),
        x if x == t(Tok::MulAssign) => t(Tok::Mul),
        x if x == t(Tok::QuoAssign) => t(Tok::Quo),
        x if x == t(Tok::RemAssign) => t(Tok::Rem),
        x if x == t(Tok::AndAssign) => t(Tok::And),
        x if x == t(Tok::OrAssign) => t(Tok::Or),
        x if x == t(Tok::XorAssign) => t(Tok::Xor),
        x if x == t(Tok::ShlAssign) => t(Tok::Shl),
        x if x == t(Tok::ShrAssign) => t(Tok::Shr),
        x if x == t(Tok::AndNotAssign) => t(Tok::AndNot),
        _ => t(Tok::Illegal),
    }
}

/// An item of a list, or of a tuple; what a value gives for one it does not hold.
fn item_of(v: &Val, k: usize) -> Val {
    match &v.items {
        Some(items) if v.obj != Obj::Map => items.get(k).cloned().unwrap_or_else(|| derived(v)),
        _ => derived(v),
    }
}

/// The value a map (or a struct literal with named fields) holds under `key`.
fn map_get(v: &Val, key: &[u32]) -> Option<Val> {
    if v.obj != Obj::Map {
        return None;
    }
    v.items.as_ref()?.iter().find(|pair| pair.items.as_ref().and_then(|p| p.first()).and_then(|k| k.s.as_ref()).is_some_and(|k| k.as_slice() == key)).map(|pair| item_of(pair, 1))
}

/// A text's bytes as a list of numbers, the text kept.
fn bytes_list(v: &Val) -> Val {
    match &v.s {
        Some(s) if !s.contains(&UNKNOWN) && s.len() <= val::MAX_ITEMS => {
            let items: Vec<Val> = val::bytes_of(s).iter().map(|&b| Val::int(b as i128)).collect();
            let mut out = Val::list(items).with_kinds(v);
            out.s = Some(s.clone());
            out
        }
        _ => v.clone(),
    }
}

/// A list's numbers read as text: bytes read as UTF-8 when they are bytes, code points when one is not.
fn text_of_numbers(v: &Val) -> Val {
    if let Some(items) = &v.items {
        if let Some(ints) = items.iter().map(|i| i.int).collect::<Option<Vec<i128>>>() {
            if ints.iter().any(|&n| !(0..=255).contains(&n)) {
                let text: PyStr = ints.iter().map(|&n| u32::try_from(n).ok().filter(|&c| char::from_u32(c).is_some()).unwrap_or(UNKNOWN)).collect();
                return Val::text(text).with_kinds(v);
            }
        }
    }
    text_of_bytes(v)
}

impl<'k, 'a> Model<'k, 'a> {
    pub fn new(k: &'k Module<'a>, p: &'k Pack) -> Self {
        Model {
            k,
            p,
            cmds: Vec::new(),
            reqs: Vec::new(),
            conns: Vec::new(),
            wfiles: Vec::new(),
            closures: Vec::new(),
            events: Vec::new(),
            reached: HashSet::new(),
            globals: HashMap::new(),
            global_stack: Vec::new(),
            no_init: HashSet::new(),
            stack: Vec::new(),
            steps: 0,
            max_steps: 2_000_000,
            max_depth: 8,
            next_id: 1,
            not_follow: HashSet::new(),
            nest: 0,
            cut: false,
            calls_c: false,
        }
    }

    fn step(&mut self) -> bool {
        self.steps += 1;
        if self.steps & 63 == 0 && !crate::budget::spend(1) {
            self.steps = self.max_steps;
        }
        if self.steps >= self.max_steps {
            self.cut = true;
            return false;
        }
        true
    }

    /// Work a step does besides the step: characters copied.
    fn charge(&mut self, chars: usize) {
        self.steps = self.steps.saturating_add((chars / 64) as u64);
    }

    pub fn out_of_steps(&self) -> bool {
        self.steps >= self.max_steps
    }

    pub fn steps_used(&self) -> u64 {
        self.steps
    }

    fn fresh_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Records what the code does (at most MAX_EVENTS; past them the reading is cut short).
    pub fn ev(&mut self, e: Ev) {
        if self.events.len() >= MAX_EVENTS {
            self.cut = true;
            return;
        }
        self.events.push(e);
    }

    // ---------------------------------------------------------------- the tree --
    fn node(&self, file: u16, id: NodeId) -> Node {
        let k: &'k Module<'a> = self.k;
        k.files[file as usize].tree.nodes[id as usize]
    }

    fn items(&self, file: u16, list: u32) -> &'k [u32] {
        let k: &'k Module<'a> = self.k;
        k.files[file as usize].tree.items(list)
    }

    fn text(&self, file: u16, id: NodeId) -> &'a [u32] {
        let src: &'a [u32] = self.k.files[file as usize].src;
        let n = self.node(file, id);
        &src[(n.start as usize).min(src.len())..(n.end as usize).min(src.len())]
    }

    /// An identifier's name (empty for a node that is not one).
    fn ident(&self, file: u16, id: NodeId) -> PyStr {
        if id == NONE || self.node(file, id).kind != K::Ident {
            return Vec::new();
        }
        self.text(file, id).to_vec()
    }

    // ---------------------------------------------------------------- roots --
    /// Reads a function declaration as a root: its parameters not known.
    pub fn run_func(&mut self, file: u16, decl: NodeId) {
        self.call_decl(file, decl, Vec::new(), None, false);
    }

    /// Reads a package-level variable's initializer (it runs when the package is loaded).
    pub fn run_global(&mut self, pkg: u32, name: &[u32]) {
        let _ = self.global(pkg, name);
    }

    /// Evaluates a package-level ValueSpec's values: `var _ = f()` runs, with no name to read it by.
    pub fn eval_spec_values(&mut self, file: u16, spec: NodeId) {
        let pkg = self.k.files[file as usize].pkg;
        let mut frame = Frame { file, pkg, vars: HashMap::new(), ret: None };
        for &e in self.items(file, self.node(file, spec).f[2]) {
            self.eval(&mut frame, e);
        }
    }

    /// Calls a function declaration with `args` (`recv` for a method's receiver; `spread`: the last argument is a
    /// list passed to a variadic parameter, `f(xs...)`); its value.
    fn call_decl(&mut self, file: u16, decl: NodeId, args: Vec<Val>, recv: Option<Val>, spread: bool) -> Val {
        let key = (file, decl);
        if self.stack.len() >= self.max_depth || self.stack.contains(&key) || self.not_follow.contains(&key) || !self.step() {
            return args_kinds(&args);
        }
        // a decoder written out: base64's alphabet in its body
        if self.k.b64_fns.contains(&key) {
            if let Some(a) = args.iter().find(|a| a.known()).or(args.first()) {
                return events::decode_b64(a, 0);
            }
        }
        let d = self.node(file, decl);
        if d.kind != K::FuncDecl || d.f[3] == NONE {
            return args_kinds(&args);
        }
        self.reached.insert(key);
        self.stack.push(key);
        let pkg = self.k.files[file as usize].pkg;
        let mut frame = Frame { file, pkg, vars: HashMap::new(), ret: None };
        if d.f[0] != NONE {
            // the receiver's name
            if let Some(&field) = self.items(file, self.node(file, d.f[0]).f[0]).first() {
                if let Some(&name) = self.items(file, self.node(file, field).f[0]).first() {
                    let n = self.ident(file, name);
                    if !n.is_empty() {
                        frame.vars.insert(n, recv.unwrap_or_default());
                    }
                }
            }
        }
        self.bind_params(&mut frame, d.f[2], args, spread);
        self.exec_block(&mut frame, d.f[3]);
        self.stack.pop();
        frame.ret.unwrap_or_default()
    }

    /// Binds a function type's parameters to `args` (a variadic parameter takes the rest as a list).
    fn bind_params(&mut self, f: &mut Frame, ftype: NodeId, args: Vec<Val>, spread: bool) {
        if ftype == NONE {
            return;
        }
        let params = self.node(f.file, ftype).f[1];
        if params == NONE {
            return;
        }
        let fields = self.items(f.file, self.node(f.file, params).f[0]);
        let mut names: Vec<(PyStr, bool)> = Vec::new();
        for &field in fields {
            let fd = self.node(f.file, field);
            let variadic = fd.f[1] != NONE && self.node(f.file, fd.f[1]).kind == K::Ellipsis;
            let ns = self.items(f.file, fd.f[0]);
            if ns.is_empty() {
                names.push((Vec::new(), variadic));
            }
            for &n in ns {
                names.push((self.ident(f.file, n), variadic));
            }
        }
        // one call of several results given to several parameters: `f(g())`
        let args = if args.len() == 1 && names.len() > 1 && args[0].obj == Obj::Tuple {
            args[0].items.as_ref().map(|i| (**i).clone()).unwrap_or_default()
        } else {
            args
        };
        let mut it = args.into_iter();
        let count = names.len();
        for (k, (name, variadic)) in names.into_iter().enumerate() {
            let v = if variadic && k + 1 == count {
                if spread {
                    it.next().unwrap_or_default()
                } else {
                    Val::list(it.by_ref().collect())
                }
            } else {
                it.next().unwrap_or_default()
            };
            if !name.is_empty() && !eqs(&name, "_") {
                self.bind(f, name, v);
            }
        }
    }

    fn bind(&mut self, f: &mut Frame, name: PyStr, v: Val) {
        let mut v = v;
        if v.id == 0 && v.s.is_none() {
            v.id = self.fresh_id();
        }
        f.vars.insert(name, v);
    }

    // ---------------------------------------------------------------- globals --
    /// A package-level variable or constant's value: read from its declaration the first time it is used.
    fn global(&mut self, pkg: u32, name: &[u32]) -> Option<Val> {
        let key = (pkg, name.to_vec());
        if let Some(v) = self.globals.get(&key) {
            return Some(v.clone());
        }
        let k: &'k Module<'a> = self.k;
        let g = *k.pkgs.get(pkg as usize)?.globals.get(name)?;
        if self.no_init.contains(&key) {
            let mut v = Val::unknown();
            v.id = self.fresh_id();
            self.globals.insert(key, v.clone());
            return Some(v);
        }
        if self.global_stack.contains(&key) || self.global_stack.len() > 32 {
            return Some(Val::unknown());
        }
        self.global_stack.push(key.clone());
        let v = self.eval_global(pkg, name, g);
        self.global_stack.pop();
        self.globals.insert(key, v.clone());
        Some(v)
    }

    fn eval_global(&mut self, pkg: u32, name: &[u32], g: Global) -> Val {
        let at = self.node(g.file, g.spec).start;
        if g.embed {
            let mut v = Val::source(K_BYTES, name.to_vec(), at);
            v.id = self.fresh_id();
            return v;
        }
        let mut frame = Frame { file: g.file, pkg, vars: HashMap::new(), ret: None };
        if g.iota >= 0 {
            frame.vars.insert(u("iota"), Val::int(g.iota as i128));
        }
        if g.values == NONE {
            let spec = self.node(g.file, g.spec);
            return self.zero(g.file, spec.f[1]);
        }
        let vs = self.items(g.file, self.node(g.file, g.values).f[2]);
        let names = self.items(g.file, self.node(g.file, g.spec).f[0]).len();
        if vs.len() == names || vs.len() > 1 {
            match vs.get(g.index as usize) {
                Some(&e) => self.eval(&mut frame, e),
                None => Val::unknown(),
            }
        } else if let Some(&e) = vs.first() {
            let v = self.eval(&mut frame, e);
            self.spread(v, names).swap_remove(g.index as usize % names.max(1))
        } else {
            Val::unknown()
        }
    }

    /// A type's zero value, as far as the reader keeps one: a string or a builder is empty text, a slice an empty
    /// list.
    fn zero(&mut self, file: u16, ty: NodeId) -> Val {
        if ty == NONE {
            return Val::unknown();
        }
        let n = self.node(file, ty);
        match n.kind {
            K::Ident if eqs(self.text(file, ty), "string") => Val::text(Vec::new()),
            K::ArrayType if n.f[0] == NONE => Val::list(Vec::new()),
            K::SelectorExpr => {
                let x = self.ident(file, n.f[0]);
                let sel = self.ident(file, n.f[1]);
                let path = self.k.files[file as usize].imports.get(&x).cloned().unwrap_or_default();
                match (pystr::to_string(&path).as_str(), pystr::to_string(&sel).as_str()) {
                    ("strings", "Builder") | ("bytes", "Buffer") | ("net/url", "Values") => Val::text(Vec::new()),
                    ("net/http", "Client") | ("net", "Dialer") => Val::obj(Obj::Client),
                    ("net", "Resolver") => Val::obj(Obj::Resolver),
                    _ => Val::unknown(),
                }
            }
            _ => Val::unknown(),
        }
    }

    /// A value given to `n` names: a tuple's items, else the value and unknowns.
    fn spread(&mut self, v: Val, n: usize) -> Vec<Val> {
        let mut out: Vec<Val> = if v.obj == Obj::Tuple { v.items.as_ref().map(|i| (**i).clone()).unwrap_or_default() } else { vec![v] };
        out.resize_with(n.max(1), Val::unknown);
        out
    }

    // ---------------------------------------------------------------- statements --
    fn exec_block(&mut self, f: &mut Frame, block: NodeId) {
        if block == NONE {
            return;
        }
        let list = self.node(f.file, block).f[0];
        for &s in self.items(f.file, list) {
            if !self.step() {
                return;
            }
            self.exec(f, s);
        }
    }

    fn exec_list(&mut self, f: &mut Frame, list: u32) {
        for &s in self.items(f.file, list) {
            if !self.step() {
                return;
            }
            self.exec(f, s);
        }
    }

    fn exec(&mut self, f: &mut Frame, s: NodeId) {
        if s == NONE {
            return;
        }
        if self.nest >= MAX_NEST {
            self.cut = true;
            return;
        }
        self.nest += 1;
        self.exec_inner(f, s);
        self.nest -= 1;
    }

    fn exec_inner(&mut self, f: &mut Frame, s: NodeId) {
        let file = f.file;
        let n = self.node(file, s);
        match n.kind {
            K::ExprStmt => {
                self.eval(f, n.f[0]);
            }
            K::AssignStmt => self.assign_stmt(f, s),
            K::DeclStmt => self.decl_stmt(f, n.f[0]),
            K::IncDecStmt => {
                let v = self.eval(f, n.f[0]);
                if let Some(x) = v.int {
                    let d = if n.op == Tok::Inc as u8 { 1 } else { -1 };
                    self.assign_to(f, n.f[0], Val::int(x.saturating_add(d)), false);
                }
            }
            K::GoStmt | K::DeferStmt => {
                self.eval(f, n.f[0]);
            }
            K::ReturnStmt => {
                let rs = self.items(file, n.f[0]);
                let v = match rs.len() {
                    0 => Val::unknown(),
                    1 => self.eval(f, rs[0]),
                    _ => {
                        let vals: Vec<Val> = rs.iter().map(|&r| self.eval(f, r)).collect();
                        let mut t = Val::list(vals);
                        t.obj = Obj::Tuple;
                        t
                    }
                };
                f.ret = Some(match f.ret.take() {
                    Some(o) => o.union(&v),
                    None => v,
                });
            }
            K::BlockStmt => self.exec_block(f, s),
            K::IfStmt => {
                // an `else if` chain is walked, not nested
                let mut cur = s;
                loop {
                    let c = self.node(file, cur);
                    self.exec(f, c.f[0]);
                    self.eval(f, c.f[1]);
                    self.exec_block(f, c.f[2]);
                    let e = c.f[3];
                    if e == NONE || !self.step() {
                        break;
                    }
                    if self.node(file, e).kind == K::IfStmt {
                        cur = e;
                        continue;
                    }
                    self.exec(f, e);
                    break;
                }
            }
            K::SwitchStmt | K::TypeSwitchStmt => {
                self.exec(f, n.f[0]);
                if n.kind == K::SwitchStmt {
                    self.eval(f, n.f[1]);
                } else if n.f[1] != NONE {
                    // `x := y.(type)`: x is y in every case
                    let a = self.node(file, n.f[1]);
                    if a.kind == K::AssignStmt {
                        let lhs = self.items(file, a.f[0]);
                        let rhs = self.items(file, a.f[1]);
                        if let (Some(&l), Some(&r)) = (lhs.first(), rhs.first()) {
                            let x = self.node(file, r);
                            let v = if x.kind == K::TypeAssertExpr { self.eval(f, x.f[0]) } else { self.eval(f, r) };
                            let name = self.ident(file, l);
                            if !name.is_empty() {
                                self.bind(f, name, v);
                            }
                        }
                    } else {
                        self.exec(f, n.f[1]);
                    }
                }
                let body = n.f[2];
                if body != NONE {
                    for &cc in self.items(file, self.node(file, body).f[0]) {
                        let c = self.node(file, cc);
                        for &e in self.items(file, c.f[0]) {
                            if c.kind == K::CaseClause && n.kind == K::SwitchStmt {
                                self.eval(f, e);
                            }
                        }
                        self.exec_list(f, c.f[1]);
                    }
                }
            }
            K::SelectStmt => {
                let body = n.f[0];
                if body != NONE {
                    for &cc in self.items(file, self.node(file, body).f[0]) {
                        let c = self.node(file, cc);
                        self.exec(f, c.f[0]);
                        self.exec_list(f, c.f[1]);
                    }
                }
            }
            K::ForStmt => self.for_stmt(f, s),
            K::RangeStmt => self.range_stmt(f, s),
            K::LabeledStmt => self.exec(f, n.f[1]),
            K::SendStmt => {
                self.eval(f, n.f[0]);
                self.eval(f, n.f[1]);
            }
            _ => {}
        }
    }

    fn decl_stmt(&mut self, f: &mut Frame, decl: NodeId) {
        let file = f.file;
        let d = self.node(file, decl);
        if d.kind != K::GenDecl || !(d.op == Tok::Var as u8 || d.op == Tok::Const as u8) {
            return;
        }
        let constant = d.op == Tok::Const as u8;
        let mut last_values: u32 = NONE;
        for (iota, &spec) in self.items(file, d.f[0]).iter().enumerate() {
            let sp = self.node(file, spec);
            let names = self.items(file, sp.f[0]);
            let mut values = sp.f[2];
            if constant {
                if values == NONE {
                    values = last_values;
                } else {
                    last_values = values;
                }
                f.vars.insert(u("iota"), Val::int(iota as i128));
            }
            let vs = self.items(file, values);
            let vals: Vec<Val> = if vs.is_empty() {
                let z = self.zero(file, sp.f[1]);
                vec![z; names.len()]
            } else if vs.len() == names.len() {
                vs.iter().map(|&e| self.eval(f, e)).collect()
            } else {
                let v = self.eval(f, vs[0]);
                self.spread(v, names.len())
            };
            for (k, &nm) in names.iter().enumerate() {
                let name = self.ident(file, nm);
                if !name.is_empty() && !eqs(&name, "_") {
                    let v = vals.get(k).cloned().unwrap_or_default();
                    self.bind(f, name, v);
                }
            }
        }
    }

    fn assign_stmt(&mut self, f: &mut Frame, s: NodeId) {
        let file = f.file;
        let n = self.node(file, s);
        let lhs = self.items(file, n.f[0]);
        let rhs = self.items(file, n.f[1]);
        if n.op == Tok::Assign as u8 || n.op == Tok::Define as u8 {
            let vals: Vec<Val> = if rhs.len() == lhs.len() {
                rhs.iter().map(|&r| self.eval(f, r)).collect()
            } else if rhs.len() == 1 {
                let v = self.eval(f, rhs[0]);
                self.spread(v, lhs.len())
            } else {
                let mut v: Vec<Val> = rhs.iter().map(|&r| self.eval(f, r)).collect();
                v.resize_with(lhs.len(), Val::unknown);
                v
            };
            for (k, &l) in lhs.iter().enumerate() {
                self.assign_to(f, l, vals.get(k).cloned().unwrap_or_default(), n.op == Tok::Define as u8);
            }
            return;
        }
        // `x op= y`
        let (Some(&l), Some(&r)) = (lhs.first(), rhs.first()) else { return };
        let op = compound(n.op);
        let v = self.eval(f, r);
        let old = self.eval(f, l);
        let new = self.binary(op, &old, &v);
        self.assign_to(f, l, new, false);
    }

    /// `lhs = v`: a name (the function's, else the package's), an element (`b[i] = …`: the list changed), a field (a
    /// command's input, output or attributes; else the value's data kept on its name).
    fn assign_to(&mut self, f: &mut Frame, lhs: NodeId, v: Val, define: bool) {
        let file = f.file;
        let n = self.node(file, lhs);
        match n.kind {
            K::Ident => {
                let name = self.text(file, lhs).to_vec();
                if eqs(&name, "_") {
                    return;
                }
                if !define && !f.vars.contains_key(&name) && self.k.pkgs[f.pkg as usize].globals.contains_key(&name) {
                    let mut v = v;
                    if v.id == 0 && v.s.is_none() {
                        v.id = self.fresh_id();
                    }
                    self.globals.insert((f.pkg, name), v);
                    return;
                }
                self.bind(f, name, v);
            }
            K::ParenExpr => self.assign_to(f, n.f[0], v, define),
            K::IndexExpr => {
                let base = n.f[0];
                let old = self.eval(f, base);
                let idx = self.eval(f, n.f[1]);
                let new = match (&old.items, idx.int) {
                    (Some(items), Some(k)) if old.obj != Obj::Map && k >= 0 && (k as usize) < items.len() => {
                        let mut it: Vec<Val> = (**items).clone();
                        it[k as usize] = v.clone();
                        let mut l = Val::list(it);
                        l.add_kinds(&old);
                        l.id = old.id;
                        l
                    }
                    (_, _) if old.obj == Obj::Map && idx.s.is_some() => {
                        let mut it: Vec<Val> = old.items.as_ref().map(|i| (**i).clone()).unwrap_or_default();
                        let key = idx.s.clone().unwrap_or_default();
                        it.retain(|p| p.items.as_ref().and_then(|x| x.first()).and_then(|k| k.s.as_ref()) != Some(&key));
                        it.push(Val::list(vec![idx.clone(), v.clone()]));
                        let mut m = Val::list(it);
                        m.obj = Obj::Map;
                        m.add_kinds(&old);
                        m
                    }
                    _ => {
                        let mut l = old.clone().with_kinds(&v);
                        if v.kinds & K_DECODED != 0 {
                            l = l.decoded(0);
                        }
                        l
                    }
                };
                self.assign_to(f, base, new, false);
            }
            K::SelectorExpr => {
                let base = n.f[0];
                if self.import_of(f, base).is_some() {
                    return; // a package's variable (`os.Stdout = …`)
                }
                let field = self.ident(file, n.f[1]);
                let obj = self.eval(f, base);
                if let Obj::Cmd(c) = obj.obj {
                    let fname = pystr::to_string(&field);
                    let shell = self.cmds.get(c as usize).is_some_and(|st| {
                        let prog = pystr::lower(&st.prog.text_or_unknown());
                        let base: PyStr = prog.iter().rposition(|&ch| ch == '/' as u32 || ch == '\\' as u32).map(|k| prog[k + 1..].to_vec()).unwrap_or(prog.clone());
                        events::SHELLS.iter().any(|s| eqs(&base, s)) || ["cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"].iter().any(|s| eqs(&base, s))
                    });
                    if let Some(st) = self.cmds.get_mut(c as usize) {
                        match fname.as_str() {
                            // (a shell's input is the script it runs: `cmd.Stdin = resp.Body`)
                            "Stdin" if shell && !matches!(v.obj, Obj::Conn(_)) && st.args.is_empty() && (v.kinds != 0 || v.s.is_some()) => {
                                let mut script = v.clone();
                                if script.obj == Obj::Resp {
                                    script = events::received(st.at, &v).with_kinds(&v);
                                }
                                script.obj = Obj::None;
                                st.args = vec![Val::text(u("-c")), script];
                            }
                            "Stdin" | "Stdout" | "Stderr" => st.conn_io |= matches!(v.obj, Obj::Conn(_)),
                            "SysProcAttr" => st.hidden |= v.obj == Obj::Hidden,
                            "Path" => st.prog = v.clone(),
                            "Args" => {
                                if let Some(items) = &v.items {
                                    st.args = items.iter().skip(1).cloned().collect();
                                }
                            }
                            _ => {}
                        }
                    }
                    return;
                }
                if obj.obj == Obj::Map {
                    // a field of a struct with its fields named
                    let mut it: Vec<Val> = obj.items.as_ref().map(|i| (**i).clone()).unwrap_or_default();
                    it.retain(|p| p.items.as_ref().and_then(|x| x.first()).and_then(|k| k.s.as_ref()).map(|k| k.as_slice()) != Some(field.as_slice()));
                    it.push(Val::list(vec![Val::text(field), v.clone()]));
                    let mut m = Val::list(it);
                    m.obj = Obj::Map;
                    m.add_kinds(&obj);
                    self.assign_to(f, base, m, false);
                    return;
                }
                if matches!(obj.obj, Obj::None) && self.node(file, base).kind == K::Ident {
                    let new = obj.with_kinds(&v);
                    self.assign_to(f, base, new, false);
                }
            }
            K::StarExpr | K::UnaryExpr => {
                let base = n.f[0];
                if base != NONE && self.node(file, base).kind == K::Ident {
                    // `*p = v`: the pointer's name stands for what it points to
                    self.assign_to(f, base, v, false);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------- loops --
    /// Does a loop's body only compute (assignments and expressions with no call but a conversion or a built-in)? A
    /// decoder's loop does; such a body is read for each index (up to COMPUTE_ITEMS).
    fn computes_only(&self, file: u16, body: NodeId) -> bool {
        if body == NONE {
            return false;
        }
        let tree = &self.k.files[file as usize].tree;
        let mut stack = vec![body];
        let mut kids: Vec<u32> = Vec::new();
        let mut seen = 0usize;
        while let Some(id) = stack.pop() {
            seen += 1;
            if seen > 4_096 {
                return false;
            }
            let n = tree.node(id);
            match n.kind {
                K::CallExpr => {
                    let fun = tree.node(n.f[0]);
                    let ok = match fun.kind {
                        K::Ident => {
                            let name = self.text(file, n.f[0]);
                            BASIC.iter().any(|b| eqs(name, b)) || ["len", "append", "cap", "min", "max", "copy"].iter().any(|b| eqs(name, b))
                        }
                        K::ArrayType => true,
                        _ => false,
                    };
                    if !ok {
                        return false;
                    }
                }
                K::GoStmt | K::DeferStmt | K::FuncLit | K::SendStmt | K::ReturnStmt | K::LabeledStmt | K::SelectStmt => return false,
                _ => {}
            }
            kids.clear();
            tree.each_child(id, &mut |x| kids.push(x));
            stack.extend(kids.iter().rev());
        }
        true
    }

    fn for_stmt(&mut self, f: &mut Frame, s: NodeId) {
        let file = f.file;
        let n = self.node(file, s);
        self.exec(f, n.f[0]);
        // a counted loop, `for i := a; i < b; i++`, whose body only computes: read for each i
        if let Some((name, from, to)) = self.counted(f, s) {
            if self.computes_only(file, n.f[3]) && to > from && (to - from) as usize <= COMPUTE_ITEMS {
                for i in from..to {
                    if self.out_of_steps() {
                        return;
                    }
                    f.vars.insert(name.clone(), Val::int(i));
                    self.exec_block(f, n.f[3]);
                }
                return;
            }
        }
        self.eval(f, n.f[1]);
        self.exec_block(f, n.f[3]);
        self.exec(f, n.f[2]);
    }

    /// `for i := a; i < b; i++` (`<=`, `len(x)` and constants read): (i, a, b).
    fn counted(&mut self, f: &mut Frame, s: NodeId) -> Option<(PyStr, i128, i128)> {
        let file = f.file;
        let n = self.node(file, s);
        if n.f[0] == NONE || n.f[1] == NONE || n.f[2] == NONE {
            return None;
        }
        let init = self.node(file, n.f[0]);
        if init.kind != K::AssignStmt {
            return None;
        }
        let name = self.ident(file, *self.items(file, init.f[0]).first()?);
        let from = f.vars.get(&name)?.int?;
        let cond = self.node(file, n.f[1]);
        if cond.kind != K::BinaryExpr || self.ident(file, cond.f[0]) != name {
            return None;
        }
        let bound = self.eval(f, cond.f[1]).int?;
        let to = if cond.op == Tok::Lss as u8 {
            bound
        } else if cond.op == Tok::Leq as u8 {
            bound + 1
        } else {
            return None;
        };
        let post = self.node(file, n.f[2]);
        if !(post.kind == K::IncDecStmt && post.op == Tok::Inc as u8 && self.ident(file, post.f[0]) == name) {
            return None;
        }
        Some((name, from, to))
    }

    fn range_stmt(&mut self, f: &mut Frame, s: NodeId) {
        let file = f.file;
        let n = self.node(file, s);
        let x = self.eval(f, n.f[2]);
        let (key, value, body) = (n.f[0], n.f[1], n.f[3]);
        // what is ranged over: a list's items, a string's code points, a number's 0 … n-1
        let items: Option<Vec<Val>> = match (&x.items, &x.s, x.int) {
            (Some(items), _, _) if x.obj != Obj::Map => Some(items.iter().cloned().collect()),
            (Some(items), _, _) => Some(items.iter().map(|p| item_of(p, 1)).collect()),
            (None, Some(s), _) if !s.contains(&UNKNOWN) => Some(
                s.iter()
                    .map(|&c| {
                        let mut v = Val::text(vec![c]).with_kinds(&x);
                        v.int = Some(c as i128);
                        v
                    })
                    .collect(),
            ),
            (None, None, Some(k)) if (0..=COMPUTE_ITEMS as i128).contains(&k) => Some((0..k).map(Val::int).collect()),
            _ => None,
        };
        let keys: Option<Vec<Val>> = if x.obj == Obj::Map { x.items.as_ref().map(|i| i.iter().map(|p| item_of(p, 0)).collect()) } else { None };
        match items {
            Some(items) if !items.is_empty() => {
                let limit = if self.computes_only(file, body) { COMPUTE_ITEMS } else { LOOP_ITEMS };
                for (k, it) in items.into_iter().take(limit).enumerate() {
                    if self.out_of_steps() {
                        return;
                    }
                    let kv = match &keys {
                        Some(ks) => ks.get(k).cloned().unwrap_or_default(),
                        None if x.int.is_some() => it.clone(),
                        None => Val::int(k as i128),
                    };
                    if key != NONE {
                        self.assign_to(f, key, kv, n.op == Tok::Define as u8);
                    }
                    if value != NONE {
                        self.assign_to(f, value, it, n.op == Tok::Define as u8);
                    }
                    self.exec_block(f, body);
                }
            }
            _ => {
                if key != NONE {
                    self.assign_to(f, key, Val::unknown(), n.op == Tok::Define as u8);
                }
                if value != NONE {
                    let el = derived(&x);
                    self.assign_to(f, value, el, n.op == Tok::Define as u8);
                }
                self.exec_block(f, body);
            }
        }
    }

    // ---------------------------------------------------------------- expressions --
    fn eval(&mut self, f: &mut Frame, e: NodeId) -> Val {
        if e == NONE || !self.step() {
            return Val::unknown();
        }
        if self.nest >= MAX_NEST {
            self.cut = true;
            return Val::unknown();
        }
        self.nest += 1;
        let v = self.eval_inner(f, e);
        self.nest -= 1;
        v
    }

    fn eval_inner(&mut self, f: &mut Frame, e: NodeId) -> Val {
        let file = f.file;
        let n = self.node(file, e);
        match n.kind {
            K::Ident => self.ident_value(f, e),
            K::BasicLit => {
                let t = self.text(file, e);
                match n.op {
                    x if x == Tok::Str as u8 => lit::string_lit(t).map(Val::text).unwrap_or_default(),
                    x if x == Tok::Char as u8 => match lit::rune_lit(t) {
                        Some(c) => {
                            let mut v = Val::text(vec![c]);
                            v.int = Some(c as i128);
                            v
                        }
                        None => Val::unknown(),
                    },
                    x if x == Tok::Int as u8 => lit::int_lit(t).map(Val::int).unwrap_or_default(),
                    _ => Val::unknown(),
                }
            }
            K::CompositeLit => self.composite(f, e),
            K::FuncLit => self.closure(f, e, false),
            K::ParenExpr | K::StarExpr | K::TypeAssertExpr | K::IndexListExpr => self.eval(f, n.f[0]),
            K::KeyValueExpr => self.eval(f, n.f[1]),
            K::SelectorExpr => self.selector(f, e),
            K::IndexExpr => {
                let v = self.eval(f, n.f[0]);
                let i = self.eval(f, n.f[1]);
                if v.obj == Obj::Map {
                    return match i.s.as_ref().and_then(|k| map_get(&v, k)) {
                        Some(x) => x,
                        None => derived(&v).with_kinds(&i),
                    };
                }
                if let (Some(items), Some(k)) = (&v.items, i.int) {
                    if k >= 0 {
                        return items.get(k as usize).cloned().unwrap_or_else(|| derived(&v));
                    }
                }
                if let (Some(s), Some(k)) = (&v.s, i.int) {
                    // a string indexed is a byte
                    if k >= 0 && !s.contains(&UNKNOWN) {
                        let b = val::bytes_of(s);
                        if let Some(&x) = b.get(k as usize) {
                            return Val::int(x as i128).with_kinds(&v);
                        }
                    }
                }
                if matches!(v.obj, Obj::Closure(_)) {
                    return v; // a generic function instantiated: `f[T]`
                }
                derived(&v).with_kinds(&i)
            }
            K::SliceExpr => {
                let v = self.eval(f, n.f[0]);
                let lo = if n.f[1] == NONE { Some(0) } else { self.eval(f, n.f[1]).int };
                let hi = if n.f[2] == NONE { None } else { self.eval(f, n.f[2]).int };
                if n.f[3] != NONE {
                    self.eval(f, n.f[3]);
                }
                if let (Some(items), Some(lo)) = (&v.items, lo) {
                    let len = items.len() as i128;
                    let hi = hi.unwrap_or(len);
                    if 0 <= lo && lo <= hi && hi <= len {
                        let mut out = Val::list(items[lo as usize..hi as usize].to_vec()).with_kinds(&v);
                        if let Some(s) = &v.s {
                            if s.len() == items.len() {
                                out.s = Some(Rc::new(s[lo as usize..hi as usize].to_vec()));
                            }
                        }
                        return out;
                    }
                }
                if let (Some(s), Some(lo)) = (&v.s, lo) {
                    if !s.contains(&UNKNOWN) {
                        let b = val::bytes_of(s);
                        let len = b.len() as i128;
                        let hi = hi.unwrap_or(len);
                        if 0 <= lo && lo <= hi && hi <= len {
                            return Val::text(val::utf8(&b[lo as usize..hi as usize])).with_kinds(&v);
                        }
                    }
                }
                derived(&v)
            }
            K::CallExpr => self.call(f, e),
            K::UnaryExpr => {
                let v = self.eval(f, n.f[0]);
                match n.op {
                    x if x == Tok::Sub as u8 => v.int.map(|i| Val::int(-i)).unwrap_or_else(|| derived(&v)),
                    x if x == Tok::Xor as u8 => v.int.map(|i| Val::int(!i).decoded(0)).unwrap_or_else(|| derived(&v)),
                    x if x == Tok::And as u8 || x == Tok::Add as u8 => v,
                    x if x == Tok::Arrow as u8 => derived(&v),
                    _ => Val::unknown(),
                }
            }
            K::BinaryExpr => {
                // the left spine walked, not recursed: `a + b + c …` is as deep as it is long
                let mut spine: Vec<(u8, NodeId)> = Vec::new();
                let mut cur = e;
                loop {
                    let c = self.node(file, cur);
                    if c.kind != K::BinaryExpr {
                        break;
                    }
                    spine.push((c.op, c.f[1]));
                    cur = c.f[0];
                }
                let mut v = self.eval(f, cur);
                for &(op, y) in spine.iter().rev() {
                    if self.out_of_steps() {
                        return Val::unknown();
                    }
                    let w = self.eval(f, y);
                    v = self.binary(op, &v, &w);
                }
                v
            }
            _ => Val::unknown(),
        }
    }

    fn binary(&mut self, op: u8, x: &Val, y: &Val) -> Val {
        let t = |k: Tok| k as u8;
        if op == t(Tok::Add) && (x.s.is_some() || y.s.is_some()) && !(x.int.is_some() && y.int.is_some() && x.items.is_none()) {
            let v = Val::concat(x, y);
            self.charge(v.s.as_ref().map_or(0, |s| s.len()));
            return v;
        }
        if let (Some(a), Some(b)) = (x.int, y.int) {
            let n = match op {
                o if o == t(Tok::Add) => a.checked_add(b),
                o if o == t(Tok::Sub) => a.checked_sub(b),
                o if o == t(Tok::Mul) => a.checked_mul(b),
                o if o == t(Tok::Quo) => a.checked_div(b),
                o if o == t(Tok::Rem) => a.checked_rem(b),
                o if o == t(Tok::Xor) => Some(a ^ b),
                o if o == t(Tok::And) => Some(a & b),
                o if o == t(Tok::Or) => Some(a | b),
                o if o == t(Tok::AndNot) => Some(a & !b),
                o if o == t(Tok::Shl) => (0..127).contains(&b).then(|| a.wrapping_shl(b as u32)),
                o if o == t(Tok::Shr) => (0..127).contains(&b).then(|| a >> b),
                _ => None,
            };
            if let Some(n) = n {
                let mut v = Val::int(n);
                v.add_kinds(x);
                v.add_kinds(y);
                if op == t(Tok::Xor) {
                    return v.decoded(0);
                }
                return v;
            }
        }
        let mut v = Val::unknown();
        v.add_kinds(x);
        v.add_kinds(y);
        if op == t(Tok::Xor) {
            v = v.decoded(0);
        }
        v
    }

    /// A name's value: the function's, the package's (a variable, a constant, a function), else unknown.
    fn ident_value(&mut self, f: &mut Frame, id: NodeId) -> Val {
        let name = self.text(f.file, id);
        if let Some(v) = f.vars.get(name) {
            return v.clone();
        }
        if eqs(name, "nil") || eqs(name, "true") || eqs(name, "false") {
            return Val::unknown();
        }
        if let Some(v) = self.global(f.pkg, name) {
            return v;
        }
        if let Some(&(file, decl)) = self.k.pkgs[f.pkg as usize].funcs.get(name).and_then(|c| c.first()) {
            return self.func_value(file, decl);
        }
        Val::unknown()
    }

    /// A function declaration as a value (`go run`, `handler := f`).
    fn func_value(&mut self, file: u16, decl: NodeId) -> Val {
        if self.closures.len() >= MAX_CLOSURES {
            self.cut = true;
            return Val::unknown();
        }
        let idx = self.closures.len() as u32;
        let pkg = self.k.files[file as usize].pkg;
        self.closures.push(ClosureState { file, pkg, node: decl, decl: true, env: HashMap::new(), creator: None });
        Val::obj(Obj::Closure(idx))
    }

    fn closure(&mut self, f: &mut Frame, lit: NodeId, _call: bool) -> Val {
        if self.closures.len() >= MAX_CLOSURES {
            self.cut = true;
            return Val::unknown();
        }
        let idx = self.closures.len() as u32;
        self.charge(f.vars.len() * 16);
        self.closures.push(ClosureState { file: f.file, pkg: f.pkg, node: lit, decl: false, env: f.vars.clone(), creator: self.stack.last().copied() });
        Val::obj(Obj::Closure(idx))
    }

    /// Calls a closure from the frame `caller`: a closure made by the function `caller` reads sees that function's
    /// names as they are now, and what it assigns to them is theirs when it returns (Go's closures share their
    /// variables).
    fn call_closure(&mut self, idx: u32, args: Vec<Val>, spread: bool, caller: Option<&mut Frame>) -> Val {
        let Some(c) = self.closures.get(idx as usize) else { return Val::unknown() };
        let (file, pkg, node, creator, decl) = (c.file, c.pkg, c.node, c.creator, c.decl);
        if decl {
            return self.call_decl(file, node, args, None, spread);
        }
        let mut env = c.env.clone();
        if self.stack.len() >= self.max_depth || !self.step() {
            return args_kinds(&args);
        }
        self.charge(env.len() * 16);
        let shared = creator.is_some() && creator == self.stack.last().copied();
        let mut caller = caller;
        if shared {
            if let Some(cf) = caller.as_deref() {
                for (k, v) in cf.vars.iter() {
                    env.insert(k.clone(), v.clone());
                }
            }
        }
        let lit = self.node(file, node);
        let mut frame = Frame { file, pkg, vars: env, ret: None };
        self.bind_params(&mut frame, lit.f[0], args, spread);
        self.stack.push((u16::MAX, idx));
        self.exec_block(&mut frame, lit.f[1]);
        self.stack.pop();
        if shared {
            if let Some(cf) = caller.as_deref_mut() {
                for (k, v) in frame.vars.iter() {
                    if cf.vars.contains_key(k) {
                        cf.vars.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        frame.ret.unwrap_or_default()
    }

    /// The import path a name stands for in `f`'s file, when it names an import and nothing of the function's or the
    /// package's.
    fn import_of(&self, f: &Frame, x: NodeId) -> Option<PyStr> {
        if self.node(f.file, x).kind != K::Ident {
            return None;
        }
        let name = self.text(f.file, x);
        if f.vars.contains_key(name) || self.k.pkgs[f.pkg as usize].globals.contains_key(name) {
            return None;
        }
        if eqs(name, "C") {
            return Some(u("C"));
        }
        self.k.files[f.file as usize].imports.get(name).cloned()
    }

    fn selector(&mut self, f: &mut Frame, e: NodeId) -> Val {
        let file = f.file;
        let n = self.node(file, e);
        let sel = self.ident(file, n.f[1]);
        if let Some(path) = self.import_of(f, n.f[0]) {
            return self.api_value(&path, &sel, n.start);
        }
        let v = self.eval(f, n.f[0]);
        self.field(&v, &sel, n.start)
    }

    /// A package's name: the module's own package's variable or function, or what the standard library's is.
    fn api_value(&mut self, path: &[u32], name: &[u32], at: u32) -> Val {
        if let Some(&pkg) = self.k.by_path.get(path) {
            if let Some(v) = self.global(pkg, name) {
                return v;
            }
            if let Some(&(file, decl)) = self.k.pkgs[pkg as usize].funcs.get(name).and_then(|c| c.first()) {
                return self.func_value(file, decl);
            }
            return Val::unknown();
        }
        let p = pystr::to_string(path);
        let n = pystr::to_string(name);
        match (p.as_str(), n.as_str()) {
            ("runtime", "GOOS") => Val::text(u("linux")),
            ("runtime", "GOARCH") => Val::text(u("amd64")),
            ("os", "O_RDONLY") => Val::int(0),
            ("os", "O_WRONLY") => Val::int(1),
            ("os", "O_RDWR") => Val::int(2),
            ("os", "O_APPEND") => Val::int(0x400),
            ("os", "O_CREATE") => Val::int(0x40),
            ("os", "O_EXCL") => Val::int(0x80),
            ("os", "O_SYNC") => Val::int(0x101000),
            ("os", "O_TRUNC") => Val::int(0x200),
            ("os", "DevNull") => Val::text(u("/dev/null")),
            ("os", "PathSeparator") | ("path/filepath", "Separator") => {
                let mut v = Val::text(u("/"));
                v.int = Some('/' as i128);
                v
            }
            ("os", "Args") => {
                let mut v = Val::unknown();
                v.items = Some(Rc::new(Vec::new()));
                v
            }
            ("encoding/base64", "StdEncoding" | "URLEncoding" | "RawStdEncoding" | "RawURLEncoding") => Val::obj(Obj::B64),
            ("net/http", "DefaultClient") => Val::obj(Obj::Client),
            ("net/http", "MethodGet") => Val::text(u("GET")),
            ("net/http", "MethodPost") => Val::text(u("POST")),
            ("net/http", "MethodPut") => Val::text(u("PUT")),
            ("net", "DefaultResolver") => Val::obj(Obj::Resolver),
            ("syscall" | "golang.org/x/sys/windows", "CREATE_NO_WINDOW") => Val::int(0x0800_0000),
            ("syscall" | "golang.org/x/sys/windows", "DETACHED_PROCESS") => Val::int(0x8),
            _ => {
                let _ = at;
                Val::unknown()
            }
        }
    }

    /// A field of a value: a handle's (a response's body, a request's header, a user's name and home), a struct's
    /// with its fields named, else what the value carries.
    fn field(&mut self, v: &Val, name: &[u32], at: u32) -> Val {
        let n = pystr::to_string(name);
        match v.obj {
            Obj::Resp => {
                if n == "Body" {
                    return v.clone();
                }
                return derived(v);
            }
            Obj::Req(_) => {
                if matches!(n.as_str(), "Header" | "URL" | "Form" | "PostForm" | "Body") {
                    return v.clone();
                }
                return derived(v);
            }
            Obj::User => {
                return match n.as_str() {
                    "Username" | "Name" | "Uid" | "Gid" => Val::source(K_IDENTITY, name.to_vec(), at),
                    "HomeDir" => {
                        let mut h = Val::text(u("~"));
                        h.add_kinds(&Val::source(K_PATH, u("home"), at));
                        h
                    }
                    _ => derived(v),
                };
            }
            Obj::Map => {
                if let Some(x) = map_get(v, name) {
                    return x;
                }
            }
            _ => {}
        }
        derived(v)
    }

    // ---------------------------------------------------------------- literals --
    fn composite(&mut self, f: &mut Frame, e: NodeId) -> Val {
        let file = f.file;
        let n = self.node(file, e);
        let ty = n.f[0];
        let elts = self.items(file, n.f[1]);
        let tk = if ty == NONE { None } else { Some(self.node(file, ty)) };
        // a type the reader knows: a client, a dialer, a resolver, process attributes, a command, a builder, a URL
        if let Some(t) = tk {
            if t.kind == K::SelectorExpr {
                let x = self.ident(file, t.f[0]);
                let sel = pystr::to_string(&self.ident(file, t.f[1]));
                let path = self.k.files[file as usize].imports.get(&x).cloned().map(|p| pystr::to_string(&p)).unwrap_or_default();
                let known = matches!(
                    (path.as_str(), sel.as_str()),
                    ("net/http", "Client" | "Transport") | ("net", "Dialer" | "Resolver") | ("syscall" | "golang.org/x/sys/windows", "SysProcAttr") | ("os/exec", "Cmd")
                        | ("strings", "Builder") | ("bytes", "Buffer") | ("net/url", "Values" | "URL")
                );
                if !known {
                    return self.literal_value(f, tk, elts);
                }
                if (path.as_str(), sel.as_str()) == ("net/url", "Values") {
                    // `url.Values{"k": {"v"}}`: the form it encodes, `k=v&…`
                    let mut text = Val::text(Vec::new());
                    for &x in elts {
                        let xn = self.node(file, x);
                        if xn.kind != K::KeyValueExpr {
                            continue;
                        }
                        let key = self.eval(f, xn.f[0]);
                        let vals = self.eval(f, xn.f[1]);
                        let items: Vec<Val> = vals.items.as_ref().map(|i| (**i).clone()).unwrap_or_else(|| vec![vals.clone()]);
                        for it in items {
                            if text.s.as_ref().is_some_and(|s| !s.is_empty()) {
                                text = Val::concat(&text, &Val::text(u("&")));
                            }
                            text = Val::concat(&Val::concat(&Val::concat(&text, &key), &Val::text(u("="))), &it);
                        }
                    }
                    return text;
                }
                let fields = self.named_fields(f, elts);
                let get = |k: &str| fields.iter().find(|(n, _)| eqs(n, k)).map(|(_, v)| v.clone());
                match (path.as_str(), sel.as_str()) {
                    ("net/http", "Client") | ("net/http", "Transport") | ("net", "Dialer") => return Val::obj(Obj::Client),
                    ("net", "Resolver") => return Val::obj(Obj::Resolver),
                    ("syscall" | "golang.org/x/sys/windows", "SysProcAttr") => {
                        // a window hidden, or no console: CREATE_NO_WINDOW, DETACHED_PROCESS
                        let hide = self.field_true(f, elts, "HideWindow") || get("CreationFlags").and_then(|v| v.int).is_some_and(|x| x & 0x0800_0008 != 0);
                        return if hide { Val::obj(Obj::Hidden) } else { Val::unknown() };
                    }
                    ("os/exec", "Cmd") => {
                        let prog = get("Path").unwrap_or_default();
                        let args: Vec<Val> = get("Args").and_then(|a| a.items.as_ref().map(|i| i.iter().skip(1).cloned().collect())).unwrap_or_default();
                        let at = n.start;
                        let c = self.new_cmd(prog, file, at);
                        if let Obj::Cmd(i) = c.obj {
                            if let Some(st) = self.cmds.get_mut(i as usize) {
                                st.args = args;
                            }
                        }
                        return c;
                    }
                    ("strings", "Builder") | ("bytes", "Buffer") => return Val::text(Vec::new()),
                    ("net/url", "URL") => {
                        let scheme = get("Scheme").map(|v| v.text_or_unknown()).unwrap_or_default();
                        let host = get("Host").unwrap_or_default();
                        let path = get("Path").map(|v| v.text_or_unknown()).unwrap_or_default();
                        let mut s = scheme.clone();
                        if !s.is_empty() {
                            s.extend(u("://"));
                        }
                        s.extend(host.text_or_unknown());
                        s.extend(path);
                        let mut v = Val::text(val::collapse(s));
                        for (_, x) in &fields {
                            v.add_kinds(x);
                        }
                        return v;
                    }
                    _ => {}
                }
            }
        }
        self.literal_value(f, tk, elts)
    }

    /// A composite literal of a type the reader does not know: a map's or a named struct's pairs, else a list.
    fn literal_value(&mut self, f: &mut Frame, tk: Option<Node>, elts: &[u32]) -> Val {
        let file = f.file;
        let is_map = tk.is_some_and(|t| t.kind == K::MapType);
        let keyed = elts.iter().any(|&x| self.node(file, x).kind == K::KeyValueExpr);
        let list_like = tk.map_or(true, |t| matches!(t.kind, K::ArrayType | K::Ellipsis));
        if is_map || (keyed && !list_like) {
            // a map, or a struct with its fields named: [key, value] pairs
            let mut pairs = Vec::new();
            let mut kinds = Val::unknown();
            for &x in elts {
                let xn = self.node(file, x);
                if xn.kind != K::KeyValueExpr {
                    let v = self.eval(f, x);
                    kinds.add_kinds(&v);
                    continue;
                }
                let key = if !is_map && self.node(file, xn.f[0]).kind == K::Ident { Val::text(self.ident(file, xn.f[0])) } else { self.eval(f, xn.f[0]) };
                let v = self.eval(f, xn.f[1]);
                kinds.add_kinds(&v);
                pairs.push(Val::list(vec![key, v]));
                if self.out_of_steps() {
                    break;
                }
            }
            let mut m = Val::list(pairs);
            m.add_kinds(&kinds);
            m.obj = Obj::Map;
            return m;
        }
        // a list: in order, or at the indexes its keys give
        let mut out: Vec<Val> = Vec::with_capacity(elts.len().min(val::MAX_ITEMS));
        let mut next = 0usize;
        for &x in elts {
            if self.out_of_steps() {
                break;
            }
            let xn = self.node(file, x);
            let (at, v) = if xn.kind == K::KeyValueExpr {
                let k = self.eval(f, xn.f[0]).int;
                let v = self.eval(f, xn.f[1]);
                match k {
                    Some(k) if (0..val::MAX_ITEMS as i128).contains(&k) => (k as usize, v),
                    _ => (next, v),
                }
            } else {
                (next, self.eval(f, x))
            };
            if at >= val::MAX_ITEMS {
                break;
            }
            if at >= out.len() {
                out.resize_with(at + 1, || Val::int(0));
            }
            out[at] = v;
            next = at + 1;
        }
        Val::list(out)
    }

    /// The fields of a struct literal written `Name: value`, evaluated.
    fn named_fields(&mut self, f: &mut Frame, elts: &[u32]) -> Vec<(PyStr, Val)> {
        let mut out = Vec::new();
        for &x in elts {
            let xn = self.node(f.file, x);
            if xn.kind == K::KeyValueExpr {
                let name = self.ident(f.file, xn.f[0]);
                let v = self.eval(f, xn.f[1]);
                out.push((name, v));
            } else {
                self.eval(f, x);
            }
        }
        out
    }

    /// Is a struct literal's field written `Name: true`?
    fn field_true(&self, f: &Frame, elts: &[u32], name: &str) -> bool {
        elts.iter().any(|&x| {
            let xn = self.node(f.file, x);
            xn.kind == K::KeyValueExpr && eqs(&self.ident(f.file, xn.f[0]), name) && eqs(self.text(f.file, xn.f[1]), "true")
        })
    }

    // ---------------------------------------------------------------- sinks --
    fn new_cmd(&mut self, prog: Val, file: u16, at: u32) -> Val {
        let idx = self.cmds.len() as u32;
        self.cmds.push(CmdState { prog, args: Vec::new(), file, at, ..CmdState::default() });
        Val::obj(Obj::Cmd(idx))
    }

    fn run_cmd(&mut self, idx: u32) {
        let Some(c) = self.cmds.get_mut(idx as usize) else { return };
        if c.ran {
            return;
        }
        c.ran = true;
        let c = c.clone();
        for e in events::run_events(&c) {
            self.ev(e);
        }
    }

    /// Commands built but never seen run: run where they were built (a command is built to be run).
    pub fn flush_cmds(&mut self) {
        for k in 0..self.cmds.len() {
            self.run_cmd(k as u32);
        }
    }

    fn write_to(&mut self, w: &Val, data: &Val, file: u16, at: u32) {
        match w.obj {
            Obj::WFile(k) => {
                let st = self.wfiles.get(k as usize).cloned().unwrap_or_default();
                self.ev(Ev::Write { file, at, path: st.path, data: data.clone(), append: st.append });
            }
            Obj::Conn(k) => {
                let st = self.conns.get(k as usize).cloned().unwrap_or_default();
                self.ev(Ev::Send { file, at, data: data.clone(), dest: st.addr, in_address: false });
            }
            Obj::Req(k) => {
                if let Some(st) = self.reqs.get_mut(k as usize) {
                    st.body = Val::concat(&st.body, data).with_kinds(data);
                }
            }
            _ => {}
        }
    }

    fn send(&mut self, file: u16, at: u32, url: &Val, body: &Val) -> Val {
        for e in events::send_events(file, at, url, body) {
            self.ev(e);
        }
        let mut r = events::received(at, url);
        r.obj = Obj::Resp;
        r
    }

    fn connect(&mut self, file: u16, at: u32, addr: Val) -> Val {
        let idx = self.conns.len() as u32;
        self.conns.push(ConnState { addr: addr.clone() });
        self.ev(Ev::Send { file, at, data: addr.clone(), dest: addr, in_address: true });
        Val::obj(Obj::Conn(idx))
    }

    fn lookup(&mut self, file: u16, at: u32, name: Val, txt: bool) -> Val {
        // (a host and its port: the host is looked up)
        let name = match &name.s {
            Some(s) => match s.iter().rposition(|&c| c == ':' as u32) {
                Some(k) if k + 1 < s.len() && s[k + 1..].iter().all(|&c| ('0' as u32..='9' as u32).contains(&c)) => Val::text(s[..k].to_vec()).with_kinds(&name),
                _ => name,
            },
            None => name,
        };
        self.ev(Ev::Lookup { file, at, name: name.clone(), txt });
        let r = events::received(at, &name);
        let mut list = Val::list(vec![r.clone()]);
        list.add_kinds(&r);
        list
    }

    /// The data a reader gives: a response's or a connection's is received; a file's or a value's is what it holds.
    fn read_from(&mut self, r: &Val, at: u32) -> Val {
        match r.obj {
            Obj::Resp => events::received(at, r).with_kinds(r),
            Obj::Conn(k) => {
                let addr = self.conns.get(k as usize).map(|c| c.addr.clone()).unwrap_or_default();
                events::received(at, &addr)
            }
            _ => {
                let mut v = derived(r);
                v.s = r.s.clone();
                v.items = r.items.clone();
                v
            }
        }
    }

    // ---------------------------------------------------------------- calls --
    fn call(&mut self, f: &mut Frame, e: NodeId) -> Val {
        let file = f.file;
        let n = self.node(file, e);
        let fun = n.f[0];
        let arg_nodes = self.items(file, n.f[1]);
        let spread = n.flags & ELLIPSIS != 0;
        let at = n.start;
        let fnode = self.node(file, fun);
        // a conversion: a type before the parenthesis
        if let Some(conv) = self.conversion_kind(f, fun) {
            let v = match arg_nodes.first() {
                Some(&a) => self.eval(f, a),
                None => Val::unknown(),
            };
            return self.convert(&conv, v);
        }
        match fnode.kind {
            K::Ident => {
                let name = self.text(file, fun);
                if let Some(c) = f.vars.get(name).cloned() {
                    let args = self.eval_args(f, arg_nodes);
                    if let Obj::Closure(k) = c.obj {
                        return self.call_closure(k, args, spread, Some(f));
                    }
                    return args_kinds(&args);
                }
                if let Some(v) = self.builtin(f, name, arg_nodes, spread) {
                    return v;
                }
                let args = self.eval_args(f, arg_nodes);
                let cands = self.k.pkgs[f.pkg as usize].funcs.get(name).cloned().unwrap_or_default();
                if !cands.is_empty() {
                    return self.call_cands(&cands, args, None, spread);
                }
                if let Some(Val { obj: Obj::Closure(k), .. }) = self.global(f.pkg, name) {
                    return self.call_closure(k, args, spread, Some(f));
                }
                args_kinds(&args)
            }
            K::SelectorExpr => {
                let x = fnode.f[0];
                let sel = self.ident(file, fnode.f[1]);
                if let Some(path) = self.import_of(f, x) {
                    let args = self.eval_args(f, arg_nodes);
                    if eqs(&path, "C") {
                        return self.cgo_call(&sel, args);
                    }
                    if let Some(&pkg) = self.k.by_path.get(&path) {
                        let cands = self.k.pkgs[pkg as usize].funcs.get(&sel).cloned().unwrap_or_default();
                        if !cands.is_empty() {
                            return self.call_cands(&cands, args, None, spread);
                        }
                        if let Some(Val { obj: Obj::Closure(k), .. }) = self.global(pkg, &sel) {
                            return self.call_closure(k, args, spread, Some(f));
                        }
                        return args_kinds(&args);
                    }
                    return self.api_call(f, &path, &sel, args, arg_nodes, spread, at);
                }
                let recv = self.eval(f, x);
                let args = self.eval_args(f, arg_nodes);
                self.method(f, recv, x, &sel, args, arg_nodes, spread, at)
            }
            _ => {
                let c = self.eval(f, fun);
                let args = self.eval_args(f, arg_nodes);
                if let Obj::Closure(k) = c.obj {
                    return self.call_closure(k, args, spread, Some(f));
                }
                args_kinds(&args).with_kinds(&c)
            }
        }
    }

    fn eval_args(&mut self, f: &mut Frame, nodes: &[u32]) -> Vec<Val> {
        nodes.iter().map(|&a| self.eval(f, a)).collect()
    }

    fn call_cands(&mut self, cands: &[(u16, NodeId)], args: Vec<Val>, recv: Option<Val>, spread: bool) -> Val {
        let mut out: Option<Val> = None;
        for &(cf, cd) in cands.iter().take(4) {
            let r = self.call_decl(cf, cd, args.clone(), recv.clone(), spread);
            out = Some(match out {
                Some(o) => o.union(&r),
                None => r,
            });
        }
        out.unwrap_or_default()
    }

    /// The type a call converts to, when the callee is a type: `string`, `[]byte`, `[]rune`, a number's type, or
    /// another (the value kept).
    fn conversion_kind(&self, f: &Frame, fun: NodeId) -> Option<String> {
        let mut cur = fun;
        let mut guard = 0;
        while self.node(f.file, cur).kind == K::ParenExpr && guard < 64 {
            cur = self.node(f.file, cur).f[0];
            guard += 1;
        }
        let n = self.node(f.file, cur);
        match n.kind {
            K::Ident => {
                let name = self.text(f.file, cur);
                if f.vars.contains_key(name) {
                    return None;
                }
                if BASIC.iter().any(|b| eqs(name, b)) {
                    return Some(pystr::to_string(name));
                }
                if self.k.pkgs[f.pkg as usize].types.contains(name) && !self.k.pkgs[f.pkg as usize].funcs.contains_key(name) {
                    return Some(String::from("type"));
                }
                None
            }
            K::ArrayType => {
                if n.f[1] != NONE && self.node(f.file, n.f[1]).kind == K::Ident {
                    let el = pystr::to_string(self.text(f.file, n.f[1]));
                    return Some(format!("[]{}", el));
                }
                Some(String::from("type"))
            }
            K::MapType | K::ChanType | K::FuncType | K::InterfaceType | K::StructType | K::StarExpr if n.kind != K::StarExpr || fun != cur => Some(String::from("type")),
            _ => None,
        }
    }

    fn convert(&mut self, to: &str, v: Val) -> Val {
        match to {
            "string" => {
                if v.items.is_some() && v.obj != Obj::Map {
                    return text_of_numbers(&v);
                }
                if v.s.is_none() {
                    if let Some(n) = v.int {
                        if let Some(c) = u32::try_from(n).ok().filter(|&c| char::from_u32(c).is_some()) {
                            return Val::text(vec![c]).with_kinds(&v);
                        }
                    }
                }
                v
            }
            "[]byte" | "[]uint8" => bytes_list(&v),
            "[]rune" | "[]int32" => match &v.s {
                Some(s) if !s.contains(&UNKNOWN) && s.len() <= val::MAX_ITEMS => {
                    let items: Vec<Val> = s.iter().map(|&c| Val::int(c as i128)).collect();
                    let mut out = Val::list(items).with_kinds(&v);
                    out.s = Some(s.clone());
                    out
                }
                _ => v,
            },
            "byte" | "uint8" => match v.int {
                Some(n) => Val::int(n & 0xFF).with_kinds(&v),
                None => v,
            },
            "uint16" => v.int.map(|n| Val::int(n & 0xFFFF).with_kinds(&v)).unwrap_or(v),
            "uint32" => v.int.map(|n| Val::int(n & 0xFFFF_FFFF).with_kinds(&v)).unwrap_or(v),
            "int8" => v.int.map(|n| Val::int((n as i8) as i128).with_kinds(&v)).unwrap_or(v),
            _ => v,
        }
    }

    /// A built-in's call (`append`, `len`, `make`, `new`, `copy`, …), unless a name of the function shadows it.
    fn builtin(&mut self, f: &mut Frame, name: &[u32], arg_nodes: &[u32], spread: bool) -> Option<Val> {
        let n = pystr::to_string(name);
        let known = matches!(n.as_str(), "append" | "len" | "cap" | "make" | "new" | "copy" | "delete" | "panic" | "print" | "println" | "recover" | "min" | "max" | "clear" | "close" | "complex" | "real" | "imag");
        if !known || self.k.pkgs[f.pkg as usize].funcs.contains_key(name) {
            return None;
        }
        if n == "make" || n == "new" {
            let ty = *arg_nodes.first()?;
            let tn = self.node(f.file, ty);
            let rest: Vec<Val> = arg_nodes[1..].iter().map(|&a| self.eval(f, a)).collect();
            return Some(match tn.kind {
                K::ArrayType if n == "make" => {
                    let len = rest.first().and_then(|v| v.int).unwrap_or(0).clamp(0, val::MAX_ITEMS as i128) as usize;
                    Val::list(vec![Val::int(0); len])
                }
                K::MapType => {
                    let mut m = Val::list(Vec::new());
                    m.obj = Obj::Map;
                    m
                }
                _ => {
                    let z = self.zero(f.file, ty);
                    z
                }
            });
        }
        let args = self.eval_args(f, arg_nodes);
        Some(match n.as_str() {
            "append" => {
                let Some(first) = args.first() else { return Some(Val::unknown()) };
                let mut items: Vec<Val> = match (&first.items, &first.s) {
                    (Some(i), _) => (**i).clone(),
                    (None, Some(_)) => bytes_list(first).items.map(|i| (*i).clone()).unwrap_or_default(),
                    _ => Vec::new(),
                };
                let unknown_base = first.items.is_none() && first.s.is_none();
                for (k, a) in args.iter().enumerate().skip(1) {
                    if spread && k + 1 == args.len() {
                        match (&a.items, &a.s) {
                            (Some(i), _) => items.extend(i.iter().cloned()),
                            (None, Some(_)) => items.extend(bytes_list(a).items.map(|i| (*i).clone()).unwrap_or_default()),
                            _ => items.push(derived(a)),
                        }
                    } else {
                        items.push(a.clone());
                    }
                }
                let mut v = Val::list(items);
                v.add_kinds(first);
                for a in &args {
                    v.add_kinds(a);
                }
                if unknown_base && first.id != 0 {
                    v.id = first.id;
                }
                self.charge(v.items.as_ref().map_or(0, |i| i.len() * 4));
                v
            }
            "len" => match args.first() {
                Some(a) => match (&a.items, &a.s) {
                    (Some(i), _) if a.obj != Obj::Map => Val::int(i.len() as i128),
                    (None, Some(s)) if !s.contains(&UNKNOWN) => Val::int(val::bytes_of(s).len() as i128),
                    _ => Val::unknown(),
                },
                None => Val::unknown(),
            },
            "copy" => {
                // copy(dst, src): what dst holds is src's
                if let (Some(&d), Some(src)) = (arg_nodes.first(), args.get(1)) {
                    let v = src.clone();
                    self.assign_to(f, d, v, false);
                }
                Val::unknown()
            }
            _ => args_kinds(&args),
        })
    }

    /// `C.f(…)`: a function of the cgo preamble (its C is read on its own); `C.CString`, `C.GoString` keep their
    /// value.
    fn cgo_call(&mut self, name: &[u32], args: Vec<Val>) -> Val {
        let n = pystr::to_string(name);
        if matches!(n.as_str(), "CString" | "GoString" | "GoStringN" | "CBytes" | "GoBytes") {
            return args.into_iter().next().unwrap_or_default();
        }
        if n != "free" {
            self.calls_c = true;
        }
        args_kinds(&args)
    }
}

impl<'k, 'a> Model<'k, 'a> {
    // ---------------------------------------------------------------- the standard library --
    /// A call of an imported package's function, by its import path.
    #[allow(clippy::too_many_arguments)]
    fn api_call(&mut self, f: &mut Frame, path: &[u32], name: &[u32], args: Vec<Val>, arg_nodes: &[u32], spread: bool, at: u32) -> Val {
        let file = f.file;
        let p = pystr::to_string(path);
        let n = pystr::to_string(name);
        let a = |k: usize| args.get(k).cloned().unwrap_or_default();
        // the arguments a variadic parameter takes from `k` on (a list spread with `...`)
        let rest = |k: usize| -> Vec<Val> {
            let mut out: Vec<Val> = Vec::new();
            for (j, v) in args.iter().enumerate().skip(k) {
                if spread && j + 1 == args.len() {
                    match &v.items {
                        Some(items) => out.extend(items.iter().cloned()),
                        None => out.push(v.clone()),
                    }
                } else {
                    out.push(v.clone());
                }
            }
            out
        };
        match (p.as_str(), n.as_str()) {
            // ---- processes
            ("os/exec", "Command") => {
                let c = self.new_cmd(a(0), file, at);
                if let Obj::Cmd(i) = c.obj {
                    let r = rest(1);
                    if let Some(st) = self.cmds.get_mut(i as usize) {
                        st.args = r;
                    }
                }
                c
            }
            ("os/exec", "CommandContext") => {
                let c = self.new_cmd(a(1), file, at);
                if let Obj::Cmd(i) = c.obj {
                    let r = rest(2);
                    if let Some(st) = self.cmds.get_mut(i as usize) {
                        st.args = r;
                    }
                }
                c
            }
            ("os/exec", "LookPath") => a(0),
            ("os", "StartProcess") | ("syscall", "Exec") | ("syscall", "ForkExec") | ("golang.org/x/sys/unix", "Exec") => {
                // (name, argv, …): argv's first is the program's own name
                let argv: Vec<Val> = a(1).items.map(|i| i.iter().skip(1).cloned().collect()).unwrap_or_default();
                let c = self.new_cmd(a(0), file, at);
                if let Obj::Cmd(i) = c.obj {
                    if let Some(st) = self.cmds.get_mut(i as usize) {
                        st.args = argv;
                    }
                    self.run_cmd(i);
                }
                Val::unknown()
            }
            // ---- the environment, the user, the machine
            ("os", "Getenv") | ("os", "LookupEnv") | ("syscall", "Getenv") => events::env_var(self.p, &a(0).text_or_unknown(), at),
            ("os", "Environ") | ("syscall", "Environ") => {
                let whole = self.p.text("_LD_WHOLE_ENV");
                let mut v = Val::source(K_WHOLE_ENV, whole, at);
                v.obj = Obj::EnvVars;
                v
            }
            ("os", "ExpandEnv") => {
                // `$NAME` and `${NAME}` read as the environment gives them
                let s = a(0);
                match &s.s {
                    Some(t) if !t.contains(&UNKNOWN) => self.expand_env(t, at).with_kinds(&s),
                    _ => derived(&s),
                }
            }
            ("os", "Hostname") => Val::source(K_IDENTITY, u("hostname"), at),
            ("os", "Getuid") | ("os", "Getpid") => Val::unknown(),
            ("os/user", "Current") | ("os/user", "Lookup") | ("os/user", "LookupId") => Val::obj(Obj::User),
            ("os", "UserHomeDir") => {
                let mut v = Val::text(u("~"));
                v.add_kinds(&Val::source(K_PATH, u("home"), at));
                v
            }
            ("os", "UserConfigDir") | ("os", "UserCacheDir") => {
                let mut v = Val::text(u(if n == "UserConfigDir" { "~/.config" } else { "~/.cache" }));
                v.add_kinds(&Val::source(K_PATH, u("home"), at));
                v
            }
            ("os", "TempDir") => Val::text(u("/tmp")),
            ("os", "Executable") | ("os", "Getwd") => Val::unknown(),
            // ---- files
            ("os", "ReadFile") | ("io/ioutil", "ReadFile") | ("os", "Open") => events::file_read(self.p, &a(0), at),
            ("os", "OpenFile") => {
                let flags = a(1).int;
                if flags.is_some_and(|x| x & 3 == 0) {
                    return events::file_read(self.p, &a(0), at);
                }
                let idx = self.wfiles.len() as u32;
                self.wfiles.push(WState { path: a(0), append: flags.is_some_and(|x| x & 0x400 != 0) });
                Val::obj(Obj::WFile(idx))
            }
            ("os", "Create") => {
                let idx = self.wfiles.len() as u32;
                self.wfiles.push(WState { path: a(0), append: false });
                Val::obj(Obj::WFile(idx))
            }
            ("os", "WriteFile") | ("io/ioutil", "WriteFile") => {
                self.ev(Ev::Write { file, at, path: a(0), data: a(1), append: false });
                Val::unknown()
            }
            ("os", "ReadDir") | ("io/ioutil", "ReadDir") | ("path/filepath", "Glob") => {
                let mut entry = Val::concat(&a(0), &Val::text(vec!['/' as u32, UNKNOWN]));
                entry.add_kinds(&a(0));
                let mut v = Val::list(vec![entry.clone()]);
                v.add_kinds(&entry);
                v
            }
            ("path/filepath", "Walk") | ("path/filepath", "WalkDir") => {
                // the callback, given a path below the root
                let root = a(0);
                let mut p = path_join(&root, &Val::text(vec![UNKNOWN]));
                p.add_kinds(&root);
                if let Obj::Closure(k) = a(1).obj {
                    self.call_closure(k, vec![p, Val::unknown(), Val::unknown()], false, Some(f));
                }
                Val::unknown()
            }
            ("path/filepath", "Join") | ("path", "Join") => {
                let parts = rest(0);
                let mut v = match parts.first() {
                    Some(x) => x.clone(),
                    None => Val::text(Vec::new()),
                };
                for x in parts.iter().skip(1) {
                    v = path_join(&v, x);
                }
                v
            }
            ("path/filepath", "Abs") | ("path/filepath", "Clean") | ("path", "Clean") | ("path/filepath", "FromSlash") | ("path/filepath", "ToSlash") => a(0),
            ("path/filepath", "Base") | ("path/filepath", "Dir") | ("path/filepath", "Ext") | ("path", "Base") | ("path", "Dir") => derived(&a(0)),
            // ---- reading and writing
            ("io", "ReadAll") | ("io/ioutil", "ReadAll") => self.read_from(&a(0), at),
            ("bufio", "NewReader") | ("bufio", "NewScanner") | ("bufio", "NewReaderSize") | ("bufio", "NewWriter") | ("bufio", "NewWriterSize") | ("io", "NopCloser")
            | ("io", "TeeReader") | ("io", "LimitReader") | ("strings", "NewReader") | ("bytes", "NewReader") | ("bytes", "NewBuffer") | ("bytes", "NewBufferString") => a(0),
            ("compress/gzip", "NewReader") | ("compress/zlib", "NewReader") | ("compress/flate", "NewReader") | ("compress/bzip2", "NewReader") | ("compress/lzw", "NewReader") => {
                // what it unpacks was packed into the program: decoded
                derived(&a(0)).decoded(at)
            }
            ("io", "Copy") | ("io", "CopyN") | ("io", "CopyBuffer") => {
                let data = self.read_from(&a(1), at);
                self.write_to(&a(0), &data, file, at);
                Val::unknown()
            }
            ("io", "WriteString") => {
                self.write_to(&a(0), &a(1), file, at);
                Val::unknown()
            }
            ("fmt", "Fprintf") => {
                let text = lit::sprintf(&a(1).text_or_unknown(), &rest(2));
                self.write_to(&a(0), &text, file, at);
                Val::unknown()
            }
            ("fmt", "Fprint") | ("fmt", "Fprintln") => {
                let parts = rest(1);
                let mut text = Val::text(Vec::new());
                for (k, x) in parts.iter().enumerate() {
                    if k > 0 && n == "Fprintln" {
                        text = Val::concat(&text, &Val::text(u(" ")));
                    }
                    text = Val::concat(&text, &self.convert("string", x.clone()));
                }
                self.write_to(&a(0), &text, file, at);
                Val::unknown()
            }
            // ---- text
            ("fmt", "Sprintf") | ("fmt", "Errorf") => {
                let v = lit::sprintf(&a(0).text_or_unknown(), &rest(1));
                self.charge(v.s.as_ref().map_or(0, |s| s.len()));
                v
            }
            ("fmt", "Sprint") | ("fmt", "Sprintln") => {
                let parts = rest(0);
                let mut v = Val::text(Vec::new());
                for (k, x) in parts.iter().enumerate() {
                    if k > 0 && n == "Sprintln" {
                        v = Val::concat(&v, &Val::text(u(" ")));
                    }
                    v = Val::concat(&v, &self.convert("string", x.clone()));
                }
                v
            }
            ("fmt", _) => Val::unknown(),
            ("strings", _) | ("bytes", _) => self.strings_call(&n, &args, f, arg_nodes, at),
            ("strconv", "Itoa") | ("strconv", "FormatInt") | ("strconv", "FormatUint") => match a(0).int {
                Some(x) => {
                    let base = a(1).int.unwrap_or(10);
                    let s = match base {
                        16 => format!("{:x}", x),
                        8 => format!("{:o}", x),
                        2 => format!("{:b}", x),
                        _ => x.to_string(),
                    };
                    Val::text(u(&s)).with_kinds(&a(0))
                }
                None => derived(&a(0)),
            },
            ("strconv", "Atoi") | ("strconv", "ParseInt") | ("strconv", "ParseUint") => match &a(0).s {
                Some(s) if !s.contains(&UNKNOWN) => {
                    let base = if n == "Atoi" { 10 } else { a(1).int.unwrap_or(10).clamp(2, 36) as u32 };
                    match i128::from_str_radix(&pystr::to_string(s), base) {
                        Ok(x) => Val::int(x),
                        Err(_) => derived(&a(0)),
                    }
                }
                _ => derived(&a(0)),
            },
            ("strconv", "Quote") => Val::concat(&Val::concat(&Val::text(u("\"")), &a(0)), &Val::text(u("\""))),
            ("strconv", "Unquote") => {
                let s = a(0);
                match &s.s {
                    Some(t) if !t.contains(&UNKNOWN) => lit::string_lit(t).map(|x| Val::text(x).with_kinds(&s)).unwrap_or_else(|| derived(&s)),
                    _ => derived(&s),
                }
            }
            // ---- decodings
            ("encoding/hex", "DecodeString") => events::decode_hex(&a(0), at),
            ("encoding/hex", "Decode") => {
                if let Some(&d) = arg_nodes.first() {
                    let v = events::decode_hex(&a(1), at);
                    self.assign_to(f, d, v, false);
                }
                Val::unknown()
            }
            ("encoding/hex", "EncodeToString") | ("encoding/base64", _) | ("encoding/base32", _) => {
                if p == "encoding/base64" && n == "NewEncoding" {
                    let mut v = Val::obj(Obj::B64);
                    v.s = a(0).s.clone();
                    return v;
                }
                derived(&a(0))
            }
            ("net/url", "QueryUnescape") | ("net/url", "PathUnescape") => {
                let s = a(0);
                match &s.s {
                    Some(t) if !t.contains(&UNKNOWN) => Val::text(percent_decode(t)).with_kinds(&s),
                    _ => derived(&s),
                }
            }
            ("net/url", "Parse") | ("net/url", "ParseRequestURI") | ("net/url", "QueryEscape") | ("net/url", "PathEscape") => a(0),
            // ---- the network
            ("net/http", "Get") | ("net/http", "Head") => self.send(file, at, &a(0), &Val::unknown()),
            ("net/http", "Post") => self.send(file, at, &a(0), &a(2)),
            ("net/http", "PostForm") => self.send(file, at, &a(0), &a(1)),
            ("net/http", "NewRequest") | ("net/http", "NewRequestWithContext") => {
                let o = if n == "NewRequest" { 0 } else { 1 };
                let idx = self.reqs.len() as u32;
                self.reqs.push(ReqState { url: a(o + 1), body: a(o + 2) });
                Val::obj(Obj::Req(idx))
            }
            ("net", "Dial") | ("net", "DialTimeout") | ("crypto/tls", "Dial") | ("crypto/tls", "DialWithDialer") => {
                let addr = if n == "DialWithDialer" { a(2) } else { a(1) };
                self.connect(file, at, addr)
            }
            ("net", "DialTCP") | ("net", "DialUDP") | ("net", "DialIP") | ("net", "DialUnix") => self.connect(file, at, a(2)),
            ("net", "LookupTXT") => self.lookup(file, at, a(0), true),
            ("net", "LookupHost") | ("net", "LookupIP") | ("net", "LookupAddr") | ("net", "LookupCNAME") | ("net", "LookupMX") | ("net", "LookupNS") | ("net", "ResolveIPAddr") => {
                let name = if n == "ResolveIPAddr" { a(1) } else { a(0) };
                self.lookup(file, at, name, false)
            }
            ("net", "ResolveTCPAddr") | ("net", "ResolveUDPAddr") => self.lookup(file, at, a(1), false),
            ("net", "LookupSRV") => self.lookup(file, at, a(2), false),
            // ---- libraries and plugins loaded
            ("plugin", "Open") | ("syscall", "LoadLibrary") | ("syscall", "LoadDLL") | ("syscall", "MustLoadDLL") | ("syscall", "NewLazyDLL")
            | ("golang.org/x/sys/windows", "LoadLibrary") | ("golang.org/x/sys/windows", "LoadDLL") | ("golang.org/x/sys/windows", "MustLoadDLL")
            | ("golang.org/x/sys/windows", "NewLazyDLL") | ("golang.org/x/sys/windows", "NewLazySystemDLL") => {
                self.ev(Ev::Load { file, at, path: a(0) });
                Val::unknown()
            }
            ("golang.org/x/sys/windows" | "syscall", "StringToUTF16Ptr" | "UTF16PtrFromString" | "StringToUTF16" | "UTF16FromString" | "BytePtrFromString" | "StringBytePtr") => a(0),
            ("os", "Rename") | ("os", "Link") | ("os", "Symlink") => {
                // the file written under the old name is there under the new one
                let old = a(0);
                let data = self.events.iter().rev().find_map(|e| match e {
                    Ev::Write { path, data, .. } if (old.id != 0 && path.id == old.id) || (old.known() && path.known() && path.s == old.s) => Some(data.clone()),
                    _ => None,
                });
                if let Some(data) = data {
                    self.ev(Ev::Write { file, at, path: a(1), data, append: false });
                }
                Val::unknown()
            }
            ("os", "CreateTemp") | ("io/ioutil", "TempFile") => {
                let mut path = path_join(&a(0), &Val::concat(&Val::text(vec![UNKNOWN]), &a(1)));
                path.id = self.fresh_id();
                let idx = self.wfiles.len() as u32;
                self.wfiles.push(WState { path, append: false });
                Val::obj(Obj::WFile(idx))
            }
            ("os", "MkdirTemp") | ("io/ioutil", "TempDir") => {
                let mut path = path_join(&a(0), &Val::concat(&Val::text(vec![UNKNOWN]), &a(1)));
                path.id = self.fresh_id();
                path
            }
            ("golang.org/x/sys/windows", "ShellExecute") => {
                // (hwnd, verb, file, args, dir, show)
                let c = self.new_cmd(a(2), file, at);
                if let Obj::Cmd(i) = c.obj {
                    let r = a(3);
                    if let Some(st) = self.cmds.get_mut(i as usize) {
                        st.args = vec![r];
                    }
                    self.run_cmd(i);
                }
                Val::unknown()
            }
            ("errors", _) | ("time", _) | ("log", _) | ("sync", _) | ("context", _) | ("sort", _) | ("math", _) | ("unicode", _) | ("unicode/utf8", _) => args_kinds(&args),
            _ => {
                // a package the reader does not know: its result carries its arguments' data
                args_kinds(&args)
            }
        }
    }

    /// `$NAME` and `${NAME}` in a text, as `os.ExpandEnv` reads them.
    fn expand_env(&mut self, t: &[u32], at: u32) -> Val {
        let mut v = Val::text(Vec::new());
        let mut k = 0;
        let mut plain: PyStr = Vec::new();
        while k < t.len() {
            if t[k] == '$' as u32 && k + 1 < t.len() {
                let (name, next) = if t[k + 1] == '{' as u32 {
                    match t[k + 2..].iter().position(|&c| c == '}' as u32) {
                        Some(e) => (t[k + 2..k + 2 + e].to_vec(), k + 3 + e),
                        None => (Vec::new(), k + 1),
                    }
                } else {
                    let e = t[k + 1..].iter().position(|&c| !char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')).unwrap_or(t.len() - k - 1);
                    (t[k + 1..k + 1 + e].to_vec(), k + 1 + e)
                };
                if !name.is_empty() {
                    v = Val::concat(&v, &Val::text(std::mem::take(&mut plain)));
                    let e = events::env_var(self.p, &name, at);
                    v = Val::concat(&v, &e);
                    k = next;
                    continue;
                }
            }
            plain.push(t[k]);
            k += 1;
        }
        Val::concat(&v, &Val::text(plain))
    }

    /// `strings`'s and `bytes`'s functions: what they make of a text.
    fn strings_call(&mut self, n: &str, args: &[Val], f: &mut Frame, arg_nodes: &[u32], at: u32) -> Val {
        let a = |k: usize| args.get(k).cloned().unwrap_or_default();
        let s = a(0);
        let known = |v: &Val| v.s.as_ref().filter(|t| !t.contains(&UNKNOWN)).map(|t| (**t).clone());
        let v = match n {
            "Join" => match &s.items {
                Some(items) => {
                    let sep = a(1).text_or_unknown();
                    let mut out: PyStr = Vec::new();
                    let mut kinds = Val::unknown();
                    for (k, it) in items.iter().enumerate() {
                        if k > 0 {
                            out.extend(&sep);
                        }
                        out.extend(self.convert("string", it.clone()).text_or_unknown());
                        kinds.add_kinds(it);
                    }
                    Val::text(val::collapse(out)).with_kinds(&kinds).with_kinds(&s)
                }
                None => derived(&s),
            },
            "Replace" | "ReplaceAll" => match (&s.s, known(&a(1))) {
                (Some(t), Some(from)) if !from.is_empty() => {
                    let to = a(2).text_or_unknown();
                    let limit = if n == "Replace" { a(3).int.unwrap_or(-1) } else { -1 };
                    let out = if limit < 0 {
                        pystr::replace(t, &from, &to)
                    } else {
                        let mut out = (**t).clone();
                        for _ in 0..limit.min(4096) {
                            match pystr::find(&out, &from, 0) {
                                Some(p) => {
                                    out.splice(p..p + from.len(), to.iter().copied());
                                }
                                None => break,
                            }
                        }
                        out
                    };
                    Val::text(out).with_kinds(&s).with_kinds(&a(2))
                }
                _ => derived(&s).with_kinds(&a(2)),
            },
            "ToLower" | "ToUpper" | "Title" | "ToTitle" => events::map_text(&s, |t| {
                t.iter().map(|&c| char::from_u32(c).map(|ch| if n == "ToLower" { ch.to_lowercase().next().unwrap_or(ch) } else { ch.to_uppercase().next().unwrap_or(ch) } as u32).unwrap_or(c)).collect()
            }),
            "TrimSpace" | "Trim" | "TrimLeft" | "TrimRight" | "TrimPrefix" | "TrimSuffix" => match (&s.s, n) {
                (Some(t), "TrimSpace") => {
                    let ws = |c: &u32| matches!(char::from_u32(*c), Some(' ' | '\n' | '\r' | '\t' | '\x0b' | '\x0c'));
                    let st = t.iter().position(|c| !ws(c)).unwrap_or(t.len());
                    let en = t.iter().rposition(|c| !ws(c)).map(|k| k + 1).unwrap_or(st);
                    Val::text(t[st..en.max(st)].to_vec()).with_kinds(&s)
                }
                (Some(t), "TrimPrefix") => match known(&a(1)) {
                    Some(pre) if t.starts_with(&pre) => Val::text(t[pre.len()..].to_vec()).with_kinds(&s),
                    _ => s.clone(),
                },
                (Some(t), "TrimSuffix") => match known(&a(1)) {
                    Some(suf) if t.ends_with(&suf) => Val::text(t[..t.len() - suf.len()].to_vec()).with_kinds(&s),
                    _ => s.clone(),
                },
                (Some(t), _) => match known(&a(1)) {
                    Some(cut) => {
                        let inset = |c: &u32| cut.contains(c);
                        let st = if n == "TrimRight" { 0 } else { t.iter().position(|c| !inset(c)).unwrap_or(t.len()) };
                        let en = if n == "TrimLeft" { t.len() } else { t.iter().rposition(|c| !inset(c)).map(|k| k + 1).unwrap_or(st) };
                        Val::text(t[st.min(en)..en.max(st)].to_vec()).with_kinds(&s)
                    }
                    None => derived(&s),
                },
                _ => derived(&s),
            },
            "Split" | "SplitN" | "Fields" | "SplitAfter" => match known(&s) {
                Some(t) => {
                    let parts: Vec<PyStr> = if n == "Fields" {
                        pystr::split_ws(&t).into_iter().map(|p| p.to_vec()).collect()
                    } else {
                        match known(&a(1)) {
                            Some(sep) if !sep.is_empty() => pystr::split_str(&t, &sep).into_iter().map(|p| p.to_vec()).collect(),
                            _ => vec![t.clone()],
                        }
                    };
                    let items: Vec<Val> = parts.into_iter().take(val::MAX_ITEMS).map(|p| Val::text(p).with_kinds(&s)).collect();
                    Val::list(items).with_kinds(&s)
                }
                None => {
                    let mut l = Val::list(vec![derived(&s)]);
                    l.add_kinds(&s);
                    l
                }
            },
            "Repeat" => match (&s.s, a(1).int) {
                (Some(t), Some(k)) if (0..=4096).contains(&k) => {
                    let k = (k as usize).min(val::MAX_TEXT / t.len().max(1) + 1);
                    Val::text(t.repeat(k)).with_kinds(&s)
                }
                _ => derived(&s),
            },
            "Map" => {
                // strings.Map(f, s): f on each character, a decoder's shape
                let text = a(1);
                match (a(0).obj, known(&text)) {
                    (Obj::Closure(k), Some(t)) if t.len() <= val::MAX_ITEMS => {
                        let mut out: PyStr = Vec::with_capacity(t.len());
                        for &c in t.iter() {
                            if self.out_of_steps() {
                                return derived(&text).decoded(at);
                            }
                            let mut ch = Val::text(vec![c]);
                            ch.int = Some(c as i128);
                            let r = self.call_closure(k, vec![ch], false, Some(f));
                            match r.int.and_then(|x| u32::try_from(x).ok()).filter(|&x| char::from_u32(x).is_some()) {
                                Some(x) => out.push(x),
                                None if r.int.is_some_and(|x| x < 0) => {}
                                None => out.push(UNKNOWN),
                            }
                        }
                        Val::text(val::collapse(out)).with_kinds(&text).decoded(at)
                    }
                    _ => derived(&text).decoded(at),
                }
            }
            "Contains" | "HasPrefix" | "HasSuffix" | "Index" | "EqualFold" | "Count" | "Compare" | "Equal" | "LastIndex" | "IndexByte" | "ContainsAny" => Val::unknown(),
            "NewReplacer" => {
                // a list of (old, new) pairs; its Replace method reads them
                let mut l = Val::list(args.to_vec());
                l.obj = Obj::None;
                l
            }
            _ => derived(&s),
        };
        let _ = arg_nodes;
        self.charge(v.s.as_ref().map_or(0, |t| t.len()));
        v
    }

    // ---------------------------------------------------------------- methods --
    #[allow(clippy::too_many_arguments)]
    fn method(&mut self, f: &mut Frame, recv: Val, recv_e: NodeId, name: &[u32], args: Vec<Val>, arg_nodes: &[u32], spread: bool, at: u32) -> Val {
        let file = f.file;
        let n = pystr::to_string(name);
        let a = |k: usize| args.get(k).cloned().unwrap_or_default();
        match recv.obj {
            Obj::Cmd(c) => {
                return match n.as_str() {
                    "Run" | "Start" => {
                        self.run_cmd(c);
                        Val::unknown()
                    }
                    "Output" | "CombinedOutput" => {
                        self.run_cmd(c);
                        match self.cmds.get(c as usize) {
                            Some(st) => events::output_of(self.p, st),
                            None => Val::unknown(),
                        }
                    }
                    _ => Val::unknown(),
                };
            }
            Obj::Client => {
                return match n.as_str() {
                    "Do" => match a(0).obj {
                        Obj::Req(r) => {
                            let st = self.reqs.get(r as usize).cloned().unwrap_or_default();
                            self.send(file, at, &st.url, &st.body)
                        }
                        _ => self.send(file, at, &Val::unknown(), &Val::unknown()),
                    },
                    "Get" | "Head" => self.send(file, at, &a(0), &Val::unknown()),
                    "Post" => self.send(file, at, &a(0), &a(2)),
                    "PostForm" => self.send(file, at, &a(0), &a(1)),
                    "Dial" | "DialTimeout" => self.connect(file, at, a(1)),
                    "DialContext" => self.connect(file, at, a(2)),
                    _ => recv,
                };
            }
            Obj::Req(r) => {
                match n.as_str() {
                    "Set" | "Add" | "SetBasicAuth" | "AddCookie" | "Write" | "WriteString" => {
                        if let Some(st) = self.reqs.get_mut(r as usize) {
                            for v in &args {
                                st.body = Val::concat(&st.body, v).with_kinds(v);
                            }
                        }
                        return Val::unknown();
                    }
                    _ => return recv,
                }
            }
            Obj::Resp => {
                if n == "Read" {
                    if let Some(&b) = arg_nodes.first() {
                        let data = events::received(at, &recv).with_kinds(&recv);
                        self.assign_to(f, b, data, false);
                    }
                    return Val::unknown();
                }
                if n == "Close" {
                    return Val::unknown();
                }
                let mut v = events::received(at, &recv).with_kinds(&recv);
                if matches!(n.as_str(), "Body") {
                    v.obj = Obj::Resp;
                }
                return v;
            }
            Obj::Conn(k) => {
                let addr = self.conns.get(k as usize).map(|c| c.addr.clone()).unwrap_or_default();
                return match n.as_str() {
                    "Write" | "WriteString" | "WriteTo" | "WriteMsgUDP" => {
                        self.ev(Ev::Send { file, at, data: a(0), dest: addr, in_address: false });
                        Val::unknown()
                    }
                    "Read" | "ReadFrom" => {
                        if let Some(&b) = arg_nodes.first() {
                            let data = events::received(at, &addr);
                            self.assign_to(f, b, data, false);
                        }
                        Val::unknown()
                    }
                    "ReadString" | "ReadLine" | "ReadBytes" | "Text" | "Bytes" | "ReadRune" | "Peek" => events::received(at, &addr),
                    "Flush" => Val::unknown(),
                    _ => recv,
                };
            }
            Obj::WFile(_) => {
                return match n.as_str() {
                    "Write" | "WriteString" | "WriteAt" => {
                        self.write_to(&recv, &a(0), file, at);
                        Val::unknown()
                    }
                    "Name" => match &recv.obj {
                        Obj::WFile(k) => self.wfiles.get(*k as usize).map(|w| w.path.clone()).unwrap_or_default(),
                        _ => Val::unknown(),
                    },
                    _ => Val::unknown(),
                };
            }
            Obj::Resolver => {
                // (ctx, name, …)
                return match n.as_str() {
                    "LookupTXT" => self.lookup(file, at, a(1), true),
                    "LookupHost" | "LookupIPAddr" | "LookupIP" | "LookupAddr" | "LookupCNAME" | "LookupMX" | "LookupNS" | "LookupNetIP" => {
                        let name = if n == "LookupIP" || n == "LookupNetIP" { a(2) } else { a(1) };
                        self.lookup(file, at, name, false)
                    }
                    "LookupSRV" => self.lookup(file, at, a(3), false),
                    _ => recv,
                };
            }
            Obj::B64 => {
                return match n.as_str() {
                    "DecodeString" => self.b64_decode(&recv, &a(0), at),
                    "Decode" => {
                        if let Some(&d) = arg_nodes.first() {
                            let v = self.b64_decode(&recv, &a(1), at);
                            self.assign_to(f, d, v, false);
                        }
                        Val::unknown()
                    }
                    "Strict" | "WithPadding" => recv,
                    _ => derived(&a(0)),
                };
            }
            Obj::Closure(k) => {
                return self.call_closure(k, args.clone(), spread, Some(f));
            }
            _ => {}
        }
        // a builder, a buffer, url.Values, a replacer: what their methods make of a text
        match n.as_str() {
            "WriteString" | "WriteByte" | "WriteRune" | "Write" if recv.s.is_some() => {
                let add = match n.as_str() {
                    "WriteByte" | "WriteRune" => match a(0).int.and_then(|x| u32::try_from(x).ok()).filter(|&x| char::from_u32(x).is_some()) {
                        Some(c) => Val::text(vec![c]).with_kinds(&a(0)),
                        None => derived(&a(0)),
                    },
                    "Write" => self.convert("string", a(0)),
                    _ => a(0),
                };
                let new = Val::concat(&recv, &add);
                self.charge(new.s.as_ref().map_or(0, |s| s.len()));
                self.assign_to(f, recv_e, new, false);
                return Val::unknown();
            }
            "String" | "Bytes" | "Encode" | "Text" if recv.s.is_some() => return recv,
            "Set" | "Add" if recv.s.is_some() && args.len() == 2 => {
                // url.Values: `k=v&`
                let mut new = recv.clone();
                if new.s.as_ref().is_some_and(|s| !s.is_empty()) {
                    new = Val::concat(&new, &Val::text(u("&")));
                }
                new = Val::concat(&new, &a(0));
                new = Val::concat(&new, &Val::text(u("=")));
                new = Val::concat(&new, &a(1));
                self.assign_to(f, recv_e, new, false);
                return Val::unknown();
            }
            "Replace" if recv.items.is_some() && recv.s.is_none() => {
                // a strings.Replacer: its pairs applied in order
                let pairs: Vec<Val> = recv.items.as_ref().map(|i| (**i).clone()).unwrap_or_default();
                let mut v = a(0);
                for pair in pairs.chunks(2) {
                    if let [from, to] = pair {
                        if let (Some(t), Some(fr)) = (&v.s, from.s.as_ref().filter(|x| !x.is_empty() && !x.contains(&UNKNOWN))) {
                            v = Val::text(pystr::replace(t, fr, &to.text_or_unknown())).with_kinds(&v).with_kinds(to);
                        }
                    }
                }
                return v;
            }
            "Len" if recv.s.is_some() => return Val::unknown(),
            "Reset" => {
                self.assign_to(f, recv_e, Val::text(Vec::new()), false);
                return Val::unknown();
            }
            _ => {}
        }
        // the package's own method of that name (a few, when the receiver is not known)
        let k: &'k Module<'a> = self.k;
        let cands: Vec<(u16, NodeId)> = k.pkgs[f.pkg as usize].methods.get(name).cloned().unwrap_or_default();
        if !cands.is_empty() && !is_std_method(&n) {
            return self.call_cands(&cands, args, Some(recv), spread);
        }
        let mut v = derived(&recv);
        for x in &args {
            v.add_kinds(x);
        }
        v
    }

    /// A base64 encoding's decoding: the standard alphabets, or the encoding's own (`base64.NewEncoding`).
    fn b64_decode(&mut self, enc: &Val, a: &Val, at: u32) -> Val {
        if let (Some(alphabet), Some(t)) = (enc.s.as_ref().filter(|x| x.len() == 64 && !x.contains(&UNKNOWN)), a.s.as_ref().filter(|_| a.known())) {
            const STD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let std: Vec<u32> = STD.chars().map(|c| c as u32).collect();
            let mapped: Option<PyStr> = t
                .iter()
                .filter(|&&c| !matches!(char::from_u32(c), Some(' ' | '\n' | '\r' | '\t')))
                .map(|&c| if c == '=' as u32 { Some(c) } else { alphabet.iter().position(|&x| x == c).map(|k| std[k]) })
                .collect();
            if let Some(m) = mapped {
                return events::decode_b64(&Val::text(m).with_kinds(a), at);
            }
        }
        events::decode_b64(a, at)
    }
}

/// `%XX` escapes read (`url.QueryUnescape`; `+` as a space).
fn percent_decode(t: &[u32]) -> PyStr {
    let mut bytes: PyStr = Vec::with_capacity(t.len());
    let mut k = 0;
    while k < t.len() {
        let c = t[k];
        if c == '%' as u32 && k + 2 < t.len() {
            let h = |x: u32| char::from_u32(x).and_then(|ch| ch.to_digit(16));
            if let (Some(a), Some(b)) = (h(t[k + 1]), h(t[k + 2])) {
                bytes.push(a * 16 + b);
                k += 3;
                continue;
            }
        }
        if c == '+' as u32 {
            bytes.push(' ' as u32);
        } else if c < 0x80 {
            bytes.push(c);
        } else {
            let mut buf = [0u8; 4];
            if let Some(ch) = char::from_u32(c) {
                bytes.extend(ch.encode_utf8(&mut buf).bytes().map(|b| b as u32));
            }
        }
        k += 1;
    }
    val::utf8(&bytes)
}
