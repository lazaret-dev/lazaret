//! The reader's evaluation of Rust code: what a function's statements do, followed into the crate's own
//! functions and closures, recorded as events (0.1.9).
//!
//! It evaluates the way the supply-chain models of Python and JavaScript read their trees: each expression
//! is a [`Val`] (the text it builds, the data it carries, the handle it is), each statement updates the
//! function's names, and the calls that matter are recorded: a process started ([`Ev::Run`]), data sent
//! ([`Ev::Send`]), a file written ([`Ev::Write`]), a name looked up ([`Ev::Lookup`]), a library loaded
//! ([`Ev::Load`]). Branches are both taken and a loop's body is read once (for each item of a list it
//! knows, up to a few); a call of the crate's own function is followed with its arguments, a few calls
//! deep, and a closure where it is called. Work is bounded by steps; past them a call is not followed.
//!
//! The APIs it knows are std's (`process::Command`, `env`, `fs`, `net`, `io`), and the crates a build script
//! or a payload uses to fetch, send or decode: reqwest, ureq, minreq, attohttpc, curl, base64, hex,
//! hickory/trust-dns, dns-lookup, libloading, dirs/home, whoami/hostname. A path is resolved through the
//! file's `use` declarations; an unresolved `Command::new` is read as std's.

use super::ast::{self, Block, Ex, Op, Pat, Stmt, Toks};
use super::val::{self, Obj, Val, UNKNOWN};
use crate::jsflow::supply::{K_BYTES, K_DECODED, K_ENV, K_FILE, K_IDENTITY, K_PATH, K_RECEIVED, K_REPORT, K_WHOLE_ENV};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::rsparse::{Kind as IK, Tree, NONE};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// A file of the crate, as the evaluator reads it.
pub struct FileRef<'a> {
    pub path: PyStr,
    pub src: &'a [u32],
    pub tree: Tree,
    /// A name a `use` brings in -> its path's segments.
    pub uses: HashMap<PyStr, Vec<PyStr>>,
    /// The compilation unit it is part of (the build script's, the library's, a binary's; 0: none).
    pub unit: u8,
    /// Items inside `#[cfg(test)]` or marked `#[test]`: not built into a dependent.
    pub test_items: HashSet<u32>,
}

pub struct Krate<'a> {
    pub files: Vec<FileRef<'a>>,
    /// (unit, name) -> the functions of that name (file, item).
    pub fns: HashMap<(u8, PyStr), Vec<(u16, u32)>>,
    /// (unit, name) -> constants and statics of that name.
    pub consts: HashMap<(u8, PyStr), Vec<(u16, u32)>>,
    /// Functions whose body holds base64's alphabet: a decoder written out.
    pub b64_fns: HashSet<(u16, u32)>,
}

/// A command being built or run.
#[derive(Clone, Debug, Default)]
pub struct CmdState {
    pub prog: Val,
    pub args: Vec<Val>,
    pub file: u16,
    pub at: u32,
    /// stdin, stdout or stderr given a connection: a shell's input and output on the network.
    pub conn_io: bool,
    /// Its output thrown away or its window hidden: run out of sight.
    pub hidden: bool,
    pub ran: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ReqState {
    pub url: Val,
    pub body: Val,
}

#[derive(Clone, Debug, Default)]
pub struct ConnState {
    pub addr: Val,
}

#[derive(Clone, Debug, Default)]
pub struct WState {
    pub path: Val,
    pub append: bool,
}

pub struct ClosureState {
    pub params: Vec<Pat>,
    pub body: Rc<Ex>,
    pub env: HashMap<PyStr, Val>,
    pub file: u16,
}

/// What the code does.
#[derive(Clone, Debug)]
pub enum Ev {
    /// A process started: its command line as a shell would read it, its program and arguments.
    Run { file: u16, at: u32, line: PyStr, prog: Val, args: Vec<Val>, script: Option<Val>, conn_io: bool, hidden: bool },
    /// Data sent to an address (`in_address`: the data is in the address itself).
    Send { file: u16, at: u32, data: Val, dest: Val, in_address: bool },
    /// A file written.
    Write { file: u16, at: u32, path: Val, data: Val, append: bool },
    /// A name looked up in the DNS (`txt`: its TXT records read).
    Lookup { file: u16, at: u32, name: Val, txt: bool },
    /// A library loaded from a path.
    Load { file: u16, at: u32, path: Val },
}

struct Frame {
    file: u16,
    vars: HashMap<PyStr, Val>,
    ret: Option<Val>,
}

/// The shells and interpreters a command line names, to read what they are handed.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "busybox"];

pub struct Model<'k, 'a> {
    pub k: &'k Krate<'a>,
    pub p: &'k Pack,
    pub cmds: Vec<CmdState>,
    pub reqs: Vec<ReqState>,
    pub conns: Vec<ConnState>,
    pub wfiles: Vec<WState>,
    pub closures: Vec<ClosureState>,
    pub events: Vec<Ev>,
    /// The functions a root's reading reached.
    pub reached: HashSet<(u16, u32)>,
    bodies: HashMap<(u16, u32), Rc<(Vec<Pat>, Block)>>,
    const_cache: HashMap<(u16, u32), Val>,
    const_stack: Vec<(u16, u32)>,
    stack: Vec<(u16, u32)>,
    steps: u64,
    pub max_steps: u64,
    pub max_depth: usize,
    next_id: u32,
    unit: u8,
    /// The functions not to follow (another scope's): their values are not known here.
    pub not_follow: HashSet<(u16, u32)>,
}

fn eqs(a: &[u32], b: &str) -> bool {
    pystr::eq(a, b)
}

/// Does `segs` end with `tail`?
fn ends(segs: &[PyStr], tail: &[&str]) -> bool {
    segs.len() >= tail.len() && segs[segs.len() - tail.len()..].iter().zip(tail).all(|(a, b)| eqs(a, b))
}

fn starts(segs: &[PyStr], head: &str) -> bool {
    segs.first().is_some_and(|s| eqs(s, head))
}

impl<'k, 'a> Model<'k, 'a> {
    pub fn new(k: &'k Krate<'a>, p: &'k Pack) -> Self {
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
            bodies: HashMap::new(),
            const_cache: HashMap::new(),
            const_stack: Vec::new(),
            stack: Vec::new(),
            steps: 0,
            max_steps: 2_000_000,
            max_depth: 8,
            next_id: 1,
            unit: 0,
            not_follow: HashSet::new(),
        }
    }

    fn step(&mut self) -> bool {
        self.steps += 1;
        if self.steps & 63 == 0 && !crate::budget::spend(1) {
            self.steps = self.max_steps;
        }
        self.steps < self.max_steps
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

    fn toks(&self, file: u16) -> Toks<'_> {
        let f = &self.k.files[file as usize];
        Toks { src: f.src, toks: &f.tree.toks, mate: &f.tree.mate }
    }

    // ---------------------------------------------------------------- functions --

    /// The parameters and the body of a function item.
    fn body(&mut self, file: u16, item: u32) -> Option<Rc<(Vec<Pat>, Block)>> {
        if let Some(b) = self.bodies.get(&(file, item)) {
            return Some(b.clone());
        }
        let f = &self.k.files[file as usize];
        let it = f.tree.items.get(item as usize)?;
        if it.kind != IK::Fn || it.body_open == NONE || it.body_close == NONE {
            return None;
        }
        let t = Toks { src: f.src, toks: &f.tree.toks, mate: &f.tree.mate };
        let params = match params_open(&f.tree, f.src, it.name, it.body_open) {
            Some(open) => ast::params(t, open),
            None => Vec::new(),
        };
        let block = ast::block(t, it.body_open as usize);
        let b = Rc::new((params, block));
        self.bodies.insert((file, item), b.clone());
        Some(b)
    }

    /// Reads a function as a root: its parameters not known.
    pub fn run_root(&mut self, file: u16, item: u32) {
        let unit = self.k.files[file as usize].unit;
        self.unit = unit;
        self.call_fn(file, item, Vec::new(), None);
    }

    /// Calls a function of the crate with `args` (`recv` for a method's `self`); its value.
    fn call_fn(&mut self, file: u16, item: u32, args: Vec<Val>, recv: Option<Val>) -> Val {
        if self.stack.len() >= self.max_depth || self.stack.contains(&(file, item)) || !self.step() || self.not_follow.contains(&(file, item)) {
            let mut v = Val::unknown();
            for a in &args {
                v.add_kinds(a);
            }
            return v;
        }
        // a decoder written out: base64's alphabet in its body
        if self.k.b64_fns.contains(&(file, item)) {
            if let Some(a) = args.iter().find(|a| a.known()).or(args.first()) {
                return self.decode_b64(a, 0);
            }
        }
        let Some(body) = self.body(file, item) else { return Val::unknown() };
        self.reached.insert((file, item));
        self.stack.push((file, item));
        let mut frame = Frame { file, vars: HashMap::new(), ret: None };
        let mut args = args.into_iter();
        let (params, block) = (&body.0, &body.1);
        for (k, p) in params.iter().enumerate() {
            let v = if k == 0 && matches!(p, Pat::Bind(n) if eqs(n, "self")) {
                recv.clone().unwrap_or_default()
            } else {
                args.next().unwrap_or_default()
            };
            self.bind(&mut frame, p, v);
        }
        let tail = self.exec_block(&mut frame, block);
        self.stack.pop();
        match frame.ret {
            Some(r) => r.union(&tail),
            None => tail,
        }
    }

    // ---------------------------------------------------------------- statements --
    fn exec_block(&mut self, f: &mut Frame, b: &Block) -> Val {
        for s in &b.stmts {
            if !self.step() {
                return Val::unknown();
            }
            match s {
                Stmt::Let(pat, init, els) => {
                    let v = match init {
                        Some(e) => self.eval(f, e),
                        None => Val::unknown(),
                    };
                    self.bind(f, pat, v);
                    if let Some(els) = els {
                        self.exec_block(f, els);
                    }
                }
                Stmt::Expr(e) => {
                    self.eval(f, e);
                }
            }
        }
        match &b.tail {
            Some(e) => self.eval(f, e),
            None => Val::unknown(),
        }
    }

    fn bind(&mut self, f: &mut Frame, p: &Pat, v: Val) {
        match p {
            Pat::Bind(n) => {
                let mut v = v;
                if v.id == 0 && v.s.is_none() {
                    v.id = self.fresh_id();
                }
                f.vars.insert(n.clone(), v);
            }
            Pat::Ref(inner) => self.bind(f, inner, v),
            Pat::TupleStruct(name, parts) => {
                // Some(x), Ok(x), Err(e): the wrapped value is the value
                if parts.len() == 1 && !eqs(name, "Err") {
                    self.bind(f, &parts[0], v);
                } else {
                    for (k, part) in parts.iter().enumerate() {
                        let item = self.item_of(&v, k);
                        self.bind(f, part, item);
                    }
                }
            }
            Pat::Tuple(parts) | Pat::Slice(parts) => {
                for (k, part) in parts.iter().enumerate() {
                    let item = self.item_of(&v, k);
                    self.bind(f, part, item);
                }
            }
            Pat::Struct(_, fields) => {
                for (_, part) in fields {
                    let item = derived(&v);
                    self.bind(f, part, item);
                }
            }
            Pat::Or(alts) => {
                if let Some(first) = alts.first() {
                    self.bind(f, first, v);
                }
            }
            Pat::Wild | Pat::Rest | Pat::Other => {}
        }
    }

    fn item_of(&self, v: &Val, k: usize) -> Val {
        match &v.items {
            Some(items) => items.get(k).cloned().unwrap_or_else(|| derived(v)),
            None => derived(v),
        }
    }

    // ---------------------------------------------------------------- names and paths --
    /// A path's segments with a `use` alias at its head replaced by what it names.
    fn resolve(&self, file: u16, segs: &[PyStr]) -> Vec<PyStr> {
        let Some(head) = segs.first() else { return Vec::new() };
        let f = &self.k.files[file as usize];
        if let Some(full) = f.uses.get(head) {
            let mut out = full.clone();
            out.extend(segs[1..].iter().cloned());
            return out;
        }
        if eqs(head, "crate") || eqs(head, "self") && segs.len() > 1 || eqs(head, "super") {
            return segs[1..].to_vec();
        }
        segs.to_vec()
    }

    fn var(&mut self, f: &mut Frame, name: &[u32]) -> Option<Val> {
        if let Some(v) = f.vars.get(name) {
            return Some(v.clone());
        }
        None
    }

    /// A constant or static of the crate by name: its initializer's value.
    fn constant(&mut self, name: &[u32]) -> Option<Val> {
        let cands = self.k.consts.get(&(self.unit, name.to_vec()))?.clone();
        let (file, item) = *cands.first()?;
        if let Some(v) = self.const_cache.get(&(file, item)) {
            return Some(v.clone());
        }
        if self.const_stack.contains(&(file, item)) || self.const_stack.len() > 16 {
            return Some(Val::unknown());
        }
        let fr = &self.k.files[file as usize];
        let it = fr.tree.items.get(item as usize)?;
        if it.extra == NONE {
            return None;
        }
        let t = Toks { src: fr.src, toks: &fr.tree.toks, mate: &fr.tree.mate };
        let mut end = it.tok_end as usize;
        // (the initializer ends before the item's `;`)
        if end > 0 && fr.tree.toks.get(end - 1).is_some_and(|k| fr.src.get(k.start as usize) == Some(&(';' as u32))) {
            end -= 1;
        }
        let e = ast::expr_of(t, it.extra as usize + 1, end);
        self.const_stack.push((file, item));
        let mut frame = Frame { file, vars: HashMap::new(), ret: None };
        let v = self.eval(&mut frame, &e);
        self.const_stack.pop();
        self.const_cache.insert((file, item), v.clone());
        Some(v)
    }

    // ---------------------------------------------------------------- expressions --
    fn eval(&mut self, f: &mut Frame, e: &Ex) -> Val {
        if !self.step() {
            return Val::unknown();
        }
        match e {
            Ex::Unknown(_) | Ex::Bool(..) | Ex::Continue(_) => Val::unknown(),
            Ex::Str(s, _, _) => Val::text(s.clone()),
            Ex::Int(n, _) => Val::int(*n),
            Ex::Char(c, _) => {
                let mut v = Val::text(vec![*c]);
                v.int = Some(*c as i128);
                v
            }
            Ex::Path(segs, at) => self.path_value(f, segs, *at),
            Ex::Macro(segs, open, close, at) => self.macro_value(f, segs, *open, *close, *at),
            Ex::Call(callee, args, at) => self.call(f, callee, args, *at),
            Ex::Method(recv, name, args, at) => self.method(f, recv, name, args, *at),
            Ex::Field(base, name, _) => {
                let v = self.eval(f, base);
                if let Obj::Output(c) = v.obj {
                    if eqs(name, "stdout") || eqs(name, "stderr") {
                        return self.output_of(c);
                    }
                }
                if name.iter().all(|&c| (b'0' as u32..=b'9' as u32).contains(&c)) {
                    let k: usize = pystr::to_string(name).parse().unwrap_or(0);
                    return self.item_of(&v, k);
                }
                derived(&v)
            }
            Ex::Index(base, idx, _) => {
                let v = self.eval(f, base);
                let i = self.eval(f, idx);
                if let (Some(items), Some(k)) = (&v.items, i.int) {
                    if k >= 0 {
                        return items.get(k as usize).cloned().unwrap_or_else(|| derived(&v));
                    }
                }
                if let (Some(s), Some(k)) = (&v.s, i.int) {
                    if k >= 0 && (k as usize) < s.len() && !s.contains(&UNKNOWN) {
                        let mut c = Val::int(s[k as usize] as i128).with_kinds(&v);
                        c.s = Some(Rc::new(vec![s[k as usize]]));
                        return c;
                    }
                }
                derived(&v).with_kinds(&i)
            }
            Ex::Unary(op, inner, _) => {
                let v = self.eval(f, inner);
                match (*op, v.int) {
                    (b'-', Some(n)) => Val::int(-n),
                    (b'*', _) => v,
                    _ => derived(&v),
                }
            }
            Ex::Ref(inner, _) | Ex::Try(inner) | Ex::Await(inner) => self.eval(f, inner),
            Ex::Cast(inner, ty) => {
                let v = self.eval(f, inner);
                if eqs(ty, "char") {
                    if let Some(n) = v.int {
                        let mut c = Val::text(vec![(n & 0x10FFFF) as u32]).with_kinds(&v);
                        c.int = Some(n);
                        return c;
                    }
                }
                if ty.first() == Some(&('u' as u32)) || ty.first() == Some(&('i' as u32)) {
                    if let Some(n) = v.int {
                        let bits = pystr::to_string(&ty[1..]).parse::<u32>().unwrap_or(64);
                        let n = if bits < 128 && ty[0] == 'u' as u32 { n & ((1i128 << bits) - 1) } else { n };
                        return Val::int(n).with_kinds(&v);
                    }
                }
                v
            }
            Ex::Bin(op, a, b, _) => {
                let x = self.eval(f, a);
                let y = self.eval(f, b);
                self.binary(*op, &x, &y)
            }
            Ex::Assign(op, lhs, rhs, _) => {
                let v = self.eval(f, rhs);
                self.assign(f, *op, lhs, v);
                Val::unknown()
            }
            Ex::Range(..) => Val::unknown(),
            Ex::Tuple(items, _) | Ex::Array(items, _) => {
                let vals: Vec<Val> = items.iter().map(|x| self.eval(f, x)).collect();
                Val::list(vals)
            }
            Ex::Repeat(x, n, _) => {
                let v = self.eval(f, x);
                let n = self.eval(f, n).int.unwrap_or(0).clamp(0, 256) as usize;
                Val::list(vec![v; n])
            }
            Ex::Struct(_, fields, _) => {
                let vals: Vec<Val> = fields.iter().map(|(_, x)| self.eval(f, x)).collect();
                let mut v = Val::unknown();
                for x in &vals {
                    v.add_kinds(x);
                }
                v.items = Some(Rc::new(vals));
                v
            }
            Ex::Block(b) => self.exec_block(f, b),
            Ex::If(cond, then, els, _) => {
                self.eval(f, cond);
                let a = self.exec_block(f, then);
                match els {
                    Some(e) => {
                        let b = self.eval(f, e);
                        a.union(&b)
                    }
                    None => a,
                }
            }
            Ex::Match(scrut, arms, _) => {
                let v = self.eval(f, scrut);
                let mut out: Option<Val> = None;
                for arm in arms {
                    self.bind(f, &arm.pat, v.clone());
                    if let Some(g) = &arm.guard {
                        self.eval(f, g);
                    }
                    let r = self.eval(f, &arm.body);
                    out = Some(match out {
                        Some(o) => o.union(&r),
                        None => r,
                    });
                }
                out.unwrap_or_default()
            }
            Ex::Loop(b, _) => {
                self.exec_block(f, b);
                Val::unknown()
            }
            Ex::While(cond, b, _) => {
                self.eval(f, cond);
                self.exec_block(f, b);
                Val::unknown()
            }
            Ex::For(pat, iter, b, _) => {
                let it = self.eval(f, iter);
                self.xor_loop(f, b);
                match &it.items {
                    Some(items) if !items.is_empty() => {
                        for item in items.iter().take(8).cloned().collect::<Vec<_>>() {
                            self.bind(f, pat, item);
                            self.exec_block(f, b);
                        }
                    }
                    _ => {
                        let el = derived(&it);
                        self.bind(f, pat, el);
                        self.exec_block(f, b);
                    }
                }
                Val::unknown()
            }
            Ex::Closure(params, body, _) => {
                let idx = self.closures.len() as u32;
                self.closures.push(ClosureState { params: params.clone(), body: Rc::new((**body).clone()), env: f.vars.clone(), file: f.file });
                Val::obj(Obj::Closure(idx))
            }
            Ex::Return(v, _) => {
                let r = match v {
                    Some(x) => self.eval(f, x),
                    None => Val::unknown(),
                };
                f.ret = Some(match f.ret.take() {
                    Some(o) => o.union(&r),
                    None => r,
                });
                Val::unknown()
            }
            Ex::Break(v, _) => {
                if let Some(x) = v {
                    self.eval(f, x);
                }
                Val::unknown()
            }
            Ex::Let(pat, x, _) => {
                let v = self.eval(f, x);
                self.bind(f, pat, v);
                Val::unknown()
            }
        }
    }

    fn binary(&mut self, op: Op, x: &Val, y: &Val) -> Val {
        if op == Op::Add && (x.s.is_some() || y.s.is_some()) && x.int.is_none() {
            return Val::concat(x, y);
        }
        if let (Some(a), Some(b)) = (x.int, y.int) {
            let n = match op {
                Op::Add => a.checked_add(b),
                Op::Sub => a.checked_sub(b),
                Op::Mul => a.checked_mul(b),
                Op::Div => a.checked_div(b),
                Op::Rem => a.checked_rem(b),
                Op::BitXor => Some(a ^ b),
                Op::BitAnd => Some(a & b),
                Op::BitOr => Some(a | b),
                Op::Shl => (0..127).contains(&b).then(|| a.wrapping_shl(b as u32)),
                Op::Shr => (0..127).contains(&b).then(|| a >> b),
                _ => None,
            };
            if let Some(n) = n {
                let mut v = Val::int(n);
                v.add_kinds(x);
                v.add_kinds(y);
                if op == Op::BitXor {
                    return v.decoded(0);
                }
                return v;
            }
        }
        let mut v = Val::unknown();
        v.add_kinds(x);
        v.add_kinds(y);
        if op == Op::BitXor {
            v = v.decoded(0);
        }
        v
    }

    fn assign(&mut self, f: &mut Frame, op: Option<Op>, lhs: &Ex, v: Val) {
        match lhs {
            Ex::Path(segs, _) if segs.len() == 1 => {
                let name = &segs[0];
                let new = match op {
                    None => v,
                    Some(o) => {
                        let old = f.vars.get(name).cloned().unwrap_or_default();
                        self.binary(o, &old, &v)
                    }
                };
                f.vars.insert(name.clone(), new);
            }
            Ex::Index(base, _, _) => {
                // `b[i] ^= k`: the list is decoded where it is changed
                if let Ex::Path(segs, _) = &**base {
                    if segs.len() == 1 {
                        if let Some(old) = f.vars.get(&segs[0]).cloned() {
                            let mut new = old.clone();
                            new.add_kinds(&v);
                            if op == Some(Op::BitXor) || matches!(op, None) && v.kinds & K_DECODED != 0 {
                                new = new.decoded(0);
                            }
                            f.vars.insert(segs[0].clone(), new);
                        }
                    }
                }
            }
            Ex::Field(base, _, _) | Ex::Unary(_, base, _) => {
                if let Ex::Path(segs, _) = &**base {
                    if segs.len() == 1 {
                        if let Some(old) = f.vars.get(&segs[0]).cloned() {
                            let new = old.with_kinds(&v);
                            f.vars.insert(segs[0].clone(), new);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// A loop `for i in …` whose body XORs a list's items in place (`b[i] ^= k`, `b[i] = b[i] ^ k[i % n]`):
    /// the list's text decoded, when it and the key are known.
    fn xor_loop(&mut self, f: &mut Frame, b: &Block) {
        for s in &b.stmts {
            let Stmt::Expr(Ex::Assign(op, lhs, rhs, _)) = s else { continue };
            let Ex::Index(base, _, _) = &**lhs else { continue };
            let Ex::Path(segs, _) = &**base else { continue };
            if segs.len() != 1 {
                continue;
            }
            let key: Option<Val> = match (op, &**rhs) {
                (Some(Op::BitXor), k) => Some(self.eval(f, k)),
                (None, Ex::Bin(Op::BitXor, a, k, _)) if matches!(&**a, Ex::Index(..)) => Some(self.eval(f, k)),
                _ => None,
            };
            let Some(key) = key else { continue };
            let Some(old) = f.vars.get(&segs[0]).cloned() else { continue };
            let bytes = list_ints(&old);
            if let (Some(bytes), Some(k)) = (bytes, key.int) {
                let out: Vec<Val> = bytes.iter().map(|&x| Val::int(x ^ k)).collect();
                let mut v = Val::list(out).decoded(0);
                v.add_kinds(&old);
                f.vars.insert(segs[0].clone(), v);
            } else {
                f.vars.insert(segs[0].clone(), old.decoded(0));
            }
        }
    }

    fn path_value(&mut self, f: &mut Frame, segs: &[PyStr], at: u32) -> Val {
        if segs.len() == 1 {
            if let Some(v) = self.var(f, &segs[0]) {
                return v;
            }
        }
        let full = self.resolve(f.file, segs);
        // std::env::consts and the like: not data
        if let Some(last) = segs.last() {
            if let Some(v) = self.constant(last) {
                return v;
            }
            if ends(&full, &["consts", "OS"]) {
                return Val::text(u("linux"));
            }
        }
        let _ = at;
        Val::unknown()
    }

    // ---------------------------------------------------------------- macros --
    fn macro_args(&mut self, f: &mut Frame, open: u32, close: u32) -> (Vec<Val>, Vec<(PyStr, Val)>, Vec<Ex>) {
        let t = self.toks(f.file);
        let exprs = ast::macro_args(t, open as usize, close as usize);
        let mut pos = Vec::new();
        let mut named = Vec::new();
        let mut raw = Vec::new();
        for (name, e) in exprs {
            let v = self.eval(f, &e);
            match name {
                Some(n) => named.push((n, v)),
                None => {
                    pos.push(v);
                    raw.push(e);
                }
            }
        }
        (pos, named, raw)
    }

    fn macro_value(&mut self, f: &mut Frame, segs: &[PyStr], open: u32, close: u32, at: u32) -> Val {
        let Some(name) = segs.last().cloned() else { return Val::unknown() };
        let n = pystr::to_string(&name);
        match n.as_str() {
            "format" | "format_args" | "concat" | "println" | "print" | "eprintln" | "eprint" | "panic" | "write" | "writeln" => {}
            "vec" => {
                let t = self.toks(f.file);
                if let Some((x, count)) = ast::macro_repeat(t, open as usize, close as usize) {
                    let v = self.eval(f, &x);
                    let c = self.eval(f, &count).int.unwrap_or(0).clamp(0, 256) as usize;
                    return Val::list(vec![v; c]);
                }
                let (pos, _, _) = self.macro_args(f, open, close);
                return Val::list(pos);
            }
            "include_bytes" | "include_str" => {
                let (pos, _, _) = self.macro_args(f, open, close);
                let what = pos.first().map(|v| v.text_or_unknown()).unwrap_or_default();
                let mut v = Val::source(K_BYTES, what, at);
                v.id = self.fresh_id();
                return v;
            }
            "env" | "option_env" => {
                let (pos, _, _) = self.macro_args(f, open, close);
                let name = pos.first().map(|v| v.text_or_unknown()).unwrap_or_default();
                return self.env_var(&name, at);
            }
            _ => {
                // any other macro: its arguments are read (a call inside one still runs), its value not known
                if n.starts_with("assert") || n.starts_with("debug_assert") || matches!(n.as_str(), "dbg" | "matches" | "cfg" | "todo" | "unimplemented" | "unreachable") {
                    return Val::unknown();
                }
                let t = self.toks(f.file);
                if ast::macro_looks_like_args(t, open as usize, close as usize) {
                    let (pos, named, _) = self.macro_args(f, open, close);
                    let mut v = Val::unknown();
                    for x in pos.iter().chain(named.iter().map(|(_, v)| v)) {
                        v.add_kinds(x);
                    }
                    return v;
                }
                return Val::unknown();
            }
        }
        let (pos, named, _) = self.macro_args(f, open, close);
        match n.as_str() {
            "concat" => {
                let mut v = Val::text(Vec::new());
                for x in &pos {
                    v = Val::concat(&v, x);
                }
                v
            }
            "write" | "writeln" => {
                // write!(w, fmt, args…): what the writer is given
                let Some(w) = pos.first().cloned() else { return Val::unknown() };
                let fmt = pos.get(1).map(|v| v.text_or_unknown()).unwrap_or_default();
                let file = f.file;
                let mut lookup = |name: &[u32]| -> Val { Val::text(name.to_vec()) };
                let mut text = val::format(&fmt, &pos[2.min(pos.len())..], &named, &mut lookup);
                if n == "writeln" {
                    text = Val::concat(&text, &Val::text(vec![10]));
                }
                self.write_to(&w, &text, file, at);
                Val::unknown()
            }
            _ => {
                if pos.is_empty() {
                    return Val::text(Vec::new());
                }
                let fmt = pos[0].text_or_unknown();
                let vars: HashMap<PyStr, Val> = f.vars.clone();
                let mut lookup = |name: &[u32]| -> Val { vars.get(name).cloned().unwrap_or_default() };
                let v = val::format(&fmt, &pos[1..], &named, &mut lookup);
                if matches!(n.as_str(), "println" | "print" | "eprintln" | "eprint" | "panic") {
                    return Val::unknown();
                }
                v
            }
        }
    }

    // ---------------------------------------------------------------- sources --
    /// An environment variable read: the kind its name says (an identity, a secret; a home folder is a path).
    fn env_var(&mut self, name: &[u32], at: u32) -> Val {
        let p = self.p;
        if p.re("_SH_IDENTITY_VAR_RE").match_(name).is_some() {
            return Val::source(K_IDENTITY, name.to_vec(), at);
        }
        if p.re("_SH_SECRET_VAR_RE").search(name).is_some() && p.re("_LD_ENV_QUIET_RE").match_(name).is_none() {
            let mut v = Val::source(K_ENV, name.to_vec(), at);
            v.s = Some(Rc::new(cat(&[&u("$"), name])));
            return v;
        }
        if ["HOME", "USERPROFILE"].iter().any(|h| eqs(name, h)) {
            let mut v = Val::text(u("~"));
            v.add_kinds(&Val::source(K_PATH, name.to_vec(), at));
            return v;
        }
        if ["APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "PROGRAMDATA"].iter().any(|h| eqs(name, h)) {
            return Val::text(cat(&[&u("%"), name, &u("%")]));
        }
        let mut v = Val::unknown();
        v.s = Some(Rc::new(cat(&[&u("${"), name, &u("}")])));
        v
    }

    fn home(&self, sub: &str) -> Val {
        Val::text(u(sub))
    }

    /// What a file read gives: data read from the machine when the path is outside the package.
    fn file_read(&mut self, path: &Val, at: u32) -> Val {
        let text = path.text_or_unknown();
        let outside = path.kinds & K_PATH != 0 || outside_path(self.p, &text);
        if !outside {
            let mut v = Val::unknown();
            v.add_kinds(path);
            return v;
        }
        let shown = shown_path(&text);
        let mut v = Val::source(K_FILE, shown.clone(), at);
        if crate::jsflow::supply::cred_store(self.p, &shown) {
            let c = Val::source(crate::jsflow::supply::K_CRED_FILE, shown, at);
            v.add_kinds(&c);
        }
        v
    }

    fn output_of(&self, cmd: u32) -> Val {
        let Some(c) = self.cmds.get(cmd as usize) else { return Val::unknown() };
        let line = command_line(c);
        let data = crate::shell::sh_output_data(self.p, &line, 0, None);
        let whole = self.p.text("_LD_WHOLE_ENV");
        let mut v = Val::unknown();
        for (kind, what) in data {
            let bit = crate::jsflow::supply::kind_bit(kind, &what, &whole);
            v.add_kinds(&Val::source(bit, what, c.at));
        }
        // (what other commands print is not the machine's data: only those the shell reader names report it)
        let _ = K_REPORT;
        v
    }

    // ---------------------------------------------------------------- sinks --
    fn write_to(&mut self, w: &Val, data: &Val, file: u16, at: u32) {
        match w.obj {
            Obj::WFile(k) => {
                let st = self.wfiles.get(k as usize).cloned().unwrap_or_default();
                self.events.push(Ev::Write { file, at, path: st.path, data: data.clone(), append: st.append });
            }
            Obj::Conn(k) => {
                let st = self.conns.get(k as usize).cloned().unwrap_or_default();
                self.events.push(Ev::Send { file, at, data: data.clone(), dest: st.addr, in_address: false });
            }
            _ => {}
        }
    }

    fn send(&mut self, file: u16, at: u32, url: &Val, body: &Val) {
        self.events.push(Ev::Send { file, at, data: url.clone(), dest: url.clone(), in_address: true });
        if body.kinds != 0 || body.s.is_some() {
            self.events.push(Ev::Send { file, at, data: body.clone(), dest: url.clone(), in_address: false });
        }
    }

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
        let line = command_line(&c);
        let script = shell_script(&c);
        self.events.push(Ev::Run { file: c.file, at: c.at, line, prog: c.prog.clone(), args: c.args.clone(), script, conn_io: c.conn_io, hidden: c.hidden });
        // a download written to a file (curl -o, wget -O, Invoke-WebRequest -OutFile, certutil): a write of what it received
        if let Some((path, url)) = download_target(&c) {
            let mut data = Val::source(K_RECEIVED, url.text_or_unknown(), c.at);
            data.add_kinds(&url);
            self.events.push(Ev::Send { file: c.file, at: c.at, data: url.clone(), dest: url.clone(), in_address: true });
            self.events.push(Ev::Write { file: c.file, at: c.at, path, data, append: false });
        }
    }

    /// Commands built but never seen run: run where they were built (a command is built to be run).
    pub fn flush_cmds(&mut self) {
        for k in 0..self.cmds.len() {
            self.run_cmd(k as u32);
        }
    }

    fn new_req(&mut self, url: Val) -> Val {
        let idx = self.reqs.len() as u32;
        self.reqs.push(ReqState { url, body: Val::unknown() });
        Val::obj(Obj::Req(idx))
    }

    fn received(&self, at: u32, what: &Val) -> Val {
        let mut v = Val::source(K_RECEIVED, what.text_or_unknown(), at);
        v.id = 0;
        v
    }

    fn decode_b64(&mut self, a: &Val, at: u32) -> Val {
        let mut v = match a.s.as_ref().filter(|_| a.known()).and_then(|s| val::base64(s)) {
            Some(bytes) => Val::text(val::utf8(&bytes)),
            None => Val::unknown(),
        };
        v.add_kinds(a);
        v.decoded(at)
    }

    fn decode_hex(&mut self, a: &Val, at: u32) -> Val {
        let mut v = match a.s.as_ref().filter(|_| a.known()).and_then(|s| val::hex(s)) {
            Some(bytes) => Val::text(val::utf8(&bytes)),
            None => Val::unknown(),
        };
        v.add_kinds(a);
        v.decoded(at)
    }

    // ---------------------------------------------------------------- calls --
    fn call(&mut self, f: &mut Frame, callee: &Ex, args: &[Ex], at: u32) -> Val {
        let vals: Vec<Val> = args.iter().map(|a| self.eval(f, a)).collect();
        let file = f.file;
        if let Ex::Path(segs, _) = callee {
            // a closure held by a name
            if segs.len() == 1 {
                if let Some(v) = f.vars.get(&segs[0]).cloned() {
                    if let Obj::Closure(c) = v.obj {
                        return self.call_closure(c, vals);
                    }
                }
            }
            let full = self.resolve(file, segs);
            if let Some(v) = self.api_call(f, &full, segs, &vals, at) {
                return v;
            }
            // the crate's own function
            if let Some(last) = segs.last() {
                let cands = self.k.fns.get(&(self.unit, last.clone())).cloned().unwrap_or_default();
                if !cands.is_empty() {
                    let mut out: Option<Val> = None;
                    for (cf, ci) in cands.into_iter().take(4) {
                        let r = self.call_fn(cf, ci, vals.clone(), None);
                        out = Some(match out {
                            Some(o) => o.union(&r),
                            None => r,
                        });
                    }
                    return out.unwrap_or_default();
                }
            }
            // a constructor that wraps its argument (Some, Ok, Box::new, String::from, PathBuf::from…)
            let mut v = vals.first().cloned().unwrap_or_default();
            for x in vals.iter().skip(1) {
                v.add_kinds(x);
            }
            return v;
        }
        let c = self.eval(f, callee);
        if let Obj::Closure(k) = c.obj {
            return self.call_closure(k, vals);
        }
        let mut v = Val::unknown();
        for x in &vals {
            v.add_kinds(x);
        }
        v
    }

    fn call_closure(&mut self, k: u32, args: Vec<Val>) -> Val {
        if self.stack.len() >= self.max_depth || !self.step() {
            return Val::unknown();
        }
        let Some(c) = self.closures.get(k as usize) else { return Val::unknown() };
        let (params, body, env, file) = (c.params.clone(), c.body.clone(), c.env.clone(), c.file);
        let mut frame = Frame { file, vars: env, ret: None };
        for (p, a) in params.iter().zip(args.into_iter().chain(std::iter::repeat(Val::unknown()))) {
            self.bind(&mut frame, p, a);
        }
        self.stack.push((u16::MAX, k));
        let v = self.eval(&mut frame, &body);
        self.stack.pop();
        match frame.ret {
            Some(r) => r.union(&v),
            None => v,
        }
    }

    /// A known API's call, by its resolved path; None when the path is not one.
    fn api_call(&mut self, f: &mut Frame, full: &[PyStr], segs: &[PyStr], vals: &[Val], at: u32) -> Option<Val> {
        let file = f.file;
        let a0 = vals.first().cloned().unwrap_or_default();
        let a1 = vals.get(1).cloned().unwrap_or_default();
        // ---- processes
        if ends(full, &["Command", "new"]) && !starts(full, "clap") {
            return Some(self.new_cmd(a0, file, at));
        }
        if ends(full, &["Stdio", "null"]) {
            return Some(Val::text(u("\u{1}null")));
        }
        if ends(full, &["Stdio", "from"]) || ends(full, &["Stdio", "from_raw_fd"]) || ends(full, &["Stdio", "from_raw_handle"]) {
            return Some(a0);
        }
        if ends(full, &["process", "exit"]) {
            return Some(Val::unknown());
        }
        // ---- the environment
        if (ends(full, &["env", "var"]) || ends(full, &["env", "var_os"])) && vals.len() == 1 {
            let name = a0.text_or_unknown();
            return Some(self.env_var(&name, at));
        }
        if ends(full, &["env", "vars"]) || ends(full, &["env", "vars_os"]) {
            let whole = self.p.text("_LD_WHOLE_ENV");
            let mut v = Val::source(K_WHOLE_ENV, whole, at);
            v.obj = Obj::EnvVars;
            return Some(v);
        }
        if ends(full, &["env", "home_dir"]) || ends(full, &["dirs", "home_dir"]) || ends(full, &["home", "home_dir"]) || ends(full, &["dirs_next", "home_dir"]) {
            let mut v = self.home("~");
            v.add_kinds(&Val::source(K_PATH, u("home"), at));
            return Some(v);
        }
        for (name, sub) in [
            ("config_dir", "~/.config"),
            ("data_dir", "~/.local/share"),
            ("data_local_dir", "~/.local/share"),
            ("cache_dir", "~/.cache"),
            ("document_dir", "~/Documents"),
            ("download_dir", "~/Downloads"),
            ("desktop_dir", "~/Desktop"),
        ] {
            if starts(full, "dirs") || starts(full, "dirs_next") {
                if ends(full, &[name]) {
                    let mut v = self.home(sub);
                    v.add_kinds(&Val::source(K_PATH, u("home"), at));
                    return Some(v);
                }
            }
        }
        if ends(full, &["env", "temp_dir"]) {
            return Some(Val::text(u("/tmp")));
        }
        // ---- who and where
        if (starts(full, "whoami") && segs.last().is_some_and(|l| ["username", "realname", "hostname", "devicename", "fallible", "username_os"].iter().any(|w| eqs(l, w))))
            || ends(full, &["hostname", "get"])
            || ends(full, &["gethostname"])
            || ends(full, &["get_current_username"])
            || (starts(full, "sys_info") && ends(full, &["hostname"]))
        {
            let what = segs.last().map(|l| if eqs(l, "get") { u("hostname") } else { l.clone() }).unwrap_or_default();
            return Some(Val::source(K_IDENTITY, what, at));
        }
        // ---- files
        if ends(full, &["fs", "read_to_string"]) || ends(full, &["fs", "read"]) {
            return Some(self.file_read(&a0, at));
        }
        if ends(full, &["File", "open"]) {
            let mut v = self.file_read(&a0, at);
            v.s = None;
            return Some(v);
        }
        if ends(full, &["fs", "read_dir"]) || ends(full, &["WalkDir", "new"]) || ends(full, &["glob", "glob"]) {
            let mut v = Val::concat(&a0, &Val::text(vec!['/' as u32, UNKNOWN]));
            v.add_kinds(&a0);
            let items = vec![v.clone()];
            v.items = Some(Rc::new(items));
            return Some(v);
        }
        if ends(full, &["fs", "write"]) {
            self.events.push(Ev::Write { file, at, path: a0, data: a1, append: false });
            return Some(Val::unknown());
        }
        if ends(full, &["fs", "copy"]) {
            let data = derived(&a0).with_kinds(&a0);
            self.events.push(Ev::Write { file, at, path: a1, data, append: false });
            return Some(Val::unknown());
        }
        if ends(full, &["File", "create"]) || ends(full, &["File", "create_new"]) {
            let idx = self.wfiles.len() as u32;
            self.wfiles.push(WState { path: a0, append: false });
            return Some(Val::obj(Obj::WFile(idx)));
        }
        if ends(full, &["OpenOptions", "new"]) {
            let idx = self.wfiles.len() as u32;
            self.wfiles.push(WState::default());
            return Some(Val::obj(Obj::WFile(idx)));
        }
        if ends(full, &["io", "copy"]) {
            // io::copy(&mut from, &mut to)
            let data = if a0.obj == Obj::Resp { self.received(at, &a0).with_kinds(&a0) } else { derived(&a0).with_kinds(&a0) };
            self.write_to(&a1, &data, file, at);
            return Some(Val::unknown());
        }
        if ends(full, &["fs", "set_permissions"]) || ends(full, &["fs", "create_dir_all"]) || ends(full, &["fs", "create_dir"]) || ends(full, &["fs", "remove_file"]) {
            return Some(Val::unknown());
        }
        if ends(full, &["Path", "new"]) || ends(full, &["PathBuf", "from"]) || ends(full, &["OsString", "from"]) || ends(full, &["String", "from"]) || ends(full, &["OsStr", "new"]) {
            return Some(a0);
        }
        if ends(full, &["String", "new"]) || ends(full, &["Vec", "new"]) || ends(full, &["PathBuf", "new"]) || ends(full, &["String", "with_capacity"]) || ends(full, &["Vec", "with_capacity"]) {
            return Some(Val::text(Vec::new()));
        }
        if ends(full, &["String", "from_utf8"]) || ends(full, &["String", "from_utf8_lossy"]) || ends(full, &["str", "from_utf8"]) || ends(full, &["String", "from_utf8_unchecked"]) {
            return Some(text_of_bytes(&a0));
        }
        if ends(full, &["char", "from"]) || ends(full, &["char", "from_u32"]) {
            if let Some(n) = a0.int {
                let mut c = Val::text(vec![(n & 0x10FFFF) as u32]).with_kinds(&a0);
                c.int = Some(n);
                return Some(c);
            }
            return Some(a0);
        }
        // ---- the network
        if ends(full, &["TcpStream", "connect"]) || ends(full, &["TcpStream", "connect_timeout"]) {
            let idx = self.conns.len() as u32;
            self.conns.push(ConnState { addr: a0.clone() });
            self.events.push(Ev::Send { file, at, data: a0.clone(), dest: a0, in_address: true });
            return Some(Val::obj(Obj::Conn(idx)));
        }
        if ends(full, &["UdpSocket", "bind"]) {
            let idx = self.conns.len() as u32;
            self.conns.push(ConnState::default());
            return Some(Val::obj(Obj::Conn(idx)));
        }
        if ends(full, &["BufReader", "new"]) || ends(full, &["BufWriter", "new"]) || ends(full, &["LineWriter", "new"]) {
            return Some(a0);
        }
        if starts(full, "reqwest") || starts(full, "ureq") || starts(full, "minreq") || starts(full, "attohttpc") || starts(full, "isahc") || starts(full, "surf") {
            let last = full.last().map(|l| pystr::to_string(l)).unwrap_or_default();
            match last.as_str() {
                "get" | "post" | "put" | "patch" | "delete" | "head" => {
                    let req = self.new_req(a0.clone());
                    // reqwest::get and reqwest::blocking::get send at once
                    if starts(full, "reqwest") || starts(full, "isahc") || (starts(full, "surf") && vals.len() == 1) {
                        self.send(file, at, &a0, &Val::unknown());
                        let mut r = self.received(at, &a0);
                        r.obj = Obj::Resp;
                        return Some(r);
                    }
                    return Some(req);
                }
                "request" => return Some(self.new_req(a1)),
                "new" | "builder" | "agent" | "build" | "Agent" | "Client" | "AgentBuilder" => return Some(Val::obj(Obj::Client)),
                _ => {}
            }
            if ends(full, &["Client", "new"]) || ends(full, &["Client", "builder"]) || ends(full, &["AgentBuilder", "new"]) {
                return Some(Val::obj(Obj::Client));
            }
        }
        if ends(full, &["Easy", "new"]) || ends(full, &["Easy2", "new"]) {
            let idx = self.reqs.len() as u32;
            self.reqs.push(ReqState::default());
            return Some(Val::obj(Obj::Curl(idx)));
        }
        if ends(full, &["lookup_host"]) || ends(full, &["dns_lookup", "lookup_host"]) {
            self.events.push(Ev::Lookup { file, at, name: a0, txt: false });
            return Some(Val::unknown());
        }
        if ends(full, &["Resolver", "new"]) || ends(full, &["Resolver", "from_system_conf"]) || ends(full, &["Resolver", "default"]) || ends(full, &["TokioAsyncResolver", "tokio"]) || ends(full, &["TokioAsyncResolver", "tokio_from_system_conf"]) {
            return Some(Val::obj(Obj::Resolver));
        }
        // ---- decodings
        if (starts(full, "base64") || starts(full, "data_encoding")) && full.last().is_some_and(|l| eqs(l, "decode") || eqs(l, "decode_config")) {
            return Some(self.decode_b64(&a0, at));
        }
        if starts(full, "hex") && full.last().is_some_and(|l| eqs(l, "decode")) {
            return Some(self.decode_hex(&a0, at));
        }
        if ends(full, &["Engine", "decode"]) {
            return Some(self.decode_b64(&a1, at));
        }
        // ---- libraries loaded
        if ends(full, &["Library", "new"]) || ends(full, &["libloading", "Library", "new"]) {
            self.events.push(Ev::Load { file, at, path: a0 });
            return Some(Val::unknown());
        }
        // ---- wrappers that keep the value
        if segs.len() == 1 && ["Some", "Ok", "Err"].iter().any(|w| eqs(&segs[0], w)) {
            return Some(a0);
        }
        if ends(full, &["Box", "new"]) || ends(full, &["Rc", "new"]) || ends(full, &["Arc", "new"]) || ends(full, &["Cow", "from"]) || ends(full, &["Cow", "Owned"]) || ends(full, &["Cow", "Borrowed"]) {
            return Some(a0);
        }
        None
    }

    // ---------------------------------------------------------------- methods --
    fn method(&mut self, f: &mut Frame, recv_e: &Ex, name: &PyStr, args: &[Ex], at: u32) -> Val {
        let recv = self.eval(f, recv_e);
        let vals: Vec<Val> = args.iter().map(|a| self.eval(f, a)).collect();
        let file = f.file;
        let n = pystr::to_string(name);
        let a0 = vals.first().cloned().unwrap_or_default();
        let a1 = vals.get(1).cloned().unwrap_or_default();
        // ---- handles
        match recv.obj {
            Obj::Cmd(c) => {
                let idx = c as usize;
                match n.as_str() {
                    "arg" => {
                        if let Some(st) = self.cmds.get_mut(idx) {
                            st.args.push(a0);
                        }
                    }
                    "args" => {
                        let items: Vec<Val> = match &a0.items {
                            Some(items) => items.iter().cloned().collect(),
                            None => vec![a0.clone()],
                        };
                        if let Some(st) = self.cmds.get_mut(idx) {
                            st.args.extend(items);
                        }
                    }
                    "stdin" | "stdout" | "stderr" => {
                        let conn = matches!(a0.obj, Obj::Conn(_));
                        let null = a0.s.as_ref().is_some_and(|s| s.first() == Some(&1));
                        if let Some(st) = self.cmds.get_mut(idx) {
                            st.conn_io |= conn;
                            st.hidden |= null;
                        }
                    }
                    "creation_flags" => {
                        // CREATE_NO_WINDOW, DETACHED_PROCESS
                        if a0.int.is_some_and(|n| n & 0x0800_0008 != 0) {
                            if let Some(st) = self.cmds.get_mut(idx) {
                                st.hidden = true;
                            }
                        }
                    }
                    "spawn" | "output" | "status" | "exec" => {
                        self.run_cmd(c);
                        if n == "output" {
                            return Val::obj(Obj::Output(c));
                        }
                        return Val::unknown();
                    }
                    _ => {}
                }
                return recv;
            }
            Obj::Output(c) => {
                if n == "stdout" || n == "stderr" {
                    return self.output_of(c);
                }
                return recv;
            }
            Obj::Client => {
                match n.as_str() {
                    "get" | "post" | "put" | "patch" | "delete" | "head" => return self.new_req(a0),
                    "request" => return self.new_req(a1),
                    _ => return recv,
                }
            }
            Obj::Req(r) => {
                let idx = r as usize;
                match n.as_str() {
                    "body" | "json" | "form" | "header" | "bearer_auth" | "basic_auth" | "headers" | "multipart" | "text" | "bytes" | "with_body" | "with_header" | "with_json" | "set" => {
                        if let Some(st) = self.reqs.get_mut(idx) {
                            for v in &vals {
                                let joined = Val::concat(&st.body, v);
                                st.body = joined.with_kinds(v);
                            }
                        }
                        return recv;
                    }
                    "query" | "param" | "with_param" => {
                        if let Some(st) = self.reqs.get_mut(idx) {
                            for v in &vals {
                                st.url = Val::concat(&st.url, v).with_kinds(v);
                            }
                        }
                        return recv;
                    }
                    "send" | "call" | "send_string" | "send_bytes" | "send_json" | "send_form" | "perform" | "await" => {
                        let st = self.reqs.get(idx).cloned().unwrap_or_default();
                        let mut body = st.body.clone();
                        for v in &vals {
                            body = Val::concat(&body, v).with_kinds(v);
                        }
                        self.send(file, at, &st.url, &body);
                        let mut r = self.received(at, &st.url);
                        r.obj = Obj::Resp;
                        return r;
                    }
                    _ => return recv,
                }
            }
            Obj::Curl(r) => {
                let idx = r as usize;
                match n.as_str() {
                    "url" => {
                        if let Some(st) = self.reqs.get_mut(idx) {
                            st.url = a0;
                        }
                    }
                    "post_fields_copy" | "post_fields" | "post_field_size" => {
                        if let Some(st) = self.reqs.get_mut(idx) {
                            st.body = a0.clone();
                        }
                    }
                    "write_function" => {
                        if let Obj::Closure(k) = a0.obj {
                            let url = self.reqs.get(idx).map(|s| s.url.clone()).unwrap_or_default();
                            let data = self.received(at, &url);
                            self.call_closure(k, vec![data]);
                        }
                    }
                    "perform" => {
                        let st = self.reqs.get(idx).cloned().unwrap_or_default();
                        self.send(file, at, &st.url, &st.body);
                    }
                    _ => {}
                }
                return recv;
            }
            Obj::Resp => {
                return match n.as_str() {
                    "copy_to" => {
                        let data = self.received(at, &recv).with_kinds(&recv);
                        self.write_to(&a0, &data, file, at);
                        Val::unknown()
                    }
                    "read_to_string" | "read_to_end" => {
                        if let Some(name) = lvalue(&args[0]) {
                            let data = self.received(at, &recv).with_kinds(&recv);
                            f.vars.insert(name, data);
                        }
                        Val::unknown()
                    }
                    _ => {
                        let mut v = self.received(at, &recv).with_kinds(&recv);
                        if matches!(n.as_str(), "error_for_status" | "into_reader" | "body_mut" | "into_body" | "bytes_stream") {
                            v.obj = Obj::Resp;
                        }
                        v
                    }
                };
            }
            Obj::Conn(k) => {
                let idx = k as usize;
                match n.as_str() {
                    "write_all" | "write" | "write_fmt" | "send" => {
                        let addr = self.conns.get(idx).map(|c| c.addr.clone()).unwrap_or_default();
                        self.events.push(Ev::Send { file, at, data: a0, dest: addr, in_address: false });
                        return Val::unknown();
                    }
                    "send_to" => {
                        self.events.push(Ev::Send { file, at, data: a0, dest: a1.clone(), in_address: false });
                        return Val::unknown();
                    }
                    "connect" => {
                        if let Some(c) = self.conns.get_mut(idx) {
                            c.addr = a0.clone();
                        }
                        self.events.push(Ev::Send { file, at, data: a0.clone(), dest: a0, in_address: true });
                        return Val::unknown();
                    }
                    "read" | "read_to_end" | "read_to_string" | "read_exact" | "read_line" | "recv" | "recv_from" | "peek" => {
                        let addr = self.conns.get(idx).map(|c| c.addr.clone()).unwrap_or_default();
                        if let Some(name) = args.first().and_then(lvalue) {
                            let data = self.received(at, &addr);
                            f.vars.insert(name, data);
                        }
                        return Val::unknown();
                    }
                    "lines" | "bytes" | "incoming" => {
                        let addr = self.conns.get(idx).map(|c| c.addr.clone()).unwrap_or_default();
                        let data = self.received(at, &addr);
                        let mut v = data.clone();
                        v.items = Some(Rc::new(vec![data]));
                        return v;
                    }
                    _ => return recv, // try_clone, as_raw_fd, set_* …: the same connection
                }
            }
            Obj::WFile(k) => {
                let idx = k as usize;
                match n.as_str() {
                    "append" => {
                        if let Some(w) = self.wfiles.get_mut(idx) {
                            w.append = !matches!(args.first(), Some(Ex::Bool(false, _)));
                        }
                        return recv;
                    }
                    "open" => {
                        if let Some(w) = self.wfiles.get_mut(idx) {
                            w.path = a0;
                        }
                        return recv;
                    }
                    "write_all" | "write" | "write_fmt" => {
                        self.write_to(&recv, &a0, file, at);
                        return Val::unknown();
                    }
                    _ => return recv, // create, write(true), truncate, mode, set_permissions, flush …
                }
            }
            Obj::Resolver => {
                if matches!(n.as_str(), "txt_lookup" | "lookup_ip" | "lookup" | "mx_lookup" | "ipv4_lookup" | "ipv6_lookup" | "ns_lookup" | "srv_lookup") {
                    let txt = n == "txt_lookup" || n == "lookup";
                    self.events.push(Ev::Lookup { file, at, name: a0.clone(), txt });
                    let mut r = self.received(at, &a0);
                    let item = r.clone();
                    r.items = Some(Rc::new(vec![item]));
                    return r;
                }
                return recv;
            }
            Obj::Closure(k) if n == "call" || n == "call_mut" || n == "call_once" => {
                return self.call_closure(k, vals);
            }
            _ => {}
        }
        // ---- a DNS lookup through ToSocketAddrs
        if n == "to_socket_addrs" {
            let name = match &recv.items {
                Some(items) => items.first().cloned().unwrap_or_default(),
                None => recv.clone(),
            };
            self.events.push(Ev::Lookup { file, at, name, txt: false });
            return Val::unknown();
        }
        // ---- base64 engines: STANDARD.decode(s), BASE64_STANDARD.decode(s), general_purpose::URL_SAFE.decode(s)
        if n == "decode" {
            if let Ex::Path(segs, _) = recv_e {
                let full = self.resolve(file, segs);
                let named_b64 = full.iter().any(|s| {
                    let t = pystr::to_string(s);
                    t.contains("STANDARD") || t.contains("URL_SAFE") || t.starts_with("BASE64") || t == "general_purpose" || t == "base64"
                });
                if named_b64 {
                    return self.decode_b64(&a0, at);
                }
                if full.iter().any(|s| pystr::to_string(s).starts_with("HEX")) {
                    return self.decode_hex(&a0, at);
                }
            }
        }
        // ---- strings, paths and lists
        if let Some(v) = self.text_method(f, &recv, recv_e, &n, &vals, at) {
            return v;
        }
        // ---- the crate's own method
        let cands = self.k.fns.get(&(self.unit, name.clone())).cloned().unwrap_or_default();
        if !cands.is_empty() && !is_std_method(&n) {
            let mut out: Option<Val> = None;
            for (cf, ci) in cands.into_iter().take(4) {
                let r = self.call_fn(cf, ci, vals.clone(), Some(recv.clone()));
                out = Some(match out {
                    Some(o) => o.union(&r),
                    None => r,
                });
            }
            return out.unwrap_or_default();
        }
        let mut v = derived(&recv);
        for x in &vals {
            v.add_kinds(x);
        }
        v
    }

    fn text_method(&mut self, f: &mut Frame, recv: &Val, recv_e: &Ex, n: &str, vals: &[Val], at: u32) -> Option<Val> {
        let a0 = vals.first().cloned().unwrap_or_default();
        let keep = |v: &Val| -> Val { v.clone() };
        Some(match n {
            "to_string" | "to_owned" | "clone" | "into" | "as_str" | "as_ref" | "to_vec" | "borrow" | "deref" | "as_path" | "as_os_str" | "to_str" | "to_string_lossy" | "display" | "into_os_string" | "into_string" | "unwrap" | "expect" | "unwrap_or_default" | "ok" | "map_err" | "context" | "with_context" | "as_slice" | "into_owned" | "to_path_buf" | "into_boxed_str" | "as_mut" | "iter" | "into_iter" | "iter_mut" | "cloned" | "copied" | "by_ref" | "unwrap_unchecked" | "flatten" | "canonicalize" | "into_inner" | "as_deref" => {
                let mut v = keep(recv);
                if v.s.is_none() {
                    if let Some(n) = recv.int.filter(|_| matches!(n, "to_string")) {
                        v = Val::text(n.to_string().chars().map(|c| c as u32).collect()).with_kinds(recv);
                    }
                }
                v
            }
            "unwrap_or" => recv.union(&a0),
            "unwrap_or_else" | "or_else" | "or" => {
                let alt = if let Obj::Closure(k) = a0.obj { self.call_closure(k, vec![]) } else { a0.clone() };
                recv.union(&alt)
            }
            "as_bytes" | "into_bytes" | "bytes" => match &recv.s {
                Some(s) if !s.contains(&UNKNOWN) => {
                    let b = val::bytes_of(s);
                    let items: Vec<Val> = b.iter().map(|&x| Val::int(x as i128)).collect();
                    let mut v = Val::list(items).with_kinds(recv);
                    v.s = Some(Rc::new(b));
                    v
                }
                _ => keep(recv),
            },
            "to_lowercase" | "to_ascii_lowercase" => map_text(recv, |s| s.iter().map(|&c| char::from_u32(c).map(|c| c.to_lowercase().next().unwrap_or(c) as u32).unwrap_or(c)).collect()),
            "to_uppercase" | "to_ascii_uppercase" => map_text(recv, |s| s.iter().map(|&c| char::from_u32(c).map(|c| c.to_uppercase().next().unwrap_or(c) as u32).unwrap_or(c)).collect()),
            "trim" | "trim_end" | "trim_start" => map_text(recv, |s| {
                let ws = |c: &u32| matches!(char::from_u32(*c), Some(' ' | '\n' | '\r' | '\t'));
                let start = if n == "trim_end" { 0 } else { s.iter().position(|c| !ws(c)).unwrap_or(s.len()) };
                let end = if n == "trim_start" { s.len() } else { s.iter().rposition(|c| !ws(c)).map(|k| k + 1).unwrap_or(start) };
                s[start..end.max(start)].to_vec()
            }),
            "replace" | "replacen" => {
                let from = vals.first().and_then(|v| v.s.clone());
                let to = vals.get(1).map(|v| v.text_or_unknown()).unwrap_or_default();
                match (&recv.s, from) {
                    (Some(s), Some(fr)) if !fr.is_empty() && !fr.contains(&UNKNOWN) => {
                        let mut v = Val::text(pystr::replace(s, &fr, &to)).with_kinds(recv);
                        if let Some(x) = vals.get(1) {
                            v.add_kinds(x);
                        }
                        v
                    }
                    _ => derived(recv),
                }
            }
            "repeat" => match (&recv.s, a0.int) {
                (Some(s), Some(k)) if (0..=64).contains(&k) => Val::text(s.repeat(k as usize)).with_kinds(recv),
                _ => derived(recv),
            },
            "push_str" | "push" | "extend" | "extend_from_slice" | "insert_str" | "append" => {
                // a change of the name's value
                if let Some(name) = lvalue(recv_e) {
                    let new = if n == "push" && recv.items.is_some() && recv.s.is_none() {
                        let mut items: Vec<Val> = recv.items.as_ref().map(|i| (**i).clone()).unwrap_or_default();
                        items.push(a0.clone());
                        let mut l = Val::list(items);
                        l.add_kinds(recv);
                        l
                    } else if n == "push" && a0.s.as_ref().is_some_and(|s| s.contains(&('/' as u32)) || s.first() == Some(&('.' as u32))) && recv.s.is_some() {
                        // PathBuf::push: a path joined
                        path_join(recv, &a0)
                    } else if a0.items.is_some() && a0.s.is_none() {
                        let mut s = recv.text_or_unknown();
                        for it in a0.items.as_ref().unwrap().iter() {
                            s.extend(it.text_or_unknown());
                        }
                        Val::text(val::collapse(s)).with_kinds(recv).with_kinds(&a0)
                    } else {
                        Val::concat(recv, &a0)
                    };
                    f.vars.insert(name, new);
                }
                Val::unknown()
            }
            "join" => {
                if let Some(items) = &recv.items {
                    if recv.s.is_none() || recv.items.as_ref().is_some_and(|i| !i.is_empty()) && recv.obj == Obj::None && recv_e_is_list(recv_e) {
                        let sep = a0.text_or_unknown();
                        let mut s: PyStr = Vec::new();
                        let mut v = Val::unknown();
                        for (k, it) in items.iter().enumerate() {
                            if k > 0 {
                                s.extend(&sep);
                            }
                            s.extend(it.text_or_unknown());
                            v.add_kinds(it);
                        }
                        let mut out = Val::text(val::collapse(s));
                        out.add_kinds(&v);
                        return Some(out);
                    }
                }
                path_join(recv, &a0)
            }
            "concat" => match &recv.items {
                Some(items) => {
                    let mut s: PyStr = Vec::new();
                    let mut v = Val::unknown();
                    for it in items.iter() {
                        s.extend(it.text_or_unknown());
                        v.add_kinds(it);
                    }
                    Val::text(val::collapse(s)).with_kinds(&v)
                }
                None => derived(recv),
            },
            "split" | "split_whitespace" | "lines" | "split_terminator" | "rsplit" | "splitn" | "split_ascii_whitespace" => match &recv.s {
                Some(s) if !s.contains(&UNKNOWN) => {
                    let parts: Vec<PyStr> = if n.contains("whitespace") {
                        pystr::split_ws(s).into_iter().map(|p| p.to_vec()).collect()
                    } else if n == "lines" {
                        s.split(|&c| c == 10).map(|p| p.to_vec()).collect()
                    } else {
                        let sep = vals.iter().rev().find_map(|v| v.s.clone()).unwrap_or_default();
                        if sep.is_empty() || sep.contains(&UNKNOWN) {
                            vec![s.to_vec()]
                        } else {
                            pystr::split_str(s, &sep).into_iter().map(|p| p.to_vec()).collect()
                        }
                    };
                    let items: Vec<Val> = parts.into_iter().map(|p| Val::text(p).with_kinds(recv)).collect();
                    let mut v = Val::list(items);
                    v.add_kinds(recv);
                    v
                }
                _ => derived(recv),
            },
            "chars" => match &recv.s {
                Some(s) if !s.contains(&UNKNOWN) && s.len() <= val::MAX_ITEMS => {
                    let items: Vec<Val> = s
                        .iter()
                        .map(|&c| {
                            let mut v = Val::text(vec![c]);
                            v.int = Some(c as i128);
                            v.with_kinds(recv)
                        })
                        .collect();
                    let mut v = Val::list(items);
                    v.add_kinds(recv);
                    v
                }
                _ => derived(recv),
            },
            "rev" => match (&recv.items, &recv.s) {
                (Some(items), _) => {
                    let mut it: Vec<Val> = (**items).clone();
                    it.reverse();
                    Val::list(it).with_kinds(recv)
                }
                (None, Some(s)) if !s.contains(&UNKNOWN) => {
                    let mut t = (**s).clone();
                    t.reverse();
                    Val::text(t).with_kinds(recv).decoded(at)
                }
                _ => derived(recv).decoded(at),
            },
            "enumerate" => match &recv.items {
                Some(items) => {
                    let pairs: Vec<Val> = items.iter().enumerate().map(|(k, it)| Val::list(vec![Val::int(k as i128), it.clone()])).collect();
                    Val::list(pairs).with_kinds(recv)
                }
                None => derived(recv),
            },
            "map" | "filter_map" | "flat_map" => {
                let Obj::Closure(k) = a0.obj else { return Some(derived(recv)) };
                match &recv.items {
                    Some(items) if items.len() <= val::MAX_ITEMS => {
                        let mut out = Vec::with_capacity(items.len());
                        let mut decoded = false;
                        for it in items.iter().cloned().collect::<Vec<_>>() {
                            let r = self.call_closure(k, vec![it]);
                            decoded |= r.kinds & K_DECODED != 0;
                            out.push(r);
                            if self.out_of_steps() {
                                break;
                            }
                        }
                        let mut v = Val::list(out);
                        v.add_kinds(recv);
                        if decoded {
                            v = v.decoded(at);
                        }
                        v
                    }
                    _ => {
                        let el = derived(recv);
                        let r = self.call_closure(k, vec![el]);
                        let mut v = derived(recv).with_kinds(&r);
                        if r.kinds & K_DECODED != 0 {
                            v = v.decoded(at);
                        }
                        v
                    }
                }
            }
            "for_each" => {
                if let Obj::Closure(k) = a0.obj {
                    let items: Vec<Val> = recv.items.as_ref().map(|i| i.iter().take(8).cloned().collect()).unwrap_or_else(|| vec![derived(recv)]);
                    for it in items {
                        self.call_closure(k, vec![it]);
                    }
                }
                Val::unknown()
            }
            "filter" | "take" | "skip" | "take_while" | "skip_while" | "chain" | "zip" | "cycle" | "peekable" | "step_by" | "sorted" | "dedup" => {
                if n == "take" || n == "skip" {
                    if let (Some(items), Some(k)) = (&recv.items, a0.int) {
                        let k = k.clamp(0, items.len() as i128) as usize;
                        let part: Vec<Val> = if n == "take" { items[..k].to_vec() } else { items[k..].to_vec() };
                        return Some(Val::list(part).with_kinds(recv));
                    }
                }
                if n == "chain" {
                    if let (Some(a), Some(b)) = (&recv.items, &a0.items) {
                        let mut all: Vec<Val> = (**a).clone();
                        all.extend(b.iter().cloned());
                        return Some(Val::list(all).with_kinds(recv).with_kinds(&a0));
                    }
                }
                let mut v = keep(recv);
                v.add_kinds(&a0);
                v
            }
            "collect" | "concat_strings" => {
                // a list of characters or strings collected into a String; of numbers, into bytes
                match &recv.items {
                    Some(items) => {
                        let all_known = items.iter().all(|it| it.s.is_some() || it.int.is_some());
                        if all_known && !items.is_empty() {
                            let chars = items.iter().all(|it| it.s.is_some());
                            if chars {
                                let mut s: PyStr = Vec::new();
                                for it in items.iter() {
                                    s.extend(it.text_or_unknown());
                                }
                                let mut v = Val::text(val::collapse(s)).with_kinds(recv);
                                v.items = recv.items.clone();
                                return Some(v);
                            }
                            // bytes
                            let bytes: PyStr = items.iter().map(|it| it.int.unwrap_or(0) as u32 & 0xFF).collect();
                            let mut v = keep(recv);
                            v.s = Some(Rc::new(bytes));
                            return Some(v);
                        }
                        keep(recv)
                    }
                    None => keep(recv),
                }
            }
            "len" | "count" => match (&recv.items, &recv.s) {
                (Some(i), _) => Val::int(i.len() as i128),
                (None, Some(s)) if !s.contains(&UNKNOWN) => Val::int(s.len() as i128),
                _ => Val::unknown(),
            },
            "get" | "nth" => match (&recv.items, a0.int) {
                (Some(items), Some(k)) if k >= 0 => items.get(k as usize).cloned().unwrap_or_else(|| derived(recv)),
                _ => derived(recv),
            },
            "first" | "last" | "next" => match &recv.items {
                Some(items) if !items.is_empty() => {
                    if n == "last" {
                        items.last().cloned().unwrap_or_default()
                    } else {
                        items.first().cloned().unwrap_or_default()
                    }
                }
                _ => derived(recv),
            },
            "with_extension" | "with_file_name" | "set_extension" => {
                let v = match &recv.s {
                    Some(s) => {
                        let mut t = (**s).clone();
                        if n == "with_file_name" {
                            if let Some(p) = t.iter().rposition(|&c| c == '/' as u32) {
                                t.truncate(p + 1);
                            } else {
                                t.clear();
                            }
                            t.extend(a0.text_or_unknown());
                        } else {
                            if let Some(p) = t.iter().rposition(|&c| c == '.' as u32) {
                                t.truncate(p);
                            }
                            t.push('.' as u32);
                            t.extend(a0.text_or_unknown());
                        }
                        Val::text(t).with_kinds(recv)
                    }
                    None => derived(recv),
                };
                if n == "set_extension" {
                    if let Some(name) = lvalue(recv_e) {
                        f.vars.insert(name, v);
                    }
                    return Some(Val::unknown());
                }
                v
            }
            "parent" | "file_name" | "file_stem" | "extension" => derived(recv),
            "exists" | "is_file" | "is_dir" | "is_empty" | "contains" | "starts_with" | "ends_with" | "eq" | "ne" | "is_ok" | "is_err" | "is_some" | "is_none" | "parse" | "status" | "success" | "code" | "wait" | "kill" | "id" | "is_success" => {
                if n == "wait" || n == "status" {
                    // a child's wait: nothing more to read
                }
                Val::unknown()
            }
            _ => return None,
        })
    }
}

/// The file an event happened in.
pub fn ev_file(e: &Ev) -> u16 {
    match e {
        Ev::Run { file, .. } | Ev::Send { file, .. } | Ev::Write { file, .. } | Ev::Lookup { file, .. } | Ev::Load { file, .. } => *file,
    }
}

/// The parameters' `(` of a function item, after its name and generics.
pub fn params_open(tree: &Tree, src: &[u32], name: u32, body_open: u32) -> Option<usize> {
    if name == NONE {
        return None;
    }
    let mut i = name as usize + 1;
    let mut angle = 0i32;
    while i < body_open as usize {
        let t = tree.toks.get(i)?;
        let ch = src.get(t.start as usize).copied().unwrap_or(0);
        if t.kind == crate::lex::Kind::Punct {
            if ch == '<' as u32 {
                angle += 1;
            } else if ch == '>' as u32 && !(i > 0 && src.get(tree.toks[i - 1].start as usize) == Some(&('-' as u32)) && tree.toks[i - 1].end == t.start) {
                angle -= 1;
            } else if ch == '(' as u32 && angle <= 0 {
                return Some(i);
            }
        }
        if t.kind == crate::lex::Kind::Punct && (ch == '(' as u32 || ch == '[' as u32 || ch == '{' as u32) {
            let m = tree.mate.get(i).copied().unwrap_or(NONE);
            if m != NONE && m as usize > i {
                i = m as usize;
            }
        }
        i += 1;
    }
    None
}

/// The value a field, an item or an unknown call gives of `v`: its kinds, nothing else.
pub fn derived(v: &Val) -> Val {
    let mut d = Val::unknown();
    d.add_kinds(v);
    d
}

fn map_text(v: &Val, f: impl Fn(&[u32]) -> PyStr) -> Val {
    match &v.s {
        Some(s) => {
            let mut out = Val::text(f(s));
            out.add_kinds(v);
            out
        }
        None => derived(v),
    }
}

fn cat(parts: &[&[u32]]) -> PyStr {
    pystr::concat(parts)
}

/// `a` joined to `b` as a path: `a/b` (b absolute: b).
pub fn path_join(a: &Val, b: &Val) -> Val {
    let bt = b.text_or_unknown();
    if bt.first() == Some(&('/' as u32)) || bt.first() == Some(&('~' as u32)) {
        return b.clone().with_kinds(a);
    }
    let mut s = a.text_or_unknown();
    if !s.is_empty() && s.last() != Some(&('/' as u32)) && s.last() != Some(&('\\' as u32)) {
        s.push('/' as u32);
    }
    s.extend(bt);
    let mut v = Val::text(val::collapse(s));
    v.add_kinds(a);
    v.add_kinds(b);
    v
}

/// A list's items as integers, if they all are.
fn list_ints(v: &Val) -> Option<Vec<i128>> {
    if let Some(items) = &v.items {
        return items.iter().map(|i| i.int).collect();
    }
    v.s.as_ref().filter(|s| !s.contains(&UNKNOWN)).map(|s| s.iter().map(|&c| c as i128).collect())
}

/// Bytes read as text: a list of numbers, or a text's code points.
fn text_of_bytes(v: &Val) -> Val {
    if let Some(items) = &v.items {
        if let Some(ints) = items.iter().map(|i| i.int).collect::<Option<Vec<i128>>>() {
            let bytes: PyStr = ints.iter().map(|&n| (n & 0xFF) as u32).collect();
            let mut out = Val::text(val::utf8(&bytes));
            out.add_kinds(v);
            return out;
        }
    }
    match &v.s {
        Some(s) => {
            let mut out = Val::text(val::utf8(s));
            out.add_kinds(v);
            out
        }
        None => derived(v),
    }
}

/// The name an expression writes to (`x`, `&mut x`, `x.field`), if it is a name.
fn lvalue(e: &Ex) -> Option<PyStr> {
    match e {
        Ex::Path(segs, _) if segs.len() == 1 => Some(segs[0].clone()),
        Ex::Ref(inner, _) | Ex::Unary(_, inner, _) => lvalue(inner),
        _ => None,
    }
}

fn recv_e_is_list(e: &Ex) -> bool {
    !matches!(e, Ex::Call(..))
}

/// std methods whose name a crate's own function may share: never followed into the crate.
fn is_std_method(n: &str) -> bool {
    matches!(
        n,
        "new" | "clone" | "into" | "from" | "unwrap" | "expect" | "len" | "is_empty" | "iter" | "map" | "collect" | "push" | "insert" | "get" | "to_string" | "fmt" | "eq" | "cmp" | "hash" | "default" | "drop" | "deref" | "as_ref" | "borrow" | "next" | "write" | "read" | "flush"
    )
}

/// A command's line as a shell would read it: an interpreter's `-c` script, or the program and its arguments.
pub fn command_line(c: &CmdState) -> PyStr {
    if let Some(script) = shell_script(c) {
        return script.text_or_unknown();
    }
    let mut out = quote_word(&c.prog.text_or_unknown());
    for a in &c.args {
        out.push(' ' as u32);
        out.extend(quote_word(&a.text_or_unknown()));
    }
    out
}

/// What a shell given `-c` (cmd `/c`, PowerShell `-Command`) runs, if the command is one.
pub fn shell_script(c: &CmdState) -> Option<Val> {
    let prog = c.prog.text_or_unknown();
    let base: PyStr = {
        let p = prog.iter().rposition(|&ch| ch == '/' as u32 || ch == '\\' as u32).map(|k| prog[k + 1..].to_vec()).unwrap_or(prog.clone());
        let lower = pystr::lower(&p);
        lower.strip_suffix(&u(".exe")[..]).map(|x| x.to_vec()).unwrap_or(lower)
    };
    let shell = SHELLS.iter().any(|s| eqs(&base, s));
    let cmd = eqs(&base, "cmd");
    let ps = eqs(&base, "powershell") || eqs(&base, "pwsh");
    if !(shell || cmd || ps) {
        return None;
    }
    for (k, a) in c.args.iter().enumerate() {
        let t = a.text_or_unknown();
        let lt = pystr::lower(&t);
        // (the shell reader's rule: a short flag that holds `c`, `-c`, `-lc`, `-ec`)
        let short_c = t.len() >= 2 && t[0] == '-' as u32 && t[1] != '-' as u32 && t[1..].iter().all(|&x| char::from_u32(x).is_some_and(|ch| ch.is_ascii_alphabetic())) && t[1..].contains(&('c' as u32));
        let flag = (shell && short_c)
            || (cmd && (eqs(&lt, "/c") || eqs(&lt, "/k")))
            || (ps && (eqs(&lt, "-command") || eqs(&lt, "-c") || eqs(&lt, "/c") || eqs(&lt, "-encodedcommand") || eqs(&lt, "-enc") || eqs(&lt, "-e")));
        if flag {
            let rest = &c.args[k + 1..];
            if rest.is_empty() {
                return None;
            }
            if ps && (eqs(&lt, "-encodedcommand") || eqs(&lt, "-enc") || eqs(&lt, "-e")) {
                // PowerShell's own command line, for the PowerShell reader
                let mut line = cat(&[&prog, &u(" "), &t]);
                for r in rest {
                    line.push(' ' as u32);
                    line.extend(r.text_or_unknown());
                }
                let mut v = Val::text(line);
                for r in rest {
                    v.add_kinds(r);
                }
                return Some(v);
            }
            let mut v = Val::text(Vec::new());
            for (j, r) in rest.iter().enumerate() {
                if j > 0 {
                    v = Val::concat(&v, &Val::text(u(" ")));
                }
                v = Val::concat(&v, r);
            }
            if ps {
                let mut line = cat(&[&u("powershell -Command \""), &v.text_or_unknown(), &u("\"")]);
                line = val::collapse(line);
                let mut out = Val::text(line);
                out.add_kinds(&v);
                return Some(out);
            }
            return Some(v);
        }
    }
    None
}

/// A word quoted for a shell where it needs it.
fn quote_word(w: &[u32]) -> PyStr {
    if !w.is_empty() && w.iter().all(|&c| char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || "-_./:=@%+,~$&|>".contains(ch)) || c == UNKNOWN) {
        return w.to_vec();
    }
    let mut out = vec!['\'' as u32];
    for &c in w {
        if c == '\'' as u32 {
            out.extend(u("'\\''"));
        } else {
            out.push(c);
        }
    }
    out.push('\'' as u32);
    out
}

/// A download a command writes to a file: (the file, the address), for curl `-o`, wget `-O`,
/// PowerShell's `-OutFile` and certutil.
fn download_target(c: &CmdState) -> Option<(Val, Val)> {
    let prog = pystr::lower(&c.prog.text_or_unknown());
    let base: PyStr = prog.iter().rposition(|&ch| ch == '/' as u32 || ch == '\\' as u32).map(|k| prog[k + 1..].to_vec()).unwrap_or(prog.clone());
    let base = base.strip_suffix(&u(".exe")[..]).map(|x| x.to_vec()).unwrap_or(base);
    let args = &c.args;
    let url = || args.iter().find(|a| a.s.as_ref().is_some_and(|s| pystr::starts_with(s, "http") || pystr::find_str(s, "://", 0).is_some())).cloned();
    if eqs(&base, "curl") || eqs(&base, "wget") {
        for (k, a) in args.iter().enumerate() {
            let t = a.text_or_unknown();
            let out_flag = if eqs(&base, "curl") { eqs(&t, "-o") || eqs(&t, "--output") } else { eqs(&t, "-O") || eqs(&t, "--output-document") };
            if out_flag {
                let path = args.get(k + 1)?.clone();
                if eqs(&path.text_or_unknown(), "-") {
                    return None;
                }
                return Some((path, url().unwrap_or_default()));
            }
        }
        return None;
    }
    if eqs(&base, "certutil") {
        let url = url()?;
        let last = args.last()?.clone();
        return Some((last, url));
    }
    if let Some(script) = shell_script(c) {
        // a shell's own download: curl -o, wget -O, Invoke-WebRequest -OutFile
        let s = script.text_or_unknown();
        let low = pystr::lower(&s);
        for (flag, curl) in [("-o ", true), ("-outfile ", false), ("--output ", true)] {
            if let Some(k) = pystr::find_str(&low, flag, 0) {
                if curl && !(pystr::find_str(&low, "curl", 0).is_some() || pystr::find_str(&low, "wget", 0).is_some()) {
                    continue;
                }
                let rest = &s[k + flag.len()..];
                let word: PyStr = rest.iter().take_while(|&&c| !matches!(char::from_u32(c), Some(' ' | ';' | '&' | '|' | '"' | '\'' | '\n'))).copied().collect();
                if !word.is_empty() {
                    let urls = pystr::find_str(&s, "http", 0).map(|k| {
                        s[k..].iter().take_while(|&&c| !matches!(char::from_u32(c), Some(' ' | ';' | '&' | '|' | '"' | '\'' | '\n'))).copied().collect::<PyStr>()
                    });
                    let mut path = Val::text(word);
                    path.add_kinds(&script);
                    return Some((path, urls.map(Val::text).unwrap_or_default()));
                }
            }
        }
    }
    None
}

/// Is a path's text one outside the package (the machine's files: an absolute path, the home folder, a
/// credential file)?
pub fn outside_path(p: &Pack, text: &[u32]) -> bool {
    if text.first() == Some(&UNKNOWN) && text.len() > 1 {
        let rest = &text[1..];
        let quoted = cat(&[&u("\""), rest, &u("\"")]);
        return p.re("_LD_CRED_FILE_RE").match_(&quoted).is_some() || crate::jsflow::supply::cred_store(p, rest);
    }
    let quoted = cat(&[&u("\""), text, &u("\"")]);
    p.re("_LD_FS_ROOT_RE").match_(&quoted).is_some() || p.re("_LD_ABSOLUTE_RE").match_(&quoted).is_some() || p.re("_LD_CRED_FILE_RE").match_(&quoted).is_some()
}

/// A path as a finding shows it: its unknown pieces as `…`.
pub fn shown_path(text: &[u32]) -> PyStr {
    let mut out = Vec::with_capacity(text.len());
    for &c in text {
        if c == UNKNOWN {
            out.push(0x2026);
        } else {
            out.push(c);
        }
    }
    out
}
