//! A project scan's collection (0.1.9, BR-7 step 4 (e)): what a folder's entries are to the scan (read, skipped,
//! followed into, reported) and how a file it meets is read. core's _collect, _collect_file, _collect_config and
//! _check_pycache and the npm package's collectFiles, checkPycache (lib/fs.js) and collectEntry (lib/collect.js)
//! each decided it, held equal by tests; the dashboard collects its uploads with the npm package's.
//!
//! The packages keep the I/O: listing a folder (its entries, each one's kind, size and, for a link, its target), the
//! identity of a folder (`key`: the walk reports a folder it has seen as a loop), reading a file's bytes, counting a
//! pruned tree, and the walk's stack. Each call answers from what it is given and says what it still needs
//! (`need`); the package calls again with the answers, as for --deps (deps.rs). The engine keeps nothing between
//! calls.
//!
//! * `collect_dir`: a folder's entries in the walk's order (by name, code point by code point), each with what the
//!   walk does with it: an issue (a link: Q-SYMLINK; a special file or an entry that could not be read:
//!   Q-UNREADABLE), a file to collect, a tree it skips (.git, an excluded name, a dependency tree without --deps:
//!   Q-SKIPPED-TREE once the package has counted it), a `__pycache__` whose .pyc files it checks, a folder it has
//!   seen (Q-UNREADABLE: a loop), or a folder it walks, with the dependency tree it belongs to. A venv, .venv, env or
//!   vendor folder is a dependency tree only with a marker inside (DEP_TREE_MARKERS), and a vendor folder is Go's
//!   (vendor/modules.txt) or cargo's (a .cargo-checksum.json in one of its first _VENDOR_PROBE folders): the call
//!   needs those folders' entries and, for cargo's, which of the checksums are regular files.
//! * `collect_file`: one regular file: which language it is read in (by its extension, a dependency tree's own
//!   languages, a vendor tree's built code, a script by its #! line), a manifest, a .pth file, a config or data file,
//!   or none (classified by its first bytes: SC-BINARY and the rest); what it needs to read of it (its head, all of
//!   it up to the size limit, the head of one over the limit); and then the file the scan reads (its text decoded
//!   as its interpreter reads it), the manifest, the config file, and the findings (SC-TRUNCATED, Q-ENCODING,
//!   SC-PTH-EXEC, a program under a source name, Q-SKIPPED-CONFIG …). A read that failed is Q-UNREADABLE.
//! * `collect_pycache`: a `__pycache__`'s entries: links, and the .pyc files whose headers it checks (SC-PYC-*).
//! * `collect_issue`: the coverage notes a package's I/O finds (a folder it cannot list, a pruned tree's counts).

use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

fn s(t: &str) -> PyStr {
    pystr::u(t)
}

fn is(a: &[u32], b: &str) -> bool {
    pystr::eq(a, b)
}

/// The folders of a vendor tree looked at for a .cargo-checksum.json.
pub const VENDOR_PROBE: usize = 256;

/// Where a folder's files belong: the project's, a dependency tree's (--deps), or a Go or cargo vendor tree's (its
/// kind and the vendor folder's path).
#[derive(Clone, Debug, PartialEq)]
pub enum Dep {
    No,
    Tree,
    Vendor(PyStr, PyStr),
}

impl Dep {
    pub fn of(v: Option<&Value>) -> Dep {
        match v {
            Some(Value::Bool(true)) => Dep::Tree,
            Some(Value::Arr(a)) if a.len() == 2 => match (&a[0], &a[1]) {
                (Value::Str(k), Value::Str(r)) => Dep::Vendor(k.clone(), r.clone()),
                _ => Dep::Tree,
            },
            _ => Dep::No,
        }
    }

    pub fn value(&self) -> Value {
        match self {
            Dep::No => Value::Bool(false),
            Dep::Tree => Value::Bool(true),
            Dep::Vendor(k, r) => Value::Arr(vec![Value::Str(k.clone()), Value::Str(r.clone())]),
        }
    }

    fn any(&self) -> bool {
        !matches!(self, Dep::No)
    }
}

// ---- the coverage notes ----------------------------------------------------------------------------------------

/// An issue as the engine's calls give them, [rule, name, type, sev, msg, why, fix, ref, line, snippet, snipStart],
/// of one of core's rule dicts in the pack, its message formatted.
fn note(p: &Pack, rule: &str, args: &[(&str, crate::findings::Arg)]) -> Value {
    let r = crate::findings::RuleText::of(p, rule);
    let msg = crate::findings::format(&r.msg, args);
    Value::Arr(vec![
        Value::Str(r.id),
        Value::Str(r.name),
        Value::Str(r.typ),
        Value::Str(r.sev),
        Value::Str(msg),
        Value::Str(r.why),
        Value::Str(r.fix),
        Value::Str(r.ref_),
        Value::Int(1),
        Value::Arr(Vec::new()),
        Value::Int(1),
    ])
}

/// core._safe_text: lone surrogates as backslash escapes.
fn safe_text(t: &[u32]) -> PyStr {
    let mut out = Vec::with_capacity(t.len());
    for &c in t {
        if (0xD800..=0xDFFF).contains(&c) {
            out.extend(s(&format!("\\u{c:04x}")));
        } else {
            out.push(c);
        }
    }
    out
}

/// Q-SYMLINK: a link in the tree, never followed (its target cut at 200 characters).
pub fn symlink_issue(p: &Pack, path: &[u32], target: &[u32]) -> Value {
    use crate::findings::Arg;
    let mut t = safe_text(target);
    if t.len() > 200 {
        t.truncate(197);
        t.extend(s("..."));
    }
    note(p, "_COLLECT_SYMLINK_RULE", &[("path", Arg::S(path.to_vec())), ("target", Arg::S(t))])
}

/// Q-UNREADABLE: an entry that could not be read (`reason`), or a special file.
pub fn unreadable_issue(p: &Pack, path: &[u32], reason: &[u32]) -> Value {
    use crate::findings::Arg;
    note(p, "_COLLECT_UNREADABLE_RULE", &[("path", Arg::S(path.to_vec())), ("reason", Arg::S(safe_text(reason)))])
}

/// Q-SKIPPED-TREE: a pruned tree, with the files and bytes it holds.
pub fn skipped_tree_issue(p: &Pack, path: &[u32], files: i64, bytes: i64) -> Value {
    use crate::findings::Arg;
    note(p, "_COLLECT_SKIPPED_TREE_RULE", &[("path", Arg::S(path.to_vec())), ("files", Arg::I(files)), ("bytes", Arg::I(bytes))])
}

/// Q-SKIPPED-CONFIG: a config or data file too large to check for credentials.
pub fn config_skipped_issue(p: &Pack, path: &[u32], detail: &str) -> Value {
    use crate::findings::Arg;
    note(p, "_COLLECT_SKIPPED_CONFIG_RULE", &[("path", Arg::S(path.to_vec())), ("detail", Arg::S(safe_text(&s(detail))))])
}

/// What a special file is, for Q-UNREADABLE (core._special_kind).
pub fn special_kind(code: &[u32]) -> PyStr {
    s(match pystr::to_string(code).as_str() {
        "fifo" => "a named pipe (FIFO)",
        "socket" => "a socket",
        "char" => "a character device",
        "block" => "a block device",
        _ => "not a regular file",
    })
}

/// A path's issue, as the calls answer it: [path, issue].
fn at(path: &[u32], issue: Value) -> Value {
    Value::Arr(vec![Value::Str(path.to_vec()), issue])
}

/// n with thousands separators (Python's f"{n:,}").
fn commas(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (k, c) in d.chars().enumerate() {
        if k > 0 && (d.len() - k) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ---- a folder ----------------------------------------------------------------------------------------------------

/// One entry of a folder, as the package lists it.
pub enum Entry {
    /// a regular file and its size
    File(u64),
    /// a folder: its identity (None: the filesystem has none) and whether the walk has seen it
    Dir(Option<PyStr>, bool),
    /// a link (or a folder that is a reparse point), and its target as read (or "?")
    Link(PyStr),
    /// a special file: fifo, socket, char, block or other
    Special(PyStr),
    /// an entry that could not be stat'ed: the error's text
    Error(PyStr),
}

/// What the package knows of the folders the call asked about (by their index in `entries`): each one's entries
/// ([name, is a folder]; None when it could not be listed), and of a vendor folder, which of the folders it was asked
/// about hold a regular .cargo-checksum.json.
#[derive(Default)]
pub struct DirAnswers {
    pub lists: Vec<(usize, Option<Vec<(PyStr, bool)>>)>,
    pub cargo: Vec<(usize, Vec<PyStr>)>,
}

pub struct DirIn<'a> {
    /// the folder's path below the scan root, as the package shows it ("" for the root)
    pub dir: PyStr,
    pub dep: Dep,
    pub entries: Vec<(PyStr, Entry)>,
    pub excludes: Vec<PyStr>,
    pub include_deps: bool,
    /// the package's path separator
    pub sep: PyStr,
    pub answers: &'a DirAnswers,
}

/// A folder's entry's path below the root.
fn child(dir: &[u32], sep: &[u32], name: &[u32]) -> PyStr {
    if dir.is_empty() {
        return name.to_vec();
    }
    let mut out = dir.to_vec();
    out.extend_from_slice(sep);
    out.extend_from_slice(name);
    out
}

/// core._dep_tree_kind from what the package answered: Some(answer) once known (a Dep::No when the folder is not one),
/// None while the call needs the folder's entries (`need_list`) or its checksums (`need_cargo`).
fn dep_tree_kind(p: &Pack, k: usize, name: &[u32], a: &DirAnswers, need_list: &mut Vec<usize>, need_cargo: &mut Vec<(usize, Vec<PyStr>)>, rel: &[u32]) -> Option<Dep> {
    if p.strs("DEP_TREE_DIRS").iter().any(|d| d == name) {
        return Some(Dep::Tree);
    }
    let markers = p.raw("DEP_TREE_MARKERS").and_then(|m| m.get("map")).and_then(|m| m.as_obj())
        .and_then(|o| o.iter().find(|(k, _)| k.as_slice() == name).map(|(_, v)| v));
    let vendor = is(name, "vendor");
    if markers.is_none() && !vendor {
        return Some(Dep::No);
    }
    let list = match a.lists.iter().find(|(n, _)| *n == k) {
        Some((_, l)) => l,
        None => {
            need_list.push(k);
            return None;
        }
    };
    let Some(list) = list else {
        return Some(Dep::No); // (it could not be listed)
    };
    if vendor {
        // _vendor_kind: Go's by its modules.txt, cargo's by a checksum in one of its first folders
        let mut sorted: Vec<&(PyStr, bool)> = list.iter().collect();
        sorted.sort_by(|x, y| x.0.cmp(&y.0));
        if sorted.iter().any(|(n, _)| is(n, "modules.txt")) {
            return Some(Dep::Vendor(s("go"), rel.to_vec()));
        }
        let probe: Vec<PyStr> = sorted.iter().filter(|(_, d)| *d).take(VENDOR_PROBE).map(|(n, _)| n.clone()).collect();
        if !probe.is_empty() {
            match a.cargo.iter().find(|(n, _)| *n == k) {
                Some((_, found)) => {
                    if probe.iter().any(|d| found.contains(d)) {
                        return Some(Dep::Vendor(s("cargo"), rel.to_vec()));
                    }
                }
                None => {
                    need_cargo.push((k, probe));
                    return None;
                }
            }
        }
    }
    // DEP_TREE_MARKERS: a marker name, or a name with a marker suffix, directly inside
    let Some(markers) = markers else { return Some(Dep::No) };
    let parts = markers.get("list").and_then(|l| l.as_arr()).unwrap_or(&[]);
    let strs_at = |k: usize| -> Vec<PyStr> {
        parts.get(k).and_then(|x| x.get("list")).and_then(|l| l.as_arr()).unwrap_or(&[]).iter()
            .filter_map(|v| v.get("value").and_then(|x| x.as_str()).map(|t| t.to_vec())).collect()
    };
    let (names, suffixes) = (strs_at(0), strs_at(1));
    let hit = list.iter().any(|(n, _)| names.contains(n) || suffixes.iter().any(|x| n.ends_with(x)));
    Some(if hit { Dep::Tree } else { Dep::No })
}

/// core._collect's loop over one folder: its entries in the walk's order, each with what the walk does with it.
/// The answer: {"do": [[index, action, extra]], "seen": [keys the walk has now seen]}, or {"need": {"lists": [index],
/// "cargo": [[index, [folder names]]]}} while it needs the package's answers. Actions: "issue" ([path, issue]), "file" (its path and Dep: collect_file), "skip"
/// (its path: count it, Q-SKIPPED-TREE), "pycache" (its path: collect_pycache, with the folder's names), "walk" (its
/// path and Dep).
pub fn dir(p: &Pack, d: &DirIn) -> Value {
    let mut order: Vec<usize> = (0..d.entries.len()).collect();
    order.sort_by(|&x, &y| d.entries[x].0.cmp(&d.entries[y].0));
    let mut out: Vec<Value> = Vec::new();
    let mut dirs: Vec<usize> = Vec::new();
    for &k in &order {
        let (name, e) = &d.entries[k];
        let rel = child(&d.dir, &d.sep, name);
        match e {
            Entry::Error(why) => out.push(row(k, "issue", at(&rel, unreadable_issue(p, &rel, why)))),
            Entry::Link(target) => out.push(row(k, "issue", at(&rel, symlink_issue(p, &rel, target)))),
            Entry::Special(kind) => out.push(row(k, "issue", at(&rel, unreadable_issue(p, &rel, &special_kind(kind))))),
            Entry::File(_) => out.push(row(k, "file", Value::Arr(vec![Value::Str(rel), d.dep.value()]))),
            Entry::Dir(..) => dirs.push(k),
        }
    }
    let mut seen_now: Vec<PyStr> = Vec::new();
    let (mut need_list, mut need_cargo) = (Vec::new(), Vec::new());
    let mut later: Vec<Value> = Vec::new();
    for k in dirs {
        let (name, e) = &d.entries[k];
        let rel = child(&d.dir, &d.sep, name);
        if p.strs("SKIP_DIRS").iter().any(|x| x == name) && !is(name, &p.string("PYCACHE_DIR")) || d.excludes.contains(name) {
            later.push(row(k, "skip", Value::Str(rel)));
            continue;
        }
        if is(name, &p.string("PYCACHE_DIR")) {
            later.push(row(k, "pycache", Value::Str(rel)));
            continue;
        }
        let Entry::Dir(key, seen) = e else { continue };
        if let Some(key) = key {
            if *seen || seen_now.contains(key) {
                later.push(row(k, "issue", at(&rel, unreadable_issue(p, &rel, &s("directory already visited (filesystem loop)")))));
                continue;
            }
            seen_now.push(key.clone());
        }
        let dep = if d.dep.any() {
            Some(d.dep.clone())
        } else {
            dep_tree_kind(p, k, name, d.answers, &mut need_list, &mut need_cargo, &rel)
        };
        let Some(dep) = dep else { continue };
        if dep.any() && !d.dep.any() && !d.include_deps {
            later.push(row(k, "skip", Value::Str(rel)));
            continue;
        }
        later.push(row(k, "walk", Value::Arr(vec![Value::Str(rel), dep.value()])));
    }
    if !need_list.is_empty() || !need_cargo.is_empty() {
        return Value::obj(vec![(
            "need",
            Value::obj(vec![
                ("lists", Value::Arr(need_list.into_iter().map(|k| Value::Int(k as i64)).collect())),
                (
                    "cargo",
                    Value::Arr(
                        need_cargo
                            .into_iter()
                            .map(|(k, ds)| Value::Arr(vec![Value::Int(k as i64), Value::Arr(ds.into_iter().map(Value::Str).collect())]))
                            .collect(),
                    ),
                ),
            ]),
        )]);
    }
    out.extend(later);
    Value::obj(vec![("do", Value::Arr(out)), ("seen", Value::Arr(seen_now.into_iter().map(Value::Str).collect()))])
}

fn row(k: usize, action: &str, extra: Value) -> Value {
    Value::Arr(vec![Value::Int(k as i64), Value::str(action), extra])
}

// ---- a file ----------------------------------------------------------------------------------------------------

/// What the package read of a file: Ok(the bytes), or Err(why it could not).
pub type Read = Option<Result<Vec<u8>, PyStr>>;

pub struct FileIn {
    /// its path below the scan root, as the package shows it
    pub rel: PyStr,
    pub name: PyStr,
    pub size: u64,
    pub dep: Dep,
    /// the size limit of a file read whole (SOURCE_SIZE_CAP, or the package's --max-source-bytes), and of a config
    /// file (CONFIG_SCAN_CAP)
    pub cap: u64,
    pub config_cap: u64,
    pub windows: bool,
    pub neumaier: bool,
    pub redact: bool,
    /// its first HEADER_SAMPLE_BYTES bytes
    pub head: Read,
    /// all of it, up to the limit and a byte (a config file's limit: CONFIG_SCAN_CAP)
    pub data: Read,
    /// an oversized file's first DISGUISE_SAMPLE_BYTES bytes (none when they could not be read)
    pub sample: Option<Vec<u8>>,
    /// the package reads a file by range (FP-MODEL-FILES: a zip model file, its directory and its pickles)
    pub ranged: bool,
    /// the ranges it read so far ((offset, length), their bytes one after another), or why it could not
    pub ranges: Option<Result<(Vec<(u64, u64)>, Vec<u8>), PyStr>>,
    /// how many times ranges were asked for
    pub rounds: u64,
    /// a .pth file too large to read whole, read in chunks (binary::pth_stream): the lines site.py runs and why one
    /// could not be kept, or why it could not be read
    pub pth_lines: Option<Result<(Vec<(u64, Vec<u8>)>, Vec<String>), PyStr>>,
    /// a file too large to read whole, walked by its structure as its stream passed (media::feed: FP-OPAQUE-MEDIA),
    /// or why it could not be read
    pub media: Option<Result<crate::media::Walked, PyStr>>,
    /// the file beside it the engine asked for (a Gradle wrapper jar's gradle-wrapper.properties: FP-GRADLE-WRAPPER):
    /// Ok(None) when there is no such regular file, or why it could not be read
    pub sibling: Option<Result<Option<Vec<u8>>, PyStr>>,
}

/// The languages a dependency tree's files are read in (DEP_LANGS: a package's Go and Rust are its readers').
fn dep_source_lang(p: &Pack, ext: &[u32]) -> Option<PyStr> {
    let lang = ext_lang(p, ext)?;
    ["py", "js", "sql"].iter().any(|l| is(&lang, l)).then_some(lang)
}

/// EXTS: a source extension's language.
fn ext_lang(p: &Pack, ext: &[u32]) -> Option<PyStr> {
    p.raw("EXTS").and_then(|m| m.get("map")).and_then(|m| m.as_obj())?.iter()
        .find(|(k, _)| k.as_slice() == ext).and_then(|(_, v)| v.get("value")).and_then(|v| v.as_str()).map(|v| v.to_vec())
}

/// core.never_built: a file the file rules leave out as no build of a dependent compiles it (a Go *_test.go, a name
/// with "_" or "." first, one under testdata/ or below a vendor/ folder's own folders; a crate's tests/, benches/ and
/// examples/). `rel`: "/"-separated, below the module's or the crate's root. A test file's name ends in `_test.go`
/// exactly, as Go reads it (and goread's never_built): `x_TEST.go` is built. A package in vendor/ itself is the
/// module's (`m/vendor`: built); one in testdata/ is built when imported, which the Go reader reads (F-06).
pub fn never_built(kind: &str, rel: &[u32]) -> bool {
    let parts: Vec<&[u32]> = rel.split(|&c| c == '/' as u32).collect();
    match kind {
        "go" => {
            let dirs = &parts[..parts.len() - 1];
            go_name_never_built(parts[parts.len() - 1])
                || dirs.iter().any(|p| is(p, "testdata"))
                || dirs.iter().rev().skip(1).any(|p| is(p, "vendor"))
        }
        "crate" => ["tests", "benches", "examples"].iter().any(|d| is(parts[0], d)),
        _ => false,
    }
}

/// A Go file no build compiles by its name alone: a test file (`_test.go` exactly), a name with "_" or "." first.
pub fn go_name_never_built(name: &[u32]) -> bool {
    matches!(name.first(), Some(&c) if c == '_' as u32 || c == '.' as u32) || pystr::ends_with(name, "_test.go")
}

/// core._vendor_lang: "go" or "rs" for a file of a Go or cargo vendor tree that a build compiles.
fn vendor_lang(p: &Pack, dep: &Dep, rel: &[u32], ext: &[u32], sep: &[u32]) -> Option<PyStr> {
    let Dep::Vendor(kind, root) = dep else { return None };
    let want = p.raw("VENDOR_CODE").and_then(|m| m.get("map")).and_then(|m| m.as_obj())?.iter()
        .find(|(k, _)| k == kind).and_then(|(_, v)| v.get("value")).and_then(|v| v.as_str())?.to_vec();
    if ext != want.as_slice() {
        return None;
    }
    let below: PyStr = rel.get(root.len() + 1..).unwrap_or(&[]).to_vec();
    let below = pystr::replace(&below, sep, &s("/"));
    if is(kind, "go") {
        // by its name alone (F-06): the path below vendor/ begins with a module's path, which may hold a `testdata`
        // or a `vendor` (example.test/vendor), and `go mod vendor` copies only the packages a build compiles; the
        // Go reader reads each module's files below its root (vendor/modules.txt: core._vendored_code)
        let name = below.rsplit(|&c| c == '/' as u32).next().unwrap_or(&[]);
        return (!go_name_never_built(name)).then(|| s("go"));
    }
    let inside = match below.iter().position(|&c| c == '/' as u32) {
        Some(k) => below[k + 1..].to_vec(),
        None => Vec::new(),
    };
    (!inside.is_empty() && !never_built("crate", &inside)).then(|| s("rs"))
}

/// core.script_source_lang: "js" or "py" for a file whose #! line makes it a Node or Python script.
fn script_source_lang(p: &Pack, head: &[u8]) -> Option<PyStr> {
    let head = &head[..head.len().min(p.usize("HEADER_SAMPLE_BYTES"))];
    if !head.starts_with(b"#!") || crate::binary::looks_binary(p, head) {
        return None;
    }
    let lang = crate::hooks::shebang_lang(p, &crate::decode::utf::utf8(head))?;
    (lang == "js" || lang == "py").then(|| s(lang))
}

/// configsecrets.is_config_file: a file read as config or data, by its name.
pub fn is_config_file(p: &Pack, name: &[u32]) -> bool {
    let low = pystr::lower(name);
    let has = |set: &str| p.strs(set).iter().any(|x| *x == low);
    if has("CONFIG_SKIP_NAMES") || (low.starts_with(&s("pylock.")) && low.ends_with(&s(".toml"))) {
        return false;
    }
    if has("CONFIG_NAMES") || low.starts_with(&s(".env.")) || low.starts_with(&s("dockerfile.")) || low.ends_with(&s(".dockerfile")) {
        return true;
    }
    let ext = pystr::lower(&crate::binary::ext_and_base(&low, false).0);
    p.strs("CONFIG_EXTS").iter().any(|x| *x == ext)
}

/// configsecrets.own_report: the text of one of Lazaret's own JSON reports.
pub fn own_report(text: &[u32]) -> bool {
    let mut i = 0;
    let space = |i: &mut usize| {
        while *i < text.len() && crate::unicode::is_space(text[*i]) {
            *i += 1;
        }
    };
    if text.first() == Some(&0xFEFF) {
        i = 1;
    }
    space(&mut i);
    if text.get(i) != Some(&('{' as u32)) {
        return false;
    }
    i += 1;
    space(&mut i);
    if !pystr::starts_with_at(text, i, "\"generatedBy\"") {
        return false;
    }
    i += 13;
    space(&mut i);
    if text.get(i) != Some(&(':' as u32)) {
        return false;
    }
    i += 1;
    space(&mut i);
    pystr::starts_with_at(text, i, "\"lazaret-")
}

fn need(what: &str, limit: u64) -> Value {
    Value::obj(vec![("need", Value::obj(vec![("read", Value::str(what)), ("limit", Value::Int(limit as i64))]))])
}

/// What a file is to the scan, once read: its findings, and the file, manifest, config or .pth file it adds.
#[derive(Default)]
struct Done {
    issues: Vec<Value>,
    file: Option<Value>,
    manifest: Option<Value>,
    config: Option<Value>,
    pth: bool,
    /// a model file read: {imports: its globals of no known kind, calls: its calls with text} (FP-MODEL-FILES:
    /// model_own's, after the collection)
    model: Option<Value>,
}

impl Done {
    fn value(self) -> Value {
        let mut out = vec![("issues", Value::Arr(self.issues))];
        if let Some(f) = self.file {
            out.push(("file", f));
        }
        if let Some(m) = self.manifest {
            out.push(("manifest", m));
        }
        if let Some(c) = self.config {
            out.push(("config", c));
        }
        if self.pth {
            out.push(("pth", Value::Bool(true)));
        }
        if let Some(m) = self.model {
            out.push(("model", m));
        }
        Value::obj(out)
    }
}

/// engine.error_issue for a step that spent its work budget.
fn exhausted(p: &Pack) -> Value {
    crate::manifest::gyp::truncated_issue(p, &p.string("EXHAUSTED"))
}

/// Run a step with the work budget of a call of its own (the calls the packages made for it had one each).
fn own<T>(f: impl FnOnce() -> T) -> Option<T> {
    crate::budget::isolated(crate::budget::DEFAULT_STEPS, f).ok()
}

/// core._collect_file and _collect_config: what to read of a file next ({"need": {read, limit}}), or what it is.
pub fn file(p: &Pack, f: &FileIn) -> Value {
    let rel = &f.rel;
    let sep = if f.windows { s("\\") } else { s("/") };
    let ext = pystr::lower(&crate::binary::ext_and_base(&f.name, false).0);
    let in_list = |set: &str, x: &[u32]| p.strs(set).iter().any(|y| y.as_slice() == x);
    let manifest = in_list("MANIFEST_NAMES", &f.name) || in_list("GYP_EXTS", &ext);
    let pth = !manifest && is(&ext, &p.string("PTH_EXT"));
    let mut lang = if manifest || pth {
        None
    } else if f.dep.any() {
        vendor_lang(p, &f.dep, rel, &ext, &sep).or_else(|| dep_source_lang(p, &ext))
    } else {
        ext_lang(p, &ext)
    };
    let header = p.usize("HEADER_SAMPLE_BYTES") as u64;
    let unreadable = |why: &[u32]| Done { issues: vec![at(rel, unreadable_issue(p, rel, why))], ..Done::default() }.value();
    let mut done = Done::default();
    let classify = |data: &[u8]| crate::binary::classify(p, rel, &data[..data.len().min(8192)], f.size, "repo", f.windows, f.neumaier);
    if !manifest && !pth && lang.is_none() {
        let head = match &f.head {
            None => return need("head", header),
            Some(Err(why)) => return unreadable(why),
            Some(Ok(h)) => h,
        };
        // An agent skill or instruction file (RA-3) is read by agentdoc in the config bucket, a dependency's too (that
        // is where the threat is: a package that ships one); a `#!` line does not make it a script. A dependency's
        // other config files are not read (their credentials are the package's business, not the project's).
        let agent = crate::agentdoc::is_agent_doc(rel).is_some();
        lang = if agent { None } else { script_source_lang(p, head) };
        if lang.is_none() {
            // FP-MODEL-FILES: a model file (a pickle, a PyTorch checkpoint, joblib's, numpy's) is read whole, for what
            // its pickles would run
            if !agent && crate::pickle::sniff(p, &f.name, head, f.windows) {
                return model(p, f, head, Done::default());
            }
            let bi = match classify_read(p, f, head) {
                Ok(bi) => bi,
                Err(need) => return need,
            };
            if !bi.is_empty() {
                done.issues.extend(bi.into_iter().map(|i| at(rel, i)));
            } else if (agent || (!f.dep.any() && is_config_file(p, &f.name)))
                && (head.starts_with(b"\xff\xfe") || head.starts_with(b"\xfe\xff") || !crate::binary::looks_binary(p, head))
            {
                return config(p, f);
            }
            return done.value();
        }
    }
    if lang.is_some() && in_list("MPEG_TS_EXTS", &ext) {
        let head = match &f.head {
            None => return need("head", header),
            Some(Err(why)) => return unreadable(why),
            Some(Ok(h)) => h,
        };
        if crate::binary::mpeg_ts(&head[..head.len().min(377)]) {
            match classify_read(p, f, head) {
                Ok(bi) => done.issues.extend(bi.into_iter().map(|i| at(rel, i))),
                Err(need) => return need,
            }
            return done.value();
        }
    }
    let cap = f.cap;
    if f.size > cap && pth && f.ranged {
        // FP-MODEL-FILES (John, Oct 21): a .pth file too large to read whole (PyTorch's checkpoints are named so) is
        // read in chunks for the lines site.py runs, each checked as pth_issues checks a line (what it could not
        // keep: SC-TRUNCATED), and a checkpoint's pickles by range, as any zip model file's
        match &f.pth_lines {
            None => return need("pth", f.size),
            Some(Err(why)) => {
                done.issues.push(at(rel, unreadable_issue(p, rel, why)));
                return done.value();
            }
            Some(Ok((lines, cuts))) => {
                done.pth = true;
                match own(|| crate::binary::pth_kept_issues(p, lines, f.redact, f.neumaier)) {
                    Some(found) => done.issues.extend(found.into_iter().map(|i| at(rel, i))),
                    None => done.issues.push(at(rel, exhausted(p))),
                }
                if let Some(c) = cuts.first() {
                    let more = if cuts.len() > 1 { format!(" (and {} more)", cuts.len() - 1) } else { String::new() };
                    done.issues.push(at(rel, crate::manifest::gyp::truncated_issue(p, &format!("{c}{more}"))));
                }
            }
        }
        match &f.head {
            None => return need("head", header),
            Some(Ok(h)) if crate::pickle::zip::first_local_name(h).is_some() && crate::pickle::sniff(p, &f.name, h, f.windows) => {
                return model(p, f, h, done);
            }
            _ => return done.value(),
        }
    }
    if f.size > cap {
        done.issues.push(at(rel, crate::manifest::gyp::truncated_issue(
            p, &format!("{} bytes exceeds the {}-byte file limit", commas(f.size), commas(cap)))));
        if lang.is_some() {
            let Some(sample) = &f.sample else {
                return need("sample", p.usize("DISGUISE_SAMPLE_BYTES") as u64);
            };
            if let Some(d) = crate::binary::disguised(p, rel, sample, f.windows) {
                done.issues.push(at(rel, d));
            }
        }
        return done.value();
    }
    let data = match &f.data {
        None => return need("data", cap + 1),
        Some(Err(why)) => return unreadable(why),
        Some(Ok(d)) => d,
    };
    if data.len() as u64 > cap {
        done.issues.push(at(rel, crate::manifest::gyp::truncated_issue(p, &format!("read exceeded the {}-byte file limit", commas(cap)))));
        if lang.is_some() {
            if let Some(d) = crate::binary::disguised(p, rel, data, f.windows) {
                done.issues.push(at(rel, d));
            }
        }
        return done.value();
    }
    if manifest {
        let kind = if is(&f.name, "package.json") || is(&f.name, "binding.gyp") { f.name.clone() } else { s("gyp") };
        let content = crate::decode::normalize_newlines(&crate::decode::utf::utf8(data));
        done.manifest = Some(Value::obj(vec![
            ("kind", Value::Str(kind)),
            ("path", Value::Str(rel.clone())),
            ("content", Value::Str(content)),
            ("dep", Value::Bool(f.dep.any())),
        ]));
        return done.value();
    }
    if pth {
        done.pth = true;
        // (a checkpoint named .pth: its pickles too)
        if crate::pickle::sniff(p, &f.name, &data[..data.len().min(header as usize)], f.windows) {
            model_into(p, f, data, data.len() as u64, &mut done, None);
        }
        // (the lines site.py runs, read byte-wise as a .pth file read in chunks is: one rule for every route)
        match own(|| crate::binary::pth_bytes_issues(p, data, f.redact, f.neumaier)) {
            Some((found, cuts)) => {
                done.issues.extend(found.into_iter().map(|i| at(rel, i)));
                if let Some(c) = cuts.first() {
                    let more = if cuts.len() > 1 { format!(" (and {} more)", cuts.len() - 1) } else { String::new() };
                    done.issues.push(at(rel, crate::manifest::gyp::truncated_issue(p, &format!("{c}{more}"))));
                }
            }
            None => done.issues.push(at(rel, exhausted(p))),
        }
        return done.value();
    }
    if data.starts_with(b"\x00\x05\x16\x07") || data.starts_with(b"\x00\x05\x16\x00") {
        if let Some(bi) = classify(&data[..data.len().min(header as usize)]) {
            done.issues.push(at(rel, bi));
        }
        return done.value();
    }
    // read as the registry reads a member: decode_member
    let lang = lang.unwrap_or_default();
    let read = own(|| {
        let (text, info) = crate::decode::decode_source(data, Some(&pystr::to_string(&lang)));
        let mut found = crate::decode::encoding_issues(p, &text, &info, f.redact);
        found.extend(crate::decode::not_text_issue(p, &text, rel, f.windows, data));
        (text, found)
    });
    let Some((text, found)) = read else {
        done.issues.push(at(rel, exhausted(p)));
        return done.value();
    };
    done.issues.extend(found.into_iter().map(|i| at(rel, i)));
    if let Some(d) = crate::binary::disguised(p, rel, data, f.windows) {
        done.issues.push(at(rel, d));
    }
    let mut entry = vec![
        ("path", Value::Str(rel.clone())),
        ("content", Value::Str(text)),
        ("lang", Value::Str(lang.clone())),
        ("dep", Value::Bool(f.dep.any())),
    ];
    // (F-06) a Go file as the Go toolchain reads it, where that differs from the text: the Go reader's
    if is(&lang, "go") {
        if let Some(go) = crate::decode::go_text(data) {
            entry.push(("goContent", Value::Str(go)));
        }
    }
    if let Dep::Vendor(_, root) = &f.dep {
        if is(&lang, "go") || is(&lang, "rs") {
            entry.push(("vendor", Value::Str(root.clone())));
        }
    }
    done.file = Some(Value::obj(entry));
    done.value()
}

/// binary::classify of a file that is not source, from its first bytes, and the whole file when it needs it
/// (FP-OPAQUE-MEDIA: a keystore, or a near-random file whose first bytes start a format media.rs walks): read whole
/// up to the size limit, else walked as its stream passes when the package reads files so ({"need": {"read":
/// "media"}}: core's _stream_media, npm's streamMedia), else judged by its first bytes (an opaque blob stays one).
/// A Gradle wrapper jar (FP-GRADLE-WRAPPER) is read whole up to the size limit, with the gradle-wrapper.properties
/// beside it ({"need": {"read": "sibling"}}). Err: what to read next.
fn classify_read(p: &Pack, f: &FileIn, head: &[u8]) -> Result<Vec<Value>, Value> {
    use crate::binary::{classify_more, Classified, More};
    let sample = &head[..head.len().min(8192)];
    let go = |more: More| classify_more(p, &f.rel, sample, f.size, "repo", f.windows, f.neumaier, more);
    let got = match go(More::Ask) {
        Classified::Need if f.size <= f.cap => match &f.data {
            None => return Err(need("data", f.cap + 1)),
            Some(Ok(d)) => go(More::Whole(d)),
            Some(Err(_)) => go(More::No),
        },
        Classified::Need if f.ranged => match &f.media {
            None => return Err(Value::obj(vec![("need", Value::obj(vec![("read", Value::str("media"))]))])),
            Some(Ok(walked)) => go(More::Walked(walked)),
            Some(Err(_)) => go(More::No),
        },
        Classified::Need => go(More::No),
        Classified::Wrapper => {
            let jar = if f.size <= f.cap {
                match &f.data {
                    None => return Err(need("data", f.cap + 1)),
                    Some(Ok(d)) if d.len() as u64 <= f.cap => Some(d.as_slice()),
                    _ => None,
                }
            } else {
                None
            };
            // (one byte more than the engine reads, so that a longer file is told; one there and not read can't be
            // verified)
            let props = match &f.sibling {
                None => {
                    return Err(Value::obj(vec![("need", Value::obj(vec![
                        ("read", Value::str("sibling")),
                        ("name", Value::str(crate::gradle::PROPERTIES)),
                        ("limit", Value::Int(crate::gradle::read_limit(p) as i64)),
                    ]))]));
                }
                Some(Ok(Some(b))) => crate::gradle::Sibling::Bytes(b),
                Some(Ok(None)) => crate::gradle::Sibling::None,
                Some(Err(e)) => crate::gradle::Sibling::Error(e),
            };
            go(More::Wrapper { jar, props })
        }
        other => other,
    };
    Ok(match got {
        Classified::Issue(v) => vec![v],
        Classified::Issues(v) => v,
        _ => Vec::new(),
    })
}

/// FP-MODEL-FILES: a model file (pickle/), read for what its pickles would run: a zip (a checkpoint, an .npz) by
/// range whatever its size, when the package reads files by range ({"need": {read: "ranges"}}: its end records, its
/// central directory and the members the reader reads, never the tensor storages); another whole up to the size
/// limit, and one larger SC-TRUNCATED by its first bytes, as the registry reads one. A file the reader finds is not
/// one, and an archive that holds more than its format's members, get what classify says of their first bytes, as
/// before.
fn model(p: &Pack, f: &FileIn, head: &[u8], mut done: Done) -> Value {
    let rel = &f.rel;
    let cap = f.cap;
    if f.ranged && crate::pickle::zip::first_local_name(head).is_some() {
        let (layout, bytes): (&[(u64, u64)], &[u8]) = match &f.ranges {
            Some(Err(why)) => { done.issues.push(at(rel, unreadable_issue(p, rel, why))); return done.value(); }
            Some(Ok((l, b))) => (l, b),
            None => (&[], &[]),
        };
        let mut given = vec![(0u64, head)];
        let mut k = 0usize;
        for &(off, len) in layout {
            let end = k.saturating_add(len as usize).min(bytes.len());
            given.push((off, &bytes[k..end]));
            k = end;
        }
        let src = crate::pickle::zip::Bytes::pieces(f.size, given, crate::pickle::range_cap(p));
        let last = f.rounds >= p.int("PICKLE_MAX_READS").max(0) as u64;
        let got = match own(|| crate::pickle::read_ranges(p, rel, &src, f.windows, last)) {
            None => None,
            Some(crate::pickle::Ranged::Need(n)) => {
                return Value::obj(vec![("need", Value::obj(vec![("read", Value::str("ranges")),
                                                                 ("ranges", crate::api::ranges_value(&n))]))]);
            }
            Some(crate::pickle::Ranged::Not) => Some(None),
            Some(crate::pickle::Ranged::Report(r)) => Some(Some(r)),
        };
        model_report(p, f, got, &mut done, Some(head));
        return done.value();
    }
    if f.size > cap {
        model_into(p, f, head, f.size, &mut done, Some(head));
        return done.value();
    }
    let data = match &f.data {
        None => return need("data", cap + 1),
        Some(Err(why)) => { done.issues.push(at(rel, unreadable_issue(p, rel, why))); return done.value(); }
        Some(Ok(d)) => d,
    };
    // (a file that grew past the limit while it was read: its first bytes)
    let slice = &data[..data.len().min(cap as usize)];
    model_into(p, f, slice, data.len() as u64, &mut done, Some(head));
    done.value()
}

/// A model file's findings and imports added to `done`; with `head`, what classify says of the file's first bytes
/// when it is not a model file after all, or holds more than one.
fn model_into(p: &Pack, f: &FileIn, data: &[u8], size: u64, done: &mut Done, head: Option<&[u8]>) {
    let got = own(|| crate::pickle::read_file(p, &f.rel, data, size, Some(f.cap), f.windows));
    model_report(p, f, got, done, head);
}

/// A model file's reading (None: it spent its work budget; Some(None): not a model file) added to `done`.
fn model_report(p: &Pack, f: &FileIn, got: Option<Option<crate::pickle::Report>>, done: &mut Done, head: Option<&[u8]>) {
    let rel = &f.rel;
    let classify = |h: &[u8]| crate::binary::classify(p, rel, &h[..h.len().min(8192)], f.size, "repo", f.windows, f.neumaier);
    match got {
        None => done.issues.push(at(rel, exhausted(p))),
        Some(None) => {
            if let Some(bi) = head.and_then(classify) {
                done.issues.push(at(rel, bi));
            }
        }
        Some(Some(r)) => {
            done.issues.extend(r.issues.into_iter().map(|i| at(rel, i)));
            if r.opaque {
                if let Some(bi) = head.and_then(classify) {
                    done.issues.push(at(rel, bi));
                }
            }
            done.model = Some(Value::obj(vec![("imports", crate::pickle::imports_value(&r.imports)),
                                              ("calls", crate::pickle::calls_value(&r.calls))]));
        }
    }
}

/// core._collect_config: a config or data file read for its credentials, or Q-SKIPPED-CONFIG over the limit.
fn config(p: &Pack, f: &FileIn) -> Value {
    let rel = &f.rel;
    let cap = f.config_cap;
    let mut done = Done::default();
    if f.size > cap {
        let why = format!("{} bytes is over the {}-byte limit for config files", commas(f.size), commas(cap));
        done.issues.push(at(rel, config_skipped_issue(p, rel, &why)));
        return done.value();
    }
    let data = match &f.data {
        None => return need("data", cap + 1),
        Some(Err(why)) => return Done { issues: vec![at(rel, unreadable_issue(p, rel, why))], ..Done::default() }.value(),
        Some(Ok(d)) => d,
    };
    if data.len() as u64 > cap {
        let why = format!("it grew past the {}-byte limit for config files while it was read", commas(cap));
        done.issues.push(at(rel, config_skipped_issue(p, rel, &why)));
        return done.value();
    }
    let (text, _) = crate::decode::decode_source(data, None);
    if !own_report(&text) {
        let mut entry = vec![("path", Value::Str(rel.clone())), ("content", Value::Str(text))];
        if f.dep.any() {
            entry.push(("dep", Value::Bool(true)));     // (a dependency's agent file: its findings count, RA-3)
        }
        done.config = Some(Value::obj(entry));
    }
    done.value()
}

// ---- a __pycache__ -----------------------------------------------------------------------------------------------

/// core._check_pycache: a __pycache__'s entries (by name), each a link (Q-SYMLINK), an entry that could not be read
/// (Q-UNREADABLE), or a .pyc file whose header (`headers`: its first 16 bytes, or why they could not be read) is
/// checked against the folder's names (`parent`: is its source there?). {"need": [names]} until every header is in.
pub fn pycache(p: &Pack, dir: &[u32], sep: &[u32], entries: &[(PyStr, Entry)], parent: &[PyStr], headers: &[(PyStr, Result<Vec<u8>, PyStr>)]) -> Value {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&x, &y| entries[x].0.cmp(&entries[y].0));
    let mut issues = Vec::new();
    let mut need = Vec::new();
    for k in order {
        let (name, e) = &entries[k];
        let rel = child(dir, sep, name);
        match e {
            Entry::Error(why) => issues.push(at(&rel, unreadable_issue(p, &rel, why))),
            Entry::Link(target) => issues.push(at(&rel, symlink_issue(p, &rel, target))),
            Entry::File(_) if name.ends_with(&s(".pyc")) => match headers.iter().find(|(n, _)| n == name) {
                None => need.push(Value::Str(name.clone())),
                Some((_, Err(why))) => issues.push(at(&rel, unreadable_issue(p, &rel, why))),
                Some((_, Ok(header))) => {
                    let module: PyStr = name.split(|&c| c == '.' as u32).next().unwrap_or(&[]).to_vec();
                    let has = |suffix: &str| {
                        let mut m = module.clone();
                        m.extend(s(suffix));
                        parent.contains(&m)
                    };
                    let has_source = has(".py") || has(".pyw");
                    issues.extend(crate::binary::pyc_issues(p, &rel, header, has_source).into_iter().map(|i| at(&rel, i)));
                }
            },
            _ => {}
        }
    }
    if !need.is_empty() {
        return Value::obj(vec![("need", Value::Arr(need))]);
    }
    Value::obj(vec![("issues", Value::Arr(issues))])
}

/// core.is_dependency_manifest: a manifest under a dependency folder (DEP_MARKERS) belongs to an installed package.
pub fn is_dependency_manifest(p: &Pack, path: &[u32]) -> bool {
    let path = pystr::replace(path, &s("\\"), &s("/"));
    let parts: Vec<&[u32]> = path.split(|&c| c == '/' as u32).collect();
    let markers = p.strs("DEP_MARKERS");
    parts[..parts.len() - 1].iter().any(|d| markers.iter().any(|m| m.as_slice() == *d))
}

// ---- the registry's test code ---------------------------------------------------------------------------------

/// registry/repo.py's is_test_path: a member under a folder of tests or fixtures (TEST_DIR_NAMES, its name exactly,
/// in any case), or a test file by its name (TEST_FILE_RE: Python's test_*.py and *_test.py, Go's *_test.go,
/// JavaScript's *.test.js and *.spec.js and their kin, and since 0.1.9 Rust's tests.rs and *_test.rs).
pub fn is_test_path(p: &Pack, rel: &[u32]) -> bool {
    let rel = pystr::replace(rel, &s("\\"), &s("/"));
    let parts: Vec<&[u32]> = rel.split(|&c| c == '/' as u32).collect();
    let dirs = p.strs("TEST_DIR_NAMES");
    parts[..parts.len() - 1].iter().any(|d| {
        let low = pystr::lower(d);
        dirs.iter().any(|x| *x == low)
    }) || p.re("TEST_FILE_RE").match_(parts[parts.len() - 1]).is_some()
}

/// registry/repo.py's _not_used_code: a member the package does not run when it is used (its tests, examples, docs,
/// demos, benchmarks, a web app's static assets: USE_RISK_SKIP_DIRS).
pub fn not_used_code(p: &Pack, rel: &[u32]) -> bool {
    if is_test_path(p, rel) {
        return true;
    }
    let rel = pystr::replace(rel, &s("\\"), &s("/"));
    let parts: Vec<&[u32]> = rel.split(|&c| c == '/' as u32).collect();
    let skip = p.strs("USE_RISK_SKIP_DIRS");
    parts[..parts.len() - 1].iter().any(|d| {
        let low = pystr::lower(d);
        skip.iter().any(|x| *x == low)
    })
}

/// registry/repo.py's _demote_test_findings: the findings in test code that become inventory, each one's message
/// then (INFO, "… (in test code: listed, not counted)"), or None: a supply-chain finding but the strong ones
/// (BLOCKER, CRITICAL) and those that say the scan is incomplete (TRUNCATION_RULES), and since 0.1.9 a secret
/// (S-SECRET, S-TOKEN: SECRET-FP), in a test path no entry point reaches. `issues`: [rule, sev, file, msg] each.
pub fn demoted(p: &Pack, issues: &[[PyStr; 4]], reachable: &[PyStr]) -> Vec<Option<PyStr>> {
    let truncation = p.strs("TRUNCATION_RULES");
    issues
        .iter()
        .map(|[rule, sev, file, msg]| {
            let weak_sc = pystr::starts_with(rule, "SC-")
                && !truncation.iter().any(|t| t == rule)
                && !["BLOCKER", "CRITICAL", "INFO"].iter().any(|x| is(sev, x));
            let secret = (is(rule, "S-SECRET") || is(rule, "S-TOKEN")) && !is(sev, "INFO");
            ((weak_sc || secret) && !reachable.contains(file) && is_test_path(p, file)).then(|| {
                let mut m = pystr::rstrip(msg).to_vec();
                m.extend(s(" (in test code: listed, not counted)"));
                m
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_go_file_carries_the_go_readers_text_where_it_differs() {
        // F-06: the rules read `content`; the Go reader reads `goContent` (decode::go_text), given only where the Go
        // toolchain reads the bytes otherwise (a lone "\r" here: white space to Go, a line end to the rules)
        let p = crate::pack::current();
        let read_at = |rel: &str, data: &[u8]| {
            let f = FileIn { rel: pystr::u(rel), name: pystr::u(rel.rsplit('/').next().unwrap()), size: data.len() as u64,
                             dep: Dep::Vendor(s("go"), s("vendor")), cap: 1 << 20, config_cap: 1 << 20, windows: false,
                             neumaier: false, redact: true, head: Some(Ok(data.to_vec())), data: Some(Ok(data.to_vec())),
                             sample: None, ranged: false, ranges: None, rounds: 0, pth_lines: None, media: None, sibling: None };
            let got = file(&p, &f);
            let entry = got.get("file").cloned().expect("a file");
            let field = |k: &str| entry.get(k).and_then(|v| v.as_str()).map(pystr::to_string);
            (field("content"), field("goContent"))
        };
        let read = |data: &[u8]| read_at("vendor/example.test/m/x.go", data);
        // (a vendored Go file by its name alone: the path below vendor/ begins with a module's, here example.test/testdata)
        assert_eq!(read_at("vendor/example.test/testdata/t.go", b"package t\n").0.as_deref(), Some("package t\n"));
        assert_eq!(read(b"package m\r// c\r\nvar a = 1\n"),
                   (Some("package m\n// c\nvar a = 1\n".into()), Some("package m\r// c\nvar a = 1\n".into())));
        assert_eq!(read(b"package m\r\nvar a = 1\n"), (Some("package m\nvar a = 1\n".into()), None));
    }

    #[test]
    fn never_built_is_cores() {
        let u = pystr::u;
        assert!(never_built("go", &u("x_test.go")));
        // (Go's test files end in `_test.go` exactly: these are built, and `.GO` read as `.go` is)
        assert!(!never_built("go", &u("x_TEST.go")));
        assert!(!never_built("go", &u("a/x_Test.go")));
        assert!(!never_built("go", &u("a/X_TEST.GO")));
        assert!(never_built("go", &u("_x.go")));
        assert!(never_built("go", &u("testdata/x.go")));
        assert!(!never_built("go", &u("a/x.go")));
        // (F-06) a package in vendor/ itself is the module's; below it, another module's
        assert!(!never_built("go", &u("vendor/v.go")));
        assert!(!never_built("go", &u("a/vendor/v.go")));
        assert!(never_built("go", &u("vendor/x/x.go")));
        // a vendor tree's file by its name alone: its path begins with a module's (example.test/testdata)
        assert!(go_name_never_built(&u("x_test.go")) && go_name_never_built(&u(".x.go")) && !go_name_never_built(&u("x.go")));
        assert!(never_built("crate", &u("tests/a.rs")));
        assert!(!never_built("crate", &u("src/tests/a.rs")));
    }

    #[test]
    fn commas_are_pythons() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(16_000_001), "16,000,001");
    }

    #[test]
    fn scripts_by_their_first_line() {
        // (the npm package's review-shebang-scripts cases, until BR-7's step 4 (e))
        let p = crate::pack::current();
        let lang = |b: &[u8]| script_source_lang(&p, b).map(|l| pystr::to_string(&l));
        assert_eq!(lang(b"#!/usr/bin/env node\nx()\n").as_deref(), Some("js"));
        assert_eq!(lang(b"#!/usr/bin/python3\n").as_deref(), Some("py"));
        assert_eq!(lang(b"#!/bin/sh\nls\n"), None);
        let mut controls = b"#!/usr/bin/node\n".to_vec();
        controls.extend((0u8..32).flat_map(|b| [b; 12]));
        assert_eq!(lang(&controls), None);
        assert_eq!(lang(b"\x7fELF#!/usr/bin/node\n"), None);
        assert_eq!(lang(b""), None);
    }

    #[test]
    fn dependency_manifests_by_their_folder() {
        let p = crate::pack::current();
        let u = pystr::u;
        assert!(is_dependency_manifest(&p, &u("node_modules/a/package.json")));
        assert!(is_dependency_manifest(&p, &u("app\\vendor\\x\\package.json")));
        assert!(!is_dependency_manifest(&p, &u("package.json")));
        assert!(!is_dependency_manifest(&p, &u("packages/node_modules_tools/package.json")));
    }

    #[test]
    fn test_paths() {
        // (the registry's tests' cases, until BR-7's step 4 (e): test_verdicts, test_review_entrypoints)
        let p = crate::pack::current();
        for (path, want) in [
            ("tests/a.py", true), ("pkg/test cases/x.sh", true), ("meson/unittests/t.py", true), ("src/test_util.py", true),
            ("lib/a.spec.js", true), ("src/pkg/contest.py", false), ("lib/attestation/sign.js", false), ("src/main.py", false),
            ("testkit/a.js", false), ("src/testing/a.js", true), ("testutils/x.py", false), ("integration_tests/x.py", false),
            ("__tests__/a.js", true), ("spec/a.js", true), ("lib/a.test.js", true), ("x_test.py", true), ("test_x.py", true),
            ("src\\Tests\\a.go", true), ("tests.rs", true), ("src/x_test.rs", true), ("src/mytests.rs", false),
        ] {
            assert_eq!(is_test_path(&p, &pystr::u(path)), want, "{path}");
        }
        assert!(not_used_code(&p, &pystr::u("docs/x.js")));
        assert!(!not_used_code(&p, &pystr::u("lib/docs.js")));
    }

    #[test]
    fn own_reports() {
        let u = pystr::u;
        assert!(own_report(&u("\u{feff} {\n \"generatedBy\" :\u{3000}\"lazaret-cli-1\"")));
        assert!(!own_report(&u("{\"generatedBy\": \"other\"}")));
        assert!(!own_report(&u("[{\"generatedBy\": \"lazaret-cli-1\"}]")));
    }
}
