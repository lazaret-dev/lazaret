//! Rust code read for what it does when it runs: a crate's build script, its procedural macros, the
//! functions it runs at start and the rest of its code (0.1.9, R-1).
//!
//! A crate's code runs at moments its author chose (`rsparse::hooks`): Cargo runs the build script before it
//! builds the crate, the compiler of whoever uses a procedural macro runs the macro's code, a binary that
//! links the crate runs its `#[ctor]` functions and load sections before `main`, and everything else runs when
//! the crate's code is called. Each is read with the test Python's and JavaScript's code of the same moment
//! gets, with the same reasons and severities:
//!
//! - the build script and a procedural macro crate: the install-script test (`setup.py`'s), every reason
//!   CRITICAL: `install_script_risk_model`;
//! - the start-up functions: the import-time test: `import_time_risk_model`;
//! - the rest: the same test, of which a scan counts only the reasons no library needs (SC-USE-RISK).
//!
//! The reading ([`eval`]) evaluates the code from each moment's entry points (the build script's `main`,
//! each `#[proc_macro…]` function, each start-up function), following the crate's own functions: it records
//! the processes started, the data sent, the files written and run, the names looked up, with the text each
//! is given where the code builds it (`format!`, a constant, base64 decoded…). `model::facts` turns those
//! into what the tests ask ([`crate::signs::ModelFacts`]); the tests also read the code's text for the signs
//! a text shows (a stager script, a reverse shell's command, a raw IP address), with comments and tests left
//! out. The values, the events and the facts are shared with Go's reader (`crate::model`).
//!
//! A crate is its files: the build script's (it and the modules it declares), the library's (its root and
//! its modules) and the binaries'. Tests, benches and examples are never built into a dependent, and are not
//! read.

pub mod ast;
pub mod eval;
pub mod lit;

#[cfg(test)]
mod tests;

use crate::model::{events, facts};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::rsparse::{self, Kind as IK, Tree, NONE};
use eval::{FileRef, Krate, Model};
use std::collections::{HashMap, HashSet};

pub use crate::model::{Found, UseRead};

/// Units of a crate: the code built together.
pub const UNIT_NONE: u8 = 0;
pub const UNIT_BUILD: u8 = 1;
pub const UNIT_LIB: u8 = 2;
pub const UNIT_BIN: u8 = 3;

/// The work one moment's reading may do, in steps of the evaluator.
const BUILD_STEPS: u64 = 3_000_000;
const USE_STEPS_PER_ROOT: u64 = 40_000;
const USE_STEPS: u64 = 6_000_000;

/// What a crate's reading is told: its build script's path (Cargo.toml's `package.build`, `build.rs` by
/// default; None for none), whether it is a procedural macro crate, its library's root, and the bounds of
/// the use-time test's reading (as the registry's for Python and JavaScript: a file of more characters is not
/// read, and the files read, smallest first, hold at most `use_chars`).
#[derive(Clone, Debug)]
pub struct Options {
    pub build: Option<PyStr>,
    pub proc_macro: bool,
    pub lib: Option<PyStr>,
    pub use_file_chars: usize,
    pub use_chars: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { build: None, proc_macro: false, lib: None, use_file_chars: 8_000_000, use_chars: 24_000_000 }
    }
}

/// A crate's reading: the build script's, the procedural macros', the start-up functions' and the rest's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    pub build: Option<Found>,
    pub macros: Option<Found>,
    pub start: Vec<Found>,
    pub uses: Vec<Found>,
    /// The files read (the others: tests, benches, examples, files no unit holds).
    pub read: Vec<usize>,
    pub use_read: UseRead,
}

fn dir_of(path: &[u32]) -> PyStr {
    match path.iter().rposition(|&c| c == '/' as u32) {
        Some(k) => path[..k].to_vec(),
        None => Vec::new(),
    }
}

fn join(dir: &[u32], rest: &[u32]) -> PyStr {
    if dir.is_empty() {
        return rest.to_vec();
    }
    let mut out = dir.to_vec();
    out.push('/' as u32);
    out.extend_from_slice(rest);
    normalize(&out)
}

fn normalize(path: &[u32]) -> PyStr {
    let mut parts: Vec<&[u32]> = Vec::new();
    for part in path.split(|&c| c == '/' as u32) {
        if part.is_empty() || pystr::eq(part, ".") {
            continue;
        }
        if pystr::eq(part, "..") {
            parts.pop();
            continue;
        }
        parts.push(part);
    }
    pystr::join(&u("/"), &parts)
}

/// Is a file one a dependent never builds (tests, benches, examples)?
fn never_built(path: &[u32]) -> bool {
    let first = path.split(|&c| c == '/' as u32).next().unwrap_or(&[]);
    ["tests", "benches", "examples"].iter().any(|d| pystr::eq(first, d))
}

/// The items inside `#[cfg(test)]`, `#[test]` and the like, and what they hold.
fn test_items(tree: &Tree, src: &[u32]) -> HashSet<u32> {
    let mut out = HashSet::new();
    for (k, it) in tree.items.iter().enumerate() {
        let _ = it;
        let mut test = false;
        for a in tree.attrs_of(k) {
            let path = tree.attr_path(src, a);
            if path == "test" || path == "bench" || path.ends_with("::test") {
                test = true;
            }
            if path == "cfg" {
                if let Some((o, c)) = tree.attr_args(src, a) {
                    let inner: String = (o + 1..c).map(|t| tree.text(src, t)).collect::<Vec<_>>().join(" ");
                    let compact: String = inner.split_whitespace().collect();
                    if compact == "test" || compact.starts_with("all(test") || compact.contains("(test,") && !compact.contains("not(test") && compact.starts_with("all(") {
                        test = true;
                    }
                }
            }
        }
        if test || (it.parent != NONE && out.contains(&it.parent)) {
            out.insert(k as u32);
        }
    }
    out
}

/// The names a file's `use` items bring in, each with its path.
fn use_map(tree: &Tree, src: &[u32]) -> HashMap<PyStr, Vec<PyStr>> {
    let mut out = HashMap::new();
    for leaf in &tree.leaves {
        if leaf.glob {
            continue;
        }
        let mut segs: Vec<PyStr> = (0..leaf.segs.1).map(|k| u(&tree.ident(src, tree.segs[(leaf.segs.0 + k) as usize]))).collect();
        if segs.last().is_some_and(|s| pystr::eq(s, "self")) {
            segs.pop();
        }
        let Some(last) = segs.last().cloned() else { continue };
        let name = if leaf.alias != NONE { u(&tree.ident(src, leaf.alias)) } else { last };
        if pystr::eq(&name, "_") {
            continue;
        }
        out.insert(name, segs);
    }
    out
}

/// The files a module tree holds, from its root: `mod x;` is `x.rs` or `x/mod.rs` beside a root (or a
/// `mod.rs`), and below `f/` for a module file `f.rs`; `#[path = "…"]` names the file.
fn module_tree(paths: &[PyStr], trees: &[Tree], srcs: &[&[u32]], root: usize) -> Vec<usize> {
    let index: HashMap<&[u32], usize> = paths.iter().enumerate().map(|(k, p)| (p.as_slice(), k)).collect();
    let mut seen: HashSet<usize> = HashSet::new();
    let mut out = vec![root];
    seen.insert(root);
    let mut queue = vec![root];
    while let Some(fi) = queue.pop() {
        let path = &paths[fi];
        let tree = &trees[fi];
        let src = srcs[fi];
        let base = {
            let name = path.iter().rposition(|&c| c == '/' as u32).map(|k| &path[k + 1..]).unwrap_or(&path[..]);
            let is_root = ["lib.rs", "main.rs", "mod.rs", "build.rs"].iter().any(|r| pystr::eq(name, r)) || fi == root;
            if is_root {
                dir_of(path)
            } else {
                let stem = &path[..path.len().saturating_sub(3)];
                stem.to_vec()
            }
        };
        for (k, it) in tree.items.iter().enumerate() {
            if it.kind != IK::Mod || it.body_open != NONE {
                continue;
            }
            // the inline modules around it
            let mut nest: Vec<PyStr> = Vec::new();
            for a in tree.ancestors(k) {
                let anc = &tree.items[a];
                if anc.kind == IK::Mod {
                    nest.push(u(&tree.name(src, a)));
                } else {
                    nest.clear();
                    break;
                }
            }
            nest.reverse();
            let name = u(&tree.name(src, k));
            let mut dir = base.clone();
            for n in &nest {
                dir = join(&dir, n);
            }
            let mut cands: Vec<PyStr> = Vec::new();
            for a in tree.attrs_of(k) {
                if tree.attr_path(src, a) == "path" {
                    if let Some(v) = tree.attr_value(src, a).and_then(|t| tree.str_value(src, t)) {
                        cands.push(join(&dir_of(path), &u(&v)));
                    }
                }
            }
            let mut rs = name.clone();
            rs.extend(u(".rs"));
            cands.push(join(&dir, &rs));
            let mut m = name.clone();
            m.extend(u("/mod.rs"));
            cands.push(join(&dir, &m));
            if let Some(&f) = cands.iter().find_map(|c| index.get(c.as_slice())) {
                if seen.insert(f) {
                    out.push(f);
                    queue.push(f);
                }
            }
        }
    }
    out
}

/// A crate's files read: which run at build, at start and when used, and what each moment's code does.
pub fn read_crate(p: &Pack, files: &[(PyStr, &[u32])], opts: &Options) -> Answer {
    let paths: Vec<PyStr> = files.iter().map(|(path, _)| normalize(path)).collect();
    let srcs: Vec<&[u32]> = files.iter().map(|(_, t)| *t).collect();
    let trees: Vec<Tree> = srcs.iter().map(|t| rsparse::parse(t)).collect();
    let find = |want: &[u32]| paths.iter().position(|p| p.as_slice() == want);
    // the units
    let mut unit: Vec<u8> = vec![UNIT_NONE; files.len()];
    let build_root = opts.build.as_ref().and_then(|b| find(&normalize(b)));
    let lib_root = find(&opts.lib.clone().map(|l| normalize(&l)).unwrap_or_else(|| u("src/lib.rs")));
    if let Some(r) = lib_root {
        for f in module_tree(&paths, &trees, &srcs, r) {
            unit[f] = UNIT_LIB;
        }
    }
    let bins: Vec<usize> = (0..files.len())
        .filter(|&k| {
            let parts: Vec<&[u32]> = paths[k].split(|&c| c == '/' as u32).collect();
            pystr::eq(&paths[k], "src/main.rs")
                || (parts.len() == 3 && pystr::eq(parts[0], "src") && pystr::eq(parts[1], "bin") && pystr::ends_with(parts[2], ".rs"))
                || (parts.len() == 4 && pystr::eq(parts[0], "src") && pystr::eq(parts[1], "bin") && pystr::eq(parts[3], "main.rs"))
        })
        .collect();
    for &b in &bins {
        for f in module_tree(&paths, &trees, &srcs, b) {
            if unit[f] == UNIT_NONE {
                unit[f] = UNIT_BIN;
            }
        }
    }
    if let Some(r) = build_root {
        for f in module_tree(&paths, &trees, &srcs, r) {
            unit[f] = UNIT_BUILD;
        }
    }
    // a file no tree reached, under src/: the library's (a module named by a macro, an include!)
    for k in 0..files.len() {
        if unit[k] == UNIT_NONE && !never_built(&paths[k]) && pystr::starts_with(&paths[k], "src/") {
            unit[k] = UNIT_LIB;
        }
    }
    let mut kfiles: Vec<FileRef> = Vec::with_capacity(files.len());
    for (k, tree) in trees.into_iter().enumerate() {
        let src = srcs[k];
        let tests = test_items(&tree, src);
        let uses = use_map(&tree, src);
        kfiles.push(FileRef { path: paths[k].clone(), src, tree, uses, unit: unit[k], test_items: tests });
    }
    let mut krate = Krate { files: kfiles, fns: HashMap::new(), consts: HashMap::new(), b64_fns: HashSet::new() };
    index(&mut krate);
    let mut answer = Answer { read: (0..files.len()).filter(|&k| unit[k] != UNIT_NONE).collect(), ..Answer::default() };

    // ---- the build script
    let mut owned: HashSet<(u16, u32)> = HashSet::new();
    if let Some(r) = build_root {
        let roots: Vec<(u16, u32)> = rsparse::hooks(&krate.files[r].tree, krate.files[r].src, true)
            .into_iter()
            .filter(|h| h.kind == rsparse::HookKind::BuildMain)
            .map(|h| (r as u16, h.item))
            .collect();
        let mut m = Model::new(&krate, p);
        m.max_steps = BUILD_STEPS;
        for &(f, i) in &roots {
            m.run_root(f, i);
        }
        m.flush_cmds();
        owned.extend(m.reached.iter().copied());
        let files_of: Vec<usize> = (0..krate.files.len()).filter(|&k| krate.files[k].unit == UNIT_BUILD).collect();
        answer.build = install_finding(p, &krate, &m.events, r, &files_of, None);
    }
    // ---- procedural macros
    let mut macro_roots: Vec<(u16, u32)> = Vec::new();
    let mut start_roots: Vec<(u16, u32)> = Vec::new();
    for (fi, f) in krate.files.iter().enumerate() {
        if f.unit != UNIT_LIB && f.unit != UNIT_BIN {
            continue;
        }
        for h in rsparse::hooks(&f.tree, f.src, false) {
            if h.item == NONE || f.test_items.contains(&h.item) {
                continue;
            }
            match h.kind {
                rsparse::HookKind::ProcMacro => macro_roots.push((fi as u16, h.item)),
                rsparse::HookKind::LoadFn | rsparse::HookKind::OwnEntry => start_roots.push((fi as u16, h.item)),
                rsparse::HookKind::LoadSection => {
                    let it = &f.tree.items[h.item as usize];
                    if it.kind == IK::Fn {
                        start_roots.push((fi as u16, h.item));
                    } else if let Some(target) = static_fn_target(&krate, fi, h.item as usize) {
                        start_roots.push(target);
                    }
                }
                rsparse::HookKind::BuildMain => {}
            }
        }
    }
    if opts.proc_macro || !macro_roots.is_empty() {
        let mut m = Model::new(&krate, p);
        m.max_steps = BUILD_STEPS;
        for &(f, i) in &macro_roots {
            m.run_root(f, i);
        }
        m.flush_cmds();
        owned.extend(m.reached.iter().copied());
        // (a procedural macro crate's library is all build-time code: its text read whole)
        if let Some(root) = lib_root.or_else(|| macro_roots.first().map(|r| r.0 as usize)) {
            let files_of: Vec<usize> = (0..krate.files.len()).filter(|&k| krate.files[k].unit == UNIT_LIB).collect();
            answer.macros = install_finding(p, &krate, &m.events, root, &files_of, None);
        }
    }
    // ---- start-up functions
    if !start_roots.is_empty() {
        let mut m = Model::new(&krate, p);
        m.max_steps = BUILD_STEPS;
        let mut by_file: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(f, i) in &start_roots {
            let before = m.events.len();
            m.run_root(f, i);
            m.flush_cmds();
            by_file.entry(f as usize).or_default().extend(before..m.events.len());
        }
        let reached = m.reached.clone();
        owned.extend(reached.iter().copied());
        let mut files: Vec<usize> = by_file.keys().copied().collect();
        files.sort_unstable();
        for fi in files {
            let evs: Vec<events::Ev> = by_file[&fi].iter().map(|&k| m.events[k].clone()).collect();
            let keep: HashSet<u32> = reached.iter().filter(|(f, _)| *f as usize == fi).map(|(_, i)| *i).collect();
            if let Some(found) = import_finding(p, &krate, &evs, fi, Some(&keep)) {
                answer.start.push(found);
            }
        }
    }
    // ---- the rest: the functions no moment above reached, when used
    if !opts.proc_macro {
        let (uses, read) = use_findings(p, &krate, &owned, opts);
        answer.uses = uses;
        answer.use_read = read;
    }
    answer
}

/// The crate's functions and constants by name, and the decoders written out.
fn index(k: &mut Krate) {
    let alphabet = u("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    for (fi, f) in k.files.iter().enumerate() {
        if f.unit == UNIT_NONE {
            continue;
        }
        for (ii, it) in f.tree.items.iter().enumerate() {
            if f.test_items.contains(&(ii as u32)) || it.name == NONE {
                continue;
            }
            let name = u(&f.tree.ident(f.src, it.name));
            match it.kind {
                IK::Fn => {
                    k.fns.entry((f.unit, name)).or_default().push((fi as u16, ii as u32));
                    if it.body_open != NONE && it.body_close != NONE {
                        let holds = (it.body_open..it.body_close).any(|t| {
                            let tok = f.tree.toks[t as usize];
                            tok.kind == crate::lex::Kind::Str && pystr::find(&f.src[tok.start as usize..tok.end as usize], &alphabet, 0).is_some()
                        });
                        if holds {
                            k.b64_fns.insert((fi as u16, ii as u32));
                        }
                    }
                }
                IK::Const | IK::Static => {
                    k.consts.entry((f.unit, name)).or_default().push((fi as u16, ii as u32));
                }
                _ => {}
            }
        }
    }
    // a binary reads the library's functions too
    let lib: Vec<((u8, PyStr), Vec<(u16, u32)>)> = k.fns.iter().filter(|((unit, _), _)| *unit == UNIT_LIB).map(|(key, v)| (key.clone(), v.clone())).collect();
    for ((_, name), v) in lib {
        k.fns.entry((UNIT_BIN, name)).or_default().extend(v);
    }
    let lib: Vec<((u8, PyStr), Vec<(u16, u32)>)> = k.consts.iter().filter(|((unit, _), _)| *unit == UNIT_LIB).map(|(key, v)| (key.clone(), v.clone())).collect();
    for ((_, name), v) in lib {
        k.consts.entry((UNIT_BIN, name)).or_default().extend(v);
    }
}

/// The function a load section's static points to (`static X: extern fn() = f;`).
fn static_fn_target(k: &Krate, fi: usize, item: usize) -> Option<(u16, u32)> {
    let f = &k.files[fi];
    let it = &f.tree.items[item];
    if it.extra == NONE {
        return None;
    }
    for t in it.extra + 1..it.tok_end {
        let tok = f.tree.toks.get(t as usize)?;
        if tok.kind == crate::lex::Kind::Name {
            let name = u(&f.tree.ident(f.src, t));
            if let Some(c) = k.fns.get(&(f.unit, name)) {
                return c.first().copied();
            }
        }
    }
    None
}

/// The text a moment's test reads in a file: its code, with comments, tests and (when `keep` is given) the
/// functions not in `keep` blanked; line breaks kept, so offsets and lines are the file's.
fn view(f: &FileRef, keep: Option<&HashSet<u32>>, drop: Option<&HashSet<u32>>) -> PyStr {
    let mut spans: Vec<(usize, usize)> = crate::lex::structure(f.src, "rs", false).map(|s| s.comments).unwrap_or_default();
    for (ii, it) in f.tree.items.iter().enumerate() {
        let ii = ii as u32;
        let blank = f.test_items.contains(&ii)
            || (it.kind == IK::Fn && keep.is_some_and(|k| !k.contains(&ii)) && !f.tree.ancestors(ii as usize).iter().any(|&a| keep.is_some_and(|k| k.contains(&(a as u32)))))
            || (it.kind == IK::Fn && drop.is_some_and(|d| d.contains(&ii)));
        if blank {
            spans.push((it.start as usize, it.end as usize));
        }
    }
    spans.sort_unstable();
    crate::signs::blank(f.src, &spans)
}

/// The install-script test's finding for a moment's code: the events of its reading, and its files' texts.
fn install_finding(p: &Pack, k: &Krate, events: &[events::Ev], root: usize, files_of: &[usize], keep: Option<&HashSet<u32>>) -> Option<Found> {
    let mut reasons: Vec<PyStr> = Vec::new();
    let mut line: Option<usize> = None;
    // the model's facts, read with the root file's text; then each other file's text alone
    let root_view = view(&k.files[root], keep, None);
    let facts = facts::facts(p, k.files[root].src, events, root);
    let _gate = crate::textgate::open(&root_view);
    for r in crate::signs::install_script_risk_model(p, &root_view, &facts.facts) {
        if !reasons.contains(&r) {
            reasons.push(r);
        }
    }
    if !reasons.is_empty() {
        line = facts.first_line;
    }
    let empty = crate::signs::ModelFacts::default();
    for &fi in files_of {
        if fi == root {
            continue;
        }
        let v = view(&k.files[fi], keep, None);
        let _gate = crate::textgate::open(&v);
        for r in crate::signs::install_script_risk_model(p, &v, &empty) {
            if !reasons.contains(&r) {
                reasons.push(r);
            }
        }
    }
    if reasons.is_empty() {
        return None;
    }
    Some(Found { file: root, reasons, line: line.unwrap_or(1) })
}

/// The import-time test's finding for code read from a start-up function: its file's events and text.
fn import_finding(p: &Pack, k: &Krate, events: &[events::Ev], file: usize, keep: Option<&HashSet<u32>>) -> Option<Found> {
    let text = view(&k.files[file], keep, None);
    let f = facts::facts(p, k.files[file].src, events, file);
    let _gate = crate::textgate::open(&text);
    let (reasons, line) = crate::signs::import_time_risk_model(p, &text, &f.facts);
    if reasons.is_empty() {
        return None;
    }
    Some(Found { file, reasons, line: line.or(f.first_line).unwrap_or(1) })
}

/// Does a function's body name something that reaches outside the program (a process, the network, a file
/// written, a library loaded, a name looked up)?
fn sinks(f: &FileRef, it: &rsparse::Item) -> bool {
    const WORDS: &[&str] = &[
        "Command", "TcpStream", "UdpSocket", "reqwest", "ureq", "minreq", "attohttpc", "isahc", "surf", "Easy", "Library",
        "to_socket_addrs", "lookup_host", "txt_lookup", "OpenOptions", "copy_to", "set_permissions", "Resolver",
    ];
    if it.body_open == NONE || it.body_close == NONE {
        return false;
    }
    let mut fs = false;
    for t in it.body_open..it.body_close {
        let tok = f.tree.toks[t as usize];
        if tok.kind != crate::lex::Kind::Name {
            continue;
        }
        let w = &f.src[tok.start as usize..tok.end as usize];
        if WORDS.iter().any(|x| pystr::eq(w, x)) {
            return true;
        }
        if pystr::eq(w, "fs") || pystr::eq(w, "File") || pystr::eq(w, "io") {
            fs = true;
        }
        if fs && (pystr::eq(w, "write") || pystr::eq(w, "create") || pystr::eq(w, "copy")) {
            return true;
        }
    }
    false
}

/// SC-USE-RISK's reading: every function the moments above did not reach that holds a sink, and the
/// functions that call one of those, each read alone (its parameters not known), a few calls deep; then
/// each file of the library and the binaries, with what its functions do, by the import-time test.
fn use_findings(p: &Pack, k: &Krate, owned: &HashSet<(u16, u32)>, opts: &Options) -> (Vec<Found>, UseRead) {
    let mut sink_fns: HashSet<(u16, u32)> = HashSet::new();
    let mut sink_names: HashSet<PyStr> = HashSet::new();
    for (fi, f) in k.files.iter().enumerate() {
        if f.unit != UNIT_LIB && f.unit != UNIT_BIN {
            continue;
        }
        for (ii, it) in f.tree.items.iter().enumerate() {
            if it.kind != IK::Fn || f.test_items.contains(&(ii as u32)) || owned.contains(&(fi as u16, ii as u32)) {
                continue;
            }
            if sinks(f, it) {
                sink_fns.insert((fi as u16, ii as u32));
                sink_names.insert(u(&f.tree.ident(f.src, it.name)));
            }
        }
    }
    // the callers of a sink function (a call of its name)
    let mut roots: Vec<(u16, u32)> = sink_fns.iter().copied().collect();
    for (fi, f) in k.files.iter().enumerate() {
        if f.unit != UNIT_LIB && f.unit != UNIT_BIN {
            continue;
        }
        for (ii, it) in f.tree.items.iter().enumerate() {
            let key = (fi as u16, ii as u32);
            if it.kind != IK::Fn || it.body_open == NONE || it.body_close == NONE || f.test_items.contains(&(ii as u32)) || owned.contains(&key) || sink_fns.contains(&key) {
                continue;
            }
            let calls = (it.body_open..it.body_close).any(|t| {
                let tok = f.tree.toks[t as usize];
                tok.kind == crate::lex::Kind::Name && sink_names.contains(&f.src[tok.start as usize..tok.end as usize].to_vec())
            });
            if calls {
                roots.push(key);
            }
        }
    }
    roots.sort_unstable();
    let mut m = Model::new(k, p);
    m.max_depth = 4;
    m.not_follow = owned.clone();
    let mut by_file: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut total = 0u64;
    for (f, i) in roots {
        if total >= USE_STEPS {
            break;
        }
        let before_steps = m.steps_used();
        m.max_steps = before_steps + USE_STEPS_PER_ROOT;
        let before = m.events.len();
        m.run_root(f, i);
        m.flush_cmds();
        total += m.steps_used() - before_steps;
        for e in before..m.events.len() {
            let ef = events::ev_file(&m.events[e]) as usize;
            by_file.entry(ef).or_default().push(e);
        }
    }
    // every file of the library and the binaries, smallest first, within the bounds
    let mut files: Vec<usize> = (0..k.files.len()).filter(|&fi| matches!(k.files[fi].unit, UNIT_LIB | UNIT_BIN)).collect();
    files.sort_by_key(|&fi| (k.files[fi].src.len(), fi));
    let mut read = UseRead { of_files: files.len(), of_chars: files.iter().map(|&fi| k.files[fi].src.len()).sum(), ..UseRead::default() };
    let mut room = opts.use_chars;
    let mut out = Vec::new();
    for fi in files {
        let n = k.files[fi].src.len();
        if n > opts.use_file_chars.min(room) {
            break; // (sizes only grow from here)
        }
        room -= n;
        read.files += 1;
        read.chars += n;
        let evs: Vec<events::Ev> = by_file.get(&fi).map(|v| v.iter().map(|&e| m.events[e].clone()).collect()).unwrap_or_default();
        let blanked: HashSet<u32> = owned.iter().filter(|(f, _)| *f as usize == fi).map(|(_, i)| *i).collect();
        let text = view(&k.files[fi], None, Some(&blanked));
        let fx = facts::facts(p, k.files[fi].src, &evs, fi);
        let (reasons, line) = {
            let _gate = crate::textgate::open(&text);
            crate::signs::import_time_risk_model(p, &text, &fx.facts)
        };
        if !reasons.is_empty() {
            out.push(Found { file: fi, reasons, line: line.or(fx.first_line).unwrap_or(1) });
        }
    }
    (out, read)
}
