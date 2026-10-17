//! Go code read for what it does when it runs: the code a package's `init` functions and package initializers reach,
//! which runs when any program that imports the package starts, and the rest when it is used (0.1.9, G-1).
//!
//! Go has no install script, but a package's code still runs at moments its user did not choose (`goparse::hooks`):
//! every `init` function and the initializer of every package-level variable run when a program that imports the
//! package starts, and a cgo preamble's C is compiled in, its constructors run at start. Each is read with the test
//! Python's and JavaScript's code of the same moment gets, with the same reasons and severities:
//!
//! - what `init` and the package initializers reach (and a cgo constructor): the import-time test
//!   (`import_time_risk_model`);
//! - the rest: the same test, of which a scan counts only the reasons no library needs (SC-USE-RISK).
//!
//! `//go:generate` runs only when someone runs `go generate`, and `//go:linkname` runs nothing: both are listed,
//! never judged here.
//!
//! The reading ([`eval`]) evaluates the code from each moment's entry points, following the package's own functions,
//! methods and closures and the module's other packages; then every function the entry points call by name, however
//! deep, is read on its own too. It records the processes started, the data sent, the files written and run, the
//! names looked up and the libraries loaded, with the text each is given where the code builds it (`+`,
//! `fmt.Sprintf`, `strings.Join`, a string array read by index, a byte slice, base64, hex, a loop that decodes).
//! `model::facts` turns those into what the tests ask; the tests also read the code's text for the signs a text
//! shows, with comments, other moments' code and what no build reads left out. A reading cut short by its bounds has
//! its text read by the text test as well.
//!
//! A module is its packages, one per folder, each read as one unit, as Go compiles it. Files no build of a
//! dependent reads are not: `_test.go` files, files and folders whose names start with `_` or `.`, `testdata/`,
//! `vendor/` (other modules, read on their own), and files constrained to `ignore`. A file the parser refuses could
//! not be built, so nothing in it runs: it is listed (`unparsed`) for the text rules.

pub mod cread;
pub mod eval;
pub mod lit;

#[cfg(test)]
mod tests;

use crate::goparse::{self, scan::Tok, tree::Kind as K, tree::NodeId, tree::NONE, HookKind};
use crate::model::{events, facts};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use eval::{FileRef, Global, Model, Module, Pkg};
use std::collections::{HashMap, HashSet};

pub use crate::model::{Found, UseRead};

/// The work each moment's reading may do, in steps of the evaluator.
const INIT_STEPS: u64 = 3_000_000;
const REST_STEPS_PER_ROOT: u64 = 40_000;
const REST_STEPS: u64 = 3_000_000;
const USE_STEPS_PER_ROOT: u64 = 40_000;
const USE_STEPS: u64 = 6_000_000;
/// The most files a module's reading reads (an event names its file in 16 bits).
pub const MAX_FILES: usize = 60_000;

/// What a module's reading is told: its module path (go.mod's `module`; when it is not given, the module's own
/// imports are recognized by the folders they end in), and the bounds of the use-time test's reading (as the
/// registry's for Python and JavaScript: a file of more characters is not read, and the files read, smallest first,
/// hold at most `use_chars`).
#[derive(Clone, Debug)]
pub struct Options {
    pub module: Option<PyStr>,
    pub use_file_chars: usize,
    pub use_chars: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { module: None, use_file_chars: 8_000_000, use_chars: 24_000_000 }
    }
}

/// A module's reading.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    /// The import-time test's findings: what `init`, the package initializers and cgo constructors reach.
    pub start: Vec<Found>,
    /// The use-time test's findings.
    pub uses: Vec<Found>,
    /// The files read.
    pub read: Vec<usize>,
    /// The `.go` files the parser refused (no build reads them; the text rules do).
    pub unparsed: Vec<usize>,
    /// `//go:generate` commands and `//go:linkname` directives: (file, 1-based line, its text).
    pub generate: Vec<(usize, usize, PyStr)>,
    pub linkname: Vec<(usize, usize, PyStr)>,
    pub use_read: UseRead,
}

fn split_path(p: &[u32]) -> Vec<&[u32]> {
    p.split(|&c| c == '/' as u32).filter(|s| !s.is_empty()).collect()
}

fn dir_of(p: &[u32]) -> PyStr {
    match p.iter().rposition(|&c| c == '/' as u32) {
        Some(k) => p[..k].to_vec(),
        None => Vec::new(),
    }
}

fn base_of(p: &[u32]) -> &[u32] {
    match p.iter().rposition(|&c| c == '/' as u32) {
        Some(k) => &p[k + 1..],
        None => p,
    }
}

fn normalize(p: &[u32]) -> PyStr {
    let mut parts: Vec<&[u32]> = Vec::new();
    for part in p.split(|&c| c == '/' as u32 || c == '\\' as u32) {
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

/// Is a file one no build of a dependent reads by its name or place?
fn never_built(path: &[u32]) -> bool {
    let parts = split_path(path);
    let Some((base, dirs)) = parts.split_last() else { return true };
    if base.first().is_some_and(|&c| c == '_' as u32 || c == '.' as u32) || pystr::ends_with(base, "_test.go") {
        return true;
    }
    dirs.iter().any(|d| pystr::eq(d, "testdata") || pystr::eq(d, "vendor"))
}

/// Is a Go file constrained to `ignore` (`//go:build ignore`, `// +build ignore`): never built?
fn build_ignored(src: &[u32]) -> bool {
    let text: String = src.iter().take(64 * 1024).filter_map(|&c| char::from_u32(c)).collect();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(expr) = l.strip_prefix("//go:build") {
            let e: String = expr.split_whitespace().collect();
            if e.contains("||") || e.contains('!') {
                return false;
            }
            return e.split("&&").any(|t| t.trim_matches(|c| c == '(' || c == ')') == "ignore");
        }
        if let Some(opts) = l.strip_prefix("// +build") {
            if opts.split_whitespace().all(|o| o.split(',').any(|t| t == "ignore")) && !opts.trim().is_empty() {
                return true;
            }
            continue;
        }
        if l.starts_with("//") {
            continue;
        }
        if l.starts_with("/*") {
            continue;
        }
        break;
    }
    false
}

fn is_c(path: &[u32]) -> bool {
    let b = pystr::lower(base_of(path));
    [".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".m", ".mm"].iter().any(|e| pystr::ends_with(&b, e))
}

/// An import's name when it has none of its own: its path's last element, without a major version (`…/v2`,
/// `gopkg.in/yaml.v3`) or a `go-` prefix.
fn default_name(path: &[u32]) -> PyStr {
    let parts = split_path(path);
    let mut last: &[u32] = parts.last().copied().unwrap_or(&[]);
    let is_major = |s: &[u32]| s.len() >= 2 && s[0] == 'v' as u32 && s[1..].iter().all(|&c| ('0' as u32..='9' as u32).contains(&c));
    if is_major(last) && parts.len() >= 2 {
        last = parts[parts.len() - 2];
    }
    let mut name = last.to_vec();
    if let Some(k) = name.iter().position(|&c| c == '.' as u32) {
        name.truncate(k);
    }
    if pystr::starts_with(&name, "go-") {
        name = name[3..].to_vec();
    }
    if pystr::ends_with(&name, "-go") {
        name.truncate(name.len() - 3);
    }
    name.into_iter().map(|c| if c == '-' as u32 { '_' as u32 } else { c }).collect()
}

fn line_of(text: &[u32], at: usize) -> usize {
    text[..at.min(text.len())].iter().filter(|&&c| c == 10).count() + 1
}

/// Does a comment written `//go:embed …` lead the code at `start` (only white space and other comments between)?
fn led_by_embed(src: &[u32], comments: &[(usize, usize)], start: usize) -> bool {
    let mut at = start;
    let mut i = comments.partition_point(|&(_, ce)| ce <= start);
    while i > 0 {
        i -= 1;
        let (cs, ce) = comments[i];
        if !src[ce.min(src.len())..at.min(src.len())].iter().all(|&c| matches!(char::from_u32(c), Some(' ' | '\t' | '\r' | '\n'))) {
            break;
        }
        if pystr::starts_with(&src[cs..ce.min(src.len())], "//go:embed") {
            return true;
        }
        at = cs;
    }
    false
}

/// A Go file parsed, with what the reading needs besides its tree.
struct GoFile {
    index: usize,
    comments: Vec<(usize, usize)>,
    hooks: Vec<goparse::Hook>,
    /// Its package clause's name.
    name: PyStr,
}

/// A module's files read: what runs when a program that imports its packages starts, and the rest when used.
pub fn read_module(p: &Pack, files: &[(PyStr, &[u32])], opts: &Options) -> Answer {
    let mut answer = Answer::default();
    let paths: Vec<PyStr> = files.iter().map(|(path, _)| normalize(path)).collect();
    // ---- the files a build reads, parsed
    let mut gofiles: Vec<GoFile> = Vec::new();
    let mut trees: Vec<(usize, goparse::Tree)> = Vec::new();
    let mut cfiles: Vec<usize> = Vec::new();
    for (k, (_, src)) in files.iter().enumerate().take(MAX_FILES) {
        let path = &paths[k];
        if pystr::ends_with(&pystr::lower(path), ".go") {
            if never_built(path) || build_ignored(src) {
                continue;
            }
            match goparse::parse(src) {
                Ok(tree) => {
                    let comments = crate::lex::structure(src, "go", false).map(|s| s.comments).unwrap_or_default();
                    let hooks = goparse::hooks(&tree, src, &comments);
                    let root = tree.node(tree.root);
                    let name = if root.f[0] != NONE {
                        let n = tree.node(root.f[0]);
                        src[n.start as usize..n.end as usize].to_vec()
                    } else {
                        Vec::new()
                    };
                    gofiles.push(GoFile { index: k, comments, hooks, name });
                    trees.push((k, tree));
                }
                Err(_) => answer.unparsed.push(k),
            }
        } else if is_c(path) && !never_built(path) {
            cfiles.push(k);
        }
    }
    // ---- packages: one per folder
    let mut dirs: Vec<PyStr> = gofiles.iter().map(|g| dir_of(&paths[g.index])).collect();
    dirs.sort();
    dirs.dedup();
    let pkg_of_dir: HashMap<PyStr, u32> = dirs.iter().enumerate().map(|(k, d)| (d.clone(), k as u32)).collect();
    let mut pkgs: Vec<Pkg> = dirs.iter().map(|d| Pkg { dir: d.clone(), ..Pkg::default() }).collect();
    let mut pkg_names: Vec<PyStr> = vec![Vec::new(); pkgs.len()];
    for g in &gofiles {
        let pk = pkg_of_dir[&dir_of(&paths[g.index])] as usize;
        if pkg_names[pk].is_empty() {
            pkg_names[pk] = g.name.clone();
        }
    }
    // the module's own packages by import path: the module's path and the folder, or, with no module path, an import
    // that ends in a folder's path
    let mut by_path: HashMap<PyStr, u32> = HashMap::new();
    let mut module = opts.module.clone().filter(|m| !m.is_empty());
    let mut all_imports: Vec<PyStr> = Vec::new();
    for (gi, g) in gofiles.iter().enumerate() {
        let (_, tree) = &trees[gi];
        let src = files[g.index].1;
        for &decl in tree.items(tree.node(tree.root).f[1]) {
            let d = tree.node(decl);
            if d.kind != K::GenDecl || d.op != Tok::Import as u8 {
                continue;
            }
            for &spec in tree.items(d.f[0]) {
                let s = tree.node(spec);
                if s.f[1] == NONE {
                    continue;
                }
                let lit = tree.node(s.f[1]);
                if let Some(path) = lit::string_lit(&src[lit.start as usize..lit.end as usize]) {
                    all_imports.push(path);
                }
            }
        }
    }
    if module.is_none() {
        for imp in &all_imports {
            for (k, d) in dirs.iter().enumerate() {
                if d.is_empty() || imp.len() <= d.len() + 1 {
                    continue;
                }
                if pystr::ends_with(imp, &pystr::to_string(d)) && imp[imp.len() - d.len() - 1] == '/' as u32 {
                    let root = imp[..imp.len() - d.len() - 1].to_vec();
                    // (the longest folder that matches says where the module's path ends)
                    if module.as_ref().map_or(true, |m: &PyStr| root.len() < m.len()) {
                        module = Some(root);
                    }
                    let _ = k;
                }
            }
        }
    }
    if let Some(m) = &module {
        for (k, d) in dirs.iter().enumerate() {
            let path = if d.is_empty() { m.clone() } else { pystr::concat(&[m, &u("/"), d]) };
            by_path.insert(path, k as u32);
        }
    }
    // ---- the files as the evaluator reads them: their imports' names
    let mut frefs: Vec<FileRef> = Vec::with_capacity(gofiles.len());
    let mut trees_it = trees.into_iter();
    for g in &gofiles {
        let (_, tree) = trees_it.next().expect("a tree per Go file");
        let src = files[g.index].1;
        let pkg = pkg_of_dir[&dir_of(&paths[g.index])];
        let mut imports: HashMap<PyStr, PyStr> = HashMap::new();
        for &decl in tree.items(tree.node(tree.root).f[1]) {
            let d = tree.node(decl);
            if d.kind != K::GenDecl || d.op != Tok::Import as u8 {
                continue;
            }
            for &spec in tree.items(d.f[0]) {
                let s = tree.node(spec);
                if s.f[1] == NONE {
                    continue;
                }
                let lit = tree.node(s.f[1]);
                let Some(path) = lit::string_lit(&src[lit.start as usize..lit.end as usize]) else { continue };
                let name = if s.f[0] != NONE {
                    let n = tree.node(s.f[0]);
                    src[n.start as usize..n.end as usize].to_vec()
                } else if let Some(&pk) = by_path.get(&path) {
                    pkg_names[pk as usize].clone()
                } else {
                    default_name(&path)
                };
                if name.is_empty() || pystr::eq(&name, "_") || pystr::eq(&name, ".") {
                    continue;
                }
                imports.insert(name, path);
            }
        }
        frefs.push(FileRef { path: paths[g.index].clone(), src, tree, pkg, imports });
    }
    // ---- each package's functions, methods, types and package-level names
    let alphabet = u("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    let mut b64_fns: HashSet<(u16, NodeId)> = HashSet::new();
    let mut var_init: Vec<(u32, u16, NodeId)> = Vec::new(); // (package, file, ValueSpec) of the initializers that run
    for (fi, f) in frefs.iter().enumerate() {
        let fi16 = fi as u16;
        let pk = &mut pkgs[f.pkg as usize];
        pk.files.push(fi16);
        let tree = &f.tree;
        let comments = &gofiles[fi].comments;
        for &decl in tree.items(tree.node(tree.root).f[1]) {
            let d = tree.node(decl);
            match d.kind {
                K::FuncDecl => {
                    if d.f[1] == NONE {
                        continue;
                    }
                    let nm = tree.node(d.f[1]);
                    let name = f.src[nm.start as usize..nm.end as usize].to_vec();
                    if d.f[0] == NONE {
                        pk.funcs.entry(name).or_default().push((fi16, decl));
                    } else {
                        pk.methods.entry(name).or_default().push((fi16, decl));
                    }
                    // a decoder written out: base64's alphabet in a string of its body
                    if d.f[3] != NONE {
                        let mut holds = false;
                        let mut stack = vec![d.f[3]];
                        let mut kids: Vec<u32> = Vec::new();
                        while let Some(id) = stack.pop() {
                            let n = tree.node(id);
                            if n.kind == K::BasicLit && n.op == Tok::Str as u8 {
                                if let Some(s) = lit::string_lit(&f.src[n.start as usize..n.end as usize]) {
                                    if pystr::find(&s, &alphabet, 0).is_some() {
                                        holds = true;
                                        break;
                                    }
                                }
                            }
                            kids.clear();
                            tree.each_child(id, &mut |x| kids.push(x));
                            stack.extend(kids.iter().rev());
                        }
                        if holds {
                            b64_fns.insert((fi16, decl));
                        }
                    }
                }
                K::GenDecl if d.op == Tok::Type as u8 => {
                    for &spec in tree.items(d.f[0]) {
                        let s = tree.node(spec);
                        if s.f[0] != NONE {
                            let nm = tree.node(s.f[0]);
                            pk.types.insert(f.src[nm.start as usize..nm.end as usize].to_vec());
                        }
                    }
                }
                K::GenDecl if d.op == Tok::Var as u8 || d.op == Tok::Const as u8 => {
                    let constant = d.op == Tok::Const as u8;
                    let mut last_values: NodeId = NONE;
                    for (iota, &spec) in tree.items(d.f[0]).iter().enumerate() {
                        let s = tree.node(spec);
                        let values = if s.f[2] != NONE {
                            last_values = spec;
                            spec
                        } else if constant {
                            last_values
                        } else {
                            NONE
                        };
                        let embed = !constant && (led_by_embed(f.src, comments, s.start as usize) || (d.flags & goparse::tree::PAREN == 0 && led_by_embed(f.src, comments, d.start as usize)));
                        for (index, &nm) in tree.items(s.f[0]).iter().enumerate() {
                            let n = tree.node(nm);
                            let name = f.src[n.start as usize..n.end as usize].to_vec();
                            if pystr::eq(&name, "_") && !constant {
                                // (`var _ = f()`: no name, but the initializer runs)
                                continue;
                            }
                            pk.globals.insert(name, Global { file: fi16, spec, index: index as u32, values, iota: if constant { iota as i64 } else { -1 }, embed });
                        }
                    }
                }
                _ => {}
            }
        }
        for h in &gofiles[fi].hooks {
            if h.kind == HookKind::VarInit {
                var_init.push((f.pkg, fi16, h.node));
            }
        }
    }
    let module_ref = Module { files: frefs, pkgs, by_path, b64_fns };
    let k = &module_ref;
    answer.read = gofiles.iter().map(|g| g.index).collect();
    // the files' directives
    for (fi, g) in gofiles.iter().enumerate() {
        let src = k.files[fi].src;
        for h in &g.hooks {
            match h.kind {
                HookKind::Generate => answer.generate.push((g.index, line_of(src, h.start as usize), h.why.chars().map(|c| c as u32).collect())),
                HookKind::Linkname => answer.linkname.push((g.index, line_of(src, h.start as usize), h.why.chars().map(|c| c as u32).collect())),
                _ => {}
            }
        }
    }

    // ---- init: the package initializers, then the init functions, package by package, file by file
    let mut m = Model::new(k, p);
    m.max_steps = INIT_STEPS;
    let mut start_files: HashSet<usize> = HashSet::new();
    let mut init_globals: HashSet<(u32, PyStr)> = HashSet::new();
    let mut roots: Vec<(u16, NodeId)> = Vec::new();
    let mut order: Vec<usize> = (0..k.files.len()).collect();
    order.sort_by(|&a, &b| (k.files[a].pkg, &k.files[a].path).cmp(&(k.files[b].pkg, &k.files[b].path)));
    for &(pkg, file, spec) in &var_init {
        let tree = &k.files[file as usize].tree;
        for &nm in tree.items(tree.node(spec).f[0]) {
            let n = tree.node(nm);
            init_globals.insert((pkg, k.files[file as usize].src[n.start as usize..n.end as usize].to_vec()));
        }
    }
    for &fi in &order {
        let pkg = k.files[fi].pkg;
        for &(p2, file, spec) in &var_init {
            if file as usize != fi || p2 != pkg {
                continue;
            }
            start_files.insert(fi);
            roots.push((file, spec));
            let tree = &k.files[fi].tree;
            let names: Vec<PyStr> = tree.items(tree.node(spec).f[0]).iter().map(|&nm| {
                let n = tree.node(nm);
                k.files[fi].src[n.start as usize..n.end as usize].to_vec()
            }).collect();
            if names.iter().all(|n| pystr::eq(n, "_")) {
                // `var _ = f()`: read the initializer itself
                m.run_spec(file, spec);
            }
            for n in names {
                m.run_global(pkg, &n);
            }
        }
    }
    for &fi in &order {
        for h in &gofiles[fi].hooks {
            if h.kind == HookKind::InitFn {
                start_files.insert(fi);
                roots.push((fi as u16, h.node));
                m.run_func(fi as u16, h.node);
            }
        }
    }
    m.flush_cmds();
    let mut cut_files: HashSet<usize> = HashSet::new();
    if m.cut {
        cut_files.extend(start_files.iter().copied());
    }
    // what they call by name, however deep, read on its own
    let rest = called_by_name(k, &roots);
    read_rest(&mut m, &rest, REST_STEPS_PER_ROOT, REST_STEPS, &mut cut_files);
    let owned: HashSet<(u16, NodeId)> = m.reached.clone();
    // ---- cgo: the C a package compiles in, at start (a constructor, or init code that calls C) or when used
    let mut c_start: Vec<events::Ev> = Vec::new();
    let mut c_use: Vec<events::Ev> = Vec::new();
    let mut preamble_at_start: HashMap<usize, (usize, usize)> = HashMap::new();
    let mut preamble_at_use: HashMap<usize, (usize, usize)> = HashMap::new();
    let mut cgo_dirs: HashSet<PyStr> = HashSet::new();
    for (fi, g) in gofiles.iter().enumerate() {
        for h in &g.hooks {
            if h.kind != HookKind::Cgo {
                continue;
            }
            cgo_dirs.insert(dir_of(&k.files[fi].path));
            let src = k.files[fi].src;
            let view = cread::preamble_view(src, &g.comments, h.start as usize, h.end as usize);
            let r = cread::read_c(&view, h.start as usize, h.end as usize, fi as u16);
            if r.constructor || m.calls_c {
                c_start.extend(r.events);
                preamble_at_start.insert(fi, (h.start as usize, h.end as usize));
                start_files.insert(fi);
            } else {
                c_use.extend(r.events);
                preamble_at_use.insert(fi, (h.start as usize, h.end as usize));
            }
        }
    }
    // a cgo package's C files (each its own file index, after the Go files')
    let mut c_texts: Vec<(usize, &[u32], bool)> = Vec::new();
    for &ci in &cfiles {
        if !cgo_dirs.contains(&dir_of(&paths[ci])) {
            continue;
        }
        let src = files[ci].1;
        let slot = (k.files.len() + c_texts.len()).min(u16::MAX as usize - 1) as u16;
        let r = cread::read_c(src, 0, src.len(), slot);
        let at_start = r.constructor || m.calls_c;
        if at_start {
            c_start.extend(r.events);
        } else {
            c_use.extend(r.events);
        }
        c_texts.push((ci, src, at_start));
        answer.read.push(ci);
    }
    for e in c_start {
        m.ev(e);
    }

    // ---- the import-time test: each file's events and the text of its init code
    let mut by_file: HashMap<usize, Vec<usize>> = HashMap::new();
    for (e, ev) in m.events.iter().enumerate() {
        by_file.entry(events::ev_file(ev) as usize).or_default().push(e);
    }
    let mut files_at_start: Vec<usize> = by_file.keys().copied().chain(start_files.iter().copied()).chain(owned.iter().map(|&(f, _)| f as usize)).collect();
    files_at_start.sort_unstable();
    files_at_start.dedup();
    for fi in files_at_start {
        let evs: Vec<events::Ev> = by_file.get(&fi).map(|v| v.iter().map(|&e| m.events[e].clone()).collect()).unwrap_or_default();
        if fi < k.files.len() {
            let keep: HashSet<NodeId> = owned.iter().filter(|(f, _)| *f as usize == fi).map(|(_, d)| *d).collect();
            let text = go_view(k, fi, &gofiles[fi].comments, &|d| keep.contains(&d), None, preamble_at_start.get(&fi).copied());
            if let Some(found) = finding(p, k.files[fi].src, &text, &evs, fi, gofiles[fi].index, cut_files.contains(&fi)) {
                answer.start.push(found);
            }
        } else if let Some(&(ci, src, true)) = c_texts.get(fi - k.files.len()) {
            if let Some(found) = finding(p, src, src, &evs, fi, ci, false) {
                answer.start.push(found);
            }
        }
    }

    // ---- the rest, when used
    let (uses, read) = use_findings(p, k, &gofiles, &owned, &init_globals, &var_init, c_use, &c_texts, &preamble_at_use, opts);
    answer.uses = uses;
    answer.use_read = read;
    answer.read.sort_unstable();
    answer.start.sort_by_key(|f| f.file);
    answer
}

impl<'k, 'a> Model<'k, 'a> {
    /// Reads a package-level ValueSpec's initializer whose names are all `_` (`var _ = f()`): it runs all the same.
    fn run_spec(&mut self, file: u16, spec: NodeId) {
        self.eval_spec_values(file, spec);
    }
}

/// The functions `roots` (function declarations, or package-level ValueSpecs) reach by name, however deep: a call's
/// name (a function of the package, of one of the module's packages it imports, or a method of the package) and a
/// function named as a value (`go worker()`, `http.HandleFunc("/", h)`).
fn called_by_name(k: &Module, roots: &[(u16, NodeId)]) -> Vec<(u16, NodeId)> {
    let mut seen: HashSet<(u16, NodeId)> = roots.iter().copied().collect();
    let mut queue: Vec<(u16, NodeId)> = roots.to_vec();
    let mut out: Vec<(u16, NodeId)> = Vec::new();
    let mut kids: Vec<u32> = Vec::new();
    while let Some((fi, root)) = queue.pop() {
        let f = &k.files[fi as usize];
        let pkg = &k.pkgs[f.pkg as usize];
        let tree = &f.tree;
        let r = tree.node(root);
        let start = if r.kind == K::FuncDecl { r.f[3] } else { root };
        if start == NONE {
            continue;
        }
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            let n = tree.node(id);
            let mut found: Vec<(u16, NodeId)> = Vec::new();
            match n.kind {
                K::Ident => {
                    let name = &f.src[n.start as usize..n.end as usize];
                    if let Some(c) = pkg.funcs.get(name) {
                        found.extend(c.iter().copied());
                    }
                }
                K::SelectorExpr => {
                    let x = tree.node(n.f[0]);
                    let sel = tree.node(n.f[1]);
                    let sname = &f.src[sel.start as usize..sel.end as usize];
                    if x.kind == K::Ident {
                        let xname = &f.src[x.start as usize..x.end as usize];
                        if let Some(&p2) = f.imports.get(xname).and_then(|path| k.by_path.get(path)) {
                            if let Some(c) = k.pkgs[p2 as usize].funcs.get(sname) {
                                found.extend(c.iter().copied());
                            }
                        }
                    }
                    if !eval::is_std_method_pub(&pystr::to_string(sname)) {
                        if let Some(c) = pkg.methods.get(sname) {
                            found.extend(c.iter().copied().take(4));
                        }
                    }
                }
                _ => {}
            }
            for x in found {
                if seen.insert(x) {
                    out.push(x);
                    queue.push(x);
                }
            }
            kids.clear();
            tree.each_child(id, &mut |x| kids.push(x));
            stack.extend(kids.iter().rev());
        }
    }
    out.sort_unstable();
    out
}

/// Reads each of `roots` the reading has not reached as a root of its own, each with `per_root` steps and all with
/// `total`; the files of a root cut short, or not read for want of steps, are added to `cut_files`.
fn read_rest(m: &mut Model, roots: &[(u16, NodeId)], per_root: u64, total: u64, cut_files: &mut HashSet<usize>) {
    let start = m.steps_used();
    for &(f, d) in roots {
        if m.reached.contains(&(f, d)) {
            continue;
        }
        if m.steps_used().saturating_sub(start) >= total {
            cut_files.insert(f as usize);
            continue;
        }
        m.cut = false;
        m.max_steps = m.steps_used() + per_root;
        m.run_func(f, d);
        m.flush_cmds();
        if m.cut {
            cut_files.insert(f as usize);
        }
    }
}

/// The text a moment's test reads of a Go file: its code with comments blanked (but the cgo preamble `preamble`,
/// when it is this moment's), and the function declarations `keep` refuses blanked, and the spans `drop` names;
/// line breaks kept, so offsets and lines are the file's.
fn go_view(k: &Module, fi: usize, comments: &[(usize, usize)], keep: &dyn Fn(NodeId) -> bool, drop: Option<&[(usize, usize)]>, preamble: Option<(usize, usize)>) -> PyStr {
    let f = &k.files[fi];
    let mut spans: Vec<(usize, usize)> = comments.iter().copied().filter(|&(s, e)| !preamble.is_some_and(|(ps, pe)| s >= ps && e <= pe)).collect();
    let tree = &f.tree;
    for &decl in tree.items(tree.node(tree.root).f[1]) {
        let d = tree.node(decl);
        if d.kind == K::FuncDecl && !keep(decl) {
            spans.push((d.start as usize, d.end as usize));
        }
    }
    if let Some(dr) = drop {
        spans.extend(dr.iter().copied());
    }
    spans.sort_unstable();
    crate::signs::blank(f.src, &spans)
}

/// The import-time test's finding for a file: its events and its text (and, for a reading cut short, the text
/// test's). `fi` is the file's place among the reading's, `index` among the files given.
fn finding(p: &Pack, src: &[u32], text: &[u32], evs: &[events::Ev], fi: usize, index: usize, cut: bool) -> Option<Found> {
    let fx = facts::facts(p, src, evs, fi);
    let _gate = crate::textgate::open(text);
    let (mut reasons, mut line) = crate::signs::import_time_risk_model(p, text, &fx.facts);
    if cut {
        let (more, at) = crate::signs::import_time_risk(p, text, None);
        for r in more {
            if !reasons.contains(&r) {
                reasons.push(r);
                line = line.or(at);
            }
        }
    }
    if reasons.is_empty() {
        return None;
    }
    Some(Found { file: index, reasons, line: line.or(fx.first_line).unwrap_or(1) })
}

/// The packages and names whose calls reach outside the program: a process, the network, a file written, a library
/// loaded.
fn sink_call(path: &str, name: &str) -> bool {
    match path {
        "os/exec" | "net" | "net/http" | "crypto/tls" | "plugin" | "golang.org/x/sys/windows" | "syscall" | "golang.org/x/sys/unix" | "C" => true,
        "os" => matches!(name, "WriteFile" | "Create" | "OpenFile" | "StartProcess" | "CreateTemp" | "Rename"),
        "io/ioutil" => matches!(name, "WriteFile" | "TempFile"),
        _ => false,
    }
}

/// Does a function's body call something that reaches outside the program?
fn has_sink(f: &FileRef, decl: NodeId) -> bool {
    let tree = &f.tree;
    let d = tree.node(decl);
    if d.f[3] == NONE {
        return false;
    }
    let mut stack = vec![d.f[3]];
    let mut kids: Vec<u32> = Vec::new();
    while let Some(id) = stack.pop() {
        let n = tree.node(id);
        if n.kind == K::CallExpr {
            let fun = tree.node(n.f[0]);
            if fun.kind == K::SelectorExpr {
                let x = tree.node(fun.f[0]);
                if x.kind == K::Ident {
                    let xname = &f.src[x.start as usize..x.end as usize];
                    let sel = tree.node(fun.f[1]);
                    let sname = pystr::to_string(&f.src[sel.start as usize..sel.end as usize]);
                    let path = if pystr::eq(xname, "C") { Some(u("C")) } else { f.imports.get(xname).cloned() };
                    if let Some(path) = path {
                        if sink_call(&pystr::to_string(&path), &sname) {
                            return true;
                        }
                    }
                }
            }
        }
        kids.clear();
        tree.each_child(id, &mut |x| kids.push(x));
        stack.extend(kids.iter().rev());
    }
    false
}

/// SC-USE-RISK's reading: every function the init reading did not reach that holds a sink, the functions that call
/// one of those, and a command's `main`, each read alone (its parameters not known), a few calls deep; then each
/// file, with what its functions do, by the import-time test.
#[allow(clippy::too_many_arguments)]
fn use_findings(
    p: &Pack,
    k: &Module,
    gofiles: &[GoFile],
    owned: &HashSet<(u16, NodeId)>,
    init_globals: &HashSet<(u32, PyStr)>,
    var_init: &[(u32, u16, NodeId)],
    c_use: Vec<events::Ev>,
    c_texts: &[(usize, &[u32], bool)],
    preamble_at_use: &HashMap<usize, (usize, usize)>,
    opts: &Options,
) -> (Vec<Found>, UseRead) {
    let mut sink_fns: HashSet<(u16, NodeId)> = HashSet::new();
    let mut sink_names: HashSet<PyStr> = HashSet::new();
    let mut decls: Vec<(u16, NodeId)> = Vec::new();
    for (fi, f) in k.files.iter().enumerate() {
        let tree = &f.tree;
        for &decl in tree.items(tree.node(tree.root).f[1]) {
            let d = tree.node(decl);
            if d.kind != K::FuncDecl || owned.contains(&(fi as u16, decl)) {
                continue;
            }
            decls.push((fi as u16, decl));
            if has_sink(f, decl) {
                sink_fns.insert((fi as u16, decl));
                if d.f[1] != NONE {
                    let n = tree.node(d.f[1]);
                    sink_names.insert(f.src[n.start as usize..n.end as usize].to_vec());
                }
            }
        }
    }
    let mut roots: Vec<(u16, NodeId)> = sink_fns.iter().copied().collect();
    for &(fi, decl) in &decls {
        if sink_fns.contains(&(fi, decl)) {
            continue;
        }
        let f = &k.files[fi as usize];
        let tree = &f.tree;
        let d = tree.node(decl);
        // a command's main
        let is_main = d.f[0] == NONE && d.f[1] != NONE && pystr::eq(&f.src[tree.node(d.f[1]).start as usize..tree.node(d.f[1]).end as usize], "main") && pystr::eq(&gofiles[fi as usize].name, "main");
        let mut calls = is_main;
        if !calls && d.f[3] != NONE {
            let mut stack = vec![d.f[3]];
            let mut kids: Vec<u32> = Vec::new();
            while let Some(id) = stack.pop() {
                let n = tree.node(id);
                if n.kind == K::Ident && sink_names.contains(&f.src[n.start as usize..n.end as usize].to_vec()) {
                    calls = true;
                    break;
                }
                kids.clear();
                tree.each_child(id, &mut |x| kids.push(x));
                stack.extend(kids.iter().rev());
            }
        }
        if calls {
            roots.push((fi, decl));
        }
    }
    roots.sort_unstable();
    let mut m = Model::new(k, p);
    m.max_depth = 4;
    m.not_follow = owned.clone();
    m.no_init = init_globals.clone();
    let mut cut_files: HashSet<usize> = HashSet::new();
    let mut total = 0u64;
    for (f, d) in roots {
        if total >= USE_STEPS {
            cut_files.insert(f as usize);
            continue;
        }
        let before = m.steps_used();
        m.max_steps = before + USE_STEPS_PER_ROOT;
        m.cut = false;
        m.run_func(f, d);
        m.flush_cmds();
        if m.cut {
            cut_files.insert(f as usize);
        }
        total += m.steps_used() - before;
    }
    for e in c_use {
        m.ev(e);
    }
    let mut by_file: HashMap<usize, Vec<usize>> = HashMap::new();
    for (e, ev) in m.events.iter().enumerate() {
        by_file.entry(events::ev_file(ev) as usize).or_default().push(e);
    }
    // every Go file, and the C files read when used, smallest first, within the bounds
    let mut files: Vec<usize> = (0..k.files.len()).collect();
    for (j, c) in c_texts.iter().enumerate() {
        if !c.2 {
            files.push(k.files.len() + j);
        }
    }
    let size = |fi: usize| if fi < k.files.len() { k.files[fi].src.len() } else { c_texts[fi - k.files.len()].1.len() };
    files.sort_by_key(|&fi| (size(fi), fi));
    let mut read = UseRead { of_files: files.len(), of_chars: files.iter().map(|&fi| size(fi)).sum(), ..UseRead::default() };
    let mut room = opts.use_chars;
    let mut out = Vec::new();
    // (the init code's initializers: theirs, not the use-time test's)
    let mut init_spans: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    for &(_, file, spec) in var_init {
        let tree = &k.files[file as usize].tree;
        let s = tree.node(spec);
        init_spans.entry(file as usize).or_default().push((s.start as usize, s.end as usize));
    }
    for fi in files {
        let n = size(fi);
        if n > opts.use_file_chars.min(room) {
            break; // (sizes only grow from here)
        }
        room -= n;
        read.files += 1;
        read.chars += n;
        let evs: Vec<events::Ev> = by_file.get(&fi).map(|v| v.iter().map(|&e| m.events[e].clone()).collect()).unwrap_or_default();
        let found = if fi < k.files.len() {
            let text = go_view(k, fi, &gofiles[fi].comments, &|d| !owned.contains(&(fi as u16, d)), init_spans.get(&fi).map(|v| v.as_slice()), preamble_at_use.get(&fi).copied());
            finding(p, k.files[fi].src, &text, &evs, fi, gofiles[fi].index, cut_files.contains(&fi))
        } else {
            let (ci, src, _) = c_texts[fi - k.files.len()];
            finding(p, src, src, &evs, fi, ci, false)
        };
        if let Some(found) = found {
            out.push(found);
        }
    }
    out.sort_by_key(|f| f.file);
    (out, read)
}
