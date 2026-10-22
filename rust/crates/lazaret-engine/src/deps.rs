//! --deps: what a dependency runs, and a project's own install hooks (BR-7 step 3 e, 0.1.9): the decisions, which
//! both packages made until then (core's dependency_checks and project_hook_checks and their helpers; the npm
//! package's deps.js). The packages read the tree.
//!
//! A call asks for what it needs to know of the tree, and the package answers (`Known`): whether a path is a regular
//! file of the tree it may read (`stat`: a file the walk read, else one on the disk under the scan root, through no
//! link and nothing an exclusion or the walk pruned), the text of a manifest the walk read (`manifest`), what a file
//! a hook runs does (`script`: the package reads it, the walk's source or manifest first, else the disk, keeps the
//! findings of reading it, and answers whether it came from the disk and the facts `script_facts` gives for its text),
//! the files a JavaScript source of the walk loads or starts (`targets`: `file_targets`' answer for its text), a
//! directory's entries (`list`) and the head of a file (`head`: at most so many bytes, decoded, and whether there is
//! more). What a call still needs comes back as `need`, and the package calls again with those answers too. The
//! engine keeps nothing between calls: each works from the start with all it was told, and asks for everything the
//! steps it could take need at once, so a call takes a few rounds, not one a file. The texts go to the engine once
//! each, to `script_facts` and `file_targets`; the decisions are made on what those answered.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::budget;
use crate::findings::{format, py_repr, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::manifest::{self, pyval::PyVal};
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

fn u(s: &str) -> PyStr {
    pystr::u(s)
}

fn arr(v: Option<&Value>) -> &[Value] {
    v.and_then(|x| x.as_arr()).unwrap_or(&[])
}

fn obj(v: Option<&Value>) -> &[(Vec<u32>, Value)] {
    v.and_then(|x| x.as_obj()).unwrap_or(&[])
}

fn text_of(v: &Value) -> Option<PyStr> {
    v.as_str().map(|s| s.to_vec())
}

fn strs_of(v: Option<&Value>) -> Vec<PyStr> {
    arr(v).iter().filter_map(text_of).collect()
}

fn pairs_of(v: Option<&Value>) -> Vec<(PyStr, PyStr)> {
    arr(v)
        .iter()
        .filter_map(|x| {
            let a = x.as_arr()?;
            Some((text_of(a.first()?)?, text_of(a.get(1)?)?))
        })
        .collect()
}

fn strs(v: &[PyStr]) -> Value {
    Value::Arr(v.iter().map(|s| Value::Str(s.clone())).collect())
}

/// Run `f` with a work budget of its own (DEFAULT_STEPS), as each of the packages' engine calls had.
fn own<T>(f: impl FnOnce() -> T) -> Result<T, Stop> {
    budget::isolated(budget::DEFAULT_STEPS, f).map_err(|_| Stop::Exhausted)
}

/// The options of a call: snippets and messages redacted, the entropy sum.
#[derive(Clone, Copy)]
pub struct Opts {
    pub redact: bool,
    pub neumaier: bool,
}

// ---------------- what a file a hook runs does (deps_script) ----------------

/// script_facts' answer for a file a hook runs, as the package hands it back; None: a check that spent its budget.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    risk: Option<Vec<PyStr>>,
    agent: Option<Option<Value>>,
    obfuscated: Option<bool>,
    spawned: Option<Vec<(PyStr, PyStr)>>,
}

impl Facts {
    pub fn from_value(v: &Value) -> Facts {
        let gone: Vec<PyStr> = strs_of(v.get("exhausted"));
        let ok = |k: &str| !gone.iter().any(|g| pystr::eq(g, k));
        Facts {
            risk: ok("risk").then(|| strs_of(v.get("risk"))),
            agent: ok("agent").then(|| v.get("agent").filter(|a| !matches!(a, Value::Null)).cloned()),
            obfuscated: ok("obfuscated").then(|| matches!(v.get("obfuscated"), Some(Value::Bool(true)))),
            spawned: ok("spawned").then(|| pairs_of(v.get("spawned"))),
        }
    }

    fn risk(&self) -> R<&[PyStr]> {
        self.risk.as_deref().ok_or(Stop::Exhausted)
    }

    fn agent(&self) -> R<Option<&Value>> {
        self.agent.as_ref().map(|a| a.as_ref()).ok_or(Stop::Exhausted)
    }

    fn obfuscated(&self) -> R<bool> {
        self.obfuscated.ok_or(Stop::Exhausted)
    }

    fn spawned(&self) -> R<&[(PyStr, PyStr)]> {
        self.spawned.as_deref().ok_or(Stop::Exhausted)
    }
}

/// engine.script_lang: the language the tests read a script a hook (or an editor's or agent's settings, an agent
/// doc) runs in, its comments blanked in it: by its extension (_SCRIPT_LANG_EXTS: "js" for .js, .mjs, .cjs, .jsx,
/// .ts…; "py" for .py, .pyw; None for a shell script, .sh, .bash, .zsh…; "bat" for a batch file, .cmd, .bat; "other"
/// for another language's, .ps1, .pl, .rb, .vbs…, whose comments are not blanked); a file with no such extension, by
/// its `#!` line ("js" for node and the other JavaScript runtimes, "py", None for a shell, "other" for any other
/// program); else "js", what node runs (`node install`).
pub fn script_lang(p: &Pack, path: &[u32], text: &[u32]) -> Option<&'static str> {
    let base = basename(path);
    if let Some(k) = base.iter().rposition(|&x| x == '.' as u32).filter(|&k| k > 0) {
        let ext = pystr::lower(&base[k..]);
        for (kind, exts) in p.map_strs("_SCRIPT_LANG_EXTS") {
            if exts.contains(&ext) {
                return match pystr::to_string(kind).as_str() {
                    "js" => Some("js"),
                    "py" => Some("py"),
                    "sh" => None,
                    "bat" => Some("bat"),
                    _ => Some("other"),
                };
            }
        }
    }
    if pystr::starts_with(text, "#!") {
        return match crate::hooks::shebang_lang(p, text) {
            Some("js") => Some("js"),
            Some("py") => Some("py"),
            Some("sh") => None,
            _ => Some("other"),
        };
    }
    Some("js")
}

/// `deps_script`: what the file `rel` ('/'-separated) a hook runs does, its text `text` (the walk's, or as the package
/// read it): {"risk": the install-script test's reasons, "spawned": the scripts it starts ([where, path]), and for a
/// dependency's hook "agent", its SC-AGENT-HIJACK issue or null, for a project's "obfuscated"}; "exhausted": the
/// checks that spent their budget (each has its own, as each was a call of its own). `release`: the name of the
/// package whose hook runs it, when known (D-9c: a rewrite of its own code is its own). Null for an empty text:
/// nothing reads it.
pub fn script_facts(p: &Pack, rel: &[u32], text: &[u32], project: bool, release: Option<&[u32]>, o: &Opts) -> Value {
    if text.is_empty() {
        return Value::Null;
    }
    let lang = script_lang(p, rel, text);
    // (a TypeScript file a hook runs, `tsx install.ts`, is read in its dialect: TS-STRIP)
    let _read = crate::jsflow::supply::read_as(crate::jsflow::supply::Dialect::of_path(rel));
    let mut out: Vec<(&str, Value)> = Vec::new();
    let mut gone: Vec<Value> = Vec::new();
    let risk = own(|| {
        let _named = release.map(crate::signs::own_release);
        crate::signs::install_script_risk(p, text, lang)
    });
    match risk {
        Ok(r) => out.push(("risk", strs(&r))),
        Err(_) => gone.push(Value::str("risk")),
    }
    if project {
        match own(|| crate::autorun::is_obfuscated(p, text)) {
            Ok(b) => out.push(("obfuscated", Value::Bool(b))),
            Err(_) => gone.push(Value::str("obfuscated")),
        }
    } else {
        match own(|| dependency_agent_issue(p, text, o)) {
            Ok(a) => out.push(("agent", a.unwrap_or(Value::Null))),
            Err(_) => gone.push(Value::str("agent")),
        }
    }
    match own(|| crate::signs::spawned_scripts(p, text, lang)) {
        Ok(s) => out.push((
            "spawned",
            Value::Arr(s.into_iter().map(|(w, path)| Value::Arr(vec![Value::str(w), Value::Str(path)])).collect()),
        )),
        Err(_) => gone.push(Value::str("spawned")),
    }
    out.push(("exhausted", Value::Arr(gone)));
    Value::obj(out)
}

// ---------------- what a JavaScript source loads or starts (deps_targets) ----------------

/// `deps_targets`: the local files a dependency's JavaScript text requires or imports (["dir", path]: from its own
/// folder) and the scripts it starts with node (spawned_scripts: [where, path]), for the reach of its npm package's
/// entry points (core._deps_npm_reach); {"targets": […], "exhausted": true} when spawned_scripts spent its budget.
pub fn file_targets(p: &Pack, text: &[u32]) -> Value {
    let mut out: Vec<Value> = p
        .re("_DEPS_LOCAL_DEP_RE")
        .finditer(text)
        .filter_map(|m| m.group(2).map(|t| Value::Arr(vec![Value::str("dir"), Value::Str(t.to_vec())])))
        .collect();
    let spawned = own(|| crate::signs::spawned_scripts(p, text, Some("js")));
    if let Ok(s) = &spawned {
        out.extend(s.iter().map(|(w, path)| Value::Arr(vec![Value::str(w), Value::Str(path.clone())])));
    }
    Value::obj(vec![("targets", Value::Arr(out)), ("exhausted", Value::Bool(spawned.is_err()))])
}

/// The answer to `targets`: not a JavaScript source of the walk, the targets, or none known (a check spent its budget).
#[derive(Clone, Debug)]
enum Targets {
    NotSource,
    Found(Vec<(PyStr, PyStr)>),
    Unknown,
}

// ---------------- what the package told, and what the call still needs ----------------

#[derive(Default, Debug)]
pub struct Known {
    stat: HashMap<PyStr, bool>,
    manifest: HashMap<PyStr, Option<PyStr>>,
    script: HashMap<(PyStr, Option<PyStr>), (bool, Option<Facts>)>,
    targets: HashMap<PyStr, Targets>,
    list: HashMap<PyStr, Option<Vec<(PyStr, bool)>>>,
    head: HashMap<(PyStr, i64), Option<(PyStr, bool)>>,
    under: HashMap<PyStr, HashSet<PyStr>>,
}

impl Known {
    /// From a call's "known": {"stat": {rel: bool}, "manifest": {rel: text or null}, "script": [[rel, the release's
    /// name or null, from the disk, script_facts' answer]…], "targets": {rel: file_targets' answer or null}, "list": {dir: [[name, a real
    /// directory]…] or null}, "head": [[path, cap, [text, more] or null]…], "under": {dir: [rel…]}: every path below
    /// `dir` `stat` would answer true for, the walk's files first (so a `stat` of a path below it is answered there)}.
    pub fn from_value(v: Option<&Value>) -> Known {
        let mut k = Known::default();
        let Some(v) = v else { return k };
        for (rel, x) in obj(v.get("stat")) {
            k.stat.insert(rel.clone(), matches!(x, Value::Bool(true)));
        }
        for (rel, x) in obj(v.get("manifest")) {
            k.manifest.insert(rel.clone(), text_of(x));
        }
        for x in arr(v.get("script")) {
            let a = x.as_arr().unwrap_or(&[]);
            let Some(rel) = a.first().and_then(text_of) else { continue };
            let release = a.get(1).and_then(text_of);
            let disk = matches!(a.get(2), Some(Value::Bool(true)));
            let facts = a.get(3).filter(|f| matches!(f, Value::Obj(_))).map(Facts::from_value);
            k.script.insert((rel, release), (disk, facts));
        }
        for (rel, x) in obj(v.get("targets")) {
            let t = match x {
                Value::Obj(_) if matches!(x.get("exhausted"), Some(Value::Bool(true))) => Targets::Unknown,
                Value::Obj(_) => Targets::Found(pairs_of(x.get("targets"))),
                _ => Targets::NotSource,
            };
            k.targets.insert(rel.clone(), t);
        }
        for (dir, x) in obj(v.get("list")) {
            let got = x.as_arr().map(|a| {
                a.iter()
                    .filter_map(|e| {
                        let e = e.as_arr()?;
                        Some((text_of(e.first()?)?, matches!(e.get(1), Some(Value::Bool(true)))))
                    })
                    .collect()
            });
            k.list.insert(dir.clone(), got);
        }
        for it in arr(v.get("head")) {
            let a = it.as_arr().unwrap_or(&[]);
            let (Some(path), Some(cap)) = (a.first().and_then(text_of), a.get(1).and_then(|c| c.as_i64())) else { continue };
            let got = a.get(2).and_then(|x| x.as_arr()).and_then(|h| {
                Some((text_of(h.first()?)?, matches!(h.get(1), Some(Value::Bool(true)))))
            });
            k.head.insert((path, cap), got);
        }
        for (dir, x) in obj(v.get("under")) {
            k.under.insert(dir.clone(), strs_of(Some(x)).into_iter().collect());
        }
        k
    }
}

/// What a call still needs to know, each once, in the order it asked.
#[derive(Default, Debug)]
pub struct Need {
    stat: Vec<PyStr>,
    manifest: Vec<PyStr>,
    script: Vec<(PyStr, Option<PyStr>)>,
    targets: Vec<PyStr>,
    list: Vec<PyStr>,
    head: Vec<(PyStr, i64)>,
    under: Vec<PyStr>,
    seen: HashSet<(u8, PyStr, i64)>,
    seen_script: HashSet<(PyStr, Option<PyStr>)>,
}

impl Need {
    fn add(&mut self, kind: u8, key: &[u32], cap: i64) -> bool {
        self.seen.insert((kind, key.to_vec(), cap))
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty() && self.seen_script.is_empty()
    }

    /// {"stat": [rel…], "manifest": [rel…], "script": [[rel, the release's name or null]…], "targets": [rel…], "list": [dir…], "head": [[path,
    /// cap]…], "under": [dir…]}
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("stat", strs(&self.stat)),
            ("manifest", strs(&self.manifest)),
            (
                "script",
                Value::Arr(
                    self.script
                        .iter()
                        .map(|(r, o)| Value::Arr(vec![Value::Str(r.clone()), o.clone().map(Value::Str).unwrap_or(Value::Null)]))
                        .collect(),
                ),
            ),
            ("targets", strs(&self.targets)),
            ("list", strs(&self.list)),
            ("head", Value::Arr(self.head.iter().map(|(p, c)| Value::Arr(vec![Value::Str(p.clone()), Value::Int(*c)])).collect())),
            ("under", strs(&self.under)),
        ])
    }
}

/// Something the call has not been told yet (it is asked for: the need is recorded).
#[derive(Debug, Clone, Copy)]
pub struct Missing;

/// A step that could not finish: something it needs is not known yet, or a check spent its work budget.
#[derive(Debug, Clone, Copy)]
pub enum Stop {
    Missing,
    Exhausted,
}

impl From<Missing> for Stop {
    fn from(_: Missing) -> Stop {
        Stop::Missing
    }
}

type R<T> = Result<T, Stop>;

/// The tree as the package told it, and what this call still needs.
pub struct Tree<'k> {
    known: &'k Known,
    pub need: Need,
}

impl<'k> Tree<'k> {
    pub fn new(known: &'k Known) -> Tree<'k> {
        Tree { known, need: Need::default() }
    }

    /// Is `rel` a regular file of the tree (core._DependencyTree.is_file)?
    fn stat(&mut self, rel: &[u32]) -> Result<bool, Missing> {
        if let Some(&b) = self.known.stat.get(rel) {
            return Ok(b);
        }
        if !self.known.under.is_empty() {
            for (k, &c) in rel.iter().enumerate() {
                if c == '/' as u32 {
                    if let Some(files) = self.known.under.get(&rel[..k]) {
                        return Ok(files.contains(rel));
                    }
                }
            }
        }
        if self.need.add(0, rel, 0) {
            self.need.stat.push(rel.to_vec());
        }
        Err(Missing)
    }

    /// A manifest the walk read: its text, or None.
    fn manifest(&mut self, rel: &[u32]) -> Result<Option<PyStr>, Missing> {
        if let Some(v) = self.known.manifest.get(rel) {
            return Ok(v.clone());
        }
        if self.need.add(1, rel, 0) {
            self.need.manifest.push(rel.to_vec());
        }
        Err(Missing)
    }

    /// A file a hook of the package named `release` runs: (it was read from the disk, its facts; None: it can't be
    /// read as text, or is empty).
    fn script(&mut self, rel: &[u32], release: &Option<PyStr>) -> Result<(bool, Option<Facts>), Missing> {
        let key = (rel.to_vec(), release.clone());
        if let Some((disk, facts)) = self.known.script.get(&key) {
            return Ok((*disk, facts.clone()));
        }
        if self.need.seen_script.insert(key.clone()) {
            self.need.script.push(key);
        }
        Err(Missing)
    }

    /// What a JavaScript source of the walk loads or starts.
    fn targets(&mut self, rel: &[u32]) -> Result<Targets, Missing> {
        if let Some(t) = self.known.targets.get(rel) {
            return Ok(t.clone());
        }
        if self.need.add(3, rel, 0) {
            self.need.targets.push(rel.to_vec());
        }
        Err(Missing)
    }

    /// A directory's entries ([(name, a real directory)]), or None when it can't be listed.
    fn list(&mut self, dir: &[u32]) -> Result<Option<Vec<(PyStr, bool)>>, Missing> {
        if let Some(v) = self.known.list.get(dir) {
            return Ok(v.clone());
        }
        if self.need.add(4, dir, 0) {
            self.need.list.push(dir.to_vec());
        }
        Err(Missing)
    }

    /// Every file below `dir` (`stat` answers there after).
    fn under(&mut self, dir: &[u32]) -> Result<(), Missing> {
        if self.known.under.contains_key(dir) {
            return Ok(());
        }
        if self.need.add(6, dir, 0) {
            self.need.under.push(dir.to_vec());
        }
        Err(Missing)
    }

    /// The first `cap` bytes of a regular file, decoded (UTF-8, errors replaced), and whether it has more; None when
    /// it can't be read (core._read_prefix's OSError).
    fn head(&mut self, path: &[u32], cap: i64) -> Result<Option<(PyStr, bool)>, Missing> {
        let key = (path.to_vec(), cap);
        if let Some(v) = self.known.head.get(&key) {
            return Ok(v.clone());
        }
        if self.need.add(5, path, cap) {
            self.need.head.push(key);
        }
        Err(Missing)
    }

    /// The first of `candidates` that is a regular file (all of them asked at once).
    fn first_file(&mut self, candidates: &[PyStr]) -> Result<Option<PyStr>, Missing> {
        let mut missing = false;
        for c in candidates {
            match self.stat(c) {
                Ok(true) => return if missing { Err(Missing) } else { Ok(Some(c.clone())) },
                Ok(false) => {}
                Err(Missing) => missing = true,
            }
        }
        if missing {
            Err(Missing)
        } else {
            Ok(None)
        }
    }

    /// The file Node runs for `path` (LOAD_AS_FILE, then LOAD_AS_DIRECTORY: its package.json "main", its index
    /// file), or None (core._DependencyTree.resolve).
    fn resolve(&mut self, p: &Pack, path: &[u32]) -> Result<Option<PyStr>, Missing> {
        let candidates = crate::hooks::node_candidates(path);
        let split = candidates.len().min(6);
        let dir = pystr::rstrip_chars(path, "/").to_vec();
        let mfile = join(&dir, "package.json");
        match self.first_file(&candidates[..split]) {
            Ok(Some(found)) => return Ok(Some(found)),
            Ok(None) => {}
            Err(Missing) => {
                // (what the rest may ask is asked with it)
                let _ = self.manifest(&mfile);
                for c in &candidates[split..] {
                    let _ = self.stat(c);
                }
                return Err(Missing);
            }
        }
        if let Some(text) = self.manifest(&mfile)? {
            let main = load(p, &mfile, &text).and_then(|d| d.get("main").and_then(|m| m.as_str()).map(|m| m.to_vec()));
            if let Some(main) = main.filter(|m| !pystr::strip(m).is_empty()) {
                if let Some(target) = tree_join(&dir, &main) {
                    if let Some(hit) = self.first_file(&crate::hooks::node_candidates(&target))? {
                        return Ok(Some(hit));
                    }
                }
            }
        }
        self.first_file(&candidates[split..])
    }
}

/// core._tree_join
pub fn tree_join(base: &[u32], target: &[u32]) -> Option<PyStr> {
    crate::autorun::tree_join(base, target)
}

/// posixpath.dirname
fn dirname(path: &[u32]) -> PyStr {
    manifest::dirname(path).to_vec()
}

/// posixpath.basename
fn basename(path: &[u32]) -> &[u32] {
    &path[path.iter().rposition(|&c| c == '/' as u32).map_or(0, |k| k + 1)..]
}

/// posixpath.join(base, name) for a plain name.
fn join(base: &[u32], name: &str) -> PyStr {
    if base.is_empty() {
        u(name)
    } else if base.last() == Some(&('/' as u32)) {
        pystr::concat(&[base, &u(name)])
    } else {
        pystr::concat(&[base, &u("/"), &u(name)])
    }
}

/// A manifest's data as core.load_manifest reads it, when it is a dict.
fn load(p: &Pack, path: &[u32], text: &[u32]) -> Option<PyVal> {
    manifest::load(p, path, text, false, None).0.filter(|d| matches!(d, PyVal::Dict(..)))
}

/// n with thousands separators (Python's f"{n:,}").
fn commas(n: i64) -> String {
    let s = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

fn joined(reasons: &[PyStr]) -> PyStr {
    pystr::join(&u("; and "), &reasons.iter().map(|r| r.as_slice()).collect::<Vec<_>>())
}

// ---------------- findings ----------------

/// The findings a follow adds, in order: an issue of the engine's (its file, '/'-separated, and the issue), or where
/// the findings of reading a file a hook runs go (the package read it, and keeps them).
#[derive(Clone, Debug)]
pub enum Out {
    Issue(PyStr, Value),
    Read(PyStr),
}

impl Out {
    pub fn to_value(&self) -> Value {
        match self {
            Out::Issue(file, issue) => Value::Arr(vec![Value::str("issue"), Value::Str(file.clone()), issue.clone()]),
            Out::Read(rel) => Value::Arr(vec![Value::str("read"), Value::Str(rel.clone())]),
        }
    }
}

/// A finding at `line` of the file whose text is `text`, made as mk_issue makes it with the file's _Redactor (its
/// entropy literals redacted too).
fn issue_at(p: &Pack, rule: RuleText, line: usize, text: &[u32], o: &Opts) -> Value {
    let snippets = Snippets::new(p, pystr::split_char(text, '\n' as u32), o.redact, o.neumaier);
    snippets.issue(&Finding::new(rule, line, None))
}

/// core._agent_hijack_issue: SC-AGENT-HIJACK (CRITICAL) at `line` of the file whose text is `text`.
fn agent_issue(p: &Pack, line: usize, text: &[u32], agent: &[u32], flag: &[u32], o: &Opts) -> Value {
    let mut r = RuleText::of(p, "_DEPS_AGENT_RULE");
    r.msg = format(&r.msg, &[("agent", Arg::S(py_repr(agent))), ("flag", Arg::S(flag.to_vec()))]);
    issue_at(p, r, line, text, o)
}

/// `agent_issue`: core._agent_hijack_issue for the registry's install hooks and files, the agent and flag found
/// (agent_hijack, agent_hijack_in_command) at `line` of the file whose text is `text`; `context`: with the file's
/// entropy literals redacted too (mk_issue with a _Redactor over its lines).
pub fn agent_issue_of(p: &Pack, text: &[u32], agent: &[u32], flag: &[u32], line: usize, context: bool, o: &Opts) -> Value {
    if context {
        return agent_issue(p, line, text, agent, flag, o);
    }
    let mut r = RuleText::of(p, "_DEPS_AGENT_RULE");
    r.msg = format(&r.msg, &[("agent", Arg::S(py_repr(agent))), ("flag", Arg::S(flag.to_vec()))]);
    let snippets = Snippets::new(p, pystr::split_char(text, '\n' as u32), o.redact, o.neumaier).plain();
    snippets.issue(&Finding::new(r, line, None))
}

/// core.dependency_agent_issue: SC-AGENT-HIJACK for a dependency's file that launches an AI agent in an autonomous
/// mode (agent_hijack), else None.
pub fn dependency_agent_issue(p: &Pack, text: &[u32], o: &Opts) -> Option<Value> {
    let (agent, flag, line) = crate::signs::agent_hijack(p, text)?;
    Some(agent_issue(p, line, text, &agent, &flag, o))
}

/// core.dependency_import_issue: SC-IMPORT-RISK (MAJOR, or CRITICAL: import_time_severity) for a dependency's
/// JavaScript or Python file that fails the import-time test, given the names of its package (`declared`: D-12b),
/// else None.
pub fn dependency_import_issue(
    p: &Pack,
    text: &[u32],
    lang: Option<&str>,
    declared: Option<&[PyStr]>,
    release: Option<&[u32]>,
    o: &Opts,
) -> Option<Value> {
    let (reasons, line) = {
        let _named = release.map(crate::signs::own_release);
        crate::signs::import_time_risk_with(p, text, lang, declared)
    };
    if reasons.is_empty() {
        return None;
    }
    let mut r = RuleText::of(p, "_DEPS_IMPORT_RULE");
    r.sev = u(crate::signs::import_time_severity(p, &reasons));
    r.msg = format(&r.msg, &[("reasons", Arg::S(joined(&reasons)))]);
    let mut issue = issue_at(p, r, line.unwrap_or(1), text, o);
    if line.is_none() {
        if let Value::Arr(items) = &mut issue {
            items[8] = Value::Null; // (mk_issue's line as it was given)
        }
    }
    Some(issue)
}

/// `dep_file_issues`: [SC-IMPORT-RISK or null, SC-AGENT-HIJACK or null] for a dependency's file no hook runs (core's
/// import-time and agent checks of dependency_checks), given its package's names (D-12b, D-9c). The agent check has a
/// budget of its own; when it runs out, the call answers as one that ran out (the file is SC-TRUNCATED, as it was).
pub fn dep_file_issues(p: &Pack, text: &[u32], lang: Option<&str>, declared: Option<&[PyStr]>, release: Option<&[u32]>, o: &Opts) -> Value {
    let found = dependency_import_issue(p, text, lang, declared, release, o);
    if budget::exhausted() {
        return Value::Null;
    }
    match budget::isolated(budget::DEFAULT_STEPS, || dependency_agent_issue(p, text, o)) {
        Ok(agent) => Value::Arr(vec![found.unwrap_or(Value::Null), agent.unwrap_or(Value::Null)]),
        Err(_) => {
            budget::exhaust();
            Value::Null
        }
    }
}

/// core._hook_not_followed_issue's SC-TRUNCATED.
fn hook_not_followed(p: &Pack) -> Value {
    let detail = format(
        &p.text("_DEPS_HOOK_NOT_FOLLOWED"),
        &[
            ("commands", Arg::S(u(&commas(p.int("HOOK_MAX_COMMANDS"))))),
            ("scripts", Arg::I(p.int("HOOK_MAX_TARGETS"))),
            ("chars", Arg::S(u(&commas(p.int("HOOK_MAX_CHARS"))))),
            ("path", Arg::S(u(&commas(p.int("HOOK_MAX_PATH"))))),
        ],
    );
    manifest::gyp::truncated_issue(p, &pystr::to_string(&detail))
}

/// engine.error_issue for a check that spent its budget: SC-TRUNCATED, EXHAUSTED.
fn exhausted_issue(p: &Pack) -> Value {
    manifest::gyp::truncated_issue(p, &p.string("EXHAUSTED"))
}

// ---------------- the follow of an install hook ----------------

/// An SC-INSTALL-HOOK finding to follow: its manifest ('/'-separated), line, severity and command; the follow may
/// make it CRITICAL with a message of its own.
#[derive(Clone, Debug)]
pub struct Hook {
    pub file: PyStr,
    pub line: usize,
    pub sev: PyStr,
    pub cmd: PyStr,
    pub msg: Option<PyStr>,
    /// a weaker reason (cert-off) of a file it runs named in `msg` already (escalate)
    pub weak_named: bool,
}

/// What a follow keeps across hooks: the files read for it, the files hooks run, the manifests already said to be
/// followed in part, and the findings.
#[derive(Default)]
pub struct Follow {
    read: HashSet<PyStr>,
    pub run: Vec<PyStr>,
    run_seen: HashSet<PyStr>,
    truncated: HashSet<PyStr>,
    pub out: Vec<Out>,
}

impl Follow {
    /// A file a hook runs (core's _dependency_script_text, _project_script_text): its facts, the reading's findings'
    /// place the first time the package read it from the disk.
    fn script(&mut self, tree: &mut Tree, rel: &[u32], release: &Option<PyStr>) -> Result<Option<Facts>, Missing> {
        if self.run_seen.insert(rel.to_vec()) {
            self.run.push(rel.to_vec());
        }
        let (disk, facts) = tree.script(rel, release)?;
        if disk && self.read.insert(rel.to_vec()) {
            self.out.push(Out::Read(rel.to_vec()));
        }
        Ok(facts)
    }
}

/// The SC-INSTALL-HOOK finding made CRITICAL with `msg`, unless it already is: the first strong reason found stands
/// (core._escalate_hook). RA-12: only a strong `reasons` makes it CRITICAL; a weaker one (cert-off) alone leaves the
/// hook MAJOR, its message then `msg` so the finding names the reason (the first such follow's, as the registry's
/// _follow_hooks does), and the follow goes on: a strong reason after it still makes it CRITICAL.
fn escalate(p: &Pack, hook: &mut Hook, msg: PyStr, reasons: &[PyStr], o: &Opts) -> R<()> {
    let strong = crate::signs::strong_install_reasons(p, reasons);
    let take = if strong {
        !pystr::eq(&hook.sev, "BLOCKER") && !pystr::eq(&hook.sev, "CRITICAL")
    } else {
        !reasons.is_empty() && pystr::eq(&hook.sev, "MAJOR") && !hook.weak_named
    };
    if take {
        let msg = if o.redact { own(|| crate::redact::redact_text(p, &msg, None))? } else { msg };
        if strong {
            hook.sev = u("CRITICAL");
        } else {
            hook.weak_named = true;
        }
        hook.msg = Some(msg);
    }
    Ok(())
}

fn runs_msg(p: &Pack, target: &[u32], reasons: &[PyStr]) -> PyStr {
    format(&p.text("_DEPS_HOOK_RUNS_MSG"), &[("target", Arg::S(target.to_vec())), ("reasons", Arg::S(joined(reasons)))])
}

fn starts_msg(p: &Pack, target: &[u32], started: &[u32], base: &[u32], reasons: &[PyStr]) -> PyStr {
    let shown = if !base.is_empty() && started.len() > base.len() && started.starts_with(base) && started[base.len()] == '/' as u32 {
        started[base.len() + 1..].to_vec()
    } else {
        started.to_vec()
    };
    format(
        &p.text("_DEPS_HOOK_STARTS_MSG"),
        &[("target", Arg::S(target.to_vec())), ("shown", Arg::S(shown)), ("reasons", Arg::S(joined(reasons)))],
    )
}

/// [(rel, facts)] of the scripts `rel` starts with node or python, and those they start (core._started_dependency_
/// scripts): at most _SPAWN_MAX_DEPTH starts deep and _SPAWN_MAX_FILES files; `cwd`: where a plain path is read from.
fn started_scripts(
    p: &Pack,
    tree: &mut Tree,
    f: &mut Follow,
    rel: &[u32],
    facts: Option<Facts>,
    cwd: &[u32],
    release: &Option<PyStr>,
) -> R<Vec<(PyStr, Option<Facts>)>> {
    let (max_depth, max_files) = (p.usize("_SPAWN_MAX_DEPTH"), p.usize("_SPAWN_MAX_FILES"));
    let mut found = Vec::new();
    let mut seen: HashSet<PyStr> = HashSet::from([rel.to_vec()]);
    let mut queue: VecDeque<(PyStr, Option<Facts>, usize)> = VecDeque::from([(rel.to_vec(), facts, 0)]);
    while seen.len() <= max_files {
        let Some((cur, cur_facts, depth)) = queue.pop_front() else { break };
        let Some(cf) = cur_facts else { continue };
        if depth >= max_depth {
            continue;
        }
        for (where_, path) in cf.spawned()? {
            let at = if pystr::eq(where_, "dir") { dirname(&cur) } else { cwd.to_vec() };
            let Some(joined) = tree_join(&at, path) else { continue };
            let Some(nxt) = tree.resolve(p, &joined)? else { continue };
            if seen.contains(&nxt) || seen.len() > max_files {
                continue;
            }
            seen.insert(nxt.clone());
            let nfacts = f.script(tree, &nxt, release)?;
            found.push((nxt.clone(), nfacts.clone()));
            queue.push_back((nxt, nfacts, depth + 1));
        }
    }
    Ok(found)
}

/// core._follow_dependency_hook: a dependency's hook followed to the files its command runs and the scripts they
/// start; CRITICAL (the first reason found) when the command itself plants something or one of them fails the
/// install-script test. Findings: an agent the command or a file it runs launches, a hook followed only in part.
fn follow_dependency(p: &Pack, tree: &mut Tree, f: &mut Follow, names: &mut InstalledNames, hook: &mut Hook, o: &Opts) -> R<()> {
    // (D-9c: the package's own name, for its install scripts)
    let release = names.of(p, tree, &hook.file)?.and_then(|n| n.1);
    let base = dirname(&hook.file);
    let cmd = hook.cmd.clone();
    if let Some((agent, flag)) = own(|| crate::signs::agent_hijack_in_command(p, &cmd))? {
        if let Some(text) = tree.manifest(&hook.file)? {
            let issue = own(|| agent_issue(p, hook.line, &text, &agent, &flag, o))?;
            f.out.push(Out::Issue(hook.file.clone(), issue));
        }
    }
    let persist = own(|| crate::signs::persistence_reasons(p, &cmd))?;
    if !persist.is_empty() {
        escalate(p, hook, format(&p.text("_DEPS_HOOK_COMMAND_MSG"), &[("reasons", Arg::S(joined(&persist)))]), &persist, o)?;
    }
    follow_targets(p, tree, f, hook, o, false, &base, &release)
}

/// core._follow_project_hook: a project's own hook followed to the files it runs and the scripts they start (read,
/// not scanned); CRITICAL when one of them fails the install-script test or is obfuscated.
fn follow_project(p: &Pack, tree: &mut Tree, f: &mut Follow, hook: &mut Hook, o: &Opts) -> R<()> {
    // (the manifest's "name": core._manifest_name)
    let release = match tree.manifest(&hook.file)? {
        Some(text) => load(p, &hook.file, &text)
            .and_then(|d| d.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty()).map(|n| n.to_vec())),
        None => None,
    };
    let base = dirname(&hook.file);
    follow_targets(p, tree, f, hook, o, true, &base, &release)
}

/// Why a file a hook runs looks hostile: the install-script test's reasons, and for a project's hook then "is
/// obfuscated" (core._project_script_risk).
fn reasons_of(p: &Pack, facts: &Facts, project: bool) -> R<Vec<PyStr>> {
    let mut reasons = facts.risk()?.to_vec();
    if project && facts.obfuscated()? {
        reasons.push(p.text("_DEPS_OBFUSCATED"));
    }
    Ok(reasons)
}

#[allow(clippy::too_many_arguments)]
fn follow_targets(
    p: &Pack,
    tree: &mut Tree,
    f: &mut Follow,
    hook: &mut Hook,
    o: &Opts,
    project: bool,
    base: &[u32],
    release: &Option<PyStr>,
) -> R<()> {
    let cmd = hook.cmd.clone();
    let (targets, complete) = own(|| crate::hooks::follow_hook(p, &cmd))?;
    if !complete && f.truncated.insert(hook.file.clone()) {
        f.out.push(Out::Issue(hook.file.clone(), hook_not_followed(p)));
    }
    for target in targets {
        let Some(path) = tree_join(base, &target) else { continue };
        let Some(rel) = tree.resolve(p, &path)? else { continue };
        let facts = f.script(tree, &rel, release)?;
        if let Some(fa) = &facts {
            let reasons = reasons_of(p, fa, project)?;
            if !reasons.is_empty() {
                escalate(p, hook, runs_msg(p, &target, &reasons), &reasons, o)?;
            }
            if !project {
                if let Some(issue) = fa.agent()? {
                    f.out.push(Out::Issue(rel.clone(), issue.clone()));
                }
            }
        }
        for (started, sfacts) in started_scripts(p, tree, f, &rel, facts, base, release)? {
            let Some(sf) = sfacts else { continue };
            let more = reasons_of(p, &sf, project)?;
            if !more.is_empty() {
                escalate(p, hook, starts_msg(p, &target, &started, base, &more), &more, o)?;
            }
        }
    }
    Ok(())
}

/// core._implicit_gyp_hooks: SC-INSTALL-HOOK (MAJOR) "install (implicit)" at the binding.gyp of each dependency whose
/// package root holds one and whose package.json names no install or preinstall script (nor sets "gypfile": false):
/// npm runs `node-gyp rebuild` on install. `manifests`: the walk's ('/'-separated path, a dependency's).
fn implicit_gyp(p: &Pack, tree: &mut Tree, manifests: &[(PyStr, bool)], o: &Opts) -> Result<Vec<Out>, Missing> {
    let all: HashSet<&[u32]> = manifests.iter().map(|(m, _)| m.as_slice()).collect();
    let mut out = Vec::new();
    let mut missing = false;
    for (rel, dep) in manifests {
        if !dep || !pystr::eq(basename(rel), "package.json") {
            continue;
        }
        let base = dirname(rel);
        let gyp = join(&base, "binding.gyp");
        if !manifest::is_package_root(&base) || !all.contains(gyp.as_slice()) {
            continue;
        }
        let text = match tree.manifest(rel) {
            Ok(Some(t)) => t,
            Ok(None) => continue,
            Err(Missing) => {
                missing = true;
                continue;
            }
        };
        let Some(data) = load(p, rel, &text) else { continue };
        if matches!(data.get("gypfile"), Some(PyVal::Bool(false))) {
            continue;
        }
        let hook_named = match data.get("scripts") {
            Some(scripts @ PyVal::Dict(..)) => ["install", "preinstall"]
                .iter()
                .any(|h| scripts.get(h).and_then(|s| s.as_str()).is_some_and(|s| !pystr::strip(s).is_empty())),
            _ => false,
        };
        if hook_named {
            continue;
        }
        let cmd = u("node-gyp rebuild");
        let finding = manifest::hook_finding(p, 1, &u("install (implicit)"), &cmd, &[], None, false);
        let snippets = Snippets::new(p, vec![&[]], o.redact, o.neumaier).plain();
        out.push(Out::Issue(gyp, snippets.issue_with(&finding, vec![("cmd", Value::Str(cmd))])));
    }
    if missing {
        Err(Missing)
    } else {
        Ok(out)
    }
}

/// What deps_hooks answers: each hook's new severity and message (None: unchanged), the findings, and the files the
/// hooks run.
pub struct Followed {
    pub hooks: Vec<Option<(PyStr, PyStr)>>,
    pub out: Vec<Out>,
    pub run: Vec<PyStr>,
}

/// `deps_hooks`: the follow of each of `hooks`, in order (`project`: a project's own hooks, core.project_hook_checks;
/// else a dependency's, after npm's implicit node-gyp hooks: core.dependency_checks). One hook's check that spends
/// its budget makes that hook's manifest SC-TRUNCATED and ends its follow, as an error did (one manifest must never
/// stop the run). Err: what the call still needs.
pub fn follow_hooks(p: &Pack, known: &Known, project: bool, hooks: &[Hook], manifests: &[(PyStr, bool)], o: &Opts) -> Result<Followed, Need> {
    let mut tree = Tree::new(known);
    let mut f = Follow::default();
    let mut missing = false;
    if !project {
        match implicit_gyp(p, &mut tree, manifests, o) {
            Ok(out) => f.out.extend(out),
            Err(Missing) => missing = true,
        }
    }
    let mut names = InstalledNames::default();
    let mut done = Vec::with_capacity(hooks.len());
    for h in hooks {
        let mut hook = h.clone();
        let step = if project {
            follow_project(p, &mut tree, &mut f, &mut hook, o)
        } else {
            follow_dependency(p, &mut tree, &mut f, &mut names, &mut hook, o)
        };
        match step {
            Ok(()) => {}
            Err(Stop::Missing) => missing = true, // (the hooks after it are followed for what they need)
            Err(Stop::Exhausted) => f.out.push(Out::Issue(hook.file.clone(), exhausted_issue(p))),
        }
        done.push(hook.msg.map(|m| (hook.sev, m)));
    }
    if missing || !tree.need.is_empty() {
        return Err(tree.need);
    }
    Ok(Followed { hooks: done, out: f.out, run: f.run })
}

// ---------------- a web app's static assets (core._deps_web_assets, _deps_npm_reach) ----------------

/// core._xf_js_package: the npm package root a dependency file lives in (node_modules/<name> or
/// node_modules/@scope/<name>, innermost), else None.
pub fn js_package(path: &[u32]) -> Option<PyStr> {
    let parts = pystr::split_char(path, '/' as u32);
    if parts.len() < 2 {
        return None;
    }
    for i in (0..parts.len() - 1).rev() {
        if pystr::eq(parts[i], "node_modules") {
            let end = if pystr::starts_with(parts[i + 1], "@") && i + 2 < parts.len() { i + 3 } else { i + 2 };
            return Some(pystr::join(&u("/"), &parts[..end]));
        }
    }
    None
}

/// core._deps_npm_entries: the paths an npm package.json's main, module, bin and exports name.
pub fn npm_entries(data: &PyVal) -> Vec<PyStr> {
    let mut out = Vec::new();
    for key in ["main", "module"] {
        if let Some(s) = data.get(key).and_then(|v| v.as_str()) {
            out.push(s.to_vec());
        }
    }
    match data.get("bin") {
        Some(PyVal::Str(s)) => out.push(s.clone()),
        Some(PyVal::Dict(items, _)) => out.extend(items.iter().filter_map(|(_, v)| v.as_str().map(|s| s.to_vec()))),
        _ => {}
    }
    let mut stack: Vec<&PyVal> = data.get("exports").into_iter().collect();
    while let Some(e) = stack.pop() {
        match e {
            PyVal::Str(s) => {
                if !s.contains(&('*' as u32)) {
                    out.push(s.clone());
                }
            }
            PyVal::Dict(items, _) => stack.extend(items.iter().rev().map(|(_, v)| v)),
            PyVal::List(items) => stack.extend(items.iter().rev()),
            _ => {}
        }
    }
    out
}

/// core._deps_npm_reach: the files of the npm package at `root` its entry points reach, transitively; None when what
/// one of them starts could not be read (a check spent its budget): then none of its files is taken for an asset.
/// What the walk from its entry points needs to know is asked at once, so a chain of requires takes no round each:
/// the files below `root` (`under`: Node's resolution of a path below it needs no `stat`), its package.json, and what
/// each of its JavaScript files of `paths` (the scan's) loads or starts.
fn npm_reach(p: &Pack, tree: &mut Tree, root: &[u32], paths: &[&PyStr]) -> Result<Option<HashSet<PyStr>>, Missing> {
    let mfile = join(root, "package.json");
    let prefix = pystr::concat(&[root, &u("/")]);
    let listed = tree.under(root);
    let manifest = tree.manifest(&mfile);
    let mut asked = false;
    for path in paths.iter().filter(|x| x.starts_with(&prefix)) {
        asked |= tree.targets(path).is_err();
    }
    listed?;
    let entries = match manifest? {
        Some(text) => load(p, &mfile, &text).map(|d| npm_entries(&d)).unwrap_or_default(),
        None => Vec::new(),
    };
    if asked {
        return Err(Missing);
    }
    let mut missing = false;
    let mut queue: Vec<PyStr> = Vec::new();
    // (the file Node runs for `path` onto the queue; false: not known yet)
    let ask = |tree: &mut Tree, path: &[u32], queue: &mut Vec<PyStr>| match tree.resolve(p, path) {
        Ok(Some(r)) => {
            queue.push(r);
            true
        }
        Ok(None) => true,
        Err(Missing) => false,
    };
    missing |= !ask(tree, root, &mut queue);
    for e in &entries {
        if let Some(t) = tree_join(root, e) {
            missing |= !ask(tree, &t, &mut queue);
        }
    }
    let mut seen: HashSet<PyStr> = HashSet::new();
    let mut unknown = false;
    while let Some(rel) = queue.pop() {
        if seen.contains(&rel) || !rel.starts_with(&prefix) {
            continue;
        }
        seen.insert(rel.clone());
        let found = match tree.targets(&rel) {
            Ok(Targets::Found(t)) => t,
            Ok(Targets::NotSource) => continue,
            Ok(Targets::Unknown) => {
                unknown = true;
                continue;
            }
            Err(Missing) => {
                missing = true;
                continue;
            }
        };
        let base = dirname(&rel);
        for (where_, target) in found {
            let at = if pystr::eq(&where_, "dir") { base.as_slice() } else { root };
            if let Some(joined) = tree_join(at, &target) {
                missing |= !ask(tree, &joined, &mut queue);
            }
        }
    }
    if missing {
        Err(Missing)
    } else if unknown {
        Ok(None)
    } else {
        Ok(Some(seen))
    }
}

/// core._deps_web_assets: of the dependency JavaScript files `paths` ('/'-separated), those that are a web app's
/// static assets: in a _next, static or public directory of their package, and reached from none of its npm
/// package's entry points.
fn web_assets(p: &Pack, tree: &mut Tree, paths: &[&PyStr]) -> Result<HashSet<PyStr>, Missing> {
    let web = p.strs("_DEPS_WEB_DIRS");
    let mut found: Vec<(Option<PyStr>, Vec<PyStr>)> = Vec::new();
    for path in paths {
        let root = js_package(path);
        let rel: &[u32] = match &root {
            Some(r) => &path[(r.len() + 1).min(path.len())..],
            None => path,
        };
        let parts = pystr::split_char(rel, '/' as u32);
        if parts[..parts.len() - 1].iter().any(|part| web.iter().any(|w| *w == pystr::lower(part))) {
            match found.iter_mut().find(|(r, _)| *r == root) {
                Some((_, v)) => v.push((*path).clone()),
                None => found.push((root, vec![(*path).clone()])),
            }
        }
    }
    let mut out = HashSet::new();
    let mut missing = false;
    for (root, ps) in &found {
        let reached = match root {
            Some(r) => match npm_reach(p, tree, r, paths) {
                Ok(Some(s)) => s,
                Ok(None) => continue,
                Err(Missing) => {
                    missing = true;
                    continue;
                }
            },
            None => HashSet::new(),
        };
        out.extend(ps.iter().filter(|x| !reached.contains(*x)).cloned());
    }
    if missing {
        Err(Missing)
    } else {
        Ok(out)
    }
}

// ---------------- the names of the installed package a file is in (core._InstalledNames) ----------------

/// (declared, own): the names a package manager may install for the package a file is in, and its own name.
pub type Names = Option<(Vec<PyStr>, Option<PyStr>)>;

/// core.npm_declared_names: a package.json's own name and the packages it names, dependencies of every kind, bundled
/// ones too (D-12), sorted.
pub fn npm_declared_names(data: &PyVal) -> Vec<PyStr> {
    let mut out: Vec<PyStr> = Vec::new();
    if let Some(n) = data.get("name").and_then(|n| n.as_str()) {
        out.push(n.to_vec());
    }
    for key in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        if let Some(PyVal::Dict(items, _)) = data.get(key) {
            out.extend(items.iter().filter_map(|(k, _)| k.as_str().map(|s| s.to_vec())));
        }
    }
    for key in ["bundleDependencies", "bundledDependencies"] {
        if let Some(PyVal::List(items)) = data.get(key) {
            out.extend(items.iter().filter_map(|k| k.as_str().map(|s| s.to_vec())));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// core.metadata_declared_names: a METADATA's or PKG-INFO's Name and each Requires-Dist's name, an extra's too
/// (D-12), sorted, and how many Requires-Dist it has; the headers end at the first empty line.
pub fn metadata_declared_names(text: &[u32]) -> (Vec<PyStr>, usize) {
    let mut names: Vec<PyStr> = Vec::new();
    let mut requires = 0;
    for line in pystr::split_char(text, '\n' as u32) {
        if pystr::strip(line).is_empty() {
            break;
        }
        let req = pystr::starts_with(line, "Requires-Dist:");
        if !req && !pystr::starts_with(line, "Name:") {
            continue;
        }
        requires += req as usize;
        let colon = line.iter().position(|&c| c == ':' as u32).unwrap_or(0);
        let value = pystr::strip(&line[colon + 1..]);
        let stop = |c: u32| pystr::is_space(c) || ";[(<>=!~@".chars().any(|x| x as u32 == c);
        let end = value.iter().position(|&c| stop(c)).unwrap_or(value.len());
        if end > 0 {
            names.push(value[..end].to_vec());
        }
    }
    names.sort();
    names.dedup();
    (names, requires)
}

/// core._xf_record_tops' reading of a RECORD's text: the top-level names its rows list (their first path parts),
/// sorted.
pub fn record_tops(text: &[u32]) -> Vec<PyStr> {
    let mut out: Vec<PyStr> = Vec::new();
    for row in pystr::split_char(text, '\n' as u32) {
        let first = row.split(|&c| c == ',' as u32).next().unwrap_or(&[]);
        let entry = pystr::replace_char(pystr::strip_chars(pystr::strip(first), "\""), '\\' as u32, '/' as u32);
        let top = entry.split(|&c| c == '/' as u32).next().unwrap_or(&[]);
        if !top.is_empty() && !pystr::eq(top, ".") && !pystr::eq(top, "..") && !top.contains(&(':' as u32)) {
            out.push(top.to_vec());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The top-level names a .dist-info's RECORD lists: none when it can't be read, or is larger than _XF_RECORD_BYTES.
fn dist_record_tops(p: &Pack, tree: &mut Tree, info: &[u32]) -> Result<Vec<PyStr>, Missing> {
    match tree.head(&join(info, "RECORD"), p.int("_XF_RECORD_BYTES"))? {
        Some((text, false)) => Ok(record_tops(&text)),
        _ => Ok(Vec::new()),
    }
}

/// The real directories `site` holds whose names end in .dist-info, by name; None when it can't be listed.
fn dist_infos(tree: &mut Tree, site: &[u32]) -> Result<Option<Vec<PyStr>>, Missing> {
    let Some(entries) = tree.list(site)? else { return Ok(None) };
    let mut infos: Vec<PyStr> = entries.into_iter().filter(|(n, dir)| *dir && pystr::ends_with(n, ".dist-info")).map(|(n, _)| n).collect();
    infos.sort();
    Ok(Some(infos))
}

/// The installed names, asked for a file at a time and kept for the call (core._InstalledNames).
#[derive(Default)]
struct InstalledNames {
    npm: HashMap<PyStr, Names>,
    sites: HashMap<PyStr, HashMap<PyStr, Vec<PyStr>>>,
}

impl InstalledNames {
    /// The names of the package the file `path` ('/'-separated) is in.
    fn of(&mut self, p: &Pack, tree: &mut Tree, path: &[u32]) -> Result<Names, Missing> {
        let parts = pystr::split_char(path, '/' as u32);
        let inner = &parts[..parts.len() - 1];
        if let Some(k) = inner.iter().rposition(|x| pystr::eq(x, "node_modules")) {
            let end = if pystr::starts_with(parts[k + 1], "@") { k + 3 } else { k + 2 };
            if end >= parts.len() {
                return Ok(None);
            }
            let directory = pystr::join(&u("/"), &parts[..end]);
            if !manifest::is_package_root(&directory) {
                return Ok(None);
            }
            if let Some(v) = self.npm.get(&directory) {
                return Ok(v.clone());
            }
            let mfile = join(&directory, "package.json");
            let names = match tree.manifest(&mfile)? {
                Some(text) => load(p, &mfile, &text).map(|data| {
                    let own = data.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty()).map(|n| n.to_vec());
                    (npm_declared_names(&data), own)
                }),
                None => None,
            };
            self.npm.insert(directory, names.clone());
            return Ok(names);
        }
        let markers = p.strs("_XF_SITE_MARKERS");
        let Some(idx) = inner.iter().rposition(|x| markers.iter().any(|m| m.as_slice() == *x)) else { return Ok(None) };
        let site = pystr::join(&u("/"), &parts[..idx + 1]);
        if !self.sites.contains_key(&site) {
            let names = site_names(p, tree, &site)?;
            self.sites.insert(site.clone(), names);
        }
        Ok(self.sites[&site].get(parts[idx + 1]).map(|d| (d.clone(), None)))
    }
}

/// core._InstalledNames._site_names: {top-level name: the names of the distributions whose RECORD lists it}.
fn site_names(p: &Pack, tree: &mut Tree, site: &[u32]) -> Result<HashMap<PyStr, Vec<PyStr>>, Missing> {
    let mut names: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    let Some(infos) = dist_infos(tree, site)? else { return Ok(names) };
    let cap = p.int("_METADATA_HEAD_BYTES");
    let mut missing = false;
    for info in &infos {
        let dir = pystr::concat(&[site, &u("/"), info]);
        let meta = match tree.head(&join(&dir, "METADATA"), cap) {
            Ok(Some((text, _more))) => text,
            Ok(None) => continue,
            Err(Missing) => {
                missing = true;
                continue;
            }
        };
        let (declared, _requires) = metadata_declared_names(&meta);
        match dist_record_tops(p, tree, &dir) {
            Ok(tops) => {
                for top in tops {
                    names.entry(top).or_default().extend(declared.iter().cloned());
                }
            }
            Err(Missing) => missing = true,
        }
    }
    if missing {
        return Err(Missing);
    }
    for v in names.values_mut() {
        v.sort();
        v.dedup();
    }
    Ok(names)
}

// ---------------- a site-packages directory's distributions (core._xf_site_groups) ----------------

/// core._xf_site_groups: (path, group) for the dependency Python files `paths` under a site-packages or
/// dist-packages directory whose top-level module or package a distribution's RECORD lists with another: the group
/// is that directory and the first such .dist-info's name, by name.
fn site_groups(p: &Pack, tree: &mut Tree, paths: &[&PyStr]) -> Result<Vec<(PyStr, PyStr)>, Missing> {
    let dep_markers = p.strs("_XF_DEP_MARKERS");
    let site_markers = p.strs("_XF_SITE_MARKERS");
    let mut sites: Vec<(PyStr, Vec<(PyStr, Vec<PyStr>)>)> = Vec::new();
    for path in paths {
        let parts = pystr::split_char(path, '/' as u32);
        let Some(idx) = dep_markers.iter().filter_map(|m| parts.iter().rposition(|x| *x == m.as_slice())).max() else { continue };
        if idx >= parts.len() - 1 || !site_markers.iter().any(|m| m.as_slice() == parts[idx]) {
            continue;
        }
        let site = pystr::join(&u("/"), &parts[..idx + 1]);
        let top = parts[idx + 1].to_vec();
        let k = match sites.iter().position(|(s, _)| *s == site) {
            Some(k) => k,
            None => {
                sites.push((site, Vec::new()));
                sites.len() - 1
            }
        };
        match sites[k].1.iter_mut().find(|(t, _)| *t == top) {
            Some((_, v)) => v.push((*path).clone()),
            None => sites[k].1.push((top, vec![(*path).clone()])),
        }
    }
    let mut out = Vec::new();
    let mut missing = false;
    for (site, tops) in &sites {
        if tops.len() < 2 {
            continue;
        }
        let infos = match dist_infos(tree, site) {
            Ok(Some(i)) => i,
            Ok(None) => continue,
            Err(Missing) => {
                missing = true;
                continue;
            }
        };
        let mut label: Vec<(PyStr, PyStr)> = Vec::new(); // top-level name -> its group's .dist-info, in order
        let mut site_missing = false;
        for name in &infos {
            let listed: Vec<PyStr> = match dist_record_tops(p, tree, &pystr::concat(&[site, &u("/"), name])) {
                Ok(t) => t.into_iter().filter(|t| tops.iter().any(|(x, _)| x == t)).collect(),
                Err(Missing) => {
                    site_missing = true;
                    continue;
                }
            };
            if site_missing || listed.len() < 2 {
                continue;
            }
            let mut joined: Vec<PyStr> = vec![name.clone()];
            joined.extend(listed.iter().filter_map(|t| label.iter().find(|(x, _)| x == t).map(|(_, g)| g.clone())));
            joined.sort();
            joined.dedup();
            let first = joined[0].clone();
            let mut relabel: Vec<PyStr> = label.iter().filter(|(_, g)| joined.contains(g)).map(|(t, _)| t.clone()).collect();
            relabel.extend(listed);
            for t in relabel {
                match label.iter_mut().find(|(x, _)| *x == t) {
                    Some((_, g)) => *g = first.clone(),
                    None => label.push((t, first.clone())),
                }
            }
        }
        if site_missing {
            missing = true;
            continue;
        }
        for (top, group) in &label {
            if let Some((_, ps)) = tops.iter().find(|(t, _)| t == top) {
                let g = pystr::concat(&[site, &u("/"), group]);
                out.extend(ps.iter().map(|path| (path.clone(), g.clone())));
            }
        }
    }
    if missing {
        Err(Missing)
    } else {
        Ok(out)
    }
}

// ---------------- the files of a --deps scan's checks (deps_files) ----------------

/// What deps_files answers: the web app's static assets, each file the import-time and agent checks read (in order)
/// with its package's names, and the site-packages groups of the cross-file follower.
pub struct Planned {
    pub assets: Vec<PyStr>,
    pub todo: Vec<(PyStr, Names)>,
    pub groups: Vec<(PyStr, PyStr)>,
}

/// `deps_files`: for the dependency files `files` ('/'-separated path, lang: "js" or "py"; the walk's, in order)
/// after the hooks were followed (`run`: the files they run), which are static assets (core._deps_web_assets), which
/// the import-time and agent checks read and with what names (core._InstalledNames), and the site-packages groups
/// (core._xf_site_groups). Err: what the call still needs.
pub fn plan_files(p: &Pack, known: &Known, files: &[(PyStr, PyStr)], run: &HashSet<PyStr>) -> Result<Planned, Need> {
    let mut tree = Tree::new(known);
    let mut missing = false;
    let js: Vec<&PyStr> = files.iter().filter(|(_, l)| pystr::eq(l, "js")).map(|(f, _)| f).collect();
    let assets = match web_assets(p, &mut tree, &js) {
        Ok(a) => a,
        Err(Missing) => {
            missing = true;
            HashSet::new()
        }
    };
    // (the names of every file no hook runs are asked with the assets: an asset's are not used)
    let mut names = InstalledNames::default();
    let mut todo = Vec::new();
    for (path, _lang) in files {
        if run.contains(path) {
            continue;
        }
        match names.of(p, &mut tree, path) {
            Ok(n) if !assets.contains(path) => todo.push((path.clone(), n)),
            Ok(_) => {}
            Err(Missing) => missing = true,
        }
    }
    let py: Vec<&PyStr> = files.iter().filter(|(_, l)| pystr::eq(l, "py")).map(|(f, _)| f).collect();
    let groups = match site_groups(p, &mut tree, &py) {
        Ok(g) => g,
        Err(Missing) => {
            missing = true;
            Vec::new()
        }
    };
    if missing || !tree.need.is_empty() {
        return Err(tree.need);
    }
    let assets = js.iter().filter(|x| assets.contains(**x)).map(|x| (*x).clone()).collect();
    Ok(Planned { assets, todo, groups })
}

/// A Names as the boundary carries it: [declared, own or null], or null.
pub fn names_value(n: &Names) -> Value {
    match n {
        Some((declared, own)) => Value::Arr(vec![strs(declared), own.clone().map(Value::Str).unwrap_or(Value::Null)]),
        None => Value::Null,
    }
}

/// `declared_names`: the names a release declares (the registry's _declared_names): "npm", its package.json's
/// (npm_declared_names; null when it is not an object), or "metadata", a METADATA's or PKG-INFO's ([names, how many
/// Requires-Dist]).
pub fn declared_names(p: &Pack, kind: &str, text: &[u32]) -> Value {
    if kind == "npm" {
        return match load(p, &u("package.json"), text) {
            Some(data) => strs(&npm_declared_names(&data)),
            None => Value::Null,
        };
    }
    let (names, requires) = metadata_declared_names(text);
    Value::Arr(vec![strs(&names), Value::Int(requires as i64)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> PyStr {
        u(x)
    }

    #[test]
    fn helpers() {
        assert_eq!(commas(1234567), "1,234,567");
        assert_eq!(commas(12), "12");
        assert_eq!(js_package(&s("a/node_modules/@s/p/x.js")), Some(s("a/node_modules/@s/p")));
        assert_eq!(js_package(&s("node_modules/p/node_modules/q/lib/x.js")), Some(s("node_modules/p/node_modules/q")));
        assert_eq!(js_package(&s("node_modules/@s")), Some(s("node_modules/@s")));
        assert_eq!(js_package(&s("lib/x.js")), None);
        assert_eq!(record_tops(&s("a/b.py,sha,1\n\"c/d\",x\n./e,1\n..\nC:\\x,1\nf.py,,\n")), vec![s("a"), s("c"), s("f.py")]);
        let (names, req) = metadata_declared_names(&s("Name: pkg\nRequires-Dist: other (>=1); extra == 'x'\nRequires-Dist: third[a]\n\nName: body"));
        assert_eq!(names, vec![s("other"), s("pkg"), s("third")]);
        assert_eq!(req, 2);
        assert_eq!(join(&s(""), "package.json"), s("package.json"));
        assert_eq!(join(&s("a/"), "b"), s("a/b"));
    }

    #[test]
    fn tree_join_inside_the_scan_root_only() {
        // (the packages' tests until BR-7 step 3e)
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("node_modules/a", "x.js", Some("node_modules/a/x.js")),
            ("node_modules/a", "./b/../x.js", Some("node_modules/a/x.js")),
            ("node_modules/a", "../../y.js", Some("y.js")),
            ("node_modules/a", "../../../y.js", None),
            ("node_modules/a", "/usr/y.js", None),
            ("node_modules/a", "C:/y.js", None),
            ("node_modules/a", "lib\\z.js", Some("node_modules/a/lib/z.js")),
            ("", "x.js", Some("x.js")),
            ("", "..", None),
            ("a", ".", Some("a")),
            ("a", "..", None),
            ("a", "b//c/", Some("a/b/c")),
        ];
        for (base, target, want) in cases {
            assert_eq!(tree_join(&s(base), &s(target)), want.map(s), "{base} + {target}");
        }
    }

    #[test]
    fn entry_points() {
        let load = |t: &str| crate::manifest::pyjson::loads(&s(t), None).unwrap();
        let data = load(concat!(
            r#"{"main": "a.js", "module": "b.mjs", "bin": {"c": "c.js", "d": 1}, "#,
            r#""exports": {".": {"import": "./e.mjs", "require": ["./f.js", "./g.js"]}, "./*": "./h/*.js"}}"#
        ));
        assert_eq!(npm_entries(&data), ["a.js", "b.mjs", "c.js", "./e.mjs", "./f.js", "./g.js"].map(s));
        assert_eq!(npm_entries(&load(r#"{"bin": "x.js", "exports": "./y.js"}"#)), ["x.js", "./y.js"].map(s));
        // every entry point (BR-5: the exports were read to 5,000)
        let many: Vec<String> = (0..6000).map(|i| format!("\"./p{i}\": \"./p{i}.js\"")).collect();
        assert_eq!(npm_entries(&load(&format!("{{\"exports\": {{{}}}}}", many.join(", ")))).len(), 6000);
    }

    #[test]
    fn declared() {
        let p = crate::pack::current();
        let npm = concat!(
            r#"{"name": "x", "dependencies": {"a": "1"}, "bundleDependencies": ["b"], "devDependencies": {"c": "1"}, "#,
            r#""peerDependencies": {"d": "1"}}"#
        );
        assert_eq!(declared_names(&p, "npm", &s(npm)), strs(&["a", "b", "c", "d", "x"].map(s)));
        assert_eq!(declared_names(&p, "npm", &s("[1]")), Value::Null);
        let meta = "Name: x\nRequires-Dist: a (>=1)\nRequires-Dist: b[s]; extra == 'y'\n\nRequires-Dist: not-a-header\n";
        assert_eq!(declared_names(&p, "metadata", &s(meta)), Value::Arr(vec![strs(&["a", "b", "x"].map(s)), Value::Int(2)]));
    }
}
