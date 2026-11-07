//! The pass over a project's files (jsflow.py's analyze, _analyze and
//! _fixpoint): the files read, the summaries to a fixpoint (callees first;
//! a function is read again when a summary or a shared value it used
//! changed), then the reporting pass; and the model's configured part.

use super::eval::{Eval, Halt};
use super::*;
use crate::findings::py_repr;
use crate::pyre::Regex;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

/// The characters of a text a configured pattern sees (taintspec's
/// MAX_MATCH_TEXT).
pub const MAX_MATCH_TEXT: usize = 2000;

/// Request data by the text of a member expression (`req.query`) or a
/// call's callee followed by "(" (`req.get(`).
pub const SOURCE_RE: &str = concat!(
    r"(?<![\w$.])(?:req|request)\.(?:query|body|params|headers|cookies)\b",
    r"|(?<![\w$.])req\.(?:signedCookies|files?|originalUrl|url|path|hostname)\b",
    r"|(?<![\w$.])req\.(?:get|header|param)\($|(?<![\w$.])process\.argv\b",
    r"|(?<![\w$.])(?:window\.|document\.)?location\.(?:search|hash|href)\b",
);

/// (pattern over a sink's text, category, the arguments that carry the
/// injection). The text is a call's callee followed by "(" (`db.query(`,
/// `new Function(`) or an assignment's target followed by " ="
/// (`el.innerHTML =`); arguments: "first", "last", "all", "second", or
/// "value" (an assignment's right side).
pub const SINKS: &[(&str, u8, &str)] = &[
    (r"\.(?:query|execute)\($", SQL, "first"),
    (r"\.(?:whereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|fromRaw)\($", SQL, "first"),
    (r"(?<![\w$.])(?:knex\.raw|sequelize\.literal|sequelize\.query)\($", SQL, "first"),
    (r"(?<![\w$])(?:exec|execSync|spawn|spawnSync)\($", CMD, "all"),
    (
        concat!(
            r"(?<![\w$.])eval\($|^new Function\($|(?<![\w$.])vm\.(?:runInNewContext|runInThisContext",
            r"|runInContext|compileFunction)\($|^new vm\.Script\($"
        ),
        CODE,
        "first",
    ),
    (
        concat!(
            r"(?<![\w$])(?:ejs|pug|jade|Handlebars|handlebars|Mustache|mustache|nunjucks|doT|_)\.(?:render",
            r"|renderString|compile|template)\($"
        ),
        TEMPLATE,
        "first",
    ),
    (r"\.(?:sendFile|download)\($", PATH, "first"),
    (r"(?<![\w$])(?:readFile|readFileSync|createReadStream)\($", PATH, "first"),
    (
        concat!(
            r"(?<![\w$.])fs(?:\.promises)?\.(?:writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|rename",
            r"|copyFile|createWriteStream)(?:Sync)?\($"
        ),
        PATH,
        "first",
    ),
    (
        concat!(
            r"(?<![\w$.])(?:fetch|needle)\($|(?<![\w$.])axios(?:\.(?:get|post|put|patch|delete|head",
            r"|request))?\($|(?<![\w$.])https?\.(?:get|request)\($|(?<![\w$.])got(?:\.(?:get|post|put|patch",
            r"|delete|head|stream))?\($"
        ),
        SSRF,
        "first",
    ),
    (r"\.redirect\($", REDIRECT, "last"),
    (r"(?<![\w$.])(?:res|response)\.location\($", REDIRECT, "first"),
    (r"\.(?:innerHTML|outerHTML) =$", XSS, "value"),
    (r"(?<![\w$.])document\.(?:write|writeln)\($", XSS, "all"),
    (r"\.insertAdjacentHTML\($", XSS, "second"),
    (r"(?<![\w$.])(?:res|response)(?:\.[\w$]+\(\))*\.(?:send|write|end)\($", XSS, "first"),
];

/// A URL whose text starts with a path on this site or a fixed host: what
/// is joined after it can change neither (core._SAME_SITE_RE, for SSRF
/// too). Matched at the start.
pub const FIXED_PREFIX_RE: &str = r"/[^/\\]|[Hh][Tt][Tt][Pp][Ss]?://[^/?#\\\s{}$]+/";
/// A Server-Sent Events frame: not HTML. Matched at the start.
pub const SSE_RE: &str = r"(?:data|event|id|retry)[ \t]*:";

fn rx(src: &str) -> Rc<Regex> {
    crate::rxutil::dynamic(u(src), 0)
}

/// The taint model's configured part (jsflow.config): sources and sinks a
/// configuration adds (each sees at most MAX_MATCH_TEXT characters of a
/// text), full sanitizers (call names) and partial ones (name ->
/// categories).
pub struct Config {
    pub extra_sources: Vec<Rc<Regex>>,
    pub extra_sinks: Vec<(Rc<Regex>, u8)>,
    pub full: HashSet<PyStr>,
    pub partial: HashMap<PyStr, u8>,
    /// one reading of one function: run_base + run_per_node steps per node
    /// of it (RUN_BASE, RUN_PER_NODE unless lowered: with_run_limit)
    pub run_base: u64,
    pub run_per_node: u64,
    /// the supply-chain model (supply.rs) instead of project mode's
    pub supply: Option<Rc<super::supply::Supply>>,
    source: Rc<Regex>,
    sinks: Vec<Rc<Regex>>,
    fixed: Rc<Regex>,
    sse: Rc<Regex>,
}

fn clip(text: &[u32]) -> &[u32] {
    &text[..text.len().min(MAX_MATCH_TEXT)]
}

impl Config {
    /// Patterns that fail to compile match nothing (taintspec refused them
    /// before they got here).
    pub fn new(extra_sources: &[PyStr], extra_sinks: &[(PyStr, u8)], full: &[PyStr], partial: &[(PyStr, u8)]) -> Config {
        let compile = |p: &PyStr| crate::rxutil::dynamic_user(p.clone(), 0);
        let mut part: HashMap<PyStr, u8> = HashMap::new();
        for (name, bits) in partial {
            *part.entry(name.clone()).or_insert(0) |= bits;
        }
        Config {
            extra_sources: extra_sources.iter().map(compile).collect(),
            extra_sinks: extra_sinks.iter().map(|(p, c)| (compile(p), *c)).collect(),
            full: full.iter().cloned().collect(),
            partial: part,
            run_base: RUN_BASE,
            run_per_node: RUN_PER_NODE,
            supply: None,
            source: rx(SOURCE_RE),
            sinks: SINKS.iter().map(|(p, _, _)| rx(p)).collect(),
            fixed: rx(FIXED_PREFIX_RE),
            sse: rx(SSE_RE),
        }
    }

    /// A lower limit for one function's reading (each part at most the
    /// default: a host can make the pass cheaper, never longer).
    pub fn with_run_limit(mut self, base: u64, per_node: u64) -> Config {
        self.run_base = base.min(RUN_BASE);
        self.run_per_node = per_node.min(RUN_PER_NODE);
        self
    }

    pub fn is_source(&self, text: &[u32]) -> bool {
        self.source.search(text).is_some() || self.extra_sources.iter().any(|r| r.search(clip(text)).is_some())
    }

    /// A call's sink: (category, the arguments), a configured one first.
    pub fn sink_of(&self, text: &[u32]) -> Option<(u8, &'static str)> {
        if let Some(cat) = self.extra_sink(text) {
            return Some((cat, "all"));
        }
        for (k, (_, cat, which)) in SINKS.iter().enumerate() {
            if *which != "value" && self.sinks[k].search(text).is_some() {
                return Some((*cat, which));
            }
        }
        None
    }

    /// The first configured sink whose pattern the text matches.
    pub fn extra_sink(&self, text: &[u32]) -> Option<u8> {
        self.extra_sinks.iter().find(|(r, _)| r.search(clip(text)).is_some()).map(|(_, c)| *c)
    }

    pub fn sink_matches(&self, k: usize, text: &[u32]) -> bool {
        self.sinks[k].search(text).is_some()
    }

    pub fn fixed_prefix(&self, text: &[u32]) -> bool {
        self.fixed.match_(text).is_some()
    }

    pub fn sse(&self, text: &[u32]) -> bool {
        self.sse.match_(text).is_some()
    }
}

/// What the pass gives, in jsflow.py's order: X-FLOW-SKIPPED findings as
/// the files are read, issues as the reporting pass finds them, then the
/// notes. The host builds its findings from them (flow._issue,
/// flow._flow_note, flow._skipped_size; flow.js's twins).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// a file over MAX_FILE code points
    SkippedSize { path: PyStr, n: usize },
    /// request data reaching a sink: (category, the file and line where it
    /// is reported, the index of that file in the input, the source's
    /// location, the sink's, the way it came)
    Issue { cat: u8, path: PyStr, file: u32, line: u32, source: PyStr, sink: PyStr, via: PyStr },
    Note { rule: &'static str, name: &'static str, path: PyStr, line: u32, msg: PyStr, why: &'static str, fix: &'static str },
    /// the supply-chain model: local data reaching a network send (the
    /// send's offset, the kind of data, what was read, whether only an
    /// address held it)
    Send { at: u32, kind: &'static str, what: PyStr, in_address: bool },
    /// the supply-chain model: data received over the network reaching code
    /// run, a module loaded or a deserializer (the sink's offset, the
    /// category: "run", "import", "deserialize")
    Received { at: u32, cat: &'static str },
    /// the supply-chain model: data the script decodes (base64, hex, a
    /// decompression, a decryption …) reaching code run (the sink's offset,
    /// the decoding's)
    Decoded { at: u32, from: u32 },
    /// the supply-chain model: a file the script writes, then runs as a
    /// program or with an interpreter, holding code or a program it decodes,
    /// carves out of another file or downloads (the run's offset, the
    /// write's, what it held: `K_DECODED`, `K_CARVED` or `K_RECEIVED`, the
    /// carved file, the interpreter)
    Dropped { at: u32, from: u32, kinds: u16, what: PyStr, interp: Option<PyStr> },
    /// the supply-chain model (Python's): what the script reads back from
    /// its own file, its docstring or a data file shipped with it, reaching
    /// code run (the run's offset)
    Own { at: u32 },
    /// RA-6: a deletion and the resolved target value.
    Delete { at: u32, path: PyStr },
    /// the supply-chain model (JavaScript's): a code file in another
    /// package's folder written (the write's offset, the package): D-9
    Rewrote { at: u32, pkg: PyStr },
}

fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (k, ch) in s.chars().enumerate() {
        if k > 0 && (s.len() - k) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn cat_s(parts: &[&[u32]]) -> PyStr {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

const WHY_SIZE: &str = "Every file is read within a budget proportional to its size, so a scan cannot run unbounded.";
const FIX_SIZE: &str = "Split or deminify very large or deeply nested files, or exclude generated code from the scan.";

impl Program {
    /// jsflow.py's _text: a callee's or a member's text — `a.b().c`,
    /// `new F()`, `this.x`, `a[]` for a computed member; "" for anything
    /// else; at most TEXT_MAX characters. Memoized per node; deep chains in
    /// a loop.
    pub fn text(&mut self, m: ModId, node: NodeId) -> Rc<PyStr> {
        use jt::A;
        if let Some(t) = self.mods[m as usize].text_memo.get(&node) {
            return t.clone();
        }
        let mut chain: Vec<NodeId> = Vec::new();
        let mut n = node;
        loop {
            if self.mods[m as usize].text_memo.contains_key(&n) {
                break;
            }
            let a = Ast(&self.mods[m as usize].tree);
            match a.kind(n) {
                Kind::MemberExpression | Kind::CallExpression | Kind::ChainExpression => {
                    chain.push(n);
                    n = a.at(n, A);
                }
                _ => break,
            }
        }
        let mut text: PyStr = match self.mods[m as usize].text_memo.get(&n) {
            Some(t) => (**t).clone(),
            None => {
                let a = Ast(&self.mods[m as usize].tree);
                let mut t = match a.kind(n) {
                    Kind::Identifier => a.name(n).to_vec(),
                    Kind::ThisExpression => u("this"),
                    Kind::Super => u("super"),
                    Kind::NewExpression => {
                        let callee = a.at(n, A);
                        let inner = self.text(m, callee);
                        cat_s(&[&u("new "), &inner, &u("()")])
                    }
                    _ => Vec::new(),
                };
                t.truncate(TEXT_MAX);
                self.mods[m as usize].text_memo.insert(n, Rc::new(t.clone()));
                t
            }
        };
        for &c in chain.iter().rev() {
            let a = Ast(&self.mods[m as usize].tree);
            match a.kind(c) {
                Kind::MemberExpression => match a.prop_name(c) {
                    Some(name) => {
                        text.push(0x2E);
                        text.extend_from_slice(&name);
                    }
                    None => text.extend(u("[]")),
                },
                Kind::CallExpression => text.extend(u("()")),
                _ => {}
            }
            text.truncate(TEXT_MAX);
            self.mods[m as usize].text_memo.insert(c, Rc::new(text.clone()));
        }
        self.mods[m as usize].text_memo.get(&node).cloned().unwrap_or_else(|| Rc::new(Vec::new()))
    }
}

/// The cross-file JavaScript pass over `files` (path, content: the
/// project's own JavaScript and TypeScript, no dependencies; None: a file
/// whose content is not text, noted as skipped).
pub fn analyze(files: &[(PyStr, Option<PyStr>)], cfg: Config) -> Vec<Out> {
    let mut prog = Program::new(Rc::new(cfg));
    let mut findings: Vec<Out> = Vec::new();
    let mut skipped: BTreeMap<PyStr, PyStr> = BTreeMap::new();
    let mut over: Vec<PyStr> = Vec::new();
    let mut total = 0usize;
    for (k, (path, content)) in files.iter().enumerate() {
        let low = lower(path);
        if [".d.ts", ".d.mts", ".d.cts"].iter().any(|e| low.ends_with(&u(e))) {
            continue; // a declaration file: types, no code
        }
        let content = match content {
            Some(c) => c,
            None => {
                skipped.insert(path.clone(), u("its content is not text"));
                continue;
            }
        };
        if content.len() > MAX_FILE {
            findings.push(Out::SkippedSize { path: path.clone(), n: content.len() });
            continue;
        }
        if total + content.len() > MAX_TOTAL {
            over.push(path.clone());
            continue;
        }
        match crate::jsparse::parse_file(path, content) {
            Ok(tree) => {
                total += content.len();
                prog.add_module(path, tree, k as u32);
            }
            Err(e) => {
                let ts = crate::jsparse::dialect(path).0;
                let mut why = u(if ts { "it could not be read as TypeScript (line " } else { "it could not be read as JavaScript (line " });
                why.extend(u(&e.line.to_string()));
                why.extend(u(": "));
                why.extend_from_slice(&e.reason);
                why.push(0x29);
                skipped.insert(path.clone(), why);
            }
        }
    }
    let mut notes: Vec<Out> = Vec::new();
    if let Some(first) = over.first() {
        let msg = cat_s(&[
            &u(&format!(
                "Cross-file taint analysis skipped {} JavaScript file(s) beyond its budget ({} characters), starting with ",
                over.len(),
                commas(MAX_TOTAL as u64)
            )),
            &py_repr(first),
            &u("."),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-INCOMPLETE",
            name: "Flow analysis incomplete (size budget)",
            path: first.clone(),
            line: 1,
            msg,
            why: "Very large code bases are analyzed up to a fixed budget so a scan cannot run unbounded; flows through the skipped files are not seen.",
            fix: "Scan sub-trees separately, or exclude generated code.",
        });
    }
    if !prog.mods.is_empty() {
        for m in 0..prog.mods.len() {
            prog.resolve_module(m as ModId);
        }
        for b in 0..prog.binds.len() {
            if prog.binds[b].kind == BindKind::Import {
                for t in prog.import_targets(b as BindId) {
                    prog.binds[t as usize].shared = true;
                }
            }
        }
        prog.mark_routes();
        notes.extend(fixpoint(&mut prog, &mut findings));
    }
    for (path, why) in &skipped {
        let msg = cat_s(&[&u("Cross-file taint analysis skipped "), &py_repr(path), &u(": "), why, &u(".")]);
        notes.push(Out::Note {
            rule: "Q-FLOW-SKIPPED",
            name: "File skipped by flow analysis",
            path: path.clone(),
            line: 1,
            msg,
            why: "Only files the JavaScript reader can parse take part in the interprocedural pass; flows into or out of this file are not seen (the per-file rules still ran).",
            fix: "Fix the syntax error, or exclude the file if it is not JavaScript (a template, for instance), then re-run.",
        });
    }
    findings.extend(notes);
    findings
}

/// (the supply-chain model) What callers give parameters written to closure variables (Func::param_writes), written
/// there by the pass rather than by each reading of a call (eval's apply, write): a value a caller gives that grew in
/// its last reading (Program::pw_grew) to every variable the callee writes the parameter to, and every caller's value
/// to a variable a summary has just learned of (Program::pw_new); as a reading writes it (not the `this.x` of a class
/// made in several places from a call on an instance; within the functions around the variable's), with what that
/// teaches the callers' summaries in turn (a parameter of theirs written there: as a reading's commit learns it, its
/// callers read again once nothing else is queued when the parameter is new to the summary, `changes`). The bindings
/// whose value grew are added to `grown`, for their readers.
fn pw_carry(prog: &mut Program, changes: &mut super::eval::Changes, grown: &mut Vec<BindId>) {
    loop {
        if let Some((callee, i, c)) = prog.pw_grew.pop() {
            let binds: Vec<BindId> =
                prog.fns[callee as usize].sc_ref().and_then(|s| s.param_writes.get(&i)).map(|s| s.iter().copied().collect()).unwrap_or_default();
            pw_write(prog, callee, i, c, &binds, changes, grown);
            continue;
        }
        if !prog.pw_new.is_empty() {
            // (the variables new to each parameter's summary at once, each caller's value read once for them)
            let mut new = std::mem::take(&mut prog.pw_new);
            new.sort_unstable();
            let mut k = 0;
            while k < new.len() {
                let (owner, i) = (new[k].0, new[k].1);
                let mut binds = Vec::new();
                while k < new.len() && (new[k].0, new[k].1) == (owner, i) {
                    binds.push(new[k].2);
                    k += 1;
                }
                let callers = prog.pw_callers.get(&(owner, i as u32)).cloned().unwrap_or_default();
                for c in callers {
                    pw_write(prog, owner, i, c, &binds, changes, grown);
                }
            }
            continue;
        }
        break;
    }
}

/// pw_carry's write of what caller `c` gives parameter `i` of `callee` to bindings `binds`.
fn pw_write(
    prog: &mut Program,
    callee: FnId,
    i: usize,
    c: FnId,
    binds: &[BindId],
    changes: &mut super::eval::Changes,
    grown: &mut Vec<BindId>,
) {
    let (inside, all) = match prog.pw_args.get(&(callee, i as u32, c)) {
        Some((inside, out)) => (inside.clone(), inside.union(out)),
        None => return,
    };
    if !all.tainted() {
        return;
    }
    let mine = prog.scope_fns(c);
    // (the last variable's declaring function: what is written there is the same for its neighbours)
    let mut last: Option<(FnId, bool, Rc<[FnId]>, V)> = None;
    for &b in binds {
        let wide = match prog.sc_this_class.get(&b).copied() {
            Some(cls) => prog.sc_made_widely(cls),
            None => false,
        };
        let t = if wide { &inside } else { &all };
        if !t.tainted() {
            continue;
        }
        let bfid = prog.binds[b as usize].fid;
        if !last.as_ref().is_some_and(|l| l.0 == bfid && l.1 == wide) {
            let outer = prog.scope_fns(bfid);
            let v = t.within(&outer);
            last = Some((bfid, wide, outer, v));
        }
        let (_, _, outer, v) = last.as_ref().expect("set above");
        for &key in t.params.iter() {
            let o = super::key_owner(key);
            if mine.contains(&o) && !outer.contains(&o) {
                let k = super::key_index(key);
                if prog.fns[o as usize].sc_mut().param_writes.entry(k).or_default().insert(b) {
                    // (as eval's commit learns one: Eval::commit)
                    if prog.pw_tracked.contains(&(o, k as u32)) {
                        prog.pw_new.push((o, k, b));
                    } else {
                        prog.pw_tracked.insert((o, k as u32));
                        changes.entry(o).or_default().later_first.insert(k);
                    }
                }
            }
        }
        if !v.tainted() && v.kind & super::supply::MARKS == 0 {
            continue;
        }
        let new = match prog.shared.get(&b) {
            None => v.clone(),
            Some(o) if o.covers(v) => {
                continue;
            }
            Some(o) => o.union(v),
        };
        if prog.shared.get(&b) != Some(&new) {
            prog.shared.insert(b, new);
            grown.push(b);
        }
    }
}

/// (the supply-chain model) The kept calls of the functions whose parameter calls grew (Program::pc_changed) run
/// again, each once for all that grew, until no more grow: what they change read again as a reading's changes are.
/// The function whose replay spent the budget, if one did.
fn replays(prog: &mut Program, q: &mut Queue, findings: &mut Vec<Out>) -> Option<FnId> {
    loop {
        let mut todo = std::mem::take(&mut prog.pc_changed);
        if todo.is_empty() {
            return None;
        }
        todo.sort_unstable();
        todo.dedup();
        // (each caller's calls run in one replay of it: (caller, callee, parameter, call))
        let mut jobs: Vec<(FnId, FnId, usize, NodeId)> = Vec::new();
        for &(f, i) in &todo {
            if let Some(sites) = prog.pc_by_callee.get(&f) {
                jobs.extend(sites.iter().map(|&(c, node)| (c, f, i, node)));
            }
        }
        jobs.sort_unstable();
        let mut k = 0;
        while k < jobs.len() {
            let c = jobs[k].0;
            let mut end = k;
            while end < jobs.len() && jobs[end].0 == c {
                end += 1;
            }
            let mut sites: Vec<((FnId, FnId, NodeId), PcSite)> = Vec::new();
            for &(_, f, _, node) in &jobs[k..end] {
                let key = (f, c, node);
                if !sites.iter().any(|(s, _)| *s == key) {
                    if let Some(site) = prog.pc_sites.remove(&key) {
                        sites.push((key, site));
                    }
                }
            }
            let mut ev = Eval::new(prog, c, false, findings);
            ev.replay = true;
            for &(_, f, i, node) in &jobs[k..end] {
                if let Some((_, site)) = sites.iter().find(|(s, _)| *s == (f, c, node)) {
                    ev.cur = site.cur;
                    ev.sc_pc_replay(node, f, i, site);
                }
            }
            let (mut changes, mut grown) = ev.commit();
            for (key, site) in sites {
                prog.pc_sites.insert(key, site);
            }
            pw_carry(prog, &mut changes, &mut grown);
            q.requeue(prog, &changes, &grown);
            if prog.work > prog.budget {
                return Some(c);
            }
            k = end;
        }
    }
}

/// The fixpoint's queue: the functions to read again, by their place in the order (callees first); the supply-chain
/// model's to read again once nothing else is queued (`later`: a round's end); the functions past the cap of readings.
struct Queue {
    heap: BinaryHeap<Reverse<(usize, FnId)>>,
    queued: Vec<bool>,
    later: Vec<FnId>,
    in_later: Vec<bool>,
    pos: Vec<usize>,
    max_iters: u32,
    cutoff: Vec<FnId>,
    /// the place in the order of the function being read (usize::MAX between rounds)
    cur: usize,
    /// (the supply-chain model) a function to read again whose place is not past the one being read waits for the
    /// round's end (`again`)
    rounds: bool,
}

impl Queue {
    /// `d` read again (not past its cap of readings: then it is cut off).
    fn push(&mut self, prog: &Program, d: FnId) {
        if self.queued[d as usize] {
            return;
        }
        if prog.fns[d as usize].runs >= self.max_iters {
            if !self.cutoff.contains(&d) {
                self.cutoff.push(d);
            }
            return;
        }
        self.queued[d as usize] = true;
        self.heap.push(Reverse((self.pos[d as usize], d)));
    }

    /// `d` read again once nothing else is queued.
    fn later(&mut self, d: FnId) {
        if !self.in_later[d as usize] {
            self.in_later[d as usize] = true;
            self.later.push(d);
        }
    }

    /// `d` read again: in this round when its place is past the function being read, else (the supply-chain model) in
    /// the next, once what this round changes is all known (BIG-BUNDLE-TAIL, John's decision of Oct 21: a function
    /// ordered before one it reads, in a recursion or a cycle of calls or shared variables, was read again at once at
    /// each change of each function in it: the busiest of TypeScript's checker 56 times, where rounds read it 8 to 11
    /// times, and the bundle's functions a third fewer times in all).
    fn again(&mut self, prog: &Program, d: FnId) {
        if self.rounds && self.pos[d as usize] <= self.cur {
            self.later(d);
        } else {
            self.push(prog, d);
        }
    }

    /// The functions a reading's (or a replay's) changes and grown bindings ask to read again.
    fn requeue(&mut self, prog: &mut Program, changes: &super::eval::Changes, grown: &[BindId]) {
        for (owner, ch) in changes {
            let callers: Vec<(FnId, Vec<u32>)> = prog.fns[*owner as usize].callers.groups();
            for (c, used) in callers {
                // a caller is read again when what it used changed: request
                // data returned, a parameter it passed a tainted value, a
                // parameter of a function around it returned (what is returned: where a call of it uses that)
                let params = super::meets(&ch.params, &used);
                let outer = ch.outer.iter().any(|&k| prog.scope_fns(c).contains(&super::key_owner(k)));
                if ch.src || params || outer {
                    self.again(prog, c);
                } else if ch.later_all || ch.src_later || super::meets(&ch.later_first, &used) {
                    self.later(c);
                } else if !ch.params.is_empty() || !ch.later_first.is_empty() {
                    // (not read again for it: the reporting pass reads it with the summary as it is then; a change
                    // of what it returns of parameters around it, none around this caller, changes nothing here)
                    prog.fns[c as usize].emits = true;
                }
            }
        }
        let mut grown = grown.to_vec();
        grown.sort_unstable();
        grown.dedup();
        let prog: &Program = prog;
        for bid in &grown {
            let Some(readers) = prog.readers.get(bid) else { continue };
            for &d in readers {
                self.again(prog, d);
            }
        }
    }
}

/// Summaries to a fixpoint, then the reporting pass; the notes.
pub(super) fn fixpoint(prog: &mut Program, findings: &mut Vec<Out>) -> Vec<Out> {
    let mut notes = Vec::new();
    let order = prog.order();
    let n = prog.fns.len();
    let mut pos = vec![0usize; n];
    for (k, &fid) in order.iter().enumerate() {
        pos[fid as usize] = k;
    }
    let heap: BinaryHeap<Reverse<(usize, FnId)>> = order.iter().enumerate().map(|(k, &f)| Reverse((k, f))).collect();
    let queued = vec![true; n];
    let mut cut: Vec<FnId> = Vec::new();
    let mut stopped: Option<FnId> = None;
    let mut stopped_at = [0u64, 0u64];
    // (the supply-chain model answers nothing once a reading is incomplete, a function cut, the cap met, the budget
    // spent: its facts are the text followers' then. So it stops there, rather than read on to a fixpoint and
    // report for nothing: P-17, monaco's TypeScript worker met the cap and read 14 s more)
    let give_up = prog.cfg.supply.is_some();
    // (BIG-BUNDLE-TAIL, the review of Oct 20: a text the supply-chain model does not read whole is SC-TRUNCATED, so
    // its budget is one that reads an ordinary bundle whole: twice the taint pass's a node, at most SUPPLY_WORK_MAX,
    // and a function read again until the budget is spent, not past MAX_ITERS readings: TypeScript's compiler, 6 and
    // 9 MB, met the cap with one function of its checker read 50 times; read in rounds, its busiest needs 11)
    prog.budget = if give_up {
        (WORK_BASE + super::SUPPLY_WORK_PER_NODE * prog.nodes).min(super::SUPPLY_WORK_MAX)
    } else {
        WORK_BASE + WORK_PER_NODE * prog.nodes
    };
    let max_iters = if give_up { super::SUPPLY_MAX_ITERS } else { MAX_ITERS };
    let mut q = Queue { heap, queued, later: Vec::new(), in_later: vec![false; n], pos, max_iters, cutoff: Vec::new(), cur: usize::MAX, rounds: give_up };
    'pass: loop {
        let fid = match q.heap.pop() {
            Some(Reverse((_, f))) => f,
            None => {
                // (the supply-chain model) the calls of functions whose parameter calls grew, run again once the
                // pass has nothing else to read (driver's replays): each call once for all its parameter's growth
                q.cur = usize::MAX;
                if !prog.pc_changed.is_empty() {
                    if let Some(c) = replays(prog, &mut q, findings) {
                        stopped = Some(c);
                        stopped_at[0] = prog.work;
                        break 'pass;
                    }
                    continue;
                }
                // (the supply-chain model) what waited for the pass to have nothing else to read
                if q.later.is_empty() {
                    break;
                }
                for d in std::mem::take(&mut q.later) {
                    if q.in_later[d as usize] {
                        q.in_later[d as usize] = false;
                        q.push(prog, d);
                    }
                }
                continue;
            }
        };
        if give_up && !(cut.is_empty() && q.cutoff.is_empty()) {
            break;
        }
        q.queued[fid as usize] = false;
        q.in_later[fid as usize] = false;
        q.cur = q.pos[fid as usize];
        prog.fns[fid as usize].runs += 1;
        let mut ev = Eval::new(prog, fid, false, findings);
        match ev.run() {
            Ok(()) => {}
            Err(Halt::Cut) => {
                if !cut.contains(&fid) {
                    cut.push(fid);
                }
            }
            Err(Halt::Stop) => {
                stopped = Some(fid);
                stopped_at[0] = ev.p.work;
                break;
            }
        }
        let (mut changes, mut grown) = ev.commit();
        // (the supply-chain model) what callers give parameters written to closure variables, written there
        pw_carry(prog, &mut changes, &mut grown);
        q.requeue(prog, &changes, &grown);
    }
    let cutoff = std::mem::take(&mut q.cutoff);
    // the reporting pass: every function once, in order of definition
    prog.budget = prog.work + WORK_BASE + EMIT_PER_NODE * prog.nodes;
    let mut emit_stopped: Option<FnId> = None;
    let incomplete = stopped.is_some() || !cut.is_empty() || !cutoff.is_empty();
    for fid in 0..(if give_up && incomplete { 0 } else { n as FnId }) {
        // (the supply-chain model: a function whose readings came nowhere near a finding is not read for one)
        if give_up && !prog.fns[fid as usize].emits {
            continue;
        }
        let mut ev = Eval::new(prog, fid, true, findings);
        match ev.run() {
            Ok(()) => {}
            Err(Halt::Cut) => {
                if !cut.contains(&fid) {
                    cut.push(fid);
                }
            }
            Err(Halt::Stop) => {
                emit_stopped = Some(fid);
                stopped_at[1] = ev.p.work;
                break;
            }
        }
    }
    let where_ = |prog: &Program, fid: FnId| -> (PyStr, u32, PyStr) {
        let f = &prog.fns[fid as usize];
        (prog.mods[f.module as usize].path.clone(), f.line, f.display())
    };
    if let Some(&first) = cutoff.iter().min() {
        let (path, line, display) = where_(prog, first);
        let msg = cat_s(&[
            &u(&format!(
                "Interprocedural summaries for {} JavaScript function(s) did not converge within {} re-analyses (first: ",
                cutoff.len(),
                max_iters
            )),
            &display,
            &u(" in "),
            &py_repr(&path),
            &u("); flows through them may be missing."),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-INCOMPLETE",
            name: "Flow analysis incomplete (iteration cap)",
            path,
            line,
            msg,
            why: "Summaries are iterated to a fixpoint with a generous safety cap; hitting it means an unusually long or cyclic chain of calls or shared variables.",
            fix: "Report the pattern to the Lazaret maintainers; split the chain if possible.",
        });
    }
    for (k, f) in [stopped, emit_stopped].into_iter().enumerate() {
        let fid = match f {
            None => continue,
            Some(fid) => fid,
        };
        let (path, line, display) = where_(prog, fid);
        let msg = cat_s(&[
            &u(if k == 1 { "The JavaScript cross-file pass stopped reporting at " } else { "The JavaScript cross-file pass stopped following values at " }),
            &display,
            &u(" in "),
            &py_repr(&path),
            &u(&format!(
                " after {} steps (its budget for {} syntax tree nodes); flows through the rest of the code may be missing.",
                commas(stopped_at[k]),
                commas(prog.nodes)
            )),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-INCOMPLETE",
            name: "Flow analysis incomplete (size budget)",
            path,
            line,
            msg,
            why: WHY_SIZE,
            fix: FIX_SIZE,
        });
    }
    cut.sort_unstable();
    for fid in cut {
        let (path, line, display) = where_(prog, fid);
        let msg = cat_s(&[
            &u("The JavaScript cross-file pass stopped reading "),
            &display,
            &u(" in "),
            &py_repr(&path),
            &u(&format!(
                " at its limit of {} + {} steps per syntax tree node; flows through the rest of it may be missing.",
                commas(prog.cfg.run_base),
                prog.cfg.run_per_node
            )),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-INCOMPLETE",
            name: "Flow analysis incomplete (size budget)",
            path,
            line,
            msg,
            why: "Deeply nested loops make one function's reading repeat; each reading has a limit so a scan cannot run unbounded.",
            fix: "Split the function, or exclude generated code from the scan.",
        });
    }
    notes
}
