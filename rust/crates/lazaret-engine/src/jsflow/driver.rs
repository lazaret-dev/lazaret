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

/// Summaries to a fixpoint, then the reporting pass; the notes.
pub(super) fn fixpoint(prog: &mut Program, findings: &mut Vec<Out>) -> Vec<Out> {
    let mut notes = Vec::new();
    let order = prog.order();
    let n = prog.fns.len();
    let mut pos = vec![0usize; n];
    for (k, &fid) in order.iter().enumerate() {
        pos[fid as usize] = k;
    }
    let mut heap: BinaryHeap<Reverse<(usize, FnId)>> = order.iter().enumerate().map(|(k, &f)| Reverse((k, f))).collect();
    let mut queued = vec![true; n];
    let mut cutoff: Vec<FnId> = Vec::new();
    let mut cut: Vec<FnId> = Vec::new();
    prog.budget = WORK_BASE + WORK_PER_NODE * prog.nodes;
    let mut stopped: Option<FnId> = None;
    let mut stopped_at = [0u64, 0u64];
    while let Some(Reverse((_, fid))) = heap.pop() {
        queued[fid as usize] = false;
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
        let (changes, grown) = ev.commit();
        let mut deps: Vec<FnId> = Vec::new();
        for (owner, (src, params, outer)) in &changes {
            let callers: Vec<(FnId, BTreeSet<usize>)> =
                prog.fns[*owner as usize].callers.iter().map(|(c, u)| (*c, u.clone())).collect();
            for (c, used) in callers {
                // a caller is read again when what it used changed: request
                // data returned, a parameter it passed a tainted value, a
                // parameter of a function around it returned
                let hit = *src
                    || !params.is_disjoint(&used)
                    || outer.iter().any(|&k| prog.scope_fns(c).contains(&((k / PARAM_BASE) as FnId)));
                if hit {
                    deps.push(c);
                }
            }
        }
        for bid in grown {
            if let Some(r) = prog.readers.get(&bid) {
                deps.extend(r.iter().copied());
            }
        }
        for d in deps {
            if queued[d as usize] {
                continue;
            }
            if prog.fns[d as usize].runs >= MAX_ITERS {
                if !cutoff.contains(&d) {
                    cutoff.push(d);
                }
                continue;
            }
            queued[d as usize] = true;
            heap.push(Reverse((pos[d as usize], d)));
        }
    }
    // the reporting pass: every function once, in order of definition
    prog.budget = prog.work + WORK_BASE + EMIT_PER_NODE * prog.nodes;
    let mut emit_stopped: Option<FnId> = None;
    for fid in 0..n as FnId {
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
                MAX_ITERS
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
