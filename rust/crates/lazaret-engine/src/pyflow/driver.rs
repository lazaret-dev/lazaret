//! The pass over a project's Python files (flow._analyze_python): the
//! files read, the pre-pass, the summaries to a fixpoint (callees first; a
//! function is read again when a summary, a class attribute or a module
//! global it used changed), then the reporting pass; and the model's
//! configured part.

use super::eval::{Analyzer, San};
use super::*;
use crate::findings::py_repr;
use crate::jsflow::Out;
use crate::pyre::Regex;
use std::collections::{BTreeMap, VecDeque};

/// The characters of a text a configured pattern sees (taintspec's
/// MAX_MATCH_TEXT).
pub const MAX_MATCH_TEXT: usize = 2000;

fn clip(text: &[u32]) -> &[u32] {
    &text[..text.len().min(MAX_MATCH_TEXT)]
}

fn rx(src: &str, flags: u32) -> Rc<Regex> {
    crate::rxutil::dynamic(pystr::u(src), flags)
}

/// The taint model's configured part (flow.configure's python section) and
/// the pass's limits.
pub struct Config {
    pub extra_sources: Vec<Rc<Regex>>,
    pub extra_sinks: Vec<(Rc<Regex>, u8)>,
    /// configured full sanitizers (call names)
    pub full: Vec<PyStr>,
    /// configured partial sanitizers: call name -> categories (merged per name)
    pub partial: Vec<(PyStr, u8)>,
    pub max_iters: u32,
    pub max_files: usize,
    pub max_bytes: usize,
    /// the fixpoint's budget: base + per node
    pub work: (u64, u64),
    pub emit_per_node: u64,
    /// one reading's limit: base + per node of the function
    pub run: (u64, u64),
    source: Rc<Regex>,
    pub orm: Rc<Regex>,
    py2: Rc<Regex>,
    /// the supply-chain model (supply.rs) instead of project mode's
    pub supply: Option<Rc<super::supply::Supply>>,
}

impl Config {
    /// Patterns that fail to compile match nothing (taintspec refused them
    /// before they got here).
    pub fn new(extra_sources: &[PyStr], extra_sinks: &[(PyStr, u8)], full: &[PyStr], partial: &[(PyStr, u8)]) -> Config {
        let compile = |p: &PyStr| crate::rxutil::dynamic(p.clone(), 0);
        let mut part: Vec<(PyStr, u8)> = Vec::new();
        for (name, bits) in partial {
            match part.iter_mut().find(|(k, _)| k == name) {
                Some(e) => e.1 |= bits,
                None => part.push((name.clone(), *bits)),
            }
        }
        Config {
            extra_sources: extra_sources.iter().map(compile).collect(),
            extra_sinks: extra_sinks.iter().map(|(p, c)| (compile(p), *c)).collect(),
            full: full.to_vec(),
            partial: part,
            max_iters: MAX_ITERS,
            max_files: MAX_FILES,
            max_bytes: MAX_BYTES,
            work: (WORK_BASE, WORK_PER_NODE),
            emit_per_node: EMIT_PER_NODE,
            run: (RUN_BASE, RUN_PER_NODE),
            source: rx(SOURCE_RE, 0),
            orm: rx(ORM_RESULT_RE, 0),
            py2: rx(PY2_PRINT_RE, 8),
            supply: None,
        }
    }

    /// Lower limits (each at most the default: a host can make the pass
    /// cheaper, never longer).
    pub fn with_limits(mut self, max_iters: Option<u32>, max_files: Option<usize>, max_bytes: Option<usize>, work: Option<(u64, u64)>, run: Option<(u64, u64)>) -> Config {
        if let Some(n) = max_iters {
            self.max_iters = n.min(MAX_ITERS);
        }
        if let Some(n) = max_files {
            self.max_files = n.min(MAX_FILES);
        }
        if let Some(n) = max_bytes {
            self.max_bytes = n.min(MAX_BYTES);
        }
        if let Some((b, p)) = work {
            self.work = (b.min(WORK_BASE), p.min(WORK_PER_NODE));
            self.emit_per_node = self.emit_per_node.min(p);
        }
        if let Some((b, p)) = run {
            self.run = (b.min(RUN_BASE), p.min(RUN_PER_NODE));
        }
        self
    }

    /// flow._is_py_source for one text.
    pub fn is_source(&self, s: &[u32]) -> bool {
        !s.is_empty() && (self.source.search(s).is_some() || self.extra_sources.iter().any(|r| r.search(clip(s)).is_some()))
    }

    /// flow._py_config_sink: the first configured sink a text matches.
    pub fn config_sink(&self, names: &[&[u32]]) -> Option<u8> {
        for (pat, cat) in &self.extra_sinks {
            for s in names {
                if !s.is_empty() && pat.search(clip(s)).is_some() {
                    return Some(*cat);
                }
            }
        }
        None
    }

    fn is_full(&self, s: &[u32]) -> bool {
        is_in(s, FULL_SANITIZERS) || self.full.iter().any(|f| f.as_slice() == s)
    }

    /// flow._py_config_sanitizer: from the configuration only.
    pub fn config_sanitizer(&self, names: &[&[u32]]) -> Option<San> {
        for callee in names {
            if callee.is_empty() {
                continue;
            }
            if self.full.iter().any(|f| f.as_slice() == *callee) && !is_in(callee, FULL_SANITIZERS) {
                return Some(San::Full);
            }
            if let Some((_, cats)) = self.partial.iter().find(|(k, _)| k.as_slice() == *callee) {
                return Some(San::Partial(*cats));
            }
        }
        None
    }

    /// flow._py_builtin_sanitizer.
    pub fn builtin_sanitizer(&self, names: &[&[u32]]) -> Option<San> {
        for callee in names {
            if callee.is_empty() {
                continue;
            }
            let last = last_part(callee);
            if self.is_full(callee) || self.is_full(last) {
                return Some(San::Full);
            }
            if let Some((_, cats)) = PARTIAL_SANITIZERS.iter().find(|(k, _)| pystr::eq(callee, k)) {
                return Some(San::Partial(*cats));
            }
            if let Some((_, cats)) = PARTIAL_SANITIZERS.iter().find(|(k, _)| pystr::eq(last, k)) {
                return Some(San::Partial(*cats));
            }
            if let Some((_, cats)) = self.partial.iter().find(|(k, _)| k.as_slice() == *callee) {
                return Some(San::Partial(*cats));
            }
            if let Some((_, cats)) = self.partial.iter().find(|(k, _)| k.as_slice() == last) {
                return Some(San::Partial(*cats));
            }
            if pystr::starts_with(last, "escape") {
                return Some(San::Partial(bit(XSS)));
            }
        }
        None
    }
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

/// Python's recursion limit reached in `f`: its file's note names the
/// first line of the functions it stopped (flow.py's overflow dict).
fn note_overflow(p: &Project, overflow: &mut BTreeMap<PyStr, u32>, f: FnId) {
    let func = &p.fns[f as usize];
    let path = p.mods[func.module as usize].path.clone();
    let e = overflow.entry(path).or_insert(1 << 30);
    *e = (*e).min(func.line);
}

/// One reading of `f` and its commit (flow._analyze_python's guarded):
/// (summary changed, class attributes changed, globals changed).
fn read(p: &mut Project, findings: &mut Vec<Out>, overflow: &mut BTreeMap<PyStr, u32>, cut: &mut Vec<FnId>, f: FnId, emit: bool) -> (bool, bool, bool) {
    p.frames = 0;
    let mut a = Analyzer::new(p, f, emit, findings);
    let r = a.run();
    let out = match r {
        Ok(()) => a.commit(),
        Err(Halt::Cut) => {
            let c = a.commit();
            if !cut.contains(&f) {
                cut.push(f);
            }
            c
        }
        Err(_) => (false, false, false),
    };
    drop(a);
    if r == Err(Halt::Overflow) {
        note_overflow(p, overflow, f);
    }
    p.frames = 0;
    out
}

const WHY_SIZE: &str = "Every file is read within a budget proportional to its size, so a scan cannot run unbounded.";
const FIX_SIZE: &str = "Split or deminify very large or deeply nested files, or exclude generated code from the scan.";

/// The cross-file Python pass over `files` (path, content: the project's
/// own Python, no dependencies; None: a file whose content is not text).
pub fn analyze(files: &[(PyStr, Option<PyStr>)], cfg: Config) -> Vec<Out> {
    let cfg = Rc::new(cfg);
    let mut p = Project::new(cfg.clone());
    let mut findings: Vec<Out> = Vec::new();
    let mut overflow: BTreeMap<PyStr, u32> = BTreeMap::new();
    let mut skipped: BTreeMap<PyStr, PyStr> = BTreeMap::new();
    let mut notes: Vec<Out> = Vec::new();
    let mut total = 0usize;
    let mut over: Vec<PyStr> = Vec::new();
    for (k, (path, content)) in files.iter().enumerate() {
        let size = content.as_ref().map(|c| c.len()).unwrap_or(0);
        if p.mods.len() >= cfg.max_files || total + size > cfg.max_bytes {
            over.push(path.clone());
            continue;
        }
        let content = match content {
            None => {
                skipped.insert(path.clone(), pystr::u("content is not text"));
                continue;
            }
            Some(c) => c,
        };
        match crate::pyparse::parse(content) {
            Ok(tree) => {
                total += size;
                if !p.add_module(k as u32, path, content, tree) {
                    overflow.insert(path.clone(), 1);
                }
            }
            Err(e) => {
                let r = &e.reason;
                if e.line == 0 && (r.starts_with("too complex") || r.starts_with("maximum recursion depth")) {
                    overflow.insert(path.clone(), 1);
                } else if r.to_lowercase().contains("null bytes") {
                    skipped.insert(path.clone(), pystr::u("it contains NUL bytes"));
                } else if r.starts_with("source code cannot hold") {
                    skipped.insert(path.clone(), pystr::u("it could not be parsed (UnicodeEncodeError)"));
                } else if r.contains("Missing parentheses in call to 'print'")
                    || r.contains("Missing parentheses in call to 'exec'")
                    || cfg.py2.search(content).is_some()
                {
                    skipped.insert(path.clone(), pystr::u("it looks like Python 2 source"));
                } else {
                    skipped.insert(path.clone(), pystr::u(&format!("syntax error at line {}", e.line)));
                }
            }
        }
    }
    if let Some(first) = over.first() {
        let msg = cat_s(&[
            &pystr::u(&format!(
                "Cross-file taint analysis skipped {} Python file(s) beyond its budget ({} files / {} characters), starting with ",
                over.len(),
                cfg.max_files,
                commas(cfg.max_bytes as u64)
            )),
            &py_repr(first),
            &pystr::u("."),
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

    let funcs: Vec<FnId> = p.mods.iter().flat_map(|m| m.all_funcs.iter().copied()).collect();
    // (the pre-pass is paid from the fixpoint's budget: past it, the
    // fixpoint stops before its first reading)
    p.budget = cfg.work.0 + cfg.work.1 * p.nodes;
    for &f in &funcs {
        p.frames = 0;
        match p.prepass(f) {
            Ok(()) => {}
            Err(Halt::Stop) => break,
            Err(_) => note_overflow(&p, &mut overflow, f),
        }
    }
    p.frames = 0;

    // callee-first order (iterative DFS post-order), then a worklist
    let n = p.fns.len();
    let mut order: Vec<FnId> = Vec::with_capacity(n);
    let mut seen = vec![false; n];
    for &root in &funcs {
        if seen[root as usize] {
            continue;
        }
        seen[root as usize] = true;
        let mut stack: Vec<(FnId, usize)> = vec![(root, 0)];
        while let Some(&mut (node, ref mut i)) = stack.last_mut() {
            let next = p.fns[node as usize].callees.get(*i).copied();
            *i += 1;
            match next {
                None => {
                    stack.pop();
                    order.push(node);
                }
                Some(x) => {
                    if !seen[x as usize] {
                        seen[x as usize] = true;
                        stack.push((x, 0));
                    }
                }
            }
        }
    }
    let mut queue: VecDeque<FnId> = order.iter().copied().collect();
    let mut queued = vec![false; n];
    for &f in &order {
        queued[f as usize] = true;
    }
    let mut cutoff: Vec<FnId> = Vec::new();
    let mut cut: Vec<FnId> = Vec::new();
    p.budget = cfg.work.0 + cfg.work.1 * p.nodes;
    let mut stopped: Option<(FnId, u64)> = None;


    while let Some(&f) = queue.front() {
        if p.work > p.budget {
            stopped = Some((f, p.work));
            break;
        }
        queue.pop_front();
        queued[f as usize] = false;
        p.fns[f as usize].runs += 1;
        let (changed, cls_changed, glob_changed) = read(&mut p, &mut findings, &mut overflow, &mut cut, f, false);
        let mut deps: Vec<FnId> = Vec::new();
        let mut dset: QuickSet<FnId> = QuickSet::default();
        let mut add = |d: FnId, deps: &mut Vec<FnId>| {
            if dset.insert(d) {
                deps.push(d);
            }
        };
        if changed {
            for &c in &p.fns[f as usize].callers {
                add(c, &mut deps);
            }
        }
        if cls_changed {
            if let Some(c0) = p.fns[f as usize].cls {
                let mut stack = vec![c0];
                let mut seen_c: QuickSet<ClsId> = QuickSet::default();
                while let Some(c) = stack.pop() {
                    if !seen_c.insert(c) {
                        continue;
                    }
                    for &(_, m) in &p.classes[c as usize].methods {
                        add(m, &mut deps);
                    }
                    stack.extend(p.classes[c as usize].subclasses.iter().copied());
                }
            }
        }
        if glob_changed {
            let m = p.fns[f as usize].module;
            for &g in &p.mods[m as usize].all_funcs {
                add(g, &mut deps);
            }
        }
        for d in deps {
            if queued[d as usize] {
                continue;
            }
            if p.fns[d as usize].runs >= cfg.max_iters {
                cutoff.push(d);
                continue;
            }
            queue.push_back(d);
            queued[d as usize] = true;
        }
    }
    let where_ = |p: &Project, f: FnId| -> (PyStr, u32, PyStr) {
        let func = &p.fns[f as usize];
        (p.mods[func.module as usize].path.clone(), func.line, p.qualname(f))
    };
    if !cutoff.is_empty() {
        let first = *cutoff
            .iter()
            .min_by(|&&x, &&y| {
                let (px, lx, _) = where_(&p, x);
                let (py, ly, _) = where_(&p, y);
                (px, lx).cmp(&(py, ly))
            })
            .unwrap_or(&cutoff[0]);
        let (path, line, qual) = where_(&p, first);
        let msg = cat_s(&[
            &pystr::u(&format!(
                "Interprocedural summaries for {} function(s) did not converge within {} re-analyses (first: ",
                cutoff.len(),
                cfg.max_iters
            )),
            &qual,
            &pystr::u("() in "),
            &py_repr(&path),
            &pystr::u("); flows through them may be missing."),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-INCOMPLETE",
            name: "Flow analysis incomplete (iteration cap)",
            path,
            line,
            msg,
            why: "Summaries are iterated to a fixpoint with a generous safety cap; hitting it means an unusually long or cyclic call chain.",
            fix: "Report the pattern to the Lazaret maintainers; split the chain if possible.",
        });
    }
    // the reporting pass
    p.budget = p.work + cfg.work.0 + cfg.emit_per_node * p.nodes;
    let mut emit_stopped: Option<(FnId, u64)> = None;
    for k in 0..order.len() {
        let f = order[k];
        read(&mut p, &mut findings, &mut overflow, &mut cut, f, true);
        if p.work > p.budget && k + 1 < order.len() {
            emit_stopped = Some((order[k + 1], p.work));
            break;
        }
    }
    for (k, s) in [stopped, emit_stopped].into_iter().enumerate() {
        let (f, steps) = match s {
            None => continue,
            Some(x) => x,
        };
        let (path, line, qual) = where_(&p, f);
        let msg = cat_s(&[
            &pystr::u(if k == 1 {
                "The Python cross-file pass stopped reporting at "
            } else {
                "The Python cross-file pass stopped following values at "
            }),
            &qual,
            &pystr::u("() in "),
            &py_repr(&path),
            &pystr::u(&format!(
                " after {} steps (its budget for {} syntax tree nodes); flows through the rest of the code may be missing.",
                commas(steps),
                commas(p.nodes)
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
    for f in cut {
        let (path, line, qual) = where_(&p, f);
        let msg = cat_s(&[
            &pystr::u("The Python cross-file pass stopped reading "),
            &qual,
            &pystr::u("() in "),
            &py_repr(&path),
            &pystr::u(&format!(
                " at its limit of {} + {} steps per syntax tree node; flows through the rest of it may be missing.",
                commas(cfg.run.0),
                cfg.run.1
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
    for (path, line) in &overflow {
        let msg = cat_s(&[
            &pystr::u("Lazaret's flow pass hit Python's parser/recursion limit while analyzing "),
            &py_repr(path),
            &pystr::u(" — findings for the affected function(s) may be missing; every other function was still analyzed."),
        ]);
        notes.push(Out::Note {
            rule: "Q-FLOW-RECURSION",
            name: "Flow analysis incomplete (recursion cutoff)",
            path: path.clone(),
            line: *line,
            msg,
            why: "A pathologically deep expression (e.g. a long operator chain in generated code) can overflow Python's parser or the analysis stack even though it is valid Python. Lazaret skips only the affected function(s), or the file if the parser overflowed, instead of crashing the whole scan.",
            fix: "Split or format the flagged file to keep expressions shallow, then re-run Lazaret.",
        });
    }
    for (path, why) in &skipped {
        let msg = cat_s(&[&pystr::u("Cross-file taint analysis skipped "), &py_repr(path), &pystr::u(": "), why, &pystr::u(".")]);
        notes.push(Out::Note {
            rule: "Q-FLOW-SKIPPED",
            name: "File skipped by flow analysis",
            path: path.clone(),
            line: 1,
            msg,
            why: "Only files Python 3 can parse take part in the interprocedural pass; flows into or out of this file are not seen (the per-file rules still ran).",
            fix: "Fix the syntax error (or port the file to Python 3), then re-run.",
        });
    }
    findings.extend(notes);
    findings
}
