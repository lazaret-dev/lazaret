//! `linre`: a regular expression engine that never backtracks.
//!
//! It runs Python's `re` syntax (str patterns) with Python's answers — the
//! same match, the same span, the same groups, for search, match, fullmatch
//! and finditer — in time linear in the text: work proportional to the
//! text's length times the pattern's size, whatever the text holds. What it
//! cannot run that way it refuses when the pattern is compiled, saying why
//! (hir.rs): backreferences, lookaheads of unbounded width, and a few
//! constructs whose sre semantics a linear matcher does not reproduce.
//!
//! The pieces: syntax.rs (the parser), hir.rs (flags resolved, character
//! sets, refusals), charset.rs (sets of code points; case folding as re
//! compiles it), nfa.rs (programs: Thompson automata ordered by priority),
//! looks.rs (zero-width tests and bounded lookarounds), dfa.rs (lazy DFAs:
//! where a match ends, and from there where it starts), backtrack.rs (sre's
//! path for the groups, never visiting a state at a position twice), pike.rs
//! (the Pike VM, with captures: the fallback), literal.rs and prefilter.rs
//! (where a search need not look).
//!
//! It is written for the engine's patterns (the rule pack's), as their
//! linear-time replacement for `pyre`; the engine does not use it yet
//! (`linre.probe` and `linre.check` call it; docs/RUST_ENGINE.md §13).

pub mod backtrack;
pub mod charset;
pub mod dfa;
pub mod hir;
pub mod literal;
pub mod looks;
pub mod nfa;
pub mod pike;
pub mod prefilter;
pub mod syntax;

use dfa::{DfaCache, DfaShape, Skip};
use nfa::Programs;
use pike::{PikeCache, Want};
use std::sync::{Arc, Mutex};

pub use syntax::{
    FLAG_ASCII as ASCII, FLAG_DOTALL as DOTALL, FLAG_IGNORECASE as IGNORECASE, FLAG_MULTILINE as MULTILINE,
    FLAG_UNICODE as UNICODE, FLAG_VERBOSE as VERBOSE,
};

/// Why a pattern did not compile: Python rejects it (`refused` false), or
/// linre does not run it (`refused` true, with the reason).
#[derive(Clone, Debug)]
pub struct Error {
    pub refused: bool,
    pub msg: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.refused {
            write!(f, "refused: {}", self.msg)
        } else {
            write!(f, "error: {}", self.msg)
        }
    }
}

impl From<syntax::Error> for Error {
    fn from(e: syntax::Error) -> Error {
        match e {
            syntax::Error::Syntax(m) => Error { refused: false, msg: m },
            syntax::Error::Refused(m) => Error { refused: true, msg: m },
        }
    }
}

/// Flags from re's letters: i m s x a u.
pub fn flags_from_letters(letters: &str) -> u32 {
    let mut f = 0;
    for c in letters.chars() {
        f |= match c {
            'i' | 'I' => syntax::FLAG_IGNORECASE,
            'm' | 'M' => syntax::FLAG_MULTILINE,
            's' | 'S' => syntax::FLAG_DOTALL,
            'x' | 'X' => syntax::FLAG_VERBOSE,
            'a' | 'A' => syntax::FLAG_ASCII,
            'u' | 'U' => syntax::FLAG_UNICODE,
            _ => 0,
        };
    }
    f
}

struct Cache {
    pike: PikeCache,
    bt: backtrack::Backtracker,
    fwd: DfaCache,
    full: DfaCache,
    rev: DfaCache,
    /// places a search tried, and those that matched
    tries: u32,
    hits: u32,
}

impl Cache {
    fn new() -> Cache {
        Cache {
            pike: PikeCache::new(),
            bt: backtrack::Backtracker::new(),
            fwd: DfaCache::new(),
            full: DfaCache::new(),
            rev: DfaCache::new(),
            tries: 0,
            hits: 0,
        }
    }
}

struct Inner {
    pattern: Vec<u32>,
    flags: u32,
    groups: usize,
    names: Vec<(Vec<u32>, usize)>,
    progs: Programs,
    shape: DfaShape,
    /// every match's length, when they all have the same
    fixed: Option<usize>,
    /// where a match can start: a scan for the next such position
    first: Option<prefilter::FirstChars>,
    /// the strings every match starts with, when worth a scan
    lead: Option<literal::LitSet>,
    /// strings one of which every match holds
    need: Option<literal::LitSet>,
    /// one character of a set, or a run of them: answered by a scan
    simple: Option<prefilter::Simple>,
    /// matcher buffers, reused across searches (one per thread at a time;
    /// boxed, so taking one out moves a pointer)
    #[allow(clippy::vec_box)]
    pool: Mutex<Vec<Box<Cache>>>,
}

/// A compiled pattern.
#[derive(Clone)]
pub struct Regex {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Regex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linre::Regex({:?})", crate::pystr::to_string(&self.inner.pattern))
    }
}

/// What a compile says about a pattern (for `linre.check`).
#[derive(Clone, Debug)]
pub struct Info {
    /// instructions of the forward program (counted repeats expanded)
    pub insts: usize,
    /// lookarounds of more than one character
    pub lookarounds: usize,
    pub groups: usize,
    /// strings one of which every match holds
    pub need: Option<String>,
    /// strings every match starts with (a scan for them finds where to try)
    pub lead: Option<String>,
    /// a set of first characters is scanned for instead
    pub first: bool,
    /// answered by a scan alone (one character of a set, or a run)
    pub simple: bool,
}

/// How a search is anchored and what it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Search,
    Match,
    Full,
}


impl Regex {
    /// re.compile(pattern, flags) for a str pattern.
    pub fn new(pattern: &[u32], flags: u32) -> Result<Regex, Error> {
        let parsed = syntax::parse(pattern, flags)?;
        let lowered = hir::lower(&parsed)?;
        let fixed = match hir::width(&lowered.hir) {
            (lo, Some(hi)) if lo == hi && lo <= usize::MAX as u64 => Some(lo as usize),
            _ => None,
        };
        let simple = if parsed.groups == 0 { prefilter::Simple::of(&lowered.hir, &lowered.sets) } else { None };
        let an = literal::Analysis { sets: &lowered.sets };
        let need_lits = an.need(&lowered.hir).filter(|l| l.iter().all(|s| s.len() >= 2));
        let lead_lits = an.prefix(&lowered.hir).filter(|l| l.iter().all(|s| !s.is_empty()));
        let progs = nfa::compile(&lowered.hir, lowered.sets.clone(), &lowered.looks, parsed.groups)?;
        let shape = DfaShape::new(&progs);
        // (the scan for a lead's strings finds more false starts the more
        // common their characters are; it beats the DFA up to a point, and
        // further for a large program, whose DFA states cost most to build)
        let dense = if progs.fwd.insts.len() > 2000 { 200 } else { 100 };
        let lead = lead_lits
            .as_ref()
            .and_then(|l| literal::LitSet::new(l))
            .filter(|l| l.density <= dense && (l.shortest() >= 2 || l.density <= 12));
        // (a lead scan already finds nothing in a text without its own strings)
        let need = match (&lead, &need_lits) {
            (Some(_), Some(n)) if Some(n) == lead_lits.as_ref() => None,
            (_, Some(n)) => literal::LitSet::new(n).filter(|n| n.density <= 150),
            _ => None,
        };
        let first = if lead.is_some() {
            None
        } else {
            prefilter::first_set(&progs, &progs.fwd).and_then(|s| prefilter::FirstChars::new(&s))
        };
        Ok(Regex {
            inner: Arc::new(Inner {
                pattern: pattern.to_vec(),
                flags: parsed.flags,
                groups: parsed.groups,
                names: parsed.names,
                progs,
                shape,
                fixed,
                first,
                lead,
                need,
                simple,
                pool: Mutex::new(Vec::new()),
            }),
        })
    }

    /// re.compile of a Rust string's code points.
    pub fn compile(pattern: &str, flags: u32) -> Result<Regex, Error> {
        let cps: Vec<u32> = pattern.chars().map(|c| c as u32).collect();
        Regex::new(&cps, flags)
    }

    pub fn pattern(&self) -> &[u32] {
        &self.inner.pattern
    }

    /// Python's `pattern.flags` (UNICODE included).
    pub fn flags(&self) -> u32 {
        self.inner.flags
    }

    pub fn groups(&self) -> usize {
        self.inner.groups
    }

    pub fn info(&self) -> Info {
        let i = &*self.inner;
        let p = &i.progs;
        Info {
            insts: p.fwd.insts.len(),
            lookarounds: p.subs.len(),
            groups: i.groups,
            need: i.need.as_ref().map(|n| n.describe()),
            lead: i.lead.as_ref().map(|n| n.describe()),
            first: i.first.is_some(),
            simple: i.simple.is_some(),
        }
    }

    /// The group number of a named group.
    pub fn group_index(&self, name: &str) -> Option<usize> {
        let n: Vec<u32> = name.chars().map(|c| c as u32).collect();
        self.inner.names.iter().find(|(k, _)| *k == n).map(|&(_, g)| g)
    }

    fn with_cache<T>(&self, f: impl FnOnce(&mut Cache) -> T) -> T {
        let taken = self.inner.pool.lock().ok().and_then(|mut p| p.pop());
        let mut cache = taken.unwrap_or_else(|| Box::new(Cache::new()));
        let out = f(&mut cache);
        if let Ok(mut p) = self.inner.pool.lock() {
            if p.len() < 8 {
                p.push(cache);
            }
        }
        out
    }

    /// (start, end) of a window as sre clamps it.
    fn clamp(s: &[u32], pos: isize, endpos: isize) -> (usize, usize) {
        let n = s.len() as isize;
        (pos.clamp(0, n) as usize, endpos.clamp(0, n) as usize)
    }

    /// The match in s[start..end] for `mode`: its slots and end.
    ///
    /// The DFAs find where sre's match ends and starts; the backtracker (or,
    /// for a long span, the Pike VM) then finds its groups on that span
    /// only. A match or fullmatch starts at `start`. A search whose matches
    /// can only start at places a scan finds (one of the strings every match
    /// starts with, a character a match starts with) tries the anchored DFA
    /// at each such place in turn — the first that matches is the leftmost —
    /// while the characters its failed tries read stay within a budget that
    /// grows with the distance covered; past it, and for any other search,
    /// the unanchored DFA finds the end and the reverse DFA the start. The
    /// Pike VM answers whatever the DFAs give up on, and a match whose start
    /// lies past the window's end.
    fn find(&self, s: &[u32], start: usize, end: usize, mode: Mode, must_advance: bool) -> Option<(Vec<isize>, usize)> {
        if mode == Mode::Search && start > end {
            return None;
        }
        let inner = &*self.inner;
        let p = &inner.progs;
        if let Some(sm) = &inner.simple {
            if let Some(span) = sm.span(s, start, end, mode != Mode::Search, mode == Mode::Full, must_advance) {
                return span.map(|(a, b)| {
                    let mut slots = vec![-1isize; p.slots];
                    slots[p.slots - 1] = a as isize;
                    (slots, b)
                });
            }
        }
        self.with_cache(|c| {
            if start <= end && inner.shape.usable {
                let r = match mode {
                    Mode::Search => self.search_dfa(s, start, end, must_advance, c),
                    _ => self.anchored_dfa(s, start, end, mode, c),
                };
                if let Ok(found) = r {
                    return found;
                }
            }
            let (prog, anchored) = match mode {
                Mode::Search => (&p.fwd, false),
                Mode::Match => (&p.fwd, true),
                Mode::Full => (&p.full, true),
            };
            pike::search(p, prog, s, start, end, Want { anchored, must_advance, end_at: None }, &mut c.pike)
        })
    }

    fn skip(&self) -> Option<&dyn Skip> {
        match (&self.inner.lead, &self.inner.first) {
            (Some(l), _) => Some(l as &dyn Skip),
            (None, Some(f)) => Some(f as &dyn Skip),
            _ => None,
        }
    }

    /// match / fullmatch: the anchored DFA from `start`.
    fn anchored_dfa(&self, s: &[u32], start: usize, end: usize, mode: Mode, c: &mut Cache) -> Result<Option<(Vec<isize>, usize)>, dfa::GiveUp> {
        let inner = &*self.inner;
        let p = &inner.progs;
        let (prog, cache) = match mode {
            Mode::Full => (&p.full, &mut c.full),
            _ => (&p.fwd, &mut c.fwd),
        };
        let mut reached = start;
        match dfa::forward(&inner.shape, p, prog, cache, s, start, end, true, false, self.skip(), &mut c.pike.oracle, &mut reached)? {
            None => Ok(None),
            Some(f) => self.with_groups(prog, s, start, f.end, end, c),
        }
    }

    /// search: at the places a match may start (anchored, within a budget),
    /// then by the unanchored and reverse DFAs.
    fn search_dfa(&self, s: &[u32], start: usize, end: usize, must_advance: bool, c: &mut Cache) -> Result<Option<(Vec<isize>, usize)>, dfa::GiveUp> {
        let inner = &*self.inner;
        let p = &inner.progs;
        let shape = &inner.shape;
        if let Some(n) = &inner.need {
            if !n.occurs(s, start, end) {
                return Ok(None);
            }
        }
        if let Some(l) = &inner.lead {
            // (the text gate may say at once that none of them is in the text)
            if l.gated_out(s, start, end) {
                return Ok(None);
            }
        }
        let skip = self.skip();
        let mut from = start;
        if let Some(k) = skip {
            // (each try is the backtracker's or the anchored DFA's: the
            // backtracker's while the DFA has no states yet (the first
            // tries), and then while most tries match — a failed try costs
            // it more than the DFA — for a pattern whose counted repeats make
            // the DFA's program large (it runs a repeat of one set as one
            // step) or that has groups (one pass instead of the DFA's and
            // then the groups'); the DFA's otherwise)
            let heavy = p.fwd.insts.len() > 2 * p.fwd_bt.insts.len() + 64;
            let counters = c.tries < 16 || ((heavy || inner.groups > 0) && c.hits * 2 >= c.tries);
            let m = if counters { p.fwd_bt.insts.len() } else { p.fwd.insts.len() };
            let mut spent = 0usize;
            let mut at = start;
            loop {
                let q = match k.next(s, at, end) {
                    None => return Ok(None),
                    Some(q) => q,
                };
                let budget = (8 * (q - start) + 4 * m + 256).saturating_sub(spent);
                if budget == 0 {
                    from = q;
                    break;
                }
                let no_empty = must_advance && q == start;
                c.tries = c.tries.saturating_add(1);
                if counters {
                    match backtrack::anchored(p, &p.fwd_bt, s, q, end, no_empty, budget, &mut c.bt, &mut c.pike.oracle, &mut spent) {
                        Ok(Some(found)) => {
                            c.hits = c.hits.saturating_add(1);
                            return Ok(Some(found));
                        }
                        Ok(None) => at = q + 1,
                        Err(_) => {
                            from = q;
                            break;
                        }
                    }
                    continue;
                }
                let mut reached = q;
                match dfa::forward(shape, p, &p.fwd, &mut c.fwd, s, q, end, true, no_empty, skip, &mut c.pike.oracle, &mut reached)? {
                    Some(f) => {
                        c.hits = c.hits.saturating_add(1);
                        return self.with_groups(&p.fwd, s, q, f.end, end, c);
                    }
                    None => {
                        spent += reached - q + 1;
                        at = q + 1;
                    }
                }
            }
        }
        let must_advance = must_advance && from == start;
        let mut reached = from;
        let found = match dfa::forward(shape, p, &p.fwd, &mut c.fwd, s, from, end, false, must_advance, skip, &mut c.pike.oracle, &mut reached)? {
            None => return Ok(None),
            Some(f) => f,
        };
        let e = found.end;
        let first = if let Some(w) = inner.fixed {
            e - w
        } else {
            match dfa::reverse(shape, p, &p.rev, &mut c.rev, s, found.lower.max(from), e, end, &mut c.pike.oracle)? {
                Some(f) => f,
                None => return Err(dfa::GiveUp),
            }
        };
        self.with_groups(&p.fwd, s, first, e, end, c)
    }

    /// The slots of sre's match text[from..e] (its groups searched for on
    /// that span).
    fn with_groups(&self, prog: &nfa::Prog, s: &[u32], from: usize, e: usize, end: usize, c: &mut Cache) -> Result<Option<(Vec<isize>, usize)>, dfa::GiveUp> {
        let p = &self.inner.progs;
        if self.inner.groups == 0 {
            let mut slots = vec![-1isize; p.slots];
            slots[p.slots - 1] = from as isize;
            return Ok(Some((slots, e)));
        }
        // (the backtracker's own program: repeats of one set as runs)
        let bt_prog = if std::ptr::eq(prog, &p.full) { &p.full_bt } else { &p.fwd_bt };
        if backtrack::fits(bt_prog, e - from) {
            return match backtrack::groups(p, bt_prog, s, from, e, end, &mut c.bt, &mut c.pike.oracle) {
                Some(slots) => Ok(Some((slots, e))),
                None => Err(dfa::GiveUp),
            };
        }
        let want = Want { anchored: true, must_advance: false, end_at: Some(e) };
        match pike::search(p, prog, s, from, end, want, &mut c.pike) {
            Some(m) => Ok(Some(m)),
            None => Err(dfa::GiveUp),
        }
    }

    fn make_match<'s>(&'s self, s: &'s [u32], found: (Vec<isize>, usize), pos: usize, endpos: usize) -> Match<'s> {
        let (slots, end) = found;
        let g = self.inner.groups;
        let mut marks = vec![-1isize; 2 * (g + 1)];
        marks[0] = slots[2 * g + 1];
        marks[1] = end as isize;
        for k in 0..g {
            let (a, b) = (slots[2 * k], slots[2 * k + 1]);
            if a >= 0 && b >= 0 {
                marks[2 * k + 2] = a;
                marks[2 * k + 3] = b;
            }
        }
        Match { s, re: self, marks, pos, endpos, lastindex: slots[2 * g] }
    }

    /// pattern.search(s, pos, endpos)
    pub fn search_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        let (a, b) = Self::clamp(s, pos, endpos);
        self.find(s, a, b, Mode::Search, false).map(|f| self.make_match(s, f, a, b))
    }

    pub fn search<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.search_at(s, 0, s.len() as isize)
    }

    pub fn is_match(&self, s: &[u32]) -> bool {
        self.find(s, 0, s.len(), Mode::Search, false).is_some()
    }

    /// pattern.match(s, pos, endpos)
    pub fn match_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        let (a, b) = Self::clamp(s, pos, endpos);
        self.find(s, a, b, Mode::Match, false).map(|f| self.make_match(s, f, a, b))
    }

    pub fn match_<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.match_at(s, 0, s.len() as isize)
    }

    /// pattern.fullmatch(s, pos, endpos)
    pub fn fullmatch_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        let (a, b) = Self::clamp(s, pos, endpos);
        self.find(s, a, b, Mode::Full, false).map(|f| self.make_match(s, f, a, b))
    }

    pub fn fullmatch<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.fullmatch_at(s, 0, s.len() as isize)
    }

    /// pattern.finditer(s, pos, endpos)
    pub fn finditer_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> FindIter<'s> {
        let (a, b) = Self::clamp(s, pos, endpos);
        FindIter { re: self, s, at: a, pos: a, end: b, must_advance: false, done: false }
    }

    pub fn finditer<'s>(&'s self, s: &'s [u32]) -> FindIter<'s> {
        self.finditer_at(s, 0, s.len() as isize)
    }

    /// pattern.sub(f, s, count) with a function.
    pub fn sub_fn<'s>(&'s self, s: &'s [u32], count: usize, mut f: impl FnMut(&Match<'s>) -> Vec<u32>) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::with_capacity(s.len());
        let mut i = 0usize;
        for (n, m) in self.finditer(s).enumerate() {
            if count != 0 && n >= count {
                break;
            }
            if i < m.start() {
                out.extend_from_slice(&s[i..m.start()]);
            }
            out.extend(f(&m));
            i = m.end();
        }
        if i < s.len() {
            out.extend_from_slice(&s[i..]);
        }
        out
    }

    /// pattern.split(s, maxsplit): the pieces between matches, with the
    /// groups (None: a group that did not take part) in between.
    pub fn split<'s>(&'s self, s: &'s [u32], maxsplit: usize) -> Vec<Option<&'s [u32]>> {
        let mut out = Vec::new();
        let mut last = 0usize;
        for (n, m) in self.finditer(s).enumerate() {
            if maxsplit != 0 && n >= maxsplit {
                break;
            }
            out.push(Some(&s[last..m.start()]));
            for g in 1..=self.inner.groups {
                out.push(m.group(g));
            }
            last = m.end();
        }
        out.push(Some(&s[last..]));
        out
    }
}

/// A match: spans are code-point indices into the string searched.
#[derive(Debug, Clone)]
pub struct Match<'s> {
    s: &'s [u32],
    re: &'s Regex,
    marks: Vec<isize>,
    pub pos: usize,
    pub endpos: usize,
    /// the last group closed (Python's lastindex; -1 for None)
    pub lastindex: isize,
}

impl<'s> Match<'s> {
    /// m.start(g) (-1 when the group did not take part)
    pub fn start_of(&self, g: usize) -> isize {
        self.marks.get(2 * g).copied().unwrap_or(-1)
    }
    pub fn end_of(&self, g: usize) -> isize {
        self.marks.get(2 * g + 1).copied().unwrap_or(-1)
    }
    pub fn start(&self) -> usize {
        self.marks[0] as usize
    }
    pub fn end(&self) -> usize {
        self.marks[1] as usize
    }
    pub fn span(&self) -> (usize, usize) {
        (self.start(), self.end())
    }
    pub fn group0(&self) -> &'s [u32] {
        &self.s[self.start()..self.end()]
    }
    /// m.group(g): None when the group did not take part.
    pub fn group(&self, g: usize) -> Option<&'s [u32]> {
        let (a, b) = (self.start_of(g), self.end_of(g));
        if a < 0 || b < 0 {
            None
        } else {
            Some(&self.s[a as usize..b as usize])
        }
    }
    pub fn name(&self, name: &str) -> Option<&'s [u32]> {
        self.re.group_index(name).and_then(|g| self.group(g))
    }
    pub fn regex(&self) -> &'s Regex {
        self.re
    }
    pub fn string(&self) -> &'s [u32] {
        self.s
    }
}

/// pattern.finditer: each match after the last, an empty match not again
/// where the last one ended.
pub struct FindIter<'s> {
    re: &'s Regex,
    s: &'s [u32],
    at: usize,
    pos: usize,
    end: usize,
    must_advance: bool,
    done: bool,
}

impl<'s> Iterator for FindIter<'s> {
    type Item = Match<'s>;
    fn next(&mut self) -> Option<Match<'s>> {
        if self.done {
            return None;
        }
        match self.re.find(self.s, self.at, self.end, Mode::Search, self.must_advance) {
            Some(f) => {
                let m = self.re.make_match(self.s, f, self.pos, self.end);
                self.must_advance = m.end() == m.start();
                self.at = m.end();
                Some(m)
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
