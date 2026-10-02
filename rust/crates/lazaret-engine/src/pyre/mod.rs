// SPDX-License-Identifier: Apache-2.0 AND Python-2.0.1
//
// In part a Rust translation of CPython's Lib/re/_parser.py (parse_template)
// and of the Pattern methods of Modules/_sre/sre.c,
// changed as rust/NOTICE summarizes, and distributed under CPython's
// license (rust/LICENSE-PYTHON) as well as Lazaret's. The original's
// notices:
//
//   (Lib/re/_parser.py:)
//   Copyright (c) 1998-2001 by Secret Labs AB.  All rights reserved.
//   See the __init__.py file for information on usage and redistribution.
//
//   (Modules/_sre/sre.c:)
//   Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved.
//
//   (Lib/re/__init__.py, and sre.c in the same words:)
//   This version of the SRE library can be redistributed under CNRI's
//   Python 1.6 license.  For any other use, please contact Secret Labs
//   AB (info@pythonware.com).
//
//   Copyright (c) 2001 Python Software Foundation; All Rights Reserved

//! `pyre`: Python's `re`, for str patterns, in Rust.
//!
//! A port of CPython's own implementation (re/_parser.py, re/_compiler.py,
//! Modules/_sre, as of 3.11-3.14): the same parse, the same compiled
//! program, the same backtracking order, so every pattern the reference
//! engine uses matches the same text at the same place with the same groups.
//! Text is a Python `str`: a slice of code points (`u32`, lone surrogates
//! included), and every position is a code-point index, as in Python.
//!
//! What it leaves out, because the scanner's patterns never use it: bytes
//! patterns, the LOCALE flag and `\N{name}` escapes (both refused at compile
//! time, never answered differently).

pub mod compiler;
pub mod constants;
pub mod first;
pub mod literal;
pub mod matcher;
pub mod parser;
pub mod prog;
pub mod scan;

use constants::*;
use matcher::State;

pub use constants::{
    FLAG_ASCII as ASCII, FLAG_DOTALL as DOTALL, FLAG_IGNORECASE as IGNORECASE, FLAG_MULTILINE as MULTILINE,
    FLAG_VERBOSE as VERBOSE,
};

#[derive(Debug, Clone)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Time spent per pattern (a development aid: the `stats` feature only).
#[cfg(feature = "stats")]
pub mod stats {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static SPENT: RefCell<HashMap<Vec<u32>, (u64, u128)>> = RefCell::new(HashMap::new());
    }

    pub fn add(pattern: &[u32], ns: u128) {
        SPENT.with(|m| {
            let mut m = m.borrow_mut();
            let e = m.entry(pattern.to_vec()).or_insert((0, 0));
            e.0 += 1;
            e.1 += ns;
        });
    }

    /// (pattern, calls, nanoseconds), and start again.
    pub fn take() -> Vec<(Vec<u32>, u64, u128)> {
        SPENT.with(|m| m.borrow_mut().drain().map(|(k, (n, t))| (k, n, t)).collect())
    }
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Regex {
    pub pattern: Vec<u32>,
    /// Python's `pattern.flags` (UNICODE included).
    pub flags: u32,
    prog: std::sync::Arc<prog::Prog>,
    pub groups: usize,
    groupindex: Vec<(Vec<u32>, usize)>,
    /// set for a pattern the matcher is not needed for (see Simple)
    simple: Option<Simple>,
    /// The same pattern compiled by linre (crate::linre), which every search
    /// runs on when it accepts the pattern: re's answers, in time linear in
    /// the text, never backtracking. None: sre's backtracking matcher here
    /// (a pattern linre refuses — a backreference, a lookahead of unbounded
    /// width … — one answered without a matcher, or new_backtracking's).
    lin: Option<crate::linre::Regex>,
}

/// A pattern simple enough to answer without the matcher: one character of
/// a set (`[/'"`]`, a lexer's next interesting character) or the longest run
/// of them (`[ \t\n]*`), a set of literals and ranges only, with no groups
/// and no IGNORECASE. search and match give the matcher's answers.
#[derive(Clone, Debug)]
enum Simple {
    One(CharSet),
    Run(CharSet),
}

#[derive(Clone, Debug)]
struct CharSet {
    ascii: u128,
    ranges: Vec<(u32, u32)>,
}

impl CharSet {
    fn of(items: &[parser::SetItem]) -> Option<CharSet> {
        let mut set = CharSet { ascii: 0, ranges: Vec::new() };
        for it in items {
            let (a, b) = match *it {
                parser::SetItem::Literal(c) => (c, c),
                parser::SetItem::Range(a, b) => (a, b),
                _ => return None, // a category (\w, \s …) or a negated set
            };
            for c in a..=b.min(127) {
                set.ascii |= 1u128 << c;
            }
            if b >= 128 {
                set.ranges.push((a.max(128), b));
            }
        }
        Some(set)
    }

    #[inline]
    fn has(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii & (1u128 << c) != 0
        } else {
            self.ranges.iter().any(|&(a, b)| a <= c && c <= b)
        }
    }
}

fn simple_of(p: &parser::SubPattern, flags: u32, groups: usize) -> Option<Simple> {
    if groups != 0 || flags & FLAG_IGNORECASE != 0 || p.data.len() != 1 {
        return None;
    }
    match &p.data[0] {
        parser::Node::In(items) => CharSet::of(items).map(Simple::One),
        parser::Node::Repeat { kind: parser::RepeatKind::Max, min: 0, max: MAXREPEAT, item } if item.data.len() == 1 => {
            match &item.data[0] {
                parser::Node::In(items) => CharSet::of(items).map(Simple::Run),
                _ => None,
            }
        }
        _ => None,
    }
}

impl std::fmt::Debug for prog::Prog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Prog({} words)", self.code.len())
    }
}

/// Flags from the letters of re's inline flags: i m s x a.
pub fn flags_from_letters(letters: &str) -> u32 {
    let mut f = 0;
    for c in letters.chars() {
        f |= match c {
            'i' | 'I' => FLAG_IGNORECASE,
            'm' | 'M' => FLAG_MULTILINE,
            's' | 'S' => FLAG_DOTALL,
            'x' | 'X' => FLAG_VERBOSE,
            'a' | 'A' => FLAG_ASCII,
            'u' | 'U' => FLAG_UNICODE,
            _ => 0,
        };
    }
    f
}

impl Regex {
    /// re.compile(pattern, flags) for a str pattern: its searches run on
    /// linre where linre accepts the pattern (see `lin`), else here.
    pub fn new(pattern: &[u32], flags: u32) -> Result<Regex, Error> {
        let mut rx = Regex::new_backtracking(pattern, flags)?;
        if rx.simple.is_none() {
            rx.lin = crate::linre::Regex::new(pattern, flags).ok();
        }
        Ok(rx)
    }

    /// re.compile(pattern, flags) whose searches all run on sre's
    /// backtracking matcher (pyre.probe: pyre held to Python's re).
    pub fn new_backtracking(pattern: &[u32], flags: u32) -> Result<Regex, Error> {
        let (p, state) = parser::parse_pattern(pattern, flags).map_err(|e| Error(format!("{} at {}", e.msg, e.pos)))?;
        let code = compiler::code(&p, &state, flags).map_err(|e| Error(e.0))?;
        let groups = state.groups() - 1;
        Ok(Regex {
            pattern: pattern.to_vec(),
            flags: state.flags | flags,
            prog: std::sync::Arc::new(prog::Prog::new(code)),
            groups,
            groupindex: state.groupdict.clone(),
            simple: simple_of(&p, state.flags | flags, groups),
            lin: None,
        })
    }

    /// Do this pattern's searches run in linear time (on linre, or without a
    /// matcher)?
    pub fn is_linear(&self) -> bool {
        self.lin.is_some() || self.simple.is_some()
    }

    /// linre's match as this pattern's.
    fn from_lin<'s>(&'s self, s: &'s [u32], m: crate::linre::Match<'s>) -> Match<'s> {
        let (marks, pos, endpos, lastindex) = m.into_parts();
        Match { s, re: self, marks, pos, endpos, lastindex }
    }

    /// re.compile of a Rust string's code points.
    pub fn compile(pattern: &str, flags: u32) -> Result<Regex, Error> {
        let cps: Vec<u32> = pattern.chars().map(|c| c as u32).collect();
        Regex::new(&cps, flags)
    }

    /// The group number of a named group.
    pub fn group_index(&self, name: &str) -> Option<usize> {
        let n: Vec<u32> = name.chars().map(|c| c as u32).collect();
        self.groupindex.iter().find(|(k, _)| *k == n).map(|&(_, g)| g)
    }

    pub fn has_group(&self, name: &str) -> bool {
        self.group_index(name).is_some()
    }

    fn new_match<'s>(&'s self, st: &State<'s>) -> Match<'s> {
        let mut marks = vec![-1isize; 2 * (self.groups + 1)];
        marks[0] = st.start as isize;
        marks[1] = st.ptr as isize;
        for i in 0..self.groups {
            let j = 2 * i;
            if (j as isize) + 1 <= st.lastmark && st.mark[j] != usize::MAX && st.mark[j + 1] != usize::MAX {
                marks[j + 2] = st.mark[j] as isize;
                marks[j + 3] = st.mark[j + 1] as isize;
            }
        }
        Match { s: st.s, re: self, marks, pos: st.pos, endpos: st.endpos, lastindex: st.lastindex }
    }

    /// pattern.search(s, pos, endpos)
    /// Run one matcher call (timed per pattern with the `stats` feature).
    #[inline(always)]
    fn timed<T>(&self, f: impl FnOnce() -> T) -> T {
        #[cfg(feature = "stats")]
        {
            let t = std::time::Instant::now();
            let r = f();
            stats::add(&self.pattern, t.elapsed().as_nanos());
            r
        }
        #[cfg(not(feature = "stats"))]
        f()
    }

    /// A match of `simple` at [a, b).
    fn simple_match<'s>(&'s self, s: &'s [u32], a: usize, b: usize, pos: usize, endpos: usize) -> Match<'s> {
        Match { s, re: self, marks: vec![a as isize, b as isize], pos, endpos, lastindex: -1 }
    }

    /// (start, end) of the clamped search range, as State::new clamps it.
    fn clamp(s: &[u32], pos: isize, endpos: isize) -> (usize, usize) {
        let n = s.len() as isize;
        (pos.clamp(0, n) as usize, endpos.clamp(0, n) as usize)
    }

    pub fn search_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        if let Some(l) = &self.lin {
            return self.timed(|| l.search_at(s, pos, endpos)).map(|m| self.from_lin(s, m));
        }
        if let Some(simple) = &self.simple {
            let (start, end) = Self::clamp(s, pos, endpos);
            return self.timed(|| match simple {
                Simple::One(set) => {
                    (start..end).find(|&i| set.has(s[i])).map(|i| self.simple_match(s, i, i + 1, start, end))
                }
                Simple::Run(set) => {
                    if start > end {
                        return None;
                    }
                    let mut j = start;
                    while j < end && set.has(s[j]) {
                        j += 1;
                    }
                    Some(self.simple_match(s, start, j, start, end))
                }
            });
        }
        let mut st = State::new(s, self.groups, pos, endpos);
        match self.timed(|| matcher::sre_search(&mut st, &self.prog)) {
            Ok(true) => Some(self.new_match(&st)),
            _ => None,
        }
    }

    /// The strings one of which every match holds (literal.rs), when the
    /// pattern has them.
    pub fn need(&self) -> Option<&literal::Need> {
        self.prog.need.as_ref()
    }

    /// (development, `stats`: need scans, characters they read, characters
    /// lead scans read to no start, and to a start)
    #[cfg(feature = "stats")]
    pub fn scanned(&self) -> [u64; 4] {
        let a = &self.prog.scanned;
        [0, 1, 2, 3].map(|i| a[i].load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Where a search's match can start (first.rs), for a person.
    pub fn start_text(&self) -> Option<String> {
        self.prog.first.as_ref().map(|f| f.describe())
    }

    /// What every match starts with (literal.rs), for a person.
    pub fn lead_text(&self) -> Option<String> {
        self.prog.lead.as_ref().map(|n| n.describe())
    }

    /// What a search needs the text to hold (literal.rs), for a person.
    pub fn need_text(&self) -> Option<String> {
        self.prog.need.as_ref().map(|n| n.describe())
    }

    pub fn search<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.search_at(s, 0, s.len() as isize)
    }

    /// Does the pattern occur in s at all?
    pub fn is_match(&self, s: &[u32]) -> bool {
        self.search(s).is_some()
    }

    /// pattern.match(s, pos, endpos)
    pub fn match_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        if let Some(l) = &self.lin {
            return self.timed(|| l.match_at(s, pos, endpos)).map(|m| self.from_lin(s, m));
        }
        if let Some(simple) = &self.simple {
            let (start, end) = Self::clamp(s, pos, endpos);
            return self.timed(|| match simple {
                Simple::One(set) => {
                    if start < end && set.has(s[start]) {
                        Some(self.simple_match(s, start, start + 1, start, end))
                    } else {
                        None
                    }
                }
                Simple::Run(set) => {
                    if start > end {
                        return None;
                    }
                    let mut j = start;
                    while j < end && set.has(s[j]) {
                        j += 1;
                    }
                    Some(self.simple_match(s, start, j, start, end))
                }
            });
        }
        let mut st = State::new(s, self.groups, pos, endpos);
        st.ptr = st.start;
        match self.timed(|| matcher::sre_match(&mut st, &self.prog, 0, true)) {
            Ok(true) => Some(self.new_match(&st)),
            _ => None,
        }
    }

    pub fn match_<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.match_at(s, 0, s.len() as isize)
    }

    /// pattern.fullmatch(s, pos, endpos)
    pub fn fullmatch_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        if let Some(l) = &self.lin {
            return self.timed(|| l.fullmatch_at(s, pos, endpos)).map(|m| self.from_lin(s, m));
        }
        let mut st = State::new(s, self.groups, pos, endpos);
        st.ptr = st.start;
        st.match_all = true;
        match self.timed(|| matcher::sre_match(&mut st, &self.prog, 0, true)) {
            Ok(true) => Some(self.new_match(&st)),
            _ => None,
        }
    }

    pub fn fullmatch<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.fullmatch_at(s, 0, s.len() as isize)
    }

    /// pattern.finditer(s, pos, endpos)
    pub fn finditer_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> FindIter<'s> {
        let walk = match &self.lin {
            Some(l) => Walk::Lin(l.finditer_at(s, pos, endpos)),
            None => Walk::Back { st: Box::new(State::new(s, self.groups, pos, endpos)), done: false },
        };
        FindIter { re: self, s, walk }
    }

    pub fn finditer<'s>(&'s self, s: &'s [u32]) -> FindIter<'s> {
        self.finditer_at(s, 0, s.len() as isize)
    }

    /// pattern.findall(s) for a pattern with at most one group: the whole
    /// match, or group 1 ('' where it did not take part).
    pub fn findall<'s>(&'s self, s: &'s [u32]) -> Vec<&'s [u32]> {
        self.finditer(s)
            .map(|m| if self.groups == 0 { m.group0() } else { m.group(1).unwrap_or(&[]) })
            .collect()
    }

    /// pattern.findall(s, pos, endpos) for a pattern with at most one group.
    pub fn findall_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Vec<&'s [u32]> {
        self.finditer_at(s, pos, endpos)
            .map(|m| if self.groups == 0 { m.group0() } else { m.group(1).unwrap_or(&[]) })
            .collect()
    }

    /// pattern.findall(s) for a pattern with groups: each match's groups
    /// ('' where one did not take part).
    pub fn findall_groups<'s>(&'s self, s: &'s [u32]) -> Vec<Vec<&'s [u32]>> {
        self.finditer(s).map(|m| (1..=self.groups).map(|g| m.group(g).unwrap_or(&[])).collect()).collect()
    }

    /// pattern.sub(repl, s, count) with a function.
    pub fn sub_fn<'s>(&'s self, s: &'s [u32], count: usize, mut f: impl FnMut(&Match<'s>) -> Vec<u32>) -> Vec<u32> {
        if let Some(l) = &self.lin {
            return l.sub_fn(s, count, |m| f(&self.from_lin(s, m.clone())));
        }
        let mut out: Vec<u32> = Vec::with_capacity(s.len());
        let mut i = 0usize;
        let mut n = 0usize;
        let mut st = State::new(s, self.groups, 0, s.len() as isize);
        while count == 0 || n < count {
            st.reset();
            st.ptr = st.start;
            match self.timed(|| matcher::sre_search(&mut st, &self.prog)) {
                Ok(true) => {}
                _ => break,
            }
            let b = st.start;
            let e = st.ptr;
            if i < b {
                out.extend_from_slice(&s[i..b]);
            }
            let m = self.new_match(&st);
            out.extend(f(&m));
            i = e;
            n += 1;
            st.must_advance = st.ptr == st.start;
            st.start = st.ptr;
        }
        if i < st.endpos {
            out.extend_from_slice(&s[i..st.endpos]);
        }
        out
    }

    /// pattern.sub(repl, s, count) with a replacement string (a template:
    /// \1, \g<name>, \n … as re reads them).
    pub fn sub<'s>(&'s self, s: &'s [u32], repl: &[u32], count: usize) -> Vec<u32> {
        if !repl.contains(&(b'\\' as u32)) {
            return self.sub_fn(s, count, |_| repl.to_vec());
        }
        match self.parse_template(repl) {
            Ok(tpl) => self.sub_fn(s, count, |m| {
                let mut out = Vec::new();
                for piece in &tpl {
                    match piece {
                        TplPiece::Lit(l) => out.extend_from_slice(l),
                        TplPiece::Group(g) => out.extend_from_slice(m.group(*g).unwrap_or(&[])),
                    }
                }
                out
            }),
            Err(_) => s.to_vec(),
        }
    }

    pub fn sub_str<'s>(&'s self, s: &'s [u32], repl: &str) -> Vec<u32> {
        let r: Vec<u32> = repl.chars().map(|c| c as u32).collect();
        self.sub(s, &r, 0)
    }

    /// pattern.split(s, maxsplit): the pieces between matches; groups, when
    /// the pattern has some, in between (None: a group that did not take part).
    pub fn split<'s>(&'s self, s: &'s [u32], maxsplit: usize) -> Vec<Option<&'s [u32]>> {
        if let Some(l) = &self.lin {
            return l.split(s, maxsplit);
        }
        let mut out = Vec::new();
        let mut st = State::new(s, self.groups, 0, s.len() as isize);
        let mut last = st.start;
        let mut n = 0usize;
        while maxsplit == 0 || n < maxsplit {
            st.reset();
            st.ptr = st.start;
            match self.timed(|| matcher::sre_search(&mut st, &self.prog)) {
                Ok(true) => {}
                _ => break,
            }
            out.push(Some(&s[last..st.start]));
            let m = self.new_match(&st);
            for g in 1..=self.groups {
                out.push(m.group(g));
            }
            n += 1;
            st.must_advance = st.ptr == st.start;
            last = st.ptr;
            st.start = st.ptr;
        }
        out.push(Some(&s[last..st.endpos]));
        out
    }

    fn parse_template(&self, repl: &[u32]) -> Result<Vec<TplPiece>, Error> {
        // re/_parser.parse_template
        let mut out: Vec<TplPiece> = Vec::new();
        let mut lit: Vec<u32> = Vec::new();
        let mut i = 0usize;
        let n = repl.len();
        let digit = |c: u32| (0x30..=0x39).contains(&c);
        let oct = |c: u32| (0x30..=0x37).contains(&c);
        while i < n {
            let c = repl[i];
            if c != b'\\' as u32 {
                lit.push(c);
                i += 1;
                continue;
            }
            if i + 1 >= n {
                return Err(Error("bad escape (end of pattern)".into()));
            }
            let d = repl[i + 1];
            i += 2;
            if d == b'g' as u32 {
                if i >= n || repl[i] != b'<' as u32 {
                    return Err(Error("missing <".into()));
                }
                let close = repl[i + 1..].iter().position(|&x| x == b'>' as u32).ok_or(Error("missing >".into()))?;
                let name = &repl[i + 1..i + 1 + close];
                i = i + 2 + close;
                let idx = if !name.is_empty() && name.iter().all(|&x| digit(x)) {
                    name.iter().fold(0usize, |a, &x| a.saturating_mul(10).saturating_add((x - 0x30) as usize))
                } else {
                    let nm: String = name.iter().filter_map(|&x| char::from_u32(x)).collect();
                    self.group_index(&nm).ok_or(Error("unknown group name".into()))?
                };
                if idx > self.groups {
                    return Err(Error("invalid group reference".into()));
                }
                out.push(TplPiece::Lit(std::mem::take(&mut lit)));
                out.push(TplPiece::Group(idx));
            } else if d == b'0' as u32 {
                let mut v = 0u32;
                let mut k = 0;
                while k < 2 && i < n && oct(repl[i]) {
                    v = v * 8 + (repl[i] - 0x30);
                    i += 1;
                    k += 1;
                }
                lit.push(v & 0xFF);
            } else if digit(d) {
                let mut ds = vec![d];
                let mut isoctal = false;
                if i < n && digit(repl[i]) {
                    ds.push(repl[i]);
                    i += 1;
                    if oct(d) && oct(ds[1]) && i < n && oct(repl[i]) {
                        ds.push(repl[i]);
                        i += 1;
                        isoctal = true;
                        let v = ds.iter().fold(0u32, |a, &x| a * 8 + (x - 0x30));
                        if v > 0o377 {
                            return Err(Error("octal escape value outside of range 0-0o377".into()));
                        }
                        lit.push(v);
                    }
                }
                if !isoctal {
                    let idx = ds.iter().fold(0usize, |a, &x| a * 10 + (x - 0x30) as usize);
                    if idx > self.groups {
                        return Err(Error("invalid group reference".into()));
                    }
                    out.push(TplPiece::Lit(std::mem::take(&mut lit)));
                    out.push(TplPiece::Group(idx));
                }
            } else {
                let v = match char::from_u32(d) {
                    Some('a') => Some(7),
                    Some('b') => Some(8),
                    Some('f') => Some(12),
                    Some('n') => Some(10),
                    Some('r') => Some(13),
                    Some('t') => Some(9),
                    Some('v') => Some(11),
                    Some('\\') => Some(b'\\' as u32),
                    _ => None,
                };
                match v {
                    Some(v) => lit.push(v),
                    None => {
                        if (0x41..=0x5A).contains(&d) || (0x61..=0x7A).contains(&d) {
                            return Err(Error("bad escape".into()));
                        }
                        lit.push(b'\\' as u32);
                        lit.push(d);
                    }
                }
            }
        }
        out.push(TplPiece::Lit(lit));
        Ok(out)
    }
}

enum TplPiece {
    Lit(Vec<u32>),
    Group(usize),
}

/// A match: spans are code-point indices into the string searched.
#[derive(Debug, Clone)]
pub struct Match<'s> {
    s: &'s [u32],
    re: &'s Regex,
    marks: Vec<isize>,
    pub pos: usize,
    pub endpos: usize,
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
    /// m.group(0)
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
    /// m.group(name)
    pub fn name(&self, name: &str) -> Option<&'s [u32]> {
        self.re.group_index(name).and_then(|g| self.group(g))
    }
    /// m.span(name)
    pub fn name_span(&self, name: &str) -> Option<(usize, usize)> {
        let g = self.re.group_index(name)?;
        let (a, b) = (self.start_of(g), self.end_of(g));
        if a < 0 {
            None
        } else {
            Some((a as usize, b as usize))
        }
    }
    pub fn string(&self) -> &'s [u32] {
        self.s
    }
    pub fn regex(&self) -> &'s Regex {
        self.re
    }
    /// The first group (in order) that took part: `next(g for g in m.groups() if g is not None)`.
    pub fn first_group(&self) -> Option<&'s [u32]> {
        (1..=self.re.groups).find_map(|g| self.group(g))
    }
}

/// pattern.finditer: the scanner's search loop.
pub struct FindIter<'s> {
    re: &'s Regex,
    s: &'s [u32],
    walk: Walk<'s>,
}

/// How a finditer searches: on linre, or with sre's matcher.
enum Walk<'s> {
    Lin(crate::linre::FindIter<'s>),
    Back { st: Box<State<'s>>, done: bool },
}

impl<'s> Iterator for FindIter<'s> {
    type Item = Match<'s>;
    fn next(&mut self) -> Option<Match<'s>> {
        let re = self.re;
        match &mut self.walk {
            Walk::Lin(it) => {
                let s = self.s;
                re.timed(|| it.next()).map(|m| re.from_lin(s, m))
            }
            Walk::Back { st, done } => {
                if *done {
                    return None;
                }
                st.reset();
                st.ptr = st.start;
                match re.timed(|| matcher::sre_search(st, &re.prog)) {
                    Ok(true) => {
                        let m = re.new_match(st);
                        st.must_advance = st.ptr == st.start;
                        st.start = st.ptr;
                        Some(m)
                    }
                    _ => {
                        *done = true;
                        None
                    }
                }
            }
        }
    }
}

/// re.escape
pub fn escape(s: &[u32]) -> Vec<u32> {
    let special = "()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c";
    let mut out = Vec::with_capacity(s.len() * 2);
    for &c in s {
        if c < 128 && special.as_bytes().contains(&(c as u8)) {
            out.push(b'\\' as u32);
        }
        out.push(c);
    }
    out
}
