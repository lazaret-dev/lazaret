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
    /// re.compile(pattern, flags) for a str pattern.
    pub fn new(pattern: &[u32], flags: u32) -> Result<Regex, Error> {
        let (p, state) = parser::parse_pattern(pattern, flags).map_err(|e| Error(format!("{} at {}", e.msg, e.pos)))?;
        let code = compiler::code(&p, &state, flags).map_err(|e| Error(e.0))?;
        Ok(Regex {
            pattern: pattern.to_vec(),
            flags: state.flags | flags,
            prog: std::sync::Arc::new(prog::Prog::new(code)),
            groups: state.groups() - 1,
            groupindex: state.groupdict.clone(),
        })
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

    pub fn search_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        let mut st = State::new(s, self.groups, pos, endpos);
        match self.timed(|| matcher::sre_search(&mut st, &self.prog)) {
            Ok(true) => Some(self.new_match(&st)),
            _ => None,
        }
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
        FindIter { re: self, st: State::new(s, self.groups, pos, endpos), done: false }
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
    st: State<'s>,
    done: bool,
}

impl<'s> Iterator for FindIter<'s> {
    type Item = Match<'s>;
    fn next(&mut self) -> Option<Match<'s>> {
        if self.done {
            return None;
        }
        self.st.reset();
        self.st.ptr = self.st.start;
        match self.re.timed(|| matcher::sre_search(&mut self.st, &self.re.prog)) {
            Ok(true) => {
                let m = self.re.new_match(&self.st);
                self.st.must_advance = self.st.ptr == self.st.start;
                self.st.start = self.st.ptr;
                Some(m)
            }
            _ => {
                self.done = true;
                None
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
