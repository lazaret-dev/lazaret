//! `pyre`: Python's `re`, for str patterns, as the engine's code calls it.
//!
//! A layer over linre (`crate::linre`), which runs every pattern in time
//! linear in the text with `re`'s answers: compile, search, match,
//! fullmatch, finditer, findall, sub (with a function or a template) and
//! split, with `re`'s spans, groups and windows, and `re.escape`. Text is a
//! Python `str`: a slice of code points (`u32`, lone surrogates included),
//! and every position is a code-point index, as in Python.
//!
//! A pattern linre does not run is an error, as one Python rejects is
//! (`linre::Error::refused` says which): every pattern of the rule pack, and
//! every pattern the engine builds, is one it runs (`linre.check`, and
//! `rxutil`'s `linre.refused`). Until P-16 this module also held sre's own
//! parser, compiler and backtracking matcher, which the patterns linre
//! refused ran on; with none left, they are retired (rust/NOTICE).

use crate::linre;

pub use linre::{ASCII, DOTALL, IGNORECASE, MULTILINE, UNICODE, VERBOSE};

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

/// Flags from the letters of re's inline flags: i m s x a u.
pub fn flags_from_letters(letters: &str) -> u32 {
    linre::flags_from_letters(letters)
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Regex {
    pub pattern: Vec<u32>,
    /// Python's `pattern.flags` (UNICODE included).
    pub flags: u32,
    pub groups: usize,
    lin: linre::Regex,
}

impl Regex {
    /// re.compile(pattern, flags) for a str pattern. A pattern Python
    /// rejects is an error, with Python's message; so is one linre does not
    /// run, with the reason.
    pub fn new(pattern: &[u32], flags: u32) -> Result<Regex, Error> {
        let lin = linre::Regex::new(pattern, flags)
            .map_err(|e| Error(if e.refused { format!("linre does not run it: {}", e.msg) } else { e.msg }))?;
        Ok(Regex { pattern: pattern.to_vec(), flags: lin.flags(), groups: lin.groups(), lin })
    }

    /// re.compile of a Rust string's code points.
    pub fn compile(pattern: &str, flags: u32) -> Result<Regex, Error> {
        let cps: Vec<u32> = pattern.chars().map(|c| c as u32).collect();
        Regex::new(&cps, flags)
    }

    /// The group number of a named group.
    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.lin.group_index(name)
    }

    pub fn has_group(&self, name: &str) -> bool {
        self.group_index(name).is_some()
    }

    /// The strings one of which every match holds (or, when linre scans
    /// for them instead, those every match starts with): a text without
    /// any of them has no match. None when the pattern has none worth a scan.
    pub fn need(&self) -> Option<&linre::literal::LitSet> {
        self.lin.required()
    }

    /// What linre makes of the pattern (its program, lookarounds and scans).
    pub fn info(&self) -> linre::Info {
        self.lin.info()
    }

    /// Run one search (timed per pattern with the `stats` feature).
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

    /// linre's match as this pattern's.
    fn from_lin<'s>(&'s self, s: &'s [u32], m: linre::Match<'s>) -> Match<'s> {
        let (marks, pos, endpos, lastindex) = m.into_parts();
        Match { s, re: self, marks, pos, endpos, lastindex }
    }

    /// pattern.search(s, pos, endpos)
    pub fn search_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        self.timed(|| self.lin.search_at(s, pos, endpos)).map(|m| self.from_lin(s, m))
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
        self.timed(|| self.lin.match_at(s, pos, endpos)).map(|m| self.from_lin(s, m))
    }

    pub fn match_<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.match_at(s, 0, s.len() as isize)
    }

    /// pattern.fullmatch(s, pos, endpos)
    pub fn fullmatch_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> Option<Match<'s>> {
        self.timed(|| self.lin.fullmatch_at(s, pos, endpos)).map(|m| self.from_lin(s, m))
    }

    pub fn fullmatch<'s>(&'s self, s: &'s [u32]) -> Option<Match<'s>> {
        self.fullmatch_at(s, 0, s.len() as isize)
    }

    /// pattern.finditer(s, pos, endpos)
    pub fn finditer_at<'s>(&'s self, s: &'s [u32], pos: isize, endpos: isize) -> FindIter<'s> {
        FindIter { re: self, s, it: self.lin.finditer_at(s, pos, endpos) }
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
        self.timed(|| self.lin.sub_fn(s, count, |m| f(&self.from_lin(s, m.clone()))))
    }

    /// pattern.sub(repl, s, count) with a replacement string: a template
    /// whose backslashes `re` reads (see `template`). A template `re` would
    /// reject leaves the text as it is.
    pub fn sub<'s>(&'s self, s: &'s [u32], repl: &[u32], count: usize) -> Vec<u32> {
        if !repl.contains(&(b'\\' as u32)) {
            return self.sub_fn(s, count, |_| repl.to_vec());
        }
        match self.template(repl) {
            Ok(pieces) => self.sub_fn(s, count, |m| {
                let mut out = Vec::new();
                for piece in &pieces {
                    match piece {
                        Piece::Text(t) => out.extend_from_slice(t),
                        Piece::Group(g) => out.extend_from_slice(m.group(*g).unwrap_or(&[])),
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
        self.timed(|| self.lin.split(s, maxsplit))
    }

    /// A replacement template as `re.sub` reads it (the documented rules,
    /// held to Python's by test_rust_parity_regex's templates): `\1` to
    /// `\99` and `\g<name>`, `\g<number>`, `\g<0>` a group's text (empty where
    /// it did not take part); `\0` and up to two more octal digits, or three
    /// octal digits, a character (at most 0o377); `\a \b \f \n \r \t \v \\`
    /// their characters; a backslash before another ASCII letter, or at the
    /// end, an error; before anything else, itself.
    fn template(&self, repl: &[u32]) -> Result<Vec<Piece>, Error> {
        let is_digit = |c: u32| (0x30..=0x39).contains(&c);
        let is_octal = |c: u32| (0x30..=0x37).contains(&c);
        let bad = |what: &str| Err(Error(what.to_string()));
        let mut out: Vec<Piece> = Vec::new();
        let mut text: Vec<u32> = Vec::new();
        let mut i = 0usize;
        while i < repl.len() {
            let c = repl[i];
            i += 1;
            if c != b'\\' as u32 {
                text.push(c);
                continue;
            }
            let Some(&d) = repl.get(i) else {
                return bad("bad escape (end of pattern)");
            };
            i += 1;
            let group = match char::from_u32(d) {
                Some('g') => {
                    if repl.get(i) != Some(&(b'<' as u32)) {
                        return bad("missing <");
                    }
                    let close = match repl[i + 1..].iter().position(|&x| x == b'>' as u32) {
                        Some(k) => i + 1 + k,
                        None => return bad("missing >"),
                    };
                    let name = &repl[i + 1..close];
                    i = close + 1;
                    let g = if !name.is_empty() && name.iter().all(|&x| is_digit(x)) {
                        name.iter().fold(0usize, |a, &x| a.saturating_mul(10).saturating_add((x - 0x30) as usize))
                    } else {
                        let n: String = name.iter().filter_map(|&x| char::from_u32(x)).collect();
                        match self.group_index(&n) {
                            Some(g) => g,
                            None => return bad("unknown group name"),
                        }
                    };
                    Some(g)
                }
                Some('0') => {
                    // \0 and up to two more octal digits: a character
                    let mut v = 0u32;
                    let mut k = 0;
                    while k < 2 && repl.get(i).is_some_and(|&x| is_octal(x)) {
                        v = v * 8 + (repl[i] - 0x30);
                        i += 1;
                        k += 1;
                    }
                    text.push(v);
                    None
                }
                Some('1'..='9') => {
                    let next = repl.get(i).copied();
                    let third = repl.get(i + 1).copied();
                    match (next, third) {
                        // three octal digits: a character
                        (Some(e), Some(f)) if is_octal(d) && is_octal(e) && is_octal(f) => {
                            let v = (d - 0x30) * 64 + (e - 0x30) * 8 + (f - 0x30);
                            if v > 0o377 {
                                return bad("octal escape value outside of range 0-0o377");
                            }
                            text.push(v);
                            i += 2;
                            None
                        }
                        // one or two digits: a group
                        (Some(e), _) if is_digit(e) => {
                            i += 1;
                            Some(((d - 0x30) * 10 + (e - 0x30)) as usize)
                        }
                        _ => Some((d - 0x30) as usize),
                    }
                }
                Some(ch) => {
                    let known = match ch {
                        'a' => Some(0x07),
                        'b' => Some(0x08),
                        'f' => Some(0x0C),
                        'n' => Some(0x0A),
                        'r' => Some(0x0D),
                        't' => Some(0x09),
                        'v' => Some(0x0B),
                        '\\' => Some(0x5C),
                        _ => None,
                    };
                    match known {
                        Some(v) => text.push(v),
                        None if ch.is_ascii_alphabetic() => return bad("bad escape"),
                        None => {
                            text.push(b'\\' as u32);
                            text.push(d);
                        }
                    }
                    None
                }
                None => {
                    text.push(b'\\' as u32);
                    text.push(d);
                    None
                }
            };
            if let Some(g) = group {
                if g > self.groups {
                    return bad("invalid group reference");
                }
                out.push(Piece::Text(std::mem::take(&mut text)));
                out.push(Piece::Group(g));
            }
        }
        out.push(Piece::Text(text));
        Ok(out)
    }
}

enum Piece {
    Text(Vec<u32>),
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
    it: linre::FindIter<'s>,
}

impl<'s> Iterator for FindIter<'s> {
    type Item = Match<'s>;
    fn next(&mut self) -> Option<Match<'s>> {
        let (re, s) = (self.re, self.s);
        re.timed(|| self.it.next()).map(|m| re.from_lin(s, m))
    }
}

/// re.escape: a backslash before each character that can have a special
/// meaning in a pattern (Python 3.7 and later).
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
