//! What a search can skip: positions where no match can start, texts that
//! hold none of the strings every match holds.
//!
//! Each is read from the program or the pattern once, at compile time, and
//! only ever skips work that cannot lead to a match; the matchers decide
//! every answer.

use super::charset::CharSet;
use super::dfa::Skip;
use super::nfa::{Inst, Prog, Programs};

/// How common an ASCII character is in source text, per mille (a guess:
/// it changes how fast a search runs, never what it finds).
fn freq(c: u32) -> u32 {
    match c {
        0x20 => 150,
        0x65 => 60,
        0x74 => 45,
        0x61 | 0x69 | 0x6E | 0x6F | 0x72 | 0x73 => 38,
        0x6C => 28,
        0x0A | 0x63 | 0x64 | 0x75 => 22,
        0x28 | 0x29 | 0x2E | 0x3D | 0x70 | 0x6D | 0x68 => 18,
        0x2C | 0x66 | 0x5F | 0x27 | 0x3B | 0x67 | 0x62 => 12,
        0x22 | 0x3A | 0x79 | 0x76 | 0x77 | 0x09 => 8,
        0x2F | 0x7B | 0x7D | 0x2D | 0x30 | 0x31 | 0x5B | 0x5D | 0x6B | 0x78 => 5,
        0x41..=0x5A => 3,
        0x32..=0x39 | 0x2A | 0x3E | 0x3C | 0x2B | 0x24 | 0x21 => 2,
        _ => 1,
    }
}

/// The characters a match can start with: None when a match can be empty
/// (or start with any character the program does not tell).
pub fn first_set(pr: &Programs, prog: &Prog) -> Option<CharSet> {
    let mut seen = vec![false; prog.insts.len()];
    let mut stack = vec![prog.start];
    let mut out = CharSet::empty();
    while let Some(pc) = stack.pop() {
        if std::mem::replace(&mut seen[pc as usize], true) {
            continue;
        }
        match prog.insts[pc as usize] {
            Inst::Split { x, y } => {
                stack.push(x);
                stack.push(y);
            }
            Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } | Inst::Look { next, .. } => stack.push(next),
            Inst::Char { set, .. } => out = out.union(&pr.sets[set as usize]),
            Inst::Match => return None,
            Inst::Run { .. } => return None,
        }
    }
    Some(out)
}

/// A pattern that is one character of a set, or a greedy repeat of one,
/// with no group: answered by scans, without a matcher (`[/'"`]`, a lexer's
/// next interesting character; `[ \t]*`; `[A-Za-z0-9_:-]{20,200}`).
pub struct Simple {
    /// a match takes at least `min` characters of the set and, greedy, as
    /// many more as follow, up to `max` (one character: 1 and 1)
    pub min: usize,
    pub max: usize,
    ascii: [bool; 128],
    other: CharSet,
}

impl Simple {
    pub fn of(h: &super::hir::Hir, sets: &[CharSet]) -> Option<Simple> {
        use super::hir::Hir;
        let (set, min, max) = match h {
            Hir::Char(s) => (*s, 1, 1),
            Hir::Repeat { min, max, greedy: true, body, .. } => match **body {
                Hir::Char(s) => (s, *min as usize, max.map_or(usize::MAX, |m| m as usize)),
                _ => return None,
            },
            _ => return None,
        };
        if min > max {
            return None;
        }
        let set = &sets[set as usize];
        let mask = set.ascii_mask();
        let mut ascii = [false; 128];
        for (c, slot) in ascii.iter_mut().enumerate() {
            *slot = mask & (1u128 << c) != 0;
        }
        Some(Simple { min, max, ascii, other: set.intersect(&CharSet::range(128, u32::MAX)) })
    }

    /// sre's match in [start, end): for a search (`anchored` false) the
    /// first run of at least `min` of the set's characters, for a match the
    /// run from `start`, each cut at `max`; for a fullmatch (`whole`) the
    /// window if it is such a run. None: not answered here (an empty match
    /// refused after an empty match, which the matchers handle).
    pub fn span(&self, text: &[u32], start: usize, end: usize, anchored: bool, whole: bool, must_advance: bool) -> Option<Option<(usize, usize)>> {
        // (no match starts past the window's end: one character needs one
        // before it, and sre's single-character repeat fails there at once)
        if start > end || end > text.len() {
            return Some(None);
        }
        if must_advance && self.min == 0 {
            return None;
        }
        if whole {
            let n = end - start;
            let ok = n >= self.min && n <= self.max && self.run_end(text, start, end) == end;
            return Some(if ok { Some((start, end)) } else { None });
        }
        // (a pattern that matches nothing matches at `start`)
        let anchored = anchored || self.min == 0;
        let mut at = start;
        loop {
            let a = if anchored {
                at
            } else {
                match self.find(text, at, end) {
                    Some(a) => a,
                    None => return Some(None),
                }
            };
            let b = self.run_end(text, a, end.min(a.saturating_add(self.max)));
            if b - a >= self.min {
                return Some(Some((a, b)));
            }
            if anchored || b >= end {
                return Some(None);
            }
            at = b;
        }
    }

    #[inline]
    pub fn has(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii[c as usize]
        } else {
            self.other.contains(c)
        }
    }

    /// The first position in [from, to) of a character of the set.
    pub fn find(&self, text: &[u32], from: usize, to: usize) -> Option<usize> {
        if self.other.is_empty() {
            super::literal::scan_by(text, from, to, |x| (x < 128) & self.ascii[(x & 127) as usize])
        } else {
            super::literal::scan_by(text, from, to, |x| self.has(x))
        }
    }

    /// The end of the run of the set's characters from `from` (before `to`).
    pub fn run_end(&self, text: &[u32], from: usize, to: usize) -> usize {
        let mut j = from;
        while j < to && self.has(text[j]) {
            j += 1;
        }
        j
    }
}

/// A scan for the next character of a set.
pub struct FirstChars {
    ascii: [bool; 128],
    /// the set's characters past ASCII (None: none)
    other: Option<CharSet>,
}

impl FirstChars {
    /// A scan worth running: one whose characters are rare in source text.
    pub fn new(set: &CharSet) -> Option<FirstChars> {
        let mask = set.ascii_mask();
        let mut ascii = [false; 128];
        let mut density = 0u32;
        for (c, slot) in ascii.iter_mut().enumerate() {
            if mask & (1u128 << c) != 0 {
                *slot = true;
                density += freq(c as u32);
            }
        }
        if density > 120 {
            return None;
        }
        let other = set.intersect(&CharSet::range(128, u32::MAX));
        if other.ranges().len() > 16 {
            return None;
        }
        Some(FirstChars { ascii, other: if other.is_empty() { None } else { Some(other) } })
    }
}

impl Skip for FirstChars {
    #[inline]
    fn next(&self, text: &[u32], from: usize, end: usize) -> Option<usize> {
        let end = end.min(text.len());
        let mut i = from;
        match &self.other {
            None => {
                while i < end {
                    let c = text[i];
                    if c < 128 && self.ascii[c as usize] {
                        return Some(i);
                    }
                    i += 1;
                }
            }
            Some(o) => {
                while i < end {
                    let c = text[i];
                    if if c < 128 { self.ascii[c as usize] } else { o.contains(c) } {
                        return Some(i);
                    }
                    i += 1;
                }
            }
        }
        None
    }
}
