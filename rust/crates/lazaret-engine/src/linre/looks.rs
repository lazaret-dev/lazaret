//! Zero-width tests at a position: anchors, word boundaries, lookarounds.
//!
//! Each follows sre's rules exactly, the odd ones included: a lookbehind
//! reads the text before `pos` (sre's `beginning` is the string's start),
//! nothing after the window's end is visible, `\b` and `\B` never hold in
//! an empty window that starts at 0, and in a match started past the
//! window's end (`pattern.match(s, 5, 2)`) `$` under MULTILINE still reads
//! the character at the position.
//!
//! A lookaround of more than one character is tried as its own small
//! program, anchored at the position (a lookahead) or `width` characters
//! before it (a lookbehind, of fixed width): a set of states stepped over at
//! most `max` characters, any path to its end answering yes. Lookarounds
//! inside it are tried the same way, one level deeper.

use super::charset::CharSet;
use super::nfa::{Flat, Inst, LookDef, Prog, Programs};

/// A set of small integers with O(1) insert, test and clear.
#[derive(Clone, Debug, Default)]
pub struct SparseSet {
    dense: Vec<u32>,
    sparse: Vec<u32>,
    len: usize,
}

impl SparseSet {
    pub fn new(n: usize) -> SparseSet {
        SparseSet { dense: vec![0; n], sparse: vec![0; n], len: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.dense.len()
    }

    pub fn resize(&mut self, n: usize) {
        if n > self.dense.len() {
            self.dense.resize(n, 0);
            self.sparse.resize(n, 0);
        }
        self.len = 0;
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn contains(&self, x: u32) -> bool {
        let i = self.sparse[x as usize] as usize;
        i < self.len && self.dense[i] == x
    }

    /// Insert x; false if it was there.
    #[inline]
    pub fn insert(&mut self, x: u32) -> bool {
        if self.contains(x) {
            return false;
        }
        self.dense[self.len] = x;
        self.sparse[x as usize] = self.len as u32;
        self.len += 1;
        true
    }

    #[inline]
    pub fn get(&self, i: usize) -> u32 {
        self.dense[i]
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.dense[..self.len]
    }
}

/// Is `c` a word character (`\w`, Unicode or ASCII)?
#[inline]
fn is_word(ascii: bool, c: u32) -> bool {
    if ascii {
        (c < 128) && ((c as u8).is_ascii_alphanumeric() || c == 0x5F)
    } else {
        crate::unicode::is_word(c)
    }
}

/// Does a one-character (or position) test hold at `p`?
#[inline]
pub fn simple_holds(pr: &Programs, d: &LookDef, text: &[u32], p: usize, end: usize) -> bool {
    match *d {
        LookDef::Begin => p == 0,
        LookDef::BeginLine => p == 0 || text.get(p.wrapping_sub(1)) == Some(&0x0A),
        LookDef::End => p == end || (p + 1 == end && text.get(p) == Some(&0x0A)),
        LookDef::EndLine => p == end || text.get(p) == Some(&0x0A),
        LookDef::EndString => p == end,
        LookDef::Word { ascii, negate } => {
            if end == 0 {
                return false;
            }
            let that = p > 0 && text.get(p - 1).is_some_and(|&c| is_word(ascii, c));
            let this = p < end && text.get(p).is_some_and(|&c| is_word(ascii, c));
            if negate {
                this == that
            } else {
                this != that
            }
        }
        LookDef::Behind1 { set, negate } => {
            let hit = p >= 1 && p - 1 < end && text.get(p - 1).is_some_and(|&c| pr.sets[set as usize].contains(c));
            hit != negate
        }
        LookDef::Ahead1 { set, negate } => {
            let hit = p < end && text.get(p).is_some_and(|&c| pr.sets[set as usize].contains(c));
            hit != negate
        }
        LookDef::Around { .. } => false,
    }
}

/// Buffers for trying lookarounds, one level per nesting depth.
#[derive(Default)]
pub struct Oracle {
    levels: Vec<Level>,
}

#[derive(Default)]
struct Level {
    cur: SparseSet,
    next: SparseSet,
    stack: Vec<u32>,
}

impl Oracle {
    pub fn new() -> Oracle {
        Oracle { levels: Vec::new() }
    }
}

/// Does test `look` hold at `p` (window end `end`)?
pub fn holds(pr: &Programs, look: u32, text: &[u32], p: usize, end: usize, oracle: &mut Oracle) -> bool {
    holds_at_depth(pr, look, text, p, end, oracle, 0)
}

fn holds_at_depth(pr: &Programs, look: u32, text: &[u32], p: usize, end: usize, oracle: &mut Oracle, depth: usize) -> bool {
    let d = &pr.looks[look as usize];
    match d {
        LookDef::Around { behind, negate, prog, width, flat, first, .. } => {
            let q = if *behind {
                match p.checked_sub(*width as usize) {
                    Some(q) => q,
                    None => return *negate,
                }
            } else {
                p
            };
            let hit = match flat {
                // (past the window's end only the program keeps sre's rules)
                Some(seqs) if p <= end => {
                    // (no sequence begins with this character: none matches)
                    let begins = match first {
                        Some(f) => q < end && q < text.len() && f.may_begin(text[q]),
                        None => true,
                    };
                    begins && flat_holds(pr, seqs, text, q, end)
                }
                _ => {
                    let sub = &pr.subs[*prog as usize];
                    run(pr, sub, text, q, end, if *behind { Some(p) } else { None }, oracle, depth)
                }
            };
            hit != *negate
        }
        _ => simple_holds(pr, d, text, p, end),
    }
}

/// Does one of the fixed sequences match at q?
#[inline]
fn flat_holds(pr: &Programs, seqs: &[Box<[Flat]>], text: &[u32], q: usize, end: usize) -> bool {
    let end = end.min(text.len());
    'seqs: for s in seqs {
        let mut pos = q;
        for item in s.iter() {
            match *item {
                Flat::Char(set) => {
                    if pos < end && pr.sets[set as usize].contains(text[pos]) {
                        pos += 1;
                    } else {
                        continue 'seqs;
                    }
                }
                Flat::Look(l) => {
                    if !simple_holds(pr, &pr.looks[l as usize], text, pos, end) {
                        continue 'seqs;
                    }
                }
            }
        }
        return true;
    }
    false
}

/// Is there a path through `prog` from `q`, ending anywhere (or at `at`)?
#[allow(clippy::too_many_arguments)]
fn run(pr: &Programs, prog: &Prog, text: &[u32], q: usize, end: usize, at: Option<usize>, oracle: &mut Oracle, depth: usize) -> bool {
    if oracle.levels.len() <= depth {
        oracle.levels.resize_with(depth + 1, Level::default);
    }
    let n = prog.insts.len();
    // (the level's buffers are taken out while this level runs, so a
    // lookaround inside it can use the next level's)
    let mut lv = std::mem::take(&mut oracle.levels[depth]);
    lv.cur.resize(n);
    lv.next.resize(n);
    let mut pos = q;
    let mut found = false;
    closure(pr, prog, prog.start, text, pos, end, &mut lv.cur, &mut lv.stack, oracle, depth);
    loop {
        for i in 0..lv.cur.len() {
            let pc = lv.cur.get(i);
            match prog.insts[pc as usize] {
                Inst::Char { set, next } if pos < end && text.get(pos).is_some_and(|&c| pr.sets[set as usize].contains(c)) => {
                    closure(pr, prog, next, text, pos + 1, end, &mut lv.next, &mut lv.stack, oracle, depth);
                }
                Inst::Match if at.map_or(true, |a| a == pos) => {
                    found = true;
                    break;
                }
                _ => {}
            }
        }
        if found || lv.next.is_empty() || pos >= end {
            break;
        }
        std::mem::swap(&mut lv.cur, &mut lv.next);
        lv.next.clear();
        pos += 1;
        if let Some(a) = at {
            if pos > a {
                break;
            }
        }
    }
    lv.cur.clear();
    lv.next.clear();
    oracle.levels[depth] = lv;
    found
}

#[allow(clippy::too_many_arguments)]
fn closure(
    pr: &Programs,
    prog: &Prog,
    from: u32,
    text: &[u32],
    pos: usize,
    end: usize,
    set: &mut SparseSet,
    stack: &mut Vec<u32>,
    oracle: &mut Oracle,
    depth: usize,
) {
    stack.clear();
    stack.push(from);
    while let Some(pc) = stack.pop() {
        if !set.insert(pc) {
            continue;
        }
        match prog.insts[pc as usize] {
            Inst::Split { x, y } => {
                stack.push(y);
                stack.push(x);
            }
            Inst::Jmp { next } | Inst::Save { next, .. } => stack.push(next),
            Inst::Guard { next } => {
                if pos <= end {
                    stack.push(next);
                }
            }
            Inst::Look { look, next } => {
                if holds_at_depth(pr, look, text, pos, end, oracle, depth + 1) {
                    stack.push(next);
                }
            }
            Inst::Char { .. } | Inst::Match | Inst::Run { .. } => {}
        }
    }
}

/// The sets a one-character test reads (for the alphabet).
pub fn test_sets(pr: &Programs) -> Vec<&CharSet> {
    let mut v = Vec::new();
    for d in &pr.looks {
        match *d {
            LookDef::Behind1 { set, .. } | LookDef::Ahead1 { set, .. } => v.push(&pr.sets[set as usize]),
            _ => {}
        }
    }
    v
}
