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
//!
//! A lookahead that may read further than `hir::MAX_LOOK` characters — of
//! unbounded width, such as `(?!\s*\()` or `(?![^"']*html)` — would cost up
//! to the rest of the text at every position it is tried at, so its walks
//! are memoized (`run_memo`): the outcome of a walk depends only on the set
//! of threads it holds and the position, so each (set, position) a walk
//! passes is remembered for the text, in runs of positions, and a later
//! walk that reaches one stops there. A walk from inside a run of blanks
//! meets the first walk's set after a step or two. Each pair is walked once,
//! so all the walks of a search together read the text a bounded number of
//! times per set: linear, with sre's answers. A lookahead whose walks meet
//! many sets (`(?![ab]*a[ab]{12}c)` on a text of a's and b's) would still
//! walk far from every position, so once its walks have taken SWEEP_AFTER
//! steps per character of the stretch it is tried on, it is decided at
//! every position of that stretch at once (`sweep`, one pass from the
//! window's end back) and answered from that: O(n) steps for a lookahead,
//! whatever the text. The memos hold for one text and window end
//! (`Oracle::begin`: one search, or one finditer).

use super::charset::CharSet;
use super::nfa::{Flat, Inst, LookDef, Prog, Programs};
use std::collections::{BTreeMap, HashMap};

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

/// Buffers for trying lookarounds, one level per nesting depth, and the
/// memos of the lookaheads walked with one (see `run_memo`).
#[derive(Default)]
pub struct Oracle {
    levels: Vec<Level>,
    /// the text (its address and length) and the window end the memos are
    /// about, and their generation: a memo of another generation is empty
    key: (usize, usize, usize),
    gen: u64,
    /// by lookaround number
    memos: Vec<LookMemo>,
    keybuf: Vec<u32>,
    /// characters the memoized walks stepped over since `begin` (the search
    /// charges them to the call's work budget)
    pub walked: usize,
}

#[derive(Default)]
struct Level {
    cur: SparseSet,
    next: SparseSet,
    stack: Vec<u32>,
    /// a memoized walk's stretch: runs of positions with one set (id, from, to)
    path: Vec<(u32, usize, usize)>,
}

/// Steps a walk takes before its sets are memoized: a short walk costs less
/// than looking it up, and a walk reaches memoized ground after at most
/// this many steps.
const MEMO_AFTER: usize = 8;
/// Sets one lookahead remembers for one text; past it, it starts again.
const MEMO_SETS: usize = 4096;
/// Steps one lookahead's walks may take for one text, per character from
/// the lowest position it was tried at to the window's end (and SWEEP_SLACK
/// more), before it is decided at every position of that stretch at once
/// (`sweep`): so its walks cost O(n) steps however many sets they meet.
const SWEEP_AFTER: usize = 4;
const SWEEP_SLACK: usize = 4096;

/// What the walks of one lookahead found in one text.
#[derive(Default)]
struct LookMemo {
    gen: u64,
    /// the sets met, by their character instructions (what decides a set's
    /// future: the others are steps of its closure)
    ids: HashMap<Box<[u32]>, u32>,
    /// per set: from -> (to, outcome), a walk from that set at any position
    /// from..to has the outcome; disjoint
    runs: Vec<BTreeMap<usize, (usize, bool)>>,
    /// the lowest position the lookahead was tried at
    lo: usize,
    /// steps its walks took since the generation began or the last sweep
    steps: usize,
    /// the outcome at each position from `.0` to the window's end, once swept
    swept: Option<(usize, Vec<u64>)>,
}

impl LookMemo {
    #[inline]
    fn known(&self, id: u32, pos: usize) -> Option<bool> {
        let (_, &(to, outcome)) = self.runs[id as usize].range(..=pos).next_back()?;
        (pos < to).then_some(outcome)
    }

    /// The sets met and their runs are forgotten (too many sets).
    fn clear(&mut self) {
        self.ids.clear();
        self.runs.clear();
    }

    /// Another text or window: nothing is known.
    fn reset(&mut self, gen: u64) {
        self.clear();
        self.gen = gen;
        self.lo = usize::MAX;
        self.steps = 0;
        self.swept = None;
    }

    /// The swept outcome at `q`, if q is in the swept stretch (to `end`).
    #[inline]
    fn swept_at(&self, q: usize, end: usize) -> Option<bool> {
        let (from, bits) = self.swept.as_ref()?;
        if q < *from || q > end {
            return None;
        }
        let i = q - from;
        Some(bits[i / 64] >> (i % 64) & 1 == 1)
    }
}

#[cfg(test)]
thread_local! {
    /// (tests) sweep a lookahead the first time it is tried
    pub static SWEEP_AT_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Have one lookahead's walks taken enough steps to sweep it instead?
#[inline]
fn sweep_due(memo: &LookMemo, end: usize) -> bool {
    #[cfg(test)]
    if SWEEP_AT_ONCE.with(|s| s.get()) {
        return true;
    }
    let stretch = end.saturating_sub(memo.lo).saturating_add(1);
    memo.steps > stretch.saturating_mul(SWEEP_AFTER).saturating_add(SWEEP_SLACK)
}

impl Oracle {
    pub fn new() -> Oracle {
        Oracle::default()
    }

    /// A search over `text` up to `end` begins: the memos are kept only when
    /// `keep` (the next search of one finditer) and the text is the same.
    pub fn begin(&mut self, text: &[u32], end: usize, keep: bool) {
        let key = (text.as_ptr() as usize, text.len(), end);
        if !keep || key != self.key {
            self.gen = self.gen.wrapping_add(1);
            self.key = key;
        }
        self.walked = 0;
    }

    /// The memos are about another text or window: they start again.
    #[inline]
    fn check_key(&mut self, text: &[u32], end: usize) {
        let key = (text.as_ptr() as usize, text.len(), end);
        if key != self.key {
            self.gen = self.gen.wrapping_add(1);
            self.key = key;
        }
    }
}

/// Does test `look` hold at `p` (window end `end`)?
pub fn holds(pr: &Programs, look: u32, text: &[u32], p: usize, end: usize, oracle: &mut Oracle) -> bool {
    holds_at_depth(pr, look, text, p, end, oracle, 0)
}

fn holds_at_depth(pr: &Programs, look: u32, text: &[u32], p: usize, end: usize, oracle: &mut Oracle, depth: usize) -> bool {
    let d = &pr.looks[look as usize];
    match d {
        LookDef::Around { behind: false, negate, prog, memo: true, .. } => {
            let sub = &pr.subs[*prog as usize];
            run_memo(pr, look, sub, text, p, end, oracle, depth) != *negate
        }
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

/// Does a path through the lookahead program `prog` (lookaround `look`)
/// start at `q` (within the window's end)? As `run`, the walk memoized: see
/// the module's doc.
#[allow(clippy::too_many_arguments)]
fn run_memo(pr: &Programs, look: u32, prog: &Prog, text: &[u32], q: usize, end: usize, oracle: &mut Oracle, depth: usize) -> bool {
    oracle.check_key(text, end);
    if oracle.levels.len() <= depth {
        oracle.levels.resize_with(depth + 1, Level::default);
    }
    if oracle.memos.len() <= look as usize {
        oracle.memos.resize_with(look as usize + 1, LookMemo::default);
    }
    let n = prog.insts.len();
    let end = end.min(text.len());
    let mut memo = std::mem::take(&mut oracle.memos[look as usize]);
    if memo.gen != oracle.gen {
        memo.reset(oracle.gen);
    }
    if let Some(o) = memo.swept_at(q, end) {
        oracle.memos[look as usize] = memo;
        return o;
    }
    let mut lv = std::mem::take(&mut oracle.levels[depth]);
    if q <= end {
        memo.lo = memo.lo.min(q);
        if sweep_due(&memo, end) {
            let bits = sweep(pr, prog, text, memo.lo, end, oracle, depth, &mut lv);
            oracle.walked = oracle.walked.saturating_add(end - memo.lo + 1);
            memo.swept = Some((memo.lo, bits));
            memo.steps = 0;
            let o = memo.swept_at(q, end) == Some(true);
            oracle.levels[depth] = lv;
            oracle.memos[look as usize] = memo;
            return o;
        }
    }
    let mut key = std::mem::take(&mut oracle.keybuf);
    lv.cur.resize(n);
    lv.next.resize(n);
    lv.path.clear();
    let mut pos = q;
    let mut steps = 0usize;
    closure(pr, prog, prog.start, text, pos, end, &mut lv.cur, &mut lv.stack, oracle, depth);
    let outcome = loop {
        if lv.cur.as_slice().iter().any(|&pc| matches!(prog.insts[pc as usize], Inst::Match)) {
            break true;
        }
        if steps >= MEMO_AFTER {
            key.clear();
            key.extend(lv.cur.as_slice().iter().copied().filter(|&pc| matches!(prog.insts[pc as usize], Inst::Char { .. })));
            key.sort_unstable();
            let id = match memo.ids.get(&key[..]) {
                Some(&id) => id,
                None => {
                    if memo.ids.len() >= MEMO_SETS {
                        memo.clear();
                        lv.path.clear();
                    }
                    let id = memo.ids.len() as u32;
                    memo.ids.insert(key.clone().into_boxed_slice(), id);
                    memo.runs.push(BTreeMap::new());
                    id
                }
            };
            if let Some(o) = memo.known(id, pos) {
                break o;
            }
            match lv.path.last_mut() {
                Some(last) if last.0 == id && last.2 == pos => last.2 = pos + 1,
                _ => lv.path.push((id, pos, pos + 1)),
            }
        }
        if pos >= end {
            break false;
        }
        let c = text[pos];
        lv.next.clear();
        for i in 0..lv.cur.len() {
            let pc = lv.cur.get(i);
            if let Inst::Char { set, next } = prog.insts[pc as usize] {
                if pr.sets[set as usize].contains(c) {
                    closure(pr, prog, next, text, pos + 1, end, &mut lv.next, &mut lv.stack, oracle, depth);
                }
            }
        }
        if lv.next.is_empty() {
            break false;
        }
        std::mem::swap(&mut lv.cur, &mut lv.next);
        pos += 1;
        steps += 1;
    };
    oracle.walked = oracle.walked.saturating_add(steps);
    memo.steps = memo.steps.saturating_add(steps);
    for &(id, from, to) in &lv.path {
        memo.runs[id as usize].insert(from, (to, outcome));
    }
    lv.cur.clear();
    lv.next.clear();
    lv.path.clear();
    oracle.levels[depth] = lv;
    oracle.memos[look as usize] = memo;
    oracle.keybuf = key;
    outcome
}

/// The outcome of the lookahead program `prog` at every position from
/// `from` to `end`, a bit each, in one pass from the window's end back: at
/// a position, the instructions from which a path reaches Match are Match,
/// a character instruction whose character is there and whose next is one
/// of them at the next position, and the instructions that reach one of
/// those by steps that read nothing (a test on the way holding at the
/// position). O((end - from + 1) · m), whatever the sets the walks meet.
#[allow(clippy::too_many_arguments)]
fn sweep(pr: &Programs, prog: &Prog, text: &[u32], from: usize, end: usize, oracle: &mut Oracle, depth: usize, lv: &mut Level) -> Vec<u64> {
    let n = prog.insts.len();
    // the steps that read nothing, backwards (who steps to each instruction)
    let mut starts = vec![0u32; n + 1];
    let mut matches = Vec::new();
    let mut chars = Vec::new();
    for (pc, inst) in prog.insts.iter().enumerate() {
        match *inst {
            Inst::Split { x, y } => {
                starts[x as usize + 1] += 1;
                starts[y as usize + 1] += 1;
            }
            Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } | Inst::Look { next, .. } => starts[next as usize + 1] += 1,
            Inst::Char { set, next } => chars.push((pc as u32, set, next)),
            Inst::Match => matches.push(pc as u32),
            Inst::Run { .. } => {}
        }
    }
    for i in 0..n {
        starts[i + 1] += starts[i];
    }
    let mut fill = starts.clone();
    let mut preds = vec![0u32; starts[n] as usize];
    for (pc, inst) in prog.insts.iter().enumerate() {
        let mut add = |to: u32| {
            let k = &mut fill[to as usize];
            preds[*k as usize] = pc as u32;
            *k += 1;
        };
        match *inst {
            Inst::Split { x, y } => {
                add(x);
                add(y);
            }
            Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } | Inst::Look { next, .. } => add(next),
            _ => {}
        }
    }
    let mut bits = vec![0u64; (end - from + 1).div_ceil(64)];
    lv.cur.resize(n);
    lv.next.resize(n);
    // lv.next: the instructions that reach Match from the next position
    let mut p = end;
    loop {
        lv.cur.clear();
        lv.stack.clear();
        for &m in &matches {
            if lv.cur.insert(m) {
                lv.stack.push(m);
            }
        }
        if p < end {
            let c = text[p];
            for &(pc, set, next) in &chars {
                if lv.next.contains(next) && pr.sets[set as usize].contains(c) && lv.cur.insert(pc) {
                    lv.stack.push(pc);
                }
            }
        }
        while let Some(s) = lv.stack.pop() {
            for k in starts[s as usize]..starts[s as usize + 1] {
                let t = preds[k as usize];
                if lv.cur.contains(t) {
                    continue;
                }
                let pass = match prog.insts[t as usize] {
                    Inst::Look { look, .. } => holds_at_depth(pr, look, text, p, end, oracle, depth + 1),
                    Inst::Guard { .. } => p <= end,
                    _ => true,
                };
                if pass {
                    lv.cur.insert(t);
                    lv.stack.push(t);
                }
            }
        }
        if lv.cur.contains(prog.start) {
            let i = p - from;
            bits[i / 64] |= 1 << (i % 64);
        }
        if p == from {
            break;
        }
        std::mem::swap(&mut lv.cur, &mut lv.next);
        p -= 1;
    }
    lv.cur.clear();
    lv.next.clear();
    lv.stack.clear();
    bits
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
