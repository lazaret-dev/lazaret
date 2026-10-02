//! Programs: a pattern as a Thompson automaton whose alternatives are
//! ordered by priority (the order sre's backtracking tries them in).
//!
//! A regex has several programs over shared character sets and zero-width
//! tests: the forward program (with capture slots; an anchored entry, and an
//! unanchored one that first skips any characters, lazily); the fullmatch
//! program (the pattern, then the end of the window); the reverse program
//! (the pattern read backwards, without captures: it finds where a match
//! starts from where it ends); and one program per lookaround sub-pattern
//! that is not a one-character test.
//!
//! Counted repeats are expanded: `x{2,4}` is `xx(?:x(?:x)?)?`, so each
//! instruction stands for one place in the pattern and a set of them is a
//! state (the matchers' work is linear in the text times the program size).
//! The backtracker (backtrack.rs) has copies of the forward and fullmatch
//! programs of its own, in which a counted repeat of one set is a single
//! `Run`: it reads the run once and tries the exits in sre's order.
//!
//! `Guard` stands before each of sre's single-character repeats: in a
//! normal search it does nothing; in a match whose start lies past the
//! window's end (`pattern.match(s, 5, 2)`), where sre's single-character
//! repeats fail before trying anything, it fails.

use super::charset::CharSet;
use super::hir::{Hir, Look};
use super::syntax::Error;

pub const HOLE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inst {
    /// consume one character of the set
    Char { set: u32, next: u32 },
    /// go on at `x`, and (with lower priority) at `y`
    Split { x: u32, y: u32 },
    Jmp { next: u32 },
    /// record the position in a capture slot
    Save { slot: u32, next: u32 },
    /// a zero-width test
    Look { look: u32, next: u32 },
    /// see the module's doc
    Guard { next: u32 },
    /// a repeat of one set, min to max times (u32::MAX: no bound): the
    /// backtracker's programs only (the others have it expanded)
    Run { set: u32, min: u32, max: u32, greedy: bool, next: u32 },
    Match,
}

#[derive(Clone, Debug, Default)]
pub struct Prog {
    pub insts: Vec<Inst>,
    /// the anchored entry
    pub start: u32,
    /// the unanchored entry (the forward program only; else = start)
    pub start_unanchored: u32,
}

/// One step of a lookaround read as fixed sequences: a character of a set,
/// or a one-character test at that point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flat {
    Char(u32),
    Look(u32),
}

/// A lookaround as the matchers run it.
#[derive(Clone, Debug)]
pub enum LookDef {
    Begin,
    BeginLine,
    End,
    EndLine,
    EndString,
    Word { ascii: bool, negate: bool },
    Behind1 { set: u32, negate: bool },
    Ahead1 { set: u32, negate: bool },
    /// a sub-pattern (program `prog`) tried at the position (a lookahead) or
    /// `width` characters before it (a lookbehind, of fixed width); `flat`:
    /// the same as a few fixed sequences, when it is that simple
    Around { behind: bool, negate: bool, prog: u32, width: u32, max: u32, flat: Option<Box<[Box<[Flat]>]>>, first: Option<FirstTest> },
}

/// The characters the flat sequences of a lookaround can begin with (every
/// one begins with a character): a quick no before trying them.
#[derive(Clone, Copy, Debug)]
pub struct FirstTest {
    pub ascii: u128,
    /// can one begin with a character past ASCII?
    pub other: bool,
}

impl FirstTest {
    fn of(seqs: &[Vec<Flat>], sets: &[CharSet]) -> Option<FirstTest> {
        let mut t = FirstTest { ascii: 0, other: false };
        for s in seqs {
            match s.first() {
                Some(Flat::Char(set)) => {
                    let cs = &sets[*set as usize];
                    t.ascii |= cs.ascii_mask();
                    t.other |= cs.has_non_ascii();
                }
                _ => return None,
            }
        }
        Some(t)
    }

    #[inline]
    pub fn may_begin(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii & (1u128 << c) != 0
        } else {
            self.other
        }
    }
}

/// Sequences the flat form of a lookaround may have, and their length.
const MAX_FLAT: usize = 64;

/// A lookaround's sub-pattern as a few fixed sequences of characters and
/// one-character tests (any of which matching is a match), when it is one.
fn flatten(h: &Hir, looks: &[Look]) -> Option<Vec<Vec<Flat>>> {
    match h {
        Hir::Empty => Some(vec![Vec::new()]),
        Hir::Char(s) => Some(vec![vec![Flat::Char(*s)]]),
        Hir::Look(l) => match looks.get(*l as usize)? {
            Look::Around { .. } => None,
            _ => Some(vec![vec![Flat::Look(*l)]]),
        },
        Hir::Group(_, b) => flatten(b, looks),
        Hir::Concat(v) => {
            let mut acc: Vec<Vec<Flat>> = vec![Vec::new()];
            for x in v {
                let f = flatten(x, looks)?;
                if acc.len() * f.len() > MAX_FLAT {
                    return None;
                }
                let mut next = Vec::with_capacity(acc.len() * f.len());
                for a in &acc {
                    for b in &f {
                        let mut s = a.clone();
                        s.extend_from_slice(b);
                        if s.len() > MAX_FLAT {
                            return None;
                        }
                        next.push(s);
                    }
                }
                acc = next;
            }
            Some(acc)
        }
        Hir::Alt(v) => {
            let mut acc = Vec::new();
            for x in v {
                acc.extend(flatten(x, looks)?);
                if acc.len() > MAX_FLAT {
                    return None;
                }
            }
            Some(acc)
        }
        Hir::Repeat { min, max, body, .. } => {
            let m = (*max)? as usize;
            let f = flatten(body, looks)?;
            let mut acc: Vec<Vec<Flat>> = Vec::new();
            let mut power: Vec<Vec<Flat>> = vec![Vec::new()];
            if *min == 0 {
                acc.push(Vec::new());
            }
            for k in 1..=m {
                if power.len() * f.len() > MAX_FLAT {
                    return None;
                }
                let mut next = Vec::new();
                for a in &power {
                    for b in &f {
                        let mut s = a.clone();
                        s.extend_from_slice(b);
                        if s.len() > MAX_FLAT {
                            return None;
                        }
                        next.push(s);
                    }
                }
                power = next;
                if k >= *min as usize {
                    acc.extend(power.iter().cloned());
                    if acc.len() > MAX_FLAT {
                        return None;
                    }
                }
            }
            Some(acc)
        }
    }
}

impl LookDef {
    pub fn is_simple(&self) -> bool {
        !matches!(self, LookDef::Around { .. })
    }
}

pub struct Programs {
    pub sets: Vec<CharSet>,
    pub looks: Vec<LookDef>,
    pub fwd: Prog,
    pub full: Prog,
    pub rev: Prog,
    /// fwd and full for the backtracker: repeats of one set as Run
    pub fwd_bt: Prog,
    pub full_bt: Prog,
    /// the lookarounds' sub-pattern programs
    pub subs: Vec<Prog>,
    /// capture slots: two per group, one for the last group closed, one for
    /// the match's start
    pub slots: usize,
    /// the set of any character
    pub any_set: u32,
}

/// Instructions one program may have.
pub const MAX_INSTS: usize = 30_000;

struct Frag {
    start: u32,
    holes: Vec<(u32, u8)>,
}

struct Builder<'a> {
    insts: Vec<Inst>,
    saves: bool,
    reverse: bool,
    guards: bool,
    /// repeats of one set as Run instructions (the backtracker's programs)
    runs: bool,
    looks: &'a [u32],
}

fn too_large<T>() -> Result<T, Error> {
    Err(Error::Refused(format!("too large: the program would exceed {} instructions (counted repeats are expanded)", MAX_INSTS)))
}

impl<'a> Builder<'a> {
    fn push(&mut self, i: Inst) -> Result<u32, Error> {
        if self.insts.len() >= MAX_INSTS {
            return too_large();
        }
        self.insts.push(i);
        Ok((self.insts.len() - 1) as u32)
    }

    fn patch(&mut self, holes: &[(u32, u8)], to: u32) {
        for &(i, which) in holes {
            let inst = &mut self.insts[i as usize];
            match inst {
                Inst::Char { next, .. }
                | Inst::Jmp { next }
                | Inst::Save { next, .. }
                | Inst::Look { next, .. }
                | Inst::Guard { next }
                | Inst::Run { next, .. } => *next = to,
                Inst::Split { x, y } => {
                    if which == 0 {
                        *x = to
                    } else {
                        *y = to
                    }
                }
                Inst::Match => {}
            }
        }
    }

    fn empty(&mut self) -> Result<Frag, Error> {
        let i = self.push(Inst::Jmp { next: HOLE })?;
        Ok(Frag { start: i, holes: vec![(i, 0)] })
    }

    fn concat(&mut self, parts: Vec<Frag>) -> Result<Frag, Error> {
        let mut it = parts.into_iter();
        let first = match it.next() {
            None => return self.empty(),
            Some(f) => f,
        };
        let start = first.start;
        let mut holes = first.holes;
        for f in it {
            self.patch(&holes, f.start);
            holes = f.holes;
        }
        Ok(Frag { start, holes })
    }

    fn c(&mut self, h: &Hir) -> Result<Frag, Error> {
        match h {
            Hir::Empty => self.empty(),
            Hir::Char(set) => {
                let i = self.push(Inst::Char { set: *set, next: HOLE })?;
                Ok(Frag { start: i, holes: vec![(i, 0)] })
            }
            Hir::Look(l) => {
                let i = self.push(Inst::Look { look: self.looks[*l as usize], next: HOLE })?;
                Ok(Frag { start: i, holes: vec![(i, 0)] })
            }
            Hir::Group(g, body) => {
                if !self.saves {
                    return self.c(body);
                }
                let a = self.push(Inst::Save { slot: 2 * (*g as u32 - 1), next: HOLE })?;
                let f = self.c(body)?;
                self.patch(&[(a, 0)], f.start);
                let b = self.push(Inst::Save { slot: 2 * (*g as u32 - 1) + 1, next: HOLE })?;
                self.patch(&f.holes, b);
                Ok(Frag { start: a, holes: vec![(b, 0)] })
            }
            Hir::Concat(v) => {
                let mut parts = Vec::with_capacity(v.len());
                if self.reverse {
                    for x in v.iter().rev() {
                        parts.push(self.c(x)?);
                    }
                } else {
                    for x in v {
                        parts.push(self.c(x)?);
                    }
                }
                self.concat(parts)
            }
            Hir::Alt(v) => {
                if v.is_empty() {
                    return self.empty();
                }
                let mut holes = Vec::new();
                let mut start = HOLE;
                let mut last_split: Option<u32> = None;
                for (k, x) in v.iter().enumerate() {
                    let entry = if k + 1 < v.len() {
                        let s = self.push(Inst::Split { x: HOLE, y: HOLE })?;
                        let f = self.c(x)?;
                        self.patch(&[(s, 0)], f.start);
                        holes.extend(f.holes);
                        s
                    } else {
                        let f = self.c(x)?;
                        holes.extend(f.holes);
                        f.start
                    };
                    match last_split {
                        None => start = entry,
                        Some(s) => self.patch(&[(s, 1)], entry),
                    }
                    if k + 1 < v.len() {
                        last_split = Some(entry);
                    }
                }
                Ok(Frag { start, holes })
            }
            Hir::Repeat { min, max, greedy, simple, body } => {
                if self.runs {
                    if let Hir::Char(set) = **body {
                        let i = self.push(Inst::Run { set, min: *min, max: max.unwrap_or(u32::MAX), greedy: *greedy, next: HOLE })?;
                        return Ok(Frag { start: i, holes: vec![(i, 0)] });
                    }
                }
                let mut parts = Vec::new();
                if *simple && self.guards {
                    let g = self.push(Inst::Guard { next: HOLE })?;
                    parts.push(Frag { start: g, holes: vec![(g, 0)] });
                }
                for _ in 0..*min {
                    parts.push(self.c(body)?);
                }
                match max {
                    None => {
                        // a loop: prefer another iteration (greedy) or leaving (lazy)
                        let s = self.push(Inst::Split { x: HOLE, y: HOLE })?;
                        let f = self.c(body)?;
                        let (body_side, exit_side) = if *greedy { (0u8, 1u8) } else { (1u8, 0u8) };
                        self.patch(&[(s, body_side)], f.start);
                        self.patch(&f.holes, s);
                        parts.push(Frag { start: s, holes: vec![(s, exit_side)] });
                    }
                    Some(m) => {
                        let extra = m.saturating_sub(*min);
                        if extra > 0 {
                            let (body_side, exit_side) = if *greedy { (0u8, 1u8) } else { (1u8, 0u8) };
                            let mut exits: Vec<(u32, u8)> = Vec::new();
                            let mut start = HOLE;
                            let mut prev: Option<Vec<(u32, u8)>> = None;
                            for _ in 0..extra {
                                let s = self.push(Inst::Split { x: HOLE, y: HOLE })?;
                                let f = self.c(body)?;
                                self.patch(&[(s, body_side)], f.start);
                                exits.push((s, exit_side));
                                match prev.take() {
                                    None => start = s,
                                    Some(h) => self.patch(&h, s),
                                }
                                prev = Some(f.holes);
                            }
                            if let Some(h) = prev {
                                exits.extend(h);
                            }
                            parts.push(Frag { start, holes: exits });
                        }
                    }
                }
                if parts.is_empty() {
                    return self.empty();
                }
                self.concat(parts)
            }
        }
    }

    fn finish(mut self, f: Frag, tail: &[Inst]) -> Result<Prog, Error> {
        // the tail: zero or more Look instructions, then Match
        let mut holes = f.holes;
        for &t in tail {
            let i = self.push(t)?;
            self.patch(&holes, i);
            holes = if matches!(t, Inst::Match) { Vec::new() } else { vec![(i, 0)] };
        }
        Ok(Prog { start: f.start, start_unanchored: f.start, insts: self.insts })
    }
}

#[allow(clippy::too_many_arguments)]
fn build(h: &Hir, saves: bool, reverse: bool, guards: bool, look_ids: &[u32], head: Option<u32>, tail: &[Inst]) -> Result<Prog, Error> {
    build_with(h, saves, reverse, guards, false, look_ids, head, tail)
}

#[allow(clippy::too_many_arguments)]
fn build_with(h: &Hir, saves: bool, reverse: bool, guards: bool, runs: bool, look_ids: &[u32], head: Option<u32>, tail: &[Inst]) -> Result<Prog, Error> {
    let mut b = Builder { insts: Vec::new(), saves, reverse, guards, runs, looks: look_ids };
    let f = b.c(h)?;
    let f = match head {
        // (a Save of the match's start before the pattern)
        Some(slot) => {
            let s = b.push(Inst::Save { slot, next: f.start })?;
            Frag { start: s, holes: f.holes }
        }
        None => f,
    };
    b.finish(f, tail)
}

/// Compile a lowered pattern into its programs.
pub fn compile(hir: &Hir, sets: Vec<CharSet>, looks: &[Look], groups: usize) -> Result<Programs, Error> {
    let mut sets = sets;
    let any_set = match sets.iter().position(|s| s.is_all()) {
        Some(i) => i as u32,
        None => {
            sets.push(CharSet::all());
            (sets.len() - 1) as u32
        }
    };
    // the lookarounds: one-character tests as they are; the others get a
    // program each (their own lookarounds compiled first)
    let mut defs: Vec<LookDef> = Vec::with_capacity(looks.len());
    let mut subs: Vec<Prog> = Vec::new();
    let ids: Vec<u32> = (0..looks.len() as u32).collect();
    for l in looks.iter() {
        let d = match l {
            Look::Begin => LookDef::Begin,
            Look::BeginLine => LookDef::BeginLine,
            Look::End => LookDef::End,
            Look::EndLine => LookDef::EndLine,
            Look::EndString => LookDef::EndString,
            Look::Word { ascii, negate } => LookDef::Word { ascii: *ascii, negate: *negate },
            Look::Behind1 { set, negate } => LookDef::Behind1 { set: *set, negate: *negate },
            Look::Ahead1 { set, negate } => LookDef::Ahead1 { set: *set, negate: *negate },
            Look::Around { behind, negate, body, lo, hi } => {
                let p = build(body, false, false, true, &ids, None, &[Inst::Match])?;
                subs.push(p);
                // (a single-character repeat's guard matters only past the
                // window's end, where a flat sequence fails at its first
                // character anyway)
                let seqs = flatten(body, looks);
                let first = seqs.as_ref().and_then(|v| FirstTest::of(v, &sets));
                let flat = seqs.map(|v| v.into_iter().map(|s| s.into_boxed_slice()).collect());
                LookDef::Around {
                    behind: *behind,
                    negate: *negate,
                    prog: (subs.len() - 1) as u32,
                    width: *lo,
                    max: *hi,
                    flat,
                    first,
                }
            }
        };
        defs.push(d);
    }
    // (the end of the window, for fullmatch)
    defs.push(LookDef::EndString);
    let end_look = (defs.len() - 1) as u32;
    // slots: each group's start and end, the last group closed, the match's start
    let slots = 2 * groups + 2;
    let start_slot = (slots - 1) as u32;
    let mut fwd = build(hir, true, false, true, &ids, Some(start_slot), &[Inst::Match])?;
    // the unanchored entry: any characters first, as few as possible
    let u = fwd.insts.len() as u32;
    if fwd.insts.len() + 2 > MAX_INSTS {
        return too_large();
    }
    fwd.insts.push(Inst::Split { x: fwd.start, y: u + 1 });
    fwd.insts.push(Inst::Char { set: any_set, next: u });
    fwd.start_unanchored = u;
    let full = build(hir, true, false, true, &ids, Some(start_slot), &[Inst::Look { look: end_look, next: HOLE }, Inst::Match])?;
    let rev = build(hir, false, true, false, &ids, None, &[Inst::Match])?;
    // the backtracker's (normal windows only: no guards)
    let fwd_bt = build_with(hir, true, false, false, true, &ids, Some(start_slot), &[Inst::Match])?;
    let full_bt = build_with(hir, true, false, false, true, &ids, Some(start_slot), &[Inst::Look { look: end_look, next: HOLE }, Inst::Match])?;
    Ok(Programs { sets, looks: defs, fwd, full, rev, fwd_bt, full_bt, subs, slots, any_set })
}

/// The alphabet: the characters no set of a program tells apart share a
/// class. `classes` maps each range of `bounds` to its class.
#[derive(Clone, Debug)]
pub struct Alphabet {
    /// start of each range (sorted; the first is 0)
    pub bounds: Vec<u32>,
    /// the class of each range
    pub class_of_range: Vec<u16>,
    /// the class of each ASCII character
    pub ascii: [u16; 128],
    pub classes: usize,
    /// for each class, a character in it
    pub rep: Vec<u32>,
}

impl Alphabet {
    /// Classes telling apart every set in `sets`.
    pub fn new(sets: &[&CharSet]) -> Alphabet {
        // every boundary of every set
        let mut points: Vec<u32> = vec![0];
        for s in sets {
            for &(a, b) in s.ranges() {
                points.push(a);
                if b < u32::MAX {
                    points.push(b + 1);
                }
            }
        }
        points.sort_unstable();
        points.dedup();
        // each elementary range's signature: which sets hold it
        let n = points.len();
        let words = sets.len().div_ceil(64);
        let mut sig = vec![0u64; n * words.max(1)];
        for (k, s) in sets.iter().enumerate() {
            for &(a, b) in s.ranges() {
                let i = points.partition_point(|&p| p < a);
                let j = if b == u32::MAX { n } else { points.partition_point(|&p| p <= b) };
                for r in i..j {
                    sig[r * words.max(1) + k / 64] |= 1u64 << (k % 64);
                }
            }
        }
        let mut ids: std::collections::HashMap<&[u64], u16> = std::collections::HashMap::new();
        let mut class_of_range = Vec::with_capacity(n);
        let mut rep = Vec::new();
        let w = words.max(1);
        for r in 0..n {
            let key = &sig[r * w..(r + 1) * w];
            let next = ids.len() as u16;
            let id = *ids.entry(key).or_insert(next);
            if id as usize == rep.len() {
                rep.push(points[r]);
            }
            class_of_range.push(id);
        }
        let classes = rep.len();
        // merge adjacent ranges of one class
        let mut bounds = Vec::with_capacity(n);
        let mut cls = Vec::with_capacity(n);
        for r in 0..n {
            if cls.last() == Some(&class_of_range[r]) {
                continue;
            }
            bounds.push(points[r]);
            cls.push(class_of_range[r]);
        }
        let mut ascii = [0u16; 128];
        for (c, slot) in ascii.iter_mut().enumerate() {
            let i = bounds.partition_point(|&p| p <= c as u32) - 1;
            *slot = cls[i];
        }
        Alphabet { bounds, class_of_range: cls, ascii, classes, rep }
    }

    #[inline]
    pub fn class(&self, c: u32) -> u16 {
        if c < 128 {
            self.ascii[c as usize]
        } else {
            let i = self.bounds.partition_point(|&p| p <= c) - 1;
            self.class_of_range[i]
        }
    }
}
