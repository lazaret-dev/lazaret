//! The lazy DFA: the Pike VM's sets of states, each computed once and kept,
//! so a search reads one table entry per character.
//!
//! A DFA state is a list of program instructions — characters to consume,
//! zero-width tests still to make, the match — in priority order, with the
//! facts about the character on the side already read (forward: the one
//! before the position; reverse: the one after it). A transition on the
//! next character first makes the tests at the position: a one-character
//! test reads the stored facts and the character itself (`$` reads whether
//! that character is a "\n" ending the window: such a character is an
//! input of its own); a lookaround of more characters is tried on the text
//! (looks.rs), and a state that has one keys its transitions by the
//! outcomes too. Then the characters are consumed.
//!
//! Forward, leftmost-first: when the tests reach the match, the threads
//! after it are cut (the unanchored restart is the last thread), and the
//! search goes on while threads before it live; the last match seen ends
//! sre's match. Reverse (from that end, backwards, any path): the furthest
//! position from which a path reaches the pattern's start is where the
//! match starts (the first start sre tries that has a match). A
//! transition's result is flagged when the tests at its position reached
//! the match: matches are seen one character late.
//!
//! States are built on demand and kept per thread; past a size limit the
//! cache is emptied, and a search that would empty it too often gives up
//! (the Pike VM answers instead).

use super::charset::CharSet;
use super::looks::{self, Oracle, SparseSet};
use super::nfa::{Alphabet, Inst, LookDef, Prog, Programs};
use std::collections::HashMap;

// facts about the character on one side of a position
const F_EDGE: u64 = 1; // before: the text's start; after: the window's end
const F_NL: u64 = 1 << 1;
const F_NLEND: u64 = 1 << 2; // after: a "\n" that ends the window
const F_WORD_U: u64 = 1 << 3;
const F_WORD_A: u64 = 1 << 4;
const F_SET0: u32 = 5; // then one bit per one-character lookaround

/// A transition not computed yet.
const UNKNOWN: u32 = u32::MAX;
/// A transition that depends on lookarounds tried on the text (kept in the
/// state's rows, by their outcomes).
const ORACLE: u32 = u32::MAX - 1;
/// Tag of a state id the scan must look at (matched, dead, a start, one
/// with lookarounds to try, one that may not match where it is).
const TAG: u32 = 1 << 31;
const MASK: u32 = !TAG;

const FL_MATCHED: u8 = 1;
const FL_NO_MATCH_HERE: u8 = 2;

/// Bytes a cache may hold before it is emptied.
const CACHE_LIMIT: usize = 2 << 20;
/// Lookarounds of more than one character a state may have to try.
const MAX_COMPLEX: usize = 32;

/// What does not change: the alphabet and what each input means.
pub struct DfaShape {
    pub alpha: Alphabet,
    nclasses: usize,
    /// inputs: the classes, then EDGE (forward: the window's end; reverse:
    /// the text's start), then NLEND (a "\n" that ends the window)
    pub stride: usize,
    /// for each set, the inputs it holds (a bit per input)
    member: Vec<Vec<u64>>,
    before: Vec<u64>,
    after: Vec<u64>,
    /// one-character lookaround bit of each look (u32::MAX: none)
    look_bit: Vec<u32>,
    /// for a lookahead of more than one character whose sub-pattern must
    /// consume one: the inputs that can begin it (any other next character
    /// fails it at once, so its outcome is known without the text); None:
    /// it is always tried on the text
    first_inputs: Vec<Option<Vec<u64>>>,
    pub has_nlend: bool,
    /// can the DFA run these programs at all?
    pub usable: bool,
}

/// The looks the programs' own instructions test (not their sub-patterns').
fn looks_used(pr: &Programs) -> Vec<bool> {
    let mut used = vec![false; pr.looks.len()];
    for prog in [&pr.fwd, &pr.full, &pr.rev] {
        for i in &prog.insts {
            if let Inst::Look { look, .. } = *i {
                used[look as usize] = true;
            }
        }
    }
    used
}

impl DfaShape {
    pub fn new(pr: &Programs) -> DfaShape {
        let used = looks_used(pr);
        let mut sets: Vec<&CharSet> = pr.sets.iter().collect();
        let nl = CharSet::one(0x0A);
        let wu = super::charset::word_set(false);
        let wa = super::charset::word_set(true);
        sets.push(&nl);
        sets.push(&wu);
        sets.push(&wa);
        let alpha = Alphabet::new(&sets);
        let nclasses = alpha.classes;
        let stride = nclasses + 2;
        let edge = nclasses;
        let nlend = nclasses + 1;
        let words = stride.div_ceil(64);
        let mut member = Vec::with_capacity(pr.sets.len());
        for s in &pr.sets {
            let mut bits = vec![0u64; words];
            for (c, &rep) in alpha.rep.iter().enumerate() {
                if s.contains(rep) {
                    bits[c / 64] |= 1 << (c % 64);
                }
            }
            if s.contains(0x0A) {
                bits[nlend / 64] |= 1 << (nlend % 64);
            }
            member.push(bits);
        }
        let mut look_bit = vec![u32::MAX; pr.looks.len()];
        let mut nbits = F_SET0;
        let mut usable = true;
        let mut before_used = 0u64;
        let mut after_used = 0u64;
        for (k, d) in pr.looks.iter().enumerate() {
            if !used[k] {
                continue;
            }
            match *d {
                LookDef::Begin => before_used |= F_EDGE,
                LookDef::BeginLine => before_used |= F_EDGE | F_NL,
                LookDef::End => after_used |= F_EDGE | F_NLEND,
                LookDef::EndLine => after_used |= F_EDGE | F_NL,
                LookDef::EndString => after_used |= F_EDGE,
                LookDef::Word { ascii, .. } => {
                    let w = if ascii { F_WORD_A } else { F_WORD_U };
                    before_used |= F_EDGE | w;
                    after_used |= F_EDGE | w;
                }
                LookDef::Behind1 { .. } | LookDef::Ahead1 { .. } => {
                    if nbits >= 64 {
                        usable = false;
                        continue;
                    }
                    look_bit[k] = nbits;
                    if matches!(d, LookDef::Behind1 { .. }) {
                        before_used |= F_EDGE | (1 << nbits);
                    } else {
                        after_used |= F_EDGE | (1 << nbits);
                    }
                    nbits += 1;
                }
                LookDef::Around { .. } => {}
            }
        }
        let has_nlend = after_used & F_NLEND != 0;
        // the facts of a character, on either side
        let facts = |c: u32| -> u64 {
            let mut f = 0u64;
            if c == 0x0A {
                f |= F_NL;
            }
            if wu.contains(c) {
                f |= F_WORD_U;
            }
            if wa.contains(c) {
                f |= F_WORD_A;
            }
            for (k, d) in pr.looks.iter().enumerate() {
                if let LookDef::Behind1 { set, .. } | LookDef::Ahead1 { set, .. } = *d {
                    if look_bit[k] != u32::MAX && pr.sets[set as usize].contains(c) {
                        f |= 1 << look_bit[k];
                    }
                }
            }
            f
        };
        let mut before = vec![0u64; stride];
        let mut after = vec![0u64; stride];
        for c in 0..nclasses {
            let f = facts(alpha.rep[c]);
            before[c] = f & before_used;
            after[c] = f & after_used;
        }
        before[edge] = F_EDGE & before_used;
        after[edge] = F_EDGE & after_used;
        before[nlend] = facts(0x0A) & before_used;
        after[nlend] = (facts(0x0A) | F_NLEND) & after_used;
        let mut first_inputs = vec![None; pr.looks.len()];
        for (k, d) in pr.looks.iter().enumerate() {
            if let LookDef::Around { behind: false, prog, .. } = *d {
                if let Some(first) = super::prefilter::first_set(pr, &pr.subs[prog as usize]) {
                    let mut bits = vec![0u64; words];
                    for (c, &rep) in alpha.rep.iter().enumerate() {
                        if first.contains(rep) {
                            bits[c / 64] |= 1 << (c % 64);
                        }
                    }
                    if first.contains(0x0A) {
                        bits[nlend / 64] |= 1 << (nlend % 64);
                    }
                    first_inputs[k] = Some(bits);
                }
            }
        }
        DfaShape { alpha, nclasses, stride, member, before, after, look_bit, first_inputs, has_nlend, usable }
    }

    /// Does lookaround `look`'s outcome at a position whose next input is
    /// `input` need the text (forward)? When not, it is "the sub-pattern
    /// fails".
    #[inline]
    fn needs_text(&self, look: u32, input: usize) -> bool {
        match &self.first_inputs[look as usize] {
            None => true,
            Some(bits) => input < self.nclasses + 2 && input != self.edge() && bits[input / 64] & (1 << (input % 64)) != 0,
        }
    }

    #[inline]
    fn holds(&self, set: u32, input: usize) -> bool {
        self.member[set as usize][input / 64] & (1 << (input % 64)) != 0
    }

    /// The input of the character at `i` of a window ending at `end`.
    #[inline]
    pub fn input_at(&self, text: &[u32], i: usize, end: usize) -> usize {
        let c = text[i];
        if c == 0x0A && i + 1 == end && self.has_nlend {
            self.nclasses + 1
        } else {
            self.alpha.class(c) as usize
        }
    }

    #[inline]
    pub fn edge(&self) -> usize {
        self.nclasses
    }

    /// Before-facts at position p.
    #[inline]
    fn before_at(&self, text: &[u32], p: usize) -> u64 {
        if p == 0 {
            self.before[self.edge()]
        } else {
            self.before[self.alpha.class(text[p - 1]) as usize]
        }
    }
}

/// Does a one-character test hold, given the facts on both sides?
#[inline]
fn simple_ok(shape: &DfaShape, look: usize, d: &LookDef, before: u64, after: u64) -> bool {
    match *d {
        LookDef::Begin => before & F_EDGE != 0,
        LookDef::BeginLine => before & (F_EDGE | F_NL) != 0,
        LookDef::End => after & (F_EDGE | F_NLEND) != 0,
        LookDef::EndLine => after & (F_EDGE | F_NL) != 0,
        LookDef::EndString => after & F_EDGE != 0,
        LookDef::Word { ascii, negate } => {
            if before & F_EDGE != 0 && after & F_EDGE != 0 {
                return false;
            }
            let w = if ascii { F_WORD_A } else { F_WORD_U };
            let that = before & w != 0;
            let this = after & w != 0;
            if negate {
                this == that
            } else {
                this != that
            }
        }
        LookDef::Behind1 { negate, .. } => {
            let hit = before & F_EDGE == 0 && before & (1 << shape.look_bit[look]) != 0;
            hit != negate
        }
        LookDef::Ahead1 { negate, .. } => {
            let hit = after & F_EDGE == 0 && after & (1 << shape.look_bit[look]) != 0;
            hit != negate
        }
        LookDef::Around { .. } => false,
    }
}

/// A quick hash for the DFA's own keys (lists of instruction numbers).
#[derive(Default, Clone, Copy)]
pub struct QuickHash(u64);

impl std::hash::Hasher for QuickHash {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            let v = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
            h = (h.rotate_left(5) ^ v).wrapping_mul(0x51_7C_C1_B7_27_22_0A_95);
        }
        for &b in chunks.remainder() {
            h = (h.rotate_left(5) ^ b as u64).wrapping_mul(0x51_7C_C1_B7_27_22_0A_95);
        }
        self.0 = h;
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x51_7C_C1_B7_27_22_0A_95);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0 = (self.0.rotate_left(5) ^ i as u64).wrapping_mul(0x51_7C_C1_B7_27_22_0A_95);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x51_7C_C1_B7_27_22_0A_95);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

type QuickMap<K, V> = HashMap<K, V, std::hash::BuildHasherDefault<QuickHash>>;

struct State {
    list: Box<[u32]>,
    bits: u64,
    flags: u8,
    /// the unanchored start (only the restart thread is alive)
    start: bool,
    /// the lookarounds of more than one character its tests may try
    complex: Box<[u32]>,
    /// for each set of their outcomes seen so far, where its row of
    /// transitions is (in `crows`)
    rows: Vec<(u64, u32)>,
}

/// A DFA's states, built on demand, for one program (one per thread at a
/// time).
pub struct DfaCache {
    states: Vec<State>,
    map: QuickMap<(Box<[u32]>, u64, u8), u32>,
    /// transitions: premultiplied, tagged state ids (UNKNOWN: not yet)
    trans: Vec<u32>,
    /// transitions of states with lookarounds to try: a row per set of outcomes
    crows: Vec<u32>,
    stride: usize,
    bytes: usize,
    pub clears: usize,
    seen: SparseSet,
    seen2: SparseSet,
    stack: Vec<u32>,
    resolved: Vec<u32>,
    next: Vec<u32>,
    /// the start lists (anchored, unanchored) of the program
    starts: [Box<[u32]>; 2],
    /// the start states made so far: (facts, flags, unanchored, id)
    start_ids: Vec<(u64, u8, bool, u32)>,
    ready: bool,
    /// are unanchored start states tagged (a skip filter is used)?
    tag_starts: bool,
}

impl Default for DfaCache {
    fn default() -> Self {
        DfaCache::new()
    }
}

/// Why a scan stopped without an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GiveUp;

impl DfaCache {
    pub fn new() -> DfaCache {
        DfaCache {
            states: Vec::new(),
            map: QuickMap::default(),
            trans: Vec::new(),
            crows: Vec::new(),
            stride: 1,
            bytes: 0,
            clears: 0,
            seen: SparseSet::new(0),
            seen2: SparseSet::new(0),
            stack: Vec::new(),
            resolved: Vec::new(),
            next: Vec::new(),
            starts: [Box::new([]), Box::new([])],
            start_ids: Vec::new(),
            ready: false,
            tag_starts: false,
        }
    }

    fn clear(&mut self) {
        self.states.clear();
        self.map.clear();
        self.trans.clear();
        self.crows.clear();
        self.start_ids.clear();
        self.bytes = 0;
        self.clears += 1;
    }

    /// The unconditional closure of `from` (through splits, jumps, saves,
    /// guards; stopping at characters, tests and the match), appended to
    /// `out` in priority order, each instruction once (`seen`).
    fn closure(prog: &Prog, from: u32, out: &mut Vec<u32>, seen: &mut SparseSet, stack: &mut Vec<u32>) {
        stack.clear();
        stack.push(from);
        while let Some(pc) = stack.pop() {
            if !seen.insert(pc) {
                continue;
            }
            match prog.insts[pc as usize] {
                Inst::Split { x, y } => {
                    stack.push(y);
                    stack.push(x);
                }
                Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } => stack.push(next),
                Inst::Char { .. } | Inst::Look { .. } | Inst::Match => out.push(pc),
                Inst::Run { .. } => {}
            }
        }
    }

    /// The lookarounds of more than one character the tests of `list` may
    /// reach (None: too many).
    fn complex_of(pr: &Programs, prog: &Prog, list: &[u32], seen: &mut SparseSet, stack: &mut Vec<u32>) -> Option<Box<[u32]>> {
        let mut out: Vec<u32> = Vec::new();
        seen.clear();
        for &pc in list {
            if !matches!(prog.insts[pc as usize], Inst::Look { .. }) {
                continue;
            }
            stack.clear();
            stack.push(pc);
            while let Some(x) = stack.pop() {
                if !seen.insert(x) {
                    continue;
                }
                match prog.insts[x as usize] {
                    Inst::Split { x: a, y: b } => {
                        stack.push(b);
                        stack.push(a);
                    }
                    Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } => stack.push(next),
                    Inst::Look { look, next } => {
                        if !pr.looks[look as usize].is_simple() && !out.contains(&look) {
                            out.push(look);
                        }
                        stack.push(next);
                    }
                    Inst::Char { .. } | Inst::Match | Inst::Run { .. } => {}
                }
            }
        }
        if out.len() > MAX_COMPLEX {
            return None;
        }
        Some(out.into_boxed_slice())
    }

    #[allow(clippy::too_many_arguments)]
    fn intern(&mut self, pr: &Programs, prog: &Prog, ordered: bool, list: Vec<u32>, bits: u64, flags: u8) -> Result<u32, GiveUp> {
        let mut list = list;
        if !ordered {
            list.sort_unstable();
        }
        let key = (list.into_boxed_slice(), bits, flags);
        if let Some(&id) = self.map.get(&key) {
            return Ok(id);
        }
        let complex = match Self::complex_of(pr, prog, &key.0, &mut self.seen2, &mut self.stack) {
            Some(c) => c,
            None => return Err(GiveUp),
        };
        let index = self.states.len() as u32;
        let dead = key.0.is_empty();
        let start = flags == 0 && *self.starts[1] == *key.0;
        // (a state with lookarounds to try is not tagged: its transitions
        // that need the text are, by the ORACLE entry)
        let special = dead || flags != 0 || (start && self.tag_starts);
        let id = (index * self.stride as u32) | if special { TAG } else { 0 };
        self.bytes += key.0.len() * 8 + self.stride * 4 + 96 + complex.len() * 4;
        self.states.push(State { list: key.0.clone(), bits, flags, start, complex, rows: Vec::new() });
        self.trans.resize(self.trans.len() + self.stride, UNKNOWN);
        self.map.insert(key, id);
        Ok(id)
    }

    #[inline]
    fn state(&self, id: u32) -> &State {
        &self.states[(id & MASK) as usize / self.stride]
    }

    fn prepare(&mut self, shape: &DfaShape, prog: &Prog, tag_starts: bool) {
        if self.ready && self.tag_starts == tag_starts {
            return;
        }
        if self.ready {
            // (a change of tagging: start over)
            self.clear();
        }
        let n = prog.insts.len();
        self.seen.resize(n);
        self.seen2.resize(n);
        self.stride = shape.stride;
        self.tag_starts = tag_starts;
        let mut v = Vec::new();
        self.seen.clear();
        Self::closure(prog, prog.start, &mut v, &mut self.seen, &mut self.stack);
        let mut u = Vec::new();
        self.seen.clear();
        Self::closure(prog, prog.start_unanchored, &mut u, &mut self.seen, &mut self.stack);
        self.starts = [v.into_boxed_slice(), u.into_boxed_slice()];
        self.ready = true;
    }

    /// The start state for these facts.
    fn start(&mut self, pr: &Programs, prog: &Prog, ordered: bool, unanchored: bool, bits: u64, no_match_here: bool) -> Result<u32, GiveUp> {
        let flags = if no_match_here { FL_NO_MATCH_HERE } else { 0 };
        if let Some(&(_, _, _, id)) = self.start_ids.iter().find(|&&(b, f, u, _)| b == bits && f == flags && u == unanchored) {
            return Ok(id);
        }
        let list = self.starts[unanchored as usize].to_vec();
        let id = self.intern(pr, prog, ordered, list, bits, flags)?;
        if self.start_ids.len() < 64 {
            self.start_ids.push((bits, flags, unanchored, id));
        }
        Ok(id)
    }

    /// Compute the transition of `id` on `input` (outcomes of its complex
    /// lookarounds in `outcomes`).
    #[allow(clippy::too_many_arguments)]
    fn compute(&mut self, shape: &DfaShape, pr: &Programs, prog: &Prog, reverse: bool, ordered: bool, id: u32, input: usize, outcomes: u64) -> Result<u32, GiveUp> {
        let si = (id & MASK) as usize / self.stride;
        let (bits, flags) = (self.states[si].bits, self.states[si].flags);
        let (before, after) = if reverse { (shape.before[input], bits) } else { (bits, shape.after[input]) };
        let edge = input == shape.edge();
        // the tests at this position, thread by thread in priority order
        self.seen.clear();
        self.resolved.clear();
        let mut matched = false;
        let list = std::mem::take(&mut self.states[si].list);
        let complex = std::mem::take(&mut self.states[si].complex);
        'threads: for &pc in list.iter() {
            self.stack.clear();
            self.stack.push(pc);
            while let Some(x) = self.stack.pop() {
                if !self.seen.insert(x) {
                    continue;
                }
                match prog.insts[x as usize] {
                    Inst::Char { .. } => self.resolved.push(x),
                    Inst::Match => {
                        if flags & FL_NO_MATCH_HERE != 0 {
                            continue;
                        }
                        matched = true;
                        if ordered {
                            // (the threads after it have lower priority)
                            break 'threads;
                        }
                    }
                    Inst::Look { look, next } => {
                        let d = &pr.looks[look as usize];
                        let ok = if d.is_simple() {
                            simple_ok(shape, look as usize, d, before, after)
                        } else {
                            match complex.iter().position(|&l| l == look) {
                                Some(k) => outcomes & (1 << k) != 0,
                                None => false,
                            }
                        };
                        if ok {
                            self.stack.push(next);
                        }
                    }
                    Inst::Split { x: a, y: b } => {
                        self.stack.push(b);
                        self.stack.push(a);
                    }
                    Inst::Jmp { next } | Inst::Save { next, .. } | Inst::Guard { next } => self.stack.push(next),
                    Inst::Run { .. } => {}
                }
            }
        }
        self.states[si].list = list;
        self.states[si].complex = complex;
        // then the character
        let mut next = std::mem::take(&mut self.next);
        next.clear();
        if !edge {
            self.seen.clear();
            for k in 0..self.resolved.len() {
                if let Inst::Char { set, next: to } = prog.insts[self.resolved[k] as usize] {
                    if shape.holds(set, input) {
                        Self::closure(prog, to, &mut next, &mut self.seen, &mut self.stack);
                    }
                }
            }
        }
        let nbits = if reverse { shape.after[input] } else { shape.before[input] };
        let t = self.intern(pr, prog, ordered, next.clone(), nbits, if matched { FL_MATCHED } else { 0 });
        self.next = next;
        t
    }

    /// The transition of `id` on `input` at `p` (trying its lookarounds of
    /// more than one character on the text when it has some).
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn step(
        &mut self,
        shape: &DfaShape,
        pr: &Programs,
        prog: &Prog,
        reverse: bool,
        ordered: bool,
        id: u32,
        input: usize,
        text: &[u32],
        p: usize,
        end: usize,
        oracle: &mut Oracle,
    ) -> Result<u32, GiveUp> {
        let slot = (id & MASK) as usize + input;
        let t = self.trans[slot];
        if t < ORACLE {
            return Ok(t);
        }
        let si = (id & MASK) as usize / self.stride;
        // a lookahead the next character cannot begin fails: its outcome
        // is its negation, whatever the text
        let failed = |look: u32| matches!(pr.looks[look as usize], LookDef::Around { negate: true, .. });
        if t == UNKNOWN {
            let complex = &self.states[si].complex;
            if complex.is_empty() || (!reverse && complex.iter().all(|&l| !shape.needs_text(l, input))) {
                let mut outcomes = 0u64;
                for (k, &l) in complex.iter().enumerate() {
                    if failed(l) {
                        outcomes |= 1 << k;
                    }
                }
                let t = self.compute(shape, pr, prog, reverse, ordered, id, input, outcomes)?;
                self.trans[slot] = t;
                return Ok(t);
            }
            self.trans[slot] = ORACLE;
        }
        let mut outcomes = 0u64;
        for k in 0..self.states[si].complex.len() {
            let look = self.states[si].complex[k];
            let v = if !reverse && !shape.needs_text(look, input) { failed(look) } else { looks::holds(pr, look, text, p, end, oracle) };
            if v {
                outcomes |= 1 << k;
            }
        }
        let row = match self.states[si].rows.iter().find(|&&(o, _)| o == outcomes) {
            Some(&(_, off)) => off as usize,
            None => {
                let off = self.crows.len();
                self.crows.resize(off + self.stride, UNKNOWN);
                self.bytes += self.stride * 4 + 16;
                self.states[si].rows.push((outcomes, off as u32));
                off
            }
        };
        let t = self.crows[row + input];
        if t != UNKNOWN {
            return Ok(t);
        }
        let t = self.compute(shape, pr, prog, reverse, ordered, id, input, outcomes)?;
        self.crows[row + input] = t;
        Ok(t)
    }

    /// Empty the cache when it is full, keeping the state `id` (its new id).
    fn maybe_clear(&mut self, pr: &Programs, prog: &Prog, ordered: bool, id: u32) -> Result<u32, GiveUp> {
        if self.bytes <= CACHE_LIMIT {
            return Ok(id);
        }
        let si = (id & MASK) as usize / self.stride;
        let (list, bits, flags) = (self.states[si].list.to_vec(), self.states[si].bits, self.states[si].flags);
        self.clear();
        self.intern(pr, prog, ordered, list, bits, flags)
    }

    pub fn states(&self) -> usize {
        self.states.len()
    }
}

/// A forward search's answer: where the leftmost-first match ends, and a
/// position no thread of it started before.
pub struct Found {
    pub end: usize,
    pub lower: usize,
}

/// A scan for the next position a match may start at (the unanchored start
/// state only: no thread is alive but the restart).
pub trait Skip {
    fn next(&self, text: &[u32], from: usize, end: usize) -> Option<usize>;
}

/// The forward, leftmost-first search of `prog` in text[start..end].
#[allow(clippy::too_many_arguments)]
pub fn forward(
    shape: &DfaShape,
    pr: &Programs,
    prog: &Prog,
    cache: &mut DfaCache,
    text: &[u32],
    start: usize,
    end: usize,
    anchored: bool,
    must_advance: bool,
    skip: Option<&dyn Skip>,
    oracle: &mut Oracle,
    reached: &mut usize,
) -> Result<Option<Found>, GiveUp> {
    // (whether start states are tagged is the regex's choice, whatever the
    // search: tagging them differently would empty the cache)
    cache.prepare(shape, prog, skip.is_some());
    let skip = if anchored { None } else { skip };
    let clears = cache.clears;
    let mut s = cache.start(pr, prog, true, !anchored, shape.before_at(text, start), must_advance)?;
    let mut p = start;
    let mut last: Option<usize> = None;
    let mut lower = start;
    let mut since_clear = 0usize;
    let fast_end = if shape.has_nlend { end.saturating_sub(1) } else { end };
    loop {
        // the fast loop: untagged states, known transitions
        if s & TAG == 0 {
            while p < fast_end {
                let t = cache.trans[s as usize + shape.alpha.class(text[p]) as usize];
                if t & TAG != 0 {
                    break;
                }
                s = t;
                p += 1;
            }
        }
        if s & TAG != 0 {
            if let Some(k) = skip {
                if cache.state(s).start {
                    // The state is the start's: whatever threads it stands for
                    // are where a fresh one is, and none of them gets past a
                    // character no match starts with. (A thread that began
                    // earlier may be merged into it, so only a real skip says
                    // no thread of the match began before.)
                    match k.next(text, p, end) {
                        None => break,
                        Some(q) => {
                            if q > p {
                                p = q;
                                s = cache.start(pr, prog, true, true, shape.before_at(text, p), false)?;
                                lower = p;
                            }
                        }
                    }
                }
            }
        }
        if p >= end {
            let t = cache.step(shape, pr, prog, false, true, s, shape.edge(), text, p, end, oracle)?;
            if cache.state(t).flags & FL_MATCHED != 0 {
                last = Some(end);
            }
            break;
        }
        let input = shape.input_at(text, p, end);
        let t = cache.step(shape, pr, prog, false, true, s, input, text, p, end, oracle)?;
        let st = cache.state(t);
        if st.flags & FL_MATCHED != 0 {
            last = Some(p);
        }
        if st.list.is_empty() {
            break;
        }
        s = t;
        p += 1;
        since_clear += 1;
        if cache.bytes > CACHE_LIMIT {
            if cache.clears - clears >= 3 && since_clear < 64 * cache.states.len().max(1) {
                return Err(GiveUp);
            }
            s = cache.maybe_clear(pr, prog, true, s)?;
            since_clear = 0;
        }
    }
    *reached = p;
    Ok(last.map(|e| Found { end: e, lower }))
}

/// The reverse search: from `e` back to `lower`, the smallest s with a path
/// of the reverse program from e to s (the start of sre's match).
#[allow(clippy::too_many_arguments)]
pub fn reverse(
    shape: &DfaShape,
    pr: &Programs,
    prog: &Prog,
    cache: &mut DfaCache,
    text: &[u32],
    lower: usize,
    e: usize,
    end: usize,
    oracle: &mut Oracle,
) -> Result<Option<usize>, GiveUp> {
    cache.prepare(shape, prog, false);
    let clears = cache.clears;
    let after_bits = if e >= end { shape.after[shape.edge()] } else { shape.after[shape.input_at(text, e, end)] };
    let mut s = cache.start(pr, prog, false, false, after_bits, false)?;
    let mut p = e;
    let mut best: Option<usize> = None;
    let mut since_clear = 0usize;
    // (the last character of the window may be a "\n" of its own input)
    let fast_top = if shape.has_nlend { end.saturating_sub(1) } else { usize::MAX };
    loop {
        if s & TAG == 0 {
            while p > lower && p <= fast_top {
                let t = cache.trans[s as usize + shape.alpha.class(text[p - 1]) as usize];
                if t & TAG != 0 {
                    break;
                }
                s = t;
                p -= 1;
            }
        }
        if p <= lower {
            // the tests at the lower bound read the character before it
            let input = if p == 0 { shape.edge() } else { shape.alpha.class(text[p - 1]) as usize };
            let t = cache.step(shape, pr, prog, true, false, s, input, text, p, end, oracle)?;
            if cache.state(t).flags & FL_MATCHED != 0 {
                best = Some(p);
            }
            break;
        }
        let input = shape.input_at(text, p - 1, end);
        let t = cache.step(shape, pr, prog, true, false, s, input, text, p, end, oracle)?;
        let st = cache.state(t);
        if st.flags & FL_MATCHED != 0 {
            best = Some(p);
        }
        if st.list.is_empty() {
            break;
        }
        s = t;
        p -= 1;
        since_clear += 1;
        if cache.bytes > CACHE_LIMIT {
            if cache.clears - clears >= 3 && since_clear < 64 * cache.states.len().max(1) {
                return Err(GiveUp);
            }
            s = cache.maybe_clear(pr, prog, false, s)?;
            since_clear = 0;
        }
    }
    Ok(best)
}
