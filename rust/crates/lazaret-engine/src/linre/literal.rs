//! Strings a match must hold or start with, read from the pattern.
//!
//! A string here is a sequence of units, each a few characters (one, or a
//! letter's case variants under IGNORECASE: `(?i)s` is s, S, ſ). From the
//! lowered pattern this reads, for a sub-pattern: the finite set of strings
//! it can match, when that set is small (`exact`); the strings every match
//! starts with (`prefix`) or ends with (`suffix`); and the strings one of
//! which every match holds (`need`), joining a run of exact items with the
//! suffix before it and the prefix after it. Lookarounds count as empty
//! (what they test may lie outside the match, before `pos`), and so does
//! anything zero-width.
//!
//! A search of a text holding none of a pattern's needed strings answers at
//! once; a search whose matches all start with one of a few strings looks
//! for them (`LitSet::find`) instead of stepping the DFA over everything
//! between.

use super::charset::CharSet;
use super::hir::Hir;

/// A unit with more characters than this ends a string.
const MAX_UNIT: usize = 4;
/// Sets of more strings than this are not kept.
const MAX_LITS: usize = 64;
/// Strings are cut at this length (a prefix of a needed string is needed).
const MAX_LEN: usize = 24;

pub type Unit = Vec<u32>;
pub type Lit = Vec<Unit>;

fn unit_of(set: &CharSet) -> Option<Unit> {
    set.chars_upto(MAX_UNIT)
}

/// The concatenation of two sets of strings (None: too many).
fn cross(a: &[Lit], b: &[Lit]) -> Option<Vec<Lit>> {
    if a.len() * b.len() > MAX_LITS {
        return None;
    }
    let mut out = Vec::with_capacity(a.len() * b.len());
    for x in a {
        for y in b {
            let mut z = x.clone();
            z.extend(y.iter().cloned());
            z.truncate(MAX_LEN);
            if !out.contains(&z) {
                out.push(z);
            }
        }
    }
    Some(out)
}

fn union(mut a: Vec<Lit>, b: Vec<Lit>) -> Option<Vec<Lit>> {
    for x in b {
        if !a.contains(&x) {
            a.push(x);
        }
    }
    if a.len() > MAX_LITS {
        None
    } else {
        Some(a)
    }
}

pub struct Analysis<'a> {
    pub sets: &'a [CharSet],
}

impl<'a> Analysis<'a> {
    /// The strings `h` can match, when they are few (lookarounds: empty).
    pub fn exact(&self, h: &Hir) -> Option<Vec<Lit>> {
        match h {
            Hir::Empty | Hir::Look(_) => Some(vec![Vec::new()]),
            Hir::Char(s) => unit_of(&self.sets[*s as usize]).map(|u| vec![vec![u]]),
            Hir::Group(_, b) => self.exact(b),
            Hir::Concat(v) => {
                let mut acc: Vec<Lit> = vec![Vec::new()];
                for x in v {
                    let e = self.exact(x)?;
                    acc = cross(&acc, &e)?;
                    if acc.iter().any(|l| l.len() >= MAX_LEN) {
                        return None;
                    }
                }
                Some(acc)
            }
            Hir::Alt(v) => {
                let mut acc = Vec::new();
                for x in v {
                    acc = union(acc, self.exact(x)?)?;
                }
                Some(acc)
            }
            Hir::Repeat { min, max, body, .. } => {
                let m = (*max)?;
                if m > 8 {
                    return None;
                }
                let e = self.exact(body)?;
                let mut acc: Vec<Lit> = if *min == 0 { vec![Vec::new()] } else { Vec::new() };
                let mut power: Vec<Lit> = vec![Vec::new()];
                for k in 1..=m {
                    power = cross(&power, &e)?;
                    if k >= *min {
                        acc = union(acc, power.clone())?;
                    }
                }
                Some(acc)
            }
        }
    }

    /// Strings every match of `h` starts with (each may be the whole match).
    pub fn prefix(&self, h: &Hir) -> Option<Vec<Lit>> {
        if let Some(e) = self.exact(h) {
            return Some(e);
        }
        match h {
            Hir::Group(_, b) => self.prefix(b),
            Hir::Concat(v) => self.prefix_seq(v),
            Hir::Alt(v) => {
                let mut acc = Vec::new();
                for x in v {
                    acc = union(acc, self.prefix(x)?)?;
                }
                Some(acc)
            }
            Hir::Repeat { min, body, .. } if *min >= 1 => self.prefix(body),
            _ => Some(vec![Vec::new()]),
        }
    }

    /// Strings every match of the sequence `v` starts with.
    fn prefix_seq(&self, v: &[Hir]) -> Option<Vec<Lit>> {
        // (`acc`: what every match starts with so far; `done`: the strings
        // of the matches that took one of the items that may match nothing)
        let mut done: Vec<Lit> = Vec::new();
        let mut acc: Vec<Lit> = vec![Vec::new()];
        for x in v {
            if let Some(e) = self.exact(x) {
                match cross(&acc, &e) {
                    Some(c) => acc = c,
                    None => break,
                }
                continue;
            }
            if let Hir::Repeat { min: 0, body, .. } = x {
                // (`(?:fs\.)?`: a match that takes it starts with one of its
                // strings; one that does not goes on with what follows; for
                // one whose strings may be empty, `\s*`, what every match
                // starts with ends here)
                let taken = match self.prefix(body) {
                    Some(p) if p.iter().all(|l| !l.is_empty()) => cross(&acc, &p).and_then(|c| union(done.clone(), c)),
                    _ => None,
                };
                match taken {
                    Some(d) => {
                        done = d;
                        continue;
                    }
                    None => break,
                }
            }
            if let Some(c) = self.prefix(x).and_then(|p| cross(&acc, &p)) {
                acc = c;
            }
            break;
        }
        union(done, acc)
    }

    /// Strings every match of `h` ends with.
    pub fn suffix(&self, h: &Hir) -> Option<Vec<Lit>> {
        if let Some(e) = self.exact(h) {
            return Some(e);
        }
        match h {
            Hir::Group(_, b) => self.suffix(b),
            Hir::Concat(v) => {
                let mut acc: Vec<Lit> = vec![Vec::new()];
                for x in v.iter().rev() {
                    match self.exact(x) {
                        Some(e) => match cross(&e, &acc) {
                            Some(c) => acc = c,
                            None => return Some(acc),
                        },
                        None => {
                            if let Some(p) = self.suffix(x) {
                                if let Some(c) = cross(&p, &acc) {
                                    acc = c;
                                }
                            }
                            return Some(acc);
                        }
                    }
                }
                Some(acc)
            }
            Hir::Alt(v) => {
                let mut acc = Vec::new();
                for x in v {
                    acc = union(acc, self.suffix(x)?)?;
                }
                Some(acc)
            }
            Hir::Repeat { min, body, .. } if *min >= 1 => self.suffix(body),
            _ => Some(vec![Vec::new()]),
        }
    }

    /// Strings one of which every match of `h` holds (None: none known).
    pub fn need(&self, h: &Hir) -> Option<Vec<Lit>> {
        match h {
            Hir::Empty | Hir::Look(_) => None,
            Hir::Char(_) => self.exact(h),
            Hir::Group(_, b) => self.need(b),
            Hir::Alt(v) => {
                if let Some(e) = self.exact(h) {
                    return Some(e);
                }
                let mut acc = Vec::new();
                for x in v {
                    acc = union(acc, self.need(x)?)?;
                }
                Some(acc)
            }
            Hir::Repeat { min, body, .. } => {
                if *min >= 1 {
                    if let Some(e) = self.exact(h) {
                        return Some(e);
                    }
                    self.need(body)
                } else {
                    None
                }
            }
            Hir::Concat(v) => {
                let mut best: Option<Vec<Lit>> = None;
                let consider = |c: Vec<Lit>, best: &mut Option<Vec<Lit>>| {
                    if c.iter().any(|l| l.is_empty()) {
                        return;
                    }
                    if best.as_ref().map_or(true, |b| better(&c, b)) {
                        *best = Some(c);
                    }
                };
                // runs of exact items, with the suffix before and the prefix after
                let mut run: Vec<Lit> = vec![Vec::new()];
                for x in v {
                    if let Some(n) = self.need(x) {
                        consider(n, &mut best);
                    }
                    match self.exact(x) {
                        Some(e) => match cross(&run, &e) {
                            Some(c) => run = c,
                            None => {
                                consider(std::mem::replace(&mut run, e.clone()), &mut best);
                                run = e;
                            }
                        },
                        None => {
                            if let Some(p) = self.prefix(x) {
                                if let Some(c) = cross(&run, &p) {
                                    consider(c, &mut best);
                                }
                            }
                            consider(std::mem::take(&mut run), &mut best);
                            run = self.suffix(x).unwrap_or_else(|| vec![Vec::new()]);
                        }
                    }
                }
                consider(run, &mut best);
                best
            }
        }
    }
}

/// Is `a` a better set of needed strings than `b`: a longer shortest
/// string, then fewer strings.
fn better(a: &[Lit], b: &[Lit]) -> bool {
    let short = |x: &[Lit]| x.iter().map(|s| s.len()).min().unwrap_or(0);
    (short(a), std::cmp::Reverse(a.len())) > (short(b), std::cmp::Reverse(b.len()))
}

/// How common an ASCII character is in source text, per mille (a guess).
pub fn freq(c: u32) -> u32 {
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

/// A unit as the scans test it.
#[derive(Clone, Debug)]
struct ScanUnit {
    ascii: u128,
    other: Vec<u32>,
}

impl ScanUnit {
    fn of(u: &Unit) -> ScanUnit {
        let mut ascii = 0u128;
        let mut other = Vec::new();
        for &c in u {
            if c < 128 {
                ascii |= 1u128 << c;
            } else {
                other.push(c);
            }
        }
        ScanUnit { ascii, other }
    }

    #[inline]
    fn has(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii & (1u128 << c) != 0
        } else {
            self.other.contains(&c)
        }
    }
}

/// How the scan finds the anchor's characters.
#[derive(Clone, Debug)]
enum Anchor {
    One(u32),
    Two(u32, u32),
    Three(u32, u32, u32),
    Table(Box<[bool; 128]>, Vec<u32>),
}

impl Anchor {
    fn of(u: &ScanUnit) -> Anchor {
        let mut cs = Vec::new();
        let mut m = u.ascii;
        while m != 0 {
            cs.push(m.trailing_zeros());
            m &= m - 1;
        }
        if u.other.is_empty() {
            match cs[..] {
                [a] => return Anchor::One(a),
                [a, b] => return Anchor::Two(a, b),
                [a, b, c] => return Anchor::Three(a, b, c),
                _ => {}
            }
        }
        let mut t = Box::new([false; 128]);
        for c in cs {
            t[c as usize] = true;
        }
        Anchor::Table(t, u.other.clone())
    }

    /// The first i in [from, to) whose character is the anchor's.
    #[inline]
    fn find(&self, text: &[u32], from: usize, to: usize) -> Option<usize> {
        match self {
            Anchor::One(a) => scan_by(text, from, to, |x| x == *a),
            Anchor::Two(a, b) => scan_by(text, from, to, |x| (x == *a) | (x == *b)),
            Anchor::Three(a, b, c) => scan_by(text, from, to, |x| (x == *a) | (x == *b) | (x == *c)),
            Anchor::Table(t, other) => {
                if other.is_empty() {
                    scan_by(text, from, to, |x| (x < 128) & t[(x & 127) as usize])
                } else {
                    scan_by(text, from, to, |x| if x < 128 { t[x as usize] } else { other.contains(&x) })
                }
            }
        }
    }
}

/// A set of strings to look for in a text.
#[derive(Clone, Debug)]
pub struct LitSet {
    lits: Vec<Vec<ScanUnit>>,
    shortest: usize,
    /// the offset the scan looks at first, and how it finds the characters
    /// any string has there
    anchor: usize,
    scan: Anchor,
    /// for each ASCII character, the ASCII characters a string starting
    /// with it can have second (all for a string of one unit, or a second
    /// unit past ASCII)
    pair: Vec<u128>,
    /// can a string start with a character past ASCII?
    first_other: bool,
    /// the strings that can start with each ASCII character
    by_first: Vec<Vec<u16>>,
    /// the text gate's view of each string (None: a unit past ASCII)
    masks: Vec<Vec<Option<u128>>>,
    /// the estimated share of positions a scan stops at, per mille
    pub density: u32,
    /// where a search over an indexed text looks (textgate's Bigrams): a
    /// column j of the strings whose characters at j and j + 1 are ASCII
    /// in every string, and the pairs `128 * x + y` they take there; the
    /// column whose pairs are rarest (by `freq`). None: no such column.
    pairs: Option<(usize, Vec<u16>)>,
}

impl LitSet {
    pub fn new(lits: &[Lit]) -> Option<LitSet> {
        if lits.is_empty() || lits.len() > MAX_LITS || lits.iter().any(|l| l.is_empty()) {
            return None;
        }
        // (a text that holds or starts with "fs." does with "fs")
        let lits: Vec<&Lit> = lits.iter().filter(|b| !lits.iter().any(|a| a.len() < b.len() && b[..a.len()] == a[..])).collect();
        let shortest = lits.iter().map(|l| l.len()).min()?;
        let scan: Vec<Vec<ScanUnit>> = lits.iter().map(|l| l.iter().map(ScanUnit::of).collect()).collect();
        let mut pair = vec![0u128; 128];
        let mut by_first: Vec<Vec<u16>> = vec![Vec::new(); 128];
        let mut first_other = false;
        for (k, l) in scan.iter().enumerate() {
            let second = match l.get(1) {
                Some(u) if u.other.is_empty() => u.ascii,
                _ => u128::MAX,
            };
            let mut m = l[0].ascii;
            while m != 0 {
                let c = m.trailing_zeros() as usize;
                pair[c] |= second;
                by_first[c].push(k as u16);
                m &= m - 1;
            }
            if !l[0].other.is_empty() {
                first_other = true;
            }
        }
        // the offset whose characters (over all strings) are rarest
        let mut best = (u32::MAX, 0usize);
        for j in 0..shortest {
            let mut cost = 0u32;
            let mut mask = 0u128;
            for l in &scan {
                mask |= l[j].ascii;
                cost += l[j].other.len() as u32;
            }
            let mut m = mask;
            while m != 0 {
                cost += freq(m.trailing_zeros());
                m &= m - 1;
            }
            if cost < best.0 {
                best = (cost, j);
            }
        }
        let anchor = best.1;
        let mut anchor_unit = ScanUnit { ascii: 0, other: Vec::new() };
        for l in &scan {
            anchor_unit.ascii |= l[anchor].ascii;
            for &c in &l[anchor].other {
                if !anchor_unit.other.contains(&c) {
                    anchor_unit.other.push(c);
                }
            }
        }
        let masks: Vec<Vec<Option<u128>>> = scan.iter().map(|l| l.iter().map(|u| if u.other.is_empty() { Some(u.ascii) } else { None }).collect()).collect();
        let scan_anchor = Anchor::of(&anchor_unit);
        let pairs = crate::textgate::pair_column(&masks, shortest, freq);
        Some(LitSet { lits: scan, shortest, anchor, scan: scan_anchor, pair, first_other, by_first, masks, density: best.0, pairs })
    }

    pub fn shortest(&self) -> usize {
        self.shortest
    }

    /// The ASCII characters a string can start with (for a caller's own
    /// scan: scan_file's per-line gates).
    pub fn first_ascii(&self) -> u128 {
        self.by_first.iter().enumerate().filter(|(_, v)| !v.is_empty()).fold(0u128, |m, (c, _)| m | (1u128 << c))
    }

    /// Can a string start with a character past ASCII?
    pub fn first_other(&self) -> bool {
        self.first_other
    }

    /// Does one of the strings start at text[i] and end by `end`?
    #[inline]
    pub fn starts_at(&self, text: &[u32], i: usize, end: usize) -> bool {
        self.at(text, i, end)
    }

    /// The strings, for a person (`|` between them, `[…]` for a unit of
    /// several characters).
    pub fn describe(&self) -> String {
        let unit = |u: &ScanUnit| {
            let mut cs: Vec<u32> = (0..128u32).filter(|&c| u.ascii & (1u128 << c) != 0).collect();
            cs.extend_from_slice(&u.other);
            let s: String = cs.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect();
            if cs.len() == 1 {
                s
            } else {
                format!("[{}]", s)
            }
        };
        self.lits.iter().map(|l| l.iter().map(unit).collect::<String>()).collect::<Vec<_>>().join("|")
    }

    #[inline]
    fn lit_at(l: &[ScanUnit], text: &[u32], i: usize, end: usize) -> bool {
        if i + l.len() > end {
            return false;
        }
        for (k, u) in l.iter().enumerate() {
            if !u.has(text[i + k]) {
                return false;
            }
        }
        true
    }

    /// Does one of the strings start at text[i] (and end by `end`)?
    #[inline]
    fn at(&self, text: &[u32], i: usize, end: usize) -> bool {
        let c = text[i];
        if c < 128 {
            if let Some(&d) = text.get(i + 1) {
                if d < 128 && i + 1 < end && self.pair[c as usize] & (1u128 << d) == 0 {
                    return false;
                }
            }
            self.by_first[c as usize].iter().any(|&k| Self::lit_at(&self.lits[k as usize], text, i, end))
        } else {
            self.first_other && self.lits.iter().any(|l| Self::lit_at(l, text, i, end))
        }
    }

    /// Does the open text gate say none of the strings is in the text?
    pub fn gated_out(&self, text: &[u32], start: usize, end: usize) -> bool {
        end >= start + crate::textgate::MIN_RANGE
            && crate::textgate::ask(&text[start..end], |p| self.masks.iter().all(|m| !p.may_hold_masks(m))).unwrap_or(false)
    }

    /// The first i >= from where one of the strings lies within [from, end).
    pub fn find(&self, text: &[u32], from: usize, end: usize) -> Option<usize> {
        let end = end.min(text.len());
        if from >= end || end - from < self.shortest {
            return None;
        }
        let last = end - self.shortest;
        if end - from >= crate::textgate::PAIRS_RANGE {
            if let Some((j, codes)) = &self.pairs {
                if let Some(found) = crate::textgate::first_by_pairs(text, from, last, *j, codes, |i| self.at(text, i, end)) {
                    return found;
                }
            }
        }
        let at = self.anchor;
        let mut q = from + at;
        let stop = last + at + 1;
        while q < stop {
            let k = self.scan.find(text, q, stop)?;
            if self.at(text, k - at, end) {
                return Some(k - at);
            }
            q = k + 1;
        }
        None
    }

    /// Does one of the strings occur in text[start..end]?
    pub fn occurs(&self, text: &[u32], start: usize, end: usize) -> bool {
        if end < start + self.shortest {
            return false;
        }
        if self.gated_out(text, start, end) {
            return false;
        }
        self.find(text, start, end).is_some()
    }
}

impl super::dfa::Skip for LitSet {
    #[inline]
    fn next(&self, text: &[u32], from: usize, end: usize) -> Option<usize> {
        self.find(text, from, end)
    }
}

const W: usize = 16;

/// The first i in [from, to) where `hit(text[i])`: sixteen characters at a
/// time (a loop the compiler vectorizes), then the one.
#[inline(always)]
pub fn scan_by(text: &[u32], from: usize, to: usize, hit: impl Fn(u32) -> bool) -> Option<usize> {
    let to = to.min(text.len());
    let mut i = from;
    while i + W <= to {
        let chunk: &[u32; W] = match text[i..i + W].try_into() {
            Ok(c) => c,
            Err(_) => break,
        };
        let mut any = false;
        for &x in chunk {
            any |= hit(x);
        }
        if any {
            return chunk.iter().position(|&x| hit(x)).map(|k| i + k);
        }
        i += W;
    }
    if i >= to {
        return None;
    }
    text[i..to].iter().position(|&x| hit(x)).map(|k| i + k)
}
