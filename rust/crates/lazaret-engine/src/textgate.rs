//! The pairs of adjacent characters a text holds, read in one pass: a gate.
//!
//! The supply-chain tests search one text for some hundred patterns and
//! needles, most of which it does not hold; each search used to scan the
//! whole text for the strings its pattern needs (pyre/literal.rs) before
//! answering no. A string with two adjacent ASCII characters the text never
//! has side by side occurs nowhere in it, nor in any part of it, so with the
//! text's pairs read once those searches answer at once. Three in a row are
//! kept too, hashed into a bit table sized to the text (a Bloom filter: a
//! triple the table lacks is not in the text; one it holds may be). It
//! changes no answer: the gate only says where a scan would find nothing.
//!
//! A gate is open for a text while the value `open` returns lives (it
//! borrows the text, which can be neither changed nor freed meanwhile);
//! a search of that text, or of any slice of it, asks it. Gates are per
//! thread.
//!
//! While it is open, a gate also keeps what a call's tests read of the
//! whole text more than once (`memo`: its tokens, which the decoded view
//! and the prose spans each lex): made once, dropped with the gate.
//!
//! A long text's gate also lists where each pair of ASCII characters
//! stands (`Bigrams`): a search for a pattern's strings over the text
//! visits the places their pairs stand, in order, instead of scanning the
//! text for a character, which a call does some dozens of times over a
//! bundle (linre/literal.rs).

use std::cell::RefCell;
use std::marker::PhantomData;

/// A text shorter than this gets no gate: scanning it is as cheap.
const MIN_TEXT: usize = 256;
/// A range shorter than this is scanned, not gated.
pub const MIN_RANGE: usize = 64;

/// Bits of the triples' table: at most 2^MAX_TRI_BITS (128 KB).
const MAX_TRI_BITS: u32 = 20;

/// A text this long or longer gets its pairs' places listed when its gate
/// opens (a shorter one is scanned as cheaply)...
const MIN_INDEX: usize = 1 << 16;
/// ...and one longer than this does not (the list holds 4 bytes a
/// character: 32 MB at most, beside the text's own 32).
const MAX_INDEX: usize = 1 << 23;

/// Where each pair of ASCII characters stands in a text: the places of
/// pair `128 * x + y` are `of(128 * x + y)`, ascending.
pub struct Bigrams {
    starts: Vec<u32>,
    places: Vec<u32>,
}

impl Bigrams {
    fn read(text: &[u32]) -> Bigrams {
        let mut starts = vec![0u32; 128 * 128 + 1];
        for w in text.windows(2) {
            if w[0] < 128 && w[1] < 128 {
                starts[(w[0] * 128 + w[1]) as usize + 1] += 1;
            }
        }
        for b in 1..starts.len() {
            starts[b] += starts[b - 1];
        }
        let mut next = starts.clone();
        let mut places = vec![0u32; starts[128 * 128] as usize];
        for (i, w) in text.windows(2).enumerate() {
            if w[0] < 128 && w[1] < 128 {
                let b = (w[0] * 128 + w[1]) as usize;
                places[next[b] as usize] = i as u32;
                next[b] += 1;
            }
        }
        Bigrams { starts, places }
    }

    /// The places of pair `b` (128 * first + second), ascending.
    #[inline]
    pub fn of(&self, b: usize) -> &[u32] {
        &self.places[self.starts[b] as usize..self.starts[b + 1] as usize]
    }
}

/// The pairs of ASCII characters a text holds side by side, and (hashed)
/// its triples.
pub struct Pairs {
    rows: [u128; 128],
    tri: Vec<u64>,
    /// 64 - log2 of the table's bits (the hash's shift)
    shift: u32,
}

#[inline]
fn tri_hash(x: u32, y: u32, z: u32, shift: u32) -> usize {
    let v = ((x as u64) << 14) | ((y as u64) << 7) | z as u64;
    (v.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> shift) as usize
}

impl Pairs {
    fn read(text: &[u32]) -> Box<Pairs> {
        let mut rows = [0u128; 128];
        let want = (text.len() * 8).next_power_of_two().clamp(4096, 1 << MAX_TRI_BITS);
        let bits = want.trailing_zeros();
        let shift = 64 - bits;
        let mut tri = vec![0u64; want / 64];
        let (mut a, mut b) = (u32::MAX, u32::MAX);
        for &c in text {
            if b < 128 && c < 128 {
                rows[b as usize] |= 1u128 << c;
                if a < 128 {
                    let h = tri_hash(a, b, c, shift);
                    tri[h >> 6] |= 1u64 << (h & 63);
                }
            }
            a = b;
            b = c;
        }
        Box::new(Pairs { rows, tri, shift })
    }

    #[inline]
    fn tri_has(&self, x: u32, y: u32, z: u32) -> bool {
        let h = tri_hash(x, y, z, self.shift);
        self.tri[h >> 6] & (1u64 << (h & 63)) != 0
    }

    /// May the text hold some x, y, z in a row, each from its ASCII mask?
    #[inline]
    pub fn holds3(&self, first: u128, second: u128, third: u128) -> bool {
        let mut m1 = first;
        while m1 != 0 {
            let x = m1.trailing_zeros();
            let mut m2 = second & self.rows[x as usize];
            while m2 != 0 {
                let y = m2.trailing_zeros();
                let mut m3 = third & self.rows[y as usize];
                while m3 != 0 {
                    if self.tri_has(x, y, m3.trailing_zeros()) {
                        return true;
                    }
                    m3 &= m3 - 1;
                }
                m2 &= m2 - 1;
            }
            m1 &= m1 - 1;
        }
        false
    }

    /// Does the text hold some x followed by some y, x a character of
    /// `first` and y one of `second` (ASCII masks)?
    #[inline]
    pub fn holds(&self, first: u128, second: u128) -> bool {
        let mut m = first;
        while m != 0 {
            let x = m.trailing_zeros() as usize;
            if self.rows[x] & second != 0 {
                return true;
            }
            m &= m - 1;
        }
        false
    }

    /// Can the text hold the string `s` (false: it does not; true: maybe)?
    pub fn may_hold(&self, s: &[u32]) -> bool {
        s.windows(2).all(|w| w[0] >= 128 || w[1] >= 128 || self.rows[w[0] as usize] & (1u128 << w[1]) != 0)
            && s.windows(3).all(|w| w[0] >= 128 || w[1] >= 128 || w[2] >= 128 || self.tri_has(w[0], w[1], w[2]))
    }

    /// Can the text hold the ASCII string `s`?
    pub fn may_hold_str(&self, s: &str) -> bool {
        let b = s.as_bytes();
        b.windows(2).all(|w| w[0] >= 128 || w[1] >= 128 || self.rows[w[0] as usize] & (1u128 << w[1]) != 0)
            && b.windows(3).all(|w| w[0] >= 128 || w[1] >= 128 || w[2] >= 128 || self.tri_has(w[0] as u32, w[1] as u32, w[2] as u32))
    }

    /// Can the text hold a string whose positions take the characters of
    /// these ASCII masks (None: a position that may take a character
    /// outside ASCII, which says nothing)?
    pub fn may_hold_masks(&self, units: &[Option<u128>]) -> bool {
        units.windows(2).all(|w| match (w[0], w[1]) {
            (Some(a), Some(b)) => self.holds(a, b),
            _ => true,
        }) && units.windows(3).all(|w| match (w[0], w[1], w[2]) {
            (Some(a), Some(b), Some(c)) => self.holds3(a, b, c),
            _ => true,
        })
    }
}

struct Opened {
    lo: usize,
    hi: usize,
    pairs: Box<Pairs>,
    /// what `memo` made for the whole text, by its key
    memo: Vec<(&'static str, Box<dyn std::any::Any>)>,
    /// a long text's pairs, by place: listed the first time a search over
    /// the whole text asks for them (most calls never search a whole text:
    /// a file's own rules read it line by line)
    bigrams: Option<Bigrams>,
}

thread_local! {
    static OPEN: RefCell<Vec<Opened>> = const { RefCell::new(Vec::new()) };
}

/// An open gate; closed when dropped.
pub struct Gate<'t> {
    lo: usize,
    _text: PhantomData<&'t [u32]>,
}

impl Drop for Gate<'_> {
    fn drop(&mut self) {
        OPEN.with(|o| {
            let mut o = o.borrow_mut();
            if let Some(i) = o.iter().rposition(|g| g.lo == self.lo) {
                o.remove(i);
            }
        });
    }
}

/// Read `text`'s pairs; searches of it ask them until the gate is dropped.
/// None for a short text.
pub fn open(text: &[u32]) -> Option<Gate<'_>> {
    if text.len() < MIN_TEXT {
        return None;
    }
    let lo = text.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(text);
    let pairs = Pairs::read(text);
    OPEN.with(|o| o.borrow_mut().push(Opened { lo, hi, pairs, memo: Vec::new(), bigrams: None }));
    Some(Gate { lo, _text: PhantomData })
}

/// The answer of `f` from the pairs of the open text `s` is part of (None:
/// no gate is open for it). Only memory of the opened text lies within its
/// addresses while it is open, so `s` is a slice of it.
#[inline]
pub fn ask<R>(s: &[u32], f: impl FnOnce(&Pairs) -> R) -> Option<R> {
    if s.is_empty() {
        return None;
    }
    let lo = s.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(s);
    OPEN.with(|o| {
        let o = o.borrow();
        o.iter().rev().find(|g| g.lo <= lo && hi <= g.hi).map(|g| f(&g.pairs))
    })
}

/// `f(where s starts in the open text, the text's pairs by place)`, when
/// `s` is part of an open text that has them (None otherwise).
#[inline]
pub fn with_bigrams<R>(s: &[u32], f: impl FnOnce(usize, &Bigrams) -> R) -> Option<R> {
    if s.is_empty() {
        return None;
    }
    let lo = s.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(s);
    // (listed from the whole text, the first time `s` is all of it: a part
    // of it cannot list the rest)
    let list = OPEN.with(|o| {
        let o = o.borrow();
        o.iter().rev().find(|g| g.lo <= lo && hi <= g.hi).is_some_and(|g| {
            g.bigrams.is_none() && g.lo == lo && g.hi == hi && (MIN_INDEX..=MAX_INDEX).contains(&s.len())
        })
    });
    if list {
        let listed = Bigrams::read(s);
        OPEN.with(|o| {
            if let Some(g) = o.borrow_mut().iter_mut().rev().find(|g| g.lo == lo && g.hi == hi) {
                g.bigrams = Some(listed);
            }
        });
    }
    OPEN.with(|o| {
        let o = o.borrow();
        let g = o.iter().rev().find(|g| g.lo <= lo && hi <= g.hi)?;
        g.bigrams.as_ref().map(|b| f((lo - g.lo) / std::mem::size_of::<u32>(), b))
    })
}

/// A column of pairs past this many is not listed.
const MAX_PAIRS: usize = 256;
/// Up to this many pairs, a search compares each pair's next place
/// rather than keep them in a heap.
const FEW_PAIRS: usize = 16;
/// A search over at least this many characters of a long open text goes
/// by where pairs of characters stand rather than by a scan.
pub const PAIRS_RANGE: usize = 4096;

/// Where a search for strings over an indexed text looks: a column j at
/// which every string has two ASCII characters (by the strings' ASCII masks
/// per position, None for one past ASCII), and the pairs `128 * x + y` they
/// take there; of such columns, the one whose pairs are rarest by `freq`
/// (per mille, a guess). None: no such column.
pub fn pair_column(masks: &[Vec<Option<u128>>], shortest: usize, freq: impl Fn(u32) -> u32) -> Option<(usize, Vec<u16>)> {
    let mut best: Option<(u64, usize, Vec<u16>)> = None;
    for j in 0..shortest.saturating_sub(1).min(24) {
        let mut codes: Vec<u16> = Vec::new();
        let mut ok = true;
        for m in masks {
            let (Some(a), Some(b)) = (m[j], m[j + 1]) else {
                ok = false;
                break;
            };
            let mut xs = a;
            while xs != 0 {
                let x = xs.trailing_zeros();
                let mut ys = b;
                while ys != 0 {
                    codes.push((x * 128 + ys.trailing_zeros()) as u16);
                    ys &= ys - 1;
                }
                xs &= xs - 1;
            }
            if codes.len() > MAX_PAIRS * 4 {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        codes.sort_unstable();
        codes.dedup();
        if codes.is_empty() || codes.len() > MAX_PAIRS {
            continue;
        }
        let cost: u64 = codes.iter().map(|&b| freq((b / 128) as u32) as u64 * freq((b % 128) as u32) as u64).sum();
        if best.as_ref().map_or(true, |(c, _, _)| cost < *c) {
            best = Some((cost, j, codes));
        }
    }
    best.map(|(_, j, codes)| (j, codes))
}

/// The first start i in [from, last] of a string in `s` whose place i + j
/// holds one of the pairs `codes` and where `is_start(i)`, by where those
/// pairs stand in the open text `s` is part of: each such place, in order,
/// tried as a scan tries the places it stops at, so the first that holds a
/// string is the scan's answer. None: no open text with its pairs listed
/// holds `s` (scan instead); Some(None): no string starts there.
pub fn first_by_pairs(s: &[u32], from: usize, last: usize, j: usize, codes: &[u16], mut is_start: impl FnMut(usize) -> bool) -> Option<Option<usize>> {
    use std::cmp::Reverse;
    with_bigrams(s, |off, bg| {
        // (the places p of the pairs in the open text: p = off + i + j)
        let (lo, hi) = (off + from + j, off + last + j);
        if codes.len() <= FEW_PAIRS {
            // each pair's places from lo on, the smallest next one taken in
            // turn (no heap to build: a search that stops early is common)
            let mut lists: [&[u32]; FEW_PAIRS] = [&[]; FEW_PAIRS];
            let mut n = 0;
            for &b in codes {
                let list = bg.of(b as usize);
                let k = list.partition_point(|&p| (p as usize) < lo);
                if k < list.len() && list[k] as usize <= hi {
                    lists[n] = &list[k..];
                    n += 1;
                }
            }
            while n > 0 {
                let mut m = 0;
                for t in 1..n {
                    if lists[t][0] < lists[m][0] {
                        m = t;
                    }
                }
                let i = lists[m][0] as usize - off - j;
                if is_start(i) {
                    return Some(i);
                }
                lists[m] = &lists[m][1..];
                if lists[m].is_empty() || lists[m][0] as usize > hi {
                    n -= 1;
                    lists[m] = lists[n];
                }
            }
            return None;
        }
        let mut heap: std::collections::BinaryHeap<Reverse<(u32, u16, u32)>> = std::collections::BinaryHeap::with_capacity(codes.len());
        for &b in codes {
            let list = bg.of(b as usize);
            let k = list.partition_point(|&p| (p as usize) < lo);
            if k < list.len() && list[k] as usize <= hi {
                heap.push(Reverse((list[k], b, k as u32)));
            }
        }
        while let Some(Reverse((p, b, k))) = heap.pop() {
            let i = p as usize - off - j;
            if is_start(i) {
                return Some(i);
            }
            let list = bg.of(b as usize);
            let k = k as usize + 1;
            if k < list.len() && list[k] as usize <= hi {
                heap.push(Reverse((list[k], b, k as u32)));
            }
        }
        None
    })
}

/// What `make` gives for `s`, made once while a gate is open for exactly
/// `s` (the whole text, not a part of it) and kept until the gate closes;
/// `make()` each time when none is. `make` must depend on `s` alone, and
/// `key` name what it makes.
pub fn memo<T: Clone + 'static>(s: &[u32], key: &'static str, make: impl FnOnce() -> T) -> T {
    let lo = s.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(s);
    let whole = |g: &&Opened| g.lo == lo && g.hi == hi;
    let kept: Option<Option<T>> = OPEN.with(|o| {
        let o = o.borrow();
        o.iter().rev().find(whole).map(|g| g.memo.iter().find(|(k, _)| *k == key).and_then(|(_, v)| v.downcast_ref::<T>().cloned()))
    });
    match kept {
        None => make(),
        Some(Some(v)) => v,
        Some(None) => {
            let v = make();
            OPEN.with(|o| {
                if let Some(g) = o.borrow_mut().iter_mut().rev().find(|g| g.lo == lo && g.hi == hi) {
                    g.memo.push((key, Box::new(v.clone())));
                }
            });
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn a_gate_answers_for_its_text_and_its_slices_only_while_open() {
        let text = cps(&"function f(a) { return a + 1; }\n".repeat(20));
        {
            let _g = open(&text).expect("long enough");
            assert_eq!(ask(&text, |p| p.may_hold_str("return")), Some(true));
            assert_eq!(ask(&text, |p| p.may_hold_str("gethostname")), Some(false));
            assert_eq!(ask(&text[40..90], |p| p.may_hold_str("xz")), Some(false));
            let other = cps(&"gethostname()".repeat(30));
            assert_eq!(ask(&other, |p| p.may_hold_str("gethostname")), None);
        }
        assert_eq!(ask(&text, |p| p.may_hold_str("return")), None);
        assert!(open(&cps("short")).is_none());
    }

    #[test]
    fn a_memo_is_made_once_for_the_whole_open_text_only() {
        let text = cps(&"let a = 1;\n".repeat(40));
        let made = std::cell::Cell::new(0);
        let make = || {
            made.set(made.get() + 1);
            text.len()
        };
        assert_eq!(memo(&text, "len", make), text.len());
        assert_eq!(made.get(), 1); // (no gate: made each time)
        {
            let _g = open(&text).unwrap();
            assert_eq!(memo(&text, "len", make), text.len());
            assert_eq!(memo(&text, "len", make), text.len());
            assert_eq!(made.get(), 2);
            assert_eq!(memo(&text[1..], "len", || 7), 7); // (a part of the text: not kept)
            assert_eq!(memo(&text, "other", || 3usize), 3);
            assert_eq!(memo(&text, "other", || 4usize), 3);
        }
        assert_eq!(memo(&text, "len", make), text.len());
        assert_eq!(made.get(), 3); // (the gate closed: what it kept went with it)
    }

    #[test]
    fn a_long_text_lists_where_its_pairs_stand() {
        let mut text = cps(&"ab cd ab\n".repeat(MIN_INDEX / 9 + 1));
        text.push(0x00E9); // (a pair past ASCII is not listed)
        text.push(c_('a'));
        let _g = open(&text).unwrap();
        // (a part first: nothing is listed until the whole text is asked)
        assert!(with_bigrams(&text[9..], |off, _| off).is_none());
        let ab = 128 * 'a' as usize + 'b' as usize;
        let got = with_bigrams(&text, |off, b| (off, b.of(ab).len(), b.of(ab)[..2].to_vec())).unwrap();
        assert_eq!(got, (0, 2 * (MIN_INDEX / 9 + 1), vec![0, 6]));
        // (a part of the text: where it starts in the text)
        assert_eq!(with_bigrams(&text[9..], |off, _| off), Some(9));
        let short = cps(&"ab".repeat(200));
        let _h = open(&short).unwrap();
        assert!(with_bigrams(&short, |_, _| ()).is_none());
    }

    fn c_(ch: char) -> u32 {
        ch as u32
    }

    #[test]
    fn pairs_of_masks() {
        let text = cps(&"Ab".repeat(200));
        let _g = open(&text).unwrap();
        let bit = |c: char| 1u128 << (c as u32);
        assert_eq!(ask(&text, |p| p.holds(bit('A') | bit('a'), bit('b'))), Some(true));
        assert_eq!(ask(&text, |p| p.holds(bit('a'), bit('b'))), Some(false));
        assert_eq!(ask(&text, |p| p.may_hold(&cps("bA"))), Some(true));
        assert_eq!(ask(&text, |p| p.may_hold(&cps("éb"))), Some(true)); // (a pair outside ASCII: maybe)
        assert_eq!(ask(&text, |p| p.may_hold(&cps("AbA"))), Some(true));
        assert_eq!(ask(&text, |p| p.holds3(bit('A'), bit('b'), bit('A'))), Some(true));
        assert_eq!(ask(&text, |p| p.may_hold_masks(&[Some(bit('A')), Some(bit('b')), None])), Some(true));
    }

    #[test]
    fn triples_rule_out_strings_whose_pairs_all_occur() {
        // every pair of "pwsh" occurs (pw, ws, sh) but not its triples
        let text = cps(&"pwd; rows; shell; ".repeat(40));
        let _g = open(&text).unwrap();
        assert_eq!(ask(&text, |p| p.may_hold_str("pwsh")), Some(false));
        assert_eq!(ask(&text, |p| p.may_hold_str("rows; s")), Some(true));
    }
}
