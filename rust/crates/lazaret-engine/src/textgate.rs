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
//! A gate open for a text can be shared with another thread that reads a
//! copy of it (`share`, `adopt`: the facts' worker thread, whose stack the
//! models need): its pairs, and its places once listed, serve both, and so
//! does what `memo_shared` keeps.
//!
//! A long text's gate also lists where each pair of ASCII characters
//! stands (`Bigrams`): a search for a pattern's strings over the text
//! visits the places their pairs stand, in order, instead of scanning the
//! text for a character, which a call does some dozens of times over a
//! bundle (linre/literal.rs).

use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};

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
    /// The places, from how many times each pair stands in the text (`Pairs::read`'s count): one pass.
    fn read(text: &[u32], counts: &[u32]) -> Bigrams {
        let mut starts = vec![0u32; 128 * 128 + 1];
        for b in 0..128 * 128 {
            starts[b + 1] = starts[b] + counts[b];
        }
        let mut next: Vec<u32> = starts[..128 * 128].to_vec();
        let mut places = vec![0u32; starts[128 * 128] as usize];
        // (the last two characters, 7 bits each, and which of them are ASCII: as Pairs::read reads them)
        let (mut k, mut ascii) = (0u32, 0u32);
        for (j, &c) in text.iter().enumerate() {
            ascii = ((ascii << 1) | (c < 128) as u32) & 3;
            k = ((k << 7) | (c & 127)) & 0x3FFF;
            if ascii == 3 {
                let at = &mut next[k as usize];
                places[*at as usize] = (j - 1) as u32;
                *at += 1;
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

/// One pass over a text (P-1): its pairs, as bits (`words`: pair `128 * x + y` is bit `y % 64` of word `2 * x + y / 64`)
/// or, with COUNT, as how many times each stands (`counts`), and its triples into `tri`.
#[inline(always)]
fn pass<const COUNT: bool>(text: &[u32], words: &mut [u64; 256], counts: &mut [u32], tri: &mut [u64], shift: u32) {
    // (the last three characters, 7 bits each: (x << 14) | (y << 7) | z, tri_hash's key; and which are ASCII)
    let (mut k, mut ascii) = (0u64, 0u32);
    for &c in text {
        ascii = ((ascii << 1) | (c < 128) as u32) & 7;
        k = ((k << 7) | (c & 127) as u64) & 0x1F_FFFF;
        if ascii & 3 == 3 {
            let b = (k & 0x3FFF) as usize;
            if COUNT {
                counts[b] += 1;
            } else {
                words[b >> 6] |= 1u64 << (b & 63);
            }
            if ascii == 7 {
                let h = (k.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> shift) as usize;
                tri[h >> 6] |= 1u64 << (h & 63);
            }
        }
    }
}

impl Pairs {
    /// A text's pairs and triples; and for a text whose pairs' places may be listed, how many times each pair stands
    /// in it, which Bigrams::read lists them from.
    fn read(text: &[u32]) -> (Arc<Pairs>, Option<Vec<u32>>) {
        let want = (text.len() * 8).next_power_of_two().clamp(4096, 1 << MAX_TRI_BITS);
        let bits = want.trailing_zeros();
        let shift = 64 - bits;
        let mut tri = vec![0u64; want / 64];
        let mut words = [0u64; 256];
        let counts = if (MIN_INDEX..=MAX_INDEX).contains(&text.len()) {
            let mut counts = vec![0u32; 128 * 128];
            pass::<true>(text, &mut words, &mut counts, &mut tri, shift);
            for (b, &n) in counts.iter().enumerate() {
                if n != 0 {
                    words[b >> 6] |= 1u64 << (b & 63);
                }
            }
            Some(counts)
        } else {
            pass::<false>(text, &mut words, &mut [], &mut tri, shift);
            None
        };
        let mut rows = [0u128; 128];
        for (x, row) in rows.iter_mut().enumerate() {
            *row = words[2 * x] as u128 | (words[2 * x + 1] as u128) << 64;
        }
        (Arc::new(Pairs { rows, tri, shift }), counts)
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
    pairs: Arc<Pairs>,
    /// what `memo` made for the whole text, by its key
    memo: Vec<(&'static str, Box<dyn std::any::Any>)>,
    /// a long text's pairs, by place: listed the first time a search over
    /// the whole text asks for them (most calls never search a whole text:
    /// a file's own rules read it line by line)
    places: Option<Arc<Places>>,
    /// what `memo_shared` made for the whole text, by its key: one for the
    /// gate and the gates that adopt it
    kept: Arc<Mutex<Kept>>,
}

type Kept = Vec<(&'static str, Arc<dyn std::any::Any + Send + Sync>)>;

/// A long text's pairs by place: how many times each stands, counted as the
/// gate opened, and the places, listed from that when first asked for.
struct Places {
    counts: Vec<u32>,
    listed: OnceLock<Bigrams>,
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
    let (pairs, counts) = Pairs::read(text);
    let places = counts.map(|counts| Arc::new(Places { counts, listed: OnceLock::new() }));
    OPEN.with(|o| o.borrow_mut().push(Opened { lo, hi, pairs, memo: Vec::new(), places, kept: Arc::default() }));
    Some(Gate { lo, _text: PhantomData })
}

/// The gate open for exactly a text, for another thread to open for a copy
/// of it (`adopt`): its pairs, and its places, listed by whichever thread
/// first needs them.
pub struct Shared {
    len: usize,
    pairs: Arc<Pairs>,
    places: Option<Arc<Places>>,
    kept: Arc<Mutex<Kept>>,
}

/// The gate open for exactly `text` (None: none is).
pub fn share(text: &[u32]) -> Option<Shared> {
    let lo = text.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(text);
    OPEN.with(|o| {
        let o = o.borrow();
        o.iter().rev().find(|g| g.lo == lo && g.hi == hi).map(|g| Shared { len: text.len(), pairs: g.pairs.clone(), places: g.places.clone(), kept: g.kept.clone() })
    })
}

/// Open the gate `shared` for `text`, which holds what the text it was
/// open for holds (a copy of it: its pairs are this text's).
pub fn adopt(text: &[u32], shared: Shared) -> Option<Gate<'_>> {
    if text.is_empty() || text.len() != shared.len {
        return None;
    }
    let lo = text.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(text);
    OPEN.with(|o| o.borrow_mut().push(Opened { lo, hi, pairs: shared.pairs, memo: Vec::new(), places: shared.places, kept: shared.kept }));
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
    OPEN.with(|o| {
        let o = o.borrow();
        let g = o.iter().rev().find(|g| g.lo <= lo && hi <= g.hi)?;
        let places = g.places.as_ref()?;
        // (listed from the whole text, the first time `s` is all of it: a part
        // of it cannot list the rest)
        if g.lo == lo && g.hi == hi {
            places.listed.get_or_init(|| Bigrams::read(s, &places.counts));
        }
        places.listed.get().map(|b| f((lo - g.lo) / std::mem::size_of::<u32>(), b))
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

/// [`memo`] for a value either thread of a shared gate may ask for (`share`, `adopt`): made once for both, while the
/// gate is open; made each time when no gate is open for exactly `s`.
pub fn memo_shared<T: Send + Sync + 'static>(s: &[u32], key: &'static str, make: impl FnOnce() -> T) -> Arc<T> {
    let lo = s.as_ptr() as usize;
    let hi = lo + std::mem::size_of_val(s);
    let kept = OPEN.with(|o| o.borrow().iter().rev().find(|g| g.lo == lo && g.hi == hi).map(|g| g.kept.clone()));
    let Some(kept) = kept else {
        return Arc::new(make());
    };
    let found = kept.lock().ok().and_then(|k| k.iter().find(|(k, _)| *k == key).and_then(|(_, v)| v.clone().downcast::<T>().ok()));
    if let Some(v) = found {
        return v;
    }
    let v = Arc::new(make());
    if let Ok(mut k) = kept.lock() {
        k.push((key, v.clone()));
    }
    v
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

    /// The pairs, triples and places as they were read before P-1 made them one pass: the reference.
    fn pairs_as_before(text: &[u32], shift: u32, tri_len: usize) -> ([u128; 128], Vec<u64>) {
        let mut rows = [0u128; 128];
        let mut tri = vec![0u64; tri_len];
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
        (rows, tri)
    }

    fn places_as_before(text: &[u32]) -> (Vec<u32>, Vec<u32>) {
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
        (starts, places)
    }

    #[test]
    fn one_pass_reads_what_the_passes_read() {
        // (P-1: seeded texts of ASCII, characters past it and both, short and long enough to be listed)
        let mut seed: u64 = 0x7A11_2026_1016_0001;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for k in 0..24 {
            let len = if k % 3 == 0 { MIN_INDEX + next(5000) as usize } else { MIN_TEXT + next(5000) as usize };
            let text: Vec<u32> = (0..len)
                .map(|_| match k % 4 {
                    0 => next(128) as u32,
                    1 => 0x20 + next(8) as u32,
                    2 => [0x61, 0x62, 0xE9, 0x2028, 0x10_0000, 0x7F, 0x80][next(7) as usize],
                    _ => if next(3) == 0 { 0x80 + next(0x10_FF80) as u32 } else { next(128) as u32 },
                })
                .collect();
            let (pairs, counts) = Pairs::read(&text);
            let (rows, tri) = pairs_as_before(&text, pairs.shift, pairs.tri.len());
            assert!(pairs.rows == rows && pairs.tri == tri, "text {}", k);
            assert_eq!(counts.is_some(), (MIN_INDEX..=MAX_INDEX).contains(&len));
            if let Some(counts) = counts {
                let b = Bigrams::read(&text, &counts);
                assert!((b.starts.clone(), b.places.clone()) == places_as_before(&text), "text {}", k);
            }
        }
    }

    #[test]
    fn a_gate_shared_with_another_thread_serves_its_copy() {
        // (P-1: the facts' worker thread reads a copy of the call's text)
        let text = cps(&"ab cd ab\n".repeat(MIN_INDEX / 9 + 1));
        let ab = 128 * 'a' as usize + 'b' as usize;
        assert!(share(&text).is_none()); // (no gate open for it)
        let _g = open(&text).unwrap();
        assert!(share(&text[1..]).is_none()); // (a part of it: no gate is open for exactly that)
        let shared = share(&text).unwrap();
        let copy = text.clone();
        assert_eq!(*memo_shared(&text, "kept", || 7usize), 7);
        assert_eq!(*memo_shared(&text[1..], "kept", || 8usize), 8); // (a part of the text: not kept)
        let (pair, triple, listed, part) = std::thread::spawn(move || {
            assert!(ask(&copy, |_| ()).is_none());
            assert_eq!(*memo_shared(&copy, "kept", || 9usize), 9); // (no gate open for it here yet)
            let _a = adopt(&copy, shared).unwrap();
            assert_eq!(*memo_shared(&copy, "kept", || 10usize), 7);
            assert_eq!(*memo_shared(&copy, "made there", || 11usize), 11);
            let pair = ask(&copy[3..], |p| (p.may_hold_str("cd"), p.may_hold_str("dc")));
            let triple = ask(&copy, |p| p.may_hold_str("ab cd"));
            let listed = with_bigrams(&copy, |off, b| (off, b.of(ab).len()));
            let part = with_bigrams(&copy[9..], |off, _| off);
            (pair, triple, listed, part)
        })
        .join()
        .unwrap();
        assert_eq!(pair, Some((true, false)));
        assert_eq!(triple, Some(true));
        assert_eq!(listed, Some((0, 2 * (MIN_INDEX / 9 + 1))));
        assert_eq!(part, Some(9));
        // (the places the other thread listed are the gate's here too, and so is what it kept)
        assert_eq!(*memo_shared(&text, "made there", || 12usize), 11);
        assert_eq!(with_bigrams(&text[9..], |off, b| (off, b.of(ab).len())), Some((9, 2 * (MIN_INDEX / 9 + 1))));
        // (a text of another length is no copy)
        let other = cps("ab cd");
        assert!(adopt(&other, share(&text).unwrap()).is_none());
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
