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

use std::cell::RefCell;
use std::marker::PhantomData;

/// A text shorter than this gets no gate: scanning it is as cheap.
const MIN_TEXT: usize = 256;
/// A range shorter than this is scanned, not gated.
pub const MIN_RANGE: usize = 64;

/// Bits of the triples' table: at most 2^MAX_TRI_BITS (128 KB).
const MAX_TRI_BITS: u32 = 20;

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
    OPEN.with(|o| o.borrow_mut().push(Opened { lo, hi, pairs }));
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
