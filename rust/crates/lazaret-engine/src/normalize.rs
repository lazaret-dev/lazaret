//! Unicode normalization: NFD, NFKD, NFC and NFKC, as Python's
//! `unicodedata.normalize` gives them for text pinned to Unicode 13.0.
//!
//! The algorithm is the standard's (Unicode Standard Annex #15): the full
//! decomposition (canonical, or with the compatibility mappings too), put in
//! canonical order (a stable sort of each run of characters whose combining
//! class is not 0), then, for the composed forms, canonical composition (each
//! character joins the last starter before it when nothing between blocks
//! it and the pair has a primary composite). Hangul syllables are
//! decomposed and composed by arithmetic. The data is Unicode 13.0's
//! (generated/unicode13.rs: CCC_RUNS, DECOMP, COMPOSE), which is every
//! supported Python's for the code points Unicode 13.0 assigns (Unicode's
//! normalization stability policy, checked by `make_rust_tables.py
//! --check` on each Python), and the scanner reads only such text
//! (lazaret/scanner/_unicode13.py: `pin`).
//!
//! Core reads a Python line with non-ASCII characters in its NFKC form
//! (Python normalizes identifiers so), and a JavaScript name's look-alike
//! letters through NFKC too.

use crate::generated::unicode13 as t;

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

/// The canonical combining class of `c` (unicodedata.combining).
pub fn ccc(c: u32) -> u8 {
    if c < 0x300 {
        return 0;
    }
    let runs = t::CCC_RUNS;
    let i = runs.partition_point(|&(a, _, _)| a <= c);
    if i == 0 {
        return 0;
    }
    let (_, b, k) = runs[i - 1];
    if c <= b {
        k
    } else {
        0
    }
}

/// One level of `c`'s decomposition: (is it a compatibility mapping, the
/// characters), else None (Hangul syllables are not listed).
pub fn decomposition(c: u32) -> Option<(bool, &'static [u32])> {
    if c < 0xA0 {
        return None;
    }
    let d = t::DECOMP;
    let i = d.partition_point(|&(x, _, _)| x < c);
    match d.get(i) {
        Some(&(x, at, n)) if x == c => {
            let at = at as usize;
            Some((n & 0x80 != 0, &t::DECOMP_DATA[at..at + (n & 0x7F) as usize]))
        }
        _ => None,
    }
}

/// The primary composite of `a` followed by `b`, else None.
pub fn compose_pair(a: u32, b: u32) -> Option<u32> {
    // Hangul: L + V -> LV, LV + T -> LVT
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return Some(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a) && (a - S_BASE) % T_COUNT == 0 && b > T_BASE && b < T_BASE + T_COUNT {
        return Some(a + (b - T_BASE));
    }
    let p = t::COMPOSE;
    let i = p.partition_point(|&(x, y, _)| (x, y) < (a, b));
    match p.get(i) {
        Some(&(x, y, z)) if x == a && y == b => Some(z),
        _ => None,
    }
}

fn push_decomposed(c: u32, compat: bool, out: &mut Vec<u32>) {
    if (S_BASE..S_BASE + S_COUNT).contains(&c) {
        let s = c - S_BASE;
        out.push(L_BASE + s / N_COUNT);
        out.push(V_BASE + (s % N_COUNT) / T_COUNT);
        if s % T_COUNT != 0 {
            out.push(T_BASE + s % T_COUNT);
        }
        return;
    }
    match decomposition(c) {
        Some((is_compat, parts)) if compat || !is_compat => {
            for &p in parts {
                push_decomposed(p, compat, out);
            }
        }
        _ => out.push(c),
    }
}

/// The canonical order: each run of non-starters stably sorted by class.
fn reorder(s: &mut [u32]) {
    let mut i = 0;
    while i < s.len() {
        if ccc(s[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < s.len() && ccc(s[i]) != 0 {
            i += 1;
        }
        if i - start > 1 {
            s[start..i].sort_by_key(|&c| ccc(c)); // (a stable sort)
        }
    }
}

fn decompose(s: &[u32], compat: bool) -> Vec<u32> {
    let mut out = Vec::with_capacity(s.len() + 8);
    for &c in s {
        if c < 0xA0 {
            out.push(c);
        } else {
            push_decomposed(c, compat, &mut out);
        }
    }
    reorder(&mut out);
    out
}

fn compose(s: Vec<u32>) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(s.len());
    let mut starter: Option<usize> = None; // the last starter's index in `out`
    let mut last: Option<u8> = None; // the class of the last character kept after it
    for c in s {
        let k = ccc(c);
        if let Some(at) = starter {
            let blocked = match last {
                None => false,
                Some(b) => b == 0 || b >= k,
            };
            if !blocked {
                if let Some(p) = compose_pair(out[at], c) {
                    out[at] = p;
                    continue;
                }
            }
        }
        if k == 0 {
            starter = Some(out.len());
            last = None;
        } else {
            last = Some(k);
        }
        out.push(c);
    }
    out
}

fn ascii(s: &[u32]) -> bool {
    s.iter().all(|&c| c < 0x80)
}

/// unicodedata.normalize("NFD", s)
pub fn nfd(s: &[u32]) -> Vec<u32> {
    if ascii(s) {
        return s.to_vec();
    }
    decompose(s, false)
}

/// unicodedata.normalize("NFKD", s)
pub fn nfkd(s: &[u32]) -> Vec<u32> {
    if ascii(s) {
        return s.to_vec();
    }
    decompose(s, true)
}

/// unicodedata.normalize("NFC", s)
pub fn nfc(s: &[u32]) -> Vec<u32> {
    if ascii(s) {
        return s.to_vec();
    }
    compose(decompose(s, false))
}

/// unicodedata.normalize("NFKC", s)
pub fn nfkc(s: &[u32]) -> Vec<u32> {
    if ascii(s) {
        return s.to_vec();
    }
    compose(decompose(s, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystr::u;

    fn s(x: &str) -> Vec<u32> {
        x.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn nfkc_of_names_python_reads_as_ascii() {
        assert_eq!(nfkc(&s("ｅｘｅｃ")), u("exec"));
        assert_eq!(nfkc(&s("ﬁle")), u("file"));
        assert_eq!(nfkc(&s("x\u{00A0}y")), u("x y"));
        assert_eq!(nfkc(&s("e\u{0301}")), s("\u{00E9}"));
        assert_eq!(nfd(&s("\u{00E9}")), s("e\u{0301}"));
        // the order of marks: a dot below (220) before an acute (230)
        assert_eq!(nfd(&s("a\u{0301}\u{0323}")), s("a\u{0323}\u{0301}"));
        assert_eq!(nfc(&s("a\u{0301}\u{0323}")), s("\u{1EA1}\u{0301}"));
    }

    #[test]
    fn hangul_by_arithmetic() {
        assert_eq!(nfd(&s("\u{AC01}")), s("\u{1100}\u{1161}\u{11A8}"));
        assert_eq!(nfc(&s("\u{1100}\u{1161}\u{11A8}")), s("\u{AC01}"));
        assert_eq!(nfc(&s("\u{1100}\u{1161}")), s("\u{AC00}"));
        assert_eq!(nfc(&s("\u{AC00}\u{11A8}")), s("\u{AC01}"));
    }

    #[test]
    fn excluded_and_singleton_characters_stay_decomposed() {
        // U+0958 (a composition exclusion), U+212B ANGSTROM SIGN (a singleton)
        assert_eq!(nfc(&s("\u{0958}")), s("\u{0915}\u{093C}"));
        assert_eq!(nfc(&s("\u{212B}")), s("\u{00C5}"));
    }
}
