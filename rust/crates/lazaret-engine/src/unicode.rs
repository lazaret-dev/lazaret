//! Character data as Python 3.10 (Unicode 13.0) reads it.
//!
//! Every lookup takes a code point as a `u32`, surrogates included: text is a
//! Python `str`, a sequence of code points 0..=0x10FFFF, and a lone surrogate
//! is one of them (a JSON string may hold one). The tables come from
//! `scripts/make_rust_tables.py` (generated/unicode13.rs).

use crate::generated::unicode13 as t;

pub const ALNUM: u16 = 1 << 0;
pub const DECIMAL: u16 = 1 << 1;
pub const DIGIT: u16 = 1 << 2;
pub const SPACE: u16 = 1 << 3;
pub const ALPHA: u16 = 1 << 4;
pub const LINEBREAK: u16 = 1 << 5;
/// Cased and not case-ignorable (str.lower()'s Final_Sigma context).
pub const CASED: u16 = 1 << 6;
pub const CASE_IGNORABLE: u16 = 1 << 7;
pub const PRINTABLE: u16 = 1 << 8;
pub const NUMERIC: u16 = 1 << 9;
pub const ID_START: u16 = 1 << 10;
pub const ID_CONTINUE: u16 = 1 << 11;
pub const UPPER: u16 = 1 << 12;
pub const LOWER: u16 = 1 << 13;
pub const TITLE: u16 = 1 << 14;

/// Property bits of the ASCII range, read once from the table.
fn ascii_props() -> &'static [u16; 128] {
    use std::sync::OnceLock;
    static A: OnceLock<[u16; 128]> = OnceLock::new();
    A.get_or_init(|| {
        let mut a = [0u16; 128];
        for (c, slot) in a.iter_mut().enumerate() {
            *slot = props_slow(c as u32);
        }
        a
    })
}

fn props_slow(c: u32) -> u16 {
    // the last run starting at or before c
    let runs = t::PROPS;
    let i = runs.partition_point(|&(start, _)| start <= c);
    if i == 0 {
        0
    } else {
        runs[i - 1].1
    }
}

/// The property bits of `c` (0 outside 0..=0x10FFFF).
#[inline]
pub fn props(c: u32) -> u16 {
    if c < 128 {
        ascii_props()[c as usize]
    } else if c > 0x10FFFF {
        0
    } else {
        props_slow(c)
    }
}

#[inline]
pub fn is_alnum(c: u32) -> bool {
    props(c) & ALNUM != 0
}
#[inline]
pub fn is_decimal(c: u32) -> bool {
    props(c) & DECIMAL != 0
}
#[inline]
pub fn is_digit(c: u32) -> bool {
    props(c) & DIGIT != 0
}
#[inline]
pub fn is_space(c: u32) -> bool {
    if c < 128 {
        matches!(c, 0x09..=0x0D | 0x1C..=0x20)
    } else {
        props(c) & SPACE != 0
    }
}
#[inline]
pub fn is_alpha(c: u32) -> bool {
    props(c) & ALPHA != 0
}
#[inline]
pub fn is_linebreak(c: u32) -> bool {
    props(c) & LINEBREAK != 0
}
#[inline]
pub fn is_printable(c: u32) -> bool {
    props(c) & PRINTABLE != 0
}
/// Python's `\w` for str patterns: isalnum() or "_".
#[inline]
pub fn is_word(c: u32) -> bool {
    if c < 128 {
        (c as u8).is_ascii_alphanumeric() || c == 0x5F
    } else {
        props(c) & ALNUM != 0
    }
}

fn lookup(table: &[(u32, u32)], c: u32) -> Option<u32> {
    table.binary_search_by_key(&c, |&(k, _)| k).ok().map(|i| table[i].1)
}

fn lookup_list(table: &'static [(u32, &'static [u32])], c: u32) -> Option<&'static [u32]> {
    table.binary_search_by_key(&c, |&(k, _)| k).ok().map(|i| table[i].1)
}

/// sre's lowercase (_sre.unicode_tolower): the simple mapping.
#[inline]
pub fn sre_lower(c: u32) -> u32 {
    if c < 128 {
        if (0x41..=0x5A).contains(&c) {
            c + 32
        } else {
            c
        }
    } else {
        lookup(t::LOWER, c).unwrap_or(c)
    }
}

/// sre's uppercase (_PyUnicode_ToUppercase).
#[inline]
pub fn sre_upper(c: u32) -> u32 {
    if c < 128 {
        if (0x61..=0x7A).contains(&c) {
            c - 32
        } else {
            c
        }
    } else {
        lookup(t::UPPER, c).unwrap_or(c)
    }
}

/// _sre.unicode_iscased.
#[inline]
pub fn sre_iscased(c: u32) -> bool {
    c != sre_lower(c) || c != sre_upper(c)
}

/// re's extra case equivalences for a lowercase code point (ſ for s, …).
pub fn case_fixes(lower: u32) -> Option<&'static [u32]> {
    lookup_list(t::CASE_FIXES, lower)
}

/// Is `c` assigned in Unicode 13.0 (surrogates and private use included)?
pub fn assigned(c: u32) -> bool {
    use std::sync::OnceLock;
    static FIRSTS: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    let unassigned = FIRSTS.get_or_init(|| {
        let mut out = Vec::new();
        let mut cp = 0u32;
        let mut is_assigned = true;
        for &n in t::ASSIGNED_RUNS {
            if !is_assigned {
                out.push((cp, cp + n - 1));
            }
            cp += n;
            is_assigned = !is_assigned;
        }
        out
    });
    let i = unassigned.partition_point(|&(a, _)| a <= c);
    i == 0 || c > unassigned[i - 1].1
}

/// The value of a decimal digit (unicodedata.decimal), else None.
pub fn decimal_value(c: u32) -> Option<u32> {
    let runs = t::DECIMAL_RUNS;
    let i = runs.partition_point(|&(a, _, _)| a <= c);
    if i == 0 {
        return None;
    }
    let (a, b, v) = runs[i - 1];
    if c <= b {
        Some(v + (c - a))
    } else {
        None
    }
}

/// Python's str.lower() (full mappings, Final_Sigma for U+03A3).
pub fn lower(s: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(s.len());
    for (i, &c) in s.iter().enumerate() {
        if c < 128 {
            out.push(sre_lower(c));
        } else if c == 0x3A3 {
            out.push(if final_sigma(s, i) { 0x3C2 } else { 0x3C3 });
        } else if let Some(full) = lookup_list(t::FULL_LOWER, c) {
            out.extend_from_slice(full);
        } else {
            out.push(sre_lower(c));
        }
    }
    out
}

/// Python's str.upper() (full mappings).
pub fn upper(s: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c < 128 {
            out.push(sre_upper(c));
        } else if let Some(full) = lookup_list(t::FULL_UPPER, c) {
            out.extend_from_slice(full);
        } else {
            out.push(sre_upper(c));
        }
    }
    out
}

/// Python's str.casefold() (full case folding; no context: `Σ` folds to `σ`
/// wherever it is): FULL_FOLD where the fold is not the character's
/// str.lower() alone, its lowercase otherwise. Names that file systems which
/// ignore case compare as one (macOS's, Windows'), read on this table's
/// Unicode 13.0 on every Python (BR-2).
pub fn casefold(s: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c < 128 {
            out.push(sre_lower(c));
        } else if let Some(full) = lookup_list(t::FULL_FOLD, c).or_else(|| lookup_list(t::FULL_LOWER, c)) {
            out.extend_from_slice(full);
        } else {
            out.push(sre_lower(c));
        }
    }
    out
}

/// Whether the capital sigma at `i` is final, so that it lowers to `ς`
/// rather than `σ`: Unicode's Final_Sigma condition (The Unicode Standard,
/// section 3.13, "Default Case Algorithms") as Python's str.lower() reads
/// it. Before the sigma, past the case-ignorable characters, comes a cased
/// one; after it, past the case-ignorable characters, comes none. A
/// character both cased and case-ignorable is passed over as case-ignorable
/// (the table's CASED bit is "cased and not case-ignorable").
fn final_sigma(s: &[u32], i: usize) -> bool {
    let decides = |&&c: &&u32| props(c) & CASE_IGNORABLE == 0;
    let cased = |c: Option<&u32>| c.is_some_and(|&c| props(c) & CASED != 0);
    cased(s[..i].iter().rev().find(decides)) && !cased(s[i + 1..].iter().find(decides))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_sigma_as_python_reads_it() {
        // (text, str.lower() on Python 3.10): the case-ignorable characters
        // (' . U+00AD, U+0345) are passed over on both sides; U+0345 is
        // cased too, and still passed over
        let cases: &[(&str, &str)] = &[
            ("A\u{3a3}", "a\u{3c2}"),
            ("\u{3a3}", "\u{3c3}"),
            ("A\u{3a3}B", "a\u{3c3}b"),
            ("A'\u{3a3}'", "a'\u{3c2}'"),
            ("A'\u{3a3}'B", "a'\u{3c3}'b"),
            ("A.\u{3a3}", "a.\u{3c2}"),
            ("A \u{3a3}", "a \u{3c3}"),
            ("1\u{3a3}", "1\u{3c3}"),
            ("1\u{345}\u{3a3}", "1\u{345}\u{3c3}"),
            ("A\u{345}\u{3a3}", "a\u{345}\u{3c2}"),
            ("A\u{3a3}\u{345}", "a\u{3c2}\u{345}"),
            ("A\u{3a3}\u{345}B", "a\u{3c3}\u{345}b"),
            ("\u{3a3}\u{3a3}", "\u{3c3}\u{3c2}"),
            ("\u{391}\u{3a3}\u{ad}", "\u{3b1}\u{3c2}\u{ad}"),
            ("\u{391}\u{3a3}\u{ad}\u{391}", "\u{3b1}\u{3c3}\u{ad}\u{3b1}"),
        ];
        for &(text, want) in cases {
            let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
            let got: String = lower(&cps).into_iter().map(|c| char::from_u32(c).unwrap()).collect();
            assert_eq!(got, want, "{text:?}");
        }
    }

    #[test]
    fn basics() {
        assert!(is_word('a' as u32) && is_word('_' as u32) && is_word(0xE9) && !is_word('-' as u32));
        assert!(is_space(0x85) && is_space(0x1C) && is_space(0x3000) && !is_space(0xFEFF));
        assert!(is_decimal(0x663) && !is_decimal(0xB2));
        assert_eq!(sre_lower(0x212A), 'k' as u32);
        assert_eq!(sre_lower(0x130), 'i' as u32);
        assert_eq!(sre_upper(0xDF), 'S' as u32);
        assert!(assigned(0x41) && !assigned(0x378) && assigned(0xD800));
        assert_eq!(lower(&[0x130]), vec![0x69, 0x307]);
        assert_eq!(lower(&[0x41, 0x3A3]), vec![0x61, 0x3C2]);
        assert_eq!(lower(&[0x3A3]), vec![0x3C3]);
    }

    #[test]
    fn casefold_as_python_reads_it() {
        // (text, str.casefold() on Python 3.10): the full folds (ß, ẞ and the
        // ligatures to two or three letters, İ to i and a dot above), the
        // folds that are not the lowercase (ς, µ, ſ, Cherokee's small letters
        // to the capitals), Σ to σ wherever it is, and what Unicode 13.0 does
        // not assign (Glagolitic's caudate chri, U+2C2F and U+2C5F, a pair
        // from 14.0) left as it is
        let cases: &[(&str, &str)] = &[
            ("Stra\u{df}e", "strasse"),
            ("\u{1e9e}", "ss"),
            ("\u{fb03}", "ffi"),
            ("\u{130}", "i\u{307}"),
            ("\u{3c2}\u{3a3}A\u{3a3}", "\u{3c3}\u{3c3}a\u{3c3}"),
            ("\u{b5}\u{17f}", "\u{3bc}s"),
            ("\u{ab70}\u{13a0}", "\u{13a0}\u{13a0}"),
            ("\u{1f80}", "\u{1f00}\u{3b9}"),
            ("x\u{2c2f}.js", "x\u{2c2f}.js"),
            ("x\u{2c5f}.js", "x\u{2c5f}.js"),
        ];
        for &(text, want) in cases {
            let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
            let want: Vec<u32> = want.chars().map(|c| c as u32).collect();
            assert_eq!(casefold(&cps), want, "{text:?}");
        }
        // a lone surrogate (a name read with surrogateescape) is itself
        assert_eq!(casefold(&[0xDC80, 0x41]), vec![0xDC80, 0x61]);
    }
}
