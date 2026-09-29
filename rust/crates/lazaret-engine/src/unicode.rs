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
            out.push(capital_sigma(s, i));
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

/// CPython's handle_capital_sigma.
fn capital_sigma(s: &[u32], i: usize) -> u32 {
    let mut j = i as isize - 1;
    let mut c = 0u32;
    while j >= 0 {
        c = s[j as usize];
        if props(c) & CASE_IGNORABLE == 0 {
            break;
        }
        j -= 1;
    }
    let mut final_sigma = j >= 0 && props(c) & CASED != 0;
    if final_sigma && i + 1 < s.len() {
        let mut k = i + 1;
        while k < s.len() {
            c = s[k];
            if props(c) & CASE_IGNORABLE == 0 {
                break;
            }
            k += 1;
        }
        final_sigma = k == s.len() || props(c) & CASED == 0;
    }
    if final_sigma {
        0x3C2
    } else {
        0x3C3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
