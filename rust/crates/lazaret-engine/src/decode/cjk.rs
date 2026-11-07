//! The Chinese, Japanese and Korean codecs, as Python's decoders read them with errors="replace".
//!
//! Python reads one character at a time from where it starts: a character (its bytes consumed), an error of `e`
//! bytes (one U+FFFD, then on after them), or "too few" (the character needs more bytes than are left: at the end
//! of the data, one U+FFFD for all that is left). For the stateless codecs which it is depends only on the bytes
//! from the start of the character, so each codec is a tree of tables (generated/codecs.rs, from Python's own
//! decoders by scripts/make_codec_tables.py): an entry is a character, a sequence of them, an error, the next
//! byte's table, or one of the two forms that are arithmetic, gb18030's four-byte sequences and EUC-KR's eight-
//! byte KS X 1001:1998 make-up sequences. The stateful codecs (HZ and the ISO-2022 family: escape sequences that
//! change what the bytes after them mean) are state machines over the same kind of tables (iso2022.rs).

use crate::generated::codecs as g;
use std::sync::OnceLock;

pub const REPLACEMENT: u32 = 0xFFFD;

// an entry of the flat table (generated::codecs::CJK)
const MULTI: u32 = 0x11_0000;
const ERR: u32 = 0x20_0000;
const ROW: u32 = 0x40_0000;
const GB4: u32 = 0x80_0000;
const MAKEUP: u32 = 0x81_0000;

/// The flat table: each codec's first-byte table (256 entries), and rows: `[lo, hi, entry for lo, …, entry for
/// hi]` (a byte outside lo..=hi is an error of one byte). Read once from the generated text.
pub struct Tables {
    pub flat: Vec<u32>,
    pub multi: Vec<Vec<u32>>,
}

pub fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut flat = Vec::with_capacity(g::CJK_ENTRIES);
        let mut prev: i64 = 0;
        let hex = |t: &str| i64::from_str_radix(t, 16).unwrap_or(0);
        for tok in g::CJK_FLAT.split(',') {
            // a character as its distance from the previous character (empty: the next one; "~n": the next n),
            // "x" an error of one byte, else "!" and the entry
            if tok == "x" {
                flat.push(ERR + 1);
            } else if let Some(rest) = tok.strip_prefix('!') {
                flat.push(hex(rest) as u32);
            } else if let Some(n) = tok.strip_prefix('~') {
                for _ in 0..hex(n) {
                    prev += 1;
                    flat.push(prev as u32);
                }
            } else {
                prev += match tok {
                    "" => 1,
                    _ => match tok.strip_prefix('-') {
                        Some(neg) => -hex(neg),
                        None => hex(tok),
                    },
                };
                flat.push(prev as u32);
            }
        }
        let multi = g::CJK_MULTI.iter().map(|s| s.chars().map(|c| c as u32).collect()).collect();
        Tables { flat, multi }
    })
}

/// The entry for byte `t` in the row at `at`.
fn in_row(flat: &[u32], at: usize, t: u8) -> u32 {
    let (lo, hi) = (flat[at], flat[at + 1]);
    let t = t as u32;
    if t >= lo && t <= hi {
        flat[at + 2 + (t - lo) as usize]
    } else {
        ERR + 1
    }
}

/// A stateless codec's decoding of `b` (`first`: where its first-byte table starts in the flat table).
pub fn stateless(first: usize, b: &[u8]) -> Vec<u32> {
    let t = tables();
    let flat = &t.flat;
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    'chars: while i < b.len() {
        let mut e = flat[first + b[i] as usize];
        let mut depth = 1usize;
        loop {
            match e {
                0..=0x10FFFF => {
                    out.push(e);
                    i += depth;
                    continue 'chars;
                }
                _ if (MULTI..ERR).contains(&e) => {
                    out.extend_from_slice(&t.multi[(e - MULTI) as usize]);
                    i += depth;
                    continue 'chars;
                }
                _ if (ERR..ROW).contains(&e) => {
                    out.push(REPLACEMENT);
                    i += (e - ERR) as usize;
                    continue 'chars;
                }
                _ if (ROW..GB4).contains(&e) => {
                    if i + depth >= b.len() {
                        out.push(REPLACEMENT); // too few: the rest
                        return out;
                    }
                    e = in_row(flat, (e - ROW) as usize, b[i + depth]);
                    depth += 1;
                }
                GB4 => match gb18030_four(&b[i..]) {
                    Step::Char(c) => {
                        out.push(c);
                        i += 4;
                        continue 'chars;
                    }
                    Step::Err => {
                        out.push(REPLACEMENT);
                        i += 1;
                        continue 'chars;
                    }
                    Step::TooFew => {
                        out.push(REPLACEMENT);
                        return out;
                    }
                },
                MAKEUP => match euc_kr_makeup(&b[i..]) {
                    Step::Char(c) => {
                        out.push(c);
                        i += 8;
                        continue 'chars;
                    }
                    Step::Err => {
                        out.push(REPLACEMENT);
                        i += 1;
                        continue 'chars;
                    }
                    Step::TooFew => {
                        out.push(REPLACEMENT);
                        return out;
                    }
                },
                _ => {
                    // (not an entry the generator writes)
                    out.push(REPLACEMENT);
                    i += 1;
                    continue 'chars;
                }
            }
        }
    }
    out
}

/// The character(s) a stateless codec reads from exactly the bytes `seq` (one character, all of them), or None.
pub fn one_char(first: usize, seq: &[u8]) -> Option<Vec<u32>> {
    let t = tables();
    let flat = &t.flat;
    let mut e = flat[first + *seq.first()? as usize];
    let mut depth = 1usize;
    loop {
        match e {
            0..=0x10FFFF => return (depth == seq.len()).then(|| vec![e]),
            _ if (MULTI..ERR).contains(&e) => return (depth == seq.len()).then(|| t.multi[(e - MULTI) as usize].clone()),
            _ if (ROW..GB4).contains(&e) => {
                let &b = seq.get(depth)?;
                e = in_row(flat, (e - ROW) as usize, b);
                depth += 1;
            }
            _ => return None,
        }
    }
}

enum Step {
    Char(u32),
    Err,
    TooFew,
}

/// gb18030's four-byte form (GB 18030: two bytes 0x81..=0xFE, each followed by one of 0x30..=0x39), by its
/// linear index: a BMP character's through GB18030_RANGES below 39,420, U+10000 and up from 189,000. Python reads
/// any other as an error of one byte, and fewer than four bytes at the end of the data as too few.
fn gb18030_four(b: &[u8]) -> Step {
    let &[b1, b2, b3, b4, ..] = b else {
        return Step::TooFew;
    };
    let digit = |x: u8, lo: u8, hi: u8| (lo..=hi).contains(&x).then(|| (x - lo) as u32);
    let (Some(p1), Some(p2), Some(p3), Some(p4)) =
        (digit(b1, 0x81, 0xFE), digit(b2, 0x30, 0x39), digit(b3, 0x81, 0xFE), digit(b4, 0x30, 0x39))
    else {
        return Step::Err;
    };
    let index = ((p1 * 10 + p2) * 126 + p3) * 10 + p4;
    if index < 39_420 {
        let r = g::GB18030_RANGES.partition_point(|&(start, _)| start <= index) - 1;
        let (start, first) = g::GB18030_RANGES[r];
        Step::Char(first + (index - start))
    } else if (189_000..189_000 + 0x10_0000).contains(&index) {
        Step::Char(0x1_0000 + (index - 189_000))
    } else {
        Step::Err
    }
}

/// EUC-KR's make-up sequence (KS X 1001:1998, annex 3): the Hangul filler (A4 D4) and three jamo, A4 and a byte
/// each (an initial, a medial and a final consonant, the filler for none), for a precomposed syllable; the jamo's
/// indexes from EUCKR_CHOSEONG and EUCKR_JONGSEONG (127: not one). Python reads any other as an error of one byte,
/// and fewer than eight bytes at the end of the data as too few.
fn euc_kr_makeup(b: &[u8]) -> Step {
    let Some(seq) = b.get(..8) else {
        return Step::TooFew;
    };
    if seq[2] != 0xA4 || seq[4] != 0xA4 || seq[6] != 0xA4 {
        return Step::Err;
    }
    let jamo = |table: &[u8; 30], x: u8| (0xA1..=0xBE).contains(&x).then(|| table[(x - 0xA1) as usize]).filter(|&k| k != 127);
    let initial = jamo(&g::EUCKR_CHOSEONG, seq[3]);
    let medial = (0xBF..=0xD3).contains(&seq[5]).then(|| seq[5] - 0xBF);
    let last = if seq[7] == 0xD4 { Some(0) } else { jamo(&g::EUCKR_JONGSEONG, seq[7]) };
    match (initial, medial, last) {
        (Some(i), Some(m), Some(f)) => Step::Char(0xAC00 + (i as u32 * 21 + m as u32) * 28 + f as u32),
        _ => Step::Err,
    }
}
