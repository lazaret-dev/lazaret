//! The stateful CJK codecs: the ISO-2022 family (ISO-2022-JP, RFC 1468; -JP-1, RFC 2237; -JP-2, RFC 1554; -KR,
//! RFC 1557; -JP-3 and -JP-2004, JIS X 0213's; -JP-EXT) and HZ (RFC 1843), as Python decodes them with
//! errors="replace". Written from the RFCs' model and from what Python's decoders do on probes; which sets each
//! codec designates and what each set's bytes are, generated/codecs.rs has, read from those decoders
//! (scripts/make_codec_tables.py), and the tests hold the whole to them byte for byte.
//!
//! The model. Three registers hold a character set each: G0, read by default, G1, read after SO in a codec that
//! shifts (ISO-2022-KR, until SI or a line feed), and G2, which ESC N reads one byte of (single shift 2, ISO-2022-JP-2).
//! All three start as ASCII. An escape sequence designates a set to one: ESC $ F or ESC $ ( F a two-byte set to G0,
//! ESC $ ) F to G1, ESC ( F a one-byte set to G0, ESC ) F to G1, ESC . F a set to G2, for the marks F the codec has.
//! What Python's decoders do beyond that, as observed:
//!
//! * An escape sequence is ESC, a byte that starts one ($ & ( ) .) and the bytes up to the first of '@'..='Z',
//!   sixteen bytes at most. One the codec does not take is an error of all its bytes; with no end within sixteen
//!   bytes, ESC alone is an error; cut short by the end of the data, it is "too few". In the codecs that read JIS X
//!   0208, "&@" in it (the JIS X 0208-1990 announcer, ESC & @) is passed over with the byte after it, and a
//!   sequence of six bytes that ends in ESC $ B designates JIS X 0208 to G0, whatever its second and third bytes
//!   (ESC & @ ESC $ B, the announced JIS X 0208, among them).
//! * ESC followed by a byte that starts none (nor single shift 2) is ESC itself, and from the byte after it each
//!   byte is the character of its value, up to and including one in '@'..='Z' ("ESC throughout").
//! * A control byte (below 0x20) is itself, in any set; a byte from 0x80 is an error of one byte.
//! * In a two-byte set, any byte from 0x20 to 0x7F starts a pair with the byte after it, whatever that is: the
//!   set's character, or an error of both bytes.
//! * Single shift 2 is ESC N and one byte: the G2 set's character for it, or an error of the three; with one G2
//!   set (JIS X 0201 Roman) Python's decoder raises, and the file is not decoded.
//! * "Too few" bytes for what has begun, at the end of the data, is one U+FFFD for all that is left.

use super::cjk::REPLACEMENT;
use crate::generated::codecs as g;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

const ESC: u8 = 0x1B;
const SO: u8 = 0x0E;
const SI: u8 = 0x0F;
const LF: u8 = 0x0A;
/// An escape sequence's bytes, at most (ESC and its last byte included).
const ESCAPE_MAX: usize = 16;
/// ASCII's mark.
const ASCII: u8 = b'B';

/// A codec of the family: the marks of the sets it designates, and whether SO and SI shift.
struct Codec {
    name: &'static str,
    wide: &'static [u8],
    narrow: &'static [u8],
    shift2: &'static [u8],
    shifts: bool,
    announcer: bool,
}

fn codec(name: &str) -> Option<Codec> {
    g::ISO2022_CODECS.iter().find(|c| c.0 == name).map(|&(name, wide, narrow, shift2, shifts, announcer)| Codec {
        name,
        wide: wide.as_bytes(),
        narrow: narrow.as_bytes(),
        shift2: shift2.as_bytes(),
        shifts,
        announcer,
    })
}

pub fn is_iso2022(name: &str) -> bool {
    codec(name).is_some()
}

/// A register's set: its mark, and whether its characters are two bytes.
#[derive(Clone, Copy)]
struct Set {
    mark: u8,
    wide: bool,
}

/// What an escape sequence does.
enum Escape {
    /// designates `set` to register `reg`; the sequence is `len` bytes
    Designate { reg: usize, set: Set, len: usize },
    /// one the codec does not take: an error of `len` bytes
    Unknown(usize),
    /// no end within ESCAPE_MAX bytes: ESC alone is the error
    Overlong,
    /// the data ends first
    TooFew,
}

fn escape(c: &Codec, b: &[u8]) -> Escape {
    let mut k = 1;
    let end = loop {
        if k >= ESCAPE_MAX {
            return Escape::Overlong;
        }
        let Some(&x) = b.get(k) else {
            return Escape::TooFew;
        };
        if (b'@'..=b'Z').contains(&x) {
            break k;
        }
        k += if c.announcer && x == b'&' && b.get(k + 1) == Some(&b'@') { 3 } else { 1 };
    };
    let len = end + 1;
    let f = b[end];
    let wide = |reg| Escape::Designate { reg, set: Set { mark: f, wide: true }, len };
    let narrow = |reg| Escape::Designate { reg, set: Set { mark: f, wide: false }, len };
    match &b[1..end] {
        b"$" | b"$(" if c.wide.contains(&f) => wide(0),
        b"$)" if c.wide.contains(&f) => wide(1),
        b"(" if c.narrow.contains(&f) => narrow(0),
        b")" if c.narrow.contains(&f) => narrow(1),
        b"." if c.shift2.contains(&f) => narrow(2),
        [_, _, ESC, b'$'] if c.announcer && f == b'B' => wide(0),
        _ => Escape::Unknown(len),
    }
}

/// A two-byte set's characters, by (first byte - 0x21) * 94 + second - 0x21: a table of its own, or a stateless
/// codec's two-byte characters with the bytes' high bits set (after `lead`, when not 0), but where `diffs` says.
enum Table {
    Own(Arc<Vec<Option<Vec<u32>>>>),
    Base { first: usize, lead: u8, diffs: HashMap<u16, Option<Vec<u32>>> },
}

/// An own table's text: a token is empty (no character), a code point as its distance in hexadecimal from the
/// previous one, or "*" and two code points (a pair).
fn parse_table(data: &str) -> Vec<Option<Vec<u32>>> {
    let mut prev: i64 = 0;
    data.split(',')
        .map(|tok| {
            if tok.is_empty() {
                None
            } else if let Some(pair) = tok.strip_prefix('*') {
                Some(pair.split('.').map(|h| u32::from_str_radix(h, 16).unwrap_or(REPLACEMENT)).collect())
            } else {
                prev += match tok.strip_prefix('-') {
                    Some(neg) => -i64::from_str_radix(neg, 16).unwrap_or(0),
                    None => i64::from_str_radix(tok, 16).unwrap_or(0),
                };
                Some(vec![prev as u32])
            }
        })
        .collect()
}

/// Every codec's two-byte sets, by (codec, mark), read once.
fn tables() -> &'static HashMap<(&'static str, u8), Table> {
    static TABLES: OnceLock<HashMap<(&'static str, u8), Table>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let own: Vec<Arc<Vec<Option<Vec<u32>>>>> = g::ISO2022_TABLES.iter().map(|t| Arc::new(parse_table(t))).collect();
        g::ISO2022_SETS
            .iter()
            .map(|&(codec, mark, base, lead, k)| {
                let mark = mark & 0x7F;
                let table = if base.is_empty() {
                    Table::Own(own[k].clone())
                } else {
                    let first = g::CJK_FIRST.iter().find(|(c, _)| *c == base).map_or(0, |&(_, at)| at);
                    let diffs = g::ISO2022_DIFFS
                        .iter()
                        .filter(|d| d.0 == codec && d.1 & 0x7F == mark)
                        .map(|&(_, _, k, chars)| (k, (!chars.is_empty()).then(|| chars.chars().map(|c| c as u32).collect())))
                        .collect();
                    Table::Base { first, lead, diffs }
                };
                ((codec, mark), table)
            })
            .collect()
    })
}

/// The character(s) of the two bytes `c1 c2` in `codec`'s two-byte set `mark`, or None.
fn pair(codec: &'static str, mark: u8, c1: u8, c2: u8) -> Option<Vec<u32>> {
    if !(0x21..=0x7E).contains(&c1) || !(0x21..=0x7E).contains(&c2) {
        return None;
    }
    let k = (c1 - 0x21) as usize * 94 + (c2 - 0x21) as usize;
    match tables().get(&(codec, mark))? {
        Table::Own(t) => t.get(k).cloned().flatten(),
        Table::Base { first, lead, diffs } => match diffs.get(&(k as u16)) {
            Some(d) => d.clone(),
            None if *lead != 0 => super::cjk::one_char(*first, &[*lead, c1 | 0x80, c2 | 0x80]),
            None => super::cjk::one_char(*first, &[c1 | 0x80, c2 | 0x80]),
        },
    }
}

/// The character of byte `c` (0x20..=0x7F) in the one-byte set `mark`, or None.
fn single(mark: u8, c: u8) -> Option<u32> {
    let (_, table) = g::ISO2022_ONE_BYTE.iter().find(|(m, _)| *m == mark)?;
    let ch = table.chars().nth((c - 0x20) as usize)? as u32;
    (ch != REPLACEMENT).then_some(ch)
}

/// Single shift 2: the character of byte `c` in the G2 set `mark` (Some(None): an error), or None where Python's
/// decoder raises.
fn shifted2(mark: u8, c: u8) -> Option<Option<u32>> {
    let (_, table) = g::ISO2022_SINGLE_SHIFT.iter().find(|(m, _)| *m == mark)?;
    let ch = table.as_ref()?.chars().nth(c as usize).map_or(REPLACEMENT, |ch| ch as u32);
    Some((ch != REPLACEMENT).then_some(ch))
}

/// `b` in the ISO-2022 codec `name`, or None where Python's decoder raises (or `name` is not one).
pub fn iso2022(name: &'static str, b: &[u8]) -> Option<Vec<u32>> {
    let c = codec(name)?;
    let ascii = Set { mark: ASCII, wide: false };
    let mut regs = [ascii; 3];
    let mut shifted = false;
    let mut throughout = false;
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let x = b[i];
        if throughout {
            out.push(x as u32);
            throughout = !(b'@'..=b'Z').contains(&x);
            i += 1;
            continue;
        }
        if x == ESC {
            let Some(&next) = b.get(i + 1) else {
                out.push(REPLACEMENT);
                break;
            };
            if matches!(next, b'$' | b'&' | b'(' | b')' | b'.') {
                match escape(&c, &b[i..]) {
                    Escape::Designate { reg, set, len } => {
                        regs[reg] = set;
                        i += len;
                    }
                    Escape::Unknown(len) => {
                        out.push(REPLACEMENT);
                        i += len;
                    }
                    Escape::Overlong => {
                        out.push(REPLACEMENT);
                        i += 1;
                    }
                    Escape::TooFew => {
                        out.push(REPLACEMENT);
                        break;
                    }
                }
            } else if next == b'N' && !c.shift2.is_empty() {
                let Some(&byte) = b.get(i + 2) else {
                    out.push(REPLACEMENT);
                    break;
                };
                out.push(shifted2(regs[2].mark, byte)?.unwrap_or(REPLACEMENT));
                i += 3;
            } else {
                out.push(ESC as u32);
                throughout = true;
                i += 1;
            }
            continue;
        }
        if c.shifts && (x == SO || x == SI || (x == LF && shifted)) {
            if x == LF {
                out.push(LF as u32);
            }
            shifted = x == SO;
            i += 1;
            continue;
        }
        if x < 0x20 {
            out.push(x as u32);
            i += 1;
            continue;
        }
        if x >= 0x80 {
            out.push(REPLACEMENT);
            i += 1;
            continue;
        }
        let set = regs[if shifted { 1 } else { 0 }];
        if !set.wide {
            out.push(single(set.mark, x).unwrap_or(REPLACEMENT));
            i += 1;
            continue;
        }
        let Some(&second) = b.get(i + 1) else {
            out.push(REPLACEMENT);
            break;
        };
        match pair(c.name, set.mark, x, second) {
            Some(chars) => out.extend_from_slice(&chars),
            None => out.push(REPLACEMENT),
        }
        i += 2;
    }
    Some(out)
}

/// HZ (RFC 1843): ASCII, and GB2312 between "~{" and "~}" as two bytes 0x21..=0x7E each. Outside, "~~" is "~"
/// and "~" before a line feed is nothing (the line goes on); "~" before anything else is an error of the "~" alone,
/// as is a byte from 0x80. Inside, a byte from 0x80 is an error of one byte, and any other starts two: "~}", a
/// character, or an error of the first byte only.
pub fn hz(b: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(b.len());
    let mut gb = false;
    let mut i = 0usize;
    while i < b.len() {
        let x = b[i];
        if x >= 0x80 {
            out.push(REPLACEMENT);
            i += 1;
            continue;
        }
        if !gb && x != b'~' {
            out.push(x as u32);
            i += 1;
            continue;
        }
        let Some(&next) = b.get(i + 1) else {
            out.push(REPLACEMENT);
            break;
        };
        if !gb {
            match next {
                b'~' => out.push('~' as u32),
                b'{' => gb = true,
                b'\n' => {}
                _ => {
                    out.push(REPLACEMENT);
                    i += 1;
                    continue;
                }
            }
            i += 2;
        } else if x == b'~' && next == b'}' {
            gb = false;
            i += 2;
        } else if let Some(chars) = pair("hz", b'A', x, next) {
            out.extend_from_slice(&chars);
            i += 2;
        } else {
            out.push(REPLACEMENT);
            i += 1;
        }
    }
    out
}
