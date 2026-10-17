//! The Unicode codecs and the two that map bytes one to one, as Python decodes them with errors="replace": each
//! error is one U+FFFD, and decoding goes on where Python's goes on (held to it by the tests). UTF-7 can leave a
//! lone surrogate, as Python's does; decode_source makes it U+FFFD.

const REPLACEMENT: u32 = 0xFFFD;

/// UTF-8: an ill-formed sequence's maximal subpart is one U+FFFD (Python's decoder, and the Unicode Standard's
/// practice: what `str::from_utf8` calls an error's length); a sequence cut short by the end of the data, one.
pub fn utf8(mut b: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.extend(s.chars().map(|c| c as u32));
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                // (the prefix is valid UTF-8, so this cannot fail)
                out.extend(std::str::from_utf8(&b[..good]).unwrap_or("").chars().map(|c| c as u32));
                out.push(REPLACEMENT);
                match e.error_len() {
                    Some(n) => b = &b[good + n..],
                    None => return out,
                }
            }
        }
    }
}

/// UTF-8 with a signature: a leading EF BB BF is dropped.
pub fn utf8_sig(b: &[u8]) -> Vec<u32> {
    utf8(b.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(b))
}

pub fn ascii(b: &[u8]) -> Vec<u32> {
    b.iter().map(|&c| if c < 0x80 { c as u32 } else { REPLACEMENT }).collect()
}

pub fn latin1(b: &[u8]) -> Vec<u32> {
    b.iter().map(|&c| c as u32).collect()
}

/// The byte order a UTF-16 or UTF-32 codec reads: `None` for "utf-16" and "utf-32", which take a leading byte order
/// mark (and drop it), and read little-endian without one (Python's native order on the hosts it runs on).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Le,
    Be,
    Bom,
}

pub fn utf16(b: &[u8], order: Order) -> Vec<u32> {
    let mut q = 0usize;
    let mut le = order != Order::Be;
    if order == Order::Bom && b.len() >= 2 {
        match (b[0], b[1]) {
            (0xFF, 0xFE) => q = 2,
            (0xFE, 0xFF) => {
                q = 2;
                le = false;
            }
            _ => {}
        }
    }
    let unit = |k: usize| -> u32 { if le { b[k] as u32 | (b[k + 1] as u32) << 8 } else { (b[k] as u32) << 8 | b[k + 1] as u32 } };
    let e = b.len();
    let mut out = Vec::with_capacity((e - q) / 2);
    while q < e {
        if e - q < 2 {
            out.push(REPLACEMENT); // an odd byte at the end
            break;
        }
        let u = unit(q);
        q += 2;
        if !(0xD800..0xE000).contains(&u) {
            out.push(u);
            continue;
        }
        if u >= 0xDC00 {
            out.push(REPLACEMENT); // a low surrogate first: its two bytes
            continue;
        }
        if e - q < 2 {
            out.push(REPLACEMENT); // a high surrogate with no unit after it: the rest
            break;
        }
        let v = unit(q);
        if (0xDC00..0xE000).contains(&v) {
            q += 2;
            out.push(0x10000 + ((u - 0xD800) << 10) + (v - 0xDC00));
        } else {
            out.push(REPLACEMENT); // a high surrogate not followed by a low one: its two bytes
        }
    }
    out
}

pub fn utf32(b: &[u8], order: Order) -> Vec<u32> {
    let mut q = 0usize;
    let mut le = order != Order::Be;
    if order == Order::Bom && b.len() >= 4 {
        match (b[0], b[1], b[2], b[3]) {
            (0xFF, 0xFE, 0, 0) => q = 4,
            (0, 0, 0xFE, 0xFF) => {
                q = 4;
                le = false;
            }
            _ => {}
        }
    }
    let e = b.len();
    let mut out = Vec::with_capacity((e - q) / 4);
    while q < e {
        if e - q < 4 {
            out.push(REPLACEMENT); // an odd byte at the end
            break;
        }
        let c = if le {
            u32::from_le_bytes([b[q], b[q + 1], b[q + 2], b[q + 3]])
        } else {
            u32::from_be_bytes([b[q], b[q + 1], b[q + 2], b[q + 3]])
        };
        q += 4;
        out.push(if c >= 0x110000 || (0xD800..0xE000).contains(&c) { REPLACEMENT } else { c });
    }
    out
}

/// A byte's value in UTF-7's modified base64 (RFC 2152: A-Z a-z 0-9 + /), or None.
fn base64(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// UTF-7 (RFC 2152), as Python decodes it with errors="replace" (held to it by the tests). Outside a shift a byte
/// below 0x80 is itself and one from 0x80 an error. "+-" is "+"; "+" before a base64 byte opens a shift, "+"
/// before anything else is an error of both bytes, and "+" at the end is nothing. In a shift the base64 bytes are
/// 16-bit units: a high surrogate waits for a low one to make a pair with, and is itself if another unit comes;
/// a low one alone is itself. The shift ends at the first other byte, which is read after it ("-" is absorbed):
/// six bits or more left, or bits left that are not 0, is an error that takes that byte with it; else a waiting
/// high surrogate is itself, unless that byte is from 0x80 (an error of the byte, the surrogate lost). At the end
/// of the data a shift with bits left or a high surrogate waiting is one error.
pub fn utf7(b: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let x = b[i];
        if x >= 0x80 {
            out.push(REPLACEMENT);
            i += 1;
            continue;
        }
        if x != b'+' {
            out.push(x as u32);
            i += 1;
            continue;
        }
        match b.get(i + 1) {
            None => break,
            Some(b'-') => {
                out.push('+' as u32);
                i += 2;
                continue;
            }
            Some(&y) if base64(y).is_none() => {
                out.push(REPLACEMENT);
                i += 2;
                continue;
            }
            Some(_) => {}
        }
        // a shift: its units as they complete
        let (mut acc, mut held) = (0u32, 0u32);
        let mut high: Option<u32> = None;
        let mut j = i + 1;
        while let Some(v) = b.get(j).and_then(|&y| base64(y)) {
            acc = (acc << 6 | v) & 0x3F_FFFF;
            held += 6;
            j += 1;
            if held < 16 {
                continue;
            }
            held -= 16;
            let unit = (acc >> held) & 0xFFFF;
            match high.take() {
                Some(h) if (0xDC00..0xE000).contains(&unit) => out.push(0x10000 + ((h - 0xD800) << 10) + (unit - 0xDC00)),
                Some(h) => {
                    out.push(h);
                    if (0xD800..0xDC00).contains(&unit) { high = Some(unit) } else { out.push(unit) }
                }
                None => {
                    if (0xD800..0xDC00).contains(&unit) { high = Some(unit) } else { out.push(unit) }
                }
            }
        }
        let bad_tail = held >= 6 || acc & ((1 << held) - 1) != 0;
        let Some(&end) = b.get(j) else {
            if bad_tail || high.is_some() {
                out.push(REPLACEMENT);
            }
            break;
        };
        if bad_tail || end >= 0x80 {
            out.push(REPLACEMENT);
            i = j + 1;
            continue;
        }
        out.extend(high);
        i = if end == b'-' { j + 1 } else { j };
    }
    out
}
