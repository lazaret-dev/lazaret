//! Literals' values: numbers (any size of int, floats and imaginary
//! numbers as Python rounds them) and the bodies of string, bytes and
//! f-string literals (escapes, line breaks, doubled braces).

use super::unicode;

/// A number literal's value.
#[derive(Clone, Debug, PartialEq)]
pub enum Num {
    /// an int: its decimal digits (up to `tree::INT_DECIMAL_BITS` bits),
    /// else `0x` and its hexadecimal digits
    Int(Vec<u32>),
    Float(f64),
    /// an imaginary number: 0 plus this times j
    Imag(f64),
}

/// Decimal digits a literal may have (Python's int_max_str_digits).
pub const MAX_DECIMAL_DIGITS: usize = 4300;

/// The value of a number token's text (the tokenizer checked its form).
pub fn number(text: &[u32]) -> Result<Num, String> {
    let clean: Vec<u8> = text.iter().filter(|&&c| c != 0x5F).map(|&c| c as u8).collect();
    let lower: Vec<u8> = clean.iter().map(|c| c.to_ascii_lowercase()).collect();
    if lower.last() == Some(&b'j') {
        return float_of(&clean[..clean.len() - 1]).map(Num::Imag);
    }
    if lower.len() > 2 && lower[0] == b'0' && matches!(lower[1], b'x' | b'o' | b'b') {
        let bits = match lower[1] {
            b'x' => 4,
            b'o' => 3,
            _ => 1,
        };
        return Ok(Num::Int(int_of_power_of_two(&lower[2..], bits)));
    }
    if lower.iter().any(|&c| c == b'.' || c == b'e') {
        return float_of(&clean).map(Num::Float);
    }
    let digits: &[u8] = {
        let first = lower.iter().position(|&c| c != b'0').unwrap_or(lower.len());
        &lower[first..]
    };
    if digits.len() > MAX_DECIMAL_DIGITS {
        return Err(format!(
            "Exceeds the limit ({} digits) for integer string conversion: value has {} digits",
            MAX_DECIMAL_DIGITS,
            digits.len()
        ));
    }
    if digits.is_empty() {
        return Ok(Num::Int(vec![0x30]));
    }
    Ok(Num::Int(digits.iter().map(|&c| c as u32).collect()))
}

fn float_of(text: &[u8]) -> Result<f64, String> {
    let s = std::str::from_utf8(text).map_err(|_| "invalid number".to_string())?;
    // Rust reads "1.", ".5" and "1e5" as Python does (correctly rounded)
    s.parse::<f64>().map_err(|_| format!("invalid number {:?}", s))
}

/// An int in base 2, 8 or 16 (`bits` per digit): decimal digits up to
/// INT_DECIMAL_BITS bits, else `0x` and hexadecimal digits.
fn int_of_power_of_two(digits: &[u8], bits: u32) -> Vec<u32> {
    // little-endian 64-bit limbs
    let mut limbs: Vec<u64> = Vec::with_capacity(digits.len() * bits as usize / 64 + 1);
    let mut acc: u128 = 0;
    let mut nacc: u32 = 0;
    for &d in digits.iter().rev() {
        let v = match d {
            b'0'..=b'9' => d - b'0',
            b'a'..=b'f' => d - b'a' + 10,
            _ => 0,
        } as u128;
        acc |= v << nacc;
        nacc += bits;
        if nacc >= 64 {
            limbs.push(acc as u64);
            acc >>= 64;
            nacc -= 64;
        }
    }
    if nacc > 0 {
        limbs.push(acc as u64);
    }
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    if limbs.is_empty() {
        return vec![0x30];
    }
    let bit_length = (limbs.len() as u32 - 1) * 64 + (64 - limbs[limbs.len() - 1].leading_zeros());
    if bit_length > super::tree::INT_DECIMAL_BITS {
        let mut out: Vec<u32> = vec![0x30, 0x78];
        let mut started = false;
        for &l in limbs.iter().rev() {
            for k in (0..16).rev() {
                let nib = ((l >> (k * 4)) & 0xF) as u32;
                if nib != 0 || started {
                    started = true;
                    out.push(if nib < 10 { 0x30 + nib } else { 0x61 + nib - 10 });
                }
            }
        }
        return out;
    }
    decimal_of_limbs(limbs)
}

/// The decimal digits of a little-endian limb number (small: a few hundred limbs).
fn decimal_of_limbs(mut limbs: Vec<u64>) -> Vec<u32> {
    const CHUNK: u64 = 10_000_000_000_000_000_000; // 10^19
    let mut chunks: Vec<u64> = Vec::new();
    while !limbs.is_empty() {
        let mut rem: u128 = 0;
        for l in limbs.iter_mut().rev() {
            let cur = (rem << 64) | *l as u128;
            *l = (cur / CHUNK as u128) as u64;
            rem = cur % CHUNK as u128;
        }
        chunks.push(rem as u64);
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
    }
    let mut out: Vec<u32> = Vec::new();
    for (i, &c) in chunks.iter().rev().enumerate() {
        let s = if i == 0 { format!("{}", c) } else { format!("{:019}", c) };
        out.extend(s.bytes().map(|b| b as u32));
    }
    if out.is_empty() {
        out.push(0x30);
    }
    out
}

/// What a string body is read as.
#[derive(Clone, Copy, Debug)]
pub struct Body {
    /// no escapes
    pub raw: bool,
    /// bytes: only ASCII; no \u, \U, \N
    pub bytes: bool,
    /// an f-string's literal text outside a format specifier: `{{` and `}}`
    /// are one brace
    pub braces: bool,
}

#[inline]
fn hex_value(c: u32) -> Option<u32> {
    match c {
        0x30..=0x39 => Some(c - 0x30),
        0x41..=0x46 => Some(c - 0x41 + 10),
        0x61..=0x66 => Some(c - 0x61 + 10),
        _ => None,
    }
}

/// Appends the value of a literal's body (the text between its quotes, or
/// an f-string's literal text) to `out`: code points (a bytes literal's
/// are below 256). Line breaks ("\r\n", "\r") read as "\n", as Python reads
/// source text.
pub fn body(text: &[u32], how: Body, out: &mut Vec<u32>) -> Result<(), String> {
    if how.bytes && text.iter().any(|&c| c >= 0x80) {
        return Err("bytes can only contain ASCII literal characters".to_string());
    }
    let n = text.len();
    let mut i = 0;
    while i < n {
        let c = text[i];
        match c {
            0x0D => {
                out.push(0x0A);
                i += if text.get(i + 1) == Some(&0x0A) { 2 } else { 1 };
            }
            0x7B | 0x7D if how.braces && text.get(i + 1) == Some(&c) => {
                out.push(c);
                i += 2;
            }
            0x5C if !how.raw => {
                let e = match text.get(i + 1) {
                    Some(&e) => e,
                    None => {
                        out.push(0x5C); // (an f-string's text ending before a field)
                        i += 1;
                        continue;
                    }
                };
                i += 2;
                match e {
                    0x0A => {}
                    0x0D => {
                        if text.get(i) == Some(&0x0A) {
                            i += 1;
                        }
                    }
                    0x5C | 0x27 | 0x22 => out.push(e),
                    0x61 => out.push(0x07),
                    0x62 => out.push(0x08),
                    0x66 => out.push(0x0C),
                    0x6E => out.push(0x0A),
                    0x72 => out.push(0x0D),
                    0x74 => out.push(0x09),
                    0x76 => out.push(0x0B),
                    0x30..=0x37 => {
                        let mut v = e - 0x30;
                        for _ in 0..2 {
                            match text.get(i) {
                                Some(&d) if (0x30..=0x37).contains(&d) => {
                                    v = v * 8 + (d - 0x30);
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(if how.bytes { v & 0xFF } else { v });
                    }
                    0x78 => {
                        let v = match (text.get(i).and_then(|&d| hex_value(d)), text.get(i + 1).and_then(|&d| hex_value(d))) {
                            (Some(a), Some(b)) => a * 16 + b,
                            _ => return Err("truncated \\xXX escape".to_string()),
                        };
                        i += 2;
                        out.push(v);
                    }
                    0x75 | 0x55 if !how.bytes => {
                        let k = if e == 0x75 { 4 } else { 8 };
                        let mut v: u32 = 0;
                        for j in 0..k {
                            match text.get(i + j).and_then(|&d| hex_value(d)) {
                                Some(d) => v = v.wrapping_mul(16).wrapping_add(d),
                                None => {
                                    return Err(if k == 4 {
                                        "truncated \\uXXXX escape".to_string()
                                    } else {
                                        "truncated \\UXXXXXXXX escape".to_string()
                                    })
                                }
                            }
                        }
                        i += k;
                        if v > 0x10FFFF {
                            return Err("illegal Unicode character".to_string());
                        }
                        out.push(v);
                    }
                    0x4E if !how.bytes => {
                        // \N{name}
                        if text.get(i) != Some(&0x7B) {
                            return Err("malformed \\N character escape".to_string());
                        }
                        let close = text[i + 1..].iter().position(|&d| d == 0x7D);
                        let close = match close {
                            Some(k) if k > 0 => i + 1 + k,
                            _ => return Err("malformed \\N character escape".to_string()),
                        };
                        match unicode::lookup_name(&text[i + 1..close]) {
                            Some(v) => out.push(v),
                            None => return Err("unknown Unicode character name".to_string()),
                        }
                        i = close + 1;
                    }
                    _ => {
                        // not an escape (Python warns): the backslash stays
                        out.push(0x5C);
                        i -= 1;
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn int(s: &str) -> String {
        match number(&cps(s)).unwrap() {
            Num::Int(d) => d.iter().map(|&c| char::from_u32(c).unwrap()).collect(),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(int("0"), "0");
        assert_eq!(int("000"), "0");
        assert_eq!(int("1_000"), "1000");
        assert_eq!(int("0x_ff"), "255");
        assert_eq!(int("0o17"), "15");
        assert_eq!(int("0B101"), "5");
        assert_eq!(int("0xffffffffffffffffffffffffffffffff"), "340282366920938463463374607431768211455");
        assert_eq!(int(&format!("0x1{}", "0".repeat(4096))), format!("0x1{}", "0".repeat(4096)));
        assert_eq!(number(&cps("1.5")).unwrap(), Num::Float(1.5));
        assert_eq!(number(&cps("1.")).unwrap(), Num::Float(1.0));
        assert_eq!(number(&cps(".5")).unwrap(), Num::Float(0.5));
        assert_eq!(number(&cps("1e5")).unwrap(), Num::Float(1e5));
        assert_eq!(number(&cps("1_0.0_1e1_0")).unwrap(), Num::Float(10.01e10));
        assert_eq!(number(&cps("1e999")).unwrap(), Num::Float(f64::INFINITY));
        assert_eq!(number(&cps("3j")).unwrap(), Num::Imag(3.0));
        assert_eq!(number(&cps("09.5J")).unwrap(), Num::Imag(9.5));
        assert!(number(&cps(&"1".repeat(4301))).is_err());
        assert!(number(&cps(&"1".repeat(4300))).is_ok());
    }

    fn decode(s: &str, raw: bool, bytes: bool) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        body(&cps(s), Body { raw, bytes, braces: false }, &mut out).map(|_| out)
    }

    #[test]
    fn escapes() {
        assert_eq!(decode("a\\nb", false, false).unwrap(), cps("a\nb"));
        assert_eq!(decode("\\777\\400\\0", false, false).unwrap(), vec![0o777, 0o400, 0]);
        assert_eq!(decode("\\777", false, true).unwrap(), vec![0xFF]);
        assert_eq!(decode("\\d\\8", false, false).unwrap(), cps("\\d\\8"));
        assert_eq!(decode("\\ud83d\\ude00", false, false).unwrap(), vec![0xD83D, 0xDE00]);
        assert_eq!(decode("\\U0001F600", false, false).unwrap(), vec![0x1F600]);
        assert_eq!(decode("\\u1234", false, true).unwrap(), cps("\\u1234"));
        assert_eq!(decode("\\N{BOM}", false, false).unwrap(), vec![0xFEFF]);
        assert!(decode("\\N{NO SUCH NAME}", false, false).is_err());
        assert!(decode("\\N", false, false).is_err());
        assert!(decode("\\x4", false, false).is_err());
        assert!(decode("\\U00110000", false, false).is_err());
        assert!(decode("\u{e9}", false, true).is_err());
        assert_eq!(decode("a\\\r\nb\r\nc\rd", false, false).unwrap(), cps("ab\nc\nd"));
        assert_eq!(decode("a\\\r\nb", true, false).unwrap(), cps("a\\\nb"));
        let mut out = Vec::new();
        body(&cps("{{a}}\\{{"), Body { raw: false, bytes: false, braces: true }, &mut out).unwrap();
        assert_eq!(out, cps("{a}\\{"));
    }
}
