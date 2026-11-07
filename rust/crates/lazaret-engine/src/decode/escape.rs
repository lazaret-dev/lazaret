//! The escape codecs a coding cookie can name (SC-ESCAPE-CODEC): Python's unicode_escape and raw_unicode_escape,
//! decoded as Python decodes them (bytes.decode, strict: Python's string escapes), or None where it raises, and
//! for a \N{name} escape (the engine has no table of Unicode names): core read such a file as UTF-8, undecoded
//! (SC-TRUNCATED), and so does the engine.

fn hex(c: u8) -> Option<u32> {
    (c as char).to_digit(16)
}

/// `count` hexadecimal digits at `b[s..]`, as a code point; None when one is missing or the value is past U+10FFFF.
fn hex_escape(b: &[u8], s: &mut usize, count: usize) -> Option<u32> {
    let mut ch = 0u32;
    for _ in 0..count {
        let d = hex(*b.get(*s)?)?;
        ch = (ch << 4) | d;
        *s += 1;
    }
    if ch > 0x10FFFF {
        return None;
    }
    Some(ch)
}

/// unicode_escape: a byte is the code point of its value, and a backslash starts an escape (Python's string
/// escapes; an unknown one is kept as written; octal to 0o777; \x, \u, \U take exactly 2, 4, 8 digits).
pub fn unicode_escape(b: &[u8]) -> Option<Vec<u32>> {
    let end = b.len();
    let mut out = Vec::with_capacity(end);
    let mut s = 0usize;
    while s < end {
        let c = b[s];
        s += 1;
        if c != b'\\' {
            out.push(c as u32);
            continue;
        }
        let c = *b.get(s)?; // a backslash at the end
        s += 1;
        match c {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => out.push(c as u32),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b't' => out.push(9),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b'v' => out.push(11),
            b'a' => out.push(7),
            b'0'..=b'7' => {
                let mut ch = (c - b'0') as u32;
                for _ in 0..2 {
                    match b.get(s) {
                        Some(&d @ b'0'..=b'7') => {
                            ch = (ch << 3) + (d - b'0') as u32;
                            s += 1;
                        }
                        _ => break,
                    }
                }
                out.push(ch);
            }
            b'x' => out.push(hex_escape(b, &mut s, 2)?),
            b'u' => out.push(hex_escape(b, &mut s, 4)?),
            b'U' => out.push(hex_escape(b, &mut s, 8)?),
            b'N' => return None,
            _ => {
                out.push('\\' as u32);
                out.push(c as u32);
            }
        }
    }
    Some(out)
}

/// raw_unicode_escape: a byte is the code point of its value, and only \u and \U (exactly 4 and 8 digits) are
/// escapes; any other backslash is kept, with the byte after it.
pub fn raw_unicode_escape(b: &[u8]) -> Option<Vec<u32>> {
    let end = b.len();
    let mut out = Vec::with_capacity(end);
    let mut s = 0usize;
    while s < end {
        let c = b[s];
        s += 1;
        if c != b'\\' || s >= end {
            out.push(c as u32);
            continue;
        }
        let c = b[s];
        s += 1;
        match c {
            b'u' => out.push(hex_escape(b, &mut s, 4)?),
            b'U' => out.push(hex_escape(b, &mut s, 8)?),
            _ => {
                out.push('\\' as u32);
                out.push(c as u32);
            }
        }
    }
    Some(out)
}
