//! Go's literals read as the compiler reads them, and `fmt`'s formatting (0.1.9, G-1).
//!
//! A Go string is bytes: an interpreted literal's escapes give bytes (`\x41`, `\101`) or code points written as
//! UTF-8 (`é`), and the reader holds a string as the text those bytes are (`model::val::utf8`: UTF-8 read as
//! text, anything else each byte its own code point). A raw literal is its text, carriage returns dropped.

use crate::model::val::{collapse, utf8, Val, UNKNOWN};
use crate::pystr::PyStr;

fn hex_val(c: u32) -> Option<u32> {
    char::from_u32(c).and_then(|c| c.to_digit(16))
}

fn oct_val(c: Option<&u32>) -> Option<u32> {
    char::from_u32(*c?).and_then(|c| c.to_digit(8))
}

/// A code point's UTF-8 bytes, each a code point.
fn push_utf8(out: &mut PyStr, cp: u32) {
    match char::from_u32(cp) {
        Some(ch) => {
            let mut buf = [0u8; 4];
            out.extend(ch.encode_utf8(&mut buf).bytes().map(|b| b as u32));
        }
        None => out.push(cp),
    }
}

/// The bytes of a literal's body (between its quotes), its escapes read as `go/scanner` reads them; None for one it
/// refuses. `quote` is the literal's quote, the one escape of a quote it allows.
fn unescape(body: &[u32], quote: char) -> Option<PyStr> {
    let mut out = Vec::with_capacity(body.len());
    let mut k = 0;
    while k < body.len() {
        let x = body[k];
        if x != '\\' as u32 {
            push_utf8(&mut out, x);
            k += 1;
            continue;
        }
        let y = char::from_u32(*body.get(k + 1)?)?;
        k += 2;
        match y {
            'a' => out.push(7),
            'b' => out.push(8),
            'f' => out.push(12),
            'n' => out.push(10),
            'r' => out.push(13),
            't' => out.push(9),
            'v' => out.push(11),
            '\\' => out.push('\\' as u32),
            '\'' if quote == '\'' => out.push('\'' as u32),
            '"' if quote == '"' => out.push('"' as u32),
            '0'..='7' => {
                let v = (y as u32 - '0' as u32) * 64 + oct_val(body.get(k))? * 8 + oct_val(body.get(k + 1))?;
                if v > 255 {
                    return None;
                }
                out.push(v);
                k += 2;
            }
            'x' => {
                let v = hex_val(*body.get(k)?)? * 16 + hex_val(*body.get(k + 1)?)?;
                out.push(v);
                k += 2;
            }
            'u' | 'U' => {
                let n = if y == 'u' { 4 } else { 8 };
                let mut v: u32 = 0;
                for j in 0..n {
                    v = v.checked_mul(16)?.checked_add(hex_val(*body.get(k + j)?)?)?;
                }
                if char::from_u32(v).is_none() {
                    return None;
                }
                push_utf8(&mut out, v);
                k += n;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// A string literal's value as text (`"…"` with its escapes, or a raw `` `…` ``); None for one `go/scanner` refuses.
pub fn string_lit(t: &[u32]) -> Option<PyStr> {
    let first = *t.first()?;
    let last = *t.last()?;
    if t.len() < 2 {
        return None;
    }
    if first == '`' as u32 && last == '`' as u32 {
        return Some(t[1..t.len() - 1].iter().copied().filter(|&c| c != 13).collect());
    }
    if first != '"' as u32 || last != '"' as u32 {
        return None;
    }
    Some(utf8(&unescape(&t[1..t.len() - 1], '"')?))
}

/// A rune literal's value (`'a'`, `'\n'`, `'\x41'`, `'é'`); None for one `go/scanner` refuses.
pub fn rune_lit(t: &[u32]) -> Option<u32> {
    if t.len() < 3 || t[0] != '\'' as u32 || *t.last()? != '\'' as u32 {
        return None;
    }
    let body = &t[1..t.len() - 1];
    if body.first() == Some(&('\\' as u32)) {
        let y = char::from_u32(*body.get(1)?)?;
        if matches!(y, 'x' | '0'..='7') {
            // a byte's value
            let b = unescape(body, '\'')?;
            return if b.len() == 1 { Some(b[0]) } else { None };
        }
        let b = unescape(body, '\'')?;
        let s = utf8(&b);
        return if s.len() == 1 { Some(s[0]) } else { None };
    }
    if body.len() == 1 {
        Some(body[0])
    } else {
        None
    }
}

/// An integer literal's value (`42`, `0x2a`, `0o52`, `052`, `0b101010`, `1_000`); None for a float, an imaginary or
/// one out of range.
pub fn int_lit(t: &[u32]) -> Option<i128> {
    let s: String = t.iter().filter_map(|&c| char::from_u32(c)).filter(|&c| c != '_').collect();
    let lower = s.to_ascii_lowercase();
    let (radix, digits) = if let Some(r) = lower.strip_prefix("0x") {
        if r.contains('p') || r.contains('.') {
            return None; // a hexadecimal float
        }
        (16, r.to_string())
    } else if let Some(r) = lower.strip_prefix("0o") {
        (8, r.to_string())
    } else if let Some(r) = lower.strip_prefix("0b") {
        (2, r.to_string())
    } else if lower.len() > 1 && lower.starts_with('0') && lower.bytes().all(|b| b.is_ascii_digit()) {
        (8, lower[1..].to_string())
    } else {
        (10, lower.clone())
    };
    if digits.is_empty() || digits.ends_with('i') || digits.contains('.') || (radix == 10 && digits.contains('e')) {
        return None;
    }
    i128::from_str_radix(&digits, radix).ok()
}

fn text_of(v: &Val) -> PyStr {
    if v.s.is_none() {
        if let Some(items) = &v.items {
            // a slice prints as `[a b c]`
            let mut out = vec!['[' as u32];
            for (k, it) in items.iter().enumerate() {
                if k > 0 {
                    out.push(' ' as u32);
                }
                out.extend(text_of(it));
            }
            out.push(']' as u32);
            return out;
        }
    }
    v.text_or_unknown()
}

fn digits(n: i128, radix: u32, upper: bool) -> PyStr {
    let s = match radix {
        16 if upper => format!("{:X}", n),
        16 => format!("{:x}", n),
        8 => format!("{:o}", n),
        2 => format!("{:b}", n),
        _ => n.to_string(),
    };
    s.chars().map(|c| c as u32).collect()
}

/// `fmt.Sprintf`'s text for a format and its arguments: the verbs, flags, widths, precisions and explicit argument
/// indexes `fmt` reads (`%s`, `%v`, `%d`, `%x`, `%q`, `%c`, `%[2]s`, `%-8s`, `%%`); padding is left out, and what
/// the reader cannot know (a float, a bool, a pointer) is an unknown piece.
pub fn sprintf(fmt: &[u32], args: &[Val]) -> Val {
    let c = |ch: char| ch as u32;
    let mut out: PyStr = Vec::with_capacity(fmt.len());
    let mut kinds = Val::unknown();
    let mut next = 0usize;
    let mut k = 0;
    while k < fmt.len() {
        if fmt[k] != c('%') {
            out.push(fmt[k]);
            k += 1;
            continue;
        }
        k += 1;
        if k >= fmt.len() {
            out.push(UNKNOWN);
            break;
        }
        if fmt[k] == c('%') {
            out.push(c('%'));
            k += 1;
            continue;
        }
        // flags, an argument index, a width, a precision (each `*` takes an argument), an argument index again
        let mut index: Option<usize> = None;
        let mut guard = 0;
        while k < fmt.len() && guard < 64 {
            guard += 1;
            let x = fmt[k];
            if [c('+'), c('-'), c('#'), c(' '), c('0'), c('.')].contains(&x) || (c('1')..=c('9')).contains(&x) {
                k += 1;
            } else if x == c('*') {
                next += 1;
                k += 1;
            } else if x == c('[') {
                let mut j = k + 1;
                let mut n = 0usize;
                while j < fmt.len() && (c('0')..=c('9')).contains(&fmt[j]) {
                    n = n.saturating_mul(10).saturating_add((fmt[j] - c('0')) as usize);
                    j += 1;
                }
                if j < fmt.len() && fmt[j] == c(']') && n > 0 {
                    index = Some(n - 1);
                    next = n - 1;
                    k = j + 1;
                } else {
                    k += 1;
                }
            } else {
                break;
            }
        }
        if k >= fmt.len() {
            out.push(UNKNOWN);
            break;
        }
        let verb = char::from_u32(fmt[k]).unwrap_or('?');
        k += 1;
        let at = index.unwrap_or(next);
        next = at + 1;
        let Some(a) = args.get(at) else {
            out.push(UNKNOWN);
            continue;
        };
        kinds.add_kinds(a);
        match verb {
            's' | 'v' => match (a.s.is_none(), a.int) {
                (true, Some(n)) => out.extend(digits(n, 10, false)),
                _ => out.extend(text_of(a)),
            },
            'd' => match a.int {
                Some(n) => out.extend(digits(n, 10, false)),
                None => out.push(UNKNOWN),
            },
            'q' => {
                out.push(c('"'));
                out.extend(a.text_or_unknown());
                out.push(c('"'));
            }
            'c' | 'U' => match a.int.and_then(|n| u32::try_from(n).ok()).filter(|&n| char::from_u32(n).is_some()) {
                Some(n) if verb == 'c' => out.push(n),
                _ => out.push(UNKNOWN),
            },
            'x' | 'X' => {
                let upper = verb == 'X';
                match (a.int, &a.s) {
                    (Some(n), None) => out.extend(digits(n, 16, upper)),
                    (_, Some(s)) if !s.contains(&UNKNOWN) => {
                        for b in crate::model::val::bytes_of(s) {
                            let d = digits(b as i128, 16, upper);
                            if d.len() < 2 {
                                out.push(c('0'));
                            }
                            out.extend(d);
                        }
                    }
                    _ => out.push(UNKNOWN),
                }
            }
            'o' | 'b' => match a.int {
                Some(n) => out.extend(digits(n, if verb == 'o' { 8 } else { 2 }, false)),
                None => out.push(UNKNOWN),
            },
            _ => out.push(UNKNOWN),
        }
    }
    let mut v = Val::text(collapse(out));
    v.add_kinds(&kinds);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> PyStr {
        s.chars().map(|c| c as u32).collect()
    }

    fn st(v: &[u32]) -> String {
        v.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()
    }

    #[test]
    fn strings_as_the_compiler_reads_them() {
        assert_eq!(string_lit(&u(r#""a\tb\x41\101é\"""#)).map(|s| st(&s)), Some("a\tbAAé\"".into()));
        // bytes that are UTF-8 read as the text they are
        assert_eq!(string_lit(&u(r#""\xe4\xb8\x96""#)).map(|s| st(&s)), Some("世".into()));
        assert_eq!(string_lit(&u("`a\\n\r\nb`")).map(|s| st(&s)), Some("a\\n\nb".into()));
        assert_eq!(string_lit(&u(r#""\U0001F600""#)).map(|s| st(&s)), Some("\u{1F600}".into()));
        // refused: an unknown escape, a quote that is not the literal's, an octal escape over 255
        assert_eq!(string_lit(&u(r#""\q""#)), None);
        assert_eq!(string_lit(&u(r#""\'""#)), None);
        assert_eq!(string_lit(&u(r#""\400""#)), None);
    }

    #[test]
    fn runes_and_integers() {
        assert_eq!(rune_lit(&u("'a'")), Some('a' as u32));
        assert_eq!(rune_lit(&u(r"'\n'")), Some(10));
        assert_eq!(rune_lit(&u(r"'\x41'")), Some(0x41));
        assert_eq!(rune_lit(&u(r"'é'")), Some(0xe9));
        assert_eq!(rune_lit(&u("'é'")), Some(0xe9));
        assert_eq!(int_lit(&u("42")), Some(42));
        assert_eq!(int_lit(&u("0x2A")), Some(42));
        assert_eq!(int_lit(&u("0o52")), Some(42));
        assert_eq!(int_lit(&u("052")), Some(42));
        assert_eq!(int_lit(&u("0b101010")), Some(42));
        assert_eq!(int_lit(&u("1_000")), Some(1000));
        assert_eq!(int_lit(&u("0")), Some(0));
        assert_eq!(int_lit(&u("1.5")), None);
        assert_eq!(int_lit(&u("1e3")), None);
        assert_eq!(int_lit(&u("2i")), None);
        assert_eq!(int_lit(&u("0x1p4")), None);
    }

    #[test]
    fn sprintf_reads_the_verbs() {
        let a = Val::text(u("x"));
        let n = Val::int(255);
        let v = sprintf(&u("%s/%d/%x/%X/%q/%c|%%|%[1]s/%-4v"), &[a.clone(), n.clone(), n.clone(), Val::text(u("hi")), Val::text(u("q")), Val::int(65)]);
        // (after `%[1]s` the next argument is the second)
        assert_eq!(st(&v.text_or_unknown()), "x/255/ff/6869/\"q\"/A|%|x/255");
        let env = Val::source(crate::jsflow::supply::K_ENV, u("TOKEN"), 1);
        let v = sprintf(&u("%s:%s"), &[a.clone(), env]);
        assert_eq!(st(&v.text_or_unknown()), "x:\u{2}");
        assert_eq!(v.kinds, crate::jsflow::supply::K_ENV);
        let v = sprintf(&u("%v and %f"), &[Val::list(vec![Val::text(u("a")), Val::text(u("b"))]), Val::unknown()]);
        assert_eq!(st(&v.text_or_unknown()), "[a b] and \u{2}");
        let v = sprintf(&u("%s %s"), &[a]);
        assert_eq!(st(&v.text_or_unknown()), "x \u{2}");
    }
}
