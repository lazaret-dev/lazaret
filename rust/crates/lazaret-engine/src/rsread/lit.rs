//! Rust's literals read as the compiler reads them, and `format!`'s formatting (0.1.9, R-1).

use crate::model::val::{collapse, Val, UNKNOWN};
use crate::pystr::PyStr;

// ---------------------------------------------------------------- literals --

/// A string or character literal's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lit {
    /// The value; true for a byte string (its bytes as code points).
    Str(PyStr, bool),
    Char(u32),
}

fn hex_val(c: u32) -> Option<u32> {
    char::from_u32(c).and_then(|c| c.to_digit(16))
}

/// The value of a string or character literal as `lex::rs` gives its token: `"…"`, `r#"…"#`, `b"…"`, `br"…"`,
/// `c"…"`, `'x'`, `b'x'`. None for a literal the compiler would refuse.
pub fn literal(t: &[u32]) -> Option<Lit> {
    let c = |ch: char| ch as u32;
    let mut i = 0;
    let mut bytes = false;
    let mut raw = false;
    while i < t.len() && (t[i] == c('b') || t[i] == c('r') || t[i] == c('c')) {
        if t[i] == c('b') {
            bytes = true;
        }
        if t[i] == c('r') {
            raw = true;
        }
        i += 1;
    }
    if i >= t.len() {
        return None;
    }
    if t[i] == c('\'') {
        let body = &t[i + 1..t.len().saturating_sub(1).max(i + 1)];
        if t.last() != Some(&c('\'')) || t.len() < i + 3 {
            return None;
        }
        let v = unescape(body, false, bytes)?;
        return if v.len() == 1 { Some(Lit::Char(v[0])) } else { None };
    }
    if raw {
        let mut h = 0;
        while i + h < t.len() && t[i + h] == c('#') {
            h += 1;
        }
        let open = i + h;
        if open >= t.len() || t[open] != c('"') {
            return None;
        }
        let close = t.len().checked_sub(h + 1)?;
        if close < open + 1 || t[close] != c('"') {
            return None;
        }
        return Some(Lit::Str(t[open + 1..close].to_vec(), bytes));
    }
    if t[i] != c('"') || t.len() < i + 2 || t.last() != Some(&c('"')) {
        return None;
    }
    let body = &t[i + 1..t.len() - 1];
    Some(Lit::Str(unescape(body, true, bytes)?, bytes))
}

/// A literal's body read: escapes, and in a string a backslash before a line break skips the break and the
/// white space after it.
fn unescape(body: &[u32], string: bool, bytes: bool) -> Option<PyStr> {
    let c = |ch: char| ch as u32;
    let mut out = Vec::with_capacity(body.len());
    let mut k = 0;
    while k < body.len() {
        let x = body[k];
        if x != c('\\') {
            out.push(x);
            k += 1;
            continue;
        }
        let y = *body.get(k + 1)?;
        k += 2;
        match char::from_u32(y)? {
            'n' => out.push(10),
            'r' => out.push(13),
            't' => out.push(9),
            '\\' => out.push(c('\\')),
            '0' => out.push(0),
            '\'' => out.push(c('\'')),
            '"' => out.push(c('"')),
            'x' => {
                let a = hex_val(*body.get(k)?)?;
                let b = hex_val(*body.get(k + 1)?)?;
                let v = a * 16 + b;
                if !bytes && v > 0x7F {
                    return None;
                }
                out.push(v);
                k += 2;
            }
            'u' if !bytes => {
                if body.get(k) != Some(&c('{')) {
                    return None;
                }
                let mut v: u32 = 0;
                let mut j = k + 1;
                let mut n = 0;
                while j < body.len() && body[j] != c('}') {
                    if body[j] != c('_') {
                        v = v.checked_mul(16)?.checked_add(hex_val(body[j])?)?;
                        n += 1;
                    }
                    j += 1;
                }
                if j >= body.len() || n == 0 || n > 6 || char::from_u32(v).is_none() {
                    return None;
                }
                out.push(v);
                k = j + 1;
            }
            '\n' if string => {
                while k < body.len() && matches!(char::from_u32(body[k]), Some(' ' | '\t' | '\n' | '\r')) {
                    k += 1;
                }
            }
            '\r' if string && body.get(k) == Some(&10) => {
                k += 1;
                while k < body.len() && matches!(char::from_u32(body[k]), Some(' ' | '\t' | '\n' | '\r')) {
                    k += 1;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// An integer literal's value (`0x7f`, `0o17`, `0b1010`, `1_000u32`); None for a float or one out of range.
pub fn int_literal(t: &[u32]) -> Option<i128> {
    let s: String = t.iter().filter_map(|&c| char::from_u32(c)).filter(|&c| c != '_').collect();
    let (radix, digits) = if let Some(r) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, r)
    } else if let Some(r) = s.strip_prefix("0o") {
        (8, r)
    } else if let Some(r) = s.strip_prefix("0b") {
        (2, r)
    } else {
        (10, s.as_str())
    };
    if radix == 10 && (digits.contains('.') || digits.contains('e') || digits.contains('E')) {
        return None;
    }
    // the suffix: i8 … u128, isize, usize
    let end = digits.find(|ch: char| !ch.is_digit(radix)).unwrap_or(digits.len());
    let (num, suffix) = digits.split_at(end);
    if !suffix.is_empty() && !matches!(suffix, "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize") {
        return None;
    }
    i128::from_str_radix(num, radix).ok()
}

// ---------------------------------------------------------------- formatting --

/// `format!`'s text for a format string and its arguments: `{}`, `{:?}`, `{0}`, `{name}`, `{:>8}` and the
/// rest give the argument's text (padding and precision left out), `{{` and `}}` a brace. `named`: the
/// arguments written `name = value`, then the names the string captures, as `lookup` gives them.
pub fn format(fmt: &[u32], args: &[Val], named: &[(PyStr, Val)], lookup: &mut dyn FnMut(&[u32]) -> Val) -> Val {
    let c = |ch: char| ch as u32;
    let mut out: PyStr = Vec::with_capacity(fmt.len());
    let mut kinds = Val::unknown();
    let mut next = 0usize;
    let mut k = 0;
    while k < fmt.len() {
        let x = fmt[k];
        if x == c('{') {
            if fmt.get(k + 1) == Some(&c('{')) {
                out.push(x);
                k += 2;
                continue;
            }
            let mut j = k + 1;
            while j < fmt.len() && fmt[j] != c('}') {
                j += 1;
            }
            if j >= fmt.len() {
                out.push(UNKNOWN);
                break;
            }
            let spec = &fmt[k + 1..j];
            let name: &[u32] = match spec.iter().position(|&ch| ch == c(':')) {
                Some(p) => &spec[..p],
                None => spec,
            };
            let v = if name.is_empty() {
                let v = args.get(next).cloned().unwrap_or_default();
                next += 1;
                v
            } else if name.iter().all(|&ch| (c('0')..=c('9')).contains(&ch)) {
                let n: usize = name.iter().fold(0usize, |a, &d| a.saturating_mul(10).saturating_add((d - c('0')) as usize));
                args.get(n).cloned().unwrap_or_default()
            } else {
                match named.iter().find(|(n, _)| n.as_slice() == name) {
                    Some((_, v)) => v.clone(),
                    None => lookup(name),
                }
            };
            out.extend(v.text_or_unknown());
            kinds.add_kinds(&v);
            k = j + 1;
            continue;
        }
        if x == c('}') && fmt.get(k + 1) == Some(&c('}')) {
            out.push(x);
            k += 2;
            continue;
        }
        out.push(x);
        k += 1;
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
    fn literals_as_the_compiler_reads_them() {
        assert_eq!(literal(&u(r#""a\tb\x41\u{1F600}\"""#)), Some(Lit::Str(u("a\tbA\u{1F600}\""), false)));
        assert_eq!(literal(&u("\"a\\\n    b\"")), Some(Lit::Str(u("ab"), false)));
        assert_eq!(literal(&u(r##"r#"x\n"y"#"##)), Some(Lit::Str(u(r#"x\n"y"#), false)));
        assert_eq!(literal(&u(r#"b"\xff\x00""#)), Some(Lit::Str(vec![0xff, 0], true)));
        assert_eq!(literal(&u(r#"br"\x""#)), Some(Lit::Str(u(r"\x"), true)));
        assert_eq!(literal(&u("'a'")), Some(Lit::Char('a' as u32)));
        assert_eq!(literal(&u(r"'\n'")), Some(Lit::Char(10)));
        assert_eq!(literal(&u(r"b'\xff'")), Some(Lit::Char(0xff)));
        // refused: a non-ASCII \x in a str, an unknown escape
        assert_eq!(literal(&u(r#""\xff""#)), None);
        assert_eq!(literal(&u(r#""\q""#)), None);
    }

    #[test]
    fn integers() {
        assert_eq!(int_literal(&u("0x7f")), Some(127));
        assert_eq!(int_literal(&u("1_000u32")), Some(1000));
        assert_eq!(int_literal(&u("0b1010")), Some(10));
        assert_eq!(int_literal(&u("0o17")), Some(15));
        assert_eq!(int_literal(&u("1.5")), None);
        assert_eq!(int_literal(&u("1e3")), None);
    }

    #[test]
    fn format_strings() {
        let a = Val::text(u("x"));
        let b = Val::source(crate::jsflow::supply::K_ENV, u("TOKEN"), 3);
        let v = format(&u("{}/{:?}/{0}/{{n}}/{name}"), &[a.clone(), b], &[(u("name"), Val::text(u("N")))], &mut |_| Val::unknown());
        assert_eq!(st(&v.text_or_unknown()), "x/\u{2}/x/{n}/N");
        assert_eq!(v.kinds, crate::jsflow::supply::K_ENV);
        // a captured name
        let v = format(&u("http://{host}:{port}"), &[], &[], &mut |n| if st(n) == "host" { Val::text(u("h")) } else { Val::unknown() });
        assert_eq!(st(&v.text_or_unknown()), "http://h:\u{2}");
    }
}
