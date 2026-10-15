//! `json.loads` as CPython 3.13's C scanner reads a str (`Modules/_json.c`),
//! with core's `parse_int` (`_json_int`: an integer literal of up to 1,000
//! characters is an int, a longer one a float): NaN, Infinity and -Infinity
//! accepted, a repeated key's last value kept in its first place, lone
//! surrogates from `\u` escapes kept, and on failure the position CPython's
//! decoder reports (a trailing comma at the comma, as 3.13 reports it), in
//! code points. The npm package's `pyjson.js` was its twin until BR-7's step
//! 3 (b).

use super::pyval::{DictBuilder, PyVal};
use crate::pystr::{self, PyStr};

/// Deeper than this, the parse stops (`json.loads` would recurse; core checks the depth first: `depth_exceeds`).
pub const MAX_DEPTH: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// nested deeper than MAX_DEPTH
    Depth,
    /// a JSONDecodeError at this position
    At(usize),
}

/// core.json_depth_exceeds: does `text` nest `[` and `{` deeper than `limit`, outside JSON (double-quoted) strings
/// (an unterminated one to the end)?
pub fn depth_exceeds(text: &[u32], limit: usize) -> bool {
    let mut depth: isize = 0;
    let mut in_str = false;
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if in_str {
            if c == '\\' as u32 {
                i += 1;
            } else if c == '"' as u32 {
                in_str = false;
            }
        } else if c == '"' as u32 {
            in_str = true;
        } else if c == '[' as u32 || c == '{' as u32 {
            depth += 1;
            if depth > limit as isize {
                return true;
            }
        } else if c == ']' as u32 || c == '}' as u32 {
            depth -= 1;
        }
        i += 1;
    }
    false
}

/// JSONDecodeError's "line L column C" for a position.
pub fn error_where(text: &[u32], pos: usize) -> String {
    let pos = pos.min(text.len());
    let line = text[..pos].iter().filter(|&&c| c == '\n' as u32).count() + 1;
    let col = match text[..pos].iter().rposition(|&c| c == '\n' as u32) {
        Some(nl) => pos - nl,
        None => pos + 1,
    };
    format!("line {} column {}", line, col)
}

struct Parser<'a> {
    s: &'a [u32],
    depth: usize,
    /// the key whose position each object records (`_load_manifest`'s `locate`)
    locate: Option<&'a [u32]>,
}

fn is_ws(c: u32) -> bool {
    c == ' ' as u32 || c == '\t' as u32 || c == '\n' as u32 || c == '\r' as u32
}

fn is_digit(c: Option<&u32>) -> bool {
    matches!(c, Some(&d) if (0x30..=0x39).contains(&d))
}

fn hex4(s: &[u32]) -> Option<u32> {
    if s.len() != 4 {
        return None;
    }
    let mut v = 0;
    for &c in s {
        v = v * 16 + char::from_u32(c)?.to_digit(16)?;
    }
    Some(v)
}

impl<'a> Parser<'a> {
    fn skip(&self, mut i: usize) -> usize {
        while i < self.s.len() && is_ws(self.s[i]) {
            i += 1;
        }
        i
    }

    /// scanstring: `end` is the index after the opening quote -> (the string, the index after its closing quote).
    fn string(&self, mut end: usize) -> Result<(PyStr, usize), Error> {
        let s = self.s;
        let n = s.len();
        let begin = end - 1;
        let mut out: PyStr = Vec::new();
        loop {
            let mut next = end;
            let mut c = 0;
            while next < n {
                c = s[next];
                if c == '"' as u32 || c == '\\' as u32 {
                    break;
                }
                if c <= 0x1f {
                    return Err(Error::At(next)); // Invalid control character
                }
                next += 1;
            }
            if next >= n {
                return Err(Error::At(begin)); // Unterminated string
            }
            out.extend_from_slice(&s[end..next]);
            next += 1;
            if c == '"' as u32 {
                return Ok((out, next));
            }
            if next == n {
                return Err(Error::At(begin));
            }
            c = s[next];
            if c != 'u' as u32 {
                end = next + 1;
                let ch = match char::from_u32(c) {
                    Some('"') => '"',
                    Some('\\') => '\\',
                    Some('/') => '/',
                    Some('b') => '\u{8}',
                    Some('f') => '\u{c}',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    _ => return Err(Error::At(end - 2)), // Invalid \escape
                };
                out.push(ch as u32);
                continue;
            }
            next += 1;
            end = next + 4;
            if end > n {
                return Err(Error::At(next - 1)); // Invalid \uXXXX escape
            }
            let mut cp = match hex4(&s[next..end]) {
                Some(v) => v,
                None => return Err(Error::At(end - 5)),
            };
            // (a surrogate pair: a low surrogate's escape whole after a high one's)
            if (0xD800..=0xDBFF).contains(&cp) && end + 6 <= n && s[end] == '\\' as u32 && s[end + 1] == 'u' as u32 {
                let Some(lo) = hex4(&s[end + 2..end + 6]) else {
                    return Err(Error::At(end + 1));
                };
                if (0xDC00..=0xDFFF).contains(&lo) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    end += 6;
                }
            }
            out.push(cp);
        }
    }

    fn number(&self, start: usize) -> Result<(PyVal, usize), Error> {
        let s = self.s;
        let n = s.len();
        let mut i = start;
        if s[i] == '-' as u32 {
            i += 1;
            if i >= n {
                return Err(Error::At(start));
            }
        }
        if (0x31..=0x39).contains(&s[i]) {
            i += 1;
            while is_digit(s.get(i)) {
                i += 1;
            }
        } else if s[i] == 0x30 {
            i += 1;
        } else {
            return Err(Error::At(start));
        }
        let mut float = false;
        if i + 1 < n && s[i] == '.' as u32 && is_digit(s.get(i + 1)) {
            float = true;
            i += 2;
            while is_digit(s.get(i)) {
                i += 1;
            }
        }
        if i + 1 < n && (s[i] == 'e' as u32 || s[i] == 'E' as u32) {
            let e0 = i;
            i += 1;
            if i + 1 < n && (s[i] == '-' as u32 || s[i] == '+' as u32) {
                i += 1;
            }
            let d0 = i;
            while is_digit(s.get(i)) {
                i += 1;
            }
            if i == d0 {
                i = e0;
            } else {
                float = true;
            }
        }
        let lit = &s[start..i];
        if !float && lit.len() <= 1000 {
            return Ok((PyVal::Int(super::pyval::int_of_json(lit)), i));
        }
        let v: f64 = pystr::to_string(lit).parse().unwrap_or(f64::NAN);
        Ok((PyVal::Float(v), i))
    }

    fn value(&mut self, i: usize) -> Result<(PyVal, usize), Error> {
        let s = self.s;
        if i >= s.len() {
            return Err(Error::At(i));
        }
        let c = s[i];
        if c == '"' as u32 {
            let (v, e) = self.string(i + 1)?;
            return Ok((PyVal::Str(v), e));
        }
        if c == '{' as u32 || c == '[' as u32 {
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err(Error::Depth);
            }
            let r = if c == '{' as u32 { self.object(i + 1) } else { self.array(i + 1) };
            self.depth -= 1;
            return r;
        }
        let at = |w: &str| pystr::starts_with_at(s, i, w);
        if c == 'n' as u32 && at("null") {
            return Ok((PyVal::None, i + 4));
        }
        if c == 't' as u32 && at("true") {
            return Ok((PyVal::Bool(true), i + 4));
        }
        if c == 'f' as u32 && at("false") {
            return Ok((PyVal::Bool(false), i + 5));
        }
        if c == 'N' as u32 && at("NaN") {
            return Ok((PyVal::Float(f64::NAN), i + 3));
        }
        if c == 'I' as u32 && at("Infinity") {
            return Ok((PyVal::Float(f64::INFINITY), i + 8));
        }
        if c == '-' as u32 && at("-Infinity") {
            return Ok((PyVal::Float(f64::NEG_INFINITY), i + 9));
        }
        self.number(i)
    }

    fn object(&mut self, i: usize) -> Result<(PyVal, usize), Error> {
        let s = self.s;
        let n = s.len();
        let mut d = DictBuilder::default();
        let mut found: Option<usize> = None;
        let mut i = self.skip(i);
        if i >= n || s[i] != '}' as u32 {
            loop {
                if i >= n || s[i] != '"' as u32 {
                    return Err(Error::At(i)); // Expecting property name enclosed in double quotes
                }
                let key_at = i;
                let (key, k2) = self.string(i + 1)?;
                i = self.skip(k2);
                if i >= n || s[i] != ':' as u32 {
                    return Err(Error::At(i)); // Expecting ':' delimiter
                }
                i = self.skip(i + 1);
                let (v, v2) = self.value(i)?;
                if matches!(self.locate, Some(l) if l == key.as_slice()) {
                    found = Some(key_at);
                }
                d.insert_str(key, v);
                i = self.skip(v2);
                if i < n && s[i] == '}' as u32 {
                    break;
                }
                if i >= n || s[i] != ',' as u32 {
                    return Err(Error::At(i)); // Expecting ',' delimiter
                }
                let comma = i;
                i = self.skip(i + 1);
                if i < n && s[i] == '}' as u32 {
                    return Err(Error::At(comma)); // Illegal trailing comma before end of object
                }
            }
        }
        Ok((PyVal::Dict(d.items, found), i + 1))
    }

    fn array(&mut self, i: usize) -> Result<(PyVal, usize), Error> {
        let s = self.s;
        let n = s.len();
        let mut out = Vec::new();
        let mut i = self.skip(i);
        if i >= n || s[i] != ']' as u32 {
            loop {
                let (v, v2) = self.value(i)?;
                out.push(v);
                i = self.skip(v2);
                if i < n && s[i] == ']' as u32 {
                    break;
                }
                if i >= n || s[i] != ',' as u32 {
                    return Err(Error::At(i));
                }
                let comma = i;
                i = self.skip(i + 1);
                if i < n && s[i] == ']' as u32 {
                    return Err(Error::At(comma)); // Illegal trailing comma before end of array
                }
            }
        }
        Ok((PyVal::List(out), i + 1))
    }
}

/// json.loads(text) (core's parse_int); `locate`: a key whose position each object that holds it records (the
/// last of equal ones), in its `Dict`'s `at`.
pub fn loads(text: &[u32], locate: Option<&[u32]>) -> Result<PyVal, Error> {
    let mut p = Parser { s: text, depth: 0, locate };
    let start = p.skip(0);
    let (v, end) = p.value(start)?;
    let e = p.skip(end);
    if e != text.len() {
        return Err(Error::At(e)); // Extra data
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> PyStr {
        pystr::u(s)
    }

    fn err(s: &str) -> String {
        match loads(&u(s), None) {
            Err(Error::At(p)) => error_where(&u(s), p),
            other => format!("{:?}", other),
        }
    }

    #[test]
    fn values_and_errors() {
        assert_eq!(
            loads(&u(" [1, -0, 1.5, \"a\\u00e9\", null] "), None).unwrap(),
            PyVal::List(vec![PyVal::Int(u("1")), PyVal::Int(u("0")), PyVal::Float(1.5), PyVal::Str(u("a\u{e9}")), PyVal::None])
        );
        assert!(matches!(loads(&u("NaN"), None).unwrap(), PyVal::Float(f) if f.is_nan()));
        assert_eq!(err("{\"a\": 1,}"), "line 1 column 8");
        assert_eq!(err("[1, ]"), "line 1 column 3");
        assert_eq!(err("{\"a\" 1}"), "line 1 column 6");
        assert_eq!(err("\n\"ab"), "line 2 column 1");
        assert_eq!(err("\"\\q\""), "line 1 column 2");
        assert_eq!(err("[1] x"), "line 1 column 5");
        assert_eq!(err("-"), "line 1 column 1");
        assert_eq!(err("\u{feff}{}"), "line 1 column 1");
        assert_eq!(err("\"\\ude00"), "line 1 column 1"); // (CPython 3.13: the escape whole, then unterminated)
        assert_eq!(err("\"\\ud83d\\ude0"), "line 1 column 9");
        assert_eq!(err("\"\\u12"), "line 1 column 3");
        match loads(&u("{\"a\": 1, \"b\": 2, \"a\": 3}"), Some(&u("a"))).unwrap() {
            PyVal::Dict(items, at) => {
                assert_eq!(items, vec![(PyVal::Str(u("a")), PyVal::Int(u("3"))), (PyVal::Str(u("b")), PyVal::Int(u("2")))]);
                assert_eq!(at, Some(17));
            }
            v => panic!("{:?}", v),
        }
        assert_eq!(loads(&u("\"\\ud83d\\ude00\\ud800\""), None).unwrap(), PyVal::Str(vec![0x1F600, 0xD800]));
        assert_eq!(loads(&u(&"1".repeat(1001)), None).unwrap(), PyVal::Float(f64::INFINITY));
        assert!(depth_exceeds(&u(&"[".repeat(501)), 500));
        assert!(!depth_exceeds(&u(&format!("\"{}\"", "[".repeat(501))), 500));
    }
}
