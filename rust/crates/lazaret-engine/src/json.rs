//! A small JSON reader and writer (RFC 8259), for the rule pack and the
//! bindings' messages.
//!
//! Strings are Python strs: `\uXXXX` escapes decode to code points, a valid
//! surrogate pair to the character it encodes and a lone surrogate to itself
//! (as Python's json does). Written JSON is ASCII (`ensure_ascii`): every
//! other code point is a `\u` escape, which JSON.parse and json.loads read
//! back to the same str. Depth is bounded, and nothing here panics.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u32>),
    Arr(Vec<Value>),
    Obj(Vec<(Vec<u32>, Value)>),
}

pub const MAX_DEPTH: usize = 500;

#[derive(Debug, Clone)]
pub struct Error(pub String);

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(items) => {
                let k: Vec<u32> = key.chars().map(|c| c as u32).collect();
                items.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
            }
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&[u32]> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_string(&self) -> Option<String> {
        self.as_str().map(crate::pystr::to_string)
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&[(Vec<u32>, Value)]> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn str(s: &str) -> Value {
        Value::Str(s.chars().map(|c| c as u32).collect())
    }
    pub fn obj(items: Vec<(&str, Value)>) -> Value {
        Value::Obj(items.into_iter().map(|(k, v)| (k.chars().map(|c| c as u32).collect(), v)).collect())
    }
}

/// Parse JSON text given as code points.
pub fn parse(text: &[u32]) -> Result<Value, Error> {
    let mut p = Parser { s: text, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(Error(format!("extra data at {}", p.i)));
    }
    Ok(v)
}

/// Parse JSON text given as a Rust string.
pub fn parse_str(text: &str) -> Result<Value, Error> {
    let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
    parse(&cps)
}

struct Parser<'a> {
    s: &'a [u32],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], 0x20 | 0x09 | 0x0A | 0x0D) {
            self.i += 1;
        }
    }
    fn err<T>(&self, msg: &str) -> Result<T, Error> {
        Err(Error(format!("{} at {}", msg, self.i)))
    }
    fn peek(&self) -> Option<u32> {
        self.s.get(self.i).copied()
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value, Error> {
        for c in word.chars() {
            if self.peek() != Some(c as u32) {
                return self.err("bad literal");
            }
            self.i += 1;
        }
        Ok(v)
    }
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return self.err("too deep");
        }
        match self.peek() {
            None => self.err("unexpected end"),
            Some(0x7B) => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(0x7D) {
                    self.i += 1;
                    return Ok(Value::Obj(items));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(0x22) {
                        return self.err("expected a key");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.peek() != Some(0x3A) {
                        return self.err("expected ':'");
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    items.push((k, v));
                    self.ws();
                    match self.peek() {
                        Some(0x2C) => self.i += 1,
                        Some(0x7D) => {
                            self.i += 1;
                            return Ok(Value::Obj(items));
                        }
                        _ => return self.err("expected ',' or '}'"),
                    }
                }
            }
            Some(0x5B) => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(0x5D) {
                    self.i += 1;
                    return Ok(Value::Arr(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(0x2C) => self.i += 1,
                        Some(0x5D) => {
                            self.i += 1;
                            return Ok(Value::Arr(items));
                        }
                        _ => return self.err("expected ',' or ']'"),
                    }
                }
            }
            Some(0x22) => Ok(Value::Str(self.string()?)),
            Some(0x74) => self.lit("true", Value::Bool(true)),
            Some(0x66) => self.lit("false", Value::Bool(false)),
            Some(0x6E) => self.lit("null", Value::Null),
            Some(c) if c == 0x2D || (0x30..=0x39).contains(&c) => self.number(),
            _ => self.err("unexpected character"),
        }
    }
    fn hex4(&mut self) -> Result<u32, Error> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = match self.peek() {
                Some(c) => c,
                None => return self.err("bad \\u escape"),
            };
            let d = match c {
                0x30..=0x39 => c - 0x30,
                0x61..=0x66 => c - 0x61 + 10,
                0x41..=0x46 => c - 0x41 + 10,
                _ => return self.err("bad \\u escape"),
            };
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }
    fn string(&mut self) -> Result<Vec<u32>, Error> {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let c = match self.peek() {
                None => return self.err("unterminated string"),
                Some(c) => c,
            };
            self.i += 1;
            match c {
                0x22 => return Ok(out),
                0x5C => {
                    let e = match self.peek() {
                        None => return self.err("unterminated escape"),
                        Some(e) => e,
                    };
                    self.i += 1;
                    match e {
                        0x22 => out.push(0x22),
                        0x5C => out.push(0x5C),
                        0x2F => out.push(0x2F),
                        0x62 => out.push(0x08),
                        0x66 => out.push(0x0C),
                        0x6E => out.push(0x0A),
                        0x72 => out.push(0x0D),
                        0x74 => out.push(0x09),
                        0x75 => {
                            let mut v = self.hex4()?;
                            // a high surrogate followed by an escaped low one: the pair
                            if (0xD800..0xDC00).contains(&v)
                                && self.peek() == Some(0x5C)
                                && self.s.get(self.i + 1) == Some(&0x75)
                            {
                                let save = self.i;
                                self.i += 2;
                                match self.hex4() {
                                    Ok(lo) if (0xDC00..0xE000).contains(&lo) => {
                                        v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
                                    }
                                    _ => self.i = save,
                                }
                            }
                            out.push(v);
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                c if c < 0x20 => return self.err("control character in string"),
                c => out.push(c),
            }
        }
    }
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.i;
        let mut float = false;
        if self.peek() == Some(0x2D) {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            match c {
                0x30..=0x39 => self.i += 1,
                0x2E | 0x65 | 0x45 | 0x2B | 0x2D => {
                    float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let text: String = self.s[start..self.i].iter().filter_map(|&c| char::from_u32(c)).collect();
        if !float {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(Value::Int(i));
            }
        }
        match text.parse::<f64>() {
            Ok(f) => Ok(Value::Float(f)),
            Err(_) => self.err("bad number"),
        }
    }
}

/// Write a str as a JSON string literal (ASCII, \u escapes).
pub fn write_str(out: &mut String, s: &[u32]) {
    out.push('"');
    for &c in s {
        match c {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x0A => out.push_str("\\n"),
            0x0D => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            0x20..=0x7E => out.push(c as u8 as char),
            c if c < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", c);
            }
            c => {
                let v = c - 0x10000;
                let _ = write!(out, "\\u{:04x}\\u{:04x}", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
            }
        }
    }
    out.push('"');
}

/// Serialize a value (compact).
pub fn write(v: &Value) -> String {
    let mut out = String::new();
    write_into(&mut out, v);
    out
}

pub fn write_into(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            let _ = write!(out, "{}", i);
        }
        Value::Float(f) => {
            if f.is_finite() {
                let _ = write!(out, "{:?}", f);
            } else {
                out.push_str("null");
            }
        }
        Value::Str(s) => write_str(out, s),
        Value::Arr(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_into(out, x);
            }
            out.push(']');
        }
        Value::Obj(items) => {
            out.push('{');
            for (i, (k, x)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_into(out, x);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let v = parse_str(r#"{"a": [1, -2.5, "x😀\ud800", true, null], "b": {}}"#).unwrap();
        let s = v.get("a").unwrap().as_arr().unwrap()[2].as_str().unwrap().to_vec();
        assert_eq!(s, vec![0x78, 0x1F600, 0xD800]);
        assert_eq!(parse_str(&write(&v)).unwrap(), v);
        assert!(parse_str("[1,]").is_err());
        assert!(parse_str(&"[".repeat(600)).is_err());
    }
}
