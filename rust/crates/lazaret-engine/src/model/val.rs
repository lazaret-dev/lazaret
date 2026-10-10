//! A reader's values: the text code builds, the data it holds and the handles it opens (0.1.9).
//!
//! A value is what a reader (Rust's `rsread`, Go's `goread`) knows of an expression: its text where the code
//! builds one (a piece it cannot know is [`UNKNOWN`], as the shell reader marks one), the items of a list,
//! the kinds of data it carries (the supply-chain models' kinds: the environment, a file, a response, a
//! decoding…) with where each was first read, and the handle it is (a command, a request, a connection, a
//! file open for writing). Also here: the decodings code uses to hide a string (base64, hex) and bytes read
//! as text. Each language's literals and formatting are its reader's (`rsread::lit`, `goread::lit`).

use crate::jsflow::supply::{K_DECODED, KIND_NAMES};
use crate::pystr::PyStr;
use std::rc::Rc;

/// A piece of text the reader does not know (the shell reader's mark for one).
pub const UNKNOWN: u32 = 2;
/// The longest text a value keeps (longer is cut, its end unknown).
pub const MAX_TEXT: usize = 1 << 16;
/// The most items a list keeps.
pub const MAX_ITEMS: usize = 4096;

/// What a value is, when it is a handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Obj {
    #[default]
    None,
    /// `std::process::Command` (an index into the model's commands).
    Cmd(u32),
    /// An HTTP request being built (an index into the model's requests).
    Req(u32),
    /// An HTTP response: what it holds was received.
    Resp,
    /// A connection (`TcpStream`, a UDP socket connected): an index into the model's connections.
    Conn(u32),
    /// A file open for writing: an index into the model's written paths.
    WFile(u32),
    /// A command's `Output`.
    Output(u32),
    /// A closure: an index into the model's closures.
    Closure(u32),
    /// An HTTP client or agent.
    Client,
    /// A DNS resolver.
    Resolver,
    /// A curl handle (the `curl` crate's `Easy`): an index into the model's requests.
    Curl(u32),
    /// The list of the environment's variables (`env::vars()`).
    EnvVars,
    /// Go: the values a call of several results gives, its items in order (`data, err := f()`).
    Tuple,
    /// Go: a map, or a struct literal with its fields named: its items are [key, value] pairs.
    Map,
    /// Go: a base64 encoding (`base64.StdEncoding`); its text, when it has one, is a custom alphabet.
    B64,
    /// Go: the user `os/user` gives (its `Username`, its `HomeDir`).
    User,
    /// Go: a `SysProcAttr` that hides the process's window or detaches it.
    Hidden,
}

/// A value.
#[derive(Clone, Debug, Default)]
pub struct Val {
    /// The text it holds, where the code builds one ([`UNKNOWN`] for a piece not known).
    pub s: Option<Rc<PyStr>>,
    /// The items of a list.
    pub items: Option<Rc<Vec<Val>>>,
    /// An integer's value.
    pub int: Option<i128>,
    /// The kinds of data it holds (`jsflow::supply`'s K_*).
    pub kinds: u16,
    /// For each kind it holds, the first source: (the kind's bit index, what was read, where).
    pub firsts: Rc<Vec<(u8, Rc<PyStr>, u32)>>,
    pub obj: Obj,
    /// The value's origin, for a path not known as text: two uses of one variable have one.
    pub id: u32,
}

impl Val {
    pub fn unknown() -> Val {
        Val::default()
    }

    pub fn text(s: PyStr) -> Val {
        let mut s = s;
        if s.len() > MAX_TEXT {
            s.truncate(MAX_TEXT);
            s.push(UNKNOWN);
        }
        Val { s: Some(Rc::new(s)), ..Val::default() }
    }

    pub fn int(n: i128) -> Val {
        Val { int: Some(n), ..Val::default() }
    }

    pub fn obj(o: Obj) -> Val {
        Val { obj: o, ..Val::default() }
    }

    pub fn list(items: Vec<Val>) -> Val {
        let mut items = items;
        items.truncate(MAX_ITEMS);
        let mut v = Val { items: Some(Rc::new(items)), ..Val::default() };
        let items = v.items.clone().unwrap_or_default();
        for it in items.iter() {
            v.add_kinds(it);
        }
        v
    }

    /// Data read from the machine or received: `bit` with `what`, at `at`.
    pub fn source(bit: u16, what: PyStr, at: u32) -> Val {
        let idx = bit.trailing_zeros() as u8;
        Val { kinds: bit, firsts: Rc::new(vec![(idx, Rc::new(what), at)]), ..Val::default() }
    }

    /// The text, or one unknown piece.
    pub fn text_or_unknown(&self) -> PyStr {
        match &self.s {
            Some(s) => (**s).clone(),
            None => match &self.int {
                Some(n) => n.to_string().chars().map(|c| c as u32).collect(),
                None => vec![UNKNOWN],
            },
        }
    }

    /// Is the whole text known?
    pub fn known(&self) -> bool {
        self.s.as_ref().is_some_and(|s| !s.contains(&UNKNOWN))
    }

    /// The kinds and sources of `other`, added.
    pub fn add_kinds(&mut self, other: &Val) {
        if other.kinds == 0 {
            return;
        }
        let new = other.kinds & !self.kinds;
        self.kinds |= other.kinds;
        if new != 0 {
            let mut firsts = (*self.firsts).clone();
            for f in other.firsts.iter() {
                if new & (1 << f.0) != 0 && !firsts.iter().any(|g| g.0 == f.0) {
                    firsts.push(f.clone());
                }
            }
            self.firsts = Rc::new(firsts);
        }
    }

    pub fn with_kinds(mut self, other: &Val) -> Val {
        self.add_kinds(other);
        self
    }

    /// This value marked decoded (what it held kept), at `at`.
    pub fn decoded(mut self, at: u32) -> Val {
        let d = Val::source(K_DECODED, crate::pystr::u("decoded"), at);
        self.add_kinds(&d);
        self
    }

    /// The first source of a kind: (what, where).
    pub fn first(&self, bit: u16) -> Option<(Rc<PyStr>, u32)> {
        let idx = bit.trailing_zeros() as u8;
        self.firsts.iter().find(|f| f.0 == idx).map(|f| (f.1.clone(), f.2))
    }

    /// The one of two values a branch gives: the first's text where it has one, both's kinds.
    pub fn union(&self, other: &Val) -> Val {
        let mut v = if self.s.is_some() || self.items.is_some() || self.obj != Obj::None || self.int.is_some() {
            self.clone()
        } else {
            let mut o = other.clone();
            o.kinds = 0;
            o.firsts = Rc::new(Vec::new());
            o.add_kinds(self);
            o
        };
        v.add_kinds(other);
        if v.obj == Obj::None {
            v.obj = other.obj;
        }
        v
    }

    /// `a` followed by `b`: a text when either has one, the kinds of both.
    pub fn concat(a: &Val, b: &Val) -> Val {
        let mut s = a.text_or_unknown();
        s.extend(b.text_or_unknown());
        let mut v = Val::text(collapse(s));
        v.add_kinds(a);
        v.add_kinds(b);
        v
    }

    /// A kind's name as the text follower writes it (`environment`, `file`, …).
    pub fn kind_name(bit: u16) -> &'static str {
        KIND_NAMES[(bit.trailing_zeros() as usize).min(KIND_NAMES.len() - 1)]
    }
}

/// Runs of unknown pieces read as one.
pub fn collapse(s: PyStr) -> PyStr {
    if !s.windows(2).any(|w| w[0] == UNKNOWN && w[1] == UNKNOWN) {
        return s;
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s {
        if c == UNKNOWN && out.last() == Some(&UNKNOWN) {
            continue;
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------- decodings --

fn hex_val(c: u32) -> Option<u32> {
    char::from_u32(c).and_then(|c| c.to_digit(16))
}

fn b64_val(c: u32, url: bool) -> Option<u32> {
    let ch = char::from_u32(c)?;
    Some(match ch {
        'A'..='Z' => ch as u32 - 'A' as u32,
        'a'..='z' => ch as u32 - 'a' as u32 + 26,
        '0'..='9' => ch as u32 - '0' as u32 + 52,
        '+' if !url => 62,
        '/' if !url => 63,
        '-' if url => 62,
        '_' if url => 63,
        _ => return None,
    })
}

/// Base64's bytes of a text (standard or URL-safe, padded or not, white space ignored), or None.
pub fn base64(s: &[u32]) -> Option<PyStr> {
    let body: Vec<u32> = s.iter().copied().filter(|&c| !matches!(char::from_u32(c), Some(' ' | '\n' | '\r' | '\t'))).collect();
    let trimmed: &[u32] = {
        let mut e = body.len();
        while e > 0 && body[e - 1] == '=' as u32 {
            e -= 1;
        }
        &body[..e]
    };
    if trimmed.is_empty() || trimmed.len() % 4 == 1 {
        return None;
    }
    let url = trimmed.iter().any(|&c| c == '-' as u32 || c == '_' as u32);
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in trimmed {
        let v = b64_val(c, url)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) & 0xFF);
        }
    }
    Some(out)
}

/// Hex's bytes of a text, or None.
pub fn hex(s: &[u32]) -> Option<PyStr> {
    if s.len() % 2 != 0 || s.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        out.push(hex_val(pair[0])? * 16 + hex_val(pair[1])?);
    }
    Some(out)
}

/// Bytes read as UTF-8 text (as `String::from_utf8_lossy` reads them), or the bytes as they are when they
/// are not UTF-8 (each byte its own code point).
pub fn utf8(bytes: &[u32]) -> PyStr {
    if bytes.iter().any(|&b| b > 0xFF) {
        return bytes.to_vec();
    }
    let raw: Vec<u8> = bytes.iter().map(|&b| b as u8).collect();
    match std::str::from_utf8(&raw) {
        Ok(s) => s.chars().map(|c| c as u32).collect(),
        Err(_) => bytes.to_vec(),
    }
}

/// The text's UTF-8 bytes, each a code point (`s.as_bytes()`, `b"…"`'s view).
pub fn bytes_of(s: &[u32]) -> PyStr {
    let text: String = s.iter().filter_map(|&c| char::from_u32(c)).collect();
    if s.iter().all(|&c| c < 0x80) {
        return s.to_vec();
    }
    text.bytes().map(|b| b as u32).collect()
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
    fn decodings() {
        assert_eq!(base64(&u("aGVsbG8=")).map(|b| st(&b)), Some("hello".into()));
        assert_eq!(base64(&u("aGVsbG8")).map(|b| st(&b)), Some("hello".into()));
        assert_eq!(base64(&u("aGV sbG8=")).map(|b| st(&b)), Some("hello".into()));
        assert_eq!(base64(&u("@@@@")), None);
        assert_eq!(hex(&u("6869")).map(|b| st(&b)), Some("hi".into()));
        assert_eq!(st(&utf8(&[0xc3, 0xa9])), "é");
        assert_eq!(bytes_of(&u("é")), vec![0xc3, 0xa9]);
    }
}
