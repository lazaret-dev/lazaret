//! String arrays and proxy objects in the decoded view (0.1.8): the Rust
//! twin of lazaret.scanner.core's `_dv_string_arrays` and `_dv_proxies`
//! (core's comments above `_SA_MAX_CHARS` and `_PX_MAX_ENTRIES`). A
//! javascript-obfuscator string array is read without running anything —
//! its strings, the accessor's offset and decoding (none, its base64, RC4
//! over that base64), and the rotation for which the checksum loop's
//! JavaScript arithmetic gives its target — and each call of the accessor,
//! an alias or a wrapper with constant arguments reads as its string; the
//! objects of proxy functions control-flow flattening leaves are read as
//! the calls, operations and strings they stand for.

use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::rxutil;
use std::collections::{HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn cat(parts: &[&[u32]]) -> PyStr {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// What the reader cannot read (core._SaStop): nothing is decoded there.
struct Stop;

type R<T> = Result<T, Stop>;

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Num(f64),
    Str(PyStr),
}

#[derive(Clone, Debug)]
enum Tree {
    Num(f64),
    Str(PyStr),
    Var(PyStr),
    Neg(Box<Tree>),
    Pos(Box<Tree>),
    Bin(u32, Box<Tree>, Box<Tree>), // '+' '-' '*' '/'
    Call(PyStr, Vec<Tree>),
    Pi(PyStr, Vec<Tree>),
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    N(f64),
    S(PyStr),
    I(PyStr),
    O(u32),
}

fn is_hex(ch: u32) -> bool {
    (c('0')..=c('9')).contains(&ch) || (c('a')..=c('f')).contains(&ch) || (c('A')..=c('F')).contains(&ch)
}

fn hex_value(s: &[u32]) -> u64 {
    s.iter().fold(0u64, |acc, &ch| {
        let d = if ch <= c('9') { ch - c('0') } else { (ch | 0x20) - c('a') + 10 };
        acc.wrapping_mul(16).wrapping_add(d as u64)
    })
}

fn radix_value(s: &[u32], radix: u64) -> u64 {
    s.iter().fold(0u64, |acc, &ch| {
        let d = if ch <= c('9') { ch - c('0') } else { (ch | 0x20) - c('a') + 10 };
        acc.wrapping_mul(radix).wrapping_add(d as u64)
    })
}

/// JavaScript's white space and line terminators (what parseInt and Number skip).
fn js_space(ch: u32) -> bool {
    matches!(ch, 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0xA0 | 0x1680 | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000 | 0xFEFF)
        || (0x2000..=0x200A).contains(&ch)
}

/// core._sa_string: the value of a JavaScript string literal's body, else None.
fn sa_string(p: &Pack, body: &[u32]) -> Option<PyStr> {
    if !body.contains(&c('\\')) {
        return Some(body.to_vec());
    }
    let mut out: PyStr = Vec::with_capacity(body.len());
    let (mut i, n) = (0usize, body.len());
    while i < n {
        let ch = body[i];
        if ch != c('\\') {
            out.push(ch);
            i += 1;
            continue;
        }
        if i + 1 >= n {
            return None;
        }
        let e = body[i + 1];
        if e == c('x') {
            let h = pystr::sub(body, i + 2, i + 4);
            if h.len() != 2 || !h.iter().all(|&x| is_hex(x)) {
                return None;
            }
            out.push(hex_value(h) as u32);
            i += 4;
        } else if e == c('u') {
            if body.get(i + 2) == Some(&c('{')) {
                let k = pystr::find_char(body, c('}'), i + 3);
                let h: &[u32] = match k {
                    Some(k) if k > 0 => &body[i + 3..k],
                    _ => &[],
                };
                if h.is_empty() || h.len() > 6 || !h.iter().all(|&x| is_hex(x)) || hex_value(h) > 0x10FFFF {
                    return None;
                }
                out.push(hex_value(h) as u32);
                i = k.unwrap_or(n) + 1;
            } else {
                let h = pystr::sub(body, i + 2, i + 6);
                if h.len() != 4 || !h.iter().all(|&x| is_hex(x)) {
                    return None;
                }
                out.push(hex_value(h) as u32);
                i += 6;
            }
        } else if let Some(v) = match e {
            0x6E => Some(0x0A), // n
            0x72 => Some(0x0D), // r
            0x74 => Some(0x09), // t
            0x62 => Some(0x08), // b
            0x66 => Some(0x0C), // f
            0x76 => Some(0x0B), // v
            _ => None,
        } {
            out.push(v);
            i += 2;
        } else if (c('0')..=c('7')).contains(&e) {
            let m = p.re("_SA_OCT_RE").match_at(body, (i + 1) as isize, body.len() as isize)?;
            out.push(radix_value(m.group0(), 8) as u32);
            i = m.end();
        } else {
            out.push(e);
            i += 2;
        }
    }
    Some(out)
}

/// core._sa_strings: (values, end) of the string literals of the array
/// literal whose '[' ends at text[i]; None when an item is not one.
fn sa_strings(p: &Pack, text: &[u32], mut i: usize) -> Option<(Vec<PyStr>, usize)> {
    let space = p.re("_SA_SPACE_RE");
    let lit = p.re("_SA_LIT_RE");
    let max = p.usize("_SA_MAX_ITEMS");
    let n = text.len();
    let mut items: Vec<PyStr> = Vec::new();
    loop {
        i = space.match_at(text, i as isize, text.len() as isize).map(|m| m.end()).unwrap_or(i);
        if i >= n {
            return None;
        }
        if text[i] == c(']') && items.is_empty() {
            return Some((items, i + 1));
        }
        let m = lit.match_at(text, i as isize, text.len() as isize)?;
        if items.len() >= max {
            return None;
        }
        let g = m.group0();
        items.push(sa_string(p, &g[1..g.len() - 1])?);
        i = m.end();
        i = space.match_at(text, i as isize, text.len() as isize).map(|m| m.end()).unwrap_or(i);
        if i < n && text[i] == c(',') {
            i += 1;
            continue;
        }
        if i < n && text[i] == c(']') {
            return Some((items, i + 1));
        }
        return None;
    }
}

/// Rust's reading of a decimal literal as a double (correctly rounded, as
/// Python's float() and JavaScript's Number()).
fn parse_decimal(s: &[u32]) -> f64 {
    pystr::to_string(s).parse::<f64>().unwrap_or(f64::NAN)
}

/// core._sa_number: a number literal's value.
fn sa_number(p: &Pack, s: &[u32]) -> f64 {
    if pystr::starts_with(s, "0x") || pystr::starts_with(s, "0X") {
        return if s.len() - 2 <= p.usize("_SA_HEX_MAX") { hex_value(&s[2..]) as f64 } else { f64::NAN };
    }
    parse_decimal(s)
}

/// core._sa_to_number: JavaScript's ToNumber of a number or a string.
fn sa_to_number(p: &Pack, v: &Val) -> f64 {
    let s = match v {
        Val::Num(x) => return *x,
        Val::Str(s) => s,
    };
    let (mut i, mut j) = (0usize, s.len());
    while i < j && js_space(s[i]) {
        i += 1;
    }
    while j > i && js_space(s[j - 1]) {
        j -= 1;
    }
    let s = &s[i..j];
    if s.is_empty() {
        return 0.0;
    }
    if s.len() > 2 && s[0] == c('0') {
        let radix = match s[1] | 0x20 {
            0x78 => Some(16u64), // x
            0x62 => Some(2),     // b
            0x6F => Some(8),     // o
            _ => None,
        };
        if let Some(radix) = radix {
            let body = &s[2..];
            let ok = body.iter().all(|&ch| match radix {
                16 => is_hex(ch),
                2 => ch == c('0') || ch == c('1'),
                _ => (c('0')..=c('7')).contains(&ch),
            });
            if !ok || body.len() > p.usize("_SA_HEX_MAX") {
                return f64::NAN;
            }
            return radix_value(body, radix) as f64;
        }
    }
    if pystr::eq(s, "Infinity") || pystr::eq(s, "+Infinity") {
        return f64::INFINITY;
    }
    if pystr::eq(s, "-Infinity") {
        return f64::NEG_INFINITY;
    }
    if pystr::is_ascii(s) && p.re("_SA_DECIMAL_RE").fullmatch(s).is_some() {
        return parse_decimal(s);
    }
    f64::NAN
}

/// core._sa_to_string: ToString of a string, or of an integer under 1e21.
fn sa_to_string(v: &Val) -> R<PyStr> {
    match v {
        Val::Str(s) => Ok(s.clone()),
        Val::Num(x) => {
            let x = *x;
            if x == x && x.abs() < 1e21 && x == x.trunc() {
                if x == 0.0 {
                    return Ok(u("0"));
                }
                Ok(u(&format!("{:.0}", x)))
            } else {
                Err(Stop)
            }
        }
    }
}

/// core._sa_parse_int: parseInt(v) (radix 10, or 16 after 0x), as core reads it.
fn sa_parse_int(p: &Pack, v: Option<&[u32]>) -> f64 {
    let v = match v {
        Some(v) => v,
        None => return f64::NAN,
    };
    let n = v.len();
    let mut i = 0usize;
    while i < n && js_space(v[i]) {
        i += 1;
    }
    let mut sign = 1.0f64;
    if i < n && (v[i] == c('+') || v[i] == c('-')) {
        sign = if v[i] == c('-') { -1.0 } else { 1.0 };
        i += 1;
    }
    let mut radix = 10u64;
    if i + 1 < n && v[i] == c('0') && (v[i + 1] == c('x') || v[i + 1] == c('X')) {
        radix = 16;
        i += 2;
    }
    let mut j = i;
    while j < n && ((c('0')..=c('9')).contains(&v[j]) || (radix == 16 && is_hex(v[j]))) {
        j += 1;
    }
    let most = if radix == 16 { p.usize("_SA_HEX_MAX") } else { p.usize("_SA_DEC_MAX") };
    if j == i || j - i > most {
        return f64::NAN;
    }
    sign * radix_value(&v[i..j], radix) as f64
}

/// core._sa_tokens: an expression's tokens.
fn sa_tokens(p: &Pack, src: &[u32]) -> R<Vec<Tok>> {
    let tok = p.re("_SA_TOKEN_RE");
    let mut out = Vec::new();
    let (mut i, n) = (0usize, src.len());
    while i < n {
        let m = match tok.match_at(src, i as isize, src.len() as isize) {
            Some(m) if m.end() > i => m,
            _ => {
                if pystr::strip(&src[i..]).is_empty() {
                    break;
                }
                return Err(Stop);
            }
        };
        if let Some(num) = m.name("num") {
            out.push(Tok::N(sa_number(p, num)));
        } else if let Some(s) = m.name("str") {
            out.push(Tok::S(sa_string(p, &s[1..s.len() - 1]).ok_or(Stop)?));
        } else if let Some(name) = m.name("name") {
            out.push(Tok::I(name.to_vec()));
        } else {
            out.push(Tok::O(m.name("op").map(|o| o[0]).unwrap_or(0)));
        }
        i = m.end();
    }
    Ok(out)
}

type Consts = HashMap<PyStr, HashMap<PyStr, Tree>>;

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    consts: &'a Consts,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.pos)
    }

    fn is_op(&self, op: char) -> bool {
        matches!(self.peek(), Some(Tok::O(o)) if *o == c(op))
    }

    fn take(&mut self) -> R<&'a Tok> {
        let t = self.toks.get(self.pos).ok_or(Stop)?;
        self.pos += 1;
        Ok(t)
    }

    fn take_op(&mut self, op: char) -> R<()> {
        match self.take()? {
            Tok::O(o) if *o == c(op) => Ok(()),
            _ => Err(Stop),
        }
    }

    fn constant(&self, name: &[u32], key: &[u32]) -> R<Tree> {
        self.consts.get(name).and_then(|t| t.get(key)).cloned().ok_or(Stop)
    }

    fn primary(&mut self) -> R<Tree> {
        let t = self.take()?;
        match t {
            Tok::N(v) => return Ok(Tree::Num(*v)),
            Tok::S(s) => return Ok(Tree::Str(s.clone())),
            Tok::O(o) if *o == c('(') => {
                let v = self.additive()?;
                self.take_op(')')?;
                return Ok(v);
            }
            Tok::O(_) => return Err(Stop),
            Tok::I(_) => {}
        }
        let name = match t {
            Tok::I(name) => name.clone(),
            _ => return Err(Stop),
        };
        if self.is_op('.') {
            self.take()?;
            return match self.take()? {
                Tok::I(key) => self.constant(&name, key),
                _ => Err(Stop),
            };
        }
        if self.is_op('[') {
            self.take()?;
            let key = self.take()?.clone();
            self.take_op(']')?;
            return match key {
                Tok::S(key) => self.constant(&name, &key),
                _ => Err(Stop),
            };
        }
        if self.is_op('(') {
            self.take()?;
            let mut args = Vec::new();
            if !self.is_op(')') {
                loop {
                    args.push(self.additive()?);
                    if !self.is_op(',') {
                        break;
                    }
                    self.take()?;
                }
            }
            self.take_op(')')?;
            if pystr::eq(&name, "parseInt") {
                if args.len() != 1 {
                    return Err(Stop);
                }
                return match args.pop() {
                    Some(Tree::Call(n, a)) => Ok(Tree::Pi(n, a)),
                    _ => Err(Stop),
                };
            }
            return Ok(Tree::Call(name, args));
        }
        Ok(Tree::Var(name))
    }

    fn unary(&mut self) -> R<Tree> {
        if self.is_op('-') {
            self.take()?;
            return Ok(Tree::Neg(Box::new(self.unary()?)));
        }
        if self.is_op('+') {
            self.take()?;
            return Ok(Tree::Pos(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn mult(&mut self) -> R<Tree> {
        let mut v = self.unary()?;
        while self.is_op('*') || self.is_op('/') {
            let op = match self.take()? {
                Tok::O(o) => *o,
                _ => return Err(Stop),
            };
            v = Tree::Bin(op, Box::new(v), Box::new(self.unary()?));
        }
        Ok(v)
    }

    fn additive(&mut self) -> R<Tree> {
        let mut v = self.mult()?;
        while self.is_op('+') || self.is_op('-') {
            let op = match self.take()? {
                Tok::O(o) => *o,
                _ => return Err(Stop),
            };
            v = Tree::Bin(op, Box::new(v), Box::new(self.mult()?));
        }
        Ok(v)
    }
}

/// core._sa_parse: an expression's tree.
fn sa_parse(toks: &[Tok], consts: &Consts) -> R<Tree> {
    let mut ps = Parser { toks, pos: 0, consts };
    let out = ps.additive()?;
    if ps.pos != toks.len() {
        return Err(Stop);
    }
    Ok(out)
}

/// core._sa_parse(…, many=True): comma-separated expressions.
fn sa_parse_many(toks: &[Tok], consts: &Consts) -> R<Vec<Tree>> {
    let mut ps = Parser { toks, pos: 0, consts };
    let mut out = Vec::new();
    if !toks.is_empty() {
        loop {
            out.push(ps.additive()?);
            if !ps.is_op(',') {
                break;
            }
            ps.take()?;
        }
    }
    if ps.pos != toks.len() {
        return Err(Stop);
    }
    Ok(out)
}

/// core._sa_value without calls: a tree's JavaScript value.
fn sa_value(p: &Pack, tree: &Tree, env: &HashMap<PyStr, Val>) -> R<Val> {
    Ok(match tree {
        Tree::Num(v) => Val::Num(*v),
        Tree::Str(s) => Val::Str(s.clone()),
        Tree::Var(name) => env.get(name).cloned().ok_or(Stop)?,
        Tree::Neg(x) => Val::Num(-sa_to_number(p, &sa_value(p, x, env)?)),
        Tree::Pos(x) => Val::Num(sa_to_number(p, &sa_value(p, x, env)?)),
        Tree::Bin(op, a, b) => {
            let (a, b) = (sa_value(p, a, env)?, sa_value(p, b, env)?);
            if *op == c('+') {
                if matches!(a, Val::Str(_)) || matches!(b, Val::Str(_)) {
                    let mut s = sa_to_string(&a)?;
                    s.extend(sa_to_string(&b)?);
                    Val::Str(s)
                } else {
                    Val::Num(sa_to_number(p, &a) + sa_to_number(p, &b))
                }
            } else {
                let (x, y) = (sa_to_number(p, &a), sa_to_number(p, &b));
                Val::Num(if *op == c('-') {
                    x - y
                } else if *op == c('*') {
                    x * y
                } else {
                    x / y
                })
            }
        }
        Tree::Call(..) | Tree::Pi(..) => return Err(Stop),
    })
}

/// core._sa_atob: the accessor's base64 over its alphabet, read as UTF-8;
/// None where that throws or holds a character past U+FFFF.
fn sa_atob(s: &[u32], alphabet: &[u32]) -> Option<PyStr> {
    let mut out: Vec<u8> = Vec::new();
    let (mut bc, mut bs) = (0i64, 0i64);
    for &ch in s {
        let v = match alphabet.iter().position(|&a| a == ch) {
            Some(v) => v as i64,
            None => continue,
        };
        bs = if bc % 4 != 0 { bs * 64 + v } else { v };
        bc += 1;
        if (bc - 1) % 4 != 0 {
            out.push((255 & (bs >> ((-2 * bc) & 6))) as u8);
        }
    }
    let text = std::str::from_utf8(&out).ok()?;
    let cps: PyStr = text.chars().map(|ch| ch as u32).collect();
    if cps.iter().any(|&x| x > 0xFFFF) {
        return None;
    }
    Some(cps)
}

/// core._sa_rc4: the accessor's RC4 with `key` over its base64, else None.
fn sa_rc4(s: &[u32], key: Option<&Val>, alphabet: &[u32]) -> Option<PyStr> {
    let data = sa_atob(s, alphabet)?;
    let key = match key {
        Some(Val::Str(k)) if !k.is_empty() && !k.iter().any(|&x| (0xD800..=0xDFFF).contains(&x) || x > 0xFFFF) => k,
        _ => return None,
    };
    let mut bx: Vec<u32> = (0..256).collect();
    let mut j = 0usize;
    for i in 0..256usize {
        j = (j + bx[i] as usize + key[i % key.len()] as usize) % 256;
        bx.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out: PyStr = Vec::with_capacity(data.len());
    for &ch in &data {
        i = (i + 1) % 256;
        j = (j + bx[i] as usize) % 256;
        bx.swap(i, j);
        out.push(ch ^ bx[(bx[i] as usize + bx[j] as usize) % 256]);
    }
    if out.iter().any(|&x| (0xD800..=0xDFFF).contains(&x)) {
        return None;
    }
    Some(out)
}

/// core._sa_consts: the objects of number and string constants text assigns.
fn sa_consts(p: &Pack, text: &[u32]) -> Consts {
    let entry = p.re("_SA_ENTRY_RE");
    let mut out: HashMap<PyStr, Option<HashMap<PyStr, Tree>>> = HashMap::new();
    for m in p.re("_SA_OBJECT_RE").finditer(text) {
        let mut i = m.end();
        let mut table: Option<HashMap<PyStr, Tree>> = Some(HashMap::new());
        loop {
            let e = match entry.match_at(text, i as isize, text.len() as isize) {
                Some(e) => e,
                None => {
                    table = None;
                    break;
                }
            };
            let key = rxutil::or_groups(&e, &["k", "k2", "k3"]).unwrap_or(&[]).to_vec();
            let v = e.name("v").unwrap_or(&[]);
            let value = if v.first() == Some(&c('\'')) || v.first() == Some(&c('"')) {
                match sa_string(p, &v[1..v.len() - 1]) {
                    Some(s) => Tree::Str(s),
                    None => {
                        table = None;
                        break;
                    }
                }
            } else {
                let neg = v.first() == Some(&c('-'));
                let num = sa_number(p, pystr::strip(pystr::lstrip_chars(v, "-")));
                Tree::Num(if neg { -num } else { num })
            };
            if let Some(t) = table.as_mut() {
                t.insert(key, value);
            }
            i = e.end();
            if e.name("end").map(|x| x == [c('}')]).unwrap_or(false) {
                break;
            }
        }
        if let Some(t) = table {
            if !t.is_empty() {
                let name = m.group(1).unwrap_or(&[]).to_vec();
                if out.contains_key(&name) {
                    out.insert(name, None);
                } else {
                    out.insert(name, Some(t));
                }
            }
        }
    }
    out.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    Plain,
    Base64,
    Rc4,
}

/// core._SaAccessor: a string array's accessor.
struct Accessor {
    fn_name: PyStr,
    items: std::rc::Rc<Vec<PyStr>>,
    off: f64,
    alphabet: Option<PyStr>,
    kind: Kind,
    rot: usize,
    memo: HashMap<(usize, PyStr, Kind), Option<PyStr>>,
}

fn key_repr(key: Option<&Val>) -> PyStr {
    match key {
        None => vec![0],
        Some(Val::Str(s)) => {
            let mut v = vec![1];
            v.extend_from_slice(s);
            v
        }
        Some(Val::Num(x)) => {
            let b = x.to_bits();
            vec![2, (b >> 48) as u32 & 0xFFFF, (b >> 32) as u32 & 0xFFFF, (b >> 16) as u32 & 0xFFFF, b as u32 & 0xFFFF]
        }
    }
}

impl Accessor {
    fn read(&mut self, p: &Pack, idx: Option<&Val>, key: Option<&Val>, kind: Kind, rot: usize) -> Option<PyStr> {
        let idx = idx?;
        let n = self.items.len();
        let i = sa_to_number(p, idx) - self.off;
        if i != i || !(i >= 0.0 && i < n as f64) || i != i.trunc() {
            return None;
        }
        let k = (i as usize + rot) % n;
        let mk = (k, key_repr(key), kind);
        if let Some(got) = self.memo.get(&mk) {
            return got.clone();
        }
        let s = &self.items[k];
        let alphabet = self.alphabet.clone().unwrap_or_default();
        let got = match kind {
            Kind::Plain => Some(s.clone()),
            Kind::Base64 => sa_atob(s, &alphabet),
            Kind::Rc4 => sa_rc4(s, key, &alphabet),
        };
        self.memo.insert(mk, got.clone());
        got
    }
}

/// core._sa_quote: a single-quoted literal on one row.
fn sa_quote(s: &[u32]) -> PyStr {
    let mut out: PyStr = vec![c('\'')];
    for &ch in s {
        match ch {
            0x5C => out.extend(u("\\\\")),
            0x27 => out.extend(u("\\'")),
            0x0A => out.extend(u("\\n")),
            0x0D => out.extend(u("\\r")),
            0x2028 => out.extend(u("\\u2028")),
            0x2029 => out.extend(u("\\u2029")),
            _ => out.push(ch),
        }
    }
    out.push(c('\''));
    out
}

struct Wrapper {
    params: Vec<PyStr>,
    target: PyStr,
    args: Vec<Tree>,
}

struct Reader<'a> {
    p: &'a Pack,
    accessors: Vec<Accessor>,
    by_name: HashMap<PyStr, usize>,
    aliases: HashMap<PyStr, Vec<PyStr>>, // (a set: distinct names, in the order found)
    wrappers: HashMap<PyStr, Vec<Wrapper>>,
}

impl<'a> Reader<'a> {
    /// (accessor, index, key) a call of `name` with `args` reads.
    fn resolve(&self, name: &[u32], args: Vec<Val>, depth: usize) -> R<(usize, Option<Val>, Option<Val>)> {
        if depth > self.p.usize("_SA_DEPTH") {
            return Err(Stop);
        }
        if let Some(&k) = self.by_name.get(name) {
            let mut it = args.into_iter();
            return Ok((k, it.next(), it.next()));
        }
        let given = self.aliases.get(name).map(|v| v.len()).unwrap_or(0);
        let wraps = self.wrappers.get(name).map(|v| v.len()).unwrap_or(0);
        if given + wraps != 1 {
            return Err(Stop);
        }
        if given == 1 {
            let to = self.aliases[name][0].clone();
            return self.resolve(&to, args, depth + 1);
        }
        let w = &self.wrappers[name][0];
        if args.len() < w.params.len() {
            return Err(Stop);
        }
        let env: HashMap<PyStr, Val> = w.params.iter().cloned().zip(args).collect();
        let mut vals = Vec::with_capacity(w.args.len());
        for a in &w.args {
            vals.push(sa_value(self.p, a, &env)?);
        }
        self.resolve(&w.target, vals, depth + 1)
    }
}

/// The parseInt terms of a checksum tree, left to right.
fn collect_terms<'t>(t: &'t Tree, out: &mut Vec<&'t Tree>) -> R<()> {
    match t {
        Tree::Pi(..) => out.push(t),
        Tree::Neg(x) | Tree::Pos(x) => collect_terms(x, out)?,
        Tree::Bin(_, a, b) => {
            collect_terms(a, out)?;
            collect_terms(b, out)?;
        }
        Tree::Num(_) => {}
        _ => return Err(Stop),
    }
    Ok(())
}

/// A checksum tree's number with its terms' values (in collect_terms' order).
fn checksum(t: &Tree, vals: &[f64], k: &mut usize) -> f64 {
    match t {
        Tree::Num(v) => *v,
        Tree::Pi(..) => {
            let v = vals[*k];
            *k += 1;
            v
        }
        Tree::Neg(x) => -checksum(x, vals, k),
        Tree::Pos(x) => checksum(x, vals, k),
        Tree::Bin(op, a, b) => {
            let x = checksum(a, vals, k);
            let y = checksum(b, vals, k);
            if *op == c('+') {
                x + y
            } else if *op == c('-') {
                x - y
            } else if *op == c('*') {
                x * y
            } else {
                x / y
            }
        }
        _ => f64::NAN,
    }
}

fn value_of(p: &Pack, src: &[u32], consts: &Consts) -> R<Val> {
    sa_value(p, &sa_parse(&sa_tokens(p, src)?, consts)?, &HashMap::new())
}

/// core._dv_string_arrays: `text` with the calls that read a string array
/// read as their strings; None when it reads none.
pub fn dv_string_arrays(p: &Pack, text: &[u32]) -> Option<PyStr> {
    sa_read(p, text).map(|(view, _)| view)
}

/// core._sa_read: (dv_string_arrays' reading of `text`, the offset of the
/// first string array whose calls it read); None when it reads none.
pub fn sa_read(p: &Pack, text: &[u32]) -> Option<(PyStr, usize)> {
    if text.len() > p.usize("_SA_MAX_CHARS") || !pystr::contains(text, "function") {
        return None;
    }
    let max_arrays = p.usize("_SA_MAX_ARRAYS");
    let mut arrays: Vec<(PyStr, std::rc::Rc<Vec<PyStr>>)> = Vec::new();
    let mut starts: HashMap<PyStr, usize> = HashMap::new();
    for m in p.re("_SA_ARRAY_FN_RE").finditer(text) {
        let got = match sa_strings(p, text, m.end()) {
            Some(g) if !g.0.is_empty() => g,
            _ => continue,
        };
        let fn_name = m.name("fn").unwrap_or(&[]);
        let fe = crate::pyre::escape(fn_name);
        let ae = crate::pyre::escape(m.name("arr").unwrap_or(&[]));
        let tail = rxutil::dynamic(
            cat(&[&p.text("_SA_TAIL_HEAD"), &fe, &p.text("_SA_TAIL_MID"), &ae, &p.text("_SA_TAIL_END"), &fe, &p.text("_SA_TAIL_CALL")]),
            0,
        );
        if tail.match_at(text, got.1 as isize, text.len() as isize).is_none() {
            continue;
        }
        arrays.push((fn_name.to_vec(), std::rc::Rc::new(got.0)));
        starts.entry(fn_name.to_vec()).or_insert(m.start());
        if arrays.len() >= max_arrays {
            break;
        }
    }
    if arrays.is_empty() {
        return None;
    }
    let consts = sa_consts(p, text);
    let body = p.usize("_SA_BODY");
    let mut accessors: Vec<Accessor> = Vec::new();
    let mut by_name: HashMap<PyStr, usize> = HashMap::new();
    for (fn_name, items) in &arrays {
        let esc = crate::pyre::escape(fn_name);
        let forms = [
            rxutil::dynamic(cat(&[&p.text("_SA_ACC_A_HEAD"), &esc, &p.text("_SA_CALL_TAIL")]), 0),
            rxutil::dynamic(cat(&[&p.text("_SA_ACC_B_HEAD"), &esc, &p.text("_SA_ACC_B_TAIL")]), 0),
        ];
        for rx in forms.iter() {
            for m in rx.finditer(text) {
                let off = match value_of(p, m.name("off").unwrap_or(&[]), &consts) {
                    Ok(v) => sa_to_number(p, &v),
                    Err(_) => continue,
                };
                if off != off || off.is_infinite() || off != off.trunc() {
                    continue;
                }
                let alphabet = p
                    .re("_SA_ALPHABET_RE")
                    .search_at(text, m.end() as isize, (m.end() + body) as isize)
                    .and_then(|a| a.group(1).map(|g| g.to_vec()));
                let g = m.name("g").unwrap_or(&[]).to_vec();
                let acc = Accessor {
                    fn_name: fn_name.clone(),
                    items: items.clone(),
                    off,
                    alphabet,
                    kind: Kind::Plain,
                    rot: 0,
                    memo: HashMap::new(),
                };
                match by_name.get(&g) {
                    Some(&k) => accessors[k] = acc,
                    None => {
                        by_name.insert(g, accessors.len());
                        accessors.push(acc);
                    }
                }
            }
        }
    }
    if accessors.is_empty() {
        return None;
    }
    // aliases (X = Y) and wrappers (function W(…){ return T(…); })
    let mut aliases: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    for m in p.re("_SA_ALIAS_RE").finditer(text) {
        let e = aliases.entry(m.group(1).unwrap_or(&[]).to_vec()).or_default();
        let to = m.group(2).unwrap_or(&[]).to_vec();
        if !e.contains(&to) {
            e.push(to);
        }
    }
    let mut wrappers: HashMap<PyStr, Vec<Wrapper>> = HashMap::new();
    let param_re = p.re("_SA_PARAM_RE");
    for m in p.re("_SA_WRAPPER_RE").finditer(text) {
        let raw = m.name("params").unwrap_or(&[]);
        let parts: Vec<&[u32]> = if pystr::strip(raw).is_empty() { Vec::new() } else { pystr::split_char(raw, c(',')) };
        let params: Vec<PyStr> =
            parts.iter().filter_map(|x| param_re.fullmatch(x).and_then(|q| q.group(1).map(|g| g.to_vec()))).collect();
        if params.len() != parts.len() {
            continue;
        }
        let args = match sa_tokens(p, m.name("args").unwrap_or(&[])).and_then(|t| sa_parse_many(&t, &consts)) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let name = rxutil::or_groups(&m, &["n1", "n2"]).unwrap_or(&[]).to_vec();
        wrappers.entry(name).or_default().push(Wrapper { params, target: m.name("target").unwrap_or(&[]).to_vec(), args });
    }
    let mut rd = Reader { p, accessors, by_name, aliases, wrappers };
    // the rotation each checksum loop applies
    let loop_back = p.usize("_SA_LOOP_BACK");
    let mut dropped: HashSet<usize> = HashSet::new();
    for k in 0..rd.accessors.len() {
        let fe = crate::pyre::escape(&rd.accessors[k].fn_name);
        let inv1 = rxutil::dynamic(cat(&[&p.text("_SA_INVOKE_HEAD"), &fe, &p.text("_SA_INVOKE_TAIL")]), 0);
        let inv2 = rxutil::dynamic(cat(&[&p.text("_SA_INVOKE2_HEAD"), &fe, &p.text("_SA_INVOKE2_TAIL")]), 0);
        let inv = inv1.search(text).or_else(|| inv2.search(text));
        let inv = match inv {
            Some(m) => m,
            None => {
                let has = rd.accessors[k].alphabet.is_some();
                rd.accessors[k].kind = if has { Kind::Base64 } else { Kind::Plain };
                continue;
            }
        };
        let lo = inv.start().saturating_sub(loop_back);
        let loop_m = p.re("_SA_CHECKSUM_RE").finditer_at(text, lo as isize, inv.start() as isize).last();
        let target_src = inv.name("t").unwrap_or(&[]).to_vec();
        let prepared: R<(f64, Tree)> = (|| {
            let lm = loop_m.as_ref().ok_or(Stop)?;
            let target = sa_to_number(p, &value_of(p, &target_src, &consts)?);
            let tree = sa_parse(&sa_tokens(p, lm.name("e").unwrap_or(&[]))?, &consts)?;
            Ok((target, tree))
        })();
        let (target, tree) = match prepared {
            Ok(x) => x,
            Err(_) => {
                dropped.insert(k);
                rd.by_name.retain(|_, v| *v != k);
                continue;
            }
        };
        let mut terms: Vec<&Tree> = Vec::new();
        let resolved: R<Vec<(Option<Val>, Option<Val>)>> = (|| {
            collect_terms(&tree, &mut terms)?;
            let mut out = Vec::new();
            for t in &terms {
                if let Tree::Pi(name, args) = t {
                    let mut vals = Vec::new();
                    for a in args {
                        vals.push(sa_value(p, a, &HashMap::new())?);
                    }
                    let (acc, idx, key) = rd.resolve(name, vals, 0)?;
                    if acc != k {
                        return Err(Stop);
                    }
                    out.push((idx, key));
                }
            }
            Ok(out)
        })();
        let resolved = match resolved {
            Ok(r) => r,
            Err(_) => {
                dropped.insert(k);
                rd.by_name.retain(|_, v| *v != k);
                continue;
            }
        };
        let kinds: &[Kind] = if rd.accessors[k].alphabet.is_some() { &[Kind::Plain, Kind::Base64, Kind::Rc4] } else { &[Kind::Plain] };
        let n = rd.accessors[k].items.len();
        let mut chosen: Option<(Kind, usize)> = None;
        'kinds: for &kind in kinds {
            for rot in 0..n {
                let mut vals: Vec<f64> = Vec::with_capacity(resolved.len());
                for (idx, key) in &resolved {
                    let s = rd.accessors[k].read(p, idx.as_ref(), key.as_ref(), kind, rot);
                    let v = sa_parse_int(p, s.as_deref());
                    if v != v {
                        break;
                    }
                    vals.push(v);
                }
                if vals.len() < resolved.len() {
                    continue;
                }
                let mut at = 0usize;
                if checksum(&tree, &vals, &mut at) == target {
                    chosen = Some((kind, rot));
                    break 'kinds;
                }
            }
        }
        match chosen {
            Some((kind, rot)) => {
                rd.accessors[k].kind = kind;
                rd.accessors[k].rot = rot;
            }
            None => {
                dropped.insert(k);
                rd.by_name.retain(|_, v| *v != k);
            }
        }
    }
    if rd.by_name.is_empty() {
        return None;
    }
    // every name that reaches an accessor
    let mut given_to: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    for (name, given) in &rd.aliases {
        if given.len() == 1 && !rd.wrappers.contains_key(name) {
            given_to.entry(given[0].clone()).or_default().push(name.clone());
        }
    }
    for (name, wraps) in &rd.wrappers {
        if wraps.len() == 1 && !rd.aliases.contains_key(name) {
            given_to.entry(wraps[0].target.clone()).or_default().push(name.clone());
        }
    }
    let mut callers: HashSet<PyStr> = rd.by_name.keys().cloned().collect();
    let mut queue: Vec<PyStr> = rd.by_name.keys().cloned().collect();
    while let Some(nm) = queue.pop() {
        if let Some(names) = given_to.get(&nm) {
            for name in names {
                if callers.insert(name.clone()) {
                    queue.push(name.clone());
                }
            }
        }
    }
    let max_calls = p.usize("_SA_MAX_CALLS");
    let tail_re = p.re("_SA_FUNCTION_TAIL_RE");
    let call_re = p.re("_SA_CALL_RE");
    let mut out: PyStr = Vec::with_capacity(text.len());
    let (mut pos, mut read) = (0usize, 0usize);
    let mut first = usize::MAX;
    while read < max_calls {
        let m = match call_re.search_at(text, pos as isize, text.len() as isize) {
            Some(m) => m,
            None => break,
        };
        let name = m.group(1).unwrap_or(&[]);
        let name_end = m.end_of(1) as usize;
        let mut got: Option<(PyStr, usize)> = None;
        if callers.contains(name)
            && tail_re.search_at(text, m.start().saturating_sub(9) as isize, m.start() as isize).is_none()
        {
            let r: R<Option<(PyStr, usize)>> = (|| {
                let trees = sa_parse_many(&sa_tokens(p, m.group(2).unwrap_or(&[]))?, &consts)?;
                let mut args = Vec::new();
                for t in &trees {
                    args.push(sa_value(p, t, &HashMap::new())?);
                }
                let (k, idx, key) = rd.resolve(name, args, 0)?;
                let (kind, rot) = (rd.accessors[k].kind, rd.accessors[k].rot);
                Ok(rd.accessors[k].read(p, idx.as_ref(), key.as_ref(), kind, rot).map(|s| (s, k)))
            })();
            got = r.ok().flatten();
        }
        match got {
            None => {
                // (the calls in its arguments are read on)
                out.extend_from_slice(&text[pos..name_end]);
                pos = name_end;
            }
            Some((s, k)) => {
                out.extend_from_slice(&text[pos..m.start()]);
                out.extend(sa_quote(&s));
                pos = m.end();
                read += 1;
                first = first.min(starts.get(&rd.accessors[k].fn_name).copied().unwrap_or(usize::MAX));
            }
        }
    }
    if read == 0 {
        return None;
    }
    out.extend_from_slice(&text[pos..]);
    Some((out, first))
}

// ---------------- proxy objects ----------------

#[derive(Clone, Debug)]
enum Entry {
    Call(usize),
    Op(PyStr),
    Str(PyStr),
    Ref(PyStr, PyStr),
    RefCall(PyStr, PyStr, usize),
}

/// core._px_params: a parameter list's names, else None.
fn px_params(p: &Pack, src: &[u32]) -> Option<Vec<PyStr>> {
    if pystr::strip(src).is_empty() {
        return Some(Vec::new());
    }
    let re = p.re("_SA_PARAM_RE");
    let mut out = Vec::new();
    for part in pystr::split_char(src, c(',')) {
        out.push(re.fullmatch(part)?.group(1)?.to_vec());
    }
    Some(out)
}

/// core._px_entries: the entries of the object literal whose '{' ends at
/// text[i] when every one is a proxy, else None.
fn px_entries(p: &Pack, text: &[u32], mut i: usize) -> Option<HashMap<PyStr, Entry>> {
    let max = p.usize("_PX_MAX_ENTRIES");
    let (key_re, func_re, str_re, ref_re, end_re) =
        (p.re("_PX_KEY_RE"), p.re("_PX_FUNCTION_RE"), p.re("_PX_STRINGS_RE"), p.re("_PX_REF_RE"), p.re("_PX_END_RE"));
    let mut out: HashMap<PyStr, Entry> = HashMap::new();
    loop {
        let k = key_re.match_at(text, i as isize, text.len() as isize)?;
        if out.len() >= max {
            return None;
        }
        let key = rxutil::or_groups(&k, &["k", "k2", "k3"]).unwrap_or(&[]).to_vec();
        i = k.end();
        let entry;
        if let Some(f) = func_re.match_at(text, i as isize, text.len() as isize) {
            let params = px_params(p, f.name("params").unwrap_or(&[]))?;
            let distinct: HashSet<&PyStr> = params.iter().collect();
            if distinct.len() != params.len() {
                return None;
            }
            let body = f.name("e").unwrap_or(&[]);
            let b = p.re("_PX_BINARY_RE").fullmatch(body);
            let cm = p.re("_PX_CALL_RE").fullmatch(body);
            let rc = p.re("_PX_REF_CALL_RE").fullmatch(body);
            if let Some(b) = b.as_ref().filter(|b| {
                params.len() == 2 && b.group(1) == Some(params[0].as_slice()) && b.group(4) == Some(params[1].as_slice())
            }) {
                entry = Entry::Op(b.group(2).or(b.group(3)).unwrap_or(&[]).to_vec());
            } else if let Some(_cm) = cm.as_ref().filter(|cm| {
                !params.is_empty()
                    && cm.group(1) == Some(params[0].as_slice())
                    && px_params(p, cm.name("a").unwrap_or(&[])).as_deref() == Some(&params[1..])
            }) {
                entry = Entry::Call(params.len() - 1);
            } else if let Some(rc) = rc.as_ref().filter(|rc| px_params(p, rc.name("a").unwrap_or(&[])).as_deref() == Some(&params[..])) {
                entry = Entry::RefCall(
                    rc.name("o").unwrap_or(&[]).to_vec(),
                    rc.name("k").or(rc.name("k2")).unwrap_or(&[]).to_vec(),
                    params.len(),
                );
            } else {
                return None;
            }
            i = f.end();
        } else if let Some(s) = str_re.match_at(text, i as isize, text.len() as isize) {
            let mut joined = Vec::new();
            for x in p.re("_SA_LIT_RE").finditer(s.group0()) {
                let g = x.group0();
                joined.extend(sa_string(p, &g[1..g.len() - 1])?);
            }
            entry = Entry::Str(joined);
            i = s.end();
        } else if let Some(r) = ref_re.match_at(text, i as isize, text.len() as isize) {
            entry = Entry::Ref(r.name("o").unwrap_or(&[]).to_vec(), r.name("k").or(r.name("k2")).unwrap_or(&[]).to_vec());
            i = r.end();
        } else {
            return None;
        }
        out.insert(key, entry);
        let e = end_re.match_at(text, i as isize, text.len() as isize)?;
        i = e.end();
        if e.group(1) == Some(&[c('}')][..]) {
            return Some(out);
        }
    }
}

/// core._px_args: (end, [(start, end)]) of the arguments of the call whose
/// '(' ends at text[i]; None when it does not close.
fn px_args(p: &Pack, text: &[u32], i: usize, hi: usize) -> Option<(usize, Vec<(usize, usize)>)> {
    let mut parts = Vec::new();
    let (mut depth, mut start, mut j) = (0usize, i, i);
    let mut quote: Option<u32> = None;
    let end = hi.min(i + p.usize("_PX_ARGS"));
    while j < end {
        let ch = text[j];
        if let Some(q) = quote {
            if ch == c('\\') {
                j += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else if matches!(ch, 0x27 | 0x22 | 0x60) {
            quote = Some(ch);
        } else if matches!(ch, 0x28 | 0x5B | 0x7B) {
            depth += 1;
        } else if matches!(ch, 0x29 | 0x5D | 0x7D) {
            if depth == 0 {
                if ch != c(')') {
                    return None;
                }
                if !pystr::strip(&text[start..j]).is_empty() || !parts.is_empty() {
                    parts.push((start, j));
                }
                return Some((j, parts));
            }
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            parts.push((start, j));
            start = j + 1;
        }
        j += 1;
    }
    None
}

/// The objects a name is given, in order: (start, its entries when it is a proxy).
type Objects = HashMap<PyStr, Vec<(usize, Option<HashMap<PyStr, Entry>>)>>;

struct Proxies<'a> {
    p: &'a Pack,
    text: &'a [u32],
    objects: Objects,
    uses: usize,
}

impl<'a> Proxies<'a> {
    /// The entries of the object `name` was last given before pos (core's
    /// lookup: a name an obfuscator reuses in each function holds that
    /// function's object), else None.
    fn lookup(&self, name: &[u32], pos: usize) -> Option<&HashMap<PyStr, Entry>> {
        let given = self.objects.get(name)?;
        let k = given.partition_point(|(a, _)| *a < pos);
        if k == 0 {
            return None;
        }
        given[k - 1].1.as_ref()
    }

    /// An entry with the entries it refers to followed.
    fn final_entry(&self, entry: &Entry, pos: usize) -> Option<Entry> {
        let max = self.p.usize("_PX_DEPTH");
        let mut e = entry.clone();
        let mut depth = 0usize;
        while matches!(e, Entry::Ref(..) | Entry::RefCall(..)) && depth <= max {
            let (o, k) = match &e {
                Entry::Ref(o, k) | Entry::RefCall(o, k, _) => (o.clone(), k.clone()),
                _ => unreachable!(),
            };
            let target = self.lookup(&o, pos).and_then(|t| t.get(&k))?.clone();
            if let Entry::RefCall(_, _, n) = e {
                match &target {
                    Entry::Str(_) => return None,
                    Entry::Call(m) if m + 1 != n => return None,
                    Entry::Op(_) if n != 2 => return None,
                    _ => {}
                }
            }
            e = target;
            depth += 1;
        }
        match e {
            Entry::Call(_) | Entry::Op(_) | Entry::Str(_) => Some(e),
            _ => None,
        }
    }

    fn rewrite(&mut self, lo: usize, hi: usize, depth: usize) -> PyStr {
        let (p, text) = (self.p, self.text);
        let use_re = p.re("_PX_USE_RE");
        let open_re = p.re("_PX_OPEN_RE");
        let max_uses = p.usize("_PX_MAX_USES");
        let max_depth = p.usize("_PX_DEPTH");
        let mut out: PyStr = Vec::new();
        let mut pos = lo;
        while self.uses < max_uses {
            let m = match use_re.search_at(text, pos as isize, hi as isize) {
                Some(m) => m,
                None => break,
            };
            let (ms, me) = (m.start(), m.end());
            let key = m.group(2).or(m.group(3)).unwrap_or(&[]).to_vec();
            let found = self.lookup(m.group(1).unwrap_or(&[]), ms).and_then(|t| t.get(&key)).cloned();
            let entry = found.and_then(|e| self.final_entry(&e, ms));
            let entry = match entry {
                Some(e) => e,
                None => {
                    out.extend_from_slice(&text[pos..me]);
                    pos = me;
                    continue;
                }
            };
            if let Entry::Str(s) = &entry {
                out.extend_from_slice(&text[pos..ms]);
                out.extend(sa_quote(s));
                pos = me;
                self.uses += 1;
                continue;
            }
            let o = open_re.match_at(text, me as isize, hi as isize);
            let got = match o {
                Some(o) if depth < max_depth => px_args(p, text, o.end(), hi),
                _ => None,
            };
            let want = match &entry {
                Entry::Call(n) => n + 1,
                _ => 2,
            };
            let (close, parts) = match got {
                Some(g) if g.1.len() == want => g,
                _ => {
                    out.extend_from_slice(&text[pos..me]);
                    pos = me;
                    continue;
                }
            };
            let mut args: Vec<PyStr> = Vec::new();
            for (a, b) in parts {
                let r = self.rewrite(a, b, depth + 1);
                args.push(pystr::strip(&r).to_vec());
            }
            out.extend_from_slice(&text[pos..ms]);
            let read: PyStr = match &entry {
                Entry::Call(_) => {
                    let rest: Vec<&[u32]> = args[1..].iter().map(|a| a.as_slice()).collect();
                    cat(&[&args[0], &u("("), &pystr::join(&u(", "), &rest), &u(")")])
                }
                Entry::Op(op) => cat(&[&u("("), &args[0], &u(" "), op, &u(" "), &args[1], &u(")")]),
                _ => unreachable!(),
            };
            let before = pystr::count_char(text, c('\n'), ms, close + 1);
            let now = pystr::count_char(&read, c('\n'), 0, read.len());
            out.extend(read);
            for _ in 0..before.saturating_sub(now) {
                out.push(c('\n'));
            }
            pos = close + 1;
            self.uses += 1;
        }
        out.extend_from_slice(&text[pos..hi]);
        out
    }
}

/// core._dv_proxies: `text` with the proxy objects' uses read as what they
/// stand for; None when it has none.
pub fn dv_proxies(p: &Pack, text: &[u32]) -> Option<PyStr> {
    if !pystr::contains(text, "function") || !text.contains(&c('[')) {
        return None;
    }
    let mut found: Objects = HashMap::new();
    for m in p.re("_PX_OBJECT_RE").finditer(text) {
        let entries = px_entries(p, text, m.end()).filter(|e| !e.is_empty());
        found.entry(m.group(1).unwrap_or(&[]).to_vec()).or_default().push((m.start(), entries));
    }
    let objects: Objects = found.into_iter().filter(|(_, v)| v.iter().any(|(_, e)| e.is_some())).collect();
    if objects.is_empty() {
        return None;
    }
    let mut px = Proxies { p, text, objects, uses: 0 };
    let out = px.rewrite(0, text.len(), 0);
    if out == text {
        None
    } else {
        Some(out)
    }
}
