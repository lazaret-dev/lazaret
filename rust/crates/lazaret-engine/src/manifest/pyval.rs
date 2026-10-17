//! Python values of a parsed manifest: what `json.loads` (with core's
//! `parse_int`) and `ast.literal_eval` make of one, with the kinds Python
//! keeps apart (an int of any size, a float, a complex number, a str, bytes,
//! a tuple, a set), dicts and sets holding equal keys once as Python's do
//! (1 == 1.0 == True == 1+0j, -0.0 == 0, tuples item by item), and Python's
//! `str()` and `repr()` of them, which the findings' messages show.

use crate::pystr::{self, PyStr};
use std::collections::HashMap;

/// Python's str() of an int refuses more than this many decimal digits
/// (ValueError: core then shows the int in hexadecimal).
pub const INT_STR_DIGITS: usize = 4300;

/// A value.
#[derive(Clone, Debug, PartialEq)]
pub enum PyVal {
    None,
    Bool(bool),
    /// An int: `-` when negative, then its decimal digits, or `0x` and its
    /// hexadecimal digits for one too large to write in decimal (the Python
    /// parser's form past `INT_DECIMAL_BITS` bits); zero is `0`.
    Int(PyStr),
    Float(f64),
    /// real, imaginary
    Complex(f64, f64),
    Str(PyStr),
    /// bytes (each below 256)
    Bytes(Vec<u32>),
    Ellipsis,
    List(Vec<PyVal>),
    Tuple(Vec<PyVal>),
    /// a set's items, each once, in the order they were first given (Python
    /// iterates a set in its hash order, which for str items changes from
    /// one run to the next)
    Set(Vec<PyVal>),
    /// A dict: its items in Python's order (an equal key keeps its first
    /// place and takes the last value); `at`: where the key the parse was
    /// asked to locate starts in the text, the last of equal ones, when the
    /// dict holds it.
    Dict(Vec<(PyVal, PyVal)>, Option<usize>),
}

impl PyVal {
    /// type(v).__name__
    pub fn type_name(&self) -> &'static str {
        match self {
            PyVal::None => "NoneType",
            PyVal::Bool(_) => "bool",
            PyVal::Int(_) => "int",
            PyVal::Float(_) => "float",
            PyVal::Complex(..) => "complex",
            PyVal::Str(_) => "str",
            PyVal::Bytes(_) => "bytes",
            PyVal::Ellipsis => "ellipsis",
            PyVal::List(_) => "list",
            PyVal::Tuple(_) => "tuple",
            PyVal::Set(_) => "set",
            PyVal::Dict(..) => "dict",
        }
    }

    /// The value of a dict's str key, the way `d.get(key)` reads it (None
    /// for anything that is not a dict).
    pub fn get(&self, key: &str) -> Option<&PyVal> {
        match self {
            PyVal::Dict(items, _) => items.iter().find(|(k, _)| matches!(k, PyVal::Str(s) if pystr::eq(s, key))).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&[u32]> {
        match self {
            PyVal::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// The negation of an int's text.
pub fn int_neg(t: &[u32]) -> PyStr {
    if t.first() == Some(&('-' as u32)) {
        t[1..].to_vec()
    } else if t == [0x30] {
        t.to_vec()
    } else {
        let mut out = vec!['-' as u32];
        out.extend_from_slice(t);
        out
    }
}

/// int(text) of a JSON integer literal (`-`? and decimal digits, no leading zero): its text, `-0` read as 0.
pub fn int_of_json(t: &[u32]) -> PyStr {
    if pystr::eq(t, "-0") {
        pystr::u("0")
    } else {
        t.to_vec()
    }
}

/// float(int): the int read as a float (correctly rounded), None where Python raises OverflowError.
pub fn int_to_float(t: &[u32]) -> Option<f64> {
    let (neg, mag) = split_sign(t);
    if mag.len() > 2 && mag[1] == 'x' as u32 {
        return None; // (more than 16,384 bits)
    }
    let v: f64 = pystr::to_string(mag).parse().ok()?;
    if v.is_infinite() {
        return None;
    }
    Some(if neg { -v } else { v })
}

fn split_sign(t: &[u32]) -> (bool, &[u32]) {
    match t.first() {
        Some(&c) if c == '-' as u32 => (true, &t[1..]),
        _ => (false, t),
    }
}

// ---------------- str() and repr() ----------------

/// Python's str() of a value as core's `_gyp_str` shows it: a str as it is, anything else its repr() (an int of
/// more than 4,300 digits, which str() refuses, in hexadecimal: `_gyp_repr`).
pub fn py_str(v: &PyVal) -> PyStr {
    match v {
        PyVal::Str(s) => s.clone(),
        _ => repr(v),
    }
}

/// Python's repr() (an int of more than 4,300 digits in hexadecimal, as `_gyp_repr` and `hex()` show it).
pub fn repr(v: &PyVal) -> PyStr {
    let mut out = Vec::new();
    repr_into(v, &mut out);
    out
}

fn repr_into(v: &PyVal, out: &mut PyStr) {
    match v {
        PyVal::None => out.extend(pystr::u("None")),
        PyVal::Bool(b) => out.extend(pystr::u(if *b { "True" } else { "False" })),
        PyVal::Ellipsis => out.extend(pystr::u("Ellipsis")),
        PyVal::Int(t) => out.extend(int_repr(t)),
        PyVal::Float(f) => out.extend(pystr::u(&float_repr(*f, false))),
        PyVal::Complex(re, im) => out.extend(pystr::u(&complex_repr(*re, *im))),
        PyVal::Str(s) => out.extend(crate::findings::py_repr(s)),
        PyVal::Bytes(b) => out.extend(bytes_repr(b)),
        PyVal::List(items) => {
            out.push('[' as u32);
            seq_into(items, out);
            out.push(']' as u32);
        }
        PyVal::Tuple(items) => {
            out.push('(' as u32);
            seq_into(items, out);
            if items.len() == 1 {
                out.push(',' as u32);
            }
            out.push(')' as u32);
        }
        PyVal::Set(items) => {
            if items.is_empty() {
                out.extend(pystr::u("set()"));
            } else {
                out.push('{' as u32);
                seq_into(items, out);
                out.push('}' as u32);
            }
        }
        PyVal::Dict(items, _) => {
            out.push('{' as u32);
            for (k, (key, val)) in items.iter().enumerate() {
                if k > 0 {
                    out.extend(pystr::u(", "));
                }
                repr_into(key, out);
                out.extend(pystr::u(": "));
                repr_into(val, out);
            }
            out.push('}' as u32);
        }
    }
}

fn seq_into(items: &[PyVal], out: &mut PyStr) {
    for (k, x) in items.iter().enumerate() {
        if k > 0 {
            out.extend(pystr::u(", "));
        }
        repr_into(x, out);
    }
}

/// repr() of an int, or hex() past 4,300 decimal digits (str() would refuse it).
pub fn int_repr(t: &[u32]) -> PyStr {
    let (neg, mag) = split_sign(t);
    let hex = if mag.len() > 2 && mag[1] == 'x' as u32 {
        Some(mag.to_vec())
    } else if mag.len() > INT_STR_DIGITS {
        Some(dec_to_hex(mag))
    } else {
        None
    };
    match hex {
        Some(h) => {
            let mut out = if neg { vec!['-' as u32] } else { Vec::new() };
            out.extend(h);
            out
        }
        None => t.to_vec(),
    }
}

/// `0x` and the hexadecimal digits of a decimal number (a few thousand digits at most: quadratic).
fn dec_to_hex(digits: &[u32]) -> PyStr {
    let mut limbs: Vec<u32> = Vec::new(); // little-endian, base 2^32
    let mut k = 0;
    while k < digits.len() {
        let take = (digits.len() - k).min(9);
        let mut chunk: u64 = 0;
        let mut scale: u64 = 1;
        for &d in &digits[k..k + take] {
            chunk = chunk * 10 + (d.saturating_sub(0x30) as u64 % 10);
            scale *= 10;
        }
        let mut carry = chunk;
        for l in limbs.iter_mut() {
            let cur = *l as u64 * scale + carry;
            *l = cur as u32;
            carry = cur >> 32;
        }
        while carry > 0 {
            limbs.push(carry as u32);
            carry >>= 32;
        }
        k += take;
    }
    let mut out = pystr::u("0x");
    let mut started = false;
    for &l in limbs.iter().rev() {
        for s in (0..8).rev() {
            let nib = (l >> (s * 4)) & 0xF;
            if nib != 0 || started {
                started = true;
                out.push(if nib < 10 { 0x30 + nib } else { 0x61 + nib - 10 });
            }
        }
    }
    if !started {
        out.push(0x30);
    }
    out
}

/// repr() of a float (`strip`: without a trailing `.0`, as a complex number's parts are shown).
pub fn float_repr(v: f64, strip: bool) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf".to_string() } else { "inf".to_string() };
    }
    crate::pyflow::unparse::float_repr(v, strip)
}

/// repr() of a complex number.
pub fn complex_repr(re: f64, im: f64) -> String {
    if re == 0.0 && re.is_sign_positive() {
        return format!("{}j", float_repr(im, true));
    }
    let i = float_repr(im, true);
    format!("({}{}{}j)", float_repr(re, true), if i.starts_with('-') { "" } else { "+" }, i)
}

/// repr() of bytes.
pub fn bytes_repr(b: &[u32]) -> PyStr {
    let q = if b.contains(&('\'' as u32)) && !b.contains(&('"' as u32)) { '"' as u32 } else { '\'' as u32 };
    let mut out = vec!['b' as u32, q];
    for &c in b {
        if c == q || c == '\\' as u32 {
            out.push('\\' as u32);
            out.push(c);
        } else if c == '\t' as u32 {
            out.extend(pystr::u("\\t"));
        } else if c == '\n' as u32 {
            out.extend(pystr::u("\\n"));
        } else if c == '\r' as u32 {
            out.extend(pystr::u("\\r"));
        } else if !(0x20..0x7f).contains(&c) {
            out.extend(pystr::u(&format!("\\x{:02x}", c & 0xFF)));
        } else {
            out.push(c);
        }
    }
    out.push(q);
    out
}

// ---------------- equal keys ----------------

/// What a dict or set compares a key by: equal for the keys Python finds equal (and hashes alike).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    None,
    Ellipsis,
    /// an integral number: its exact value (decimal digits, or `x` and hexadecimal digits past 16,384 bits)
    Num(PyStr),
    /// a float that is not integral, by its bits
    Float(u64),
    /// a complex number with an imaginary part, by its parts' bits (-0.0 as 0.0)
    Complex(u64, u64),
    Str(PyStr),
    Bytes(Vec<u32>),
    Tuple(Vec<Key>),
}

/// The key of a value, or None for one Python cannot hash (a list, dict or set: literal_eval's TypeError).
pub fn key(v: &PyVal) -> Option<Key> {
    Some(match v {
        PyVal::None => Key::None,
        PyVal::Ellipsis => Key::Ellipsis,
        PyVal::Bool(b) => Key::Num(pystr::u(if *b { "1" } else { "0" })),
        PyVal::Int(t) => {
            let (neg, mag) = split_sign(t);
            let mut out = if neg { vec!['-' as u32] } else { Vec::new() };
            if mag.len() > 2 && mag[1] == 'x' as u32 {
                out.push('x' as u32);
                out.extend_from_slice(&mag[2..]);
            } else {
                out.extend_from_slice(mag);
            }
            Key::Num(out)
        }
        PyVal::Float(f) => float_key(*f),
        PyVal::Complex(re, im) => {
            if *im == 0.0 {
                float_key(*re)
            } else {
                Key::Complex(zero(*re).to_bits(), zero(*im).to_bits())
            }
        }
        PyVal::Str(s) => Key::Str(s.clone()),
        PyVal::Bytes(b) => Key::Bytes(b.clone()),
        PyVal::Tuple(items) => {
            let mut keys = Vec::with_capacity(items.len());
            for x in items {
                keys.push(key(x)?);
            }
            Key::Tuple(keys)
        }
        PyVal::List(_) | PyVal::Set(_) | PyVal::Dict(..) => return None,
    })
}

fn zero(f: f64) -> f64 {
    if f == 0.0 {
        0.0
    } else {
        f
    }
}

fn float_key(f: f64) -> Key {
    if f.is_finite() && f.fract() == 0.0 {
        Key::Num(exact_integer(f))
    } else {
        Key::Float(f.to_bits())
    }
}

/// The exact decimal digits of an integral finite float (`-` when negative; -0.0 is 0).
fn exact_integer(f: f64) -> PyStr {
    if f == 0.0 {
        return pystr::u("0");
    }
    let neg = f < 0.0;
    let a = f.abs();
    let digits = format!("{:.0}", a); // (Rust prints a float's fixed-point digits exactly)
    let mut out = if neg { vec!['-' as u32] } else { Vec::new() };
    out.extend(pystr::u(&digits));
    out
}

/// A dict being built: Python's insertion (an equal key keeps its first place and its first spelling, and takes
/// the last value).
#[derive(Default)]
pub struct DictBuilder {
    pub items: Vec<(PyVal, PyVal)>,
    index: HashMap<Key, usize>,
}

impl DictBuilder {
    /// d[k] = v; false when Python cannot hash the key.
    pub fn insert(&mut self, k: PyVal, v: PyVal) -> bool {
        let Some(id) = key(&k) else {
            return false;
        };
        match self.index.get(&id) {
            Some(&at) => self.items[at].1 = v,
            None => {
                self.index.insert(id, self.items.len());
                self.items.push((k, v));
            }
        }
        true
    }

    /// d[k] = v for a str key (a JSON object's).
    pub fn insert_str(&mut self, k: PyStr, v: PyVal) {
        self.insert(PyVal::Str(k), v);
    }
}

/// {…} of `items` as a set: each once, in the order first given; None when one cannot be hashed.
pub fn set_of(items: Vec<PyVal>) -> Option<PyVal> {
    let mut seen: HashMap<Key, ()> = HashMap::new();
    let mut out = Vec::with_capacity(items.len());
    for x in items {
        let id = key(&x)?;
        if seen.insert(id, ()).is_none() {
            out.push(x);
        }
    }
    Some(PyVal::Set(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> PyVal {
        PyVal::Str(pystr::u(x))
    }

    #[test]
    fn reprs() {
        let t = |v: &PyVal| pystr::to_string(&repr(v));
        assert_eq!(t(&PyVal::Float(1e16)), "1e+16");
        assert_eq!(t(&PyVal::Float(-0.0)), "-0.0");
        assert_eq!(t(&PyVal::Float(f64::INFINITY)), "inf");
        assert_eq!(t(&PyVal::Complex(0.0, 2.0)), "2j");
        assert_eq!(t(&PyVal::Complex(-0.0, -2.0)), "(-0-2j)");
        assert_eq!(t(&PyVal::Complex(1.0, -0.0)), "(1-0j)");
        assert_eq!(t(&PyVal::Complex(1.5, 1e16)), "(1.5+1e+16j)");
        assert_eq!(t(&PyVal::Tuple(vec![s("a")])), "('a',)");
        assert_eq!(t(&PyVal::Set(vec![])), "set()");
        assert_eq!(t(&PyVal::Bytes(vec![0x27, 0x0, 0xff, 0x41])), "b\"'\\x00\\xffA\"");
        assert_eq!(t(&PyVal::Dict(vec![(PyVal::Int(pystr::u("1")), PyVal::None)], None)), "{1: None}");
        let big = "9".repeat(4301);
        assert_eq!(pystr::to_string(&int_repr(&pystr::u(&big))).len(), 2 + 3572);
        assert_eq!(pystr::to_string(&int_repr(&pystr::u("-255"))), "-255");
        assert_eq!(pystr::to_string(&dec_to_hex(&pystr::u("255"))), "0xff");
        assert_eq!(pystr::to_string(&dec_to_hex(&pystr::u("4294967296"))), "0x100000000");
    }

    #[test]
    fn equal_keys() {
        let one = key(&PyVal::Int(pystr::u("1")));
        assert_eq!(one, key(&PyVal::Float(1.0)));
        assert_eq!(one, key(&PyVal::Bool(true)));
        assert_eq!(one, key(&PyVal::Complex(1.0, 0.0)));
        assert_eq!(key(&PyVal::Float(-0.0)), key(&PyVal::Int(pystr::u("0"))));
        assert_eq!(key(&PyVal::Float(1e300)), Some(Key::Num(pystr::u(&format!("{:.0}", 1e300f64)))));
        assert_ne!(key(&s("1")), one);
        assert_eq!(key(&PyVal::List(vec![])), None);
        assert_eq!(key(&PyVal::Tuple(vec![PyVal::List(vec![])])), None);
        let mut d = DictBuilder::default();
        d.insert(PyVal::Int(pystr::u("1")), s("a"));
        d.insert(PyVal::Float(1.0), s("b"));
        assert_eq!(d.items, vec![(PyVal::Int(pystr::u("1")), s("b"))]);
    }
}
