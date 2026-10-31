//! `ast.literal_eval(ast.parse(src, mode="eval"))` (Python 3.13's), on the
//! engine's Python parser: what a binding.gyp or .gypi file holds, read as gyp
//! reads it (a Python literal: single quotes, comments, trailing commas, any
//! string prefix but f, implicit concatenation, numbers of every form). The
//! parser builds the tree `ast.parse` builds or fails where it fails; the
//! tree is then read as `literal_eval` reads it: constants, tuples, lists,
//! sets, dicts, `set()`, a sign on a number, a real plus or minus an
//! imaginary number. The npm package's `pyLiteralParse` (pyjson.js) was its
//! twin until BR-7's step 3 (b).

use super::pyval::{self, DictBuilder, PyVal};
use crate::pyparse::{self, tree, Kind, NodeId, Tree, NONE};
use crate::pystr;

/// Why a literal could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// RecursionError: nested too deeply to parse (core reports the manifest SC-MANIFEST-DEPTH)
    Depth,
    /// any other exception, by its name (SyntaxError, ValueError, TypeError, MemoryError, OverflowError)
    Error(&'static str),
}

/// The value of `src` (a whole text, already stripped as core strips it); `locate`: a key whose position every dict
/// that holds it records in its `at` (the last of equal keys' first token, offset by `base`).
pub fn literal_eval(src: &[u32], locate: Option<&[u32]>, base: usize) -> Result<PyVal, Fail> {
    let t = match pyparse::parse(src) {
        Ok(t) => t,
        Err(e) => {
            return Err(if e.reason.starts_with("maximum recursion depth") {
                Fail::Depth
            } else if e.reason.starts_with("too complex") {
                Fail::Error("MemoryError")
            } else {
                Fail::Error("SyntaxError")
            })
        }
    };
    // mode="eval": one expression, and nothing after it but blank space and comments (`1;` is a module's)
    let body = t.children_of(t.root, "body");
    if body.len() != 1 || t.kind(body[0]) != Kind::Expr || !only_blank(src, t.node(body[0]).end as usize) {
        return Err(Fail::Error("SyntaxError"));
    }
    let Some(expr) = t.child(body[0], "value") else {
        return Err(Fail::Error("SyntaxError"));
    };
    if !eval_mode(&t, src, expr) {
        return Err(Fail::Error("SyntaxError"));
    }
    let r = Reader { t: &t, locate, base };
    r.convert(expr).map_err(Fail::Error)
}

/// Would mode="eval" read the expression a module's one statement holds? Its grammar has no starred expression at
/// the top (`*a`, `a, *b`) and no unparenthesized yield.
fn eval_mode(t: &Tree, src: &[u32], expr: NodeId) -> bool {
    let n = t.node(expr);
    match n.kind {
        Kind::Starred => false,
        Kind::Yield | Kind::YieldFrom => n.start > 0, // (a top-level yield starts the text unless it is in parentheses)
        Kind::Tuple => {
            let elts = t.children_of(expr, "elts");
            let starred = elts.iter().any(|&e| t.kind(e) == Kind::Starred);
            let (a, b) = (n.start as usize, n.end as usize);
            let parenthesized = src.get(a) == Some(&('(' as u32))
                && b > 0
                && src.get(b - 1) == Some(&(')' as u32))
                && elts.first().is_none_or(|&e| t.node(e).start as usize > a);
            !starred || parenthesized
        }
        _ => true,
    }
}

/// Is `src[from..]` blank space, comments and line continuations only?
fn only_blank(src: &[u32], from: usize) -> bool {
    let mut i = from;
    while i < src.len() {
        let c = src[i];
        if c == ' ' as u32 || c == '\t' as u32 || c == '\x0c' as u32 || c == '\n' as u32 || c == '\r' as u32 {
            i += 1;
        } else if c == '#' as u32 {
            while i < src.len() && src[i] != '\n' as u32 && src[i] != '\r' as u32 {
                i += 1;
            }
        } else if c == '\\' as u32 {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

struct Reader<'a> {
    t: &'a Tree,
    locate: Option<&'a [u32]>,
    base: usize,
}

const MALFORMED: &str = "ValueError";

impl<'a> Reader<'a> {
    fn constant(&self, id: NodeId) -> PyVal {
        let n = self.t.node(id);
        match n.op {
            tree::V_NONE => PyVal::None,
            tree::V_TRUE => PyVal::Bool(true),
            tree::V_FALSE => PyVal::Bool(false),
            tree::V_ELLIPSIS => PyVal::Ellipsis,
            tree::V_STR => PyVal::Str(self.t.str(n.f[0]).to_vec()),
            tree::V_BYTES => PyVal::Bytes(self.t.str(n.f[0]).to_vec()),
            tree::V_INT => PyVal::Int(self.t.str(n.f[0]).to_vec()),
            tree::V_FLOAT => PyVal::Float(self.float(id)),
            _ => PyVal::Complex(0.0, self.float(id)),
        }
    }

    fn float(&self, id: NodeId) -> f64 {
        let n = self.t.node(id);
        f64::from_bits(n.f[1] as u64 | ((n.f[2] as u64) << 32))
    }

    /// _convert_num: a number constant (an int, a float or a complex number; not a bool).
    fn num(&self, id: NodeId) -> Result<PyVal, &'static str> {
        if self.t.kind(id) == Kind::Constant && matches!(self.t.node(id).op, tree::V_INT | tree::V_FLOAT | tree::V_COMPLEX) {
            Ok(self.constant(id))
        } else {
            Err(MALFORMED)
        }
    }

    /// _convert_signed_num: a number constant, or + or - one.
    fn signed_num(&self, id: NodeId) -> Result<PyVal, &'static str> {
        let n = self.t.node(id);
        if n.kind == Kind::UnaryOp && (n.op == tree::UADD || n.op == tree::USUB) {
            let Some(operand) = self.t.child(id, "operand") else {
                return Err(MALFORMED);
            };
            let v = self.num(operand)?;
            if n.op == tree::UADD {
                return Ok(v);
            }
            return Ok(match v {
                PyVal::Int(t) => PyVal::Int(pyval::int_neg(&t)),
                PyVal::Float(f) => PyVal::Float(-f),
                PyVal::Complex(re, im) => PyVal::Complex(-re, -im),
                other => other,
            });
        }
        self.num(id)
    }

    fn items(&self, id: NodeId) -> Result<Vec<PyVal>, &'static str> {
        self.t.children_of(id, "elts").iter().map(|&e| self.convert(e)).collect()
    }

    fn convert(&self, id: NodeId) -> Result<PyVal, &'static str> {
        let t = self.t;
        match t.kind(id) {
            Kind::Constant => Ok(self.constant(id)),
            Kind::Tuple => Ok(PyVal::Tuple(self.items(id)?)),
            Kind::List => Ok(PyVal::List(self.items(id)?)),
            Kind::Set => pyval::set_of(self.items(id)?).ok_or("TypeError"),
            Kind::Call => {
                let is_set = t.child(id, "func").is_some_and(|f| t.kind(f) == Kind::Name && t.text_of(f, "id").is_some_and(|n| pystr::eq(n, "set")));
                if is_set && t.children_of(id, "args").is_empty() && t.children_of(id, "keywords").is_empty() {
                    Ok(PyVal::Set(Vec::new()))
                } else {
                    Err(MALFORMED)
                }
            }
            Kind::Dict => {
                let keys = t.children_of(id, "keys");
                let values = t.children_of(id, "values");
                if keys.len() != values.len() {
                    return Err(MALFORMED);
                }
                let mut d = DictBuilder::default();
                let mut found = None;
                for (&k, &v) in keys.iter().zip(values) {
                    if k == NONE {
                        return Err(MALFORMED); // (`**x`)
                    }
                    let key = self.convert(k)?;
                    let val = self.convert(v)?;
                    if let (Some(l), PyVal::Str(s)) = (self.locate, &key) {
                        if l == s.as_slice() {
                            found = Some(self.base + t.node(k).start as usize);
                        }
                    }
                    if !d.insert(key, val) {
                        return Err("TypeError");
                    }
                }
                Ok(PyVal::Dict(d.items, found))
            }
            Kind::BinOp if t.node(id).op == tree::ADD || t.node(id).op == tree::SUB => {
                let (Some(l), Some(r)) = (t.child(id, "left"), t.child(id, "right")) else {
                    return Err(MALFORMED);
                };
                let left = self.signed_num(l)?;
                let right = self.num(r)?;
                let re = match &left {
                    PyVal::Int(text) => Some(pyval::int_to_float(text).ok_or("OverflowError")?),
                    PyVal::Float(f) => Some(*f),
                    _ => None,
                };
                match (re, right) {
                    (Some(a), PyVal::Complex(b_re, b_im)) => Ok(if t.node(id).op == tree::ADD {
                        PyVal::Complex(a + b_re, 0.0 + b_im)
                    } else {
                        PyVal::Complex(a - b_re, 0.0 - b_im)
                    }),
                    _ => Err(MALFORMED),
                }
            }
            _ => self.signed_num(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(s: &str) -> Result<PyVal, Fail> {
        literal_eval(&pystr::u(s), None, 0)
    }

    fn r(s: &str) -> String {
        match ev(s) {
            Ok(v) => pystr::to_string(&pyval::repr(&v)),
            Err(e) => format!("{:?}", e),
        }
    }

    #[test]
    fn literals() {
        assert_eq!(r("{'a': [1, 2.5, -3, +4j, 1-2j, (1,), set(), {1, 1.0, True}], 'b': b'x\\xff', 'c': None, 1: ...}"),
            "{'a': [1, 2.5, -3, 4j, (1-2j), (1,), set(), {1}], 'b': b'x\\xff', 'c': None, 1: Ellipsis}");
        assert_eq!(r("{'a': 1, 'a': 2,}  # c"), "{'a': 2}");
        assert_eq!(r("'a' \"b\" r'\\n'"), "'ab\\\\n'");
        assert_eq!(r("-2j"), "(-0-2j)");
        assert_eq!(r("0x10"), "16");
        assert_eq!(r("1;"), "Error(\"SyntaxError\")");
        assert_eq!(r("x = 1"), "Error(\"SyntaxError\")");
        assert_eq!(r("*j"), "Error(\"SyntaxError\")");
        assert_eq!(r("a, *b"), "Error(\"SyntaxError\")");
        assert_eq!(r("(*a, b)"), "Error(\"ValueError\")");
        assert_eq!(r("yield 1"), "Error(\"SyntaxError\")");
        assert_eq!(r("(yield 1)"), "Error(\"ValueError\")");
        assert_eq!(r("null"), "Error(\"ValueError\")");
        assert_eq!(r("--1"), "Error(\"ValueError\")");
        assert_eq!(r("-True"), "Error(\"ValueError\")");
        assert_eq!(r("{[1]: 2}"), "Error(\"TypeError\")");
        assert_eq!(r("{**a}"), "Error(\"ValueError\")");
        assert_eq!(r("f'x'"), "Error(\"ValueError\")");
        assert_eq!(r("set([1])"), "Error(\"ValueError\")");
        assert_eq!(r(&format!("0x{} + 1j", "f".repeat(300))), "Error(\"OverflowError\")");
        assert_eq!(r(&"(".repeat(201)), "Error(\"SyntaxError\")");
        match literal_eval(&pystr::u("{'action': 1, 'x': {'action': 2, 'action': 3}}"), Some(&pystr::u("action")), 5).unwrap() {
            PyVal::Dict(items, at) => {
                assert_eq!(at, Some(6));
                match &items[1].1 {
                    PyVal::Dict(_, inner) => assert_eq!(*inner, Some(5 + 33)),
                    v => panic!("{:?}", v),
                }
            }
            v => panic!("{:?}", v),
        }
    }
}
