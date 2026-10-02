//! `ast.unparse` of an expression, as Python 3.13 writes it (Lib/ast.py's
//! _Unparser, the expression half): the text flow.py's route handlers read
//! a parameter's annotation and default as (`frameworks.rs`). None where
//! Python's would raise (an int too long to write in decimal).

use crate::pyparse::tree::{self as pt, Kind, NodeId, Tree, NONE};
use crate::pystr::{u, PyStr};
use crate::quickhash::QuickMap;

// _Precedence
const NAMED_EXPR: u8 = 1;
const TUPLE: u8 = 2;
const YIELD: u8 = 3;
const TEST: u8 = 4;
const OR: u8 = 5;
const AND: u8 = 6;
const NOT: u8 = 7;
const CMP: u8 = 8;
const EXPR: u8 = 9;
const BOR: u8 = 9;
const BXOR: u8 = 10;
const BAND: u8 = 11;
const SHIFT: u8 = 12;
const ARITH: u8 = 13;
const TERM: u8 = 14;
const FACTOR: u8 = 15;
const POWER: u8 = 16;
const AWAIT: u8 = 17;
const ATOM: u8 = 18;

fn next(p: u8) -> u8 {
    if p >= ATOM {
        ATOM
    } else {
        p + 1
    }
}

const SINGLE_QUOTES: [&str; 2] = ["'", "\""];
const MULTI_QUOTES: [&str; 2] = ["\"\"\"", "'''"];
const ALL_QUOTES: [&str; 4] = ["'", "\"", "\"\"\"", "'''"];
/// The longest int Python writes in decimal (sys.int_info's default limit).
const MAX_INT_DIGITS: usize = 4300;

struct Unparser<'t> {
    t: &'t Tree,
    out: PyStr,
    prec: QuickMap<NodeId, u8>,
    failed: bool,
}

/// The text of expression `node` (None: Python's unparse would raise).
pub fn unparse(t: &Tree, node: NodeId) -> Option<PyStr> {
    if node == NONE {
        return Some(Vec::new());
    }
    let mut p = Unparser { t, out: Vec::new(), prec: QuickMap::default(), failed: false };
    p.traverse(node);
    if p.failed {
        None
    } else {
        Some(p.out)
    }
}

impl<'t> Unparser<'t> {
    fn w(&mut self, s: &str) {
        self.out.extend(s.chars().map(|c| c as u32));
    }

    fn wcp(&mut self, s: &[u32]) {
        self.out.extend_from_slice(s);
    }

    fn get_prec(&self, n: NodeId) -> u8 {
        self.prec.get(&n).copied().unwrap_or(TEST)
    }

    fn set_prec(&mut self, p: u8, n: NodeId) {
        if n != NONE {
            self.prec.insert(n, p);
        }
    }

    fn a(&self, n: NodeId) -> u32 {
        self.t.node(n).f[pt::A as usize]
    }
    fn b(&self, n: NodeId) -> u32 {
        self.t.node(n).f[pt::B as usize]
    }
    fn c(&self, n: NodeId) -> u32 {
        self.t.node(n).f[pt::C as usize]
    }
    fn list(&self, id: u32) -> Vec<u32> {
        self.t.list(id).to_vec()
    }

    /// `(…)` around what `body` writes when `cond`.
    fn delimit_if(&mut self, open: &str, close: &str, cond: bool, body: impl FnOnce(&mut Self)) {
        if cond {
            self.w(open);
        }
        body(self);
        if cond {
            self.w(close);
        }
    }

    fn require_parens(&mut self, p: u8, n: NodeId, body: impl FnOnce(&mut Self)) {
        let cond = self.get_prec(n) > p;
        self.delimit_if("(", ")", cond, body);
    }

    fn interleave_nodes(&mut self, sep: &str, items: &[u32]) {
        for (k, &x) in items.iter().enumerate() {
            if k > 0 {
                self.w(sep);
            }
            self.traverse(x);
        }
    }

    fn items_view(&mut self, items: &[u32]) {
        if items.len() == 1 {
            self.traverse(items[0]);
            self.w(",");
        } else {
            self.interleave_nodes(", ", items);
        }
    }

    fn traverse(&mut self, n: NodeId) {
        if n == NONE || self.failed {
            return;
        }
        let kind = self.t.kind(n);
        match kind {
            Kind::Name => {
                let s = self.t.str(self.a(n)).to_vec();
                self.wcp(&s);
            }
            Kind::Constant => self.constant(n),
            Kind::NamedExpr => {
                self.require_parens(NAMED_EXPR, n, |p| {
                    let (tg, v) = (p.a(n), p.b(n));
                    p.set_prec(ATOM, tg);
                    p.set_prec(ATOM, v);
                    p.traverse(tg);
                    p.w(" := ");
                    p.traverse(v);
                });
            }
            Kind::Await => {
                self.require_parens(AWAIT, n, |p| {
                    p.w("await");
                    let v = p.a(n);
                    if v != NONE {
                        p.w(" ");
                        p.set_prec(ATOM, v);
                        p.traverse(v);
                    }
                });
            }
            Kind::Yield => {
                self.require_parens(YIELD, n, |p| {
                    p.w("yield");
                    let v = p.a(n);
                    if v != NONE {
                        p.w(" ");
                        p.set_prec(ATOM, v);
                        p.traverse(v);
                    }
                });
            }
            Kind::YieldFrom => {
                self.require_parens(YIELD, n, |p| {
                    p.w("yield from ");
                    let v = p.a(n);
                    p.set_prec(ATOM, v);
                    p.traverse(v);
                });
            }
            Kind::JoinedStr => self.joined_str(n),
            Kind::FormattedValue => self.formatted_value(n),
            Kind::List => {
                let elts = self.list(self.a(n));
                self.w("[");
                self.interleave_nodes(", ", &elts);
                self.w("]");
            }
            Kind::ListComp | Kind::GeneratorExp | Kind::SetComp => {
                let (open, close) = match kind {
                    Kind::ListComp => ("[", "]"),
                    Kind::GeneratorExp => ("(", ")"),
                    _ => ("{", "}"),
                };
                self.w(open);
                self.traverse(self.a(n));
                for g in self.list(self.b(n)) {
                    self.traverse(g);
                }
                self.w(close);
            }
            Kind::DictComp => {
                self.w("{");
                self.traverse(self.a(n));
                self.w(": ");
                self.traverse(self.b(n));
                for g in self.list(self.c(n)) {
                    self.traverse(g);
                }
                self.w("}");
            }
            Kind::comprehension => {
                if self.t.node(n).flags & pt::ASYNC != 0 {
                    self.w(" async for ");
                } else {
                    self.w(" for ");
                }
                let target = self.a(n);
                self.set_prec(TUPLE, target);
                self.traverse(target);
                self.w(" in ");
                let iter = self.b(n);
                let ifs = self.list(self.c(n));
                self.set_prec(next(TEST), iter);
                for &i in &ifs {
                    self.set_prec(next(TEST), i);
                }
                self.traverse(iter);
                for i in ifs {
                    self.w(" if ");
                    self.traverse(i);
                }
            }
            Kind::IfExp => {
                self.require_parens(TEST, n, |p| {
                    let (test, body, orelse) = (p.a(n), p.b(n), p.c(n));
                    p.set_prec(next(TEST), body);
                    p.set_prec(next(TEST), test);
                    p.traverse(body);
                    p.w(" if ");
                    p.traverse(test);
                    p.w(" else ");
                    p.set_prec(TEST, orelse);
                    p.traverse(orelse);
                });
            }
            Kind::Set => {
                let elts = self.list(self.a(n));
                if elts.is_empty() {
                    self.w("{*()}");
                } else {
                    self.w("{");
                    self.interleave_nodes(", ", &elts);
                    self.w("}");
                }
            }
            Kind::Dict => {
                let keys = self.list(self.a(n));
                let values = self.list(self.b(n));
                self.w("{");
                for (k, (&key, &v)) in keys.iter().zip(values.iter()).enumerate() {
                    if k > 0 {
                        self.w(", ");
                    }
                    if key == NONE {
                        self.w("**");
                        self.set_prec(EXPR, v);
                        self.traverse(v);
                    } else {
                        self.traverse(key);
                        self.w(": ");
                        self.traverse(v);
                    }
                }
                self.w("}");
            }
            Kind::Tuple => {
                let elts = self.list(self.a(n));
                let cond = elts.is_empty() || self.get_prec(n) > TUPLE;
                self.delimit_if("(", ")", cond, |p| p.items_view(&elts));
            }
            Kind::UnaryOp => {
                let op = self.t.node(n).op;
                let (sym, p) = match op {
                    pt::INVERT => ("~", FACTOR),
                    pt::NOT => ("not", NOT),
                    pt::UADD => ("+", FACTOR),
                    _ => ("-", FACTOR),
                };
                self.require_parens(p, n, |q| {
                    q.w(sym);
                    if p != FACTOR {
                        q.w(" ");
                    }
                    let operand = q.a(n);
                    q.set_prec(p, operand);
                    q.traverse(operand);
                });
            }
            Kind::BinOp => {
                let op = self.t.node(n).op;
                let (sym, p) = match op {
                    pt::ADD => ("+", ARITH),
                    pt::SUB => ("-", ARITH),
                    pt::MULT => ("*", TERM),
                    pt::MATMULT => ("@", TERM),
                    pt::DIV => ("/", TERM),
                    pt::MOD => ("%", TERM),
                    pt::LSHIFT => ("<<", SHIFT),
                    pt::RSHIFT => (">>", SHIFT),
                    pt::BITOR => ("|", BOR),
                    pt::BITXOR => ("^", BXOR),
                    pt::BITAND => ("&", BAND),
                    pt::FLOORDIV => ("//", TERM),
                    _ => ("**", POWER),
                };
                self.require_parens(p, n, |q| {
                    let (lp, rp) = if sym == "**" { (next(p), p) } else { (p, next(p)) };
                    let (l, r) = (q.a(n), q.b(n));
                    q.set_prec(lp, l);
                    q.traverse(l);
                    q.w(" ");
                    q.w(sym);
                    q.w(" ");
                    q.set_prec(rp, r);
                    q.traverse(r);
                });
            }
            Kind::Compare => {
                self.require_parens(CMP, n, |p| {
                    let left = p.a(n);
                    let ops = p.list(p.b(n));
                    let comps = p.list(p.c(n));
                    p.set_prec(next(CMP), left);
                    for &c in &comps {
                        p.set_prec(next(CMP), c);
                    }
                    p.traverse(left);
                    for (&o, &e) in ops.iter().zip(comps.iter()) {
                        let sym = match o as u8 {
                            pt::EQ => "==",
                            pt::NOTEQ => "!=",
                            pt::LT => "<",
                            pt::LTE => "<=",
                            pt::GT => ">",
                            pt::GTE => ">=",
                            pt::IS => "is",
                            pt::ISNOT => "is not",
                            pt::IN => "in",
                            _ => "not in",
                        };
                        p.w(" ");
                        p.w(sym);
                        p.w(" ");
                        p.traverse(e);
                    }
                });
            }
            Kind::BoolOp => {
                let and = self.t.node(n).op == pt::AND;
                let (sym, base) = if and { (" and ", AND) } else { (" or ", OR) };
                self.require_parens(base, n, |p| {
                    let values = p.list(p.a(n));
                    let mut level = base;
                    for (k, &v) in values.iter().enumerate() {
                        if k > 0 {
                            p.w(sym);
                        }
                        level = next(level);
                        p.set_prec(level, v);
                        p.traverse(v);
                    }
                });
            }
            Kind::Attribute => {
                let v = self.a(n);
                self.set_prec(ATOM, v);
                self.traverse(v);
                if self.t.kind(v) == Kind::Constant
                    && matches!(self.t.node(v).op, pt::V_INT | pt::V_TRUE | pt::V_FALSE)
                {
                    self.w(" ");
                }
                self.w(".");
                let attr = self.t.str(self.b(n)).to_vec();
                self.wcp(&attr);
            }
            Kind::Call => {
                let func = self.a(n);
                self.set_prec(ATOM, func);
                self.traverse(func);
                self.w("(");
                let mut comma = false;
                for e in self.list(self.b(n)).into_iter().chain(self.list(self.c(n))) {
                    if comma {
                        self.w(", ");
                    } else {
                        comma = true;
                    }
                    self.traverse(e);
                }
                self.w(")");
            }
            Kind::Subscript => {
                let v = self.a(n);
                self.set_prec(ATOM, v);
                self.traverse(v);
                self.w("[");
                let s = self.b(n);
                let elts = if self.t.kind(s) == Kind::Tuple { self.list(self.a(s)) } else { Vec::new() };
                if !elts.is_empty() {
                    self.items_view(&elts);
                } else {
                    self.traverse(s);
                }
                self.w("]");
            }
            Kind::Starred => {
                self.w("*");
                let v = self.a(n);
                self.set_prec(EXPR, v);
                self.traverse(v);
            }
            Kind::Slice => {
                let (lo, up, st) = (self.a(n), self.b(n), self.c(n));
                if lo != NONE {
                    self.traverse(lo);
                }
                self.w(":");
                if up != NONE {
                    self.traverse(up);
                }
                if st != NONE {
                    self.w(":");
                    self.traverse(st);
                }
            }
            Kind::keyword => {
                let arg = self.a(n);
                if arg == NONE {
                    self.w("**");
                } else {
                    let s = self.t.str(arg).to_vec();
                    self.wcp(&s);
                    self.w("=");
                }
                self.traverse(self.b(n));
            }
            Kind::Lambda => {
                self.require_parens(TEST, n, |p| {
                    p.w("lambda");
                    let mark = p.out.len();
                    p.w(" ");
                    let inner = p.out.len();
                    p.arguments(p.a(n));
                    if p.out.len() == inner {
                        p.out.truncate(mark);
                    }
                    p.w(": ");
                    let body = p.b(n);
                    p.set_prec(TEST, body);
                    p.traverse(body);
                });
            }
            Kind::arg => {
                let s = self.t.str(self.a(n)).to_vec();
                self.wcp(&s);
                let ann = self.b(n);
                if ann != NONE {
                    self.w(": ");
                    self.traverse(ann);
                }
            }
            Kind::arguments => self.arguments(n),
            _ => self.failed = true,
        }
    }

    fn arguments(&mut self, n: NodeId) {
        let t = self.t;
        let node = t.node(n);
        let posonly = t.list(node.f[pt::A as usize]).to_vec();
        let args = t.list(node.f[pt::B as usize]).to_vec();
        let vararg = node.f[pt::C as usize];
        let ext = |i: u8| t.raw(node, pt::At::Ext(i));
        let kwonly = t.list(ext(0)).to_vec();
        let kw_defaults = t.list(ext(1)).to_vec();
        let kwarg = ext(2);
        let defaults = t.list(ext(3)).to_vec();
        let all: Vec<u32> = posonly.iter().chain(args.iter()).copied().collect();
        let mut dflt: Vec<u32> = vec![NONE; all.len().saturating_sub(defaults.len())];
        dflt.extend(defaults.iter().copied());
        let mut first = true;
        for (index, (&a, &d)) in all.iter().zip(dflt.iter()).enumerate() {
            if first {
                first = false;
            } else {
                self.w(", ");
            }
            self.traverse(a);
            if d != NONE {
                self.w("=");
                self.traverse(d);
            }
            if index + 1 == posonly.len() {
                self.w(", /");
            }
        }
        if vararg != NONE || !kwonly.is_empty() {
            if first {
                first = false;
            } else {
                self.w(", ");
            }
            self.w("*");
            if vararg != NONE {
                let s = t.str(t.node(vararg).f[pt::A as usize]).to_vec();
                self.wcp(&s);
                let ann = t.node(vararg).f[pt::B as usize];
                if ann != NONE {
                    self.w(": ");
                    self.traverse(ann);
                }
            }
        }
        for (k, &a) in kwonly.iter().enumerate() {
            self.w(", ");
            self.traverse(a);
            let d = kw_defaults.get(k).copied().unwrap_or(NONE);
            if d != NONE {
                self.w("=");
                self.traverse(d);
            }
        }
        if kwarg != NONE {
            if !first {
                self.w(", ");
            }
            self.w("**");
            let s = t.str(t.node(kwarg).f[pt::A as usize]).to_vec();
            self.wcp(&s);
            let ann = t.node(kwarg).f[pt::B as usize];
            if ann != NONE {
                self.w(": ");
                self.traverse(ann);
            }
        }
    }

    fn constant(&mut self, n: NodeId) {
        let node = *self.t.node(n);
        match node.op {
            pt::V_NONE => self.w("None"),
            pt::V_TRUE => self.w("True"),
            pt::V_FALSE => self.w("False"),
            pt::V_ELLIPSIS => self.w("..."),
            pt::V_STR => {
                if node.flags & pt::KIND_U != 0 {
                    self.w("u");
                }
                let s = self.t.str(node.f[pt::A as usize]);
                let r = crate::findings::py_repr(s);
                self.wcp(&r);
            }
            pt::V_BYTES => {
                let s = self.t.str(node.f[pt::A as usize]).to_vec();
                let r = bytes_repr(&s);
                self.wcp(&r);
            }
            pt::V_INT => {
                let s = self.t.str(node.f[pt::A as usize]);
                if s.len() > MAX_INT_DIGITS || s.starts_with(&[0x30, 0x78]) {
                    self.failed = true; // (repr: "Exceeds the limit (4300 digits) for integer string conversion")
                } else {
                    let s = s.to_vec();
                    self.wcp(&s);
                }
            }
            pt::V_FLOAT => {
                let v = f64::from_bits(node.f[pt::B as usize] as u64 | ((node.f[pt::C as usize] as u64) << 32));
                let r = float_repr(v, false);
                self.w(&r);
            }
            _ => {
                // an imaginary number: 0 plus that float times j
                let v = f64::from_bits(node.f[pt::B as usize] as u64 | ((node.f[pt::C as usize] as u64) << 32));
                let r = float_repr(v, true);
                self.w(&r);
                self.w("j");
            }
        }
    }

    fn joined_str(&mut self, n: NodeId) {
        self.w("f");
        let mut parts: Vec<(PyStr, bool)> = Vec::new();
        for v in self.list(self.a(n)) {
            let saved = std::mem::take(&mut self.out);
            self.fstring_inner(v, false);
            let buf = std::mem::replace(&mut self.out, saved);
            parts.push((buf, self.t.kind(v) == Kind::Constant));
        }
        let mut new_parts: Vec<PyStr> = Vec::new();
        let mut quote_types: Vec<&'static str> = ALL_QUOTES.to_vec();
        let mut fallback = false;
        for (value, is_constant) in &parts {
            if *is_constant {
                let (v, new_qt) = str_literal_helper(value, &quote_types, true);
                if new_qt.iter().all(|q| !quote_types.contains(q)) {
                    fallback = true;
                    break;
                }
                quote_types = new_qt;
                new_parts.push(v);
            } else {
                if value.contains(&0x0A) {
                    quote_types.retain(|q| MULTI_QUOTES.contains(q));
                }
                let new_qt: Vec<&'static str> =
                    quote_types.iter().copied().filter(|q| !contains_str(value, q)).collect();
                if !new_qt.is_empty() {
                    quote_types = new_qt;
                }
                new_parts.push(value.clone());
            }
        }
        if fallback {
            quote_types = vec!["'''"];
            new_parts.clear();
            for (value, is_constant) in &parts {
                if *is_constant {
                    let mut s = vec![0x22];
                    s.extend_from_slice(value);
                    let r = crate::findings::py_repr(&s);
                    // repr('"' + value) starts with '" and ends with '
                    new_parts.push(r[2..r.len() - 1].to_vec());
                } else {
                    new_parts.push(value.clone());
                }
            }
        }
        let quote = quote_types.first().copied().unwrap_or("'");
        self.w(quote);
        for p in &new_parts {
            self.wcp(p);
        }
        self.w(quote);
    }

    fn fstring_inner(&mut self, n: NodeId, is_format_spec: bool) {
        match self.t.kind(n) {
            Kind::JoinedStr => {
                for v in self.list(self.a(n)) {
                    self.fstring_inner(v, is_format_spec);
                }
            }
            Kind::Constant if self.t.node(n).op == pt::V_STR => {
                let s = self.t.str(self.a(n));
                let mut v: PyStr = Vec::with_capacity(s.len());
                for &c in s {
                    if c == 0x7B {
                        v.extend([0x7B, 0x7B]);
                    } else if c == 0x7D {
                        v.extend([0x7D, 0x7D]);
                    } else {
                        v.push(c);
                    }
                }
                if is_format_spec {
                    let mut w: PyStr = Vec::with_capacity(v.len());
                    for c in v {
                        match c {
                            0x5C => w.extend([0x5C, 0x5C]),
                            0x27 => w.extend([0x5C, 0x27]),
                            0x22 => w.extend([0x5C, 0x22]),
                            0x0A => w.extend([0x5C, 0x6E]),
                            _ => w.push(c),
                        }
                    }
                    v = w;
                }
                self.wcp(&v);
            }
            Kind::FormattedValue => self.formatted_value(n),
            _ => self.failed = true,
        }
    }

    fn formatted_value(&mut self, n: NodeId) {
        self.w("{");
        let value = self.a(n);
        let mut inner = Unparser { t: self.t, out: Vec::new(), prec: QuickMap::default(), failed: false };
        inner.set_prec(next(TEST), value);
        inner.traverse(value);
        if inner.failed {
            self.failed = true;
            return;
        }
        if inner.out.first() == Some(&0x7B) {
            self.w(" ");
        }
        let text = inner.out;
        self.wcp(&text);
        let conv = pt::CONVERSIONS.get(self.t.node(n).op as usize).copied().unwrap_or(-1);
        if conv != -1 {
            self.w("!");
            self.out.push(conv as u32);
        }
        let spec = self.b(n);
        if spec != NONE {
            self.w(":");
            self.fstring_inner(spec, true);
        }
        self.w("}");
    }
}

fn contains_str(h: &[u32], needle: &str) -> bool {
    let n: Vec<u32> = needle.chars().map(|c| c as u32).collect();
    !n.is_empty() && h.windows(n.len()).any(|w| w == n.as_slice())
}

/// One character as `unicode_escape` encodes it.
fn unicode_escape(c: u32, out: &mut PyStr) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex = |out: &mut PyStr, c: u32, n: usize| {
        for k in (0..n).rev() {
            out.push(HEX[((c >> (4 * k)) & 0xF) as usize] as u32);
        }
    };
    match c {
        0x09 => out.extend(u("\\t")),
        0x0A => out.extend(u("\\n")),
        0x0D => out.extend(u("\\r")),
        0x5C => out.extend(u("\\\\")),
        _ if c < 0x20 || (0x7F..0x100).contains(&c) => {
            out.extend(u("\\x"));
            hex(out, c, 2);
        }
        _ if c < 0x7F => out.push(c),
        _ if c < 0x10000 => {
            out.extend(u("\\u"));
            hex(out, c, 4);
        }
        _ => {
            out.extend(u("\\U"));
            hex(out, c, 8);
        }
    }
}

/// _Unparser._str_literal_helper: (the text to write, the quotes it may
/// take).
fn str_literal_helper(s: &[u32], quote_types: &[&'static str], escape_special_whitespace: bool) -> (PyStr, Vec<&'static str>) {
    let mut escaped: PyStr = Vec::with_capacity(s.len());
    for &c in s {
        if !escape_special_whitespace && (c == 0x0A || c == 0x09) {
            escaped.push(c);
        } else if c == 0x5C || !crate::unicode::is_printable(c) {
            unicode_escape(c, &mut escaped);
        } else {
            escaped.push(c);
        }
    }
    let mut possible: Vec<&'static str> = quote_types.to_vec();
    if escaped.contains(&0x0A) {
        possible.retain(|q| MULTI_QUOTES.contains(q));
    }
    possible.retain(|q| !contains_str(&escaped, q));
    if possible.is_empty() {
        let r = crate::findings::py_repr(s);
        let first = r[0];
        let quote = quote_types
            .iter()
            .copied()
            .find(|q| q.chars().any(|ch| ch as u32 == first))
            .unwrap_or(if first == 0x22 { "\"" } else { "'" });
        return (r[1..r.len() - 1].to_vec(), vec![quote]);
    }
    if let Some(&last) = escaped.last() {
        // sort so that a quote that is not the last character comes first (stable)
        let (mut no, mut yes): (Vec<&'static str>, Vec<&'static str>) = (Vec::new(), Vec::new());
        for q in possible {
            if q.chars().next().map(|ch| ch as u32) == Some(last) {
                yes.push(q);
            } else {
                no.push(q);
            }
        }
        no.extend(yes);
        possible = no;
        if possible[0].chars().next().map(|ch| ch as u32) == Some(last) {
            escaped.pop();
            escaped.push(0x5C);
            escaped.push(last);
        }
    }
    let _ = SINGLE_QUOTES;
    (escaped, possible)
}

/// repr() of a bytes value (its items as code points below 256).
fn bytes_repr(b: &[u32]) -> PyStr {
    let has_single = b.contains(&0x27);
    let has_double = b.contains(&0x22);
    let quote = if has_single && !has_double { 0x22 } else { 0x27 };
    let mut out: PyStr = vec![0x62, quote];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &c in b {
        if c == quote || c == 0x5C {
            out.push(0x5C);
            out.push(c);
        } else if c == 0x09 {
            out.extend(u("\\t"));
        } else if c == 0x0A {
            out.extend(u("\\n"));
        } else if c == 0x0D {
            out.extend(u("\\r"));
        } else if !(0x20..0x7F).contains(&c) {
            out.extend(u("\\x"));
            out.push(HEX[((c >> 4) & 0xF) as usize] as u32);
            out.push(HEX[(c & 0xF) as usize] as u32);
        } else {
            out.push(c);
        }
    }
    out.push(quote);
    out
}

/// repr() of a float (`imag`: as a complex number's imaginary part, which
/// keeps no ".0"), with ast.unparse's infinities: 1e309 for inf, and
/// (1e309-1e309) for nan.
pub fn float_repr(v: f64, imag: bool) -> String {
    const INF: &str = "1e309";
    if v.is_nan() {
        return format!("({}-{})", INF, INF);
    }
    if v.is_infinite() {
        return if v < 0.0 { format!("-{}", INF) } else { INF.to_string() };
    }
    if v == 0.0 {
        let neg = v.is_sign_negative();
        let body = if imag { "0" } else { "0.0" };
        return if neg { format!("-{}", body) } else { body.to_string() };
    }
    // shortest digits and exponent: d.ddd e x
    let sci = format!("{:e}", v);
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        let decpt = exp + 1; // digits before the point
        if decpt <= 0 {
            out.push_str("0.");
            for _ in 0..(-decpt) {
                out.push('0');
            }
            out.push_str(&digits);
        } else {
            let d = decpt as usize;
            if digits.len() <= d {
                out.push_str(&digits);
                for _ in digits.len()..d {
                    out.push('0');
                }
                if !imag {
                    out.push_str(".0");
                }
            } else {
                out.push_str(&digits[..d]);
                out.push('.');
                out.push_str(&digits[d..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let a = exp.unsigned_abs();
        if a < 10 {
            out.push('0');
        }
        out.push_str(&a.to_string());
    }
    out
}
