//! The tree as JSON: each node an object, `_type` (its class), its fields
//! in `_fields` order, then `lineno`, `col_offset`, `end_lineno` and
//! `end_col_offset` for the classes that have them — the columns in UTF-8
//! bytes from the line's start, as Python counts them — and with `spans`,
//! `start` and `end` (code points, every node). A context or an operator is
//! `{"_type": "Load"}`. A Constant's value: null, true, false, a string,
//! `{"bytes": hex}`, `{"int": decimal digits, or "0x" and hex digits past
//! 16384 bits}`, `{"float": float.hex()}`, `{"complex": [real, imag]}`
//! (float.hex() each), `{"Ellipsis": true}`. Compact and ASCII, as
//! `json.dumps` writes them. Written with an explicit stack: a tree may be
//! as deep as its input is long.

use super::tree::*;
use crate::json::write_str;
use std::fmt::Write as _;

enum Task {
    Node(NodeId),
    Fields(NodeId, usize),
    Items(u32, usize, Item),
    Close(NodeId),
}

#[derive(Clone, Copy)]
enum Item {
    Node,
    Str,
    Cmp,
}

/// Line and UTF-8 column of code-point offsets.
pub struct Positions<'a> {
    src: &'a [u32],
    starts: &'a [u32],
    ascii: bool,
    /// UTF-8 bytes before each 64-code-point block (when not ASCII)
    blocks: Vec<u32>,
    hint: std::cell::Cell<usize>,
}

#[inline]
fn width(c: u32) -> u32 {
    match c {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        0x800..=0xFFFF => 3,
        _ => 4,
    }
}

impl<'a> Positions<'a> {
    pub fn new(src: &'a [u32], starts: &'a [u32]) -> Positions<'a> {
        let ascii = src.iter().all(|&c| c < 0x80);
        let mut blocks = Vec::new();
        if !ascii {
            let mut total = 0u32;
            for (i, &c) in src.iter().enumerate() {
                if i % 64 == 0 {
                    blocks.push(total);
                }
                total += width(c);
            }
            blocks.push(total);
        }
        Positions { src, starts, ascii, blocks, hint: std::cell::Cell::new(0) }
    }

    fn utf8_at(&self, at: u32) -> u32 {
        let at = (at as usize).min(self.src.len());
        let b = at / 64;
        let mut n = self.blocks.get(b).copied().unwrap_or(0);
        for &c in &self.src[b * 64..at] {
            n += width(c);
        }
        n
    }

    /// (line, column in UTF-8 bytes) of an offset.
    pub fn at(&self, at: u32) -> (u32, u32) {
        let h = self.hint.get();
        let line = if h < self.starts.len()
            && self.starts[h] <= at
            && (h + 1 >= self.starts.len() || self.starts[h + 1] > at)
        {
            h
        } else {
            self.starts.partition_point(|&s| s <= at).max(1) - 1
        };
        self.hint.set(line);
        let start = self.starts.get(line).copied().unwrap_or(0);
        let col = if self.ascii { at - start } else { self.utf8_at(at) - self.utf8_at(start) };
        (line as u32 + 1, col)
    }
}

/// Python's float.hex().
pub fn float_hex(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f < 0.0 { "-inf".to_string() } else { "inf".to_string() };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    let bits = f.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let mant = bits & ((1u64 << 52) - 1);
    if exp == 0 && mant == 0 {
        return format!("{}0x0.0p+0", sign);
    }
    if exp == 0 {
        return format!("{}0x0.{:013x}p-1022", sign, mant);
    }
    format!("{}0x1.{:013x}p{:+}", sign, mant, exp - 1023)
}

#[inline]
fn push_num(out: &mut String, v: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &d in &buf[i..] {
        out.push(d as char);
    }
}

fn push_type(out: &mut String, name: &str) {
    out.push_str("{\"_type\":\"");
    out.push_str(name);
    out.push_str("\"}");
}

fn write_value(tree: &Tree, n: &Node, out: &mut String) {
    match n.op {
        V_NONE => out.push_str("null"),
        V_TRUE => out.push_str("true"),
        V_FALSE => out.push_str("false"),
        V_ELLIPSIS => out.push_str("{\"Ellipsis\":true}"),
        V_STR => write_str(out, tree.str(n.f[A as usize])),
        V_BYTES => {
            out.push_str("{\"bytes\":\"");
            for &b in tree.str(n.f[A as usize]) {
                let _ = write!(out, "{:02x}", b & 0xFF);
            }
            out.push_str("\"}");
        }
        V_INT => {
            out.push_str("{\"int\":");
            write_str(out, tree.str(n.f[A as usize]));
            out.push('}');
        }
        V_FLOAT | V_COMPLEX => {
            let f = f64::from_bits(n.f[B as usize] as u64 | (n.f[C as usize] as u64) << 32);
            if n.op == V_FLOAT {
                out.push_str("{\"float\":\"");
                out.push_str(&float_hex(f));
                out.push_str("\"}");
            } else {
                out.push_str("{\"complex\":[\"0x0.0p+0\",\"");
                out.push_str(&float_hex(f));
                out.push_str("\"]}");
            }
        }
        _ => out.push_str("null"),
    }
}

/// Writes the tree from `root` into `out`.
pub fn write_tree(tree: &Tree, src: &[u32], spans: bool, out: &mut String) {
    let pos = Positions::new(src, &tree.line_starts);
    let mut stack: Vec<Task> = vec![Task::Node(tree.root)];
    while let Some(task) = stack.pop() {
        match task {
            Task::Node(id) => {
                if id == NONE || id as usize >= tree.nodes.len() {
                    out.push_str("null");
                    continue;
                }
                let n = tree.node(id);
                out.push_str("{\"_type\":\"");
                out.push_str(n.kind.name());
                out.push('"');
                stack.push(Task::Close(id));
                stack.push(Task::Fields(id, 0));
            }
            Task::Close(id) => {
                let n = tree.node(id);
                if n.kind.has_position() {
                    let (l, c) = pos.at(n.start);
                    let (el, ec) = pos.at(n.end);
                    out.push_str(",\"lineno\":");
                    push_num(out, l);
                    out.push_str(",\"col_offset\":");
                    push_num(out, c);
                    out.push_str(",\"end_lineno\":");
                    push_num(out, el);
                    out.push_str(",\"end_col_offset\":");
                    push_num(out, ec);
                }
                if spans {
                    out.push_str(",\"start\":");
                    push_num(out, n.start);
                    out.push_str(",\"end\":");
                    push_num(out, n.end);
                }
                out.push('}');
            }
            Task::Fields(id, i) => {
                let n = tree.node(id);
                let fs = fields(n.kind);
                if i >= fs.len() {
                    continue;
                }
                stack.push(Task::Fields(id, i + 1));
                let fd = fs[i];
                out.push_str(",\"");
                out.push_str(fd.key);
                out.push_str("\":");
                match fd.ty {
                    Ty::Node(at) | Ty::Opt(at) => stack.push(Task::Node(tree.raw(n, at))),
                    Ty::Nodes(at) | Ty::OptNodes(at) => {
                        out.push('[');
                        stack.push(Task::Items(tree.raw(n, at), 0, Item::Node));
                    }
                    Ty::Names(at) => {
                        out.push('[');
                        stack.push(Task::Items(tree.raw(n, at), 0, Item::Str));
                    }
                    Ty::CmpOps(at) => {
                        out.push('[');
                        stack.push(Task::Items(tree.raw(n, at), 0, Item::Cmp));
                    }
                    Ty::Str(at) => write_str(out, tree.str(tree.raw(n, at))),
                    Ty::OptStr(at) => {
                        let s = tree.raw(n, at);
                        if s == NONE {
                            out.push_str("null");
                        } else {
                            write_str(out, tree.str(s));
                        }
                    }
                    Ty::Int(at) => push_num(out, tree.raw(n, at)),
                    Ty::Op(names) => push_type(out, names.get(n.op as usize).copied().unwrap_or("?")),
                    Ty::Conversion => {
                        let _ = write!(out, "{}", CONVERSIONS.get(n.op as usize).copied().unwrap_or(-1));
                    }
                    Ty::Flag(bit) => out.push(if n.flags & bit != 0 { '1' } else { '0' }),
                    Ty::Value => write_value(tree, n, out),
                    Ty::ConstKind => out.push_str(if n.flags & KIND_U != 0 { "\"u\"" } else { "null" }),
                    Ty::Singleton => out.push_str(match n.op {
                        V_TRUE => "true",
                        V_FALSE => "false",
                        _ => "null",
                    }),
                    Ty::Null => out.push_str("null"),
                    Ty::Empty => out.push_str("[]"),
                }
            }
            Task::Items(list, k, item) => {
                let items = tree.list(list);
                if k >= items.len() {
                    out.push(']');
                    continue;
                }
                if k > 0 {
                    out.push(',');
                }
                stack.push(Task::Items(list, k + 1, item));
                match item {
                    Item::Node => stack.push(Task::Node(items[k])),
                    Item::Str => write_str(out, tree.str(items[k])),
                    Item::Cmp => push_type(out, CMPOPS.get(items[k] as usize).copied().unwrap_or("?")),
                }
            }
        }
    }
}

/// `{"error": {"line": n, "reason": "…"}}`.
pub fn write_error(line: u32, reason: &str, out: &mut String) {
    let _ = write!(out, "{{\"error\":{{\"line\":{},\"reason\":", line);
    let cps: Vec<u32> = reason.chars().map(|c| c as u32).collect();
    write_str(out, &cps);
    out.push_str("}}");
}
