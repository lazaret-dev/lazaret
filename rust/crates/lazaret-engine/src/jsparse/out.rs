//! The tree as JSON: jsparse.py's nodes, key for key and in their order
//! (`type`, `line`, then each kind's fields), compact and ASCII as
//! `json.dumps` writes them; with `spans`, each node's `start` and `end`
//! after its `line`. Written with an explicit stack: a tree may be as deep
//! as its input is long (`a.b.c…`, `x + x + …`, `if … else if …`).

use super::scan::LITERALS;
use super::tree::*;
use crate::json::write_str;
use std::fmt::Write as _;

enum Task {
    Node(NodeId),
    Fields(NodeId, usize),
    Items(u32, usize),
}

/// Writes the tree from `root` into `out`.
pub fn write_tree(tree: &Tree, root: NodeId, spans: bool, out: &mut String) {
    let mut stack: Vec<Task> = vec![Task::Node(root)];
    while let Some(task) = stack.pop() {
        match task {
            Task::Node(id) => {
                if id == NONE {
                    out.push_str("null");
                    continue;
                }
                let n = tree.node(id);
                out.push_str("{\"type\":\"");
                out.push_str(n.kind.name());
                out.push_str("\",\"line\":");
                push_num(out, n.line);
                if spans {
                    out.push_str(",\"start\":");
                    push_num(out, n.start);
                    out.push_str(",\"end\":");
                    push_num(out, n.end);
                }
                stack.push(Task::Fields(id, 0));
            }
            Task::Fields(id, i) => {
                let n = tree.node(id);
                let fields = fields(n.kind);
                if i >= fields.len() {
                    out.push('}');
                    continue;
                }
                stack.push(Task::Fields(id, i + 1));
                let fd = fields[i];
                let key = |out: &mut String| {
                    out.push_str(",\"");
                    out.push_str(fd.key);
                    out.push_str("\":");
                };
                match fd.ty {
                    Ty::Node(s) | Ty::Opt(s) => {
                        key(out);
                        stack.push(Task::Node(n.f[s as usize]));
                    }
                    Ty::List(s) | Ty::Holes(s) => {
                        key(out);
                        out.push('[');
                        stack.push(Task::Items(n.f[s as usize], 0));
                    }
                    Ty::Decorators => {
                        let d = n.f[D as usize];
                        if d != NONE {
                            key(out);
                            out.push('[');
                            stack.push(Task::Items(d, 0));
                        }
                    }
                    Ty::Str(s) => {
                        key(out);
                        write_str(out, tree.str(n.f[s as usize]));
                    }
                    Ty::Flag(bit) => {
                        key(out);
                        out.push_str(if n.flags & bit != 0 { "true" } else { "false" });
                    }
                    Ty::Op(names) => {
                        key(out);
                        out.push('"');
                        out.push_str(names.get(n.op as usize).copied().unwrap_or(""));
                        out.push('"');
                    }
                    Ty::Operator => {
                        key(out);
                        let op: Vec<u32> = LITERALS.get(n.op as usize).copied().unwrap_or("").chars().map(|c| c as u32).collect();
                        write_str(out, &op);
                    }
                    Ty::Null => {
                        key(out);
                        out.push_str("null");
                    }
                    Ty::False => {
                        key(out);
                        out.push_str("false");
                    }
                    Ty::Exported => {
                        if n.flags & EXPORTED != 0 {
                            key(out);
                            out.push_str("true");
                        }
                    }
                    Ty::LitValue => {
                        key(out);
                        match n.op {
                            L_BOOLEAN => out.push_str(if n.flags & VALUE != 0 { "true" } else { "false" }),
                            L_NULL => out.push_str("null"),
                            _ => write_str(out, tree.str(n.f[A as usize])),
                        }
                    }
                    Ty::LitFlags => {
                        if n.op == L_REGEX {
                            key(out);
                            write_str(out, tree.str(n.f[B as usize]));
                        }
                    }
                }
            }
            Task::Items(list, k) => {
                let items = tree.list(list);
                if k >= items.len() {
                    out.push(']');
                    continue;
                }
                if k > 0 {
                    out.push(',');
                }
                stack.push(Task::Items(list, k + 1));
                stack.push(Task::Node(items[k]));
            }
        }
    }
}

/// A number's decimal digits.
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

/// `{"error": {"line": n, "reason": "…"}}`.
pub fn write_error(line: u32, reason: &[u32], out: &mut String) {
    let _ = write!(out, "{{\"error\":{{\"line\":{},\"reason\":", line);
    write_str(out, reason);
    out.push_str("}}");
}
