//! The items as text: one line per item, in the order they are written, then the `use` leaves. This is what
//! `scripts/rsparse/rustc_items.py` prints for `rustc`'s own tree (`-Zunpretty=ast-tree`), so the two are compared
//! line by line.
//!
//! ```text
//! item <n> <Kind> <name|-> <start> <end> <vis> <parent|-> <flags> <abi|-> <attrs|-> <inner|->
//! use <n> <path> [as <alias>]
//! crate <paths of the crate's inner attributes>
//! ```
//!
//! `vis` is `inherited`, `pub` or `restricted`; `flags` the letters `u` unsafe, `a` async, `c` const, `e` extern,
//! `d` default, `t` auto, `s` safe, `m` mut, `n` negative impl, or `-`; `abi` the ABI's string as written, with its
//! quotes (a space, a control character and `%` in it are written `%XX`, so that a line stays one line and a field one
//! word); `attrs` and `inner` the paths of the outer and the inner attributes, comma separated.

use super::tree::*;

fn flag_letters(f: u16) -> String {
    let mut s = String::new();
    for (bit, c) in [(UNSAFE, 'u'), (ASYNC, 'a'), (CONST, 'c'), (EXTERN, 'e'), (DEFAULT, 'd'), (AUTO, 't'), (SAFE, 's'), (MUT, 'm'), (NEGATIVE, 'n')] {
        if f & bit != 0 {
            s.push(c);
        }
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// `s` as one word of a line: whitespace, control characters and `%` become `%XX`, one for each byte.
fn word(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for c in s.chars() {
        if c.is_whitespace() || c.is_control() || c == '%' {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{:02X}", b);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn paths(tree: &Tree, src: &[u32], attrs: &[Attr]) -> String {
    if attrs.is_empty() {
        return "-".to_string();
    }
    attrs.iter().map(|a| tree.attr_path(src, a)).collect::<Vec<_>>().join(",")
}

/// Appends the item lines and the use lines of `tree`.
pub fn write_items(tree: &Tree, src: &[u32], out: &mut String) {
    use std::fmt::Write as _;
    for (n, it) in tree.items.iter().enumerate() {
        let name = if it.name == NONE { "-".to_string() } else { tree.ident(src, it.name) };
        let vis = match it.vis {
            Vis::Inherited => "inherited",
            Vis::Pub => "pub",
            Vis::Restricted => "restricted",
        };
        let parent = if it.parent == NONE { "-".to_string() } else { it.parent.to_string() };
        let abi = if it.abi == NONE { "-".to_string() } else { word(&tree.text(src, it.abi)) };
        let _ = writeln!(
            out,
            "item {} {} {} {} {} {} {} {} {} {} {}",
            n,
            it.kind.name(),
            name,
            it.start,
            it.end,
            vis,
            parent,
            flag_letters(it.flags),
            abi,
            paths(tree, src, tree.attrs_of(n)),
            paths(tree, src, tree.inner_attrs_of(n)),
        );
    }
    for l in &tree.leaves {
        let alias = if l.alias == NONE { String::new() } else { format!(" as {}", tree.ident(src, l.alias)) };
        let _ = writeln!(out, "use {} {}{}", l.item, tree.leaf_path(src, l), alias);
    }
    let (first, count) = tree.crate_attrs;
    if count > 0 {
        let attrs = &tree.attrs[first as usize..(first + count) as usize];
        let _ = writeln!(out, "crate {}", paths(tree, src, attrs));
    }
}
