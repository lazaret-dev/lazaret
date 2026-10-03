//! The tree as text: one line per node, `Kind start end`, in the order `ast.Inspect` visits them. This is what
//! `scripts/goparse/astdump.go` prints for `go/parser`'s tree, so the two are compared line by line.

use super::tree::*;

/// Appends `Kind start end` and a newline for every node reachable from the root.
pub fn write_nodes(tree: &Tree, out: &mut String) {
    use std::fmt::Write as _;
    tree.preorder(|id| {
        let n = tree.node(id);
        let _ = writeln!(out, "{} {} {}", n.kind.name(), n.start, n.end);
    });
}
