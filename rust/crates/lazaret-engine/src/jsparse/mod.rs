//! A JavaScript parser: a port of `lazaret.scanner.jsparse` (jsparse.py,
//! retired in phase 3 of the Rust-first refactor).
//!
//! # What it reads
//!
//! ECMAScript 2025 with JSX and TypeScript — the syntax of .js .mjs .cjs
//! .jsx .ts .tsx .mts .cts files — into an ESTree-shaped tree: the node
//! types and fields acorn uses for JavaScript and acorn-jsx for JSX.
//! TypeScript's types are read and left out, and so are interfaces, type
//! aliases, overload signatures, abstract members and `declare` statements;
//! an enum, a namespace, `import x = require(...)` and `export =` get nodes
//! of their own (TSEnumDeclaration, TSModuleDeclaration, TSImportEquals,
//! TSExportAssignment). Decorators are kept. Flow's annotations in a .js
//! file are read as TypeScript's are. It is a reader for analysis, not a
//! validator: a program it cannot read is a syntax error (a line and a
//! reason), early errors are not checked.
//!
//! For every input it builds exactly the tree jsparse.py built — every
//! node, field, value and line — or fails with the same line and reason
//! (it was held to that node for node until jsparse.py retired; since then
//! python/tests/architecture/test_snapshot_js_parse.py holds its trees to
//! the recorded ones). Where jsparse.py had a bug, this has the same one
//! (see docs/RUST_ENGINE.md, "The JavaScript parser").
//!
//! # The tree
//!
//! An arena ([`Tree`]): `nodes`, a `Vec` of fixed-size [`Node`]s (32
//! bytes) addressed by `u32` ids, in document order (pre-order: a node
//! before its children, children in field order; `tree.root` is 0, the
//! Program). A node holds its [`Kind`] (the ESTree type), its `line` (as
//! jsparse.py gives it), `start` and `end` (code-point offsets, half-open:
//! `start` is where the token the line is taken from starts, `end` is past
//! the node's last token), and four field slots whose meaning each kind
//! gives in one table, [`tree::fields`]: for each kind, its fields in
//! jsparse.py's order, each a key (`"test"`, `"params"` …) and a type —
//! a child (`Node`/`Opt`, NONE for null), a list (`List`, or `Holes` where
//! items may be NONE: an array's holes), a string, a flag bit, an
//! enumeration (`op`: a VariableDeclaration's kind, an operator …).
//! Walking: [`Tree::each_child`] (children in order), [`Tree::child`],
//! [`Tree::children_of`] and [`Tree::text_of`] by field key, or the slots
//! directly (`tree::slot(kind, key)`), and [`Tree::parents`]. Lists live in
//! `lists` (a list id is the index of its length, the items follow; list 0
//! is empty). Strings — names, cooked string values, numbers' and
//! regexes' text, templates' raw text — are interned in `strings`: equal
//! names have equal ids, so a later pass compares names by id. A cooked
//! string is code points, as the engine's PyStr: lone surrogates are kept,
//! and an escaped surrogate pair is the one character it encodes.
//!
//! The trees can be as deep as their input is long (member and call chains,
//! binary operators and `else if` chains are read in loops, and nest):
//! walk them with an explicit stack, as [`out::write_tree`] and
//! [`Tree::compact`] do.
//!
//! # Limits
//!
//! Linear time. The parser reads one token at a time; speculative reads (an
//! arrow function's return type, TypeScript's type arguments in an
//! expression, a generic arrow function) consume at most
//! [`SPECULATION_TOKENS`] tokens each, and all of a file's together at most
//! [`SPECULATION_TOTAL`] plus 2 per code point (past that a read ahead
//! fails, as one that does not fit does). A token, comment or blank run of
//! 48 code points or more is scanned once and kept by its start, so a read
//! ahead that crosses it again costs nothing more. Nesting deeper than
//! [`MAX_DEPTH`] (statements, expressions, types, JSX) is an error,
//! "nesting too deep": the recursion is bounded by it, and fits a 1 MiB
//! stack (in WebAssembly on Node's main thread every construct reads to 3.8
//! times the bound: docs/RUST_ENGINE.md §12). No input panics: every input
//! gives a tree or an error.

pub mod expr;
pub mod out;
pub mod parser;
pub mod scan;
pub mod tree;
pub mod types;

pub use parser::{MAX_DEPTH, SPECULATION_TOKENS, SPECULATION_TOTAL};
pub use tree::{Kind, Node, NodeId, Tree, NONE};

/// A program the parser cannot read: jsparse.py's JsSyntaxError. Line 0
/// where it is none: jsparse.py's KeyError (docs/RUST_ENGINE.md §12), or a
/// text of `parser::MAX_LEN` code points or more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub line: u32,
    pub reason: Vec<u32>,
}

/// The Program of `src` (its nodes in document order), or the error.
pub fn parse(src: &[u32], ts: bool, jsx: bool) -> Result<Tree, SyntaxError> {
    parse_with(src, ts, jsx, !ts)
}

/// parse(), `<!--` opening a line comment (JavaScript's reading) or read as
/// `<` `!` `--` (tsc's, and a module's by the standard): parser.rs, skip().
pub fn parse_with(src: &[u32], ts: bool, jsx: bool, html_open: bool) -> Result<Tree, SyntaxError> {
    match parser::parse_with(src, ts, jsx, html_open) {
        parser::Outcome::Tree(t) => Ok(t.compact()),
        parser::Outcome::Error(line, reason) => Err(SyntaxError { line, reason }),
    }
}

/// (TypeScript, JSX) for a file name, as jsparse.dialect gives it.
pub fn dialect(path: &[u32]) -> (bool, bool) {
    let ends = |suffix: &str| {
        let s: Vec<u32> = suffix.chars().map(|c| c as u32).collect();
        path.len() >= s.len()
            && path[path.len() - s.len()..]
                .iter()
                .zip(&s)
                .all(|(&a, &b)| (if (0x41..=0x5A).contains(&a) { a + 32 } else { a }) == b)
    };
    if ends(".ts") || ends(".mts") || ends(".cts") {
        (true, false)
    } else if ends(".tsx") {
        (true, true)
    } else {
        (false, true)
    }
}

/// parse() in the dialect of the file name.
pub fn parse_file(path: &[u32], src: &[u32]) -> Result<Tree, SyntaxError> {
    let (ts, jsx) = dialect(path);
    parse(src, ts, jsx)
}

/// The tree as JSON (jsparse.py's nodes; `spans`: each node's start and
/// end too), or `{"error": {"line": n, "reason": "…"}}`.
pub fn to_json(src: &[u32], ts: bool, jsx: bool, spans: bool) -> String {
    let mut out = String::new();
    match parser::parse(src, ts, jsx) {
        parser::Outcome::Tree(t) => {
            out.reserve(src.len() * 8);
            out::write_tree(&t, t.root, spans, &mut out);
        }
        parser::Outcome::Error(line, reason) => out::write_error(line, &reason, &mut out),
    }
    out
}

#[cfg(test)]
pub(crate) mod tests;
