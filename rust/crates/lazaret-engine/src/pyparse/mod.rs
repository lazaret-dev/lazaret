//! A Python parser: source text in, the tree Python 3.13's `ast.parse`
//! builds out (or the error it raises).
//!
//! # What it reads
//!
//! Everything Python 3.13 reads (its grammar, its tokenizer): PEP 701
//! f-strings (nested quotes, comments and backslashes in replacement fields,
//! `=` and `!r` and nested format specifiers), `match` and its patterns,
//! `type` aliases and type parameters (bounds, defaults, `*Ts`, `**P`),
//! `except*`, the walrus, positional-only parameters, any decorator
//! expression, the soft keywords, async forms, star expressions. For every
//! input it builds the tree `ast.parse(source)` builds — every node, field
//! and value, `lineno`, `col_offset`, `end_lineno` and `end_col_offset` —
//! or fails where Python raises (SyntaxError, IndentationError, TabError,
//! the ValueError of a NUL, RecursionError or MemoryError for nesting;
//! python/tests/architecture/test_pyparse_native*.py hold it to that, node
//! for node). Python 2 is refused as Python refuses it. Only what
//! `ast.parse` checks is checked: `return` outside a function, `nonlocal`
//! at the top level or a starred assignment target alone are trees, as
//! there (the compiler refuses them later).
//!
//! The text is code points, as the engine's PyStr: a lone surrogate or a
//! value past U+10FFFF is refused (Python cannot encode such a str for its
//! tokenizer), as is a NUL. A coding declaration is not read (`ast.parse`
//! of a str ignores it), and neither is a byte order mark (U+FEFF is not
//! allowed in Python source given as a str).
//!
//! # The tree
//!
//! An arena ([`Tree`], `tree.rs`), as the JavaScript parser's: `nodes`, a
//! `Vec` of 28-byte [`Node`]s addressed by `u32` ids, in document order
//! (pre-order, children in field order: `tree.root` is 0, the Module). A
//! node holds its [`Kind`] (the `ast` class), `start` and `end` (code-point
//! offsets, half-open: where its first token starts, past its last), a
//! small enumeration `op` (an expression's context, an operator, a
//! conversion, a constant's type), `flags` (`is_async`, `simple`, a
//! constant's `kind`), and four slots whose meaning one table gives,
//! [`tree::fields`]: each kind's fields in `_fields` order, each a name and
//! a type — a child, a child or None, a list (of nodes; of nodes or Nones
//! for a Dict's keys and `kw_defaults`; of strings; of comparison
//! operators), a string, an int, a flag, an enumeration — and where it is
//! kept: a slot, or (FunctionDef, AsyncFunctionDef, ClassDef and arguments
//! have more fields than slots) an item of the node's extension list, whose
//! id slot D holds. Walking: [`Tree::each_child`] (children in order),
//! [`Tree::child`], [`Tree::children_of`] and [`Tree::text_of`] by field
//! name, [`Tree::raw`] by place, [`Tree::parents`]. Lists live in `lists`
//! (a list id is the index of its length, the items follow; list 0 is
//! empty). Strings are interned in `strings`: names (NFKC, as Python
//! normalizes identifiers), string and bytes values (code points: a lone
//! surrogate from `\ud800` is kept; bytes below 256), ints as their decimal
//! digits (in hexadecimal, `0x…`, past 16,384 bits: converting a longer
//! hexadecimal literal to decimal would take quadratic time). Equal names
//! have equal ids, which scope resolution can compare. A float's (or an
//! imaginary number's) value is its f64, its bits in two slots.
//! `line_starts` gives each line's start (a line ends at "\r\n", "\r" or
//! "\n", as Python reads source text): the JSON writer turns spans into
//! Python's lines and UTF-8 byte columns with it.
//!
//! A tree can be as deep as its input is long (chains of binary operators,
//! attributes, calls, subscripts): walk it with an explicit stack, as the
//! writer and [`Tree::compact`] do.
//!
//! # Limits
//!
//! Python's, so that what it refuses for nesting is refused here
//! (`limits.rs`): 200 open brackets, 99 indentation levels, 149 nested
//! f-strings, 2 nested format specifiers (the tokenizer's); its parser's
//! stack of 6000 rule calls, followed by an estimate of what each construct
//! costs there (`limits::MAX_LEVEL`); a tree 9,997 nodes deep at most (what
//! Python converts to objects). The parser's own recursion follows
//! brackets, blocks and f-strings only — chains without brackets (unary
//! operators, `**`, lambda bodies, conditional expressions, `elif`) are
//! loops —, so the deepest input it accepts takes a small, bounded stack.
//! Linear time: the tokens are read once (the parenthesized items of a
//! `with` at most twice); a `\N{…}` name is found by binary search. No
//! input panics: every input gives a tree or an error.

pub mod expr;
pub mod lexer;
pub mod limits;
pub mod literal;
pub mod out;
pub mod parser;
pub mod pattern;
pub mod tree;
pub mod unicode;
#[rustfmt::skip]
pub mod unidata;

pub use tree::{Kind, Node, NodeId, Tree, NONE};

/// What Python refuses: the line (1-based) and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub line: u32,
    pub reason: String,
}

/// The longest text read (offsets, ids and lengths are u32).
pub const MAX_LEN: usize = (u32::MAX / 4) as usize;

/// The Module of `src` (its nodes in document order), or the error.
pub fn parse(src: &[u32]) -> Result<Tree, SyntaxError> {
    if src.len() > MAX_LEN {
        return Err(SyntaxError { line: 0, reason: "the text is too long".to_string() });
    }
    let lexed = match lexer::tokenize(src) {
        Ok(l) => l,
        Err((line, reason)) => return Err(SyntaxError { line, reason }),
    };
    let mut p = parser::Parser::new(src, lexed);
    match p.module() {
        Ok(root) => {
            p.tree.root = root;
            let tree = std::mem::take(&mut p.tree);
            let (tree, depth) = tree.compact();
            if depth > limits::MAX_DEPTH {
                // (Python's RecursionError: no line)
                return Err(SyntaxError { line: 0, reason: "maximum recursion depth exceeded during ast construction".to_string() });
            }
            Ok(tree)
        }
        Err(_) => {
            let (line, reason) = p.error();
            Err(SyntaxError { line, reason })
        }
    }
}

/// The tree as JSON (`out.rs`; `spans`: each node's `start` and `end`
/// too), or `{"error": {"line": n, "reason": "…"}}`.
pub fn to_json(src: &[u32], spans: bool) -> String {
    let mut out = String::new();
    match parse(src) {
        Ok(tree) => {
            out.reserve(src.len() * 8);
            out::write_tree(&tree, src, spans, &mut out);
        }
        Err(e) => out::write_error(e.line, &e.reason, &mut out),
    }
    out
}

#[cfg(test)]
mod tests;
