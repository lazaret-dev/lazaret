//! Rust's items, read for the detectors (0.1.9, R-2).
//!
//! [`parse`] takes the code points of a Rust file and gives its items ([`Tree::items`]): `fn`, `struct`, `enum`,
//! `union`, `trait`, `impl`, `mod`, `use`, `extern crate`, `extern { … }`, `static`, `const`, `type`, `macro_rules!`
//! and macro calls in item position, each with its kind, name, visibility, qualifiers, attributes, its span (code
//! point offsets: the span `rustc` gives the item, outer attributes not included) and the braces of its body, and
//! the leaves of the `use` items, one per name brought in. Items in a function's body, in a block and in an
//! initializer are found too ([`LOCAL`]). What is inside a body is tokens ([`Tree::toks`], with the delimiter pairs
//! in [`Tree::mate`]) for a detector to read as it likes; a macro's tokens are never read as code.
//!
//! It is not a parser of Rust, which this crate needs nothing of: it is the item grammar over the tokens of
//! [`crate::lex::rs`], held to `rustc` by a differential driver (`scripts/rsparse/`: for every file of a corpus of
//! crates, the items `rustc -Zunpretty=ast-tree` prints and the items found here are compared: kind, name, start,
//! end, visibility, qualifiers, attributes, the paths of the `use` leaves).
//!
//! What it does not read: the inside of a macro (to the compiler's parser too, its tokens are not code until the macro
//! is expanded) and the arguments of attributes. A `struct`'s fields, an `enum`'s variants, a function's parameters and
//! the types are not items, but the groups in them are read for the items they hold, as the compiler's parser sees them:
//! `[u8; { struct S; 1 }]`, `Foo<{ fn f() {} 1 }>` and `A = { fn f() {} 1 }` hold an item each, found with the
//! item they are in for its parent. A text that is not Rust gives what could be read of it and a count in
//! [`Tree::problems`] (the head of an item cut off by an unclosed group is not read for items); `parse` never panics,
//! has no `unsafe` and uses no recursion (a stack on the heap holds the groups still to be read), and every token is
//! looked at a bounded number of times.

pub mod hooks;
pub mod out;
pub mod parser;
pub mod tree;

pub use hooks::{hooks, Hook, HookKind};
pub use parser::{parse, MAX_LEN, MAX_USE_SEGS};
pub use tree::{Attr, Item, Kind, Tree, UseLeaf, Vis, NONE};
pub use tree::{ASYNC, AUTO, CONST, CUT, DEFAULT, EXTERN, LOCAL, MUT, NEGATIVE, SAFE, UNSAFE};

#[cfg(test)]
mod tests;
