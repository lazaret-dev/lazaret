//! Go's syntax, read as `go/parser` reads it (0.1.9, G-2).
//!
//! [`parse`] takes the code points of a Go file and gives the tree `go/parser` (Go 1.24, `SkipObjectResolution`)
//! builds for it, or the first thing it would refuse the file for: a file is accepted exactly when `go/parser`
//! accepts it (`scripts/goparse/astdump.go` is the reference, and the differential driver compares every node of
//! every file of the Go distribution's source and tests). Comments are skipped, so there are no comment groups, no
//! doc and no line comments.
//!
//! The tree is an arena ([`Tree`]): nodes in a `Vec`, each [`Node`] with its kind, its span (code-point offsets: the
//! `Pos()` and `End()` of `go/ast`) and four slots, A to D, that hold what `go/ast` names for the kind (below); a slot
//! is a node id, a list id (a list is read with [`Tree::items`]) or [`NONE`]. [`Tree::each_child`] visits the
//! children in `ast.Inspect`'s order and [`Tree::preorder`] visits the tree without recursion (a tree can be as
//! deep as its text is long: `a.b.c…`, `x + x + …`, `if … else if …`). No node of an accepted file is a `Bad*`.
//!
//! | kind | A | B | C | D | other |
//! |---|---|---|---|---|---|
//! | `File` | Name | Decls (list) | | | |
//! | `GenDecl` | Specs (list) | | | | `op` the keyword; `PAREN` |
//! | `FuncDecl` | Recv (`FieldList`) | Name | Type (`FuncType`) | Body | |
//! | `ImportSpec` | Name | Path | | | |
//! | `ValueSpec` | Names (list) | Type | Values (list) | | |
//! | `TypeSpec` | Name | TypeParams (`FieldList`) | Type | | `ALIAS` |
//! | `Field` | Names (list) | Type | Tag | | |
//! | `FieldList` | Fields (list) | | | | `DELIMITED` |
//! | `Ident`, `BasicLit`, `EmptyStmt` | | | | | `BasicLit`: `op` the literal's token; `EmptyStmt`: `IMPLICIT` |
//! | `Ellipsis` | Elt | | | | |
//! | `FuncLit` | Type | Body | | | |
//! | `CompositeLit` | Type | Elts (list) | | | |
//! | `ParenExpr`, `StarExpr`, `ExprStmt`, `DeclStmt`, `GoStmt` (Call), `DeferStmt` (Call), `SelectStmt` (Body) | X | | | | |
//! | `UnaryExpr` | X | | | | `op` the operator |
//! | `BinaryExpr` | X | Y | operator's position | | `op` the operator |
//! | `SelectorExpr` | X | Sel | | | |
//! | `IndexExpr` | X | Index | | | |
//! | `IndexListExpr` | X | Indices (list) | | | |
//! | `SliceExpr` | X | Low | High | Max | `SLICE3` |
//! | `TypeAssertExpr` | X | Type (none for `x.(type)`) | | | |
//! | `CallExpr` | Fun | Args (list) | `(`'s position | | `ELLIPSIS` |
//! | `KeyValueExpr` | Key | Value | | | |
//! | `ArrayType` | Len | Elt | | | |
//! | `StructType`, `InterfaceType` | Fields, Methods (`FieldList`) | | | | |
//! | `FuncType` | TypeParams | Params | Results | | |
//! | `MapType` | Key | Value | | | |
//! | `ChanType` | Value | `<-`'s position or `NONE` | | | `op` the direction (`CHAN_*`) |
//! | `LabeledStmt` | Label | Stmt | | | |
//! | `SendStmt` | Chan | Value | | | |
//! | `IncDecStmt` | X | | | | `op` `++` or `--` |
//! | `AssignStmt` | Lhs (list) | Rhs (list) | | | `op` the operator |
//! | `ReturnStmt`, `BlockStmt` | Results, List (list) | | | | |
//! | `BranchStmt` | Label | | | | `op` the keyword |
//! | `IfStmt` | Init | Cond | Body | Else | |
//! | `CaseClause` | Exprs (list) | Body (list) | | | |
//! | `SwitchStmt` | Init | Tag | Body | | |
//! | `TypeSwitchStmt` | Init | Assign | Body | | |
//! | `CommClause` | Comm | Body (list) | | | |
//! | `ForStmt` | Init | Cond | Post | Body | |
//! | `RangeStmt` | Key | Value | X | Body | `op` `:=`, `=` or none (`for range x`) |
//!
//! Slots that hold a position, not a child, are the ones marked so in the table; nothing visits them.
//!
//! Depth is bounded ([`MAX_DEPTH`]: statements, expressions, types and composite literals nested): deeper is an
//! error, "exceeded max nesting depth" (`go/parser` has the same check at 100,000). Chains cost no depth: they are
//! loops. Time and memory are linear in the text: every token is read once, and no parse function reads a token
//! twice.
//!
//! `parse` never panics and has no `unsafe`; the one thing it does not bound is the node count, which is at most a
//! small multiple of the number of tokens.
//!
//! The arena also holds a few nodes the parser made and then replaced (the `ExprStmt` of an `if` condition, the one
//! that is read as a statement and turns out to be an expression); nothing reaches them, so read the tree with
//! [`Tree::preorder`] or [`Tree::each_child`], not by walking `nodes`.

pub mod out;
pub mod parser;
pub mod scan;
pub mod tree;

pub use parser::{parse, Error, MAX_DEPTH, MAX_LEN};
pub use tree::{Kind, Node, NodeId, Tree, NONE};

#[cfg(test)]
mod tests;
