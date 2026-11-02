# scripts/rsparse: rustc's answers, for Lazaret's Rust item reader

Added in 0.1.9 (R-2 of `specs/lazaret-sources-and-languages-plan-2026-10-02`). The Rust reader in the engine
(`rust/crates/lazaret-engine/src/rsparse`) finds the items of a Rust file: `fn`, `struct`, `enum`, `union`, `trait`, `impl`,
`mod`, `use`, `extern crate`, `extern { … }`, `static`, `const`, `type`, `macro_rules!` and macro calls in item position,
with their visibility, qualifiers, attributes and spans, and the leaves of the `use` items. It is not a parser of Rust. It is
the item grammar over the tokens of the Rust lexer, and what is inside a body stays tokens for a detector to read. What it must
get right is which items there are and where: a `#[ctor]` function or a `#[proc_macro]` that the scan does not see is a place
to hide code, and a reader that found an item the compiler does not (or missed one it does) is a way to hide it. So the
reference is the compiler's own parser, and this directory holds the tools that hold the reader to it.

| File | What |
|---|---|
| `rustc_items.py` | The oracle. For each file named it runs `RUSTC_BOOTSTRAP=1 rustc -Zunpretty=ast-tree` (the parser's tree, before macro expansion and before `cfg` is applied, which is what the item reader sees), reads the tree's debug text with a small reader of its own, and prints the items in the format of `rsparse_dump` (`== path`, then `item …` and `use …` lines, or `!! message` for a file `rustc` refuses). It runs `rustc` on the file and nothing else: no build script, no macro, no crate. |
| `diff.py` | Compares the oracle's output with the reader's (`cargo build --release --example rsparse_dump`), file by file: which items are in one and not the other (kind, name, start, end) and, for the items in both, visibility, qualifiers, ABI, attributes, parent and the paths of the `use` leaves. A file `rustc` refuses is not compared (the reader is for what compiles); `--refused` says why each was refused. The edition is read from the nearest `Cargo.toml` (none or no `edition`: 2015, as Cargo reads it; `edition.workspace = true`: 2021). Says how many files fell in each case; exits 1 on any difference. Standard library only. |
| `mutate.py` | Makes broken Rust files from good ones (a span deleted, a keyword, an operator, a name or a literal put in, a character replaced, lines deleted, copied or swapped, the text cut short, a NUL, a byte order mark, a carriage return or a non-ASCII letter put in), to compare the two where `rustc` refuses and on the odd shapes that are still Rust. The same seed gives the same files. Standard library only. |

```
cargo build --release --example rsparse_dump                                              # in rust/
find ~/.cargo/registry/src -name '*.rs' | sort > /tmp/rsparse-paths.txt                   # any corpus of crates will do
python3 scripts/rsparse/diff.py --bin rust/target/release/examples/rsparse_dump --jobs 2 --refused --list /tmp/rsparse-paths.txt

python3 scripts/rsparse/mutate.py /tmp/rsparse-paths.txt /tmp/rsparse-mutants --count 6000 --seed 1 --max-size 8000
python3 scripts/rsparse/diff.py --bin rust/target/release/examples/rsparse_dump --jobs 2 --refused --list /tmp/rsparse-mutants/list.txt
```

`rustc` must be nightly or `RUSTC_BOOTSTRAP=1` must be accepted (the oracle sets it); the results below came from rustc 1.97.0.

## What it found

On the 7,468 `.rs` files of 186 crates in a cargo registry cache (63 MB, 325,606 items) the reader finds the same items as
`rustc` in every file: none differs and `rustc` refuses none. The reader takes 0.8 seconds for all of them.

On 18,000 broken variants of those files (`mutate.py`, two seeds: 6,000 and 12,000 files of up to 8,000 bytes) `rustc` still
parses 6,646 and the reader finds the same items in every one of them; `rustc` refuses the other 11,354 (an unclosed delimiter is
the commonest cause, then an unterminated string, a stray closing delimiter and an unknown start of token). One variant differed
in the first pass: an `extern "…"` ABI string that held a DEL character. The difference was in how the two sides wrote the
string, not in what they found, so the ABI is now one word on each side (`%XX` for a space, a control character or `%`) and is
compared as the string it holds.

The oracle itself had four faults the corpus showed, all fixed in `rustc_items.py` and `diff.py` and kept as cases in
`tests/architecture/test_rsparse_scripts.py`: a raw identifier (`r#type`) is the name `type` for the reader and `r#type` in the
tree's text; a file whose name has parentheses (`into_bytes_enum.repr(u8).expected.rs`) broke the span pattern; a path that starts
with `::` (`#[::core::prelude::v1::test]`) is the crate root's `{{root}}`; and a `Cargo.toml` with no `edition` is 2015, not 2021
(`try` is a keyword in 2018 and later, and a name before).

The reader had two gaps the corpus showed (24 of the 7,468 files at first), both fixed and each a test in `rsparse/tests.rs`:
an item inside a group in an item's head (a const-generic block, an array length, a discriminant: `[u8; { struct S; 1 }]`) is an
item the compiler's parser finds, and a `#[ctor]` could hide in one, so the heads of items and the bodies of `struct`, `enum`
and `union` are now read for the items they hold; the item they sit in is the parent.

## What it does not read

The inside of a macro (to the compiler's parser too, its tokens are not code until the macro is expanded), the arguments of an
attribute (`#[doc = { fn f() {} }]`: an item inside an expression in an attribute's argument is one the compiler's parser finds and
this reader does not; it is the one known gap, and the corpus has no file where it shows), and `cfg` (both sides of `#[cfg(…)]` are read, as the parser sees them). A text that is not Rust gives what could be read
of it and a count in `Tree::problems`; the reader never panics, has no `unsafe` and no recursion (a stack on the heap holds the
groups still to be read), and looks at every token a bounded number of times.

## Tests

`cargo test -p lazaret-engine rsparse` (46 tests; they need no `rustc`): the items of small files, every qualifier, `use` trees,
macros in item position, items in bodies and in heads, the hooks (proc-macro, constructors and destructors, load-time
sections, a library's own entry point, a build script's `main`), spans in code points, a text that is not Rust, invariants on
3,000 seeded soups of tokens (every item is inside its parent, in order, with its parts inside it), and nesting 200,000 deep that
costs no stack. `python/tests/architecture/test_rsparse_scripts.py` (46) tests the three scripts here: they never run
`rustc` in the tests (a stand-in prints a tree), and the test reads `rustc_items.py` for what it must not do.
