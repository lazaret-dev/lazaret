# scripts/goparse: go/parser's answers, for Lazaret's Go parser

Added in 0.1.9 (G-2 of `specs/lazaret-sources-and-languages-plan-2026-10-02`). The Go parser in the engine
(`rust/crates/lazaret-engine/src/goparse`) reads a Go file as `go/parser` reads it: it accepts exactly the files
`go/parser` accepts, and gives the same tree. A parser that read Go differently would be a way to hide code from the
scan (a file the compiler builds that the scan cannot read, or reads as something else), so the reference is Go's own
parser, and this directory holds the tools that hold the port to it.

| File | What |
|---|---|
| `astdump.go` | The oracle: a Go program over `go/parser` and `go/ast` (standard library only). For each file named on the command line (or listed on the standard input) it prints `== path`, then one line per node, `Kind start end`, in the order `ast.Inspect` visits them, with offsets counted in code points; a file `go/parser` refuses prints `!! first error`. It parses with `SkipObjectResolution`, as the port does, and it opens no connection and runs no program. |
| `diff.py` | Compares the oracle's output with the port's (`cargo run --release --example goparse_dump`, same format), file by file: both refuse, or both accept and agree on every node's kind and span. Says how many files fell in each case; exits 1 on any difference. Standard library only. |
| `mutate.py` | Makes broken Go files from good ones (a span deleted, a keyword, an operator or a literal put in, a character replaced, lines deleted, copied or swapped, the text cut short, a NUL, a byte order mark, a carriage return or a non-ASCII letter put in), to compare the two parsers where they refuse and on the odd shapes that are still Go. The same seed gives the same files. Standard library only. |

```
go build -o /tmp/goparse-bin/astdump scripts/goparse/astdump.go                      # go 1.24 (the version the results below came from)
cargo build --release --example goparse_dump                                         # in rust/
cd "$(go env GOROOT)" && find src test -name '*.go' | sort > /tmp/goparse-paths.txt
/tmp/goparse-bin/astdump < /tmp/goparse-paths.txt > /tmp/goparse-oracle.txt
rust/target/release/examples/goparse_dump < /tmp/goparse-paths.txt > /tmp/goparse-mine.txt
python3 scripts/goparse/diff.py /tmp/goparse-oracle.txt /tmp/goparse-mine.txt         # from the same directory: the paths are relative

python3 scripts/goparse/mutate.py /tmp/goparse-paths.txt /tmp/goparse-mutants --count 50000 --seed 7 --max-size 8000 --root "$(go env GOROOT)"
/tmp/goparse-bin/astdump < /tmp/goparse-mutants/list.txt > /tmp/goparse-m-oracle.txt
rust/target/release/examples/goparse_dump < /tmp/goparse-mutants/list.txt > /tmp/goparse-m-mine.txt
python3 scripts/goparse/diff.py /tmp/goparse-m-oracle.txt /tmp/goparse-m-mine.txt
```

## What it found

On the source and tests of Go 1.24.7 (10,368 files), the port gives `go/parser`'s tree for 10,245, both refuse the 122
files that do not parse (`test/` holds many on purpose), and one file is refused by the port alone: it nests deeper
than 256 (`test/fixedbugs/issue29312.go`), which is the port's own limit (below). Not one node differs. The
port reads the whole corpus in 1.7 seconds.

On about 430,000 mutants of those files (eight seeds of 50,000, and 30,000 more after the last change to the parser) the two
agree on every one that does not nest past the limit. The mutants are what found the places the port had been
reading differently from `go/parser`, all now fixed and each in `tests.rs`'s accepted or refused cases: a NUL or a byte
order mark inside a comment or a string (`go/scanner` refuses them there too), `//line` directives (a
malformed one is an error, and only when it starts a line), and a carriage return in a raw string (`go/ast` counts it out of
the literal's end, so the oracle is given the file with each carriage return made a space).

## The one difference, on purpose

`go/parser` refuses a file nested more than 100,000 deep; the port refuses at 256 (`goparse::MAX_DEPTH`: statements,
expressions, types and composite literals nested), "exceeded max nesting depth", because the engine reads untrusted files
on a stack of 1 MiB to 8 MiB and a limit that the stack cannot reach is no limit. Chains (`a.b.c…`, `x + x + …`,
`if … else if …`, `f()()()…`) cost no depth: they are loops, and the tree is read by a loop too. `diff.py` counts a file
refused for depth apart (a limit, not a difference) and does not fail on it. `tests.rs` pins the deepest nesting read
for every construct that nests, and checks that the deepest of each fits a 1 MiB stack.

## Tests

`cargo test -p lazaret-engine goparse` (14 tests; they need no Go): a small file's tree, a table of files the parser
accepts and files it refuses (each checked against `go/parser` with `astdump.go` when it was written), where and why the
errors are reported, the nesting table, the stack, chains, spans and code-point counting, flags, tree invariants on every
prefix and one-character edit of the accepted files and on seeded soups of Go's tokens and arbitrary code points, and linear
time. `python/tests/architecture/test_goparse_scripts.py` tests the two scripts here (they never run Go) and reads
`astdump.go` for what it must not do.
