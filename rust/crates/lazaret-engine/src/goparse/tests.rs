//! The parser's own tests: the trees it builds, what it accepts and refuses (each case below was checked against
//! `go/parser` by `scripts/goparse/astdump.go` when it was written), the depth at which every nesting ends and the
//! stack the deepest of them takes, spans, linear time, and inputs that must never panic. (Every node of every file of
//! the Go distribution is held to `go/parser`'s by `scripts/goparse/diff.py`, which needs a Go toolchain and so is
//! not a test here.)

use super::tree::{ALIAS, CHAN_RECV, CHAN_SEND, DELIMITED, ELLIPSIS, PAREN, SLICE3};
use super::*;

fn cp(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn dump(src: &str) -> String {
    let tree = parse(&cp(src)).unwrap_or_else(|e| panic!("{:?}: {}", &src[..src.len().min(60)], e.message()));
    let mut out = String::new();
    out::write_nodes(&tree, &mut out);
    out
}

/// Where and why a file is refused.
fn error(src: &str) -> (u32, String) {
    match parse(&cp(src)) {
        Ok(_) => panic!("{:?} parsed", &src[..src.len().min(60)]),
        Err(e) => (e.pos, e.message()),
    }
}

const ACCEPTED: &[&str] = &[
    "package p\n",
    "package p\nimport \"a\"\nimport b \"c\"\nimport . \"d\"\nimport _ \"e\"\nimport (\n\t\"f\"\n)\n",
    "package p\ntype T[P any] struct{}\ntype U[P *C,] int\ntype V [N]int\ntype W[P interface{ ~int }] []P\n",
    "package p\ntype A = B\ntype C[T any] = []T\n",
    "package p\nfunc f[T, U any](a T, b ...U) (int, error) { return 0, nil }\n",
    "package p\nvar _ = f[int, string]\nvar _ = g[int](1)\n",
    "package p\ntype I interface{ ~int | ~string; m(); fmt.Stringer }\n",
    "package p\ntype S struct { a, b int `t`; *T; p.U; V[int] }\n",
    "package p\nfunc (r *T[K, V]) m() {}\nfunc (T) n() {}\n",
    "package p\nvar x = [...]int{1, 2, 3}\nvar y = map[string][]int{\"a\": {1}}\nvar z = struct{ a int }{1}\n",
    "package p\nfunc f() { for i := range 10 { _ = i }; for range ch {}; for k, v := range m {}; for ;; {}; for x {} }\n",
    "package p\nfunc f() { switch { case a: fallthrough; default: }; switch x := y.(type) { case int, string: case nil: } }\n",
    "package p\nfunc f() { select { case v := <-c: case c <- 1: case <-c: default: } }\n",
    "package p\nfunc f() { L: for { break L; continue L }; goto L }\n",
    "package p\nfunc f() { go g(); defer h(); x++; y--; a, b = b, a; c <<= 1; d &^= 2 }\n",
    "package p\nfunc f() { if x := g(); x > 0 { } else if y { } else { } }\n",
    "package p\nvar f = func(a int) int { return a }\nvar g = func() {}()\n",
    "package p\nvar x = a[1:2]\nvar y = a[:]\nvar z = a[1:2:3]\nvar w = a.(T)\nvar v = <-ch\nvar u = *p\nvar t = &T{}\n",
    "package p\nvar x = 0b1 + 0o7 + 0x1p-2 + 1_000 + 'a' + '\\n' + `raw` + \"s\" + 1i\n",
    "package p\n//go:build linux\n// +build linux\n\n/* c */\nvar x = 1 // t\n",
    "package p\n//line foo.go:10\nvar x = 1\n",
    "package \u{e9}\nvar \u{fc} = 1\n",
    "package p\nfunc f() {\n\tx := T{\n\t\ta: 1,\n\t}\n}\n",
    "package p\nvar x = chan<- int(nil)\nvar y = (<-chan int)(nil)\nvar z chan (<-chan int)\n",
    "package p\nfunc f(int, string)\nfunc g(a, b int) (c, d int)\n",
    "package p\r\nvar x = 1\r\n",
    "\u{feff}package p\n",
    "package p\nvar x = a.(type)\n",
    "package p\nfunc f() { switch x := y.(type) { case int: }; var z = x.(type) }\n",
    "package p\ntype T[] int\n",
    "package p\nvar x = [...]int\n",
    "package p\nfunc f() { select { case 1: } }\n",
    "package p\nfunc f() { L: }\n",
    "package p\nvar x = `a\r\nb`\n",
];

const REFUSED: &[&str] = &[
    "",
    "func f() {}\n",
    "package p\nvar x = (\n",
    "package p\nfunc f() { a := }\n",
    "package p\nfunc f() { if x { } else y }\n",
    "package p\ntype T struct { a int b int }\n",
    "package p\nvar s = \"abc\n",
    "package p\nvar s = 'ab'\n",
    "package p\nfunc f() { x := 08 }\n",
    "package p\nfunc f() { go f }\n",
    "package p\nfunc f() { defer f }\n",
    "package p\nfunc f() { x[1:2:] }\n",
    "package p\n/* unterminated\n",
    "package p\nvar x = 0x\n",
    "package p\nvar x = 1_\n",
    "package p\nvar x = `abc\n",
    "package p\nfunc f() { for i := 0; i < 1 { } }\n",
    "package p\nfunc f() { x := 1 2 }\n",
    "package p\nfunc f[]() {}\n",
    "package p\nfunc (a T) f[U any]() {}\n",
    "package p\nimport \"a\"\nvar x = 1\nimport \"b\"\n",
    "package p\nvar x = 1 +\n",
    "package p\nvar x = @\n",
    "package p\nvar x = \"\\q\"\n",
    "package p\nvar x = '\\400'\n",
    "package p\nvar x = 0b12\n",
    "package p\nvar x = 1e\n",
    "package p\nvar x = 0x1.8\n",
    "package p\nfunc f() { break 1 }\n",
    "package p\nfunc f() { x := <-<-<- }\n",
    "package p\ntype I interface{ int | }\n",
    "package p\nvar x struct{ a int; }}\n",
    "package p\nvar x = []int{1,\n2\n}\n",
    "package p\nfunc f() { switch { case a; } }\n",
    "package p\nvar \0 = 1\n",
    "package p\nvar x = \"a\0b\"\n",
    "package p\n//line foo.go:0\nvar x = 1\n",
    "package p\nvar x = 1 // \0\n",
    "package p\nvar x = 1\u{feff}\n",
];

/// A construct that nests: (name, head, opener, middle, closer, tail, the deepest nesting that is read; one
/// deeper is refused). `MAX_DEPTH` is counted in type, unary, literal, statement and `if` levels, so the numbers
/// differ by what a level costs (a function literal is an expression and a block).
type Nesting = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str, usize);

const NESTINGS: &[Nesting] = &[
    ("parentheses", "package p\nvar x = ", "(", "1", ")", "\n", 255),
    ("blocks", "package p\nfunc f() {\n", "{\n", "", "}\n", "}\n", 256),
    ("function literals", "package p\nfunc f() {\n", "x := func() {\n", "x", "}\n", "}\n", 127),
    ("composite literals", "package p\nvar x = ", "T{", "1", "}", "\n", 127),
    ("slice types", "package p\nvar x ", "[]", "int", "", "\n", 255),
    ("unary operators", "package p\nvar x = ", "- ", "1", "", "\n", 255),
    ("receives", "package p\nvar x = ", "<- ", "1", "", "\n", 255),
    ("dereferences", "package p\nvar x = ", "* ", "1", "", "\n", 255),
    ("pointer types", "package p\nvar x ", "*", "int", "", "\n", 255),
    ("if", "package p\nfunc f() {\n", "if x {\n", "", "}\n", "}\n", 127),
    ("for", "package p\nfunc f() {\n", "for {\n", "", "}\n", "}\n", 256),
    ("switch", "package p\nfunc f() {\n", "switch {\ncase x:\n", "", "}\n", "}\n", 255),
    ("struct types", "package p\nvar x ", "struct { a ", "int", "}", "\n", 255),
    ("map types", "package p\nvar x ", "map[int]", "int", "", "\n", 255),
    ("channel types", "package p\nvar x ", "chan ", "int", "", "\n", 255),
    ("calls", "package p\nvar x = ", "f(", "1", ")", "\n", 255),
    ("indexes", "package p\nvar x = ", "a[", "1", "]", "\n", 255),
    ("operators and parentheses", "package p\nvar x = ", "1 || 1 && 1 == 1 + 1 * (", "1", ")", "\n", 255),
    ("operators and calls", "package p\nvar x = ", "1 || 1 && 1 == 1 + 1 * f(", "1", ")", "\n", 255),
    ("operators and literals", "package p\nvar x = ", "1 || 1 && 1 == 1 + 1 * T{", "1", "}", "\n", 127),
    ("operators and functions", "package p\nvar x = ", "1 || 1 && 1 == 1 + 1 * func() int { return ", "1", "}", "\n", 127),
];

fn nested(n: &Nesting, k: usize) -> String {
    format!("{}{}{}{}{}", n.1, n.2.repeat(k), n.3, n.4.repeat(k), n.5)
}

#[test]
fn a_small_file() {
    assert_eq!(
        dump("package p\n\nimport \"os\"\n\nfunc f(a int, b ...string) (n int) {\n\tx := a + 1*2\n\treturn x\n}\n"),
        "File 0 86\nIdent 8 9\nGenDecl 11 22\nImportSpec 18 22\nBasicLit 18 22\nFuncDecl 24 86\nIdent 29 30\n\
         FuncType 24 58\nFieldList 30 50\nField 31 36\nIdent 31 32\nIdent 33 36\nField 38 49\nIdent 38 39\n\
         Ellipsis 40 49\nIdent 43 49\nFieldList 51 58\nField 52 57\nIdent 52 53\nIdent 54 57\nBlockStmt 59 86\n\
         AssignStmt 62 74\nIdent 62 63\nBinaryExpr 67 74\nIdent 67 68\nBinaryExpr 71 74\nBasicLit 71 72\n\
         BasicLit 73 74\nReturnStmt 76 84\nIdent 83 84\n"
    );
}

#[test]
fn what_is_accepted() {
    for src in ACCEPTED {
        let tree = parse(&cp(src)).unwrap_or_else(|e| panic!("{:?}: {}", src, e.message()));
        assert_eq!(tree.node(tree.root).kind, Kind::File, "{:?}", src);
    }
}

#[test]
fn what_is_refused() {
    for src in REFUSED {
        assert!(parse(&cp(src)).is_err(), "{:?} parsed", src);
    }
}

#[test]
fn errors_say_where_and_why() {
    // the position is a code-point offset (go/parser's `line:column` is the same place), the message go/parser's
    // meaning
    for (src, pos, msg) in [
        ("package p\nvar x = (\n", 20, "expected operand (at 'EOF')"),
        ("package p\nfunc f() { a := }\n", 26, "expected operand (at '}')"),
        ("package p\nfunc f() { if x { } else y }\n", 35, "expected if statement or block (at 'IDENT')"),
        ("package p\ntype T struct { a int b int }\n", 32, "expected ';', found 'IDENT'"),
        ("package p\nvar s = \"abc\n", 18, "string literal not terminated (at 'STRING')"),
        ("package p\nvar s = 'ab'\n", 18, "illegal rune literal (at 'CHAR')"),
        ("package p\nvar s = `abc\n", 18, "raw string literal not terminated (at 'STRING')"),
        ("package p\nfunc f() { go f }\n", 26, "expression in go/defer must be function call (at '}')"),
        ("package p\nfunc f() { x[1:2:] }\n", 29, "final index required in 3-index slice (at '}')"),
        ("package p\n/* unterminated\n", 10, "comment not terminated (at 'EOF')"),
        ("package p\nvar x = 1_\n", 19, "'_' must separate successive digits (at 'INT')"),
        ("func f() {}\n", 0, "expected 'package', found 'func'"),
        ("", 0, "expected 'package', found 'EOF'"),
    ] {
        assert_eq!(error(src), (pos, msg.to_string()), "{:?}", src);
    }
}

#[test]
fn every_nesting_ends_where_it_is_pinned() {
    for n in NESTINGS {
        assert!(parse(&cp(&nested(n, n.6))).is_ok(), "{} at {}", n.0, n.6);
        let (_, msg) = error(&nested(n, n.6 + 1));
        assert!(msg.starts_with("exceeded max nesting depth"), "{} at {}: {}", n.0, n.6 + 1, msg);
    }
}

#[test]
fn depth_is_given_back() {
    // a level is released when its construct ends: siblings, each as deep as can be read, are all read
    let n = &NESTINGS[0];
    let one = nested(n, n.6);
    let many = format!("package p\n{}", (0..50).map(|_| one["package p\n".len()..].to_string()).collect::<String>());
    assert!(parse(&cp(&many)).is_ok());
    let blocks = &NESTINGS[1];
    let body = format!("{}{}", blocks.2.repeat(blocks.6 - 1), blocks.4.repeat(blocks.6 - 1));
    let src = format!("package p\nfunc f() {{\n{}{}{}}}\n", body, body, body);
    assert!(parse(&cp(&src)).is_ok());
}

/// The stack the deepest nesting of each construct takes fits `kib` KiB (a release build; the wasm build has 8
/// MiB, rust/.cargo/config.toml).
fn deepest_on_a_stack(kib: usize) {
    let inputs: Vec<String> = NESTINGS.iter().map(|n| nested(n, n.6)).collect();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for src in &inputs {
                let tree = parse(&cp(src)).unwrap();
                // and the writer, which walks the tree without recursing
                let mut out = String::new();
                out::write_nodes(&tree, &mut out);
                assert!(out.starts_with("File 0 "));
            }
        })
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn the_deepest_nesting_fits_a_small_stack() {
    // a release build fits 1 MiB (cargo test --release); a debug build's frames are several times larger
    deepest_on_a_stack(if cfg!(debug_assertions) { 16 * 1024 } else { 1024 });
}

#[test]
fn chains_are_loops_not_depth() {
    // selector, call, index, binary-operator and `else if` chains, and a tree as deep as the text is long: read in
    // loops, and the writer does not recurse either
    for src in [
        format!("package p\nvar x = a{}\n", ".b".repeat(200_000)),
        format!("package p\nvar x = a{}\n", "+a".repeat(200_000)),
        format!("package p\nvar x = a{}\n", "()".repeat(100_000)),
        format!("package p\nvar x = a{}\n", "[0]".repeat(100_000)),
        format!("package p\nfunc f() {{ if x {{}}{} }}\n", " else if x {}".repeat(100_000)),
        format!("package p\nvar x = a{}\n", ".(T)".repeat(100_000)),
        format!("package p\nvar x = a{}\n", "[1:2]".repeat(100_000)),
    ] {
        let tree = parse(&cp(&src)).unwrap();
        assert!(tree.nodes.len() > 10, "{}", &src[..40]);
        let mut out = String::new();
        out::write_nodes(&tree, &mut out);
        // (the arena also holds nodes the parser made and then replaced, such as the ExprStmt of a condition)
        assert!(out.lines().count() <= tree.nodes.len() && out.lines().count() > 10, "{}", &src[..40]);
    }
}

#[test]
fn spans() {
    let src = "package p\n\nimport \"os\"\n\ntype T struct {\n\ta, b int `t`\n}\n\nfunc (t *T) m(x ...int) (y string) {\n\
               \tfor i := range x { _ = t.a[i] }\n\treturn \"s\"\n}\n\nvar v = map[string][]int{\"a\": {1}}\n";
    let s = cp(src);
    let tree = parse(&s).unwrap();
    let text = |id: NodeId| -> String {
        let n = tree.node(id);
        s[n.start as usize..n.end as usize].iter().map(|&c| char::from_u32(c).unwrap()).collect()
    };
    let mut seen = 0;
    let mut ids = Vec::new();
    tree.preorder(|id| {
        let n = tree.node(id);
        assert!(n.start <= n.end && n.end as usize <= s.len(), "{:?}", n.kind);
        // every child lies within its parent, and (but for the `func` of a FuncDecl's type, which comes first)
        // in document order
        let mut last = n.start;
        tree.each_child(id, &mut |c| {
            let k = tree.node(c);
            assert!(k.start >= n.start && k.end <= n.end, "{:?} in {:?}", k.kind, n.kind);
            if n.kind != Kind::FuncDecl {
                assert!(k.start >= last, "{:?} in {:?}", k.kind, n.kind);
            }
            last = k.start;
        });
        ids.push(id);
        seen += 1;
    });
    assert_eq!(seen, ids.len());
    let find = |kind: Kind| ids.iter().copied().find(|&i| tree.node(i).kind == kind).unwrap();
    assert_eq!(text(find(Kind::GenDecl)), "import \"os\"");
    assert_eq!(text(find(Kind::ImportSpec)), "\"os\"");
    assert_eq!(text(find(Kind::StructType)), "struct {\n\ta, b int `t`\n}");
    assert_eq!(text(find(Kind::Field)), "a, b int `t`");
    assert_eq!(text(find(Kind::FuncDecl)), "func (t *T) m(x ...int) (y string) {\n\tfor i := range x { _ = t.a[i] }\n\treturn \"s\"\n}");
    assert_eq!(text(find(Kind::Ellipsis)), "...int");
    assert_eq!(text(find(Kind::RangeStmt)), "for i := range x { _ = t.a[i] }");
    assert_eq!(text(find(Kind::IndexExpr)), "t.a[i]");
    assert_eq!(text(find(Kind::SelectorExpr)), "t.a");
    assert_eq!(text(find(Kind::MapType)), "map[string][]int");
    assert_eq!(text(find(Kind::CompositeLit)), "map[string][]int{\"a\": {1}}");
    assert_eq!(text(find(Kind::KeyValueExpr)), "\"a\": {1}");
    assert_eq!(text(find(Kind::ReturnStmt)), "return \"s\"");
    assert_eq!(tree.node(tree.root).kind, Kind::File);
    // File.End() is the end of its last declaration, not of the text: the newline after it is outside
    assert_eq!((tree.node(tree.root).start, tree.node(tree.root).end as usize), (0, s.len() - 1));
}

#[test]
fn positions_count_code_points() {
    // not bytes, not UTF-16 units: `é` is one, and so are U+10400 (a letter) and U+1F600
    let src = "package p\nvar \u{e9}\u{10400} = \"\u{1F600}\"\nvar x = 1\n";
    let s = cp(src);
    let tree = parse(&s).unwrap();
    let mut texts = Vec::new();
    tree.preorder(|id| {
        let n = tree.node(id);
        if n.kind == Kind::Ident || n.kind == Kind::BasicLit {
            texts.push(s[n.start as usize..n.end as usize].iter().map(|&c| char::from_u32(c).unwrap()).collect::<String>());
        }
    });
    assert_eq!(texts, ["p", "\u{e9}\u{10400}", "\"\u{1F600}\"", "x", "1"]);
}

#[test]
fn flags_and_operators() {
    let s = cp("package p\ntype A = B\nvar _ = f(a...)\nvar _ = a[1:2:3]\nvar c chan<- int\nvar d <-chan int\nconst (\n)\nfunc f() {\n\tx++\n}\n");
    let tree = parse(&s).unwrap();
    let mut kinds: Vec<(Kind, u8, u8)> = Vec::new();
    tree.preorder(|id| {
        let n = tree.node(id);
        kinds.push((n.kind, n.op, n.flags));
    });
    let has = |k: Kind, f: u8| kinds.iter().any(|&(kk, _, ff)| kk == k && ff & f == f);
    assert!(has(Kind::TypeSpec, ALIAS));
    assert!(has(Kind::CallExpr, ELLIPSIS));
    assert!(has(Kind::SliceExpr, SLICE3));
    assert!(has(Kind::GenDecl, PAREN));
    assert!(has(Kind::FieldList, DELIMITED));
    assert!(has(Kind::EmptyStmt, 0) || !kinds.iter().any(|&(k, _, _)| k == Kind::EmptyStmt));
    assert!(kinds.iter().any(|&(k, op, _)| k == Kind::ChanType && op == CHAN_SEND));
    assert!(kinds.iter().any(|&(k, op, _)| k == Kind::ChanType && op == CHAN_RECV));
    assert!(kinds.iter().any(|&(k, op, _)| k == Kind::IncDecStmt && op == scan::Tok::Inc as u8));
}

/// A small xorshift generator: the inputs below are the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn no_input_panics() {
    // seeded soups of Go's pieces and of arbitrary code points (lone surrogates, controls, NUL, a byte order mark,
    // and values past U+10FFFF a binding never sends)
    let pieces = [
        "package p\n", "package", "import", "\"a\"", "func", "f", "(", ")", "{", "}", "[", "]", ";", ",", ".", "...", ":",
        ":=", "=", "==", "!=", "<-", "<", ">", ">>=", "&^=", "&&", "||", "~", "|", "*", "&", "+", "-", "/", "%", "!", "^",
        "var", "const", "type", "struct", "interface", "map", "chan", "if", "else", "for", "range", "switch", "case",
        "default", "select", "go", "defer", "return", "break", "continue", "goto", "fallthrough", "x", "y", "T", "_", "1",
        "0x", "0b2", "1e+", ".5", "1_", "1i", "'a'", "'", "'\\", "\"", "\"\\", "`", "`raw`", "//", "//line a:1\n", "/*", "*/",
        "/* c */", "//go:build x\n", "\n", "\r", "\r\n", " ", "\t", "\u{0}", "\u{feff}", "\u{2028}", "\u{e9}", "\u{1F600}", "#",
        "@", "$", "?", "\\",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for k in 0..20_000 {
        let mut src: Vec<u32> = cp("package p\n");
        for _ in 0..rng.below(60) + 1 {
            if k % 3 == 0 && rng.below(4) == 0 {
                let c = match rng.below(5) {
                    0 => rng.below(0x80) as u32,
                    1 => 0xD800 + rng.below(0x800) as u32,
                    2 => 0x110000 + rng.below(1000) as u32,
                    3 => u32::MAX - rng.below(4) as u32,
                    _ => rng.below(0x110000) as u32,
                };
                src.push(c);
            } else {
                src.extend(cp(pieces[rng.below(pieces.len())]));
            }
        }
        if k % 7 == 0 {
            src.drain(..10);
        }
        if let Ok(tree) = parse(&src) {
            check(&tree, src.len(), "a soup");
        }
    }
}

/// What every tree the parser gives must be: spans in bounds and nested, every node reachable once, and a File at
/// the root.
fn check(tree: &Tree, len: usize, what: &str) {
    assert_eq!(tree.node(tree.root).kind, Kind::File, "{}", what);
    let mut seen = vec![false; tree.nodes.len()];
    tree.preorder(|id| {
        assert!(!seen[id as usize], "{}: node {} visited twice", what, id);
        seen[id as usize] = true;
        let n = tree.node(id);
        assert!(n.start <= n.end && n.end as usize <= len, "{}: {:?} {}..{}", what, n.kind, n.start, n.end);
        tree.each_child(id, &mut |c| {
            let k = tree.node(c);
            assert!(
                k.start >= n.start && k.end <= n.end,
                "{}: {:?} {}..{} in {:?} {}..{}",
                what, k.kind, k.start, k.end, n.kind, n.start, n.end
            );
        });
    });
}

#[test]
fn no_cut_or_edit_of_a_file_panics() {
    // every prefix of every accepted file, and each with one code point left out or doubled; every tree that
    // comes out is a well-formed one
    let mut trees = 0;
    for src in ACCEPTED {
        let s = cp(src);
        for i in 0..=s.len() {
            let mut variants = vec![s[..i].to_vec()];
            if i < s.len() {
                let mut t = s.clone();
                t.remove(i);
                variants.push(t);
                let mut u = s.clone();
                u.insert(i, s[i]);
                variants.push(u);
            }
            for v in variants {
                if let Ok(tree) = parse(&v) {
                    check(&tree, v.len(), src);
                    trees += 1;
                }
            }
        }
    }
    assert!(trees > 1000, "{}", trees);
}

#[test]
fn time_is_linear() {
    // each of these would take minutes if a parse function read a token twice; two seconds is a loose bound on a
    // release build and a debug build both
    let t = std::time::Instant::now();
    for src in [
        format!("package p\n{}", "var x = 1\n".repeat(100_000)),
        format!("package p\nvar x = {}1\n", "a < ".repeat(100_000)),
        format!("package p\nvar x = {}\n", "f(a, b, c) + ".repeat(50_000) + "1"),
        format!("package p\nfunc f() {{\n{}}}\n", "x := []int{1, 2, 3}\n".repeat(50_000)),
        format!("package p\nvar x = {}\n", "(".repeat(1_000_000)),
        format!("package p\nvar x = {}\n", "[]".repeat(1_000_000)),
        format!("package p\nfunc f() {{ {} }}\n", "x := func() {".repeat(1_000_000)),
        format!("package p\ntype T[P {}\n", "interface{ ~".repeat(100_000)),
        format!("package p\ntype T {}\n", "struct{ a ".repeat(100_000)),
        format!("package p\nvar x = {}\n", "T{".repeat(100_000)),
        format!("package p\nvar x = {}\n", "a[b[".repeat(100_000)),
        format!("package p\ntype T[A, B any] struct {{ a [{}", "N]".repeat(100_000)),
    ] {
        let _ = parse(&cp(&src));
    }
    assert!(t.elapsed().as_secs_f64() < 20.0, "{:?}", t.elapsed());
}
