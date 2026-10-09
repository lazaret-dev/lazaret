//! The parser's own tests: the depth limit of every construct that nests
//! and the stack the deepest of them takes, the speculation budgets, the
//! places jsparse.py fails outside its JsSyntaxError, spans, and inputs
//! that must never panic. (The trees are held to the recorded ones by
//! python/tests/architecture/test_snapshot_js_parse.py; the depths and
//! answers pinned here are jsparse.py's.)

use super::*;

fn cp(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn json(src: &str, ts: bool, jsx: bool) -> String {
    to_json(&cp(src), ts, jsx, false)
}

fn error(src: &str, ts: bool, jsx: bool) -> (u32, String) {
    match parse(&cp(src), ts, jsx) {
        Ok(_) => panic!("{:?} parsed", &src[..src.len().min(60)]),
        Err(e) => (e.line, e.reason.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()),
    }
}

/// A construct that nests: (name, ts, jsx, head, opener, middle, closer,
/// tail, the deepest jsparse.py reads, its error one deeper).
pub(crate) type Nesting = (&'static str, bool, bool, &'static str, &'static str, &'static str, &'static str, &'static str, usize, &'static str);

/// Every construct that nests.
pub(crate) const NESTINGS: &[Nesting] = &[
    ("parentheses", false, true, "", "(", "x", ")", "", 126, "nesting too deep"),
    ("arrays", false, true, "", "[", "x", "]", "", 126, "nesting too deep"),
    ("objects", false, true, "x = ", "{a: ", "1", "}", "", 84, "nesting too deep"),
    ("blocks", false, true, "", "{", "", "}", "", 256, "nesting too deep"),
    ("functions", false, true, "", "function f(){", "", "}", "", 256, "nesting too deep"),
    ("function expressions", false, true, "x = ", "function(){ return ", "1", "}", "", 84, "nesting too deep"),
    ("arrows", false, true, "x = ", "a => ", "a", "", "", 252, "nesting too deep"),
    ("async arrows", false, true, "x = ", "async a => ", "a", "", "", 252, "nesting too deep"),
    ("paren arrows", false, true, "x = ", "(a) => ", "a", "", "", 126, "nesting too deep"),
    ("if", false, true, "", "if (x) ", "y;", "", "", 253, "nesting too deep"),
    ("while", false, true, "", "while (x) ", "y;", "", "", 253, "nesting too deep"),
    ("for", false, true, "", "for (;;) ", "y;", "", "", 253, "nesting too deep"),
    ("for of", false, true, "", "for (a of b) ", "y;", "", "", 253, "nesting too deep"),
    ("labels", false, true, "", "a: ", "x;", "", "", 253, "nesting too deep"),
    ("try", false, true, "", "try { ", "", "} finally {}", "", 256, "nesting too deep"),
    ("switch", false, true, "", "switch (x) { case 1: ", "", "}", "", 254, "nesting too deep"),
    ("conditionals", false, true, "x = ", "a ? ", "b", " : c", "", 252, "nesting too deep"),
    ("assignments", false, true, "", "a = ", "b", "", "", 253, "nesting too deep"),
    ("unary", false, true, "x = ", "!", "y", "", "", 256, "nesting too deep"),
    ("typeof", false, true, "x = ", "typeof ", "y", "", "", 256, "nesting too deep"),
    ("await", false, true, "async function f() { x = ", "await ", "y", "", " }", 256, "nesting too deep"),
    ("calls", false, true, "", "f(", "x", ")", "", 253, "nesting too deep"),
    ("computed members", false, true, "", "a[", "x", "]", "", 253, "nesting too deep"),
    ("optional calls", false, true, "", "a?.(", "x", ")", "", 253, "nesting too deep"),
    ("spreads", false, true, "f(", "...[", "x", "]", ")", 126, "nesting too deep"),
    ("templates", false, true, "", "`${", "x", "}`", "", 126, "nesting too deep"),
    ("tagged templates", false, true, "", "f`${", "x", "}`", "", 253, "nesting too deep"),
    ("new", false, true, "", "new ", "X", "", "", 252, "nesting too deep"),
    ("classes", false, true, "", "class A { m() { ", "", "} }", "", 128, "nesting too deep"),
    ("class expressions", false, true, "x = ", "class extends (", "B", ") {}", "", 84, "nesting too deep"),
    ("array patterns", false, true, "let ", "[", "a", "]", " = x;", 255, "nesting too deep"),
    ("object patterns", false, true, "let ", "{a: ", "b", "}", " = x;", 255, "nesting too deep"),
    ("parameter patterns", false, true, "function f(", "{a: ", "b", "}", ") {}", 255, "nesting too deep"),
    ("arrow parameters", false, true, "x = (", "[", "a", "]", ") => 0;", 125, "nesting too deep"),
    ("assignment patterns", false, true, "(", "[", "a", "]", " = x);", 125, "nesting too deep"),
    ("jsx elements", false, true, "", "<a>", "", "</a>", "", 253, "nesting too deep"),
    ("jsx fragments", false, true, "", "<>", "", "</>", "", 253, "nesting too deep"),
    ("jsx attributes", false, true, "x = ", "<a b=", "<a />", " />", "", 251, "nesting too deep"),
    ("jsx containers", false, true, "", "<a>{", "x", "}</a>", "", 84, "nesting too deep"),
    ("ts generics", true, false, "let x: ", "A<", "T", ">", ";", 126, "nesting too deep"),
    ("ts object types", true, false, "let x: ", "{a: ", "T", "}", ";", 84, "nesting too deep"),
    ("ts tuple types", true, false, "let x: ", "[", "T", "]", ";", 126, "nesting too deep"),
    ("ts function types", true, false, "let x: ", "(a: ", "T", ") => T", ";", 253, "nesting too deep"),
    ("ts parenthesized types", true, false, "let x: ", "(", "T", ")", ";", 126, "nesting too deep"),
    ("ts keyof", true, false, "let x: ", "keyof ", "T;", "", "", 253, "nesting too deep"),
    ("ts indexed types", true, false, "let x: ", "T[", "K", "]", ";", 126, "nesting too deep"),
    ("ts conditional types", true, false, "type X = ", "A extends B ? ", "C", " : D", ";", 253, "nesting too deep"),
    ("ts namespaces", true, false, "", "namespace A { ", "", "}", "", 256, "nesting too deep"),
    ("ts type arguments", true, false, "", "f<", "T", ">", "();", 127, "unexpected token '>'"),
    ("ts generic arrows", true, false, "x = ", "<T,>(a: T) => ", "a;", "", "", 252, "unexpected token ','"),
    ("tsx generic arrows", true, true, "x = ", "<T,>(a: T) => ", "<a />;", "", "", 251, "unexpected character ','"),
];

pub(crate) fn nested(n: &Nesting, k: usize) -> String {
    format!("{}{}{}{}{}", n.3, n.4.repeat(k), n.5, n.6.repeat(k), n.7)
}

#[test]
fn a_small_program() {
    assert_eq!(
        json("a = 1;", false, true),
        r#"{"type":"Program","line":1,"body":[{"type":"ExpressionStatement","line":1,"expression":{"type":"AssignmentExpression","line":1,"operator":"=","left":{"type":"Identifier","line":1,"name":"a"},"right":{"type":"Literal","line":1,"kind":"number","value":"1"}}}]}"#
    );
    assert_eq!(json("'a", false, true), r#"{"error":{"line":1,"reason":"unterminated string"}}"#);
}

#[test]
fn annex_b_html_comments_are_comments_in_javascript() {
    // (F-12) `<!--` opens a line comment anywhere a token may begin; `-->` opens one at a line's start (the input's,
    // or after only blanks and comments since a line terminator), as V8 reads a script (Node's CommonJS). Before
    // F-12 the parser read `<!--` as `<` `!` `--`, and a file that opened with one did not parse.
    let ok = |src: &str| {
        for jsx in [false, true] {
            assert!(parse(&cp(src), false, jsx).is_ok(), "{src:?} (jsx={jsx})");
        }
    };
    let err = |src: &str| {
        assert!(parse(&cp(src), false, false).is_err(), "{src:?} parsed");
    };
    ok("<!-- banner\nmodule.exports = 1;\n");           // a leading open comment
    ok("x = 1;\n--> banner\ny = 2;\n");                 // `-->` after a line terminator
    ok("--> banner\nx = 1;\n");                          // `-->` at the input's start
    ok("   --> banner\nx = 1;\n");                       // blanks before it, still the input's first line
    ok("/* a\nb */ --> banner\nx = 1;\n");              // a block comment with a line terminator opens the line
    ok("#!/usr/bin/env node\n<!-- banner\nx = 1;\n");   // after a hashbang (its line ends first)
    ok("x = a <!-- b;\n");                               // `<!--` mid-line: a comment to the line's end
    ok("x<!--y\nz = 1;\n");                              // `<!--` with no space: still a comment
    ok("i-->0;\n");                                      // `i-- > 0`: a postfix `--`, not a close comment
    ok("<!-- only a comment\n");                         // nothing but the comment
    // `-->` that does not begin a line stays `--` `>` (V8 refuses `x = 1; --> y`)
    err("x = 1; --> y\n");
    // the exact bytes only: a real less-than is untouched
    assert!(json("a < !b;", false, false).contains("BinaryExpression"));
    assert!(json("a-->b;", false, false).contains("UpdateExpression"));
    // what the comment hides is no part of the tree
    assert!(!json("z = 5 <!--y, f()\n", false, false).contains("CallExpression"));
}

#[test]
fn typescript_reads_html_like_open_comments_as_tsc_does() {
    // tsc (6.0.3) has no HTML-like comments: `<!--` is `<` `!` `--`, so `z = 5 <!--y, f()` compiles to
    // `z = 5 < !--y, f();`, which calls f, and a file that opens with `<!--` is a syntax error to it (tsx and Node's
    // type stripping read a comment; the supply-chain facts read a TypeScript file's text as JavaScript first,
    // jsflow::supply::facts). `-->` where a line begins is never code, and is a comment in either dialect.
    for jsx in [false, true] {
        let tree = json("z = 5 <!--y, f()\n", true, jsx);
        assert!(tree.contains("CallExpression") && tree.contains("UpdateExpression"), "{tree}");
        assert!(json("z = 5\n<!--y, f()\n", true, jsx).contains("CallExpression"));
        assert!(parse(&cp("<!-- banner\nx = 1;\n"), true, jsx).is_err());
        assert!(!parse(&cp("x = a <!-- b;\n"), true, jsx).unwrap().html_after_code);
        assert!(!json("x = y\n--> 0, f()\n", true, jsx).contains("CallExpression"));
        assert!(parse(&cp("--> banner\nx = 1;\n"), true, jsx).is_ok());
    }
    // JavaScript read as tsc reads `<!--` (parse_with, html_open false): the supply-chain facts' second reading
    let tree = parse_with(&cp("z = 5 <!--y, f()\n--> c\n"), false, true, false).unwrap();
    assert!(!tree.html_after_code);
    assert!(parse_with(&cp("<!-- banner\nx = 1;\n"), false, true, false).is_err());
}

#[test]
fn an_html_like_open_comment_after_code_is_marked() {
    // Tree::html_after_code: the JavaScript reading took a `<!--` after the first token for a comment, where tsc
    // (and a module, by the standard) reads code. Before the first token it is a comment in every reading that runs
    // the file, and `-->` hides nothing that runs.
    let marked = |src: &str| parse(&cp(src), false, true).unwrap().html_after_code;
    assert!(marked("z = 5 <!--y, f()\n"));
    assert!(marked("z = 5\n<!--y, f()\n"));
    assert!(marked("x = 1;\n<!-- a note\n"));
    assert!(marked("x = 1 <!-- at the end"));                 // (the comment before the end of the input)
    assert!(marked("f(<a\n<!-- c\nb='1'/>);\n"));          // (in a JSX tag)
    assert!(!marked("<!-- banner\nmodule.exports = 1;\n"));
    assert!(!marked("#!/usr/bin/env node\n<!-- banner\nx = 1;\n"));
    assert!(!marked("/* a */ <!-- banner\nx = 1;\n"));
    assert!(!marked("x = 1;\n--> banner\ny = 2;\n"));
    assert!(!marked("s = '<!--'; t = `<!-- ${u} -->`; r = /<!--/; // <!--\n"));   // in a string, a template, a regex
    assert!(!marked("a = b < !--c;\n"));
    // (a read ahead, an arrow's parameters here, leaves no mark of its own: the mark is state save() keeps)
    assert!(!marked("x = (a = /<!--/, b = '<!--') => a;\n"));
}

#[test]
fn every_nesting_ends_where_jsparse_ends_it() {
    for n in NESTINGS {
        let deepest = nested(n, n.8);
        assert!(parse(&cp(&deepest), n.1, n.2).is_ok(), "{} at {}", n.0, n.8);
        assert_eq!(error(&nested(n, n.8 + 1), n.1, n.2), (1, n.9.to_string()), "{} at {}", n.0, n.8 + 1);
    }
}

/// The stack the deepest nesting of each construct takes fits `kib` KiB
/// (a release build; the wasm build has 8 MiB, rust/.cargo/config.toml).
fn deepest_on_a_stack(kib: usize) {
    let inputs: Vec<(String, bool, bool)> = NESTINGS.iter().map(|n| (nested(n, n.8), n.1, n.2)).collect();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for (src, ts, jsx) in &inputs {
                assert!(parse(&cp(src), *ts, *jsx).is_ok());
                // and the JSON writer, which walks the tree without recursing
                assert!(to_json(&cp(src), *ts, *jsx, true).starts_with("{\"type\":\"Program\""));
            }
        })
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn the_deepest_nesting_fits_a_small_stack() {
    // a release build fits 1 MiB (cargo test --release); a debug build's
    // frames are several times larger
    deepest_on_a_stack(if cfg!(debug_assertions) { 16 * 1024 } else { 1024 });
}

#[test]
fn deep_trees_from_loops_are_read_and_written() {
    // member chains, binary operators, `else if`: read in loops, and the
    // tree as deep as the input is long; the writer and compact() do not recurse
    for src in ["x".to_string() + &".y".repeat(200_000), "a".to_string() + &"+a".repeat(200_000),
                "if (x) y;".to_string() + &" else if (x) y;".repeat(100_000), "f()".to_string() + &"()".repeat(100_000)] {
        let tree = parse(&cp(&src), false, true).unwrap();
        assert!(tree.nodes.len() > 100_000);
        assert!(to_json(&cp(&src), false, true, false).ends_with("}]}"));
    }
}

#[test]
fn a_speculative_read_stops_at_its_budget() {
    // `<T,>(a, a, …) => 0`: the generic arrow is read ahead, at most 4096 tokens
    let arrow = |n: usize| format!("x = <T,>({}) => 0;", "a,".repeat(n));
    assert!(json(&arrow(2044), true, false).contains("\"ArrowFunctionExpression\""));
    assert_eq!(error(&arrow(2045), true, false), (1, "unexpected token ','".to_string()));
    // function_type_ahead reads at most 256 tokens of `([…]) =>`
    let ftype = |n: usize| format!("let x: ([{}]) => T;", "a,".repeat(n));
    assert!(parse(&cp(&ftype(126)), true, false).is_ok());
    assert_eq!(error(&ftype(127), true, false), (1, "unexpected token '=>'".to_string()));
}

#[test]
fn all_reads_ahead_share_one_allowance() {
    // each `<` of `a < a < …` reads type arguments ahead to the end of the
    // statement; once the file's allowance (2 per code point and 16 * 4096)
    // is spent, no read ahead fits, a peek sees the end of the input, and
    // `let x = 1` is read as an expression
    let src = "a < ".repeat(10_000) + "z;\nlet x = 1;";
    assert_eq!(error(&src, true, false), (2, "unexpected token 'x'".to_string()));
    let short = "a < ".repeat(100) + "z;\nlet x = 1;";
    assert!(json(&short, true, false).contains("\"VariableDeclaration\""));
    // and `f<f<f<…` stays linear (jsparse.py once was not)
    let t = std::time::Instant::now();
    assert_eq!(error(&"f<".repeat(40_000), true, false), (1, "unexpected end of input".to_string()));
    assert!(t.elapsed().as_secs_f64() < 5.0);
}

#[test]
fn where_jsparse_raises_past_its_errors() {
    // `( ...a, b )` that is no arrow's parameters: jsparse.py raises
    // KeyError: 'line' (line 0 says it is not a JsSyntaxError)
    assert_eq!(error("x = (...a, b);", false, true), (0, "KeyError: 'line'".to_string()));
    assert!(parse(&cp("(...a, b) => 0"), false, true).is_ok());
    // its recursion limit: Flow's `?T` chains, long JSX member names
    let q = |n: usize| format!("let x: {}T;", "? ".repeat(n));
    assert!(parse(&cp(&q(parser::PY_CHAIN_LIMIT as usize - 1)), false, true).is_ok());
    assert_eq!(error(&q(parser::PY_CHAIN_LIMIT as usize), false, true), (1, "nesting too deep".to_string()));
    let name = |n: usize| vec!["a"; n].join(".");
    let el = |n: usize| format!("<{}></{}>", name(n), name(n));
    assert!(parse(&cp(&el(parser::PY_CHAIN_LIMIT as usize)), false, true).is_ok());
    assert_eq!(error(&el(parser::PY_CHAIN_LIMIT as usize + 1), false, true), (1, "nesting too deep".to_string()));
}

#[test]
fn spans() {
    let src = "let a = 1;\nfunction f(x, y = 2) {\n  return x?.y(z) + `t${a}`;\n}\nclass C { m() {} }\n<div a=\"b\">{c}</div>;";
    let s = cp(src);
    let tree = parse(&s, false, true).unwrap();
    let line_at = |pos: u32| 1 + s[..pos as usize].iter().filter(|&&c| c == '\n' as u32).count() as u32;
    let text = |id: NodeId| -> String {
        let n = tree.node(id);
        s[n.start as usize..n.end as usize].iter().map(|&c| char::from_u32(c).unwrap()).collect()
    };
    for (id, n) in tree.nodes.iter().enumerate() {
        assert!(n.start <= n.end && n.end as usize <= s.len());
        assert_eq!(n.line, line_at(n.start), "{:?}", n.kind);
        tree.each_child(id as u32, |c| assert!(c > id as u32)); // document order
    }
    let find = |kind: Kind| (0..tree.nodes.len() as u32).find(|&i| tree.kind(i) == kind).unwrap();
    assert_eq!(text(find(Kind::VariableDeclaration)), "let a = 1;");
    assert_eq!(text(find(Kind::AssignmentPattern)), "y = 2");
    assert_eq!(text(find(Kind::ChainExpression)), "x?.y(z)");
    assert_eq!(text(find(Kind::TemplateLiteral)), "`t${a}`");
    assert_eq!(text(find(Kind::MethodDefinition)), "m() {}");
    assert_eq!(text(find(Kind::JSXElement)), "<div a=\"b\">{c}</div>");
    assert_eq!(text(find(Kind::JSXExpressionContainer)), "{c}");
    assert_eq!(tree.root, 0);
    assert_eq!(tree.kind(0), Kind::Program);
    // the field accessors
    let f = find(Kind::FunctionDeclaration);
    assert_eq!(tree.children_of(f, "params").len(), 2);
    let id = tree.child(f, "id").unwrap();
    assert_eq!(tree.text_of(id, "name"), Some(&cp("f")[..]));
    let parents = tree.parents();
    assert_eq!(parents[0], NONE);
    assert_eq!(parents[id as usize], f);
}

#[test]
fn names_are_interned() {
    let tree = parse(&cp("a; b; a; 'a';"), false, true).unwrap();
    let ids: Vec<u32> = (0..tree.nodes.len() as u32)
        .filter(|&i| matches!(tree.kind(i), Kind::Identifier | Kind::Literal))
        .map(|i| tree.node(i).f[0])
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(ids[0], ids[2]);
    assert_eq!(ids[0], ids[3]); // the string 'a' is the same string
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn dialects() {
    let d = |p: &str| dialect(&cp(p));
    assert_eq!(d("a.ts"), (true, false));
    assert_eq!(d("b.MTS"), (true, false));
    assert_eq!(d("c.cts"), (true, false));
    assert_eq!(d("d.Tsx"), (true, true));
    assert_eq!(d("e.js"), (false, true));
    assert_eq!(d("f.d.ts"), (true, false));
    assert_eq!(d("ts"), (false, true));
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
    // seeded soups of pieces and of arbitrary code points (lone
    // surrogates, controls, and values past U+10FFFF a binding never sends)
    let pieces = [
        "a", "1", ".5", "0x", "'s", "'s'", "\"", "`", "`a${", "}", "${", "/", "/re/", "[", "]", "(", ")", "{", "}",
        ";", ",", ".", "...", "?.", "?", ":", "=", "=>", "<", ">", ">>=", "!", "@", "#", "#p", "\\", "\\u", "\\u{",
        "\n", "\r", " ", "/*", "*/", "//", "<a>", "</a>", "<>", "</>", "<a/>", "if", "else", "for", "of", "let",
        "async", "await", "yield", "function", "class", "new", "import", "export", "type", "enum", "declare",
        "interface", "namespace", "abstract", "as", "satisfies", "keyof", "infer", "extends", "is", "asserts",
        "\u{2028}", "\u{feff}", "é", "\u{1F600}",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for k in 0..6000 {
        let mut src: Vec<u32> = Vec::new();
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
        let (ts, jsx) = [(false, true), (true, false), (true, true), (false, false)][k % 4];
        let _ = to_json(&src, ts, jsx, true);
        let _ = parse(&src, ts, jsx);
    }
}
