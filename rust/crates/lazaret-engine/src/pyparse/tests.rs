//! The parser's own tests: the depth limit of every construct that nests
//! and the stack the deepest of them takes, deep and long inputs, which
//! error Python reports where there are several, spans and the tree's
//! accessors, interned names, and inputs that must never panic. (The
//! comparison with Python 3.13's ast, node for node, is
//! python/tests/architecture/test_pyparse_native*.py; the depths and lines
//! pinned here are Python's.)

use super::*;

fn cp(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn json(src: &str) -> String {
    to_json(&cp(src), false)
}

fn error(src: &str) -> (u32, String) {
    match parse(&cp(src)) {
        Ok(_) => panic!("{:?} parsed", &src[..src.len().min(60)]),
        Err(e) => (e.line, e.reason),
    }
}

fn nest(head: &str, opener: &str, middle: &str, closer: &str, k: usize) -> String {
    format!("{}{}{}{}", head, opener.repeat(k), middle, closer.repeat(k))
}

fn blocks(head: &str, k: usize, body: &str) -> String {
    let mut s = String::new();
    for i in 0..k {
        s.push_str(&" ".repeat(i));
        s.push_str(head);
    }
    s.push_str(&" ".repeat(k));
    s.push_str(body);
    s
}

/// A construct that nests: its name, the source nested k deep, and the
/// deepest Python 3.13 reads (and the parser too).
type Nesting = (&'static str, fn(usize) -> String, usize);

const NESTINGS: &[Nesting] = &[
    ("parentheses", |k| nest("", "(", "x", ")", k), 200),
    ("lists", |k| nest("", "[", "x", "]", k), 200),
    ("dicts", |k| nest("", "{1: ", "x", "}", k), 200),
    ("tuples", |k| nest("", "(x, ", "x", ")", k), 199),
    ("calls", |k| nest("", "f(", "x", ")", k), 200),
    ("not", |k| nest("", "not ", "x", "", k), 5969),
    ("minus", |k| nest("", "-", "x", "", k), 5969),
    ("lambda", |k| nest("", "lambda: ", "x", "", k), 2984),
    ("conditional", |k| nest("", "a if b else ", "c", "", k), 5969),
    ("power", |k| nest("", "a ** ", "a", "", k), 2984),
    ("f-strings", |k| nest("", "f'{", "x", "}'", k), 149),
    ("if", |k| blocks("if x:\n", k, "pass\n"), 99),
    ("elif", |k| format!("if a: pass\n{}", "elif b: pass\n".repeat(k)), 5965),
    ("def", |k| blocks("def f():\n", k, "pass\n"), 99),
    ("blocks and parentheses", |k| blocks("if x:\n", 98, &format!("{}x{}\n", "(".repeat(k), ")".repeat(k))), 193),
    ("patterns", |k| format!("match x:\n case {}a{}: pass\n", "[".repeat(k), "]".repeat(k)), 200),
    ("class patterns", |k| format!("match x:\n case {}1{}: pass\n", "A(a=".repeat(k), ")".repeat(k)), 200),
    ("lambda defaults", |k| nest("", "lambda a=", "1", ": 0", k), 746),
    ("with items", |k| format!("with ({}a{} as b): pass", "(".repeat(k), ")".repeat(k)), 199),
    ("type parameters", |k| format!("def f[T: {}int{}](): pass", "list[".repeat(k), "]".repeat(k)), 199),
    ("chained +", |k| format!("a{}", " + a".repeat(k)), 9994),
    ("attributes", |k| format!("a{}", ".b".repeat(k)), 9994),
    ("call chains", |k| format!("a{}", "()".repeat(k)), 9994),
];

#[test]
fn a_small_module() {
    assert_eq!(
        json("x = 1\n"),
        r#"{"_type":"Module","body":[{"_type":"Assign","targets":[{"_type":"Name","id":"x","ctx":{"_type":"Store"},"lineno":1,"col_offset":0,"end_lineno":1,"end_col_offset":1}],"value":{"_type":"Constant","value":{"int":"1"},"kind":null,"lineno":1,"col_offset":4,"end_lineno":1,"end_col_offset":5},"type_comment":null,"lineno":1,"col_offset":0,"end_lineno":1,"end_col_offset":5}],"type_ignores":[]}"#
    );
    assert_eq!(json("x = (\n"), r#"{"error":{"line":1,"reason":"'(' was never closed"}}"#);
    assert_eq!(json(""), r#"{"_type":"Module","body":[],"type_ignores":[]}"#);
}

#[test]
fn every_nesting_ends_where_python_ends_it() {
    for &(name, make, deepest) in NESTINGS {
        assert!(parse(&cp(&make(deepest))).is_ok(), "{} at {}", name, deepest);
        assert!(parse(&cp(&make(deepest + 1))).is_err(), "{} at {}", name, deepest + 1);
    }
    // the tokenizer's limits, and the parser's (Python's MemoryError and
    // RecursionError have no line)
    assert_eq!(error(&nest("", "(", "x", ")", 201)), (1, "too many nested parentheses".to_string()));
    assert_eq!(error(&blocks("if x:\n", 100, "pass\n")), (101, "too many levels of indentation".to_string()));
    assert_eq!(error(&nest("", "f'{", "x", "}'", 150)).1, "too many nested f-strings");
    assert_eq!(error(&nest("", "-", "x", "", 5970)), (0, "too complex: nesting too deep".to_string()));
    assert_eq!(error(&format!("a{}", ".b".repeat(9995))).0, 0);
}

/// The stack the deepest nesting of each construct takes (parsed, then
/// written with spans) fits `kib` KiB.
fn deepest_on_a_stack(kib: usize) {
    let inputs: Vec<String> = NESTINGS.iter().map(|&(_, make, deepest)| make(deepest)).collect();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for src in &inputs {
                assert!(parse(&cp(src)).is_ok());
                // (the JSON writer and compact() walk the tree without recursing)
                assert!(to_json(&cp(src), true).starts_with("{\"_type\":\"Module\""));
            }
        })
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn the_deepest_nesting_fits_a_small_stack() {
    // a release build fits 1 MiB (cargo test --release; the deepest takes
    // under 400 KiB, the wasm build has 8 MiB); a debug build's frames are
    // several times larger
    deepest_on_a_stack(if cfg!(debug_assertions) { 16 * 1024 } else { 1024 });
}

#[test]
fn long_inputs() {
    // flat and long: read in loops, in linear time
    let t = std::time::Instant::now();
    for src in [
        "x = 1\n".repeat(100_000),
        format!("x = [{}]\n", "1, ".repeat(200_000)),
        format!("f({})\n", "a, ".repeat(200_000)),
        format!("if x:\n{}", "    y = 1\n".repeat(100_000)),
        format!("f'{}'\n", "{a}b".repeat(50_000)),
        "'a' ".repeat(100_000) + "\n",
    ] {
        assert!(parse(&cp(&src)).is_ok());
        assert!(to_json(&cp(&src), false).ends_with("\"type_ignores\":[]}"));
    }
    assert!(t.elapsed().as_secs_f64() < 10.0);
}

#[test]
fn which_error_python_reports() {
    // Python's parser takes tokens one at a time: its error, before a
    // token the tokenizer refuses, stands …
    assert_eq!(error("a b\n  c\n d\n").0, 1);
    assert_eq!(error("x = 1\n  y = 2\nz = (\n"), (2, "unexpected indent".to_string()));
    // … unless the tokenizer raises an error itself further on
    assert_eq!(error("a b\nc = 'unterminated\n"), (2, "unterminated string literal".to_string()));
    assert_eq!(error("a b\n1__0\n"), (2, "invalid decimal literal".to_string()));
    // (not inside an f-string; a string's escapes are the parser's)
    assert_eq!(error("a b\nf'{x!}'\n").0, 1);
    assert_eq!(error("a b\n'\\N{NOSUCH}'\n").0, 1);
    // a bracket left open on a line before is reported
    assert_eq!(error("x = (1,\n2 3\n"), (1, "'(' was never closed".to_string()));
    // `$`, `?`, a backquote: tokens the parser refuses
    assert_eq!(error("a b\n$\n").0, 1);
    // the end of the text is on the last line
    assert_eq!(error("@d\n\n\n").0, 3);
    assert_eq!(error("if x:\n").0, 1);
    // the error pass's own: a missing comma, `print`, `if` without `else`,
    // a target that is none
    assert_eq!(error("f(a\n b)"), (1, "invalid syntax. Perhaps you forgot a comma?".to_string()));
    assert_eq!(error("f(print\n x)").0, 1);
    assert_eq!(error("x = (1 if 2\n 3)"), (1, "expected 'else' after 'if' expression".to_string()));
    assert_eq!(error("f() += \\\n 1 +").0, 1);
    assert_eq!(error("x = ('a'\n b'b')"), (2, "cannot mix bytes and nonbytes literals".to_string()));
    // a dict's key after its first item, not followed by `:` (at the key,
    // whatever follows), a value missing after `:` (at the `:`)
    assert_eq!(error("x = {'a': 1,\n 'b' c}"), (2, "':' expected after dictionary key".to_string()));
    assert_eq!(error("{1: 1,\n 2 if 3}").0, 2);
    assert_eq!(error("x = {'a':\n}"), (1, "expression expected after dictionary key and ':'".to_string()));
    // a statement `x, f(…)` whose call's arguments do not read: Python's
    // error pass reads from the call's `(` again (invalid_assignment), and
    // a `name = value` there is its error, at the name; not in brackets,
    // not after a keyword argument's positional one, which comes first
    let meant = "invalid syntax. Maybe you meant '==' or ':=' instead of '='?".to_string();
    assert_eq!(error("p , f(a=1,\n b='x'= c=2)"), (1, meant.clone()));
    assert_eq!(error("p , x.f(1, a=b,\n c='x' = 2)"), (1, meant.clone()));
    assert_eq!(error("p , g(f(a=1,\n b='x'= c=2))").0, 2);
    assert_eq!(error("p , [f(a=1,\n b='x'= c=2)]").0, 2);
    assert_eq!(error("q = p , f(a=1,\n b='x'= c=2)").0, 2);
    assert_eq!(error("p , g(x, a=1,\n h(b='x'= c=2))"), (2, "positional argument follows keyword argument".to_string()));
    assert_eq!(error("f(**k, h(b=1 =))").1, "positional argument follows keyword argument unpacking");
    // the expression after another: its failing trailers dropped, an error
    // inside the brackets it starts with reported
    assert_eq!(error("[u g(\n b c)]").0, 1);
    assert_eq!(error("f(a) {\n b\n c}").0, 2);
    // a missing block is an error of Python's own: an error its tokenizer
    // raises further on takes its place; the generic "unexpected unindent"
    // stands
    assert_eq!(error("class A:\n    def f(self):\nx = 1\nz = 'u"), (4, "unterminated string literal".to_string()));
    assert_eq!(error("class A:\n    @d\nx = 1\nz = 'u").0, 3);
    // an f-string field that reads in part: after its first atom
    assert_eq!(error("f\"{p.q[-2#0:]}\"\nx = 1\n").0, 1);
    // what Python refuses before reading: no line
    assert_eq!(error("x = 1\ny\0").0, 0);
    assert_eq!(parse(&[0x78, 0xD800]).unwrap_err().line, 0);
    assert_eq!(parse(&[0x78, 0x110000]).unwrap_err().line, 0);
}

#[test]
fn values() {
    assert!(json(&format!("0x{}", "f".repeat(5000))).contains(r#"{"int":"0x"#));
    assert!(json("10**100; 123456789012345678901234567890").contains(r#"{"int":"123456789012345678901234567890"}"#));
    assert!(json("1.5; 1e400; 2j").contains(r#"{"float":"0x1.8000000000000p+0"}"#));
    assert!(json("'\\ud800'").contains(r#""value":"\ud800""#));
    assert!(json("b'\\xff'").contains(r#"{"bytes":"ff"}"#));
    assert!(json("u'a'").contains(r#""kind":"u""#));
    // 4300 digits at most in a decimal int
    assert!(parse(&cp(&"1".repeat(4300))).is_ok());
    assert!(parse(&cp(&"1".repeat(4301))).is_err());
    // `<>` is `!=` under barry_as_FLUFL, and `!=` an error
    assert!(json("from __future__ import barry_as_FLUFL\nx <> y").contains("NotEq"));
    assert!(parse(&cp("from __future__ import barry_as_FLUFL\nx != y")).is_err());
    assert!(parse(&cp("x <> y")).is_err());
}

#[test]
fn spans_and_accessors() {
    let src = "import os\ndef f(a, b=1, *c, d, **e) -> int:\n    return [x async for x in y if x]\nclass C(B, metaclass=M):\n    x: int = f'{a!r:>{w}}'\nmatch p:\n    case {1: [a, *r]} | C(k=v) if g:\n        pass\n";
    let s = cp(src);
    let tree = parse(&s).unwrap();
    let starts = lexer::line_starts(&s);
    let line_at = |pos: u32| starts.partition_point(|&st| st <= pos) as u32;
    let text = |id: NodeId| -> String {
        let n = tree.node(id);
        s[n.start as usize..n.end as usize].iter().map(|&c| char::from_u32(c).unwrap()).collect()
    };
    for (id, n) in tree.nodes.iter().enumerate() {
        assert!(n.start <= n.end && n.end as usize <= s.len(), "{:?}", n.kind);
        tree.each_child(id as u32, |c| assert!(c > id as u32)); // document order
        let _ = line_at(n.start);
    }
    let find = |kind: Kind| (0..tree.nodes.len() as u32).find(|&i| tree.kind(i) == kind).unwrap();
    assert_eq!(tree.root, 0);
    assert_eq!(tree.kind(0), Kind::Module);
    assert_eq!(text(find(Kind::Import)), "import os");
    assert_eq!(text(find(Kind::ListComp)), "[x async for x in y if x]");
    assert_eq!(text(find(Kind::JoinedStr)), "f'{a!r:>{w}}'");
    assert_eq!(text(find(Kind::MatchOr)), "{1: [a, *r]} | C(k=v)");
    assert_eq!(line_at(tree.node(find(Kind::ClassDef)).start), 4);
    // the field accessors
    let f = find(Kind::FunctionDef);
    assert_eq!(tree.text_of(f, "name"), Some(&cp("f")[..]));
    let args = tree.child(f, "args").unwrap();
    assert_eq!(tree.children_of(args, "args").len(), 2);
    assert_eq!(tree.children_of(args, "kwonlyargs").len(), 1);
    assert_eq!(tree.children_of(args, "defaults").len(), 1);
    assert!(tree.child(args, "vararg").is_some());
    assert!(tree.child(f, "returns").is_some());
    let c = find(Kind::ClassDef);
    assert_eq!(tree.children_of(c, "keywords").len(), 1);
    let parents = tree.parents();
    assert_eq!(parents[0], NONE);
    assert_eq!(parents[args as usize], f);
    // spans in the JSON: after the positions, and nothing else changed
    let plain = to_json(&s, false);
    let with = to_json(&s, true);
    assert!(with.contains(r#""end_col_offset":9,"start":0,"end":9}"#));
    assert!(with.len() > plain.len());
}

#[test]
fn names_are_interned() {
    // equal names, equal ids; Python's NFKC: `ﬁ` is `fi`
    let tree = parse(&cp("fi; b; fi; \u{FB01}")).unwrap();
    let ids: Vec<u32> = (0..tree.nodes.len() as u32)
        .filter(|&i| tree.kind(i) == Kind::Name)
        .map(|i| tree.node(i).f[0])
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(ids[0], ids[2]);
    assert_eq!(ids[0], ids[3]);
    assert_ne!(ids[0], ids[1]);
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
    // seeded soups of pieces and of arbitrary code points (controls, lone
    // surrogates, NUL, values past U+10FFFF a binding never sends); every
    // tree written is JSON
    let pieces = [
        "x", "1", "1.5", "0x", "1_", "1e", "'s'", "'", "\"", "'''", "f'", "f'{", "}'", "{", "}", "(", ")", "[", "]",
        ":", ",", ";", ".", "=", "==", "+", "-", "*", "**", "/", "//", "@", "<", ">", "!", "!r", ":=", "->", "~",
        "if", "else", "elif", "for", "in", "while", "def", "class", "return", "lambda", "not", "and", "or", "is",
        "with", "as", "try", "except", "finally", "import", "from", "yield", "await", "async", "pass", "None",
        "match", "case", "type", "_", "global", "del", "raise", "\n", "\n    ", "\n  ", "\n\t", "\r\n", "\r", " ",
        "#c", "\\", "\\\n", "\\N{", "\\x", "\\u", "$", "?", "`", "\u{c}", "\u{FEFF}", "é", "ﬁ", "€", "\u{1F600}",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for k in 0..8000 {
        let mut src: Vec<u32> = Vec::new();
        for _ in 0..rng.below(50) + 1 {
            if k % 3 == 0 && rng.below(5) == 0 {
                let c = match rng.below(6) {
                    0 => rng.below(0x80) as u32,
                    1 => 0xD800 + rng.below(0x800) as u32,
                    2 => 0x110000 + rng.below(1000) as u32,
                    3 => u32::MAX - rng.below(4) as u32,
                    4 => 0,
                    _ => rng.below(0x110000) as u32,
                };
                src.push(c);
            } else {
                src.extend(cp(pieces[rng.below(pieces.len())]));
            }
        }
        let out = to_json(&src, k % 2 == 0);
        assert!(crate::json::parse_str(&out).is_ok(), "{:?}", out);
        let _ = parse(&src);
    }
}
