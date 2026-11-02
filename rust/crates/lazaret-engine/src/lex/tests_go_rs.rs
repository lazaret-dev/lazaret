//! The Go and Rust lexers (0.1.9) on the cases a quote-pairing scanner
//! misreads, and on their edges.

use super::*;

fn u(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

/// (kind, text) of each token that is not a name, a number or a punctuator.
fn lits(src: &str, toks: &[Token]) -> Vec<(Kind, String)> {
    let cs: Vec<char> = src.chars().collect();
    toks.iter()
        .filter(|t| !matches!(t.kind, Kind::Name | Kind::Num | Kind::Punct))
        .map(|t| (t.kind, cs[t.start as usize..t.end as usize].iter().collect()))
        .collect()
}

fn texts(src: &str, toks: &[Token]) -> Vec<String> {
    let cs: Vec<char> = src.chars().collect();
    toks.iter().map(|t| cs[t.start as usize..t.end as usize].iter().collect()).collect()
}

fn go(src: &str) -> Vec<(Kind, String)> {
    lits(src, &go::tokens(&u(src)))
}

fn rs(src: &str) -> Vec<(Kind, String)> {
    lits(src, &rs::tokens(&u(src)))
}

fn k(kind: Kind, text: &str) -> (Kind, String) {
    (kind, text.to_string())
}

#[test]
fn go_comments_strings_and_runes() {
    use Kind::*;
    // a block comment does not nest; a line comment holds quotes
    assert_eq!(go("a /* x /* y */ b */ \"s\""), vec![k(Comment, "/* x /* y */"), k(Str, "\"s\"")]);
    assert_eq!(go("x := 1 // it's \"q\"\ny := 'a'"), vec![k(Comment, "// it's \"q\""), k(Str, "'a'")]);
    // a raw string spans lines, takes no escapes and holds quotes and comment openers
    assert_eq!(go("s := `a\\\n\"b\" // c`; t := \"\\\"\""), vec![k(Str, "`a\\\n\"b\" // c`"), k(Str, "\"\\\"\"")]);
    // runes with escapes, including the quote itself
    assert_eq!(go(r"a := '\'' + '\\' + '\x41' + 'é'"), vec![k(Str, r"'\''"), k(Str, r"'\\'"), k(Str, r"'\x41'"), k(Str, "'é'")]);
    // a comment opener inside a string is not one
    assert_eq!(go("u := \"http://x\" // real"), vec![k(Str, "\"http://x\""), k(Comment, "// real")]);
}

#[test]
fn go_what_the_compiler_refuses_hides_nothing_below() {
    use Kind::*;
    // an interpreted string not closed on its line ends there: the next line is code
    assert_eq!(go("x := \"abc\ny := 'q'"), vec![k(Str, "\"abc"), k(Str, "'q'")]);
    // a block comment not closed, and a raw string not closed, run to the end
    assert_eq!(go("a /* b\n'c'"), vec![k(Comment, "/* b\n'c'")]);
    assert_eq!(go("a `b\n'c'"), vec![k(Str, "`b\n'c'")]);
}

#[test]
fn go_numbers_and_names() {
    let src = "x := 0x1p-2 + 1_000 + .5e+3 + 3i + a.b";
    let toks = go::tokens(&u(src));
    let nums: Vec<String> = texts(src, &toks.iter().copied().filter(|t| t.kind == Kind::Num).collect::<Vec<_>>());
    assert_eq!(nums, vec!["0x1p-2", "1_000", ".5e+3", "3i"]);
    // unicode names
    let src = "π := héllo";
    let names: Vec<String> = texts(src, &go::tokens(&u(src)).into_iter().filter(|t| t.kind == Kind::Name).collect::<Vec<_>>());
    assert_eq!(names, vec!["π", "héllo"]);
}

#[test]
fn rust_comments_nest_and_doc_comments_are_comments() {
    use Kind::*;
    assert_eq!(rs("a /* x /* y */ still */ \"s\""), vec![k(Comment, "/* x /* y */ still */"), k(Str, "\"s\"")]);
    assert_eq!(rs("/// it's a doc\n//! inner\nlet x = 1; // c"), vec![k(Comment, "/// it's a doc"), k(Comment, "//! inner"), k(Comment, "// c")]);
    // a comment opener in a string, a quote in a comment
    assert_eq!(rs("let u = \"http://x\"; /* \" */ let v = 'c';"), vec![k(Str, "\"http://x\""), k(Comment, "/* \" */"), k(Str, "'c'")]);
}

#[test]
fn rust_strings_raw_byte_and_c() {
    use Kind::*;
    // spans lines; a backslash takes the next character, a newline too
    assert_eq!(rs("let s = \"a\\\"b\nc\\\n d\"; x"), vec![k(Str, "\"a\\\"b\nc\\\n d\"")]);
    // raw: no escapes, quotes inside, any number of hashes
    assert_eq!(rs("r\"a\\\" r#\"say \"hi\" \\\"# r##\"x\"#y\"## z"), vec![k(Str, "r\"a\\\""), k(Str, "r#\"say \"hi\" \\\"#"), k(Str, "r##\"x\"#y\"##")]);
    // byte and C strings, raw or not, and bytes
    assert_eq!(rs("b\"x\" br#\"y\"# c\"z\" cr\"w\" b'q' b'\\''"), vec![
        k(Str, "b\"x\""), k(Str, "br#\"y\"#"), k(Str, "c\"z\""), k(Str, "cr\"w\""), k(Str, "b'q'"), k(Str, "b'\\''")]);
    // a name that ends in r, b or c is a name, not a prefix
    assert_eq!(rs("for \"s\"; ab\"t\""), vec![k(Str, "\"s\""), k(Str, "\"t\"")]);
    let src = "for \"s\"";
    assert_eq!(texts(src, &rs::tokens(&u(src))), vec!["for", "\"s\""]);
}

#[test]
fn rust_characters_are_not_lifetimes() {
    use Kind::*;
    assert_eq!(rs("let c = 'a'; let d = '\\n'; let e = '\\u{1F600}'; let f = '\\'';"),
        vec![k(Str, "'a'"), k(Str, "'\\n'"), k(Str, "'\\u{1F600}'"), k(Str, "'\\''")]);
    // lifetimes and labels: names, and the quote after one is a string's
    let src = "fn f<'a, 'static>(x: &'a str) -> &'static str { 'outer: loop { break 'outer; } } let q = \"s\";";
    let toks = rs::tokens(&u(src));
    let lifetimes: Vec<String> = texts(src, &toks.iter().copied().filter(|t| t.kind == Kind::Name && src.chars().nth(t.start as usize) == Some('\'')).collect::<Vec<_>>());
    assert_eq!(lifetimes, vec!["'a", "'static", "'a", "'static", "'outer", "'outer"]);
    assert_eq!(lits(src, &toks), vec![k(Str, "\"s\"")]);
    // a character that is a quote of the other kind
    assert_eq!(rs("let q = '\"'; let r = \"'\";"), vec![k(Str, "'\"'"), k(Str, "\"'\"")]);
}

#[test]
fn rust_raw_identifiers_numbers_and_shebang() {
    use Kind::*;
    let src = "let r#type = 1..2; let a = 1.max(2); let b = 1.5e-3f64 + 0x1e + 1_000u32; t.0.1";
    let toks = rs::tokens(&u(src));
    let names: Vec<String> = texts(src, &toks.iter().copied().filter(|t| t.kind == Kind::Name).collect::<Vec<_>>());
    assert!(names.contains(&"r#type".to_string()), "{names:?}");
    assert!(names.contains(&"max".to_string()), "{names:?}");
    let nums: Vec<String> = texts(src, &toks.iter().copied().filter(|t| t.kind == Kind::Num).collect::<Vec<_>>());
    assert_eq!(nums, vec!["1", "2", "1", "2", "1.5e-3f64", "0x1e", "1_000u32", "0.1"]);
    // (`t.0.1` is one float to the lexer, as rustc's: the parser splits it)
    // a shebang is a comment; an inner attribute is not
    assert_eq!(rs("#!/usr/bin/env run-cargo-script\nfn main() {}"), vec![k(Comment, "#!/usr/bin/env run-cargo-script")]);
    assert_eq!(rs("#![allow(dead_code)]\nlet s = \"x\";"), vec![k(Str, "\"x\"")]);
}

#[test]
fn rust_not_closed_runs_to_the_end() {
    use Kind::*;
    assert_eq!(rs("a /* b /* c */\n\"d\""), vec![k(Comment, "/* b /* c */\n\"d\"")]);
    assert_eq!(rs("a \"b\n'c'"), vec![k(Str, "\"b\n'c'")]);
    assert_eq!(rs("a r#\"b\" c"), vec![k(Str, "r#\"b\" c")]);
}

#[test]
fn go_and_rust_structure() {
    let t = u("// c\nx := \"a\" + `b`");
    let st = structure(&t, "go", false).unwrap();
    assert_eq!((st.comments.len(), st.strings.len(), st.literals.len()), (1, 2, 2));
    let t = u("/* c */ let x = r#\"a\"#; // d");
    let st = structure(&t, "rs", false).unwrap();
    assert_eq!((st.comments.len(), st.strings.len(), st.literals.len()), (2, 1, 1));
    assert!(structure(&t, "c", false).is_none());
}

#[test]
fn go_and_rust_are_linear_and_total() {
    // quotes, openers and prefixes that never close, over and over
    for src in ["x = '\n".repeat(30_000), "/*".repeat(60_000), "r#\"".repeat(60_000), "'a ".repeat(60_000), "\"\\".repeat(60_000), "1.".repeat(60_000), "`".repeat(60_000)] {
        let t = std::time::Instant::now();
        let _ = go::tokens(&u(&src));
        let _ = rs::tokens(&u(&src));
        assert!(t.elapsed().as_secs_f64() < 2.0, "{:?}: {:?}", &src[..2], t.elapsed());
    }
    let samples = ["", "'", "\"", "`", "/", "/*", "//", "r", "r#", "r#\"", "br", "b'", "b'\\", "'\\", "'a", "#!", "0x", "1e", "1.", "\\", "\u{0}", "\u{feff}x", "é", "'é'", "🦀", "'🦀'"];
    for s in samples {
        for lang in ["go", "rs"] {
            let text = u(s);
            let t = if lang == "go" { go::tokens(&text) } else { rs::tokens(&text) };
            let mut at = 0u32;
            for tok in &t {
                assert!(tok.start >= at && tok.end > tok.start && tok.end as usize <= text.len(), "{lang} {s:?} {t:?}");
                at = tok.end;
            }
        }
    }
}
