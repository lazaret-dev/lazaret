//! The lexers on the cases the old scanners misread, and on their edges.

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

fn js(src: &str) -> Vec<(Kind, String)> {
    lits(src, &js::tokens(&u(src), false))
}

fn jsx(src: &str) -> Vec<(Kind, String)> {
    lits(src, &js::tokens(&u(src), true))
}

fn py(src: &str) -> Vec<(Kind, String)> {
    lits(src, &py::tokens(&u(src)))
}

fn k(kind: Kind, text: &str) -> (Kind, String) {
    (kind, text.to_string())
}

#[test]
fn templates_nest_and_their_holes_are_code() {
    use Kind::*;
    assert_eq!(js("x = `a ${ `b ${c} d` } e`; y = 'q'"), vec![
        k(Template, "`a ${"), k(Template, "`b ${"), k(Template, "} d`"), k(Template, "} e`"), k(Str, "'q'")]);
    // a hole's object literal and a string with a backtick in it
    assert_eq!(js("`${ {a: '`'}.a }`"), vec![k(Template, "`${"), k(Str, "'`'"), k(Template, "}`")]);
    // `$` not before `{`, escapes
    assert_eq!(js(r"`a $b \${c} \` d`"), vec![k(Template, r"`a $b \${c} \` d`")]);
    // not closed: the rest of the text
    assert_eq!(js("`abc ${x} def"), vec![k(Template, "`abc ${"), k(Template, "} def")]);
}

#[test]
fn a_regular_expression_or_a_division() {
    use Kind::*;
    assert_eq!(js("a = b / c / d"), vec![]);
    assert_eq!(js("a = /'/.test(x); b = '\"'"), vec![k(Regex, "/'/"), k(Str, "'\"'")]);
    assert_eq!(js("return /[/']/g"), vec![k(Regex, "/[/']/g")]);
    assert_eq!(js("if (x) /re/.test(y)"), vec![k(Regex, "/re/")]);
    assert_eq!(js("f(x) / 2 / 3"), vec![]);
    assert_eq!(js("a[0] / 2 / 3"), vec![]);
    assert_eq!(js("x = {} / 2 / 1"), vec![]);
    assert_eq!(js("{} /re/.test(y)"), vec![k(Regex, "/re/")]);
    assert_eq!(js("x++ / 2 / y"), vec![]);
    assert_eq!(js("typeof /x/"), vec![k(Regex, "/x/")]);
    assert_eq!(js("if (a) b(); else /[~@]/.test(c)"), vec![k(Regex, "/[~@]/")]);
    assert_eq!(js("do /x/.exec(s); while (y)"), vec![k(Regex, "/x/")]);
    // after a member access's `.` or `?.` a name follows: a `/` there divides
    assert_eq!(js("a./b/ + c?./d/"), vec![]);
    // a `/` that would begin one not closed on its line: a character, and
    // every later `/` on its line divides (each try reads to the line's end)
    assert_eq!(js("a = / b\n'c'"), vec![k(Str, "'c'")]);
    assert_eq!(js("a = /[ x = /y/\nz = /w/"), vec![k(Regex, "/w/")]);
}

#[test]
fn comments_and_strings() {
    use Kind::*;
    assert_eq!(js("a = 'it''s' // c 'q\n/* x\ny */ b"), vec![
        k(Str, "'it'"), k(Str, "'s'"), k(Comment, "// c 'q"), k(Comment, "/* x\ny */")]);
    assert_eq!(js("#!/usr/bin/env node\nx"), vec![k(Comment, "#!/usr/bin/env node")]);
    // Annex B's HTML-like comments are code (a module reads `x <!--y` as `x < !--y`)
    assert_eq!(js("a <!-- 'b'\n --> 'c'"), vec![k(Str, "'b'"), k(Str, "'c'")]);
    // a quote not closed on its line is a string to the line's end: nothing
    // after it opens a comment (which would hide the lines below), and the
    // next line is code
    assert_eq!(js("x = 'abc /* d\ny = 1 // e\n*/"), vec![k(Str, "'abc /* d"), k(Comment, "// e")]);
    assert_eq!(js("x = \"a\\\nb /*\nc"), vec![k(Str, "\"a\\\nb /*")]);
    // a string's line continuation
    assert_eq!(js("'a\\\nb'"), vec![k(Str, "'a\\\nb'")]);
}

#[test]
fn jsx_text_attributes_and_code() {
    use Kind::*;
    assert_eq!(jsx("x = <a href=\"it's\" b={'c'}>don't {y} </a>; z = 'q'"), vec![
        k(JsxStr, "\"it's\""), k(Str, "'c'"), k(JsxText, "don't "), k(JsxText, " "), k(Str, "'q'")]);
    // nested elements, a fragment, an element in a hole's code
    assert_eq!(jsx("<><b>it's</b>{xs.map(x => <i>'{x}</i>)}</>"), vec![
        k(JsxText, "it's"), k(JsxText, "'")]);
    // a comparison is not JSX, nor TypeScript's generic arrow
    assert_eq!(jsx("a < b && c > 'd'"), vec![k(Str, "'d'")]);
    assert_eq!(jsx("const f = <T,>(x: T) => 'y'"), vec![k(Str, "'y'")]);
    assert_eq!(jsx("const f = <T extends U>(x: T) => 'y'"), vec![k(Str, "'y'")]);
    // without JSX, `<a>` is a comparison, and the quote, not closed on its line, a string to its end
    assert_eq!(js("x = <a>it's</a>"), vec![k(Str, "'s</a>")]);
    // TypeScript's type arguments after a tag's name are code (an arrow's `=>` in them too)
    assert_eq!(jsx("x = <Table<Row> d={1}>it's</Table>"), vec![k(JsxText, "it's")]);
    assert_eq!(jsx("x = <F<(a: 'b') => void> c=\"d\" />; y = 'q'"), vec![k(Str, "'b'"), k(JsxStr, "\"d\""), k(Str, "'q'")]);
}

#[test]
fn linear_on_what_would_be_quadratic() {
    // a `/` in a regular expression's place, and nothing closing it, over and over
    for src in ["=/[".repeat(60_000), "(/".repeat(90_000), "x = '\n".repeat(30_000), "`${".repeat(60_000)] {
        let t = std::time::Instant::now();
        for jsx in [false, true] {
            let _ = js::tokens(&u(&src), jsx);
        }
        assert!(t.elapsed().as_secs_f64() < 2.0, "{:?}: {:?}", &src[..6], t.elapsed());
    }
}

#[test]
fn every_character_once_and_no_panic() {
    let samples = ["", "`", "${", "}", "/", "<", "</", "<a", "<a {", "'", "\"\\", "`${`${`", "a/*", "x=/[", "#!",
        "<!-", "-->", "\u{2028}", "<a>{</a>", "})]>", "`${}`}"];
    for s in samples {
        for jsx in [false, true] {
            let t = js::tokens(&u(s), jsx);
            let mut at = 0u32;
            for tok in &t {
                assert!(tok.start >= at && tok.end > tok.start && tok.end as usize <= s.chars().count(), "{s:?} {t:?}");
                at = tok.end;
            }
        }
        let t = py::tokens(&u(s));
        let mut at = 0u32;
        for tok in &t {
            assert!(tok.start >= at && tok.end >= tok.start, "{s:?} {t:?}");
            at = tok.end;
        }
    }
}

#[test]
fn python_strings_fstrings_and_comments() {
    use Kind::*;
    assert_eq!(py("x = 'a#b'  # c 'd'\ny = b\"q\"\n"), vec![k(Str, "'a#b'"), k(Comment, "# c 'd'"), k(Str, "b\"q\"")]);
    assert_eq!(py("f'{a!r} {\"#\"} {b:>{w}}'\n"), vec![
        k(Template, "f'"), k(Template, " "), k(Str, "\"#\""), k(Template, " "), k(Template, ">"), k(Template, "'")]);
    assert_eq!(py("s = '''a\n# not a comment\n'''  # one\n"), vec![k(Str, "'''a\n# not a comment\n'''"), k(Comment, "# one")]);
    // past a token the tokenizer refuses, the fallback reading
    assert_eq!(py("x = 1\ny = $ 'a#'  # c\n"), vec![k(Str, "'a#'"), k(Comment, "# c")]);
    assert_eq!(py("x = 'abc\ny = 'd'\n"), vec![k(Str, "'abc"), k(Str, "'d'")]);
}

#[test]
fn structure_intersects_the_jsx_readings() {
    // both readings agree on 'q' (and the JSX reading's text is no literal of the plain one)
    let src = u("x = <a>its</a>; y = 'q'");
    let st = structure(&src, "js", true).unwrap();
    let q = (src.len() - 3, src.len());
    assert_eq!(st.literals, vec![q]);
    assert_eq!(st.strings, vec![q]);
    // where they disagree (the plain reading pairs the text's apostrophe with the quote of 'q'),
    // only what both read as literal is kept: what one reads as code stays code
    let src = u("x = <a>it's</a>; y = 'q'");
    let st = structure(&src, "js", true).unwrap();
    let text: Vec<String> = st.literals.iter().map(|&(a, b)| src[a..b].iter().map(|&x| char::from_u32(x).unwrap()).collect()).collect();
    assert_eq!(text, vec!["'s".to_string(), "'".to_string(), "'".to_string()]);
    // a TypeScript file: one reading
    assert_eq!(structure(&src, "js", false).unwrap(), Structure::of(&js::tokens(&src, false)));
}

#[test]
fn structure_intersects_the_python_readings() {
    // 3.12 reads a string in the hole; 3.11 an f-string to the hole's first
    // quote, and a comment after it: only the comment both see is one, and
    // the hole is code
    let src = u("x = f\"{a + \"#\"}\"  # c\n");
    let st = structure(&src, "py", false).unwrap();
    assert_eq!(st.comments, vec![(18, 21)]);
    assert_eq!(st.literals, vec![(4, 6), (11, 12)]);
    assert_eq!(st.strings, vec![]);
    // where they agree, every string, f-string text and comment
    let src = u("s = 'a'  # b\nt = f'x{y}z'  # c\n");
    let st = structure(&src, "py", false).unwrap();
    assert_eq!(st.comments, vec![(9, 12), (27, 30)]);
    assert_eq!(st.strings, vec![(4, 7)]);
    // (the f-string's start, its texts, its end: its hole `{y}` is code)
    assert_eq!(st.literals, vec![(4, 7), (17, 19), (19, 20), (23, 24), (24, 25)]);
}

fn s(v: &[u32]) -> String {
    v.iter().map(|&x| char::from_u32(x).unwrap_or('\u{FFFD}')).collect()
}

#[test]
fn string_values_as_the_runtimes_read_them() {
    // JavaScript: every escape, a line continuation, a surrogate pair
    assert_eq!(value::js(&u(r"'child_pro\x63ess'")).map(|v| s(&v)), Some("child_process".into()));
    assert_eq!(value::js(&u("'a\\\nb\\u{41}\\101\\0'")).map(|v| s(&v)), Some("abAA\0".into()));
    assert_eq!(value::js(&u(r"'😀'")).map(|v| s(&v)), Some("😀".into()));
    assert_eq!(value::js(&u("`a\r\nb`")).map(|v| s(&v)), Some("a\nb".into()));
    // not closed, or its quote escaped
    assert_eq!(value::js(&u("'abc")), None);
    assert_eq!(value::js(&u(r"'abc\'")), None);
    // an escape JavaScript refuses: no value (jsparse's cooking would read one)
    assert_eq!(value::js(&u(r"'12ab\x2'")), None);
    assert_eq!(value::js(&u(r"'\u12'")), None);
    assert_eq!(value::js(&u(r"'\u{110000}'")), None);
    assert_eq!(value::js(&u(r"`\1`")), None);
    assert_eq!(value::js(&u(r"`\01`")), None);
    // a string's legacy octal escapes and \8 are sloppy mode's; a template's \0
    assert_eq!(value::js(&u(r"'\1\8'")).map(|v| s(&v)), Some("\u{1}8".into()));
    assert_eq!(value::js(&u(r"`\0`")).map(|v| s(&v)), Some("\0".into()));
    assert_eq!(value::js(&u(r"'\u{0000041}'")).map(|v| s(&v)), Some("A".into()));
    // Python: prefixes, raw strings, bytes, \N{…}, triple quotes
    let py = |x: &str| value::py(&u(x)).map(|v| (s(&v.chars), v.bytes));
    assert_eq!(py(r"'os.sys\x74em'"), Some(("os.system".into(), false)));
    assert_eq!(py(r"b'\x63url'"), Some(("curl".into(), true)));
    assert_eq!(py(r"R'\x63'"), Some((r"\x63".into(), false)));
    assert_eq!(py(r"'\N{LATIN SMALL LETTER E}val'"), Some(("eval".into(), false)));
    assert_eq!(py("'''a\nb'''"), Some(("a\nb".into(), false)));
    assert_eq!(py("u'x'"), Some(("x".into(), false)));
    // not constants, or refused
    assert_eq!(py("f'x'"), None);
    assert_eq!(py("'abc"), None);
    assert_eq!(py(r"'\x6'"), None);
    assert_eq!(py("b'é'"), None);
    assert_eq!(py("'a\nb'"), None);
}

#[test]
fn code_escapes_are_the_ones_that_hide_characters() {
    assert!(value::has_code_escape(&u(r"'a\x41'"), "js"));
    assert!(value::has_code_escape(&u(r"'\u{41}'"), "js"));
    assert!(value::has_code_escape(&u(r"'\101'"), "js"));
    assert!(value::has_code_escape(&u(r"'\N{BULLET}'"), "py"));
    assert!(!value::has_code_escape(&u(r"'a\nb\'c\\'"), "js"));
    assert!(!value::has_code_escape(&u(r"'a\0'"), "js"));
    assert!(!value::has_code_escape(&u(r"r'\x41'"), "py"));
    assert!(!value::has_code_escape(&u(r"'\\x41'"), "js"));
}

/// (text of each run, its value, its literal count, its code escape)
fn runs(src: &str, lang: &str) -> Vec<(String, String, usize, bool)> {
    let text = u(src);
    let toks = if lang == "py" { py::tokens(&text) } else { js::tokens(&text, false) };
    value::runs(&text, &toks, lang, 4000)
        .into_iter()
        .map(|r| (s(&text[r.start..r.end]), s(&r.value.chars), r.literals, r.code_escape))
        .collect()
}

fn run(text: &str, value: &str, literals: usize, escape: bool) -> (String, String, usize, bool) {
    (text.to_string(), value.to_string(), literals, escape)
}

#[test]
fn literals_joined_as_the_runtime_joins_them() {
    // quotes of every kind, a comment and lines between
    assert_eq!(
        runs("require('child_' + /* x */ \"pro\" +\n `cess`)", "js"),
        vec![run("'child_' + /* x */ \"pro\" +\n `cess`", "child_process", 3, false)]
    );
    // one literal: only with a code escape
    assert_eq!(runs("x = 'a\\x62' ; y = 'cd'", "js"), vec![run("'a\\x62'", "ab", 1, true)]);
    // what binds tighter takes its literal
    assert_eq!(runs("x * 'a' + 'b' + 'c'", "js"), vec![run("'b' + 'c'", "bc", 2, false)]);
    assert_eq!(runs("'a' + 'b' + 'c'.length", "js"), vec![run("'a' + 'b'", "ab", 2, false)]);
    assert_eq!(runs("'a' + 'b'[0]", "js"), vec![]);
    assert_eq!(runs("x - 'a' + 'b'", "js"), vec![]);
    assert_eq!(runs("f(+'a' + 'b')", "js"), vec![]);
    assert_eq!(runs("x + 'a' + 'b'", "js"), vec![run("'a' + 'b'", "ab", 2, false)]);
    assert_eq!(runs("typeof 'a' + 'b'", "js"), vec![]);
    // a tagged template is a call
    assert_eq!(runs("'a' + tag`b`", "js"), vec![]);
    // a template with holes is not a constant
    assert_eq!(runs("'a' + `b${c}`", "js"), vec![]);
    // Python: adjacent literals join before any operator, lines apart in brackets
    assert_eq!(runs("x = ('chi'\n  \"ld\")", "py"), vec![run("'chi'\n  \"ld\"", "child", 2, false)]);
    assert_eq!(runs("'a' 'b'.join(x)", "py"), vec![run("'a' 'b'", "ab", 2, false)]);
    assert_eq!(runs("x * 'a' 'b' + 'c'", "py"), vec![]);
    // at the top level a line break ends the statement
    assert_eq!(runs("'a'\n'b'", "py"), vec![]);
    // a comment between; past a token Python refuses, strings with code
    // between them (read plainly, no punctuator known) are not adjacent
    assert_eq!(runs("f(x, 'a' # c\n 'b')", "py"), vec![run("'a' # c\n 'b'", "ab", 2, false)]);
    assert_eq!(runs("f(x ? 'a', 'b')", "py"), vec![]);
    assert_eq!(runs("f(x ? 'a' 'b')", "py"), vec![run("'a' 'b'", "ab", 2, false)]);
    assert_eq!(runs("x = 'a' \\\n 'b'", "py"), vec![run("'a' \\\n 'b'", "ab", 2, false)]);
    // str and bytes do not join; % formats its literal
    assert_eq!(runs("b'a' + 'b'", "py"), vec![]);
    assert_eq!(runs("'a' + 'b%s' % x", "py"), vec![]);
    assert_eq!(runs("os.system('cu' + 'rl ' + u)", "py"), vec![run("'cu' + 'rl '", "curl ", 2, false)]);
    // an f-string is not a constant
    assert_eq!(runs("'a' + f'b'", "py"), vec![]);
}
