//! linre's own tests: the parser, the programs, the matchers against each
//! other, and no panic on seeded random patterns and texts. Its answers
//! are held to Python's `re` by python/tests/architecture/test_linre*.py.

use super::*;

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn spans(re: &Regex, text: &str) -> Vec<(usize, usize)> {
    let t = cps(text);
    re.finditer(&t).map(|m| m.span()).collect()
}

/// A match as Python shows it: start, end, lastindex (-1: None), and each
/// group's span ((-1, -1): None).
type View = Option<(isize, isize, isize, Vec<(isize, isize)>)>;

fn view(m: Option<Match>) -> View {
    m.map(|m| {
        let g = m.regex().groups();
        (m.start() as isize, m.end() as isize, m.lastindex, (1..=g).map(|k| (m.start_of(k), m.end_of(k))).collect())
    })
}

/// The same from a matcher's slots (each group's start and end, the last
/// group closed, the match's start) and end.
fn view_slots(re: &Regex, found: Option<(Vec<isize>, usize)>) -> View {
    found.map(|(slots, end)| {
        let g = re.groups();
        let groups = (0..g)
            .map(|k| {
                let (a, b) = (slots[2 * k], slots[2 * k + 1]);
                if a >= 0 && b >= 0 {
                    (a, b)
                } else {
                    (-1, -1)
                }
            })
            .collect();
        (slots[2 * g + 1], end as isize, slots[2 * g], groups)
    })
}

/// A small seeded generator (xorshift).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

// ---------------------------------------------------------------- parser

#[test]
fn accepts_the_syntax_the_pack_uses() {
    let ok: &[(&str, u32, usize)] = &[
        (r"abc", 0, 0),
        (r"a\.b\(\)\[\]\{\}\\\n\t\x41é\U0001F600\101\0", 0, 0),
        (r"[a-z_$][\w$]*", 0, 0),
        (r"[^\s\d]+|[\W\S\D]", 0, 0),
        (r"[]a]|[^]a]|[a-]|[\]]|[\\]", 0, 0),
        (r".+?|.*|.?|.{2}|.{2,}|.{,3}|.{1,3}?", DOTALL, 0),
        (r"(a)(?:b)(?P<name>c)", 0, 2),
        (r"^a$|\Aa\Z|\bx\B", MULTILINE, 0),
        (r"(?<=ab)c(?<!x)(?=d)(?!e)", 0, 0),
        (r"(?<![\w$.])[A-Za-z_$][\w$]*(?=[ \t]{0,8}\()", 0, 0),
        (r"(?i)straße|(?-i:A)b(?s:.)(?m:^)", 0, 0),
        (r"(?x) a b  # comment
              [ ]c", 0, 0),
        (r"x{", 0, 0),
        (r"a{2,1a}", 0, 0),
        (r"(?:)|", 0, 0),
        (r"(a|b)(c)", IGNORECASE | MULTILINE | DOTALL | VERBOSE, 2),
        (r"(?a)\w+\b", 0, 0),
        (r"\ud800[\udc00-\udfff]", 0, 0),
    ];
    for &(src, flags, groups) in ok {
        match Regex::compile(src, flags) {
            Ok(re) => {
                if groups > 0 {
                    assert_eq!(re.groups(), groups, "{:?}", src);
                }
            }
            Err(e) => panic!("{:?} flags {} did not compile: {}", src, flags, e),
        }
    }
    let re = Regex::compile(r"(a)(?:b)(?P<name>c)", 0).unwrap();
    assert_eq!((re.groups(), re.group_index("name")), (2, Some(2)));
}

#[test]
fn python_errors_are_errors() {
    // patterns Python's re rejects (a global flag after the start: 3.11 on;
    // 3.10 warns and applies it to the whole pattern)
    for src in [
        "(", ")", "[a", "a**", "a{2}{3}", "*a", "+", "?", "(?P<1a>x)", "(?P<a>x)(?P<a>y)", "(?P=b)", "\\", "[z-a]",
        "(?<=a*)b", "(?<=a|bc)d", "(?i", "(?z)", "a(?i)b", "\\9", "(?P<a>x)(?P=a", "[\\d-z]", "x{3,2}", "\\c",
    ] {
        match Regex::compile(src, 0) {
            Err(e) => assert!(!e.refused, "{:?} is Python's error, not a refusal: {}", src, e),
            Ok(_) => panic!("{:?} should not compile", src),
        }
    }
}

#[test]
fn refuses_with_a_reason() {
    let cases: &[(&str, &str)] = &[
        (r"(['\x22])x\1", "backreference"),
        (r"(?P<q>a)(?P=q)", "backreference"),
        (r"(a)?(?(1)b|c)", "conditional"),
        (r"a(?=.*b)", "lookahead of unbounded width"),
        (r"a(?!\s*\()", "lookahead of unbounded width"),
        (r"(a|)*", "empty string"),
        (r"(?:a*)+b", "empty string"),
        (r"(?=(a))a", "capturing group inside a positive lookaround"),
        (r"(?>a+)b", "atomic"),
        (r"a++", "possessive"),
        (r"\N{DIGIT ONE}", "character names"),
        (r"(?:a{1,2000}){1,2000}", "too large"),
        (r"(?<=a{1001})b", "wider than 1000"),
    ];
    for &(src, why) in cases {
        match Regex::compile(src, 0) {
            Err(e) => {
                assert!(e.refused, "{:?}: {}", src, e);
                assert!(e.msg.contains(why), "{:?}: {:?} does not say {:?}", src, e.msg, why);
            }
            Ok(_) => panic!("{:?} should be refused", src),
        }
    }
    // a lookahead of bounded width, a fixed-width lookbehind: accepted
    for src in [r"a(?=b{1,9}c)", r"a(?!\s{0,64}\()", r"(?<=ab|cd)e", r"(?<![\w$.]{2})x", r"x(?=(?:ab|c){1,3})"] {
        assert!(Regex::compile(src, 0).is_ok(), "{:?}", src);
    }
}

#[test]
fn flags_inline_and_as_arguments() {
    assert_eq!(flags_from_letters("imsxa"), IGNORECASE | MULTILINE | DOTALL | VERBOSE | ASCII);
    let t = cps("A\nb");
    for (src, flags) in [(r"(?i)a", 0), (r"a", IGNORECASE)] {
        let re = Regex::compile(src, flags).unwrap();
        assert_eq!(re.search(&t).map(|m| m.span()), Some((0, 1)));
    }
    for (src, flags) in [(r"(?s)A.b", 0), (r"A.b", DOTALL)] {
        assert!(Regex::compile(src, flags).unwrap().fullmatch(&t).is_some());
    }
    assert!(Regex::compile(r"A.b", 0).unwrap().fullmatch(&t).is_none());
    for (src, flags) in [(r"(?m)^b$", 0), (r"^b$", MULTILINE)] {
        assert_eq!(Regex::compile(src, flags).unwrap().search(&t).map(|m| m.span()), Some((2, 3)));
    }
    // (UNICODE is reported, as Python's pattern.flags does)
    assert_eq!(Regex::compile("a", 0).unwrap().flags() & UNICODE, UNICODE);
}

// ---------------------------------------------------------------- answers

#[test]
fn basics() {
    let re = Regex::compile(r"a+b", 0).unwrap();
    assert_eq!(spans(&re, "xaab ab b"), vec![(1, 4), (5, 7)]);
    let re = Regex::compile(r"a*?", 0).unwrap();
    assert_eq!(spans(&re, "aa"), vec![(0, 0), (0, 1), (1, 1), (1, 2), (2, 2)]);
    let re = Regex::compile(r"(?:(a)|b)*", 0).unwrap();
    let t = cps("ab");
    let m = re.match_(&t).unwrap();
    assert_eq!((m.start_of(1), m.end_of(1), m.lastindex), (0, 1, 1));
}

#[test]
fn python_answers() {
    // (pattern, flags, text, finditer as (start, end, lastindex, groups))
    type Case<'a> = (&'a str, u32, &'a str, Vec<(isize, isize, isize, Vec<(isize, isize)>)>);
    let cases: Vec<Case> = vec![
        (r"x*", 0, "axx", vec![(0, 0, -1, vec![]), (1, 3, -1, vec![]), (3, 3, -1, vec![])]),
        (r"$", 0, "a\n", vec![(1, 1, -1, vec![]), (2, 2, -1, vec![])]),
        (r"(a)|b", 0, "ba", vec![(0, 1, -1, vec![(-1, -1)]), (1, 2, 1, vec![(1, 2)])]),
        (r"(a)(b)?", 0, "a", vec![(0, 1, 1, vec![(0, 1), (-1, -1)])]),
        (r"((a)b)", 0, "ab", vec![(0, 2, 1, vec![(0, 2), (0, 1)])]),
        (r"(?:(a)|(b))+", 0, "ab", vec![(0, 2, 2, vec![(0, 1), (1, 2)])]),
        (r"\b", 0, "", vec![]),
        (r"\b\w+\b", 0, "ab cd", vec![(0, 2, -1, vec![]), (3, 5, -1, vec![])]),
        (r"(?i)k", 0, "K\u{212A}k", vec![(0, 1, -1, vec![]), (1, 2, -1, vec![]), (2, 3, -1, vec![])]),
        (r"(?i)s", 0, "S\u{17F}", vec![(0, 1, -1, vec![]), (1, 2, -1, vec![])]),
        // (an astral letter written in a class under IGNORECASE: both cases,
        // as Python 3.13 on and pyre; 3.10-3.12 match neither)
        (r"(?i)[\U00010400a]", 0, "A\u{10428}\u{10400}", vec![(0, 1, -1, vec![]), (1, 2, -1, vec![]), (2, 3, -1, vec![])]),
        (r"(?ai)[\U00010400-\U00010401]", 0, "\u{10428}\u{10400}", vec![(1, 2, -1, vec![])]),
        (r"(?i)\U00010400", 0, "A\u{10428}\u{10400}", vec![(1, 2, -1, vec![]), (2, 3, -1, vec![])]),
        (r"\s+", 0, "a\u{1c}\u{85}\u{a0}b", vec![(1, 4, -1, vec![])]),
        (r"\d", 0, "1\u{663}x", vec![(0, 1, -1, vec![]), (1, 2, -1, vec![])]),
        (r"(?<=a)b|(?<!a)c", 0, "abcac", vec![(1, 2, -1, vec![]), (2, 3, -1, vec![])]),
        (r"a(?=bc|d)", 0, "abcadab", vec![(0, 1, -1, vec![]), (3, 4, -1, vec![])]),
        (r".", 0, "a\nb", vec![(0, 1, -1, vec![]), (2, 3, -1, vec![])]),
        (r"^.", MULTILINE, "a\nb", vec![(0, 1, -1, vec![]), (2, 3, -1, vec![])]),
    ];
    for (src, flags, text, want) in cases {
        let re = Regex::compile(src, flags).unwrap();
        let t: Vec<u32> = text.chars().map(|c| c as u32).collect();
        let got: Vec<_> = re.finditer(&t).map(|m| view(Some(m)).unwrap()).collect();
        assert_eq!(got, want, "{:?} on {:?}", src, text);
    }
    // a lone surrogate is a character like any other
    let re = Regex::compile(r"[^a]", 0).unwrap();
    assert_eq!(re.search(&[0x61, 0xD800]).map(|m| m.span()), Some((1, 2)));
    // pos and endpos: a lookbehind sees before pos, nothing sees past endpos
    let re = Regex::compile(r"(?<=a)b\b", 0).unwrap();
    let t = cps("abc");
    assert_eq!(re.search_at(&t, 1, 2).map(|m| m.span()), Some((1, 2)));
    assert_eq!(re.search_at(&t, 1, 3).map(|m| m.span()), None);
    // a match past the window's end: `$` reads the text there, a repeat fails
    let t = cps("ab\ncd");
    assert_eq!(Regex::compile(r"$", MULTILINE).unwrap().match_at(&t, 2, 1).map(|m| m.span()), Some((2, 2)));
    assert!(Regex::compile(r"x*", 0).unwrap().match_at(&t, 2, 1).is_none());
    assert_eq!(Regex::compile(r"", 0).unwrap().match_at(&t, 2, 1).map(|m| m.span()), Some((2, 2)));
}

#[test]
fn sub_and_split() {
    let re = Regex::compile(r"(-)|b", 0).unwrap();
    let t = cps("a-b-c");
    let out = re.sub_fn(&t, 0, |m| {
        let mut v = cps("<");
        v.extend_from_slice(m.group0());
        v.push('>' as u32);
        v
    });
    assert_eq!(out, cps("a<-><b><->c"));
    let parts: Vec<Option<Vec<u32>>> = re.split(&t, 0).into_iter().map(|p| p.map(|s| s.to_vec())).collect();
    let want: Vec<Option<Vec<u32>>> = vec![Some(cps("a")), Some(cps("-")), Some(cps("")), None, Some(cps("")), Some(cps("-")), Some(cps("c"))];
    assert_eq!(parts, want);
}

// ---------------------------------------------------------------- the matchers against each other

/// Every way of answering agrees: the public entry points (DFAs, literal
/// scans, the backtracker for groups), the Pike VM alone, and the
/// backtracker alone (sre's search: a try from each start in turn).
fn agree(re: &Regex, text: &[u32], pos: isize, endpos: isize) {
    let p = &re.inner.progs;
    let (a, b) = Regex::clamp(text, pos, endpos);
    let mut pc = pike::PikeCache::new();
    let mut bt = backtrack::Backtracker::new();
    let mut oracle = looks::Oracle::new();
    let ctx = || format!("{:?} on {:?} [{}, {}]", re, text, pos, endpos);
    // search
    let want = view(re.search_at(text, pos, endpos));
    let pike = if a <= b { pike::search(p, &p.fwd, text, a, b, Want { anchored: false, must_advance: false, end_at: None }, &mut pc) } else { None };
    assert_eq!(view_slots(re, pike), want, "search, Pike VM: {}", ctx());
    if a <= b && backtrack::fits(&p.fwd_bt, b - a + 1) {
        let mut found = None;
        for q in a..=b {
            let r = backtrack::anchored(p, &p.fwd_bt, text, q, b, false, usize::MAX, &mut bt, &mut oracle, &mut 0).unwrap();
            if r.is_some() {
                found = r;
                break;
            }
        }
        assert_eq!(view_slots(re, found), want, "search, backtracker: {}", ctx());
    }
    // match and fullmatch (a window past the text's end included)
    for (full, prog, bt_prog) in [(false, &p.fwd, &p.fwd_bt), (true, &p.full, &p.full_bt)] {
        let want = view(if full { re.fullmatch_at(text, pos, endpos) } else { re.match_at(text, pos, endpos) });
        let pike = pike::search(p, prog, text, a, b, Want { anchored: true, must_advance: false, end_at: None }, &mut pc);
        assert_eq!(view_slots(re, pike), want, "{}, Pike VM: {}", if full { "fullmatch" } else { "match" }, ctx());
        if backtrack::fits(bt_prog, b.saturating_sub(a) + 1) {
            let r = backtrack::anchored(p, bt_prog, text, a, b, false, usize::MAX, &mut bt, &mut oracle, &mut 0).unwrap();
            assert_eq!(view_slots(re, r), want, "{}, backtracker: {}", if full { "fullmatch" } else { "match" }, ctx());
        }
    }
    // finditer, against the Pike VM's searches with sre's empty-match rule
    let got: Vec<View> = re.finditer_at(text, pos, endpos).take(200).map(|m| view(Some(m))).collect();
    let mut want: Vec<View> = Vec::new();
    if a <= b {
        let (mut at, mut must_advance) = (a, false);
        while want.len() < 200 {
            match pike::search(p, &p.fwd, text, at, b, Want { anchored: false, must_advance, end_at: None }, &mut pc) {
                Some((slots, end)) => {
                    let start = slots[p.slots - 1] as usize;
                    must_advance = end == start;
                    at = end;
                    want.push(view_slots(re, Some((slots, end))));
                }
                None => break,
            }
        }
    }
    assert_eq!(got, want, "finditer: {}", ctx());
}

const TEXT_PIECES: &[&str] = &[
    "a", "b", "c", "ab", "abc", "x", "xy", "_", "1", "9", " ", "  ", "\t", "\n", "\r\n", ".", "(", ")", "=", "'", "\"",
    "$", "\\", "/", "-", "ſ", "K", "\u{212A}", "k", "s", "S", "İ", "ı", "i", "é", "É", "ß", "Σ", "ς", "σ", "\u{85}",
    "\u{a0}", "\u{1c}", "\u{1f}", "\u{2028}", "٣", "\u{10400}", "\u{10428}", "\u{1F600}", "def", "foo", "bar",
];

fn random_text(rng: &mut Rng, most: usize) -> Vec<u32> {
    let n = rng.below(most + 1);
    let mut t = Vec::new();
    for _ in 0..n {
        match rng.below(40) {
            // a lone surrogate (a Python str may hold one)
            0 => t.push(0xD800 + rng.below(0x800) as u32),
            _ => t.extend(rng.pick(TEXT_PIECES).chars().map(|c| c as u32)),
        }
    }
    t
}

#[test]
fn matchers_agree_on_handwritten_patterns() {
    let pats: &[(&str, u32)] = &[
        (r"a+b", 0), (r"(a|ab)(c|bcd)(d*)", 0), (r"(?:ab|a)(?:bc|c)", 0), (r"(a*)b", 0), (r"(a*?)(a*)", 0),
        (r"((a)|b)+", 0), (r"(?:x(y)?)*z", 0), (r"(a)?(b)?c", 0), (r"(?P<k>[A-Za-z_$][\w$]*)\s*=", 0),
        (r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", 0), (r"'([^'\\\n]{1,40})'|\x22([^\x22\\\n]*)\x22", 0),
        (r"\b(?:open|read)\s*\(", 0), (r"(?:^|(?<=\s))//", MULTILINE), (r"^\s*$", MULTILINE), (r"$", 0),
        (r"a(?=b{1,3}c)", 0), (r"(?<=ab|cd)e", 0), (r"x(?!\s{0,4}\()", 0), (r"(?i)straße|ſt|k", 0),
        (r"[^\W\d_]+", 0), (r"(?s).{2,4}?x", 0), (r"\w{2,5}", ASCII), (r"(?x) a (b) # c", 0), (r"(?:a|b|c)+?c", 0),
        (r"(a{2,3}){1,2}", 0), (r"(?:(?<=a)b|(c)|(?=d)d|)e", 0), (r"\s*(?:$|;)", 0), (r"[a-z]*(?<=c)d", 0),
        (r"(?i)[\U00010400-\U0001044f]+", 0), (r"(\w+)\s*:\s*(\d+)?", 0), (r"\Bb|b\B", 0), (r"(?:\bx|(?<=\.)y)z", 0),
        (r"(?<=^)ab|(?<![\w])cd", MULTILINE), (r"(?:a(?=bc)|ab(?!x))\w", 0), (r"(?<=(?<!b)a)c", 0),
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for &(src, flags) in pats {
        let re = Regex::compile(src, flags).unwrap_or_else(|e| panic!("{:?}: {}", src, e));
        for k in 0..60 {
            let t = random_text(&mut rng, if k < 40 { 8 } else { 24 });
            let n = t.len() as isize;
            agree(&re, &t, 0, n);
            agree(&re, &t, 1, n - 1);
            agree(&re, &t, 3, 1);
        }
    }
}

// ---------------------------------------------------------------- random patterns

/// A random pattern of the syntax linre runs (and some it refuses or that
/// Python rejects).
fn random_pattern(rng: &mut Rng, depth: usize, groups: &mut usize) -> String {
    // (characters, which a repeat may follow; then what it may not)
    const ATOMS: &[&str] = &[
        "a", "b", "c", "ab", "x", ".", r"\w", r"\W", r"\d", r"\D", r"\s", r"\S", "[a-c]", "[^ab]", r"[\w.]", "[ſK]",
        r"\n", "İ", "é", r"\U00010400", r"\x41", "[]a]", "k", "s",
    ];
    const ZERO_WIDTH: &[&str] = &[
        r"\b", r"\B", "^", "$", r"\A", r"\Z", "(?=a)", "(?!b)", "(?<=a)", "(?<!b)", "(?<=ab|cd)", "(?=ab|c)",
        r"(?<![\w$])", r"(?=\s{0,3}\()", r"(?<=(?<!b)a)", r"\1", "(?=a*)", "",
    ];
    let mut out = String::new();
    let items = 1 + rng.below(4);
    for _ in 0..items {
        if rng.below(5) == 0 {
            out.push_str(*rng.pick(ZERO_WIDTH));
            continue;
        }
        let atom = if depth > 0 && rng.below(3) == 0 {
            let inner = random_pattern(rng, depth - 1, groups);
            match rng.below(6) {
                0 => {
                    *groups += 1;
                    format!("({})", inner)
                }
                1 => {
                    *groups += 1;
                    format!("(?P<g{}>{})", *groups, inner)
                }
                2 => format!("(?i:{})", inner),
                3 => format!("(?s-i:{})", inner),
                4 => format!("(?:{}|{})", inner, random_pattern(rng, depth - 1, groups)),
                _ => format!("(?:{})", inner),
            }
        } else {
            rng.pick(ATOMS).to_string()
        };
        out.push_str(&atom);
        match rng.below(10) {
            0 => out.push('*'),
            1 => out.push('+'),
            2 => out.push('?'),
            3 => out.push_str("*?"),
            4 => out.push_str("+?"),
            5 => {
                let m = rng.below(3);
                out.push_str(&format!("{{{},{}}}", m, m + rng.below(3)));
            }
            6 => out.push_str(&format!("{{{}}}?", rng.below(3))),
            _ => {}
        }
    }
    if rng.below(5) == 0 {
        out.push('|');
        out.push_str(&random_pattern(rng, depth.saturating_sub(1), groups));
    }
    out
}

#[test]
fn random_patterns_agree_and_never_panic() {
    let mut rng = Rng(20261001);
    let (mut compiled, mut refused, mut errors) = (0, 0, 0);
    for _ in 0..12000 {
        let mut groups = 0;
        let mut src = random_pattern(&mut rng, 2, &mut groups);
        let flags = *rng.pick(&[0, 0, 0, IGNORECASE, MULTILINE, DOTALL, IGNORECASE | MULTILINE, ASCII]);
        if rng.below(8) == 0 {
            src = format!("(?i){}", src);
        }
        let re = match Regex::compile(&src, flags) {
            Ok(re) => re,
            Err(e) if e.refused => {
                refused += 1;
                continue;
            }
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        compiled += 1;
        for k in 0..6 {
            let t = random_text(&mut rng, if k < 4 { 6 } else { 20 });
            let n = t.len() as isize;
            agree(&re, &t, 0, n);
            if k == 0 {
                agree(&re, &t, 1, n - 1);
                agree(&re, &t, 2, 0);
            }
        }
    }
    eprintln!("compiled {} refused {} errors {}", compiled, refused, errors);
    assert!(compiled > 6000 && refused > 300 && errors > 100, "compiled {} refused {} errors {}", compiled, refused, errors);
}

#[test]
fn garbage_patterns_never_panic() {
    const PIECES: &[&str] = &[
        "(", ")", "[", "]", "{", "}", "|", "*", "+", "?", "^", "$", ".", "\\", "a", "b", "-", ",", "1", "9", "0",
        "(?", "(?P<", ">", "(?P=", "(?#", "(?<=", "(?<!", "(?=", "(?!", "(?:", "(?i", "(?-", "(?x)", "#", "\n", " ",
        "\\x", "\\u", "\\U", "\\N{", "\\1", "\\0", "\\b", "\\B", "\\d", "\\w", "\\s", "\\Z", "\\A", "{1,", "65536}",
        "4294967296", "[^", "[]", "[\\", "-]", "ſ", "\u{10400}", "\u{0}",
    ];
    let mut rng = Rng(77);
    for _ in 0..20000 {
        let n = 1 + rng.below(12);
        let src: String = (0..n).map(|_| *rng.pick(PIECES)).collect();
        let flags = *rng.pick(&[0, IGNORECASE, VERBOSE, IGNORECASE | VERBOSE, ASCII | MULTILINE]);
        if let Ok(re) = Regex::compile(&src, flags) {
            let t = random_text(&mut rng, 10);
            let _ = re.search(&t);
            let _ = re.fullmatch(&t);
            let _ = re.finditer(&t).take(50).count();
        }
    }
    // a pattern of code points that are not characters
    let _ = Regex::new(&[0x28, 0x110000, 0x29, u32::MAX, 0x2A], 0).map(|re| re.search(&[0x110000, u32::MAX]).is_some());
}

#[test]
fn texts_of_any_code_points() {
    // a text is any u32s: lone surrogates, values past U+10FFFF
    let mut rng = Rng(5);
    for src in [r"[^a]+", r"(?i)\w+|\W", r".*(?<=\D)", r"(?s).", r"\b\S+\b", r"[\x00-\U0010FFFF]{2}"] {
        let re = Regex::compile(src, 0).unwrap();
        for _ in 0..200 {
            let t: Vec<u32> = (0..rng.below(20)).map(|_| match rng.below(4) {
                0 => rng.next() as u32,
                1 => 0xD800 + rng.below(0x800) as u32,
                2 => 0x110000 + rng.below(100) as u32,
                _ => rng.below(0x80) as u32,
            }).collect();
            let n = t.len() as isize;
            agree(&re, &t, 0, n);
        }
    }
}

#[test]
fn long_texts_stay_linear() {
    // texts that make a backtracking matcher go quadratic or worse: each
    // search here reads them a bounded number of times
    let cases: &[(&str, &str, &str)] = &[
        (r"(a|aa)*c", "a", ""),
        (r"(?:a+)+b", "a", ""),
        (r"(\w+\s?)*$", "ab ", "!"),
        (r"(?<![\w$.])[A-Za-z_$][\w$]*\s*=\s*\{", "a", ""),
        (r"'([^'\\\n]{1,400})'", "'", "x"),
        (r"\s*(?:(?P<k>[A-Za-z_$][\w$]*)|'(?P<k2>[^'\\\n]*)')\s*:\s*", " ", "a"),
    ];
    for &(src, unit, tail) in cases {
        let re = Regex::compile(src, 0).unwrap();
        let mut text = cps(&unit.repeat(20_000));
        text.extend(cps(tail));
        let t = std::time::Instant::now();
        let _ = re.search(&text);
        let _ = re.finditer(&text).take(100).count();
        // (a generous bound: linear work on 40k characters takes milliseconds)
        assert!(t.elapsed().as_secs_f64() < 5.0, "{:?} took {:?}", src, t.elapsed());
    }
}

#[test]
fn the_budget_is_charged_what_the_automata_read() {
    let text = cps(&"a".repeat(1_000_000));
    // a search a scan for its strings answers reads nothing with an automaton
    let needle = Regex::compile(r"needle\d+", 0).unwrap();
    crate::budget::reset(16);
    for _ in 0..1000 {
        assert!(needle.search(&text).is_none());
    }
    assert!(!crate::budget::exhausted());
    // a match that fails at once reads a character or two, wherever it is tried
    let anchored = Regex::compile(r"ab+c", 0).unwrap();
    for k in 0..1000 {
        assert!(anchored.match_at(&text, k, text.len() as isize).is_none());
    }
    assert!(!crate::budget::exhausted());
    // a search the DFA answers by reading the whole text costs a sixteenth of it
    let runs = Regex::compile(r"a+[^a]", 0).unwrap();
    crate::budget::reset(1_000_000 / 16 - 1_000);
    assert!(runs.search(&text).is_none());
    assert!(crate::budget::exhausted());
    crate::budget::reset(crate::budget::DEFAULT_STEPS);
}
