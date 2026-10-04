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
        (r"(\w)x\1", "backreference"),
        (r"(?P<q>ab)(?P=q)", "backreference"),
        (r"(a)?(?(1)b|c)", "conditional"),
        (r"(a|)*", "empty string"),
        (r"(?:a*)+b", "empty string"),
        (r"(?=(a))a", "capturing group inside a positive lookaround"),
        (r"(?>a+)b", "atomic"),
        (r"a++", "possessive"),
        (r"\N{DIGIT ONE}", "character names"),
        (r"(?:a{1,2000}){1,2000}", "too large"),
        (r"(?<=a{1001})b", "lookbehind wider than 1000"),
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
    // a lookahead of bounded width, a fixed-width lookbehind, a lookahead
    // of unbounded width or wider than 1000 (memoized): accepted
    for src in [
        r"a(?=b{1,9}c)", r"a(?!\s{0,64}\()", r"(?<=ab|cd)e", r"(?<![\w$.]{2})x", r"x(?=(?:ab|c){1,3})", r"a(?=.*b)",
        r"a(?!\s*\()", r"a(?=b{1001})", r"(?<=a(?=b*c))b",
    ] {
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

/// A search for a set of strings over a long open text goes by where the
/// pairs of its characters stand (textgate's Bigrams); its answers are the
/// scan's, for every range, set and text (each in turn: with the gate open,
/// and with none, which scans).
#[test]
fn a_search_by_pairs_answers_as_the_scan_does() {
    use super::literal::{Lit, LitSet};
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    // a text of few characters (so that strings occur), with lines, a
    // character past ASCII here and there, and a run of one character
    let alphabet: Vec<u32> = "abcde =(.\n_".chars().map(|c| c as u32).chain([0x00E9]).collect();
    let mut text: Vec<u32> = (0..70_000).map(|_| alphabet[next(alphabet.len() as u64) as usize]).collect();
    for c in &mut text[30_000..30_400] {
        *c = 'a' as u32;
    }
    let mut checked = 0;
    for round in 0..60 {
        // strings of 1 to 6 units, a unit of one character or of the case
        // variants of a letter
        let mut lits: Vec<Lit> = Vec::new();
        for _ in 0..1 + next(6) {
            let len = 1 + next(6) as usize;
            let lit: Lit = (0..len)
                .map(|_| {
                    let c = alphabet[next(alphabet.len() as u64) as usize];
                    if round % 3 == 0 && (c as u8 as char).is_ascii_lowercase() {
                        vec![c, c - 32]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            lits.push(lit);
        }
        let set = match LitSet::new(&lits) {
            Some(s) => s,
            None => continue,
        };
        for _ in 0..8 {
            let from = next(text.len() as u64 - 5_000) as usize;
            let end = from + 4_096 + next((text.len() - from - 4_096) as u64 + 1) as usize;
            // a part of the text too (a slice starts elsewhere in it)
            let part_lo = next(1_000) as usize;
            let scanned = (set.find(&text, from, end), set.find(&text[part_lo..], from.saturating_sub(part_lo), end - part_lo));
            let indexed = {
                let _gate = crate::textgate::open(&text);
                (set.find(&text, from, end), set.find(&text[part_lo..], from.saturating_sub(part_lo), end - part_lo))
            };
            assert_eq!(indexed, scanned, "round {} {:?} [{}, {})", round, set.describe(), from, end);
            checked += 1;
        }
    }
    assert!(checked > 200, "{}", checked);
}


// ------------------------------------------------- unbounded lookaheads

/// A text for a message.
fn show(text: &[u32]) -> String {
    text.iter().map(|&c| char::from_u32(c).unwrap_or('\u{FFFD}')).collect()
}

/// A match of sre's own matcher (pyre, backtracking) as a View.
fn view_sre(m: Option<crate::pyre::Match>, groups: usize) -> View {
    m.map(|m| (m.start() as isize, m.end() as isize, m.lastindex, (1..=groups).map(|k| (m.start_of(k), m.end_of(k))).collect()))
}

/// linre answers as sre's backtracking matcher (pyre.probe's) does: search,
/// match, fullmatch and finditer, in a window.
fn agree_with_sre(src: &str, re: &Regex, sre: &crate::pyre::Regex, text: &[u32], pos: isize, endpos: isize) {
    let g = re.groups();
    assert_eq!(g, sre.groups, "{:?}", src);
    let ctx = || format!("{:?} on {:?} [{}, {}]", src, show(text), pos, endpos);
    assert_eq!(view(re.search_at(text, pos, endpos)), view_sre(sre.search_at(text, pos, endpos), g), "search: {}", ctx());
    assert_eq!(view(re.match_at(text, pos, endpos)), view_sre(sre.match_at(text, pos, endpos), g), "match: {}", ctx());
    assert_eq!(view(re.fullmatch_at(text, pos, endpos)), view_sre(sre.fullmatch_at(text, pos, endpos), g), "fullmatch: {}", ctx());
    let got: Vec<View> = re.finditer_at(text, pos, endpos).take(300).map(|m| view(Some(m))).collect();
    let want: Vec<View> = sre.finditer_at(text, pos, endpos).take(300).map(|m| view_sre(Some(m), g)).collect();
    assert_eq!(got, want, "finditer: {}", ctx());
}

/// The shapes of the pack's lookaheads of unbounded width, and others.
const UNBOUNDED_LOOKAHEADS: &[(&str, u32)] = &[
    (r"\((?![^()]*\)\s*\{)", 0),
    (r"yaml\.load\s*\((?!(?:(?!yaml\.load)[^)])*(?:SafeLoader|safe_load))", 0),
    (r"a(?=.*b)", 0),
    (r"a(?=.*b)", DOTALL),
    (r"a(?!\s*\()", 0),
    (r"\w+(?!\s*\()", 0),
    (r"(?<![\w$])[A-Za-z_$][\w$]*(?![\w$])(?!\s*\()", 0),
    (r#"\.(?:type\s*\()\s*["'](?![^"']*(?:html|xml|svg))"#, 0),
    (r"x(?=[ab ]*b)", 0),
    (r"(?=[a-z0-9_-]{3,}\.ey[a-z]{2})", 0),
    (r"(\w+)(?=\s*=(?!=))", 0),
    (r"(?:(?!ab)[a-c])*c", 0),
    (r"a(?=(?:[^()]|\([^()]*\))*,\s*\{)", 0),
    (r"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+|EXECUTE\s+IMMEDIATE\b(?:(?!EXECUTE\s+IMMEDIATE\b)[^;])*\|\|", IGNORECASE),
    (r"npm_(?:package|config)_(?![\w]*(?:auth|token))\w*\Z", IGNORECASE),
    (r"\bfoo\b(?![ \t]*=[^=])", 0),
    (r"=[ \t]*(?=(?:async[ \t]+)?(?:function\b|\([^()]*\)[ \t]*=>|[A-Za-z_$][\w$]*[ \t]*=>))", 0),
    (r"a(?=b*(?!c+d)e*)", 0),
    (r"(?!x*(?=y*z))\w", 0),
    (r"(?<=a(?=b*c))b", 0),
    (r"(a)(?=(?:b|c)*d)", 0),
    (r"^\s*(?!.*\bx\b)\w+$", MULTILINE),
    (r"(?=.*?\d)(?=.*?[a-z])\w{3,}", 0),
    (r"\b\w+\b(?=(?:\s+\w+){2,}\s*;)", 0),
    (r"(?P<n>[a-c]+)(?!(?:\s|,)*\))", 0),
];

const LOOK_PIECES: &[&str] = &[
    "a", "b", "c", "d", "e", "x", "y", "z", "_", "1", "-", " ", "  ", "\t", "\n", "(", ")", "{", "}", ",", ";", "=",
    "==", "=>", "'", "\"", ".", "@", "+", "||", "html", "xml", "svg", "safe_load", "SafeLoader", "yaml.load(",
    "EXECUTE", "IMMEDIATE", "exec(", "npm_package_", "npm_config_", "token", "auth", "foo", ".ey", ".eyJab",
    "async", "function", "type(", ".type(", "ſ", "K", "é", "\u{10400}",
];

fn look_text(rng: &mut Rng, most: usize) -> Vec<u32> {
    let n = rng.below(most + 1);
    let mut t = Vec::new();
    for _ in 0..n {
        let piece = *rng.pick(LOOK_PIECES);
        // (now and then a long run of one piece: what a walk crosses)
        let times = if rng.below(12) == 0 { 1 + rng.below(40) } else { 1 };
        for _ in 0..times {
            t.extend(piece.chars().map(|c| c as u32));
        }
    }
    t
}

/// `f` with the memoized lookaheads walked (as a search runs them until
/// their walks have cost enough), then swept the first time each is tried
/// (`looks::sweep`): the same answers both ways.
fn walked_and_swept(mut f: impl FnMut(bool)) {
    for at_once in [false, true] {
        super::looks::SWEEP_AT_ONCE.with(|s| s.set(at_once));
        f(at_once);
    }
    super::looks::SWEEP_AT_ONCE.with(|s| s.set(false));
}

#[test]
fn unbounded_lookaheads_answer_as_sre() {
    walked_and_swept(|_| {
        let mut rng = Rng(20261004);
        for &(src, flags) in UNBOUNDED_LOOKAHEADS {
            let re = Regex::compile(src, flags).unwrap_or_else(|e| panic!("{:?}: {}", src, e));
            let cps: Vec<u32> = src.chars().map(|c| c as u32).collect();
            let sre = crate::pyre::Regex::new_backtracking(&cps, flags).unwrap();
            for k in 0..400 {
                let t = look_text(&mut rng, if k < 300 { 8 } else { 30 });
                let n = t.len() as isize;
                agree_with_sre(src, &re, &sre, &t, 0, n);
                if k % 4 == 0 {
                    let a = rng.below(t.len() + 1) as isize;
                    let b = rng.below(t.len() + 2) as isize;
                    agree_with_sre(src, &re, &sre, &t, a, b);
                }
            }
        }
    });
}

/// A random pattern with lookaheads of unbounded width in it.
fn random_lookahead_pattern(rng: &mut Rng, depth: usize) -> String {
    const ATOMS: &[&str] = &["a", "b", "c", "x", ".", r"\w", r"\s", "[ab]", "[^a]", r"[^()]", r"\(", r"\)", " "];
    let mut out = String::new();
    for _ in 0..1 + rng.below(3) {
        if depth > 0 && rng.below(3) == 0 {
            let inner = random_lookahead_pattern(rng, depth - 1);
            out.push_str(&match rng.below(4) {
                0 => format!("(?={})", inner),
                1 => format!("(?!{})", inner),
                2 => format!("(?:{}|{})", inner, random_lookahead_pattern(rng, depth - 1)),
                _ => format!("(?:{})", inner),
            });
        } else {
            out.push_str(*rng.pick(ATOMS));
        }
        match rng.below(6) {
            0 => out.push('*'),
            1 => out.push('+'),
            2 => out.push_str("*?"),
            3 => out.push('?'),
            _ => {}
        }
    }
    out
}

#[test]
fn random_unbounded_lookaheads_answer_as_sre() {
    walked_and_swept(|_| {
        let mut rng = Rng(4242);
        let mut compiled = 0;
        for _ in 0..3000 {
            let src = format!("{}(?{}{})", random_lookahead_pattern(&mut rng, 1), if rng.below(2) == 0 { "=" } else { "!" },
                              random_lookahead_pattern(&mut rng, 2));
            let re = match Regex::compile(&src, 0) {
                Ok(re) => re,
                Err(_) => continue,
            };
            let cps: Vec<u32> = src.chars().map(|c| c as u32).collect();
            let sre = match crate::pyre::Regex::new_backtracking(&cps, 0) {
                Ok(r) => r,
                Err(_) => continue,
            };
            compiled += 1;
            for k in 0..8 {
                let t = random_text(&mut rng, 7);
                let n = t.len() as isize;
                agree_with_sre(&src, &re, &sre, &t, 0, n);
                if k % 2 == 0 {
                    let a = rng.below(t.len() + 1) as isize;
                    let b = rng.below(t.len() + 2) as isize;
                    agree_with_sre(&src, &re, &sre, &t, a, b);
                }
            }
        }
        assert!(compiled > 1500, "{}", compiled);
    });
}

/// The memos (and sweeps) a finditer's searches share are about its own
/// text: the next finditer, over another text in the same buffer (same
/// address, same length), starts afresh with the pattern's pooled buffers.
#[test]
fn a_finditer_never_reads_what_was_learnt_of_another_text() {
    walked_and_swept(|_| {
        let re = Regex::compile(r"a(?![^b]*b)", 0).unwrap();
        // a b at the end: every walk finds it, so nothing matches
        let mut t = cps(&format!("{}b", "a ".repeat(200)));
        assert_eq!(re.finditer(&t).count(), 0);
        // the same buffer, the b made a c: no walk finds one, every a matches
        let n = t.len();
        t[n - 1] = 0x63;
        assert_eq!(re.finditer(&t).count(), 200);
        let sre = crate::pyre::Regex::new_backtracking(&cps(r"a(?![^b]*b)"), 0).unwrap();
        agree_with_sre(r"a(?![^b]*b)", &re, &sre, &t, 0, n as isize);
    });
}

/// Lookaheads whose walks meet thousands of sets of threads (what the last
/// dozen characters were): more than a memo keeps, so without the sweep
/// each walk would go to the text's end. Both shapes, on texts of a's and
/// b's: the same answers as sre's, and linear time.
#[test]
fn lookaheads_of_many_sets_are_swept() {
    // (none of the bodies ever matches but the second's, at the text's end:
    // each walk would go to the end)
    let cases: &[&str] = &[r"a(?![ab]*a[ab]{12}c)", r"b(?=[ab]*b[ab]{10}a[ab]{2}$)", r"(?![ab]*?a[ab]{11}ac)[ab]"];
    // random a's and b's, then a b and 13 a's (the second's body matches
    // from every b)
    let ab = |rng: &mut Rng, n: usize| -> Vec<u32> {
        let mut t: Vec<u32> = (0..n).map(|_| if rng.below(2) == 0 { 0x61 } else { 0x62 }).collect();
        t.extend(cps("baaaaaaaaaaaaa"));
        t
    };
    for &src in cases {
        let re = Regex::compile(src, 0).unwrap();
        let sre = crate::pyre::Regex::new_backtracking(&cps(src), 0).unwrap();
        let mut rng = Rng(77);
        // (3,000 characters: the walks cost enough to be swept part of the
        // way through a finditer)
        walked_and_swept(|_| {
            for _ in 0..3 {
                let t = ab(&mut rng, 3000);
                agree_with_sre(src, &re, &sre, &t, 0, t.len() as isize);
                agree_with_sre(src, &re, &sre, &t, 1000, 2500);
            }
        });
        let (small, large) = (ab(&mut rng, 20_000), ab(&mut rng, 80_000));
        let mut count = (0, 0);
        let t1 = timed(|| count.0 = re.finditer(&small).count());
        let t4 = timed(|| count.1 = re.finditer(&large).count());
        assert!(count.0 > 1000 && count.1 > 3 * count.0, "{:?}: {:?}", src, count);
        // (four times the text: about four times the work, never sixteen)
        assert!(t4 < 8.0 * t1 + 0.05, "{:?}: {:.4}s for 20k, {:.4}s for 80k", src, t1, t4);
        assert!(t4 < 2.0, "{:?} took {:.3}s", src, t4);
    }
}

/// Seconds a closure takes (the best of three).
fn timed(mut f: impl FnMut()) -> f64 {
    (0..3)
        .map(|_| {
            let t = std::time::Instant::now();
            f();
            t.elapsed().as_secs_f64()
        })
        .fold(f64::MAX, f64::min)
}

#[test]
fn unbounded_lookaheads_stay_linear() {
    // each of these, searched from every position (finditer) or matched at
    // every position, would read the rest of the text at each: n² without
    // the memo
    let cases: &[(&str, &str, &str)] = &[
        (r"\s(?!\s*\()", " ", "x"),
        (r"x(?=[a ]*b)", "x a", "b"),
        (r#"a(?![^"]*html)"#, "a", ""),
        (r"a(?=(?:(?!zz)[a-y])*q)", "a", "q"),
        (r"\((?![^()]*\)\s*\{)", "(", ""),
        (r"(?:(?!ab)[a-c])*c", "a", "c"),
    ];
    for &(src, unit, tail) in cases {
        let re = Regex::compile(src, 0).unwrap();
        let make = |n: usize| {
            let mut t = cps(&unit.repeat(n));
            t.extend(cps(tail));
            t
        };
        let (small, large) = (make(10_000), make(40_000));
        let mut count = (0, 0);
        let t1 = timed(|| count.0 = re.finditer(&small).count());
        let t4 = timed(|| count.1 = re.finditer(&large).count());
        assert!(count.1 >= count.0, "{:?}", src);
        // (four times the text: about four times the work, never sixteen)
        assert!(t4 < 8.0 * t1 + 0.02, "{:?}: {:.4}s for 10k, {:.4}s for 40k", src, t1, t4);
        assert!(t4 < 2.0, "{:?} took {:.3}s", src, t4);
        // a match at each position of one text, each walk on memos learnt
        // by none of the others (each search starts afresh): linear per call
        let one = make(20_000);
        let t = std::time::Instant::now();
        let _ = re.search(&one);
        assert!(t.elapsed().as_secs_f64() < 1.0, "{:?}", src);
    }
}

// ------------------------------------- backreferences to one character

/// The pack's quote patterns' shapes, and others a one-character group's
/// backreference makes: each run as branches, answering as sre.
const CHAR_BACKREFS: &[(&str, u32)] = &[
    (r#"(["'])([^"'\\\n]*)\1"#, 0),
    (r#"\(\s*[rRuU]?(["'])(.*?)\1"#, 0),
    (r#"[fFrRbBuU]{0,2}(["'`])([^"'`\n]*)\1\Z"#, 0),
    (r#"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]"#, 0),
    (r#"^\s*([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]\s*=(?![=>])"#, MULTILINE),
    (r#"[fF]{0,2}(["'`])(?:https?)://[^"'`/\s?#]{0,20}?(?:\1\s*\+\s*([^\n+;,)]{1,20})|\$\{([^}\n]{1,20})\}|\{([^}\n]{1,20})\})"#, 0),
    (r#"(?<![\w$.])(?P<obj>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*emit[ \t]*\([ \t]*(?P<q>['"`])(?P<event>[^'"`\n]{1,20})\2[ \t]*,"#, 0),
    (r#"(?:\brequire\s*\(\s*|\bfrom\s+)(['"])(\.{1,2}/[^'"\n]+)\1"#, 0),
    (r#"(?:(["'])x\1)*y"#, 0),
    (r#"(["'])abc\1"#, IGNORECASE),
    (r#"(['"])(?=\w*\1)"#, 0),
    (r#"(?P<q>[-+])\d+(?P=q)"#, 0),
    (r#"([ab])x\1"#, 0),
    (r#"(['"])(?:a|\1b)+\1"#, 0),
    (r#"(a)(["'])\2\1"#, 0),
];

/// Backreferences still refused: a cased character under IGNORECASE, a
/// group of many characters or of more than one, a group that may not
/// take part, one inside a repeat with its backreference outside it.
const STILL_REFUSED: &[(&str, u32)] = &[
    (r"([ab])x\1", IGNORECASE),
    (r"(\w)x\1", 0),
    (r"(xa)\1", 0),
    (r"(?:(a)|b)\1", 0),
    (r"(?:(a))*\1", 0),
    (r"(a)?b\1", 0),
];

const BACKREF_PIECES: &[&str] = &[
    "\"", "'", "`", "a", "b", "x", "y", "abc", "ABC", "1", "23", "-", "+", " ", "\t", "\n", "(", ")", "[", "]", "{",
    "}", "${", "=", "==", ".", ",", ";", "r", "f", "\\", "https://", "http://h", "./", "../m", "require(", "from ",
    "o.emit(", "_", "$", "ſ",
];

#[test]
fn one_character_backreferences_answer_as_sre() {
    let mut rng = Rng(9);
    for &(src, flags) in CHAR_BACKREFS {
        let re = Regex::compile(src, flags).unwrap_or_else(|e| panic!("{:?}: {}", src, e));
        let cps: Vec<u32> = src.chars().map(|c| c as u32).collect();
        let sre = crate::pyre::Regex::new_backtracking(&cps, flags).unwrap();
        for k in 0..500 {
            let n = rng.below(if k < 400 { 10 } else { 30 });
            let mut t = Vec::new();
            for _ in 0..n {
                t.extend(rng.pick(BACKREF_PIECES).chars().map(|c| c as u32));
            }
            let len = t.len() as isize;
            agree_with_sre(src, &re, &sre, &t, 0, len);
            if k % 5 == 0 {
                let a = rng.below(t.len() + 1) as isize;
                agree_with_sre(src, &re, &sre, &t, a, len);
            }
        }
    }
    for &(src, flags) in STILL_REFUSED {
        match Regex::compile(src, flags) {
            Err(e) => assert!(e.refused && e.msg.contains("backreference"), "{:?}: {}", src, e),
            Ok(_) => panic!("{:?} should be refused", src),
        }
    }
}
