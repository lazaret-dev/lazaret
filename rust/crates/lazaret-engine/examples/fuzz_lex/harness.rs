//! A fuzzer for the Go and Rust lexers (`src/lex/go.rs`, `rs.rs`), in the
//! engine's own terms: no external crates (`scripts/check_rust_deps.py`),
//! so no libFuzzer; a seeded generator and mutator, properties every
//! reading must keep, and a shrinker. The same file is the example's
//! (`cargo run --release --example fuzz_lex`, for long runs) and a
//! `cargo test` module's (`src/lex/tests_fuzz.rs`, a short deterministic run
//! that CI's rust job already executes).
//!
//! What it checks, on programs it generates from known tokens and on
//! mutants of them (a deleted, duplicated or replaced span, a tricky
//! snippet inserted, a truncation):
//!
//! 1. **Round trip.** A program built from known tokens (every kind of
//!    literal and comment the language has, with quotes, comment openers,
//!    backslashes and newlines inside) lexes back to exactly those tokens.
//! 2. **Prefix.** Cut at the start of any token, the lexer returns the
//!    tokens before it: lexing is left to right and reads nothing before
//!    a token's own text.
//! 3. **Total.** No panic, tokens in order, each non-empty and in bounds,
//!    and everything outside a token is white space.
//! 4. **A token is itself.** Lexing a comment's or a string's own text
//!    gives that one token.
//! 5. **Deterministic**, and `lex::structure`'s spans in order, disjoint,
//!    in bounds, with no comment inside a literal.
//! 6. **Linear.** Every input is timed, and `probe_quadratic` feeds
//!    200,000 characters of each opener that never closes, which a lexer that
//!    looked ahead from every quote would take minutes to read.
//!
//! A failure prints its seed and iteration (`--seed S --iter I` runs only
//! it) and the smallest input that still fails.
#![allow(dead_code)]

#[cfg(test)]
use crate::lex as lexmod;
#[cfg(not(test))]
use lazaret_engine::lex as lexmod;

use lexmod::{Kind, Token};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

/// A deterministic generator (SplitMix64).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        let mut r = Rng(seed ^ 0x9E37_79B9_7F4A_7C15);
        r.next();
        r.next();
        r
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

/// A language under test.
pub struct Lang {
    pub name: &'static str,
    pub lex: fn(&[u32]) -> Vec<Token>,
    pub is_space: fn(char) -> bool,
    pub gen: fn(&mut Rng) -> Tok,
    /// openers that never close, for the linearity probe
    pub probes: &'static [&'static str],
}

pub fn go() -> Lang {
    Lang {
        name: "go",
        lex: lexmod::go::tokens,
        is_space: |c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{feff}'),
        gen: go_tok,
        probes: &["'", "\"", "/*", "`", "'a", "1.", "//", "0x", "\\", "'\\", "\"\\", "/", "*/", "1e", ".", "'\\'\n", "\"\\\n", "x := 'a\n", "/*\n", "1e+", "0x1p-"],
    }
}

pub fn rs() -> Lang {
    Lang {
        name: "rs",
        lex: lexmod::rs::tokens,
        is_space: |c| c.is_whitespace() || c == '\u{feff}',
        gen: rs_tok,
        probes: &["'", "\"", "/*", "r#\"", "r##", "r#", "b'", "b\"", "'\\", "'\\'", "'a ", "1.", "1.e", "0x", "\\", "/* /*", "*/", "#!", "'\\'\\", "br#", "cr", "'\\\n", "\"\\\n", "'a'\n", "r\"", "///", "'\\u{", "0b1.", "1..", "x.0.1."],
    }
}

pub fn langs() -> Vec<Lang> {
    vec![go(), rs()]
}

/// A token of a generated program: its kind, its text and what follows it.
#[derive(Clone, Debug)]
pub struct Tok {
    pub kind: Kind,
    pub text: String,
    pub sep: &'static str,
}

const SEPS: &[&str] = &[" ", " ", "\n", "\t", "  ", "\r\n", "\n\n", " \n "];

/// Pieces of text that give a lexer trouble inside a literal or a comment.
const BITS: &[&str] = &[
    "a", "b", "Z", "0", " ", "\t", "é", "π", "🦀", "\"", "'", "`", "\\", "/", "*", "//", "/*", "*/", "#", "r#", "\"#", "\n", "\r", "{", "}", "${", "'a", "\u{0}",
];

fn bits(rng: &mut Rng, max: usize) -> String {
    let mut s = String::new();
    for _ in 0..rng.below(max + 1) {
        s.push_str(rng.pick(BITS));
    }
    s
}

/// Text for a quoted literal: no bare quote or backslash (escapes instead),
/// and no bare line break unless `newlines`.
fn quoted_body(rng: &mut Rng, quote: &str, escapes: &[&str], newlines: bool) -> String {
    let mut s = String::new();
    for _ in 0..rng.below(10) {
        let b = *rng.pick(BITS);
        let bad = b.contains(quote) || b.contains('\\') || (!newlines && (b.contains('\n') || b.contains('\r')));
        if bad {
            s.push_str(rng.pick(escapes));
        } else {
            s.push_str(b);
        }
    }
    s
}

/// A block comment's body: no `*/` and no `/*` (but for the comment's own).
fn comment_body(rng: &mut Rng) -> String {
    let mut s = bits(rng, 8);
    while s.contains("*/") || s.contains("/*") {
        s = s.replace("*/", "* /").replace("/*", "/ *");
    }
    s
}

fn tok(kind: Kind, text: String) -> Tok {
    Tok { kind, text, sep: "" }
}

fn line_comment(rng: &mut Rng, open: &str) -> Tok {
    let body = bits(rng, 8).replace('\n', " ");
    Tok { kind: Kind::Comment, text: format!("{open}{body}"), sep: "\n" }
}

const PUNCT: &[&str] = &["+", "-", "*", "%", "&", "|", "^", "<", ">", "=", "!", "(", ")", "{", "}", "[", "]", ",", ";", ":", ".", "~", "@", "$", "?", "#", "/", "\\"];

fn go_tok(rng: &mut Rng) -> Tok {
    const NAMES: &[&str] = &["x", "foo", "_y", "π", "héllo", "if", "func", "r", "b", "go", "a1", "init"];
    const NUMS: &[&str] = &["0", "42", "0x1F", "1_000", "3.14", "1e+10", "0x1p-2", ".5", "1i", "0b101", "0o17", "1.5e-3i", "0X_1F", "07"];
    const ESC: &[&str] = &["\\\"", "\\\\", "\\n", "\\x41", "\\u00e9", "\\'"];
    const RUNES: &[&str] = &["a", "é", "🦀", "\\'", "\\\\", "\\n", "\"", "/", "`", " ", "\\x41", "\\u00e9", "#"];
    match rng.below(12) {
        0 | 1 => tok(Kind::Name, rng.pick(NAMES).to_string()),
        2 => tok(Kind::Num, rng.pick(NUMS).to_string()),
        3 | 4 => tok(Kind::Punct, rng.pick(PUNCT).to_string()),
        5 => line_comment(rng, "//"),
        6 => tok(Kind::Comment, format!("/*{}*/", comment_body(rng))),
        7 | 8 => tok(Kind::Str, format!("\"{}\"", quoted_body(rng, "\"", ESC, false))),
        9 => tok(Kind::Str, format!("'{}'", rng.pick(RUNES))),
        _ => tok(Kind::Str, format!("`{}`", bits(rng, 10).replace('`', "'"))),
    }
}

/// A Rust block comment, nested to `depth` more levels.
fn rs_block(rng: &mut Rng, depth: usize) -> String {
    let mut s = String::from("/*");
    s.push(' ');
    s.push_str(&comment_body(rng));
    s.push(' ');
    if depth > 0 {
        for _ in 0..rng.below(3) {
            s.push_str(&rs_block(rng, depth - 1));
            s.push(' ');
            s.push_str(&comment_body(rng));
            s.push(' ');
        }
    }
    s.push_str("*/");
    s
}

fn rs_tok(rng: &mut Rng) -> Tok {
    const NAMES: &[&str] = &["x", "foo", "_y", "π", "if", "fn", "r", "b", "c", "br", "cr", "rb", "raw", "a1", "r_", "b_", "unsafe"];
    const NUMS: &[&str] = &["0", "42", "0xFF", "0b1010", "0o77", "1_000u32", "3.14", "1e10", "1.5e-3f64", "2.", "1u8", "0x1e", "1E+5"];
    const ESC: &[&str] = &["\\\"", "\\\\", "\\n", "\\\n", "\\u{1F600}", "\\x41", "\\'"];
    const CHARS: &[&str] = &["a", "é", "🦀", "\\n", "\\'", "\\\\", "\\u{1F600}", "\"", "/", "#", " ", "\\x41", "\\0"];
    const BYTES: &[&str] = &["a", "\\n", "\\'", "\\\\", "\"", "/", " ", "\\x41"];
    const LIFETIMES: &[&str] = &["a", "static", "_", "outer", "b1", "é"];
    const RAWIDENTS: &[&str] = &["type", "match", "fn", "x1"];
    match rng.below(12) {
        0 | 1 => tok(Kind::Name, rng.pick(NAMES).to_string()),
        2 => tok(Kind::Num, rng.pick(NUMS).to_string()),
        3 | 4 => tok(Kind::Punct, rng.pick(PUNCT).to_string()),
        5 => {
            let open = *rng.pick(&["//", "///", "//!", "////"]);
            line_comment(rng, open)
        }
        6 => {
            let depth = rng.below(4);
            tok(Kind::Comment, rs_block(rng, depth))
        }
        7 => {
            let prefix = *rng.pick(&["", "", "b", "c"]);
            tok(Kind::Str, format!("{prefix}\"{}\"", quoted_body(rng, "\"", ESC, true)))
        }
        8 => {
            let prefix = *rng.pick(&["r", "br", "cr"]);
            let h = rng.below(4);
            let hashes = "#".repeat(h);
            let mut body = bits(rng, 10);
            let closer = format!("\"{hashes}");
            while body.contains(&closer) {
                body = body.replace(&closer, "' ");
            }
            tok(Kind::Str, format!("{prefix}{hashes}\"{body}\"{hashes}"))
        }
        9 => tok(Kind::Str, format!("'{}'", rng.pick(CHARS))),
        10 => match rng.below(3) {
            0 => tok(Kind::Str, format!("b'{}'", rng.pick(BYTES))),
            1 => tok(Kind::Name, format!("'{}", rng.pick(LIFETIMES))),
            _ => tok(Kind::Name, format!("r#{}", rng.pick(RAWIDENTS))),
        },
        _ => tok(Kind::Name, format!("'{}", rng.pick(LIFETIMES))),
    }
}

/// A program: its text and the tokens it must lex to (code-point offsets).
pub struct Prog {
    pub text: Vec<u32>,
    pub expect: Vec<Token>,
}

pub fn render(toks: &[Tok]) -> Prog {
    let mut text = Vec::new();
    let mut expect = Vec::new();
    for t in toks {
        let start = text.len();
        text.extend(t.text.chars().map(|c| c as u32));
        expect.push(Token { kind: t.kind, start: start as u32, end: text.len() as u32 });
        text.extend(t.sep.chars().map(|c| c as u32));
    }
    Prog { text, expect }
}

pub fn gen_toks(lang: &Lang, rng: &mut Rng) -> Vec<Tok> {
    let n = rng.below(40);
    (0..n)
        .map(|_| {
            let mut t = (lang.gen)(rng);
            if t.sep.is_empty() {
                t.sep = rng.pick(SEPS);
            }
            t
        })
        .collect()
}

fn chars_of(text: &[u32]) -> String {
    text.iter().map(|&x| char::from_u32(x).unwrap_or('\u{fffd}')).collect()
}

fn show(text: &[u32], t: &Token) -> String {
    format!("{:?} {:?}", t.kind, chars_of(&text[t.start as usize..t.end as usize]))
}

/// The properties of any text (3, 4, 5).
pub fn check_text(lang: &Lang, text: &[u32]) -> Result<(), String> {
    let t0 = Instant::now();
    let toks = (lang.lex)(text);
    let took = t0.elapsed();
    if took > Duration::from_millis(1500) {
        return Err(format!("slow: {} characters took {took:?}", text.len()));
    }
    if (lang.lex)(text) != toks {
        return Err("not deterministic".into());
    }
    let mut at = 0usize;
    for t in &toks {
        let (a, e) = (t.start as usize, t.end as usize);
        if a < at || e <= a || e > text.len() {
            return Err(format!("token out of order or bounds: {:?} {a}..{e} after {at} of {}", t.kind, text.len()));
        }
        if let Some(&x) = text[at..a].iter().find(|&&x| !(lang.is_space)(char::from_u32(x).unwrap_or('\u{fffd}'))) {
            return Err(format!("{:?} is in no token (before {a})", char::from_u32(x)));
        }
        at = e;
    }
    if let Some(&x) = text[at..].iter().find(|&&x| !(lang.is_space)(char::from_u32(x).unwrap_or('\u{fffd}'))) {
        return Err(format!("{:?} is in no token (after the last)", char::from_u32(x)));
    }
    // a comment or a string is itself, lexed alone
    for t in &toks {
        if matches!(t.kind, Kind::Comment | Kind::Str) {
            let own = &text[t.start as usize..t.end as usize];
            let again = (lang.lex)(own);
            let want = Token { kind: t.kind, start: 0, end: own.len() as u32 };
            if again != [want] {
                return Err(format!("{} alone lexes to {:?}", show(text, t), again));
            }
        }
    }
    // the detectors' view
    let st = lexmod::structure(text, lang.name, false).ok_or("structure is None")?;
    for (name, spans) in [("comments", &st.comments), ("strings", &st.strings), ("literals", &st.literals)] {
        let mut end = 0usize;
        for &(a, e) in spans.iter() {
            if a < end || e <= a || e > text.len() {
                return Err(format!("structure.{name} not in order or bounds: {a}..{e} after {end}"));
            }
            end = e;
        }
    }
    for &(a, e) in &st.comments {
        if st.literals.iter().any(|&(la, le)| la < e && a < le) {
            return Err(format!("a comment at {a}..{e} overlaps a literal"));
        }
    }
    Ok(())
}

/// The properties of a generated program (1, 2, then 3 to 5).
pub fn check_prog(lang: &Lang, toks: &[Tok]) -> Result<(), String> {
    let p = render(toks);
    let got = (lang.lex)(&p.text);
    if got != p.expect {
        let k = got.iter().zip(&p.expect).position(|(a, b)| a != b).unwrap_or(got.len().min(p.expect.len()));
        let side = |v: &[Token]| v.get(k).map(|t| show(&p.text, t)).unwrap_or_else(|| "(none)".into());
        return Err(format!("token {k}: expected {}, got {}", side(&p.expect), side(&got)));
    }
    for (k, t) in p.expect.iter().enumerate() {
        let cut = t.start as usize;
        let before = (lang.lex)(&p.text[..cut]);
        if before != p.expect[..k] {
            return Err(format!("cut before token {k} ({}): {} tokens, expected {k}", show(&p.text, t), before.len()));
        }
    }
    check_text(lang, &p.text)
}

/// A mutant of `text`: a few edits at random places.
pub fn mutate(rng: &mut Rng, text: &[u32]) -> Vec<u32> {
    let mut v = text.to_vec();
    for _ in 0..1 + rng.below(4) {
        let n = v.len();
        match rng.below(6) {
            0 if n > 0 => {
                let a = rng.below(n);
                let b = (a + 1 + rng.below(8)).min(n);
                v.drain(a..b);
            }
            1 => {
                let at = rng.below(n + 1);
                let bit: Vec<u32> = rng.pick(BITS).chars().map(|c| c as u32).collect();
                v.splice(at..at, bit);
            }
            2 if n > 0 => {
                let a = rng.below(n);
                let b = (a + 1 + rng.below(30)).min(n);
                let copy = v[a..b].to_vec();
                let at = rng.below(n + 1);
                v.splice(at..at, copy);
            }
            3 if n > 0 => {
                let at = rng.below(n);
                v[at] = rng.pick(BITS).chars().next().unwrap_or('x') as u32;
            }
            4 => v.truncate(rng.below(n + 1)),
            _ => {
                let at = rng.below(n + 1);
                v.insert(at, rng.below(0x250) as u32);
            }
        }
    }
    v
}

/// Delta debugging: the smallest list (by dropping chunks) that still fails.
pub fn ddmin<T: Clone>(mut v: Vec<T>, fails: &dyn Fn(&[T]) -> bool) -> Vec<T> {
    let mut chunk = (v.len() / 2).max(1);
    let mut budget = 4000usize;
    loop {
        let mut i = 0;
        while i < v.len() && budget > 0 {
            budget -= 1;
            let end = (i + chunk).min(v.len());
            let mut w = v.clone();
            w.drain(i..end);
            if fails(&w) {
                v = w;
            } else {
                i += chunk;
            }
        }
        if chunk == 1 || budget == 0 {
            return v;
        }
        chunk = (chunk / 2).max(1);
    }
}

/// `f`, with a panic turned into an error.
fn guard(f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            Err(format!("panic: {msg}"))
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub lang: &'static str,
    pub seed: u64,
    pub iter: u64,
    pub what: String,
    pub input: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} (seed {}, iteration {}: --seed {} --iter {})\n  smallest input: {}", self.lang, self.what, self.seed, self.iter, self.seed, self.iter, self.input)
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub programs: u64,
    pub mutants: u64,
    pub chars: u64,
}

/// One iteration: a program and a few mutants of it.
fn iteration(lang: &Lang, seed: u64, iter: u64, stats: &mut Stats) -> Result<(), Failure> {
    let mut rng = Rng::new(seed.wrapping_add(iter.wrapping_mul(0xD1B5_4A32_D192_ED03)));
    let toks = gen_toks(lang, &mut rng);
    let fail = |what: String, input: String| Failure { lang: lang.name, seed, iter, what, input };
    if let Err(what) = guard(|| check_prog(lang, &toks)) {
        let small = ddmin(toks.clone(), &|t| guard(|| check_prog(lang, t)).is_err());
        let text = render(&small).text;
        let what = guard(|| check_prog(lang, &small)).err().unwrap_or(what);
        return Err(fail(what, format!("{:?}", chars_of(&text))));
    }
    let text = render(&toks).text;
    stats.programs += 1;
    stats.chars += text.len() as u64;
    for _ in 0..3 {
        let m = mutate(&mut rng, &text);
        stats.mutants += 1;
        if let Err(what) = guard(|| check_text(lang, &m)) {
            let small = ddmin(m.clone(), &|t| guard(|| check_text(lang, t)).is_err());
            let what = guard(|| check_text(lang, &small)).err().unwrap_or(what);
            return Err(fail(what, format!("{:?}", chars_of(&small))));
        }
    }
    Ok(())
}

/// Runs `iters` iterations (or `only` one), or until `budget` is spent.
pub fn run(lang: &Lang, seed: u64, iters: u64, only: Option<u64>, budget: Option<Duration>) -> Result<Stats, Failure> {
    let mut stats = Stats::default();
    let t0 = Instant::now();
    let range = match only {
        Some(i) => i..i + 1,
        None => 0..iters,
    };
    for iter in range {
        iteration(lang, seed, iter, &mut stats)?;
        if let Some(b) = budget {
            if iter % 64 == 0 && t0.elapsed() > b {
                break;
            }
        }
    }
    Ok(stats)
}

/// 200,000 characters of each opener that never closes: a lexer that looked
/// ahead from every quote, or restarted a scan at every `/`, would take
/// minutes. Each must read in under two seconds.
pub fn probe_quadratic(lang: &Lang) -> Result<(), String> {
    for unit in lang.probes {
        let n = 200_000 / unit.chars().count().max(1);
        let text: Vec<u32> = unit.repeat(n).chars().map(|c| c as u32).collect();
        let t0 = Instant::now();
        let toks = guard(|| {
            let _ = (lang.lex)(&text);
            Ok(())
        });
        let took = t0.elapsed();
        toks.map_err(|e| format!("{unit:?} x {n}: {e}"))?;
        if took > Duration::from_secs(2) {
            return Err(format!("{unit:?} x {n} ({} characters) took {took:?}", text.len()));
        }
    }
    Ok(())
}
