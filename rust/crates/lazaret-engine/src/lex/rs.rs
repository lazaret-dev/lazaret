//! Rust read into tokens the way the Rust Reference reads it: `//` comments
//! (doc comments too) to the end of the line, `/* … */` comments that nest,
//! strings that may span lines (a backslash taking the next character),
//! raw strings with any number of `#` (`r"…"`, `r#"…"#`), byte strings and C
//! strings (`b"…"`, `br#"…"#`, `c"…"`, `cr#"…"#`), characters and bytes
//! (`'a'`, `'\n'`, `'\u{1F600}'`, `b'x'`) told apart from lifetimes and
//! loop labels (`'a`, `'static`, `'outer:`), raw identifiers (`r#type`),
//! numbers with their suffixes, and names. A first-line `#!` that is not an
//! inner attribute (`#![`) is a comment, as the compiler reads it.
//!
//! A string, a raw string or a block comment not closed runs to the end of
//! the text, as the compiler reads it (a file that does not compile runs
//! nothing, and a build script that does not compile runs nothing either).
//!
//! Linear and total: every character is in at most one token, any text, no
//! panic. A macro's body is read as tokens like any other code (the parser
//! that follows keeps it as a token tree).

use super::{Kind, Token};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn ch(x: u32) -> char {
    char::from_u32(x).unwrap_or('\u{fffd}')
}

fn is_name_start(x: u32) -> bool {
    x == c('_') || ch(x).is_alphabetic()
}

fn is_name_char(x: u32) -> bool {
    x == c('_') || ch(x).is_alphanumeric()
}

fn is_digit(x: u32) -> bool {
    (c('0')..=c('9')).contains(&x)
}

fn is_space(x: u32) -> bool {
    ch(x).is_whitespace() || x == c('\u{feff}')
}

/// The tokens of `s`.
pub fn tokens(s: &[u32]) -> Vec<Token> {
    let n = s.len();
    let mut out: Vec<Token> = Vec::new();
    let at = |k: usize| -> u32 { if k < n { s[k] } else { 0 } };
    let mut i = 0usize;
    // a shebang: `#!` on the first line, and not an inner attribute `#![`
    if at(0) == c('#') && at(1) == c('!') {
        let mut j = 2;
        while j < n && (s[j] == c(' ') || s[j] == c('\t')) {
            j += 1;
        }
        if at(j) != c('[') {
            let mut e = 2;
            while e < n && s[e] != c('\n') {
                e += 1;
            }
            out.push(Token { kind: Kind::Comment, start: 0, end: e as u32 });
            i = e;
        }
    }
    while i < n {
        let x = s[i];
        if is_space(x) {
            i += 1;
            continue;
        }
        let (kind, end) = if x == c('/') && at(i + 1) == c('/') {
            let mut e = i + 2;
            while e < n && s[e] != c('\n') {
                e += 1;
            }
            (Kind::Comment, e)
        } else if x == c('/') && at(i + 1) == c('*') {
            (Kind::Comment, block_comment(s, i))
        } else if x == c('"') {
            (Kind::Str, quoted(s, i + 1, c('"')))
        } else if x == c('\'') {
            quote(s, i)
        } else if is_digit(x) {
            (Kind::Num, number(s, i))
        } else if is_name_start(x) {
            name_or_prefixed(s, i)
        } else if x < 128 && (x as u8).is_ascii_punctuation() {
            (Kind::Punct, i + 1)
        } else {
            (Kind::Other, i + 1)
        };
        let end = end.clamp(i + 1, n);
        out.push(Token { kind, start: i as u32, end: end as u32 });
        i = end;
    }
    out
}

/// The end of the block comment opening at `i`: they nest.
fn block_comment(s: &[u32], i: usize) -> usize {
    let n = s.len();
    let mut depth = 1usize;
    let mut e = i + 2;
    while e < n {
        if s[e] == c('/') && e + 1 < n && s[e + 1] == c('*') {
            depth += 1;
            e += 2;
        } else if s[e] == c('*') && e + 1 < n && s[e + 1] == c('/') {
            depth -= 1;
            e += 2;
            if depth == 0 {
                return e;
            }
        } else {
            e += 1;
        }
    }
    n
}

/// The end of a string whose body starts at `from`, closed by `q`: a
/// backslash takes the next character; not closed, the end of the text.
fn quoted(s: &[u32], from: usize, q: u32) -> usize {
    let n = s.len();
    let mut e = from;
    while e < n {
        if s[e] == c('\\') {
            e += 2;
        } else if s[e] == q {
            return e + 1;
        } else {
            e += 1;
        }
    }
    n
}

/// The end of a raw string whose `#`s start at `from` (its quote is at
/// `from + hashes`): the quote and as many `#`s; not closed, the end of the
/// text. None if what is there is not a raw string's opening.
fn raw(s: &[u32], from: usize) -> Option<usize> {
    let n = s.len();
    let mut h = 0usize;
    while from + h < n && s[from + h] == c('#') {
        h += 1;
    }
    if from + h >= n || s[from + h] != c('"') {
        return None;
    }
    let mut e = from + h + 1;
    while e < n {
        if s[e] == c('"') {
            let mut k = 0usize;
            while k < h && e + 1 + k < n && s[e + 1 + k] == c('#') {
                k += 1;
            }
            if k == h {
                return Some(e + 1 + h);
            }
        }
        e += 1;
    }
    Some(n)
}

/// A `'` at `i`: a character literal (`'a'`, `'\n'`, `'\u{..}'`) or a
/// lifetime / loop label (`'a`, `'static`, `'_`).
fn quote(s: &[u32], i: usize) -> (Kind, usize) {
    let n = s.len();
    let next = if i + 1 < n { s[i + 1] } else { 0 };
    if next == c('\\') {
        return (Kind::Str, quoted_line(s, i + 1, c('\'')));
    }
    // one character, then the closing quote: a character
    if i + 2 < n && s[i + 2] == c('\'') && next != c('\'') && next != c('\n') {
        return (Kind::Str, i + 3);
    }
    if is_name_start(next) {
        let mut e = i + 2;
        while e < n && is_name_char(s[e]) {
            e += 1;
        }
        return (Kind::Name, e); // a lifetime or a label
    }
    (Kind::Punct, i + 1)
}

/// A character or a byte's literal whose body starts at `from`, closed by
/// `q`: a backslash takes the next character, and a line break ends it
/// unclosed (a character cannot span lines, so a quote with none after it
/// never reads on to the end of the text). Its end.
fn quoted_line(s: &[u32], from: usize, q: u32) -> usize {
    let n = s.len();
    let mut e = from;
    while e < n {
        if s[e] == c('\\') && e + 1 < n && s[e + 1] != c('\n') {
            e += 2;
        } else if s[e] == q {
            return e + 1;
        } else if s[e] == c('\n') {
            return e.max(from + 1);
        } else {
            e += 1;
        }
    }
    n
}

/// A number: digits, `_`, a base prefix, a fraction, an exponent and a
/// suffix. `1..2` is a range and `1.max(2)` a method call; `1.` is a float.
fn number(s: &[u32], i: usize) -> usize {
    let n = s.len();
    let mut e = i + 1;
    let hex = s[i] == c('0') && matches!(char::from_u32(if e < n { s[e] } else { 0 }), Some('x' | 'X'));
    let based = hex || (s[i] == c('0') && matches!(char::from_u32(if e < n { s[e] } else { 0 }), Some('b' | 'B' | 'o' | 'O')));
    let mut seen_dot = false;
    while e < n {
        let y = s[e];
        let prev = s[e - 1];
        if is_name_char(y) || ((y == c('+') || y == c('-')) && !based && matches!(char::from_u32(prev), Some('e' | 'E'))) {
            e += 1;
        } else if y == c('.') && !based && !seen_dot {
            let after = if e + 1 < n { s[e + 1] } else { 0 };
            if after == c('.') || is_name_start(after) {
                break;
            }
            seen_dot = true;
            e += 1;
        } else {
            break;
        }
    }
    e
}

/// A name at `i`, or what a name's letters prefix: a raw string (`r"…"`,
/// `r#"…"#`), a byte or C string (`b"…"`, `br"…"`, `c"…"`, `cr#"…"#`), a
/// byte (`b'x'`), a raw identifier (`r#type`).
fn name_or_prefixed(s: &[u32], i: usize) -> (Kind, usize) {
    let n = s.len();
    let mut e = i + 1;
    while e < n && is_name_char(s[e]) {
        e += 1;
    }
    let word: String = s[i..e].iter().map(|&x| ch(x)).collect();
    let next = if e < n { s[e] } else { 0 };
    match word.as_str() {
        "r" | "br" | "cr" => {
            if let Some(end) = raw(s, e) {
                return (Kind::Str, end);
            }
            if word == "r" && next == c('#') && e + 1 < n && is_name_start(s[e + 1]) {
                // a raw identifier
                let mut k = e + 2;
                while k < n && is_name_char(s[k]) {
                    k += 1;
                }
                return (Kind::Name, k);
            }
        }
        "b" | "c" => {
            if next == c('"') {
                return (Kind::Str, quoted(s, e + 1, c('"')));
            }
            if word == "b" && next == c('\'') {
                let (kind, end) = quote(s, e);
                if kind == Kind::Str {
                    return (Kind::Str, end);
                }
            }
        }
        _ => {}
    }
    (Kind::Name, e)
}
