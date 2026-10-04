//! Go read into tokens the way the Go specification reads it: `//` comments
//! to the end of the line, `/* … */` comments (they do not nest), interpreted
//! strings and runes with backslash escapes, raw strings in backticks (no
//! escapes, any number of lines), numbers with their `_` separators, hex
//! floats and imaginary suffix, and names (letters, digits and `_`).
//!
//! What the compiler would refuse is read so that it hides nothing below it:
//! an interpreted string or a rune not closed on its line ends at the
//! line's end (a Go string cannot span lines), and a comment or a raw
//! string not closed runs to the end of the text, as the compiler reads it
//! (a file that does not compile runs nothing).
//!
//! Linear and total: every character is in at most one token, any text, no
//! panic.

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
    // Go's white space: space, tab, CR, LF (and a byte order mark)
    matches!(char::from_u32(x), Some(' ' | '\t' | '\n' | '\r' | '\u{feff}'))
}

/// The tokens of `s`.
pub fn tokens(s: &[u32]) -> Vec<Token> {
    let n = s.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    let at = |k: usize| -> u32 { if k < n { s[k] } else { 0 } };
    let mut push = |kind: Kind, a: usize, b: usize| out.push(Token { kind, start: a as u32, end: b as u32 });
    while i < n {
        let x = s[i];
        if is_space(x) {
            i += 1;
        } else if x == c('/') && at(i + 1) == c('/') {
            let mut e = i + 2;
            while e < n && s[e] != c('\n') {
                e += 1;
            }
            push(Kind::Comment, i, e);
            i = e;
        } else if x == c('/') && at(i + 1) == c('*') {
            let mut e = i + 2;
            let end = loop {
                if e >= n {
                    break n;
                }
                if s[e] == c('*') && at(e + 1) == c('/') {
                    break e + 2;
                }
                e += 1;
            };
            push(Kind::Comment, i, end);
            i = end;
        } else if x == c('`') {
            let mut e = i + 1;
            while e < n && s[e] != c('`') {
                e += 1;
            }
            let end = (e + 1).min(n);
            push(Kind::Str, i, end);
            i = end;
        } else if x == c('"') || x == c('\'') {
            // an interpreted string or a rune: to its closing quote, a
            // backslash taking the next character, or to the line's end
            let mut e = i + 1;
            let end = loop {
                if e >= n {
                    break n;
                }
                let y = s[e];
                if y == c('\\') && e + 1 < n && s[e + 1] != c('\n') {
                    e += 2;
                    continue;
                }
                if y == x {
                    break e + 1;
                }
                if y == c('\n') {
                    break e;
                }
                e += 1;
            };
            push(Kind::Str, i, end);
            i = end.max(i + 1);
        } else if is_digit(x) || (x == c('.') && is_digit(at(i + 1))) {
            let hex = x == c('0') && matches!(char::from_u32(at(i + 1)), Some('x' | 'X'));
            let mut e = i + 1;
            while e < n {
                let y = s[e];
                let prev = s[e - 1];
                let exp = if hex { matches!(char::from_u32(prev), Some('p' | 'P')) } else { matches!(char::from_u32(prev), Some('e' | 'E')) };
                if is_name_char(y) || y == c('.') || ((y == c('+') || y == c('-')) && exp) {
                    e += 1;
                } else {
                    break;
                }
            }
            push(Kind::Num, i, e);
            i = e;
        } else if is_name_start(x) {
            let mut e = i + 1;
            while e < n && is_name_char(s[e]) {
                e += 1;
            }
            push(Kind::Name, i, e);
            i = e;
        } else {
            let kind = if x < 128 && (x as u8).is_ascii_punctuation() { Kind::Punct } else { Kind::Other };
            push(kind, i, i + 1);
            i += 1;
        }
    }
    out
}
