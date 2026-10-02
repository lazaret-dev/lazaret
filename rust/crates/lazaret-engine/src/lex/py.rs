//! Python read into tokens with pyparse's tokenizer (Python 3.13's: strings
//! with their prefixes, f-strings in pieces, PEP 701 nesting; and template
//! strings, read as Python 3.14 reads them, PEP 750), the comments it skips
//! found between its tokens. Past a token the tokenizer refuses (an
//! unterminated string, a stray character, a bad indentation …), and in a
//! text it refuses whole (a NUL, a lone surrogate), the rest is read by a
//! plain reading of Python's strings and comments ([`fallback`]).

use super::{Kind, Token};
use crate::pyparse::lexer::{tokenize_with, T};

const fn c(ch: char) -> u32 {
    ch as u32
}

/// The tokens of `s`.
pub fn tokens(s: &[u32]) -> Vec<Token> {
    let lexed = match tokenize_with(s, true) {
        Ok(l) => l,
        Err(_) => {
            let mut out = Vec::new();
            fallback(s, 0, &mut out);
            return out;
        }
    };
    let stop = lexed.fail.as_ref().map(|f| f.tok);
    let mut out = Vec::with_capacity(lexed.toks.len() + 8);
    let mut gap = 0usize;
    for (k, t) in lexed.toks.iter().enumerate() {
        let (a, e) = (t.s as usize, t.e as usize);
        if Some(k) == stop || t.t == T::Error {
            comments(s, gap, a.min(s.len()), &mut out);
            fallback(s, a.min(s.len()), &mut out);
            return out;
        }
        let kind = match t.t {
            T::Str => Kind::Str,
            T::FStart | T::FMiddle | T::FEnd => Kind::Template, // (a t-string's too)
            T::Name | T::Kw => Kind::Name,
            T::Number => Kind::Num,
            T::Op => Kind::Punct,
            _ => continue, // NEWLINE, INDENT, DEDENT, ENDMARKER: no text of their own here
        };
        if a < gap || e > s.len() {
            continue;
        }
        comments(s, gap, a, &mut out);
        out.push(Token { kind, start: a as u32, end: e as u32 });
        gap = e;
    }
    comments(s, gap, s.len(), &mut out);
    out
}

/// The comments in `s[a..b]`, text between tokens: each `#` begins one, to
/// the end of its line.
fn comments(s: &[u32], a: usize, b: usize, out: &mut Vec<Token>) {
    let mut i = a;
    while i < b {
        if s[i] == c('#') {
            let mut e = i;
            while e < b && s[e] != c('\n') && s[e] != c('\r') {
                e += 1;
            }
            out.push(Token { kind: Kind::Comment, start: i as u32, end: e as u32 });
            i = e;
        } else {
            i += 1;
        }
    }
}

fn is_prefix_char(x: u32) -> bool {
    matches!(char::from_u32(x), Some('r' | 'R' | 'b' | 'B' | 'u' | 'U' | 'f' | 'F' | 't' | 'T'))
}

fn is_name_char(x: u32) -> bool {
    x == c('_') || x >= 128 || (x < 128 && (x as u8 as char).is_ascii_alphanumeric())
}

/// Python's strings and comments read plainly from `from`: a `#` to the end
/// of its line; a quote (with up to two prefix letters before it, not part
/// of a longer name) to its closing quote — three quotes to three, one to
/// one or to the end of the line —, a backslash taking the next character
/// (in a raw string too: it keeps the quote after it from closing it); an
/// f-string (or t-string) whole, as text.
pub fn fallback(s: &[u32], from: usize, out: &mut Vec<Token>) {
    let n = s.len();
    let mut i = from;
    while i < n {
        let x = s[i];
        if x == c('#') {
            let mut e = i;
            while e < n && s[e] != c('\n') && s[e] != c('\r') {
                e += 1;
            }
            out.push(Token { kind: Kind::Comment, start: i as u32, end: e as u32 });
            i = e;
            continue;
        }
        if x != c('"') && x != c('\'') {
            i += 1;
            continue;
        }
        // the prefix: up to two letters right before, not the end of a longer name
        let mut a = i;
        while a > from && i - a < 2 && is_prefix_char(s[a - 1]) {
            a -= 1;
        }
        if a > from && is_name_char(s[a - 1]) {
            a = i;
        }
        let prefix: Vec<char> = s[a..i].iter().filter_map(|&p| char::from_u32(p)).map(|p| p.to_ascii_lowercase()).collect();
        let fstr = prefix.contains(&'f') || prefix.contains(&'t');
        let triple = i + 2 < n && s[i + 1] == x && s[i + 2] == x;
        let mut j = if triple { i + 3 } else { i + 1 };
        let end = loop {
            if j >= n {
                break n;
            }
            let y = s[j];
            if y == c('\\') {
                // (a raw string's backslash, too, keeps its quote from closing it)
                j += 2;
                continue;
            }
            if triple {
                if y == x && j + 2 < n && s[j + 1] == x && s[j + 2] == x {
                    break j + 3;
                }
            } else {
                if y == x {
                    break j + 1;
                }
                if y == c('\n') || y == c('\r') {
                    break j;
                }
            }
            j += 1;
        };
        let end = end.min(n);
        out.push(Token { kind: if fstr { Kind::Template } else { Kind::Str }, start: a as u32, end: end as u32 });
        i = end.max(i + 1);
    }
}
