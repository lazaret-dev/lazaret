//! String literals' values, read as their runtimes read them, and the runs
//! of literals a runtime joins into one string.
//!
//! - [`js`]: a JavaScript string literal (or a template with no holes):
//!   jsparse's cooking (escapes, line continuations; a pair of surrogate
//!   escapes is the one character it encodes).
//! - [`py`]: a Python string or bytes literal, prefix and all: pyparse's
//!   reading of its body (raw strings, `\N{…}`, line breaks); an f-string
//!   or a t-string is not a constant.
//! - [`runs`]: literals joined by `+` where nothing binds tighter on either
//!   side (`x * 'a' + 'b'` joins only `'b'`; `'a' + 'b'.length` nothing),
//!   and in Python adjacent literals (`'a' 'b'`, lines apart inside
//!   brackets), which the tokenizer joins before any operator.

use super::{Kind, Token};
use crate::jsparse::scan::cook;
use crate::pyparse::literal::{body, Body};

const fn c(ch: char) -> u32 {
    ch as u32
}

/// A literal's value: its characters (a bytes literal's below 256).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub chars: Vec<u32>,
    pub bytes: bool,
}

/// The value of a JavaScript string literal or hole-less template, quotes
/// or backticks included; None for anything else (an unclosed one, or one
/// with an escape JavaScript refuses).
pub fn js(lit: &[u32]) -> Option<Vec<u32>> {
    let n = lit.len();
    if n < 2 {
        return None;
    }
    let q = lit[0];
    if !matches!(q, 0x27 | 0x22 | 0x60) || lit[n - 1] != q {
        return None;
    }
    // (the closing quote not escaped: a backslash run before it is even)
    let run = lit[1..n - 1].iter().rev().take_while(|&&x| x == c('\\')).count();
    if run % 2 == 1 {
        return None;
    }
    let raw = &lit[1..n - 1];
    if q == c('`') && raw.iter().any(|&x| x == c('\r')) {
        // a template's CR and CRLF are LF, as written and as cooked
        let mut lf = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == c('\r') {
                lf.push(0x0A);
                i += if raw.get(i + 1) == Some(&0x0A) { 2 } else { 1 };
                continue;
            }
            lf.push(raw[i]);
            i += 1;
        }
        return cooked(&lf, true);
    }
    cooked(raw, q == c('`'))
}

fn cooked(raw: &[u32], template: bool) -> Option<Vec<u32>> {
    if !raw.contains(&c('\\')) {
        return Some(raw.to_vec());
    }
    if !escapes_valid(raw, template) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len());
    cook(raw, &mut out);
    Some(out)
}

fn hex(x: u32) -> bool {
    matches!(x, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
}

/// Are a literal body's escapes ones JavaScript accepts? A `\x` takes two
/// hex digits, a `\u` four or a `{…}` of at most 0x10FFFF; in a template
/// (an untagged one: a tag would make it a call) no legacy octal escape and
/// no `\8` or `\9`. A runtime refuses the file otherwise, so the literal
/// has no value (jsparse's cooking, the parser's twin, reads such escapes
/// leniently).
fn escapes_valid(raw: &[u32], template: bool) -> bool {
    let n = raw.len();
    let mut i = 0;
    while i < n {
        if raw[i] != c('\\') {
            i += 1;
            continue;
        }
        let Some(&e) = raw.get(i + 1) else { return false };
        match e {
            0x78 => {
                // \xHH
                if !(i + 3 < n && hex(raw[i + 2]) && hex(raw[i + 3])) {
                    return false;
                }
                i += 4;
            }
            0x75 => {
                // \uHHHH or \u{H…}
                if raw.get(i + 2) == Some(&c('{')) {
                    let mut k = i + 3;
                    let mut v: u32 = 0;
                    while k < n && hex(raw[k]) {
                        v = v.saturating_mul(16).saturating_add(char::from_u32(raw[k]).and_then(|ch| ch.to_digit(16)).unwrap_or(0));
                        k += 1;
                    }
                    if k == i + 3 || raw.get(k) != Some(&c('}')) || v > 0x10FFFF {
                        return false;
                    }
                    i = k + 1;
                } else {
                    if !(i + 5 < n && (2..6).all(|d| hex(raw[i + d]))) {
                        return false;
                    }
                    i += 6;
                }
            }
            0x30 if template => {
                // \0 only where no digit follows
                if raw.get(i + 2).is_some_and(|&d| (0x30..=0x39).contains(&d)) {
                    return false;
                }
                i += 2;
            }
            0x31..=0x39 if template => return false,
            _ => i += 2,
        }
    }
    true
}

/// The value of a Python string or bytes literal, its prefix and quotes
/// included; None for an f-string or t-string, an unclosed literal, or
/// one Python refuses (a bad escape, a non-ASCII byte).
pub fn py(lit: &[u32]) -> Option<Value> {
    let q = lit.iter().position(|&x| x == c('\'') || x == c('"'))?;
    if q > 2 {
        return None;
    }
    let (mut raw, mut bytes) = (false, false);
    for &x in &lit[..q] {
        match char::from_u32(x).map(|ch| ch.to_ascii_lowercase()) {
            Some('r') => raw = true,
            Some('b') => bytes = true,
            Some('u') => {}
            _ => return None, // f, t: not a constant
        }
    }
    let quote = lit[q];
    let rest = &lit[q..];
    let width = if rest.len() >= 6 && rest[1] == quote && rest[2] == quote { 3 } else { 1 };
    if rest.len() < 2 * width || rest[rest.len() - width..].iter().any(|&x| x != quote) {
        return None;
    }
    let inner = &rest[width..rest.len() - width];
    // (the closing quote not escaped, in a raw string too)
    if inner.iter().rev().take_while(|&&x| x == c('\\')).count() % 2 == 1 {
        return None;
    }
    if width == 1 && inner.iter().any(|&x| x == 0x0A || x == 0x0D) {
        // a line break only after a backslash (a continuation)
        let mut i = 0;
        while i < inner.len() {
            if inner[i] == c('\\') {
                i += 2;
                continue;
            }
            if inner[i] == 0x0A || inner[i] == 0x0D {
                return None;
            }
            i += 1;
        }
    }
    let mut chars = Vec::with_capacity(inner.len());
    body(inner, Body { raw, bytes, braces: false }, &mut chars).ok()?;
    Some(Value { chars, bytes })
}

/// Does a literal's text hold an escape that writes a character by its
/// code (`\x41`, `A`, `\u{41}`, `\101`; Python's `\U…` and `\N{…}`)?
/// What obfuscation hides names with; `\n` or `\'` hide nothing.
pub fn has_code_escape(lit: &[u32], lang: &str) -> bool {
    let mut i = 0;
    let n = lit.len();
    let py = lang == "py";
    if py {
        // (a raw string has no escapes)
        let q = lit.iter().position(|&x| x == c('\'') || x == c('"')).unwrap_or(0);
        if lit[..q].iter().any(|&x| x == c('r') || x == c('R')) {
            return false;
        }
    }
    while i + 1 < n {
        if lit[i] == c('\\') {
            let e = lit[i + 1];
            if e == c('x') || e == c('u') || (0x30..=0x37).contains(&e) || (py && (e == c('U') || e == c('N'))) {
                // (`\0` alone is NUL, written so in ordinary code)
                if !(e == c('0') && !lit.get(i + 2).is_some_and(|&d| (0x30..=0x37).contains(&d))) {
                    return true;
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// A run of literals the runtime joins into one string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// from the first literal's start to the last one's end
    pub start: usize,
    pub end: usize,
    pub value: Value,
    /// how many literals
    pub literals: usize,
    /// a literal in it holds a code escape ([`has_code_escape`])
    pub code_escape: bool,
}

/// Is `t` a literal with a value: a string, or a template with no holes?
fn literal(text: &[u32], t: &Token) -> bool {
    match t.kind {
        Kind::Str => true,
        Kind::Template => {
            let (s, e) = t.span();
            e >= s + 2 && text[s] == c('`') && text[e - 1] == c('`')
        }
        _ => false,
    }
}

fn punct_is(text: &[u32], t: &Token, p: &str) -> bool {
    t.kind == Kind::Punct && {
        let (s, e) = t.span();
        e - s == p.len() && text[s..e].iter().zip(p.chars()).all(|(&x, y)| x == y as u32)
    }
}

/// Does a token end a value (so that a `+` after it adds, not signs)?
fn ends_value(text: &[u32], t: Option<&Token>) -> bool {
    match t {
        None => false,
        Some(t) => match t.kind {
            Kind::Name | Kind::Num | Kind::Str | Kind::Template | Kind::Regex | Kind::JsxText | Kind::JsxStr => true,
            Kind::Punct => punct_is(text, t, ")") || punct_is(text, t, "]") || punct_is(text, t, "}"),
            _ => false,
        },
    }
}

/// May the literal at `code[k]` begin a run, given what comes before it?
/// Not after an operator that binds tighter than `+` (it takes the
/// literal), a unary `+` or `-`, or before a template a tag (`f\`…\``).
fn left_free(text: &[u32], code: &[&Token], k: usize, lang: &str) -> bool {
    let prev = if k > 0 { Some(code[k - 1]) } else { None };
    let Some(prev) = prev else { return true };
    if code[k].kind == Kind::Template && ends_value(text, Some(prev)) && !punct_is(text, prev, "}") {
        return false; // a tagged template
    }
    if prev.kind == Kind::Name {
        let (s, e) = prev.span();
        let w = &text[s..e];
        let is = |x: &str| w.len() == x.len() && w.iter().zip(x.chars()).all(|(&a, b)| a == b as u32);
        return !(is("typeof") || is("void") || is("delete") || is("await") || (lang == "py" && is("await")));
    }
    if prev.kind != Kind::Punct {
        return true;
    }
    for op in ["*", "/", "%", "**", "-", "!", "~", ".", "?.", "//", "@", "++", "--"] {
        if punct_is(text, prev, op) {
            return false;
        }
    }
    if punct_is(text, prev, "+") {
        return ends_value(text, if k >= 2 { Some(code[k - 2]) } else { None });
    }
    true
}

/// May a run end with the literal before `code[k]`, given what follows
/// (`code[k]`, or nothing)? Not before an operator that binds tighter than
/// `+`, a member access, a call or a tagged template.
fn right_free(text: &[u32], code: &[&Token], k: usize) -> bool {
    let Some(next) = code.get(k) else { return true };
    if next.kind == Kind::Template {
        return false;
    }
    if next.kind != Kind::Punct {
        return true;
    }
    for op in ["*", "/", "%", "**", ".", "?.", "[", "(", "//", "@", "++", "--"] {
        if punct_is(text, next, op) {
            return false;
        }
    }
    true
}

/// The value of one literal token.
fn value_of(text: &[u32], t: &Token, lang: &str) -> Option<Value> {
    let (s, e) = t.span();
    let lit = &text[s..e];
    if lang == "py" {
        py(lit)
    } else {
        js(lit).map(|chars| Value { chars, bytes: false })
    }
}

/// The runs of literals in `tokens` (a reading of `text` in `lang`, "js"
/// or "py"), in order, each of two literals or more, or of one holding a
/// code escape; at most `max` characters of value each (longer runs are
/// left out). Python's adjacent literals join first, then `+` joins runs.
pub fn runs(text: &[u32], tokens: &[Token], lang: &str, max: usize) -> Vec<Run> {
    let py = lang == "py";
    let code: Vec<&Token> = tokens.iter().filter(|t| t.kind != Kind::Comment).collect();
    // Python's bracket depth before each token (adjacent literals on lines
    // apart join only inside brackets, or after a backslash)
    let mut depth_before: Vec<usize> = Vec::new();
    if py {
        let mut d = 0usize;
        for t in &code {
            depth_before.push(d);
            if t.kind == Kind::Punct {
                if punct_is(text, t, "(") || punct_is(text, t, "[") || punct_is(text, t, "{") {
                    d += 1;
                } else if punct_is(text, t, ")") || punct_is(text, t, "]") || punct_is(text, t, "}") {
                    d = d.saturating_sub(1);
                }
            }
        }
    }
    // is Python's text between code[a] and code[b] (a < b) only what may
    // stand between the parts of one expression: blanks, comments, a
    // backslash's line continuation, and line breaks inside brackets? (Past
    // a token its tokenizer refuses Python is read plainly, strings and
    // comments only: what lies between them is not known to be blank.)
    let blank_between = |a: usize, b: usize| -> bool {
        let gap = &text[code[a].end as usize..code[b].start as usize];
        let breaks = depth_before[b] > 0;
        let mut i = 0;
        while i < gap.len() {
            let x = gap[i];
            if x == c('\\') {
                match gap.get(i + 1) {
                    Some(&0x0D) => i += if gap.get(i + 2) == Some(&0x0A) { 3 } else { 2 },
                    Some(&0x0A) => i += 2,
                    _ => return false,
                }
                continue;
            }
            if x == c('#') {
                while i < gap.len() && gap[i] != 0x0A && gap[i] != 0x0D {
                    i += 1;
                }
                continue;
            }
            if x == 0x0A || x == 0x0D {
                if !breaks {
                    return false; // (at the top level a line break ends the statement)
                }
            } else if !matches!(x, 0x20 | 0x09 | 0x0C) {
                return false;
            }
            i += 1;
        }
        true
    };
    // is code[k] a literal Python joins to the one before it?
    let adjacent = |k: usize| -> bool {
        py && k > 0 && k < code.len() && literal(text, code[k]) && literal(text, code[k - 1]) && blank_between(k - 1, k)
    };
    // is code[j] a `+` whose operands are the code tokens next to it (in
    // Python, with only blanks between)?
    let plus = |j: usize| -> bool {
        j > 0 && j + 1 < code.len() && punct_is(text, code[j], "+") && (!py || (blank_between(j - 1, j) && blank_between(j, j + 1)))
    };
    // the literal at code[k] with the ones adjacent to it: (value, code
    // escape, the index past them); None when one has no value or the
    // kinds (str, bytes) differ
    let group = |k: usize| -> Option<(Value, bool, usize)> {
        let lit = |t: &Token| &text[t.start as usize..t.end as usize];
        let mut v = value_of(text, code[k], lang)?;
        let mut esc = has_code_escape(lit(code[k]), lang);
        let mut m = k + 1;
        while adjacent(m) {
            let w = value_of(text, code[m], lang)?;
            if w.bytes != v.bytes {
                return None;
            }
            v.chars.extend_from_slice(&w.chars);
            esc |= has_code_escape(lit(code[m]), lang);
            m += 1;
        }
        Some((v, esc, m))
    };
    // past the literals adjacent to code[k]
    let past = |k: usize| -> usize {
        let mut m = k + 1;
        while adjacent(m) {
            m += 1;
        }
        m
    };
    let mut out = Vec::new();
    let mut k = 0usize;
    while k < code.len() {
        if !literal(text, code[k]) {
            k += 1;
            continue;
        }
        if !left_free(text, &code, k, lang) {
            k = past(k);
            continue;
        }
        let Some((value, code_escape, mut j)) = group(k) else {
            k = past(k);
            continue;
        };
        let mut run = Run { start: code[k].start as usize, end: code[j - 1].end as usize, value, literals: j - k, code_escape };
        // `+` and a literal (with its adjacent ones), where nothing after it binds tighter
        while plus(j) && literal(text, code[j + 1]) && run.value.chars.len() <= max {
            let Some((v, esc, m)) = group(j + 1) else { break };
            if v.bytes != run.value.bytes || !right_free(text, &code, m) {
                break;
            }
            run.value.chars.extend_from_slice(&v.chars);
            run.end = code[m - 1].end as usize;
            run.literals += m - (j + 1);
            run.code_escape |= esc;
            j = m;
        }
        if run.value.chars.len() <= max && (run.literals >= 2 || run.code_escape) {
            out.push(run);
        }
        k = j;
    }
    out
}
