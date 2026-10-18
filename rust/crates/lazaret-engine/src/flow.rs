//! Local data sent (0.1.8): a port of lazaret.scanner.core's
//! `local_data_sent_at` and its helpers (section "Local data sent"), and of
//! `secret_endpoint_at` (a webhook whose secret is written in the code),
//! function for function. What a script reads from the machine is followed
//! through the names given it to where it is sent; offsets are code-point
//! indices, as in Python.

use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::rxutil;
use crate::shell;
use crate::signs::{call_args_len, first_arg, literal_spans};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn is(s: &[u32], lit: &str) -> bool {
    pystr::eq(s, lit)
}

fn in_set(set: &[PyStr], s: &[u32]) -> bool {
    set.iter().any(|x| x.as_slice() == s)
}

/// The kind names local data is read as (core's strings).
fn kind_of(s: &[u32]) -> &'static str {
    for k in ["identity", "report", "environment", "file", "credentials", "address", "lookup-identity"] {
        if is(s, k) {
            return k;
        }
    }
    "identity"
}

/// A read: (offset, end, the index after its '(' or -1, kind, what).
type Source = (usize, usize, isize, &'static str, PyStr);
/// What a name holds: (kind, what, through a parameter).
type Got = (&'static str, PyStr, bool);
/// Where a parameter holds what it is given: its function, (start, end).
type Scope = Option<(usize, usize)>;
/// Where each followed name was given what it holds, and where it holds it.
type Origins = HashMap<PyStr, Vec<(usize, Scope)>>;

/// core._local_data_sent_at's near: may what `name` holds reach `pos`? In
/// a long text, only `span` characters from where it was given it; a
/// parameter, in its function.
fn near(origins: &Origins, long: bool, span: usize, name: &[u32], pos: usize) -> bool {
    origins.get(name).map_or(false, |os| {
        os.iter().any(|&(o, scope)| {
            (!long || (pos as isize - o as isize).unsigned_abs() <= span) && scope.map_or(true, |(lo, hi)| lo <= pos && pos <= hi)
        })
    })
}

/// core._local_data_sent_at's bind: `name` holds `got` from `pos` (where it
/// does not yet: also from there), within `scope`: is that new?
fn bind(followed: &mut HashMap<PyStr, Got>, origins: &mut Origins, long: bool, span: usize, name: &PyStr, got: Got, pos: usize) -> bool {
    bind_in(followed, origins, long, span, name, got, pos, None)
}

#[allow(clippy::too_many_arguments)]
fn bind_in(followed: &mut HashMap<PyStr, Got>, origins: &mut Origins, long: bool, span: usize, name: &PyStr, got: Got, pos: usize, scope: Scope) -> bool {
    // (FP-GITHUB-SCRIPT: where a name is given what it holds is in its scope; a callback's parameter, given it at the
    // call that takes the callback, before the parameter's scope begins, is given it where the scope begins: else the
    // name is never near where it was given it, and is given it again at each pass)
    let pos = scope.map_or(pos, |(lo, hi)| pos.clamp(lo, hi));
    if !followed.contains_key(name) {
        followed.insert(name.clone(), got);
        origins.insert(name.clone(), vec![(pos, scope)]);
        return true;
    }
    if !near(origins, long, span, name, pos) {
        origins.get_mut(name).expect("a followed name has origins").push((pos, scope));
        return true;
    }
    false
}

/// text[lo:lo+span] clipped, and the length core's _call_args gives it.
fn args_len(text: &[u32], lo: usize, span: usize) -> usize {
    call_args_len(pystr::sub(text, lo, lo + span))
}

/// core._ld_literal_test: is a position in a string literal (a template's
/// or an f-string's text is code)?
pub struct LiteralTest {
    spans: Vec<(usize, usize)>,
    starts: Vec<usize>,
}

impl LiteralTest {
    pub fn new(p: &Pack, text: &[u32]) -> LiteralTest {
        let is_ff = |x: u32| x == c('f') || x == c('F');
        let is_rb = |x: u32| x == c('r') || x == c('R') || x == c('b') || x == c('B');
        let spans: Vec<(usize, usize)> = literal_spans(p, text)
            .iter()
            .copied()
            .filter(|&(a, _)| {
                text[a] != c('`') && !(a > 0 && is_ff(text[a - 1])) && !(a > 1 && is_ff(text[a - 2]) && is_rb(text[a - 1]))
            })
            .collect();
        let starts = spans.iter().map(|&(a, _)| a).collect();
        LiteralTest { spans, starts }
    }

    pub fn at(&self, pos: usize) -> bool {
        let k = self.starts.partition_point(|&s| s <= pos);
        k > 0 && pos < self.spans[k - 1].1
    }
}

/// core._ld_statement_end: the end of the statement whose value starts at i.
pub fn ld_statement_end(p: &Pack, text: &[u32], mut i: usize) -> usize {
    let n = text.len().min(i + p.usize("_LD_STATEMENT_SPAN"));
    let mut depth = 0usize;
    while i < n {
        let ch = text[i];
        if ch == c('"') || ch == c('\'') || ch == c('`') {
            if ch != c('`') && i + 3 <= text.len() && text[i + 1] == ch && text[i + 2] == ch {
                let triple = [ch, ch, ch];
                match pystr::find(text, &triple, i + 3) {
                    Some(j) if j + 3 <= n => {
                        i = j + 3;
                        continue;
                    }
                    _ => return n,
                }
            }
            let mut j = i + 1;
            while j < n && text[j] != ch {
                j += if text[j] == c('\\') { 2 } else { 1 };
            }
            if j >= n {
                return n;
            }
            i = j + 1;
            continue;
        }
        if ch == c('(') || ch == c('[') || ch == c('{') {
            depth += 1;
        } else if ch == c(')') || ch == c(']') || ch == c('}') {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        } else if depth == 0 && (ch == c(';') || ch == c('\n')) {
            return i;
        }
        i += 1;
    }
    n
}

/// core._ld_block_end: the index of the '}' that closes the '{' at text[i]
/// (string literals and comments skipped), or None when it is not closed
/// within _LD_BODY_SPAN characters. A line comment ends at any of
/// ECMAScript's line terminators (js_line_end: LF, CR, U+2028, U+2029), as
/// in js_block_end (FP-GITHUB-SCRIPT: core ended it at LF alone, which hid
/// the code after a CR, U+2028 or U+2029 in a comment).
fn ld_block_end(p: &Pack, text: &[u32], mut i: usize) -> Option<usize> {
    let n = text.len().min(i + p.usize("_LD_BODY_SPAN"));
    let mut depth: isize = 0;
    while i < n {
        let ch = text[i];
        if ch == c('"') || ch == c('\'') || ch == c('`') {
            let mut j = i + 1;
            while j < n && text[j] != ch {
                j += if text[j] == c('\\') { 2 } else { 1 };
            }
            if j >= n {
                return None;
            }
            i = j + 1;
            continue;
        }
        if ch == c('/') && i + 1 < n && (text[i + 1] == c('/') || text[i + 1] == c('*')) {
            let line = text[i + 1] == c('/');
            let j = if line { find_line_end(text, i + 2, n) } else { pystr::find_in(text, &u("*/"), i + 2, n) };
            match j {
                None => return None,
                Some(j) => {
                    i = j + if line { 1 } else { 2 };
                    continue;
                }
            }
        }
        if ch == c('{') {
            depth += 1;
        } else if ch == c('}') {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// ECMAScript's LineTerminator: LF, CR, U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR). Each ends a line
/// comment and a regular expression literal, and each is a line break to ASI (the review of Oct 20: U+2028 after
/// `debugger` was read as code, the `/` after it as a division).
fn js_line_end(x: u32) -> bool {
    x == 0x0A || x == 0x0D || x == 0x2028 || x == 0x2029
}

/// ECMAScript's WhiteSpace: TAB, VT, FF, SP, NBSP, U+FEFF (ZWNBSP) and every other character of the Unicode category
/// Zs (U+1680, U+2000 to U+200A, U+202F, U+205F, U+3000).
fn js_space(x: u32) -> bool {
    matches!(x, 0x09 | 0x0B | 0x0C | 0x20 | 0xA0 | 0xFEFF | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000)
}

/// White space or a line terminator: what separates tokens.
fn js_blank(x: u32) -> bool {
    js_space(x) || js_line_end(x)
}

/// The first line terminator in text[from:n], if any.
fn find_line_end(text: &[u32], from: usize, n: usize) -> Option<usize> {
    (from..n.min(text.len())).find(|&j| js_line_end(text[j]))
}

/// Does the token that ends at text[k] lie past what js_block_end models, so that a decision resting on it (a `/`'s,
/// what a `{` or a `(` opens) is a guess? A character outside ASCII there (a name's: `fuß`; any other the reading does
/// not know), or a word the decisions read (KNOWN_WORDS) whose name goes on before it past what the reading reads as a
/// name's (a character outside ASCII, an escape: `ñreturn` is a name, and so is a `return` after an escaped letter).
fn lex_unsure(text: &[u32], k: usize) -> bool {
    if text[k] >= 0x80 {
        return true;
    }
    let w = word_at(text, k);
    if w.is_empty() || !KNOWN_WORDS.iter().any(|known| known.iter().any(|x| is(w, x))) {
        return false;
    }
    let s = k + 1 - w.len();
    if s > 0 && (text[s - 1] >= 0x80 && !js_blank(text[s - 1]) || text[s - 1] == c('\\')) {
        return true;
    }
    // (a code point's escape before it, `\u{61}`: one name's)
    let mut q = s;
    if q == 0 || text[q - 1] != c('}') {
        return false;
    }
    q -= 1;
    while q > 0 && text[q - 1] < 0x80 && (text[q - 1] as u8).is_ascii_hexdigit() {
        q -= 1;
    }
    q >= 3 && text[q - 1] == c('{') && text[q - 2] == c('u') && text[q - 3] == c('\\')
}

/// The words after which a `/` can only begin a regular expression: reserved words that end no expression, and those
/// a line ends (`break`, `continue`, `debugger`: ASI).
const REGEX_WORDS: &[&str] = &[
    "return", "typeof", "case", "do", "else", "in", "new", "delete", "void", "throw", "instanceof", "break", "continue",
    "debugger",
];
/// Words that are names in some code and keywords in other: a `/` after one is a guess.
const MAYBE_WORDS: &[&str] = &["of", "yield", "await", "let", "async", "get", "set", "static"];
/// The words whose `(…)` a statement follows (`if (x) /re/.test(y)`: a regular expression after its `)`).
const HEAD_WORDS: &[&str] = &["if", "while", "for", "with"];
/// The words whose `(…)` a block follows (`catch (e) {`, `switch (x) {`).
const BLOCK_HEAD_WORDS: &[&str] = &["catch", "switch"];
/// The words a block follows (`else {`, `do {`, a class's `static {`).
const BLOCK_AFTER_WORDS: &[&str] = &["else", "do", "try", "finally", "static"];
/// The words an expression follows (`return {`: an object).
const EXPR_AFTER_WORDS: &[&str] = &["return", "typeof", "case", "in", "new", "delete", "void", "throw", "instanceof", "yield", "await"];
/// The words js_block_end's decisions read.
const KNOWN_WORDS: &[&[&str]] = &[REGEX_WORDS, MAYBE_WORDS, HEAD_WORDS, BLOCK_HEAD_WORDS, BLOCK_AFTER_WORDS, EXPR_AFTER_WORDS, &["for"]];

/// The word that ends at text[k] (an identifier's characters), or an empty slice.
fn word_at(text: &[u32], k: usize) -> &[u32] {
    if !ld_ident_char(text[k]) {
        return &[];
    }
    let mut s = k;
    while s > 0 && ld_ident_char(text[s - 1]) {
        s -= 1;
    }
    if s > 0 && (text[s - 1] == c('.') || text[s - 1] == c('#')) {
        return &[]; // (a member: `x.return`; a private name: `this.#return`)
    }
    &text[s..=k]
}

/// The word before the word that ends at text[k], on its line (`break lbl`: `break`; white space between, no line
/// terminator), or an empty slice; None when what stands between is past what js_block_end models (a comment, which
/// may hold a line terminator; a name it may not read whole: lex_unsure).
fn word_before(text: &[u32], k: usize) -> Option<&[u32]> {
    let w = word_at(text, k);
    let mut j = k + 1 - w.len();
    while j > 0 && js_space(text[j - 1]) {
        j -= 1;
    }
    if j == 0 || j == k + 1 - w.len() {
        return Some(&[]);
    }
    if j > 1 && text[j - 1] == c('/') && text[j - 2] == c('*') {
        return None; // (`break /* … */ lbl`)
    }
    if lex_unsure(text, j - 1) {
        return None;
    }
    Some(word_at(text, j - 1))
}

/// What a brace opened, as js_block_end reads it: a block (a `/` after its `}` begins a regular expression), an
/// expression's (an object, a template's `${…}`: a division), or what the reader cannot say (a function's or a
/// class's body, a label's or a property's `{`: a `/` after it is a guess).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Brace {
    Block,
    Expr,
    Unknown,
}

/// What a parenthesis opened: a statement's head (`if (…)`: a regular expression may follow), a head a block
/// follows (`catch (…)`, `switch (…)`), or any other (a call's, a function's parameters).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paren {
    Head,
    BlockHead,
    Other,
}

/// FP-GITHUB-SCRIPT: the index of the '}' that closes the JavaScript block whose '{' is at text[open], read as a
/// JavaScript tokenizer reads it — string literals, comments, template literals (and the code of their `${…}`,
/// templates in it among it) and regular expression literals skipped — and whether that reading is certain. A `/`
/// begins a regular expression after an operator, an opening bracket, `,`, `;`, `:`, a reserved word such as `return`
/// or a word ASI ends a statement after (`break`, `continue` and a labeled one, `debugger`), the `)` of an `if`,
/// `while`, `for` or `with` head or a block's `}`; it is a division after a name, a number, a literal, `++`/`--`,
/// another `)`, `]`, or an expression's `}`. Where the kind of what precedes a `/` cannot be told from the tokens (the
/// `}` of a function's, an arrow's or a class's body, of a label's or a property's `{`; a word that is a name in some
/// code and a keyword in other: `of`, `yield`, `await`), or a regular expression has no closing `/` on its line, or V8's
/// HTML-like comments are met (a script's, not a module's), the end found is a guess: `certain` is false, and the
/// follower narrows nothing to it (the review of Oct 18: `class Marker {}` then `/}/.test(s)` read the class body's `}`
/// as an object's, the regular expression as a division, and its `}` as the function's end). Line terminators and
/// white space are ECMAScript's (js_line_end, js_space: U+2028 and U+2029 end a line comment, a regular expression and
/// a line to ASI; NBSP, U+FEFF and every Zs separate tokens; a block comment holding a line terminator is a line
/// break), and a decision that rests on a character the reading does not model (outside ASCII, an escape in a name:
/// lex_unsure) is a guess too (the review of Oct 20: `debugger` then U+2028 then `/}/.test(s)` was read as a name and
/// a division, by both readers alike: their agreeing proves nothing where they share a blind spot). None when the
/// block is not closed within _LD_BODY_SPAN characters, or a string runs past its line (no JavaScript string does).
fn js_block_end(p: &Pack, text: &[u32], open: usize) -> Option<(usize, bool)> {
    let n = text.len().min(open + p.usize("_LD_BODY_SPAN"));
    let mut braces: Vec<Brace> = Vec::new(); // the open braces
    let mut subs: Vec<usize> = Vec::new(); // the brace depth at which each open `${` began
    let mut parens: Vec<Paren> = Vec::new(); // the open parentheses
    let (mut closed_paren, mut closed_brace) = (Paren::Other, Brace::Block); // what the last `)` and `}` closed
    let mut certain = true;
    let mut in_template = false;
    let mut last: Option<usize> = None; // the last character of code read, not a blank
    let mut line_start = true; // nothing but blanks since the line began
    let mut i = open;
    while i < n {
        let ch = text[i];
        if in_template {
            if ch == c('\\') {
                i += 2;
            } else if ch == c('`') {
                in_template = false;
                last = Some(i);
                i += 1;
            } else if ch == c('$') && i + 1 < n && text[i + 1] == c('{') {
                subs.push(braces.len());
                braces.push(Brace::Expr);
                in_template = false;
                last = Some(i + 1);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if js_line_end(ch) {
            line_start = true;
            i += 1;
            continue;
        }
        if js_space(ch) {
            i += 1;
            continue;
        }
        let at_line_start = std::mem::replace(&mut line_start, false);
        if ch == c('"') || ch == c('\'') {
            let mut j = i + 1;
            while j < n && text[j] != ch {
                if text[j] == c('\n') || text[j] == c('\r') {
                    return None; // (U+2028 and U+2029 may stand in a string: ES2019)
                }
                j += if text[j] == c('\\') { 2 } else { 1 };
            }
            if j >= n {
                return None;
            }
            last = Some(j);
            i = j + 1;
            continue;
        }
        if ch == c('`') {
            in_template = true;
            i += 1;
            continue;
        }
        let html = (ch == c('<') && pystr::starts_with(&text[i..], "<!--")) || (at_line_start && pystr::starts_with(&text[i..], "-->"));
        if html || ch == c('/') && i + 1 < n && (text[i + 1] == c('/') || text[i + 1] == c('*')) {
            // (an HTML-like comment is one in a script, not in a module: which this is, the text does not say)
            certain &= !html;
            let line = html || text[i + 1] == c('/');
            let j = if line { find_line_end(text, i + 1, n) } else { pystr::find_in(text, &u("*/"), i + 2, n) };
            match j {
                None => return None,
                Some(j) => {
                    // (after a line comment, the terminator that ends it; a block comment holding one is a line break)
                    line_start = at_line_start && !line || !line && (i + 2..j).any(|q| js_line_end(text[q]));
                    i = if line { j } else { j + 2 };
                }
            }
            continue;
        }
        // (a decision on a token the reading does not model is a guess)
        if (ch == c('/') || ch == c('(') || ch == c('{')) && last.is_some_and(|k| lex_unsure(text, k)) {
            certain = false;
        }
        if ch == c('/') {
            let (regex, sure) = regex_may_start(text, last, closed_paren, closed_brace);
            certain &= sure;
            if regex {
                // a regular expression to its closing `/` on its line (a class's `/` and an escaped one inside it)
                let mut j = i + 1;
                let mut class = false;
                let mut end = None;
                while j < n && !js_line_end(text[j]) {
                    let x = text[j];
                    if x == c('\\') {
                        j += 2;
                        continue;
                    }
                    if class {
                        class = x != c(']');
                    } else if x == c('[') {
                        class = true;
                    } else if x == c('/') {
                        end = Some(j);
                        break;
                    }
                    j += 1;
                }
                if let Some(j) = end {
                    let mut k = j + 1;
                    while k < n && ld_ident_char(text[k]) {
                        k += 1; // (its flags)
                    }
                    last = Some(k - 1);
                    i = k;
                    continue;
                }
                certain = false; // (no closing `/` on the line: read as a division, a guess)
            }
        }
        if ch == c('(') {
            let kind = match last.map(|k| (k, word_at(text, k))) {
                Some((_, w)) if HEAD_WORDS.iter().any(|h| is(w, h)) => Paren::Head,
                Some((_, w)) if BLOCK_HEAD_WORDS.iter().any(|h| is(w, h)) => Paren::BlockHead,
                // (`for await (…)`: a loop's head)
                Some((k, w)) if is(w, "await") => match word_before(text, k) {
                    Some(b) if is(b, "for") => Paren::Head,
                    Some(_) => Paren::Other,
                    None => {
                        certain = false;
                        Paren::Other
                    }
                },
                _ => Paren::Other,
            };
            parens.push(kind);
        } else if ch == c(')') {
            closed_paren = parens.pop().unwrap_or(Paren::Other);
        } else if ch == c('{') {
            braces.push(brace_kind(text, last, closed_paren));
        } else if ch == c('}') {
            closed_brace = braces.pop().unwrap_or(Brace::Block);
            if subs.last() == Some(&braces.len()) {
                subs.pop(); // (a template's `${…}` closed: the template goes on)
                in_template = true;
                i += 1;
                continue;
            }
            if braces.is_empty() {
                return Some((i, certain));
            }
        }
        last = Some(i);
        i += 1;
    }
    None
}

/// FP-GITHUB-SCRIPT: where the block whose `{` is at text[open] ends, when that is certain: the brace counter
/// (ld_block_end) and the JavaScript reading (js_block_end) close it at the same `}`, and nothing in the reading was a
/// guess. A name the follower narrows to a body is narrowed only to one whose end this gives (else it reaches as
/// before): narrowing to a body that ends too soon would lose what the code really sends after (the review of Oct 18).
fn sure_block_end(p: &Pack, text: &[u32], open: usize) -> Option<usize> {
    let ld = ld_block_end(p, text, open)?;
    let (js, certain) = js_block_end(p, text, open)?;
    (certain && js == ld).then_some(js)
}

/// What the `{` after the code character at `last` opens (js_block_end); `closed_paren`: what the last `)` closed.
fn brace_kind(text: &[u32], last: Option<usize>, closed_paren: Paren) -> Brace {
    let Some(k) = last else { return Brace::Block };
    let x = text[k];
    if x == c(')') {
        return if closed_paren == Paren::Other { Brace::Unknown } else { Brace::Block };
    }
    if x == c('>') && k > 0 && text[k - 1] == c('=') {
        return Brace::Unknown; // (an arrow's body)
    }
    if x == c(';') || x == c('{') || x == c('}') {
        return Brace::Block;
    }
    if let Some(ch) = char::from_u32(x) {
        if "(,=[?!&|+-*%<>~^".contains(ch) {
            return Brace::Expr;
        }
    }
    let w = word_at(text, k);
    if BLOCK_AFTER_WORDS.iter().any(|b| is(w, b)) {
        Brace::Block
    } else if EXPR_AFTER_WORDS.iter().any(|b| is(w, b)) {
        Brace::Expr
    } else {
        Brace::Unknown // (`:`, a class's name or what it extends, a name)
    }
}

/// Does a `/` after the code character at `last` (None: nothing before it in the block) begin a regular expression
/// (js_block_end), and is that certain? `closed_paren` and `closed_brace`: what the last `)` and `}` closed.
fn regex_may_start(text: &[u32], last: Option<usize>, closed_paren: Paren, closed_brace: Brace) -> (bool, bool) {
    let Some(k) = last else { return (true, true) };
    let ch = text[k];
    if ch == c(')') {
        return (closed_paren == Paren::Head, true);
    }
    if ch == c('}') {
        return match closed_brace {
            Brace::Block => (true, true),
            Brace::Expr => (false, true),
            Brace::Unknown => (true, false),
        };
    }
    if (ch == c('+') || ch == c('-')) && k > 0 && text[k - 1] == ch {
        return (false, true); // (`x++ / 2`)
    }
    if ch == c('.') && k > 1 && text[k - 1] == ch && text[k - 2] == ch {
        return (true, true); // (`[.../x/.exec(s)]`: a spread's)
    }
    if let Some(x) = char::from_u32(ch) {
        if "(,=:[!&|?{;+-*%<>~^".contains(x) {
            return (true, true);
        }
    }
    let w = word_at(text, k);
    if REGEX_WORDS.iter().any(|r| is(w, r)) {
        return (true, true);
    }
    if !w.is_empty() {
        match word_before(text, k) {
            Some(b) if ["break", "continue"].iter().any(|r| is(b, r)) => return (true, true), // (`break lbl` then a line's `/`)
            Some(_) => {}
            None => return (false, false),
        }
    }
    if MAYBE_WORDS.iter().any(|r| is(w, r)) {
        return (true, false);
    }
    (false, true) // (a name, a number, a literal's end, `]`)
}

/// core._ld_def_end: where the body of the `def` at text[start] ends (the
/// start of the first line after it indented no deeper than the `def`, not
/// blank, a comment or in a string literal; the text's end), or None beyond
/// _LD_BODY_SPAN characters.
fn ld_def_end(p: &Pack, text: &[u32], start: usize, lit: &LiteralTest) -> Option<usize> {
    let line = pystr::rfind_char(text, c('\n'), 0, start).map_or(0, |k| k + 1);
    let blank = |x: u32| x == c(' ') || x == c('\t');
    let mut k = line;
    while k < start && blank(text[k]) {
        k += 1;
    }
    let indent = k - line;
    let n = text.len().min(start + p.usize("_LD_BODY_SPAN"));
    let mut pos = pystr::find_char(text, c('\n'), start);
    loop {
        match pos {
            None => return Some(text.len()),
            Some(q) if q >= n => return None,
            Some(q) => {
                let first = q + 1;
                let mut k = first;
                while k < text.len() && blank(text[k]) {
                    k += 1;
                }
                if k < text.len()
                    && text[k] != c('\r')
                    && text[k] != c('\n')
                    && text[k] != c('#')
                    && k - first <= indent
                    && !lit.at(k)
                {
                    return Some(first);
                }
                pos = pystr::find_char(text, c('\n'), k);
            }
        }
    }
}

/// What core._ld_func_end reads of a function _LD_FUNC_RE matched.
#[derive(Clone, Copy)]
struct FuncM {
    start: usize,
    end: usize,
    def: bool,    // `def f(…)`: an indented block
    method: bool, // `f(…) {`
    arrow: bool,  // `f = (…) =>`, `f = x =>`
}

/// core._ld_func_end: where the body of a function ends (its closing '}',
/// the line after its block, the end of an arrow's expression), or None.
fn ld_func_end(p: &Pack, text: &[u32], m: &FuncM, lit: &LiteralTest) -> Option<usize> {
    if m.def {
        return ld_def_end(p, text, m.start, lit);
    }
    if m.method {
        return ld_block_end(p, text, m.end - 1);
    }
    if let Some(body) = p.re("_LD_BODY_RE").match_at(text, m.end as isize, text.len() as isize) {
        return ld_block_end(p, text, body.end() - 1);
    }
    if m.arrow {
        return Some(ld_statement_end(p, text, m.end));
    }
    None
}

/// core._ld_then_params: the names a callback's first parameter gives what
/// it is called with: the parameter, or the names it destructures.
fn ld_then_params(p: &Pack, args: &[u32]) -> Vec<PyStr> {
    let not_names = p.strs("_LD_NOT_NAMES");
    if let Some(d) = p.re("_LD_DESTRUCT_PARAM_RE").match_(args) {
        let name_re = p.re("_DD_DESTRUCT_NAME_RE");
        return pystr::split_char(d.group(1).unwrap_or(&[]), c(','))
            .into_iter()
            .filter_map(|part| name_re.search(pystr::strip(part)).map(|n| n.group(1).unwrap_or(&[]).to_vec()))
            .filter(|n| !in_set(not_names, n))
            .collect();
    }
    match p.re("_DD_PARAM_RE").match_(args) {
        Some(m) if !in_set(not_names, m.group(1).unwrap_or(&[])) => vec![m.group(1).unwrap_or(&[]).to_vec()],
        _ => Vec::new(),
    }
}

/// core._ld_params: the names in a parameter list (not self, cls or a keyword).
fn ld_params(p: &Pack, plist: &[u32]) -> Vec<PyStr> {
    let param_re = p.re("_LD_PARAM_RE");
    let not_names = p.strs("_LD_NOT_NAMES");
    let mut names: Vec<PyStr> = Vec::new();
    for part in pystr::split_char(plist, c(',')) {
        if let Some(pm) = param_re.match_(part) {
            let pn = pm.group(1).unwrap_or(&[]);
            if !is(pn, "self") && !is(pn, "cls") && !in_set(not_names, pn) {
                names.push(pn.to_vec());
            }
        }
    }
    names
}

/// core._ld_split_args: (start, end) of a call's arguments in args.
fn ld_split_args(args: &[u32]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let n = args.len();
    let mut depth: isize = 0;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < n {
        let ch = args[i];
        if ch == c('"') || ch == c('\'') || ch == c('`') {
            match pystr::find_char(args, ch, i + 1) {
                None => break,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        if ch == c('(') || ch == c('[') || ch == c('{') {
            depth += 1;
        } else if ch == c(')') || ch == c(']') || ch == c('}') {
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            out.push((start, i));
            start = i + 1;
        }
        i += 1;
    }
    out.push((start, n));
    out
}

/// core._ld_object_spans: the values of the object literal whose '{' is at lo.
fn ld_object_spans(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize, bool)> {
    let close = lo + 1 + call_args_len(pystr::sub(text, lo + 1, hi));
    let keys = p.strs("_LD_OPTION_KEYS");
    let key_re = p.re("_LD_KEY_RE");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let mut out = Vec::new();
    let method = p.re("_LD_METHOD_RE");
    for (a, b) in ld_split_args(pystr::sub(text, lo + 1, close)) {
        let part = pystr::sub(text, lo + 1 + a, lo + 1 + b);
        if method.match_(part).is_some() {
            continue; // a method: code, not data
        }
        match key_re.match_(part) {
            Some(key) => {
                if func_value.match_at(part, key.end() as isize, part.len() as isize).is_some() {
                    continue; // a function (a callback): code, not data
                }
                let name = key.group(1).or_else(|| key.group(2)).unwrap_or(&[]);
                out.push((lo + 1 + a + key.end(), lo + 1 + b, in_set(keys, name)));
            }
            None => out.push((lo + 1 + a, lo + 1 + b, in_set(keys, pystr::strip(part)))),
        }
    }
    out
}

/// core._ld_value_spans: an object literal's values, else the value whole
/// but the bodies of the methods of the object literals in it.
fn ld_value_spans(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize, bool)> {
    let stripped = pystr::lstrip(pystr::sub(text, lo, hi));
    if pystr::starts_with(stripped, "{") {
        return ld_object_spans(p, text, hi - stripped.len(), hi);
    }
    let mut out = Vec::new();
    let mut pos = lo;
    for m in p.re("_LD_METHOD_IN_RE").finditer_at(text, lo as isize, hi as isize) {
        if m.start() < pos {
            continue;
        }
        let body = m.end() + call_args_len(pystr::sub(text, m.end(), hi)) + 1; // (after the '}' that closes it)
        out.push((pos, m.end(), false));
        pos = body.min(hi);
    }
    out.push((pos, hi, false));
    out
}

/// core._ld_key: the name data is followed in for `name` (ending at
/// text[end]): itself, a receiver's member (`this.x`), or None (a keyword,
/// a module's exports or the runtime's objects, a computed member).
fn ld_key(p: &Pack, text: &[u32], name: &[u32], end: usize) -> Option<PyStr> {
    if in_set(p.strs("_LD_NOT_NAMES"), name) || in_set(p.strs("_LD_NOT_RECEIVERS"), name) {
        return None;
    }
    if !in_set(p.strs("_LD_RECEIVERS"), name) {
        return Some(name.to_vec());
    }
    let m = p.re("_LD_FIRST_MEMBER_RE").match_at(text, end as isize, text.len() as isize)?;
    let member = m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(2)).unwrap_or(&[]);
    Some(pystr::concat(&[name, &u("."), member]))
}

/// core._ld_arg_spans: a call's arguments text[lo:hi], each an address or data.
fn ld_arg_spans(p: &Pack, text: &[u32], lo: usize, hi: usize, addresses: usize, process: bool) -> Vec<(usize, usize, bool)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let option_keys = p.strs("_LD_OPTION_KEYS");
    let process_keys = p.strs("_LD_PROCESS_KEYS");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let mut out = Vec::new();
    for (k, (a, b)) in ld_split_args(pystr::sub(text, lo, hi)).into_iter().enumerate() {
        let (a, b) = (lo + a, lo + b);
        if func_value.match_at(text, a as isize, b as isize).is_some() {
            continue; // a callback: code run later, not data sent
        }
        if k < addresses {
            out.push((a, b, true));
            continue;
        }
        if let Some(kw) = kwarg.match_at(text, a as isize, b as isize) {
            let name = kw.group(1).unwrap_or(&[]);
            out.push((kw.end(), b, in_set(option_keys, name) || (process && in_set(process_keys, name))));
        } else if process && pystr::starts_with(pystr::lstrip(pystr::sub(text, a, b)), "{") {
            out.push((a, b, true));
        } else {
            out.extend(ld_value_spans(p, text, a, b));
        }
    }
    out
}

/// core._ld_process_options: the values of a process's options in a call's arguments text[lo:hi].
fn ld_process_options(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let key_re = p.re("_LD_KEY_RE");
    let process_keys = p.strs("_LD_PROCESS_KEYS");
    let mut out = Vec::new();
    for (a, b) in ld_split_args(pystr::sub(text, lo, hi)) {
        let (a, b) = (lo + a, lo + b);
        if let Some(kw) = kwarg.match_at(text, a as isize, b as isize) {
            if in_set(process_keys, kw.group(1).unwrap_or(&[])) {
                out.push((kw.end(), b));
            }
            continue;
        }
        let stripped = pystr::lstrip(pystr::sub(text, a, b));
        if pystr::starts_with(stripped, "{") {
            let start = b - stripped.len();
            let close = start + 1 + call_args_len(pystr::sub(text, start + 1, b));
            for (cc, d) in ld_split_args(pystr::sub(text, start + 1, close)) {
                if let Some(key) = key_re.match_at(text, (start + 1 + cc) as isize, (start + 1 + d) as isize) {
                    let name = key.group(1).or_else(|| key.group(2)).unwrap_or(&[]);
                    if in_set(process_keys, name) {
                        out.push((key.end(), start + 1 + d));
                    }
                }
            }
        }
    }
    out
}

/// core._ld_bound: the arguments of a call at `at` given a function whose parameters are `names`.
fn ld_bound(p: &Pack, text: &[u32], at: usize, args_len: usize, names: &[PyStr]) -> Vec<(PyStr, usize, usize)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let mut out = Vec::new();
    for (k, (a, b)) in ld_split_args(pystr::sub(text, at, at + args_len)).into_iter().enumerate() {
        let (a, b) = (at + a, at + b);
        match kwarg.match_at(text, a as isize, b as isize) {
            Some(kw) if in_set(names, kw.group(1).unwrap_or(&[])) => {
                out.push((kw.group(1).unwrap_or(&[]).to_vec(), kw.end(), b));
            }
            _ => {
                if k < names.len() {
                    out.push((names[k].clone(), a, b));
                }
            }
        }
    }
    out
}

/// FP-GITHUB-SCRIPT: where the `const`, `let` or `var` that declares what starts at text[at] (a name, or a
/// destructuring's `{` or `[`) begins, with only blanks between, or None when no such keyword stands there (an
/// assignment, which may give a name declared anywhere, and Python's names).
fn declared_at(text: &[u32], at: usize) -> Option<usize> {
    let mut k = at.min(text.len());
    while k > 0 && js_blank(text[k - 1]) {
        k -= 1;
    }
    if k == at {
        return None;
    }
    for kw in ["const", "let", "var"] {
        let n = kw.len();
        if k >= n && is(&text[k - n..k], kw) && (k == n || !ld_ident_char(text[k - n - 1]) && text[k - n - 1] != c('.')) {
            return Some(k - n);
        }
    }
    None
}

/// FP-GITHUB-SCRIPT: where a callback's parameters are its own: (its parameter list's start, its body's end), for a
/// callback whose first parameter is at text[param_at] (`(data) => {…}`, `data => {…}`, `function (data) {…}`, a
/// destructuring's `{` or `[` among them) and whose body is a block whose end is certain (sure_block_end). None for any
/// other (an arrow's expression, a name given where a callback goes, a body whose end is not certain): the parameters
/// reach as before.
fn callback_scope(p: &Pack, text: &[u32], param_at: usize) -> Scope {
    let blank = js_blank;
    let skip = |mut i: usize| {
        while i < text.len() && blank(text[i]) {
            i += 1;
        }
        i
    };
    let mut b = param_at.min(text.len());
    while b > 0 && blank(text[b - 1]) {
        b -= 1;
    }
    let (lo, after) = if b > 0 && text[b - 1] == c('(') {
        let open = b - 1;
        let close = open + 1 + args_len(text, open + 1, p.usize("_DD_ARG_SPAN"));
        if close >= text.len() || text[close] != c(')') {
            return None;
        }
        (open, close + 1)
    } else {
        let mut e = param_at;
        while e < text.len() && ld_ident_char(text[e]) {
            e += 1;
        }
        if e == param_at {
            return None;
        }
        (param_at, e)
    };
    let mut i = skip(after);
    if i + 1 < text.len() && text[i] == c('=') && text[i + 1] == c('>') {
        i = skip(i + 2);
    }
    if i >= text.len() || text[i] != c('{') {
        return None;
    }
    Some((lo, sure_block_end(p, text, i)?))
}

/// Where the first parameter of the callback that starts at text[at] stands (`async`, `function` and its name, a
/// `(` passed over), or None when what is there is not a callback's head.
fn first_param_at(text: &[u32], at: usize) -> Option<usize> {
    let blank = js_blank;
    let skip = |mut i: usize| {
        while i < text.len() && blank(text[i]) {
            i += 1;
        }
        i
    };
    let word = |i: usize, w: &str| {
        let n = w.chars().count();
        i + n <= text.len() && is(&text[i..i + n], w) && (i + n == text.len() || !ld_ident_char(text[i + n]))
    };
    let mut i = skip(at);
    if word(i, "async") {
        i = skip(i + 5);
    }
    if word(i, "function") {
        i = skip(i + 8);
        while i < text.len() && ld_ident_char(text[i]) {
            i += 1; // (its name)
        }
        i = skip(i);
        if i >= text.len() || text[i] != c('(') {
            return None;
        }
    }
    if i < text.len() && text[i] == c('(') {
        i = skip(i + 1);
    }
    (i < text.len() && (ld_ident_char(text[i]) || text[i] == c('{') || text[i] == c('['))).then_some(i)
}

/// core._ld_word_before: where the run of spaces before text[i] starts.
fn ld_word_before(text: &[u32], mut i: usize) -> usize {
    while i > 0 && (text[i - 1] == c(' ') || text[i - 1] == c('\t') || text[i - 1] == c('\n')) {
        i -= 1;
    }
    i
}

fn ld_ident_char(ch: u32) -> bool {
    ch < 128 && (pystr::is_alnum(ch) || ch == c('_') || ch == c('$'))
}

/// Does a word of `words` end at j in text, not inside a longer name?
fn word_ends_at(text: &[u32], j: usize, words: &[PyStr]) -> bool {
    words.iter().any(|w| {
        j >= w.len() && {
            let k = j - w.len();
            text[k..j] == w[..] && (k == 0 || !ld_ident_char(text[k - 1]))
        }
    })
}

/// core._ld_tested: is the value text[start:end] tested rather than used?
fn ld_tested(p: &Pack, text: &[u32], start: usize, end: usize) -> bool {
    if p.re("_LD_TEST_AFTER_RE").match_at(text, end as isize, text.len() as isize).is_some() {
        return true;
    }
    let j = ld_word_before(text, start);
    (j > 0 && text[j - 1] == c('!')) || word_ends_at(text, j, p.strs("_LD_TEST_BEFORE"))
}

/// core._ld_defined: is the call text[start:end] (to its ')') a function's definition?
fn ld_defined(p: &Pack, text: &[u32], start: usize, end: usize) -> bool {
    if end < text.len()
        && text[end] == c(')')
        && p.re("_LD_BODY_RE").match_at(text, end as isize + 1, text.len() as isize).is_some()
    {
        return true;
    }
    word_ends_at(text, ld_word_before(text, start), &[u("def"), u("function")])
}

/// One of _DD_ASSIGN_RE's matches: the spans (start_of, end_of: -1 for a
/// group that took no part) of its name and of its value.
#[derive(Clone, Copy)]
pub(crate) struct Assign {
    name: (isize, isize),
    value: (isize, isize),
}

impl Assign {
    fn group<'t>(text: &'t [u32], (a, b): (isize, isize)) -> &'t [u32] {
        if a < 0 {
            &[]
        } else {
            &text[a as usize..b as usize]
        }
    }

    /// m.group(1).unwrap_or(&[])
    pub(crate) fn name<'t>(&self, text: &'t [u32]) -> &'t [u32] {
        Self::group(text, self.name)
    }

    /// m.group(2).unwrap_or(&[])
    pub(crate) fn value<'t>(&self, text: &'t [u32]) -> &'t [u32] {
        Self::group(text, self.value)
    }

    /// m.start_of(1) as usize
    pub(crate) fn name_start(&self) -> usize {
        self.name.0 as usize
    }

    /// m.start_of(2) as usize
    pub(crate) fn value_start(&self) -> usize {
        self.value.0 as usize
    }
}

/// _DD_ASSIGN_RE's first `_DD_MAX_ASSIGNS` matches in `text`, as
/// finditer gives them. The follower, the secret endpoints and the command
/// lines a shell is handed each read them of one text, so they are kept
/// for the call while a gate is open for it.
pub(crate) fn dd_assigns(p: &Pack, text: &[u32]) -> Vec<Assign> {
    let max = p.usize("_DD_MAX_ASSIGNS");
    crate::textgate::memo(text, "_DD_ASSIGN_RE matches", || {
        let re = p.re("_DD_ASSIGN_RE");
        if pystr::eq(&re.pattern, DD_ASSIGN_SRC) && re.flags == crate::pyre::UNICODE {
            return dd_assigns_by_hand(text, max);
        }
        re.finditer(text)
            .take(max)
            .map(|m| Assign { name: (m.start_of(1), m.end_of(1)), value: (m.start_of(2), m.end_of(2)) })
            .collect()
    })
}

/// _DD_ASSIGN_RE as dd_assigns reads it: by hand (P-1), as NameTokens reads its pattern, for the pattern's search
/// tried at every place of a long text cost a call's test some 40 M instructions over a large Python file (with
/// another pattern in the pack, the pattern's matches).
const DD_ASSIGN_SRC: &str = r"(?:(?<![^\n])|[;{]|=>)[ \t]*(?:(?:const|let|var)[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*\+?=(?![=>])([^;\n]*)";

/// [`DD_ASSIGN_SRC`]'s first `max` matches in `text`, as finditer gives them: at each place in turn, its three starts
/// tried in order (a line's start, `;` or `{`, `=>`), then blanks, a `const`, `let` or `var` and blanks if the rest
/// then matches (else none), a name, blanks, `=` or `+=` not followed by `=` or `>`, and the value up to a `;` or a
/// line's end; the next search from the match's end. (Each repeat but the value's is followed by what it cannot hold,
/// so the pattern's backtracking finds nothing its greedy reading misses.)
fn dd_assigns_by_hand(text: &[u32], max: usize) -> Vec<Assign> {
    let n = text.len();
    let blank = |ch: u32| ch == c(' ') || ch == c('\t');
    let word = |ch: u32| crate::unicode::is_word(ch) || ch == c('$');
    let first = |ch: u32| ch < 128 && ((ch as u8).is_ascii_alphabetic() || ch == c('_') || ch == c('$'));
    let blanks = |mut i: usize| {
        while i < n && blank(text[i]) {
            i += 1;
        }
        i
    };
    // the name from r: (its start, its end, the value's start, the value's end)
    let named = |r: usize| -> Option<(usize, usize, usize, usize)> {
        if r >= n || !first(text[r]) {
            return None;
        }
        let mut e = r + 1;
        while e < n && word(text[e]) {
            e += 1;
        }
        let k = blanks(e);
        let eq = if k + 1 < n && text[k] == c('+') && text[k + 1] == c('=') {
            k + 1
        } else if k < n && text[k] == c('=') {
            k
        } else {
            return None;
        };
        let v = eq + 1;
        if v < n && (text[v] == c('=') || text[v] == c('>')) {
            return None;
        }
        let mut end = v;
        while end < n && text[end] != c(';') && text[end] != c('\n') {
            end += 1;
        }
        Some((r, e, v, end))
    };
    let rest = |q: usize| -> Option<(usize, usize, usize, usize)> {
        let q = blanks(q);
        for kw in ["const", "let", "var"] {
            if pystr::starts_with(&text[q..], kw) {
                let k = q + kw.len();
                if k < n && blank(text[k]) {
                    if let Some(m) = named(blanks(k)) {
                        return Some(m);
                    }
                }
                break;
            }
        }
        named(q)
    };
    let mut out: Vec<Assign> = Vec::new();
    let mut i = 0usize;
    while i < n && out.len() < max {
        // (to the next place a match can start: a line's start, a `;` or `{`, or a `=` that may start `=>`)
        if i > 0 && text[i - 1] != c('\n') {
            match crate::linre::literal::scan_by(text, i, n, |ch| ch == c('\n') || ch == c(';') || ch == c('{') || ch == c('=')) {
                None => break,
                Some(q) => i = if text[q] == c('\n') { q + 1 } else { q },
            }
            if i >= n {
                break;
            }
        }
        let ch = text[i];
        let mut got = None;
        if i == 0 || text[i - 1] == c('\n') {
            got = rest(i);
        }
        if got.is_none() && (ch == c(';') || ch == c('{')) {
            got = rest(i + 1);
        }
        if got.is_none() && ch == c('=') && i + 1 < n && text[i + 1] == c('>') {
            got = rest(i + 2);
        }
        match got {
            Some((a, b, v, end)) => {
                out.push(Assign { name: (a as isize, b as isize), value: (v as isize, end as isize) });
                i = end;
            }
            None => i += 1,
        }
    }
    out
}

/// _LD_NAME_TOKEN_RE as the follower's names are read (`NameTokens` reads
/// this pattern by hand, and only this one).
const NAME_TOKEN_SRC: &str = r"(?:(?<=\.\.\.)|(?<![\w$.]))[A-Za-z_$][\w$]*";

/// _LD_NAME_TOKEN_RE's matches in text[lo..hi], as its finditer_at gives
/// them (start, end): the follower reads the names of every span it looks
/// at, some hundred thousand in a bundle, so this pattern is read by hand.
/// A name starts at a letter, `_` or `$` before which no word character,
/// `$` or `.` stands (but `...` may: a spread), looking before `lo` as the
/// pattern does, and runs through the word characters and `$` after it,
/// up to `hi`. With another pattern in the pack, the pattern's matches.
enum NameTokens<'t> {
    Hand { text: &'t [u32], i: usize, hi: usize },
    Pattern(crate::pyre::FindIter<'t>),
}

impl<'t> NameTokens<'t> {
    fn of(p: &'t Pack, text: &'t [u32], lo: usize, hi: usize) -> NameTokens<'t> {
        let re = p.re("_LD_NAME_TOKEN_RE");
        if pystr::eq(&re.pattern, NAME_TOKEN_SRC) && re.flags == crate::pyre::UNICODE {
            NameTokens::Hand { text, i: lo, hi: hi.min(text.len()) }
        } else {
            NameTokens::Pattern(re.finditer_at(text, lo as isize, hi as isize))
        }
    }
}

impl Iterator for NameTokens<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        match self {
            NameTokens::Pattern(it) => it.next().map(|m| (m.start(), m.end())),
            NameTokens::Hand { text, i, hi } => {
                let t: &[u32] = text;
                let name_char = |ch: u32| crate::unicode::is_word(ch) || ch == c('$');
                while *i < *hi {
                    let at = *i;
                    let ch = t[at];
                    let first = ch < 128 && ((ch as u8).is_ascii_alphabetic() || ch == c('_') || ch == c('$'));
                    let spread = at >= 3 && t[at - 3] == c('.') && t[at - 2] == c('.') && t[at - 1] == c('.');
                    if !first || !(spread || at == 0 || !(name_char(t[at - 1]) || t[at - 1] == c('.'))) {
                        *i += 1;
                        continue;
                    }
                    let mut end = at + 1;
                    while end < *hi && name_char(t[end]) {
                        end += 1;
                    }
                    *i = end;
                    return Some((at, end));
                }
                None
            }
        }
    }
}

/// FP-GITHUB-SCRIPT: the names of the members text[lo..hi] reads (`x.name`, `this.name`, `x?.name`; not a spread's
/// `...name`): (start, end) of each, in order.
fn member_tokens(text: &[u32], lo: usize, hi: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
    let hi = hi.min(text.len());
    let first = |ch: u32| ch < 128 && ((ch as u8).is_ascii_alphabetic() || ch == c('_') || ch == c('$'));
    let name_char = |ch: u32| crate::unicode::is_word(ch) || ch == c('$');
    let mut i = lo.max(1);
    std::iter::from_fn(move || {
        while i < hi {
            let at = i;
            i += 1;
            if text[at - 1] == c('.') && first(text[at]) && !(at >= 2 && text[at - 2] == c('.')) {
                let mut end = at + 1;
                while end < hi && name_char(text[end]) {
                    end += 1;
                }
                i = end;
                return Some((at, end));
            }
        }
        None
    })
}

/// core._ld_names_in: the first name of `names` used in text[lo:hi] (not in a literal).
fn ld_names_in(p: &Pack, text: &[u32], lo: usize, hi: usize, names: &HashSet<PyStr>, lit: &LiteralTest) -> Option<PyStr> {
    if names.is_empty() {
        return None;
    }
    for (a, b) in NameTokens::of(p, text, lo, hi) {
        if names.contains(&text[a..b]) && !lit.at(a) {
            return Some(text[a..b].to_vec());
        }
    }
    None
}

/// core._ld_outside: does text[lo:hi], a call's first argument, name a path outside the package?
pub(crate) fn ld_outside(p: &Pack, text: &[u32], lo: usize, hi: usize, reader: bool, outside: &HashSet<PyStr>, lit: &LiteralTest) -> bool {
    let first = pystr::sub(text, lo, hi);
    if p.re("_LD_OWN_FOLDER_RE").search(first).is_some() {
        return false;
    }
    if p.re("_LD_FS_ROOT_RE").match_(first).is_some() || outside.contains(pystr::strip(first)) {
        return true;
    }
    if reader
        && (p.re("_LD_ABSOLUTE_RE").match_(first).is_some()
            || p.re("_LD_HOME_RE").search(first).is_some()
            || p.re("_LD_ABSOLUTE_IN_RE").search(first).is_some()
            || p.re("_LD_CRED_FILE_RE").match_(first).is_some())
    {
        return true;
    }
    !outside.is_empty() && p.re("_LD_PATH_EXPR_RE").match_(first).is_some() && ld_names_in(p, text, lo, hi, outside, lit).is_some()
}

/// The module's names for the machine's names (core._LD_MODULE_NAMES[module]): (name, kind) pairs.
pub(crate) fn module_names(p: &Pack, module: &[u32]) -> Vec<(PyStr, &'static str)> {
    let raw = match p.raw("_LD_MODULE_NAMES") {
        Some(v) => v,
        None => return Vec::new(),
    };
    let table = raw.get("map").and_then(|m| m.get(&pystr::to_string(module))).and_then(|v| v.get("map")).and_then(|m| m.as_obj());
    match table {
        Some(entries) => entries
            .iter()
            .map(|(k, v)| (k.clone(), kind_of(v.get("value").and_then(|x| x.as_str()).unwrap_or(&[]))))
            .collect(),
        None => Vec::new(),
    }
}

/// core._ld_sources: where text reads local data.
fn ld_sources(p: &Pack, text: &[u32], lit: &LiteralTest, outside: &HashSet<PyStr>, own: &HashSet<PyStr>, rd: &Reading) -> Vec<Source> {
    let max = p.usize("_LD_MAX");
    let span = p.usize("_DD_ARG_SPAN");
    let mut out: Vec<Source> = Vec::new();
    let identity_var = p.re("_SH_IDENTITY_VAR_RE");
    let secret_var = p.re("_SH_SECRET_VAR_RE");
    let quiet = p.re("_LD_ENV_QUIET_RE");
    for (k, m) in p.re("_LD_ENV_RE").finditer(text).enumerate() {
        if k >= max {
            rd.cap();
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let name = (1..=5).find_map(|g| m.group(g));
        let mut end = m.end();
        if m.group(4).is_some() || m.group(5).is_some() {
            // a call's value: after the call
            end += args_len(text, end, span) + 1;
        }
        let name = match name {
            None => continue,
            Some(n) => n,
        };
        if ld_tested(p, text, m.start(), end) {
            continue;
        }
        if identity_var.match_(name).is_some() {
            out.push((m.start(), m.end(), -1, "identity", name.to_vec()));
        } else if secret_var.search(name).is_some() && quiet.match_(name).is_none() {
            out.push((m.start(), m.end(), -1, "environment", name.to_vec()));
        }
    }
    let select = p.re("_LD_ENV_SELECT_RE");
    let excludes = p.re("_LD_EXCLUDES_RE");
    let whole = p.text("_LD_WHOLE_ENV");
    for (k, m) in p.re("_LD_ENV_ALL_RE").finditer(text).enumerate() {
        if k >= max {
            rd.cap();
            break;
        }
        if lit.at(m.start()) || ld_tested(p, text, m.start(), m.end()) {
            continue;
        }
        if let Some(s) = select.match_at(text, m.end() as isize, text.len() as isize) {
            let cond = pystr::sub(text, s.end(), s.end() + args_len(text, s.end(), span));
            if excludes.search(cond).is_none() && secret_var.search(cond).is_none() {
                continue;
            }
        }
        out.push((m.start(), m.end(), -1, "environment", whole.clone()));
    }
    for (k, m) in p.re("_LD_IDENTITY_RE").finditer(text).enumerate() {
        if k >= max {
            rd.cap();
            break;
        }
        if !lit.at(m.start()) {
            let g1 = m.group(1);
            let kind = if g1.map_or(false, |g| is(g, "homedir") || is(g, "networkInterfaces")) { "report" } else { "identity" };
            let called = m.group(2).is_some() || m.group(3).is_some();
            let what = match g1 {
                Some(g) if !g.is_empty() => g.to_vec(),
                _ => u("user or host name"),
            };
            out.push((m.start(), m.end(), if called { m.end() as isize } else { -1 }, kind, what));
        }
    }
    let mut imported: Vec<(PyStr, (&'static str, PyStr))> = Vec::new(); // local name -> (kind, the module's name for it)
    if pystr::contains(text, "os") {
        let name_re = p.re("_LD_IMPORT_NAME_RE");
        for (js, pattern) in [(true, p.re("_LD_IMPORT_JS_RE")), (false, p.re("_LD_IMPORT_PY_RE"))] {
            for (k, m) in pattern.finditer(text).enumerate() {
                if k >= max {
                    rd.cap();
                    break;
                }
                let (module, names): (PyStr, &[u32]) = if js {
                    (u("os"), m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(2)).unwrap_or(&[]))
                } else {
                    (m.group(1).unwrap_or(&[]).to_vec(), m.group(2).unwrap_or(&[]))
                };
                let table = module_names(p, &module);
                for part in pystr::split_char(names, c(',')) {
                    if let Some(n) = name_re.match_(part) {
                        let theirs = n.group(1).unwrap_or(&[]);
                        if let Some((_, kind)) = table.iter().find(|(k2, _)| k2.as_slice() == theirs) {
                            let local = n.group(2).filter(|g| !g.is_empty()).unwrap_or(theirs).to_vec();
                            if !imported.iter().any(|(l, _)| *l == local) {
                                imported.push((local, (kind, theirs.to_vec())));
                            }
                        }
                    }
                }
            }
        }
    }
    if !imported.is_empty() {
        let mut names: Vec<&PyStr> = imported.iter().map(|(n, _)| n).collect();
        names.sort();
        let escaped: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let src = pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\b(\s*\()?")]);
        let uses = rxutil::dynamic(src, 0);
        for (k, m) in uses.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if !lit.at(m.start()) {
                let g1 = m.group(1).unwrap_or(&[]);
                if let Some((_, (kind, theirs))) = imported.iter().find(|(l, _)| l.as_slice() == g1) {
                    let what = if *kind == "report" { theirs.clone() } else { u("user or host name") };
                    let open = if m.group(2).is_some() { m.end() as isize } else { -1 };
                    out.push((m.start(), m.end(), open, kind, what));
                }
            }
        }
    }
    // the machine's modules under another name: `const o = require('os')`, `import socket as s`
    let mut aliases: Vec<(PyStr, PyStr)> = Vec::new(); // (local name, the module it names)
    if pystr::contains(text, "os'") || pystr::contains(text, "os\"") {
        for (k, m) in p.re("_LD_ALIAS_JS_RE").finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            let name = m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(2)).unwrap_or(&[]);
            if !is(name, "os") && !lit.at(m.start()) && !aliases.iter().any(|(n, _)| n.as_slice() == name) {
                aliases.push((name.to_vec(), u("os")));
            }
        }
    }
    if pystr::contains(text, " as ") {
        let part_re = p.re("_LD_ALIAS_PY_PART_RE");
        for (k, m) in p.re("_LD_ALIAS_PY_RE").finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if lit.at(m.start()) {
                continue;
            }
            for part in pystr::split_char(m.group(1).unwrap_or(&[]), c(',')) {
                if let Some(a) = part_re.match_(part) {
                    let (module, local) = (a.group(1).unwrap_or(&[]), a.group(2).unwrap_or(&[]));
                    if local != module && !aliases.iter().any(|(n, _)| n.as_slice() == local) {
                        aliases.push((local.to_vec(), module.to_vec()));
                    }
                }
            }
        }
    }
    if !aliases.is_empty() {
        let mut names: Vec<&PyStr> = aliases.iter().map(|(n, _)| n).collect();
        names.sort();
        let escaped: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let src = pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &p.text("_LD_ALIAS_TAIL")]);
        let uses = rxutil::dynamic(src, 0);
        let os_named = p.strs("_LD_OS_NAMED");
        for (k, m) in uses.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            let local = m.group(1).unwrap_or(&[]);
            let module = match aliases.iter().find(|(n, _)| n.as_slice() == local) {
                Some((_, module)) => module,
                None => continue,
            };
            let member = m.group(2).unwrap_or(&[]);
            let kind = match module_names(p, module).into_iter().find(|(name, _)| name.as_slice() == member) {
                Some((_, kind)) => kind,
                None => continue,
            };
            if lit.at(m.start()) {
                continue;
            }
            let what = if is(module, "os") && in_set(os_named, member) { member.to_vec() } else { u("user or host name") };
            let open = if m.group(3).is_some() { m.end() as isize } else { -1 };
            out.push((m.start(), m.end(), open, kind, what));
        }
    }
    if p.re("_LD_READS_RE").search(text).is_some() {
        let max_calls = p.usize("_LD_MAX_CALLS");
        let not_reads = p.strs("_LD_NOT_READS");
        let readers = p.strs("_LD_READERS");
        let fs_root = p.re("_LD_FS_ROOT_RE");
        let plain_literal = p.re("_LD_PLAIN_LITERAL_RE");
        let empty: HashSet<PyStr> = HashSet::new();
        for (k, m) in p.re("_LD_CALL_RE").finditer(text).enumerate() {
            if k >= max_calls || out.len() >= max * 3 {
                rd.cap();
                break;
            }
            let name = m.group(1).unwrap_or(&[]);
            if in_set(not_reads, name) || lit.at(m.start()) {
                continue;
            }
            let reader = in_set(readers, name);
            let names: &HashSet<PyStr> =
                if reader || (m.start_of(1) as usize == m.start() && own.contains(name)) { outside } else { &empty };
            if !reader && names.is_empty() && fs_root.match_at(text, m.end() as isize, text.len() as isize).is_none() {
                continue;
            }
            let alen = args_len(text, m.end(), span);
            let args = pystr::sub(text, m.end(), m.end() + alen);
            let first = first_arg(args);
            let lead = args.len() - pystr::lstrip(args).len();
            if ld_outside(p, text, m.end() + lead, m.end() + lead + first.len(), reader, names, lit) {
                let what: PyStr = if reader {
                    match plain_literal.match_(first) {
                        Some(pl) => pl.group(2).unwrap_or(&[]).to_vec(),
                        None => first.to_vec(),
                    }
                } else {
                    pystr::concat(&[name, &u("("), first, &u(")")])
                };
                out.push((m.start(), m.end() + alen, m.end() as isize, "file", crate::jsflow::supply::shown_what(p, &what)));
            }
        }
    }
    let argv_item = p.re("_LD_ARGV_ITEM_RE");
    // (and a runner under the script's own name: `util.promisify(exec)`)
    let mut runners: Vec<std::rc::Rc<crate::pyre::Regex>> = Vec::new();
    if pystr::contains(text, "promisify") {
        let mut ms = p.re("_LD_PROMISIFY_RE").finditer(text);
        let mut names: Vec<PyStr> = ms
            .by_ref()
            .take(max)
            .filter(|m| !lit.at(m.start()))
            .map(|m| m.group(1).unwrap_or(&[]).to_vec())
            .collect();
        if ms.next().is_some() {
            rd.cap();
        }
        names.sort();
        names.dedup();
        if !names.is_empty() {
            let escaped: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
            let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
            runners.push(rxutil::dynamic(
                pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("(?:"), &pystr::join(&u("|"), &parts), &u(")"), &p.text("_LD_EXEC_TAIL")]),
                0,
            ));
        }
    }
    for runner in std::iter::once(p.re("_LD_EXEC_RE")).chain(runners.iter().map(|r| &**r)) {
        for (k, m) in runner.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if lit.at(m.start()) {
                continue;
            }
            let mut argv: Vec<&[u32]> = vec![m.group(2).unwrap_or(&[])];
            for it in argv_item.finditer(m.group(3).unwrap_or(&[])) {
                argv.push(it.group(1).unwrap_or(&[]));
            }
            let line = pystr::join(&u(" "), &argv);
            if let Some((kind, what)) = shell::sh_output_data(p, &line, 0, None).into_iter().next() {
                out.push((m.start(), m.end(), m.end_of(1) as isize, kind, what));
            }
        }
    }
    let metadata = p.needles("_LD_METADATA_NEEDLES").any_in(text);
    let public_ip = p.re("_LD_PUBLIC_IP_RE");
    if metadata || public_ip.search(text).is_some() {
        let metadata_re = p.re("_LD_METADATA_RE");
        for (k, f) in p.re("_DD_FETCH_RE").finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if lit.at(f.start()) {
                continue;
            }
            let alen = args_len(text, f.end(), span);
            let args = pystr::sub(text, f.end(), f.end() + alen);
            if metadata && metadata_re.search(args).is_some() {
                out.push((f.start(), f.end() + alen, f.end() as isize, "credentials", u("the instance's metadata")));
            } else if public_ip.search(args).is_some() {
                out.push((f.start(), f.end() + alen, f.end() as isize, "address", u("the machine's public IP address")));
            }
        }
    }
    out
}

/// A send found: (offset, kind, what).
type Found = (usize, &'static str, PyStr);

/// FP-GITHUB-SCRIPT: one reading of a text by the follower. A reading that narrows (`narrow`) gives a variable a
/// function declares that function's body, where the function and its body's end are certain; `capped` records that
/// one of the follower's limits stopped a list the reading reads before its end (a match left unread, a function's
/// parameters not kept, a return not placed, a pass that still had more to give), `narrowed` that a name the reading
/// follows was so narrowed.
struct Reading {
    narrow: bool,
    capped: Cell<bool>,
    narrowed: Cell<bool>,
}

impl Reading {
    fn new(narrow: bool) -> Reading {
        Reading { narrow, capped: Cell::new(false), narrowed: Cell::new(false) }
    }

    /// A limit stopped a list.
    fn cap(&self) {
        self.capped.set(true);
    }
}

/// core.local_data_sent_at: (offset, kind, what, in_address) of the first
/// send of data text reads from the machine, else None.
///
/// FP-GITHUB-SCRIPT: the text is read narrowing the names functions declare
/// to their functions; when that reading narrowed a name and met one of the
/// follower's limits, the text is read again without narrowing (core's
/// reading), and that reading's answer is given, or the narrowing one's when
/// it has none: what a narrowed name holds leaves its function only by the
/// paths the lists hold (a return to its callers, a call's arguments to its
/// callee's parameters), and a list a limit cut short may not hold the one
/// it leaves by.
pub fn local_data_sent_at(p: &Pack, text: &[u32]) -> Option<(usize, &'static str, PyStr, bool)> {
    let rd = Reading::new(true);
    let found = ld_read(p, text, &rd);
    if !(rd.capped.get() && rd.narrowed.get()) {
        return found;
    }
    ld_read(p, text, &Reading::new(false)).or(found)
}

/// FP-GITHUB-SCRIPT: the passes the narrowing reading may take, in core's (`_DD_PASSES`).
const NARROW_PASSES: usize = 4;

/// local_data_sent_at's reading of text as `rd` says.
fn ld_read(p: &Pack, text: &[u32], rd: &Reading) -> Option<(usize, &'static str, PyStr, bool)> {
    if !p.needles("_LD_SEND_NEEDLES").any_in(text) || !p.needles("_LD_NEEDLES").any_in(text) {
        return None;
    }
    let lit = LiteralTest::new(p, text);
    let max = p.usize("_LD_MAX");
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    let max_calls = p.usize("_DD_MAX_CALLS");
    let span = p.usize("_DD_ARG_SPAN");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let not_names = p.strs("_LD_NOT_NAMES");
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new(); // (name, start, end) of what is assigned
    // (FP-GITHUB-SCRIPT) for each of assigns, where the `const`, `let` or `var` that declares its name stands, if
    // one does: the function around it is where the variable holds what it is given
    let mut declared: Vec<Option<usize>> = Vec::new();
    let mut arrows: Vec<(PyStr, usize, usize)> = Vec::new(); // what an arrow or a lambda returns
    let matched = dd_assigns(p, text);
    if matched.len() >= max_assigns {
        rd.cap();
    }
    for m in matched {
        if !lit.at(m.name_start()) && !in_set(not_names, m.name(text)) {
            let v = m.value_start();
            let end = ld_statement_end(p, text, v);
            let name = m.name(text).to_vec();
            if func_value.match_at(text, v as isize, end as isize).is_none() {
                assigns.push((name, v, end));
                declared.push(declared_at(text, m.name_start()));
            } else if let Some(body) = p.re("_LD_ARROW_BODY_RE").match_at(text, v as isize, end as isize) {
                arrows.push((name, body.end(), end));
            }
        }
    }
    let destruct_name = p.re("_DD_DESTRUCT_NAME_RE");
    for (array, pattern) in [(false, p.re("_DD_DESTRUCT_RE")), (true, p.re("_LD_DESTRUCT_ARRAY_RE"))] {
        // `{a, b: c} = …`, `[a, , b] = …`
        for (k, m) in pattern.finditer(text).enumerate() {
            if k >= max_assigns {
                rd.cap();
                break;
            }
            if lit.at(m.start()) {
                continue;
            }
            let v = m.start_of(2) as usize;
            let end = ld_statement_end(p, text, v);
            // `[a, b] = [x, y]`: a is x, b is y
            let mut items: Option<Vec<(usize, usize)>> = None;
            if array {
                let value = pystr::sub(text, v, end);
                let stripped = pystr::lstrip(value);
                if pystr::starts_with(stripped, "[") {
                    let at = v + value.len() - stripped.len() + 1;
                    let inner = pystr::sub(text, at, at + call_args_len(pystr::sub(text, at, end)));
                    items = Some(ld_split_args(inner).into_iter().map(|(a, b)| (at + a, at + b)).collect());
                }
            }
            for (n, part) in pystr::split_char(m.group(1).unwrap_or(&[]), c(',')).into_iter().enumerate() {
                let name = match destruct_name.search(pystr::strip(part)) {
                    Some(name) => name.group(1).unwrap_or(&[]).to_vec(),
                    None => continue,
                };
                if in_set(not_names, &name) {
                    continue;
                }
                let rest = pystr::starts_with(pystr::strip(part), "...");
                match &items {
                    None => assigns.push((name, v, end)),
                    Some(items) if n < items.len() && !rest => assigns.push((name, items[n].0, items[n].1)),
                    Some(items) if rest => assigns.push((name, if n < items.len() { items[n].0 } else { end }, end)),
                    Some(_) => {}
                }
                // (both patterns begin at the declaring keyword)
                declared.resize(assigns.len(), Some(m.start()));
            }
        }
    }
    if pystr::contains(text, ",") {
        // `out, err = p.communicate()`, `user, host = a, b`
        for (k, m) in p.re("_LD_TUPLE_ASSIGN_RE").finditer(text).enumerate() {
            if k >= max_assigns {
                rd.cap();
                break;
            }
            if lit.at(m.start_of(1) as usize) {
                continue;
            }
            let v = m.start_of(2) as usize;
            let end = ld_statement_end(p, text, v);
            let names: Vec<&[u32]> = pystr::split_char(m.group(1).unwrap_or(&[]), c(',')).into_iter().map(pystr::strip).collect();
            let items: Vec<(usize, usize)> = ld_split_args(pystr::sub(text, v, end)).into_iter().map(|(a, b)| (v + a, v + b)).collect();
            for (n, name) in names.iter().enumerate() {
                if !in_set(not_names, name) {
                    let (lo, hi) = if items.len() == names.len() { items[n] } else { (v, end) };
                    assigns.push((name.to_vec(), lo, hi));
                    declared.push(None);
                }
            }
        }
    }
    let plain = assigns.len(); // (the assignments of a name itself)
    // the names that hold a path outside the package
    let path_expr = p.re("_LD_PATH_EXPR_RE");
    let own_folder = p.re("_LD_OWN_FOLDER_RE");
    let fs_root = p.re("_LD_FS_ROOT_RE");
    let home = p.re("_LD_HOME_RE");
    let mut outside: HashSet<PyStr> = HashSet::new();
    for (name, lo, hi) in &assigns[..plain] {
        let value = pystr::strip(pystr::sub(text, *lo, *hi));
        if path_expr.match_(value).is_some()
            && own_folder.search(value).is_none()
            && (fs_root.match_(value).is_some() || home.search(value).is_some())
        {
            outside.insert(name.clone());
        }
    }
    let passes = p.usize("_DD_PASSES");
    for pass in 0..(if outside.is_empty() { 0 } else { passes }) {
        let mut grown = false;
        for (name, lo, hi) in &assigns[..plain] {
            if !outside.contains(name)
                && path_expr.match_at(text, *lo as isize, *hi as isize).is_some()
                && own_folder.search_at(text, *lo as isize, *hi as isize).is_none()
                && ld_names_in(p, text, *lo, *hi, &outside, &lit).is_some()
            {
                outside.insert(name.clone());
                grown = true;
            }
        }
        if !grown {
            break;
        }
        if pass + 1 == passes {
            rd.cap();
        }
    }
    // a copy's destination, of a file outside the package: a name or a literal it is read by
    if pystr::contains(text, "cop") {
        let plain_literal = p.re("_LD_PLAIN_LITERAL_RE");
        let ident = p.re("_IDENT_TOKEN_RE");
        for (k, m) in p.re("_LD_COPY_RE").finditer(text).enumerate() {
            if k >= p.usize("_LD_MAX") {
                rd.cap();
                break;
            }
            if lit.at(m.start()) {
                continue;
            }
            let alen = args_len(text, m.end(), span);
            let args = pystr::sub(text, m.end(), m.end() + alen);
            let parts = ld_split_args(args);
            if parts.len() < 2 {
                continue;
            }
            let ((a, b), (cc, d)) = (parts[0], parts[1]);
            let lead = b - a - pystr::lstrip(&args[a..b]).len();
            let dest = pystr::strip(&args[cc..d]);
            if (plain_literal.match_(dest).is_some() || ident.fullmatch(dest).is_some())
                && ld_outside(p, text, m.end() + a + lead, m.end() + b, true, &outside, &lit)
            {
                outside.insert(dest.to_vec());
            }
        }
    }
    // (an early answer core does not give, the same answer: with no name
    // holding a path outside the package, the reads do not depend on the
    // names assigned or the functions defined; with none of those reads and
    // no text of the instance's metadata (the strings every match of
    // _LD_METADATA_RE holds), nothing is followed and nothing is sent, so
    // the passes below would end in None)
    let early: Option<Vec<Source>> =
        if outside.is_empty() { Some(ld_sources(p, text, &lit, &outside, &HashSet::new(), rd)) } else { None };
    if let Some(found) = &early {
        let metadata_text = p.re("_LD_METADATA_RE").need().map_or(true, |n| n.occurs(text, 0, text.len()));
        if found.is_empty() && !metadata_text {
            return None;
        }
    }
    let mut options: Vec<(PyStr, usize, usize)> = Vec::new(); // the values given a request's option
    let option_keys = p.strs("_LD_OPTION_KEYS");
    let member = p.re("_LD_MEMBER_RE");
    for (k, m) in p.re("_LD_MEMBER_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            rd.cap();
            break;
        }
        if lit.at(m.start_of(1) as usize) {
            continue;
        }
        let name = match ld_key(p, text, m.group(1).unwrap_or(&[]), m.end_of(1) as usize) {
            Some(name) => name,
            None => continue,
        };
        let end = ld_statement_end(p, text, m.end());
        if func_value.match_at(text, m.end() as isize, end as isize).is_some() {
            continue; // (a method: what it returns is its own)
        }
        let chain = m.group(2).unwrap_or(&[]);
        let is_option = member.finditer(chain).any(|mm| {
            let key = mm.group(1).filter(|g| !g.is_empty()).or_else(|| mm.group(2)).unwrap_or(&[]);
            in_set(option_keys, key)
        });
        if is_option {
            options.push((name, m.end(), end));
        } else {
            assigns.push((name, m.end(), end));
        }
    }
    for (k, m) in p.re("_LD_COLLECT_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            rd.cap();
            break;
        }
        if !lit.at(m.start_of(1) as usize) {
            if let Some(name) = ld_key(p, text, m.group(1).unwrap_or(&[]), m.end_of(1) as usize) {
                assigns.push((name, m.end(), m.end() + args_len(text, m.end(), span)));
            }
        }
    }
    if pystr::contains(text, "assign") {
        // `Object.assign(o, …)`: o holds the rest
        for (k, m) in p.re("_LD_MERGE_RE").finditer(text).enumerate() {
            if k >= max_assigns {
                rd.cap();
                break;
            }
            if !lit.at(m.start()) {
                if let Some(name) = ld_key(p, text, m.group(1).unwrap_or(&[]), m.end_of(1) as usize) {
                    assigns.push((name, m.end(), m.end() + args_len(text, m.end(), span)));
                }
            }
        }
    }
    // (a member's, a collection's and a merge's: not declarations)
    declared.resize(assigns.len(), None);
    let mut loops: Vec<(PyStr, usize, usize)> = Vec::new();
    let mut loop_declared: Vec<Option<usize>> = Vec::new(); // (as `declared`, for loops)
    for (k, m) in p.re("_DD_FOR_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            rd.cap();
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let name = m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(3)).unwrap_or(&[]).to_vec();
        if in_set(not_names, &name) {
            continue;
        }
        if m.group(2).map_or(false, |g| !g.is_empty()) {
            loops.push((name, m.start_of(2) as usize, m.end_of(2) as usize));
            loop_declared.push(None); // (Python's `for k in …`)
        } else {
            loops.push((name, m.start_of(4) as usize, m.end_of(4) as usize));
            loop_declared.push(declared_at(text, m.start_of(3) as usize));
        }
    }
    for (k, m) in p.re("_LD_FOR_DESTRUCT_RE").finditer(text).enumerate() {
        // `for (const [k, v] of …)`, `for k, v in …:`
        if k >= max_assigns {
            rd.cap();
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let g = if m.group(1).is_some() { 1 } else { 3 };
        // (`for (const [k, v] of …)`: the keyword before the bracket; Python's: none)
        let decl = if g == 1 { declared_at(text, (m.start_of(1) as usize).saturating_sub(1)) } else { None };
        for part in pystr::split_char(m.group(g).unwrap_or(&[]), c(',')) {
            let bare = pystr::strip(pystr::strip_chars(pystr::strip(part), "()"));
            if let Some(name) = destruct_name.search(bare) {
                let name = name.group(1).unwrap_or(&[]);
                if !in_set(not_names, name) {
                    loops.push((name.to_vec(), m.start_of(g + 1) as usize, m.end_of(g + 1) as usize));
                    loop_declared.push(decl);
                }
            }
        }
    }
    let mut funcs: Vec<(usize, PyStr)> = Vec::new(); // (start, name)
    let mut func_ms: Vec<FuncM> = Vec::new(); // the matches, for where their bodies end
    let mut params: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    let mut defined_at: HashMap<PyStr, usize> = HashMap::new(); // where a function is defined
    // (FP-GITHUB-SCRIPT) each function's parameters, and the first function of each name that has some, past the
    // `_LD_MAX` that `params` keeps: the calls a scope holding data makes (below) are read with them
    let mut func_params: Vec<Vec<PyStr>> = Vec::new();
    let mut first_def: HashMap<PyStr, usize> = HashMap::new();
    let constructors = p.strs("_LD_CONSTRUCTORS");
    let mut classes: Option<Vec<(usize, PyStr)>> = None; // (start, name), once a constructor is found
    for (k, m) in p.re("_LD_FUNC_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            rd.cap();
            break;
        }
        let name = [1usize, 3, 5, 9].iter().find_map(|&g| m.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]).to_vec();
        funcs.push((m.start(), name.clone()));
        func_ms.push(FuncM {
            start: m.start(),
            end: m.end(),
            def: m.group(1).is_some(),
            method: m.group(9).is_some(),
            arrow: m.group(7).is_some() || m.group(8).is_some(),
        });
        let plist = [2usize, 4, 6, 7, 8, 10].iter().find_map(|&g| m.group(g)).unwrap_or(&[]);
        let names = ld_params(p, plist);
        if !names.is_empty() {
            first_def.entry(name.clone()).or_insert(funcs.len() - 1);
        }
        func_params.push(names.clone());
        if !names.is_empty() && !params.contains_key(&name) && params.len() < max {
            defined_at.insert(name.clone(), m.start());
            params.insert(name.clone(), names.clone());
        } else if !names.is_empty() && !params.contains_key(&name) {
            rd.cap();
        }
        if !names.is_empty() && in_set(constructors, &name) {
            // the class's: `new C(…)`, `C(…)`
            let found = classes.get_or_insert_with(|| {
                let mut ms = p.re("_LD_CLASS_RE").finditer(text);
                let kept: Vec<(usize, PyStr)> = ms
                    .by_ref()
                    .take(max_assigns)
                    .filter(|cm| !lit.at(cm.start()))
                    .map(|cm| (cm.start(), cm.group(1).unwrap_or(&[]).to_vec()))
                    .collect();
                if ms.next().is_some() {
                    rd.cap();
                }
                kept
            });
            let ci = found.partition_point(|(a, _)| *a < m.start());
            if ci > 0 {
                let cname = found[ci - 1].1.clone();
                if !params.contains_key(&cname) && params.len() < max {
                    defined_at.insert(cname.clone(), m.start());
                    params.insert(cname, names);
                } else if !params.contains_key(&cname) {
                    rd.cap();
                }
            }
        }
    }
    let func_starts: Vec<usize> = funcs.iter().map(|(a, _)| *a).collect();
    let call_re = if params.is_empty() {
        None
    } else {
        let mut keys: Vec<&PyStr> = params.keys().collect();
        keys.sort();
        let escaped: Vec<PyStr> = keys.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        Some(rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\s*\(")]),
            0,
        ))
    };
    let own: HashSet<PyStr> = funcs.iter().map(|(_, n)| n.clone()).collect();
    // (with no name outside the package, the reads found above: they do not
    // depend on `own` then)
    let mut sources = match early {
        Some(found) => found,
        None => ld_sources(p, text, &lit, &outside, &own, rd),
    };
    sources.sort();
    let metadata_re = p.re("_LD_METADATA_RE");
    let metadata_names: Vec<(PyStr, usize)> = assigns
        .iter()
        .filter(|(_, lo, hi)| metadata_re.search_at(text, *lo as isize, *hi as isize).is_some())
        .map(|(n, lo, _)| (n.clone(), *lo))
        .collect();
    if sources.is_empty() && metadata_names.is_empty() {
        return None;
    }
    let source_starts: Vec<usize> = sources.iter().map(|s| s.0).collect();
    let mut followed: HashMap<PyStr, Got> = HashMap::new(); // name -> the data it holds
    let mut origins: Origins = HashMap::new(); // name -> where it was given it
    let long = text.len() > p.usize("_LD_LONG");
    let near_span = p.usize("_LD_NEAR");
    let mut called: HashSet<PyStr> = HashSet::new(); // the followed names of functions: their calls hold it
    // the path a read is given, and a program's options: sealed
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (k, m) in p.re("_LD_SEAL_RE").finditer(text).enumerate() {
        if k >= max {
            rd.cap();
            break;
        }
        let args = pystr::sub(text, m.end(), m.end() + args_len(text, m.end(), span));
        let first = first_arg(args);
        if !pystr::strip(first).is_empty() {
            spans.push((m.end(), m.end() + first.len()));
        }
    }
    let exec_send = p.re("_LD_EXEC_SEND_RE");
    for (k, m) in exec_send.finditer(text).enumerate() {
        if k >= max {
            rd.cap();
            break;
        }
        if !lit.at(m.start()) {
            let alen = args_len(text, m.end(), span);
            spans.extend(ld_process_options(p, text, m.end(), m.end() + alen));
        }
    }
    if pystr::contains(text, "env") {
        // the environment a call is given as a keyword argument: the program's
        for (k, m) in p.re("_LD_ENV_KWARG_RE").finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if !lit.at(m.start()) {
                let alen = args_len(text, m.end(), span);
                let value = first_arg(pystr::sub(text, m.end(), m.end() + alen));
                if !value.is_empty() {
                    spans.push((m.end(), m.end() + value.len()));
                }
            }
        }
    }
    spans.sort();
    let mut sealed: Vec<(usize, usize)> = Vec::new();
    for (a, b) in spans {
        match sealed.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => sealed.push((a, b)),
        }
    }
    let sealed_starts: Vec<usize> = sealed.iter().map(|(a, _)| *a).collect();
    let is_sealed = |pos: usize| -> bool {
        let k = sealed_starts.partition_point(|&s| s <= pos);
        k > 0 && pos < sealed[k - 1].1
    };
    let not_in_address = p.strs("_LD_NOT_IN_ADDRESS");
    let whole = p.text("_LD_WHOLE_ENV");
    let method_call = p.re("_LD_METHOD_CALL_RE");
    let called_re = p.re("_LD_CALLED_RE");
    let member_read = p.re("_LD_MEMBER_READ_RE");
    let not_in_addr = |kind: &str| not_in_address.iter().any(|x| is(x, kind));
    // (kind, what, through a parameter) of the first read, or of a followed name, in the spans
    let receivers = p.strs("_LD_RECEIVERS");
    let first_member = p.re("_LD_FIRST_MEMBER_RE");
    let read_in = |spans: &[(usize, usize, bool)], loose: bool, followed: &HashMap<PyStr, Got>, called: &HashSet<PyStr>, origins: &Origins| -> Option<Got> {
        for &(lo, hi, address) in spans {
            let mut k = source_starts.partition_point(|&s| s < lo);
            while k < sources.len() && sources[k].0 < hi {
                let s = &sources[k];
                if (!address || loose || !not_in_addr(s.3) || s.4 == whole) && !is_sealed(s.0) {
                    return Some((s.3, s.4.clone(), false));
                }
                k += 1;
            }
            if !followed.is_empty() {
                for (start, m_end) in NameTokens::of(p, text, lo, hi) {
                    let mut name: PyStr = text[start..m_end].to_vec();
                    let mut end = m_end;
                    if in_set(receivers, &name) {
                        // a receiver's member: `this.x`; its method's call: `this.f()`
                        match first_member.match_at(text, end as isize, text.len() as isize) {
                            Some(member) => {
                                let key = member.group(1).filter(|g| !g.is_empty()).or_else(|| member.group(2)).unwrap_or(&[]);
                                name = pystr::concat(&[&name, &u("."), key]);
                                end = member.end();
                            }
                            None => {
                                let method = match method_call.match_at(text, end as isize, text.len() as isize) {
                                    Some(method) => method,
                                    None => continue,
                                };
                                let fname = method.group(1).unwrap_or(&[]);
                                if !called.contains(fname) {
                                    continue;
                                }
                                name = fname.to_vec();
                                end = method.end_of(1) as usize;
                            }
                        }
                    }
                    if let Some(got) = followed.get(&name) {
                        if near(origins, long, near_span, &name, start)
                            && (!address || loose || !not_in_addr(got.0) || got.1 == whole)
                            && !lit.at(start)
                            && !is_sealed(start)
                            && (!called.contains(&name) || called_re.match_at(text, end as isize, text.len() as isize).is_some())
                            && (got.1 != whole || member_read.match_at(text, end as isize, text.len() as isize).is_none())
                            && !ld_tested(p, text, start, end)
                        {
                            return Some(got.clone());
                        }
                    }
                }
            }
        }
        None
    };
    // FP-GITHUB-SCRIPT: a variable a function declares (`const`, `let`, `var`: a name, a destructuring's, a loop's)
    // is that function's: what it is given reaches the function's body (the functions in it among it) and nowhere
    // else, for another function's variable of that name is another variable (a bundle's `result`, `data`,
    // `options`, one in each of its helpers). The follower narrows a name only where it is sure: the function is the
    // innermost one it sees around the declaration, and its body's end is certain (sure_block_end: the brace counter
    // and the JavaScript reading agree, and nothing in the body was a guess); with none such (a module's top, a body
    // whose end is not certain, an arrow's expression, a `def`) the name reaches as before; so do assignments without
    // a keyword, members (`this.x`) and Python's names. And a reading that met one of the follower's limits gives
    // core's answer (local_data_sent_at): what narrowing leaves to the follower's other paths (a return to a caller,
    // a call's arguments to its callee's parameters) is only complete when every list it reads is.
    let body_re = p.re("_LD_BODY_RE");
    let mut scope_ends: HashMap<usize, Option<usize>> = HashMap::new();
    let mut scope_end = |k: usize| -> Option<usize> {
        *scope_ends.entry(k).or_insert_with(|| {
            let m = &func_ms[k];
            if m.def {
                return None;
            }
            let open = if m.method { m.end - 1 } else { body_re.match_at(text, m.end as isize, text.len() as isize)?.end() - 1 };
            sure_block_end(p, text, open)
        })
    };
    let mut decl_scope = |at: Option<usize>| -> Scope {
        if !rd.narrow {
            return None;
        }
        let pos = at?;
        let mut k = func_starts.partition_point(|&s| s <= pos);
        for _ in 0..max {
            if k == 0 {
                return None;
            }
            match scope_end(k - 1) {
                Some(end) if end <= pos => k -= 1,
                Some(end) => return Some((func_starts[k - 1], end)),
                None => return None,
            }
        }
        None
    };
    let scopes: Vec<Scope> = declared.iter().map(|&at| decl_scope(at)).collect();
    let loop_scopes: Vec<Scope> = loop_declared.iter().map(|&at| decl_scope(at)).collect();
    let metadata_scopes: Vec<Scope> = assigns
        .iter()
        .zip(&scopes)
        .filter(|((_, lo, hi), _)| metadata_re.search_at(text, *lo as isize, *hi as isize).is_some())
        .map(|(_, s)| *s)
        .collect();
    for ((name, lo), scope) in metadata_names.iter().zip(&metadata_scopes) {
        bind_in(&mut followed, &mut origins, long, near_span, name, ("credentials", u("the instance's metadata"), false), *lo, *scope);
    }
    // the names given a value composed with a literal
    let quote = p.re("_LD_COMPOSED_RE"); // a value composed with a literal
    let mut composed: HashSet<PyStr> = HashSet::new();
    for ((name, lo, hi), scope) in assigns.iter().zip(&scopes) {
        if !followed.contains_key(name) || !near(&origins, long, near_span, name, *lo) {
            if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called, &origins) {
                if bind_in(&mut followed, &mut origins, long, near_span, name, got, *lo, *scope) && quote.search_at(text, *lo as isize, *hi as isize).is_some() {
                    composed.insert(name.clone());
                }
            }
        }
    }
    let arg_callback = p.re("_DD_ARG_CALLBACK_RE");
    let as_re = p.re("_DD_AS_RE");
    let then_head = p.re("_DD_THEN_HEAD_RE");
    let then_max = p.usize("_DD_THEN_MAX");
    for s in &sources {
        // what a read gives: its callback, `with … as`, `.then(…)`
        let (opening, kind, what) = (s.2, s.3, &s.4);
        if opening < 0 {
            continue;
        }
        let opening = opening as usize;
        let alen = args_len(text, opening, span);
        let args = pystr::sub(text, opening, opening + alen);
        for cb in arg_callback.finditer(args) {
            let Some(g) = [1usize, 2, 3].into_iter().find(|&g| cb.group(g).is_some_and(|x| !x.is_empty())) else { continue };
            let name = cb.group(g).unwrap_or(&[]);
            if !in_set(not_names, name) && !lit.at(opening + cb.start()) {
                // (FP-GITHUB-SCRIPT: the callback's parameter is the callback's)
                let scope = if rd.narrow { callback_scope(p, text, opening + cb.start_of(g) as usize) } else { None };
                bind_in(&mut followed, &mut origins, long, near_span, &name.to_vec(), (kind, what.clone(), false), opening + cb.start(), scope);
            }
        }
        let mut pos = opening + alen + 1;
        if let Some(m) = as_re.match_at(text, pos as isize, text.len() as isize) {
            let name = m.group(1).unwrap_or(&[]);
            if !in_set(not_names, name) {
                bind(&mut followed, &mut origins, long, near_span, &name.to_vec(), (kind, what.clone(), false), pos);
            }
        }
        for link in 0..=then_max {
            let h = match then_head.match_at(text, pos as isize, text.len() as isize) {
                None => break,
                Some(h) => h,
            };
            if link == then_max {
                rd.cap();
                break;
            }
            let tlen = args_len(text, h.end(), span);
            let scope = first_param_at(text, h.end()).filter(|_| rd.narrow).and_then(|at| callback_scope(p, text, at));
            for name in ld_then_params(p, pystr::sub(text, h.end(), h.end() + tlen)) {
                bind_in(&mut followed, &mut origins, long, near_span, &name, (kind, what.clone(), false), h.end(), scope);
            }
            pos = h.end() + tlen + 1;
        }
    }
    // where each function's body ends (None: not known), read when a return asks
    let mut ends: HashMap<usize, Option<usize>> = HashMap::new();
    let body_end = |k: usize, ends: &mut HashMap<usize, Option<usize>>| -> Option<usize> {
        *ends.entry(k).or_insert_with(|| ld_func_end(p, text, &func_ms[k], &lit))
    };
    // the index in funcs of the innermost function whose body holds pos (a
    // function defined before pos whose body ends before it does not)
    let owner = |pos: usize, ends: &mut HashMap<usize, Option<usize>>| -> Option<usize> {
        let mut k = func_starts.partition_point(|&s| s <= pos);
        for _ in 0..max {
            if k == 0 {
                return None;
            }
            match body_end(k - 1, ends) {
                Some(end) if end <= pos => k -= 1,
                _ => return Some(k - 1),
            }
        }
        rd.cap();
        None
    };
    // where the parameters of the script's function are its own: (its
    // definition, its body's end), or None when that is not known
    let scope_of = |fname: &[u32], ends: &mut HashMap<usize, Option<usize>>| -> Scope {
        let at = defined_at[fname];
        let k = func_starts.partition_point(|&s| s < at);
        if k < funcs.len() && func_starts[k] == at {
            body_end(k, ends).map(|end| (at, end))
        } else {
            None
        }
    };
    let mut returns: Vec<(PyStr, usize, usize)> = Vec::new(); // (function, start, end) of what a function returns
    for (k, m) in p.re("_DD_RETURN_RE").finditer(text).enumerate() {
        if k >= max_calls {
            rd.cap();
            break;
        }
        let v = m.start_of(1) as usize;
        let end = ld_statement_end(p, text, v);
        if !lit.at(m.start()) && func_value.match_at(text, v as isize, end as isize).is_none() {
            if let Some(at) = owner(m.start(), &mut ends) {
                returns.push((funcs[at].1.clone(), v, end));
            }
        }
    }
    // (the calls of the script's functions, and the callbacks on names, read
    // once: each pass reads them with what is followed by then)
    let mut calls: Vec<(usize, usize, PyStr, usize)> = Vec::new(); // (start, end, function, its arguments' length)
    if let Some(call_re) = &call_re {
        for (k, cm) in call_re.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if !lit.at(cm.start()) {
                calls.push((cm.start(), cm.end(), cm.group(1).unwrap_or(&[]).to_vec(), args_len(text, cm.end(), span)));
            }
        }
    }
    let callback_re = p.re("_DD_CALLBACK_RE");
    // (start, the name, the callback's parameter, where the parameter is the callback's: FP-GITHUB-SCRIPT)
    let mut ons: Vec<(usize, PyStr, PyStr, Scope)> = Vec::new();
    for (k, m) in callback_re.finditer(text).enumerate() {
        if k >= max_calls {
            rd.cap();
            break;
        }
        if let Some(on) = ld_key(p, text, m.group(1).unwrap_or(&[]), m.end_of(1) as usize) {
            let param = m.group(2).unwrap_or(&[]);
            if !in_set(not_names, param) && !lit.at(m.start()) {
                let scope = if rd.narrow { callback_scope(p, text, m.start_of(2) as usize) } else { None };
                ons.push((m.start(), on, param.to_vec(), scope));
            }
        }
    }
    // the callbacks the script's own functions are given: (the callback's
    // parameters, the callback, the arguments of each call of the
    // function's parameter in its body)
    let mut callbacks: Vec<(Vec<PyStr>, (usize, usize), Vec<Vec<(usize, usize)>>)> = Vec::new();
    let callback_head = p.re("_LD_CALLBACK_HEAD_RE");
    let body_span = p.usize("_LD_BODY_SPAN");
    for (_start, end, fname, alen) in &calls {
        let names_f = match params.get(fname) {
            Some(n) => n,
            None => continue,
        };
        for (i, (a, b)) in ld_split_args(pystr::sub(text, *end, end + alen)).into_iter().enumerate() {
            if i >= names_f.len() {
                break;
            }
            let head = match callback_head.match_at(text, (end + a) as isize, (end + b) as isize) {
                Some(head) => head,
                None => continue,
            };
            let names = ld_params(p, (1..=4).find_map(|g| head.group(g)).unwrap_or(&[]));
            let at_def = defined_at[fname];
            let f = func_starts.partition_point(|&s| s < at_def);
            if names.is_empty() || f >= funcs.len() || func_starts[f] != at_def {
                continue;
            }
            let hi = body_end(f, &mut ends).unwrap_or_else(|| text.len().min(at_def + body_span));
            let src = pystr::concat(&[&p.text("_DV_NAME_HEAD"), &crate::pyre::escape(&names_f[i]), &u(r"\s*\(")]);
            let uses = rxutil::dynamic(src, 0);
            let mut inner: Vec<Vec<(usize, usize)>> = Vec::new(); // the arguments of each call of the parameter
            for (j, um) in uses.finditer_at(text, at_def as isize, hi as isize).enumerate() {
                if j >= max {
                    rd.cap();
                    break;
                }
                if !lit.at(um.start()) {
                    let glen = args_len(text, um.end(), span);
                    let e = um.end();
                    inner.push(ld_split_args(pystr::sub(text, e, e + glen)).into_iter().map(|(x, y)| (e + x, e + y)).collect());
                }
            }
            if !inner.is_empty() {
                callbacks.push((names, (end + a, end + b), inner));
            }
        }
    }
    // a thread's target given its arguments: its parameters
    let mut threads: Vec<(PyStr, usize, usize)> = Vec::new(); // (function, its arguments' start, their length)
    if !params.is_empty() && pystr::contains(text, "target") {
        for (k, m) in p.re("_LD_THREAD_RE").finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            let fname = m.group(1).unwrap_or(&[]);
            if !lit.at(m.start()) && params.contains_key(fname) {
                threads.push((fname.to_vec(), m.end(), args_len(text, m.end(), span)));
            }
        }
    }
    // (start, function, [(parameter, its callback)]): `f().then((d) => …)`, `this.f().then(…)`
    let mut thens: Vec<(usize, PyStr, Vec<(PyStr, (usize, usize))>)> = Vec::new();
    let mut then_names: HashSet<PyStr> = HashSet::new();
    // `name` holds `got`, from text[lo:hi] (`at`: where it is given it instead, a parameter's function): new?
    let follow = |name: &PyStr, got: Got, lo: usize, hi: usize, at: usize, scope: Scope, followed: &mut HashMap<PyStr, Got>, origins: &mut Origins, composed: &mut HashSet<PyStr>| -> bool {
        if !bind_in(followed, origins, long, near_span, name, got, at, scope) {
            return false;
        }
        if quote.search_at(text, lo as isize, hi as isize).is_some() {
            composed.insert(name.clone());
        }
        true
    };
    let then_head_re = p.re("_DD_THEN_HEAD_RE");
    let then_links = p.usize("_DD_THEN_MAX");
    // (FP-GITHUB-SCRIPT) the scopes whose calls are read: the declarations', the callbacks' (a receiver's, and a
    // read's, among the origins bound above), and the parameters' those calls give
    let owned_scopes: HashSet<(usize, usize)> = scopes.iter().chain(loop_scopes.iter()).filter_map(|s| *s).chain(
        ons.iter().filter_map(|o| o.3)).chain(origins.values().flatten().filter_map(|o| o.1)).collect();
    let mut bound_scopes: HashSet<(usize, usize)> = HashSet::new();
    let mut call_scopes: HashSet<(usize, usize)> = HashSet::new(); // (read)
    // (args' start, their length, the callee's start, its parameters, their scope, whether a member's call: `x.f(…)`)
    let mut scoped_calls: Vec<(usize, usize, usize, Vec<PyStr>, Scope, bool)> = Vec::new();
    // (FP-GITHUB-SCRIPT) may what `name` holds reach `pos` as core's reading reaches it: `near`, but a declaration's or
    // a callback's scope (a narrowing one) is not one
    let core_near = |origins: &Origins, name: &[u32], pos: usize| -> bool {
        origins.get(name).map_or(false, |os| {
            os.iter().any(|&(o, scope)| {
                (!long || (pos as isize - o as isize).unsigned_abs() <= near_span)
                    && scope.map_or(true, |s| owned_scopes.contains(&s) || (s.0 <= pos && pos <= s.1))
            })
        })
    };
    // (FP-GITHUB-SCRIPT) the spans each function returns, by its name
    let mut returned: HashMap<&[u32], Vec<(usize, usize)>> = HashMap::new();
    if rd.narrow {
        for (name, lo, hi) in &returns {
            returned.entry(name.as_slice()).or_default().push((*lo, *hi));
        }
    }
    // (FP-GITHUB-SCRIPT) the narrowing reading follows a narrowed name out of its function by a return or a call, a pass
    // each, where core's reading reached the same send by the name at once: it reads until nothing grows, up to
    // NARROW_PASSES times core's passes (a pass that still grew at the last is a limit met)
    let rounds = if rd.narrow { passes * NARROW_PASSES } else { passes };
    for pass in 0..rounds {
        let mut grown = false;
        for ((name, lo, hi), scope) in assigns.iter().zip(&scopes).chain(loops.iter().zip(&loop_scopes)) {
            if !followed.contains_key(name) || !near(&origins, long, near_span, name, *lo) {
                let mut got = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called, &origins);
                if got.is_none() && rd.narrow && !called.is_empty() && core_near(&origins, name, *lo) {
                    // (FP-GITHUB-SCRIPT) `const data = s.grab()`, grab returning its own `data`: core's reading
                    // followed the name there; the narrowing reading, the member's call of a function that returns a
                    // variable of the name (what core reached by the name, and no more)
                    got = member_tokens(text, *lo, *hi)
                        .filter(|&(a, b)| called.contains(&text[a..b]) && called_re.match_at(text, b as isize, text.len() as isize).is_some())
                        .find(|&(a, b)| {
                            returned.get(&text[a..b]).is_some_and(|spans| {
                                spans.iter().any(|&(rlo, rhi)| {
                                    NameTokens::of(p, text, rlo, rhi).any(|(x, y)| text[x..y] == name[..] && near(&origins, long, near_span, name, x))
                                })
                            })
                        })
                        .and_then(|(a, b)| followed.get(&text[a..b]).cloned());
                }
                if let Some(got) = got {
                    if follow(name, got, *lo, *hi, *lo, *scope, &mut followed, &mut origins, &mut composed) {
                        grown = true;
                    }
                }
            }
        }
        for (name, lo, hi) in &options {
            if !followed.contains_key(name) || !near(&origins, long, near_span, name, *lo) {
                if let Some(got) = read_in(&[(*lo, *hi, true)], false, &followed, &called, &origins) {
                    if follow(name, got, *lo, *hi, *lo, None, &mut followed, &mut origins, &mut composed) {
                        grown = true;
                    }
                }
            }
        }
        for (start, on, param, scope) in &ons {
            if let Some(got) = followed.get(on).cloned() {
                if near(&origins, long, near_span, on, *start) && bind_in(&mut followed, &mut origins, long, near_span, param, got, *start, *scope) {
                    grown = true;
                }
            }
        }
        // (what a function returns from its parameters depends on the call: not followed)
        for (name, lo, hi) in returns.iter().chain(arrows.iter()) {
            if !in_set(not_names, name) && (!followed.contains_key(name) || !near(&origins, long, near_span, name, *lo)) {
                if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called, &origins) {
                    if !got.2 && follow(name, got, *lo, *hi, *lo, None, &mut followed, &mut origins, &mut composed) {
                        called.insert(name.clone());
                        grown = true;
                    }
                }
            }
        }
        if called.iter().any(|n| !then_names.contains(n)) {
            // `collect().then((d) => …)`, `this.info().then(…)`
            then_names = called.clone();
            let mut sorted: Vec<&PyStr> = then_names.iter().collect();
            sorted.sort();
            let escaped: Vec<PyStr> = sorted.iter().map(|n| crate::pyre::escape(n)).collect();
            let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
            let heads = rxutil::dynamic(pystr::concat(&[&p.text("_LD_OWN_CALL_HEAD"), &pystr::join(&u("|"), &parts), &u(r")\s*\(")]), 0);
            thens.clear();
            for (k, cm) in heads.finditer(text).enumerate() {
                if k >= max {
                    rd.cap();
                    break;
                }
                if lit.at(cm.start()) {
                    continue;
                }
                let mut links: Vec<(PyStr, (usize, usize))> = Vec::new();
                let mut pos = cm.end() + args_len(text, cm.end(), span) + 1;
                for link in 0..=then_links {
                    let h = match then_head_re.match_at(text, pos as isize, text.len() as isize) {
                        None => break,
                        Some(h) => h,
                    };
                    if link == then_links {
                        rd.cap();
                        break;
                    }
                    let tlen = args_len(text, h.end(), span);
                    for name in ld_then_params(p, pystr::sub(text, h.end(), h.end() + tlen)) {
                        links.push((name, (h.end(), h.end() + tlen)));
                    }
                    pos = h.end() + tlen + 1;
                }
                if !links.is_empty() {
                    thens.push((cm.start(), cm.group(1).unwrap_or(&[]).to_vec(), links));
                }
            }
        }
        for (start, name, links) in &thens {
            if near(&origins, long, near_span, name, *start) {
                for (param, scope) in links {
                    let got = followed[name].clone();
                    if bind_in(&mut followed, &mut origins, long, near_span, param, got, scope.0, Some(*scope)) {
                        grown = true;
                    }
                }
            }
        }
        for (names, scope, inner) in &callbacks {
            // a callback's parameters: what the function calls it with
            for args in inner {
                for (i, (lo, hi)) in args.iter().take(names.len()).enumerate() {
                    let name = &names[i];
                    if !followed.contains_key(name) || !near(&origins, long, near_span, name, scope.0) {
                        if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called, &origins) {
                            if follow(name, got, *lo, *hi, scope.0, Some(*scope), &mut followed, &mut origins, &mut composed) {
                                grown = true;
                            }
                        }
                    }
                }
            }
        }
        for (fname, start, alen) in &threads {
            // a thread's target: its parameters
            let at = defined_at[fname];
            for (param, lo, hi) in ld_bound(p, text, *start, *alen, &params[fname]) {
                if !followed.contains_key(&param) || !near(&origins, long, near_span, &param, at) {
                    if let Some(got) = read_in(&ld_value_spans(p, text, lo, hi), false, &followed, &called, &origins) {
                        if follow(&param, (got.0, got.1, true), lo, hi, at, scope_of(fname, &mut ends), &mut followed, &mut origins, &mut composed) {
                            grown = true;
                        }
                    }
                }
            }
        }
        for (_start, end, fname, alen) in &calls {
            // a function of the script's called with data: its parameters
            let names = match params.get(fname) {
                Some(n) => n,
                None => continue,
            };
            let at = defined_at[fname];
            for (param, lo, hi) in ld_bound(p, text, *end, *alen, names) {
                if func_value.match_at(text, lo as isize, hi as isize).is_some() {
                    continue; // (a callback: code run later, not data given)
                }
                if !followed.contains_key(&param) || !near(&origins, long, near_span, &param, at) {
                    if let Some(got) = read_in(&ld_value_spans(p, text, lo, hi), false, &followed, &called, &origins) {
                        if follow(&param, (got.0, got.1, true), lo, hi, at, scope_of(fname, &mut ends), &mut followed, &mut origins, &mut composed) {
                            grown = true;
                        }
                    }
                }
            }
        }
        // FP-GITHUB-SCRIPT: a scoped variable's data leaves its function by the calls the function makes, which the
        // text's first `_LD_MAX` calls and functions (above) may not reach in a long text: the calls of the script's
        // functions in each scope that holds data (a declaration's or a callback's, then a parameter's these calls
        // gave data) are read, a member's among them (`this.send(d)`: the function of that name, its parameter of the
        // variable's name alone), at most `_LD_MAX` a scope and `_DD_MAX_ASSIGNS` in all, and give their callees'
        // parameters as above.
        let pending: Vec<(usize, usize)> = origins
            .values()
            .flatten()
            .filter_map(|&(_, scope)| scope)
            .filter(|s| (owned_scopes.contains(s) || bound_scopes.contains(s)) && !call_scopes.contains(s))
            .collect();
        for (lo, hi) in pending {
            if !call_scopes.insert((lo, hi)) {
                continue;
            }
            let mut taken = 0;
            let plain = NameTokens::of(p, text, lo, hi).map(|t| (t, false));
            for ((start, name_end), member) in plain.chain(member_tokens(text, lo, hi).map(|t| (t, true))) {
                let Some(open) = called_re.match_at(text, name_end as isize, text.len() as isize) else { continue };
                let fname = &text[start..name_end];
                if lit.at(start) || in_set(not_names, fname) {
                    continue;
                }
                let callee = match params.get(fname) {
                    Some(names) => Some((defined_at[fname], names.clone(), scope_of(fname, &mut ends))),
                    None => first_def.get(fname).map(|&k| (func_starts[k], func_params[k].clone(), body_end(k, &mut ends).map(|e| (func_starts[k], e)))),
                };
                let Some((at, names, scope)) = callee else { continue };
                let alen = args_len(text, open.end(), span);
                if ld_defined(p, text, start, open.end() + alen) {
                    continue; // (a function's definition, not a call)
                }
                if taken >= max || scoped_calls.len() >= max_assigns {
                    rd.cap();
                    break;
                }
                scoped_calls.push((open.end(), alen, at, names, scope, member));
                taken += 1;
            }
        }
        for (end, alen, at, names, scope, member) in &scoped_calls {
            for (param, lo, hi) in ld_bound(p, text, *end, *alen, names) {
                if func_value.match_at(text, lo as isize, hi as isize).is_some() {
                    continue;
                }
                // (a member's call, `this.send(data)`, by the function of its name: only a parameter of the name of
                // the variable it is given, which core's reading followed there by the name, and no more)
                if *member && !(pystr::strip(pystr::sub(text, lo, hi)) == param.as_slice() && core_near(&origins, &param, *at)) {
                    continue;
                }
                if !followed.contains_key(&param) || !near(&origins, long, near_span, &param, *at) {
                    if let Some(got) = read_in(&ld_value_spans(p, text, lo, hi), false, &followed, &called, &origins) {
                        if follow(&param, (got.0, got.1, true), lo, hi, *at, *scope, &mut followed, &mut origins, &mut composed) {
                            grown = true;
                            if let Some(s) = scope {
                                bound_scopes.insert(*s);
                            }
                        }
                    }
                }
            }
        }
        if !grown {
            break;
        }
        if pass + 1 == rounds {
            rd.cap();
        }
    }
    // (FP-GITHUB-SCRIPT) a name narrowed: given what it holds in a declaration's or a callback's scope
    if origins.values().flatten().any(|&(_, s)| s.is_some_and(|s| owned_scopes.contains(&s))) {
        rd.narrowed.set(true);
    }
    let mut found: Vec<Found> = Vec::new(); // sends of data
    let mut in_address: Vec<Found> = Vec::new(); // sends of what an address may hold
    // a send `re` finds whose data holds what the script read
    #[derive(Clone, Copy)]
    enum Where<'r> {
        Any,
        Composed,
        Re(&'r crate::pyre::Regex),
    }
    let first_send = |re: &crate::pyre::Regex, addresses: isize, where_: Where, process: bool, found: &mut Vec<Found>, in_address: &mut Vec<Found>| {
        for (k, s) in re.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                return;
            }
            if lit.at(s.start()) {
                continue;
            }
            let alen = args_len(text, s.end(), span);
            let args = pystr::sub(text, s.end(), s.end() + alen);
            let end = s.end() + alen;
            if ld_defined(p, text, s.start(), end) {
                continue;
            }
            match where_ {
                Where::Any => {}
                Where::Composed => {
                    if quote.search(args).is_none() && ld_names_in(p, text, s.end(), end, &composed, &lit).is_none() {
                        continue;
                    }
                }
                Where::Re(rx) => {
                    if rx.search(args).is_none() {
                        continue;
                    }
                }
            }
            let spans = ld_arg_spans(p, text, s.end(), end, if addresses < 0 { alen + 1 } else { addresses as usize }, process);
            if let Some(got) = read_in(&spans, false, &followed, &called, &origins) {
                found.push((s.start(), got.0, got.1));
                return;
            }
            if in_address.is_empty() {
                if let Some(got) = read_in(&spans, true, &followed, &called, &origins) {
                    in_address.push((s.start(), got.0, got.1));
                }
            }
        }
    };
    first_send(p.re("_LD_SEND_RE"), 1, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_OPTIONS_SEND_RE"), 0, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_REQUEST_SEND_RE"), 2, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_ADDRESS_SEND_RE"), -1, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_LOOKUP_SEND_RE"), -1, Where::Composed, false, &mut found, &mut in_address);
    first_send(exec_send, 0, Where::Re(p.re("_LD_NET_PROGRAM_RE")), true, &mut found, &mut in_address);
    let connection = p.re("_LD_CONNECTION_RE");
    let mut connections: Vec<PyStr> = assigns[..plain]
        .iter()
        .filter(|(_, lo, hi)| connection.search_at(text, *lo as isize, (*hi).min(lo + 300) as isize).is_some())
        .map(|(n, _, _)| n.clone())
        .collect();
    connections.sort();
    connections.dedup();
    if !connections.is_empty() {
        let escaped: Vec<PyStr> = connections.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let rx = rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("(?:"), &pystr::join(&u("|"), &parts), &u(")"), &p.text("_LD_WRITE_TAIL")]),
            0,
        );
        first_send(&rx, 0, Where::Any, false, &mut found, &mut in_address);
    }
    // HTTP clients under the script's own names
    let client_re = p.re("_LD_CLIENT_RE");
    let mut clients: Vec<PyStr> = assigns[..plain]
        .iter()
        .filter(|(_, lo, hi)| client_re.search_at(text, *lo as isize, (*hi).min(lo + 300) as isize).is_some())
        .map(|(n, _, _)| n.clone())
        .collect();
    for (pattern, needle) in [(p.re("_LD_CLIENT_IMPORT_RE"), "import"), (p.re("_LD_CLIENT_AS_RE"), " as ")] {
        if !pystr::contains(text, needle) {
            continue;
        }
        for (k, m) in pattern.finditer(text).enumerate() {
            if k >= max {
                rd.cap();
                break;
            }
            if !lit.at(m.start()) {
                clients.push(m.group(1).unwrap_or(&[]).to_vec());
            }
        }
    }
    clients.retain(|n| !in_set(not_names, n));
    clients.sort();
    clients.dedup();
    if !clients.is_empty() {
        let escaped: Vec<PyStr> = clients.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let names = pystr::concat(&[&u("(?:"), &pystr::join(&u("|"), &parts)]);
        let send = rxutil::dynamic(pystr::concat(&[&p.text("_DV_NAME_HEAD"), &names, &p.text("_LD_CLIENT_SEND_TAIL")]), 0);
        first_send(&send, 1, Where::Any, false, &mut found, &mut in_address);
        let request = rxutil::dynamic(pystr::concat(&[&p.text("_DV_NAME_HEAD"), &names, &p.text("_LD_CLIENT_REQUEST_TAIL")]), 0);
        first_send(&request, 2, Where::Any, false, &mut found, &mut in_address);
    }
    for (k, m) in p.re("_LD_HOST_BUILT_RE").finditer(text).enumerate() {
        // data resolved in a host name: sent
        if k >= max {
            rd.cap();
            break;
        }
        let g = if m.group(2).is_some() {
            2
        } else if m.group(3).is_some() {
            3
        } else {
            4
        };
        let spans = [(m.start_of(g).max(0) as usize, m.end_of(g).max(0) as usize, true)];
        if let Some(got) = read_in(&spans, false, &followed, &called, &origins) {
            found.push((m.start(), got.0, got.1));
            break;
        }
    }
    if found.is_empty() {
        // a connection written to as it is made: https.request(o).end(d)
        let write_tail = p.re("_LD_WRITE_TAIL_RE");
        for (k, cm) in connection.finditer(text).enumerate() {
            if !found.is_empty() {
                break;
            }
            if k >= max {
                rd.cap();
                break;
            }
            if lit.at(cm.start()) {
                continue;
            }
            let close = cm.end() + args_len(text, cm.end(), span);
            if let Some(w) = write_tail.match_at(text, close as isize + 1, text.len() as isize) {
                let end = w.end() + args_len(text, w.end(), span);
                if let Some(got) = read_in(&ld_arg_spans(p, text, w.end(), end, 0, false), false, &followed, &called, &origins) {
                    found.push((cm.start(), got.0, got.1));
                }
            }
        }
    }
    if let Some((at, kind, what)) = found.into_iter().min() {
        return Some((at, kind, what, false));
    }
    if let Some((at, kind, what)) = in_address.into_iter().min() {
        return Some((at, kind, what, true));
    }
    None
}

// ---------------- a webhook whose secret is written in the code ----------------

/// core._se_secret: is a path segment a credential?
fn se_secret(p: &Pack, segment: &[u32]) -> bool {
    if p.re("_SE_SEGMENT_RE").fullmatch(segment).is_none() {
        return false;
    }
    let distinct: HashSet<u32> = segment.iter().copied().collect();
    distinct.len() >= p.usize("_SE_MIN_DISTINCT")
        && segment.iter().any(|&x| (c('A')..=c('Z')).contains(&x))
        && segment.iter().any(|&x| (c('a')..=c('z')).contains(&x))
        && segment.iter().any(|&x| (c('0')..=c('9')).contains(&x))
}

/// core._se_url_secret: does a URL (an _SE_URL_RE match) carry a credential in its path?
fn se_url_secret(p: &Pack, path: &[u32], values: &HashMap<PyStr, PyStr>) -> bool {
    let hole = p.re("_SE_HOLE_RE");
    for segment in pystr::split_char(path, c('/')) {
        let resolved: PyStr = if segment.contains(&c('{')) {
            hole.sub_fn(segment, 0, |h| {
                let name = h.group(1).filter(|g| !g.is_empty()).or_else(|| h.group(2)).unwrap_or(&[]);
                values.get(name).cloned().unwrap_or_else(|| u("{"))
            })
        } else {
            segment.to_vec()
        };
        if se_secret(p, &resolved) {
            return true;
        }
    }
    false
}

/// core.secret_endpoint_at: (offset, reason) of the first request to a
/// webhook whose secret is written in text, else None.
pub fn secret_endpoint_at(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    if !pystr::contains(text, "http") || !p.needles("_SE_NEEDLES").any_in(text) {
        return None;
    }
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    let se_max = p.usize("_SE_MAX");
    let span = p.usize("_DD_ARG_SPAN");
    let plain_literal = p.re("_LD_PLAIN_LITERAL_RE");
    let mut values: HashMap<PyStr, PyStr> = HashMap::new(); // name -> the plain literal it is given
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new();
    for m in dd_assigns(p, text) {
        let name = m.name(text).to_vec();
        if let Some(lit) = plain_literal.match_(pystr::strip(m.value(text))) {
            values.entry(name.clone()).or_insert_with(|| lit.group(2).unwrap_or(&[]).to_vec());
        }
        let v = m.value_start();
        assigns.push((name, v, ld_statement_end(p, text, v)));
    }
    let url_re = p.re("_SE_URL_RE");
    let mut endpoints: Vec<(usize, PyStr)> = Vec::new(); // (start, host) of the literals that hold one
    for &(a, b) in literal_spans(p, text).iter() {
        if endpoints.len() >= se_max {
            break;
        }
        if pystr::find_in(text, &u("http"), a, b).is_none() {
            continue;
        }
        for url in url_re.finditer_at(text, a as isize, b as isize) {
            if se_url_secret(p, url.group(2).unwrap_or(&[]), &values) {
                let host = url.group(1).unwrap_or(&[]);
                let host = match host.iter().rposition(|&x| x == c('@')) {
                    Some(k) => &host[k + 1..],
                    None => host,
                };
                endpoints.push((a, pystr::upto(host, 60).to_vec()));
                break;
            }
        }
    }
    if endpoints.is_empty() {
        return None;
    }
    let starts: Vec<usize> = endpoints.iter().map(|(a, _)| *a).collect();
    let lit = LiteralTest::new(p, text);
    let ident = p.re("_IDENT_TOKEN_RE");
    let mut held: HashMap<PyStr, PyStr> = HashMap::new(); // name -> the host of the endpoint it holds
    let holds = |lo: usize, hi: usize, held: &HashMap<PyStr, PyStr>| -> Option<PyStr> {
        let k = starts.partition_point(|&s| s < lo);
        if k < starts.len() && starts[k] < hi {
            return Some(endpoints[k].1.clone());
        }
        if !held.is_empty() {
            for m in ident.finditer_at(text, lo as isize, hi as isize) {
                if let Some(h) = held.get(m.group0()) {
                    if !lit.at(m.start()) {
                        return Some(h.clone());
                    }
                }
            }
        }
        None
    };
    let mut params: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    let param_re = p.re("_LD_PARAM_RE");
    for (k, m) in p.re("_LD_FUNC_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        let name = [1usize, 3, 5, 9].iter().find_map(|&g| m.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]).to_vec();
        let plist = [2usize, 4, 6, 7, 8, 10].iter().find_map(|&g| m.group(g)).unwrap_or(&[]);
        let mut names: Vec<PyStr> = Vec::new();
        for part in pystr::split_char(plist, c(',')) {
            if let Some(pm) = param_re.match_(part) {
                let pn = pm.group(1).unwrap_or(&[]);
                if !is(pn, "self") && !is(pn, "cls") {
                    names.push(pn.to_vec());
                }
            }
        }
        if !names.is_empty() && !params.contains_key(&name) && params.len() < se_max {
            params.insert(name, names);
        }
    }
    let call_re = if params.is_empty() {
        None
    } else {
        let mut keys: Vec<&PyStr> = params.keys().collect();
        keys.sort();
        let escaped: Vec<PyStr> = keys.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        Some(rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\s*\(")]),
            0,
        ))
    };
    for _ in 0..p.usize("_DD_PASSES") {
        let mut grown = false;
        for (name, lo, hi) in &assigns {
            if !held.contains_key(name) {
                if let Some(host) = holds(*lo, *hi, &held) {
                    held.insert(name.clone(), host);
                    grown = true;
                }
            }
        }
        if let Some(call_re) = &call_re {
            for (k, cm) in call_re.finditer(text).enumerate() {
                if k >= se_max {
                    break;
                }
                if lit.at(cm.start()) {
                    continue;
                }
                let alen = args_len(text, cm.end(), span);
                let names = match params.get(cm.group(1).unwrap_or(&[])) {
                    Some(n) => n,
                    None => continue,
                };
                for (param, lo, hi) in ld_bound(p, text, cm.end(), alen, names) {
                    if !held.contains_key(&param) {
                        if let Some(host) = holds(lo, hi, &held) {
                            held.insert(param, host);
                            grown = true;
                        }
                    }
                }
            }
        }
        if !grown {
            break;
        }
    }
    let mut found: Vec<(usize, PyStr)> = Vec::new();
    let net_program = p.re("_LD_NET_PROGRAM_RE");
    for (pattern, where_) in [(p.re("_SE_REQUEST_RE"), None), (p.re("_LD_EXEC_SEND_RE"), Some(net_program))] {
        for (k, r) in pattern.finditer(text).enumerate() {
            if k >= se_max {
                break;
            }
            if lit.at(r.start()) {
                continue;
            }
            let alen = args_len(text, r.end(), span);
            let args = pystr::sub(text, r.end(), r.end() + alen);
            if let Some(rx) = where_ {
                if rx.search(args).is_none() {
                    continue;
                }
            }
            if let Some(host) = holds(r.end(), r.end() + alen, &held) {
                found.push((r.start(), host));
                break;
            }
        }
    }
    let (at, host) = found.into_iter().min()?;
    Some((at, pystr::concat(&[&u("sends data to a webhook whose secret is written in the code ("), &host, &u(")")])))
}

#[cfg(test)]
#[path = "flow_scope_tests.rs"]
mod scope_tests;

#[cfg(test)]
#[path = "flow_scope_review_tests.rs"]
mod scope_review_tests;

#[cfg(test)]
mod name_token_tests {
    use super::*;

    /// The assignments read by hand are the pattern's matches (P-1), whatever the text, at most `max` of them.
    #[test]
    fn assignments_by_hand_are_the_patterns_matches() {
        let p = crate::pack::current();
        let re = p.re("_DD_ASSIGN_RE");
        assert!(pystr::eq(&re.pattern, DD_ASSIGN_SRC) && re.flags == crate::pyre::UNICODE, "the pack's pattern is the one read by hand");
        let mut seed: u64 = 0x0DDA_5516_2026_1016;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let pieces = [
            "a", "Z", "_", "$", "9", "x1", "é", "ſ", "٣", "\u{2160}", " ", "\t", "\n", "\r", ";", "{", "}", "=", "==", "=>", "+=", "+",
            "+==", ">", "const", "let", "var", "const ", "let\t", "var  ", "constx", "lets", ".", "(", "'", "\"", "-", "\u{2028}",
        ];
        for k in 0..20_000 {
            let text: Vec<u32> = (0..next(30)).flat_map(|_| pieces[next(pieces.len() as u64) as usize].chars().map(|ch| ch as u32)).collect();
            let max = if k % 7 == 0 { next(4) as usize } else { 5000 };
            let want: Vec<(isize, isize, isize, isize)> =
                re.finditer(&text).take(max).map(|m| (m.start_of(1), m.end_of(1), m.start_of(2), m.end_of(2))).collect();
            let got: Vec<(isize, isize, isize, isize)> =
                dd_assigns_by_hand(&text, max).iter().map(|a| (a.name.0, a.name.1, a.value.0, a.value.1)).collect();
            assert_eq!(got, want, "{:?}", text.iter().map(|&ch| char::from_u32(ch).unwrap()).collect::<String>());
        }
    }

    /// The names read by hand are the pattern's matches, for any text and
    /// range (a range's start may have a name or a spread before it).
    #[test]
    fn names_by_hand_are_the_patterns_matches() {
        let p = crate::pack::current();
        let re = p.re("_LD_NAME_TOKEN_RE");
        assert!(matches!(NameTokens::of(&p, &[], 0, 0), NameTokens::Hand { .. }), "the pack's pattern is the one read by hand");
        let mut seed: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let pieces = ["a", "Z", "_", "$", "9", ".", "...", " ", "(", "\n", "é", "ſ", "x1", "..a", "٣", "\u{2160}", "=", "'"];
        for _ in 0..3_000 {
            let text: Vec<u32> = (0..next(40)).flat_map(|_| pieces[next(pieces.len() as u64) as usize].chars().map(|ch| ch as u32)).collect();
            let lo = next(text.len() as u64 + 1) as usize;
            let hi = lo + next((text.len() - lo) as u64 + 1) as usize;
            let want: Vec<(usize, usize)> = re.finditer_at(&text, lo as isize, hi as isize).map(|m| (m.start(), m.end())).collect();
            let got: Vec<(usize, usize)> = NameTokens::of(&p, &text, lo, hi).collect();
            assert_eq!(got, want, "{:?} [{}, {})", crate::pystr::to_string(&text), lo, hi);
        }
    }
}
