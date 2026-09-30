//! The comment lexer: a port of lazaret.scanner.core's `_lex_comment_spans`
//! (section "Comment lexer"): two readings of each language — Python with
//! and without PEP 701 f-strings, JavaScript with and without JSX, SQL as
//! standard and as MySQL reads it — and the spans both agree on. Every
//! offset is a code-point index.

use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use crate::pyre::Regex;
use crate::unicode;

pub type Spans = Vec<(usize, usize)>;

const fn c(ch: char) -> u32 {
    ch as u32
}

fn lang_key(lang: Option<&str>) -> Value {
    match lang {
        Some(l) => Value::str(l),
        None => Value::Null,
    }
}

// ---- the literals' patterns, matched by hand ----
// The lexer consumes a literal once per token with one of a few patterns
// (_LEX_STR, _LEX_MYSQL_STR, _JS_REGEX_LIT_RE). Each is matched here by a
// loop that gives the pattern's own match (each pattern has one way to
// match: see the notes at each loop), when the pack's pattern is the text
// the loop was written for (the text and flags are compared once); any
// other text runs as a regex.

/// How a string pattern consumes a literal starting at its quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrScan {
    /// Q(?:[^Q\\\n]|\\.)*Q? with DOTALL; `newlines`: Q(?:[^Q\\]|\\.)*Q?
    Escaped { q: u32, newlines: bool },
    /// QQQ(?:[^Q\\]|\\.|Q(?!QQ))*(?:QQQ|\Z) with DOTALL
    Triple { q: u32 },
    /// Q[^Q]*Q? without flags
    Plain { q: u32 },
}

fn str_scan_of(rx: &Regex) -> Option<StrScan> {
    let text = pystr::to_string(&rx.pattern);
    let flags = rx.flags & !crate::pyre::constants::FLAG_UNICODE;
    let dotall = flags == crate::pyre::DOTALL;
    for q in ['\'', '"', '`'] {
        let found = if text == format!(r"{q}(?:[^{q}\\\n]|\\.)*{q}?") && dotall {
            StrScan::Escaped { q: q as u32, newlines: false }
        } else if text == format!(r"{q}(?:[^{q}\\]|\\.)*{q}?") && dotall {
            StrScan::Escaped { q: q as u32, newlines: true }
        } else if text == format!(r"{q}{q}{q}(?:[^{q}\\]|\\.|{q}(?!{q}{q}))*(?:{q}{q}{q}|\Z)") && dotall {
            StrScan::Triple { q: q as u32 }
        } else if text == format!(r"{q}[^{q}]*{q}?") && flags == 0 {
            StrScan::Plain { q: q as u32 }
        } else {
            continue;
        };
        return Some(found);
    }
    None
}

impl StrScan {
    /// The end of the match at k (match_at(s, k, len)), or None.
    fn end(self, s: &[u32], k: usize) -> Option<usize> {
        let n = s.len();
        match self {
            // The loop takes any character but the quote, a backslash and
            // (unless `newlines`) a newline, or a backslash and the character
            // after it; it stops at the quote, a newline, a backslash that
            // ends the text, or the end. `Q?` then takes a quote there: the
            // whole always matches, so the greedy loop is never given back.
            StrScan::Escaped { q, newlines } => {
                if s.get(k) != Some(&q) {
                    return None;
                }
                let mut i = k + 1;
                while i < n {
                    let c = s[i];
                    if c == q || (!newlines && c == '\n' as u32) {
                        break;
                    }
                    if c == '\\' as u32 {
                        if i + 1 < n {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                if i < n && s[i] == q {
                    i += 1;
                }
                Some(i)
            }
            // The loop stops at the first QQQ (no alternative takes its first
            // quote), at a backslash that ends the text, or at the end; QQQ or
            // \Z must follow, and no shorter loop ends at one (it would have
            // stopped there), so a backslash at the end is no match.
            StrScan::Triple { q } => {
                if s.len() < k + 3 || s[k..k + 3] != [q, q, q] {
                    return None;
                }
                let mut i = k + 3;
                loop {
                    if i >= n {
                        return Some(n);
                    }
                    let c = s[i];
                    if c == '\\' as u32 {
                        if i + 1 < n {
                            i += 2;
                            continue;
                        }
                        return None;
                    }
                    if c == q && i + 2 < n && s[i + 1] == q && s[i + 2] == q {
                        return Some(i + 3);
                    }
                    i += 1;
                }
            }
            StrScan::Plain { q } => {
                if s.get(k) != Some(&q) {
                    return None;
                }
                let mut i = k + 1;
                while i < n && s[i] != q {
                    i += 1;
                }
                Some(if i < n { i + 1 } else { i })
            }
        }
    }
}

/// A string pattern of the lexer's tables, with its hand matcher when it has one.
struct LexStr {
    lang: Value,
    key: Vec<u32>,
    rx: Regex,
    scan: Option<StrScan>,
}

fn lex_str_table(v: &Value) -> Vec<LexStr> {
    let compile = |x: &Value| -> Option<Regex> {
        let src = x.get("re")?.as_str()?;
        let flags = x.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
        Regex::new(src, crate::pyre::flags_from_letters(&flags)).ok()
    };
    let mut out = Vec::new();
    if let Some(items) = v.get("items").and_then(|l| l.as_arr()) {
        for kv in items {
            let kv = match kv.as_arr() {
                Some(kv) if kv.len() == 2 => kv,
                _ => continue,
            };
            let key = match kv[0].as_arr() {
                Some(k) if k.len() == 2 => k,
                _ => continue,
            };
            if let (Some(rx), Some(ks)) = (compile(&kv[1]), key[1].as_str()) {
                let scan = str_scan_of(&rx);
                out.push(LexStr { lang: key[0].clone(), key: ks.to_vec(), rx, scan });
            }
        }
    }
    if let Some(map) = v.get("map").and_then(|m| m.as_obj()) {
        for (k, x) in map {
            if let Some(rx) = compile(x) {
                let scan = str_scan_of(&rx);
                out.push(LexStr { lang: Value::Null, key: k.clone(), rx, scan });
            }
        }
    }
    out
}

/// The end of the literal the lexer's table `table` (_LEX_STR, keyed by
/// language and quote; _LEX_MYSQL_STR, by quote) matches at k, or None.
fn str_end(p: &Pack, table: &str, lang: Option<&str>, key: &[u32], s: &[u32], k: usize) -> Option<usize> {
    let rows = p.derived(table, lex_str_table);
    let want = if table == "_LEX_STR" { lang_key(lang) } else { Value::Null };
    match rows.iter().find(|r| r.key == key && r.lang == want) {
        Some(r) => match r.scan {
            Some(scan) => scan.end(s, k),
            None => r.rx.match_at(s, k as isize, s.len() as isize).map(|m| m.end()),
        },
        None => panic!("{} has no pattern for {:?}", table, pystr::to_string(key)),
    }
}

const JS_REGEX_LIT_TEXT: &str = r"/(?![*/])(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/";

/// The end of the regular-expression literal _JS_REGEX_LIT_RE matches at k
/// (a '/'), or None. By hand when the pattern is the text this was written
/// for: after "/" not followed by * or /, the loop takes a character but
/// / \ [ and a newline, a backslash and the character after it (not a
/// newline), or a class [ … ] (the same inside, ] ends it); every step
/// starts at a character no other step takes and none of them is '/', so
/// the only match ends at the "/" where the loop (of one step at least) stops.
fn js_regex_end(p: &Pack, rx: &Regex, s: &[u32], k: usize) -> Option<usize> {
    let hand = *p.derived("_JS_REGEX_LIT_RE", |v| {
        v.get("re").and_then(|r| r.as_str()) == Some(pystr::u(JS_REGEX_LIT_TEXT).as_slice())
            && v.get("flags").and_then(|f| f.as_str()).map(|f| f.is_empty()).unwrap_or(false)
    });
    if !hand {
        return rx.match_at(s, k as isize, s.len() as isize).map(|m| m.end());
    }
    let n = s.len();
    let (slash, nl, bs) = ('/' as u32, '\n' as u32, '\\' as u32);
    if s.get(k) != Some(&slash) || matches!(s.get(k + 1), Some(&c) if c == '*' as u32 || c == slash) {
        return None;
    }
    let mut i = k + 1;
    let mut steps = 0usize;
    while i < n {
        let c = s[i];
        if c == bs {
            if i + 1 < n && s[i + 1] != nl {
                i += 2;
                steps += 1;
                continue;
            }
            break;
        }
        if c == '[' as u32 {
            let mut j = i + 1;
            let mut closed = false;
            while j < n {
                let d = s[j];
                if d == ']' as u32 {
                    closed = true;
                    j += 1;
                    break;
                }
                if d == nl {
                    break;
                }
                if d == bs {
                    if j + 1 < n && s[j + 1] != nl {
                        j += 2;
                        continue;
                    }
                    break;
                }
                j += 1;
            }
            if !closed {
                break;
            }
            i = j;
            steps += 1;
            continue;
        }
        if c == slash || c == nl {
            break;
        }
        i += 1;
        steps += 1;
    }
    if steps > 0 && i < n && s[i] == slash {
        Some(i + 1)
    } else {
        None
    }
}

fn is_word_char(ch: u32) -> bool {
    unicode::is_alnum(ch) || ch == c('_') || ch == c('$')
}

/// core._js_regex_allowed: may a '/' after this code start a regex literal?
fn js_regex_allowed(p: &Pack, prev: Option<u32>, tail: &[u32], keywords: &[PyStr]) -> bool {
    let prev = match prev {
        None => return true,
        Some(ch) => ch,
    };
    if p.strs("_JS_REGEX_PREV").iter().any(|x| x.len() == 1 && x[0] == prev) {
        return true;
    }
    if is_word_char(prev) {
        let mut k = tail.len();
        while k > 0 && is_word_char(tail[k - 1]) {
            k -= 1;
        }
        if k == 0 && tail.len() >= 11 {
            return false;
        }
        return keywords.iter().any(|kw| kw.as_slice() == &tail[k..]);
    }
    false
}

/// core._intersect_spans
pub fn intersect_spans(a: &[(usize, usize)], b: &[(usize, usize)]) -> Spans {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let s = a[i].0.max(b[j].0);
        let e = a[i].1.min(b[j].1);
        if s < e {
            out.push((s, e));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn seg_tail(content: &[u32], pos: usize, k: usize) -> Option<(u32, PyStr)> {
    let seg = pystr::rstrip(pystr::sub(content, pos, k));
    seg.last().map(|&last| (last, seg[seg.len().saturating_sub(11)..].to_vec()))
}

fn find_or(content: &[u32], needle: &str, from: usize, n: usize) -> usize {
    pystr::find_str(content, needle, from).unwrap_or(n)
}

/// core._lex_comment_spans. `lang` "py", "js", "sql" or anything else (None);
/// `strings` and `literals`, when given, get the literal spans appended.
pub fn lex_comment_spans(
    p: &Pack,
    content: &[u32],
    lang: Option<&str>,
    strings: Option<&mut Spans>,
    jsx: bool,
    literals: Option<&mut Spans>,
) -> Spans {
    if lang == Some("cfg") {
        panic!("config comment spans are not in the Rust engine yet");
    }
    let lang = lang.filter(|l| matches!(*l, "py" | "js" | "sql"));
    if lang.is_none() || (lang == Some("js") && !jsx) {
        return lex_pass(p, content, lang, strings, false, literals);
    }
    let want_strings = strings.is_some();
    let want_literals = literals.is_some();
    let mut sa: Spans = Vec::new();
    let mut sb: Spans = Vec::new();
    let mut la: Spans = Vec::new();
    let mut lb: Spans = Vec::new();
    let a = lex_pass(
        p,
        content,
        lang,
        if want_strings { Some(&mut sa) } else { None },
        false,
        if want_literals { Some(&mut la) } else { None },
    );
    let b = if lang == Some("js") {
        lex_js_jsx(p, content, if want_strings { Some(&mut sb) } else { None }, if want_literals { Some(&mut lb) } else { None })
    } else {
        lex_pass(
            p,
            content,
            lang,
            if want_strings { Some(&mut sb) } else { None },
            true,
            if want_literals { Some(&mut lb) } else { None },
        )
    };
    if let Some(s) = strings {
        s.extend(intersect_spans(&sa, &sb));
    }
    if let Some(l) = literals {
        l.extend(intersect_spans(&la, &lb));
    }
    intersect_spans(&a, &b)
}

/// core._lex_pass
fn lex_pass(
    p: &Pack,
    content: &[u32],
    lang: Option<&str>,
    mut strings: Option<&mut Spans>,
    second: bool,
    mut literals: Option<&mut Spans>,
) -> Spans {
    let mysql = second && lang == Some("sql");
    let nxt = if mysql { p.re("_LEX_MYSQL_NEXT") } else { p.item_re("_LEX_NEXT", &lang_key(lang)) };
    let fstrings = second && lang == Some("py");
    let js = lang == Some("js");
    let keywords = p.strs("_JS_REGEX_KEYWORDS");
    let js_regex = p.re("_JS_REGEX_LIT_RE");
    let mut spans = Vec::new();
    let n = content.len();
    let mut pos = 0usize;
    let mut prev: Option<u32> = None;
    let mut tail: PyStr = Vec::new();
    let mut no_regex_until: isize = -1;
    while pos < n {
        let m = match nxt.search_at(content, pos as isize, n as isize) {
            None => break,
            Some(m) => m,
        };
        let k = m.start();
        if js && k > pos {
            if let Some((last, t)) = seg_tail(content, pos, k) {
                prev = Some(last);
                tail = t;
            }
        }
        let ch = content[k];
        let two = pystr::sub(content, k, k + 2);
        if (ch == c('#') && (lang == Some("py") || lang.is_none()))
            || (pystr::eq(two, "//") && (js || lang.is_none()))
            || (pystr::eq(two, "--") && lang == Some("sql"))
        {
            let e = find_or(content, "\n", k, n);
            spans.push((k, e));
            pos = e;
            continue;
        }
        if pystr::eq(two, "/*") && lang != Some("py") {
            if mysql && (pystr::starts_with_at(content, k + 2, "!") || pystr::starts_with_at(content, k + 2, "M!")) {
                pos = k + 2;
                continue;
            }
            let e = match pystr::find_str(content, "*/", k + 2) {
                None => n,
                Some(e) => e + 2,
            };
            spans.push((k, e));
            pos = e;
            continue;
        }
        if ch == c('/') {
            if k as isize >= no_regex_until && js_regex_allowed(p, prev, &tail, keywords) {
                if let Some(end) = js_regex_end(p, js_regex, content, k) {
                    pos = end;
                    prev = Some(c('"'));
                    tail.clear();
                    if let Some(l) = literals.as_deref_mut() {
                        l.push((k, pos));
                    }
                    continue;
                }
                no_regex_until = find_or(content, "\n", k, n) as isize;
            }
            pos = k + 1;
            prev = Some(c('/'));
            tail = vec![c('/')];
            continue;
        }
        let (fstring, raw) = if fstrings { py_fstring_prefix(p, content, k) } else { (false, false) };
        if fstring {
            pos = py_fstring_end(p, content, k, raw);
            if let Some(l) = literals.as_deref_mut() {
                l.push((k, pos));
            }
            continue;
        }
        let end = if mysql {
            str_end(p, "_LEX_MYSQL_STR", None, &[ch], content, k)
        } else {
            let triple = [ch, ch, ch];
            let key: &[u32] =
                if lang == Some("py") && content.len() >= k + 3 && content[k..k + 3] == triple { &triple } else { &triple[..1] };
            str_end(p, "_LEX_STR", lang, key, content, k)
        };
        pos = end.unwrap_or(k + 1).max(k + 1);
        prev = Some(c('"'));
        tail.clear();
        if ch != c('`') {
            if let Some(s) = strings.as_deref_mut() {
                s.push((k, pos));
            }
        }
        if let Some(l) = literals.as_deref_mut() {
            l.push((k, pos));
        }
    }
    spans
}

fn py_name_char(ch: u32) -> bool {
    ch == c('_') || ch >= 128 || unicode::is_alnum(ch)
}

/// core._py_fstring_prefix: (is an f-/t-string, raw)
fn py_fstring_prefix(p: &Pack, s: &[u32], k: usize) -> (bool, bool) {
    let mut j = k;
    while j > 0 && k - j <= 2 && py_name_char(s[j - 1]) {
        j -= 1;
    }
    if k - j > 2 || (j > 0 && py_name_char(s[j - 1])) {
        return (false, false);
    }
    let pre = pystr::lower(&s[j..k]);
    let is_f = p.strs("_PY_FSTRING_PREFIXES").iter().any(|x| *x == pre);
    (is_f, pre.contains(&c('r')))
}

#[derive(Clone, Copy)]
enum Frame {
    /// an f-string's text: quote, quote length, raw
    S(u32, usize, bool),
    /// a format spec
    P(u32, usize, bool),
    /// a replacement field's code: bracket depth, and its f-string's quote, length, raw
    F(usize, u32, usize, bool),
}

/// core._py_fstring_end
fn py_fstring_end(p: &Pack, s: &[u32], k: usize, raw: bool) -> usize {
    let n = s.len();
    let q = s[k];
    let ql = if s.len() >= k + 3 && s[k..k + 3] == [q, q, q] { 3 } else { 1 };
    let mut stack: Vec<Frame> = vec![Frame::S(q, ql, raw)];
    let mut i = k + ql;
    let mut named = false;
    let field_stop = p.re("_FSTR_FIELD_STOP");
    fn pop_string(stack: &mut Vec<Frame>) {
        while let Some(f) = stack.pop() {
            if matches!(f, Frame::S(..)) {
                break;
            }
        }
    }
    while let Some(&fr) = stack.last() {
        let (q, ql, rw, is_p) = match fr {
            Frame::S(q, ql, rw) => (q, ql, rw, false),
            Frame::P(q, ql, rw) => (q, ql, rw, true),
            Frame::F(..) => (0, 0, false, false),
        };
        if !matches!(fr, Frame::F(..)) {
            let stop = p.map_re("_FSTR_TEXT_STOP", &pystr::to_string(&[q]));
            let m = match stop.search_at(s, i as isize, n as isize) {
                None => return n,
                Some(m) => m,
            };
            i = m.start();
            let ch = s[i];
            if ch == q {
                if ql == 3 && !(s.len() >= i + 3 && s[i..i + 3] == [q, q, q]) {
                    i += 1;
                    continue;
                }
                i += ql;
                pop_string(&mut stack);
                named = false;
            } else if ch == c('\n') {
                if is_p {
                    stack.pop();
                } else if ql == 1 {
                    pop_string(&mut stack);
                } else {
                    i += 1;
                }
                named = false;
            } else if ch == c('\\') {
                let nx = s.get(i + 1).copied();
                if nx == Some(c('{')) || nx == Some(c('}')) {
                    i += 1;
                } else if !rw && nx == Some(c('N')) && s.get(i + 2) == Some(&c('{')) {
                    i += 3;
                    named = true;
                } else {
                    i += 2;
                }
            } else if ch == c('{') {
                if !is_p && s.get(i + 1) == Some(&c('{')) {
                    i += 2;
                } else {
                    stack.push(Frame::F(0, q, ql, rw));
                    i += 1;
                }
                named = false;
            } else if named {
                named = false;
                i += 1;
            } else if is_p {
                stack.pop();
            } else {
                i += if s.get(i + 1) == Some(&c('}')) { 2 } else { 1 };
            }
            continue;
        }
        let (depth, fq, fql, frw) = match fr {
            Frame::F(d, q, ql, rw) => (d, q, ql, rw),
            _ => (0, 0, 0, false),
        };
        let m = match field_stop.search_at(s, i as isize, n as isize) {
            None => return n,
            Some(m) => m,
        };
        i = m.start();
        let ch = s[i];
        let set_depth = |stack: &mut Vec<Frame>, d: usize| {
            if let Some(Frame::F(dd, ..)) = stack.last_mut() {
                *dd = d;
            }
        };
        if ch == c('#') {
            match pystr::find_char(s, c('\n'), i) {
                None => return n,
                Some(e) => i = e,
            }
        } else if ch == c('\'') || ch == c('"') {
            let (is_f, sraw) = py_fstring_prefix(p, s, i);
            let ql2 = if s.len() >= i + 3 && s[i..i + 3] == [ch, ch, ch] { 3 } else { 1 };
            if is_f {
                stack.push(Frame::S(ch, ql2, sraw));
                i += ql2;
            } else {
                let key: Vec<u32> = vec![ch; ql2];
                i = str_end(p, "_LEX_STR", Some("py"), &key, s, i).unwrap_or(i + 1).max(i + 1);
            }
        } else if matches!(ch, 0x28 | 0x5B | 0x7B) {
            set_depth(&mut stack, depth + 1);
            i += 1;
        } else if ch == c(')') || ch == c(']') {
            set_depth(&mut stack, depth.saturating_sub(1));
            i += 1;
        } else if ch == c('}') {
            i += 1;
            if depth > 0 {
                set_depth(&mut stack, depth - 1);
            } else {
                stack.pop();
            }
        } else {
            // ':'
            if depth == 0 {
                stack.push(Frame::P(fq, fql, frw));
            }
            i += 1;
        }
    }
    i
}

fn jsx_name_start(ch: u32) -> bool {
    if ch < 128 {
        (ch as u8).is_ascii_alphabetic() || ch == c('_') || ch == c('$')
    } else {
        true
    }
}

fn jsx_tag_at(p: &Pack, s: &[u32], j: usize) -> isize {
    let j = p.re("_JSX_WS_RE").match_at(s, j as isize, s.len() as isize).map(|m| m.end()).unwrap_or(j);
    if j < s.len() && (s[j] == c('>') || jsx_name_start(s[j])) {
        j as isize
    } else {
        -1
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Jf {
    Js(usize),
    Tag,
    Text,
}

/// core._lex_js_jsx
fn lex_js_jsx(p: &Pack, content: &[u32], mut strings: Option<&mut Spans>, mut literals: Option<&mut Spans>) -> Spans {
    let mut spans = Vec::new();
    let n = content.len();
    let mut pos = 0usize;
    let mut prev: Option<u32> = None;
    let mut tail: PyStr = Vec::new();
    let mut no_regex_until: isize = -1;
    let mut stack: Vec<Jf> = vec![Jf::Js(0)];
    let js_next = p.re("_JSX_JS_NEXT");
    let file_next = p.re("_JSX_FILE_NEXT");
    let text_next = p.re("_JSX_TEXT_NEXT");
    let ws = p.re("_JSX_WS_RE");
    let name_re = p.re("_JSX_NAME_RE");
    let keywords = p.strs("_JS_REGEX_KEYWORDS");
    let jsx_keywords = p.strs("_JSX_KEYWORDS");
    let js_regex = p.re("_JS_REGEX_LIT_RE");
    let ws_end = |j: usize| ws.match_at(content, j as isize, n as isize).map(|m| m.end()).unwrap_or(j);
    let name_end = |j: usize| name_re.match_at(content, j as isize, n as isize).map(|m| m.end()).unwrap_or(j);
    while pos < n {
        let fr = match stack.last() {
            Some(&f) => f,
            None => break,
        };
        let abort: usize;
        match fr {
            Jf::Js(depth) => {
                let rx = if stack.len() > 1 { js_next } else { file_next };
                let m = match rx.search_at(content, pos as isize, n as isize) {
                    None => break,
                    Some(m) => m,
                };
                let k = m.start();
                if k > pos {
                    if let Some((last, t)) = seg_tail(content, pos, k) {
                        prev = Some(last);
                        tail = t;
                    }
                }
                let ch = content[k];
                let two = pystr::sub(content, k, k + 2);
                if pystr::eq(two, "//") {
                    let e = find_or(content, "\n", k, n);
                    spans.push((k, e));
                    pos = e;
                } else if pystr::eq(two, "/*") {
                    let e = match pystr::find_str(content, "*/", k + 2) {
                        None => n,
                        Some(e) => e + 2,
                    };
                    spans.push((k, e));
                    pos = e;
                } else if ch == c('/') {
                    pos = k + 1;
                    if k as isize >= no_regex_until && js_regex_allowed(p, prev, &tail, keywords) {
                        if let Some(end) = js_regex_end(p, js_regex, content, k) {
                            pos = end;
                            prev = Some(c('"'));
                            tail.clear();
                            if let Some(l) = literals.as_deref_mut() {
                                l.push((k, pos));
                            }
                            continue;
                        }
                        no_regex_until = find_or(content, "\n", k, n) as isize;
                    }
                    prev = Some(c('/'));
                    tail = vec![c('/')];
                } else if ch == c('{') {
                    if let Some(Jf::Js(d)) = stack.last_mut() {
                        *d += 1;
                    }
                    pos = k + 1;
                    prev = Some(c('{'));
                    tail = vec![c('{')];
                } else if ch == c('}') {
                    pos = k + 1;
                    if depth > 0 {
                        if let Some(Jf::Js(d)) = stack.last_mut() {
                            *d -= 1;
                        }
                    } else if stack.len() > 1 {
                        stack.pop();
                        continue;
                    }
                    prev = Some(c('}'));
                    tail = vec![c('}')];
                } else if ch == c('<') {
                    let mut t: isize = -1;
                    if prev == Some(c(')')) || prev == Some(c(']')) || js_regex_allowed(p, prev, &tail, jsx_keywords) {
                        t = jsx_tag_at(p, content, k + 1);
                    }
                    if t >= 0 {
                        stack.push(Jf::Tag);
                        pos = name_end(t as usize);
                    } else {
                        pos = k + 1;
                        prev = Some(c('<'));
                        tail = vec![c('<')];
                    }
                } else {
                    pos = str_end(p, "_LEX_STR", Some("js"), &[ch], content, k).unwrap_or(k + 1).max(k + 1);
                    prev = Some(c('"'));
                    tail.clear();
                    if ch != c('`') {
                        if let Some(s) = strings.as_deref_mut() {
                            s.push((k, pos));
                        }
                    }
                    if let Some(l) = literals.as_deref_mut() {
                        l.push((k, pos));
                    }
                }
                continue;
            }
            Jf::Tag => {
                let j = ws_end(pos);
                if j >= n {
                    break;
                }
                let ch = content[j];
                let two = pystr::sub(content, j, j + 2);
                if pystr::eq(two, "/>") {
                    stack.pop();
                    pos = j + 2;
                    if matches!(stack.last(), Some(Jf::Js(_))) {
                        prev = Some(c('"'));
                        tail.clear();
                    }
                    continue;
                }
                if ch == c('>') {
                    if let Some(last) = stack.last_mut() {
                        *last = Jf::Text;
                    }
                    pos = j + 1;
                    continue;
                }
                if pystr::eq(two, "//") || pystr::eq(two, "/*") {
                    let line = pystr::eq(two, "//");
                    let e = match pystr::find_str(content, if line { "\n" } else { "*/" }, j + 2) {
                        None => n,
                        Some(e) => {
                            if line {
                                e
                            } else {
                                e + 2
                            }
                        }
                    };
                    spans.push((j, e));
                    pos = e;
                    continue;
                }
                if ch == c('{') {
                    stack.push(Jf::Js(0));
                    pos = j + 1;
                    prev = Some(c('{'));
                    tail = vec![c('{')];
                    continue;
                }
                if ch == c('"') || ch == c('\'') {
                    let e = match pystr::find_char(content, ch, j + 1) {
                        None => n,
                        Some(e) => e + 1,
                    };
                    if let Some(s) = strings.as_deref_mut() {
                        s.push((j, e));
                    }
                    if let Some(l) = literals.as_deref_mut() {
                        l.push((j, e));
                    }
                    pos = e;
                    continue;
                }
                if ch == c('=') {
                    pos = j + 1;
                    continue;
                }
                if jsx_name_start(ch) {
                    pos = name_end(j);
                    continue;
                }
                let t = if ch == c('<') { jsx_tag_at(p, content, j + 1) } else { -1 };
                if t >= 0 {
                    stack.push(Jf::Tag);
                    pos = name_end(t as usize);
                    continue;
                }
                abort = j;
            }
            Jf::Text => {
                let m = match text_next.search_at(content, pos as isize, n as isize) {
                    None => break,
                    Some(m) => m,
                };
                let k = m.start();
                let ch = content[k];
                if ch == c('{') {
                    stack.push(Jf::Js(0));
                    pos = k + 1;
                    prev = Some(c('{'));
                    tail = vec![c('{')];
                    continue;
                }
                if ch == c('<') {
                    let mut j = ws_end(k + 1);
                    if pystr::starts_with_at(content, j, "/") {
                        j = ws_end(j + 1);
                        j = name_end(j);
                        j = ws_end(j);
                        if pystr::starts_with_at(content, j, ">") {
                            stack.pop();
                            pos = j + 1;
                            if matches!(stack.last(), Some(Jf::Js(_))) {
                                prev = Some(c('"'));
                                tail.clear();
                            }
                            continue;
                        }
                    } else {
                        let t = jsx_tag_at(p, content, k + 1);
                        if t >= 0 {
                            stack.push(Jf::Tag);
                            pos = name_end(t as usize);
                            continue;
                        }
                    }
                }
                abort = k;
            }
        }
        // not JSX after all: back to the code around it, from this character
        while !matches!(stack.last(), Some(Jf::Js(_)) | None) {
            stack.pop();
        }
        pos = abort;
        prev = Some(c('<'));
        tail = vec![c('<')];
    }
    spans
}
