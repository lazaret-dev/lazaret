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

fn str_re<'p>(p: &'p Pack, lang: Option<&str>, key: &[u32]) -> &'p Regex {
    p.item_re("_LEX_STR", &Value::Arr(vec![lang_key(lang), Value::Str(key.to_vec())]))
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
                if let Some(rm) = js_regex.match_at(content, k as isize, n as isize) {
                    pos = rm.end();
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
        let sm = if mysql {
            p.map_re("_LEX_MYSQL_STR", &pystr::to_string(&[ch])).match_at(content, k as isize, n as isize)
        } else {
            let triple = [ch, ch, ch];
            let key: &[u32] =
                if lang == Some("py") && content.len() >= k + 3 && content[k..k + 3] == triple { &triple } else { &triple[..1] };
            str_re(p, lang, key).match_at(content, k as isize, n as isize)
        };
        pos = sm.map(|m| m.end()).unwrap_or(k + 1).max(k + 1);
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
                let sm = str_re(p, Some("py"), &key).match_at(s, i as isize, n as isize);
                i = sm.map(|m| m.end()).unwrap_or(i + 1).max(i + 1);
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
                        if let Some(rm) = js_regex.match_at(content, k as isize, n as isize) {
                            pos = rm.end();
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
                    let sm = str_re(p, Some("js"), &[ch]).match_at(content, k as isize, n as isize);
                    pos = sm.map(|m| m.end()).unwrap_or(k + 1).max(k + 1);
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
