//! The comment lexer of SQL and of text in no language the engine lexes
//! (a port of lazaret.scanner.core's `_lex_comment_spans`), and the entry
//! point every caller asks for a text's comments and literals:
//! `lex_comment_spans`. JavaScript and Python are read by the engine's
//! lexers (crate::lex: the tokens their runtimes read, two readings where
//! runtimes differ); SQL is read twice, as standard SQL and as MySQL reads
//! it, and the spans both agree on kept; any other text with `#` and `//`
//! line comments, `/* … */` and quoted strings. Every offset is a code-point
//! index.

use crate::json::Value;
use crate::pack::Pack;
use crate::pystr;
use crate::pyre::Regex;

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
// (_LEX_STR, _LEX_MYSQL_STR). Each is matched here by a loop that gives the
// pattern's own match (each pattern has one way to match: see the notes at
// each loop), when the pack's pattern is the text the loop was written for
// (the text and flags are compared once); any other text runs as a regex.

/// How a string pattern consumes a literal starting at its quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrScan {
    /// Q(?:[^Q\\\n]|\\.)*Q? with DOTALL; `newlines`: Q(?:[^Q\\]|\\.)*Q?
    Escaped { q: u32, newlines: bool },
    /// Q[^Q]*Q? without flags
    Plain { q: u32 },
}

fn str_scan_of(rx: &Regex) -> Option<StrScan> {
    let text = pystr::to_string(&rx.pattern);
    let flags = rx.flags & !crate::pyre::UNICODE;
    let dotall = flags == crate::pyre::DOTALL;
    for q in ['\'', '"', '`'] {
        let found = if text == format!(r"{q}(?:[^{q}\\\n]|\\.)*{q}?") && dotall {
            StrScan::Escaped { q: q as u32, newlines: false }
        } else if text == format!(r"{q}(?:[^{q}\\]|\\.)*{q}?") && dotall {
            StrScan::Escaped { q: q as u32, newlines: true }
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

fn find_or(content: &[u32], needle: &str, from: usize, n: usize) -> usize {
    pystr::find_str(content, needle, from).unwrap_or(n)
}

/// The comments of `content` in `lang` ("js", "py", "sql", or anything
/// else: None), sorted; `strings` and `literals`, when given, get the
/// spans of its string literals ('…' "…": a template is no string) and of
/// every literal (strings, regular expressions, a template's or an
/// f-string's text, JSX text) appended. `jsx`: a JavaScript file that may
/// hold JSX (every one but TypeScript's .ts).
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
    if let Some(l @ ("js" | "py" | "go" | "rs")) = lang {
        let st = crate::lex::structure(content, l, jsx).unwrap_or_default();
        if let Some(s) = strings {
            s.extend(st.strings);
        }
        if let Some(x) = literals {
            x.extend(st.literals);
        }
        return st.comments;
    }
    if lang != Some("sql") {
        return lex_pass(p, content, None, strings, false, literals);
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
    let b = lex_pass(
        p,
        content,
        lang,
        if want_strings { Some(&mut sb) } else { None },
        true,
        if want_literals { Some(&mut lb) } else { None },
    );
    if let Some(s) = strings {
        s.extend(intersect_spans(&sa, &sb));
    }
    if let Some(l) = literals {
        l.extend(intersect_spans(&la, &lb));
    }
    intersect_spans(&a, &b)
}

/// core._lex_pass, for SQL (`second`: as MySQL reads it: `/*! … */` code,
/// backslash escapes in strings) and for a text of no known language
/// (`lang` None).
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
    let mut spans = Vec::new();
    let n = content.len();
    let mut pos = 0usize;
    while pos < n {
        let m = match nxt.search_at(content, pos as isize, n as isize) {
            None => break,
            Some(m) => m,
        };
        let k = m.start();
        let ch = content[k];
        let two = pystr::sub(content, k, k + 2);
        if (ch == c('#') && lang.is_none())
            || (pystr::eq(two, "//") && lang.is_none())
            || (pystr::eq(two, "--") && lang == Some("sql"))
        {
            let e = find_or(content, "\n", k, n);
            spans.push((k, e));
            pos = e;
            continue;
        }
        if pystr::eq(two, "/*") {
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
        let end = if mysql {
            str_end(p, "_LEX_MYSQL_STR", None, &[ch], content, k)
        } else {
            str_end(p, "_LEX_STR", lang, &[ch], content, k)
        };
        pos = end.unwrap_or(k + 1).max(k + 1);
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
