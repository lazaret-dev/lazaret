//! Project mode's intra-file taint (core.taint_scan; 0.1.9, Q-1): data from the request, the command line or a
//! decoder that reaches a dangerous call in the same file, read line by line with the file's scopes.
//!
//! Each line is read in its match text without comments (`FileCtx::mcode`). A name assigned a value that carries
//! untrusted data (a source, or a name tainted before) is tainted, with the sink categories it is clean for (a
//! sanitizer for the category, a guard that leaves, a value an allowlist holds); a sink whose arguments carry a
//! tainted name or a source is a T-* finding. Where a taint lives comes from the indentation: a name tainted in a
//! function's body is dropped when it ends; a reassignment in the same block or one around it replaces the value,
//! one in a nested or sibling block adds to it. A statement whose brackets stay open is read with the lines that
//! continue it. Flask views' `return`s are XSS sinks, and route handlers' parameters (Flask, FastAPI, Django:
//! `pyflow::frameworks`) are sources in their bodies.
//!
//! The model is the pack's (TAINT_SOURCES, TAINT_SINKS, _FULL_SAN, _PARTIAL_SAN, the guards, views and routes); a
//! taint configuration (`--taint-config`, `.lazaret-taint.json`) adds sources, sinks and sanitizers for one call
//! (`Model`): its patterns, as taintspec validated them, each see at most _TAINT_MAX_MATCH_TEXT characters of a
//! text, and its sanitizers' names are joined to the pack's patterns as core joined them.

use crate::filectx::{FileCtx, Lang};
use crate::findings::{self, Arg, Finding, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pyflow::frameworks;
use crate::pyre::{self, Regex};
use crate::pystr::{self, PyStr};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- the configured part of the model

/// The configured part of the taint model for one language (a `--taint-config` or `.lazaret-taint.json`, as
/// taintspec validated it): `{"sources": [pattern, …], "sinks": [[pattern, category], …], "full": [name, …],
/// "partial": [[name, [category, …]], …]}` under the call's `"taint"`.
#[derive(Default)]
pub struct Model {
    sources: Vec<Regex>,
    sinks: Vec<(Regex, PyStr)>,
    full: Vec<PyStr>,
    partial: Vec<(PyStr, Vec<PyStr>)>,
    /// The sanitizers' patterns with the configured names joined (`full`, by suffix `partial`), made per language.
    joined: Mutex<HashMap<&'static str, Arc<Joined>>>,
}

#[derive(Default)]
struct Joined {
    full: Option<Regex>,
    partial: Vec<(PyStr, Regex)>,
}

fn strs(v: Option<&Value>) -> Vec<PyStr> {
    v.and_then(|l| l.as_arr()).unwrap_or(&[]).iter().filter_map(|s| s.as_str().map(|s| s.to_vec())).collect()
}

fn compile(src: &[u32]) -> Result<Regex, String> {
    Regex::new(src, 0).map_err(|e| format!("taint: a configured pattern does not compile ({})", e.0))
}

/// A sink category the pack knows (taintspec's CATEGORIES: `_SUFFIX_BY_CATEGORY`'s keys), as the call gave it.
fn category(p: &Pack, v: Option<&Value>) -> Result<PyStr, String> {
    let cat = v.and_then(|v| v.as_str()).ok_or("taint: a category is not a string")?;
    let known = p.raw("_SUFFIX_BY_CATEGORY").and_then(|e| e.get("map")).and_then(|m| m.get(&pystr::to_string(cat)));
    match known {
        Some(_) => Ok(cat.to_vec()),
        None => Err(format!("taint: an unknown category ({:?})", pystr::to_string(cat))),
    }
}

impl Model {
    /// The model a call's arguments give (`"taint"`; none: the pack's alone). A category the pack does not know
    /// is refused, as a pattern that does not compile is (taintspec let neither through).
    pub fn from_args(p: &Pack, args: &Value) -> Result<Model, String> {
        let Some(t) = args.get("taint") else { return Ok(Model::default()) };
        if matches!(t, Value::Null) {
            return Ok(Model::default());
        }
        let mut m = Model::default();
        for s in strs(t.get("sources")) {
            m.sources.push(compile(&s)?);
        }
        for item in t.get("sinks").and_then(|l| l.as_arr()).unwrap_or(&[]) {
            let parts = item.as_arr().ok_or("taint: a sink is not [pattern, category]")?;
            let pat = parts.first().and_then(|v| v.as_str()).ok_or("taint: a sink's pattern")?;
            m.sinks.push((compile(pat)?, category(p, parts.get(1))?));
        }
        m.full = strs(t.get("full"));
        for item in t.get("partial").and_then(|l| l.as_arr()).unwrap_or(&[]) {
            let parts = item.as_arr().ok_or("taint: a partial sanitizer is not [name, [category, …]]")?;
            let name = parts.first().and_then(|v| v.as_str()).ok_or("taint: a partial sanitizer's name")?;
            let cats = parts.get(1).and_then(|v| v.as_arr()).unwrap_or(&[]);
            let cats = cats.iter().map(|c| category(p, Some(c))).collect::<Result<Vec<_>, _>>()?;
            m.partial.push((name.to_vec(), cats));
        }
        Ok(m)
    }

    fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.sinks.is_empty() && self.full.is_empty() && self.partial.is_empty()
    }

    /// The sanitizers of language `lang` with the configured names joined, as core.apply_taint_config joins them.
    fn joined(&self, p: &Pack, lang: &'static str) -> Arc<Joined> {
        let mut cache = self.joined.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = cache.get(lang) {
            return j.clone();
        }
        let body = p.text("_SAN_BODY");
        let call = |name: &[u32]| -> PyStr {
            let mut s = pyre::escape(name);
            s.extend(pystr::u(r"\s*\("));
            s.extend_from_slice(&body);
            s.extend(pystr::u(r"\)"));
            s
        };
        let mut j = Joined::default();
        if !self.full.is_empty() {
            let mut src = pattern_text(p, "_FULL_SAN", lang);
            for name in &self.full {
                src.push('|' as u32);
                src.extend(call(name));
            }
            j.full = Regex::new(&src, 0).ok();
        }
        let mut by_suffix: Vec<(PyStr, PyStr)> = Vec::new();
        for (name, cats) in &self.partial {
            let add = call(name);
            let mut cats = cats.clone();
            cats.sort();
            for cat in cats {
                let suf = suffix_of(p, &cat);
                match by_suffix.iter_mut().find(|(s, _)| *s == suf) {
                    Some((_, src)) => {
                        src.push('|' as u32);
                        src.extend_from_slice(&add);
                    }
                    None => {
                        let src = match partial_text(p, lang, &suf) {
                            Some(mut base) => {
                                base.push('|' as u32);
                                base.extend_from_slice(&add);
                                base
                            }
                            None => add.clone(),
                        };
                        by_suffix.push((suf, src));
                    }
                }
            }
        }
        j.partial = by_suffix.into_iter().filter_map(|(s, src)| Some((s, Regex::new(&src, 0).ok()?))).collect();
        let j = Arc::new(j);
        cache.insert(lang, j.clone());
        j
    }
}

/// A pattern's text in the pack, under a language key.
fn pattern_text(p: &Pack, name: &str, lang: &str) -> PyStr {
    p.raw(name).and_then(|v| v.get("map")).and_then(|m| m.get(lang)).and_then(|e| e.get("re")).and_then(|r| r.as_str())
        .map(|s| s.to_vec()).unwrap_or_default()
}

fn partial_text(p: &Pack, lang: &str, suffix: &[u32]) -> Option<PyStr> {
    let key = pystr::to_string(suffix);
    p.raw("_PARTIAL_SAN")?.get("map")?.get(lang)?.get("map")?.get(&key)?.get("re")?.as_str().map(|s| s.to_vec())
}

fn suffix_of(p: &Pack, cat: &[u32]) -> PyStr {
    p.map_text("_SUFFIX_BY_CATEGORY", &pystr::to_string(cat))
}

// ---------------------------------------------------------------- the pack's model, read once

/// How much of a built-in sink's arguments carries the injection (core._SINK_ARGS).
#[derive(Clone, Copy, PartialEq)]
enum ArgMode {
    First,
    Positional,
    Extent,
}

struct BaseSink {
    suffix: PyStr,
    re: Regex,
    cat: PyStr,
    sev: PyStr,
    cwe: PyStr,
    fix: PyStr,
    mode: ArgMode,
    template: bool,
}

/// TAINT_SINKS[lang], read once, with each row's argument mode and whether it is the Template row.
fn base_sinks<'p>(p: &'p Pack, lang: &str) -> &'p [BaseSink] {
    let all: &Vec<(PyStr, Vec<BaseSink>)> = p.derived("TAINT_SINKS", |v| {
        v.get("map")
            .and_then(|m| m.as_obj())
            .unwrap_or(&[])
            .iter()
            .map(|(lang, rows)| {
                let py = pystr::eq(lang, "py");
                let rows = rows.get("list").and_then(|l| l.as_arr()).unwrap_or(&[]).iter().map(|row| {
                    let f = row.get("list").and_then(|l| l.as_arr()).expect("a sink row");
                    let text = |k: usize| f[k].get("value").and_then(|x| x.as_str()).unwrap_or(&[]).to_vec();
                    let src = f[1].get("re").and_then(|x| x.as_str()).unwrap_or(&[]).to_vec();
                    let flags = f[1].get("flags").and_then(|x| x.as_string()).unwrap_or_default();
                    let suffix = text(0);
                    let s = pystr::to_string(&suffix);
                    let has = |needle: &str| pystr::contains(&src, needle);
                    let mode = if py {
                        if has("send_from_directory") {
                            ArgMode::First
                        } else if ["SQL", "XSS", "REDIR", "SSTI", "CODE"].contains(&s.as_str()) && !has("extra") {
                            ArgMode::First
                        } else if ["CMD", "PATH", "SSRF"].contains(&s.as_str()) {
                            ArgMode::Positional
                        } else {
                            ArgMode::Extent
                        }
                    } else if ["SQL", "SSTI"].contains(&s.as_str()) || (s == "PATH" && has("writeFile")) || (s == "XSS" && has("send")) {
                        ArgMode::First
                    } else {
                        ArgMode::Extent
                    };
                    BaseSink {
                        template: py && pystr::eq(&src, r"(?<![\w.])Template\s*\("),
                        re: Regex::new(&src, pyre::flags_from_letters(&flags)).expect("a sink pattern"),
                        suffix,
                        cat: text(2),
                        sev: text(3),
                        cwe: text(4),
                        fix: text(5),
                        mode,
                    }
                }).collect();
                (lang.clone(), rows)
            })
            .collect::<Vec<_>>()
    });
    all.iter().find(|(l, _)| pystr::eq(l, lang)).map(|(_, r)| r.as_slice()).unwrap_or(&[])
}

/// A list of patterns under a language key (`{"map": {"py": {"list": […]}, …}}`), read once.
fn lang_res<'p>(p: &'p Pack, name: &'static str, lang: &str) -> &'p [Regex] {
    let all: &Vec<(PyStr, Vec<Regex>)> = p.derived(name, |v| {
        v.get("map").and_then(|m| m.as_obj()).unwrap_or(&[]).iter().map(|(k, l)| {
            let res = l.get("list").and_then(|x| x.as_arr()).unwrap_or(&[]).iter().map(|e| {
                let src = e.get("re").and_then(|x| x.as_str()).unwrap_or(&[]);
                let flags = e.get("flags").and_then(|x| x.as_string()).unwrap_or_default();
                Regex::new(src, pyre::flags_from_letters(&flags)).expect("a guard pattern")
            }).collect();
            (k.clone(), res)
        }).collect::<Vec<_>>()
    });
    all.iter().find(|(l, _)| pystr::eq(l, lang)).map(|(_, r)| r.as_slice()).unwrap_or(&[])
}

// ---------------------------------------------------------------- what taint reads of a text

/// core._js_tagged: does the backtick at `start` open a tagged template (sql`…`)?
fn js_tagged(p: &Pack, text: &[u32], start: usize) -> bool {
    let word = |c: u32| p.strs("_ASCII_WORD").iter().any(|w| w.len() == 1 && w[0] == c);
    let mut j = start;
    while j > 0 && (text[j - 1] == ' ' as u32 || text[j - 1] == '\t' as u32) {
        j -= 1;
    }
    if j == 0 || !(word(text[j - 1]) || text[j - 1] == ')' as u32 || text[j - 1] == ']' as u32) {
        return false;
    }
    let mut k = j;
    while k > 0 && word(text[k - 1]) {
        k -= 1;
    }
    !p.strs("_JS_TAG_KEYWORDS").iter().any(|kw| kw.as_slice() == &text[k..j])
}

fn spaces(n: usize) -> PyStr {
    vec![' ' as u32; n]
}

/// core._drop_indexes: a subscript's index blanked (`users[req.params.id]` reads `users`), and the index arguments
/// of slice() and the like, innermost first, at most _SUBSCRIPT_PASSES levels.
fn drop_indexes(p: &Pack, text: PyStr) -> PyStr {
    let mut text = text;
    if text.contains(&('.' as u32)) {
        text = p.re("_INDEX_ARGS_RE").sub_fn(&text, 0, |m| {
            let mut out = m.group(1).unwrap_or(&[]).to_vec();
            out.extend(spaces(m.group(2).map_or(0, |g| g.len())));
            out.push(')' as u32);
            out
        });
    }
    let not_sub = p.strs("_NOT_SUBSCRIPTED");
    for _ in 0..p.usize("_SUBSCRIPT_PASSES") {
        if !text.contains(&('[' as u32)) {
            break;
        }
        let new = p.re("_SUBSCRIPT_RE").sub_fn(&text, 0, |m| {
            let g1 = m.group(1).unwrap_or(&[]);
            if not_sub.iter().any(|w| w.as_slice() == g1) {
                return m.group0().to_vec();
            }
            let g2 = m.group(2).unwrap_or(&[]);
            let mut out = g1.to_vec();
            out.extend_from_slice(g2);
            out.extend(spaces(m.group0().len() - g1.len() - g2.len()));
            out
        });
        if new == text {
            break;
        }
        text = new;
    }
    text
}

/// core._taint_code: `text` without its string literals and subscripts' indexes, but the fields of a Python
/// f-string and of a JavaScript template literal no tag reads (their values become part of the string).
fn taint_code(p: &Pack, text: &[u32], lang: Lang) -> PyStr {
    if lang == Lang::Py {
        let field = p.map_re("_FIELD_RE", "py");
        let out = p.re("_PY_LIT_RE").sub_fn(text, 0, |m| {
            let prefix = m.group(1).map(pystr::lower).unwrap_or_default();
            let lit = m.group(2).unwrap_or(&[]);
            let f_string = ["f", "rf", "fr"].iter().any(|f| pystr::eq(&prefix, f));
            if !f_string || lit.first() == Some(&('`' as u32)) {
                return Vec::new();
            }
            let body = pystr::replace(&pystr::replace(&lit[1..lit.len() - 1], &pystr::u("{{"), &pystr::u("  ")),
                                      &pystr::u("}}"), &pystr::u("  "));
            fields(field, &body)
        });
        return drop_indexes(p, out);
    }
    let field = p.map_re("_FIELD_RE", "js");
    let out = p.re("STRING_LIT_RE").sub_fn(text, 0, |m| {
        let lit = m.group0();
        if lit[0] != '`' as u32 || js_tagged(p, text, m.start()) {
            return Vec::new();
        }
        fields(field, &lit[1..lit.len() - 1])
    });
    drop_indexes(p, out)
}

/// " " + the fields' text joined by spaces + " " (`" " + " ".join(_FIELD_RE.findall(body)) + " "`).
fn fields(field: &Regex, body: &[u32]) -> PyStr {
    let mut out = vec![' ' as u32];
    for (k, m) in field.finditer(body).enumerate() {
        if k > 0 {
            out.push(' ' as u32);
        }
        out.extend_from_slice(m.group(1).unwrap_or(&[]));
    }
    out.push(' ' as u32);
    out
}

/// core._bracket_depth: the brackets `code` opens and leaves open (string literals not counted).
fn bracket_depth(p: &Pack, code: &[u32]) -> i64 {
    let bare = p.re("STRING_LIT_RE").sub(code, &[], 0);
    delta(&bare)
}

fn delta(text: &[u32]) -> i64 {
    text.iter().map(|&c| match char::from_u32(c) {
        Some('(' | '[' | '{') => 1,
        Some(')' | ']' | '}') => -1,
        _ => 0,
    }).sum()
}

fn is_quote(c: u32) -> bool {
    c == '"' as u32 || c == '\'' as u32 || c == '`' as u32
}

/// core._arg_end: where the argument starting at `start` ends (its comma or closing bracket; the text's end).
fn arg_end(text: &[u32], start: usize) -> usize {
    let (mut depth, mut i, n) = (0i64, start, text.len());
    while i < n {
        let ch = text[i];
        if is_quote(ch) {
            match pystr::find_char(text, ch, i + 1) {
                None => return n,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        match char::from_u32(ch) {
            Some('(' | '[' | '{') => depth += 1,
            Some(')' | ']' | '}') => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            Some(',') if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    n
}

/// core._call_close: the bracket that closes a call whose arguments start at `start`.
fn call_close(text: &[u32], start: usize) -> usize {
    let mut start = start;
    loop {
        let end = arg_end(text, start);
        if end >= text.len() || text[end] != ',' as u32 {
            return end;
        }
        start = end + 1;
    }
}

/// core._first_arg: a call's first argument (a parenthesized tuple read as its first element).
fn first_arg(text: &[u32]) -> &[u32] {
    let arg = &text[..arg_end(text, 0)];
    let s = pystr::lstrip(arg);
    if s.first() == Some(&('(' as u32)) {
        let k = arg_end(s, 1);
        if k < s.len() && s[k] == ',' as u32 {
            return &s[1..k];
        }
    }
    arg
}

/// The arguments of a call (`text` after its opening parenthesis) that `keep` keeps, joined by commas.
fn args_where(text: &[u32], keep: impl Fn(&[u32]) -> bool) -> PyStr {
    let (mut out, mut i, n) = (Vec::<&[u32]>::new(), 0usize, text.len());
    loop {
        let end = arg_end(text, i);
        let arg = &text[i..end];
        if keep(arg) {
            out.push(arg);
        }
        if end >= n || text[end] != ',' as u32 {
            return pystr::join(&[',' as u32], &out);
        }
        i = end + 1;
    }
}

/// core._extent: what follows a sink's match, up to the end of its arguments (the closing bracket, or a `;`
/// outside brackets for an assignment sink).
fn extent(text: &[u32]) -> &[u32] {
    let (mut depth, mut i, n) = (0i64, 0usize, text.len());
    while i < n {
        let ch = text[i];
        if is_quote(ch) {
            match pystr::find_char(text, ch, i + 1) {
                None => return text,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        match char::from_u32(ch) {
            Some('(' | '[' | '{') => depth += 1,
            Some(')' | ']' | '}') => {
                if depth == 0 {
                    return &text[..i];
                }
                depth -= 1;
            }
            Some(';') if depth == 0 => return &text[..i],
            _ => {}
        }
        i += 1;
    }
    text
}

/// core._sink_args: the part of a sink's arguments that carries the injection.
fn sink_args(p: &Pack, text: &[u32], mode: ArgMode, suffix: &[u32]) -> PyStr {
    let args = match mode {
        ArgMode::First => first_arg(text).to_vec(),
        ArgMode::Positional => {
            let kw = p.re("_KWARG_RE");
            args_where(text, |a| kw.match_(a).is_none())
        }
        ArgMode::Extent => extent(text).to_vec(),
    };
    if pystr::eq(suffix, "REDIR") {
        let same = p.re("_SAME_SITE_RE");
        return args_where(&args, |a| same.match_(a).is_none());
    }
    args
}

// ---------------------------------------------------------------- assignments

fn is_keyword(p: &Pack, name: &[u32]) -> bool {
    p.strs("_PY_KEYWORDS").iter().any(|k| k.as_slice() == name)
}

/// core._destructured_names: the names a one-level JS destructuring pattern binds.
fn destructured_names(p: &Pack, pattern: &[u32]) -> Vec<PyStr> {
    let mut names = Vec::new();
    if pattern.len() < 2 {
        return names;
    }
    let binding = p.re("_JS_BINDING_RE");
    for part in pystr::split_char(&pattern[1..pattern.len() - 1], ',' as u32) {
        let mut part = pystr::strip(part);
        if pystr::starts_with(part, "...") {
            part = pystr::strip(&part[3..]);
        } else if pattern[0] == '{' as u32 && part.contains(&(':' as u32)) {
            let k = part.iter().position(|&c| c == ':' as u32).expect("found");
            part = pystr::strip(&part[k + 1..]);
        }
        let part = match part.iter().position(|&c| c == '=' as u32) {
            Some(k) => pystr::strip(&part[..k]),
            None => pystr::strip(part),
        };
        if binding.fullmatch(part).is_some() {
            names.push(part.to_vec());
        }
    }
    names
}

/// core._assignment: (the names an assignment line binds, its right-hand side).
fn assignment(p: &Pack, line: &[u32], lang: Lang) -> Option<(Vec<PyStr>, PyStr)> {
    let key = if lang == Lang::Py { "py" } else { "js" };
    if let Some(m) = p.map_re("ASSIGN_RE", key).match_(line) {
        let name = m.group(1).unwrap_or(&[]);
        if lang == Lang::Py
            && (is_keyword(p, name)
                || (p.strs("_PY_SOFT_KEYWORDS").iter().any(|k| k.as_slice() == name)
                    && pystr::starts_with(pystr::lstrip(&line[m.end_of(1) as usize..]), ":")))
        {
            return None;
        }
        return Some((vec![name.to_vec()], m.group(2).unwrap_or(&[]).to_vec()));
    }
    if lang == Lang::Js {
        if let Some(dm) = p.re("_JS_DESTRUCT_RE").match_(line) {
            let names = destructured_names(p, dm.group(1).unwrap_or(&[]));
            if !names.is_empty() {
                return Some((names, dm.group(2).unwrap_or(&[]).to_vec()));
            }
        }
    }
    None
}

/// core._container_write: (the container a line puts a value into, the value).
fn container_write(p: &Pack, line: &[u32], lang: Lang) -> Option<(PyStr, PyStr)> {
    let key = if lang == Lang::Py { "py" } else { "js" };
    let m = p.map_re("_CONTAINER_WRITE_RE", key).match_(line)?;
    let name = m.group(1).unwrap_or(&[]);
    if lang == Lang::Py && is_keyword(p, name) {
        return None;
    }
    let between = &line[m.end_of(1) as usize..m.start_of(2) as usize];
    let added = pystr::rstrip(between).last() == Some(&('(' as u32));
    let value = m.group(2).unwrap_or(&[]);
    Some((name.to_vec(), if added { extent(value).to_vec() } else { value.to_vec() }))
}

/// Containers' elements under literal keys: {container: [(key, clean set or None: no untrusted data)]}.
type Keyed = HashMap<PyStr, Vec<(PyStr, Option<Clean>)>>;

/// core._keyed_reads: `text` with its reads of container elements known to hold no untrusted data blanked.
fn keyed_reads(p: &Pack, text: &[u32], keyed: &Keyed) -> PyStr {
    if keyed.is_empty() || !text.contains(&('[' as u32)) {
        return text.to_vec();
    }
    p.re("_KEYED_READ_RE").sub_fn(text, 0, |m| {
        let keys = keyed.get(m.group(1).unwrap_or(&[]));
        let key = m.group(3).unwrap_or(&[]);
        match keys.and_then(|ks| ks.iter().find(|(k, _)| k.as_slice() == key)) {
            Some((_, None)) => spaces(m.group0().len()),
            _ => m.group0().to_vec(),
        }
    })
}

// ---------------------------------------------------------------- guards

fn lang_key(lang: Lang) -> &'static str {
    if lang == Lang::Py {
        "py"
    } else {
        "js"
    }
}

/// core._allow_guard: (name, collection text, negated) of an allowlist guard.
fn allow_guard(p: &Pack, stmt: &[u32], lang: Lang) -> Option<(PyStr, PyStr, bool)> {
    let m = p.map_re("_ALLOW_GUARD_RE", lang_key(lang)).match_(stmt)?;
    let g = |k: usize| m.group(k).map(|x| x.to_vec());
    if lang == Lang::Py {
        Some((g(1).unwrap_or_default(), g(3).unwrap_or_default(), m.group(2).is_some_and(|x| !x.is_empty())))
    } else {
        Some((g(3).unwrap_or_default(), g(2).unwrap_or_default(), m.group(1).is_some_and(|x| !x.is_empty())))
    }
}

/// core._guarded_names: the names a path-traversal guard in `stmt` checks.
fn guarded_names(p: &Pack, stmt: &[u32], lang: Lang) -> Vec<PyStr> {
    let mut names: Vec<PyStr> = Vec::new();
    for r in lang_res(p, "_GUARD_VAR_RES", lang_key(lang)) {
        for m in r.finditer(stmt) {
            names.push(m.group(1).unwrap_or(&[]).to_vec());
        }
    }
    if lang == Lang::Py && pystr::contains(stmt, "commonpath") {
        let name_re = p.re("_GUARD_NAME_RE");
        for m in p.re("_GUARD_COMMONPATH_RE").finditer(stmt) {
            for part in pystr::split_char(m.group(1).unwrap_or(&[]), ',' as u32) {
                if let Some(n) = name_re.match_(part) {
                    names.push(n.group(1).unwrap_or(&[]).to_vec());
                }
            }
        }
    }
    names
}

fn indent_of(line: &[u32]) -> usize {
    line.len() - pystr::lstrip(line).len()
}

/// core._guard_exits: does the `if` on line i leave (an exit on its line, or starting a line of its block)?
fn guard_exits(p: &Pack, ctx: &FileCtx, i: usize, stmt: &[u32], lang: Lang) -> bool {
    let exit_re = p.map_re("_GUARD_EXIT_RE", lang_key(lang));
    if exit_re.search(stmt).is_some() {
        return true;
    }
    let indent = indent_of(ctx.mcode(i));
    let (mut seen, mut j) = (0usize, i + 1);
    let block = p.usize("_GUARD_BLOCK_LINES");
    while j < ctx.len() && seen < block {
        if !ctx.cmask[j] {
            let code = ctx.mcode(j);
            let body = pystr::lstrip(code);
            if !body.is_empty() {
                if code.len() - body.len() <= indent {
                    return false;
                }
                if exit_re.match_(body).is_some() {
                    return true;
                }
                seen += 1;
            }
        }
        j += 1;
    }
    false
}

// ---------------------------------------------------------------- views and routes

/// Each line's match text without comments, "" for a comment line (core's `code` lists).
fn code_lines(ctx: &FileCtx) -> Vec<PyStr> {
    (0..ctx.len()).map(|i| if ctx.cmask[i] { Vec::new() } else { ctx.mcode(i).to_vec() }).collect()
}

/// core._view_returns: the `return` lines of the file's Flask views and HTML FastAPI path operations.
fn view_returns(p: &Pack, ctx: &FileCtx) -> HashSet<usize> {
    let code = code_lines(ctx);
    let flask = code.iter().any(|c| p.re("_FLASK_IMPORT_RE").match_(c).is_some());
    let fastapi = !flask && code.iter().any(|c| p.re("_FASTAPI_IMPORT_RE").match_(c).is_some());
    let join_max = p.usize("TAINT_JOIN_MAX_LINES");
    let mut out = HashSet::new();
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let (mut pending, mut operation) = (false, false);
    let (mut open_brackets, mut continued) = (0i64, 0usize);
    for (i, c) in code.iter().enumerate() {
        let body = pystr::lstrip(c);
        if body.is_empty() {
            continue;
        }
        if open_brackets > 0 && continued < join_max {
            open_brackets += bracket_depth(p, c);
            continued += 1;
            if operation && p.re("_HTML_RESPONSE_CLASS_RE").search(c).is_some() {
                pending = true;
            }
            continue;
        }
        open_brackets = 0;
        operation = false;
        let indent = c.len() - body.len();
        while stack.last().is_some_and(|&(ind, _)| indent <= ind) {
            stack.pop();
        }
        if body[0] == '@' as u32 {
            let d = p.re("_VIEW_DECORATOR_RE").match_(c);
            if let Some(d) = &d {
                if pystr::eq(d.group(1).unwrap_or(&[]), "route") || flask {
                    pending = true;
                } else if fastapi {
                    operation = true;
                    if p.re("_HTML_RESPONSE_CLASS_RE").search(c).is_some() {
                        pending = true;
                    }
                }
            }
            open_brackets = bracket_depth(p, c);
            continued = 0;
            continue;
        }
        if p.re("_DEF_RE").match_(c).is_some() {
            stack.push((indent, pending && !pystr::starts_with(body, "class")));
            pending = false;
            continue;
        }
        pending = false;
        if stack.last().is_some_and(|&(_, view)| view) && p.re("_RETURN_RE").match_(c).is_some() {
            out.insert(i);
        }
    }
    out
}

/// core._signature_params: [(name, annotation, default)] of a def's parameters (`sig`: its text with the lines that
/// continue it).
fn signature_params(p: &Pack, sig: &[u32]) -> Vec<(PyStr, PyStr, PyStr)> {
    let Some(m) = p.re("_DEF_HEAD_RE").match_(sig) else { return Vec::new() };
    let param_re = p.re("_PARAM_RE");
    let mut out = Vec::new();
    let inner = &sig[m.end()..call_close(sig, m.end())];
    for part in frameworks::top_split(inner, ',' as u32) {
        let Some(pm) = param_re.match_(part) else { continue };
        if pm.end() < part.len() && part[pm.end()] != ':' as u32 && part[pm.end()] != '=' as u32 {
            continue;
        }
        let rest = &part[pm.end()..];
        let (mut ann, mut default): (PyStr, PyStr) = (Vec::new(), Vec::new());
        if rest.first() == Some(&(':' as u32)) {
            let pieces = frameworks::top_split(&rest[1..], '=' as u32);
            ann = pieces[0].to_vec();
            default = pystr::join(&['=' as u32], &pieces[1..]);
        } else if rest.first() == Some(&('=' as u32)) {
            default = rest[1..].to_vec();
        }
        out.push((pm.group(1).unwrap_or(&[]).to_vec(), pystr::strip(&ann).to_vec(), pystr::strip(&default).to_vec()));
    }
    out
}

/// core._route_params: {a route handler's def line: the names of the parameters the framework fills from the
/// request}.
fn route_params(p: &Pack, ctx: &FileCtx) -> HashMap<usize, Vec<PyStr>> {
    let code = code_lines(ctx);
    let flask = code.iter().any(|c| p.re("_FLASK_IMPORT_RE").match_(c).is_some());
    let fastapi = !flask && code.iter().any(|c| p.re("_FASTAPI_IMPORT_RE").match_(c).is_some());
    let django = code.iter().any(|c| p.re("_DJANGO_IMPORT_RE").match_(c).is_some());
    let aliases = if fastapi {
        frameworks::dep_aliases(&pystr::join(&['\n' as u32], &code.iter().map(|c| c.as_slice()).collect::<Vec<_>>()))
    } else {
        Vec::new()
    };
    let join_max = p.usize("TAINT_JOIN_MAX_LINES");
    let joined = |i: usize| -> (PyStr, usize) {
        let mut parts: Vec<&[u32]> = vec![&code[i]];
        let mut depth = bracket_depth(p, &code[i]);
        let mut j = i;
        while depth > 0 && j + 1 < code.len() && j + 1 <= i + join_max {
            j += 1;
            parts.push(&code[j]);
            depth += bracket_depth(p, &code[j]);
        }
        (pystr::join(&[' ' as u32], &parts), j)
    };
    let mut out = HashMap::new();
    let mut routes: Vec<(bool, PyStr)> = Vec::new(); // (fastapi, the Flask rule)
    let mut i = 0;
    while i < code.len() {
        let c = &code[i];
        let body = pystr::lstrip(c);
        if body.is_empty() {
            i += 1;
            continue;
        }
        if body[0] == '@' as u32 {
            let (text, last) = joined(i);
            if let Some(d) = p.re("_ROUTE_DECORATOR_RE").match_(&text) {
                let method = d.group(1).unwrap_or(&[]);
                if pystr::eq(method, "route") || (flask && frameworks::is_in(method, frameworks::FLASK_ROUTE_METHODS)) {
                    let rule = p.re("_ROUTE_RULE_RE").search_at(&text, d.end() as isize - 1, text.len() as isize)
                        .map(|r| r.group(2).unwrap_or(&[]).to_vec()).unwrap_or_default();
                    routes.push((false, rule));
                } else if fastapi {
                    routes.push((true, Vec::new()));
                }
            }
            i = last + 1;
            continue;
        }
        if p.re("_DEF_HEAD_RE").match_(c).is_some() {
            let (text, last) = joined(i);
            let params = signature_params(p, &text);
            let mut names: Vec<PyStr> = Vec::new();
            for (is_fastapi, rule) in &routes {
                if *is_fastapi {
                    names.extend(params.iter().filter(|(n, a, d)| frameworks::fastapi_param(n, a, d, &aliases)).map(|(n, _, _)| n.clone()));
                } else {
                    let free = frameworks::flask_free_vars(rule);
                    names.extend(params.iter().filter(|(n, _, _)| free.contains(n)).map(|(n, _, _)| n.clone()));
                }
            }
            if routes.is_empty() && django {
                let ns: Vec<&PyStr> = params.iter().map(|(n, _, _)| n).collect();
                let first = if ns.len() >= 2 && pystr::eq(ns[0], "self") && pystr::eq(ns[1], "request") {
                    2
                } else if !ns.is_empty() && pystr::eq(ns[0], "request") {
                    1
                } else {
                    0
                };
                if first > 0 {
                    names = params[first..].iter().filter(|(n, a, _)| frameworks::django_param(n, a)).map(|(n, _, _)| n.clone()).collect();
                }
            }
            if !names.is_empty() {
                let mut unique: Vec<PyStr> = Vec::new();
                for n in names {
                    if !unique.contains(&n) {
                        unique.push(n);
                    }
                }
                out.insert(i, unique);
            }
            routes.clear();
            i = last + 1;
            continue;
        }
        routes.clear();
        i += 1;
    }
    out
}

/// core._view_body: false when a view's return value is a call of a function that is not a string builder.
fn view_body(p: &Pack, value: &[u32]) -> bool {
    let Some(m) = p.re("_VIEW_CALL_RE").match_(value) else { return true };
    let name = m.group(1).unwrap_or(&[]);
    let last = match name.iter().rposition(|&c| c == '.' as u32) {
        Some(k) => &name[k + 1..],
        None => name,
    };
    if p.strs("_STRING_BUILDERS").iter().any(|b| b.as_slice() == last) {
        return true;
    }
    let end = call_close(value, m.end());
    end >= value.len() || !pystr::strip(&value[end + 1..]).is_empty()
}

/// core._scope_opener: does line `code` open a function's body?
fn scope_opener(p: &Pack, code: &[u32], lang: Lang) -> bool {
    if lang == Lang::Py {
        return p.re("_DEF_RE").match_(code).is_some();
    }
    let t = pystr::rstrip(code);
    if t.last() != Some(&('{' as u32)) {
        return false;
    }
    let head = pystr::rstrip(&t[..t.len() - 1]);
    if pystr::ends_with(head, "=>") {
        return true;
    }
    if head.last() != Some(&(')' as u32)) {
        return false;
    }
    p.re("_JS_FUNCTION_WORD_RE").search(head).is_some() || p.re("_JS_METHOD_HEAD_RE").match_(head).is_some()
}

/// core._literal_continuations: the lines whose first non-blank character is inside a literal begun earlier.
fn literal_continuations(ctx: &FileCtx) -> HashSet<usize> {
    let mut out = HashSet::new();
    let Some(lits) = ctx.literals() else { return out };
    if lits.is_empty() {
        return out;
    }
    let (mut k, mut reach) = (0usize, -1i64);
    for j in 0..ctx.len() {
        let line = ctx.line(j);
        let at = ctx.starts[j] + indent_of(line);
        while k < lits.len() && lits[k].0 < at {
            reach = reach.max(lits[k].1 as i64);
            k += 1;
        }
        if (at as i64) < reach {
            out.insert(j);
        }
    }
    out
}

// ---------------------------------------------------------------- the pass

/// The sink categories a value is clean for (a sorted set of suffixes).
type Clean = Vec<PyStr>;

fn clean_union(a: &Clean, b: &[PyStr]) -> Clean {
    let mut out = a.clone();
    for s in b {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    out.sort();
    out
}

fn clean_inter(a: &Clean, b: &Clean) -> Clean {
    a.iter().filter(|s| b.contains(s)).cloned().collect()
}

/// A tainted name: the line it was tainted at, the categories it is clean for, its taint order, the scope it lives
/// in, and the blocks ((indent, block id), …) it was tainted in.
struct Taint {
    line: usize,
    clean: Clean,
    order: usize,
    scope: Option<usize>,
    chain: Vec<(usize, usize)>,
}

/// One sink row as the pass reads it (the pack's, then the configuration's).
struct Sink<'a> {
    suffix: PyStr,
    re: &'a Regex,
    guarded: bool,
    cat: PyStr,
    sev: PyStr,
    cwe: PyStr,
    fix: PyStr,
    mode: ArgMode,
}

/// core.taint_scan's findings for the file, added to `found`.
pub fn scan(ctx: &FileCtx, model: &Model, found: &mut Vec<Finding>) {
    let lang = ctx.lang;
    if lang != Lang::Py && lang != Lang::Js {
        return; // SQL and the rest: pattern rules only
    }
    let p = ctx.p;
    let key = lang_key(lang);
    let max_match = p.usize("_TAINT_MAX_MATCH_TEXT");
    let clip = |t: &[u32]| -> usize { t.len().min(max_match) };
    let joined = if model.is_empty() { Arc::new(Joined::default()) } else { model.joined(p, key) };
    // the model: sources, sinks, sanitizers
    let base_src = p.map_re("TAINT_SOURCES", key);
    let src_search = |t: &[u32]| -> bool {
        base_src.search(t).is_some() || model.sources.iter().any(|r| r.search(&t[..clip(t)]).is_some())
    };
    let template_ok = lang != Lang::Py || p.re("_TEMPLATE_IMPORT_RE").search(&ctx.content).is_some();
    let mut sinks: Vec<Sink> = base_sinks(p, key)
        .iter()
        .filter(|s| template_ok || !s.template)
        .map(|s| Sink { suffix: s.suffix.clone(), re: &s.re, guarded: false, cat: s.cat.clone(), sev: s.sev.clone(),
                        cwe: s.cwe.clone(), fix: s.fix.clone(), mode: s.mode })
        .collect();
    for (re, cat) in &model.sinks {
        let meta = p.raw("_CAT_META").and_then(|v| v.get("map")).and_then(|m| m.get(&pystr::to_string(cat)))
            .and_then(|l| l.get("list")).and_then(|l| l.as_arr()).unwrap_or(&[]);
        let text = |k: usize| meta.get(k).and_then(|v| v.get("value")).and_then(|v| v.as_str()).unwrap_or(&[]).to_vec();
        sinks.push(Sink { suffix: suffix_of(p, cat), re, guarded: true, cat: cat.clone(), sev: text(0), cwe: text(1),
                          fix: text(2), mode: ArgMode::Extent });
    }
    let mut suffixes: Vec<PyStr> = Vec::new();
    for s in &sinks {
        if !suffixes.contains(&s.suffix) {
            suffixes.push(s.suffix.clone());
        }
    }
    let mut all_clean = suffixes.clone();
    all_clean.sort();
    let full_san: &Regex = joined.full.as_ref().unwrap_or_else(|| p.map_re("_FULL_SAN", key));
    let neutralize = |text: &[u32], suffix: Option<&[u32]>| -> PyStr {
        let mut text = full_san.sub(text, &[' ' as u32], 0);
        if lang == Lang::Py && pystr::contains(&text, "type") {
            let typed_arg = p.re("_TYPED_ARG_RE");
            text = p.re("_TYPED_GET_RE").sub_fn(&text, 0, |m| {
                if typed_arg.search(m.group(1).unwrap_or(&[])).is_some() {
                    vec![' ' as u32]
                } else {
                    m.group0().to_vec()
                }
            });
        }
        if let Some(suf) = suffix {
            if let Some(r) = partial_for(&joined, p, key, suf) {
                text = r.sub(&text, &[' ' as u32], 0);
            }
        }
        text
    };
    let ident_re = p.map_re("_IDENT_RUN_RE", key);
    let has_at = ctx.content.contains(&('@' as u32));
    let views = if lang == Lang::Py && has_at { view_returns(p, ctx) } else { HashSet::new() };
    let routes = if lang == Lang::Py && pystr::contains(&ctx.content, "def") { route_params(p, ctx) } else { HashMap::new() };
    let xss_sink = sinks.iter().position(|s| pystr::eq(&s.suffix, "XSS"));
    let guard_if = p.map_re("_GUARD_IF_RE", key);
    let inside = literal_continuations(ctx);
    let join_max = p.usize("TAINT_JOIN_MAX_LINES");
    let join_chars = p.usize("TAINT_JOIN_MAX_CHARS");
    let same_site = p.re("_SAME_SITE_RE");

    let mut tainted: HashMap<PyStr, Taint> = HashMap::new();
    let mut levels: Vec<(usize, usize, Option<usize>)> = Vec::new(); // (indent, block id, scope id)
    let (mut next_block, mut next_scope, mut next_order) = (0usize, 0usize, 0usize);
    let mut in_scope: HashMap<usize, Vec<PyStr>> = HashMap::new();
    let mut opener: Option<(usize, usize)> = None; // (indent, scope id) of a function whose body is not yet seen
    let mut pending: Option<(usize, Vec<PyStr>, usize)> = None; // (scope id, names, def line) of a route handler
    let (mut open_depth, mut continued) = (0i64, 0usize);
    let mut keyed: Keyed = HashMap::new();
    let mut allowed: Vec<(usize, PyStr, usize, Clean)> = Vec::new(); // (indent, name, taint order, clean before)

    // the tainted names in `text` still dangerous for `suf` (None: any), in their taint order
    let carriers_in = |tainted: &HashMap<PyStr, Taint>, text: &[u32], suf: Option<&[u32]>| -> Vec<PyStr> {
        if tainted.is_empty() {
            return Vec::new();
        }
        let mut seen: HashSet<&[u32]> = HashSet::new();
        let mut out: Vec<PyStr> = Vec::new();
        for m in ident_re.finditer(text) {
            let v = m.group0();
            if !seen.insert(v) {
                continue;
            }
            if let Some(t) = tainted.get(v) {
                if suf.is_none_or(|s| !t.clean.iter().any(|c| c.as_slice() == s)) {
                    out.push(v.to_vec());
                }
            }
        }
        out.sort_by_key(|v| tainted[v].order);
        out
    };
    // line i's code joined with the lines that continue its open brackets
    let statement = |i: usize, line: &[u32]| -> PyStr {
        let mut depth = bracket_depth(p, line);
        if depth <= 0 {
            return line.to_vec();
        }
        let mut parts: Vec<PyStr> = vec![line.to_vec()];
        let (mut total, mut j) = (0usize, i + 1);
        while depth > 0 && j < ctx.len() && j <= i + join_max && total < join_chars {
            if !ctx.cmask[j] {
                let next = ctx.mcode(j);
                let next = &next[..next.len().min(join_chars - total)];
                parts.push(next.to_vec());
                total += next.len();
                depth += bracket_depth(p, next);
            }
            j += 1;
        }
        pystr::join(&[' ' as u32], &parts.iter().map(|x| x.as_slice()).collect::<Vec<_>>())
    };
    // the categories value `rhs` is clean for, or None when it carries no untrusted data
    let value_clean = |tainted: &HashMap<PyStr, Taint>, keyed: &Keyed, rhs: &[u32]| -> Option<Clean> {
        let rhs = keyed_reads(p, rhs, keyed);
        let base = taint_code(p, &neutralize(&rhs, None), lang);
        if !(src_search(&base) || !carriers_in(tainted, &base, None).is_empty()) {
            return None;
        }
        let mut clean: Clean = Vec::new();
        for suf in &suffixes {
            let neut = if partial_for(&joined, p, key, suf).is_some() { taint_code(p, &neutralize(&rhs, Some(suf)), lang) } else { base.clone() };
            if !src_search(&neut) && carriers_in(tainted, &neut, Some(suf)).is_empty() && !clean.contains(suf) {
                clean.push(suf.clone());
            }
        }
        if let Some(x) = xss_sink {
            if sink_search(&sinks[x], &rhs, max_match).is_some() && !clean.iter().any(|c| pystr::eq(c, "XSS")) {
                clean.push(pystr::u("XSS"));
            }
        }
        if same_site.match_(&rhs).is_some() && !clean.iter().any(|c| pystr::eq(c, "REDIR")) {
            clean.push(pystr::u("REDIR"));
        }
        clean.sort();
        Some(clean)
    };
    let rule_texts = RuleText::of(p, "_TAINT_RULE");
    let what_via = p.text("_TAINT_WHAT_VIA");
    let what_plain = p.text("_TAINT_WHAT");
    // a T-* finding when `text` (a sink's arguments, a view's return value) carries untrusted data for the sink
    let report = |tainted: &HashMap<PyStr, Taint>, keyed: &Keyed, found: &mut Vec<Finding>, sink: &Sink, text: &[u32], i: usize, col: usize| {
        let rest = taint_code(p, &neutralize(&keyed_reads(p, text, keyed), Some(&sink.suffix)), lang);
        let carriers = carriers_in(tainted, &rest, Some(&sink.suffix));
        if carriers.is_empty() && !src_search(&rest) {
            return;
        }
        let what = match carriers.first() {
            Some(c) => findings::format(&what_via, &[("carrier", Arg::S(c.clone())), ("line", Arg::I(tainted[c].line as i64))]),
            None => what_plain.clone(),
        };
        let mut id = pystr::u("T-");
        id.extend_from_slice(&sink.suffix);
        let rule = RuleText {
            id,
            name: findings::format(&rule_texts.name, &[("cat", Arg::S(sink.cat.clone()))]),
            typ: rule_texts.typ.clone(),
            sev: sink.sev.clone(),
            msg: findings::format(&rule_texts.msg, &[("cat", Arg::S(sink.cat.clone())), ("what", Arg::S(what))]),
            why: rule_texts.why.clone(),
            fix: sink.fix.clone(),
            ref_: findings::format(&rule_texts.ref_, &[("cwe", Arg::S(sink.cwe.clone()))]),
        };
        found.push(Finding::new(rule, i + 1, Some(col)));
    };
    let current_scope = |levels: &[(usize, usize, Option<usize>)]| levels.iter().rev().find_map(|l| l.2);
    let chain_of = |levels: &[(usize, usize, Option<usize>)]| levels.iter().map(|l| (l.0, l.1)).collect::<Vec<_>>();
    let aug_re = p.map_re("_AUG_ASSIGN_RE", key);

    for i in 0..ctx.len() {
        if ctx.cmask[i] {
            continue;
        }
        let line = ctx.mcode(i);
        if line.is_empty() || line.iter().all(|&c| pystr::is_space(c)) {
            continue;
        }
        // ---- the structure
        let mut structural = false;
        if !inside.contains(&i) {
            let depth = if lang == Lang::Py { delta(&ctx.names_code(i)) } else { 0 };
            if open_depth > 0 && continued < join_max {
                open_depth = (open_depth + depth).max(0);
                continued += 1;
            } else {
                structural = true;
                open_depth = depth.max(0);
                continued = 0;
                let indent = indent_of(ctx.line(i));
                while allowed.last().is_some_and(|a| indent <= a.0) {
                    let (_, n, order, before) = allowed.pop().expect("there");
                    if let Some(t) = tainted.get_mut(&n) {
                        if t.order == order {
                            t.clean = before;
                        }
                    }
                }
                while levels.last().is_some_and(|l| l.0 > indent) {
                    if let Some(gone) = levels.pop().expect("there").2 {
                        for n in in_scope.remove(&gone).unwrap_or_default() {
                            if tainted.get(&n).is_some_and(|t| t.scope == Some(gone)) {
                                tainted.remove(&n);
                            }
                        }
                    }
                }
                if levels.last().is_none_or(|l| l.0 < indent) {
                    let scope = match opener {
                        Some((ind, s)) if indent > ind => Some(s),
                        _ => None,
                    };
                    levels.push((indent, next_block, scope));
                    next_block += 1;
                    if let Some((pscope, names, def_line)) = &pending {
                        if scope == Some(*pscope) {
                            let chain = chain_of(&levels);
                            for name in names.clone() {
                                keyed.remove(&name);
                                tainted.insert(name.clone(), Taint { line: def_line + 1, clean: Vec::new(), order: next_order,
                                                                     scope, chain: chain.clone() });
                                next_order += 1;
                                in_scope.entry(*pscope).or_default().push(name);
                            }
                            pending = None;
                        }
                    }
                }
                opener = None;
                if scope_opener(p, line, lang) {
                    opener = Some((indent, next_scope));
                    pending = routes.get(&i).map(|names| (next_scope, names.clone(), i));
                    next_scope += 1;
                }
            }
        }
        // ---- what the line does
        let mut stmt: Option<PyStr> = None;
        let assigned = assignment(p, line, lang);
        let container = if assigned.is_none() { container_write(p, line, lang) } else { None };
        if let Some((mut names, mut rhs)) = assigned {
            let s = statement(i, line);
            if let Some((jn, jr)) = assignment(p, &s, lang) {
                names = jn;
                rhs = jr;
            }
            let clean = value_clean(&tainted, &keyed, &rhs);
            let chain = chain_of(&levels);
            let scope = current_scope(&levels);
            let augmented = aug_re.match_(&s).is_some();
            stmt = Some(s);
            for name in names {
                if !augmented {
                    keyed.remove(&name);
                }
                let replaces = match tainted.get(&name) {
                    Some(old) => structural && !augmented && {
                        let last = levels.last().expect("structural lines have a level");
                        old.chain.contains(&(last.0, last.1))
                    },
                    None => false,
                };
                if !tainted.contains_key(&name) || replaces {
                    match &clean {
                        None => {
                            tainted.remove(&name);
                        }
                        Some(c) => {
                            tainted.insert(name.clone(), Taint { line: i + 1, clean: c.clone(), order: next_order, scope,
                                                                 chain: chain.clone() });
                            next_order += 1;
                            if let Some(s) = scope {
                                in_scope.entry(s).or_default().push(name);
                            }
                        }
                    }
                } else if let Some(c) = &clean {
                    let old = tainted.get_mut(&name).expect("there");
                    old.clean = clean_inter(&old.clean, c);
                }
            }
        } else if let Some((name, mut written)) = container {
            let s = statement(i, line);
            if let Some((jn, jw)) = container_write(p, &s, lang) {
                if jn == name {
                    written = jw;
                }
            }
            let clean = value_clean(&tainted, &keyed, &written);
            if let Some(km) = p.re("_KEYED_WRITE_RE").match_(&s) {
                if km.group(1).unwrap_or(&[]) == name.as_slice() {
                    let key = km.group(3).unwrap_or(&[]).to_vec();
                    let entry = keyed.entry(name.clone()).or_default();
                    match entry.iter_mut().find(|(k, _)| *k == key) {
                        Some(e) => e.1 = clean.clone(),
                        None => entry.push((key, clean.clone())),
                    }
                }
            }
            stmt = Some(s);
            if let Some(c) = &clean {
                if let Some(old) = tainted.get_mut(&name) {
                    old.clean = clean_inter(&old.clean, c);
                } else {
                    let scope = current_scope(&levels);
                    tainted.insert(name.clone(), Taint { line: i + 1, clean: c.clone(), order: next_order, scope,
                                                         chain: chain_of(&levels) });
                    next_order += 1;
                    if let Some(s) = scope {
                        in_scope.entry(s).or_default().push(name);
                    }
                }
            }
        } else if !tainted.is_empty() && guard_if.match_(line).is_some() {
            let s = statement(i, line);
            let guarded: Vec<PyStr> = guarded_names(p, &s, lang).into_iter().filter(|n| tainted.contains_key(n)).collect();
            if !guarded.is_empty() && guard_exits(p, ctx, i, &s, lang) {
                for n in &guarded {
                    let t = tainted.get_mut(n).expect("there");
                    t.clean = clean_union(&t.clean, &[pystr::u("PATH")]);
                }
            }
            if let Some((name, collection, negated)) = allow_guard(p, &s, lang) {
                if tainted.contains_key(&name) {
                    let code = taint_code(p, &collection, lang);
                    if !src_search(&code) && carriers_in(&tainted, &code, None).is_empty() {
                        if negated {
                            if guard_exits(p, ctx, i, &s, lang) {
                                tainted.get_mut(&name).expect("there").clean = all_clean.clone();
                            }
                        } else {
                            let entry = tainted.get_mut(&name).expect("there");
                            allowed.push((indent_of(ctx.line(i)), name.clone(), entry.order, entry.clean.clone()));
                            entry.clean = all_clean.clone();
                        }
                    }
                }
            }
            stmt = Some(s);
        }
        // ---- the sinks on the line
        let mut xss_here = false;
        for k in 0..sinks.len() {
            let sink = &sinks[k];
            let Some(sm) = sink_search(sink, line, max_match) else { continue };
            let (start, end) = (sm.start(), sm.end());
            let s = stmt.get_or_insert_with(|| statement(i, line)).clone();
            let is_xss = pystr::eq(&sink.suffix, "XSS");
            xss_here = xss_here || is_xss;
            if is_xss {
                let plain = if lang == Lang::Py {
                    p.re("_NON_HTML_TYPE_RE").search(extent(&s[end.min(s.len())..])).is_some()
                } else {
                    p.re("_NON_HTML_CHAIN_RE").search(sm.group0()).is_some()
                };
                if plain {
                    continue; // a text/plain or JSON response
                }
            }
            let args = sink_args(p, &s[end.min(s.len())..], sink.mode, &sink.suffix);
            report(&tainted, &keyed, found, sink, &args, i, start);
        }
        if views.contains(&i) && !xss_here {
            if let Some(x) = xss_sink {
                let s = stmt.get_or_insert_with(|| statement(i, line)).clone();
                if let Some(rm) = p.re("_RETURN_RE").match_(&s) {
                    let value = first_arg(&s[rm.end()..]);
                    if !pystr::strip(value).is_empty() && p.re("_VIEW_RETURN_SKIP_RE").match_(value).is_none() && view_body(p, value) {
                        report(&tainted, &keyed, found, &sinks[x], value, i, rm.end() - 6);
                    }
                }
            }
        }
    }
}

/// A sink's first match in `t` (a configured sink's in the text's first `max` characters).
fn sink_search<'s>(s: &'s Sink, t: &'s [u32], max: usize) -> Option<pyre::Match<'s>> {
    if s.guarded {
        s.re.search(&t[..t.len().min(max)])
    } else {
        s.re.search(t)
    }
}

/// The partial sanitizer for `suffix`: the configuration's joined one, else the pack's, else none.
fn partial_for<'a>(joined: &'a Joined, p: &'a Pack, lang: &str, suffix: &[u32]) -> Option<&'a Regex> {
    if let Some((_, r)) = joined.partial.iter().find(|(s, _)| s.as_slice() == suffix) {
        return Some(r);
    }
    partial_text(p, lang, suffix).map(|_| partial_re(p, lang, suffix))
}

/// A partial sanitizer of the pack by suffix (core._PARTIAL_SAN[lang][suffix]).
fn partial_re<'p>(p: &'p Pack, lang: &str, suffix: &[u32]) -> &'p Regex {
    let all: &Vec<(PyStr, Vec<(PyStr, Regex)>)> = p.derived("_PARTIAL_SAN", |v| {
        v.get("map").and_then(|m| m.as_obj()).unwrap_or(&[]).iter().map(|(l, m)| {
            let rows = m.get("map").and_then(|x| x.as_obj()).unwrap_or(&[]).iter().map(|(suf, e)| {
                let src = e.get("re").and_then(|x| x.as_str()).unwrap_or(&[]);
                let flags = e.get("flags").and_then(|x| x.as_string()).unwrap_or_default();
                (suf.clone(), Regex::new(src, pyre::flags_from_letters(&flags)).expect("a sanitizer pattern"))
            }).collect();
            (l.clone(), rows)
        }).collect::<Vec<_>>()
    });
    all.iter().find(|(l, _)| pystr::eq(l, lang)).and_then(|(_, rows)| rows.iter().find(|(s, _)| s.as_slice() == suffix))
        .map(|(_, r)| r).expect("a partial sanitizer the pack has")
}

#[cfg(test)]
#[path = "taint_tests.rs"]
mod tests;
