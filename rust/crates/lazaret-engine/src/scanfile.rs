//! core.scan_file: one source file's findings.
//!
//! Dependency mode (registry, guard and `--deps` scans: only the
//! supply-chain and credential rules) is here whole, family by family as
//! core's `_scan_file` runs them, in the same order, so the findings come
//! out as core lists them: per line the pattern rules (`RULES`, with the
//! multi-line decode-and-run join and the private-key material check),
//! hex-escaped text and names, look-alike names, invisible-character runs,
//! char-code strings, base64 blobs, off-screen code and high-entropy
//! literals; then the file's obfuscator identifiers and self-publishing;
//! then the decode flow across lines. `findings` makes the issues.
//!
//! Project mode (your own files) is here as far as core's `_scan_rules`
//! goes (`scan_rules`): every pattern rule of the language, with Q-LONGLINE
//! and SC-PIPE-SHELL in their places on each line, the same families, then
//! the whole-text rules (`TEXT_RULES`). What core does after that — the SQL
//! statements without WHERE, the taint and SQL-sink passes, the function
//! metrics — and the suppression markers and the cap are the caller's.

use crate::filectx::{FileCtx, Lang};
use crate::findings::{self, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::linre::literal::LitSet as Need;
use crate::pyre::{self, Regex};
use crate::pystr::{self, PyStr};
use crate::rxutil;
use crate::signs;
use crate::token::TokenPattern;
use crate::unicode;
use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

pub struct Options {
    /// Dependency mode (core's dep=True).
    pub dep: bool,
    /// core.REDACT_SECRETS
    pub redact: bool,
    /// This Python's sum() adds floats with Neumaier's compensation (3.12+).
    pub neumaier: bool,
}

// ---------------- the rule table ----------------

pub enum Matcher {
    Re(Regex),
    Token(TokenPattern),
    /// SQL-DYNAMIC's pattern, matched by hand in linear time (crate::linear)
    SqlDynamic(Regex, crate::linear::SqlDynamic),
}

impl Matcher {
    fn from_value(v: &Value) -> Matcher {
        if v.get("token").is_some() {
            return Matcher::Token(TokenPattern::from_value(v).expect("a token pattern"));
        }
        let re = compile(v).expect("a rule pattern");
        let text = v.get("re").and_then(|t| t.as_str()).unwrap_or(&[]);
        let flags = v.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
        if pystr::eq(text, crate::linear::SQL_DYNAMIC_TEXT) && flags == crate::linear::SQL_DYNAMIC_FLAGS {
            return Matcher::SqlDynamic(re, crate::linear::SqlDynamic::new());
        }
        Matcher::Re(re)
    }

    /// (start, end) of the first match.
    pub fn search(&self, s: &[u32]) -> Option<(usize, usize)> {
        match self {
            Matcher::Re(r) => r.search(s).map(|m| (m.start(), m.end())),
            Matcher::Token(t) => t.search(s, 0),
            Matcher::SqlDynamic(r, hand) => hand.find(s).map(|a| {
                let end = r.match_at(s, a as isize, s.len() as isize).map(|m| m.end()).unwrap_or(a);
                (a, end)
            }),
        }
    }
}

fn compile(v: &Value) -> Option<Regex> {
    let src = v.get("re")?.as_str()?;
    let flags = v.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
    Regex::new(src, pyre::flags_from_letters(&flags)).ok()
}

pub struct Rule {
    pub text: RuleText,
    pub langs: Vec<PyStr>,
    pub re: Matcher,
    pub need: Option<Regex>,
    pub skip: Option<Regex>,
}

fn field<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
    v.get("map").and_then(|m| m.get(key))
}

/// core.RULES, read once.
pub fn rules(p: &Pack) -> &[Rule] {
    p.derived("RULES", |v| {
        v.get("list")
            .and_then(|l| l.as_arr())
            .unwrap_or(&[])
            .iter()
            .map(|r| Rule {
                text: RuleText::from_value(r),
                langs: field(r, "langs")
                    .and_then(|l| l.get("list"))
                    .and_then(|l| l.as_arr())
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|x| x.get("value").and_then(|s| s.as_str()).map(|s| s.to_vec()))
                    .collect(),
                re: Matcher::from_value(field(r, "re").expect("a rule has a pattern")),
                need: field(r, "need").and_then(compile),
                skip: field(r, "skip").and_then(compile),
            })
            .collect::<Vec<Rule>>()
    })
}

fn is(s: &[u32], lit: &str) -> bool {
    pystr::eq(s, lit)
}

fn is_blank(s: &[u32]) -> bool {
    s.iter().all(|&c| unicode::is_space(c))
}

/// Python's `ch.isalpha()` etc. on one code point.
fn ascii_alnum(c: u32) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A)
}

// ---------------- prefilters ----------------
// Tests a line must pass for one of these patterns to match on it, each
// written for the pattern's text as it is (and unused, so the pattern runs on
// every line, if the text in the pack is another): patterns core runs on
// every line that pyre's literal analysis finds no required text for.

const ENTROPY_VALUE_TEXT: &str = r#"[=:]\s*[\"']([A-Za-z0-9+/=_\-]{20,})[\"']"#;
const B64_BLOB_TEXT: &str = r#"[\"'][A-Za-z0-9+/]{200,}={0,2}[\"']"#;
const SINK_WORD_TEXT: &str = concat!(
    r#"\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\b|\[\s*['\"`](?:e(?:['\"`]\s*\+\s*['\"`])?v"#,
    r#"(?:['\"`]\s*\+\s*['\"`])?a(?:['\"`]\s*\+\s*['\"`])?l|F(?:['\"`]\s*\+\s*['\"`])?u(?:['\"`]\s*\+\s*['\"`])?n"#,
    r#"(?:['\"`]\s*\+\s*['\"`])?c(?:['\"`]\s*\+\s*['\"`])?t(?:['\"`]\s*\+\s*['\"`])?i(?:['\"`]\s*\+\s*['\"`])?o"#,
    r#"(?:['\"`]\s*\+\s*['\"`])?n)['\"`]\s*\]"#
);

/// Is the pack's pattern `name` the one a prefilter was written for (its
/// text, and no flags)?
fn written_for(p: &Pack, name: &str, text: &str) -> bool {
    *p.derived(name, |v| {
        v.get("re").and_then(|r| r.as_str()) == Some(pystr::u(text).as_slice())
            && v.get("flags").and_then(|f| f.as_str()).map(|f| f.is_empty()).unwrap_or(false)
    })
}

fn is_quote(c: u32) -> bool {
    c == '"' as u32 || c == '\'' as u32
}

fn b64ish(c: u32) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A) || c == '+' as u32 || c == '/' as u32 || c == '=' as u32 || c == '_' as u32 || c == '-' as u32
}

/// ENTROPY_VALUE_RE needs a quote followed by 20 characters of its class.
fn entropy_value_possible(line: &[u32]) -> bool {
    line.len() >= 21 && (0..line.len() - 20).any(|q| is_quote(line[q]) && line[q + 1..q + 21].iter().all(|&c| b64ish(c)))
}

/// _SC_SINK_WORD_RE needs a sink's name, or '[', blanks and a quote before an 'e' or 'F'.
fn sink_word_possible(code: &[u32]) -> bool {
    for (k, &c) in code.iter().enumerate() {
        let hit = match char::from_u32(c) {
            Some('e') => pystr::starts_with_at(code, k, "eval") || pystr::starts_with_at(code, k, "exec"),
            Some('F') => pystr::starts_with_at(code, k, "Function"),
            Some('r') => pystr::starts_with_at(code, k, "runIn"),
            Some('[') => {
                let mut j = k + 1;
                while j < code.len() && unicode::is_space(code[j]) {
                    j += 1;
                }
                j + 1 < code.len()
                    && (is_quote(code[j]) || code[j] == '`' as u32)
                    && (code[j + 1] == 'e' as u32 || code[j + 1] == 'F' as u32)
            }
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

// ---------------- which lines may match ----------------

/// Which of some patterns each line may match, a bit per pattern, from one
/// pass over the file: pyre knows, for most patterns, strings one of which
/// every match holds (literal.rs), and a line holding none of a pattern's
/// strings has no match of it. The bits answer for a search of the line's
/// own text only: a line whose match text differs is searched whatever
/// they say. A pattern without such strings has its bit set on every line.
struct Gates {
    masks: Vec<u64>,
}

impl Gates {
    /// `needs[j]`: the requirements of pattern j (a line may match it when
    /// one of them occurs in it); None when it has none (any line may).
    fn new(ctx: &FileCtx, needs: &[Option<Vec<&Need>>]) -> Gates {
        assert!(needs.len() <= 64);
        let mut always = 0u64;
        let mut first = [0u64; 128];
        let mut other = 0u64;
        for (j, n) in needs.iter().enumerate() {
            match n {
                None => always |= 1 << j,
                Some(list) => {
                    for need in list {
                        let fa = need.first_ascii();
                        for (c, slot) in first.iter_mut().enumerate() {
                            if fa & (1u128 << c) != 0 {
                                *slot |= 1 << j;
                            }
                        }
                        if need.first_other() {
                            other |= 1 << j;
                        }
                    }
                }
            }
        }
        let full = if needs.len() == 64 { !0u64 } else { (1u64 << needs.len()) - 1 };
        let s = &ctx.content;
        let masks = (0..ctx.len())
            .map(|i| {
                let (a, b) = (ctx.starts[i], ctx.end_of(i));
                let mut got = always;
                let mut k = a;
                while k < b && got != full {
                    let c = s[k];
                    let cand = (if c < 128 { first[c as usize] } else { other }) & !got;
                    if cand != 0 {
                        for (j, n) in needs.iter().enumerate() {
                            if cand & (1 << j) != 0 {
                                if let Some(list) = n {
                                    if list.iter().any(|need| need.starts_at(s, k, b)) {
                                        got |= 1 << j;
                                    }
                                }
                            }
                        }
                    }
                    k += 1;
                }
                got
            })
            .collect();
        Gates { masks }
    }

    #[inline]
    fn may(&self, i: usize, j: usize) -> bool {
        self.masks[i] & (1 << j) != 0
    }
}

/// A regex's requirement for Gates (None: it has none).
fn need_of(rx: &Regex) -> Option<Vec<&Need>> {
    rx.need().map(|n| vec![n])
}

impl Matcher {
    fn needs(&self) -> Option<Vec<&Need>> {
        match self {
            Matcher::Re(r) | Matcher::SqlDynamic(r, _) => need_of(r),
            // the other alternatives' strings, or a JWT's "eyJ"
            Matcher::Token(t) => match (t.others().need(), TokenPattern::jwt_start().need()) {
                (Some(a), Some(b)) => Some(vec![a, b]),
                _ => None,
            },
        }
    }
}

// ---------------- per-line helpers ----------------

/// core._paren_balance
fn paren_balance(p: &Pack, code: &[u32]) -> isize {
    let t = p.re("STRING_LIT_RE").sub(code, &[], 0);
    let open = t.iter().filter(|&&c| c == '(' as u32).count() as isize;
    let close = t.iter().filter(|&&c| c == ')' as u32).count() as isize;
    open - close
}

/// What _joined_eval_decode reads, resolved once per file.
struct Join<'p> {
    sink_word: &'p Regex,
    prefilter: bool,
    sink_names: &'p [PyStr],
    max_lines: usize,
    max_chars: usize,
}

impl<'p> Join<'p> {
    fn new(p: &'p Pack) -> Join<'p> {
        Join {
            sink_word: p.re("_SC_SINK_WORD_RE"),
            prefilter: written_for(p, "_SC_SINK_WORD_RE", SINK_WORD_TEXT),
            sink_names: p.strs("_SC_SINK_NAMES"),
            max_lines: p.usize("SC_JOIN_MAX_LINES"),
            max_chars: p.usize("SC_JOIN_MAX_CHARS"),
        }
    }
}

/// core._joined_eval_decode: the column (on line i) of an SC-EVAL-DECODE
/// match over the statement that starts on line i and continues on the next.
fn joined_eval_decode(ctx: &FileCtx, j: &Join, i: usize, rule: &Matcher) -> Option<usize> {
    let p = ctx.p;
    let code = ctx.mcode(i);
    if j.prefilter && !sink_word_possible(code) {
        return None;
    }
    j.sink_word.search(code)?;
    let mut depth = paren_balance(p, code);
    if depth <= 0 {
        let tail = pystr::rstrip(code);
        if !j.sink_names.iter().any(|n| tail.ends_with(n)) {
            return None;
        }
    }
    let (max_lines, max_chars) = (j.max_lines, j.max_chars);
    let mut joined: Vec<u32> = code.to_vec();
    let mut added = 0;
    for k in i + 1..ctx.len().min(i + 1 + max_lines) {
        if ctx.cmask[k] {
            continue;
        }
        let nxt = ctx.mcode(k);
        joined.push(' ' as u32);
        joined.extend_from_slice(nxt);
        added += nxt.len();
        depth += paren_balance(p, nxt);
        if (depth <= 0 && !is_blank(nxt)) || added > max_chars {
            break;
        }
    }
    let (start, _) = rule.search(&joined)?;
    if start < code.len() {
        Some(start)
    } else {
        None
    }
}

/// core._token_has_material: a private-key header needs key material after
/// it, on its line or the next two (match text).
fn token_has_material(ctx: &FileCtx, rule: &Matcher, line: &[u32], i: usize) -> bool {
    let (a, b) = match rule.search(line) {
        None => return true,
        Some(s) => s,
    };
    if !pystr::starts_with(&line[a..], "-----BEGIN") {
        return true;
    }
    let body = ctx.p.re("_PEM_BODY_RE");
    if body.search(&line[b..]).is_some() {
        return true;
    }
    (i + 1..ctx.len().min(i + 3)).any(|k| body.search(ctx.mline(k)).is_some())
}

/// core.hex_hidden_text: the readable text hidden in a line's \xNN escapes.
pub fn hex_hidden_text(p: &Pack, line: &[u32]) -> Option<PyStr> {
    let rx = p.re("_HEX_ESCAPE_RE");
    let codes: Vec<u32> = rx
        .finditer(line)
        .filter_map(|m| m.group(1).map(|h| h.iter().fold(0u32, |v, &d| v * 16 + char::from_u32(d).and_then(|c| c.to_digit(16)).unwrap_or(0))))
        .collect();
    if codes.len() < p.usize("HEX_MIN_ESCAPES") {
        return None;
    }
    let printable: Vec<u32> = codes.iter().copied().filter(|&c| (0x20..0x7F).contains(&c)).collect();
    if (printable.len() as f64) / (codes.len() as f64) < p.float("HEX_PRINTABLE_SHARE") {
        return None;
    }
    let letters = printable.iter().filter(|&&c| unicode::is_alpha(c)).count();
    if p.re("_LETTER_RUN_RE").search(&printable).is_none()
        || (letters as f64) / (printable.len() as f64) < p.float("HEX_LETTER_SHARE")
    {
        return None;
    }
    Some(printable)
}

/// core._hidden_name_in
fn hidden_name_in(p: &Pack, seg: &[u32], offset: usize) -> Option<(PyStr, usize)> {
    let mut text: Vec<u32> = Vec::with_capacity(seg.len());
    let mut esc_at: Vec<usize> = Vec::new();
    let mut esc_col: Vec<usize> = Vec::new();
    let (mut pos, mut total, mut printable) = (0usize, 0usize, 0usize);
    for m in p.re("_NAME_ESCAPE_RE").finditer(seg) {
        let start = m.start();
        let mut run = start;
        while run > 0 && seg[run - 1] == '\\' as u32 {
            run -= 1;
        }
        if (start - run) % 2 == 1 {
            continue; // "\\x65": an escaped backslash, then text
        }
        total += 1;
        let code: u64 = match (1..=4).find_map(|g| m.group(g)) {
            Some(h) => h.iter().fold(0u64, |v, &d| v * 16 + char::from_u32(d).and_then(|c| c.to_digit(16)).unwrap_or(0) as u64),
            None => m.group(5).unwrap_or(&[]).iter().fold(0u64, |v, &d| v * 8 + (d - '0' as u32) as u64),
        };
        if code > 0x10FFFF {
            continue; // no character: left as written
        }
        let code = code as u32;
        text.extend_from_slice(&seg[pos..start]);
        if (0x20..0x7F).contains(&code) {
            printable += 1;
            if ascii_alnum(code) || code == '_' as u32 {
                esc_at.push(text.len());
                esc_col.push(offset + start);
            }
        }
        text.push(code);
        pos = m.end();
    }
    if esc_at.is_empty() || (printable as f64) / (total as f64) < p.float("HEX_PRINTABLE_SHARE") {
        return None;
    }
    text.extend_from_slice(&seg[pos..]);
    for m in p.re("HIDDEN_TEXT_DANGER_RE").finditer(&text) {
        let k = esc_at.partition_point(|&x| x < m.start());
        if k < esc_at.len() && esc_at[k] < m.end() {
            return Some((m.group0().to_vec(), esc_col[k]));
        }
    }
    None
}

/// core.hex_hidden_name: (name, column) for the first string literal whose
/// escapes spell part of a dangerous name.
pub fn hex_hidden_name(p: &Pack, line: &[u32]) -> Option<(PyStr, usize)> {
    if !line.contains(&('\\' as u32)) {
        return None;
    }
    for lit in p.re("STRING_LIT_RE").finditer(line) {
        let g = lit.group0();
        if g.contains(&('\\' as u32)) {
            if let Some(found) = hidden_name_in(p, &g[1..g.len() - 1], lit.start() + 1) {
                return Some(found);
            }
        }
    }
    None
}

struct Lookalikes {
    map: HashMap<u32, u32>,
}

fn lookalikes(p: &Pack) -> &Lookalikes {
    p.derived("_LOOKALIKES", |v| Lookalikes {
        map: v
            .get("map")
            .and_then(|m| m.as_obj())
            .unwrap_or(&[])
            .iter()
            .filter_map(|(k, x)| {
                let to = x.get("value")?.as_str()?;
                if k.len() == 1 && to.len() == 1 {
                    Some((k[0], to[0]))
                } else {
                    None
                }
            })
            .collect(),
    })
}

struct Lookalike {
    name: PyStr,
    skeleton: PyStr,
    critical: bool,
    other: bool,
    detail: PyStr,
    col: usize,
}

fn hex4(c: u32) -> PyStr {
    pystr::u(&format!("U+{:04X}", c))
}

/// core.lookalike_name for the parity tests: (name, reads as, severity,
/// another name of the file it reads as, detail, column), `words` the file's
/// ASCII words.
pub fn lookalike_view(p: &Pack, code: &[u32], lang: Lang, words: &[PyStr]) -> Option<(PyStr, PyStr, &'static str, bool, PyStr, usize)> {
    let word_in = |w: &[u32]| words.iter().any(|x| x.as_slice() == w);
    lookalike_name(p, code, lang, &word_in).map(|f| {
        (f.name, f.skeleton, if f.critical { "CRITICAL" } else { "MAJOR" }, f.other, f.detail, f.col)
    })
}

/// core.lookalike_name, on a line as names_code reads it.
fn lookalike_name(p: &Pack, code: &[u32], lang: Lang, word_in: &dyn Fn(&[u32]) -> bool) -> Option<Lookalike> {
    if pystr::is_ascii(code) {
        return None;
    }
    let map = &lookalikes(p).map;
    let invisible = |c: u32| p.strs("_INVISIBLE_IN_NAMES").iter().any(|s| s.len() == 1 && s[0] == c);
    let look = |c: u32| *map.get(&c).unwrap_or(&c);
    for m in p.re("_NAME_RUN_RE").finditer(code) {
        let name = m.group0();
        if pystr::is_ascii(name) || (m.start() > 0 && code[m.start() - 1] == '\\' as u32) {
            continue;
        }
        let seen: PyStr = if lang == Lang::Js { crate::normalize::nfkc(name) } else { name.to_vec() };
        let skeleton: PyStr = seen.iter().copied().filter(|&c| !invisible(c)).map(look).collect();
        if skeleton.is_empty()
            || skeleton.as_slice() == name
            || !pystr::is_ascii(&skeleton)
            || (0x30..=0x39).contains(&skeleton[0])
        {
            continue;
        }
        // (a keyword's look-alike names what the keyword can't: `funсtion`, a
        // parameter jQuery's typings call function; not another of the file's names)
        let keywords = match lang {
            Lang::Py => p.strs("_LOOKALIKE_KEYWORDS_PY"),
            Lang::Js => p.strs("_LOOKALIKE_KEYWORDS_JS"),
            _ => &[],
        };
        let keyword = keywords.iter().any(|k| *k == skeleton);
        let (critical, other) = if p.strs("_LOOKALIKE_TARGETS").iter().any(|t| *t == skeleton) {
            (true, false)
        } else if !keyword && skeleton.len() >= 3 && word_in(&skeleton) {
            (true, true)
        } else if p.re("_ASCII_LETTER_RE").search(name).is_some() {
            (false, false)
        } else {
            continue;
        };
        let mut parts: Vec<PyStr> = Vec::new();
        for &ch in name {
            if ch < 0x80 {
                continue;
            }
            let part = if invisible(ch) {
                findings::format(&p.text("_LOOKALIKE_INVISIBLE"), &[("cp", Arg::S(hex4(ch)))])
            } else {
                let shown: PyStr = if lang == Lang::Js { crate::normalize::nfkc(&[ch]) } else { vec![ch] };
                let reads: PyStr = shown.iter().map(|&c| look(c)).collect();
                findings::format(&p.text("_LOOKALIKE_LETTER"), &[("cp", Arg::S(hex4(ch))), ("reads", Arg::S(reads))])
            };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let refs: Vec<&[u32]> = parts.iter().map(|x| x.as_slice()).collect();
        return Some(Lookalike {
            name: name.to_vec(),
            skeleton,
            critical,
            other,
            detail: pystr::join(&pystr::u(", "), &refs),
            col: m.start(),
        });
    }
    None
}

/// The column of the first quoted run B64_BLOB_RE finds in `line` that can be
/// base64 data (G-5): not digits alone, hex digits alone (after a `0x` or
/// not) or letters alone (a table of names: Go's stringer writes them) up to
/// `plain_max` characters, nor a period of at most `period_max` characters
/// repeated (a test string). Base64 of 150 bytes or more mixes letters and
/// digits and does not repeat itself; those are what Go's own tree, Ubuntu's
/// Go modules and the popular crates hold under the rule (Part F: 24 of 39 Go
/// WARNs, 11 of 30 crates'), the longest 9,327 digits. A longer run of one
/// class is reported: it is what a payload written in hex is (three of the
/// benchmark's malicious PyPI releases hold one of 270,000 hex digits or more).
fn b64_blob_col(re: &Regex, line: &[u32], plain_max: usize, period_max: usize) -> Option<usize> {
    for m in re.finditer(line) {
        let run = m.group0();
        let mut body = &run[1..run.len() - 1];
        while body.last() == Some(&('=' as u32)) {
            body = &body[..body.len() - 1];
        }
        if !b64_plain(body, plain_max, period_max) && !b64_data(body) {
            return Some(m.start());
        }
    }
    None
}

/// The base64 that the formats datafmt reads begin with: a WebAssembly module (`\0asm`), a PNG, a GIF, RIFF
/// (WAV, WebP).
const B64_DATA_HEADS: [&str; 4] = ["AGFzbQ", "iVBORw0KGgo", "R0lGOD", "UklGR"];

/// Is `body` (the characters of a B64_BLOB_RE run, its quotes and `=` taken off) the base64 of a whole file of a
/// format code keeps as data, read by its structure (datafmt: a WebAssembly module, a PNG, GIF or WebP image, WAV
/// audio)? N-4: the WebAssembly HTTP parser every action bundling the Actions toolkit carries (undici's llhttp),
/// and what made 5 of the popular set's 32 WARNs, were such files.
fn b64_data(body: &[u32]) -> bool {
    if body.len() % 4 == 1 || !B64_DATA_HEADS.iter().any(|h| pystr::starts_with(body, h)) {
        return false;
    }
    let mut padded = body.to_vec();
    while padded.len() % 4 != 0 {
        padded.push('=' as u32);
    }
    crate::signs::b64decode_strict(&padded).is_some_and(|b| crate::datafmt::data_format(&b).is_some())
}

/// Is `body` (the characters of a B64_BLOB_RE run, its quotes and `=` taken
/// off) one of the runs b64_blob_col passes over? A period is checked from
/// the shortest, each stopping at its first mismatch; a period carries no
/// more than one period's characters, however long the run.
fn b64_plain(body: &[u32], plain_max: usize, period_max: usize) -> bool {
    let digit = |c: u32| (0x30..=0x39).contains(&c);
    let hex = |c: u32| digit(c) || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c);
    let letter = |c: u32| (0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c);
    let hex_body = if body.len() > 2 && body[0] == '0' as u32 && (body[1] == 'x' as u32 || body[1] == 'X' as u32) {
        &body[2..]
    } else {
        body
    };
    if body.len() <= plain_max
        && (body.iter().all(|&c| digit(c)) || hex_body.iter().all(|&c| hex(c)) || body.iter().all(|&c| letter(c)))
    {
        return true;
    }
    (1..=period_max.min(body.len() / 2)).any(|k| (k..body.len()).all(|i| body[i] == body[i - k]))
}

/// core.hidden_unicode_run: (column, run) of the first run of invisible
/// carrier characters that is not a flag emoji, nor an emoji's presentation
/// selector repeated (N-23: U+2622 and U+FE0F twice, in a top-100 crate; one
/// character repeated a few times carries no data, and GlassWorm's encoding
/// is a run of many different selectors).
fn hidden_unicode_run(p: &Pack, line: &[u32]) -> Option<(usize, PyStr)> {
    let base = p.text("_FLAG_EMOJI_BASE");
    let tag_start = p.text("_TAG_START")[0];
    let tag_end = p.text("_TAG_END")[0];
    let presentation = p.text("_PRESENTATION_SELECTORS");
    let repeat_max = p.usize("_PRESENTATION_REPEAT_MAX");
    for m in p.re("_HIDDEN_RUN_RE").finditer(line) {
        let run = m.group0();
        let flag = m.start() > 0
            && base.len() == 1
            && line[m.start() - 1] == base[0]
            && run.last() == Some(&tag_end)
            && run.iter().all(|&c| (tag_start..=tag_end).contains(&c));
        let repeated = run.len() <= repeat_max && presentation.contains(&run[0]) && run.iter().all(|&c| c == run[0]);
        if !flag && !repeated {
            return Some((m.start(), run.to_vec()));
        }
    }
    None
}

/// core._call_args_end
fn call_args_end(line: &[u32], k: usize, stop: usize) -> Option<usize> {
    let (mut depth, mut quote, mut j) = (0isize, None::<u32>, k);
    while j < stop {
        let c = line[j];
        if let Some(q) = quote {
            if c == '\\' as u32 {
                j += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
        } else if c == '\'' as u32 || c == '"' as u32 || c == '`' as u32 {
            quote = Some(c);
        } else if c == '(' as u32 {
            depth += 1;
        } else if c == ')' as u32 {
            depth -= 1;
            if depth == 0 {
                return Some(j);
            }
        }
        j += 1;
    }
    None
}

/// core._charcode_col
fn charcode_col(p: &Pack, line: &[u32]) -> Option<usize> {
    let call = p.re("CHARCODE_RE");
    call.search(line)?;
    let nums: Vec<usize> = p.re("CHARCODE_NUM_RE").finditer(line).map(|m| m.start()).collect();
    if nums.len() < 10 {
        return None;
    }
    let mut tables: HashSet<PyStr> = HashSet::new();
    for m in p.re("_CHARCODE_TABLE_RE").finditer(line) {
        let values = m.group(2).unwrap_or(&[]);
        let mut ok = true;
        let mut k = 0;
        while k < values.len() {
            if (0x30..=0x39).contains(&values[k]) {
                let mut v: u64 = 0;
                while k < values.len() && (0x30..=0x39).contains(&values[k]) {
                    v = v.saturating_mul(10).saturating_add((values[k] - 0x30) as u64);
                    k += 1;
                }
                if !(32..=126).contains(&v) {
                    ok = false;
                }
            } else {
                k += 1;
            }
        }
        if ok {
            tables.insert(m.group(1).unwrap_or(&[]).to_vec());
        }
    }
    let refs: Vec<usize> = if tables.is_empty() {
        Vec::new()
    } else {
        p.re("_CHARCODE_NAME_RE").finditer(line).filter(|m| tables.contains(m.group0())).map(|m| m.start()).collect()
    };
    let tail = p.re("_CHARCODE_CALL_TAIL_RE");
    let args_max = p.usize("CHARCODE_ARGS_MAX");
    let mut budget = p.int("CHARCODE_SCAN_BUDGET");
    for m in call.finditer(line) {
        let t = match tail.match_at(line, m.end() as isize, line.len() as isize) {
            None => continue,
            Some(t) => t,
        };
        let k = t.end() - 1; // the '('
        let stop = line.len().min(k + args_max);
        let end = if budget > 0 { call_args_end(line, k, stop) } else { None };
        let e = end.unwrap_or(stop);
        budget -= (e - k) as i64;
        let before = |v: &[usize], x: usize| v.partition_point(|&y| y < x);
        if before(&nums, e) - before(&nums, k) >= 10 || before(&refs, e) > before(&refs, k) {
            return Some(m.start());
        }
    }
    None
}

// ---------------- the decode flow (dependency mode) ----------------

/// core._decoder_aliases
fn decoder_aliases(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut out: Vec<PyStr> = Vec::new();
    if !pystr::contains(text, "import") || !pystr::contains(text, " as ") {
        return out;
    }
    let names = p.strs("_DECODER_NAMES");
    let plain = p.re("_PLAIN_NAME_RE");
    for m in p.re("_DECODER_IMPORT_RE").finditer(text) {
        let g: PyStr =
            m.group(1).unwrap_or(&[]).iter().map(|&c| if c == '(' as u32 || c == ')' as u32 { ' ' as u32 } else { c }).collect();
        for part in pystr::split_char(&g, ',' as u32) {
            let bits = pystr::split_ws(part);
            if bits.len() == 3
                && is(bits[1], "as")
                && names.iter().any(|n| n.as_slice() == bits[0])
                && plain.match_(bits[2]).is_some()
                && !out.iter().any(|o| o.as_slice() == bits[2])
            {
                out.push(bits[2].to_vec());
            }
        }
    }
    out.truncate(20);
    out
}

/// core._file_decode_re (Python) / _DECODE_CALL_RE
fn decode_re(ctx: &FileCtx) -> std::rc::Rc<Regex> {
    let p = ctx.p;
    let aliases = if ctx.lang == Lang::Py { decoder_aliases(p, &ctx.content) } else { Vec::new() };
    let mut src = p.text("_DECODE_CALL_SRC");
    let flags = pyre::flags_from_letters(&p.raw("_DECODE_CALL_RE").and_then(|v| v.get("flags")).and_then(|f| f.as_string()).unwrap_or_default());
    if !aliases.is_empty() {
        src.extend(pystr::u("|(?<![\\w.])(?:"));
        for (k, a) in aliases.iter().enumerate() {
            if k > 0 {
                src.push('|' as u32);
            }
            src.extend_from_slice(a);
        }
        src.extend(pystr::u(")\\s*\\("));
    }
    rxutil::dynamic(src, flags)
}

/// core._child_process_aliases
fn child_process_aliases(p: &Pack, content: &[u32]) -> HashSet<PyStr> {
    let mut out = HashSet::new();
    if !pystr::contains(content, "child_process") {
        return out;
    }
    for m in p.re("_CP_ALIAS_RE").finditer(content) {
        if let Some(g) = m.group(1).or_else(|| m.group(2)) {
            out.insert(g.to_vec());
        }
    }
    out
}

/// core._blank_strings: string literals' contents as spaces (same length).
fn blank_strings(p: &Pack, code: &[u32]) -> PyStr {
    p.re("STRING_LIT_RE").sub_fn(code, 0, |m| {
        let g = m.group0();
        let mut v = Vec::with_capacity(g.len());
        v.push(g[0]);
        v.extend(std::iter::repeat(' ' as u32).take(g.len() - 2));
        v.push(g[g.len() - 1]);
        v
    })
}

/// core._paren_close_map
fn paren_close_map(p: &Pack, line: &[u32]) -> HashMap<usize, usize> {
    let mut close = HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut quote: Option<u32> = None;
    for m in p.re("_PAREN_TOKEN_RE").finditer(line) {
        let (ch, j) = (m.group0()[0], m.start());
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '"' as u32 || ch == '\'' as u32 {
            quote = Some(ch);
        } else if ch == '(' as u32 {
            stack.push(j);
        } else if let Some(open) = stack.pop() {
            close.insert(open, j);
        }
    }
    close
}

/// core._is_code_sink
fn is_code_sink<'a>(p: &Pack, code: &[u32], m: &pyre::Match, cp_aliases: &dyn Fn() -> &'a HashSet<PyStr>) -> bool {
    let name = m.group(2).unwrap_or(&[]);
    if !is(name, "eval") && !is(name, "exec") {
        return true;
    }
    if m.start_of(1) < 0 {
        let mut j = m.start_of(2) - 1;
        while j >= 0 && (code[j as usize] == ' ' as u32 || code[j as usize] == '\t' as u32) {
            j -= 1;
        }
        return j < 0 || code[j as usize] != '.' as u32;
    }
    let recv = &code[m.start_of(1) as usize..m.end_of(1) as usize];
    if pystr::starts_with(recv, "require") {
        return is(name, "exec") && p.re("_CHILD_PROCESS_RE").search(recv).is_some();
    }
    if p.strs("_GLOBAL_EVAL_RECEIVERS").iter().any(|r| r.as_slice() == recv) {
        return is(name, "eval") || is(recv, "builtins") || is(recv, "__builtins__");
    }
    is(name, "exec") && (is(recv, "child_process") || cp_aliases().contains(recv))
}

/// Does a text write out a decoder the text's reading doesn't know (an
/// XOR, characters made of their codes, a reversal; in JavaScript zlib's
/// decompressions, hex) and call something that runs code or a program
/// (`_TREE_DECODER_SHAPE_RE`, `_TREE_RUN_GATE_RE`, an indirect eval), in
/// code? (A comment's "O(n^2)" or a docstring's "exec" is neither.) Or, in
/// Python, use a decoder the text knows (base64, hex, zlib, codecs) and a
/// shell (`_TREE_PY_KNOWN_DECODER_RE`, `_TREE_PY_SHELL_RE`): the text's
/// sinks have no shell for Python, so `os.system(b64decode(s).decode())`
/// had no candidate, while JavaScript's child_process is one (0.1.8).
fn may_run_written_decoder(ctx: &FileCtx) -> bool {
    let lang = if ctx.lang == Lang::Py { "py" } else { "js" };
    let p = ctx.p;
    let c = &ctx.content;
    let in_code = |re: &Regex| re.finditer(c).any(|m| ctx.in_code(m.start()));
    (in_code(p.map_re("_TREE_DECODER_SHAPE_RE", lang))
        && (in_code(p.map_re("_TREE_RUN_GATE_RE", lang)) || in_code(p.re("_INDIRECT_SINK_RE"))))
        || (ctx.lang == Lang::Py && in_code(p.re("_TREE_PY_KNOWN_DECODER_RE")) && in_code(p.re("_TREE_PY_SHELL_RE")))
}

/// The decoded-payload flow on JavaScript's and Python's trees (the
/// supply-chain models): a decoded value followed by scope to code run, in
/// code (code in a string is not code). None when the tree can't read the
/// text (the text's names and windows answer then).
fn tree_decode_flow(ctx: &FileCtx, rule: &RuleText, out: &mut Vec<Finding>) -> Option<()> {
    if !matches!(ctx.lang, Lang::Py | Lang::Js) {
        return None;
    }
    let runs = if ctx.lang == Lang::Py {
        crate::pyflow::supply::decoded_runs(&ctx.content)?
    } else {
        crate::jsflow::supply::decoded_runs(&ctx.content)?
    };
    let p = ctx.p;
    let content = &ctx.content;
    let mut have: HashSet<usize> = out.iter().filter(|f| is(&f.rule.id, "SC-EVAL-DECODE")).map(|f| f.line).collect();
    let flow_msg = p.text("_DECODE_FLOW_MSG");
    let same_call_msg = p.text("_DECODE_SAME_CALL_MSG");
    let line_of = |at: usize| pystr::count_char(content, '\n' as u32, 0, at.min(content.len())) + 1;
    for (at, from) in runs {
        let line = line_of(at);
        if !have.insert(line) {
            continue;
        }
        // (a decode inside the run's call is the same call; one before it, on
        // its line too, `d = decode(s); eval(d)`, is a decoded value's flow)
        let msg = if from >= at {
            same_call_msg.clone()
        } else {
            findings::format(&flow_msg, &[("line", Arg::I(line_of(from) as i64))])
        };
        let col = at.min(content.len()) - pystr::rfind_char(content, '\n' as u32, 0, at.min(content.len())).map(|x| x + 1).unwrap_or(0);
        let mut text = rule.clone();
        text.msg = msg;
        out.push(Finding::new(text, line, Some(col)));
    }
    Some(())
}

/// core._dep_decode_flow: a decoded value followed to a sink. The text's
/// reading (names within a window) finds the candidates. A JavaScript or
/// Python text that has one, or that writes out a decoder the text's
/// reading doesn't know and calls a runner, is read on its tree, whose
/// answer stands: it drops a candidate whose code is in a string or whose
/// value never reaches the run, and finds what the windows miss. (Reading a
/// tree costs several times the text's reading: only those texts pay it.)
fn dep_decode_flow(ctx: &FileCtx, rule: &RuleText, out: &mut Vec<Finding>, decode: &Regex, gates: &Gates, g_decode: usize) {
    let mut found = Vec::new();
    dep_decode_flow_text(ctx, rule, out, &mut found, decode, gates, g_decode);
    // (a text over the trees' limit is read on its text alone)
    let limit = if ctx.lang == Lang::Py { crate::pyflow::supply::MAX_TEXT } else { crate::jsflow::MAX_FILE };
    if matches!(ctx.lang, Lang::Py | Lang::Js)
        && ctx.content.len() <= limit
        && (!found.is_empty() || may_run_written_decoder(ctx))
        && tree_decode_flow(ctx, rule, out).is_some()
    {
        return;
    }
    out.extend(found);
}

/// dep_decode_flow on the text: names followed within DEP_FLOW_WINDOW to a
/// sink (`existing`: the findings so far, a line of whose is not reported
/// twice).
fn dep_decode_flow_text(ctx: &FileCtx, rule: &RuleText, existing: &[Finding], out: &mut Vec<Finding>, decode: &Regex, gates: &Gates, g_decode: usize) {
    let p = ctx.p;
    let ident = p.map_re("_IDENT_RUN_RE", if ctx.lang == Lang::Py { "py" } else { "js" });
    let mut have: HashSet<usize> = existing.iter().filter(|f| is(&f.rule.id, "SC-EVAL-DECODE")).map(|f| f.line).collect();
    // (read when a sink needs them: core reads them first, and they depend on
    // nothing the pass changes)
    let cp_aliases: OnceCell<HashSet<PyStr>> = OnceCell::new();
    let aliases = || cp_aliases.get_or_init(|| if ctx.lang == Lang::Js { child_process_aliases(p, &ctx.content) } else { HashSet::new() });
    let window = p.usize("DEP_FLOW_WINDOW");
    let args_max = p.usize("DEP_SINK_ARGS_MAX");
    let assign_re = p.re("_DEP_ASSIGN_RE");
    let sink_re = p.re("_DECODE_SINK_RE");
    let indirect_re = p.re("_INDIRECT_SINK_RE");
    let fn_def = p.re("_FN_DEF_BEFORE_RE");
    let flow_msg = p.text("_DECODE_FLOW_MSG");
    let same_call_msg = p.text("_DECODE_SAME_CALL_MSG");
    let mut decoded: HashMap<PyStr, (usize, usize)> = HashMap::new(); // name -> (line of the decode, its offset)
    // the newest offset of a decode in `decoded`: once the window has passed
    // it, no name of `decoded` is in reach again, and a line without a decode
    // call can change nothing (as when `decoded` is empty)
    let mut newest: Option<usize> = None;
    let mut offset = 0usize;
    for i in 0..ctx.len() {
        let base = offset;
        offset += ctx.line(i).len() + 1;
        if ctx.cmask[i] {
            continue;
        }
        let code = ctx.mcode(i);
        if code.is_empty() || is_blank(code) {
            continue;
        }
        // (a line whose match text without comments is a part of the file's
        // text holds no decode call when its gate says so)
        let has_decode = (ctx.mcode_differs(i) || gates.may(i, g_decode)) && decode.search(code).is_some();
        if !has_decode && newest.map(|n| n + window < base).unwrap_or(true) {
            continue;
        }
        let blank = blank_strings(p, code);
        // code in a literal is not code: a string's, a template's or a
        // regular expression's text, one begun on an earlier line too (a
        // template or a triple-quoted string over many lines)
        let lits = ctx.code_literals(i).unwrap_or_default();
        let in_lit = |pos: usize| crate::lex::within(&lits, pos);
        let names: Cow<[u32]> = if lits.is_empty() {
            Cow::Borrowed(&blank)
        } else {
            let mut v = blank.clone();
            for &(a, b) in &lits {
                for c in &mut v[a.min(blank.len())..b.min(blank.len())] {
                    *c = ' ' as u32;
                }
            }
            Cow::Owned(v)
        };
        // a decode call in code[a..b]
        let decodes = |a: usize, b: usize| decode.finditer_at(code, a as isize, b as isize).any(|d| !in_lit(d.start()));
        let mut events: Vec<(usize, u8, pyre::Match)> = Vec::new();
        for m in assign_re.finditer(&blank) {
            if !in_lit(m.start()) {
                events.push((m.start(), 0, m));
            }
        }
        for m in sink_re.finditer(&blank) {
            if !in_lit(m.start()) {
                events.push((m.start(), 1, m));
            }
        }
        for m in indirect_re.finditer(code) {
            if blank[m.start()] == code[m.start()] && !in_lit(m.start()) {
                events.push((m.start(), 2, m));
            }
        }
        events.sort_by_key(|e| (e.0, e.1));
        let mut close: Option<HashMap<usize, usize>> = None;
        // decodes behind the decoded names in names[a..b], still in reach at `at`
        let live = |decoded: &HashMap<PyStr, (usize, usize)>, a: usize, b: usize, at: usize| -> Vec<(usize, usize)> {
            let mut seen: HashSet<&[u32]> = HashSet::new();
            let mut src = Vec::new();
            for m in ident.finditer_at(&names, a as isize, b as isize) {
                let v = m.group0();
                if !seen.insert(v) {
                    continue;
                }
                if let Some(&d) = decoded.get(v) {
                    if at.saturating_sub(d.1) <= window || at < d.1 {
                        src.push(d);
                    }
                }
            }
            src
        };
        for (pos, kind, m) in events {
            let at = base + pos;
            if kind == 0 {
                let (a, b) = (m.start_of(2) as usize, m.end_of(2) as usize);
                let name = m.group(1).unwrap_or(&[]).to_vec();
                if decodes(a, b) {
                    decoded.insert(name, (i + 1, at));
                    newest = Some(newest.map_or(at, |n| n.max(at)));
                    continue;
                }
                let src = live(&decoded, a, b, at);
                if let Some(best) = src.iter().copied().reduce(|x, y| if y.1 > x.1 { y } else { x }) {
                    decoded.insert(name, best);
                    newest = Some(newest.map_or(best.1, |n| n.max(best.1)));
                }
                continue;
            }
            if have.contains(&(i + 1)) {
                continue;
            }
            if kind == 1 {
                if !is_code_sink(p, code, &m, &aliases) {
                    continue;
                }
                let s2 = m.start_of(2) as usize;
                if fn_def.search(&blank[s2.saturating_sub(24)..s2]).is_some() {
                    continue; // a definition, not a call
                }
            }
            let close = close.get_or_insert_with(|| paren_close_map(p, &blank));
            let closed = close.get(&(m.end() - 1)).copied();
            if let Some(cl) = closed {
                let from = (cl + 1).min(blank.len());
                let to = (cl + 2 + args_max).min(blank.len());
                if pystr::lstrip(&blank[from..to]).first() == Some(&('{' as u32)) {
                    continue; // `exec(a, b) {`: a method definition
                }
            }
            let end = closed.unwrap_or(blank.len()).min(m.end() + args_max);
            let src = live(&decoded, m.end(), end, at);
            let msg = if !src.is_empty() {
                let line = src.iter().map(|d| d.0).min().unwrap_or(0);
                findings::format(&flow_msg, &[("line", Arg::I(line as i64))])
            } else if decodes(m.end(), end) {
                same_call_msg.clone()
            } else {
                continue;
            };
            have.insert(i + 1);
            let mut text = rule.clone();
            text.msg = msg;
            out.push(Finding::new(text, i + 1, Some(m.start())));
        }
    }
}

// ---------------- the pass ----------------

/// core.scan_file, dependency mode: the issues, as mk_issue makes them.
pub fn scan_file(p: &Pack, text: &[u32], lang_name: Option<&str>, jsx: bool, opts: &Options) -> Vec<Value> {
    let lang = Lang::from(lang_name);
    let ctx = FileCtx::new(p, text, lang, jsx);
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
    let snippets = Snippets::new(p, lines, opts.redact, opts.neumaier);
    let mut found = findings_of(&ctx, lang_name, opts, &snippets);
    if lang == Lang::Rs && opts.dep && !found.is_empty() {
        if let Some(test_only) = rs_test_only_lines(&ctx) {
            found.retain(|f| !test_only.get(f.line.wrapping_sub(1)).copied().unwrap_or(false));
        }
    }
    findings::cap(p, &snippets, found).iter().map(|f| snippets.issue(f)).collect()
}

/// N-20: the lines of a dependency's Rust file that hold only code no dependent builds, as `*_test.go` is a Go
/// file none builds: the items under `#[cfg(test)]` (or `cfg(all(…, test))`), `#[test]`, `#[bench]` and the like,
/// with their attributes (the Rust reader's test items, `rsread::test_items`), an item whose own inner attributes
/// are such a `cfg`, or the whole file under its `#![cfg(test)]`. A line is left out only when all of its text,
/// blanks aside, is in such an item; a file the parser could not read whole leaves none out (None).
fn rs_test_only_lines(ctx: &FileCtx) -> Option<Vec<bool>> {
    let src = &ctx.content;
    let tree = crate::rsparse::parse(src);
    if tree.problems != 0 {
        return None;
    }
    let only_in_tests = |attrs: &[crate::rsparse::Attr]| attrs.iter().any(|a| crate::rsread::cfg_only_in_tests(&tree, src, a));
    let (first, count) = tree.crate_attrs;
    if only_in_tests(&tree.attrs[first as usize..(first + count) as usize]) {
        return Some(vec![true; ctx.len()]);
    }
    let mut tests = crate::rsread::test_items(&tree, src);
    for k in 0..tree.items.len() {
        let parent = tree.items[k].parent;
        if only_in_tests(tree.inner_attrs_of(k)) || (parent != crate::rsparse::NONE && tests.contains(&parent)) {
            tests.insert(k as u32);
        }
    }
    if tests.is_empty() {
        return None;
    }
    let mut covered = vec![false; src.len()];
    for &k in &tests {
        let it = &tree.items[k as usize];
        let start = tree.attrs_of(k as usize).iter().map(|a| tree.toks[a.tok_start as usize].start).fold(it.start, u32::min);
        let (start, end) = ((start as usize).min(src.len()), (it.end as usize).min(src.len()));
        covered[start..end.max(start)].iter_mut().for_each(|c| *c = true);
    }
    let blank = |c: u32| c == ' ' as u32 || c == '\t' as u32 || c == 0x0B || c == 0x0C;
    Some(
        (0..ctx.len())
            .map(|i| {
                let (s, e) = (ctx.starts[i], ctx.end_of(i));
                (s..e).any(|j| covered[j]) && (s..e).all(|j| covered[j] || blank(src[j]))
            })
            .collect(),
    )
}

/// core.scan_file in project mode (Q-1): the rules part (`scan_rules`), then the passes that follow it, the
/// suppression markers and the cap (crate::project), as core's `scan_file(…, dep=False)` makes them. `model`: the
/// taint configuration's part of the model.
pub fn scan_project(p: &Pack, text: &[u32], lang_name: Option<&str>, jsx: bool, opts: &Options, model: &crate::taint::Model) -> Vec<Value> {
    let lang = Lang::from(lang_name);
    let ctx = FileCtx::new(p, text, lang, jsx);
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
    let snippets = Snippets::new(p, lines, opts.redact, opts.neumaier);
    let mut found = findings_of(&ctx, lang_name, opts, &snippets);
    crate::project::passes(&ctx, &mut found, model);
    let found = crate::project::unsuppressed(&ctx, found);
    findings::cap(p, &snippets, found).iter().map(|f| snippets.issue(f)).collect()
}

/// core._scan_rules in project mode: the findings of the pattern rules and
/// the families, in core's order, before the passes that follow them, the
/// suppression markers and the cap (the caller's: see the module docs).
pub fn scan_rules(p: &Pack, text: &[u32], lang_name: Option<&str>, jsx: bool, redact: bool, neumaier: bool) -> Vec<Value> {
    let lang = Lang::from(lang_name);
    let ctx = FileCtx::new(p, text, lang, jsx);
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
    let snippets = Snippets::new(p, lines, redact, neumaier);
    let opts = Options { dep: false, redact, neumaier };
    findings_of(&ctx, lang_name, &opts, &snippets).iter().map(|f| snippets.issue(f)).collect()
}

/// core.TEXT_RULES, read once: (the rule, its languages, its pattern).
fn text_rules(p: &Pack) -> &[(RuleText, Vec<PyStr>, Option<Regex>)] {
    p.derived("TEXT_RULES", |v| {
        v.get("list")
            .and_then(|l| l.as_arr())
            .unwrap_or(&[])
            .iter()
            .map(|r| {
                let langs = field(r, "langs")
                    .and_then(|l| l.get("list"))
                    .and_then(|l| l.as_arr())
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|x| x.get("value").and_then(|s| s.as_str()).map(|s| s.to_vec()))
                    .collect();
                (RuleText::from_value(r), langs, field(r, "re").and_then(compile))
            })
            .collect::<Vec<_>>()
    })
}

/// core._runs_download_through_shell: does this line hand a download piped
/// into a shell, or substituted into a command line, to an exec call?
fn runs_download_through_shell(p: &Pack, row: &[u32]) -> bool {
    (pystr::contains(row, "curl") || pystr::contains(row, "wget"))
        && p.re("_EXEC_CALL_RE").search(row).is_some()
        && (signs::pipes_download_to_shell(p, row) || signs::runs_substituted_download(p, row))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    EqEq,
    EvalDecode,
    Token,
    Secret,
}

/// A rule of RULES as this file's per-line pass runs it.
struct Active<'a> {
    rule: &'a Rule,
    kind: Kind,
    on_comments: bool,
}

/// The findings of `_scan_file`, in core's order, before the cap.
pub fn findings_of(ctx: &FileCtx, lang_name: Option<&str>, opts: &Options, snippets: &Snippets) -> Vec<Finding> {
    let p = ctx.p;
    let lang = ctx.lang;
    let content = &ctx.content;
    let prefixes = p.strs("DEP_RULE_PREFIXES");
    let comment_rules = p.strs("_COMMENT_LINE_RULES");
    let lang_str = lang_name.map(pystr::u);
    let active: Vec<Active> = rules(p)
        .iter()
        .filter(|r| {
            lang_str.as_ref().map(|l| r.langs.contains(l)).unwrap_or(false)
                && (!opts.dep || prefixes.iter().any(|pre| r.text.id.starts_with(pre)))
        })
        .map(|r| Active {
            rule: r,
            kind: match () {
                _ if is(&r.text.id, "B-EQEQ") => Kind::EqEq,
                _ if is(&r.text.id, "SC-EVAL-DECODE") => Kind::EvalDecode,
                _ if is(&r.text.id, "S-TOKEN") => Kind::Token,
                _ if is(&r.text.id, "S-SECRET") => Kind::Secret,
                _ => Kind::Plain,
            },
            on_comments: comment_rules.contains(&r.text.id),
        })
        .collect();
    let mut out: Vec<Finding> = Vec::new();
    let mut secret_lines: HashSet<usize> = HashSet::new();
    let words: OnceCell<HashSet<PyStr>> = OnceCell::new();
    let word_in = |w: &[u32]| {
        words
            .get_or_init(|| p.re("_ASCII_WORD_RE").finditer(content).map(|m| m.group0().to_vec()).collect())
            .contains(w)
    };
    let runs_code: OnceCell<bool> = OnceCell::new();
    let hexstr_text = RuleText::of(p, "_HEXSTR_TEXT_RULE");
    let hexstr_name = RuleText::of(p, "_HEXSTR_NAME_RULE");
    let lookalike = RuleText::of(p, "_LOOKALIKE_RULE");
    let hidden = RuleText::of(p, "_HIDDEN_UNICODE_RULE");
    let charcode = RuleText::of(p, "_CHARCODE_RULE");
    let b64 = RuleText::of(p, "_B64_RULE");
    let offscreen = RuleText::of(p, "_OFFSCREEN_RULE");
    let entropy = RuleText::of(p, "_ENTROPY_RULE");
    let string_lit = p.re("STRING_LIT_RE");
    let hex_escape = p.re("_HEX_ESCAPE_RE");
    let danger = p.re("HIDDEN_TEXT_DANGER_RE");
    let b64_re = p.re("B64_BLOB_RE");
    let secret_skip = p.re("SECRET_SKIP_RE");
    let entropy_re = p.re("ENTROPY_VALUE_RE");
    // which lines may match what, read in one pass (Gates): each rule (B-EQEQ
    // reads the line with its strings emptied, not a part of the file: any
    // line may), then hex escapes, char codes and decode calls
    let decode = decode_re(ctx);
    let mut needs: Vec<Option<Vec<&Need>>> =
        active.iter().map(|a| if a.kind == Kind::EqEq { None } else { a.rule.re.needs() }).collect();
    let (g_hex, g_charcode, g_decode) = (needs.len(), needs.len() + 1, needs.len() + 2);
    needs.push(need_of(hex_escape));
    needs.push(need_of(p.re("CHARCODE_RE")));
    needs.push(need_of(&decode));
    let gates = Gates::new(ctx, &needs);
    let b64_filter = written_for(p, "B64_BLOB_RE", B64_BLOB_TEXT);
    let b64_plain_max = p.usize("_B64_PLAIN_MAX");
    let b64_period_max = p.usize("_B64_PERIOD_MAX");
    let entropy_filter = written_for(p, "ENTROPY_VALUE_RE", ENTROPY_VALUE_TEXT);
    let js_name = if lang == Lang::Js { "js" } else { "py" };
    let join = Join::new(p);
    let offscreen_min = p.usize("_OFFSCREEN_MIN"); // (offscreen_code reads no shorter line)
    let preview = |t: &[u32]| -> PyStr {
        let max = p.usize("PREVIEW_MAX");
        if t.len() <= max {
            t.to_vec()
        } else {
            let mut v = t[..max - 3].to_vec();
            v.extend(pystr::u("..."));
            v
        }
    };
    let js_or_py = matches!(lang, Lang::Js | Lang::Py);
    let project = !opts.dep;
    let long_line = p.usize("LONG_LINE");
    let longline = RuleText::of(p, "_LONGLINE_RULE");
    let pipe_shell = RuleText::of(p, "_PIPE_SHELL_RULE");
    for i in 0..ctx.len() {
        let line = ctx.line(i);
        if line.is_empty() || is_blank(line) {
            // no rule or family matches blanks alone; only the length rule applies
            if project && line.len() > long_line {
                out.push(Finding::new(longline.clone(), i + 1, None));
            }
            continue;
        }
        let mline = ctx.mline(i);
        let own_text = ctx.mline_differs(i); // its match text is not a part of the file's text
        let cm = ctx.cmask[i];
        for (j, a) in active.iter().enumerate() {
            if cm && !a.on_comments {
                continue;
            }
            let r = a.rule;
            let mut col = if !own_text && !gates.may(i, j) {
                None
            } else if a.kind == Kind::EqEq {
                r.re.search(&string_lit.sub(mline, &pystr::u("\"\""), 0)).map(|s| s.0)
            } else {
                r.re.search(mline).map(|s| s.0)
            };
            if col.is_none() && a.kind == Kind::EvalDecode && !cm {
                col = joined_eval_decode(ctx, &join, i, &r.re);
            }
            let col = match col {
                None => continue,
                Some(c) => c,
            };
            if let Some(need) = &r.need {
                if need.search(mline).is_none() {
                    continue;
                }
            }
            if let Some(skip) = &r.skip {
                if skip.search(mline).is_some() {
                    continue;
                }
            }
            if a.kind == Kind::Token && !token_has_material(ctx, &r.re, mline, i) {
                continue;
            }
            if a.kind == Kind::Token || a.kind == Kind::Secret {
                secret_lines.insert(i);
            }
            out.push(Finding::new(r.text.clone(), i + 1, Some(col)));
        }
        if project && line.len() > long_line {
            out.push(Finding::new(longline.clone(), i + 1, None));
        }
        // obfuscation
        let hidden_text = if gates.may(i, g_hex) { hex_hidden_text(p, line) } else { None };
        if let Some(h) = hidden_text {
            let mut rule = hexstr_text.clone();
            rule.msg = findings::format(&hexstr_text.msg, &[("preview", Arg::S(preview(&h)))]);
            if danger.search(&h).is_some() {
                rule.sev = pystr::u("CRITICAL");
                rule.why = p.text("_HEXSTR_DANGER_WHY");
            }
            let col = hex_escape.search(line).map(|m| m.start());
            out.push(Finding::new(rule, i + 1, col));
        } else if let Some((name, col)) = hex_hidden_name(p, line) {
            let mut rule = hexstr_name.clone();
            rule.msg = findings::format(&hexstr_name.msg, &[("name", Arg::S(name))]);
            out.push(Finding::new(rule, i + 1, Some(col)));
        }
        if js_or_py && !cm {
            let code = ctx.mcode(i);
            if !pystr::is_ascii(code) {
                if let Some(f) = lookalike_name(p, &ctx.names_code(i), lang, &word_in) {
                    let mut rule = lookalike.clone();
                    if !f.critical {
                        rule.sev = pystr::u("MAJOR");
                    }
                    let where_ = if f.other { p.text("_LOOKALIKE_OTHER") } else { Vec::new() };
                    rule.msg = findings::format(
                        &lookalike.msg,
                        &[
                            ("name", Arg::S(f.name)),
                            ("skeleton", Arg::S(f.skeleton)),
                            ("where", Arg::S(where_)),
                            ("detail", Arg::S(f.detail)),
                        ],
                    );
                    out.push(Finding::new(rule, i + 1, Some(f.col)));
                }
            }
            if project && runs_download_through_shell(p, code) {
                let col = p.re("_EXEC_CALL_RE").search(code).map(|m| m.start());
                out.push(Finding::new(pipe_shell.clone(), i + 1, col));
            }
        }
        if !pystr::is_ascii(line) {
            if let Some((col, run)) = hidden_unicode_run(p, line) {
                let runs = *runs_code.get_or_init(|| p.re("_HIDDEN_EXEC_RE").search(content).is_some());
                let tag_start = p.text("_TAG_START")[0];
                let tag_end = p.text("_TAG_END")[0];
                let tags = run.iter().any(|&c| (tag_start..=tag_end).contains(&c));
                let varsel = run.iter().any(|&c| !(tag_start..=tag_end).contains(&c));
                let what = p.map_text("_HIDDEN_UNICODE_WHAT", if tags && varsel { "both" } else if tags { "tags" } else { "selectors" });
                let mut rule = hidden.clone();
                let template = if runs { p.text("_HIDDEN_UNICODE_RUNS_MSG") } else { hidden.msg.clone() };
                rule.msg = findings::format(&template, &[("n", Arg::I(run.len() as i64)), ("what", Arg::S(what))]);
                if runs {
                    rule.sev = pystr::u("CRITICAL");
                }
                out.push(Finding::new(rule, i + 1, Some(col)));
            }
        }
        if lang == Lang::Js && gates.may(i, g_charcode) {
            if let Some(col) = charcode_col(p, line) {
                out.push(Finding::new(charcode.clone(), i + 1, Some(col)));
            }
        }
        if !b64_filter || line.len() >= 202 {
            if let Some(col) = b64_blob_col(b64_re, line, b64_plain_max, b64_period_max) {
                if !pystr::contains(line, "sourceMappingURL") {
                    out.push(Finding::new(b64.clone(), i + 1, Some(col)));
                }
            }
        }
        if js_or_py && line.len() > offscreen_min {
            if let Some((col, blanks, hidden_text, runs)) = signs::offscreen_code(p, line, js_name) {
                if !is_blank(&ctx.names_code(i)) {
                    let mut rule = offscreen.clone();
                    rule.msg = findings::format(
                        &offscreen.msg,
                        &[("blanks", Arg::I(blanks as i64)), ("preview", Arg::S(preview(&hidden_text)))],
                    );
                    if runs {
                        rule.sev = pystr::u("CRITICAL");
                        rule.why = p.text("_OFFSCREEN_RUNS_WHY");
                    }
                    out.push(Finding::new(rule, i + 1, Some(col)));
                }
            }
        }
        // high-entropy literals (the literal before the skip words: core asks
        // both, in the other order, and a finding needs the two answers)
        if !cm && !secret_lines.contains(&i) && (!entropy_filter || entropy_value_possible(line)) {
            if let Some(em) = entropy_re.search(line) {
                if let Some(v) = em.group(1) {
                    if secret_skip.search(line).is_none() && snippets.secrets().contains(v) {
                        out.push(Finding::new(entropy.clone(), i + 1, Some(em.start_of(1) as usize)));
                    }
                }
            }
        }
    }
    // file-level: javascript-obfuscator's identifiers
    if lang == Lang::Js {
        let obf: Vec<&[u32]> = p.re("OBF_IDENT_RE").finditer(content).map(|m| m.group0()).collect();
        let distinct: HashSet<&[u32]> = obf.iter().copied().collect();
        if distinct.len() >= p.usize("OBF_IDENT_MIN") {
            let first = pystr::find(content, obf[0], 0).unwrap_or(0);
            let line = pystr::count_char(content, '\n' as u32, 0, first) + 1;
            let col = first - pystr::rfind_char(content, '\n' as u32, 0, first).map(|x| x + 1).unwrap_or(0);
            let mut rule = RuleText::of(p, "_OBF_IDENT_RULE");
            rule.msg = findings::format(&rule.msg, &[("n", Arg::I(distinct.len() as i64))]);
            out.push(Finding::new(rule, line, Some(col)));
        }
    }
    if js_or_py {
        let at = signs::self_publish_at(p, content);
        if at >= 0 {
            let at = at as usize;
            let line = pystr::count_char(content, '\n' as u32, 0, at) + 1;
            let col = at - pystr::rfind_char(content, '\n' as u32, 0, at).map(|x| x + 1).unwrap_or(0);
            out.push(Finding::new(RuleText::of(p, "_SELF_PUBLISH_RULE"), line, Some(col)));
        }
    }
    if opts.dep {
        let eval_decode = rules(p).iter().find(|r| is(&r.text.id, "SC-EVAL-DECODE")).map(|r| r.text.clone()).unwrap_or_default();
        dep_decode_flow(ctx, &eval_decode, &mut out, &decode, &gates, g_decode);
        return out;
    }
    // project mode: the rules matched against the whole text (match text),
    // reported once per line; the SQL statements without WHERE are core's
    // linear pass, not theirs
    let skip = p.strs("_SQL_NOWHERE_SKIP");
    let mut mcontent: Option<PyStr> = None;
    let mut starts: Vec<usize> = Vec::new();
    for (rule, langs, re) in text_rules(p) {
        let re = match re {
            Some(r) => r,
            None => continue,
        };
        if !lang_str.as_ref().map(|l| langs.contains(l)).unwrap_or(false) || skip.contains(&rule.id) {
            continue;
        }
        let text = mcontent.get_or_insert_with(|| {
            let parts: Vec<&[u32]> = (0..ctx.len()).map(|k| ctx.mline(k)).collect();
            let joined = pystr::join(&['\n' as u32], &parts);
            starts = std::iter::once(0)
                .chain(joined.iter().enumerate().filter(|(_, &ch)| ch == '\n' as u32).map(|(k, _)| k + 1))
                .collect();
            joined
        });
        let mut last: Option<usize> = None;
        for m in re.finditer(text) {
            let line_no = starts.partition_point(|&s| s <= m.start());
            if last == Some(line_no) {
                continue;
            }
            last = Some(line_no);
            out.push(Finding::new(rule.clone(), line_no, Some(m.start() - starts[line_no - 1])));
        }
    }
    out
}
