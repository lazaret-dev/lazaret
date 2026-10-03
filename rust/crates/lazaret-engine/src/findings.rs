//! Findings as core makes them (`mk_issue`, `cap_issues`): a rule's texts,
//! the flagged line and column, the snippet of the lines around it (each
//! clipped, secrets redacted: PEM key blocks whole, the credential patterns,
//! the file's high-entropy literals), and the per-file dedupe and cap.
//!
//! The texts come from the pack (core's rule dicts; a message with {fields}
//! is a str.format template, filled here as Python fills it, `!r` with
//! Python's repr of a str).

use crate::json::Value;
use crate::pack::Pack;
use crate::pyre::Regex;
use crate::pystr::{self, PyStr};
use crate::token::TokenPattern;
use crate::unicode;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};

/// A rule's texts (core's rule dicts: id, name, type, sev, msg, why, fix, ref).
#[derive(Clone, Debug, Default)]
pub struct RuleText {
    pub id: PyStr,
    pub name: PyStr,
    pub typ: PyStr,
    pub sev: PyStr,
    pub msg: PyStr,
    pub why: PyStr,
    pub fix: PyStr,
    pub ref_: PyStr,
}

fn map_text(v: &Value, key: &str) -> PyStr {
    v.get("map")
        .and_then(|m| m.get(key))
        .and_then(|x| x.get("value"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

impl RuleText {
    /// From the pack's form of a rule dict ({"map": {"id": {"value": …}, …}}).
    pub fn from_value(v: &Value) -> RuleText {
        RuleText {
            id: map_text(v, "id"),
            name: map_text(v, "name"),
            typ: map_text(v, "type"),
            sev: map_text(v, "sev"),
            msg: map_text(v, "msg"),
            why: map_text(v, "why"),
            fix: map_text(v, "fix"),
            ref_: map_text(v, "ref"),
        }
    }

    /// A module-level rule dict of core, by name.
    pub fn of(p: &Pack, name: &str) -> RuleText {
        p.derived(name, RuleText::from_value).clone()
    }
}

/// One finding before its snippet is made.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: RuleText,
    /// 1-based.
    pub line: usize,
    /// The match's column on the flagged line (centres its snippet window).
    pub col: Option<usize>,
    /// Q-CAPPED: how many findings it stands for, and their type.
    pub omitted: Option<(usize, PyStr)>,
}

impl Finding {
    pub fn new(rule: RuleText, line: usize, col: Option<usize>) -> Finding {
        Finding { rule, line, col, omitted: None }
    }
}

// ---------------- str.format and repr ----------------

pub enum Arg {
    S(PyStr),
    I(i64),
}

/// Python's repr() of a str.
pub fn py_repr(s: &[u32]) -> PyStr {
    let has_single = s.contains(&('\'' as u32));
    let has_double = s.contains(&('"' as u32));
    let quote = if has_single && !has_double { '"' as u32 } else { '\'' as u32 };
    let mut out = Vec::with_capacity(s.len() + 2);
    out.push(quote);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex = |out: &mut Vec<u32>, c: u32, n: usize| {
        for k in (0..n).rev() {
            out.push(HEX[((c >> (4 * k)) & 0xF) as usize] as u32);
        }
    };
    for &c in s {
        if c == quote || c == '\\' as u32 {
            out.push('\\' as u32);
            out.push(c);
        } else if c == '\t' as u32 {
            out.extend(pystr::u("\\t"));
        } else if c == '\n' as u32 {
            out.extend(pystr::u("\\n"));
        } else if c == '\r' as u32 {
            out.extend(pystr::u("\\r"));
        } else if c < 0x20 || c == 0x7F {
            out.extend(pystr::u("\\x"));
            hex(&mut out, c, 2);
        } else if c < 0x7F || unicode::is_printable(c) {
            out.push(c);
        } else if c <= 0xFF {
            out.extend(pystr::u("\\x"));
            hex(&mut out, c, 2);
        } else if c <= 0xFFFF {
            out.extend(pystr::u("\\u"));
            hex(&mut out, c, 4);
        } else {
            out.extend(pystr::u("\\U"));
            hex(&mut out, c, 8);
        }
    }
    out.push(quote);
    out
}

/// str.format with named fields: {name} and {name!r} (and {{ }}).
pub fn format(template: &[u32], args: &[(&str, Arg)]) -> PyStr {
    let mut out = Vec::with_capacity(template.len() + 16);
    let mut i = 0;
    while i < template.len() {
        let c = template[i];
        if c == '{' as u32 && template.get(i + 1) == Some(&('{' as u32)) {
            out.push(c);
            i += 2;
            continue;
        }
        if c == '}' as u32 && template.get(i + 1) == Some(&('}' as u32)) {
            out.push(c);
            i += 2;
            continue;
        }
        if c != '{' as u32 {
            out.push(c);
            i += 1;
            continue;
        }
        let close = match template[i..].iter().position(|&x| x == '}' as u32) {
            Some(k) => i + k,
            None => panic!("unclosed field in a message template"),
        };
        let field = pystr::to_string(&template[i + 1..close]);
        let (name, conv) = match field.split_once('!') {
            Some((n, cv)) => (n.to_string(), Some(cv.to_string())),
            None => (field.clone(), None),
        };
        let arg = match args.iter().find(|(n, _)| *n == name) {
            Some((_, a)) => a,
            None => panic!("no value for {{{}}} in a message template", name),
        };
        match (arg, conv.as_deref()) {
            (Arg::S(s), None) => out.extend_from_slice(s),
            (Arg::S(s), Some("r")) => out.extend(py_repr(s)),
            (Arg::I(n), None) => out.extend(pystr::u(&n.to_string())),
            _ => panic!("unsupported conversion in a message template"),
        }
        i = close + 1;
    }
    out
}

// ---------------- secret literals and redaction ----------------

/// core.shannon_entropy: -sum(p * log2(p)) over the characters in the order
/// they first appear, summed as this Python's sum() adds floats (plainly
/// before 3.12, with Neumaier's compensation since).
pub fn shannon_entropy(s: &[u32], neumaier: bool) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut order: Vec<u32> = Vec::new();
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for &c in s {
        let e = counts.entry(c).or_insert(0);
        if *e == 0 {
            order.push(c);
        }
        *e += 1;
    }
    let len = s.len() as f64;
    let terms = order.iter().map(|c| {
        let q = counts[c] as f64 / len;
        q * q.log2()
    });
    let mut total: Option<f64> = None;
    let mut comp = 0.0f64;
    for x in terms {
        match total {
            None => total = Some(0.0 + x), // (sum() starts from the int 0)
            Some(t) => {
                if neumaier {
                    let sum = t + x;
                    if t.abs() >= x.abs() {
                        comp += (t - sum) + x;
                    } else {
                        comp += (x - sum) + t;
                    }
                    total = Some(sum);
                } else {
                    total = Some(t + x);
                }
            }
        }
    }
    let mut r = total.unwrap_or(0.0);
    if neumaier && comp != 0.0 && comp.is_finite() {
        r += comp;
    }
    -r
}

/// core.entropy_secretish
pub fn entropy_secretish(v: &[u32], neumaier: bool) -> bool {
    let slash = '/' as u32;
    if v.iter().filter(|&&c| c == slash).count() >= 2
        || v.first() == Some(&slash)
        || v.contains(&(' ' as u32))
        || v.contains(&('\\' as u32))
    {
        return false;
    }
    let core: Vec<u32> = v.iter().copied().filter(|&c| c != '_' as u32 && c != '-' as u32 && c != '.' as u32).collect();
    if !core.is_empty() && core.iter().all(|&c| unicode::is_alpha(c)) {
        return false;
    }
    if !(v.iter().any(|&c| unicode::is_digit(c)) || v.iter().any(|&c| c == '+' as u32 || c == '=' as u32)) {
        return false;
    }
    shannon_entropy(v, neumaier) > 4.0
}

/// core._SecretLiterals: the high-entropy literals S-ENTROPY would flag in
/// one file, redacted wherever they appear.
pub struct SecretLiterals {
    lits: HashSet<PyStr>,
    by_prefix: HashMap<PyStr, Vec<PyStr>>,
}

impl SecretLiterals {
    pub fn new<'a>(p: &Pack, lines: impl Iterator<Item = &'a [u32]>, neumaier: bool) -> SecretLiterals {
        let skip = p.re("SECRET_SKIP_RE");
        let value = p.re("ENTROPY_VALUE_RE");
        let mut lits = HashSet::new();
        let mut found: Vec<&[u32]> = Vec::new();
        for line in lines {
            if !line.iter().any(|&c| c == '=' as u32 || c == ':' as u32) {
                continue;
            }
            // (the literals first, the skip words only for a line with some:
            // core asks in the other order, and a literal needs both answers)
            found.clear();
            for m in value.finditer(line) {
                if let Some(v) = m.group(1) {
                    if entropy_secretish(v, neumaier) {
                        found.push(v);
                    }
                }
            }
            if !found.is_empty() && skip.search(line).is_none() {
                lits.extend(found.iter().map(|v| v.to_vec()));
            }
        }
        let mut by_prefix: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
        for lit in &lits {
            by_prefix.entry(lit[..20.min(lit.len())].to_vec()).or_default().push(lit.clone());
        }
        SecretLiterals { lits, by_prefix }
    }

    pub fn contains(&self, v: &[u32]) -> bool {
        self.lits.contains(v)
    }

    pub fn redact(&self, p: &Pack, text: &[u32]) -> PyStr {
        if self.lits.is_empty() {
            return text.to_vec();
        }
        let redacted = p.text("REDACTED");
        let mut hits: Vec<(usize, usize)> = Vec::new();
        for m in p.re("_SECRET_RUN_RE").finditer(text) {
            let (base, end) = (m.start(), m.end());
            let run = &text[base..end];
            if self.lits.contains(run) {
                hits.push((base, end));
                continue;
            }
            if run.len() >= 20 {
                for q in 0..run.len() - 19 {
                    if let Some(cands) = self.by_prefix.get(&run[q..q + 20]) {
                        for lit in cands {
                            if run[q..].starts_with(lit) {
                                hits.push((base + q, base + q + lit.len()));
                            }
                        }
                    }
                }
            }
        }
        if hits.is_empty() {
            return text.to_vec();
        }
        hits.sort_unstable();
        let mut out = Vec::with_capacity(text.len());
        let mut pos = 0;
        for (a, b) in hits {
            if b <= pos {
                continue;
            }
            out.extend_from_slice(&text[pos..a.max(pos)]);
            out.extend_from_slice(&redacted);
            pos = b;
        }
        out.extend_from_slice(&text[pos..]);
        out
    }
}

/// core._SECRET_LINE_PATTERNS, read once.
enum LinePattern {
    Token(TokenPattern),
    Re(Regex),
}

fn line_patterns(p: &Pack) -> &[LinePattern] {
    p.derived("_SECRET_LINE_PATTERNS", |v| {
        v.get("list")
            .and_then(|l| l.as_arr())
            .unwrap_or(&[])
            .iter()
            .map(|x| {
                if x.get("token").is_some() {
                    LinePattern::Token(TokenPattern::from_value(x).expect("a token pattern"))
                } else {
                    let src = x.get("re").and_then(|s| s.as_str()).unwrap_or(&[]).to_vec();
                    let flags = x.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
                    LinePattern::Re(
                        Regex::new(&src, crate::pyre::flags_from_letters(&flags)).expect("a redaction pattern compiles"),
                    )
                }
            })
            .collect::<Vec<_>>()
    })
}

/// core._redact_context_line
pub fn redact_context_line(p: &Pack, line: &[u32]) -> PyStr {
    let redacted = p.text("REDACTED");
    let mut out = line.to_vec();
    for pat in line_patterns(p) {
        out = match pat {
            LinePattern::Token(t) => t.sub(&redacted, &out),
            LinePattern::Re(r) => r.sub(&out, &redacted, 0),
        };
    }
    out
}

/// core._pem_block_lines
pub fn pem_block_lines(p: &Pack, lines: &[&[u32]]) -> HashSet<usize> {
    let begin = p.re("_PEM_BEGIN_RE");
    let end = p.re("_PEM_END_RE");
    let mut out = HashSet::new();
    let mut inside = false;
    for (k, line) in lines.iter().enumerate() {
        if inside {
            out.insert(k);
            if pystr::contains(line, "-----END") && end.search(line).is_some() {
                inside = false;
            }
        } else if pystr::contains(line, "PRIVATE KEY-----") {
            inside = match begin.search(line) {
                Some(m) => end.search_at(line, m.end() as isize, line.len() as isize).is_none(),
                None => false,
            };
        }
    }
    out
}

/// core.clip_snippet_line
pub fn clip_snippet_line(p: &Pack, text: &[u32], col: Option<usize>) -> PyStr {
    let max = p.usize("SNIPPET_MAX");
    if text.len() <= max {
        return text.to_vec();
    }
    let lead = p.usize("SNIPPET_LEAD");
    let ellipsis = p.text("ELLIPSIS");
    let mut start = match col {
        None => 0,
        Some(c) => c.saturating_sub(lead),
    };
    start = start.min(text.len() - (max - 1));
    let head: &[u32] = if start > 0 { &ellipsis } else { &[] };
    let end = start + max - head.len();
    let mut out = head.to_vec();
    if end < text.len() {
        out.extend_from_slice(&text[start..end - 1]);
        out.extend_from_slice(&ellipsis);
    } else {
        out.extend_from_slice(&text[start..]);
    }
    out
}

/// The snippets of one file's findings (mk_issue with a scan_file context):
/// the file's lines, and what redaction reads, computed once.
pub struct Snippets<'a> {
    p: &'a Pack,
    lines: Vec<&'a [u32]>,
    redact: bool,
    neumaier: bool,
    secrets: OnceCell<SecretLiterals>,
    pem: OnceCell<HashSet<usize>>,
    red: RefCell<HashMap<usize, PyStr>>,
}

impl<'a> Snippets<'a> {
    pub fn new(p: &'a Pack, lines: Vec<&'a [u32]>, redact: bool, neumaier: bool) -> Snippets<'a> {
        Snippets { p, lines, redact, neumaier, secrets: OnceCell::new(), pem: OnceCell::new(), red: RefCell::new(HashMap::new()) }
    }

    /// The file's entropy literals (_Redactor.secrets).
    pub fn secrets(&self) -> &SecretLiterals {
        self.secrets.get_or_init(|| SecretLiterals::new(self.p, self.lines.iter().copied(), self.neumaier))
    }

    /// Line k as any snippet may show it (_Redactor.redacted).
    fn redacted(&self, k: usize) -> PyStr {
        if let Some(r) = self.red.borrow().get(&k) {
            return r.clone();
        }
        let pem = self.pem.get_or_init(|| pem_block_lines(self.p, &self.lines));
        let r = if pem.contains(&k) {
            self.p.text("REDACTED")
        } else {
            self.secrets().redact(self.p, &redact_context_line(self.p, self.lines[k]))
        };
        self.red.borrow_mut().insert(k, r.clone());
        r
    }

    /// core._redact_text, with this file's literals.
    fn redact_text(&self, text: &[u32]) -> PyStr {
        if text.contains(&('\n' as u32)) {
            let parts = pystr::split_char(text, '\n' as u32);
            let pem = pem_block_lines(self.p, &parts);
            let mut out = Vec::with_capacity(text.len());
            for (k, l) in parts.iter().enumerate() {
                if k > 0 {
                    out.push('\n' as u32);
                }
                if pem.contains(&k) {
                    out.extend(self.p.text("REDACTED"));
                } else {
                    out.extend(self.secrets().redact(self.p, &redact_context_line(self.p, l)));
                }
            }
            return out;
        }
        self.secrets().redact(self.p, &redact_context_line(self.p, text))
    }

    /// The message a finding shows (redacted as mk_issue redacts it).
    pub fn shown_msg(&self, f: &Finding) -> PyStr {
        if self.redact {
            self.redact_text(&f.rule.msg)
        } else {
            f.rule.msg.clone()
        }
    }

    /// The issue core's mk_issue makes: [rule, name, type, sev, msg, why, fix,
    /// ref, line, snippet, snipStart] (+ [omitted, omittedType] for Q-CAPPED).
    pub fn issue(&self, f: &Finding) -> Value {
        let p = self.p;
        let n = self.lines.len();
        let line_no = f.line;
        let start = line_no.saturating_sub(3);
        let stop = n.min(line_no + 2);
        let flag = line_no as isize - 1;
        let msg = self.shown_msg(f);
        let redact = self.redact && flag >= 0 && (flag as usize) < n;
        let secret_rule = p.strs("SECRET_RULES").iter().any(|s| *s == f.rule.id);
        let mut snippet = Vec::with_capacity(stop.saturating_sub(start));
        for k in start..stop {
            let flagged = k as isize == flag;
            let l: PyStr = if redact {
                if flagged && secret_rule {
                    let mut t = pystr::replace(&p.text("REDACT_PLACEHOLDER"), &pystr::u("{RULE}"), &f.rule.id);
                    t.extend(pystr::u(&format!(" ({} chars)", self.lines[k].len())));
                    t
                } else {
                    self.redacted(k)
                }
            } else {
                self.lines[k].to_vec()
            };
            snippet.push(Value::Str(clip_snippet_line(p, &l, if flagged { f.col } else { None })));
        }
        let mut v = vec![
            Value::Str(f.rule.id.clone()),
            Value::Str(f.rule.name.clone()),
            Value::Str(f.rule.typ.clone()),
            Value::Str(f.rule.sev.clone()),
            Value::Str(msg),
            Value::Str(f.rule.why.clone()),
            Value::Str(f.rule.fix.clone()),
            Value::Str(f.rule.ref_.clone()),
            Value::Int(line_no as i64),
            Value::Arr(snippet),
            Value::Int(start as i64 + 1),
        ];
        if let Some((count, typ)) = &f.omitted {
            v.push(Value::Int(*count as i64));
            v.push(Value::Str(typ.clone()));
        }
        Value::Arr(v)
    }
}

/// core.cap_issues (for one file's findings, before their snippets): the
/// repeats of (rule, line, msg) dropped, then at most CAP_PER_RULE findings
/// per rule that is not a security rule, the rest replaced by one Q-CAPPED
/// note per capped rule.
pub fn cap(p: &Pack, snippets: &Snippets, findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<(PyStr, usize, PyStr)> = HashSet::new();
    let mut kept: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        if seen.insert((f.rule.id.clone(), f.line, snippets.shown_msg(&f))) {
            kept.push(f);
        }
    }
    let never = p.strs("_NEVER_CAPPED_PREFIXES");
    let limit = p.usize("CAP_PER_RULE");
    let mut order: Vec<usize> = (0..kept.len()).collect();
    order.sort_by_key(|&k| kept[k].line); // (stable, as sorted())
    let mut counts: HashMap<PyStr, usize> = HashMap::new();
    let mut dropped: HashSet<usize> = HashSet::new();
    let mut omitted: Vec<(PyStr, usize, usize, PyStr)> = Vec::new(); // rule, count, first line, type
    for k in order {
        let f = &kept[k];
        if never.iter().any(|pre| f.rule.id.starts_with(pre)) {
            continue;
        }
        let c = counts.entry(f.rule.id.clone()).or_insert(0);
        *c += 1;
        if *c > limit {
            dropped.insert(k);
            match omitted.iter_mut().find(|o| o.0 == f.rule.id) {
                Some(o) => o.1 += 1,
                None => omitted.push((f.rule.id.clone(), 1, f.line, f.rule.typ.clone())),
            }
        }
    }
    if dropped.is_empty() {
        return kept;
    }
    let mut out: Vec<Finding> = kept.into_iter().enumerate().filter(|(k, _)| !dropped.contains(k)).map(|(_, f)| f).collect();
    let base = RuleText::of(p, "_CAPPED_RULE");
    for (rid, count, first, typ) in omitted {
        let mut rule = base.clone();
        rule.msg = format(&base.msg, &[("n", Arg::I(count as i64)), ("rule", Arg::S(rid.clone()))]);
        rule.fix = format(&base.fix, &[("rule", Arg::S(rid))]);
        out.push(Finding { rule, line: first, col: None, omitted: Some((count, typ)) });
    }
    out
}
