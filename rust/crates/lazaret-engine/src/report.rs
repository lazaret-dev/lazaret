//! Reports (0.1.9, BR-7 step 4 (c)): the JSON, SARIF, HTML and terminal forms of a scan's result, and the
//! sanitizers terminal output goes through. Core's `json_renderer`, `sarif_report` and `sarif_renderer`,
//! `html_report` and `print_report`, and the npm package's `jsonReportChunks`, `sarifReport`, `htmlReportChunks` and
//! `printReport` each made them, in Python and in JavaScript (npm's HTML page held the JSON in a `<pre>`, and its
//! terminal summary was a shorter one of its own); `sanitize_term`, `sanitize_term_line` and `safe_excerpt` were
//! written in both too. The engine makes them for both packages, as core made them, so both write the same bytes:
//!
//! * JSON as Python's `json.dumps(…, indent=2)` writes it: every character outside ASCII a `\u` escape, a float as
//!   Python's `repr` writes it (a result's `metrics.dupPct` is one, whatever the package sent);
//! * SARIF 2.1.0: the rules in the order of their first finding, each finding's location a percent-encoded
//!   reference below `%SRCROOT%` or a `file:` URI, as `pathlib`'s `as_uri` writes one on the package's OS;
//! * HTML: core's page (the gate, the cards, the findings by file, every finding with its snippet);
//! * the terminal summary: core's (the gate, the ratings, the counts, the findings by file, colored on a terminal).
//!
//! A report can hold a million findings, more than one JavaScript string holds, so each form is made in pieces: a
//! frame (`report_json`, `sarif_frame`, `html_frame`, `text_frame`: the text before and after the findings) and the
//! findings, a batch at a time (`report_items`, `sarif_items`, `html_items`, `text_items`), which the packages write
//! as they come. What stays each package's: the time, the project's path, whether its output is a terminal, the
//! files it writes.

use crate::json::{self, Value};
use crate::manifest::pyval::float_repr;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use crate::unicode;

const DOT: u32 = 0xB7; // '·'
const ELLIPSIS: u32 = 0x2026; // '…'

// ---- the terminal sanitizers ----------------------------------------------------------------------------------

fn is_bidi(c: u32) -> bool {
    (0x202A..=0x202E).contains(&c) || (0x2066..=0x2069).contains(&c)
}

/// What `sanitize_term` maps to '·': the C0 controls but TAB and LF, CR, DEL, the C1 controls and the bidi
/// controls (core's `_SANITIZE_TERM_CHARS`).
fn term_unsafe(c: u32) -> bool {
    c <= 0x08 || c == 0x0B || c == 0x0C || (0x0D..=0x1F).contains(&c) || (0x7F..=0x9F).contains(&c) || is_bidi(c)
}

/// core.sanitize_term: terminal-control characters become '·' (a line break stays one).
pub fn sanitize_term(s: &[u32]) -> PyStr {
    s.iter().map(|&c| if term_unsafe(c) { DOT } else { c }).collect()
}

/// core.sanitize_term_line: sanitize_term for a value printed inside one line, its line breaks '·' too.
pub fn sanitize_term_line(s: &[u32]) -> PyStr {
    s.iter().map(|&c| if term_unsafe(c) || c == 0x0A || c == 0x2028 || c == 0x2029 { DOT } else { c }).collect()
}

/// core.safe_excerpt: a source line for the terminal, its tabs spaces, stripped, the first `width` characters
/// (Python's slice: a negative width counts from the end) with everything not printable '·', and '…' when cut.
pub fn safe_excerpt(text: &[u32], width: i64) -> PyStr {
    let tabbed: PyStr = text.iter().map(|&c| if c == 0x09 { 0x20 } else { c }).collect();
    let t = pystr::strip(&tabbed);
    if t.is_empty() {
        return Vec::new();
    }
    let mut out: PyStr = pystr::slice(t, 0, width.clamp(isize::MIN as i64, isize::MAX as i64) as isize)
        .iter()
        .map(|&c| {
            if c == 0x20 || (0x20..0x7F).contains(&c) || (c > 0xA0 && unicode::is_printable(c) && !is_bidi(c)) {
                c
            } else {
                DOT
            }
        })
        .collect();
    if (t.len() as i64) > width {
        out.push(ELLIPSIS);
    }
    out
}

// ---- Python's str() of a value, and its truth --------------------------------------------------------------

/// Python's str() of a JSON value as the package had it (None, True, a float's repr, a list's repr …).
pub fn py_str(v: &Value) -> PyStr {
    match v {
        Value::Str(s) => s.clone(),
        other => py_repr(other),
    }
}

fn py_repr(v: &Value) -> PyStr {
    match v {
        Value::Null => pystr::u("None"),
        Value::Bool(b) => pystr::u(if *b { "True" } else { "False" }),
        Value::Int(i) => pystr::u(&i.to_string()),
        Value::Float(f) => pystr::u(&float_repr(*f, false)),
        Value::Str(s) => crate::findings::py_repr(s),
        Value::Raw(s) => pystr::u(s),
        Value::Arr(items) => {
            let mut out = pystr::u("[");
            for (k, x) in items.iter().enumerate() {
                if k > 0 {
                    out.extend(pystr::u(", "));
                }
                out.extend(py_repr(x));
            }
            out.push(']' as u32);
            out
        }
        Value::Obj(items) => {
            let mut out = pystr::u("{");
            for (k, (key, x)) in items.iter().enumerate() {
                if k > 0 {
                    out.extend(pystr::u(", "));
                }
                out.extend(crate::findings::py_repr(key));
                out.extend(pystr::u(": "));
                out.extend(py_repr(x));
            }
            out.push('}' as u32);
            out
        }
    }
}

/// Python's truth of a value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Int(i)) => *i != 0,
        Some(Value::Float(f)) => *f != 0.0,
        Some(Value::Str(s)) => !s.is_empty(),
        Some(Value::Arr(a)) => !a.is_empty(),
        Some(Value::Obj(o)) => !o.is_empty(),
        Some(Value::Raw(s)) => !s.is_empty(),
    }
}

fn s(v: &str) -> PyStr {
    pystr::u(v)
}

/// `format(x, ">n")` / `format(x, "<n")` of a str: padded with spaces to n code points.
fn rjust(t: &[u32], n: usize) -> PyStr {
    let mut out = vec![0x20; n.saturating_sub(t.len())];
    out.extend_from_slice(t);
    out
}
fn ljust(t: &[u32], n: usize) -> PyStr {
    let mut out = t.to_vec();
    out.resize(t.len().max(n), 0x20);
    out
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key)
}

fn get_str(v: &Value, key: &str) -> PyStr {
    get(v, key).map(py_str).unwrap_or_else(|| s("None"))
}

// ---- JSON as json.dumps(indent=2) writes it ---------------------------------------------------------------------

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// `v` as Python's json.dumps(v, indent=2) writes it, starting at `level` (its first line not indented).
pub fn pretty(out: &mut String, v: &Value, level: usize) {
    match v {
        Value::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&float_repr(*f, false));
            }
        }
        Value::Arr(items) if !items.is_empty() => {
            out.push('[');
            for (k, x) in items.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, level + 1);
                pretty(out, x, level + 1);
            }
            out.push('\n');
            indent(out, level);
            out.push(']');
        }
        Value::Obj(items) if !items.is_empty() => {
            out.push('{');
            for (k, (key, x)) in items.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, level + 1);
                json::write_str(out, key);
                out.push_str(": ");
                pretty(out, x, level + 1);
            }
            out.push('\n');
            indent(out, level);
            out.push('}');
        }
        other => json::write_into(out, other),
    }
}

/// Where the findings go in a frame: the text before and after them, written with none in their place.
const SLOT: &str = "\u{1}lazaret-items\u{1}"; // (a control character no string writes unescaped)

/// One step into a document: a key or an index.
pub enum Step {
    Key(&'static str),
    Index(usize),
}

/// `doc` with the array at `path` taken out (head, tail): the findings that go there are written between, `count`
/// of them (report_items' text at `path.len() + 1`). Without the array, all of `doc` is the head.
pub fn frame(mut doc: Value, path: &[Step], count: usize) -> (String, String) {
    let found = {
        let mut at: Option<&mut Value> = Some(&mut doc);
        for step in path {
            at = match (at, step) {
                (Some(Value::Obj(items)), Step::Key(k)) => {
                    let key = pystr::u(k);
                    items.iter_mut().find(|(n, _)| *n == key).map(|(_, v)| v)
                }
                (Some(Value::Arr(items)), Step::Index(i)) => items.get_mut(*i),
                _ => None,
            };
        }
        match at {
            Some(v @ Value::Arr(_)) => {
                *v = Value::Raw(SLOT.to_string());
                true
            }
            _ => false,
        }
    };
    let mut text = String::new();
    pretty(&mut text, &doc, 0);
    if !found {
        return (text, String::new());
    }
    let at = text.find(SLOT).unwrap_or(text.len());
    let (before, after) = (&text[..at], text.get(at + SLOT.len()..).unwrap_or(""));
    let mut head = before.to_string();
    head.push('[');
    let mut tail = String::new();
    if count > 0 {
        tail.push('\n');
        indent(&mut tail, path.len());
    }
    tail.push(']');
    tail.push_str(after);
    (head, tail)
}

/// Items of an array a frame left out, at `level` (the frame's path's length + 1): `first` when no item of it was
/// written before.
pub fn items_text(items: &[Value], level: usize, first: bool) -> String {
    let mut out = String::new();
    for (k, x) in items.iter().enumerate() {
        if !(first && k == 0) {
            out.push(',');
        }
        out.push('\n');
        indent(&mut out, level);
        pretty(&mut out, x, level);
    }
    out
}

/// A result as the reports write it: its `metrics.dupPct` a float (the npm package's 12 is Python's 12.0), and its
/// `perFile` in `order` (the files of its findings in the order of their first finding: what Python's dict keeps
/// and a JavaScript object does not, which puts a name like "7" first) when the package gives one.
fn as_written(mut doc: Value, order: Option<&[Value]>) -> Value {
    if let Value::Obj(items) = &mut doc {
        for (k, v) in items.iter_mut() {
            if pystr::eq(k, "metrics") {
                if let Value::Obj(m) = v {
                    for (mk, mv) in m.iter_mut() {
                        if pystr::eq(mk, "dupPct") {
                            if let Value::Int(i) = mv {
                                *mv = Value::Float(*i as f64);
                            }
                        }
                    }
                }
            } else if pystr::eq(k, "perFile") {
                if let (Value::Obj(files), Some(order)) = (v, order) {
                    let mut rest: Vec<(PyStr, Value)> = std::mem::take(files);
                    let mut sorted = Vec::with_capacity(rest.len());
                    for name in order.iter().filter_map(|n| n.as_str()) {
                        if let Some(at) = rest.iter().position(|(n, _)| n.as_slice() == name) {
                            sorted.push(rest.remove(at));
                        }
                    }
                    sorted.extend(rest);
                    *files = sorted;
                }
            }
        }
    }
    doc
}

/// `doc` with `prefix`'s members first ([key, value] pairs), the rest of its own after them in their order:
/// core's mark_result (the report's marker first, the baseline signature second).
fn with_prefix(doc: Value, prefix: &[Value]) -> Value {
    let mut out: Vec<(PyStr, Value)> = Vec::new();
    for pair in prefix {
        if let Some([Value::Str(k), v]) = pair.as_arr() {
            out.retain(|(n, _)| n != k);
            out.push((k.clone(), v.clone()));
        }
    }
    if let Value::Obj(items) = doc {
        for (k, v) in items {
            if !out.iter().any(|(n, _)| *n == k) {
                out.push((k, v));
            }
        }
    }
    Value::Obj(out)
}

/// The JSON report's frame (core.json_renderer, npm's jsonReportChunks): `doc` (a result, its findings left out,
/// `count` of them) with `prefix` first, the findings' array at "issues" left out.
pub fn json_frame(doc: Value, prefix: &[Value], order: Option<&[Value]>, count: Option<usize>) -> (String, String) {
    let count = count.unwrap_or_else(|| doc.get("issues").and_then(|v| v.as_arr()).map_or(0, |a| a.len()));
    let doc = with_prefix(as_written(doc, order), prefix);
    frame(doc, &[Step::Key("issues")], count)
}

// ---- SARIF 2.1.0 (core.sarif_report) ------------------------------------------------------------------------------

const SARIF_SRCROOT: &str = "%SRCROOT%";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://lazaret.dev";

fn sarif_level(sev: &[u32]) -> &'static str {
    match pystr::to_string(sev).as_str() {
        "BLOCKER" | "CRITICAL" => "error",
        "MAJOR" => "warning",
        _ => "note",
    }
}

/// The rules of `issues` not in `known` (their ids), each as its first finding names it.
pub fn sarif_rules(issues: &[Value], known: &[PyStr]) -> Vec<Value> {
    let mut seen: Vec<PyStr> = known.to_vec();
    let mut out = Vec::new();
    for i in issues {
        let id = i.get("rule").cloned().unwrap_or(Value::Null);
        let key = py_str(&id);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let field = |k: &str| i.get(k).cloned().unwrap_or(Value::Null);
        out.push(Value::obj(vec![
            ("id", id),
            ("name", field("name")),
            ("shortDescription", Value::obj(vec![("text", field("name"))])),
            ("fullDescription", Value::obj(vec![("text", field("why"))])),
            ("help", Value::obj(vec![("text", field("fix"))])),
        ]));
    }
    out
}

/// The text core's `_safe_text` makes of a str: a lone surrogate as its backslash escape.
fn safe_text(t: &[u32]) -> PyStr {
    let mut out = Vec::with_capacity(t.len());
    for &c in t {
        if (0xD800..=0xDFFF).contains(&c) {
            out.extend(pystr::u(&format!("\\u{:04x}", c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn utf8_of(c: u32, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    match char::from_u32(c) {
        Some(ch) => out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes()),
        None if (0xDC80..=0xDCFF).contains(&c) => out.push((c - 0xDC00) as u8), // os.fsencode's surrogateescape
        None => out.extend_from_slice(format!("\\u{:04x}", c).as_bytes()),
    }
}

/// urllib.parse.quote of a str's UTF-8 bytes, '/' safe.
fn quote(t: &[u32]) -> String {
    let mut bytes = Vec::new();
    for &c in t {
        utf8_of(c, &mut bytes);
    }
    let mut out = String::new();
    for b in bytes {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Is `p` absolute on the package's OS (os.path.isabs)?
fn is_abs(p: &[u32], windows: bool) -> bool {
    if !windows {
        return p.first() == Some(&('/' as u32));
    }
    let sep = |c: Option<&u32>| matches!(c, Some(&0x5C) | Some(&0x2F));
    (p.len() >= 3 && char::from_u32(p[0]).is_some_and(|c| c.is_ascii_alphabetic()) && p[1] == ':' as u32 && sep(p.get(2)))
        || (sep(p.first()) && sep(p.get(1)))
}

/// pathlib's as_uri() of an absolute path on the package's OS.
fn file_uri(p: &[u32], windows: bool) -> String {
    if !windows {
        return format!("file://{}", quote(p));
    }
    let p: PyStr = p.iter().map(|&c| if c == 0x5C { 0x2F } else { c }).collect();
    if p.len() >= 2 && char::from_u32(p[0]).is_some_and(|c| c.is_ascii_alphabetic()) && p[1] == ':' as u32 {
        return format!("file:///{}{}", pystr::to_string(&p[..2]), quote(&p[2..]));
    }
    format!("file:{}", quote(&p))
}

/// core.sarif_uri: a report path as a SARIF artifactLocation.
fn sarif_location(file: &[u32], windows: bool) -> Value {
    let p = safe_text(file);
    if is_abs(&p, windows) {
        return Value::obj(vec![("uri", Value::str(&file_uri(&p, windows)))]);
    }
    let p: PyStr = if windows { p.iter().map(|&c| if c == 0x5C { 0x2F } else { c }).collect() } else { p };
    Value::obj(vec![("uri", Value::str(&quote(&p))), ("uriBaseId", Value::str(SARIF_SRCROOT))])
}

/// The scan root as SARIF's %SRCROOT% (core._root_uri: its as_uri(), ending in '/').
fn root_uri(root: &[u32], windows: bool) -> String {
    let mut uri = file_uri(root, windows);
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

/// int(i.get("line") or 1), at least 1 (as core reads a finding's line for SARIF).
fn sarif_line(v: Option<&Value>) -> i64 {
    let n = match v {
        Some(Value::Int(i)) if *i != 0 => *i,
        Some(Value::Bool(true)) => 1,
        Some(Value::Float(f)) if *f != 0.0 && f.is_finite() => f.trunc() as i64,
        Some(Value::Str(t)) if !t.is_empty() => pystr::to_string(pystr::strip(t)).replace('_', "").parse().unwrap_or(1),
        _ => 1,
    };
    n.max(1)
}

/// Why a finding a signed baseline holds does not count (N-15).
const ACCEPTED_WHY: &str = "Accepted: held by a baseline whose signature verifies with LAZARET_BASELINE_KEY";

/// One finding as a SARIF result; `rules`: the rule ids in their index order.
fn sarif_result(i: &Value, rules: &[PyStr], windows: bool) -> Value {
    let id = i.get("rule").cloned().unwrap_or(Value::Null);
    let index = rules.iter().position(|r| *r == py_str(&id)).unwrap_or(0) as i64;
    let file = i.get("file").map(py_str).unwrap_or_default();
    let mut out = vec![
        ("ruleId", id),
        ("ruleIndex", Value::Int(index)),
        ("level", Value::str(sarif_level(&get_str(i, "sev")))),
        ("message", Value::obj(vec![("text", i.get("msg").cloned().unwrap_or(Value::Null))])),
        (
            "locations",
            Value::Arr(vec![Value::obj(vec![(
                "physicalLocation",
                Value::obj(vec![
                    ("artifactLocation", sarif_location(&file, windows)),
                    ("region", Value::obj(vec![("startLine", Value::Int(sarif_line(i.get("line"))))])),
                ]),
            )])]),
        ),
    ];
    if truthy(i.get("accepted")) {
        // a finding a signed baseline accepted (N-15: baseline.rs)
        out.push((
            "suppressions",
            Value::Arr(vec![Value::obj(vec![
                ("kind", Value::str("external")),
                ("status", Value::str("accepted")),
                ("justification", Value::str(ACCEPTED_WHY)),
            ])]),
        ));
    }
    if let Some(v @ Value::Obj(_)) = i.get("verified") {
        out.push(("properties", Value::obj(vec![("verified", v.clone())])));
    }
    Value::obj(out)
}

/// The SARIF log's frame: its rules, the scan root as %SRCROOT%, the package's version, a github: or gitlab:
/// scan's repository and commit; `marker` the report's marker ([key, value]) in a property bag, first.
pub fn sarif_frame(
    rules: Vec<Value>,
    root: &[u32],
    windows: bool,
    version: Value,
    source: Option<&Value>,
    marker: Option<&Value>,
    count: usize,
) -> (String, String) {
    let mut run = vec![
        (
            "tool",
            Value::obj(vec![(
                "driver",
                Value::obj(vec![
                    ("name", Value::str("Lazaret")),
                    ("version", version),
                    ("informationUri", Value::str(INFORMATION_URI)),
                    ("rules", Value::Arr(rules)),
                ]),
            )]),
        ),
        (
            "originalUriBaseIds",
            Value::obj(vec![(SARIF_SRCROOT, Value::obj(vec![("uri", Value::str(&root_uri(root, windows)))]))]),
        ),
        ("results", Value::Arr(Vec::new())),
    ];
    if let Some(src) = source {
        let (uri, commit) = (src.get("uri"), src.get("commit"));
        if matches!(src, Value::Obj(_)) && truthy(uri) && truthy(commit) {
            run.push((
                "versionControlProvenance",
                Value::Arr(vec![Value::obj(vec![
                    ("repositoryUri", uri.cloned().unwrap_or(Value::Null)),
                    ("revisionId", commit.cloned().unwrap_or(Value::Null)),
                    ("mappedTo", Value::obj(vec![("uriBaseId", Value::str(SARIF_SRCROOT))])),
                ])]),
            ));
        }
    }
    let mut doc = Vec::new();
    if let Some(m) = marker.and_then(|m| m.as_arr()).filter(|m| m.len() == 2) {
        if let Value::Str(k) = &m[0] {
            doc.push((s("properties"), Value::Obj(vec![(k.clone(), m[1].clone())])));
        }
    }
    doc.push((s("$schema"), Value::str(SARIF_SCHEMA)));
    doc.push((s("version"), Value::str("2.1.0")));
    doc.push((s("runs"), Value::Arr(vec![Value::obj(run)])));
    frame(Value::Obj(doc), &[Step::Key("runs"), Step::Index(0), Step::Key("results")], count)
}

/// A batch of findings as SARIF results (report_items' text at the results' level).
pub fn sarif_items(issues: &[Value], rules: &[PyStr], windows: bool, first: bool) -> String {
    let results: Vec<Value> = issues.iter().map(|i| sarif_result(i, rules, windows)).collect();
    items_text(&results, 4, first)
}

// ---- the HTML report (core.html_report) ---------------------------------------------------------------------

const HTML_CSS: &str = r#"
:root{--border:#dde3ea;--muted:#6b7785;--navy:#1a2634;
--blocker:#c4160f;--critical:#d4380d;--major:#e08a00;--minor:#8a9aa8;--info:#4b9fd5;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f3f5f7;color:#1f2933}
header{background:var(--navy);color:#fff;padding:14px 24px}
header .logo{font-size:17px;font-weight:700}header .logo span{color:#4b9fd5}
header .meta{font-size:12px;color:#9fb0c0;margin-top:2px}
.wrap{max-width:1150px;margin:0 auto;padding:20px 24px 60px}
.panel{background:#fff;border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:18px}
h2{font-size:15px;margin-bottom:12px}
.gate{display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.gate-badge{font-size:15px;font-weight:700;color:#fff;padding:8px 18px;border-radius:6px}
.gate-badge.pass{background:#00aa55}.gate-badge.fail{background:#d4380d}
.cond{font-size:12px;padding:4px 10px;border-radius:12px;border:1px solid var(--border)}
.cond.ok{border-color:#bfe8d2;background:#eefaf3;color:#0a7a44}
.cond.ko{border-color:#f3c4bb;background:#fdf0ee;color:#b32d16}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.card .num{font-size:26px;font-weight:700}.card .lbl{font-size:12px;color:var(--muted);margin-top:2px}
.rating{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:50%;
color:#fff;font-size:13px;font-weight:700;margin-left:8px;vertical-align:3px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 10px;border-bottom:1px solid var(--border);text-align:left}
th{color:var(--muted);font-size:12px}td.n{text-align:right;font-variant-numeric:tabular-nums}
details{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;background:#fff;overflow:hidden}
summary{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}summary:hover{background:#f7f9fb}
.sev{font-size:10.5px;font-weight:700;color:#fff;padding:2px 8px;border-radius:10px;flex-shrink:0}
.sev.BLOCKER{background:var(--blocker)}.sev.CRITICAL{background:var(--critical)}
.sev.MAJOR{background:var(--major)}.sev.MINOR{background:var(--minor)}.sev.INFO{background:var(--info)}
.itype{font-size:11px;color:var(--muted);border:1px solid var(--border);padding:1px 8px;border-radius:10px;flex-shrink:0}
.imsg{flex:1;font-weight:600;font-size:13px}
.iloc{font:11.5px var(--mono);color:var(--muted);flex-shrink:0}
.body{border-top:1px solid var(--border);padding:12px 14px;background:#fbfcfd}
.snippet{font:12px/1.6 var(--mono);background:#1a2634;color:#d7e0ea;border-radius:6px;padding:10px 0;margin-bottom:10px;overflow-x:auto}
.snippet .ln{display:flex}.snippet .no{width:52px;text-align:right;padding-right:12px;color:#5d7186;flex-shrink:0}
.snippet .hl{background:#5c2b29}.snippet code{white-space:pre}
.why{margin-bottom:8px}.why b{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.refs{font-size:12px;color:var(--muted)}
footer{max-width:1150px;margin:0 auto;padding:0 24px 30px;font-size:11.5px;color:var(--muted)}
"#;

/// Text built of code points (a lone surrogate in a value stays one: the packages' writers replace it).
#[derive(Default)]
struct Out(PyStr);

impl Out {
    fn s(&mut self, t: &str) -> &mut Self {
        self.0.extend(t.chars().map(|c| c as u32));
        self
    }
    /// html.escape(t, quote=True)
    fn e(&mut self, t: &[u32]) -> &mut Self {
        for &c in t {
            match c {
                0x26 => self.0.extend(s("&amp;")),
                0x3C => self.0.extend(s("&lt;")),
                0x3E => self.0.extend(s("&gt;")),
                0x22 => self.0.extend(s("&quot;")),
                0x27 => self.0.extend(s("&#x27;")),
                c => self.0.push(c),
            }
        }
        self
    }
    /// html.escape(str(v), quote=True)
    fn ev(&mut self, v: Option<&Value>) -> &mut Self {
        let t = v.map(py_str).unwrap_or_else(|| s("None"));
        self.e(&t)
    }
}

fn type_label(t: &[u32]) -> PyStr {
    match pystr::to_string(t).as_str() {
        "VULN" => s("Vulnerability"),
        "HOTSPOT" => s("Security Hotspot"),
        "BUG" => s("Bug"),
        "SMELL" => s("Code Smell"),
        _ => t.to_vec(),
    }
}

fn rating_badge(o: &mut Out, r: &[u32]) {
    let color = match pystr::to_string(r).as_str() {
        "A" => "#00aa55",
        "B" => "#7dc94a",
        "C" => "#f0c000",
        "D" => "#ed7d20",
        _ => "#d4380d",
    };
    o.s(r#"<span class="rating" style="background:"#).s(color).s(r#"">"#).e(r).s("</span>");
}

/// os.path.basename on the package's OS.
fn basename(p: &[u32], windows: bool) -> PyStr {
    let mut start = 0;
    for (k, &c) in p.iter().enumerate() {
        if c == '/' as u32 || (windows && (c == 0x5C || (k == 1 && c == ':' as u32))) {
            start = k + 1;
        }
    }
    p[start..].to_vec()
}

/// The findings a signed baseline accepted (N-15: baseline.rs).
fn accepted_line(doc: &Value) -> PyStr {
    let mut t = s("Accepted by the signed baseline: ");
    t.extend(get_str(doc, "acceptedIssues"));
    t.extend(s(" (supply-chain and cross-file findings the gate does not count)"));
    t
}

/// core.verification_line: what --verify-secrets' providers said.
pub fn verification_line(v: &Value) -> PyStr {
    let empty = Value::Obj(Vec::new());
    let cred = v.get("credentials").unwrap_or(&empty);
    let found = v.get("findings").unwrap_or(&empty);
    let n = |o: &Value, k: &str| o.get(k).cloned().unwrap_or(Value::Int(0));
    let parts = [n(cred, "live"), n(cred, "rejected"), n(cred, "unknown")];
    let asked = if parts.iter().any(|x| matches!(x, Value::Float(_))) {
        let sum: f64 = parts
            .iter()
            .map(|x| match x {
                Value::Int(i) => *i as f64,
                Value::Float(f) => *f,
                Value::Bool(b) => *b as i64 as f64,
                _ => 0.0,
            })
            .sum();
        float_repr(sum, false)
    } else {
        let sum: i64 = parts
            .iter()
            .map(|x| match x {
                Value::Int(i) => *i,
                Value::Bool(b) => *b as i64,
                _ => 0,
            })
            .sum();
        sum.to_string()
    };
    let mut out = s("Secrets verified  ");
    out.extend(py_str(&parts[0]));
    out.extend(s(" live, "));
    out.extend(py_str(&parts[1]));
    out.extend(s(" rejected, "));
    out.extend(py_str(&parts[2]));
    out.extend(s(&format!(" unknown (of {asked} asked about)")));
    if let Some(nv) = found.get("notVerified").filter(|x| truthy(Some(x))) {
        out.extend(s("; "));
        out.extend(py_str(nv));
        let one = matches!(nv, Value::Int(1) | Value::Bool(true)) || matches!(nv, Value::Float(f) if *f == 1.0);
        out.extend(s(&format!(" secret finding{} no provider can be asked about", if one { "" } else { "s" })));
    }
    out
}

/// The HTML report's frame (core.html_report; with `marker` ([key, value]), the provenance meta tag core's
/// _html_report_marked puts before the viewport's): `doc` a result, `count` findings left out.
pub fn html_frame(doc: &Value, count: usize, windows: bool, marker: Option<&Value>, order: Option<&[Value]>) -> (PyStr, PyStr) {
    let empty = Value::Obj(Vec::new());
    let doc = as_written(doc.clone(), order);
    let m = doc.get("metrics").unwrap_or(&empty);
    let ct = doc.get("counts").unwrap_or(&empty);
    let rt = doc.get("ratings").unwrap_or(&empty);
    let pass = truthy(doc.get("pass"));
    let project = get_str(&doc, "project");
    let mut o = Out::default();
    o.s("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"UTF-8\">\n");
    if let Some([k, v]) = marker.and_then(|m| m.as_arr()) {
        o.s("<meta name=\"").e(&py_str(k)).s("\" content=\"").e(&py_str(v)).s("\">\n");
    }
    o.s("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>Lazaret Report — ");
    o.e(&basename(&project, windows));
    o.s("</title>\n<style>").s(HTML_CSS).s("</style></head><body>\n");
    o.s("<header><div class=\"logo\">Laza<span>ret</span> · Project Report</div>\n<div class=\"meta\">");
    o.e(&project).s(" · scanned ").ev(doc.get("scannedAt")).s("</div></header>\n<div class=\"wrap\">\n");
    o.s("<div class=\"panel\"><div class=\"gate\"><div class=\"gate-badge ").s(if pass { "pass" } else { "fail" });
    o.s("\">").s(if pass { "Quality Gate: Passed" } else { "Quality Gate: Failed" }).s("</div>");
    for c in doc.get("conditions").and_then(|c| c.as_arr()).unwrap_or(&[]) {
        let ok = truthy(c.get("ok"));
        o.s("<span class=\"cond ").s(if ok { "ok" } else { "ko" }).s("\">").s(if ok { "✓" } else { "✗" }).s(" ");
        o.ev(c.get("label")).s("</span>");
    }
    o.s("</div>\n<div class=\"cards\">");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(ct.get("VULN"));
    rating_badge(&mut o, &get_str(rt, "security"));
    o.s("</div><div class=\"lbl\">Vulnerabilities · Security</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(ct.get("HOTSPOT"));
    o.s("</div><div class=\"lbl\">Security Hotspots</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(ct.get("BUG"));
    rating_badge(&mut o, &get_str(rt, "reliability"));
    o.s("</div><div class=\"lbl\">Bugs · Reliability</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(ct.get("SMELL"));
    rating_badge(&mut o, &get_str(rt, "maintainability"));
    o.s("</div><div class=\"lbl\">Code Smells · Maintainability</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(m.get("dupPct")).s("%</div><div class=\"lbl\">Duplication");
    if truthy(m.get("dupLeftOut")) {
        o.s(" (").ev(m.get("dupLeftOut")).s(" lines of Go and Rust not measured)");
    }
    o.s("</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(m.get("ncloc"));
    o.s("</div><div class=\"lbl\">Lines of Code</div></div>");
    o.s("\n<div class=\"card\"><div class=\"num\">").ev(m.get("files"));
    o.s("</div><div class=\"lbl\">Files Scanned</div></div>");
    o.s("</div>");
    if let Some(v @ Value::Obj(_)) = doc.get("verification") {
        o.s("<p class=\"verified\">").e(&verification_line(v)).s("</p>");
    }
    if truthy(doc.get("acceptedIssues")) {
        o.s("<p class=\"accepted\">").e(&accepted_line(&doc)).s("</p>");
    }
    o.s("</div>\n<div class=\"panel\"><h2>Issues by file</h2>");
    let mut files: Vec<(PyStr, Value)> = doc.get("perFile").and_then(|p| p.as_obj()).map(|o| o.to_vec()).unwrap_or_default();
    let key = |v: &Value| match v {
        Value::Int(i) => -(*i as f64),
        Value::Float(f) => -*f,
        Value::Bool(b) => -(*b as i64 as f64),
        _ => 0.0,
    };
    files.sort_by(|a, b| key(&a.1).partial_cmp(&key(&b.1)).unwrap_or(std::cmp::Ordering::Equal));
    if files.is_empty() {
        o.s("<p>No issues in any file. 🎉</p>");
    } else {
        o.s("<table><tr><th>File</th><th style='text-align:right'>Issues</th></tr>");
        for (f, n) in &files {
            o.s("<tr><td>").e(f).s("</td><td class='n'>").ev(Some(n)).s("</td></tr>");
        }
        o.s("</table>");
    }
    o.s(&format!("</div>\n<div class=\"panel\"><h2>All issues ({count})</h2>"));
    let mut t = Out::default();
    if count == 0 {
        t.s("<p>No issues found. 🎉</p>");
    }
    t.s("</div>\n</div>\n<footer>Generated by Lazaret CLI. Pattern- and heuristic-based static analysis — not a substitute ");
    t.s("for a full security audit.</footer>\n</body></html>");
    (o.0, t.0)
}

fn int_of(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Int(i)) => Some(*i),
        Some(Value::Bool(b)) => Some(*b as i64),
        _ => None,
    }
}

/// A batch of findings as the HTML report's items (`first`: none written before).
pub fn html_items(issues: &[Value], first: bool) -> PyStr {
    let mut o = Out::default();
    for (k, i) in issues.iter().enumerate() {
        if !(first && k == 0) {
            o.s("\n");
        }
        let sev = get_str(i, "sev");
        o.s("\n<details><summary><span class=\"sev ").e(&sev).s("\">").e(&sev).s("</span>\n");
        o.s("<span class=\"itype\">").e(&type_label(&get_str(i, "type"))).s("</span>\n");
        if truthy(i.get("accepted")) {
            o.s("<span class=\"itype\">Accepted</span>\n");
        }
        o.s("<span class=\"imsg\">").ev(i.get("msg")).s("</span>\n");
        o.s("<span class=\"iloc\">").ev(i.get("file")).s(":").ev(i.get("line")).s("</span></summary>\n");
        o.s("<div class=\"body\"><div class=\"snippet\">");
        let start = int_of(i.get("snipStart")).unwrap_or(0);
        let line_n = int_of(i.get("line"));
        for (k, l) in i.get("snippet").and_then(|v| v.as_arr()).unwrap_or(&[]).iter().enumerate() {
            let no = start + k as i64;
            o.s("<div class=\"ln").s(if Some(no) == line_n { " hl" } else { "" }).s("\"><span class=\"no\">");
            o.s(&no.to_string()).s("</span><code>");
            let t = py_str(l);
            if t.is_empty() {
                o.s(" ");
            } else {
                o.e(&t);
            }
            o.s("</code></div>");
        }
        o.s("</div>\n<div class=\"why\"><b>Why it matters</b><div>").ev(i.get("why")).s("</div></div>\n");
        o.s("<div class=\"why\"><b>How to fix</b><div>").ev(i.get("fix")).s("</div></div>\n");
        o.s("<div class=\"refs\">Rule ").ev(i.get("rule")).s(" · ").ev(i.get("ref")).s("</div></div></details>");
    }
    o.0
}

// ---- the terminal summary (core.print_report) ---------------------------------------------------------------

fn c(color: bool, code: &str, t: &[u32]) -> PyStr {
    if !color {
        return t.to_vec();
    }
    let mut out = s(&format!("\x1b[{code}m"));
    out.extend_from_slice(t);
    out.extend(s("\x1b[0m"));
    out
}

fn sev_color(sev: &[u32]) -> &'static str {
    match pystr::to_string(sev).as_str() {
        "BLOCKER" => "41;97",
        "CRITICAL" => "31",
        "MAJOR" => "33",
        "MINOR" => "36",
        "INFO" => "34",
        _ => "0",
    }
}

fn sev_order(sev: &[u32]) -> u8 {
    match pystr::to_string(sev).as_str() {
        "BLOCKER" => 0,
        "CRITICAL" => 1,
        "MAJOR" => 2,
        "MINOR" => 3,
        "INFO" => 4,
        _ => 5,
    }
}

fn line(out: &mut PyStr, t: PyStr) {
    out.extend(t);
    out.push(0x0A);
}

/// The terminal summary's frame: what is printed before the findings (the gate, the ratings, the counts and, when
/// findings follow, their heading) and after them.
pub fn text_frame(doc: &Value, count: usize, quiet: bool, color: bool) -> (PyStr, PyStr) {
    let empty = Value::Obj(Vec::new());
    let doc = as_written(doc.clone(), None);
    let m = doc.get("metrics").unwrap_or(&empty);
    let ct = doc.get("counts").unwrap_or(&empty);
    let rt = doc.get("ratings").unwrap_or(&empty);
    let mut out = Vec::new();
    line(&mut out, Vec::new());
    let mut title = s("Lazaret scan — ");
    title.extend(sanitize_term_line(&get_str(&doc, "project")));
    line(&mut out, c(color, "1", &title));
    let configs = if truthy(m.get("configFiles")) {
        let mut t = s(" · ");
        t.extend(get_str(m, "configFiles"));
        t.extend(s(" config files"));
        t
    } else {
        Vec::new()
    };
    let left = if truthy(m.get("dupLeftOut")) {
        let mut t = s(" (");
        t.extend(get_str(m, "dupLeftOut"));
        t.extend(s(" lines of Go and Rust not measured)"));
        t
    } else {
        Vec::new()
    };
    let mut t = s("  ");
    t.extend(get_str(m, "files"));
    t.extend(s(" files · "));
    t.extend(get_str(m, "ncloc"));
    t.extend(s(" lines of code · "));
    t.extend(get_str(m, "dupPct"));
    t.extend(s("% duplication"));
    t.extend(left);
    t.extend(configs);
    line(&mut out, t);
    line(&mut out, Vec::new());
    let gate = if truthy(doc.get("pass")) { c(color, "42;30", &s(" PASSED ")) } else { c(color, "41;97", &s(" FAILED ")) };
    let mut t = s("  Quality gate: ");
    t.extend(gate);
    line(&mut out, t);
    for cond in doc.get("conditions").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let mark = if truthy(cond.get("ok")) { c(color, "32", &s("✓")) } else { c(color, "31", &s("✗")) };
        let mut t = s("    ");
        t.extend(mark);
        t.push(0x20);
        t.extend(sanitize_term_line(&get_str(cond, "label")));
        line(&mut out, t);
    }
    line(&mut out, Vec::new());
    let row = |label: &str, n: PyStr, rest: &str, rating: Option<PyStr>| -> PyStr {
        let mut t = s(label);
        t.extend(rjust(&n, 4));
        t.extend(s(rest));
        if let Some(r) = rating {
            t.extend(r);
        }
        t
    };
    line(&mut out, row("  Vulnerabilities   ", get_str(ct, "VULN"), "   Security rating        ", Some(get_str(rt, "security"))));
    line(&mut out, row("  Security hotspots ", get_str(ct, "HOTSPOT"), "", None));
    line(&mut out, row("  Bugs              ", get_str(ct, "BUG"), "   Reliability rating     ", Some(get_str(rt, "reliability"))));
    line(&mut out, row("  Code smells       ", get_str(ct, "SMELL"), "   Maintainability rating ", Some(get_str(rt, "maintainability"))));
    let sc = doc.get("supplyChain").map(py_str).unwrap_or_else(|| s("0"));
    line(&mut out, row("  Supply-chain      ", sc, "   (obfuscation/install-hook indicators)", None));
    if truthy(doc.get("crossFile")) {
        let xf = c(color, "31", &get_str(&doc, "crossFile"));
        line(&mut out, row("  Cross-file flows  ", xf, "   (interprocedural taint)", None));
    }
    if truthy(m.get("depFiles")) {
        let mut t = s("  Dependency files scanned: ");
        t.extend(get_str(m, "depFiles"));
        line(&mut out, t);
    }
    if doc.get("newIssues").is_some() {
        let mut t = s("  New issues vs baseline: ");
        t.extend(c(color, "1", &get_str(&doc, "newIssues")));
        line(&mut out, t);
    }
    if truthy(doc.get("acceptedIssues")) {
        let mut t = s("  ");
        t.extend(accepted_line(&doc));
        line(&mut out, t);
    }
    if let Some(v @ Value::Obj(_)) = doc.get("verification") {
        let mut t = s("  ");
        t.extend(verification_line(v));
        line(&mut out, t);
    }
    line(&mut out, Vec::new());
    let mut tail = Vec::new();
    if !quiet && count > 0 {
        line(&mut out, c(color, "1", &s("  Issues")));
        line(&mut tail, Vec::new());
    }
    (out, tail)
}

/// The order the terminal summary lists findings in: by file (code point by code point), severity and line, as
/// Python's sort of (file, SEV_ORDER[sev], line), stable. `rows`: [file, sev, line] per finding.
pub fn text_order(rows: &[Value]) -> Vec<usize> {
    let key = |r: &Value| -> (PyStr, u8, i64) {
        let a = r.as_arr().unwrap_or(&[]);
        let file = a.first().map(py_str).unwrap_or_default();
        let sev = a.get(1).map(py_str).unwrap_or_default();
        let line = match a.get(2) {
            Some(Value::Int(i)) => *i,
            Some(Value::Float(f)) => *f as i64,
            Some(Value::Bool(b)) => *b as i64,
            _ => 0,
        };
        (file, sev_order(&sev), line)
    };
    let keys: Vec<(PyStr, u8, i64)> = rows.iter().map(key).collect();
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&a, &b| keys[a].cmp(&keys[b]));
    order
}

/// core.issue_excerpt: a finding's flagged line for the terminal; `shown` the line as read (--show-secrets).
pub fn issue_excerpt(p: &Pack, i: &Value, width: i64, shown: Option<&Value>, redact: bool) -> PyStr {
    if let Some(Value::Str(raw)) = shown {
        return safe_excerpt(raw, width);
    }
    let snip = i.get("snippet").and_then(|v| v.as_arr()).unwrap_or(&[]);
    let Some(line) = int_of(i.get("line")) else { return Vec::new() };
    let start = int_of(i.get("snipStart")).unwrap_or(line);
    let idx = line - start;
    let Some(Value::Str(flagged)) = usize::try_from(idx).ok().and_then(|k| snip.get(k)) else { return Vec::new() };
    let rule = get_str(i, "rule");
    if redact && p.strs("SECRET_RULES").iter().any(|r| *r == rule) {
        return s("[redacted]");
    }
    safe_excerpt(flagged, width)
}

/// A batch of findings, in text_order's order, as the terminal summary lists them: a file's name before its first
/// finding (`file`: the file of the finding printed last), each finding's line, severity, rule and message, then
/// its flagged line. Returns the text and the file of its last finding.
pub fn text_items(
    p: &Pack,
    issues: &[Value],
    mut file: Option<PyStr>,
    color: bool,
    width: i64,
    redact: bool,
    shown: &[Value],
) -> (PyStr, Option<PyStr>) {
    let mut out = Vec::new();
    for (k, i) in issues.iter().enumerate() {
        let f = get_str(i, "file");
        if file.as_ref() != Some(&f) {
            let mut t = s("\n  ");
            t.extend(c(color, "4", &sanitize_term_line(&f)));
            line(&mut out, t);
            file = Some(f);
        }
        let sev = get_str(i, "sev");
        let sev_txt = ljust(&sev, 8);
        let rule = sanitize_term_line(&get_str(i, "rule"));
        let lno = ljust(&get_str(i, "line"), 5);
        let mut prefix_len = 0;
        let mut t = s("    L");
        t.extend(lno.iter());
        t.push(0x20);
        prefix_len += t.len() + sev_txt.len();
        t.extend(c(color, sev_color(&sev), &sev_txt));
        t.extend(s(" ["));
        t.extend(rule.iter());
        t.extend(s("] "));
        prefix_len += 2 + rule.len() + 2;
        t.extend(sanitize_term_line(&get_str(i, "msg")));
        line(&mut out, t);
        let ex = issue_excerpt(p, i, width, shown.get(k), redact);
        if !ex.is_empty() {
            let mut t = vec![0x20; prefix_len];
            let mut shown_ex = s("» ");
            shown_ex.extend(ex);
            t.extend(c(color, "2", &shown_ex));
            line(&mut out, t);
        }
    }
    (out, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py(v: &str) -> Value {
        json::parse_str(v).unwrap()
    }

    #[test]
    fn pretty_is_json_dumps_indent_2() {
        let mut out = String::new();
        pretty(&mut out, &py(r#"{"a": [1, 2.5, "é\u0001", {}], "b": {}, "c": [], "d": 1e-05, "e": 12.0}"#), 0);
        assert_eq!(
            out,
            "{\n  \"a\": [\n    1,\n    2.5,\n    \"\\u00e9\\u0001\",\n    {}\n  ],\n  \"b\": {},\n  \"c\": [],\n  \"d\": 1e-05,\n  \"e\": 12.0\n}"
        );
    }

    #[test]
    fn a_frame_and_its_items_are_the_whole_document() {
        let doc = py(r#"{"x": 1, "issues": [{"a": 1}, {"b": [2]}], "y": "z"}"#);
        let mut whole = String::new();
        pretty(&mut whole, &doc, 0);
        let items = doc.get("issues").unwrap().as_arr().unwrap().to_vec();
        let (head, tail) = frame(doc.clone(), &[Step::Key("issues")], items.len());
        let joined = format!("{head}{}{}{tail}", items_text(&items[..1], 2, true), items_text(&items[1..], 2, false));
        assert_eq!(joined, whole);
        let (head, tail) = frame(py(r#"{"issues": [], "y": 1}"#), &[Step::Key("issues")], 0);
        assert_eq!(format!("{head}{tail}"), "{\n  \"issues\": [],\n  \"y\": 1\n}");
        let (head, tail) = frame(py(r#"{"pass": true}"#), &[Step::Key("issues")], 0);
        assert_eq!((head.as_str(), tail.as_str()), ("{\n  \"pass\": true\n}", ""));
    }

    #[test]
    fn sanitizers() {
        assert_eq!(pystr::to_string(&sanitize_term(&pystr::u("a\x1b[31m\nb\u{202e}\t"))), "a·[31m\nb·\t");
        assert_eq!(pystr::to_string(&sanitize_term_line(&pystr::u("a\nb\u{2028}"))), "a·b·");
        assert_eq!(pystr::to_string(&safe_excerpt(&pystr::u("\t x = 1 \x07 "), 100)), "x = 1 ·");
        assert_eq!(pystr::to_string(&safe_excerpt(&pystr::u("abcdef"), 3)), "abc…");
        assert_eq!(pystr::to_string(&safe_excerpt(&pystr::u("abcdef"), -2)), "abcd…");
        assert_eq!(safe_excerpt(&pystr::u("   "), 3), Vec::<u32>::new());
    }

    #[test]
    fn sarif_locations() {
        let loc = |p: &str, w: bool| json::write(&sarif_location(&pystr::u(p), w));
        assert_eq!(loc("my dir/a#1%2.py", false), r#"{"uri":"my%20dir/a%231%252.py","uriBaseId":"%SRCROOT%"}"#);
        assert_eq!(loc("/abs/x y.py", false), r#"{"uri":"file:///abs/x%20y.py"}"#);
        assert_eq!(loc("C:\\a b\\x.py", true), r#"{"uri":"file:///C:/a%20b/x.py"}"#);
        assert_eq!(loc("\\\\srv\\share\\x.py", true), r#"{"uri":"file://srv/share/x.py"}"#);
        assert_eq!(loc("sub\\x.py", true), r#"{"uri":"sub/x.py","uriBaseId":"%SRCROOT%"}"#);
        assert_eq!(root_uri(&pystr::u("/p"), false), "file:///p/");
    }
}
