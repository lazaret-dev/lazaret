//! A scan's result (0.1.9, BR-7 step 4 (a)): what core's `build_result`, `regrade` and `compute_metrics` and the npm
//! package's `buildResult`, `regrade` and `computeMetrics` each made of a scan's findings and files, in Python and
//! in JavaScript, held equal by the parity tests. The packages keep what is theirs: the project's path, the time,
//! and asking the engine for each file's line metrics (`file_metrics`, or a project scan's own `lineMetrics`).
//!
//! * `metrics`: a project's files, lines of code, comment lines and duplication, from each file's line metrics
//!   (metrics.rs): the windows of six lines of code that occur twice or more across the project's own files (its
//!   dependencies' are not counted), as a share of the lines whose duplication is measured, rounded to a tenth as
//!   Python's `round` rounds; `dupLeftOut`, the lines of code of the languages it does not measure (Go, Rust: N-13).
//!   A file whose line metrics the engine could not give counts its non-blank lines as code (review B3), its text
//!   pinned to Unicode 13.0 and split at "\n" alone, and its windows are not compared.
//! * `result`: the findings in their order (severity, then file by code point, then line: Python's sort, stable),
//!   the counts by type, the security, reliability and maintainability ratings, the gate's six conditions and the
//!   gate, the supply-chain indicators (an SC-* finding above INFO; a CI file's hardening check only when CRITICAL:
//!   HARDENING_RULES) and cross-file flows (X-*), and the findings by file.
//! * `regrade`: a result graded again after its findings changed (`--verify-secrets`): their order, the counts, the
//!   security and reliability ratings, the two conditions on severities, and the gate.
//!
//! A finding comes as `[rule, type, severity, file, line, omitted, omittedType]` (the last two a Q-CAPPED note's:
//! the rating counts the smells it stands for), and the answer gives the findings' order (`order`, indices into
//! what was sent) rather than the findings, which are each package's to keep as they are.

use std::collections::HashMap;

use crate::json::Value;
use crate::pack::Pack;
use crate::pystr;

/// The finding types, in the order the counts are written (core's TYPE_LABEL).
const TYPES: [&str; 4] = ["VULN", "HOTSPOT", "BUG", "SMELL"];

/// What the result reads of a finding.
pub struct Finding {
    pub rule: Vec<u32>,
    pub typ: Vec<u32>,
    pub sev: Vec<u32>,
    pub file: Vec<u32>,
    pub line: i64,
    pub omitted: Option<i64>,
    pub omitted_type: Option<Vec<u32>>,
}

/// One file, as `metrics` reads it.
pub struct FileIn {
    pub dep: bool,
    pub lang: Option<String>,
    pub got: Got,
}

/// A file's line metrics, or its text when the engine could not give them.
pub enum Got {
    Metrics { ncloc: usize, comments: usize, measured: usize, windows: Vec<u32> },
    Text(Vec<u32>),
}

/// Python's `round(x, 1)`: the decimal nearest to x's exact binary value, a tie to the even digit (Rust's exact
/// formatting rounds the same way), read back as the nearest double.
pub fn round1(x: f64) -> f64 {
    format!("{x:.1}").parse().unwrap_or(x)
}

pub fn metrics(files: &[FileIn]) -> Value {
    let own: Vec<&FileIn> = files.iter().filter(|f| !f.dep).collect();
    let (mut ncloc, mut comments, mut measured, mut left_out) = (0usize, 0usize, 0usize, 0usize);
    // a window's key (its 16 hexadecimal digits) -> where each occurrence starts, in the order first seen
    let mut starts: HashMap<&[u32], Vec<usize>> = HashMap::new();
    for f in &own {
        let dup_lang = crate::metrics::measured_lang(f.lang.as_deref());
        match &f.got {
            Got::Text(text) => {
                // every non-blank line is code
                let mut t = text.clone();
                if !pystr::is_ascii(&t) {
                    crate::filectx::pin(&mut t);
                }
                let lines = t.split(|&c| c == '\n' as u32).filter(|l| !pystr::strip(l).is_empty()).count();
                ncloc += lines;
                if dup_lang {
                    measured += lines;
                } else {
                    left_out += lines;
                }
            }
            Got::Metrics { ncloc: n, comments: c, measured: m, windows } => {
                ncloc += n;
                if !dup_lang {
                    left_out += n;
                }
                comments += c;
                for (k, w) in windows.chunks(16).enumerate() {
                    starts.entry(w).or_default().push(measured + k);
                }
                measured += m;
            }
        }
    }
    let mut dup = vec![false; measured + 6];
    let mut count = 0usize;
    for at in starts.values() {
        if at.len() > 1 {
            for &a in at {
                for j in a..a + 6 {
                    if j < dup.len() && !dup[j] {
                        dup[j] = true;
                        count += 1;
                    }
                }
            }
        }
    }
    let dup_pct = if measured > 0 { round1((100 * count) as f64 / measured as f64) } else { 0.0 };
    Value::obj(vec![
        ("files", Value::Int(own.len() as i64)),
        ("depFiles", Value::Int((files.len() - own.len()) as i64)),
        ("ncloc", Value::Int(ncloc as i64)),
        ("comments", Value::Int(comments as i64)),
        ("dupPct", Value::Float(dup_pct)),
        ("dupLeftOut", Value::Int(left_out as i64)),
    ])
}

fn is(s: &[u32], t: &str) -> bool {
    pystr::eq(s, t)
}

/// The findings' order: severity (SEV_ORDER), then file by code point, then line; stable.
fn order(p: &Pack, issues: &[Finding]) -> Result<Vec<usize>, String> {
    let sev_order = sev_order(p);
    let mut keys = Vec::with_capacity(issues.len());
    for (k, i) in issues.iter().enumerate() {
        let s = sev_order.iter().find(|(name, _)| *name == i.sev).map(|&(_, n)| n);
        match s {
            Some(n) => keys.push((n, k)),
            None => return Err(format!("finding {k}: no severity {}", pystr::to_string(&i.sev))),
        }
    }
    keys.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| issues[a.1].file.cmp(&issues[b.1].file)).then(issues[a.1].line.cmp(&issues[b.1].line)));
    Ok(keys.into_iter().map(|(_, k)| k).collect())
}

fn sev_order(p: &Pack) -> &Vec<(Vec<u32>, i64)> {
    p.derived("SEV_ORDER", |raw| {
        raw.get("map").and_then(|m| m.as_obj()).unwrap_or(&[]).iter()
            .filter_map(|(k, v)| v.get("value").and_then(|n| n.as_i64()).map(|n| (k.clone(), n)))
            .collect::<Vec<_>>()
    })
}

/// The worst severity among the findings of `types`, as a rating: BLOCKER E, CRITICAL D, MAJOR C, MINOR B, else A.
fn worst(issues: &[&Finding], types: &[&str]) -> &'static str {
    let has = |sev: &str| issues.iter().any(|i| types.iter().any(|t| is(&i.typ, t)) && is(&i.sev, sev));
    for (sev, rating) in [("BLOCKER", "E"), ("CRITICAL", "D"), ("MAJOR", "C"), ("MINOR", "B")] {
        if has(sev) {
            return rating;
        }
    }
    "A"
}

/// Code smells per hundred lines of code: at most 5 A, 10 B, 20 C, 40 D, else E. The scan's coverage notes
/// (COVERAGE_RULES) are not smells of the code; a Q-CAPPED note counts the smells it stands for, and nothing for
/// bugs, so the rating is what it would be without the cap.
fn maintainability(p: &Pack, issues: &[&Finding], ncloc: usize) -> &'static str {
    let coverage = p.strs("COVERAGE_RULES");
    let mut smells: i64 = 0;
    for i in issues {
        if !is(&i.typ, "SMELL") || coverage.iter().any(|r| *r == i.rule) {
            continue;
        }
        smells += match (is(&i.rule, "Q-CAPPED"), i.omitted) {
            (true, Some(n)) => {
                if i.omitted_type.as_deref().is_some_and(|t| is(t, "SMELL")) {
                    n
                } else {
                    0
                }
            }
            _ => 1,
        };
    }
    let per100 = if ncloc > 0 { (100 * smells) as f64 / ncloc as f64 } else { 0.0 };
    for (limit, rating) in [(5.0, "A"), (10.0, "B"), (20.0, "C"), (40.0, "D")] {
        if per100 <= limit {
            return rating;
        }
    }
    "E"
}

fn cond(label: &str, ok: bool) -> Value {
    Value::obj(vec![("label", Value::str(label)), ("ok", Value::Bool(ok))])
}

/// (the counts by type, the security and reliability ratings, the gate's two conditions on severities).
fn severity_grades(issues: &[&Finding]) -> (Value, Vec<(&'static str, Value)>, Vec<(&'static str, bool)>) {
    let counts = Value::obj(TYPES.iter().map(|t| (*t, Value::Int(issues.iter().filter(|i| is(&i.typ, t)).count() as i64))).collect());
    let ratings = vec![("security", Value::str(worst(issues, &["VULN"]))), ("reliability", Value::str(worst(issues, &["BUG"])))];
    let conds = vec![
        ("No blocker issues", !issues.iter().any(|i| is(&i.sev, "BLOCKER"))),
        ("No critical vulnerabilities", !issues.iter().any(|i| is(&i.typ, "VULN") && (is(&i.sev, "CRITICAL") || is(&i.sev, "BLOCKER")))),
    ];
    (counts, ratings, conds)
}

pub fn result(p: &Pack, issues: &[Finding], files: &[FileIn]) -> Result<Value, String> {
    let ord = order(p, issues)?;
    let sorted: Vec<&Finding> = ord.iter().map(|&k| &issues[k]).collect();
    let m = metrics(files);
    let ncloc = m.get("ncloc").and_then(|v| v.as_i64()).unwrap_or(0) as usize;
    let dup_pct = match m.get("dupPct") {
        Some(Value::Float(f)) => *f,
        _ => 0.0,
    };
    let (counts, mut ratings, sev_conds) = severity_grades(&sorted);
    let maint = maintainability(p, &sorted, ncloc);
    ratings.push(("maintainability", Value::str(maint)));
    let hardening = p.strs("HARDENING_RULES");
    let supply = sorted.iter().filter(|i| {
        pystr::starts_with(&i.rule, "SC-") && !is(&i.sev, "INFO") && (!hardening.iter().any(|r| *r == i.rule) || is(&i.sev, "CRITICAL"))
    }).count();
    let cross_file = sorted.iter().filter(|i| pystr::starts_with(&i.rule, "X-")).count();
    let mut conds: Vec<(&str, bool)> = sev_conds;
    conds.push(("Duplication < 10%", dup_pct < 10.0));
    conds.push(("Maintainability \u{2265} C", matches!(maint, "A" | "B" | "C")));
    conds.push(("No supply-chain indicators", supply == 0));
    conds.push(("No cross-file taint flows", cross_file == 0));
    let mut per_file: Vec<(Vec<u32>, i64)> = Vec::new();
    let mut at: HashMap<&[u32], usize> = HashMap::new();
    for i in &sorted {
        match at.get(i.file.as_slice()) {
            Some(&k) => per_file[k].1 += 1,
            None => {
                at.insert(&i.file, per_file.len());
                per_file.push((i.file.clone(), 1));
            }
        }
    }
    Ok(Value::obj(vec![
        ("order", Value::Arr(ord.iter().map(|&k| Value::Int(k as i64)).collect())),
        ("pass", Value::Bool(conds.iter().all(|c| c.1))),
        ("conditions", Value::Arr(conds.iter().map(|&(l, ok)| cond(l, ok)).collect())),
        ("metrics", m),
        ("counts", counts),
        ("ratings", Value::obj(ratings)),
        ("supplyChain", Value::Int(supply as i64)),
        ("crossFile", Value::Int(cross_file as i64)),
        ("perFile", Value::Obj(per_file.into_iter().map(|(f, n)| (f, Value::Int(n))).collect())),
    ]))
}

/// `conditions`: the result's, as `[label, ok]`; the two on severities take their new values, the others stay.
pub fn regrade(p: &Pack, issues: &[Finding], conditions: &[(Vec<u32>, bool)]) -> Result<Value, String> {
    let ord = order(p, issues)?;
    let sorted: Vec<&Finding> = ord.iter().map(|&k| &issues[k]).collect();
    let (counts, ratings, now) = severity_grades(&sorted);
    let conds: Vec<(Vec<u32>, bool)> = conditions.iter().map(|(label, ok)| {
        let new = now.iter().find(|(l, _)| is(label, l)).map(|&(_, v)| v);
        (label.clone(), new.unwrap_or(*ok))
    }).collect();
    Ok(Value::obj(vec![
        ("order", Value::Arr(ord.iter().map(|&k| Value::Int(k as i64)).collect())),
        ("pass", Value::Bool(conds.iter().all(|c| c.1))),
        ("conditions", Value::Arr(conds.into_iter().map(|(l, ok)| Value::obj(vec![("label", Value::Str(l)), ("ok", Value::Bool(ok))])).collect())),
        ("counts", counts),
        ("ratings", Value::obj(ratings)),
    ]))
}

// ---------------------------------------------------------------- reading a call's arguments

fn text_of(v: &Value) -> Option<Vec<u32>> {
    v.as_str().map(|s| s.to_vec())
}

/// The findings of a call: `[[rule, type, severity, file, line, omitted, omittedType], …]`.
pub fn findings_arg(v: Option<&Value>) -> Result<Vec<Finding>, String> {
    let items = v.and_then(|v| v.as_arr()).ok_or("issues is not a list")?;
    items.iter().enumerate().map(|(k, it)| {
        let a = it.as_arr().filter(|a| a.len() == 7).ok_or(format!("issue {k} is not [rule, type, sev, file, line, omitted, omittedType]"))?;
        let s = |j: usize, what: &str| text_of(&a[j]).ok_or(format!("issue {k}: {what} is not a string"));
        Ok(Finding {
            rule: s(0, "rule")?,
            typ: s(1, "type")?,
            sev: s(2, "sev")?,
            file: s(3, "file")?,
            line: a[4].as_i64().ok_or(format!("issue {k}: line is not an integer"))?,
            omitted: a[5].as_i64(),
            omitted_type: text_of(&a[6]),
        })
    }).collect()
}

/// The files of a call: `[[dep, lang, metrics], …]`, metrics `[ncloc, comments, measured, windows]` or the text.
pub fn files_arg(v: Option<&Value>) -> Result<Vec<FileIn>, String> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(v) => v.as_arr().ok_or("files is not a list")?,
    };
    items.iter().enumerate().map(|(k, it)| {
        let a = it.as_arr().filter(|a| a.len() == 3).ok_or(format!("file {k} is not [dep, lang, metrics or text]"))?;
        let dep = matches!(a[0], Value::Bool(true));
        let lang = a[1].as_string();
        let got = match &a[2] {
            Value::Str(t) => Got::Text(t.clone()),
            Value::Arr(m) if m.len() == 4 => {
                let n = |j: usize| m[j].as_i64().filter(|&x| x >= 0).map(|x| x as usize).ok_or(format!("file {k}: a count is not one"));
                let windows = text_of(&m[3]).ok_or(format!("file {k}: windows is not a string"))?;
                if windows.len() % 16 != 0 {
                    return Err(format!("file {k}: windows is not 16 digits a window"));
                }
                Got::Metrics { ncloc: n(0)?, comments: n(1)?, measured: n(2)?, windows }
            }
            _ => return Err(format!("file {k}: metrics is neither [ncloc, comments, measured, windows] nor a text")),
        };
        Ok(FileIn { dep, lang, got })
    }).collect()
}

/// The conditions of a `regrade` call: `[[label, ok], …]`.
pub fn conditions_arg(v: Option<&Value>) -> Result<Vec<(Vec<u32>, bool)>, String> {
    let items = v.and_then(|v| v.as_arr()).ok_or("conditions is not a list")?;
    items.iter().enumerate().map(|(k, it)| {
        let a = it.as_arr().filter(|a| a.len() == 2).ok_or(format!("condition {k} is not [label, ok]"))?;
        match (&a[0], &a[1]) {
            (Value::Str(l), Value::Bool(ok)) => Ok((l.clone(), *ok)),
            _ => Err(format!("condition {k} is not [label, ok]")),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round1_is_pythons_round() {
        // (Python 3: round(x, 1) for each)
        for (x, want) in [(0.25, 0.2), (0.35, 0.3), (0.45, 0.5), (12.25, 12.2), (12.75, 12.8), (2.675, 2.7),
                          (33.333333333333336, 33.3), (66.66666666666667, 66.7), (0.05, 0.1), (0.15, 0.1), (100.0, 100.0)] {
            assert_eq!(round1(x), want, "{x}");
        }
    }
}
