//! Baselines (0.1.9, BR-7 step 4 (d)): what core's `apply_baseline` and the reports module's `fingerprint`,
//! `sign_fingerprints` and `verify_signature`, and the npm package's `baseline.js` over its `pyjson.js`, each did,
//! held equal by tests. The packages keep what is theirs: whether the file is one of their reports (its head) and
//! where it is (inside the scanned tree, its links followed), reading its bytes, the key from the environment, and
//! printing the warnings.
//!
//! * A finding's fingerprint: its rule | its path with forward slashes | its flagged line stripped, as Python's
//!   `f"{issue['rule']}|{str(issue['file']).replace(chr(92), '/')}|{line_text}"` makes it of a baseline's entry
//!   whatever its values are (`json.loads`' types: Python's str() of each, its arithmetic and indexing); an entry
//!   Python fails on (KeyError, TypeError, AttributeError) has none and is skipped. Where Python raised an error the
//!   CLI did not catch (OverflowError: an int too large for a float, subtracted from a float), the entry has none.
//! * The signature: HMAC-SHA256 with the key's UTF-8 bytes (surrogateescape: a byte the environment could not
//!   decode is that byte) over `lazaret-baseline-v1\n` and `json.dumps(sorted(set(fingerprints)),
//!   ensure_ascii=True, separators=(",", ":"))`, in hexadecimal.
//! * Applying a baseline: its bytes read as `open(path, encoding="utf-8")` reads them (strict UTF-8, universal
//!   newlines) and parsed as `json.loads` parses them, nested no deeper than MAX_MANIFEST_DEPTH; the trust rules
//!   (audit G17: not one of our reports, or inside the scanned tree with no key, or a signature that does not
//!   verify: untrusted, every finding new); the shape checks; the malformed entries skipped; each finding new or
//!   not. The warnings are the packages' text, sanitized for the terminal (core's sanitize_term_line).
//! * N-15 (John, Oct 15: "the baseline, with its HMAC"): a baseline whose signature verifies with the key accepts the
//!   findings it holds that no marker can accept (UNSUPPRESSIBLE_PREFIXES: SC-*, X-*): they stay in the reports,
//!   marked, and in the counts and ratings, and the gate's conditions on findings are judged without them
//!   (result.rs `accept`). A baseline with no key, trusted or not, accepts nothing.

use crate::json::{self, Value};
use crate::manifest::pyjson;
use crate::manifest::pyval::{self, PyVal};
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use crate::report::sanitize_term_line;
use crate::result::{self, Finding};

pub const KEY_ENV: &str = "LAZARET_BASELINE_KEY";
pub const SIGNATURE_FIELD: &str = "baselineSignature";
pub const SIGNATURE_ALG: &str = "HMAC-SHA256";
const DOMAIN: &[u8] = b"lazaret-baseline-v1\n";

// ---- a fingerprint ------------------------------------------------------------------------------------------

/// A number as Python's arithmetic makes it of json.loads' values: an int (its decimal text) or a float.
enum Num {
    Int(PyStr),
    Float(f64),
}

fn num(v: &PyVal) -> Option<Num> {
    match v {
        PyVal::Int(t) => Some(Num::Int(t.clone())),
        PyVal::Bool(b) => Some(Num::Int(pystr::u(if *b { "1" } else { "0" }))),
        PyVal::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

/// Decimal magnitudes: compare (no leading zeros), add, subtract (a >= b).
fn mag_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn mag_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (mut out, mut carry) = (Vec::new(), 0u8);
    let (mut i, mut j) = (a.len(), b.len());
    while i > 0 || j > 0 || carry > 0 {
        let x = if i > 0 { i -= 1; a[i] } else { 0 };
        let y = if j > 0 { j -= 1; b[j] } else { 0 };
        let s = x + y + carry;
        out.push(s % 10);
        carry = s / 10;
    }
    out.reverse();
    out
}

fn mag_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (mut out, mut borrow) = (Vec::new(), 0i8);
    let mut j = b.len();
    for i in (0..a.len()).rev() {
        let y = if j > 0 { j -= 1; b[j] as i8 } else { 0 };
        let mut d = a[i] as i8 - y - borrow;
        borrow = 0;
        if d < 0 {
            d += 10;
            borrow = 1;
        }
        out.push(d as u8);
    }
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out.reverse();
    out
}

fn split_int(t: &[u32]) -> (bool, Vec<u8>) {
    let neg = t.first() == Some(&('-' as u32));
    let digits: Vec<u8> = t[neg as usize..].iter().map(|&c| (c - '0' as u32) as u8).collect();
    (neg && digits != [0], digits)
}

/// a - b, exactly.
fn int_sub(a: &[u32], b: &[u32]) -> (bool, Vec<u8>) {
    let (an, am) = split_int(a);
    let (bn, bm) = split_int(b);
    let bn = !bn && bm != [0]; // a + (-b)
    if an == bn {
        return (an, mag_add(&am, &bm));
    }
    match mag_cmp(&am, &bm) {
        std::cmp::Ordering::Less => (bn, mag_sub(&bm, &am)),
        _ => {
            let m = mag_sub(&am, &bm);
            (an && m != [0], m)
        }
    }
}

/// The index `line - snipStart`: Python's int, or float when either is a float (None where Python raises: not
/// numbers, or an int too large for a float).
enum Index {
    Int(bool, Vec<u8>),
    Float(f64),
}

fn index_of(line: &PyVal, start: &PyVal) -> Option<Index> {
    match (num(line)?, num(start)?) {
        (Num::Int(a), Num::Int(b)) => {
            let (neg, m) = int_sub(&a, &b);
            Some(Index::Int(neg, m))
        }
        (Num::Int(a), Num::Float(b)) => Some(Index::Float(pyval::int_to_float(&a)? - b)),
        (Num::Float(a), Num::Int(b)) => Some(Index::Float(a - pyval::int_to_float(&b)?)),
        (Num::Float(a), Num::Float(b)) => Some(Index::Float(a - b)),
    }
}

/// bool(v)
fn truthy(v: &PyVal) -> bool {
    match v {
        PyVal::None => false,
        PyVal::Bool(b) => *b,
        PyVal::Int(t) => !pystr::eq(t, "0"),
        PyVal::Float(f) => *f != 0.0,
        PyVal::Complex(a, b) => *a != 0.0 || *b != 0.0,
        PyVal::Str(s) | PyVal::Bytes(s) => !s.is_empty(),
        PyVal::Ellipsis => true,
        PyVal::List(v) | PyVal::Tuple(v) | PyVal::Set(v) => !v.is_empty(),
        PyVal::Dict(d, _) => !d.is_empty(),
    }
}

/// `snippet[idx].strip() if 0 <= idx < len(snippet) else ""` (Err: Python raises).
fn line_text(snippet: Option<&PyVal>, idx: &Index) -> Result<PyStr, ()> {
    let nonneg = match idx {
        Index::Int(neg, _) => !neg,
        Index::Float(f) => *f >= 0.0,
    };
    if !nonneg {
        return Ok(Vec::new()); // (the chain stops: len() is not asked)
    }
    let len = match snippet {
        None => 0,
        Some(PyVal::List(v)) => v.len(),
        Some(PyVal::Str(s)) => s.len(),
        Some(PyVal::Dict(d, _)) => d.len(),
        Some(_) => return Err(()), // object of type … has no len()
    };
    let at = match idx {
        Index::Int(_, m) => {
            if m.len() > 19 {
                return Ok(Vec::new());
            }
            let k = m.iter().fold(0u64, |n, &d| n * 10 + d as u64);
            if k >= len as u64 {
                return Ok(Vec::new());
            }
            k as usize
        }
        Index::Float(f) => {
            if *f < len as f64 {
                return Err(()); // list indices must be integers or slices, not float
            }
            return Ok(Vec::new());
        }
    };
    match snippet {
        Some(PyVal::List(v)) => match &v[at] {
            PyVal::Str(s) => Ok(pystr::strip(s).to_vec()),
            _ => Err(()), // … has no attribute 'strip'
        },
        Some(PyVal::Str(s)) => Ok(pystr::strip(&s[at..at + 1]).to_vec()),
        _ => Err(()), // a dict's keys are strs: KeyError
    }
}

/// reports.fingerprint of one value json.loads made (None: Python raises).
pub fn fingerprint(issue: &PyVal) -> Option<PyStr> {
    if !matches!(issue, PyVal::Dict(..)) {
        return None;
    }
    let idx = index_of(issue.get("line")?, issue.get("snipStart")?)?;
    let snippet = issue.get("snippet").filter(|v| truthy(v));
    let text = line_text(snippet, &idx).ok()?;
    let path: PyStr = pyval::py_str(issue.get("file")?).into_iter().map(|c| if c == '\\' as u32 { '/' as u32 } else { c }).collect();
    let mut out = pyval::py_str(issue.get("rule")?);
    out.push('|' as u32);
    out.extend(path);
    out.push('|' as u32);
    out.extend(text);
    Some(out)
}

/// A finding a package sends (a JSON value) as the value json.loads would have made of it.
pub fn pyval_of(v: &Value) -> PyVal {
    match v {
        Value::Null => PyVal::None,
        Value::Bool(b) => PyVal::Bool(*b),
        Value::Int(i) => PyVal::Int(pystr::u(&i.to_string())),
        Value::Float(f) => PyVal::Float(*f),
        Value::Str(s) => PyVal::Str(s.clone()),
        Value::Arr(a) => PyVal::List(a.iter().map(pyval_of).collect()),
        Value::Obj(o) => PyVal::Dict(o.iter().map(|(k, v)| (PyVal::Str(k.clone()), pyval_of(v))).collect(), None),
        Value::Raw(_) => PyVal::None,
    }
}

/// The fingerprints of a list's entries, and how many have none.
fn fingerprints(issues: &[PyVal]) -> (Vec<PyStr>, usize) {
    let mut out = Vec::with_capacity(issues.len());
    let mut skipped = 0;
    for i in issues {
        match fingerprint(i) {
            Some(fp) => out.push(fp),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

// ---- the signature -------------------------------------------------------------------------------------------

/// The key's bytes: `key.encode("utf-8", "surrogateescape")` (a lone surrogate the escape does not make, WTF-8).
pub fn key_bytes(key: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len());
    for &c in key {
        if (0xDC80..=0xDCFF).contains(&c) {
            out.push((c - 0xDC00) as u8);
        } else if let Some(ch) = char::from_u32(c) {
            let mut b = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
        } else {
            out.extend_from_slice(&[0xE0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 0x3F) as u8, 0x80 | (c & 0x3F) as u8]);
        }
    }
    out
}

/// reports.sign_fingerprints: the hex HMAC over the domain and the sorted, distinct fingerprints as ASCII JSON.
pub fn sign(fps: &[PyStr], key: &[u32]) -> String {
    let mut v: Vec<&PyStr> = fps.iter().collect();
    v.sort();
    v.dedup();
    let mut canon = String::from("[");
    for (k, fp) in v.iter().enumerate() {
        if k > 0 {
            canon.push(',');
        }
        json::write_str(&mut canon, fp);
    }
    canon.push(']');
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(canon.as_bytes());
    crate::secrets::hmac_sha256(&key_bytes(key), &msg).iter().map(|b| format!("{b:02x}")).collect()
}

/// reports.verify_signature of a parsed report (a dict): Err(why) when it does not verify.
fn verify(doc: &PyVal, issues: &[PyVal], key: &[u32]) -> Result<(), String> {
    let sig = doc.get(SIGNATURE_FIELD);
    let value = match sig {
        Some(s @ PyVal::Dict(..)) => match s.get("value") {
            Some(PyVal::Str(v)) => v,
            _ => return Err("it carries no baseline signature".into()),
        },
        _ => return Err("it carries no baseline signature".into()),
    };
    if !matches!(sig.and_then(|s| s.get("alg")), Some(PyVal::Str(a)) if pystr::eq(a, SIGNATURE_ALG)) {
        return Err("unsupported signature algorithm".into());
    }
    let want = sign(&fingerprints(issues).0, key);
    // hmac.compare_digest: equal lengths compared in full (a value that is not ASCII: Python's TypeError, which the
    // CLI did not catch; here it does not verify)
    let got = value;
    let same = got.len() == want.len()
        && want.bytes().zip(got.iter()).fold(0u32, |acc, (w, &g)| acc | (w as u32 ^ g)) == 0;
    if same {
        Ok(())
    } else {
        Err(format!("its signature does not verify with ${KEY_ENV} (forged, edited, or signed with another key)"))
    }
}

// ---- reading a baseline --------------------------------------------------------------------------------------

/// The bytes decoded as strict UTF-8, or the UnicodeDecodeError's text.
fn utf8_strict(b: &[u8]) -> Result<PyStr, String> {
    match std::str::from_utf8(b) {
        Ok(s) => Ok(s.chars().map(|c| c as u32).collect()),
        Err(e) => {
            let start = e.valid_up_to();
            let (end, reason) = match e.error_len() {
                Some(n) => {
                    let lead = b[start];
                    let starts = matches!(lead, 0xC2..=0xDF | 0xE0..=0xEF | 0xF0..=0xF4);
                    (start + n, if starts { "invalid continuation byte" } else { "invalid start byte" })
                }
                None => (b.len(), "unexpected end of data"),
            };
            Err(if end - start == 1 {
                format!("'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}", b[start])
            } else {
                format!("'utf-8' codec can't decode bytes in position {start}-{}: {reason}", end - 1)
            })
        }
    }
}

/// What a package hands over of a baseline and of the scan it is applied to.
pub struct ApplyIn {
    /// the path as given (for the warnings)
    pub path: PyStr,
    /// one of our JSON reports (reports.is_our_report)
    pub ours: bool,
    /// inside the scanned tree (reports.path_is_inside)
    pub inside: bool,
    /// $LAZARET_BASELINE_KEY, when set and not empty
    pub key: Option<PyStr>,
    /// the file's bytes, or why they could not be read
    pub data: Result<Vec<u8>, PyStr>,
    /// the scan's findings' fingerprints (None: none) and what the gate reads of them, in the same order
    pub fingerprints: Vec<Option<PyStr>>,
    pub rows: Vec<Finding>,
    /// the result's conditions, `[label, ok]`
    pub conditions: Vec<(PyStr, bool)>,
}

fn s(t: &str) -> PyStr {
    pystr::u(t)
}

fn warning(path: &[u32], rest: &str) -> PyStr {
    let mut w = s("warning: baseline ");
    w.extend(sanitize_term_line(path));
    w.extend(s(rest));
    w
}

/// core.apply_baseline: what to print and what to mark.
pub fn apply(p: &Pack, a: &ApplyIn) -> Value {
    let mut warnings: Vec<PyStr> = Vec::new();
    let n = a.fingerprints.len();
    let untrusted = |warnings: &mut Vec<PyStr>, reason: &str| {
        warnings.push(warning(&a.path, &format!(" {reason} \u{2014} treating it as untrusted: all current findings are counted as new")));
        Value::obj(vec![
            ("warnings", Value::Arr(warnings.iter().map(|w| Value::Str(w.clone())).collect())),
            ("new", Value::Arr(vec![Value::Bool(true); n])),
            ("newIssues", Value::Int(n as i64)),
            ("untrusted", Value::Bool(true)),
        ])
    };
    let ignored = |warnings: Vec<PyStr>| Value::obj(vec![("warnings", Value::Arr(warnings.into_iter().map(Value::Str).collect()))]);
    if !a.ours {
        return untrusted(&mut warnings, "is not a report produced by this engine (no matching engine marker, or wrong shape)");
    }
    if a.key.is_none() && a.inside {
        return untrusted(
            &mut warnings,
            &format!(
                "is inside the scanned tree and ${KEY_ENV} is not set (the scanned repository could have planted it) \u{2014} \
                 keep baselines outside the scanned tree (e.g. in $RUNNER_TEMP) or set {KEY_ENV} so reports are signed"
            ),
        );
    }
    let read = |why: &[u32]| {
        let mut w = s("warning: could not read baseline ");
        w.extend(sanitize_term_line(&a.path));
        w.extend(s(": "));
        w.extend(sanitize_term_line(why));
        w
    };
    let bytes = match &a.data {
        Ok(b) => b,
        Err(why) => return ignored(vec![read(why)]),
    };
    let text = match utf8_strict(bytes) {
        Ok(t) => crate::decode::normalize_newlines(&t),
        Err(why) => return ignored(vec![read(&s(&why))]),
    };
    let limit = p.usize("MAX_MANIFEST_DEPTH");
    let prev = if pyjson::depth_exceeds(&text, limit) {
        return ignored(vec![read(&s(&format!("JSON nested deeper than {limit} levels")))]);
    } else {
        match pyjson::loads_plain(&text) {
            Ok(v) => v,
            Err(e) => return ignored(vec![read(&s(&pyjson::message(&text, e)))]),
        }
    };
    if !matches!(prev, PyVal::Dict(..)) {
        return ignored(vec![warning(
            &a.path,
            &format!(": top level is {}, not an object \u{2014} expected {{\"issues\": [...]}}; baseline ignored", prev.type_name()),
        )]);
    }
    let empty = PyVal::List(Vec::new());
    let issues = match prev.get("issues").unwrap_or(&empty) {
        PyVal::List(v) => v,
        other => {
            return ignored(vec![warning(&a.path, &format!(": 'issues' is {}, not a list \u{2014} baseline ignored", other.type_name()))]);
        }
    };
    if let Some(key) = &a.key {
        if let Err(why) = verify(&prev, issues, key) {
            return untrusted(&mut warnings, &format!("is not trusted: {why}"));
        }
    }
    let (known, skipped) = fingerprints(issues);
    if skipped > 0 {
        warnings.push(warning(
            &a.path,
            &format!(": {skipped} malformed issue entrie(s) skipped (expected objects with rule/file/line)"),
        ));
    }
    let mut known = known;
    known.sort();
    known.dedup();
    let new: Vec<bool> = a.fingerprints.iter().map(|fp| fp.as_ref().map_or(true, |f| known.binary_search(f).is_err())).collect();
    let mut out = vec![
        ("warnings", Value::Arr(warnings.into_iter().map(Value::Str).collect())),
        ("new", Value::Arr(new.iter().map(|&b| Value::Bool(b)).collect())),
        ("newIssues", Value::Int(new.iter().filter(|&&b| b).count() as i64)),
    ];
    if a.key.is_some() {
        // N-15: a signed baseline accepts what no marker can
        let prefixes = p.strs("UNSUPPRESSIBLE_PREFIXES");
        let accepted: Vec<bool> = (0..n)
            .map(|k| !new[k] && a.rows.get(k).is_some_and(|r| prefixes.iter().any(|pre| r.rule.starts_with(pre))))
            .collect();
        let count = accepted.iter().filter(|&&b| b).count();
        if count > 0 {
            let gate = result::accept(p, &a.rows, &accepted, &a.conditions);
            out.push(("accepted", Value::Arr(accepted.into_iter().map(Value::Bool).collect())));
            out.push(("acceptedIssues", Value::Int(count as i64)));
            out.push(("pass", gate.get("pass").cloned().unwrap_or(Value::Null)));
            out.push(("conditions", gate.get("conditions").cloned().unwrap_or(Value::Null)));
        }
    }
    Value::obj(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(t: &str) -> PyStr {
        pystr::u(t)
    }

    fn fp_of(json: &str) -> Option<String> {
        let v = pyjson::loads_plain(&u(json)).unwrap();
        fingerprint(&v).map(|f| pystr::to_string(&f))
    }

    #[test]
    fn fingerprints_as_python_makes_them() {
        // (Python 3.13: reports.fingerprint(json.loads(text)) for each, or the exception it raises: None)
        let cases: &[(&str, Option<&str>)] = &[
            (r#"{"rule": "R", "file": "a\\b.js", "line": 3, "snipStart": 2, "snippet": ["x", "  eval(q)  ", "z"]}"#, Some("R|a/b.js|eval(q)")),
            (r#"{"rule": "S-EVAL-PY", "file": "app\\views\\admin.py", "line": 3, "snipStart": 1, "snippet": ["import os", "", "eval(data)", ""]}"#,
             Some("S-EVAL-PY|app/views/admin.py|eval(data)")),
            (r#"{"rule": 5, "file": [1, "a"], "line": true, "snipStart": false, "snippet": "ab"}"#, Some("5|[1, 'a']|b")),
            (r#"{"rule": null, "file": {"a": 1.0}, "line": 1, "snipStart": 9}"#, Some("None|{'a': 1.0}|")),
            (r#"{"rule": "R", "file": "f", "line": -1.5, "snipStart": 0, "snippet": 7}"#, Some("R|f|")),
            (r#"{"rule": "R", "file": "f", "line": 1.0, "snipStart": 0, "snippet": ["a", "b"]}"#, None),
            (r#"{"rule": "R", "file": "f", "line": 0, "snipStart": 0, "snippet": 7}"#, None),
            (r#"{"rule": "R", "file": "f", "line": 0, "snipStart": 0, "snippet": [1]}"#, None),
            (r#"{"rule": "R", "file": "f", "line": 0, "snipStart": 0, "snippet": {"0": "x"}}"#, None),
            (r#"{"rule": "R", "file": "f", "line": 0, "snipStart": 0, "snippet": 0}"#, Some("R|f|")),
            (r#"{"rule": "R", "file": "f", "line": "1", "snipStart": 0}"#, None),
            (r#"{"rule": "R", "line": 1, "snipStart": 0}"#, None),
            (r#"{"file": "f", "line": 1, "snipStart": 0}"#, None),
            (r#"{"rule": "R", "file": "f", "line": 1}"#, None),
            (r#"["R", "f", 1]"#, None),
            (r#""R|f|x""#, None),
            (r#"{"rule": "R", "file": "f", "line": 100000000000000000000000000000001, "snipStart": 100000000000000000000000000000000, "snippet": ["a", " b "]}"#,
             Some("R|f|b")),
            (r#"{"rule": "R", "file": "f", "line": NaN, "snipStart": 0, "snippet": 7}"#, Some("R|f|")),
            (r#"{"rule": "R", "file": 1e300, "line": -0.0, "snipStart": 0.0, "snippet": []}"#, Some("R|1e+300|")),
        ];
        for (json, want) in cases {
            assert_eq!(fp_of(json).as_deref(), *want, "{json}");
        }
    }

    #[test]
    fn the_signature_is_pythons() {
        // (lazaret.scanner.reports.sign_fingerprints on the same input, as review-baseline.test.js held it)
        let fps: Vec<PyStr> = ["S-EVAL-JS|src/a.js|eval(y)", "S-EVAL-PY|caf\u{e9}.py|eval(\"\u{e9}\u{1F600}\")",
            "S-EVAL-JS|src/a.js|eval(y)", "Q-TODO|b.js|// TODO \\ \"q\"\t"].iter().map(|t| u(t)).collect();
        assert_eq!(sign(&fps, &u("test-key-\u{e9}")), "98eb9a02086a38114576d43088eef92cf35471c29c6a9696ba6c099560041a44");
        assert_eq!(key_bytes(&[0x61, 0xDCFF, 0xE9]), vec![0x61, 0xFF, 0xC3, 0xA9]);
    }

    #[test]
    fn utf8_errors_are_pythons() {
        for (b, want) in [
            (&b"\xff"[..], "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"),
            (b"a\xc3", "'utf-8' codec can't decode byte 0xc3 in position 1: unexpected end of data"),
            (b"\xc3a", "'utf-8' codec can't decode byte 0xc3 in position 0: invalid continuation byte"),
            (b"\xe2\x82", "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data"),
            (b"\xed\xa0\x80", "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte"),
            (b"\xe2\x82a", "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte"),
        ] {
            assert_eq!(utf8_strict(b).unwrap_err(), want);
        }
    }

    #[test]
    fn int_arithmetic() {
        let d = |a: &str, b: &str| {
            let (neg, m) = int_sub(&u(a), &u(b));
            format!("{}{}", if neg { "-" } else { "" }, m.iter().map(|d| d.to_string()).collect::<String>())
        };
        assert_eq!(d("3", "1"), "2");
        assert_eq!(d("1", "3"), "-2");
        assert_eq!(d("-1", "3"), "-4");
        assert_eq!(d("-1", "-3"), "2");
        assert_eq!(d("5", "5"), "0");
        assert_eq!(d("0", "-0"), "0");
        assert_eq!(d("1000", "1"), "999");
        assert_eq!(d("-1000", "-1001"), "1");
        assert_eq!(d("99999999999999999999", "-1"), "100000000000000000000");
    }
}
