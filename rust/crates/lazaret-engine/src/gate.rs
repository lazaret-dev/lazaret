//! The commit-time gate (0.1.9, BR-7 step 4 (f)): which findings `lazaret hook` prints, which of a result's
//! conditions it gates on, the lines it prints, its exit, what it does with each file the commit holds and why a file
//! could not be read for it. hook.py's and the npm package's hook.js' (shown, GATE, report, gather's choices and
//! texts), held equal by tests until then. The packages keep git, copying the files the commit holds into a
//! temporary tree, the project scan of it and printing the lines.

use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use crate::report::{c, issue_excerpt, sanitize_term_line, sev_color, sev_order};

fn s(t: &str) -> PyStr {
    pystr::u(t)
}

fn text(v: Option<&Value>) -> PyStr {
    v.and_then(|x| x.as_str()).map(|t| t.to_vec()).unwrap_or_default()
}

/// The result's conditions the gate keeps (--ci's security and supply-chain ones: duplication and
/// maintainability are not a commit's business).
pub const GATE: [&str; 4] = ["No blocker issues", "No critical vulnerabilities", "No supply-chain indicators", "No cross-file taint flows"];

/// What the gate's conditions read: vulnerabilities of MAJOR and above, supply-chain indicators, cross-file flows.
pub fn shown(i: &Value) -> bool {
    let (rule, sev) = (text(i.get("rule")), text(i.get("sev")));
    if pystr::starts_with(&rule, "SC-") {
        return !pystr::eq(&sev, "INFO");
    }
    if pystr::starts_with(&rule, "X-") {
        return true;
    }
    pystr::eq(&text(i.get("type")), "VULN") && sev_order(&sev) <= sev_order(&s("MAJOR"))
}

/// A path as git writes it: "/" between folders, on Windows too.
fn git_form(path: &[u32], windows: bool) -> PyStr {
    if windows {
        pystr::replace(path, &s("\\"), &s("/"))
    } else {
        path.to_vec()
    }
}

/// hook.report and the exit: `issues` the result's (each with what --show-secrets shows of its line, or None), the
/// lines printed and 1 when a condition the gate keeps failed, else 0.
pub struct Report<'a> {
    pub checked: usize,
    pub issues: &'a [(Value, Option<Value>)],
    pub conditions: &'a [(PyStr, bool)],
    pub quiet: bool,
    pub color: bool,
    pub windows: bool,
    pub width: i64,
    pub redact: bool,
}

pub fn report(p: &Pack, r: &Report) -> (Vec<PyStr>, i64) {
    let mut out = Vec::new();
    let mut issues: Vec<&(Value, Option<Value>)> = r.issues.iter().filter(|(i, _)| shown(i)).collect();
    let failed: Vec<&PyStr> = r.conditions.iter().filter(|(l, ok)| !ok && GATE.iter().any(|g| pystr::eq(l, g))).map(|(l, _)| l).collect();
    if !r.quiet || !issues.is_empty() {
        out.push(s(&format!("lazaret hook: {} file{} checked", r.checked, if r.checked != 1 { "s" } else { "" })));
    }
    let line_of = |i: &Value| i.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
    issues.sort_by(|(a, _), (b, _)| {
        git_form(&text(a.get("file")), r.windows)
            .cmp(&git_form(&text(b.get("file")), r.windows))
            .then(sev_order(&text(a.get("sev"))).cmp(&sev_order(&text(b.get("sev")))))
            .then(line_of(a).cmp(&line_of(b)))
    });
    let mut cur: Option<PyStr> = None;
    for (i, raw) in issues {
        let file = git_form(&text(i.get("file")), r.windows);
        if cur.as_ref() != Some(&file) {
            let mut l = s("  ");
            l.extend(c(r.color, "4", &sanitize_term_line(&file)));
            out.push(l);
            cur = Some(file);
        }
        let sev = text(i.get("sev"));
        let rule = text(i.get("rule"));
        let mut sev_padded = sev.clone();
        while sev_padded.len() < 8 {
            sev_padded.push(' ' as u32);
        }
        let mut num = s(&line_of(i).to_string());
        while num.len() < 5 {
            num.push(' ' as u32);
        }
        let mut prefix = s("    L");
        prefix.extend(&num);
        prefix.push(' ' as u32);
        prefix.extend(&sev_padded);
        prefix.extend(s(" ["));
        prefix.extend(&rule);
        prefix.extend(s("] "));
        let mut l = s("    L");
        l.extend(&num);
        l.push(' ' as u32);
        l.extend(c(r.color, sev_color(&sev), &sev_padded));
        l.extend(s(" ["));
        l.extend(&rule);
        l.extend(s("] "));
        l.extend(sanitize_term_line(&text(i.get("msg"))));
        out.push(l);
        let ex = issue_excerpt(p, i, r.width, raw.as_ref(), r.redact);
        if !ex.is_empty() && !r.quiet {
            let mut l: PyStr = vec![' ' as u32; prefix.len()];
            let mut shown_ex = s("» ");
            shown_ex.extend(ex);
            l.extend(c(r.color, "2", &shown_ex));
            out.push(l);
        }
    }
    if !failed.is_empty() {
        let mut l = s("  Commit gate: ");
        l.extend(c(r.color, "41;97", &s(" FAILED ")));
        out.push(l);
        for label in &failed {
            let mut l = s("    ");
            l.extend(c(r.color, "31", &s("\u{2717}")));
            l.push(' ' as u32);
            l.extend(sanitize_term_line(label));
            out.push(l);
        }
    } else if !r.quiet {
        let mut l = s("  Commit gate: ");
        l.extend(c(r.color, "42;30", &s(" PASSED ")));
        out.push(l);
    }
    (out, if failed.is_empty() { 0 } else { 1 })
}

/// What the gate does with a path the commit holds, by its index entry's mode: a regular file's blob is read from
/// the index, a link or a submodule is not followed, and a file the index does not hold is read from the disk.
pub fn source(mode: Option<&[u32]>) -> &'static str {
    match mode {
        Some(m) if pystr::eq(m, "100644") || pystr::eq(m, "100755") => "blob",
        Some(_) => "skip",
        None => "disk",
    }
}

/// Why a file the commit holds could not be read for the scan (hook.py's texts): `kind` and the I/O's own words.
pub fn why(kind: &str, detail: &[u32]) -> Option<PyStr> {
    let with = |head: &str| {
        let mut t = s(head);
        t.extend_from_slice(detail);
        t.push(')' as u32);
        t
    };
    Some(match kind {
        "collision" => s("its name is another file's on this system (they differ only in case, in their Unicode form or by a \
                          backslash), so it could not be copied for the scan"),
        "unprinted" => s("git could not print it from the index"),
        "not_copied" => with("it could not be copied for the scan ("),
        "stopped" => s("it could not be copied for the scan (git stopped mid-file)"),
        "unreadable" => with("it could not be read ("),
        "not_regular" => s("it is not a regular file"),
        "git_missing" => s("git could not be run (it is not on PATH)"),
        "git_failed" => with("git could not be run ("),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::pack::EMBEDDED;

    fn py(v: &str) -> Value {
        json::parse_str(v).unwrap()
    }

    fn lines(r: &Report) -> (Vec<String>, i64) {
        let p = Pack::from_json(EMBEDDED).unwrap();
        let (l, exit) = report(&p, r);
        (l.iter().map(|x| pystr::to_string(x)).collect(), exit)
    }

    #[test]
    fn what_the_gate_shows() {
        // (the npm package's hook test's cases, until BR-7's step 4 (f))
        let cases = [
            (r#"{"rule": "SC-INSTALL-HOOK", "sev": "MAJOR", "type": "VULN"}"#, true),
            (r#"{"rule": "SC-INSTALL-HOOK", "sev": "INFO", "type": "VULN"}"#, false),
            (r#"{"rule": "X-CMD", "sev": "MINOR", "type": "VULN"}"#, true),
            (r#"{"rule": "S-TOKEN", "sev": "BLOCKER", "type": "VULN"}"#, true),
            (r#"{"rule": "P-EVAL", "sev": "MAJOR", "type": "VULN"}"#, true),
            (r#"{"rule": "P-EVAL", "sev": "CRITICAL", "type": "VULN"}"#, true),
            (r#"{"rule": "P-X", "sev": "MINOR", "type": "VULN"}"#, false),
            (r#"{"rule": "Q-LONG", "sev": "BLOCKER", "type": "BUG"}"#, false),
        ];
        for (issue, want) in cases {
            assert_eq!(shown(&py(issue)), want, "{issue}");
        }
    }

    #[test]
    fn the_report_is_hook_pys() {
        // (Python 3.13: hook.report's print()s for the same result, os.sep "\\")
        let issues = vec![
            (py(r#"{"rule": "S-TOKEN", "sev": "BLOCKER", "type": "VULN", "file": "b.py", "line": 3, "msg": "Token",
                    "snippet": ["x", "y", "t = 1"], "snipStart": 1}"#), None),
            (py(r#"{"rule": "Q-LONG", "sev": "BLOCKER", "type": "BUG", "file": "b.py", "line": 1, "msg": "Long"}"#), None),
            (py(r#"{"rule": "P-EVAL", "sev": "MAJOR", "type": "VULN", "file": "a\\c.py", "line": 12, "msg": "Eval\nhere",
                    "snippet": ["eval(x)"], "snipStart": 12}"#), None),
            (py(r#"{"rule": "P-EVAL", "sev": "CRITICAL", "type": "VULN", "file": "a\\c.py", "line": 40, "msg": "Eval",
                    "snippet": ["eval(y)"], "snipStart": 40}"#), Some(Value::Str(pystr::u("eval(z)")))),
        ];
        let conditions = vec![
            (pystr::u("No blocker issues"), false),
            (pystr::u("No new code duplication"), false),
            (pystr::u("No critical vulnerabilities"), false),
            (pystr::u("No supply-chain indicators"), true),
        ];
        let mut r = Report { checked: 2, issues: &issues, conditions: &conditions, quiet: false, color: false, windows: true, width: 100, redact: true };
        let (got, exit) = lines(&r);
        let pad = " ".repeat("    L12    CRITICAL [P-EVAL] ".chars().count());
        assert_eq!(exit, 1);
        assert_eq!(got, vec![
            "lazaret hook: 2 files checked".to_string(),
            "  a/c.py".into(),
            "    L40    CRITICAL [P-EVAL] Eval".into(),
            format!("{pad}» eval(z)"),
            "    L12    MAJOR    [P-EVAL] Eval\u{b7}here".into(),
            format!("{pad}» eval(x)"),
            "  b.py".into(),
            "    L3     BLOCKER  [S-TOKEN] Token".into(),
            format!("{pad} » [redacted]"),                      // (S-TOKEN: one more)
            "  Commit gate:  FAILED ".into(),
            "    \u{2717} No blocker issues".into(),
            "    \u{2717} No critical vulnerabilities".into(),
        ]);
        r.quiet = true;
        let (got, _) = lines(&r);
        assert_eq!(got.len(), 9);
        assert!(!got.iter().any(|l| l.contains('\u{bb}')));
        // passed, quiet: nothing; passed: a line for the files and the verdict
        let ok = vec![(pystr::u("No blocker issues"), true), (pystr::u("No new code duplication"), false)];
        let none: Vec<(Value, Option<Value>)> = vec![issues[1].clone()];
        r = Report { checked: 1, issues: &none, conditions: &ok, quiet: true, color: false, windows: false, width: 100, redact: true };
        assert_eq!(lines(&r), (vec![], 0));
        r.quiet = false;
        assert_eq!(lines(&r), (vec!["lazaret hook: 1 file checked".to_string(), "  Commit gate:  PASSED ".into()], 0));
        r.color = true;
        assert_eq!(lines(&r).0[1], "  Commit gate: \x1b[42;30m PASSED \x1b[0m");
        // windows: false leaves a backslash in a name as it is
        let one = vec![issues[2].clone()];
        r = Report { checked: 1, issues: &one, conditions: &ok, quiet: true, color: true, windows: false, width: 100, redact: true };
        let (got, _) = lines(&r);
        assert_eq!(got[1], "  \x1b[4ma\\c.py\x1b[0m");
        assert_eq!(got[2], "    L12    \x1b[33mMAJOR   \x1b[0m [P-EVAL] Eval\u{b7}here");
    }

    #[test]
    fn sources_and_reasons() {
        assert_eq!(source(Some(&pystr::u("100644"))), "blob");
        assert_eq!(source(Some(&pystr::u("100755"))), "blob");
        assert_eq!(source(Some(&pystr::u("120000"))), "skip");
        assert_eq!(source(Some(&pystr::u("160000"))), "skip");
        assert_eq!(source(None), "disk");
        let w = |k: &str, d: &str| why(k, &pystr::u(d)).map(|t| pystr::to_string(&t));
        assert_eq!(w("unreadable", "No such file or directory").unwrap(), "it could not be read (No such file or directory)");
        assert_eq!(w("git_failed", "Permission denied").unwrap(), "git could not be run (Permission denied)");
        assert_eq!(w("not_copied", "File exists").unwrap(), "it could not be copied for the scan (File exists)");
        assert!(w("collision", "").unwrap().starts_with("its name is another file's on this system"));
        assert_eq!(w("other", ""), None);
    }
}
