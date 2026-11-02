//! The one redactor, for the findings the packages still build (BR-7 step 3 c, 0.1.9; core's mk_issue,
//! redact_result, redact_file_issues and _redact_text, and the npm package's issue.js and redact.js, until then): a
//! finding's snippet and message made and redacted as the engine makes its own (findings.rs), a result swept before
//! it is written, a file's redaction applied to the findings built outside its scan. A file's text comes once per
//! call, with every finding of that file the call makes or sweeps.

use crate::findings::{clip_snippet_line, pem_block_lines, redact_context_line, Finding, RuleText, SecretLiterals, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

/// core._redact_lines: PEM blocks whole, then the line patterns and the file's entropy literals (`secrets`).
pub fn redact_lines(p: &Pack, lines: &[&[u32]], secrets: Option<&SecretLiterals>) -> Vec<PyStr> {
    let pem = pem_block_lines(p, lines);
    lines
        .iter()
        .enumerate()
        .map(|(k, l)| {
            if pem.contains(&k) {
                p.text("REDACTED")
            } else {
                let r = redact_context_line(p, l);
                match secrets {
                    Some(s) => s.redact(p, &r),
                    None => r,
                }
            }
        })
        .collect()
}

/// core._redact_text: free text that may copy source (an issue's msg, a hook's cmd).
pub fn redact_text(p: &Pack, text: &[u32], secrets: Option<&SecretLiterals>) -> PyStr {
    if text.contains(&('\n' as u32)) {
        let parts = pystr::split_char(text, '\n' as u32);
        let out = redact_lines(p, &parts, secrets);
        return pystr::join(&[0x0A], &out.iter().map(|x| x.as_slice()).collect::<Vec<_>>());
    }
    let r = redact_context_line(p, text);
    match secrets {
        Some(s) => s.redact(p, &r),
        None => r,
    }
}

/// A file's entropy literals (core._Redactor(lines).secrets()).
pub fn literals(p: &Pack, text: &[u32], neumaier: bool) -> SecretLiterals {
    SecretLiterals::new(p, pystr::split_char(text, '\n' as u32).into_iter(), neumaier)
}

/// A rule's texts as the packages hand them: {id, name, type, sev, msg, why, fix, ref}.
pub fn rule_of(v: &Value) -> RuleText {
    let t = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_vec()).unwrap_or_default();
    RuleText {
        id: t("id"),
        name: t("name"),
        typ: t("type"),
        sev: t("sev"),
        msg: t("msg"),
        why: t("why"),
        fix: t("fix"),
        ref_: t("ref"),
    }
}

/// core.mk_issue for each of `items` ([rule, line, col or null]), a finding of the file whose lines are `text`'s
/// (split at "\n"): its ±2 lines clipped, redacted when `redact` (the flagged line of a secret rule replaced by the
/// placeholder; the others by the PEM blocks and the line patterns, and the file's entropy literals with `context`:
/// a redactor over these lines, core's _Redactor), and its message redacted the same way.
pub fn make_issues(p: &Pack, text: &[u32], items: &[Value], redact: bool, context: bool, neumaier: bool) -> Vec<Value> {
    let lines = pystr::split_char(text, '\n' as u32);
    let snippets = Snippets::new(p, lines, redact, neumaier);
    let snippets = if context { snippets } else { snippets.plain() };
    items
        .iter()
        .map(|it| {
            let a = it.as_arr().unwrap_or(&[]);
            let rule = a.first().map(rule_of).unwrap_or_default();
            let line = a.get(1).and_then(|x| x.as_i64()).unwrap_or(1).max(0) as usize;
            let col = a.get(2).and_then(|x| x.as_i64()).filter(|&c| c >= 0).map(|c| c as usize);
            snippets.issue(&Finding::new(rule, line, col))
        })
        .collect()
}

fn str_lines(snippet: &[Value]) -> Vec<Option<&[u32]>> {
    snippet.iter().map(|v| v.as_str()).collect()
}

/// `lines` redacted as core._redact_lines does a snippet's (its strings; anything else kept), as values.
fn redact_snippet(p: &Pack, snippet: &[Value]) -> Vec<Value> {
    let lines = str_lines(snippet);
    let strs: Vec<&[u32]> = lines.iter().map(|l| l.unwrap_or(&[])).collect();
    let pem = pem_block_lines(p, &strs);
    snippet
        .iter()
        .enumerate()
        .map(|(k, v)| match v.as_str() {
            Some(_) if pem.contains(&k) => Value::Str(p.text("REDACTED")),
            Some(l) => Value::Str(redact_context_line(p, l)),
            None => v.clone(),
        })
        .collect()
}

fn clip_value(p: &Pack, v: &Value) -> Value {
    match v.as_str() {
        Some(s) => Value::Str(clip_snippet_line(p, s, None)),
        None => v.clone(),
    }
}

/// core.redact_result for each issue ([rule, line, snipStart or null, snippet or null, msg or null, cmd or null]):
/// [snippet, msg, cmd] as the sweep leaves them. With `redact`: msg and cmd redacted (no literals); a secret rule's
/// flagged line not redacted yet replaced by the placeholder (redact_secret_snippet); every other line redacted
/// (PEM blocks whole, the line patterns); every line clipped. Without: the lines clipped.
pub fn redact_issues(p: &Pack, issues: &[Value], redact: bool) -> Vec<Value> {
    let secret_rules = p.strs("SECRET_RULES");
    let fingerprint = p.text("REDACT_FINGERPRINT");
    issues
        .iter()
        .map(|it| {
            let a = it.as_arr().unwrap_or(&[]);
            let get = |k: usize| a.get(k).cloned().unwrap_or(Value::Null);
            let (mut msg, mut cmd) = (get(4), get(5));
            if redact {
                for v in [&mut msg, &mut cmd] {
                    if let Some(s) = v.as_str() {
                        *v = Value::Str(redact_text(p, s, None));
                    }
                }
            }
            let snippet = match a.get(3).and_then(|v| v.as_arr()) {
                None => get(3),
                Some(snip) if !redact => Value::Arr(snip.iter().map(|l| clip_value(p, l)).collect()),
                Some(snip) => {
                    let line = a.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                    let start = a.get(2).and_then(|v| v.as_i64()).unwrap_or(line);
                    let idx = line - start;
                    let rule = a.first().and_then(|v| v.as_str()).unwrap_or(&[]);
                    let secret = secret_rules.iter().any(|s| s.as_slice() == rule);
                    let flagged = if idx >= 0 { snip.get(idx as usize).and_then(|v| v.as_str()) } else { None };
                    let mut out = redact_snippet(p, snip);
                    if let Some(raw) = flagged.filter(|raw| secret && pystr::find(raw, &fingerprint, 0).is_none()) {
                        let mut t = pystr::replace(&p.text("REDACT_PLACEHOLDER"), &pystr::u("{RULE}"), rule);
                        t.extend(pystr::u(&format!(" ({} chars)", raw.len())));
                        out[idx as usize] = Value::Str(t);
                    }
                    Value::Arr(out.iter().map(|l| clip_value(p, l)).collect())
                }
            };
            Value::Arr(vec![snippet, msg, cmd])
        })
        .collect()
}

/// core.redact_file_issues for the findings ([lines or null, msg or null, cmd or null]) built outside the scan of the
/// file whose scan lines are `text`'s: [shown, msg, cmd], `shown` each of `lines` (0-based indices of the file's lines
/// whose raw text the finding's snippet still shows: the packages compare, so that a line is never read twice) as the
/// scan's snippets show it (null past the file's end), msg and cmd redacted with the file's entropy literals.
pub fn redact_file(p: &Pack, text: &[u32], issues: &[Value], neumaier: bool) -> Vec<Value> {
    let lines = pystr::split_char(text, '\n' as u32);
    let n = lines.len();
    let snippets = Snippets::new(p, lines, true, neumaier);
    issues
        .iter()
        .map(|it| {
            let a = it.as_arr().unwrap_or(&[]);
            let get = |k: usize| a.get(k).cloned().unwrap_or(Value::Null);
            let (mut msg, mut cmd) = (get(1), get(2));
            for v in [&mut msg, &mut cmd] {
                if let Some(s) = v.as_str() {
                    *v = Value::Str(snippets.redact_text(s));
                }
            }
            let shown = match a.first().and_then(|v| v.as_arr()) {
                Some(ix) => Value::Arr(
                    ix.iter()
                        .map(|j| match j.as_i64() {
                            Some(j) if j >= 0 && (j as usize) < n => Value::Str(snippets.shown_line(j as usize)),
                            _ => Value::Null,
                        })
                        .collect(),
                ),
                None => Value::Null,
            };
            Value::Arr(vec![shown, msg, cmd])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_and_sweeps() {
        let p = crate::pack::current();
        let u = pystr::u;
        let text = u(&format!("a\nkey = \"{}\"\nb", "Zq8vN3pL0wX7rT2mK9sB4hF6jD1xQ"));
        let rule = Value::obj(vec![
            ("id", Value::Str(u("X-1"))),
            ("name", Value::Str(u("n"))),
            ("type", Value::Str(u("BUG"))),
            ("sev", Value::Str(u("MAJOR"))),
            ("msg", Value::Str(u("m"))),
            ("why", Value::Str(u("w"))),
            ("fix", Value::Str(u("f"))),
            ("ref", Value::Str(u("r"))),
        ]);
        let item = Value::Arr(vec![rule, Value::Int(1), Value::Null]);
        let with = make_issues(&p, &text, std::slice::from_ref(&item), true, true, false);
        let without = make_issues(&p, &text, std::slice::from_ref(&item), true, false, false);
        let snip = |v: &Value| v.as_arr().unwrap()[9].as_arr().unwrap()[1].as_str().unwrap().to_vec();
        assert_eq!(pystr::to_string(&snip(&with[0])), "key = \"[redacted]\"");
        assert!(pystr::to_string(&snip(&without[0])).contains("Zq8v"));
        let swept = redact_issues(&p, &[Value::Arr(vec![Value::Str(u("S-SECRET")), Value::Int(2), Value::Int(1),
            Value::Arr(vec![Value::Str(u("x")), Value::Str(u("password = 'hunter22'")), Value::Int(3)]), Value::Null, Value::Null])], true);
        let s = swept[0].as_arr().unwrap()[0].as_arr().unwrap();
        assert_eq!(pystr::to_string(s[1].as_str().unwrap()), "[redacted: secret rule S-SECRET] (21 chars)");
        assert_eq!(s[2], Value::Int(3));
    }
}
