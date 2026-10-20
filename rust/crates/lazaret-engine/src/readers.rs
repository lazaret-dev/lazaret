//! The findings of the package readers (BR-7 step 3 f, 0.1.9; core.package_reader_issues and the npm package's
//! packageReaderIssues until then): what goread and rsread answer for a Go module or a crate, as the issues a --deps
//! scan's vendored modules and crates and the registry's releases report. `go_package` and `rs_crate` add them to
//! their answer when the caller says whose code it is (`what`) and names the files (`names`, as the issues show them).

use crate::findings::{format, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};

fn u(s: &str) -> PyStr {
    pystr::u(s)
}

/// What the readers' answers say ("module": a Go module's, "crate": a crate's, "sdist": the crate inside an sdist,
/// N-17), and how the issues are made.
pub struct Reading<'a> {
    pub what: &'a str,
    /// the files' names, as the issues show them, in the order the reader was given the files
    pub names: &'a [PyStr],
    /// the files' texts, in the same order
    pub texts: &'a [&'a [u32]],
    pub redact: bool,
    pub neumaier: bool,
}

/// `text` on one line, at most `limit` characters (core._one_line).
fn one_line(text: &[u32], limit: usize) -> PyStr {
    let joined = pystr::join(&u(" "), &pystr::split_ws(text));
    if joined.len() <= limit {
        return joined;
    }
    let mut out = joined[..limit.saturating_sub(1)].to_vec();
    out.push(0x2026);
    out
}

/// n with thousands separators (Python's f"{n:,}").
fn commas(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn text(p: &Pack, key: &str) -> PyStr {
    p.map_text("_READER_TEXTS", key)
}

fn strs_of(v: Option<&Value>) -> Vec<PyStr> {
    v.and_then(|x| x.as_arr()).unwrap_or(&[]).iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect()
}

fn joined(reasons: &[PyStr]) -> PyStr {
    pystr::join(&u("; and "), &reasons.iter().map(|r| r.as_slice()).collect::<Vec<_>>())
}

/// The issues of a reader's answer (`answer`: go_package's or rs_crate's, as the call answers it): [(the index of
/// the file it is in, the issue)]. A build script and a procedural macro are SC-INSTALL-HOOK, CRITICAL for a strong
/// reason and MAJOR when every reason is a weaker one (install_script_severity: TLS certificate verification turned
/// off), the reasons of all the files it reads taken together; what runs at start (Go's init code, #[ctor]) the
/// import-time test; the strong reasons of the rest SC-USE-RISK; //go:generate SC-GO-GENERATE (INFO); an import of
/// another module's testdata/ package SC-GO-TESTDATA-IMPORT (MAJOR); a .go file the parser refused SC-TRUNCATED.
pub fn issues(p: &Pack, answer: &Value, r: &Reading) -> Vec<(usize, Value)> {
    let mut out: Vec<(usize, Value)> = Vec::new();
    let n = r.names.len();
    let at = |found: &Value| match found.get("file").and_then(|f| f.as_i64()) {
        Some(k) if k >= 0 && (k as usize) < n => k as usize,
        _ => 0,
    };
    let name = |k: usize| r.names.get(k).cloned().unwrap_or_default();
    let line_of = |found: &Value| found.get("line").and_then(|l| l.as_i64()).filter(|&l| l > 0).unwrap_or(1) as usize;
    let mut issue = |rule: &str, sev: &str, k: usize, line: usize, msg: PyStr, why: PyStr, fix: PyStr| {
        let rt = RuleText {
            id: u(rule),
            name: p.map_text("_PACKAGE_RULE_NAMES", rule),
            typ: u("HOTSPOT"),
            sev: u(sev),
            msg,
            why,
            fix,
            ref_: text(p, "ref"),
        };
        // (lines as the text rules number them: a Go file's lone "\r", which the reader keeps, ends one, F-06)
        let lined = crate::decode::normalize_newlines(r.texts.get(k).copied().unwrap_or(&[]));
        let lines = pystr::split_char(&lined, '\n' as u32);
        let snippets = Snippets::new(p, lines, r.redact, r.neumaier); // (the file's own literals too)
        out.push((k, snippets.issue(&Finding::new(rt, line, None))));
    };
    let sdist = r.what == "sdist";
    let variant = |key: &str| text(p, &format!("{key}_{}", if sdist { "sdist" } else { "crate" }));
    for (key, why) in [("build", if sdist { "_SDIST_BUILD_WHY" } else { "_BUILD_SCRIPT_WHY" }), ("macros", if sdist { "_SDIST_PROC_MACRO_WHY" } else { "_PROC_MACRO_WHY" })] {
        let Some(found) = answer.get(key).filter(|f| matches!(f, Value::Obj(_))) else { continue };
        let reasons = strs_of(found.get("reasons"));
        if reasons.is_empty() {
            continue;
        }
        let k = at(found);
        let msg = format(
            &text(p, "hook_msg"),
            &[("path", Arg::S(name(k))), ("how", Arg::S(variant(key))), ("reasons", Arg::S(joined(&reasons)))],
        );
        // RA-12: a build script / procedural macro is CRITICAL for any strong reason, MAJOR for a weaker one
        // (cert-off) alone
        let sev = crate::signs::install_script_severity(p, &reasons).unwrap_or("MAJOR");
        issue("SC-INSTALL-HOOK", sev, k, line_of(found), msg, p.text(why), variant("hook_fix"));
    }
    let (start_how, start_why) = match r.what {
        "module" => (text(p, "start_module"), p.text("_GO_START_WHY")),
        "crate" => (text(p, "start_crate"), p.text("_RUST_START_WHY")),
        _ => (text(p, "start_sdist"), p.text("_SDIST_START_WHY")),
    };
    for found in answer.get("start").and_then(|s| s.as_arr()).unwrap_or(&[]) {
        let reasons = strs_of(found.get("reasons"));
        if reasons.is_empty() {
            continue;
        }
        let k = at(found);
        let msg = format(
            &text(p, "hook_msg"),
            &[("path", Arg::S(name(k))), ("how", Arg::S(start_how.clone())), ("reasons", Arg::S(joined(&reasons)))],
        );
        let sev = crate::signs::import_time_severity(p, &reasons);
        issue("SC-IMPORT-RISK", sev, k, line_of(found), msg, start_why.clone(), text(p, "start_fix"));
    }
    let strong_prefixes = p.strs("_STRONG_IMPORT_REASONS");
    let whose = text(p, &format!("whose_{}", r.what));
    for found in answer.get("uses").and_then(|s| s.as_arr()).unwrap_or(&[]) {
        let strong: Vec<PyStr> =
            strs_of(found.get("reasons")).into_iter().filter(|x| strong_prefixes.iter().any(|s| x.starts_with(s))).collect();
        if strong.is_empty() {
            continue;
        }
        let k = at(found);
        let msg = format(
            &text(p, "use_msg"),
            &[
                ("path", Arg::S(name(k))),
                ("strong", Arg::S(joined(&strong))),
                ("when", Arg::S(text(p, if sdist { "use_when_sdist" } else { "use_when" }))),
                ("whose", Arg::S(whose.clone())),
            ],
        );
        let fix = if sdist { text(p, "use_fix_sdist") } else { format(&text(p, "use_fix"), &[("what", Arg::S(u(r.what)))]) };
        let sev = if strong.iter().all(|s| s.starts_with(&u(crate::model::deletion::REASON))) { "MAJOR" } else { "CRITICAL" };
        issue("SC-USE-RISK", sev, k, line_of(found), msg, p.text("_PACKAGE_USE_RISK_WHY"), fix);
    }
    let generate = answer.get("generate").and_then(|g| g.as_arr()).unwrap_or(&[]);
    if let Some(first) = generate.first().and_then(|g| g.as_arr()) {
        let k = first.first().and_then(|x| x.as_i64()).filter(|&k| k >= 0 && (k as usize) < n).unwrap_or(0) as usize;
        let line = first.get(1).and_then(|x| x.as_i64()).unwrap_or(1).max(0) as usize;
        let cmd = first.get(2).and_then(|x| x.as_str()).unwrap_or(&[]);
        let more = if generate.len() > 1 { u(&format!(" (and {} more)", commas(generate.len() - 1))) } else { Vec::new() };
        let msg = format(
            &text(p, "generate_msg"),
            &[("path", Arg::S(name(k))), ("cmd", Arg::S(one_line(cmd, 200))), ("more", Arg::S(more))],
        );
        issue("SC-GO-GENERATE", "INFO", k, line, msg, p.text("_GO_GENERATE_WHY"), text(p, "generate_fix"));
    }
    // F-06: an import of another module's testdata/ package (MAJOR): a build of this module compiles it, while that
    // module's own reading leaves it out (no import of its own names it). Once, on the first, with how many more
    // import paths
    let triple = |g: &Value| -> Option<(usize, usize, PyStr)> {
        let g = g.as_arr()?;
        let k = g.first().and_then(|x| x.as_i64()).filter(|&k| k >= 0 && (k as usize) < n).unwrap_or(0) as usize;
        let line = g.get(1).and_then(|x| x.as_i64()).unwrap_or(1).max(1) as usize;
        Some((k, line, g.get(2).and_then(|x| x.as_str()).unwrap_or(&[]).to_vec()))
    };
    let imports: Vec<(usize, usize, PyStr)> =
        answer.get("testdataImports").and_then(|g| g.as_arr()).unwrap_or(&[]).iter().filter_map(triple).collect();
    if let Some((k, line, path)) = imports.first() {
        let mut paths: Vec<&PyStr> = imports.iter().map(|(_, _, p)| p).collect();
        paths.sort();
        paths.dedup();
        let more = match paths.len() - 1 {
            0 => Vec::new(),
            1 => u(" (and 1 more such import)"),
            m => u(&format!(" (and {} more such imports)", commas(m))),
        };
        let msg = format(
            &text(p, "testdata_import_msg"),
            &[("path", Arg::S(name(*k))), ("import", Arg::S(one_line(path, 200))), ("more", Arg::S(more))],
        );
        issue("SC-GO-TESTDATA-IMPORT", "MAJOR", *k, *line, msg, p.text("_GO_TESTDATA_IMPORT_WHY"), text(p, "testdata_import_fix"));
    }
    // F-06: a .go file the Go reader's parser refused, in a package a build may compile (the parser is not Go's own):
    // what its code does was not read, so the module is not cleared (SC-TRUNCATED: INCOMPLETE), once, on the first.
    // A file whose text, as the reader was given it, is not text (decode_member's measure) is not one, so a file has
    // one SC-TRUNCATED: the decoding's says so already, or the file is UTF-16 or UTF-32, whose NULs and invalid UTF-8
    // Go refuses (go_text)
    let refused: Vec<(usize, usize, PyStr)> = answer.get("refused").and_then(|g| g.as_arr()).unwrap_or(&[]).iter()
        .filter_map(triple)
        .filter(|(k, _, _)| !r.texts.get(*k).is_some_and(|t| crate::decode::undecodable_share(t) > crate::decode::NON_TEXT_SHARE))
        .collect();
    if let Some((k, line, why)) = refused.first() {
        let (k, line) = (*k, *line);
        let why = one_line(why, 200);
        let (more, them) = match refused.len() - 1 {
            0 => (String::new(), ("its", "it")),
            1 => (" and 1 more .go file".to_string(), ("their", "them")),
            m => (format!(" and {} more .go files", commas(m)), ("their", "them")),
        };
        let detail = format!(
            "the engine's Go parser refused {} at line {} ({}){}, so what {} code does was not read (only {} text); a \
             build may compile {}",
            pystr::to_string(&name(k)), line, pystr::to_string(&why), more, them.0, them.0, them.1
        );
        out.push((k, crate::manifest::gyp::truncated_issue(p, &detail)));
    }
    out
}

/// The answer's issues as the calls give them: [[file index, issue]…].
pub fn issues_value(found: Vec<(usize, Value)>) -> Value {
    Value::Arr(found.into_iter().map(|(k, i)| Value::Arr(vec![Value::Int(k as i64), i])).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(one_line(&u("a \n\t b  c"), 200), u("a b c"));
        assert_eq!(one_line(&u("abcdef"), 4), u("abc\u{2026}"));
        assert_eq!(commas(1234), "1,234");
    }
}
