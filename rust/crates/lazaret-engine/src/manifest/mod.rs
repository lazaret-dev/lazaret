//! Manifests (BR-7 step 3 (b), 0.1.9; core's load_manifest, scan_manifest
//! and scan_gyp, and the npm package's supplychain.js, pyjson.js and
//! pycompat.js until then): a package.json's install hooks (SC-INSTALL-HOOK)
//! and its dependencies from an insecure source (SC-DEP-URL), a binding.gyp's
//! actions and command expansions (`gyp.rs`), and the manifests that cannot
//! be read (SC-MANIFEST-DEPTH, SC-MANIFEST-UNPARSEABLE). A manifest is read
//! as the package manager reads it: a package.json as `json.loads` reads it
//! (`pyjson.rs`), a .gyp file as JSON or else as the Python literal gyp reads
//! (`pylit.rs`), to Python's values (`pyval.rs`).

pub mod gyp;
pub mod pyjson;
pub mod pylit;
pub mod pyval;

use crate::findings::{self, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use pyval::PyVal;
use std::collections::HashMap;

/// The text without one leading byte-order mark (npm strips it).
pub fn body(content: &[u32]) -> &[u32] {
    if content.first() == Some(&0xFEFF) {
        &content[1..]
    } else {
        content
    }
}

/// posixpath.dirname
pub fn dirname(p: &[u32]) -> &[u32] {
    let i = p.iter().rposition(|&c| c == '/' as u32).map_or(0, |k| k + 1);
    let head = &p[..i];
    if !head.is_empty() && head.iter().any(|&c| c != '/' as u32) {
        pystr::rstrip_chars(head, "/")
    } else {
        head
    }
}

/// core.is_root_manifest: a manifest at the top of the tree or package (no directory part).
pub fn is_root(path: &[u32]) -> bool {
    let p = pystr::replace_char(path, '\\' as u32, '/' as u32);
    let d = dirname(pystr::lstrip_chars(&p, "/"));
    d.is_empty() || pystr::eq(d, ".")
}

/// A manifest's issues before its data (core._sc_manifest_depth_issue, manifest_unparseable_issue), at line 1.
fn depth_finding(p: &Pack) -> Finding {
    Finding::new(RuleText::of(p, "_MF_DEPTH_RULE"), 1, None)
}

fn unparseable_finding(p: &Pack, path: &[u32], reason: &str) -> Finding {
    let p2 = pystr::replace_char(path, '\\' as u32, '/' as u32);
    let base = p2.rsplit(|&c| c == '/' as u32).next().unwrap_or(&[]).to_vec();
    let name = if base.is_empty() { path.to_vec() } else { base };
    let mut rule = RuleText::of(p, "_MF_UNPARSEABLE_RULE");
    rule.msg = findings::format(&rule.msg, &[("name", Arg::S(name)), ("reason", Arg::S(pystr::u(reason)))]);
    Finding::new(rule, 1, None)
}

/// core._load_manifest: the manifest's data, a dict, or None and the issue that says why (SC-MANIFEST-DEPTH for a
/// text nested deeper than MAX_MANIFEST_DEPTH, SC-MANIFEST-UNPARSEABLE for a root manifest that cannot be read or
/// whose top level is not an object; nothing for a nested one). `literal`: a .gyp file, read as a Python literal
/// when it is not JSON. `locate`: a key whose position each dict that holds it records (`PyVal::Dict`'s `at`).
pub fn load(p: &Pack, path: &[u32], content: &[u32], literal: bool, locate: Option<&[u32]>) -> (Option<PyVal>, Vec<Finding>) {
    let text = body(content);
    if pyjson::depth_exceeds(text, p.usize("MAX_MANIFEST_DEPTH")) {
        return (None, vec![depth_finding(p)]);
    }
    let mut reason: Option<String> = None;
    let mut data = match pyjson::loads(text, locate) {
        Ok(v) => Some(v),
        Err(pyjson::Error::Depth) => return (None, vec![depth_finding(p)]),
        Err(pyjson::Error::IntDigits(_)) => None, // (loads_plain's alone)
        Err(pyjson::Error::At(at, _)) => {
            reason = Some(format!("JSONDecodeError: {}", pyjson::error_where(text, at)));
            None
        }
    };
    if matches!(data, Some(PyVal::None)) {
        data = None; // (`null`: data is None, as json.loads gives it)
    }
    if data.is_none() && literal {
        let src = pystr::strip(text);
        let base = text.len() - pystr::lstrip(text).len();
        match pylit::literal_eval(src, locate, base) {
            Ok(v) => {
                reason = None;
                data = if v == PyVal::None { None } else { Some(v) };
            }
            Err(pylit::Fail::Depth) => return (None, vec![depth_finding(p)]),
            Err(pylit::Fail::Error(name)) => {
                if reason.is_none() {
                    reason = Some(name.to_string());
                }
            }
        }
    }
    match data {
        Some(v @ PyVal::Dict(..)) => (Some(v), Vec::new()),
        other => {
            if let Some(v) = other {
                reason = Some(format!("top level is a {}, not an object", v.type_name()));
            }
            let issues = if is_root(path) {
                vec![unparseable_finding(p, path, reason.as_deref().unwrap_or("unparseable"))]
            } else {
                Vec::new()
            };
            (None, issues)
        }
    }
}

/// The data of a package.json as the boundary carries it (for the npm package's --deps reading): numbers as ints
/// or floats where JSON has them (null where it has none: NaN, an infinity, a complex number), and each dict as
/// {"d": [[key, value]…]}, its str keys in Python's order (a JavaScript object lists integer-like keys first).
pub fn data_value(v: &PyVal) -> Value {
    match v {
        PyVal::None | PyVal::Ellipsis | PyVal::Complex(..) | PyVal::Bytes(_) => Value::Null,
        PyVal::Bool(b) => Value::Bool(*b),
        PyVal::Int(t) => match pystr::to_string(t).parse::<i64>() {
            Ok(n) if n.unsigned_abs() <= (1u64 << 53) => Value::Int(n),
            _ => match pyval::int_to_float(t) {
                Some(f) => Value::Float(f),
                None => Value::Null,
            },
        },
        PyVal::Float(f) if f.is_finite() => Value::Float(*f),
        PyVal::Float(_) => Value::Null,
        PyVal::Str(s) => Value::Str(s.clone()),
        PyVal::List(items) | PyVal::Tuple(items) | PyVal::Set(items) => Value::Arr(items.iter().map(data_value).collect()),
        PyVal::Dict(items, _) => Value::obj(vec![(
            "d",
            Value::Arr(
                items
                    .iter()
                    .filter_map(|(k, x)| k.as_str().map(|s| Value::Arr(vec![Value::Str(s.to_vec()), data_value(x)])))
                    .collect(),
            ),
        )]),
    }
}

// ---------------- install hooks ----------------

/// core._sc_install_hook_issue's finding: CRITICAL with the reasons a command looks hostile, else MAJOR (or `sev`);
/// `hint`: it runs a download or evaluation tool, worth reading, not evidence.
pub fn hook_finding(p: &Pack, line: usize, script: &[u32], cmd: &[u32], reasons: &[PyStr], sev: Option<&str>, hint: bool) -> Finding {
    let mut rule = RuleText::of(p, "_MF_INSTALL_HOOK_RULE");
    // RA-12: a non-empty reason list is CRITICAL only when a reason is strong; a weaker one (cert-off) is MAJOR
    let sev = sev.or_else(|| crate::signs::install_script_severity(p, reasons)).unwrap_or("MAJOR");
    rule.sev = pystr::u(sev);
    let args = |extra: (&'static str, Arg)| vec![("script", Arg::S(script.to_vec())), extra];
    if !reasons.is_empty() {
        let joined = pystr::join(&pystr::u("; and "), &reasons.iter().map(|r| r.as_slice()).collect::<Vec<_>>());
        rule.msg = findings::format(&p.text("_MF_HOOK_HOSTILE_MSG"), &args(("reasons", Arg::S(joined))));
        rule.why = p.text("_MF_HOOK_HOSTILE_WHY");
    } else {
        let template = p.text(if hint { "_MF_HOOK_HINT_MSG" } else { "_MF_HOOK_MSG" });
        rule.msg = findings::format(&template, &args(("cmd", Arg::S(cmd.to_vec()))));
        rule.why = p.text(if sev == "INFO" { "_MF_HOOK_PREPARE_WHY" } else { "_MF_HOOK_WHY" });
    }
    rule.fix = findings::format(&rule.fix, &[("script", Arg::S(script.to_vec()))]);
    Finding::new(rule, line, None)
}

/// core._script_key_lines: {key: 1-based line of the key} for the keys of the top-level object `section` of a JSON
/// document that parsed (keys compared decoded; a repeated key or section counts where it last appears).
pub fn key_lines(text: &[u32], section: &str) -> HashMap<PyStr, usize> {
    let n = text.len();
    let mut found: HashMap<PyStr, usize> = HashMap::new();
    let mut containers: Vec<u32> = Vec::new();
    let (mut top_key, mut in_section, mut expect_key): (Option<PyStr>, bool, bool) = (None, false, false);
    let (mut line, mut pos) = (1usize, 0usize);
    let mut at = 0;
    while at < n {
        let tok = text[at];
        let c = |ch: char| tok == ch as u32;
        if !(c('"') || c('{') || c('}') || c('[') || c(']') || c(',') || c(':')) {
            at += 1;
            continue;
        }
        let depth = containers.len();
        if c('"') {
            let mut e = at + 1;
            while e < n && text[e] != '"' as u32 {
                if text[e] != '\\' as u32 {
                    e += 1;
                } else if e + 1 < n && text[e + 1] != '\n' as u32 {
                    e += 2;
                } else {
                    e = n;
                }
            }
            if e >= n {
                at += 1; // (no string starts here)
                continue;
            }
            let start = at;
            at = e + 1;
            if expect_key && (depth == 1 || (depth == 2 && in_section)) {
                let key = match pyjson::loads(&text[start..e + 1], None) {
                    Ok(PyVal::Str(k)) => k,
                    _ => text[start + 1..e].to_vec(),
                };
                if depth == 1 {
                    if pystr::eq(&key, section) {
                        found = HashMap::new(); // (a later section of the name replaces an earlier one)
                    }
                    top_key = Some(key);
                } else {
                    line += text[pos..start].iter().filter(|&&ch| ch == '\n' as u32).count();
                    pos = start;
                    found.insert(key, line);
                }
            }
            expect_key = false;
            continue;
        }
        if c('{') || c('[') {
            if depth == 1 && c('{') {
                in_section = top_key.as_deref().is_some_and(|k| pystr::eq(k, section));
            }
            containers.push(tok);
            expect_key = c('{');
        } else if c('}') || c(']') {
            containers.pop();
            if containers.len() < 2 {
                in_section = false;
            }
            expect_key = false;
        } else if c(',') {
            expect_key = containers.last() == Some(&('{' as u32));
        }
        at += 1;
    }
    found
}

/// The scripts of a package.json that run on install: `hooks` when given (a VS Code extension's), npm's otherwise.
fn hook_names(p: &Pack, registry: bool, hooks: Option<&[PyStr]>) -> Vec<PyStr> {
    match hooks {
        Some(h) => h.to_vec(),
        None => p.strs(if registry { "NPM_INSTALL_SCRIPTS" } else { "NPM_LOCAL_INSTALL_SCRIPTS" }).to_vec(),
    }
}

/// core.scan_manifest: a package.json's install hooks (SC-INSTALL-HOOK: G11, hook_command_risk) and the dependencies
/// npm would fetch from an insecure source (SC-DEP-URL, D-14); SC-MANIFEST-DEPTH or SC-MANIFEST-UNPARSEABLE when it
/// cannot be read. `registry`: a package installed from a registry (npm runs preinstall, install and postinstall),
/// else a checked-out project (the prepare family too, INFO when nothing in it looks hostile); `hooks`: the scripts
/// that run when they are not npm's (none for a manifest no tool reads scripts from).
pub fn scan_manifest(p: &Pack, path: &[u32], content: &[u32], registry: bool, hooks: Option<&[PyStr]>, redact: bool) -> Vec<Value> {
    let (data, early) = load(p, path, content, false, None);
    let Some(data) = data else {
        let none = Snippets::new(p, Vec::new(), redact, false).plain();
        return early.iter().map(|f| none.issue(f)).collect();
    };
    let text = body(content);
    let lines: Vec<&[u32]> = pystr::split_char(text, '\n' as u32);
    let snippets = Snippets::new(p, lines.clone(), redact, false).plain();
    let mut out = Vec::new();
    if let Some(PyVal::Dict(..)) = data.get("scripts") {
        let scripts = data.get("scripts").unwrap();
        let prepare = p.strs("NPM_PREPARE_SCRIPTS");
        let mut keys: Option<HashMap<PyStr, usize>> = None;
        for hook in hook_names(p, registry, hooks) {
            let cmd = match scripts.get(&pystr::to_string(&hook)) {
                Some(PyVal::Str(c)) => c,
                _ => continue,
            };
            if pystr::strip(cmd).is_empty() {
                continue;
            }
            let reasons = crate::shell::hook_command_risk(p, cmd, false);
            let hint = reasons.is_empty() && crate::hooks::hook_is_suspicious(p, cmd);
            let sev = if !registry && prepare.contains(&hook) && reasons.is_empty() && !hint { Some("INFO") } else { None };
            let keys = keys.get_or_insert_with(|| key_lines(text, "scripts"));
            let quoted = {
                let mut q = vec!['"' as u32];
                q.extend_from_slice(&hook);
                q.push('"' as u32);
                q
            };
            let line = keys
                .get(&hook)
                .copied()
                .or_else(|| lines.iter().position(|l| pystr::find(l, &quoted, 0).is_some()).map(|i| i + 1))
                .unwrap_or(1);
            let f = hook_finding(p, line, &hook, cmd, &reasons, sev, hint);
            out.push(snippets.issue_with(&f, vec![("cmd", Value::Str(cmd.clone()))]));
        }
    }
    out.extend(dependency_url_issues(p, path, &data, text, &snippets, registry, hooks));
    out
}

// ---------------- dependencies from an insecure source (SC-DEP-URL, D-14) ----------------

/// core.dependency_url_risk: what makes a dependency's spec risky to fetch ("a plain-http URL", "a raw IP address
/// (HOST)"), the ones that apply.
pub fn dependency_url_risk(p: &Pack, spec: &[u32]) -> Vec<PyStr> {
    let mut reasons = Vec::new();
    let Some(m) = p.re("_DEP_URL_RE").match_(spec) else {
        return reasons;
    };
    let scheme = pystr::lower(m.name("scheme").unwrap_or(&[]));
    if pystr::eq(&scheme, "http") || pystr::eq(&scheme, "git+http") {
        reasons.push(pystr::u("a plain-http URL"));
    }
    let host = m.name("host").unwrap_or(&[]);
    let trimmed = pystr::rstrip_chars(host, ".");
    let last = match trimmed.iter().rposition(|&c| c == '.' as u32) {
        Some(k) => &trimmed[k + 1..],
        None => trimmed,
    };
    let bracketed = pystr::starts_with(host, "[") && pystr::ends_with(host, "]");
    if bracketed || (!last.is_empty() && p.re("_IP_LABEL_RE").fullmatch(last).is_some()) {
        let mut r = pystr::u("a raw IP address (");
        r.extend_from_slice(host);
        r.push(')' as u32);
        reasons.push(r);
    }
    reasons
}

/// core._is_package_root: node_modules/<name> or node_modules/@scope/<name>.
pub fn is_package_root(directory: &[u32]) -> bool {
    let parts = pystr::split_char(directory, '/' as u32);
    let k = parts.len();
    k >= 2 && (pystr::eq(parts[k - 2], "node_modules") || (k >= 3 && pystr::eq(parts[k - 3], "node_modules") && pystr::starts_with(parts[k - 2], "@")))
}

/// core._at_package_root: a package's root manifest (at the top, or node_modules/<name>/). (`/`-separated: a
/// backslash is a file name's, as core reads a path on POSIX.)
fn at_package_root(path: &[u32]) -> bool {
    let base = dirname(path);
    base.is_empty() || pystr::eq(base, ".") || is_package_root(base)
}

fn dependency_url_issues(
    p: &Pack,
    path: &[u32],
    data: &PyVal,
    text: &[u32],
    snippets: &Snippets,
    registry: bool,
    hooks: Option<&[PyStr]>,
) -> Vec<Value> {
    let mut out = Vec::new();
    if !(hooks.is_none() && (!registry || at_package_root(path))) {
        return out;
    }
    let base = RuleText::of(p, "_MF_DEP_URL_RULE");
    for field in p.strs(if registry { "NPM_DEP_FIELDS" } else { "NPM_LOCAL_DEP_FIELDS" }) {
        let Some(PyVal::Dict(deps, _)) = data.get(&pystr::to_string(field)) else {
            continue;
        };
        let found: Vec<(&PyStr, &PyStr, Vec<PyStr>)> = deps
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (PyVal::Str(name), PyVal::Str(spec)) => Some((name, spec, dependency_url_risk(p, spec))),
                _ => None,
            })
            .collect();
        if !found.iter().any(|(_, _, why)| !why.is_empty()) {
            continue;
        }
        let keys = key_lines(text, &pystr::to_string(field));
        for (name, spec, why) in found {
            if why.is_empty() {
                continue;
            }
            let joined = pystr::join(&pystr::u(" and "), &why.iter().map(|r| r.as_slice()).collect::<Vec<_>>());
            let mut rule = base.clone();
            let msg = findings::format(
                &base.msg,
                &[("name", Arg::S(name.clone())), ("field", Arg::S(field.clone())), ("reasons", Arg::S(joined)), ("spec", Arg::S(spec.clone()))],
            );
            rule.msg = if snippets.redacts() { snippets.redact_text(&msg) } else { msg };
            let f = Finding::new(rule, keys.get(name).copied().unwrap_or(1), None);
            out.push(snippets.issue(&f));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_and_key_lines() {
        let u = pystr::u;
        assert!(is_root(&u("package.json")) && is_root(&u("/package.json")) && is_root(&u("./package.json")));
        assert!(!is_root(&u("a/package.json")));
        assert!(at_package_root(&u("node_modules/x/package.json")) && at_package_root(&u("a/node_modules/@s/x/package.json")));
        assert!(!at_package_root(&u("node_modules/x/lib/package.json")));
        let text = u("{\n \"scripts\": {\n  \"post\\u0069nstall\": \"x\",\n  \"a\": 1\n },\n \"x\": {\"install\": 1}\n}");
        let k = key_lines(&text, "scripts");
        assert_eq!(k.get(&u("postinstall")), Some(&3));
        assert_eq!(k.get(&u("a")), Some(&4));
        assert_eq!(k.get(&u("install")), None);
    }
}
