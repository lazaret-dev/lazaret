//! binding.gyp and .gypi files (G11; core.scan_gyp and its npm twin until
//! BR-7's step 3 (b)): the custom build actions node-gyp runs at `npm
//! install`, and the command expansions (`<!(cmd)`, `>!(cmd)`, `^!(cmd)`,
//! `<!([argv])`, `<!pymod_do_main(module)`) it runs while it configures the
//! build, found anywhere in the document. An action is SC-INSTALL-HOOK:
//! CRITICAL when its command looks hostile read as a program
//! (hook_command_risk), MAJOR otherwise. An expansion is CRITICAL when its
//! command looks hostile (its value is what it prints, so a request it prints
//! is kept), MAJOR when it runs a download or evaluation tool, and INFO
//! inventory when it runs a file of the package (the Miasma trick), with the
//! command as it runs in `cmd`, which --deps and the registry follow to that
//! file; the usual include-path queries are not findings. At most
//! GYP_MAX_HOOK_FINDINGS are listed and one more sums up the rest; a document
//! past the walk's bounds is SC-TRUNCATED. Linear in the size of the file.

use super::pylit;
use super::pyval::{self, PyVal};
use super::{body, hook_finding, load};
use crate::findings::{self, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Action,
    Expansion,
    Pymod,
}

/// {offset of '(': offset of its balanced ')'} (core._gyp_closing_parens).
fn closing_parens(text: &[u32]) -> HashMap<usize, usize> {
    let mut close = HashMap::new();
    let mut opened = Vec::new();
    for (k, &c) in text.iter().enumerate() {
        if c == '(' as u32 {
            opened.push(k);
        } else if c == ')' as u32 {
            if let Some(o) = opened.pop() {
                close.insert(o, k);
            }
        }
    }
    close
}

/// core._gyp_expansion_commands: (command, is_pymod) of every expansion in `text`, in order: the command up to its
/// balanced closing parenthesis, or to the end of the string.
fn expansion_commands(p: &Pack, text: &[u32]) -> Vec<(PyStr, bool)> {
    let close = closing_parens(text);
    let mut out = Vec::new();
    for m in p.re("_GYP_EXPANSION_RE").finditer(text) {
        let i = m.end() - 1;
        let cmd = match close.get(&i) {
            Some(&j) => text[i + 1..j].to_vec(),
            None => text[i + 1..].to_vec(),
        };
        out.push((cmd, pystr::contains(m.group0(), "pymod_do_main")));
    }
    out
}

/// shlex.quote
fn shlex_quote(s: &[u32]) -> PyStr {
    if s.is_empty() {
        return pystr::u("''");
    }
    let safe = |c: u32| {
        char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || "_@%+=:,./-".contains(ch))
    };
    if s.iter().all(|&c| safe(c)) {
        return s.to_vec();
    }
    let mut out = vec!['\'' as u32];
    out.extend(pystr::replace(s, &pystr::u("'"), &pystr::u("'\"'\"'")));
    out.push('\'' as u32);
    out
}

/// core._gyp_hook_command: the shell command an expansion's `cmd` runs, as follow_hook reads it: its expansions and
/// variables replaced (`<(module_root_dir)` and `<(DEPTH)` by `.`, any other by `/_`, a path outside the package), an
/// argv list joined, `pymod_do_main(module args)` as `python -m module args`.
fn hook_command(p: &Pack, cmd: &[u32], kind: Kind) -> PyStr {
    let close = closing_parens(cmd);
    let roots = p.strs("_GYP_ROOT_VARIABLES");
    let mut flat: PyStr = Vec::new();
    let mut pos = 0usize;
    for m in p.re("_GYP_REFERENCE_RE").finditer(cmd) {
        if m.start() < pos {
            continue; // (inside one replaced already)
        }
        let i = m.end() - 1;
        let j = close.get(&i).copied().unwrap_or(cmd.len().saturating_sub(1));
        let g = m.group0();
        let variable = pystr::eq(g, "<(") || pystr::eq(g, ">(") || pystr::eq(g, "^(");
        flat.extend_from_slice(pystr::sub(cmd, pos, m.start()));
        let inner = pystr::strip(pystr::sub(cmd, i + 1, j));
        flat.extend(pystr::u(if variable && roots.iter().any(|r| r.as_slice() == inner) { "." } else { "/_" }));
        pos = j + 1;
    }
    flat.extend_from_slice(pystr::from(cmd, pos));
    if kind == Kind::Pymod {
        let mut out = pystr::u("python -m ");
        out.extend(flat);
        return out;
    }
    if pystr::starts_with(pystr::lstrip(&flat), "[") {
        if let Ok(PyVal::List(items)) = pylit::literal_eval(pystr::strip(&flat), None, 0) {
            if !items.is_empty() && items.iter().all(|a| matches!(a, PyVal::Str(_))) {
                let quoted: Vec<PyStr> = items.iter().map(|a| shlex_quote(a.as_str().unwrap_or(&[]))).collect();
                return pystr::join(&pystr::u(" "), &quoted.iter().map(|q| q.as_slice()).collect::<Vec<_>>());
            }
        }
    }
    flat
}

/// An expansion's command as it runs (`hook_command`), for the tests: `pymod`, a pymod_do_main's.
pub fn hook_command_of(p: &Pack, cmd: &[u32], pymod: bool) -> PyStr {
    hook_command(p, cmd, if pymod { Kind::Pymod } else { Kind::Expansion })
}

/// core._gyp_package_files: the files of the package an expansion's command runs (not a tool, a path outside the
/// package or a JSON file).
fn package_files(p: &Pack, follow: &[u32]) -> BTreeSet<PyStr> {
    let (targets, _complete) = crate::hooks::follow_hook(p, follow);
    targets
        .into_iter()
        .filter(|t| {
            !pystr::starts_with(&pystr::replace_char(t, '\\' as u32, '/' as u32), "/") && !pystr::ends_with(&pystr::lower(t), ".json")
        })
        .collect()
}

/// core._gyp_commands: (command, kind, where the dict holding an action's "action" key has it) for every action and
/// command expansion in the document, in document order, and why the walk stopped early (None if it did not).
fn commands(p: &Pack, data: &PyVal) -> (Vec<(PyStr, Kind, Option<usize>)>, Option<String>) {
    let max_nodes = p.usize("_GYP_MAX_NODES");
    let max_chars = p.usize("_GYP_MAX_COMMAND_CHARS");
    let expansion = p.re("_GYP_EXPANSION_RE");
    let mut out = Vec::new();
    let mut stack: Vec<&PyVal> = vec![data];
    let (mut seen, mut chars) = (0usize, 0usize);
    let mut truncated = None;
    while let Some(&node) = stack.last() {
        if seen >= max_nodes {
            truncated = Some(format!("more than {} values in the gyp document", max_nodes));
            break;
        }
        stack.pop();
        seen += 1;
        match node {
            PyVal::Dict(items, at) => {
                for (k, v) in items {
                    if matches!(k, PyVal::Str(s) if pystr::eq(s, "action")) {
                        if let PyVal::List(args) | PyVal::Tuple(args) = v {
                            let parts: Vec<PyStr> = args.iter().map(pyval::py_str).collect();
                            let cmd = pystr::join(&pystr::u(" "), &parts.iter().map(|x| x.as_slice()).collect::<Vec<_>>());
                            chars += cmd.len();
                            out.push((cmd, Kind::Action, *at));
                        }
                    }
                    stack.push(k);
                    stack.push(v);
                }
            }
            PyVal::List(items) | PyVal::Tuple(items) | PyVal::Set(items) => stack.extend(items.iter()),
            PyVal::Str(s) if expansion.search(s).is_some() => {
                for (cmd, pymod) in expansion_commands(p, s) {
                    chars += cmd.len();
                    out.push((cmd, if pymod { Kind::Pymod } else { Kind::Expansion }, None));
                    if chars > max_chars {
                        break;
                    }
                }
            }
            _ => {}
        }
        if chars > max_chars {
            truncated = Some(format!("more than {} characters of gyp commands", max_chars));
            break;
        }
    }
    out.reverse();
    (out, truncated)
}

/// The first place `needle` is in `hay` (Python's str.find, in linear time: Knuth-Morris-Pratt).
fn find(hay: &[u32], needle: &[u32]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let mut fail = vec![0usize; needle.len()];
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = fail[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let mut k = 0;
    for (i, &c) in hay.iter().enumerate() {
        while k > 0 && c != needle[k] {
            k = fail[k - 1];
        }
        if c == needle[k] {
            k += 1;
            if k == needle.len() {
                return Some(i + 1 - k);
            }
        }
    }
    None
}

struct Hook {
    shown: PyStr,
    kind: Kind,
    at: Option<usize>,
    reasons: Vec<PyStr>,
    follow: Option<PyStr>,
    sev: Option<&'static str>,
    hint: bool,
}

/// core.scan_gyp's issues for a binding.gyp or .gypi file at `path`.
pub fn scan_gyp(p: &Pack, path: &[u32], content: &[u32], redact: bool) -> Vec<Value> {
    let (data, early) = load(p, path, content, true, Some(&pystr::u("action")));
    let Some(data) = data else {
        let none = Snippets::new(p, Vec::new(), redact, false).plain();
        return early.iter().map(|f| none.issue(f)).collect();
    };
    let text = body(content);
    let lines: Vec<&[u32]> = pystr::split_char(text, '\n' as u32);
    let (cmds, truncated) = commands(p, &data);
    let install = p.re("INSTALL_HOOK_RE");
    let require = p.re("_GYP_NODE_REQUIRE_RE");
    let mut hooks: Vec<Hook> = Vec::new();
    let mut listed: Vec<BTreeSet<PyStr>> = Vec::new(); // the files the listed INFO expansions run
    for (cmd, kind, at) in cmds {
        if kind == Kind::Action {
            let reasons = crate::shell::hook_command_risk(p, &cmd, false);
            let hint = reasons.is_empty() && install.search(&cmd).is_some();
            hooks.push(Hook { shown: cmd, kind, at, reasons, follow: None, sev: None, hint });
            continue;
        }
        let follow = hook_command(p, &cmd, kind);
        // an expansion's output is its value: a request it prints is kept
        let reasons = crate::shell::hook_command_risk(p, &follow, true);
        let hint = reasons.is_empty() && install.search(&require.sub(&cmd, &pystr::u(" "), 0)).is_some();
        if reasons.is_empty() && !hint {
            let runs = package_files(p, &follow);
            if runs.is_empty() || listed.contains(&runs) {
                continue; // (the usual include-path queries; a file listed already)
            }
            listed.push(runs);
        }
        let shown = if kind == Kind::Pymod {
            let mut s = pystr::u("pymod_do_main(");
            s.extend(&cmd);
            s.push(')' as u32);
            s
        } else {
            cmd
        };
        let sev = if reasons.is_empty() && !hint { Some("INFO") } else { None };
        hooks.push(Hook { shown, kind, at: None, reasons, follow: Some(follow), sev, hint });
    }
    let newlines: Vec<usize> = if hooks.is_empty() { Vec::new() } else { (0..text.len()).filter(|&k| text[k] == '\n' as u32).collect() };
    let mut first_line: HashMap<PyStr, usize> = HashMap::new();
    let mut line_of = |h: &Hook| -> usize {
        if h.kind == Kind::Action {
            return h.at.map_or(1, |at| newlines.partition_point(|&n| n < at) + 1);
        }
        let cmd = &h.shown;
        if cmd.is_empty() || cmd.contains(&('\n' as u32)) {
            return 1; // (no single line holds it)
        }
        if let Some(&l) = first_line.get(cmd) {
            return l;
        }
        let at = find(text, cmd).or_else(|| {
            // written with \' or \" in a quoted string
            let a = find(text, &pystr::replace(cmd, &pystr::u("'"), &pystr::u("\\'")));
            let b = find(text, &pystr::replace(cmd, &pystr::u("\""), &pystr::u("\\\"")));
            a.or(b)
        });
        let l = at.map_or(1, |at| newlines.partition_point(|&n| n < at) + 1);
        first_line.insert(cmd.clone(), l);
        l
    };
    let snippets = Snippets::new(p, lines, redact, false).plain();
    let limit = p.usize("GYP_MAX_HOOK_FINDINGS");
    let mut out = Vec::new();
    for h in hooks.iter().take(limit) {
        let script = pystr::u(if h.kind == Kind::Action { "binding.gyp action" } else { "binding.gyp command expansion" });
        let mut f = hook_finding(p, line_of(h), &script, &h.shown, &h.reasons, h.sev, h.hint);
        if h.sev == Some("INFO") {
            f.rule.why = p.text("_GYP_EXPANSION_FILE_WHY");
        }
        let cmd = h.follow.clone().unwrap_or_else(|| h.shown.clone());
        out.push(snippets.issue_with(&f, vec![("cmd", Value::Str(cmd))]));
    }
    if hooks.len() > limit {
        let rest = &hooks[limit..];
        let bad = rest.iter().filter(|h| !h.reasons.is_empty()).count();
        let mut rule = RuleText::of(p, "_MF_INSTALL_HOOK_RULE");
        rule.sev = pystr::u(if bad > 0 {
            "CRITICAL"
        } else if rest.iter().any(|h| h.sev != Some("INFO")) {
            "MAJOR"
        } else {
            "INFO"
        });
        rule.msg = findings::format(
            &p.text("_MF_GYP_REST_MSG"),
            &[("n", Arg::I(rest.len() as i64)), ("bad", Arg::I(bad as i64)), ("limit", Arg::I(limit as i64))],
        );
        rule.why = p.text("_MF_GYP_REST_WHY");
        rule.fix = p.text("_MF_GYP_REST_FIX");
        let f = Finding::new(rule, line_of(&rest[0]), None);
        out.push(snippets.issue(&f));
    }
    if let Some(detail) = truncated {
        out.push(truncated_issue(p, &detail));
    }
    out
}

/// core.truncated_issue (a plain dict: no snippet, nothing redacted).
pub fn truncated_issue(p: &Pack, detail: &str) -> Value {
    let r = RuleText::of(p, "_MF_TRUNCATED_RULE");
    let msg = findings::format(&r.msg, &[("detail", Arg::S(pystr::u(detail)))]);
    Value::Arr(vec![
        Value::Str(r.id),
        Value::Str(r.name),
        Value::Str(r.typ),
        Value::Str(r.sev),
        Value::Str(msg),
        Value::Str(r.why),
        Value::Str(r.fix),
        Value::Str(r.ref_),
        Value::Int(1),
        Value::Arr(Vec::new()),
        Value::Int(1),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_finding() {
        let u = pystr::u;
        assert_eq!(pystr::to_string(&shlex_quote(&u("a b'c"))), "'a b'\"'\"'c'");
        assert_eq!(pystr::to_string(&shlex_quote(&u("x/y.z-1"))), "x/y.z-1");
        assert_eq!(pystr::to_string(&shlex_quote(&u(""))), "''");
        assert_eq!(find(&u("aaab aab"), &u("aab")), Some(1));
        assert_eq!(find(&u("abc"), &u("abd")), None);
        assert_eq!(closing_parens(&u("a(b(c)d)(")).get(&1), Some(&7));
    }
}
