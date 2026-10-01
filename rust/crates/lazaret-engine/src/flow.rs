//! Local data sent (0.1.8): a port of lazaret.scanner.core's
//! `local_data_sent_at` and its helpers (section "Local data sent"), and of
//! `secret_endpoint_at` (a webhook whose secret is written in the code),
//! function for function. What a script reads from the machine is followed
//! through the names given it to where it is sent; offsets are code-point
//! indices, as in Python.

use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::rxutil;
use crate::shell;
use crate::signs::{call_args_len, first_arg, literal_spans};
use std::collections::{HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn is(s: &[u32], lit: &str) -> bool {
    pystr::eq(s, lit)
}

fn in_set(set: &[PyStr], s: &[u32]) -> bool {
    set.iter().any(|x| x.as_slice() == s)
}

/// The kind names local data is read as (core's strings).
fn kind_of(s: &[u32]) -> &'static str {
    for k in ["identity", "report", "environment", "file", "credentials", "address", "lookup-identity"] {
        if is(s, k) {
            return k;
        }
    }
    "identity"
}

/// A read: (offset, end, the index after its '(' or -1, kind, what).
type Source = (usize, usize, isize, &'static str, PyStr);
/// What a name holds: (kind, what, through a parameter).
type Got = (&'static str, PyStr, bool);

/// text[lo:lo+span] clipped, and the length core's _call_args gives it.
fn args_len(text: &[u32], lo: usize, span: usize) -> usize {
    call_args_len(pystr::sub(text, lo, lo + span))
}

/// core._ld_literal_test: is a position in a string literal (a template's
/// or an f-string's text is code)?
pub struct LiteralTest {
    spans: Vec<(usize, usize)>,
    starts: Vec<usize>,
}

impl LiteralTest {
    pub fn new(p: &Pack, text: &[u32]) -> LiteralTest {
        let is_ff = |x: u32| x == c('f') || x == c('F');
        let is_rb = |x: u32| x == c('r') || x == c('R') || x == c('b') || x == c('B');
        let spans: Vec<(usize, usize)> = literal_spans(p, text)
            .into_iter()
            .filter(|&(a, _)| {
                text[a] != c('`') && !(a > 0 && is_ff(text[a - 1])) && !(a > 1 && is_ff(text[a - 2]) && is_rb(text[a - 1]))
            })
            .collect();
        let starts = spans.iter().map(|&(a, _)| a).collect();
        LiteralTest { spans, starts }
    }

    pub fn at(&self, pos: usize) -> bool {
        let k = self.starts.partition_point(|&s| s <= pos);
        k > 0 && pos < self.spans[k - 1].1
    }
}

/// core._ld_statement_end: the end of the statement whose value starts at i.
pub fn ld_statement_end(p: &Pack, text: &[u32], mut i: usize) -> usize {
    let n = text.len().min(i + p.usize("_LD_STATEMENT_SPAN"));
    let mut depth = 0usize;
    while i < n {
        let ch = text[i];
        if ch == c('"') || ch == c('\'') || ch == c('`') {
            if ch != c('`') && i + 3 <= text.len() && text[i + 1] == ch && text[i + 2] == ch {
                let triple = [ch, ch, ch];
                match pystr::find(text, &triple, i + 3) {
                    Some(j) if j + 3 <= n => {
                        i = j + 3;
                        continue;
                    }
                    _ => return n,
                }
            }
            let mut j = i + 1;
            while j < n && text[j] != ch {
                j += if text[j] == c('\\') { 2 } else { 1 };
            }
            if j >= n {
                return n;
            }
            i = j + 1;
            continue;
        }
        if ch == c('(') || ch == c('[') || ch == c('{') {
            depth += 1;
        } else if ch == c(')') || ch == c(']') || ch == c('}') {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        } else if depth == 0 && (ch == c(';') || ch == c('\n')) {
            return i;
        }
        i += 1;
    }
    n
}

/// core._ld_split_args: (start, end) of a call's arguments in args.
fn ld_split_args(args: &[u32]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let n = args.len();
    let mut depth: isize = 0;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < n {
        let ch = args[i];
        if ch == c('"') || ch == c('\'') || ch == c('`') {
            match pystr::find_char(args, ch, i + 1) {
                None => break,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        if ch == c('(') || ch == c('[') || ch == c('{') {
            depth += 1;
        } else if ch == c(')') || ch == c(']') || ch == c('}') {
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            out.push((start, i));
            start = i + 1;
        }
        i += 1;
    }
    out.push((start, n));
    out
}

/// core._ld_object_spans: the values of the object literal whose '{' is at lo.
fn ld_object_spans(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize, bool)> {
    let close = lo + 1 + call_args_len(pystr::sub(text, lo + 1, hi));
    let keys = p.strs("_LD_OPTION_KEYS");
    let key_re = p.re("_LD_KEY_RE");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let mut out = Vec::new();
    for (a, b) in ld_split_args(pystr::sub(text, lo + 1, close)) {
        let part = pystr::sub(text, lo + 1 + a, lo + 1 + b);
        match key_re.match_(part) {
            Some(key) => {
                if func_value.match_at(part, key.end() as isize, part.len() as isize).is_some() {
                    continue; // a function (a callback): code, not data
                }
                let name = key.group(1).or_else(|| key.group(2)).unwrap_or(&[]);
                out.push((lo + 1 + a + key.end(), lo + 1 + b, in_set(keys, name)));
            }
            None => out.push((lo + 1 + a, lo + 1 + b, in_set(keys, pystr::strip(part)))),
        }
    }
    out
}

/// core._ld_value_spans: an object literal's values, else the value whole.
fn ld_value_spans(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize, bool)> {
    let stripped = pystr::lstrip(pystr::sub(text, lo, hi));
    if pystr::starts_with(stripped, "{") {
        return ld_object_spans(p, text, hi - stripped.len(), hi);
    }
    vec![(lo, hi, false)]
}

/// core._ld_arg_spans: a call's arguments text[lo:hi], each an address or data.
fn ld_arg_spans(p: &Pack, text: &[u32], lo: usize, hi: usize, addresses: usize, process: bool) -> Vec<(usize, usize, bool)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let option_keys = p.strs("_LD_OPTION_KEYS");
    let process_keys = p.strs("_LD_PROCESS_KEYS");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let mut out = Vec::new();
    for (k, (a, b)) in ld_split_args(pystr::sub(text, lo, hi)).into_iter().enumerate() {
        let (a, b) = (lo + a, lo + b);
        if func_value.match_at(text, a as isize, b as isize).is_some() {
            continue; // a callback: code run later, not data sent
        }
        if k < addresses {
            out.push((a, b, true));
            continue;
        }
        if let Some(kw) = kwarg.match_at(text, a as isize, b as isize) {
            let name = kw.group(1).unwrap_or(&[]);
            out.push((kw.end(), b, in_set(option_keys, name) || (process && in_set(process_keys, name))));
        } else if process && pystr::starts_with(pystr::lstrip(pystr::sub(text, a, b)), "{") {
            out.push((a, b, true));
        } else {
            out.extend(ld_value_spans(p, text, a, b));
        }
    }
    out
}

/// core._ld_process_options: the values of a process's options in a call's arguments text[lo:hi].
fn ld_process_options(p: &Pack, text: &[u32], lo: usize, hi: usize) -> Vec<(usize, usize)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let key_re = p.re("_LD_KEY_RE");
    let process_keys = p.strs("_LD_PROCESS_KEYS");
    let mut out = Vec::new();
    for (a, b) in ld_split_args(pystr::sub(text, lo, hi)) {
        let (a, b) = (lo + a, lo + b);
        if let Some(kw) = kwarg.match_at(text, a as isize, b as isize) {
            if in_set(process_keys, kw.group(1).unwrap_or(&[])) {
                out.push((kw.end(), b));
            }
            continue;
        }
        let stripped = pystr::lstrip(pystr::sub(text, a, b));
        if pystr::starts_with(stripped, "{") {
            let start = b - stripped.len();
            let close = start + 1 + call_args_len(pystr::sub(text, start + 1, b));
            for (cc, d) in ld_split_args(pystr::sub(text, start + 1, close)) {
                if let Some(key) = key_re.match_at(text, (start + 1 + cc) as isize, (start + 1 + d) as isize) {
                    let name = key.group(1).or_else(|| key.group(2)).unwrap_or(&[]);
                    if in_set(process_keys, name) {
                        out.push((key.end(), start + 1 + d));
                    }
                }
            }
        }
    }
    out
}

/// core._ld_bound: the arguments of a call at `at` given a function whose parameters are `names`.
fn ld_bound(p: &Pack, text: &[u32], at: usize, args_len: usize, names: &[PyStr]) -> Vec<(PyStr, usize, usize)> {
    let kwarg = p.re("_LD_KWARG_RE");
    let mut out = Vec::new();
    for (k, (a, b)) in ld_split_args(pystr::sub(text, at, at + args_len)).into_iter().enumerate() {
        let (a, b) = (at + a, at + b);
        match kwarg.match_at(text, a as isize, b as isize) {
            Some(kw) if in_set(names, kw.group(1).unwrap_or(&[])) => {
                out.push((kw.group(1).unwrap_or(&[]).to_vec(), kw.end(), b));
            }
            _ => {
                if k < names.len() {
                    out.push((names[k].clone(), a, b));
                }
            }
        }
    }
    out
}

/// core._ld_word_before: where the run of spaces before text[i] starts.
fn ld_word_before(text: &[u32], mut i: usize) -> usize {
    while i > 0 && (text[i - 1] == c(' ') || text[i - 1] == c('\t') || text[i - 1] == c('\n')) {
        i -= 1;
    }
    i
}

fn ld_ident_char(ch: u32) -> bool {
    ch < 128 && (pystr::is_alnum(ch) || ch == c('_') || ch == c('$'))
}

/// Does a word of `words` end at j in text, not inside a longer name?
fn word_ends_at(text: &[u32], j: usize, words: &[PyStr]) -> bool {
    words.iter().any(|w| {
        j >= w.len() && {
            let k = j - w.len();
            text[k..j] == w[..] && (k == 0 || !ld_ident_char(text[k - 1]))
        }
    })
}

/// core._ld_tested: is the value text[start:end] tested rather than used?
fn ld_tested(p: &Pack, text: &[u32], start: usize, end: usize) -> bool {
    if p.re("_LD_TEST_AFTER_RE").match_at(text, end as isize, text.len() as isize).is_some() {
        return true;
    }
    let j = ld_word_before(text, start);
    (j > 0 && text[j - 1] == c('!')) || word_ends_at(text, j, p.strs("_LD_TEST_BEFORE"))
}

/// core._ld_defined: is the call text[start:end] (to its ')') a function's definition?
fn ld_defined(p: &Pack, text: &[u32], start: usize, end: usize) -> bool {
    if end < text.len()
        && text[end] == c(')')
        && p.re("_LD_BODY_RE").match_at(text, end as isize + 1, text.len() as isize).is_some()
    {
        return true;
    }
    word_ends_at(text, ld_word_before(text, start), &[u("def"), u("function")])
}

/// core._ld_names_in: the first name of `names` used in text[lo:hi] (not in a literal).
fn ld_names_in(p: &Pack, text: &[u32], lo: usize, hi: usize, names: &HashSet<PyStr>, lit: &LiteralTest) -> Option<PyStr> {
    if names.is_empty() {
        return None;
    }
    for m in p.re("_IDENT_TOKEN_RE").finditer_at(text, lo as isize, hi as isize) {
        if names.contains(m.group0()) && !lit.at(m.start()) {
            return Some(m.group0().to_vec());
        }
    }
    None
}

/// core._ld_outside: does text[lo:hi], a call's first argument, name a path outside the package?
fn ld_outside(p: &Pack, text: &[u32], lo: usize, hi: usize, reader: bool, outside: &HashSet<PyStr>, lit: &LiteralTest) -> bool {
    let first = pystr::sub(text, lo, hi);
    if p.re("_LD_OWN_FOLDER_RE").search(first).is_some() {
        return false;
    }
    if p.re("_LD_FS_ROOT_RE").match_(first).is_some() {
        return true;
    }
    if reader
        && (p.re("_LD_ABSOLUTE_RE").match_(first).is_some()
            || p.re("_LD_HOME_RE").search(first).is_some()
            || p.re("_LD_ABSOLUTE_IN_RE").search(first).is_some()
            || p.re("_LD_CRED_FILE_RE").match_(first).is_some())
    {
        return true;
    }
    !outside.is_empty() && p.re("_LD_PATH_EXPR_RE").match_(first).is_some() && ld_names_in(p, text, lo, hi, outside, lit).is_some()
}

/// The module's names for the machine's names (core._LD_MODULE_NAMES[module]): (name, kind) pairs.
fn module_names(p: &Pack, module: &[u32]) -> Vec<(PyStr, &'static str)> {
    let raw = match p.raw("_LD_MODULE_NAMES") {
        Some(v) => v,
        None => return Vec::new(),
    };
    let table = raw.get("map").and_then(|m| m.get(&pystr::to_string(module))).and_then(|v| v.get("map")).and_then(|m| m.as_obj());
    match table {
        Some(entries) => entries
            .iter()
            .map(|(k, v)| (k.clone(), kind_of(v.get("value").and_then(|x| x.as_str()).unwrap_or(&[]))))
            .collect(),
        None => Vec::new(),
    }
}

/// core._ld_sources: where text reads local data.
fn ld_sources(p: &Pack, text: &[u32], lit: &LiteralTest, outside: &HashSet<PyStr>, own: &HashSet<PyStr>) -> Vec<Source> {
    let max = p.usize("_LD_MAX");
    let span = p.usize("_DD_ARG_SPAN");
    let mut out: Vec<Source> = Vec::new();
    let identity_var = p.re("_SH_IDENTITY_VAR_RE");
    let secret_var = p.re("_SH_SECRET_VAR_RE");
    let quiet = p.re("_LD_ENV_QUIET_RE");
    for (k, m) in p.re("_LD_ENV_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let name = (1..=5).find_map(|g| m.group(g));
        let mut end = m.end();
        if m.group(4).is_some() || m.group(5).is_some() {
            // a call's value: after the call
            end += args_len(text, end, span) + 1;
        }
        let name = match name {
            None => continue,
            Some(n) => n,
        };
        if ld_tested(p, text, m.start(), end) {
            continue;
        }
        if identity_var.match_(name).is_some() {
            out.push((m.start(), m.end(), -1, "identity", name.to_vec()));
        } else if secret_var.search(name).is_some() && quiet.match_(name).is_none() {
            out.push((m.start(), m.end(), -1, "environment", name.to_vec()));
        }
    }
    let select = p.re("_LD_ENV_SELECT_RE");
    let excludes = p.re("_LD_EXCLUDES_RE");
    let whole = p.text("_LD_WHOLE_ENV");
    for (k, m) in p.re("_LD_ENV_ALL_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if lit.at(m.start()) || ld_tested(p, text, m.start(), m.end()) {
            continue;
        }
        if let Some(s) = select.match_at(text, m.end() as isize, text.len() as isize) {
            let cond = pystr::sub(text, s.end(), s.end() + args_len(text, s.end(), span));
            if excludes.search(cond).is_none() && secret_var.search(cond).is_none() {
                continue;
            }
        }
        out.push((m.start(), m.end(), -1, "environment", whole.clone()));
    }
    for (k, m) in p.re("_LD_IDENTITY_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if !lit.at(m.start()) {
            let g1 = m.group(1);
            let kind = if g1.map_or(false, |g| is(g, "homedir") || is(g, "networkInterfaces")) { "report" } else { "identity" };
            let called = m.group(2).is_some() || m.group(3).is_some();
            let what = match g1 {
                Some(g) if !g.is_empty() => g.to_vec(),
                _ => u("user or host name"),
            };
            out.push((m.start(), m.end(), if called { m.end() as isize } else { -1 }, kind, what));
        }
    }
    let mut imported: Vec<(PyStr, (&'static str, PyStr))> = Vec::new(); // local name -> (kind, the module's name for it)
    if pystr::contains(text, "os") {
        let name_re = p.re("_LD_IMPORT_NAME_RE");
        for (js, pattern) in [(true, p.re("_LD_IMPORT_JS_RE")), (false, p.re("_LD_IMPORT_PY_RE"))] {
            for (k, m) in pattern.finditer(text).enumerate() {
                if k >= max {
                    break;
                }
                let (module, names): (PyStr, &[u32]) = if js {
                    (u("os"), m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(2)).unwrap_or(&[]))
                } else {
                    (m.group(1).unwrap_or(&[]).to_vec(), m.group(2).unwrap_or(&[]))
                };
                let table = module_names(p, &module);
                for part in pystr::split_char(names, c(',')) {
                    if let Some(n) = name_re.match_(part) {
                        let theirs = n.group(1).unwrap_or(&[]);
                        if let Some((_, kind)) = table.iter().find(|(k2, _)| k2.as_slice() == theirs) {
                            let local = n.group(2).filter(|g| !g.is_empty()).unwrap_or(theirs).to_vec();
                            if !imported.iter().any(|(l, _)| *l == local) {
                                imported.push((local, (kind, theirs.to_vec())));
                            }
                        }
                    }
                }
            }
        }
    }
    if !imported.is_empty() {
        let mut names: Vec<&PyStr> = imported.iter().map(|(n, _)| n).collect();
        names.sort();
        let escaped: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let src = pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\b(\s*\()?")]);
        let uses = rxutil::dynamic(src, 0);
        for (k, m) in uses.finditer(text).enumerate() {
            if k >= max {
                break;
            }
            if !lit.at(m.start()) {
                let g1 = m.group(1).unwrap_or(&[]);
                if let Some((_, (kind, theirs))) = imported.iter().find(|(l, _)| l.as_slice() == g1) {
                    let what = if *kind == "report" { theirs.clone() } else { u("user or host name") };
                    let open = if m.group(2).is_some() { m.end() as isize } else { -1 };
                    out.push((m.start(), m.end(), open, kind, what));
                }
            }
        }
    }
    if p.re("_LD_READS_RE").search(text).is_some() {
        let max_calls = p.usize("_LD_MAX_CALLS");
        let not_reads = p.strs("_LD_NOT_READS");
        let readers = p.strs("_LD_READERS");
        let fs_root = p.re("_LD_FS_ROOT_RE");
        let plain_literal = p.re("_LD_PLAIN_LITERAL_RE");
        let empty: HashSet<PyStr> = HashSet::new();
        for (k, m) in p.re("_LD_CALL_RE").finditer(text).enumerate() {
            if k >= max_calls || out.len() >= max * 3 {
                break;
            }
            let name = m.group(1).unwrap_or(&[]);
            if in_set(not_reads, name) || lit.at(m.start()) {
                continue;
            }
            let reader = in_set(readers, name);
            let names: &HashSet<PyStr> =
                if reader || (m.start_of(1) as usize == m.start() && own.contains(name)) { outside } else { &empty };
            if !reader && names.is_empty() && fs_root.match_at(text, m.end() as isize, text.len() as isize).is_none() {
                continue;
            }
            let alen = args_len(text, m.end(), span);
            let args = pystr::sub(text, m.end(), m.end() + alen);
            let first = first_arg(args);
            let lead = args.len() - pystr::lstrip(args).len();
            if ld_outside(p, text, m.end() + lead, m.end() + lead + first.len(), reader, names, lit) {
                let what: PyStr = if reader {
                    match plain_literal.match_(first) {
                        Some(pl) => pl.group(2).unwrap_or(&[]).to_vec(),
                        None => first.to_vec(),
                    }
                } else {
                    pystr::concat(&[name, &u("("), first, &u(")")])
                };
                out.push((m.start(), m.end() + alen, m.end() as isize, "file", pystr::upto(&what, 60).to_vec()));
            }
        }
    }
    let argv_item = p.re("_LD_ARGV_ITEM_RE");
    for (k, m) in p.re("_LD_EXEC_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let mut argv: Vec<&[u32]> = vec![m.group(2).unwrap_or(&[])];
        for it in argv_item.finditer(m.group(3).unwrap_or(&[])) {
            argv.push(it.group(1).unwrap_or(&[]));
        }
        let line = pystr::join(&u(" "), &argv);
        if let Some((kind, what)) = shell::sh_output_data(p, &line, 0, None).into_iter().next() {
            out.push((m.start(), m.end(), m.end_of(1) as isize, kind, what));
        }
    }
    let metadata = p.needles("_LD_METADATA_NEEDLES").any_in(text);
    let public_ip = p.re("_LD_PUBLIC_IP_RE");
    if metadata || public_ip.search(text).is_some() {
        let metadata_re = p.re("_LD_METADATA_RE");
        for (k, f) in p.re("_DD_FETCH_RE").finditer(text).enumerate() {
            if k >= max {
                break;
            }
            if lit.at(f.start()) {
                continue;
            }
            let alen = args_len(text, f.end(), span);
            let args = pystr::sub(text, f.end(), f.end() + alen);
            if metadata && metadata_re.search(args).is_some() {
                out.push((f.start(), f.end() + alen, f.end() as isize, "credentials", u("the instance's metadata")));
            } else if public_ip.search(args).is_some() {
                out.push((f.start(), f.end() + alen, f.end() as isize, "address", u("the machine's public IP address")));
            }
        }
    }
    out
}

/// A send found: (offset, kind, what).
type Found = (usize, &'static str, PyStr);

/// core.local_data_sent_at: (offset, kind, what, in_address) of the first
/// send of data text reads from the machine, else None.
pub fn local_data_sent_at(p: &Pack, text: &[u32]) -> Option<(usize, &'static str, PyStr, bool)> {
    if !p.needles("_LD_SEND_NEEDLES").any_in(text) || !p.needles("_LD_NEEDLES").any_in(text) {
        return None;
    }
    let lit = LiteralTest::new(p, text);
    let max = p.usize("_LD_MAX");
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    let max_calls = p.usize("_DD_MAX_CALLS");
    let span = p.usize("_DD_ARG_SPAN");
    let func_value = p.re("_LD_FUNC_VALUE_RE");
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new(); // (name, start, end) of what is assigned
    let mut arrows: Vec<(PyStr, usize, usize)> = Vec::new(); // what an arrow or a lambda returns
    for (k, m) in p.re("_DD_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if !lit.at(m.start_of(1) as usize) {
            let v = m.start_of(2) as usize;
            let end = ld_statement_end(p, text, v);
            let name = m.group(1).unwrap_or(&[]).to_vec();
            if func_value.match_at(text, v as isize, end as isize).is_none() {
                assigns.push((name, v, end));
            } else if let Some(body) = p.re("_LD_ARROW_BODY_RE").match_at(text, v as isize, end as isize) {
                arrows.push((name, body.end(), end));
            }
        }
    }
    let destruct_name = p.re("_DD_DESTRUCT_NAME_RE");
    for (k, m) in p.re("_DD_DESTRUCT_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if lit.at(m.start()) {
            continue;
        }
        let v = m.start_of(2) as usize;
        let end = ld_statement_end(p, text, v);
        for part in pystr::split_char(m.group(1).unwrap_or(&[]), c(',')) {
            if let Some(name) = destruct_name.search(pystr::strip(part)) {
                assigns.push((name.group(1).unwrap_or(&[]).to_vec(), v, end));
            }
        }
    }
    let plain = assigns.len(); // (the assignments of a name itself)
    let mut options: Vec<(PyStr, usize, usize)> = Vec::new(); // the values given a request's option
    let option_keys = p.strs("_LD_OPTION_KEYS");
    let member = p.re("_LD_MEMBER_RE");
    for (k, m) in p.re("_LD_MEMBER_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if lit.at(m.start_of(1) as usize) {
            continue;
        }
        let end = ld_statement_end(p, text, m.end());
        if func_value.match_at(text, m.end() as isize, end as isize).is_some() {
            continue; // (a method: what it returns is its own)
        }
        let chain = m.group(2).unwrap_or(&[]);
        let is_option = member.finditer(chain).any(|mm| {
            let key = mm.group(1).filter(|g| !g.is_empty()).or_else(|| mm.group(2)).unwrap_or(&[]);
            in_set(option_keys, key)
        });
        let name = m.group(1).unwrap_or(&[]).to_vec();
        if is_option {
            options.push((name, m.end(), end));
        } else {
            assigns.push((name, m.end(), end));
        }
    }
    for (k, m) in p.re("_LD_COLLECT_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if !lit.at(m.start_of(1) as usize) {
            assigns.push((m.group(1).unwrap_or(&[]).to_vec(), m.end(), m.end() + args_len(text, m.end(), span)));
        }
    }
    let mut loops: Vec<(PyStr, usize, usize)> = Vec::new();
    for m in p.re("_DD_FOR_RE").finditer(text).take(max_assigns) {
        if lit.at(m.start()) {
            continue;
        }
        let name = m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(3)).unwrap_or(&[]).to_vec();
        if m.group(2).map_or(false, |g| !g.is_empty()) {
            loops.push((name, m.start_of(2) as usize, m.end_of(2) as usize));
        } else {
            loops.push((name, m.start_of(4) as usize, m.end_of(4) as usize));
        }
    }
    // the names that hold a path outside the package
    let path_expr = p.re("_LD_PATH_EXPR_RE");
    let own_folder = p.re("_LD_OWN_FOLDER_RE");
    let fs_root = p.re("_LD_FS_ROOT_RE");
    let home = p.re("_LD_HOME_RE");
    let mut outside: HashSet<PyStr> = HashSet::new();
    for (name, lo, hi) in &assigns[..plain] {
        let value = pystr::strip(pystr::sub(text, *lo, *hi));
        if path_expr.match_(value).is_some()
            && own_folder.search(value).is_none()
            && (fs_root.match_(value).is_some() || home.search(value).is_some())
        {
            outside.insert(name.clone());
        }
    }
    let passes = p.usize("_DD_PASSES");
    for _ in 0..(if outside.is_empty() { 0 } else { passes }) {
        let mut grown = false;
        for (name, lo, hi) in &assigns[..plain] {
            if !outside.contains(name)
                && path_expr.match_at(text, *lo as isize, *hi as isize).is_some()
                && own_folder.search_at(text, *lo as isize, *hi as isize).is_none()
                && ld_names_in(p, text, *lo, *hi, &outside, &lit).is_some()
            {
                outside.insert(name.clone());
                grown = true;
            }
        }
        if !grown {
            break;
        }
    }
    let mut funcs: Vec<(usize, PyStr)> = Vec::new(); // (start, name)
    let mut params: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    let param_re = p.re("_LD_PARAM_RE");
    for (k, m) in p.re("_LD_FUNC_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        let name = [1usize, 3, 5, 9].iter().find_map(|&g| m.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]).to_vec();
        funcs.push((m.start(), name.clone()));
        let plist = [2usize, 4, 6, 7, 8, 10].iter().find_map(|&g| m.group(g)).unwrap_or(&[]);
        let mut names: Vec<PyStr> = Vec::new();
        for part in pystr::split_char(plist, c(',')) {
            if let Some(pm) = param_re.match_(part) {
                let pn = pm.group(1).unwrap_or(&[]);
                if !is(pn, "self") && !is(pn, "cls") {
                    names.push(pn.to_vec());
                }
            }
        }
        if !names.is_empty() && !params.contains_key(&name) && params.len() < max {
            params.insert(name, names);
        }
    }
    let func_starts: Vec<usize> = funcs.iter().map(|(a, _)| *a).collect();
    let call_re = if params.is_empty() {
        None
    } else {
        let mut keys: Vec<&PyStr> = params.keys().collect();
        keys.sort();
        let escaped: Vec<PyStr> = keys.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        Some(rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\s*\(")]),
            0,
        ))
    };
    let own: HashSet<PyStr> = funcs.iter().map(|(_, n)| n.clone()).collect();
    let mut sources = ld_sources(p, text, &lit, &outside, &own);
    sources.sort();
    let metadata_re = p.re("_LD_METADATA_RE");
    let metadata_names: Vec<PyStr> = assigns
        .iter()
        .filter(|(_, lo, hi)| metadata_re.search_at(text, *lo as isize, *hi as isize).is_some())
        .map(|(n, _, _)| n.clone())
        .collect();
    if sources.is_empty() && metadata_names.is_empty() {
        return None;
    }
    let source_starts: Vec<usize> = sources.iter().map(|s| s.0).collect();
    let mut followed: HashMap<PyStr, Got> = HashMap::new(); // name -> the data it holds
    let mut called: HashSet<PyStr> = HashSet::new(); // the followed names of functions: their calls hold it
    // the path a read is given, and a program's options: sealed
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (k, m) in p.re("_LD_SEAL_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let args = pystr::sub(text, m.end(), m.end() + args_len(text, m.end(), span));
        let first = first_arg(args);
        if !pystr::strip(first).is_empty() {
            spans.push((m.end(), m.end() + first.len()));
        }
    }
    let exec_send = p.re("_LD_EXEC_SEND_RE");
    for (k, m) in exec_send.finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if !lit.at(m.start()) {
            let alen = args_len(text, m.end(), span);
            spans.extend(ld_process_options(p, text, m.end(), m.end() + alen));
        }
    }
    spans.sort();
    let mut sealed: Vec<(usize, usize)> = Vec::new();
    for (a, b) in spans {
        match sealed.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => sealed.push((a, b)),
        }
    }
    let sealed_starts: Vec<usize> = sealed.iter().map(|(a, _)| *a).collect();
    let is_sealed = |pos: usize| -> bool {
        let k = sealed_starts.partition_point(|&s| s <= pos);
        k > 0 && pos < sealed[k - 1].1
    };
    let not_in_address = p.strs("_LD_NOT_IN_ADDRESS");
    let whole = p.text("_LD_WHOLE_ENV");
    let ident = p.re("_IDENT_TOKEN_RE");
    let called_re = p.re("_LD_CALLED_RE");
    let member_read = p.re("_LD_MEMBER_READ_RE");
    let not_in_addr = |kind: &str| not_in_address.iter().any(|x| is(x, kind));
    // (kind, what, through a parameter) of the first read, or of a followed name, in the spans
    let read_in = |spans: &[(usize, usize, bool)], loose: bool, followed: &HashMap<PyStr, Got>, called: &HashSet<PyStr>| -> Option<Got> {
        for &(lo, hi, address) in spans {
            let mut k = source_starts.partition_point(|&s| s < lo);
            while k < sources.len() && sources[k].0 < hi {
                let s = &sources[k];
                if (!address || loose || !not_in_addr(s.3) || s.4 == whole) && !is_sealed(s.0) {
                    return Some((s.3, s.4.clone(), false));
                }
                k += 1;
            }
            if !followed.is_empty() {
                for m in ident.finditer_at(text, lo as isize, hi as isize) {
                    let name = m.group0();
                    if let Some(got) = followed.get(name) {
                        if (!address || loose || !not_in_addr(got.0) || got.1 == whole)
                            && !lit.at(m.start())
                            && !is_sealed(m.start())
                            && (!called.contains(name) || called_re.match_at(text, m.end() as isize, text.len() as isize).is_some())
                            && (got.1 != whole || member_read.match_at(text, m.end() as isize, text.len() as isize).is_none())
                            && !ld_tested(p, text, m.start(), m.end())
                        {
                            return Some(got.clone());
                        }
                    }
                }
            }
        }
        None
    };
    for name in &metadata_names {
        followed.entry(name.clone()).or_insert(("credentials", u("the instance's metadata"), false));
    }
    for (name, lo, hi) in &assigns {
        if !followed.contains_key(name) {
            if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called) {
                followed.insert(name.clone(), got);
            }
        }
    }
    let arg_callback = p.re("_DD_ARG_CALLBACK_RE");
    let as_re = p.re("_DD_AS_RE");
    let then_head = p.re("_DD_THEN_HEAD_RE");
    let dd_param = p.re("_DD_PARAM_RE");
    let then_max = p.usize("_DD_THEN_MAX");
    for s in &sources {
        // what a read gives: its callback, `with … as`, `.then(…)`
        let (opening, kind, what) = (s.2, s.3, &s.4);
        if opening < 0 {
            continue;
        }
        let opening = opening as usize;
        let alen = args_len(text, opening, span);
        let args = pystr::sub(text, opening, opening + alen);
        for cb in arg_callback.finditer(args) {
            let name = [1usize, 2, 3].iter().find_map(|&g| cb.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]);
            if !followed.contains_key(name) && !lit.at(opening + cb.start()) {
                followed.insert(name.to_vec(), (kind, what.clone(), false));
            }
        }
        let mut pos = opening + alen + 1;
        if let Some(m) = as_re.match_at(text, pos as isize, text.len() as isize) {
            followed.entry(m.group(1).unwrap_or(&[]).to_vec()).or_insert((kind, what.clone(), false));
        }
        for _ in 0..then_max {
            let h = match then_head.match_at(text, pos as isize, text.len() as isize) {
                None => break,
                Some(h) => h,
            };
            let tlen = args_len(text, h.end(), span);
            let then_args = pystr::sub(text, h.end(), h.end() + tlen);
            if let Some(param) = dd_param.match_(then_args) {
                followed.entry(param.group(1).unwrap_or(&[]).to_vec()).or_insert((kind, what.clone(), false));
            }
            pos = h.end() + tlen + 1;
        }
    }
    let mut returns: Vec<(PyStr, usize, usize)> = Vec::new(); // (function, start, end) of what a function returns
    for (k, m) in p.re("_DD_RETURN_RE").finditer(text).enumerate() {
        if k >= max_calls {
            break;
        }
        let v = m.start_of(1) as usize;
        let end = ld_statement_end(p, text, v);
        let at = func_starts.partition_point(|&s| s <= m.start());
        if !lit.at(m.start()) && at > 0 && func_value.match_at(text, v as isize, end as isize).is_none() {
            returns.push((funcs[at - 1].1.clone(), v, end));
        }
    }
    // the names given a value composed with a literal
    let quote = p.re("_QUOTE_CHAR_RE");
    let mut composed: HashSet<PyStr> = HashSet::new();
    let follow = |name: &PyStr, got: Got, lo: usize, hi: usize, followed: &mut HashMap<PyStr, Got>, composed: &mut HashSet<PyStr>| {
        followed.insert(name.clone(), got);
        if quote.search_at(text, lo as isize, hi as isize).is_some() {
            composed.insert(name.clone());
        }
    };
    let callback_re = p.re("_DD_CALLBACK_RE");
    for _ in 0..passes {
        let mut grown = false;
        for (name, lo, hi) in assigns.iter().chain(loops.iter()) {
            if !followed.contains_key(name) {
                if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called) {
                    follow(name, got, *lo, *hi, &mut followed, &mut composed);
                    grown = true;
                }
            }
        }
        for (name, lo, hi) in &options {
            if !followed.contains_key(name) {
                if let Some(got) = read_in(&[(*lo, *hi, true)], false, &followed, &called) {
                    follow(name, got, *lo, *hi, &mut followed, &mut composed);
                    grown = true;
                }
            }
        }
        for (k, m) in callback_re.finditer(text).enumerate() {
            if k >= max_calls {
                break;
            }
            let obj = m.group(1).unwrap_or(&[]);
            let param = m.group(2).unwrap_or(&[]);
            if !followed.contains_key(param) && !lit.at(m.start()) {
                if let Some(got) = followed.get(obj).cloned() {
                    followed.insert(param.to_vec(), got);
                    grown = true;
                }
            }
        }
        // (what a function returns from its parameters depends on the call: not followed)
        for (name, lo, hi) in returns.iter().chain(arrows.iter()) {
            if !followed.contains_key(name) {
                if let Some(got) = read_in(&ld_value_spans(p, text, *lo, *hi), false, &followed, &called) {
                    if !got.2 {
                        follow(name, got, *lo, *hi, &mut followed, &mut composed);
                        called.insert(name.clone());
                        grown = true;
                    }
                }
            }
        }
        if let Some(call_re) = &call_re {
            // a function of the script's called with data: its parameters
            for (k, cm) in call_re.finditer(text).enumerate() {
                if k >= max {
                    break;
                }
                if lit.at(cm.start()) {
                    continue;
                }
                let alen = args_len(text, cm.end(), span);
                let names = match params.get(cm.group(1).unwrap_or(&[])) {
                    Some(n) => n,
                    None => continue,
                };
                for (param, lo, hi) in ld_bound(p, text, cm.end(), alen, names) {
                    if !followed.contains_key(&param) {
                        if let Some(got) = read_in(&ld_value_spans(p, text, lo, hi), false, &followed, &called) {
                            follow(&param, (got.0, got.1, true), lo, hi, &mut followed, &mut composed);
                            grown = true;
                        }
                    }
                }
            }
        }
        if !grown {
            break;
        }
    }
    let mut found: Vec<Found> = Vec::new(); // sends of data
    let mut in_address: Vec<Found> = Vec::new(); // sends of what an address may hold
    // a send `re` finds whose data holds what the script read
    #[derive(Clone, Copy)]
    enum Where<'r> {
        Any,
        Quote,
        Re(&'r crate::pyre::Regex),
    }
    let first_send = |re: &crate::pyre::Regex, addresses: isize, where_: Where, process: bool, found: &mut Vec<Found>, in_address: &mut Vec<Found>| {
        for (k, s) in re.finditer(text).enumerate() {
            if k >= max {
                return;
            }
            if lit.at(s.start()) {
                continue;
            }
            let alen = args_len(text, s.end(), span);
            let args = pystr::sub(text, s.end(), s.end() + alen);
            let end = s.end() + alen;
            if ld_defined(p, text, s.start(), end) {
                continue;
            }
            match where_ {
                Where::Any => {}
                Where::Quote => {
                    if quote.search(args).is_none() && ld_names_in(p, text, s.end(), end, &composed, &lit).is_none() {
                        continue;
                    }
                }
                Where::Re(rx) => {
                    if rx.search(args).is_none() {
                        continue;
                    }
                }
            }
            let spans = ld_arg_spans(p, text, s.end(), end, if addresses < 0 { alen + 1 } else { addresses as usize }, process);
            if let Some(got) = read_in(&spans, false, &followed, &called) {
                found.push((s.start(), got.0, got.1));
                return;
            }
            if in_address.is_empty() {
                if let Some(got) = read_in(&spans, true, &followed, &called) {
                    in_address.push((s.start(), got.0, got.1));
                }
            }
        }
    };
    first_send(p.re("_LD_SEND_RE"), 1, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_OPTIONS_SEND_RE"), 0, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_REQUEST_SEND_RE"), 2, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_ADDRESS_SEND_RE"), -1, Where::Any, false, &mut found, &mut in_address);
    first_send(p.re("_LD_LOOKUP_SEND_RE"), -1, Where::Quote, false, &mut found, &mut in_address);
    first_send(exec_send, 0, Where::Re(p.re("_LD_NET_PROGRAM_RE")), true, &mut found, &mut in_address);
    let connection = p.re("_LD_CONNECTION_RE");
    let mut connections: Vec<PyStr> = assigns[..plain]
        .iter()
        .filter(|(_, lo, hi)| connection.search_at(text, *lo as isize, (*hi).min(lo + 300) as isize).is_some())
        .map(|(n, _, _)| n.clone())
        .collect();
    connections.sort();
    connections.dedup();
    if !connections.is_empty() {
        let escaped: Vec<PyStr> = connections.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        let rx = rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("(?:"), &pystr::join(&u("|"), &parts), &u(")"), &p.text("_LD_WRITE_TAIL")]),
            0,
        );
        first_send(&rx, 0, Where::Any, false, &mut found, &mut in_address);
    }
    for (k, m) in p.re("_LD_HOST_BUILT_RE").finditer(text).enumerate() {
        // data resolved in a host name: sent
        if k >= max {
            break;
        }
        let g = if m.group(2).is_some() {
            2
        } else if m.group(3).is_some() {
            3
        } else {
            4
        };
        let spans = [(m.start_of(g).max(0) as usize, m.end_of(g).max(0) as usize, true)];
        if let Some(got) = read_in(&spans, false, &followed, &called) {
            found.push((m.start(), got.0, got.1));
            break;
        }
    }
    if found.is_empty() {
        // a connection written to as it is made: https.request(o).end(d)
        let write_tail = p.re("_LD_WRITE_TAIL_RE");
        for (k, cm) in connection.finditer(text).enumerate() {
            if k >= max || !found.is_empty() {
                break;
            }
            if lit.at(cm.start()) {
                continue;
            }
            let close = cm.end() + args_len(text, cm.end(), span);
            if let Some(w) = write_tail.match_at(text, close as isize + 1, text.len() as isize) {
                let end = w.end() + args_len(text, w.end(), span);
                if let Some(got) = read_in(&ld_arg_spans(p, text, w.end(), end, 0, false), false, &followed, &called) {
                    found.push((cm.start(), got.0, got.1));
                }
            }
        }
    }
    if let Some((at, kind, what)) = found.into_iter().min() {
        return Some((at, kind, what, false));
    }
    if let Some((at, kind, what)) = in_address.into_iter().min() {
        return Some((at, kind, what, true));
    }
    None
}

// ---------------- a webhook whose secret is written in the code ----------------

/// core._se_secret: is a path segment a credential?
fn se_secret(p: &Pack, segment: &[u32]) -> bool {
    if p.re("_SE_SEGMENT_RE").fullmatch(segment).is_none() {
        return false;
    }
    let distinct: HashSet<u32> = segment.iter().copied().collect();
    distinct.len() >= p.usize("_SE_MIN_DISTINCT")
        && segment.iter().any(|&x| (c('A')..=c('Z')).contains(&x))
        && segment.iter().any(|&x| (c('a')..=c('z')).contains(&x))
        && segment.iter().any(|&x| (c('0')..=c('9')).contains(&x))
}

/// core._se_url_secret: does a URL (an _SE_URL_RE match) carry a credential in its path?
fn se_url_secret(p: &Pack, path: &[u32], values: &HashMap<PyStr, PyStr>) -> bool {
    let hole = p.re("_SE_HOLE_RE");
    for segment in pystr::split_char(path, c('/')) {
        let resolved: PyStr = if segment.contains(&c('{')) {
            hole.sub_fn(segment, 0, |h| {
                let name = h.group(1).filter(|g| !g.is_empty()).or_else(|| h.group(2)).unwrap_or(&[]);
                values.get(name).cloned().unwrap_or_else(|| u("{"))
            })
        } else {
            segment.to_vec()
        };
        if se_secret(p, &resolved) {
            return true;
        }
    }
    false
}

/// core.secret_endpoint_at: (offset, reason) of the first request to a
/// webhook whose secret is written in text, else None.
pub fn secret_endpoint_at(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    if !pystr::contains(text, "http") || !p.needles("_SE_NEEDLES").any_in(text) {
        return None;
    }
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    let se_max = p.usize("_SE_MAX");
    let span = p.usize("_DD_ARG_SPAN");
    let plain_literal = p.re("_LD_PLAIN_LITERAL_RE");
    let mut values: HashMap<PyStr, PyStr> = HashMap::new(); // name -> the plain literal it is given
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new();
    for (k, m) in p.re("_DD_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        let name = m.group(1).unwrap_or(&[]).to_vec();
        if let Some(lit) = plain_literal.match_(pystr::strip(m.group(2).unwrap_or(&[]))) {
            values.entry(name.clone()).or_insert_with(|| lit.group(2).unwrap_or(&[]).to_vec());
        }
        let v = m.start_of(2) as usize;
        assigns.push((name, v, ld_statement_end(p, text, v)));
    }
    let url_re = p.re("_SE_URL_RE");
    let mut endpoints: Vec<(usize, PyStr)> = Vec::new(); // (start, host) of the literals that hold one
    for (a, b) in literal_spans(p, text) {
        if endpoints.len() >= se_max {
            break;
        }
        if pystr::find_in(text, &u("http"), a, b).is_none() {
            continue;
        }
        for url in url_re.finditer_at(text, a as isize, b as isize) {
            if se_url_secret(p, url.group(2).unwrap_or(&[]), &values) {
                let host = url.group(1).unwrap_or(&[]);
                let host = match host.iter().rposition(|&x| x == c('@')) {
                    Some(k) => &host[k + 1..],
                    None => host,
                };
                endpoints.push((a, pystr::upto(host, 60).to_vec()));
                break;
            }
        }
    }
    if endpoints.is_empty() {
        return None;
    }
    let starts: Vec<usize> = endpoints.iter().map(|(a, _)| *a).collect();
    let lit = LiteralTest::new(p, text);
    let ident = p.re("_IDENT_TOKEN_RE");
    let mut held: HashMap<PyStr, PyStr> = HashMap::new(); // name -> the host of the endpoint it holds
    let holds = |lo: usize, hi: usize, held: &HashMap<PyStr, PyStr>| -> Option<PyStr> {
        let k = starts.partition_point(|&s| s < lo);
        if k < starts.len() && starts[k] < hi {
            return Some(endpoints[k].1.clone());
        }
        if !held.is_empty() {
            for m in ident.finditer_at(text, lo as isize, hi as isize) {
                if let Some(h) = held.get(m.group0()) {
                    if !lit.at(m.start()) {
                        return Some(h.clone());
                    }
                }
            }
        }
        None
    };
    let mut params: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
    let param_re = p.re("_LD_PARAM_RE");
    for (k, m) in p.re("_LD_FUNC_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        let name = [1usize, 3, 5, 9].iter().find_map(|&g| m.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]).to_vec();
        let plist = [2usize, 4, 6, 7, 8, 10].iter().find_map(|&g| m.group(g)).unwrap_or(&[]);
        let mut names: Vec<PyStr> = Vec::new();
        for part in pystr::split_char(plist, c(',')) {
            if let Some(pm) = param_re.match_(part) {
                let pn = pm.group(1).unwrap_or(&[]);
                if !is(pn, "self") && !is(pn, "cls") {
                    names.push(pn.to_vec());
                }
            }
        }
        if !names.is_empty() && !params.contains_key(&name) && params.len() < se_max {
            params.insert(name, names);
        }
    }
    let call_re = if params.is_empty() {
        None
    } else {
        let mut keys: Vec<&PyStr> = params.keys().collect();
        keys.sort();
        let escaped: Vec<PyStr> = keys.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = escaped.iter().map(|x| x.as_slice()).collect();
        Some(rxutil::dynamic(
            pystr::concat(&[&p.text("_DV_NAME_HEAD"), &u("("), &pystr::join(&u("|"), &parts), &u(r")\s*\(")]),
            0,
        ))
    };
    for _ in 0..p.usize("_DD_PASSES") {
        let mut grown = false;
        for (name, lo, hi) in &assigns {
            if !held.contains_key(name) {
                if let Some(host) = holds(*lo, *hi, &held) {
                    held.insert(name.clone(), host);
                    grown = true;
                }
            }
        }
        if let Some(call_re) = &call_re {
            for (k, cm) in call_re.finditer(text).enumerate() {
                if k >= se_max {
                    break;
                }
                if lit.at(cm.start()) {
                    continue;
                }
                let alen = args_len(text, cm.end(), span);
                let names = match params.get(cm.group(1).unwrap_or(&[])) {
                    Some(n) => n,
                    None => continue,
                };
                for (param, lo, hi) in ld_bound(p, text, cm.end(), alen, names) {
                    if !held.contains_key(&param) {
                        if let Some(host) = holds(lo, hi, &held) {
                            held.insert(param, host);
                            grown = true;
                        }
                    }
                }
            }
        }
        if !grown {
            break;
        }
    }
    let mut found: Vec<(usize, PyStr)> = Vec::new();
    let net_program = p.re("_LD_NET_PROGRAM_RE");
    for (pattern, where_) in [(p.re("_SE_REQUEST_RE"), None), (p.re("_LD_EXEC_SEND_RE"), Some(net_program))] {
        for (k, r) in pattern.finditer(text).enumerate() {
            if k >= se_max {
                break;
            }
            if lit.at(r.start()) {
                continue;
            }
            let alen = args_len(text, r.end(), span);
            let args = pystr::sub(text, r.end(), r.end() + alen);
            if let Some(rx) = where_ {
                if rx.search(args).is_none() {
                    continue;
                }
            }
            if let Some(host) = holds(r.end(), r.end() + alen, &held) {
                found.push((r.start(), host));
                break;
            }
        }
    }
    let (at, host) = found.into_iter().min()?;
    Some((at, pystr::concat(&[&u("sends data to a webhook whose secret is written in the code ("), &host, &u(")")])))
}
