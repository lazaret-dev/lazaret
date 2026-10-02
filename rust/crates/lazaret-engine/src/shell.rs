//! A shell text read as a program (0.1.8): a port of lazaret.scanner.core's
//! shell reader (section "An install hook's command read as a program":
//! `_sh_parse` … `_sh_reasons`), function for function, and of the reading
//! of the command lines a script hands a shell (section "Commands a script
//! runs, read as programs": `_sh_literal_at`, `_sh_command_value`,
//! `_exec_command_flows`). The Rust engine reads it for the install-script
//! test (a shell script, a command line an exec call is given) and the
//! import-time test (what such a command line sends). Offsets are code-point
//! indices, as in Python.

use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::HashMap;

const fn c(ch: char) -> u32 {
    ch as u32
}

fn is(s: &[u32], lit: &str) -> bool {
    pystr::eq(s, lit)
}

fn in_set(set: &[PyStr], s: &[u32]) -> bool {
    set.iter().any(|x| x.as_slice() == s)
}

fn push_new(reasons: &mut Vec<PyStr>, r: PyStr) {
    if !reasons.contains(&r) {
        reasons.push(r);
    }
}

/// The local data a shell word or command gives: (kind, what). Kinds are
/// core's: identity, lookup-identity, environment, file, report,
/// credentials, address.
pub type Datum = (&'static str, PyStr);
/// The shell variables a text assigns local data (`T=$(whoami)`).
pub type ShVars = HashMap<PyStr, Vec<Datum>>;

/// core._HookWalk: the commands read so far, and whether a limit stopped the reading.
pub struct HookWalk {
    pub commands: usize,
    pub complete: bool,
}

impl HookWalk {
    pub fn new() -> HookWalk {
        HookWalk { commands: 0, complete: true }
    }
}

impl Default for HookWalk {
    fn default() -> Self {
        HookWalk::new()
    }
}

/// core._ShCommand: one simple command of a shell text.
#[derive(Clone, Debug)]
pub struct ShCommand {
    pub words: Vec<PyStr>,
    pub subs: Vec<Vec<PyStr>>,
    pub redirs: Vec<(PyStr, PyStr)>,
    pub pipe_in: bool,
    pub pipe_out: bool,
    pub after: &'static str,
}

/// core._sh_subst_end
fn sh_subst_end(text: &[u32], mut i: usize) -> usize {
    let n = text.len();
    let mut depth = 0usize;
    let mut quote: Option<u32> = None;
    while i < n {
        let ch = text[i];
        if let Some(q) = quote {
            if ch == c('\\') && q == c('"') {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else if ch == c('\\') {
            i += 2;
            continue;
        } else if ch == c('\'') || ch == c('"') {
            quote = Some(ch);
        } else if ch == c('(') {
            depth += 1;
        } else if ch == c(')') {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        }
        i += 1;
    }
    n
}

/// core._sh_tick_end
fn sh_tick_end(text: &[u32], mut i: usize) -> usize {
    let n = text.len();
    while i < n {
        if text[i] == c('\\') {
            i += 2;
            continue;
        }
        if text[i] == c('`') {
            return i;
        }
        i += 1;
    }
    n
}

/// The parse's word under construction (core's `state`).
struct State {
    cur: Option<PyStr>,
    cur_subs: Vec<PyStr>,
    redir: Option<PyStr>,
    pipe_in: bool,
}

impl State {
    fn cur(&mut self) -> &mut PyStr {
        self.cur.get_or_insert_with(Vec::new)
    }
}

const REDIRECT_OPS: [&str; 10] = ["<<<", "<<-", ">>", ">&", ">|", "<<", "<&", "<>", ">", "<"];

/// core._sh_parse: the simple commands of a shell text, in order.
pub fn sh_parse(p: &Pack, text: &[u32]) -> Vec<ShCommand> {
    let mut out: Vec<ShCommand> = Vec::new();
    let mut words: Vec<PyStr> = Vec::new();
    let mut subs: Vec<Vec<PyStr>> = Vec::new();
    let mut redirs: Vec<(PyStr, PyStr)> = Vec::new();
    let mut state = State { cur: None, cur_subs: Vec::new(), redir: None, pipe_in: false };
    let plain_run = p.re("_SH_PLAIN_RUN_RE");

    fn end_word(state: &mut State, words: &mut Vec<PyStr>, subs: &mut Vec<Vec<PyStr>>, redirs: &mut Vec<(PyStr, PyStr)>) {
        let cur = match state.cur.take() {
            None => return,
            Some(cur) => cur,
        };
        if let Some(op) = state.redir.take() {
            redirs.push((op, cur));
        } else {
            words.push(cur);
            subs.push(std::mem::take(&mut state.cur_subs));
        }
        state.cur_subs.clear();
    }

    fn end_command(
        state: &mut State,
        out: &mut Vec<ShCommand>,
        words: &mut Vec<PyStr>,
        subs: &mut Vec<Vec<PyStr>>,
        redirs: &mut Vec<(PyStr, PyStr)>,
        after: &'static str,
    ) {
        end_word(state, words, subs, redirs);
        state.redir = None;
        if !words.is_empty() || !redirs.is_empty() {
            out.push(ShCommand {
                words: std::mem::take(words),
                subs: std::mem::take(subs),
                redirs: std::mem::take(redirs),
                pipe_in: state.pipe_in,
                pipe_out: after == "|",
                after,
            });
            state.pipe_in = after == "|";
        } else {
            state.pipe_in = false;
        }
        words.clear();
        subs.clear();
        redirs.clear();
    }

    let n = text.len();
    let mut i = 0usize;
    while i < n {
        let ch = text[i];
        if ch == c(' ') || ch == c('\t') || ch == c('\r') {
            end_word(&mut state, &mut words, &mut subs, &mut redirs);
            i += 1;
        } else if ch == c('\n') || ch == c(';') || ch == c('(') || ch == c(')') {
            end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "");
            i += 1;
        } else if ch == c('&') {
            if pystr::starts_with_at(text, i, "&&") {
                end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "&&");
                i += 2;
            } else if pystr::starts_with_at(text, i, "&>") {
                end_word(&mut state, &mut words, &mut subs, &mut redirs);
                let op = if pystr::starts_with_at(text, i, "&>>") { "&>>" } else { "&>" };
                state.redir = Some(u(op));
                i += op.len();
            } else {
                end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "");
                i += 1;
            }
        } else if ch == c('|') {
            if pystr::starts_with_at(text, i, "||") {
                end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "||");
                i += 2;
            } else {
                end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "|");
                i += if pystr::starts_with_at(text, i, "|&") { 2 } else { 1 };
            }
        } else if ch == c('<') || ch == c('>') {
            let fd = match &state.cur {
                Some(cur) => !cur.is_empty() && cur.iter().all(|&d| (c('0')..=c('9')).contains(&d)) && state.cur_subs.is_empty(),
                None => false,
            };
            if fd {
                state.cur = None; // 2>/dev/null: the fd number is the redirect's
                state.cur_subs.clear();
            } else {
                end_word(&mut state, &mut words, &mut subs, &mut redirs);
            }
            let op = REDIRECT_OPS.iter().find(|o| pystr::starts_with_at(text, i, o)).copied().unwrap_or(">");
            state.redir = Some(u(op));
            i += op.len();
        } else {
            state.cur();
            match plain_run.match_at(text, i as isize, n as isize) {
                Some(m) => {
                    let end = m.end();
                    state.cur().extend_from_slice(&text[i..end]);
                    i = end;
                }
                None => {
                    i = sh_word_part(text, i, &mut state);
                }
            }
        }
    }
    end_command(&mut state, &mut out, &mut words, &mut subs, &mut redirs, "");
    out
}

/// core._sh_word_part: adds the part of a word at text[i] to the word; the index after it.
fn sh_word_part(text: &[u32], mut i: usize, state: &mut State) -> usize {
    let n = text.len();
    let ch = text[i];
    if ch == c('\\') {
        if i + 1 < n && text[i + 1] != c('\n') {
            let q = sh_quiet(text[i + 1]);
            state.cur().push(q);
        }
        return i + 2;
    }
    if ch == c('\'') {
        let j = pystr::find_char(text, c('\''), i + 1).unwrap_or(n);
        for &x in &text[i + 1..j] {
            let q = if x == c('$') {
                0
            } else if x == c('`') {
                1
            } else {
                x
            };
            state.cur().push(q);
        }
        return j + 1;
    }
    if ch == c('"') {
        i += 1;
        while i < n && text[i] != c('"') {
            let c2 = text[i];
            if c2 == c('\\') && i + 1 < n && [c('$'), c('`'), c('"'), c('\\'), c('\n')].contains(&text[i + 1]) {
                let nxt = text[i + 1];
                if nxt != c('\n') {
                    let q = sh_quiet(nxt);
                    state.cur().push(q);
                }
                i += 2;
            } else if (c2 == c('$') && pystr::starts_with_at(text, i, "$(")) || c2 == c('`') {
                i = sh_substitution(text, i, state);
            } else {
                state.cur().push(c2);
                i += 1;
            }
        }
        return i + 1;
    }
    if (ch == c('$') && pystr::starts_with_at(text, i, "$(")) || ch == c('`') {
        return sh_substitution(text, i, state);
    }
    state.cur().push(ch);
    i + 1
}

/// core._sh_quiet: `$` is \x00, a backtick \x01 (a character that expands nothing).
fn sh_quiet(ch: u32) -> u32 {
    if ch == c('$') {
        0
    } else if ch == c('`') {
        1
    } else {
        ch
    }
}

/// core._sh_literal: a word as the text it is.
pub fn sh_literal(word: &[u32]) -> PyStr {
    word.iter()
        .map(|&x| if x == 0 { c('$') } else if x == 1 { c('`') } else { x })
        .collect()
}

/// core._sh_substitution: adds the substitution at text[i] to the word and its text to the word's substitutions.
fn sh_substitution(text: &[u32], i: usize, state: &mut State) -> usize {
    let n = text.len();
    let j;
    if text[i] == c('`') {
        j = sh_tick_end(text, i + 1);
        state.cur_subs.push(pystr::sub(text, i + 1, j).to_vec());
    } else {
        j = sh_subst_end(text, i + 2);
        state.cur_subs.push(pystr::sub(text, i + 2, j).to_vec());
    }
    let part = pystr::sub(text, i, (j + 1).min(n)).to_vec();
    state.cur().extend_from_slice(&part);
    j + 1
}

/// core._sh_name: a program's name as a word gives it: lower case, no directory, no .exe.
pub fn sh_name(word: &[u32]) -> PyStr {
    let slashed = pystr::replace_char(word, c('\\'), c('/'));
    let last = match slashed.iter().rposition(|&x| x == c('/')) {
        Some(k) => &slashed[k + 1..],
        None => &slashed[..],
    };
    let name = pystr::lower(last);
    if pystr::ends_with(&name, ".exe") && name.len() > 4 {
        name[..name.len() - 4].to_vec()
    } else {
        name
    }
}

/// core._sh_xargs_command: the index in xargs' arguments of the command it runs.
fn sh_xargs_command(p: &Pack, args: &[PyStr]) -> Option<usize> {
    let long_value = p.strs("_SH_XARGS_LONG_VALUE");
    let short_value = p.strs("_SH_XARGS_SHORT_VALUE");
    let mut k = 0usize;
    while k < args.len() {
        let a = &args[k];
        if is(a, "--") {
            return if k + 1 < args.len() { Some(k + 1) } else { None };
        }
        if !pystr::starts_with(a, "-") || is(a, "-") {
            return Some(k);
        }
        if pystr::starts_with(a, "--") {
            k += if in_set(long_value, a) { 2 } else { 1 };
            continue;
        }
        let letter = pystr::sub(a, 1, 2);
        k += if in_set(short_value, letter) && a.len() == 2 { 2 } else { 1 };
    }
    None
}

/// Python's str.partition("="): (head, found, tail).
fn partition_eq(s: &[u32]) -> (&[u32], bool, &[u32]) {
    match s.iter().position(|&x| x == c('=')) {
        Some(k) => (&s[..k], true, &s[k + 1..]),
        None => (s, false, &[]),
    }
}

/// core._sh_program: (index of the program word or None, its name, whether a keyword in front uses its exit status).
pub fn sh_program(p: &Pack, cmd: &ShCommand) -> (Option<usize>, PyStr, bool) {
    let words = &cmd.words;
    let env_assign = p.re("_ENV_ASSIGN_RE");
    let keywords = p.strs("_SH_KEYWORDS");
    let status_keywords = p.strs("_SH_STATUS_KEYWORDS");
    let wrappers = p.strs("_HOOK_WRAPPERS");
    let value_options = p.map_strs("_WRAPPER_VALUE_OPTIONS");
    let mut i = 0usize;
    let mut status = false;
    let mut last: Option<(usize, PyStr)> = None;
    while i < words.len() {
        let word = &words[i];
        if env_assign.match_(word).is_some() {
            i += 1;
            continue;
        }
        if in_set(keywords, word) {
            status = status || in_set(status_keywords, word);
            i += 1;
            continue;
        }
        let name = sh_name(word);
        if !in_set(wrappers, &name) {
            return (Some(i), name, status);
        }
        last = Some((i, name.clone()));
        i += 1;
        let values: &[PyStr] = value_options.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_slice()).unwrap_or(&[]);
        while i < words.len() && pystr::starts_with(&words[i], "-") && (!is(&words[i], "-") || is(&name, "env")) {
            let opt = &words[i];
            i += 1;
            if is(opt, "--") {
                break;
            }
            if pystr::starts_with(opt, "--") {
                let (head, eq, _) = partition_eq(opt);
                if in_set(values, head) && !eq {
                    i += 1;
                }
            } else if in_set(values, pystr::upto(opt, 2)) && opt.len() == 2 {
                i += 1;
            }
        }
    }
    match last {
        Some((k, name)) => (Some(k), name, status),
        None => (None, Vec::new(), status),
    }
}

/// An option of a command: (name, its value or None, the index of the word holding the value).
type ShOpt = (PyStr, Option<PyStr>, usize);

/// core._sh_options: the options and the positional arguments of a command.
fn sh_options(args: &[PyStr], short_value: &[PyStr], long_value: &[PyStr]) -> (Vec<ShOpt>, Vec<(PyStr, usize)>) {
    let mut opts: Vec<ShOpt> = Vec::new();
    let mut pos: Vec<(PyStr, usize)> = Vec::new();
    let mut k = 0usize;
    while k < args.len() {
        let a = &args[k];
        if is(a, "--") {
            for (j, x) in args.iter().enumerate().skip(k + 1) {
                pos.push((x.clone(), j));
            }
            break;
        }
        if pystr::starts_with(a, "--") && a.len() > 2 {
            let (name, eq, value) = partition_eq(a);
            if in_set(long_value, name) && !eq {
                opts.push((name.to_vec(), Some(args.get(k + 1).cloned().unwrap_or_default()), k + 1));
                k += 2;
                continue;
            }
            opts.push((name.to_vec(), if eq { Some(value.to_vec()) } else { None }, k));
        } else if pystr::starts_with(a, "-") && a.len() > 1 {
            for j in 1..a.len() {
                let letter = a[j];
                let mut flag = u("-");
                flag.push(letter);
                if short_value.iter().any(|s| s.len() == 1 && s[0] == letter) {
                    if j + 1 < a.len() {
                        opts.push((flag, Some(a[j + 1..].to_vec()), k));
                    } else {
                        opts.push((flag, Some(args.get(k + 1).cloned().unwrap_or_default()), k + 1));
                        k += 1;
                    }
                    break;
                }
                opts.push((flag, None, k));
            }
        } else {
            pos.push((a.clone(), k));
        }
        k += 1;
    }
    (opts, pos)
}

/// core._sh_code: the command line a program hands a shell to read again.
fn sh_code(p: &Pack, name: &[u32], args: &[PyStr]) -> Option<PyStr> {
    let code: Option<PyStr> = if in_set(p.strs("_SH_SHELLS"), name) {
        sh_c_code(args)
    } else if in_set(p.strs("_SH_EVAL"), name) {
        let parts: Vec<&[u32]> = args.iter().map(|a| a.as_slice()).collect();
        Some(pystr::join(&u(" "), &parts))
    } else if in_set(p.strs("_SH_CMD"), name) && !args.is_empty() && {
        let low = pystr::lower(&args[0]);
        is(&low, "/c") || is(&low, "/k")
    } {
        let parts: Vec<&[u32]> = args[1..].iter().map(|a| a.as_slice()).collect();
        Some(pystr::join(&u(" "), &parts))
    } else {
        return None;
    };
    code.map(|x| sh_literal(&x))
}

/// core._sh_c_code: the command line of `sh -c CODE`.
fn sh_c_code(args: &[PyStr]) -> Option<PyStr> {
    for (k, a) in args.iter().enumerate() {
        if pystr::starts_with(a, "-") && !pystr::starts_with(a, "--") && a[1..].contains(&c('c')) {
            return Some(args.get(k + 1).cloned().unwrap_or_default());
        }
        if !pystr::starts_with(a, "-") {
            return None;
        }
    }
    None
}

fn dollar(name: &[u32]) -> PyStr {
    let mut s = u("$");
    s.extend_from_slice(name);
    s
}

/// core._sh_word_data: the local data a word of a request sends.
pub fn sh_word_data(p: &Pack, word: &[u32], subs: &[PyStr], depth: usize, download: bool, shvars: Option<&ShVars>) -> Vec<Datum> {
    let mut out: Vec<Datum> = Vec::new();
    for sub in subs {
        for (kind, what) in sh_output_data(p, sub, depth + 1, None) {
            if !download || kind == "identity" {
                out.push((kind, what));
            }
        }
    }
    let identity_var = p.re("_SH_IDENTITY_VAR_RE");
    let path_var = p.re("_SH_PATH_VAR_RE");
    let secret_var = p.re("_SH_SECRET_VAR_RE");
    for m in p.re("_SH_ENV_REF_RE").finditer(word) {
        let name: &[u32] = [1usize, 2, 3].iter().find_map(|&g| m.group(g).filter(|x| !x.is_empty())).unwrap_or(&[]);
        if let Some(held) = shvars.filter(|v| !v.is_empty()).and_then(|v| v.get(name)) {
            for (kind, what) in held {
                if !download || *kind == "identity" {
                    out.push((kind, what.clone()));
                }
            }
        } else if identity_var.match_(name).is_some() {
            out.push(("identity", dollar(name)));
        } else if download {
            continue;
        } else if path_var.match_(name).is_some() {
            out.push(("report", dollar(name)));
        } else if secret_var.search(name).is_some() {
            out.push(("environment", dollar(name)));
        }
    }
    out
}

/// core._sh_output_data: the local data shell text prints.
pub fn sh_output_data(p: &Pack, text: &[u32], depth: usize, shvars: Option<&ShVars>) -> Vec<Datum> {
    if depth > p.usize("_SH_MAX_DEPTH") {
        return Vec::new();
    }
    let cmds = sh_parse(p, text);
    let mut out = Vec::new();
    for (k, cmd) in cmds.iter().enumerate() {
        if !cmd.pipe_out {
            out.extend(sh_piped_data(p, &cmds, k + 1, depth, shvars));
        }
    }
    out
}

/// core._sh_piped_data: the local data piped into cmds[at], back through filters.
fn sh_piped_data(p: &Pack, cmds: &[ShCommand], at: usize, depth: usize, shvars: Option<&ShVars>) -> Vec<Datum> {
    let mut k = at as isize - 1;
    while k >= 0 {
        let cmd = &cmds[k as usize];
        if k < at as isize - 1 && !cmd.pipe_out {
            return Vec::new();
        }
        if let Some(found) = sh_command_data(p, cmd, depth, shvars) {
            return found;
        }
        if !cmd.pipe_in {
            return Vec::new();
        }
        k -= 1;
    }
    Vec::new()
}

/// core._sh_command_data: the local data one command prints; None for a filter.
fn sh_command_data(p: &Pack, cmd: &ShCommand, depth: usize, shvars: Option<&ShVars>) -> Option<Vec<Datum>> {
    let (pi, name, _status) = sh_program(p, cmd);
    let pi = match pi {
        None => return Some(Vec::new()),
        Some(x) => x,
    };
    let args = &cmd.words[pi + 1..];
    let positional: Vec<&PyStr> = args.iter().filter(|a| !a.is_empty() && a[0] != c('-')).collect();
    if is(&name, "uname") {
        let flag = p.re("_SH_FLAG_A_OR_N_RE");
        let named = args.iter().any(|a| is(a, "--all") || is(a, "--nodename") || flag.match_(a).is_some());
        return Some(if named { vec![("identity", u("uname"))] } else { Vec::new() });
    }
    if in_set(p.strs("_SH_IDENTITY"), &name) {
        return Some(vec![("identity", name)]);
    }
    if is(&name, "env") || is(&name, "printenv") || (in_set(p.strs("_SH_ENVIRONMENT"), &name) && positional.is_empty()) {
        return Some(vec![("environment", p.text("_LD_WHOLE_ENV"))]);
    }
    for (op, target) in &cmd.redirs {
        if is(op, "<") || is(op, "<>") {
            return Some(vec![("file", target.clone())]);
        }
    }
    let filters = p.strs("_SH_FILTERS");
    if in_set(p.strs("_SH_FILE_READERS"), &name) || in_set(filters, &name) {
        let files: &[&PyStr] = if in_set(p.strs("_SH_SCRIPTED_FILTERS"), &name) {
            if positional.is_empty() {
                &[]
            } else {
                &positional[1..]
            }
        } else if is(&name, "tr") || is(&name, "openssl") {
            &[]
        } else {
            &positional[..]
        };
        if let Some(last) = files.last() {
            return Some(vec![("file", (*last).clone())]);
        }
        return if in_set(filters, &name) { None } else { Some(Vec::new()) };
    }
    if in_set(p.strs("_SH_LISTINGS"), &name) {
        return Some(vec![("report", name)]);
    }
    if in_set(p.strs("_SH_ECHO"), &name) {
        let mut out = Vec::new();
        for (word, subs) in cmd.words[pi + 1..].iter().zip(cmd.subs[pi + 1..].iter()) {
            out.extend(sh_word_data(p, word, subs, depth, false, shvars));
        }
        return Some(out);
    }
    if in_set(p.strs("_SH_HTTP"), &name) {
        let metadata = p.re("_LD_METADATA_RE");
        if args.iter().any(|a| metadata.search(a).is_some()) {
            return Some(vec![("credentials", u("the instance's metadata"))]);
        }
        let public_ip = p.re("_LD_PUBLIC_IP_RE");
        if args.iter().any(|a| public_ip.search(a).is_some()) {
            return Some(vec![("address", u("the machine's public IP address"))]);
        }
    }
    Some(Vec::new())
}

/// core._sh_assignments: records the local data the shell variables a command assigns hold.
fn sh_assignments(p: &Pack, cmd: &ShCommand, depth: usize, shvars: &mut ShVars) {
    let words = &cmd.words;
    let env_assign = p.re("_ENV_ASSIGN_RE");
    let mut k = 0usize;
    while k < words.len() && env_assign.match_(&words[k]).is_some() {
        k += 1;
    }
    let mut at: Vec<usize> = (0..k).collect();
    if k < words.len() && in_set(p.strs("_SH_DECLARE"), &sh_name(&words[k])) {
        at.extend((k + 1..words.len()).filter(|&j| env_assign.match_(&words[j]).is_some()));
    }
    for j in at {
        let (name, _eq, value) = partition_eq(&words[j]);
        let mut data: Vec<Datum> = Vec::new();
        for sub in &cmd.subs[j] {
            data.extend(sh_output_data(p, sub, depth + 1, Some(shvars)));
        }
        data.extend(sh_word_data(p, value, &[], depth, false, Some(shvars)));
        if data.is_empty() {
            shvars.remove(name);
        } else {
            shvars.insert(name.to_vec(), data);
        }
    }
}

/// core._sh_remote: is an address a server elsewhere (not loopback, not a reserved name)?
fn sh_remote(p: &Pack, address: &[u32]) -> bool {
    let group: &[u32] = p.re("_SH_HOST_RE").match_(address).and_then(|m| m.group(1)).unwrap_or(&[]);
    let host = pystr::rstrip_chars(&pystr::lower(pystr::strip_chars(group, "[]")), ".").to_vec();
    if host.is_empty() || is(&host, "localhost") || is(&host, "0.0.0.0") || is(&host, "::1") || pystr::starts_with(&host, "127.") {
        return false;
    }
    let tld = match host.iter().rposition(|&x| x == c('.')) {
        Some(k) => &host[k + 1..],
        None => &host[..],
    };
    !in_set(p.strs("_DNS_LOCAL_TLDS"), tld)
}

/// What a curl or wget command sends, and where its answer goes (core._sh_request).
struct Request {
    sent: Vec<(usize, &'static str)>,
    uploads: Vec<PyStr>,
    stdin: bool,
    disposition: &'static str,
    addresses: Vec<(PyStr, usize)>,
}

/// core._sh_request
fn sh_request(p: &Pack, name: &[u32], args: &[PyStr]) -> Request {
    let curl = is(name, "curl");
    let (short, long) = if curl { ("_SH_CURL_SHORT_VALUE", "_SH_CURL_LONG_VALUE") } else { ("_SH_WGET_SHORT_VALUE", "_SH_WGET_LONG_VALUE") };
    let (opts, pos) = sh_options(args, p.strs(short), p.strs(long));
    let url = p.re("_SH_URL_RE");
    let mut req = Request {
        sent: Vec::new(),
        uploads: Vec::new(),
        stdin: false,
        disposition: if curl { "stdout" } else { "file" },
        addresses: pos.into_iter().filter(|(a, _)| url.match_(a).is_some()).collect(),
    };
    let mut writes_out = false;
    let null = p.strs("_SH_NULL");
    for (opt, value, k) in opts {
        let value = match value {
            None => {
                if curl && in_set(p.strs("_SH_CURL_REMOTE_NAME"), &opt) {
                    req.disposition = "file";
                } else if !curl && is(&opt, "--spider") {
                    req.disposition = "discard";
                }
                continue;
            }
            Some(v) => v,
        };
        if curl && is(&opt, "--url") {
            if url.match_(&value).is_some() {
                req.addresses.push((value, k));
            }
        } else if curl && in_set(p.strs("_SH_CURL_DATA"), &opt) {
            let body: &[u32] = if (is(&opt, "-F") || is(&opt, "--form")) && value.contains(&c('=')) {
                let k2 = value.iter().position(|&x| x == c('=')).unwrap_or(0);
                &value[k2 + 1..]
            } else {
                &value[..]
            };
            let at = body.iter().position(|&x| x == c('@'));
            let name_part: &[u32] = match at {
                Some(k2) => &body[..k2],
                None => body,
            };
            let named = is(&opt, "--data-urlencode") && at.is_some() && !name_part.contains(&c('='));
            let lead = body.first().copied();
            if named
                || ((lead == Some(c('@')) || lead == Some(c('<')))
                    && !(is(&opt, "--form-string") || is(&opt, "--data-raw") || is(&opt, "--url-query")))
            {
                let path_full: &[u32] = if named {
                    match at {
                        Some(k2) => &body[k2 + 1..],
                        None => &[],
                    }
                } else {
                    &body[1..]
                };
                let path: &[u32] = match path_full.iter().position(|&x| x == c(';')) {
                    Some(k2) => &path_full[..k2],
                    None => path_full,
                };
                if is(path, "-") || path.is_empty() {
                    req.stdin = true;
                } else {
                    req.uploads.push(path.to_vec());
                }
            } else {
                req.sent.push((k, "data"));
            }
        } else if !curl && in_set(p.strs("_SH_WGET_DATA"), &opt) {
            req.sent.push((k, "data"));
        } else if (curl && in_set(p.strs("_SH_CURL_META"), &opt)) || (!curl && in_set(p.strs("_SH_WGET_META"), &opt)) {
            req.sent.push((k, "meta"));
        } else if (curl && in_set(p.strs("_SH_CURL_UPLOAD"), &opt)) || (!curl && in_set(p.strs("_SH_WGET_UPLOAD"), &opt)) {
            if is(&value, "-") || is(&value, ".") {
                req.stdin = true;
            } else {
                req.uploads.push(value);
            }
        } else if (curl && in_set(p.strs("_SH_CURL_OUTPUT"), &opt)) || (!curl && in_set(p.strs("_SH_WGET_OUTPUT"), &opt)) {
            if in_set(null, &pystr::lower(&value)) {
                req.disposition = "discard";
            } else if is(&value, "-") {
                req.disposition = "stdout";
            } else {
                req.disposition = "file";
            }
        } else if curl && (is(&opt, "-w") || is(&opt, "--write-out")) {
            writes_out = true;
        }
    }
    if req.disposition == "discard" && writes_out {
        req.disposition = "stdout"; // what -w writes (the status code …) is the output
    }
    req
}

/// core._sh_kept: is what a command writes to its standard output kept?
fn sh_kept(p: &Pack, cmd: &ShCommand, in_subst: bool) -> bool {
    for (op, target) in &cmd.redirs {
        if is(op, ">") || is(op, ">>") || is(op, ">|") || is(op, "&>") || is(op, "&>>") {
            return !in_set(p.strs("_SH_NULL"), &pystr::lower(target));
        }
    }
    cmd.pipe_out || in_subst
}

/// core._sh_status_used: does what runs next depend on cmds[k]'s exit status?
fn sh_status_used(p: &Pack, cmds: &[ShCommand], k: usize, status: bool) -> bool {
    if status {
        return true;
    }
    let cmd = &cmds[k];
    if !(cmd.after == "&&" || cmd.after == "||") || k + 1 >= cmds.len() {
        return false;
    }
    !in_set(p.strs("_SH_NOOPS"), &sh_program(p, &cmds[k + 1]).1)
}

/// core._sh_reasons: the reasons a shell text's network commands give.
pub fn sh_reasons(p: &Pack, text: &[u32], depth: usize, in_subst: bool, walk: &mut HookWalk) -> Vec<PyStr> {
    let mut reasons: Vec<PyStr> = Vec::new();
    if depth > p.usize("_SH_MAX_DEPTH") || text.is_empty() {
        return reasons;
    }
    let cmds = sh_parse(p, text);
    let mut shvars: ShVars = HashMap::new();
    let max_commands = p.usize("HOOK_MAX_COMMANDS");
    let var_name = p.re("_SH_VAR_NAME_RE");
    for (k, cmd) in cmds.iter().enumerate() {
        if walk.commands >= max_commands {
            walk.complete = false;
            break;
        }
        walk.commands += 1;
        for word_subs in &cmd.subs {
            for sub in word_subs {
                for r in sh_reasons(p, sub, depth + 1, true, walk) {
                    push_new(&mut reasons, r);
                }
            }
        }
        sh_assignments(p, cmd, depth, &mut shvars);
        let (pi, mut name, status) = sh_program(p, cmd);
        let pi = match pi {
            None => continue,
            Some(x) => x,
        };
        let mut args: &[PyStr] = &cmd.words[pi + 1..];
        let mut arg_subs: &[Vec<PyStr>] = &cmd.subs[pi + 1..];
        if is(&name, "read") {
            // `… | while read V`: V holds what is piped in
            let data = if cmd.pipe_in { sh_piped_data(p, &cmds, k, depth, Some(&shvars)) } else { Vec::new() };
            for a in args {
                if var_name.match_(a).is_some() {
                    if data.is_empty() {
                        shvars.remove(a);
                    } else {
                        shvars.insert(a.clone(), data.clone());
                    }
                }
            }
            continue;
        }
        if let Some(code) = sh_code(p, &name, args) {
            let kept = in_subst || sh_kept(p, cmd, in_subst);
            for r in sh_reasons(p, &code, depth + 1, kept, walk) {
                push_new(&mut reasons, r);
            }
            continue;
        }
        let mut piped: Vec<Datum> = Vec::new(); // what xargs hands the command as arguments
        if is(&name, "xargs") {
            let inner = match sh_xargs_command(p, args) {
                None => continue,
                Some(i) => i,
            };
            if cmd.pipe_in {
                piped = sh_piped_data(p, &cmds, k, depth, Some(&shvars));
            }
            args = &args[inner + 1..];
            arg_subs = &arg_subs[inner + 1..];
            name = sh_name(&cmd.words[pi + 1 + inner]);
        }
        let mut data: Vec<Datum> = Vec::new();
        let beacon;
        if in_set(p.strs("_SH_HTTP"), &name) {
            let req = sh_request(p, &name, args);
            if req.addresses.is_empty() {
                continue;
            }
            let kept = req.disposition == "file" || (req.disposition == "stdout" && sh_kept(p, cmd, in_subst));
            for &(idx, what) in &req.sent {
                if idx < args.len() {
                    // (an option given no value sends nothing)
                    data.extend(sh_word_data(p, &args[idx], &arg_subs[idx], depth, kept && what == "meta", Some(&shvars)));
                }
            }
            for (address, idx) in &req.addresses {
                data.extend(sh_word_data(p, address, &arg_subs[*idx], depth, kept, Some(&shvars)));
            }
            for path in &req.uploads {
                data.push(("file", path.clone()));
            }
            if req.stdin && cmd.pipe_in && piped.is_empty() {
                data.extend(sh_piped_data(p, &cmds, k, depth, Some(&shvars)));
            }
            for (kind, what) in &piped {
                if !kept || *kind == "identity" {
                    data.push((kind, what.clone()));
                }
            }
            beacon = !kept && !sh_status_used(p, &cmds, k, status) && req.addresses.iter().any(|(a, _)| sh_remote(p, a));
        } else if in_set(p.strs("_SH_RAW"), &name) {
            if cmd.pipe_in {
                if piped.is_empty() {
                    data.extend(sh_piped_data(p, &cmds, k, depth, Some(&shvars)));
                } else {
                    data.extend(piped.iter().cloned());
                }
            }
            for (op, target) in &cmd.redirs {
                if is(op, "<") || is(op, "<>") {
                    data.push(("file", target.clone()));
                }
            }
            let url = p.re("_SH_URL_RE");
            let hosts: Vec<(&PyStr, &Vec<PyStr>)> = args
                .iter()
                .zip(arg_subs.iter())
                .filter(|(a, _)| !a.is_empty() && a[0] != c('-') && url.match_(a).is_some())
                .collect();
            for (word, subs) in &hosts {
                data.extend(sh_word_data(p, word, subs, depth, false, Some(&shvars)));
            }
            beacon = !sh_status_used(p, &cmds, k, status) && !sh_kept(p, cmd, in_subst) && hosts.iter().any(|(a, _)| sh_remote(p, a));
        } else if in_set(p.strs("_SH_LOOKUP"), &name) {
            for (kind, what) in &piped {
                data.push((if *kind == "identity" { "lookup-identity" } else { kind }, what.clone()));
            }
            let url = p.re("_SH_URL_RE");
            let names: Vec<(&PyStr, &Vec<PyStr>)> = args
                .iter()
                .zip(arg_subs.iter())
                .filter(|(a, _)| !a.is_empty() && a[0] != c('-') && url.match_(a).is_some())
                .collect();
            for (word, subs) in &names {
                for (kind, what) in sh_word_data(p, word, subs, depth, false, Some(&shvars)) {
                    data.push((if kind == "identity" { "lookup-identity" } else { kind }, what));
                }
            }
            beacon = !sh_status_used(p, &cmds, k, status) && !sh_kept(p, cmd, in_subst) && names.iter().any(|(a, _)| sh_remote(p, a));
        } else {
            continue;
        }
        for (kind, what) in &data {
            let mut reason = p.map_text("_SH_DATA_REASONS", kind);
            if *kind == "file" || *kind == "report" || *kind == "environment" {
                reason.extend(u(" ("));
                reason.extend_from_slice(pystr::upto(&sh_literal(what), 40));
                reason.extend(u(")"));
            }
            push_new(&mut reasons, reason);
        }
        let beacon_reason = p.text("_SH_BEACON_REASON");
        if beacon && data.is_empty() && !reasons.contains(&beacon_reason) {
            reasons.push(beacon_reason);
        }
    }
    reasons
}

// ---------------- a shell script, and code ----------------

/// core._code_text: is text JavaScript or Python rather than shell?
pub fn code_text(p: &Pack, text: &[u32]) -> bool {
    if pystr::starts_with(text, "#!") {
        if let Some(lang) = crate::hooks::shebang_lang(p, text) {
            return lang != "sh";
        }
    }
    p.re("_SH_NOT_SHELL_RE").search(text).is_some()
}

/// core._shell_text: is text a shell script?
pub fn shell_text(p: &Pack, text: &[u32]) -> bool {
    if text.len() > p.usize("_SH_SCRIPT_MAX_CHARS") {
        return false;
    }
    if pystr::starts_with(text, "#!") {
        return crate::hooks::shebang_lang(p, text) == Some("sh");
    }
    p.re("_SH_NOT_SHELL_RE").search(text).is_none()
}

// ---------------- commands a script runs, read as programs ----------------

/// core._sh_literal_at: (value, end) of the string literal at text[i]
/// (escapes decoded, a template's or an f-string's holes \x02), else None.
pub fn sh_literal_at(p: &Pack, text: &[u32], i: usize) -> Option<(PyStr, usize)> {
    let n_all = text.len();
    let mut j = i;
    while j < n_all && j - i < 2 && "rbuRBUfF".chars().any(|x| x as u32 == text[j]) {
        j += 1;
    }
    let prefix = pystr::lower(&text[i..j]);
    let i = j;
    if i >= n_all || !(text[i] == c('"') || text[i] == c('\'') || text[i] == c('`')) {
        return None;
    }
    let q = text[i];
    let triple = q != c('`') && i + 3 <= n_all && text[i + 1] == q && text[i + 2] == q;
    let close_len = if triple { 3 } else { 1 };
    let raw = prefix.contains(&c('r'));
    let fmt = prefix.contains(&c('f'));
    let tpl = q == c('`');
    let escapes = p.map_strs("_SH_ESCAPES");
    let mut out: PyStr = Vec::new();
    let mut k = i + close_len;
    let n = n_all.min(i + p.usize("HOOK_MAX_CHARS"));
    let closes = |k: usize| -> bool { k + close_len <= n_all && text[k..k + close_len].iter().all(|&x| x == q) };
    while k < n {
        if closes(k) {
            return Some((out, k + close_len));
        }
        let ch = text[k];
        if ch == c('\n') && !triple && !tpl {
            return None;
        }
        if ch == c('\\') && k + 1 < n {
            let nxt = text[k + 1];
            if raw {
                out.push(c('\\'));
                out.push(nxt);
            } else if nxt != c('\n') {
                match escapes.iter().find(|(key, _)| key.len() == 1 && key[0] == nxt) {
                    Some((_, v)) => out.extend_from_slice(v.first().map(|x| x.as_slice()).unwrap_or(&[])),
                    None => out.push(nxt),
                }
            }
            k += 2;
            continue;
        }
        if (tpl && pystr::starts_with_at(text, k, "${")) || (fmt && ch == c('{') && !pystr::starts_with_at(text, k, "{{")) {
            let mut depth: isize = 1;
            k += if tpl { 2 } else { 1 };
            while k < n && depth != 0 {
                if text[k] == c('{') {
                    depth += 1;
                } else if text[k] == c('}') {
                    depth -= 1;
                }
                k += 1;
            }
            out.push(2);
            continue;
        }
        if fmt && (pystr::starts_with_at(text, k, "{{") || pystr::starts_with_at(text, k, "}}")) {
            out.push(ch);
            k += 2;
            continue;
        }
        out.push(ch);
        k += 1;
    }
    None
}

/// core._sh_literal_value
pub fn sh_literal_value(p: &Pack, text: &[u32], i: usize) -> Option<PyStr> {
    sh_literal_at(p, text, i).map(|(v, _)| v)
}

/// core._sh_command_value: the command line an exec call's argument at
/// text[i] builds (literals and names given one joined with +), else None.
fn sh_command_value(p: &Pack, text: &[u32], mut i: usize, values: &HashMap<PyStr, PyStr>) -> Option<PyStr> {
    let n = text.len();
    let mut parts: Vec<PyStr> = Vec::new();
    let max = p.usize("_SH_CONCAT_MAX");
    let ident = p.re("_IDENT_TOKEN_RE");
    let skip = |mut i: usize| -> usize {
        while i < n && (text[i] == c(' ') || text[i] == c('\t') || text[i] == c('\n')) {
            i += 1;
        }
        i
    };
    while parts.len() < max {
        i = skip(i);
        if let Some((value, end)) = sh_literal_at(p, text, i) {
            parts.push(value);
            i = end;
        } else {
            let m = match ident.match_at(text, i as isize, n as isize) {
                None => break,
                Some(m) => m,
            };
            match values.get(m.group0()) {
                Some(v) => parts.push(v.clone()),
                None => {
                    if parts.is_empty() {
                        return None;
                    }
                    parts.push(vec![2]);
                }
            }
            i = m.end();
        }
        i = skip(i);
        if i >= n || text[i] != c('+') {
            break;
        }
        i += 1;
    }
    let joined: PyStr = parts.concat();
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// core._exec_command_flows: [(offset, reason)] of what each command line
/// text hands a shell gives, and where it is handed over.
pub fn exec_command_flows(p: &Pack, text: &[u32]) -> Vec<(usize, PyStr)> {
    if !p.needles("_SH_EXEC_NEEDLES").any_in(text) {
        return Vec::new();
    }
    let mut out: Vec<(usize, PyStr)> = Vec::new();
    let mut walk = HookWalk::new();
    for (at, cmd) in exec_command_lines(p, text) {
        if crate::signs::pipes_download_to_shell(p, &cmd) {
            // (a hook's command reads these as the install test does)
            out.push((at, u("pipes a download into a shell")));
        }
        if pystr::split_char(&cmd, c('\n')).iter().any(|row| crate::signs::runs_substituted_download(p, row)) {
            out.push((at, crate::signs::cat_reason(p, "run")));
        }
        for r in sh_reasons(p, &cmd, 0, true, &mut walk) {
            out.push((at, r));
        }
    }
    out
}

/// core._exec_command_lines: [(offset, command line)] — what each exec call
/// of `text` is handed as a command line (a string literal, a name given
/// one, or such pieces joined), and where; at most _SH_EXEC_MAX.
pub(crate) fn exec_command_lines(p: &Pack, text: &[u32]) -> Vec<(usize, PyStr)> {
    let mut out: Vec<(usize, PyStr)> = Vec::new();
    let mut values: Option<HashMap<PyStr, PyStr>> = None; // name -> the string literal it is given
    let max = p.usize("_SH_EXEC_MAX");
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    for m in p.re("_SH_EXEC_LINE_RE").finditer(text) {
        if out.len() >= max {
            break;
        }
        let vals = values.get_or_insert_with(|| {
            let mut v: HashMap<PyStr, PyStr> = HashMap::new();
            for (k, a) in p.re("_DD_ASSIGN_RE").finditer(text).enumerate() {
                if k >= max_assigns {
                    break;
                }
                let value = a.group(2).unwrap_or(&[]);
                let lead = value.len() - pystr::lstrip(value).len();
                if let Some((got, _)) = sh_literal_at(p, text, a.start_of(2) as usize + lead) {
                    let name = a.group(1).unwrap_or(&[]).to_vec();
                    v.entry(name).or_insert(got);
                }
            }
            v
        });
        if let Some(cmd) = sh_command_value(p, text, m.end(), vals) {
            out.push((m.start(), cmd));
        }
    }
    out
}

/// core.exec_command_reasons: the reasons the command lines text hands a shell give.
pub fn exec_command_reasons(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut reasons: Vec<PyStr> = Vec::new();
    for (_, r) in exec_command_flows(p, text) {
        push_new(&mut reasons, r);
    }
    reasons
}

// ---------------- an install hook's command, read as a program ----------------

/// core._hook_inline_code: the code a shell text hands node (-e, --eval, -p,
/// --print, and the other JavaScript runtimes) or python (-c) inline, also
/// inside `sh -c`, `eval` and `cmd /c` command lines: (its language, "js"
/// or "py", the code).
pub fn hook_inline_code(p: &Pack, text: &[u32], walk: &mut HookWalk, depth: usize) -> Vec<(&'static str, PyStr)> {
    let mut out: Vec<(&'static str, PyStr)> = Vec::new();
    if depth > p.usize("_SH_MAX_DEPTH") {
        return out;
    }
    let max_commands = p.usize("HOOK_MAX_COMMANDS");
    let runtimes = p.map_strs("_JS_RUNTIMES");
    for cmd in sh_parse(p, text) {
        if walk.commands >= max_commands {
            walk.complete = false;
            break;
        }
        walk.commands += 1;
        let (pi, name, _status) = sh_program(p, &cmd);
        let pi = match pi {
            None => continue,
            Some(x) => x,
        };
        let args = &cmd.words[pi + 1..];
        if in_set(p.strs("_NODE_NAMES"), &name) || runtimes.iter().any(|(k, _)| *k == name) {
            if let Some(code) = crate::hooks::node_script(p, args).2 {
                if !code.is_empty() {
                    out.push(("js", sh_literal(&code)));
                }
            }
        } else if p.re("_PYTHON_NAME_RE").match_(&name).is_some() {
            if let Some(code) = crate::hooks::interpreter_script(args).1 {
                if !code.is_empty() {
                    out.push(("py", sh_literal(&code)));
                }
            }
        } else if let Some(code) = sh_code(p, &name, args) {
            if !code.is_empty() {
                out.extend(hook_inline_code(p, &code, walk, depth + 1));
            }
        }
    }
    out
}

/// core.hook_command_risk: the reasons an install hook's command looks
/// hostile ([] if none), read as a program: the install-script test's
/// reasons for the command and for the code it hands an interpreter inline,
/// then what its network commands do. `output_kept`: what the command
/// prints is used (a binding.gyp command expansion's value).
pub fn hook_command_risk(p: &Pack, cmd: &[u32], output_kept: bool) -> Vec<PyStr> {
    if pystr::strip(cmd).is_empty() || cmd.len() > p.usize("HOOK_MAX_CHARS") {
        return Vec::new();
    }
    let mut reasons = crate::signs::install_script_risk_with(p, cmd, false, true, None);
    let mut walk = HookWalk::new();
    for (lang, code) in hook_inline_code(p, cmd, &mut walk, 0) {
        for r in crate::signs::install_script_risk_with(p, &code, false, false, Some(lang)) {
            push_new(&mut reasons, r);
        }
    }
    for r in sh_reasons(p, cmd, 0, output_kept, &mut walk) {
        push_new(&mut reasons, r);
    }
    crate::signs::label_sends(p, cmd, &mut reasons);
    reasons
}
