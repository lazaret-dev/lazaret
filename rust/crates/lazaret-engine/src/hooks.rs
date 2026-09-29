//! Following an install hook to the files it runs: a port of
//! lazaret.scanner.core's `_hook_tokens`, `follow_hook` and their helpers
//! (section "Following a hook command to the files it runs"), with CPython's
//! shlex (posix, punctuation_chars, whitespace_split, no commenters) and
//! `node_candidates` / `shebang_lang`.

use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::{HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn is_shlex_ws(ch: u32) -> bool {
    matches!(ch, 0x20 | 0x09 | 0x0D | 0x0A)
}

fn is_punct(ch: u32) -> bool {
    matches!(ch, 0x28 | 0x29 | 0x3B | 0x3C | 0x3E | 0x7C | 0x26) // ();<>|&
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Space,
    Word,
    Punct,
    Quote(u32),
    Escape,
    Eof,
}

/// CPython's shlex.shlex(cmd, posix=True, punctuation_chars=True) with
/// whitespace_split = True and commenters = "": list(lex), or None where it
/// raises ValueError (an open quote or a trailing backslash).
pub fn shlex_split(cmd: &[u32]) -> Option<Vec<PyStr>> {
    let mut i = 0usize;
    let mut pushback: Vec<u32> = Vec::new();
    let mut state = St::Space;
    let mut out = Vec::new();
    loop {
        // read_token
        let mut quoted = false;
        let mut escapedstate = St::Space;
        let mut token: PyStr = Vec::new();
        loop {
            let nextchar = if let Some(ch) = pushback.pop() {
                Some(ch)
            } else if i < cmd.len() {
                i += 1;
                Some(cmd[i - 1])
            } else {
                None
            };
            match state {
                St::Eof => {
                    token.clear();
                    break;
                }
                St::Space => match nextchar {
                    None => {
                        state = St::Eof;
                        break;
                    }
                    Some(ch) if is_shlex_ws(ch) => {
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(ch) if ch == c('\\') => {
                        escapedstate = St::Word;
                        state = St::Escape;
                    }
                    Some(ch) if is_punct(ch) => {
                        token = vec![ch];
                        state = St::Punct;
                    }
                    Some(ch) if ch == c('\'') || ch == c('"') => state = St::Quote(ch),
                    Some(ch) => {
                        token = vec![ch];
                        state = St::Word;
                    }
                },
                St::Quote(q) => {
                    quoted = true;
                    match nextchar {
                        None => return None, // No closing quotation
                        Some(ch) if ch == q => state = St::Word,
                        Some(ch) if ch == c('\\') && q == c('"') => {
                            escapedstate = St::Quote(q);
                            state = St::Escape;
                        }
                        Some(ch) => token.push(ch),
                    }
                }
                St::Escape => match nextchar {
                    None => return None, // No escaped character
                    Some(ch) => {
                        if let St::Quote(eq) = escapedstate {
                            if ch != c('\\') && ch != eq {
                                token.push(c('\\'));
                            }
                        }
                        token.push(ch);
                        state = escapedstate;
                    }
                },
                St::Word | St::Punct => match nextchar {
                    None => {
                        state = St::Eof;
                        break;
                    }
                    Some(ch) if is_shlex_ws(ch) => {
                        state = St::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(ch) if state == St::Punct => {
                        if is_punct(ch) {
                            token.push(ch);
                        } else {
                            pushback.push(ch); // (not whitespace: handled above)
                            state = St::Space;
                            break;
                        }
                    }
                    Some(ch) if ch == c('\'') || ch == c('"') => state = St::Quote(ch),
                    Some(ch) if ch == c('\\') => {
                        escapedstate = St::Word;
                        state = St::Escape;
                    }
                    Some(ch) if !is_punct(ch) => token.push(ch),
                    Some(ch) => {
                        pushback.push(ch);
                        state = St::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                },
            }
        }
        if !quoted && token.is_empty() {
            return Some(out); // None: the end
        }
        out.push(token);
    }
}

/// core._hook_tokens: shlex's tokens, or the fallback's where shlex raises.
pub fn hook_tokens(p: &Pack, cmd: &[u32]) -> Vec<PyStr> {
    match shlex_split(cmd) {
        Some(t) => t,
        None => p.re("_HOOK_FALLBACK_TOKEN_RE").findall(cmd).into_iter().map(|s| s.to_vec()).collect(),
    }
}

fn in_set(set: &[PyStr], s: &[u32]) -> bool {
    set.iter().any(|x| x.as_slice() == s)
}

fn is(s: &[u32], lit: &str) -> bool {
    pystr::eq(s, lit)
}

fn local_module(p: &Pack, value: &[u32]) -> bool {
    !value.is_empty()
        && (pystr::starts_with(value, "./")
            || pystr::starts_with(value, "../")
            || pystr::starts_with(value, "/")
            || p.re("_SCRIPT_EXT_RE").search(value).is_some())
}

/// Python's str.partition("="): (head, found, tail).
fn partition_eq(s: &[u32]) -> (&[u32], bool, &[u32]) {
    match s.iter().position(|&x| x == c('=')) {
        Some(k) => (&s[..k], true, &s[k + 1..]),
        None => (s, false, &[]),
    }
}

/// core._node_script: (script, preloads, code).
fn node_script(p: &Pack, args: &[PyStr]) -> (Option<PyStr>, Vec<PyStr>, Option<PyStr>) {
    let code_flags = p.strs("_NODE_CODE_FLAGS");
    let value_flags = p.strs("_NODE_VALUE_FLAGS");
    let preload_flags = p.strs("_NODE_PRELOAD_FLAGS");
    let mut preloads = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if is(a, "--") {
            return (args.get(i + 1).cloned(), preloads, None);
        }
        if pystr::starts_with(a, "-") && !is(a, "-") {
            let (name, eq, val) = partition_eq(a);
            if in_set(code_flags, name) {
                let code = if eq { val.to_vec() } else { args.get(i + 1).cloned().unwrap_or_default() };
                return (None, preloads, Some(code));
            }
            if in_set(value_flags, name) {
                let value = if eq { val.to_vec() } else { args.get(i + 1).cloned().unwrap_or_default() };
                if in_set(preload_flags, name) && local_module(p, &value) {
                    preloads.push(value);
                }
                i += if eq { 1 } else { 2 };
                continue;
            }
            i += 1;
            continue;
        }
        return (Some(a.clone()), preloads, None);
    }
    (None, preloads, None)
}

/// core._interpreter_script: (script, inline code).
fn interpreter_script(args: &[PyStr]) -> (Option<PyStr>, Option<PyStr>) {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if is(a, "-c") {
            return (None, Some(args.get(i + 1).cloned().unwrap_or_default()));
        }
        if is(a, "-m") && i + 1 < args.len() {
            let mut m = pystr::replace_char(&args[i + 1], c('.'), c('/'));
            m.extend(u(".py"));
            return (Some(m), None);
        }
        if (is(a, "-o") || is(a, "-O") || is(a, "-W") || is(a, "-X")) && i + 1 < args.len() {
            i += 2;
            continue;
        }
        if pystr::starts_with(a, "-") && !is(a, "-") {
            i += 1;
            continue;
        }
        return (Some(a.clone()), None);
    }
    (None, None)
}

struct Walk {
    commands: usize,
    complete: bool,
}

/// core._apply_path: posixpath.normpath's loop on the components kept so far.
fn apply_path(comps: &mut Vec<PyStr>, path: &[u32]) {
    for comp in path.split(|&x| x == c('/')) {
        if comp.is_empty() || is(comp, ".") {
            continue;
        }
        if !is(comp, "..") || comps.is_empty() || comps.last().map(|l| is(l, "..")).unwrap_or(false) {
            comps.push(comp.to_vec());
        } else {
            comps.pop();
        }
    }
}

type Where = (bool, Vec<PyStr>);

/// core._hook_cd
fn hook_cd(where_: &Where, dest: &[u32]) -> Option<Where> {
    if dest.is_empty() || is(dest, "~") || is(dest, "-") || pystr::starts_with(dest, "$") || pystr::starts_with(dest, "~")
    {
        return None;
    }
    let dest = pystr::replace_char(dest, c('\\'), c('/'));
    if pystr::starts_with(&dest, "/") {
        let raw = pystr::lstrip_chars(&dest, "/");
        let mut comps = Vec::new();
        apply_path(&mut comps, raw);
        return Some((!(raw.is_empty() || is(raw, ".")), comps));
    }
    let mut comps = where_.1.clone();
    apply_path(&mut comps, &dest);
    Some((!comps.is_empty(), comps))
}

fn join_comps(comps: &[PyStr]) -> PyStr {
    let parts: Vec<&[u32]> = comps.iter().map(|x| x.as_slice()).collect();
    let j = pystr::join(&[c('/')], &parts);
    if j.is_empty() {
        u(".")
    } else {
        j
    }
}

struct Seg<'p> {
    p: &'p Pack,
    depth: usize,
    state: Where,
    joined: HashMap<PyStr, PyStr>,
    targets: Vec<PyStr>,
}

impl<'p> Seg<'p> {
    fn join(&mut self, path: &[u32], where_: Option<&Where>) -> PyStr {
        let path = pystr::replace_char(path, c('\\'), c('/'));
        let (is_set, comps) = match where_ {
            Some(w) => (w.0, &w.1),
            None => (self.state.0, &self.state.1),
        };
        if !is_set || pystr::starts_with(&path, "/") {
            return path;
        }
        if where_.is_some() {
            let mut cs = comps.clone();
            apply_path(&mut cs, &path);
            return join_comps(&cs);
        }
        if let Some(j) = self.joined.get(&path) {
            return j.clone();
        }
        let mut cs = comps.clone();
        apply_path(&mut cs, &path);
        let j = join_comps(&cs);
        self.joined.insert(path, j.clone());
        j
    }

    fn flush(&mut self, seg: &[PyStr], walk: &mut Walk) {
        let p = self.p;
        let redirects = p.strs("_HOOK_REDIRECTS");
        let redirect_re = p.re("_REDIRECT_TOKEN_RE");
        let dup_fd = p.re("_DUP_FD_RE");
        let fd_number = p.re("_FD_NUMBER_RE");
        let mut words: Vec<PyStr> = Vec::new();
        let mut skip = false;
        for tok in seg {
            if skip {
                skip = false;
                continue;
            }
            if in_set(redirects, tok) || redirect_re.fullmatch(tok).is_some() {
                skip = dup_fd.search(tok).is_none();
                if words.last().map(|w| fd_number.fullmatch(w).is_some()).unwrap_or(false) {
                    words.pop();
                }
                continue;
            }
            words.push(tok.clone());
        }
        if words.is_empty() {
            return;
        }
        if walk.commands >= p.usize("HOOK_MAX_COMMANDS") {
            walk.complete = false;
            return;
        }
        walk.commands += 1;
        let wrappers = p.strs("_HOOK_WRAPPERS");
        let env_assign = p.re("_ENV_ASSIGN_RE");
        let value_options = p.map_strs("_WRAPPER_VALUE_OPTIONS");
        let chdir_options = p.map_strs("_WRAPPER_CHDIR_OPTIONS");
        let command_options = p.map_strs("_WRAPPER_COMMAND_OPTIONS");
        let lookup = |table: &'p [(PyStr, Vec<PyStr>)], name: &[u32]| -> &'p [PyStr] {
            table.iter().find(|(k, _)| k.as_slice() == name).map(|(_, v)| v.as_slice()).unwrap_or(&[])
        };
        let mut i = 0usize;
        let mut where_: Option<Where> = None;
        while i < words.len() {
            let word = words[i].clone();
            if env_assign.match_(&word).is_some() {
                i += 1;
                continue;
            }
            let name = pystr::lower(&word);
            if !in_set(wrappers, &name) {
                break;
            }
            i += 1;
            let values = lookup(value_options, &name);
            while i < words.len() && pystr::starts_with(&words[i], "-") && (!is(&words[i], "-") || is(&name, "env")) {
                let opt = words[i].clone();
                i += 1;
                if is(&opt, "--") {
                    break;
                }
                let (key, value): (PyStr, PyStr);
                if pystr::starts_with(&opt, "--") {
                    let (k, eq, v) = partition_eq(&opt);
                    if !in_set(values, k) {
                        continue;
                    }
                    key = k.to_vec();
                    if eq {
                        value = v.to_vec();
                    } else {
                        value = words.get(i).cloned().unwrap_or_default();
                        i += 1;
                    }
                } else if in_set(values, pystr::upto(&opt, 2)) {
                    key = pystr::upto(&opt, 2).to_vec();
                    let v = pystr::from(&opt, 2).to_vec();
                    if v.is_empty() {
                        value = words.get(i).cloned().unwrap_or_default();
                        i += 1;
                    } else {
                        value = v;
                    }
                } else {
                    continue;
                }
                if in_set(lookup(chdir_options, &name), &key) {
                    let base = where_.clone().unwrap_or_else(|| self.state.clone());
                    if let Some(w) = hook_cd(&base, &value) {
                        where_ = Some(w);
                    }
                } else if in_set(lookup(command_options, &name), &key) {
                    if self.depth < 2 {
                        let inner = hook_targets(p, &value, self.depth + 1, walk);
                        for t in inner {
                            let j = self.join(&t, where_.as_ref());
                            self.targets.push(j);
                        }
                    }
                    return;
                }
            }
        }
        if i >= words.len() {
            return;
        }
        let head = pystr::replace_char(&words[i], c('\\'), c('/'));
        let base_raw = match head.iter().rposition(|&x| x == c('/')) {
            Some(k) => &head[k + 1..],
            None => &head[..],
        };
        let base = pystr::lower(base_raw);
        if is(&base, "cd") || is(&base, "pushd") {
            let dest = words[i + 1..].iter().find(|w| !pystr::starts_with(w, "-")).cloned().unwrap_or_default();
            if let Some(moved) = hook_cd(&self.state, &dest) {
                self.state = moved;
                self.joined.clear();
            }
            return;
        }
        let mut script: Option<PyStr> = None;
        let mut extra: Vec<PyStr> = Vec::new();
        let mut code: Option<PyStr> = None;
        let rest = &words[i + 1..];
        if in_set(p.strs("_NODE_NAMES"), &base) {
            let (s, e, cd) = node_script(p, rest);
            script = s;
            extra = e;
            code = cd;
        } else if in_set(p.strs("_SHELL_NAMES"), &base) || p.re("_PYTHON_NAME_RE").match_(&base).is_some() {
            let (s, inline) = interpreter_script(rest);
            script = s;
            if let Some(inline) = inline {
                if !inline.is_empty() && self.depth < 2 && in_set(p.strs("_SHELL_NAMES"), &base) {
                    let inner = hook_targets(p, &inline, self.depth + 1, walk);
                    for t in inner {
                        let j = self.join(&t, where_.as_ref());
                        self.targets.push(j);
                    }
                }
            }
        } else if pystr::starts_with(&head, "./")
            || pystr::starts_with(&head, "../")
            || (head.contains(&c('/')) && !pystr::starts_with(&head, "/"))
            || p.re("_SCRIPT_EXT_RE").search(&head).is_some()
        {
            script = Some(head.clone());
        }
        let mut all: Vec<PyStr> = Vec::new();
        if let Some(s) = script {
            all.push(s);
        }
        all.extend(extra);
        for t in all {
            if !t.is_empty() {
                let j = self.join(&t, where_.as_ref());
                self.targets.push(j);
            }
        }
        if let Some(code) = code {
            if !code.is_empty() {
                let req = p.re("_LOCAL_REQUIRE_RE");
                let found: Vec<PyStr> = req.finditer(&code).filter_map(|m| m.group(1).map(|g| g.to_vec())).collect();
                for t in found {
                    let j = self.join(&t, where_.as_ref());
                    self.targets.push(j);
                }
            }
        }
    }
}

fn only_operators(tok: &[u32]) -> bool {
    !tok.is_empty() && tok.iter().all(|&x| matches!(x, 0x3B | 0x26 | 0x7C | 0x28 | 0x29)) // ;&|()
}

/// core._hook_segment_targets
fn hook_segment_targets(p: &Pack, tokens: &[PyStr], depth: usize, walk: &mut Walk) -> Vec<PyStr> {
    let separators = p.strs("_HOOK_SEPARATORS");
    let mut seg_state = Seg { p, depth, state: (false, Vec::new()), joined: HashMap::new(), targets: Vec::new() };
    let mut seg: Vec<PyStr> = Vec::new();
    for tok in tokens {
        if in_set(separators, tok) || only_operators(tok) {
            seg_state.flush(&seg, walk);
            seg.clear();
        } else {
            seg.push(tok.clone());
        }
    }
    seg_state.flush(&seg, walk);
    seg_state.targets
}

fn hook_targets(p: &Pack, cmd: &[u32], depth: usize, walk: &mut Walk) -> Vec<PyStr> {
    let mut targets = Vec::new();
    let mut variants: Vec<PyStr> = vec![cmd.to_vec()];
    if cmd.contains(&c('\\')) {
        variants.push(pystr::replace_char(cmd, c('\\'), c('/')));
    }
    for v in variants {
        let toks = hook_tokens(p, &v);
        targets.extend(hook_segment_targets(p, &toks, depth, walk));
    }
    targets
}

/// core.follow_hook: (targets, complete).
pub fn follow_hook(p: &Pack, cmd: &[u32]) -> (Vec<PyStr>, bool) {
    if pystr::strip(cmd).is_empty() {
        return (Vec::new(), true);
    }
    if cmd.len() > p.usize("HOOK_MAX_CHARS") {
        return (Vec::new(), false);
    }
    let mut walk = Walk { commands: 0, complete: true };
    let mut targets = hook_targets(p, cmd, 0, &mut walk);
    let node_e = p.re("_NODE_E_RE");
    let req = p.re("_LOCAL_REQUIRE_RE");
    for m in node_e.finditer(cmd) {
        let code = m.first_group().unwrap_or(&[]);
        for s in req.findall(code) {
            targets.push(s.to_vec());
        }
    }
    let max_path = p.usize("HOOK_MAX_PATH");
    let mut seen: HashSet<PyStr> = HashSet::new();
    let mut out: Vec<PyStr> = Vec::new();
    for t in targets {
        if !t.is_empty() && !seen.contains(&t) && !is(&t, "-") && !is(&t, ".") {
            if t.len() > max_path {
                walk.complete = false;
                continue;
            }
            seen.insert(t.clone());
            out.push(t);
        }
    }
    let max_targets = p.usize("HOOK_MAX_TARGETS");
    if out.len() > max_targets {
        out.truncate(max_targets);
        walk.complete = false;
    }
    (out, walk.complete)
}

/// The code of each `node -e` in a command, as written (the parity tests' view).
pub fn node_e_codes(p: &Pack, cmd: &[u32]) -> Vec<PyStr> {
    p.re("_NODE_E_RE").finditer(cmd).map(|m| m.first_group().unwrap_or(&[]).to_vec()).collect()
}

/// core.node_candidates
pub fn node_candidates(rel: &[u32]) -> Vec<PyStr> {
    let rel = pystr::rstrip_chars(rel, "/");
    [
        "", ".js", ".cjs", ".mjs", ".json", ".node", "/index.js", "/index.cjs", "/index.mjs", "/index.json",
    ]
    .iter()
    .map(|ext| {
        let mut v = rel.to_vec();
        v.extend(u(ext));
        v
    })
    .collect()
}

/// core.shebang_lang: "js" | "py" | "sh" | None.
pub fn shebang_lang(p: &Pack, text: &[u32]) -> Option<&'static str> {
    let m = p.re("_SHEBANG_RE").match_(text)?;
    let last = |s: &[u32]| -> PyStr {
        let tail = match s.iter().rposition(|&x| x == c('/')) {
            Some(k) => &s[k + 1..],
            None => s,
        };
        pystr::lower(tail)
    };
    let mut prog = last(m.group(1).unwrap_or(&[]));
    if is(&prog, "env") {
        if let Some(g2) = m.group(2) {
            if !g2.is_empty() {
                prog = last(g2);
            }
        }
    }
    if in_set(p.strs("_SHEBANG_JS_NAMES"), &prog) {
        return Some("js");
    }
    if p.re("_PYTHON_NAME_RE").match_(&prog).is_some() {
        return Some("py");
    }
    if in_set(p.strs("_SHELL_NAMES"), &prog) {
        return Some("sh");
    }
    None
}
