//! Secrets sent out by name, and credential sweeps (RA-1, 0.1.9; SC-WORKFLOW-EXFIL).
//!
//! GhostAction (August to October 2026) committed workflows under its victims' names: the first wave named the
//! secrets the repository's own workflows use (`${{ secrets.VPS_HOST }}`, …) and sent them in one `curl -X POST -d`
//! to a raw IP over plain HTTP; the October wave checked out the whole history, searched the tree and `git log -p`
//! for credentials with `grep`, and sent what it found. `exfil` reads each step's script as the shell does, as far
//! as the question needs: commands, pipes, redirections, `$( … )`, variables, the step's, job's and workflow's `env:`
//! and the files the job's steps write; a secret is sent when it is in a request's body, its query, its path or a
//! header that is not a credential's, or what the command reads from stdin. Not counted: a secret that is a
//! credential of the service (an Authorization or token header, `-u`, a token parameter of the query), one that is
//! the address itself (a webhook's URL), a request over https to a named host whose path holds a secret (a bot's
//! token, a repository kept secret: the service it is for), one sent over https to a host its name names
//! (TELEGRAM_CHAT_ID to api.telegram.org), and anything sent to the runner itself (localhost, a private address, a
//! service container's name). The patterns, lists, limits and rule texts are the pack's (`_WFX_*`).

use super::outline::{self, Rec};
use super::workflow::{self, Found};
use crate::findings::{self, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::{BTreeMap, BTreeSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

const MARK: u32 = 1;

/// What a word, a command's output or a file holds: the secrets in it, and the text of the credential search whose
/// output it is (if any).
#[derive(Clone, Default)]
struct Content {
    names: BTreeSet<PyStr>,
    search: Option<PyStr>,
}

impl Content {
    fn join(&mut self, b: &Content) {
        self.names.extend(b.names.iter().cloned());
        if self.search.is_none() {
            self.search = b.search.clone();
        }
    }
}

fn any_of(ch: u32, set: &str) -> bool {
    set.chars().any(|x| x as u32 == ch)
}

fn is_digit(ch: u32) -> bool {
    (c('0')..=c('9')).contains(&ch)
}

fn is_letter(ch: u32) -> bool {
    (c('A')..=c('Z')).contains(&ch) || (c('a')..=c('z')).contains(&ch)
}

/// s with its ASCII letters in lower case.
fn lower(s: &[u32]) -> PyStr {
    s.iter().map(|&ch| if (c('A')..=c('Z')).contains(&ch) { ch + 32 } else { ch }).collect()
}

fn at(s: &[u32], i: usize, lit: &str) -> bool {
    pystr::starts_with_at(s, i, lit)
}

fn has(list: &[PyStr], x: &[u32]) -> bool {
    list.iter().any(|y| y.as_slice() == x)
}

fn is(x: &[u32], names: &[&str]) -> bool {
    names.iter().any(|n| pystr::eq(x, n))
}

fn find(s: &[u32], ch: u32, from: usize) -> Option<usize> {
    if from > s.len() {
        return None;
    }
    pystr::find_char(s, ch, from)
}

/// (before, found, after) of s split at the first `sep` (str.partition).
fn partition(s: &[u32], sep: u32) -> (&[u32], bool, &[u32]) {
    match find(s, sep, 0) {
        Some(k) => (&s[..k], true, &s[k + 1..]),
        None => (s, false, &s[s.len()..]),
    }
}

/// s up to the first of `seps`.
fn cut_at(s: &[u32], seps: &str) -> PyStr {
    let mut rest = s;
    for sep in seps.chars() {
        if let Some(j) = find(rest, sep as u32, 0) {
            rest = &rest[..j];
        }
    }
    rest.to_vec()
}

/// The index after the group that opened before i: kind '(' (`$( … )`) or '"' (a double-quoted string), read with
/// the quotes, escapes and substitutions inside it, in one pass.
fn group_end(s: &[u32], mut i: usize, kind: u32) -> usize {
    let n = s.len();
    let mut stack = vec![kind];
    while i < n && !stack.is_empty() {
        let ch = s[i];
        if ch == c('\\') {
            i += 2;
            continue;
        }
        if stack.last() == Some(&c('"')) {
            if ch == c('"') {
                stack.pop();
            } else if ch == c('$') && at(s, i, "$(") {
                stack.push(c('('));
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if ch == c('\'') || ch == c('`') {
            i = find(s, ch, i + 1).map_or(n, |j| j + 1);
            continue;
        }
        if ch == c('"') || ch == c('(') {
            stack.push(ch);
        } else if ch == c(')') {
            stack.pop();
        }
        i += 1;
    }
    i.min(n)
}

/// A logical line's commands, as pipelines of segments (the text of each command between `|`): split at `;`, `&&`,
/// `||`, `&` and `|` outside quotes and substitutions, up to a comment.
fn pipelines(line: &[u32]) -> Vec<Vec<PyStr>> {
    let n = line.len();
    let mut out: Vec<Vec<PyStr>> = Vec::new();
    let mut segs: Vec<PyStr> = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    fn cut(line: &[u32], segs: &mut Vec<PyStr>, start: usize, end: usize) {
        if start < end {
            let seg = pystr::strip_chars(&line[start..end], " \t");
            if !seg.is_empty() {
                segs.push(seg.to_vec());
            }
        }
    }
    while i < n {
        let ch = line[i];
        if ch == c('\\') {
            i += 2;
        } else if ch == c('\'') || ch == c('`') {
            i = find(line, ch, i + 1).map_or(n, |j| j + 1);
        } else if ch == c('"') {
            i = group_end(line, i + 1, c('"'));
        } else if ch == c('$') && at(line, i, "$(") {
            i = group_end(line, i + 2, c('('));
        } else if ch == c('#') && (i == 0 || any_of(line[i - 1], " \t;&|(")) {
            break;
        } else if ch == c('|') || ch == c(';') || ch == c('&') {
            let pipe = ch == c('|') && !at(line, i, "||");
            if ch == c('&') && !at(line, i, "&&") && (at(line, i, "&>") || (i > 0 && any_of(line[i - 1], "<>"))) {
                i += 1; // a redirection's &: `&>f`, `2>&1`
                continue;
            }
            cut(line, &mut segs, start, i);
            i += if at(line, i, "||") || at(line, i, "&&") || at(line, i, "|&") || at(line, i, ";;") { 2 } else { 1 };
            if !pipe && !segs.is_empty() {
                out.push(std::mem::take(&mut segs));
            }
            start = i;
        } else {
            i += 1;
        }
    }
    cut(line, &mut segs, start, i.min(n));
    if !segs.is_empty() {
        out.push(segs);
    }
    out
}

/// (words, redirections) of a command's text: its words with their quotes taken off (a substitution kept as
/// written), and each redirection as (operator, target): '<', '<<' (a here-document: its delimiter), '<<<', '>',
/// '>>'. A redirection to another descriptor (`2>&1`) is dropped.
fn words(seg: &[u32]) -> (Vec<PyStr>, Vec<(PyStr, PyStr)>) {
    struct W {
        words: Vec<PyStr>,
        redirs: Vec<(PyStr, PyStr)>,
        cur: PyStr,
        has: bool,
        pending: Option<PyStr>,
    }
    impl W {
        fn flush(&mut self) {
            if self.has {
                let w = std::mem::take(&mut self.cur);
                match self.pending.take() {
                    Some(op) => self.redirs.push((op, w)),
                    None => self.words.push(w),
                }
            }
            self.cur.clear();
            self.has = false;
        }
    }
    let n = seg.len();
    let mut w = W { words: Vec::new(), redirs: Vec::new(), cur: Vec::new(), has: false, pending: None };
    let mut i = 0;
    while i < n {
        let ch = seg[i];
        if ch == c(' ') || ch == c('\t') {
            w.flush();
            i += 1;
        } else if ch == c('\'') {
            let j = find(seg, c('\''), i + 1).unwrap_or(n);
            w.cur.extend_from_slice(&seg[i + 1..j]);
            w.has = true;
            i = j + 1;
        } else if ch == c('"') {
            let j = group_end(seg, i + 1, c('"'));
            let inner = if seg[j - 1] == c('"') && j - 1 > i { &seg[i + 1..j - 1] } else { &seg[i + 1..j] };
            w.cur.extend_from_slice(inner);
            w.has = true;
            i = j;
        } else if ch == c('\\') && i + 1 < n {
            w.cur.push(seg[i + 1]);
            w.has = true;
            i += 2;
        } else if ch == c('$') && at(seg, i, "$(") {
            let j = group_end(seg, i + 2, c('('));
            w.cur.extend_from_slice(&seg[i..j]);
            w.has = true;
            i = j;
        } else if ch == c('`') {
            let j = find(seg, c('`'), i + 1).map_or(n, |j| j + 1);
            w.cur.extend_from_slice(&seg[i..j]);
            w.has = true;
            i = j;
        } else if ch == c('>') || ch == c('<') || (ch == c('&') && at(seg, i, "&>")) {
            if w.has && w.cur.iter().all(|&d| is_digit(d)) {
                w.cur.clear(); // the descriptor the operator is for
                w.has = false;
            }
            w.flush();
            let mut op_ch = ch;
            if ch == c('&') {
                i += 1;
                op_ch = c('>');
            }
            let mut k = i;
            while k < n && k - i < 3 && seg[k] == op_ch {
                k += 1;
            }
            let op = seg[i..k].to_vec();
            if k < n && seg[k] == c('|') {
                k += 1;
            }
            if k < n && seg[k] == c('&') {
                // >&2, <&0: another descriptor
                k += 1;
                while k < n && (is_digit(seg[k]) || seg[k] == c('-')) {
                    k += 1;
                }
                i = k;
                continue;
            }
            w.pending = if is(&op, &["<", "<<", "<<<", ">", ">>"]) { Some(op.clone()) } else { None };
            if pystr::eq(&op, "<<") && k < n && seg[k] == c('-') {
                k += 1;
            }
            i = k;
        } else {
            w.cur.push(ch);
            w.has = true;
            i += 1;
        }
    }
    w.flush();
    (w.words, w.redirs)
}

/// A command's name as written: its last path part, without `.exe`.
fn shown(word: &[u32]) -> PyStr {
    let w = pystr::replace_char(word, c('\\'), c('/'));
    let name = match w.iter().rposition(|&x| x == c('/')) {
        Some(k) => &w[k + 1..],
        None => &w[..],
    };
    if pystr::ends_with(&lower(name), ".exe") {
        name[..name.len() - 4].to_vec()
    } else {
        name.to_vec()
    }
}

/// A command's name: its last path part, lower case, without `.exe`.
fn base(word: &[u32]) -> PyStr {
    lower(&shown(word))
}

struct Command {
    name: Option<PyStr>,
    args: Vec<PyStr>,
    assigns: Vec<(PyStr, PyStr)>,
    xargs: bool,
    shown: PyStr,
}

fn split_assign(w: &[u32]) -> (PyStr, PyStr) {
    let k = find(w, c('='), 0).unwrap_or(w.len());
    (w[..k].to_vec(), w[(k + 1).min(w.len())..].to_vec())
}

/// The command of a command's words: VAR=value words, sudo, env, time and the like passed over; `xargs CMD` read as
/// CMD given its input. name None: assignments alone.
fn command(p: &Pack, words: &[PyStr]) -> Command {
    let assign = p.re("_WFX_ASSIGN_RE");
    let is_assign = |x: &[u32]| assign.match_(x).is_some();
    let wrappers = p.strs("_WFX_WRAPPERS");
    let mut assigns: Vec<(PyStr, PyStr)> = Vec::new();
    let mut xargs = false;
    let mut i = 0;
    let done = |name: Option<PyStr>, args: Vec<PyStr>, assigns: Vec<(PyStr, PyStr)>, xargs: bool, shown: PyStr| Command {
        name,
        args,
        assigns,
        xargs,
        shown,
    };
    while i < words.len() {
        let w = &words[i];
        if is_assign(w) {
            assigns.push(split_assign(w));
            i += 1;
            continue;
        }
        let name = base(w);
        let rest = &words[i + 1..];
        if is(&name, &["export", "declare", "typeset", "local", "readonly"])
            && i + 1 < words.len()
            && rest.iter().all(|x| is_assign(x) || pystr::starts_with(x, "-"))
            && rest.iter().any(|x| is_assign(x))
        {
            for x in rest {
                if is_assign(x) {
                    assigns.push(split_assign(x));
                }
            }
            return done(None, Vec::new(), assigns, false, Vec::new());
        }
        if has(wrappers, &name) {
            let mut j = i + 1;
            while j < words.len() && pystr::starts_with(&words[j], "-") {
                j += 1;
            }
            if pystr::eq(&name, "timeout") && j < words.len() {
                j += 1; // its duration
            }
            if j >= words.len() || (pystr::eq(&name, "env") && words[j..].iter().all(|x| is_assign(x))) {
                // `env` alone prints the environment
                return done(Some(name), rest.to_vec(), assigns, xargs, shown(w));
            }
            i = j;
            continue;
        }
        if pystr::eq(&name, "xargs") {
            xargs = true;
            i += 1;
            while i < words.len() && pystr::starts_with(&words[i], "-") {
                let flag = &words[i];
                i += 1;
                if is(flag, &["-I", "-n", "-L", "-P", "-d", "-E", "-s", "-a"]) && i < words.len() {
                    i += 1;
                }
            }
            continue;
        }
        return done(Some(name), rest.to_vec(), assigns, xargs, shown(w));
    }
    done(None, Vec::new(), assigns, xargs, Vec::new())
}

/// What a step's script holds as it is read: the expressions taken out of it, the environment (variable -> the
/// secrets it holds), the plain values of the environment's and the script's variables, the script's own variables
/// (-> content, in the order they were first set), the files the job wrote (-> content), and the findings.
struct Ctx<'p> {
    p: &'p Pack,
    exprs: Vec<PyStr>,
    env: BTreeMap<PyStr, BTreeSet<PyStr>>,
    values: BTreeMap<PyStr, Option<PyStr>>,
    local: Vec<(PyStr, Content)>,
    local_at: BTreeMap<PyStr, usize>,
    files: BTreeMap<PyStr, Content>,
    job: PyStr,
    line: usize,
    found: Vec<Found>,
    depth_max: usize,
}

impl<'p> Ctx<'p> {
    /// A variable of the script given `text`: what it holds, and its value when it is plain text.
    fn assign(&mut self, name: &[u32], text: &[u32], content: Content) {
        match self.local_at.get(name) {
            Some(&k) => self.local[k].1 = content,
            None => {
                self.local_at.insert(name.to_vec(), self.local.len());
                self.local.push((name.to_vec(), content));
            }
        }
        if text.iter().any(|&ch| any_of(ch, "$`(") || ch == MARK) {
            self.values.remove(name);
        } else {
            self.values.insert(name.to_vec(), Some(text.to_vec()));
        }
    }

    /// A variable's plain value (the script's, else the environment's), or `default`.
    fn value(&self, name: &[u32], default: &[u32]) -> PyStr {
        match self.values.get(name) {
            Some(Some(v)) => v.clone(),
            _ => default.to_vec(),
        }
    }

    fn expr_names(&self, k: usize) -> BTreeSet<PyStr> {
        let mut names = BTreeSet::new();
        let e = match self.exprs.get(k) {
            Some(e) => e,
            None => return names,
        };
        names.extend(secret_names(self.p, e));
        for m in self.p.re("_WFX_ENV_NAME_RE").finditer(e) {
            if let Some(set) = self.env.get(first_group(&m)) {
                names.extend(set.iter().cloned());
            }
        }
        names
    }

    fn var(&self, name: &[u32]) -> Content {
        if let Some(&k) = self.local_at.get(name) {
            return self.local[k].1.clone();
        }
        Content { names: self.env.get(name).cloned().unwrap_or_default(), search: None }
    }

    /// What a dump of the environment holds: every secret of it, and the script's variables.
    fn everything(&self) -> Content {
        let mut out = Content::default();
        for set in self.env.values() {
            out.names.extend(set.iter().cloned());
        }
        for (_, v) in &self.local {
            out.join(v);
        }
        out
    }

    fn restore(&self, text: &[u32]) -> PyStr {
        self.p.re("_WFX_MARK_RE").sub_fn(text, 0, |m| {
            let k = m.group(1).and_then(pystr::int_of_digits).map(|k| k as usize);
            match k.and_then(|k| self.exprs.get(k)) {
                Some(e) => pystr::concat(&[&u("${{"), e, &u("}}")]),
                None => m.group0().to_vec(),
            }
        })
    }

    fn file(&self, path: &[u32]) -> Content {
        let path = if pystr::starts_with(path, "./") { &path[2..] } else { path };
        self.files.get(path).cloned().unwrap_or_default()
    }

    fn set_file(&mut self, path: &[u32], value: &Content, append: bool) {
        let path = if pystr::starts_with(path, "./") { &path[2..] } else { path };
        let slot = self.files.entry(path.to_vec()).or_default();
        if append {
            slot.join(value);
        } else {
            *slot = value.clone();
        }
    }
}

/// The name of a `secrets.NAME` / `secrets['NAME']` / `env.NAME` match (whichever group took part).
fn first_group<'s>(m: &crate::pyre::Match<'s>) -> &'s [u32] {
    m.group(1).or_else(|| m.group(2)).or_else(|| m.group(3)).unwrap_or(&[])
}

fn secret_names(p: &Pack, e: &[u32]) -> Vec<PyStr> {
    p.re("_WFX_SECRET_NAME_RE").finditer(e).map(|m| first_group(&m).to_vec()).collect()
}

/// The secrets (and a credential search's output) a word holds: its expressions, the variables it reads, the output
/// of the commands it substitutes.
fn content(word: &[u32], ctx: &mut Ctx, depth: usize) -> Content {
    let p = ctx.p;
    let mut out = Content::default();
    for m in p.re("_WFX_MARK_RE").finditer(word) {
        if let Some(k) = m.group(1).and_then(pystr::int_of_digits) {
            out.names.extend(ctx.expr_names(k as usize));
        }
    }
    for m in p.re("_WFX_VAR_RE").finditer(word) {
        let v = ctx.var(first_group(&m));
        out.join(&v);
    }
    if pystr::contains(word, "$(") || word.contains(&c('`')) {
        let n = word.len();
        let mut i = 0;
        while i < n {
            if at(word, i, "$(") {
                let j = group_end(word, i + 2, c('('));
                let inner = if word[j - 1] == c(')') && j - 1 >= i + 2 { &word[i + 2..j - 1] } else { &word[i + 2..j] };
                let got = eval(inner, ctx, depth + 1, None);
                out.join(&got);
                i = j;
            } else if word[i] == c('`') {
                let j = find(word, c('`'), i + 1).unwrap_or(n);
                let got = eval(&word[i + 1..j], ctx, depth + 1, None);
                out.join(&got);
                i = j + 1;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Read a line of a script (or a substitution's text): the findings of its sends go to ctx; -> the content of what
/// its last command writes to its output.
fn eval(text: &[u32], ctx: &mut Ctx, depth: usize, mut heredocs: Option<&mut Vec<Content>>) -> Content {
    if depth > ctx.depth_max {
        return Content::default();
    }
    let mut last = Content::default();
    for segs in pipelines(text) {
        last = pipeline(&segs, ctx, depth, heredocs.as_deref_mut());
    }
    last
}

/// The text of a search for credentials this command is (a grep of credential patterns, `git log -p`), or None.
fn sweep_of(name: &[u32], args: &[PyStr], seg: &[u32], ctx: &Ctx) -> Option<PyStr> {
    let first_is = |w: &str| args.first().is_some_and(|a| pystr::eq(a, w));
    if pystr::eq(name, "git") && first_is("log") && args.iter().any(|a| is(a, &["-p", "--patch", "-u"])) {
        return Some(ctx.restore(seg));
    }
    if has(ctx.p.strs("_WFX_GREPS"), name) || (pystr::eq(name, "git") && first_is("grep")) {
        let refs: Vec<&[u32]> = args.iter().map(|a| a.as_slice()).collect();
        if ctx.p.re("_WFX_CRED_PATTERN_RE").search(&pystr::join(&u(" "), &refs)).is_some() {
            return Some(ctx.restore(seg));
        }
    }
    None
}

/// Does this command print the environment (`env`, `printenv`, `set`, `export -p`, `gci env:`)?
fn is_dump(name: &[u32], args: &[PyStr]) -> bool {
    if is(name, &["env", "printenv"]) {
        return args.iter().all(|a| pystr::starts_with(a, "-"));
    }
    if is(name, &["set", "export", "declare", "typeset"]) {
        return args.iter().all(|a| is(a, &["-p", "-x", "-px", "-xp"]));
    }
    if is(name, &["get-childitem", "gci", "dir", "ls", "get-item", "gi"]) {
        return args.iter().any(|a| pystr::eq(pystr::rstrip_chars(&lower(a), "\\/*"), "env:"));
    }
    false
}

fn pipeline(segs: &[PyStr], ctx: &mut Ctx, depth: usize, mut heredocs: Option<&mut Vec<Content>>) -> Content {
    let p = ctx.p;
    let mut inp = Content::default();
    for seg in segs {
        if let Some(m) = p.re("_WFX_PS_ASSIGN_RE").match_(seg) {
            // PowerShell: $x = …, $env:X = …
            let var = m.group(1).unwrap_or(&[]).to_vec();
            let mut value = pystr::strip_chars(&seg[m.end()..], " \t");
            if value.len() >= 2 && value[0] == value[value.len() - 1] && any_of(value[0], "'\"") {
                value = &value[1..value.len() - 1];
            }
            let got = content(value, ctx, depth);
            ctx.assign(&var, value, got);
            inp = Content::default();
            continue;
        }
        let (words, redirs) = words(seg);
        let mut stdin = inp.clone();
        for (op, target) in &redirs {
            if pystr::eq(op, "<") {
                stdin.join(&ctx.file(target));
            } else if pystr::eq(op, "<<<") {
                let got = content(target, ctx, depth);
                stdin.join(&got);
            } else if pystr::eq(op, "<<") {
                if let Some(h) = heredocs.as_deref_mut() {
                    if !h.is_empty() {
                        let first = h.remove(0);
                        stdin.join(&first);
                    }
                }
            }
        }
        let cmd = command(p, &words);
        let name = match cmd.name {
            Some(name) => name,
            None => {
                for (var, value) in &cmd.assigns {
                    let got = content(value, ctx, depth);
                    ctx.assign(var, value, got);
                }
                inp = Content::default();
                continue;
            }
        };
        let args = cmd.args;
        let mut own = Content::default();
        for a in &args {
            let got = content(a, ctx, depth);
            own.join(&got);
        }
        if is_dump(&name, &args) {
            own.join(&ctx.everything());
        }
        if let Some(search) = sweep_of(&name, &args, seg, ctx) {
            own.join(&Content { names: BTreeSet::new(), search: Some(search) });
        }
        if is(&name, &["cat", "type", "get-content", "gc", "base64", "xxd", "gzip", "head", "tail"]) {
            for a in &args {
                if !pystr::starts_with(a, "-") {
                    own.join(&ctx.file(a));
                }
            }
        }
        if has(p.strs("_WFX_SENDERS"), &name) {
            send(&name, &cmd.shown, &args, &stdin, cmd.xargs, ctx, depth);
            stdin = Content::default(); // what comes out is the answer
            own = Content::default();
        }
        let mut out = stdin;
        out.join(&own);
        for (op, target) in &redirs {
            if !is(op, &[">", ">>"]) {
                continue;
            }
            if pystr::starts_with(target, "/dev/tcp/") || pystr::starts_with(target, "/dev/udp/") {
                let parts = pystr::split_char(target, c('/'));
                let raw: PyStr = parts.get(3).map(|x| x.to_vec()).unwrap_or_default();
                let host = lower(&raw);
                let secret = !content(&raw, ctx, depth).names.is_empty();
                if secret {
                    // an address the repository keeps secret
                } else if host.contains(&MARK) || host.contains(&c('$')) {
                    let to = ctx.restore(target);
                    report(ctx, &out, &u("a redirection"), &[], Some("socket"), Some(to));
                } else if !(!host.is_empty() && local_host(p, &host)) {
                    let to = ctx.restore(target);
                    report(ctx, &out, &u("a redirection"), &host, Some("socket"), Some(to));
                }
            } else {
                ctx.set_file(target, &out, pystr::eq(op, ">>"));
            }
        }
        if pystr::eq(&name, "tee") {
            let append = args.iter().any(|a| is(a, &["-a", "--append"]));
            for a in &args {
                if !pystr::starts_with(a, "-") {
                    ctx.set_file(a, &out, append);
                }
            }
        }
        inp = out;
    }
    inp
}

/// (scheme, host) of an address as a command is given it: the scheme '' when it has none, the host '' when the
/// address is not known (a variable, an expression).
fn host_of(url: &[u32]) -> (PyStr, PyStr) {
    let mut rest: &[u32] = url;
    let mut scheme: PyStr = Vec::new();
    if let Some(k) = pystr::find_str(rest, "://", 0) {
        if k > 0 && rest[..k].iter().all(|&ch| is_letter(ch)) {
            scheme = lower(&rest[..k]);
            rest = &rest[k + 3..];
        }
    }
    let cut = cut_at(rest, "/?#");
    let mut rest: &[u32] = match cut.iter().rposition(|&x| x == c('@')) {
        Some(k) => &cut[k + 1..],
        None => &cut,
    };
    if rest.first() == Some(&c('[')) {
        if let Some(j) = find(rest, c(']'), 0) {
            if j > 0 {
                rest = &rest[..j + 1];
            }
        }
    } else if let Some(j) = find(rest, c(':'), 0) {
        rest = &rest[..j];
    }
    let mut host = lower(rest);
    if host.is_empty() || host.iter().any(|&ch| ch == MARK || any_of(ch, "$%`")) {
        host = Vec::new();
    }
    (scheme, host)
}

fn ipv4(p: &Pack, host: &[u32]) -> Option<[u64; 4]> {
    let m = p.re("_WFX_IPV4_RE").match_(host)?;
    let mut out = [0u64; 4];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = m.group(k + 1).and_then(pystr::int_of_digits).unwrap_or(0);
    }
    Some(out)
}

/// Is this host the runner itself, its network, or a service container (a name with no dot)?
fn local_host(p: &Pack, host: &[u32]) -> bool {
    if is(host, &["localhost", "ip6-localhost"])
        || pystr::ends_with(host, ".localhost")
        || (pystr::starts_with(host, "[") && is(host, &["[::1]", "[::]"]))
        || pystr::starts_with(host, "[fe80:")
        || pystr::starts_with(host, "[fc")
        || pystr::starts_with(host, "[fd")
    {
        return true;
    }
    if let Some([a, b, _, _]) = ipv4(p, host) {
        return a == 0 || a == 10 || a == 127 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254);
    }
    !host.contains(&c('.')) && !pystr::starts_with(host, "[")
}

fn raw_ip(p: &Pack, host: &[u32]) -> bool {
    match ipv4(p, host) {
        Some(parts) => parts.iter().all(|&g| g <= 255),
        None => pystr::starts_with(host, "["),
    }
}

/// Is `host` the service a secret's name names (TELEGRAM_CHAT_ID and api.telegram.org, DOCKERHUB_TOKEN and
/// hub.docker.com)?
fn for_service(p: &Pack, secret: &[u32], host: &[u32]) -> bool {
    let generic = p.strs("_WFX_GENERIC_WORDS");
    let labels_generic = p.strs("_WFX_GENERIC_LABELS");
    let labels: Vec<&[u32]> = pystr::split_char(host, c('.'))
        .into_iter()
        .filter(|x| x.len() >= 4 && !has(generic, x) && !has(labels_generic, x))
        .collect();
    let low = lower(secret);
    let word_char = |ch: u32| (c('a')..=c('z')).contains(&ch) || is_digit(ch);
    for word in low.split(|&ch| !word_char(ch)) {
        if word.len() >= 4
            && !has(generic, word)
            && (pystr::find(host, word, 0).is_some() || labels.iter().any(|x| pystr::find(word, x, 0).is_some()))
        {
            return true;
        }
    }
    false
}

fn short(text: &[u32], n: usize) -> PyStr {
    if text.len() <= n {
        text.to_vec()
    } else {
        let mut out = text[..n - 1].to_vec();
        out.push(0x2026);
        out
    }
}

/// A send of `sent` (content) to `host` (empty when not known; never the runner's own): a finding when it carries a
/// credential search's output or secrets.
fn report(ctx: &mut Ctx, sent: &Content, how: &[u32], host: &[u32], plain: Option<&str>, to: Option<PyStr>) {
    let raw = !host.is_empty() && raw_ip(ctx.p, host);
    if let Some(search) = &sent.search {
        let d = Value::obj(vec![
            ("job", Value::Str(ctx.job.clone())),
            ("search", Value::Str(short(search, 80))),
            ("how", Value::Str(how.to_vec())),
        ]);
        ctx.found.push(("sweep", ctx.line, d));
        return;
    }
    let names: Vec<&PyStr> = sent
        .names
        .iter()
        .filter(|n| !(!host.is_empty() && plain.is_none() && !raw && for_service(ctx.p, n, host)))
        .collect();
    if names.is_empty() {
        return;
    }
    let to = match to {
        Some(t) if !t.is_empty() => Value::Str(short(&t, 100)),
        _ => Value::Null,
    };
    let d = Value::obj(vec![
        ("job", Value::Str(ctx.job.clone())),
        ("names", Value::Arr(names.into_iter().map(|n| Value::Str(n.clone())).collect())),
        ("how", Value::Str(how.to_vec())),
        ("to", to),
        ("plain", plain.map(Value::str).unwrap_or(Value::Null)),
        ("raw_ip", Value::Bool(raw)),
    ]);
    ctx.found.push(("exfil", ctx.line, d));
}

const KEY_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-";

/// The name of the field whose value starts at `at` (`name=`, `"name": "`, `name: '`), or ''.
fn key_before(text: &[u32], at: usize) -> &[u32] {
    let mut i = at as isize - 1;
    let ch = |i: isize| if i >= 0 { text[i as usize] } else { 0 };
    while i >= 0 && any_of(ch(i), " \t") {
        i -= 1;
    }
    if i >= 0 && any_of(ch(i), "'\"") {
        i -= 1;
    }
    while i >= 0 && any_of(ch(i), " \t") {
        i -= 1;
    }
    if i < 0 || !any_of(ch(i), ":=") {
        return &text[..0];
    }
    i -= 1;
    while i >= 0 && any_of(ch(i), " \t") {
        i -= 1;
    }
    if i >= 0 && any_of(ch(i), "'\"") {
        i -= 1;
    }
    let end = i + 1;
    while i >= 0 && any_of(ch(i), KEY_CHARS) && end - i <= 100 {
        i -= 1;
    }
    &text[(i + 1) as usize..end as usize]
}

/// content(text), but a value given to a field that holds a credential (`client_secret=…`, `"password": "…"`) is not
/// counted: a body sent over https to a named host that is the service's login.
fn keyed_content(text: &[u32], ctx: &mut Ctx, depth: usize) -> Content {
    let p = ctx.p;
    let cred = p.re("_WFX_CRED_KEY_RE");
    let mut kept: PyStr = Vec::new();
    let mut i = 0;
    for m in p.re("_WFX_REF_RE").finditer(text) {
        if cred.search(key_before(text, m.start())).is_some() {
            kept.extend_from_slice(&text[i..m.start()]);
            i = m.end();
        }
    }
    kept.extend_from_slice(&text[i..]);
    content(&kept, ctx, depth)
}

/// What an address's query sends that is not a credential of the service (`?token=` is).
fn query_content(url: &[u32], ctx: &mut Ctx, depth: usize) -> Content {
    let p = ctx.p;
    let mut out = Content::default();
    let k = match find(url, c('?'), 0) {
        Some(k) => k,
        None => return out,
    };
    let query = partition(&url[k + 1..], c('#')).0.to_vec();
    let cred = p.re("_WFX_CRED_NAME_RE");
    for pair in pystr::split_char(&query, c('&')) {
        let (key, eq, value) = partition(pair, c('='));
        if cred.search(key).is_none() {
            let got = content(if eq { value } else { key }, ctx, depth);
            out.join(&got);
        }
    }
    out
}

/// What a header sends that is not a credential (an Authorization or token header is).
fn header_content(value: &[u32], ctx: &mut Ctx, depth: usize) -> Content {
    let p = ctx.p;
    let key = partition(value, c(':')).0;
    if p.re("_WFX_CRED_NAME_RE").search(key).is_some() {
        return Content::default();
    }
    content(value, ctx, depth)
}

/// [(option, value)] of a command's arguments, curl's and wget's way: (None, word) for a positional word; a short
/// option's value attached or the next word; `--name=value` or `--name value`.
fn options(args: &[PyStr], short_value: &[u32], long_value: &[PyStr]) -> Vec<(Option<PyStr>, Option<PyStr>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if pystr::starts_with(a, "--") && a.len() > 2 {
            let (name, eq, value) = partition(&a[2..], c('='));
            if eq {
                out.push((Some(name.to_vec()), Some(value.to_vec())));
            } else if has(long_value, name) && i < args.len() {
                out.push((Some(name.to_vec()), Some(args[i].clone())));
                i += 1;
            } else {
                out.push((Some(name.to_vec()), None));
            }
        } else if pystr::starts_with(a, "-") && a.len() > 1 {
            for k in 1..a.len() {
                if short_value.contains(&a[k]) {
                    if k + 1 < a.len() {
                        out.push((Some(vec![a[k]]), Some(a[k + 1..].to_vec())));
                    } else if i < args.len() {
                        out.push((Some(vec![a[k]]), Some(args[i].clone())));
                        i += 1;
                    }
                    break;
                }
                out.push((Some(vec![a[k]]), None));
            }
        } else {
            out.push((None, Some(a.clone())));
        }
    }
    out
}

/// How many brackets a word of PowerShell opens and does not close (`@{`, `(`, `{`).
fn ps_depth(word: &[u32]) -> isize {
    let n = |ch: char| word.iter().filter(|&&x| x == c(ch)).count() as isize;
    n('{') + n('(') - n('}') - n(')')
}

/// What a send carries, gathered before its address is known.
enum Item {
    Stdin,
    File(PyStr),
    Query(PyStr),
    Header(PyStr),
    Body(PyStr),
}

fn file_or_stdin(path: &[u32], stdin_names: &[&str]) -> Item {
    if is(path, stdin_names) {
        Item::Stdin
    } else {
        Item::File(path.to_vec())
    }
}

/// Put `value` at the address (dest) when it is the first one, or the first with a scheme; else it is a query.
fn place_dest(dest: &mut Option<PyStr>, items: &mut Vec<Item>, value: PyStr) {
    let better = match dest {
        None => true,
        Some(d) => pystr::contains(&value, "://") && !pystr::contains(d, "://"),
    };
    if better {
        if let Some(d) = dest.take() {
            items.push(Item::Query(d));
        }
        *dest = Some(value);
    } else {
        items.push(Item::Query(value));
    }
}

/// A command that sends data out: what it sends, to where, reported (`how`: its name as written). What it sends is
/// gathered first; then read once the address is known (a body's credentials are not counted when it goes over
/// https to a named host).
fn send(name: &[u32], how: &[u32], args: &[PyStr], stdin: &Content, xargs: bool, ctx: &mut Ctx, depth: usize) {
    let p = ctx.p;
    let mut items: Vec<Item> = Vec::new();
    if xargs {
        items.push(Item::Stdin);
    }
    let mut dest: Option<PyStr> = None;
    let mut plain: Option<&str> = None;
    let mut shown_as: Option<PyStr> = None;
    let web = is(name, &["curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"]);
    let socket = is(name, &["nc", "ncat", "netcat", "socat"]);
    if pystr::eq(name, "curl") {
        let header = p.strs("_WFX_CURL_HEADER");
        let body = p.strs("_WFX_CURL_BODY");
        for (opt, value) in options(args, &p.text("_WFX_CURL_SHORT_VALUE"), p.strs("_WFX_CURL_LONG_VALUE")) {
            let value = match value {
                Some(v) => v,
                None => continue,
            };
            let opt_is = |names: &[&str]| opt.as_deref().is_some_and(|o| is(o, names));
            if opt.is_none() || opt_is(&["url"]) {
                place_dest(&mut dest, &mut items, value);
            } else if opt.as_deref().is_some_and(|o| has(header, o)) {
                items.push(Item::Header(value));
            } else if opt_is(&["url-query"]) {
                items.push(Item::Query(pystr::concat(&[&u("?"), &value])));
            } else if opt_is(&["F", "form", "form-string"]) {
                let after = match find(&value, c('='), 0) {
                    Some(k) => &value[k + 1..],
                    None => &value[..],
                };
                let v = partition(after, c(';')).0;
                if (pystr::starts_with(v, "@") || pystr::starts_with(v, "<")) && !opt_is(&["form-string"]) {
                    items.push(file_or_stdin(&v[1..], &["-"]));
                } else {
                    items.push(Item::Body(value));
                }
            } else if opt_is(&["T", "upload-file"]) {
                items.push(file_or_stdin(&value, &["-", "."]));
            } else if opt.as_deref().is_some_and(|o| has(body, o)) {
                if pystr::starts_with(&value, "@") && !opt_is(&["data-raw"]) {
                    items.push(file_or_stdin(&value[1..], &["-"]));
                } else if opt_is(&["data-urlencode"])
                    && value.contains(&c('@'))
                    && !partition(&value, c('@')).0.contains(&c('='))
                {
                    items.push(file_or_stdin(partition(&value, c('@')).2, &["-"]));
                } else {
                    items.push(Item::Body(value));
                }
            }
        }
    } else if pystr::eq(name, "wget") {
        for (opt, value) in options(args, &p.text("_WFX_WGET_SHORT_VALUE"), p.strs("_WFX_WGET_LONG_VALUE")) {
            let value = match value {
                Some(v) => v,
                None => continue,
            };
            let opt_is = |names: &[&str]| opt.as_deref().is_some_and(|o| is(o, names));
            if opt.is_none() {
                place_dest(&mut dest, &mut items, value);
            } else if opt_is(&["header"]) {
                items.push(Item::Header(value));
            } else if opt_is(&["post-file", "body-file"]) {
                items.push(file_or_stdin(&value, &["-", "/dev/stdin"]));
            } else if opt_is(&["post-data", "body-data"]) {
                items.push(Item::Body(value));
            }
        }
    } else if is(name, &["invoke-webrequest", "iwr", "invoke-restmethod", "irm"]) {
        let switches = p.strs("_WFX_PS_SWITCHES");
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            if pystr::starts_with(a, "-") && a.len() > 1 && is_letter(a[1]) {
                let (param, colon, after) = partition(&a[1..], c(':'));
                let param = lower(param);
                if has(switches, &param) {
                    continue;
                }
                let mut value = after.to_vec();
                if !colon {
                    if i >= args.len() {
                        break;
                    }
                    value = args[i].clone();
                    i += 1;
                    // a hashtable or an expression in brackets is one value, whatever its spaces: @{ k = 'v' }
                    let mut open = ps_depth(&value);
                    while open > 0 && i < args.len() {
                        value.push(c(' '));
                        value.extend_from_slice(&args[i]);
                        open += ps_depth(&args[i]);
                        i += 1;
                    }
                }
                if is(&param, &["uri", "url"]) {
                    if dest.is_none() {
                        dest = Some(value);
                    }
                } else if is(&param, &["body", "form"]) {
                    items.push(Item::Body(value));
                } else if pystr::eq(&param, "infile") {
                    items.push(Item::File(value));
                }
            } else if dest.as_ref().map_or(true, |d| pystr::contains(a, "://") && !pystr::contains(d, "://")) {
                dest = Some(a.clone());
            }
        }
    } else if is(name, &["nc", "ncat", "netcat"]) {
        let nc_value = p.strs("_WFX_NC_VALUE");
        let listens = args.iter().any(|a| {
            is(a, &["-l", "--listen"])
                || (pystr::starts_with(a, "-") && !pystr::starts_with(a, "--") && a[1..].contains(&c('l')) && !has(nc_value, a))
        });
        if listens {
            return;
        }
        plain = if args.iter().any(|a| pystr::eq(a, "--ssl")) { None } else { Some("socket") };
        items.push(Item::Stdin);
        let mut pos: Vec<&[u32]> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            if has(nc_value, a) {
                i += 1;
            } else if !pystr::starts_with(a, "-") {
                pos.push(a);
            }
        }
        if pos.is_empty() {
            return;
        }
        let two: Vec<&[u32]> = pos.into_iter().take(2).collect();
        dest = Some(pystr::join(&u(":"), &two));
    } else if pystr::eq(name, "socat") {
        let addr = p.re("_WFX_SOCAT_ADDR_RE");
        let mut target: Option<(PyStr, PyStr, PyStr)> = None;
        for a in args {
            if pystr::starts_with(a, "-") && !pystr::eq(a, "-") {
                continue;
            }
            let la = lower(a);
            if pystr::eq(a, "-") || pystr::starts_with(&la, "stdin") || pystr::starts_with(&la, "stdio") {
                items.push(Item::Stdin);
            }
            if target.is_none() {
                if let Some(m) = addr.match_(a) {
                    target = Some((m.group(1).unwrap_or(&[]).to_vec(), m.group(2).unwrap_or(&[]).to_vec(), a.clone()));
                }
            }
        }
        let (kind, host, whole) = match target {
            Some(t) => t,
            None => return,
        };
        dest = Some(host);
        shown_as = Some(whole);
        let lk = lower(&kind);
        plain = if pystr::starts_with(&lk, "openssl") || pystr::starts_with(&lk, "ssl") { None } else { Some("socket") };
    }
    let (scheme, host) = match &dest {
        None => (Vec::new(), Vec::new()),
        Some(d) => {
            let (scheme, host, secret) = dest_of(d, ctx, depth);
            if secret {
                return; // an address the repository keeps secret: its own service
            }
            if web {
                items.push(Item::Query(d.clone()));
            }
            (scheme, host)
        }
    };
    if !host.is_empty() && local_host(p, &host) {
        return;
    }
    if plain.is_none() && !socket {
        plain = if (scheme.is_empty() || pystr::eq(&scheme, "http")) && !host.is_empty() { Some("http") } else { None };
    }
    let named_tls = !host.is_empty() && plain.is_none() && !raw_ip(p, &host);
    let mut sent = Content::default();
    if let Some(d) = &dest {
        let path = content(&path_of(d), ctx, depth);
        if named_tls && !path.names.is_empty() {
            return; // a resource the repository keeps secret (a bot's token, a repository)
        }
        sent = path;
    }
    for item in &items {
        let got = match item {
            Item::Stdin => stdin.clone(),
            Item::File(f) => ctx.file(f),
            Item::Query(q) => query_content(q, ctx, depth),
            Item::Header(h) => header_content(h, ctx, depth),
            Item::Body(b) => {
                if named_tls {
                    keyed_content(b, ctx, depth)
                } else {
                    content(b, ctx, depth)
                }
            }
        };
        sent.join(&got);
    }
    let shown_as = shown_as.or(dest);
    let to = shown_as.map(|s| ctx.restore(&s));
    report(ctx, &sent, how, &host, plain, to);
}

/// The path of an address: what follows its host, up to its query.
fn path_of(word: &[u32]) -> PyStr {
    let rest = after_scheme(word);
    match find(rest, c('/'), 0) {
        Some(j) => cut_at(&rest[j..], "?#"),
        None => Vec::new(),
    }
}

fn after_scheme(word: &[u32]) -> &[u32] {
    match pystr::find_str(word, "://", 0) {
        Some(k) if k > 0 && word[..k].iter().all(|&ch| is_letter(ch)) => &word[k + 3..],
        _ => word,
    }
}

/// (scheme, host, secret) of the address a command is given: its variables put in where the script or the
/// environment gives them a plain value; `secret` when the host comes from a secret (a webhook the repository keeps
/// secret).
fn dest_of(word: &[u32], ctx: &mut Ctx, depth: usize) -> (PyStr, PyStr, bool) {
    let p = ctx.p;
    let authority = cut_at(after_scheme(word), "/?#");
    if !content(&authority, ctx, depth).names.is_empty() {
        return (Vec::new(), Vec::new(), true);
    }
    let ctx: &Ctx = ctx;
    let filled = p.re("_WFX_VAR_RE").sub_fn(word, 0, |m| ctx.value(first_group(m), m.group0()));
    let (scheme, host) = host_of(&filled);
    (scheme, host, false)
}

/// The secrets an `env:` value names (its expressions' `secrets.X`, and `env.Y` of an environment above).
fn secrets_in(p: &Pack, text: &[u32], env: &BTreeMap<PyStr, BTreeSet<PyStr>>) -> BTreeSet<PyStr> {
    let mut names = BTreeSet::new();
    for e in outline::expressions(text) {
        names.extend(secret_names(p, e));
        for m in p.re("_WFX_ENV_NAME_RE").finditer(e) {
            if let Some(set) = env.get(first_group(&m)) {
                names.extend(set.iter().cloned());
            }
        }
    }
    names
}

type Env = BTreeMap<PyStr, BTreeSet<PyStr>>;
type Values = BTreeMap<PyStr, Option<PyStr>>;

/// An `env:` entry: the secrets it holds into `env`, its plain value into `values` (None when it has an expression),
/// so that an entry below one of the same name replaces it.
fn env_entry(p: &Pack, r: &Rec, env: &mut Env, values: &mut Values, above: Option<&Env>) {
    let value = r.text();
    let key = r.key.clone().unwrap_or_default();
    let names = secrets_in(p, &value, above.unwrap_or(env));
    env.insert(key.clone(), names);
    values.insert(key, if pystr::contains(&value, "${{") { None } else { Some(value) });
}

/// text with each `${{ … }}` replaced by a mark that holds its index in exprs (the expressions are pasted in before
/// the shell reads the script, so they are words of their own whatever their spaces).
fn marked(text: &[u32], exprs: &mut Vec<PyStr>) -> PyStr {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    for (start, end) in outline::expression_spans(text) {
        out.extend_from_slice(&text[i..start]);
        out.push(MARK);
        out.extend(u(&exprs.len().to_string()));
        out.push(MARK);
        exprs.push(text[start + 3..end - 2].to_vec());
        i = end;
    }
    out.extend_from_slice(&text[i..]);
    out
}

/// The secrets a workflow sends out by name, and what a search of the repository or its history for credentials
/// found and sent, in the order of its steps: 'exfil' {job, names (sorted), how (the command), to (the address as
/// written, or null), plain ('http' for an address without TLS, 'socket' for a raw socket, or null), raw_ip};
/// 'sweep' {job, search (the command that searches for credentials), how}.
pub fn exfil(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = outline::outline(text, true, false);
    let mut workflow_env: Env = BTreeMap::new();
    let mut workflow_values: Values = BTreeMap::new();
    let mut job_env: BTreeMap<PyStr, (Env, Values)> = BTreeMap::new();
    for r in &records {
        if r.key.is_none() || !r.path_ends("env") {
            continue;
        }
        if r.path_is(&["env"]) {
            env_entry(p, r, &mut workflow_env, &mut workflow_values, Some(&BTreeMap::new()));
        } else if r.path.len() == 3 && pystr::eq(&r.path[0], "jobs") {
            let slot = job_env.entry(r.path[1].clone()).or_default();
            env_entry(p, r, &mut slot.0, &mut slot.1, Some(&workflow_env));
        }
    }
    let line_max = p.usize("_WFX_LINE_MAX");
    let depth_max = p.usize("_WFX_DEPTH");
    let mut found: Vec<Found> = Vec::new();
    let mut files_of: BTreeMap<PyStr, BTreeMap<PyStr, Content>> = BTreeMap::new();
    for (job, recs) in workflow::steps(&records) {
        let mut env = workflow_env.clone();
        let mut values = workflow_values.clone();
        if let Some((e, v)) = job_env.get(&job) {
            env.extend(e.iter().map(|(k, x)| (k.clone(), x.clone())));
            values.extend(v.iter().map(|(k, x)| (k.clone(), x.clone())));
        }
        for r in &recs {
            if r.key.is_some() && r.path.len() == 5 && pystr::eq(&r.path[4], "env") {
                env_entry(p, r, &mut env, &mut values, None);
            }
        }
        let lines = workflow::logical_lines(&workflow::step_run_lines(&recs));
        if lines.is_empty() {
            continue;
        }
        let files = files_of.remove(&job).unwrap_or_default();
        let mut ctx = Ctx {
            p,
            exprs: Vec::new(),
            env,
            values,
            local: Vec::new(),
            local_at: BTreeMap::new(),
            files,
            job: job.clone(),
            line: 0,
            found: std::mem::take(&mut found),
            depth_max,
        };
        let heredoc = p.re("_WFX_HEREDOC_RE");
        let mut k = 0;
        while k < lines.len() {
            let (line, t) = &lines[k];
            k += 1;
            if t.len() > line_max {
                continue;
            }
            ctx.line = *line;
            let mark = marked(t, &mut ctx.exprs);
            let mut heredocs: Vec<Content> = Vec::new();
            for m in heredoc.finditer(&mark) {
                let delimiter = first_group(&m);
                let mut body: Vec<PyStr> = Vec::new();
                while k < lines.len() && pystr::strip_chars(&lines[k].1, " \t") != delimiter {
                    body.push(marked(&lines[k].1, &mut ctx.exprs));
                    k += 1;
                }
                k += 1;
                let mut got = Content::default();
                for b in &body {
                    let c = content(b, &mut ctx, 0);
                    got.join(&c);
                }
                heredocs.push(got);
            }
            eval(&mark, &mut ctx, 0, Some(&mut heredocs));
        }
        found = std::mem::take(&mut ctx.found);
        files_of.insert(job, ctx.files);
    }
    found
}

// ---------------------------------------------------------------- the rule

/// `the secret A`, `the secrets A and B`, `the secrets A, B and C` (five at most, then how many more).
fn names_text(names: &[PyStr]) -> PyStr {
    if names.len() == 1 {
        return pystr::concat(&[&u("the secret "), &names[0]]);
    }
    let shown: Vec<&[u32]> = names.iter().take(5).map(|x| x.as_slice()).collect();
    let more = names.len() - shown.len();
    if more > 0 {
        return pystr::concat(&[&u("the secrets "), &pystr::join(&u(", "), &shown), &u(&format!(" and {} more", more))]);
    }
    match shown.split_last() {
        Some((last, rest)) => pystr::concat(&[&u("the secrets "), &pystr::join(&u(", "), rest), &u(" and "), last]),
        None => u("the secrets "),
    }
}

/// The SC-WORKFLOW-EXFIL rule of one of exfil()'s findings.
pub fn rule(p: &Pack, kind: &str, d: &Value) -> Option<RuleText> {
    let st = |k: &str| d.get(k).and_then(|v| v.as_str()).map(|x| x.to_vec()).unwrap_or_default();
    let fill = |name: &str, args: &[(&str, Arg)]| {
        let mut rule = RuleText::of(p, name);
        rule.msg = findings::format(&rule.msg, args);
        rule
    };
    match kind {
        "sweep" => Some(fill("_WFX_SWEEP_RULE", &[("job", Arg::S(st("job"))), ("search", Arg::S(st("search"))), ("how", Arg::S(st("how")))])),
        "exfil" => {
            let names: Vec<PyStr> = d
                .get("names")
                .and_then(|v| v.as_arr())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|y| y.to_vec())).collect())
                .unwrap_or_default();
            let to = st("to");
            let where_ = if to.is_empty() { u("to an address the step builds") } else { pystr::concat(&[&u("to "), &to]) };
            let mut why: Vec<PyStr> = Vec::new();
            match d.get("plain").and_then(|v| v.as_str()) {
                Some(x) if pystr::eq(x, "http") => why.push(u("over plain HTTP")),
                Some(x) if pystr::eq(x, "socket") => why.push(u("over a raw socket")),
                _ => {}
            }
            if matches!(d.get("raw_ip"), Some(Value::Bool(true))) {
                why.push(u("to a raw IP address"));
            }
            if !to.is_empty() {
                if let Some(m) = crate::signs::capture_service(p, &to) {
                    why.push(pystr::concat(&[&u("to "), m.group0(), &u(", a data-capture service")]));
                }
            }
            if names.len() >= 2 {
                why.push(u(&format!("{} secrets in one request", names.len())));
            }
            let args = |extra: Vec<(&'static str, Arg)>| {
                let mut a = vec![
                    ("job", Arg::S(st("job"))),
                    ("names", Arg::S(names_text(&names))),
                    ("how", Arg::S(st("how"))),
                    ("where", Arg::S(where_.clone())),
                ];
                a.extend(extra);
                a
            };
            Some(if why.is_empty() {
                fill("_WFX_SENT_CHECK_RULE", &args(Vec::new()))
            } else {
                let refs: Vec<&[u32]> = why.iter().map(|x| x.as_slice()).collect();
                fill("_WFX_SENT_RULE", &args(vec![("why", Arg::S(pystr::join(&u(", "), &refs)))]))
            })
        }
        _ => None,
    }
}
