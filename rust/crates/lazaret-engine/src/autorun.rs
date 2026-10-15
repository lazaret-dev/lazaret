//! Editor and AI-agent settings that run commands on their own (0.1.7; scanner/autorun.py and core.autorun_issues,
//! with their npm twins, until BR-7's step 2 moved them here, 0.1.9).
//!
//! Opening a folder in VS Code runs its folder-open tasks; Claude Code, Cursor and Gemini CLI run a project's hooks as
//! a session starts and around the agent's tool calls; an agent starts the MCP servers a project lists. None of it
//! asks each time. Mini Shai-Hulud and the keyv wave (May and August 2026) committed a SessionStart hook and a
//! folder-open task to every repository they reached, each running a copy of the worm's loader, so opening a checkout
//! ran the worm (SC-AUTORUN).
//!
//! Which files these are (`config_kind`), a JSON-with-comments reader that keeps each value's line (`parse_jsonc`:
//! VS Code's files allow comments and trailing commas), the commands each file makes its tool run (`entries`), and
//! the issues of a settings file (`issues`): each command judged by the install-script test, and followed into the
//! files of the tree it runs. The engine reads no file: `issues` answers the files it needs (`Need`) until the
//! package has given it each one's text (or none).

use crate::findings::{self, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::BTreeMap;

const fn c(ch: char) -> u32 {
    ch as u32
}

/// Nesting deeper than this is not read (an error).
pub const MAX_DEPTH: usize = 256;
/// Tasks a folder-open task's dependsOn chain is followed to, per file
pub const MAX_TASKS: usize = 100;

/// (the file's last two path components, lowercased) -> (kind, tool)
const KINDS: &[(&str, &str, &str)] = &[
    (".vscode/tasks.json", "vscode-tasks", "VS Code"),
    (".vscode/mcp.json", "vscode-mcp", "VS Code"),
    (".claude/settings.json", "claude", "Claude Code"),
    (".claude/settings.local.json", "claude", "Claude Code"),
    (".cursor/hooks.json", "cursor-hooks", "Cursor"),
    (".cursor/mcp.json", "mcp", "Cursor"),
    (".gemini/settings.json", "gemini", "Gemini CLI"),
];
/// Words that show a file, even one that cannot be read, asks its tool to run something
fn markers(kind: &str) -> &'static [&'static str] {
    match kind {
        "vscode-tasks" => &["folderOpen"],
        "claude" => &[
            "\"hooks\"",
            "\"statusLine\"",
            "\"apiKeyHelper\"",
            "\"awsAuthRefresh\"",
            "\"awsCredentialExport\"",
            "\"otelHeadersHelper\"",
        ],
        "gemini" => &["\"hooks\"", "\"command\""],
        _ => &["\"command\""],
    }
}
/// Claude Code settings whose value is a command it runs
const CLAUDE_HELPERS: &[&str] = &["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"];
const PLATFORMS: &[(&str, &str)] = &[("windows", "on Windows"), ("linux", "on Linux"), ("osx", "on macOS")];

fn parts(path: &[u32]) -> Vec<PyStr> {
    pystr::split_char(&pystr::replace_char(path, c('\\'), c('/')), c('/')).into_iter().map(|x| x.to_vec()).collect()
}

/// (kind, tool) for a settings file that makes a tool run commands, by its path ('/' or '\\' separators).
pub fn config_kind(path: &[u32]) -> Option<(&'static str, &'static str)> {
    let parts = parts(path);
    let last = parts.last().cloned().unwrap_or_default();
    if pystr::eq(&pystr::lower(&last), ".mcp.json") {
        return Some(("mcp", "Claude Code"));
    }
    if parts.len() < 2 {
        return None;
    }
    let key = pystr::lower(&pystr::concat(&[&parts[parts.len() - 2], &u("/"), &last]));
    KINDS.iter().find(|(k, _, _)| pystr::eq(&key, k)).map(|(_, kind, tool)| (*kind, *tool))
}

/// The folder a settings file belongs to ('/'-separated, '' for the root): the parent of its .vscode / .claude /
/// .cursor / .gemini directory, or the directory of a .mcp.json. Its commands run there.
pub fn owner_dir(path: &[u32]) -> PyStr {
    let parts = parts(path);
    let n = parts.len();
    let keep = if pystr::eq(&pystr::lower(&parts[n - 1]), ".mcp.json") { n - 1 } else { n.saturating_sub(2) };
    let refs: Vec<&[u32]> = parts[..keep].iter().map(|x| x.as_slice()).collect();
    pystr::join(&u("/"), &refs)
}

// ---------------------------------------------------------------- a JSON reader that keeps lines

/// A JSON value and the 1-based line it starts on. An object keeps its members in first-seen order, the last of a
/// repeated key winning.
#[derive(Clone, Debug)]
pub struct JNode {
    pub line: usize,
    pub kind: JKind,
}

#[derive(Clone, Debug)]
pub enum JKind {
    Object(Vec<(PyStr, JNode)>),
    Array(Vec<JNode>),
    Str(PyStr),
    /// its text
    Num(PyStr),
    True,
    False,
    Null,
}

impl JNode {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            JKind::Object(_) => "object",
            JKind::Array(_) => "array",
            JKind::Str(_) => "string",
            JKind::Num(_) => "number",
            JKind::True => "true",
            JKind::False => "false",
            JKind::Null => "null",
        }
    }

    /// As the `autorun_jsonc` call answers it: {k, l, v} (an object's v: [[key, value], …]).
    pub fn to_value(&self) -> Value {
        let v = match &self.kind {
            JKind::Object(members) => Value::Arr(
                members.iter().map(|(k, x)| Value::Arr(vec![Value::Str(k.clone()), x.to_value()])).collect(),
            ),
            JKind::Array(items) => Value::Arr(items.iter().map(|x| x.to_value()).collect()),
            JKind::Str(s) | JKind::Num(s) => Value::Str(s.clone()),
            _ => Value::Null,
        };
        Value::obj(vec![("k", Value::str(self.kind_name())), ("l", Value::Int(self.line as i64)), ("v", v)])
    }
}

/// Where a file cannot be read as JSON: (line, reason).
pub type JsonError = (usize, PyStr);

struct Reader<'a> {
    s: &'a [u32],
    i: usize,
    line: usize,
}

fn is_hex4(s: &[u32], at: usize) -> bool {
    at + 4 <= s.len() && s[at..at + 4].iter().all(|&ch| (ch as u8 as u32 == ch) && (ch as u8).is_ascii_hexdigit())
}

fn hex4(s: &[u32], at: usize) -> u32 {
    s[at..at + 4].iter().fold(0, |acc, &ch| acc * 16 + (ch as u8 as char).to_digit(16).unwrap_or(0))
}

fn digit(ch: u32) -> bool {
    (c('0')..=c('9')).contains(&ch)
}

impl<'a> Reader<'a> {
    fn fail<T>(&self, reason: &str) -> Result<T, JsonError> {
        Err((self.line, u(reason)))
    }

    fn at(&self, lit: &str) -> bool {
        pystr::starts_with_at(self.s, self.i, lit)
    }

    fn blank(&mut self) -> Result<(), JsonError> {
        let n = self.s.len();
        while self.i < n {
            let ch = self.s[self.i];
            if ch == c(' ') || ch == c('\t') || ch == c('\n') || ch == c('\r') {
                if ch == c('\n') {
                    self.line += 1;
                }
                self.i += 1;
            } else if self.at("//") {
                self.i = pystr::find_char(self.s, c('\n'), self.i).unwrap_or(n);
            } else if self.at("/*") {
                let end = match pystr::find(self.s, &u("*/"), self.i + 2) {
                    Some(e) => e,
                    None => return self.fail("unterminated comment"),
                };
                self.line += pystr::count_char(self.s, c('\n'), self.i, end);
                self.i = end + 2;
            } else {
                return Ok(());
            }
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<JNode, JsonError> {
        self.blank()?;
        if self.i >= self.s.len() {
            return self.fail("unexpected end of input");
        }
        if depth > MAX_DEPTH {
            return self.fail("nesting too deep");
        }
        let (ch, line) = (self.s[self.i], self.line);
        if ch == c('{') {
            return self.obj(depth, line);
        }
        if ch == c('[') {
            return self.arr(depth, line);
        }
        if ch == c('"') {
            return Ok(JNode { line, kind: JKind::Str(self.string()?) });
        }
        for (word, kind) in [("true", JKind::True), ("false", JKind::False), ("null", JKind::Null)] {
            if self.at(word) {
                self.i += word.len();
                return Ok(JNode { line, kind });
            }
        }
        if let Some(end) = self.number() {
            let text = self.s[self.i..end].to_vec();
            self.i = end;
            return Ok(JNode { line, kind: JKind::Num(text) });
        }
        let reason = format!("unexpected character U+{:04X}", ch);
        self.fail(&reason)
    }

    /// The end of a JSON number at i (`-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`), or None.
    fn number(&self) -> Option<usize> {
        let (s, n) = (self.s, self.s.len());
        let mut j = self.i;
        if j < n && s[j] == c('-') {
            j += 1;
        }
        if j < n && s[j] == c('0') {
            j += 1;
        } else if j < n && (c('1')..=c('9')).contains(&s[j]) {
            j += 1;
            while j < n && digit(s[j]) {
                j += 1;
            }
        } else {
            return None;
        }
        if j + 1 < n && s[j] == c('.') && digit(s[j + 1]) {
            j += 2;
            while j < n && digit(s[j]) {
                j += 1;
            }
        }
        if j < n && (s[j] == c('e') || s[j] == c('E')) {
            let mut k = j + 1;
            if k < n && (s[k] == c('+') || s[k] == c('-')) {
                k += 1;
            }
            if k < n && digit(s[k]) {
                k += 1;
                while k < n && digit(s[k]) {
                    k += 1;
                }
                j = k;
            }
        }
        Some(j)
    }

    fn obj(&mut self, depth: usize, line: usize) -> Result<JNode, JsonError> {
        self.i += 1;
        let mut members: Vec<(PyStr, JNode)> = Vec::new();
        let mut index: BTreeMap<PyStr, usize> = BTreeMap::new();
        let done = |members: Vec<(PyStr, JNode)>| Ok(JNode { line, kind: JKind::Object(members) });
        self.blank()?;
        if self.i < self.s.len() && self.s[self.i] == c('}') {
            self.i += 1;
            return done(members);
        }
        loop {
            self.blank()?;
            if self.i >= self.s.len() {
                return self.fail("unexpected end of input");
            }
            if self.s[self.i] != c('"') {
                return self.fail("a key must be a string");
            }
            let key = self.string()?;
            self.blank()?;
            if self.i >= self.s.len() || self.s[self.i] != c(':') {
                return self.fail("expected ':' after a key");
            }
            self.i += 1;
            let v = self.value(depth + 1)?;
            match index.get(&key) {
                Some(&k) => members[k].1 = v,
                None => {
                    index.insert(key.clone(), members.len());
                    members.push((key, v));
                }
            }
            self.blank()?;
            if self.i >= self.s.len() {
                return self.fail("unexpected end of input");
            }
            let ch = self.s[self.i];
            self.i += 1;
            if ch == c('}') {
                return done(members);
            }
            if ch != c(',') {
                return self.fail("expected ',' or '}'");
            }
            self.blank()?;
            if self.i < self.s.len() && self.s[self.i] == c('}') {
                self.i += 1;
                return done(members);
            }
        }
    }

    fn arr(&mut self, depth: usize, line: usize) -> Result<JNode, JsonError> {
        self.i += 1;
        let mut items: Vec<JNode> = Vec::new();
        self.blank()?;
        if self.i < self.s.len() && self.s[self.i] == c(']') {
            self.i += 1;
            return Ok(JNode { line, kind: JKind::Array(items) });
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.blank()?;
            if self.i >= self.s.len() {
                return self.fail("unexpected end of input");
            }
            let ch = self.s[self.i];
            self.i += 1;
            if ch == c(']') {
                return Ok(JNode { line, kind: JKind::Array(items) });
            }
            if ch != c(',') {
                return self.fail("expected ',' or ']'");
            }
            self.blank()?;
            if self.i < self.s.len() && self.s[self.i] == c(']') {
                self.i += 1;
                return Ok(JNode { line, kind: JKind::Array(items) });
            }
        }
    }

    fn string(&mut self) -> Result<PyStr, JsonError> {
        let (s, n) = (self.s, self.s.len());
        self.i += 1;
        let mut out: PyStr = Vec::new();
        let mut start = self.i;
        loop {
            if self.i >= n {
                return self.fail("unterminated string");
            }
            let ch = s[self.i];
            if ch == c('"') {
                out.extend_from_slice(&s[start..self.i]);
                self.i += 1;
                return Ok(out);
            }
            if ch == c('\n') || ch == c('\r') {
                return self.fail("unterminated string");
            }
            if ch != c('\\') {
                self.i += 1;
                continue;
            }
            out.extend_from_slice(&s[start..self.i]);
            let e = s.get(self.i + 1).copied();
            let simple = match e.and_then(char::from_u32) {
                Some('"') => Some(c('"')),
                Some('\\') => Some(c('\\')),
                Some('/') => Some(c('/')),
                Some('b') => Some(8),
                Some('f') => Some(12),
                Some('n') => Some(10),
                Some('r') => Some(13),
                Some('t') => Some(9),
                _ => None,
            };
            if let Some(x) = simple {
                out.push(x);
                self.i += 2;
            } else if e == Some(c('u')) && is_hex4(s, self.i + 2) {
                let mut code = hex4(s, self.i + 2);
                self.i += 6;
                if (0xD800..0xDC00).contains(&code) && pystr::starts_with_at(s, self.i, "\\u") && is_hex4(s, self.i + 2) {
                    let low = hex4(s, self.i + 2);
                    if (0xDC00..0xE000).contains(&low) {
                        // a surrogate pair is one character
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                        self.i += 6;
                    }
                }
                out.push(code);
            } else {
                return self.fail("invalid escape in a string");
            }
            start = self.i;
        }
    }
}

/// The JSON value of `text` (a leading BOM, // and /* */ comments and trailing commas allowed; lines counted at
/// "\n").
pub fn parse_jsonc(text: &[u32]) -> Result<JNode, JsonError> {
    let s = if text.first() == Some(&0xFEFF) { &text[1..] } else { text };
    let mut r = Reader { s, i: 0, line: 1 };
    let v = r.value(0)?;
    r.blank()?;
    if r.i < s.len() {
        return r.fail("unexpected content after the value");
    }
    Ok(v)
}

// ---------------------------------------------------------------- the commands each file makes its tool run

/// One command a settings file makes its tool run: the line it is on, what runs it, and the command (None when the
/// entry names none, as a typescript task does).
#[derive(Clone, Debug)]
pub struct Entry {
    pub line: usize,
    pub trigger: PyStr,
    pub command: Option<PyStr>,
}

impl Entry {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("line", Value::Int(self.line as i64)),
            ("trigger", Value::Str(self.trigger.clone())),
            ("command", self.command.clone().map(Value::Str).unwrap_or(Value::Null)),
        ])
    }
}

/// Member `key` of object `v` (of `kind` when given).
fn get<'a>(v: Option<&'a JNode>, key: &str, kind: Option<&str>) -> Option<&'a JNode> {
    match v.map(|x| &x.kind) {
        Some(JKind::Object(members)) => {
            let m = members.iter().find(|(k, _)| pystr::eq(k, key)).map(|(_, x)| x)?;
            if kind.map_or(true, |k| m.kind_name() == k) {
                Some(m)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn str_of(v: Option<&JNode>) -> Option<&PyStr> {
    match v.map(|x| &x.kind) {
        Some(JKind::Str(s)) => Some(s),
        _ => None,
    }
}

/// A string value's text when it is not blank.
fn text_of(v: Option<&JNode>) -> Option<PyStr> {
    str_of(v).filter(|s| !pystr::strip(s).is_empty()).cloned()
}

fn needs_quotes(arg: &[u32]) -> bool {
    arg.iter().any(|&ch| pystr::is_space(ch) || "\"'\\$`;&|<>()".chars().any(|x| x as u32 == ch))
}

fn quote(arg: &[u32]) -> PyStr {
    if !arg.is_empty() && !needs_quotes(arg) {
        return arg.to_vec();
    }
    let escaped = pystr::replace(&pystr::replace(arg, &u("\\"), &u("\\\\")), &u("\""), &u("\\\""));
    pystr::concat(&[&u("\""), &escaped, &u("\"")])
}

/// A task argument: a string, or VS Code's {value, quoting} form.
fn arg_text(v: &JNode) -> Option<PyStr> {
    match &v.kind {
        JKind::Str(s) => Some(s.clone()),
        _ => str_of(get(Some(v), "value", Some("string"))).cloned(),
    }
}

fn is_str_or_obj(v: &JNode) -> bool {
    matches!(v.kind, JKind::Str(_) | JKind::Object(_))
}

/// command (a string, or VS Code's {value, quoting}) with its args (an array, or None), as one shell line.
fn command_line(command: Option<&JNode>, args: Option<&JNode>) -> Option<PyStr> {
    let command = command?;
    let head = if is_str_or_obj(command) { arg_text(command) } else { None };
    let head = head.filter(|h| !pystr::strip(h).is_empty())?;
    let mut parts = vec![head];
    if let Some(JKind::Array(items)) = args.map(|a| &a.kind) {
        for a in items {
            if is_str_or_obj(a) {
                if let Some(t) = arg_text(a) {
                    parts.push(quote(&t));
                }
            }
        }
    }
    let refs: Vec<&[u32]> = parts.iter().map(|x| x.as_slice()).collect();
    Some(pystr::join(&u(" "), &refs))
}

fn entry(line: usize, trigger: PyStr, command: Option<PyStr>) -> Entry {
    Entry { line, trigger, command }
}

fn label_of(task: &JNode) -> Option<PyStr> {
    text_of(get(Some(task), "label", None)).or_else(|| text_of(get(Some(task), "taskName", None)))
}

fn task_label(task: &JNode) -> PyStr {
    match label_of(task) {
        Some(t) => pystr::concat(&[&u("the task \""), &t, &u("\"")]),
        None => u("an unnamed task"),
    }
}

/// The command of one task and of each platform's variant of it.
fn task_entries(task: &JNode, trigger: &[u32], out: &mut Vec<Entry>) {
    let mut seen: Vec<PyStr> = Vec::new();
    let mut command = get(Some(task), "command", None);
    let args = get(Some(task), "args", Some("array"));
    let script = get(Some(task), "script", Some("string"));
    let mut base = command_line(command, args);
    if base.is_none() && text_of(get(Some(task), "type", None)).is_some_and(|t| pystr::eq(&t, "npm")) && text_of(script).is_some() {
        base = Some(pystr::concat(&[&u("npm run "), &quote(str_of(script).map(|x| x.as_slice()).unwrap_or(&[]))]));
        command = script;
    }
    if let (Some(b), Some(cmd)) = (&base, command) {
        seen.push(b.clone());
        out.push(entry(cmd.line, trigger.to_vec(), Some(b.clone())));
    }
    for (key, where_) in PLATFORMS {
        let plat = match get(Some(task), key, Some("object")) {
            Some(p) => p,
            None => continue,
        };
        let pcmd = get(Some(plat), "command", None);
        let pargs = get(Some(plat), "args", Some("array"));
        let line = match pcmd.or(pargs) {
            Some(l) => l.line,
            None => continue,
        };
        let cmd = command_line(pcmd.or(command), pargs.or(args));
        if let Some(cmd) = cmd {
            if !seen.contains(&cmd) {
                seen.push(cmd.clone());
                out.push(entry(line, pystr::concat(&[trigger, &u(&format!(" ({})", where_))]), Some(cmd)));
            }
        }
    }
    if base.is_none() && seen.is_empty() {
        let kind = text_of(get(Some(task), "type", None));
        let mut t = trigger.to_vec();
        if let Some(k) = kind {
            t.extend(u(" (a "));
            t.extend(k);
            t.extend(u(" task)"));
        }
        out.push(entry(task.line, t, None));
    }
}

fn vscode_tasks(root: &JNode, out: &mut Vec<Entry>) {
    let tasks = match get(Some(root), "tasks", Some("array")).map(|t| &t.kind) {
        Some(JKind::Array(items)) => items,
        _ => return,
    };
    let items: Vec<&JNode> = tasks.iter().filter(|t| matches!(t.kind, JKind::Object(_))).collect();
    let mut by_label: Vec<(PyStr, usize)> = Vec::new();
    for (k, t) in items.iter().enumerate() {
        if let Some(label) = label_of(t) {
            if !by_label.iter().any(|(l, _)| *l == label) {
                by_label.push((label, k));
            }
        }
    }
    let mut queue: Vec<(usize, Option<PyStr>)> = Vec::new();
    for (k, t) in items.iter().enumerate() {
        let run_on = get(get(Some(t), "runOptions", Some("object")), "runOn", Some("string"));
        if str_of(run_on).is_some_and(|v| pystr::eq(v, "folderOpen")) {
            queue.push((k, None));
        }
    }
    let mut seen: Vec<usize> = Vec::new();
    let mut k = 0;
    while k < queue.len() && seen.len() < MAX_TASKS {
        let (t, parent) = queue[k].clone();
        k += 1;
        if seen.contains(&t) {
            continue;
        }
        seen.push(t);
        let task = items[t];
        let mut trigger = pystr::concat(&[&u("Opening this folder in VS Code runs "), &task_label(task)]);
        if let Some(parent) = parent {
            trigger = pystr::concat(&[&trigger, &u(", which "), &parent, &u(" depends on")]);
        }
        task_entries(task, &trigger, out);
        let deps = get(Some(task), "dependsOn", None);
        let names: Vec<&JNode> = match deps.map(|d| &d.kind) {
            Some(JKind::Str(_)) => vec![deps.unwrap_or(task)],
            Some(JKind::Array(a)) => a.iter().collect(),
            _ => Vec::new(),
        };
        for d in names {
            if let JKind::Str(name) = &d.kind {
                if let Some((_, dep)) = by_label.iter().find(|(l, _)| l == name) {
                    queue.push((*dep, Some(task_label(task))));
                }
            }
        }
    }
}

/// A hooks object: event -> [group] where a group is {matcher, hooks: [{type, command}]} (Claude Code, Gemini CLI),
/// or event -> [{command}] (Cursor).
fn hooks(root: &JNode, tool: &str, out: &mut Vec<Entry>, grouped: bool) {
    let events = match get(Some(root), "hooks", Some("object")).map(|h| &h.kind) {
        Some(JKind::Object(m)) => m,
        _ => return,
    };
    for (event, groups) in events {
        let groups = match &groups.kind {
            JKind::Array(g) => g,
            _ => continue,
        };
        for g in groups {
            if !matches!(g.kind, JKind::Object(_)) {
                continue;
            }
            let matcher = text_of(get(Some(g), "matcher", None));
            let mut trigger = pystr::concat(&[&u(tool), &u(" runs a hook on "), event]);
            if let Some(m) = matcher.filter(|m| !pystr::eq(m, "*")) {
                trigger = pystr::concat(&[&trigger, &u(" for \""), &m, &u("\"")]);
            }
            let hs: Vec<&JNode> = if grouped {
                match get(Some(g), "hooks", Some("array")).map(|h| &h.kind) {
                    Some(JKind::Array(items)) => items.iter().collect(),
                    _ => Vec::new(),
                }
            } else {
                vec![g]
            };
            for h in hs {
                let kind = text_of(get(Some(h), "type", None));
                let command = get(Some(h), "command", Some("string"));
                if kind.as_ref().map_or(true, |k| pystr::eq(k, "command")) && text_of(command).is_some() {
                    if let (Some(cmd), Some(text)) = (command, str_of(command)) {
                        out.push(entry(cmd.line, trigger.clone(), Some(text.clone())));
                    }
                }
            }
        }
    }
}

fn mcp_servers(servers: Option<&JNode>, tool: &str, out: &mut Vec<Entry>) {
    let servers = match servers.map(|s| &s.kind) {
        Some(JKind::Object(m)) => m,
        _ => return,
    };
    for (name, server) in servers {
        let command = get(Some(server), "command", Some("string"));
        if text_of(command).is_none() {
            continue;
        }
        let cmd = command_line(command, get(Some(server), "args", Some("array")));
        let trigger = pystr::concat(&[&u(tool), &u(" starts the MCP server \""), name, &u("\"")]);
        out.push(entry(command.map_or(0, |c| c.line), trigger, cmd));
    }
}

/// The commands a settings file of `kind` (see config_kind) makes `tool` run, in document order; and (line, reason)
/// when the file cannot be read. A file that cannot be read but names what it would run has the error and no
/// entries; one that names nothing has neither.
pub fn entries(kind: &str, tool: &str, text: &[u32]) -> (Vec<Entry>, Option<JsonError>) {
    let root = match parse_jsonc(text) {
        Ok(r) => r,
        Err(e) => {
            let named = markers(kind).iter().any(|m| pystr::contains(text, m));
            return (Vec::new(), if named { Some(e) } else { None });
        }
    };
    let mut out = Vec::new();
    if !matches!(root.kind, JKind::Object(_)) {
        return (out, None);
    }
    match kind {
        "vscode-tasks" => vscode_tasks(&root, &mut out),
        "claude" => {
            hooks(&root, tool, &mut out, true);
            let status = get(Some(&root), "statusLine", Some("object"));
            let command = get(status, "command", Some("string"));
            let stype = text_of(get(status, "type", None));
            if text_of(command).is_some() && stype.as_ref().map_or(true, |t| pystr::eq(t, "command")) {
                if let (Some(cmd), Some(t)) = (command, str_of(command)) {
                    out.push(entry(cmd.line, u(&format!("{} runs a status-line command", tool)), Some(t.clone())));
                }
            }
            for key in CLAUDE_HELPERS {
                let helper = get(Some(&root), key, Some("string"));
                if text_of(helper).is_some() {
                    if let (Some(h), Some(t)) = (helper, str_of(helper)) {
                        out.push(entry(h.line, u(&format!("{} runs its {} command", tool, key)), Some(t.clone())));
                    }
                }
            }
        }
        "gemini" => {
            hooks(&root, tool, &mut out, true);
            mcp_servers(get(Some(&root), "mcpServers", Some("object")), tool, &mut out);
        }
        "cursor-hooks" => hooks(&root, tool, &mut out, false),
        "mcp" => mcp_servers(get(Some(&root), "mcpServers", Some("object")), tool, &mut out),
        "vscode-mcp" => mcp_servers(get(Some(&root), "servers", Some("object")), tool, &mut out),
        _ => {}
    }
    (out, None)
}

/// The command with the folder variables its tool sets (`${workspaceFolder}`, `$CLAUDE_PROJECT_DIR` …) replaced by
/// '.', so follow_hook reads `"$CLAUDE_PROJECT_DIR"/.claude/x.sh` as ./.claude/x.sh.
pub fn local_command(p: &Pack, command: &[u32]) -> PyStr {
    p.re("_AUTORUN_DIR_VARS_RE").sub_str(command, ".")
}

// ---------------------------------------------------------------- the issues

/// The files of the tree the package has read for this file's issues: '/'-separated root-relative path -> its text
/// (newlines as text mode reads them), or None when there is no such file. A path asked for and not given is noted.
pub struct Tree<'a> {
    pub follow: bool,
    pub files: &'a BTreeMap<PyStr, Option<PyStr>>,
    pub need: Vec<PyStr>,
}

impl<'a> Tree<'a> {
    fn read(&mut self, rel: &[u32]) -> Option<PyStr> {
        match self.files.get(rel) {
            Some(v) => v.clone(),
            None => {
                if !self.need.iter().any(|x| x.as_slice() == rel) {
                    self.need.push(rel.to_vec());
                }
                None
            }
        }
    }
}

/// A command's `target` joined with the directory `base` ('/'-separated, relative to the scan root), normalized;
/// None when it is absolute (a file of the machine, not of the tree) or leaves the scan root (core._tree_join).
pub fn tree_join(base: &[u32], target: &[u32]) -> Option<PyStr> {
    let target = pystr::replace_char(target, c('\\'), c('/'));
    if target.first() == Some(&c('/'))
        || (target.len() >= 2 && (target[0] as u8 as u32 == target[0]) && (target[0] as u8).is_ascii_alphabetic() && target[1] == c(':'))
    {
        return None;
    }
    let base: &[u32] = if base.is_empty() { &[c('.')] } else { base };
    let joined = if base.last() == Some(&c('/')) {
        pystr::concat(&[base, &target])
    } else {
        pystr::concat(&[base, &u("/"), &target])
    };
    let joined = pystr::normpath(&joined);
    if pystr::eq(&joined, ".") || pystr::eq(&joined, "..") || pystr::starts_with(&joined, "../") {
        return None;
    }
    Some(joined)
}

/// posixpath.dirname
fn dirname(path: &[u32]) -> PyStr {
    let i = path.iter().rposition(|&ch| ch == c('/')).map_or(0, |k| k + 1);
    let head = &path[..i];
    if !head.is_empty() && head.iter().any(|&ch| ch != c('/')) {
        pystr::rstrip_chars(head, "/").to_vec()
    } else {
        head.to_vec()
    }
}

/// The language a script runs in (engine.script_lang): "py" for a .py file, None for a shell script, "js" for the
/// rest (what node runs).
fn script_lang(path: &[u32]) -> Option<&'static str> {
    if pystr::ends_with(path, ".py") {
        Some("py")
    } else if pystr::ends_with(path, ".sh") {
        None
    } else {
        Some("js")
    }
}

fn normalize_newlines(text: &[u32]) -> PyStr {
    if !text.contains(&c('\r')) {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == c('\r') {
            out.push(c('\n'));
            if text.get(i + 1) == Some(&c('\n')) {
                i += 1;
            }
        } else {
            out.push(text[i]);
        }
        i += 1;
    }
    out
}

/// The install-script test for what a settings file runs, but for writing an agent's or editor's settings: an
/// agent's own hooks manage them (a WorktreeCreate hook copies settings.local.json into the new worktree).
fn script_risk(p: &Pack, text: &[u32], lang: Option<&str>) -> Vec<PyStr> {
    let own = p.text("_AGENT_SETTINGS_REASON");
    crate::signs::install_script_risk(p, text, lang).into_iter().filter(|r| !r.starts_with(&own)).collect()
}

pub fn is_obfuscated(p: &Pack, text: &[u32]) -> bool {
    let mut names: Vec<&[u32]> = p.re("OBF_IDENT_RE").finditer(text).map(|m| m.group0()).collect();
    names.sort();
    names.dedup();
    names.len() >= p.usize("OBF_IDENT_MIN")
}

/// (reasons, target): why a command a settings file runs looks hostile, and the file of the tree it runs that does
/// (None when it is the command itself); nothing when nothing does.
fn risk(p: &Pack, command: &[u32], base: &[u32], tree: &mut Tree) -> (Vec<PyStr>, Option<PyStr>) {
    let mut reasons: Vec<PyStr> = Vec::new();
    if let Some((agent, how)) = crate::signs::agent_hijack_in_command(p, command) {
        reasons.push(pystr::concat(&[&u("starts the AI agent \""), &agent, &u("\" with "), &how]));
    }
    reasons.extend(script_risk(p, command, None));
    if !reasons.is_empty() || !tree.follow {
        return (reasons, None);
    }
    for target in crate::hooks::follow_hook(p, &local_command(p, command)).0 {
        let rel = match tree_join(base, &target) {
            Some(r) => r,
            None => continue,
        };
        let text = match tree.read(&rel) {
            Some(t) => t,
            None => continue,
        };
        let lang = script_lang(&rel);
        let mut found = script_risk(p, &text, lang);
        if is_obfuscated(p, &text) {
            found.push(u("is obfuscated"));
        }
        if !found.is_empty() {
            return (found, Some(target));
        }
        // (0.1.8) the scripts it starts: a loader that fetches a runtime and runs a file of the tree with it
        for (where_, path) in crate::signs::spawned_scripts(p, &normalize_newlines(&text), lang) {
            let from = if where_ == "dir" { dirname(&rel) } else { base.to_vec() };
            let srel = match tree_join(&from, &path) {
                Some(s) => s,
                None => continue,
            };
            let more = match tree.read(&srel) {
                Some(t) if !t.is_empty() => script_risk(p, &t, script_lang(&srel)),
                _ => Vec::new(),
            };
            if !more.is_empty() {
                let refs: Vec<&[u32]> = more.iter().map(|x| x.as_slice()).collect();
                let said = pystr::join(&u("; and "), &refs);
                return (vec![pystr::concat(&[&u("starts "), &srel, &u(", which "), &said])], Some(target));
            }
        }
    }
    (Vec::new(), None)
}

fn rule(p: &Pack, name: &str, args: &[(&str, Arg)]) -> RuleText {
    let mut r = RuleText::of(p, name);
    r.msg = findings::format(&r.msg, args);
    r
}

/// The issues of a settings file at `path` (config_kind(path) is not None) whose text is `text`: [(line, rule)]; or
/// Err(need), the files of the tree it has yet to read (tree.follow: commands are followed into the files they run).
pub fn issues(p: &Pack, path: &[u32], text: &[u32], tree: &mut Tree) -> Result<Vec<(usize, RuleText)>, Vec<PyStr>> {
    let (kind, tool) = match config_kind(path) {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let (found, error) = entries(kind, tool, text);
    if let Some((line, reason)) = error {
        let r = rule(
            p,
            "_AUTORUN_UNREADABLE_RULE",
            &[("tool", Arg::S(u(tool))), ("line", Arg::I(line as i64)), ("reason", Arg::S(reason))],
        );
        return Ok(vec![(line, r)]);
    }
    let base = owner_dir(path);
    let show = p.usize("AUTORUN_SHOW");
    let mut out = Vec::new();
    for e in &found {
        let cmd = match &e.command {
            Some(c) => c,
            None => {
                out.push((e.line, rule(p, "_AUTORUN_LISTED_RULE", &[("trigger", Arg::S(e.trigger.clone()))])));
                continue;
            }
        };
        let shown = if cmd.len() <= show { cmd.clone() } else { pystr::concat(&[&cmd[..show], &[0x2026]]) };
        let (reasons, target) = risk(p, cmd, &base, tree);
        let r = if reasons.is_empty() {
            rule(p, "_AUTORUN_LISTED_COMMAND_RULE", &[("trigger", Arg::S(e.trigger.clone())), ("shown", Arg::S(shown))])
        } else {
            let refs: Vec<&[u32]> = reasons.iter().map(|x| x.as_slice()).collect();
            let said = pystr::join(&u("; and "), &refs);
            match target {
                None => rule(
                    p,
                    "_AUTORUN_HOSTILE_RULE",
                    &[("trigger", Arg::S(e.trigger.clone())), ("shown", Arg::S(shown)), ("said", Arg::S(said))],
                ),
                Some(t) => rule(
                    p,
                    "_AUTORUN_HOSTILE_FILE_RULE",
                    &[
                        ("trigger", Arg::S(e.trigger.clone())),
                        ("shown", Arg::S(shown)),
                        ("target", Arg::S(t)),
                        ("said", Arg::S(said)),
                    ],
                ),
            }
        };
        out.push((e.line, r));
    }
    if !tree.need.is_empty() {
        return Err(std::mem::take(&mut tree.need));
    }
    Ok(out)
}
