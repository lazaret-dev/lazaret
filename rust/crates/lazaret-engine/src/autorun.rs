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
//!
//! RA-2 (0.1.9): Claude Code plugins too (a plugin's manifest, `hooks/hooks.json`, `monitors/monitors.json`, `.lsp.json`
//! and a marketplace's `marketplace.json`: their hooks, MCP servers, monitors and language servers, and the files a
//! manifest names for them), a hook's exec form (`args`) and an MCP server's `headersHelper`; what a file sends out
//! (SC-AGENT-ENDPOINT: a remote MCP server, an HTTP hook, a model provider's base URL set to another host) and what it
//! lets the agent do (SC-AGENT-CONFIG: permission prompts bypassed, network-wide allow rules, every project MCP server
//! approved, plugin marketplaces added, VS Code's chat tools approved); and, of a command, a hidden file outside the
//! repository it runs (MAJOR), a hook that approves the agent's tool calls or writes its permissions (CRITICAL).

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
    (".vscode/settings.json", "vscode-settings", "VS Code"),
    (".claude/settings.json", "claude", "Claude Code"),
    (".claude/settings.local.json", "claude", "Claude Code"),
    // a Claude Code plugin (RA-2): its manifest, its default hooks and monitors files, and a marketplace's catalog
    (".claude-plugin/plugin.json", "claude-plugin", "Claude Code"),
    (".claude-plugin/marketplace.json", "claude-marketplace", "Claude Code"),
    ("hooks/hooks.json", "claude-hooks", "Claude Code"),
    ("monitors/monitors.json", "claude-monitors", "Claude Code"),
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
            "\"gcpAuthRefresh\"",
            "\"fileSuggestion\"",
        ],
        "gemini" => &["\"hooks\"", "\"command\""],
        "vscode-settings" => &["autoApprove"],
        _ => &["\"command\""],
    }
}
/// Claude Code settings whose value is a command it runs
const CLAUDE_HELPERS: &[&str] =
    &["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "gcpAuthRefresh"];
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
    if pystr::eq(&pystr::lower(&last), ".lsp.json") {
        return Some(("claude-lsp", "Claude Code"));        // a plugin's language servers (RA-2)
    }
    if parts.len() < 2 {
        return None;
    }
    let key = pystr::lower(&pystr::concat(&[&parts[parts.len() - 2], &u("/"), &last]));
    KINDS.iter().find(|(k, _, _)| pystr::eq(&key, k)).map(|(_, kind, tool)| (*kind, *tool))
}

/// The folder a settings file belongs to ('/'-separated, '' for the root): the parent of its .vscode / .claude /
/// .cursor / .gemini directory, or the directory of a .mcp.json. Its commands run there. A plugin's files belong to
/// the plugin's root: the parent of its .claude-plugin, hooks or monitors directory, or the directory of its .lsp.json
/// (`${CLAUDE_PLUGIN_ROOT}`).
pub fn owner_dir(path: &[u32]) -> PyStr {
    let parts = parts(path);
    let n = parts.len();
    let last = pystr::lower(&parts[n - 1]);
    let keep = if pystr::eq(&last, ".mcp.json") || pystr::eq(&last, ".lsp.json") { n - 1 } else { n.saturating_sub(2) };
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

/// Each hook of an event map (event -> [group] where a group is {matcher, hooks: [hook]}, Claude Code's and Gemini
/// CLI's; event -> [hook], Cursor's): f(event, matcher, hook).
fn each_hook<'a>(events: &'a JNode, grouped: bool, f: &mut dyn FnMut(&'a PyStr, Option<PyStr>, &'a JNode)) {
    let events = match &events.kind {
        JKind::Object(m) => m,
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
            let hs: Vec<&JNode> = if grouped {
                match get(Some(g), "hooks", Some("array")).map(|h| &h.kind) {
                    Some(JKind::Array(items)) => items.iter().collect(),
                    _ => Vec::new(),
                }
            } else {
                vec![g]
            };
            for h in hs {
                f(event, matcher.clone(), h);
            }
        }
    }
}

/// "{who} on {event}" and the matcher, as a hook's trigger says it.
fn hook_trigger(who: &[u32], event: &[u32], matcher: Option<PyStr>) -> PyStr {
    let mut trigger = pystr::concat(&[who, &u(" on "), event]);
    if let Some(m) = matcher.filter(|m| !pystr::eq(m, "*")) {
        trigger = pystr::concat(&[&trigger, &u(" for \""), &m, &u("\"")]);
    }
    trigger
}

/// The command hooks of an event map, `who` saying who runs them ("Claude Code runs a hook"). A hook's exec form
/// (`args`: the command spawned with them, no shell) is read as the command line it runs.
fn hook_events(events: &JNode, who: &[u32], out: &mut Vec<Entry>, grouped: bool) {
    each_hook(events, grouped, &mut |event, matcher, h| {
        let kind = text_of(get(Some(h), "type", None));
        let command = get(Some(h), "command", Some("string"));
        if kind.as_ref().map_or(true, |k| pystr::eq(k, "command")) && text_of(command).is_some() {
            let args = get(Some(h), "args", Some("array"));
            let line = if args.is_some() { command_line(command, args) } else { str_of(command).cloned() };
            if let (Some(cmd), Some(text)) = (command, line) {
                out.push(entry(cmd.line, hook_trigger(who, event, matcher), Some(text)));
            }
        }
    });
}

/// A hooks object: event -> [group] where a group is {matcher, hooks: [{type, command}]} (Claude Code, Gemini CLI),
/// or event -> [{command}] (Cursor).
fn hooks(root: &JNode, tool: &str, out: &mut Vec<Entry>, grouped: bool) {
    if let Some(events) = get(Some(root), "hooks", Some("object")) {
        hook_events(events, &pystr::concat(&[&u(tool), &u(" runs a hook")]), out, grouped);
    }
}

fn mcp_servers(servers: Option<&JNode>, tool: &str, out: &mut Vec<Entry>) {
    let servers = match servers.map(|s| &s.kind) {
        Some(JKind::Object(m)) => m,
        _ => return,
    };
    for (name, server) in servers {
        // a remote server's headersHelper: a command its tool runs to make the request's headers (RA-2)
        let helper = get(Some(server), "headersHelper", Some("string"));
        if let (Some(h), Some(t)) = (helper, text_of(helper)) {
            let trigger = pystr::concat(&[&u(tool), &u(" runs the headers helper of the MCP server \""), name, &u("\"")]);
            out.push(entry(h.line, trigger, Some(t)));
        }
        let command = get(Some(server), "command", Some("string"));
        if text_of(command).is_none() {
            continue;
        }
        let cmd = command_line(command, get(Some(server), "args", Some("array")));
        let trigger = pystr::concat(&[&u(tool), &u(" starts the MCP server \""), name, &u("\"")]);
        out.push(entry(command.map_or(0, |c| c.line), trigger, cmd));
    }
}

/// The objects of a value that is an object or an array of them (a plugin's component fields).
fn objects(v: Option<&JNode>) -> Vec<&JNode> {
    match v.map(|x| (&x.kind, x)) {
        Some((JKind::Object(_), x)) => vec![x],
        Some((JKind::Array(items), _)) => items.iter().filter(|i| matches!(i.kind, JKind::Object(_))).collect(),
        _ => Vec::new(),
    }
}

/// A plugin's language servers: name -> {command, args} (Claude Code starts each).
fn lsp_servers(servers: Option<&JNode>, out: &mut Vec<Entry>) {
    if let Some(JKind::Object(m)) = servers.map(|s| &s.kind) {
        for (name, server) in m {
            let command = get(Some(server), "command", Some("string"));
            if text_of(command).is_some() {
                let cmd = command_line(command, get(Some(server), "args", Some("array")));
                let trigger = pystr::concat(&[&u("Claude Code starts the language server \""), name, &u("\"")]);
                out.push(entry(command.map_or(0, |c| c.line), trigger, cmd));
            }
        }
    }
}

/// A plugin's monitors: [{name, command}], each a command Claude Code keeps running in the background.
fn monitors(list: Option<&JNode>, out: &mut Vec<Entry>) {
    if let Some(JKind::Array(items)) = list.map(|l| &l.kind) {
        for m in items {
            let command = get(Some(m), "command", Some("string"));
            if let (Some(c), Some(t)) = (command, text_of(command)) {
                let trigger = match text_of(get(Some(m), "name", None)) {
                    Some(n) => pystr::concat(&[&u("Claude Code runs the monitor \""), &n, &u("\" in the background")]),
                    None => u("Claude Code runs a monitor in the background"),
                };
                out.push(entry(c.line, trigger, Some(t)));
            }
        }
    }
}

/// "the plugin \"name\"" (or "a plugin").
fn plugin_label(v: &JNode) -> PyStr {
    match text_of(get(Some(v), "name", None)) {
        Some(n) => pystr::concat(&[&u("the plugin \""), &n, &u("\"")]),
        None => u("a plugin"),
    }
}

/// What a plugin's manifest (or a marketplace's entry for it) declares inline: hooks (an event map with no wrapper,
/// or an array of them), MCP servers, language servers, monitors, and the settings' subagent status line.
fn plugin_entries(plugin: &JNode, out: &mut Vec<Entry>) {
    let who = pystr::concat(&[&u("Claude Code runs a hook of "), &plugin_label(plugin)]);
    for events in objects(get(Some(plugin), "hooks", None)) {
        hook_events(events, &who, out, true);
    }
    for servers in objects(get(Some(plugin), "mcpServers", None)) {
        mcp_servers(Some(servers), "Claude Code", out);
    }
    for servers in objects(get(Some(plugin), "lspServers", None)) {
        lsp_servers(Some(servers), out);
    }
    monitors(get(get(Some(plugin), "experimental", Some("object")), "monitors", Some("array")), out);
    monitors(get(Some(plugin), "monitors", Some("array")), out);
    let status = get(get(Some(plugin), "settings", Some("object")), "subagentStatusLine", Some("object"));
    let command = get(status, "command", Some("string"));
    if let (Some(c), Some(t)) = (command, text_of(command)) {
        let trigger = pystr::concat(&[&u("Claude Code runs the subagent status-line command of "), &plugin_label(plugin)]);
        out.push(entry(c.line, trigger, Some(t)));
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
    if kind == "claude-monitors" {
        monitors(Some(&root), &mut out);                  // (the file is the monitors array)
        return (out, None);
    }
    if !matches!(root.kind, JKind::Object(_)) {
        return (out, None);
    }
    match kind {
        "vscode-tasks" => vscode_tasks(&root, &mut out),
        "claude" => {
            hooks(&root, tool, &mut out, true);
            let suggest = get(Some(&root), "fileSuggestion", Some("object"));
            let command = get(suggest, "command", Some("string"));
            if let (Some(c), Some(t)) = (command, text_of(command)) {
                out.push(entry(c.line, u(&format!("{} runs its fileSuggestion command", tool)), Some(t)));
            }
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
        "claude-hooks" => hooks(&root, tool, &mut out, true),
        "claude-plugin" => plugin_entries(&root, &mut out),
        "claude-marketplace" => {
            for plugin in objects(get(Some(&root), "plugins", Some("array"))) {
                plugin_entries(plugin, &mut out);
            }
        }
        "claude-lsp" => lsp_servers(Some(&root), &mut out),
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
    pub(crate) fn read(&mut self, rel: &[u32]) -> Option<PyStr> {
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

/// RA-2: a command or a file it runs that writes the agent's permissions (CRITICAL, as a hostile command is).
fn agent_reasons(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    match crate::signs::writes_agent_permissions(p, text) {
        Some(file) => vec![pystr::concat(&[&u("writes the agent's permissions ("), &file, &u(")")])],
        None => Vec::new(),
    }
}

/// RA-2: what a command or a file it runs prints to approve the agent's tool calls itself (a PreToolUse hook's
/// permissionDecision "allow" or the older decision "approve", a PermissionRequest hook's behavior "allow").
fn approves(p: &Pack, text: &[u32]) -> Option<PyStr> {
    p.re("_AGENT_APPROVE_RE").search(text).map(|m| m.group0().to_vec())
}

/// A file a command runs that is outside the repository (in the home folder, a temporary or absolute path) and
/// hidden there: a folder or file whose name starts with a dot, the toolchains' own folders aside (_AUTORUN_TOOL_DIRS:
/// ~/.cargo/bin, ~/.local/bin …). The scan cannot read it.
fn hidden_outside(p: &Pack, target: &[u32]) -> bool {
    if p.re("_AUTORUN_OUTSIDE_RE").match_(target).is_none() {
        return false;
    }
    let path = pystr::replace_char(target, c('\\'), c('/'));
    let tools = p.strs("_AUTORUN_TOOL_DIRS");
    pystr::split_char(&path, c('/')).into_iter().skip(1).any(|comp| {
        comp.first() == Some(&c('.')) && !pystr::eq(comp, ".") && !pystr::eq(comp, "..")
            && !tools.iter().any(|t| t.as_slice() == pystr::lower(comp).as_slice())
    })
}

/// What a command a settings file runs does: why it looks hostile (`reasons`), and the file of the tree it runs that
/// does (`target`, None when it is the command itself); a hidden file outside the repository it runs (hidden_outside),
/// which the scan cannot read; and what it prints to approve the agent's tool calls, with the file that does
/// (`approves`).
struct Risk {
    reasons: Vec<PyStr>,
    target: Option<PyStr>,
    outside: Option<PyStr>,
    approves: Option<(PyStr, Option<PyStr>)>,
}

fn risk(p: &Pack, command: &[u32], base: &[u32], tree: &mut Tree) -> Risk {
    let mut approval = approves(p, command).map(|m| (m, None));
    let (reasons, target, outside) = risk_of(p, command, base, tree, &mut approval);
    Risk { reasons, target, outside, approves: approval }
}

fn risk_of(
    p: &Pack,
    command: &[u32],
    base: &[u32],
    tree: &mut Tree,
    approval: &mut Option<(PyStr, Option<PyStr>)>,
) -> (Vec<PyStr>, Option<PyStr>, Option<PyStr>) {
    let mut reasons: Vec<PyStr> = Vec::new();
    if let Some((agent, how)) = crate::signs::agent_hijack_in_command(p, command) {
        reasons.push(pystr::concat(&[&u("starts the AI agent \""), &agent, &u("\" with "), &how]));
    }
    reasons.extend(script_risk(p, command, None));
    reasons.extend(agent_reasons(p, command));
    let targets = crate::hooks::follow_hook(p, &local_command(p, command)).0;
    let outside = targets.iter().find(|t| hidden_outside(p, t)).cloned();
    if !reasons.is_empty() || !tree.follow {
        return (reasons, None, outside);
    }
    for target in targets {
        if p.re("_AUTORUN_OUTSIDE_RE").match_(&target).is_some() {
            continue;                                 // (a file of the machine, not of the tree)
        }
        let rel = match tree_join(base, &target) {
            Some(r) => r,
            None => continue,
        };
        let text = match tree.read(&rel) {
            Some(t) => t,
            None => continue,
        };
        let lang = script_lang(&rel);
        if approval.is_none() {
            *approval = approves(p, &text).map(|m| (m, Some(target.clone())));
        }
        let mut found = script_risk(p, &text, lang);
        found.extend(agent_reasons(p, &text));
        if is_obfuscated(p, &text) {
            found.push(u("is obfuscated"));
        }
        if !found.is_empty() {
            return (found, Some(target), outside);
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
                return (vec![pystr::concat(&[&u("starts "), &srel, &u(", which "), &said])], Some(target), outside);
            }
        }
    }
    (Vec::new(), None, outside)
}

fn rule(p: &Pack, name: &str, args: &[(&str, Arg)]) -> RuleText {
    let mut r = RuleText::of(p, name);
    r.msg = findings::format(&r.msg, args);
    r
}

// ---------------------------------------------------------------- what a file sends out, what it lets the agent do

/// (scheme, host) of a URL, lowercased, the host without its port, user or brackets; None when it is not one (or its
/// host is a variable the tool fills in).
fn url_host(url: &[u32]) -> Option<(PyStr, PyStr)> {
    let url = pystr::strip(url);
    let k = (0..url.len().saturating_sub(2)).find(|&i| url[i] == c(':') && url[i + 1] == c('/') && url[i + 2] == c('/'))?;
    let scheme = pystr::lower(&url[..k]);
    let rest = &url[k + 3..];
    let end = rest.iter().position(|&ch| ch == c('/') || ch == c('?') || ch == c('#')).unwrap_or(rest.len());
    let mut auth = &rest[..end];
    if let Some(at) = auth.iter().rposition(|&ch| ch == c('@')) {
        auth = &auth[at + 1..];
    }
    let host = if auth.first() == Some(&c('[')) {
        let close = auth.iter().position(|&ch| ch == c(']'))?;
        &auth[1..close]
    } else {
        let colon = auth.iter().position(|&ch| ch == c(':')).unwrap_or(auth.len());
        &auth[..colon]
    };
    let host = pystr::lower(pystr::rstrip_chars(host, "."));
    if host.is_empty() || scheme.is_empty() || host.contains(&c('$')) || host.contains(&c('{')) || host.contains(&c('%')) {
        return None;
    }
    Some((scheme, host))
}

fn is_ip(host: &[u32]) -> bool {
    host.contains(&c(':')) || (!host.is_empty() && host.iter().all(|&ch| digit(ch) || ch == c('.')))
}

fn is_loopback(host: &[u32]) -> bool {
    pystr::eq(host, "localhost") || pystr::ends_with(host, ".localhost") || pystr::starts_with(host, "127.")
        || pystr::eq(host, "::1") || pystr::eq(host, "0.0.0.0") || pystr::eq(host, "::")
}

/// A name of the local network: one with no dot (a container's in a compose file's network, a machine's on the LAN)
/// or a local suffix (.local, .internal, .lan, .home.arpa).
fn is_local_name(host: &[u32]) -> bool {
    (!host.contains(&c('.')) && !is_ip(host))
        || [".local", ".internal", ".lan", ".home.arpa"].iter().any(|s| pystr::ends_with(host, s))
}

/// Why sending to `url` is a risk: a tunnel or capture service, a raw IP address, or plain http (or ws) to another
/// machine; None for anything else (an https host, this machine, a URL the tool fills in).
fn url_risk(p: &Pack, url: &[u32]) -> Option<PyStr> {
    let (scheme, host) = url_host(url)?;
    if p.re("_AGENT_TUNNEL_HOST_RE").search(&host).is_some() {
        return Some(pystr::concat(&[&u("a tunnel or capture service ("), &host, &u(")")]));
    }
    if is_loopback(&host) {
        return None;
    }
    if is_ip(&host) {
        return Some(pystr::concat(&[&u("a raw IP address ("), &host, &u(")")]));
    }
    if (pystr::eq(&scheme, "http") || pystr::eq(&scheme, "ws")) && !is_local_name(&host) {
        return Some(pystr::concat(&[&u("plain "), &scheme, &u(" to another machine ("), &host, &u(")")]));
    }
    None
}

fn shown(p: &Pack, text: &[u32]) -> PyStr {
    let show = p.usize("AUTORUN_SHOW");
    if text.len() <= show { text.to_vec() } else { pystr::concat(&[&text[..show], &[0x2026]]) }
}

/// SC-AGENT-ENDPOINT for `what` sending to `url`: MAJOR when url_risk says why, else listed (INFO).
fn endpoint(p: &Pack, line: usize, what: PyStr, url: &[u32]) -> (usize, RuleText) {
    let args = |extra: Option<PyStr>| {
        let mut a = vec![("what", Arg::S(what.clone())), ("url", Arg::S(shown(p, url)))];
        if let Some(e) = extra {
            a.push(("said", Arg::S(e)));
        }
        a
    };
    match url_risk(p, url) {
        Some(why) => (line, rule(p, "_AGENT_ENDPOINT_RISK_RULE", &args(Some(why)))),
        None => (line, rule(p, "_AGENT_ENDPOINT_LISTED_RULE", &args(None))),
    }
}

/// SC-AGENT-CONFIG: what a file lets the agent do (MAJOR), or adds to it (listed, INFO).
fn config(p: &Pack, line: usize, said: PyStr, risky: bool) -> (usize, RuleText) {
    let name = if risky { "_AGENT_CONFIG_RISK_RULE" } else { "_AGENT_CONFIG_LISTED_RULE" };
    (line, rule(p, name, &[("said", Arg::S(said))]))
}

/// The remote MCP servers of a servers map (no command; a url, Windsurf's serverUrl or Gemini CLI's httpUrl).
fn remote_servers(p: &Pack, servers: Option<&JNode>, tool: &str, out: &mut Vec<(usize, RuleText)>) {
    if let Some(JKind::Object(m)) = servers.map(|s| &s.kind) {
        for (name, server) in m {
            if text_of(get(Some(server), "command", Some("string"))).is_some() {
                continue;
            }
            for key in ["url", "serverUrl", "httpUrl"] {
                let v = get(Some(server), key, Some("string"));
                if let (Some(n), Some(url)) = (v, text_of(v)) {
                    let what = pystr::concat(&[&u(tool), &u(" connects to the MCP server \""), name, &u("\" at")]);
                    out.push(endpoint(p, n.line, what, &url));
                    break;
                }
            }
        }
    }
}

/// The HTTP hooks of an event map: each sends the event's input (a tool call's, a prompt's) to its url.
fn http_hooks(p: &Pack, events: &JNode, who: &[u32], out: &mut Vec<(usize, RuleText)>) {
    each_hook(events, true, &mut |event, matcher, h| {
        let kind = text_of(get(Some(h), "type", None));
        let url = get(Some(h), "url", Some("string"));
        if kind.is_some_and(|k| pystr::eq(&k, "http")) {
            if let (Some(n), Some(text)) = (url, text_of(url)) {
                let what = pystr::concat(&[&hook_trigger(who, event, matcher), &u(", sending its input to")]);
                out.push(endpoint(p, n.line, what, &text));
            }
        }
    });
}

/// What a plugin's manifest (or a marketplace's entry) sends out: its remote MCP servers, its HTTP hooks, an MCP
/// bundle it downloads.
fn plugin_findings(p: &Pack, plugin: &JNode, out: &mut Vec<(usize, RuleText)>) {
    let who = pystr::concat(&[&u("Claude Code runs a hook of "), &plugin_label(plugin)]);
    for events in objects(get(Some(plugin), "hooks", None)) {
        http_hooks(p, events, &who, out);
    }
    for servers in objects(get(Some(plugin), "mcpServers", None)) {
        remote_servers(p, Some(servers), "Claude Code", out);
    }
    let servers = get(Some(plugin), "mcpServers", None);
    let strings: Vec<&JNode> = match servers.map(|v| &v.kind) {
        Some(JKind::Str(_)) => vec![servers.unwrap_or(plugin)],
        Some(JKind::Array(items)) => items.iter().filter(|i| matches!(i.kind, JKind::Str(_))).collect(),
        _ => Vec::new(),
    };
    for v in strings {
        if let Some(t) = str_of(Some(v)).filter(|t| url_host(t).is_some()) {
            let what = pystr::concat(&[&u("Claude Code downloads an MCP bundle of "), &plugin_label(plugin), &u(" from")]);
            out.push(endpoint(p, v.line, what, t));
        }
    }
}

/// Where a marketplace (a source object) gets its plugins: (what it says, a URL to judge).
fn source_of(source: &JNode) -> Option<(PyStr, Option<PyStr>)> {
    if let JKind::Str(path) = &source.kind {
        return Some((path.clone(), url_host(path).map(|_| path.clone())));
    }
    let kind = text_of(get(Some(source), "source", None))?;
    for key in ["url", "repo", "package", "path"] {
        if let Some(v) = text_of(get(Some(source), key, None)) {
            let judged = (key == "url").then(|| v.clone());
            return Some((pystr::concat(&[&kind, &u(": "), &v]), judged));
        }
    }
    Some((kind, None))
}

/// What a Claude Code settings file sends out and lets the agent do.
fn claude_settings(p: &Pack, root: &JNode, tool: &str, out: &mut Vec<(usize, RuleText)>) {
    let these = format!("These {} settings", tool);
    if let Some(events) = get(Some(root), "hooks", Some("object")) {
        http_hooks(p, events, &pystr::concat(&[&u(tool), &u(" runs a hook")]), out);
    }
    let perms = get(Some(root), "permissions", Some("object"));
    let mode = get(perms, "defaultMode", Some("string"));
    if let Some(m) = mode.filter(|m| str_of(Some(*m)).is_some_and(|v| pystr::eq(v, "bypassPermissions"))) {
        let said = u(&format!(
            "{} start every session with its permission prompts off (permissions.defaultMode: bypassPermissions)",
            these
        ));
        out.push(config(p, m.line, said, true));
    }
    if let Some(JKind::Array(rules)) = get(perms, "allow", Some("array")).map(|a| &a.kind) {
        let wide_re = p.re("_AGENT_WIDE_ALLOW_RE");
        let wide: Vec<&JNode> = rules
            .iter()
            .filter(|r| str_of(Some(*r)).is_some_and(|t| wide_re.fullmatch(pystr::strip(t)).is_some()))
            .collect();
        if let Some(first) = wide.first() {
            let names: Vec<PyStr> = wide.iter().take(5).filter_map(|r| str_of(Some(*r)).cloned()).collect();
            let refs: Vec<&[u32]> = names.iter().map(|x| x.as_slice()).collect();
            let more = if wide.len() > 5 { format!(" and {} more", wide.len() - 5) } else { String::new() };
            let head = format!("{} let the agent reach the network or run any command without asking: ", these);
            let said = pystr::concat(&[&u(&head), &pystr::join(&u(", "), &refs), &u(&more)]);
            out.push(config(p, first.line, said, true));
        }
    }
    let all = get(Some(root), "enableAllProjectMcpServers", None);
    if let Some(a) = all.filter(|a| matches!(a.kind, JKind::True)) {
        let said = u(&format!("{} approve every MCP server the project lists (enableAllProjectMcpServers)", these));
        out.push(config(p, a.line, said, true));
    }
    if let Some(JKind::Object(vars)) = get(Some(root), "env", Some("object")).map(|e| &e.kind) {
        let names = p.strs("_AGENT_BASE_URL_ENVS");
        for (name, v) in vars {
            if !names.iter().any(|n| n.as_slice() == name.as_slice()) {
                continue;
            }
            let url = match text_of(Some(v)) {
                Some(t) => t,
                None => continue,
            };
            let (_, host) = match url_host(&url) {
                Some(h) => h,
                None => continue,
            };
            let risk = url_risk(p, &url);
            if risk.is_none() && (is_loopback(&host) || p.re("_AGENT_PROVIDER_HOST_RE").search(&host).is_some()) {
                continue;
            }
            let said = risk.map(|r| pystr::concat(&[&u(", "), &r])).unwrap_or_default();
            let r = rule(p, "_AGENT_BASE_URL_RULE", &[("tool", Arg::S(u(tool))), ("name", Arg::S(name.clone())),
                                                        ("url", Arg::S(shown(p, &url))), ("said", Arg::S(said))]);
            out.push((v.line, r));
        }
    }
    if let Some(JKind::Object(markets)) = get(Some(root), "extraKnownMarketplaces", Some("object")).map(|m| &m.kind) {
        for (name, market) in markets {
            let source = get(Some(market), "source", None);
            let (what, url) = match source.and_then(source_of) {
                Some(x) => x,
                None => continue,
            };
            let risk = url.as_ref().and_then(|x| url_risk(p, x));
            let head = format!("{} add the plugin marketplace \"", these);
            let mut said = pystr::concat(&[&u(&head), name, &u("\" ("), &shown(p, &what), &u(")")]);
            if let Some(r) = &risk {
                said = pystr::concat(&[&said, &u(", "), r]);
            }
            out.push(config(p, source.map_or(market.line, |s| s.line), said, risk.is_some()));
        }
    }
    if let Some(JKind::Object(plugins)) = get(Some(root), "enabledPlugins", Some("object")).map(|m| &m.kind) {
        let on: Vec<&PyStr> = plugins.iter().filter(|(_, v)| matches!(v.kind, JKind::True)).map(|(k, _)| k).collect();
        if !on.is_empty() {
            let refs: Vec<&[u32]> = on.iter().take(10).map(|x| x.as_slice()).collect();
            let more = if on.len() > 10 { format!(" and {} more", on.len() - 10) } else { String::new() };
            let head = format!("{} enable the plugins ", these);
            let said = pystr::concat(&[&u(&head), &pystr::join(&u(", "), &refs), &u(&more),
                                       &u(", whose hooks and servers run as the project's own do")]);
            let line = get(Some(root), "enabledPlugins", None).map_or(1, |e| e.line);
            out.push(config(p, line, said, false));
        }
    }
}

/// The findings of a settings file that are not commands: SC-AGENT-ENDPOINT and SC-AGENT-CONFIG.
fn config_findings(p: &Pack, kind: &str, tool: &str, root: &JNode) -> Vec<(usize, RuleText)> {
    let mut out = Vec::new();
    if !matches!(root.kind, JKind::Object(_)) {
        return out;
    }
    match kind {
        "claude" => claude_settings(p, root, tool, &mut out),
        "claude-hooks" => {
            if let Some(events) = get(Some(root), "hooks", Some("object")) {
                http_hooks(p, events, &u("Claude Code runs a hook"), &mut out);
            }
        }
        "mcp" | "gemini" => remote_servers(p, get(Some(root), "mcpServers", Some("object")), tool, &mut out),
        "vscode-mcp" => remote_servers(p, get(Some(root), "servers", Some("object")), tool, &mut out),
        "claude-plugin" => plugin_findings(p, root, &mut out),
        "claude-marketplace" => {
            for plugin in objects(get(Some(root), "plugins", Some("array"))) {
                plugin_findings(p, plugin, &mut out);
                let source = get(Some(plugin), "source", None);
                if let Some((what, url)) = source.and_then(source_of) {
                    if url.is_none() && matches!(source.map(|s| &s.kind), Some(JKind::Str(_))) {
                        continue;                         // (a folder of the marketplace's own repository)
                    }
                    let risk = url.as_ref().and_then(|x| url_risk(p, x));
                    let label = plugin_label(plugin);
                    let mut said = pystr::concat(&[&u("This marketplace lists "), &label, &u(" from "), &shown(p, &what)]);
                    if let Some(r) = &risk {
                        said = pystr::concat(&[&said, &u(", "), r]);
                    }
                    out.push(config(p, source.map_or(plugin.line, |s| s.line), said, risk.is_some()));
                }
            }
        }
        "vscode-settings" => {
            for key in ["chat.tools.autoApprove", "chat.tools.global.autoApprove"] {
                if let Some(v) = get(Some(root), key, None).filter(|v| matches!(v.kind, JKind::True)) {
                    let said =
                        u(&format!("These VS Code settings approve every tool call of its chat agent without asking ({})", key));
                    out.push(config(p, v.line, said, true));
                }
            }
        }
        _ => {}
    }
    out
}

/// The files a plugin's manifest names for its hooks, MCP servers, language servers and monitors (a path each, or
/// paths in an array): (the line of the path, the kind its file is read as, the path). Its default files, which are
/// read as files of their own, and MCP bundles are not.
fn plugin_refs(root: &JNode) -> Vec<(usize, &'static str, PyStr)> {
    let mut out = Vec::new();
    let fields: [(Option<&JNode>, &'static str, &str); 5] = [
        (get(Some(root), "hooks", None), "claude-hooks", "hooks/hooks.json"),
        (get(Some(root), "mcpServers", None), "mcp-map", ".mcp.json"),
        (get(Some(root), "lspServers", None), "claude-lsp", ".lsp.json"),
        (
            get(get(Some(root), "experimental", Some("object")), "monitors", None),
            "claude-monitors",
            "monitors/monitors.json",
        ),
        (get(Some(root), "monitors", None), "claude-monitors", "monitors/monitors.json"),
    ];
    for (v, kind, default) in fields {
        let items: Vec<&JNode> = match v.map(|x| (&x.kind, x)) {
            Some((JKind::Str(_), x)) => vec![x],
            Some((JKind::Array(items), _)) => items.iter().collect(),
            _ => Vec::new(),
        };
        for item in items {
            if let JKind::Str(path) = &item.kind {
                let low = pystr::lower(path);
                if url_host(path).is_some() || pystr::ends_with(&low, ".mcpb") || pystr::ends_with(&low, ".dxt") {
                    continue;
                }
                if pystr::normpath(path).as_slice() == u(default).as_slice() {
                    continue;
                }
                out.push((item.line, kind, path.clone()));
            }
        }
    }
    out
}

/// The commands of a file a plugin's manifest names (plugin_refs), each at the line of its path in the manifest.
fn referenced_entries(kind: &str, path: &[u32], text: &[u32]) -> Vec<Entry> {
    let found = if kind == "mcp-map" {
        // ("a .json file the manifest names is read as an mcpServers map": its mcpServers, or the file itself)
        match parse_jsonc(text) {
            Ok(root) => {
                let mut out = Vec::new();
                let servers = get(Some(&root), "mcpServers", Some("object")).unwrap_or(&root);
                mcp_servers(Some(servers), "Claude Code", &mut out);
                out
            }
            Err(_) => Vec::new(),
        }
    } else {
        entries(kind, "Claude Code", text).0
    };
    found.into_iter().map(|e| Entry { trigger: pystr::concat(&[&e.trigger, &u(" (in "), path, &u(")")]), ..e }).collect()
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
    let root = parse_jsonc(text).ok();
    let mut found = found;
    if kind == "claude-plugin" && tree.follow {
        for (line, rkind, rpath) in root.as_ref().map(plugin_refs).unwrap_or_default() {
            let rel = match tree_join(&base, &rpath) {
                Some(r) => r,
                None => continue,
            };
            if let Some(t) = tree.read(&rel) {
                found.extend(referenced_entries(rkind, &rpath, &t).into_iter().map(|e| Entry { line, ..e }));
            }
        }
    }
    for e in &found {
        let cmd = match &e.command {
            Some(c) => c,
            None => {
                out.push((e.line, rule(p, "_AUTORUN_LISTED_RULE", &[("trigger", Arg::S(e.trigger.clone()))])));
                continue;
            }
        };
        let shown = if cmd.len() <= show { cmd.clone() } else { pystr::concat(&[&cmd[..show], &[0x2026]]) };
        let Risk { reasons, target, outside, approves } = risk(p, cmd, &base, tree);
        if let Some((said, file)) = approves {
            let said = match file {
                Some(f) => {
                    pystr::concat(&[&u("it runs "), &f, &u(", which approves the agent's tool calls itself ("), &said, &u(")")])
                }
                None => pystr::concat(&[&u("a command that approves the agent's tool calls itself ("), &said, &u(")")]),
            };
            let shown = if cmd.len() <= show { cmd.clone() } else { pystr::concat(&[&cmd[..show], &[0x2026]]) };
            let args = [("trigger", Arg::S(e.trigger.clone())), ("shown", Arg::S(shown)), ("said", Arg::S(said))];
            out.push((e.line, rule(p, "_AGENT_APPROVE_RULE", &args)));
        }
        let r = if reasons.is_empty() {
            match outside {
                Some(o) => rule(
                    p,
                    "_AUTORUN_OUTSIDE_RULE",
                    &[("trigger", Arg::S(e.trigger.clone())), ("shown", Arg::S(shown)), ("target", Arg::S(o))],
                ),
                None => rule(
                    p,
                    "_AUTORUN_LISTED_COMMAND_RULE",
                    &[("trigger", Arg::S(e.trigger.clone())), ("shown", Arg::S(shown))],
                ),
            }
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
    if let Some(root) = &root {
        out.extend(config_findings(p, kind, tool, root));
    }
    if !tree.need.is_empty() {
        return Err(std::mem::take(&mut tree.need));
    }
    Ok(out)
}
