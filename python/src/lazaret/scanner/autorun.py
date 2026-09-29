"""Editor and AI-agent settings that run commands on their own (0.1.7).

Opening a folder in VS Code runs its folder-open tasks; Claude Code, Cursor
and Gemini CLI run a project's hooks as a session starts and around the
agent's tool calls; an agent starts the MCP servers a project lists. None of
it asks each time. Mini Shai-Hulud and the keyv wave (May and August 2026)
committed a SessionStart hook and a folder-open task to every repository they
reached, each running a copy of the worm's loader, so opening a checkout ran
the worm (core.scan_config_file reports them: SC-AUTORUN).

This module holds the pure parts, twinned in js/src/lib/autorun.js: which
files these are (config_kind), a JSON-with-comments reader that keeps each
value's line (parse_jsonc: VS Code's files allow comments and trailing
commas), and the commands each file makes its tool run (entries).
"""
import re

#: Nesting deeper than this is not read (a JsoncError).
MAX_DEPTH = 256

# (the file's last two path components, lowercased) -> (kind, tool)
_KINDS = {
    ".vscode/tasks.json": ("vscode-tasks", "VS Code"),
    ".vscode/mcp.json": ("vscode-mcp", "VS Code"),
    ".claude/settings.json": ("claude", "Claude Code"),
    ".claude/settings.local.json": ("claude", "Claude Code"),
    ".cursor/hooks.json": ("cursor-hooks", "Cursor"),
    ".cursor/mcp.json": ("mcp", "Cursor"),
    ".gemini/settings.json": ("gemini", "Gemini CLI"),
}
#: Words that show a file, even one that cannot be read, asks its tool to run
#: something (see core: SC-AUTORUN on a malformed file)
_MARKERS = {
    "vscode-tasks": re.compile(r"folderOpen"),
    "vscode-mcp": re.compile(r'"command"'),
    "claude": re.compile(r'"(?:hooks|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)"'),
    "cursor-hooks": re.compile(r'"command"'),
    "mcp": re.compile(r'"command"'),
    "gemini": re.compile(r'"(?:hooks|command)"'),
}
#: Claude Code settings whose value is a command it runs
_CLAUDE_HELPERS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")
_PLATFORMS = (("windows", "on Windows"), ("linux", "on Linux"), ("osx", "on macOS"))
#: Tasks a folder-open task's dependsOn chain is followed to, per file
MAX_TASKS = 100
_NEEDS_QUOTES_RE = re.compile(r"""[\s"'\\$`;&|<>()]""")
_WS = " \t\n\r"
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX4_RE = re.compile(r"[0-9A-Fa-f]{4}")
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def config_kind(path):
    """(kind, tool) for a settings file that makes a tool run commands, by its
    path ('/' or os separators), else None."""
    parts = path.replace("\\", "/").split("/")
    if parts[-1].lower() == ".mcp.json":
        return ("mcp", "Claude Code")
    if len(parts) < 2:
        return None
    return _KINDS.get(f"{parts[-2]}/{parts[-1]}".lower())


def owner_dir(path):
    """The folder a settings file belongs to ('/'-separated, '' for the root):
    the parent of its .vscode / .claude / .cursor / .gemini directory, or the
    directory of a .mcp.json. Its commands run there."""
    parts = path.replace("\\", "/").split("/")
    keep = parts[:-1] if parts[-1].lower() == ".mcp.json" else parts[:-2]
    return "/".join(keep)


# ---- a JSON reader that keeps lines (comments and trailing commas allowed) ----
class JsoncError(ValueError):
    def __init__(self, line, reason):
        super().__init__(f"line {line}: {reason}")
        self.line = line
        self.reason = reason


class Value:
    """A JSON value: kind 'object' (value: dict of key -> Value, the last of
    a repeated key winning, in first-seen order), 'array' (list), 'string',
    'number' (its text), 'true', 'false' or 'null'; line: the 1-based line
    it starts on."""
    __slots__ = ("kind", "line", "value")

    def __init__(self, kind, line, value=None):
        self.kind = kind
        self.line = line
        self.value = value


def _char_name(c):
    return f"U+{ord(c):04X}"


class _Reader:
    def __init__(self, text):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.line = 1

    def fail(self, reason, line=None):
        raise JsoncError(self.line if line is None else line, reason)

    def blank(self):
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in _WS:
                if c == "\n":
                    self.line += 1
                self.i += 1
            elif s.startswith("//", self.i):
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                if end < 0:
                    self.fail("unterminated comment")
                self.line += s.count("\n", self.i, end)
                self.i = end + 2
            else:
                return

    def value(self, depth):
        self.blank()
        if self.i >= self.n:
            self.fail("unexpected end of input")
        if depth > MAX_DEPTH:
            self.fail("nesting too deep")
        c, line = self.s[self.i], self.line
        if c == "{":
            return self.obj(depth, line)
        if c == "[":
            return self.arr(depth, line)
        if c == '"':
            return Value("string", line, self.string())
        for word in ("true", "false", "null"):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return Value(word, line)
        m = _NUMBER_RE.match(self.s, self.i)
        if m is not None:
            self.i = m.end()
            return Value("number", line, m.group())
        self.fail("unexpected character " + _char_name(c))

    def obj(self, depth, line):
        self.i += 1
        members = {}
        self.blank()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return Value("object", line, members)
        while True:
            self.blank()
            if self.i >= self.n:
                self.fail("unexpected end of input")
            if self.s[self.i] != '"':
                self.fail("a key must be a string")
            key = self.string()
            self.blank()
            if self.i >= self.n or self.s[self.i] != ":":
                self.fail("expected ':' after a key")
            self.i += 1
            members[key] = self.value(depth + 1)
            self.blank()
            if self.i >= self.n:
                self.fail("unexpected end of input")
            c = self.s[self.i]
            self.i += 1
            if c == "}":
                return Value("object", line, members)
            if c != ",":
                self.fail("expected ',' or '}'")
            self.blank()
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                return Value("object", line, members)

    def arr(self, depth, line):
        self.i += 1
        items = []
        self.blank()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return Value("array", line, items)
        while True:
            items.append(self.value(depth + 1))
            self.blank()
            if self.i >= self.n:
                self.fail("unexpected end of input")
            c = self.s[self.i]
            self.i += 1
            if c == "]":
                return Value("array", line, items)
            if c != ",":
                self.fail("expected ',' or ']'")
            self.blank()
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                return Value("array", line, items)

    def string(self):
        s, n = self.s, self.n
        self.i += 1
        out, start = [], self.i
        while True:
            if self.i >= n:
                self.fail("unterminated string")
            c = s[self.i]
            if c == '"':
                out.append(s[start:self.i])
                self.i += 1
                return "".join(out)
            if c == "\n" or c == "\r":
                self.fail("unterminated string")
            if c != "\\":
                self.i += 1
                continue
            out.append(s[start:self.i])
            e = s[self.i + 1:self.i + 2]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                self.i += 2
            elif e == "u" and _HEX4_RE.match(s, self.i + 2):
                code = int(s[self.i + 2:self.i + 6], 16)
                self.i += 6
                if 0xD800 <= code < 0xDC00 and s.startswith("\\u", self.i) and _HEX4_RE.match(s, self.i + 2):
                    low = int(s[self.i + 2:self.i + 6], 16)
                    if 0xDC00 <= low < 0xE000:           # a surrogate pair is one character
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                        self.i += 6
                out.append(chr(code))
            else:
                self.fail("invalid escape in a string")
            start = self.i


def parse_jsonc(text):
    """The JSON value of `text` (a leading BOM, // and /* */ comments and
    trailing commas allowed; lines counted at "\\n"). Raises JsoncError."""
    r = _Reader(text[1:] if text.startswith("﻿") else text)
    v = r.value(0)
    r.blank()
    if r.i < r.n:
        r.fail("unexpected content after the value")
    return v


# ---- the commands each file makes its tool run ----
def _get(v, key, kind=None):
    """Member `key` of object `v` (of `kind` when given), else None."""
    if v is None or v.kind != "object":
        return None
    m = v.value.get(key)
    return m if m is not None and (kind is None or m.kind == kind) else None


def _text(v):
    """A string Value's text when it is not blank, else None."""
    return v.value if v is not None and v.kind == "string" and v.value.strip() else None


def _quote(arg):
    if arg and not _NEEDS_QUOTES_RE.search(arg):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _arg_text(v):
    """A task argument: a string, or VS Code's {value, quoting} form."""
    if v.kind == "string":
        return v.value
    inner = _get(v, "value", "string")
    return inner.value if inner is not None else None


def _command_line(command, args):
    """command (a string Value, or VS Code's {value, quoting}) with its args
    (an array Value, or None), as one shell line; None when there is none."""
    if command is None:
        return None
    head = _arg_text(command) if command.kind in ("string", "object") else None
    if head is None or not head.strip():
        return None
    parts = [head]
    if args is not None and args.kind == "array":
        for a in args.value:
            t = _arg_text(a) if a.kind in ("string", "object") else None
            if t is not None:
                parts.append(_quote(t))
    return " ".join(parts)


def _entry(line, trigger, command):
    return {"line": line, "trigger": trigger, "command": command}


def _task_label(task):
    t = _text(_get(task, "label")) or _text(_get(task, "taskName"))
    return f'the task "{t}"' if t is not None else "an unnamed task"


def _task_entries(task, trigger, out):
    """The command of one task and of each platform's variant of it."""
    seen = set()
    command, args = _get(task, "command"), _get(task, "args", "array")
    script = _get(task, "script", "string")
    base = _command_line(command, args)
    if base is None and _text(_get(task, "type")) == "npm" and _text(script) is not None:
        base = "npm run " + _quote(script.value)
        command = script
    if base is not None:
        seen.add(base)
        out.append(_entry(command.line, trigger, base))
    for key, where in _PLATFORMS:
        plat = _get(task, key, "object")
        if plat is None:
            continue
        pcmd = _get(plat, "command")
        pargs = _get(plat, "args", "array")
        line = pcmd if pcmd is not None else pargs
        if line is None:
            continue
        cmd = _command_line(pcmd if pcmd is not None else command, pargs if pargs is not None else args)
        if cmd is not None and cmd not in seen:
            seen.add(cmd)
            out.append(_entry(line.line, f"{trigger} ({where})", cmd))
    if base is None and len(seen) == 0:
        kind = _text(_get(task, "type"))
        out.append(_entry(task.line, trigger + (f" (a {kind} task)" if kind else ""), None))


def _vscode_tasks(root, out):
    tasks = _get(root, "tasks", "array")
    if tasks is None:
        return
    items = [t for t in tasks.value if t.kind == "object"]
    by_label = {}
    for t in items:
        label = _text(_get(t, "label")) or _text(_get(t, "taskName"))
        if label is not None and label not in by_label:
            by_label[label] = t
    queue, seen = [], set()
    for t in items:
        run_on = _get(_get(t, "runOptions", "object"), "runOn", "string")
        if run_on is not None and run_on.value == "folderOpen":
            queue.append((t, None))
    k = 0
    while k < len(queue) and len(seen) < MAX_TASKS:
        task, parent = queue[k]
        k += 1
        if id(task) in seen:
            continue
        seen.add(id(task))
        trigger = "Opening this folder in VS Code runs " + _task_label(task)
        if parent is not None:
            trigger += f", which {parent} depends on"
        _task_entries(task, trigger, out)
        deps = _get(task, "dependsOn")
        names = [deps] if deps is not None and deps.kind == "string" else (
            deps.value if deps is not None and deps.kind == "array" else [])
        for d in names:
            dep = by_label.get(d.value) if d.kind == "string" else None
            if dep is not None:
                queue.append((dep, _task_label(task)))


def _hooks(root, tool, out, grouped):
    """A hooks object: event -> [group] where a group is {matcher, hooks:
    [{type, command}]} (Claude Code, Gemini CLI), or event -> [{command}]
    (Cursor)."""
    hooks = _get(root, "hooks", "object")
    if hooks is None:
        return
    for event, groups in hooks.value.items():
        if groups.kind != "array":
            continue
        for g in groups.value:
            if g.kind != "object":
                continue
            matcher = _text(_get(g, "matcher"))
            trigger = f"{tool} runs a hook on {event}" + (
                f' for "{matcher}"' if matcher is not None and matcher != "*" else "")
            inner = _get(g, "hooks", "array") if grouped else None
            for h in (inner.value if inner is not None else ([] if grouped else [g])):
                kind = _text(_get(h, "type"))
                command = _get(h, "command", "string")
                if (kind is None or kind == "command") and _text(command) is not None:
                    out.append(_entry(command.line, trigger, command.value))


def _mcp_servers(servers, tool, out):
    if servers is None:
        return
    for name, server in servers.value.items():
        command = _get(server, "command", "string")
        if _text(command) is None:
            continue
        cmd = _command_line(command, _get(server, "args", "array"))
        out.append(_entry(command.line, f'{tool} starts the MCP server "{name}"', cmd))


def entries(kind, tool, text):
    """-> (entries, error): the commands a settings file of `kind` (see
    config_kind) makes `tool` run, each {line, trigger, command} (command None
    when the entry names none, as a typescript task), in document order; and
    (line, reason) when the file cannot be read, None otherwise. A file that
    cannot be read but names what it would run has error set and no entries;
    one that names nothing gives ([], None)."""
    try:
        root = parse_jsonc(text)
    except JsoncError as exc:
        marker = _MARKERS[kind]
        return [], ((exc.line, exc.reason) if marker.search(text) else None)
    out = []
    if root.kind != "object":
        return out, None
    if kind == "vscode-tasks":
        _vscode_tasks(root, out)
    elif kind == "claude":
        _hooks(root, tool, out, grouped=True)
        status = _get(root, "statusLine", "object")
        command = _get(status, "command", "string")
        stype = _text(_get(status, "type"))
        if _text(command) is not None and (stype is None or stype == "command"):
            out.append(_entry(command.line, f"{tool} runs a status-line command", command.value))
        for key in _CLAUDE_HELPERS:
            helper = _get(root, key, "string")
            if _text(helper) is not None:
                out.append(_entry(helper.line, f"{tool} runs its {key} command", helper.value))
    elif kind == "gemini":
        _hooks(root, tool, out, grouped=True)
        _mcp_servers(_get(root, "mcpServers", "object"), tool, out)
    elif kind == "cursor-hooks":
        _hooks(root, tool, out, grouped=False)
    elif kind == "mcp":
        _mcp_servers(_get(root, "mcpServers", "object"), tool, out)
    elif kind == "vscode-mcp":
        _mcp_servers(_get(root, "servers", "object"), tool, out)
    return out, None


# ---- following a command to the files it runs ----
# Directory variables the tools set before running a command, read as the
# folder the settings file belongs to: VS Code's ${workspaceFolder} (also
# ${workspaceFolder:name} and the old ${workspaceRoot}), Claude Code's and
# Gemini CLI's $CLAUDE_PROJECT_DIR / $GEMINI_PROJECT_DIR.
_DIR_VARS_RE = re.compile(
    r"\$\{workspace(?:Folder(?::[^}\n]{0,200})?|Root)\}"
    r"|\$\{(?:CLAUDE|GEMINI)_PROJECT_DIR\}|\$(?:CLAUDE|GEMINI)_PROJECT_DIR\b|%(?:CLAUDE|GEMINI)_PROJECT_DIR%")


def local_command(command):
    """The command with the folder variables its tool sets replaced by '.', so
    core.follow_hook reads `"$CLAUDE_PROJECT_DIR"/.claude/x.sh` as
    ./.claude/x.sh."""
    return _DIR_VARS_RE.sub(".", command)
