"""Editor and AI-agent settings that run commands on their own (0.1.7).

Opening a folder in VS Code runs its folder-open tasks; Claude Code, Cursor
and Gemini CLI run a project's hooks as a session starts and around the
agent's tool calls; an agent starts the MCP servers a project lists. None of
it asks each time. Mini Shai-Hulud and the keyv wave (May and August 2026)
committed a SessionStart hook and a folder-open task to every repository they
reached, each running a copy of the worm's loader, so opening a checkout ran
the worm (core.scan_config_file reports them: SC-AUTORUN).

The reading is the native engine's since 0.1.9 (BR-7 step 2:
`rust/crates/lazaret-engine/src/autorun.rs`, the `autorun_*` calls), as it is
for the npm package; until then this module and js/src/lib/autorun.js were
twins. It keeps the names the package calls: which files these are
(config_kind), a JSON-with-comments reader that keeps each value's line
(parse_jsonc), the commands each file makes its tool run (entries) and the
command with its folder variables read as the folder (local_command).
"""
from . import _native, engine

# The pack's limits, read when first asked (importing never needs the engine): MAX_DEPTH (nesting deeper than this
# is not read: a JsoncError) and MAX_TASKS (tasks a folder-open task's dependsOn chain is followed to, per file).
_LAZY = {"MAX_DEPTH": "_AUTORUN_MAX_DEPTH", "MAX_TASKS": "_AUTORUN_MAX_TASKS"}


def __getattr__(name):
    if name in _LAZY:
        value = engine.pack_value(_LAZY[name])
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def config_kind(path):
    """(kind, tool) for a settings file that makes a tool run commands, by its
    path ('/' or os separators), else None."""
    got = _native.call("autorun_kind", {}, path)
    return tuple(got) if got is not None else None


def owner_dir(path):
    """The folder a settings file belongs to ('/'-separated, '' for the root):
    the parent of its .vscode / .claude / .cursor / .gemini directory, or the
    directory of a .mcp.json. Its commands run there."""
    return _native.call("autorun_owner", {}, path)


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


def _value(v):
    kind, line, inner = v["k"], v["l"], v["v"]
    if kind == "object":
        return Value(kind, line, {k: _value(x) for k, x in inner})
    if kind == "array":
        return Value(kind, line, [_value(x) for x in inner])
    return Value(kind, line, inner)


def parse_jsonc(text):
    """The JSON value of `text` (a leading BOM, // and /* */ comments and
    trailing commas allowed; lines counted at "\\n"). Raises JsoncError."""
    got = _native.call("autorun_jsonc", {}, text)
    if "error" in got:
        raise JsoncError(*got["error"])
    return _value(got["ok"])


def entries(kind, tool, text):
    """-> (entries, error): the commands a settings file of `kind` (see
    config_kind) makes `tool` run, each {line, trigger, command} (command None
    when the entry names none, as a typescript task), in document order; and
    (line, reason) when the file cannot be read, None otherwise. A file that
    cannot be read but names what it would run has error set and no entries;
    one that names nothing gives ([], None)."""
    got = _native.call("autorun_entries", {"kind": kind, "tool": tool}, text)
    error = got["error"]
    return got["entries"], (tuple(error) if error is not None else None)


def local_command(command):
    """The command with the folder variables its tool sets replaced by '.', so
    core.follow_hook reads `"$CLAUDE_PROJECT_DIR"/.claude/x.sh` as
    ./.claude/x.sh."""
    return _native.call("autorun_local_command", {}, command)
