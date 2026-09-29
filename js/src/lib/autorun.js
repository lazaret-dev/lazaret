// Editor and AI-agent settings that run commands on their own (0.1.7) — twin
// of lazaret.scanner.autorun. VS Code's folder-open tasks, the hooks of
// Claude Code, Cursor and Gemini CLI, and the MCP servers an agent starts:
// which files these are (configKind), a JSON-with-comments reader that keeps
// each value's line (parseJsonc), and the commands each file makes its tool
// run (entries). The scanner reports them as SC-AUTORUN (scanner/scan.js).

import { pyRe, pyStrip } from "./pycompat.js";

/** Nesting deeper than this is not read (a JsoncError). */
export const MAX_DEPTH = 256;
/** Tasks a folder-open task's dependsOn chain is followed to, per file. */
export const MAX_TASKS = 100;

const KINDS = new Map([
  [".vscode/tasks.json", ["vscode-tasks", "VS Code"]],
  [".vscode/mcp.json", ["vscode-mcp", "VS Code"]],
  [".claude/settings.json", ["claude", "Claude Code"]],
  [".claude/settings.local.json", ["claude", "Claude Code"]],
  [".cursor/hooks.json", ["cursor-hooks", "Cursor"]],
  [".cursor/mcp.json", ["mcp", "Cursor"]],
  [".gemini/settings.json", ["gemini", "Gemini CLI"]],
]);
const MARKERS = {
  "vscode-tasks": /folderOpen/,
  "vscode-mcp": /"command"/,
  claude: /"(?:hooks|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)"/,
  "cursor-hooks": /"command"/,
  mcp: /"command"/,
  gemini: /"(?:hooks|command)"/,
};
const CLAUDE_HELPERS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"];
const PLATFORMS = [["windows", "on Windows"], ["linux", "on Linux"], ["osx", "on macOS"]];
const NEEDS_QUOTES_SRC = String.raw`[\s"'\\$` + "`" + String.raw`;&|<>()]`;
const NEEDS_QUOTES_RE = pyRe(NEEDS_QUOTES_SRC);
const NUMBER_SRC = String.raw`-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`;
const NUMBER_RE = new RegExp(NUMBER_SRC, "y");
const HEX4_RE = /[0-9A-Fa-f]{4}/y;
const ESCAPES = new Map([['"', '"'], ["\\", "\\"], ["/", "/"], ["b", "\b"], ["f", "\f"], ["n", "\n"], ["r", "\r"], ["t", "\t"]]);
const WS = new Set([" ", "\t", "\n", "\r"]);

/** Python's str.lower() for the ASCII-only names compared here. */
const lower = (s) => s.toLowerCase();

/** [kind, tool] for a settings file that makes a tool run commands, by its path, else null (autorun.config_kind). */
export function configKind(path) {
  const parts = path.replaceAll("\\", "/").split("/");
  if (lower(parts[parts.length - 1]) === ".mcp.json") return ["mcp", "Claude Code"];
  if (parts.length < 2) return null;
  return KINDS.get(lower(`${parts[parts.length - 2]}/${parts[parts.length - 1]}`)) ?? null;
}

/** The folder a settings file belongs to ('/'-separated, '' for the root) (autorun.owner_dir). */
export function ownerDir(path) {
  const parts = path.replaceAll("\\", "/").split("/");
  const keep = lower(parts[parts.length - 1]) === ".mcp.json" ? parts.slice(0, -1) : parts.slice(0, -2);
  return keep.join("/");
}

// ---- a JSON reader that keeps lines (comments and trailing commas allowed) ----
export class JsoncError extends Error {
  constructor(line, reason) {
    super(`line ${line}: ${reason}`);
    this.line = line;
    this.reason = reason;
  }
}

/** A JSON value: kind object (value: Map key -> Value), array, string, number (its text), true, false or null. */
export class Value {
  constructor(kind, line, value = null) {
    this.kind = kind;
    this.line = line;
    this.value = value;
  }
}

const charName = (s, i) => `U+${s.codePointAt(i).toString(16).toUpperCase().padStart(4, "0")}`;

class Reader {
  constructor(text) {
    this.s = text;
    this.n = text.length;
    this.i = 0;
    this.line = 1;
  }

  fail(reason, line = null) {
    throw new JsoncError(line ?? this.line, reason);
  }

  blank() {
    const { s, n } = this;
    while (this.i < n) {
      const c = s[this.i];
      if (WS.has(c)) {
        if (c === "\n") this.line++;
        this.i++;
      } else if (s.startsWith("//", this.i)) {
        const end = s.indexOf("\n", this.i);
        this.i = end < 0 ? n : end;
      } else if (s.startsWith("/*", this.i)) {
        const end = s.indexOf("*/", this.i + 2);
        if (end < 0) this.fail("unterminated comment");
        for (let k = s.indexOf("\n", this.i); k !== -1 && k < end; k = s.indexOf("\n", k + 1)) this.line++;
        this.i = end + 2;
      } else {
        return;
      }
    }
  }

  value(depth) {
    this.blank();
    if (this.i >= this.n) this.fail("unexpected end of input");
    if (depth > MAX_DEPTH) this.fail("nesting too deep");
    const c = this.s[this.i];
    const line = this.line;
    if (c === "{") return this.obj(depth, line);
    if (c === "[") return this.arr(depth, line);
    if (c === '"') return new Value("string", line, this.string());
    for (const word of ["true", "false", "null"]) {
      if (this.s.startsWith(word, this.i)) {
        this.i += word.length;
        return new Value(word, line);
      }
    }
    NUMBER_RE.lastIndex = this.i;
    const m = NUMBER_RE.exec(this.s);
    if (m) {
      this.i += m[0].length;
      return new Value("number", line, m[0]);
    }
    return this.fail("unexpected character " + charName(this.s, this.i));
  }

  obj(depth, line) {
    this.i++;
    const members = new Map();
    this.blank();
    if (this.i < this.n && this.s[this.i] === "}") {
      this.i++;
      return new Value("object", line, members);
    }
    for (;;) {
      this.blank();
      if (this.i >= this.n) this.fail("unexpected end of input");
      if (this.s[this.i] !== '"') this.fail("a key must be a string");
      const key = this.string();
      this.blank();
      if (this.i >= this.n || this.s[this.i] !== ":") this.fail("expected ':' after a key");
      this.i++;
      members.set(key, this.value(depth + 1));
      this.blank();
      if (this.i >= this.n) this.fail("unexpected end of input");
      const c = this.s[this.i++];
      if (c === "}") return new Value("object", line, members);
      if (c !== ",") this.fail("expected ',' or '}'");
      this.blank();
      if (this.i < this.n && this.s[this.i] === "}") {
        this.i++;
        return new Value("object", line, members);
      }
    }
  }

  arr(depth, line) {
    this.i++;
    const items = [];
    this.blank();
    if (this.i < this.n && this.s[this.i] === "]") {
      this.i++;
      return new Value("array", line, items);
    }
    for (;;) {
      items.push(this.value(depth + 1));
      this.blank();
      if (this.i >= this.n) this.fail("unexpected end of input");
      const c = this.s[this.i++];
      if (c === "]") return new Value("array", line, items);
      if (c !== ",") this.fail("expected ',' or ']'");
      this.blank();
      if (this.i < this.n && this.s[this.i] === "]") {
        this.i++;
        return new Value("array", line, items);
      }
    }
  }

  string() {
    const { s, n } = this;
    this.i++;
    const out = [];
    let start = this.i;
    for (;;) {
      if (this.i >= n) this.fail("unterminated string");
      const c = s[this.i];
      if (c === '"') {
        out.push(s.slice(start, this.i));
        this.i++;
        return out.join("");
      }
      if (c === "\n" || c === "\r") this.fail("unterminated string");
      if (c !== "\\") {
        this.i++;
        continue;
      }
      out.push(s.slice(start, this.i));
      const e = s.slice(this.i + 1, this.i + 2);
      HEX4_RE.lastIndex = this.i + 2;
      if (ESCAPES.has(e)) {
        out.push(ESCAPES.get(e));
        this.i += 2;
      } else if (e === "u" && HEX4_RE.test(s)) {
        let code = parseInt(s.slice(this.i + 2, this.i + 6), 16);
        this.i += 6;
        HEX4_RE.lastIndex = this.i + 2;
        if (code >= 0xd800 && code < 0xdc00 && s.startsWith("\\u", this.i) && HEX4_RE.test(s)) {
          const low = parseInt(s.slice(this.i + 2, this.i + 6), 16);
          if (low >= 0xdc00 && low < 0xe000) {             // a surrogate pair is one character
            code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
            this.i += 6;
          }
        }
        out.push(code > 0xffff ? String.fromCodePoint(code) : String.fromCharCode(code));
      } else {
        this.fail("invalid escape in a string");
      }
      start = this.i;
    }
  }
}

/** The JSON value of text (a BOM, comments and trailing commas allowed). Throws JsoncError (autorun.parse_jsonc). */
export function parseJsonc(text) {
  const r = new Reader(text.startsWith("﻿") ? text.slice(1) : text);
  const v = r.value(0);
  r.blank();
  if (r.i < r.n) r.fail("unexpected content after the value");
  return v;
}

// ---- the commands each file makes its tool run ----
function get(v, key, kind = null) {
  if (v === null || v === undefined || v.kind !== "object") return null;
  const m = v.value.get(key);
  return m !== undefined && (kind === null || m.kind === kind) ? m : null;
}

const text = (v) => (v !== null && v.kind === "string" && pyStrip(v.value) ? v.value : null);

function quote(arg) {
  if (arg && !NEEDS_QUOTES_RE.test(arg)) return arg;
  return `"${arg.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function argText(v) {
  if (v.kind === "string") return v.value;
  const inner = get(v, "value", "string");
  return inner !== null ? inner.value : null;
}

function commandLine(command, args) {
  if (command === null) return null;
  const head = command.kind === "string" || command.kind === "object" ? argText(command) : null;
  if (head === null || !pyStrip(head)) return null;
  const parts = [head];
  if (args !== null && args.kind === "array") {
    for (const a of args.value) {
      const t = a.kind === "string" || a.kind === "object" ? argText(a) : null;
      if (t !== null) parts.push(quote(t));
    }
  }
  return parts.join(" ");
}

const entry = (line, trigger, command) => ({ line, trigger, command });

function taskLabel(task) {
  const t = text(get(task, "label")) ?? text(get(task, "taskName"));
  return t !== null ? `the task "${t}"` : "an unnamed task";
}

function taskEntries(task, trigger, out) {
  const seen = new Set();
  let command = get(task, "command");
  const args = get(task, "args", "array");
  const script = get(task, "script", "string");
  let base = commandLine(command, args);
  if (base === null && text(get(task, "type")) === "npm" && text(script) !== null) {
    base = "npm run " + quote(script.value);
    command = script;
  }
  if (base !== null) {
    seen.add(base);
    out.push(entry(command.line, trigger, base));
  }
  for (const [key, where] of PLATFORMS) {
    const plat = get(task, key, "object");
    if (plat === null) continue;
    const pcmd = get(plat, "command");
    const pargs = get(plat, "args", "array");
    const line = pcmd !== null ? pcmd : pargs;
    if (line === null) continue;
    const cmd = commandLine(pcmd !== null ? pcmd : command, pargs !== null ? pargs : args);
    if (cmd !== null && !seen.has(cmd)) {
      seen.add(cmd);
      out.push(entry(line.line, `${trigger} (${where})`, cmd));
    }
  }
  if (base === null && seen.size === 0) {
    const kind = text(get(task, "type"));
    out.push(entry(task.line, trigger + (kind ? ` (a ${kind} task)` : ""), null));
  }
}

function vscodeTasks(root, out) {
  const tasks = get(root, "tasks", "array");
  if (tasks === null) return;
  const items = tasks.value.filter((t) => t.kind === "object");
  const byLabel = new Map();
  for (const t of items) {
    const label = text(get(t, "label")) ?? text(get(t, "taskName"));
    if (label !== null && !byLabel.has(label)) byLabel.set(label, t);
  }
  const queue = [];
  const seen = new Set();
  for (const t of items) {
    const runOn = get(get(t, "runOptions", "object"), "runOn", "string");
    if (runOn !== null && runOn.value === "folderOpen") queue.push([t, null]);
  }
  for (let k = 0; k < queue.length && seen.size < MAX_TASKS;) {
    const [task, parent] = queue[k++];
    if (seen.has(task)) continue;
    seen.add(task);
    let trigger = "Opening this folder in VS Code runs " + taskLabel(task);
    if (parent !== null) trigger += `, which ${parent} depends on`;
    taskEntries(task, trigger, out);
    const deps = get(task, "dependsOn");
    const names = deps !== null && deps.kind === "string" ? [deps] : (deps !== null && deps.kind === "array" ? deps.value : []);
    for (const d of names) {
      const dep = d.kind === "string" ? byLabel.get(d.value) : undefined;
      if (dep !== undefined) queue.push([dep, taskLabel(task)]);
    }
  }
}

function hooks(root, tool, out, grouped) {
  const all = get(root, "hooks", "object");
  if (all === null) return;
  for (const [event, groups] of all.value) {
    if (groups.kind !== "array") continue;
    for (const g of groups.value) {
      if (g.kind !== "object") continue;
      const matcher = text(get(g, "matcher"));
      const trigger = `${tool} runs a hook on ${event}` + (matcher !== null && matcher !== "*" ? ` for "${matcher}"` : "");
      const inner = grouped ? get(g, "hooks", "array") : null;
      for (const h of inner !== null ? inner.value : (grouped ? [] : [g])) {
        const kind = text(get(h, "type"));
        const command = get(h, "command", "string");
        if ((kind === null || kind === "command") && text(command) !== null) out.push(entry(command.line, trigger, command.value));
      }
    }
  }
}

function mcpServers(servers, tool, out) {
  if (servers === null) return;
  for (const [name, server] of servers.value) {
    const command = get(server, "command", "string");
    if (text(command) === null) continue;
    out.push(entry(command.line, `${tool} starts the MCP server "${name}"`, commandLine(command, get(server, "args", "array"))));
  }
}

/**
 * [entries, error]: the commands a settings file of `kind` makes `tool` run,
 * each {line, trigger, command} (command null when the entry names none), in
 * document order; and [line, reason] when the file cannot be read but names
 * what it would run, else null (autorun.entries).
 */
export function entries(kind, tool, source) {
  let root;
  try {
    root = parseJsonc(source);
  } catch (e) {
    if (!(e instanceof JsoncError)) throw e;
    return [[], MARKERS[kind].test(source) ? [e.line, e.reason] : null];
  }
  const out = [];
  if (root.kind !== "object") return [out, null];
  if (kind === "vscode-tasks") {
    vscodeTasks(root, out);
  } else if (kind === "claude") {
    hooks(root, tool, out, true);
    const status = get(root, "statusLine", "object");
    const command = get(status, "command", "string");
    const stype = text(get(status, "type"));
    if (text(command) !== null && (stype === null || stype === "command")) {
      out.push(entry(command.line, `${tool} runs a status-line command`, command.value));
    }
    for (const key of CLAUDE_HELPERS) {
      const helper = get(root, key, "string");
      if (text(helper) !== null) out.push(entry(helper.line, `${tool} runs its ${key} command`, helper.value));
    }
  } else if (kind === "gemini") {
    hooks(root, tool, out, true);
    mcpServers(get(root, "mcpServers", "object"), tool, out);
  } else if (kind === "cursor-hooks") {
    hooks(root, tool, out, false);
  } else if (kind === "mcp") {
    mcpServers(get(root, "mcpServers", "object"), tool, out);
  } else if (kind === "vscode-mcp") {
    mcpServers(get(root, "servers", "object"), tool, out);
  }
  return [out, null];
}

// ---- following a command to the files it runs ----
const DIR_VARS_SRC =
  String.raw`\$\{workspace(?:Folder(?::[^}\n]{0,200})?|Root)\}` +
  String.raw`|\$\{(?:CLAUDE|GEMINI)_PROJECT_DIR\}|\$(?:CLAUDE|GEMINI)_PROJECT_DIR\b|%(?:CLAUDE|GEMINI)_PROJECT_DIR%`;
const DIR_VARS_RE = pyRe(DIR_VARS_SRC, "g");

/** The command with the folder variables its tool sets replaced by "." (autorun.local_command). */
export const localCommand = (command) => command.replace(DIR_VARS_RE, ".");

/** The module's pattern text and limits, for the parity test (autorun's). */
export const PY_TWINS = {
  patterns: { _DIR_VARS_RE: DIR_VARS_SRC, _NEEDS_QUOTES_RE: NEEDS_QUOTES_SRC, _NUMBER_RE: NUMBER_SRC },
  limits: { MAX_DEPTH, MAX_TASKS },
};
