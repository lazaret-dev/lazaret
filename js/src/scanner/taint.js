// Taint sources/sinks and sanitizer model — the Python engine's tables
// (lazaret.scanner.core TAINT_SOURCES / TAINT_SINKS / ASSIGN_RE /
// _FULL_SAN / _PARTIAL_SAN), pattern text verbatim, Python regex semantics.

import { pyRe, pyStrip, pyLstrip, pyRstrip } from "../lib/pycompat.js";

/* ---------------- Taint tracking (lightweight, intra-file) ---------------- */
export const TAINT_SOURCES = {
  // Flask / Werkzeug request data (query_string, get_data, stream, full_path
  // too) and Django's (GET, POST, COOKIES, META, FILES, body)
  py: pyRe(String.raw`request\.(args|form|values|json|data|cookies|headers|files|get_json|get_data|query_string|stream|full_path|GET|POST|COOKIES|META|FILES|body)|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\(`),
  js: pyRe(String.raw`req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams(?!\s*\(\s*\))|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\(`),
};
export const TAINT_SINKS = {
  py: [
    ["CMD", pyRe(String.raw`os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(`), "command injection", "CRITICAL", "CWE-78", "Validate/allowlist the value; pass args as a list with shell=False."],
    ["CODE", pyRe(String.raw`(?<![\w.])(eval|exec)\s*\(`), "code injection", "CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."],
    ["SQL", pyRe(String.raw`\.(execute|executemany)\s*\(`), "SQL injection", "BLOCKER", "CWE-89", "Use parameterized queries."],
    ["PATH", pyRe(String.raw`(?<![\w.])open\s*\(|(?:codecs|io|os)\.open\s*\(|send_file\s*\(|send_from_directory\s*\(|shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)\s*\(|os\.(?:remove|unlink|rmdir|removedirs|rename|replace|listdir|scandir)\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", pyRe(String.raw`requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\(`), "server-side request forgery", "MAJOR", "CWE-918", "Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", pyRe(String.raw`(?<![\w.])redirect\s*\(|flask\.redirect\s*\(|HttpResponse(?:Permanent)?Redirect\s*\(`), "open redirect", "MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
    ["SSTI", pyRe(String.raw`render_template_string\s*\(`), "template injection", "CRITICAL", "CWE-1336", "Pass data as template parameters, never into template source."],
    // a response body built from the value (Flask / Werkzeug, Django), or the
    // value marked as safe HTML; a Flask view's own `return` is checked too
    ["XSS", pyRe(String.raw`make_response\s*\(|(?<![\w.])Response\s*\(|(?<![\w.])HttpResponse\s*\(|(?<![\w.])Markup\s*\(|mark_safe\s*\(`), "cross-site scripting", "MAJOR", "CWE-79", "Escape the value (or render it through an autoescaping template) before it is returned."],
  ],
  js: [
    ["CMD", pyRe(String.raw`\b(exec|execSync|spawn|spawnSync)\s*\(`), "command injection", "CRITICAL", "CWE-78", "Use execFile/spawn with an args array; validate the value."],
    ["CODE", pyRe(String.raw`(?<![\w.])eval\s*\(|new\s+Function\s*\(`), "code injection", "CRITICAL", "CWE-95", "Never execute untrusted strings; use JSON.parse or a dispatch map."],
    ["SQL", pyRe(String.raw`\.(query|execute)\s*\(`), "SQL injection", "BLOCKER", "CWE-89", "Use placeholders with a parameter array."],
    ["PATH", pyRe(String.raw`\.(sendFile|download)\s*\(|readFile(Sync)?\s*\(|createReadStream\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", pyRe(String.raw`\bfetch\s*\(|axios(\.(get|post|put|delete|request))?\s*\(|https?\.(get|request)\s*\(`), "server-side request forgery", "MAJOR", "CWE-918", "Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", pyRe(String.raw`\.redirect\s*\(`), "open redirect", "MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
    ["XSS", pyRe(String.raw`\.innerHTML\s*=|document\.write\s*\(`), "cross-site scripting", "MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."],
  ],
};

// Spec 12: a Python annotated assignment `x: T = source` binds x (the
// optional `: T` part), and a JS destructuring declaration binds every name
// in its (one-level) pattern — twin of core.ASSIGN_RE / _assignment.
// An augmented assignment (`html += f"<p>{q}</p>"`) taints its target too.
export const ASSIGN_RE = {
  py: pyRe(String.raw`^\s*([A-Za-z_]\w*)\s*(?::[^=\n]*|[-+*/%&|^@]|//|\*\*|<<|>>)?=(?![=])\s*(.+)`),
  js: pyRe(String.raw`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>])\s*(.+)`),
};
// the augmented forms (`x += y`, `x ||= y`): the target keeps what it held
export const AUG_ASSIGN_RE = {
  py: pyRe(String.raw`^\s*[A-Za-z_]\w*\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)=`),
  js: pyRe(String.raw`^\s*[A-Za-z_$][\w$]*\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)=`),
};
// one-level object / array pattern: `{ a, b: c, d = 1, ...e }` / `[a, , b = 2, ...c]`
const JS_DESTRUCT_RE = pyRe(String.raw`^\s*(?:(?:const|let|var)\s+)?(\{[^{}]*\}|\[[^\[\]]*\])\s*=(?![=>])\s*(.+)`);
const JS_BINDING_RE = pyRe(String.raw`^[A-Za-z_$][\w$]*$`);
// Python 3.11 keyword.kwlist / softkwlist
const PY_KEYWORDS = new Set(["False", "None", "True", "and", "as", "assert", "async", "await", "break",
  "class", "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
  "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
  "while", "with", "yield"]);
const PY_SOFT_KEYWORDS = new Set(["_", "case", "match"]);

/** Names bound by a one-level JS destructuring pattern (twin of core._destructured_names). */
export function destructuredNames(pattern) {
  const names = [];
  for (let part of pattern.slice(1, -1).split(",")) {
    part = pyStrip(part);
    if (part.startsWith("...")) part = pyStrip(part.slice(3));
    else if (pattern[0] === "{" && part.includes(":")) part = pyStrip(part.slice(part.indexOf(":") + 1));
    part = pyStrip(part.split("=")[0]);
    if (JS_BINDING_RE.test(part)) names.push(part);
  }
  return names;
}

/** {names, rhs} of an assignment line, or null (twin of core._assignment). */
export function parseAssignment(line, lang) {
  const m = ASSIGN_RE[lang].exec(line);
  if (m) {
    const name = m[1];
    if (lang === "py" && (PY_KEYWORDS.has(name)
        || (PY_SOFT_KEYWORDS.has(name) && pyLstrip(line.slice(m.index + m[0].indexOf(name) + name.length)).startsWith(":")))) {
      return null;
    }
    return { names: [name], rhs: m[2] };
  }
  if (lang === "js") {
    const dm = JS_DESTRUCT_RE.exec(line);
    if (dm) {
      const names = destructuredNames(dm[1]);
      if (names.length) return { names, rhs: dm[2] };
    }
  }
  return null;
}

export const STRING_LIT_RE = pyRe(String.raw`\"[^\"]*\"|'[^']*'|` + "`[^`]*`", "g");

export const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/* Sanitizer model (SonarQube / Semgrep style). Full sanitizers (numeric
   coercion) cleanse every sink; partial ones clear a category. Body allows one
   nested-paren level so int(request.args.get("id")) is recognized. */
export const SAN_BODY = String.raw`(?:[^()]|\([^()]*\))*`;
export const FULL_SAN = {
  py: pyRe(String.raw`(?:int|float|bool|complex|uuid\.UUID|ipaddress\.ip_address)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
  js: pyRe(String.raw`(?:parseInt|parseFloat|Number)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
};
export const PARTIAL_SAN = {
  py: {
    CMD: pyRe(String.raw`(?:shlex|pipes)\.quote\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    // escape(), escape_html(), …; an autoescaping template and the JSON and
    // URL builders encode the value too. Not unescape().
    XSS: pyRe(String.raw`(?<!\w)(?:html\.escape|markupsafe\.escape|cgi\.escape|escape\w*|bleach\.clean|conditional_escape|format_html|render_template|jsonify|url_for)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`(?:os\.path\.basename|basename|secure_filename|safe_join)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    // url_for builds a URL on this site from an endpoint's name
    REDIR: pyRe(String.raw`(?<![\w.])(?:flask\.)?url_for\s*\(` + SAN_BODY + String.raw`\)`, "g"),
  },
  js: {
    XSS: pyRe(String.raw`(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    SQL: pyRe(String.raw`(?:mysql2?|pool|connection|conn|db)\.escape\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`path\.basename\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    CMD: pyRe(String.raw`(?:shellQuote|shell_quote)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
  },
};
// Flask's typed lookup, `request.args.get("page", 1, type=int)`, returns a
// number (or the default): a full sanitizer like int(…).
const TYPED_GET_RE = pyRe(String.raw`(?<![\w.])[A-Za-z_][\w.]*\.get(?:list)?\s*\(([^()]{0,256})\)`, "g");
const TYPED_ARG_RE = pyRe(String.raw`\btype\s*=\s*(?:int|float|bool)\b`);
export function neutralize(text, lang, suffix) {
  text = text.replace(FULL_SAN[lang], " ");
  if (lang === "py" && text.includes("type"))
    text = text.replace(TYPED_GET_RE, (m, args) => (TYPED_ARG_RE.test(args) ? " " : m));
  if (suffix && PARTIAL_SAN[lang] && PARTIAL_SAN[lang][suffix])
    text = text.replace(PARTIAL_SAN[lang][suffix], " ");
  return text;
}

/* What taint reads of a text (twin of core._taint_code): its string literals
   removed, except the fields of a Python f-string (`f"/srv/{name}"`, prefix
   f / rf / fr in either case) and of a JavaScript template literal no tag
   reads (`ls ${dir}` — a tagged sql`…${x}` template is parameterized): those
   are code whose value becomes part of the string. A field is the text
   between one-level braces; `{{` / `}}` in an f-string are literal braces. A
   Python literal's prefix (r, b, u, f or a pair) is part of the literal, not
   a name. */
const FIELD_RE = { py: pyRe(String.raw`\{([^{}]*)\}`, "g"), js: pyRe(String.raw`\$\{([^{}]*)\}`, "g") };
const PY_LIT_RE = pyRe(String.raw`(?:(?<![A-Za-z0-9_])([rRbBuUfF]{1,2}))?(\"[^\"]*\"|'[^']*'|` + "`[^`]*`)", "g");
const ASCII_WORD = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$");
const JS_TAG_KEYWORDS = new Set(["return", "typeof", "case", "in", "of", "yield", "await", "throw",
  "delete", "void", "else", "do", "new"]);
const fields = (lang, body) => [...body.matchAll(FIELD_RE[lang])].map((m) => m[1]).join(" ");

/** True when the backtick at `start` opens a tagged template (twin of core._js_tagged). */
export function jsTagged(text, start) {
  let j = start;
  while (j > 0 && (text[j - 1] === " " || text[j - 1] === "\t")) j--;
  if (j === 0 || !(ASCII_WORD.has(text[j - 1]) || text[j - 1] === ")" || text[j - 1] === "]")) return false;
  let k = j;
  while (k > 0 && ASCII_WORD.has(text[k - 1])) k--;
  return !JS_TAG_KEYWORDS.has(text.slice(k, j));
}

/** `text` without its string literals, as taint reads it (twin of core._taint_code). */
export function taintCode(text, lang) {
  if (lang === "py") {
    return text.replace(PY_LIT_RE, (m, prefix, lit) => {
      if (!["f", "rf", "fr"].includes((prefix ?? "").toLowerCase()) || lit[0] === "`") return "";
      return " " + fields("py", lit.slice(1, -1).replaceAll("{{", "  ").replaceAll("}}", "  ")) + " ";
    });
  }
  return text.replace(STRING_LIT_RE, (lit, offset) => {
    if (lit[0] !== "`" || jsTagged(text, offset)) return "";
    return " " + fields("js", lit.slice(1, -1)) + " ";
  });
}

/* A statement taint reads may run over several lines (twin of core's): a
   line whose brackets stay open is read with the lines that continue it — at
   most TAINT_JOIN_MAX_LINES of them and TAINT_JOIN_MAX_CHARS of their text. */
export const TAINT_JOIN_MAX_LINES = 8;
export const TAINT_JOIN_MAX_CHARS = 4000;
export const BRACKET_DELTA = { "(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1 };
/** Brackets `code` opens and leaves open, string literals not counted (core._bracket_depth). */
export function bracketDepth(code) {
  let d = 0;
  for (const ch of code.replace(STRING_LIT_RE, "")) d += BRACKET_DELTA[ch] ?? 0;
  return d;
}
/** The first n code points of s. */
export function cpHead(s, n) {
  if (s.length <= n) return s;
  let i = 0;
  for (let c = 0; c < n && i < s.length; c++) {
    const u = s.charCodeAt(i);
    i += u >= 0xd800 && u <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return s.slice(0, i);
}

/** Index of the comma or closing bracket that ends the argument starting at `start` (core._arg_end). */
export function argsEnd(text, start) {
  let depth = 0, i = start;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const j = text.indexOf(ch, i + 1);
      if (j < 0) return n;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return i;
      depth--;
    } else if (ch === "," && depth === 0) return i;
    i++;
  }
  return n;
}
/** Index of the bracket that closes a call whose arguments start at `start` (core._call_close). */
export function callClose(text, start) {
  for (;;) {
    const end = argsEnd(text, start);
    if (end >= text.length || text[end] !== ",") return end;
    start = end + 1;
  }
}
/** A call's first argument; a parenthesized tuple is read as its first element (core._first_arg). */
export function firstArg(text) {
  const arg = text.slice(0, argsEnd(text, 0));
  const s = pyLstrip(arg);
  if (s.startsWith("(")) {
    const k = argsEnd(s, 1);
    if (k < s.length && s[k] === ",") return s.slice(1, k);
  }
  return arg;
}
// a keyword argument that names no target (core._KWARG_RE)
const KWARG_RE = pyRe(String.raw`^\s*(?!(?:url|uri|file|filename|path|path_or_file|args|cmd|command|src|dst|source|destination)\s*=)[A-Za-z_]\w*\s*=(?!=)`);
/** A call's arguments without its keyword arguments (core._positional_args). */
export function positionalArgs(text) {
  const out = [];
  let i = 0;
  for (;;) {
    const end = argsEnd(text, i);
    const arg = text.slice(i, end);
    if (!KWARG_RE.test(arg)) out.push(arg);
    if (end >= text.length || text[end] !== ",") return out.join(",");
    i = end + 1;
  }
}
/** `text` up to the end of a sink's arguments (core._extent). */
export function extent(text) {
  let depth = 0, i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const j = text.indexOf(ch, i + 1);
      if (j < 0) return text;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return text.slice(0, i);
      depth--;
    } else if (ch === ";" && depth === 0) return text.slice(0, i);
    i++;
  }
  return text;
}
// Which arguments of a built-in sink carry the injection (core._SINK_ARGS).
const SINK_ARGS = new Map([
  ...TAINT_SINKS.py.filter((r) => ["SQL", "XSS", "REDIR", "SSTI", "CODE"].includes(r[0])).map((r) => [r[1], "first"]),
  ...TAINT_SINKS.py.filter((r) => ["CMD", "PATH", "SSRF"].includes(r[0])).map((r) => [r[1], "positional"]),
  ...TAINT_SINKS.js.filter((r) => r[0] === "SQL").map((r) => [r[1], "first"]),
]);
// A redirect to a path on this site (core._SAME_SITE_RE).
const SAME_SITE_RE = pyRe(String.raw`^\s*[rRuUfF]{0,2}["'` + "`" + String.raw`]/(?![/\\])`);
/** `args` without the arguments that redirect to this site (core._offsite_args). */
export function offsiteArgs(args) {
  const out = [];
  let i = 0;
  for (;;) {
    const end = argsEnd(args, i);
    const arg = args.slice(i, end);
    if (!SAME_SITE_RE.test(arg)) out.push(arg);
    if (end >= args.length || args[end] !== ",") return out.join(",");
    i = end + 1;
  }
}
/** The part of a sink's arguments that carries the injection (core._sink_args). */
export function sinkArgs(text, sinkRe, lang, suffix) {
  const mode = SINK_ARGS.get(sinkRe);
  const args = mode === "first" ? firstArg(text) : mode === "positional" ? positionalArgs(text) : extent(text);
  return suffix === "REDIR" ? offsiteArgs(args) : args;
}

/* Path-traversal guards (core._GUARD_*): a condition that rejects a value
   holding '..' or checks that it stays under a base directory, on a branch
   that leaves. */
const GUARD_BLOCK_LINES = 12;
export const GUARD_IF_RE = { py: pyRe(String.raw`^\s*(?:el)?if\b`), js: pyRe(String.raw`^\s*(?:\}\s*)?(?:else\s+)?if\s*\(`) };
const DOTDOT = String.raw`(?:'\.\.[/\\]{0,2}'|"\.\.[/\\]{0,2}"|` + "`" + String.raw`\.\.[/\\]{0,2}` + "`)";
const GUARD_VAR_RES = {
  py: [pyRe(DOTDOT + String.raw`\s+(?:not\s+)?in\s+([A-Za-z_]\w*)(?![\w.(\[])`, "g"),
    pyRe(String.raw`(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(?:startswith|is_relative_to)\s*\(\s*(?![\s'"])`, "g"),
    pyRe(String.raw`(?:realpath|abspath|normpath)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*startswith\s*\(\s*(?![\s'"])`, "g")],
  js: [pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:includes|indexOf)\s*\(\s*` + DOTDOT + String.raw`\s*\)`, "g"),
    pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*startsWith\s*\(\s*(?![\s'"` + "`])", "g")],
};
const GUARD_COMMONPATH_RE = pyRe(String.raw`commonpath\s*\(\s*[\[(]([^\[\]()]{0,256})[\])]`, "g");
const GUARD_NAME_RE = pyRe(String.raw`^\s*([A-Za-z_]\w*)\s*$`);
const GUARD_EXIT_RE = {
  py: pyRe(String.raw`\b(?:return|raise|continue|break)\b|(?<![\w.])(?:abort|flask\.abort|sys\.exit)\s*\(`),
  js: pyRe(String.raw`\b(?:return|throw|continue|break)\b|(?<![\w$.])process\.exit\s*\(`),
};
const GUARD_EXIT_START_RE = {
  py: pyRe(String.raw`^(?:\b(?:return|raise|continue|break)\b|(?<![\w.])(?:abort|flask\.abort|sys\.exit)\s*\()`),
  js: pyRe(String.raw`^(?:\b(?:return|throw|continue|break)\b|(?<![\w$.])process\.exit\s*\()`),
};
/** Names a path-traversal guard condition in `stmt` checks (core._guarded_names). */
export function guardedNames(stmt, lang) {
  const names = [];
  for (const r of GUARD_VAR_RES[lang]) for (const m of stmt.matchAll(r)) names.push(m[1]);
  if (lang === "py" && stmt.includes("commonpath")) {
    for (const m of stmt.matchAll(GUARD_COMMONPATH_RE)) {
      for (const part of m[1].split(",")) {
        const n = GUARD_NAME_RE.exec(part);
        if (n) names.push(n[1]);
      }
    }
  }
  return names;
}
/** True when the `if` on line i (joined statement `stmt`) leaves (core._guard_exits). */
export function guardExits(ctx, i, stmt, lang) {
  if (GUARD_EXIT_RE[lang].test(stmt)) return true;
  const line = ctx.mcode(i);
  const indent = line.length - pyLstrip(line).length;
  let seen = 0;
  for (let j = i + 1; j < ctx.lines.length && seen < GUARD_BLOCK_LINES; j++) {
    if (ctx.cmask[j]) continue;
    const code = ctx.mcode(j);
    const body = pyLstrip(code);
    if (!body) continue;
    if (code.length - body.length <= indent) return false;
    if (GUARD_EXIT_START_RE[lang].test(body)) return true;
    seen++;
  }
  return false;
}

/* Flask (or Quart) views (core._view_returns): what one returns is the
   response body, HTML by default. */
const FLASK_IMPORT_RE = pyRe(String.raw`^\s*(?:from\s+(?:flask|quart)\b|import\s+(?:flask|quart)\b)`);
const VIEW_DECORATOR_RE = pyRe(String.raw`^\s*@[\w.]+\.(route|get|post|put|patch|delete)\s*\(`);
export const DEF_RE = pyRe(String.raw`^\s*(?:async\s+def|def|class)\b`);
export const VIEW_RETURN_RE = pyRe(String.raw`^\s*return\b`);
export const VIEW_RETURN_SKIP_RE = pyRe(String.raw`^\s*(?:\{|\[|dict\s*\(|(?:[A-Za-z_][\w.]*\.)?(?:redirect|jsonify|url_for|send_file|send_from_directory|send_static_file|abort|render_template)\s*\()`);
const VIEW_CALL_RE = pyRe(String.raw`^\s*([A-Za-z_][\w.]*)\s*\(`);
const STRING_BUILDERS = new Set(["str", "format", "join", "replace", "strip", "lstrip", "rstrip", "upper",
  "lower", "title", "capitalize", "casefold", "swapcase", "decode", "zfill", "ljust", "rjust", "center",
  "expandtabs", "dumps"]);
/** False when a view's return value is a call of a function that is not a string builder (core._view_body). */
export function viewBody(value) {
  const m = VIEW_CALL_RE.exec(value);
  if (!m || STRING_BUILDERS.has(m[1].split(".").pop())) return true;
  const end = callClose(value, m[0].length);
  return end >= value.length || !!pyStrip(value.slice(end + 1));
}
/** Indices of the `return` lines of the file's Flask views (core._view_returns). */
export function viewReturns(ctx) {
  const code = ctx.lines.map((_, i) => (ctx.cmask[i] ? "" : ctx.mcode(i)));
  const flask = code.some((c) => FLASK_IMPORT_RE.test(c));
  const out = new Set();
  const stack = [];
  let pending = false, openBrackets = 0, continued = 0;
  code.forEach((c, i) => {
    const body = pyLstrip(c);
    if (!body) return;
    if (openBrackets > 0 && continued < TAINT_JOIN_MAX_LINES) {
      openBrackets += bracketDepth(c);
      continued++;
      return;
    }
    openBrackets = 0;
    const indent = c.length - body.length;
    while (stack.length && indent <= stack[stack.length - 1][0]) stack.pop();
    if (body.startsWith("@")) {
      const d = VIEW_DECORATOR_RE.exec(c);
      if (d && (d[1] === "route" || flask)) pending = true;
      openBrackets = bracketDepth(c);
      continued = 0;
      return;
    }
    if (DEF_RE.test(c)) {
      stack.push([indent, pending && !body.startsWith("class")]);
      pending = false;
      return;
    }
    pending = false;
    if (stack.length && stack[stack.length - 1][1] && VIEW_RETURN_RE.test(c)) out.add(i);
  });
  return out;
}

/* Where a taint lives (core, "Where a taint lives"): function bodies by
   indentation, strong and weak updates. */
const JS_FUNCTION_WORD_RE = pyRe(String.raw`\bfunction\b`);
const JS_METHOD_HEAD_RE = pyRe(String.raw`^\s*(?:(?:async|static|get|set)\s+){0,3}(?!(?:if|for|while|switch|catch|with|function|return)\b)[A-Za-z_$][\w$]*\s*\([^()]*\)$`);
/** True when line `code` opens a function body (core._scope_opener). */
export function scopeOpener(code, lang) {
  if (lang === "py") return DEF_RE.test(code);
  const t = pyRstrip(code);
  if (!t.endsWith("{")) return false;
  const head = pyRstrip(t.slice(0, -1));
  if (head.endsWith("=>")) return true;
  if (!head.endsWith(")")) return false;
  return JS_FUNCTION_WORD_RE.test(head) || JS_METHOD_HEAD_RE.test(head);
}
/** Indices of the lines whose first non-blank character lies inside a multi-line literal (core._literal_continuations). */
export function literalContinuations(ctx) {
  const lits = ctx.lex.literals;
  const out = new Set();
  if (!lits || !lits.length) return out;
  const starts = ctx.lex.starts;
  let k = 0, reach = -1;
  ctx.lines.forEach((line, j) => {
    const p = starts[j] + line.length - pyLstrip(line).length;
    while (k < lits.length && lits[k][0] < p) {
      reach = Math.max(reach, lits[k][1]);
      k++;
    }
    if (p < reach) out.add(j);
  });
  return out;
}
