// Taint sources/sinks and sanitizer model — the Python engine's tables
// (lazaret.scanner.core TAINT_SOURCES / TAINT_SINKS / ASSIGN_RE /
// _FULL_SAN / _PARTIAL_SAN), pattern text verbatim, Python regex semantics.

import { pyRe, pyStrip, pyLstrip } from "../lib/pycompat.js";

/* ---------------- Taint tracking (lightweight, intra-file) ---------------- */
export const TAINT_SOURCES = {
  py: pyRe(String.raw`request\.(args|form|values|json|data|cookies|headers|files|get_json)|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\(`),
  js: pyRe(String.raw`req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\(`),
};
export const TAINT_SINKS = {
  py: [
    ["CMD", pyRe(String.raw`os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(`), "command injection", "CRITICAL", "CWE-78", "Validate/allowlist the value; pass args as a list with shell=False."],
    ["CODE", pyRe(String.raw`(?<![\w.])(eval|exec)\s*\(`), "code injection", "CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."],
    ["SQL", pyRe(String.raw`\.(execute|executemany)\s*\(`), "SQL injection", "BLOCKER", "CWE-89", "Use parameterized queries."],
    ["PATH", pyRe(String.raw`(?<![\w.])open\s*\(|send_file\s*\(|send_from_directory\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", pyRe(String.raw`requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\(`), "server-side request forgery", "MAJOR", "CWE-918", "Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", pyRe(String.raw`(?<![\w.])redirect\s*\(`), "open redirect", "MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
    ["SSTI", pyRe(String.raw`render_template_string\s*\(`), "template injection", "CRITICAL", "CWE-1336", "Pass data as template parameters, never into template source."],
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
export const ASSIGN_RE = {
  py: pyRe(String.raw`^\s*([A-Za-z_]\w*)\s*(?::[^=\n]*)?=(?![=])\s*(.+)`),
  js: pyRe(String.raw`^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)`),
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
    XSS: pyRe(String.raw`(?:html\.escape|markupsafe\.escape|cgi\.escape|bleach\.clean|escape)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`(?:os\.path\.basename|basename|secure_filename)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
  },
  js: {
    XSS: pyRe(String.raw`(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    SQL: pyRe(String.raw`(?:mysql2?|pool|connection|conn|db)\.escape\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`path\.basename\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    CMD: pyRe(String.raw`(?:shellQuote|shell_quote)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
  },
};
export function neutralize(text, lang, suffix) {
  text = text.replace(FULL_SAN[lang], " ");
  if (suffix && PARTIAL_SAN[lang] && PARTIAL_SAN[lang][suffix])
    text = text.replace(PARTIAL_SAN[lang][suffix], " ");
  return text;
}
