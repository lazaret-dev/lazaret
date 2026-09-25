export const STRING_LIT_RE = /"[^"]*"|'[^']*'|`[^`]*`/g;
// Taint sources/sinks and sanitizer model — verbatim from the dashboard (lazaret/web/lazaret.html).

/* ---------------- Taint tracking (lightweight, intra-file) ---------------- */
export const TAINT_SOURCES = {
  py: /request\.(args|form|values|json|data|cookies|headers|files|get_json)|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\(/,
  js: /req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\(/
};
export const TAINT_SINKS = {
  py: [
    ["CMD", /os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(/, "command injection","CRITICAL","CWE-78","Validate/allowlist the value; pass args as a list with shell=False."],
    ["CODE", /(?<![\w.])(eval|exec)\s*\(/, "code injection","CRITICAL","CWE-95","Never execute untrusted strings; use safe parsing."],
    ["SQL", /\.(execute|executemany)\s*\(/, "SQL injection","BLOCKER","CWE-89","Use parameterized queries."],
    ["PATH", /(?<![\w.])open\s*\(|send_file\s*\(|send_from_directory\s*\(/, "path traversal","MAJOR","CWE-22","Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", /requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\(/, "server-side request forgery","MAJOR","CWE-918","Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", /(?<![\w.])redirect\s*\(/, "open redirect","MAJOR","CWE-601","Allowlist redirect targets or use relative paths."],
    ["SSTI", /render_template_string\s*\(/, "template injection","CRITICAL","CWE-1336","Pass data as template parameters, never into template source."],
  ],
  js: [
    ["CMD", /\b(exec|execSync|spawn|spawnSync)\s*\(/, "command injection","CRITICAL","CWE-78","Use execFile/spawn with an args array; validate the value."],
    ["CODE", /(?<![\w.])eval\s*\(|new\s+Function\s*\(/, "code injection","CRITICAL","CWE-95","Never execute untrusted strings; use JSON.parse or a dispatch map."],
    ["SQL", /\.(query|execute)\s*\(/, "SQL injection","BLOCKER","CWE-89","Use placeholders with a parameter array."],
    ["PATH", /\.(sendFile|download)\s*\(|readFile(Sync)?\s*\(|createReadStream\s*\(/, "path traversal","MAJOR","CWE-22","Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", /\bfetch\s*\(|axios(\.(get|post|put|delete|request))?\s*\(|https?\.(get|request)\s*\(/, "server-side request forgery","MAJOR","CWE-918","Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", /\.redirect\s*\(/, "open redirect","MAJOR","CWE-601","Allowlist redirect targets or use relative paths."],
    ["XSS", /\.innerHTML\s*=|document\.write\s*\(/, "cross-site scripting","MAJOR","CWE-79","Escape/sanitize before rendering; prefer textContent."],
  ]
};

export const ASSIGN_RE = {
  py: /^\s*([A-Za-z_]\w*)\s*=(?!=)\s*(.+)/,
  js: /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)/
};

export const escRe = s=>s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");

/* Sanitizer model (SonarQube / Semgrep style). Full sanitizers (numeric
   coercion) cleanse every sink; partial ones clear a category. Body allows one
   nested-paren level so int(request.args.get("id")) is recognized. */
export const SAN_BODY = "(?:[^()]|\\([^()]*\\))*";
export const FULL_SAN = {
  py: new RegExp("(?:int|float|bool|complex|uuid\\.UUID|ipaddress\\.ip_address)\\s*\\("+SAN_BODY+"\\)","g"),
  js: new RegExp("(?:parseInt|parseFloat|Number)\\s*\\("+SAN_BODY+"\\)","g")
};
export const PARTIAL_SAN = {
  py: {
    CMD: new RegExp("(?:shlex|pipes)\\.quote\\s*\\("+SAN_BODY+"\\)","g"),
    XSS: new RegExp("(?:html\\.escape|markupsafe\\.escape|cgi\\.escape|bleach\\.clean|escape)\\s*\\("+SAN_BODY+"\\)","g"),
    PATH: new RegExp("(?:os\\.path\\.basename|basename|secure_filename)\\s*\\("+SAN_BODY+"\\)","g")
  },
  js: {
    XSS: new RegExp("(?:DOMPurify\\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\\s*\\("+SAN_BODY+"\\)","g"),
    SQL: new RegExp("(?:mysql2?|pool|connection|conn|db)\\.escape\\s*\\("+SAN_BODY+"\\)","g"),
    PATH: new RegExp("path\\.basename\\s*\\("+SAN_BODY+"\\)","g"),
    CMD: new RegExp("(?:shellQuote|shell_quote)\\s*\\("+SAN_BODY+"\\)","g")
  }
};
export function neutralize(text, lang, suffix){
  text = text.replace(FULL_SAN[lang], " ");
  if(suffix && PARTIAL_SAN[lang] && PARTIAL_SAN[lang][suffix])
    text = text.replace(PARTIAL_SAN[lang][suffix], " ");
  return text;
}
