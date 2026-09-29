// Taint sources/sinks and sanitizer model — the Python engine's tables
// (lazaret.scanner.core TAINT_SOURCES / TAINT_SINKS / ASSIGN_RE /
// _FULL_SAN / _PARTIAL_SAN), pattern text verbatim, Python regex semantics.

import { pyRe, pyStrip, pyLstrip, pyRstrip, cpLen } from "../lib/pycompat.js";

/* ---------------- Taint tracking (lightweight, intra-file) ---------------- */
export const TAINT_SOURCES = {
  // Flask / Werkzeug request data (query_string, get_data, stream, full_path
  // too), Django's (GET, POST, COOKIES, META, FILES, body) and Starlette's,
  // FastAPI's and Django REST framework's (query_params, path_params, a
  // websocket's messages); the parameters a route handler takes from the
  // request (routeParams)
  py: pyRe(String.raw`request\.(args|form|values|json|data|cookies|headers|files|get_json|get_data|query_string|stream|full_path|GET|POST|COOKIES|META|FILES|body|query_params|path_params)|\b(?:websocket|ws)\.receive_(?:text|json|bytes)\s*\(|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\(`),
  // Express's request (`req`, or `request` as a name of its own): the
  // parsed parts, the URL and host, and a header read with req.get()
  js: pyRe(String.raw`req\.(query|body|params|headers|cookies|signedCookies|files?|originalUrl|url|path|hostname)|(?<![\w$.])request\.(query|body|params|headers|cookies)|\breq\.(?:get|header|param)\s*\(|process\.argv|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams(?!\s*\(\s*\))|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\(`),
};
export const TAINT_SINKS = {
  py: [
    ["CMD", pyRe(String.raw`os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(|asyncio\.create_subprocess_shell\s*\(`), "command injection", "CRITICAL", "CWE-78", "Validate/allowlist the value; pass args as a list with shell=False."],
    ["CODE", pyRe(String.raw`(?<![\w.])(eval|exec)\s*\(`), "code injection", "CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."],
    // DB-API cursors, Django's Manager.raw and RawSQL (the query is their first argument) …
    ["SQL", pyRe(String.raw`\.(execute|executemany|executescript)\s*\(|\.objects\.raw\s*\(|(?<![\w.])RawSQL\s*\(`), "SQL injection", "BLOCKER", "CWE-89", "Use parameterized queries."],
    // … and Django's QuerySet.extra(), whose SQL is in its keywords
    ["SQL", pyRe(String.raw`\.extra\s*\(\s*(?:select|where|tables|order_by)\s*=`), "SQL injection", "BLOCKER", "CWE-89", "Use parameterized queries."],
    ["PATH", pyRe(String.raw`(?<![\w.])open\s*\(|(?:codecs|io|os)\.open\s*\(|send_file\s*\(|(?<![\w.])FileResponse\s*\(|shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)\s*\(|os\.(?:remove|unlink|rmdir|removedirs|rename|replace|listdir|scandir)\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    // Flask joins the file name to the directory safely (safe_join): the directory is the sink
    ["PATH", pyRe(String.raw`send_from_directory\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", pyRe(String.raw`requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\(|httpx\.(?:get|post|put|patch|delete|head|request|stream)\s*\(`), "server-side request forgery", "MAJOR", "CWE-918", "Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", pyRe(String.raw`(?<![\w.])redirect\s*\(|flask\.redirect\s*\(|HttpResponse(?:Permanent)?Redirect\s*\(|(?<![\w.])RedirectResponse\s*\(`), "open redirect", "MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
    ["SSTI", pyRe(String.raw`render_template_string\s*\(|(?<![\w.])jinja2\.Template\s*\(|(?:\b\w*[eE]nv(?:ironment)?|Environment\s*\([^()]{0,200}\))\s*\.\s*from_string\s*\(`), "template injection", "CRITICAL", "CWE-1336", "Pass data as template parameters, never into template source."],
    // a Template class imported from jinja2, mako or django.template (not string.Template):
    // only in a file that imports one (TEMPLATE_IMPORT_RE)
    ["SSTI", pyRe(String.raw`(?<![\w.])Template\s*\(`), "template injection", "CRITICAL", "CWE-1336", "Pass data as template parameters, never into template source."],
    // a response body built from the value (Flask / Werkzeug, Django, Starlette / FastAPI),
    // or the value marked as safe HTML; a Flask view's own `return` is checked too
    ["XSS", pyRe(String.raw`make_response\s*\(|(?<![\w.])Response\s*\(|(?<![\w.])HttpResponse\s*\(|(?<![\w.])HTMLResponse\s*\(|(?<![\w.])Markup\s*\(|mark_safe\s*\(|(?<![\w.])SafeString\s*\(`), "cross-site scripting", "MAJOR", "CWE-79", "Escape the value (or render it through an autoescaping template) before it is returned."],
  ],
  js: [
    ["CMD", pyRe(String.raw`\b(exec|execSync|spawn|spawnSync)\s*\(`), "command injection", "CRITICAL", "CWE-78", "Use execFile/spawn with an args array; validate the value."],
    ["CODE", pyRe(String.raw`(?<![\w.])eval\s*\(|new\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\(`), "code injection", "CRITICAL", "CWE-95", "Never execute untrusted strings; use JSON.parse or a dispatch map."],
    // driver queries, and the raw SQL of knex and Sequelize
    ["SQL", pyRe(String.raw`\.(query|execute)\s*\(|\.(?:whereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|fromRaw)\s*\(|\bknex\.raw\s*\(|\bsequelize\.literal\s*\(`), "SQL injection", "BLOCKER", "CWE-89", "Use placeholders with a parameter array."],
    ["PATH", pyRe(String.raw`\.(sendFile|download)\s*\((?!(?:[^()]|\([^()]*\))*,\s*\{[^{}]*\broot\s*[:,}])|readFile(Sync)?\s*\(|createReadStream\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    // a file written, removed or listed (the path is the first argument)
    ["PATH", pyRe(String.raw`\bfs(?:\.promises)?\.(?:writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|rename|copyFile|createWriteStream)(?:Sync)?\s*\(`), "path traversal", "MAJOR", "CWE-22", "Resolve the path and verify it stays inside an allowed base directory."],
    ["SSRF", pyRe(String.raw`\bfetch\s*\(|axios(\.(get|post|put|delete|request))?\s*\(|https?\.(get|request)\s*\(|\bgot(?:\.(?:get|post|put|patch|delete|head|stream))?\s*\(|\bneedle\s*\(`), "server-side request forgery", "MAJOR", "CWE-918", "Allowlist target hosts and schemes; block internal addresses."],
    ["REDIR", pyRe(String.raw`\.redirect\s*\(|\b(?:res|response)\.location\s*\(`), "open redirect", "MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
    // template source compiled or rendered: EJS, Pug, Handlebars, Mustache, Nunjucks, doT, lodash
    ["SSTI", pyRe(String.raw`\b(?:ejs|pug|jade|Handlebars|handlebars|Mustache|mustache|nunjucks|doT|_)\.(?:render|renderString|compile|template)\s*\(`), "template injection", "CRITICAL", "CWE-1336", "Pass data as template parameters, never into template source."],
    ["XSS", pyRe(String.raw`\.innerHTML\s*=|document\.write\s*\(`), "cross-site scripting", "MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."],
    // an Express or Node response body (Express sends a string as HTML; a
    // whole parsed object, `res.send(req.query)`, as JSON)
    ["XSS", pyRe(String.raw`\b(?:res|response)(?:\.(?:status|type|set|header|append|vary|cookie|clearCookie)\s*\([^()]{0,200}\))*\.(?:send|write|end)\s*\((?!\s*(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\s*\))`), "cross-site scripting", "MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."],
  ],
};
// A response whose content type is set to one a browser does not render as
// HTML is no XSS sink (core._NON_HTML_TYPE_RE).
export const NON_HTML_TYPE_RE = pyRe(String.raw`\b(?:content_type|mimetype|media_type)\s*=\s*[rRuU]?["'](?![^"']*(?:html|xml|svg))`);
// … nor is an Express response whose chain sets one first (core._NON_HTML_CHAIN_RE).
export const NON_HTML_CHAIN_RE = pyRe(String.raw`\.(?:type\s*\(|(?:set|header)\s*\(\s*["'` + "`" + String.raw`][Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee]["'` + "`" + String.raw`]\s*,)\s*["'` + "`" + String.raw`](?![^"'` + "`" + String.raw`]*(?:html|xml|svg))`);
// The Template row of TAINT_SINKS.py counts only in a file that imports a
// Template class from a template engine (core._TEMPLATE_SINK_RE / _TEMPLATE_IMPORT_RE).
const TEMPLATE_SINK_SOURCE = pyRe(String.raw`(?<![\w.])Template\s*\(`).source;
export const TEMPLATE_SINK_RE = TAINT_SINKS.py.find((r) => r[1].source === TEMPLATE_SINK_SOURCE)[1];
export const TEMPLATE_IMPORT_RE = pyRe(String.raw`(?<![^\n])[ \t]*from[ \t]+(?:jinja2|mako\.template|django\.template)[ \t]+import\b[^\n]*\bTemplate\b`);

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

// A value put into a container — an element assigned or added — taints the
// container, a weak update (core._CONTAINER_WRITE_RE / _container_write).
const CONTAINER_WRITE_RE = {
  py: pyRe(String.raw`^\s*([A-Za-z_]\w*)\s*(?:\[[^\[\]\n]*\]\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)?=(?!=)|\.\s*(?:append|extend|insert|add)\s*\()\s*(.+)`, "d"),
  js: pyRe(String.raw`^\s*([A-Za-z_$][\w$]*)\s*(?:\[[^\[\]\n]*\]\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>])|\.\s*(?:push|unshift)\s*\()\s*(.+)`, "d"),
};
/** [container name, the value written] of a line that puts a value into a container, or null (core._container_write). */
export function containerWrite(line, lang) {
  const m = CONTAINER_WRITE_RE[lang].exec(line);
  if (!m || (lang === "py" && PY_KEYWORDS.has(m[1]))) return null;
  const added = pyRstrip(line.slice(m.indices[1][1], m.indices[2][0])).endsWith("(");
  return [m[1], added ? extent(m[2]) : m[2]];
}
// An element assigned under a literal key is followed by its key too
// (core._KEYED_WRITE_RE / _KEYED_READ_RE / _keyed_reads).
export const KEYED_WRITE_RE = pyRe(String.raw`^\s*([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]\s*=(?![=>])`);
const KEYED_READ_RE = pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]`, "g");
/** `text` with its reads of container elements known to hold no untrusted data blanked (core._keyed_reads). */
export function keyedReads(text, keyed) {
  if (!keyed.size || !text.includes("[")) return text;
  return text.replace(KEYED_READ_RE, (m, name, _q, key) => {
    const keys = keyed.get(name);
    if (!keys || !keys.has(key) || keys.get(key) !== null) return m;
    return " ".repeat(cpLen(m));
  });
}

export const STRING_LIT_RE = pyRe(String.raw`\"[^\"]*\"|'[^']*'|` + "`[^`]*`", "g");

export const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/* Sanitizer model (SonarQube / Semgrep style). Full sanitizers (numeric
   coercion) cleanse every sink; partial ones clear a category. Body allows one
   nested-paren level so int(request.args.get("id")) is recognized. */
export const SAN_BODY = String.raw`(?:[^()]|\([^()]*\))*`;
// A record looked up by a value (get_object_or_404, Model.objects.filter,
// Model.query.filter_by, session.execute …) is the database's, not the
// value; what a file read gives is the file's (core._FULL_SAN).
export const FULL_SAN = {
  py: pyRe(String.raw`(?:int|float|bool|complex|uuid\.UUID|ipaddress\.ip_address|get_object_or_404|get_list_or_404|\.objects\.\w+|\.query\.\w+|\bsession\.(?:query|get|scalars?|execute))\s*\(` + SAN_BODY + String.raw`\)`
    + String.raw`|(?<![\w.])open\s*\(` + SAN_BODY + String.raw`\)\s*\.\s*read(?:lines)?\s*\(\s*\)`, "g"),
  js: pyRe(String.raw`(?:parseInt|parseFloat|Number|readFileSync)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
};
export const PARTIAL_SAN = {
  py: {
    CMD: pyRe(String.raw`(?:shlex|pipes)\.quote\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    // escape(), escape_html(), …; an autoescaping template and the JSON and
    // URL builders encode the value too. Not unescape().
    XSS: pyRe(String.raw`(?<!\w)(?:html\.escape|markupsafe\.escape|cgi\.escape|escape\w*|bleach\.clean|conditional_escape|format_html|render_template|render_to_string|TemplateResponse|jsonify|url_for)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`(?:os\.path\.basename|basename|secure_filename|safe_join)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    // url_for and Django's reverse() build a URL on this site from a view's
    // name (Flask's, Starlette's request.url_for); the Referer is the page
    // the user came from (a redirect "back")
    REDIR: pyRe(String.raw`(?<![\w.])(?:[A-Za-z_][\w.]*\.)?(?:url_for|reverse|reverse_lazy)\s*\(` + SAN_BODY + String.raw`\)`
      + String.raw`|request\.(?:META\.get|headers\.get)\s*\(\s*[\"'](?:HTTP_REFERER|[Rr]eferr?er)[\"']` + SAN_BODY
      + String.raw`\)|request\.META\s*\[\s*[\"']HTTP_REFERER[\"']\s*\]`, "g"),
  },
  js: {
    XSS: pyRe(String.raw`(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml|he\.(?:encode|escape)|validator\.escape|filterXSS|xssFilters\.\w+|_\.escape|lodash\.escape)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    SQL: pyRe(String.raw`(?:mysql2?|pool|connection|conn|db)\.escape\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    PATH: pyRe(String.raw`path\.basename\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    CMD: pyRe(String.raw`(?:shellQuote|shell_quote)\s*\(` + SAN_BODY + String.raw`\)`, "g"),
    // the Referer: the page the user came from (a redirect "back")
    REDIR: pyRe(String.raw`\b(?:req|request)\.(?:get|header)\s*\(\s*['\"][Rr]eferr?er['\"]\s*\)|\b(?:req|request)\.headers\s*(?:\.\s*referr?er\b|\[\s*['\"]referr?er['\"]\s*\])`, "g"),
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
// An element looked up by a key is the container's, not the key's: taint
// reads a subscript's container and not its index, nor the index arguments
// of slice(), substring(), at() … (core._drop_indexes).
const SUBSCRIPT_RE = pyRe(String.raw`((?<![\w$])[\w$]+|[)\]])(\s*)\[[^\[\]]*\]`, "g");
const INDEX_ARGS_RE = pyRe(String.raw`(\.\s*(?:slice|substring|substr|at|charAt|charCodeAt|codePointAt)\s*\()([^()]*)\)`, "g");
const SUBSCRIPT_PASSES = 4;
const NOT_SUBSCRIPTED = new Set(["return", "yield", "in", "await", "else", "and", "or", "not", "is", "if", "lambda",
  "assert", "del", "typeof", "case", "of", "new", "delete", "void", "throw", "instanceof", "print", "elif", "while",
  "for", "with", "from", "import", "raise", "except", "do"]);
/** `text` with its subscripts' indexes blanked (core._drop_indexes). */
export function dropIndexes(text) {
  if (text.includes(".")) text = text.replace(INDEX_ARGS_RE, (m, head, args) => head + " ".repeat(cpLen(args)) + ")");
  for (let k = 0; k < SUBSCRIPT_PASSES; k++) {
    if (!text.includes("[")) break;
    const next = text.replace(SUBSCRIPT_RE, (m, head, space) =>
      (NOT_SUBSCRIPTED.has(head) ? m : head + space + " ".repeat(cpLen(m) - cpLen(head) - cpLen(space))));
    if (next === text) break;
    text = next;
  }
  return text;
}
export function taintCode(text, lang) {
  if (lang === "py") {
    return dropIndexes(text.replace(PY_LIT_RE, (m, prefix, lit) => {
      if (!["f", "rf", "fr"].includes((prefix ?? "").toLowerCase()) || lit[0] === "`") return "";
      return " " + fields("py", lit.slice(1, -1).replaceAll("{{", "  ").replaceAll("}}", "  ")) + " ";
    }));
  }
  return dropIndexes(text.replace(STRING_LIT_RE, (lit, offset) => {
    if (lit[0] !== "`" || jsTagged(text, offset)) return "";
    return " " + fields("js", lit.slice(1, -1)) + " ";
  }));
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
// Which arguments of a built-in sink carry the injection (core._SINK_ARGS):
// by the row's pattern text, as core picks them.
const SINK_ARGS = new Map([
  ...TAINT_SINKS.py.filter((r) => ["SQL", "XSS", "REDIR", "SSTI", "CODE"].includes(r[0]) && !r[1].source.includes("extra"))
    .map((r) => [r[1], "first"]),
  ...TAINT_SINKS.py.filter((r) => ["CMD", "PATH", "SSRF"].includes(r[0]) && !r[1].source.includes("send_from_directory"))
    .map((r) => [r[1], "positional"]),
  ...TAINT_SINKS.py.filter((r) => r[1].source.includes("send_from_directory")).map((r) => [r[1], "first"]),
  ...TAINT_SINKS.js.filter((r) => ["SQL", "SSTI"].includes(r[0]) || (r[0] === "PATH" && r[1].source.includes("writeFile"))
    || (r[0] === "XSS" && r[1].source.includes("send"))).map((r) => [r[1], "first"]),
]);
// A redirect to a path on this site, or to a URL on a fixed host; a value
// assigned from one is clean for open redirect (core._SAME_SITE_RE).
export const SAME_SITE_RE = pyRe(String.raw`^\s*[rRuUfF]{0,2}["'` + "`" + String.raw`](?:/(?![/\\"'` + "`" + String.raw`{$])|https?://[^/"'` + "`" + String.raw`?#\\\s{}$]+/)`);
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
// Allowlist guards: a value found in a collection of the code's own is one of
// its members inside the block, and after a branch that leaves when it is not
// (core._ALLOW_GUARD_RE / _allow_guard).
const ALLOW_GUARD_RE = {
  py: pyRe(String.raw`^\s*(?:el)?if\s+(?:\(\s*)?([A-Za-z_]\w*)\s+(not\s+)?in\s+([^:\n]+?)\s*\)?\s*:`),
  js: pyRe(String.raw`^\s*(?:\}\s*)?(?:else\s+)?if\s*\(\s*(!\s*)?([\w$.]+|\[[^\[\]\n]*\])\s*\.\s*(?:includes|has)\s*\(`
    + String.raw`\s*([A-Za-z_$][\w$]*)\s*\)\s*\)`),
};
/** [name, collection text, negated] of an allowlist guard in `stmt`, or null (core._allow_guard). */
export function allowGuard(stmt, lang) {
  const m = ALLOW_GUARD_RE[lang].exec(stmt);
  if (!m) return null;
  return lang === "py" ? [m[1], m[3], !!m[2]] : [m[3], m[2], !!m[1]];
}
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
   response body, HTML by default; a FastAPI path operation whose decorator
   sets response_class=HTMLResponse is a view too. */
const FLASK_IMPORT_RE = pyRe(String.raw`^\s*(?:from\s+(?:flask|quart)\b|import\s+(?:flask|quart)\b)`);
const FASTAPI_IMPORT_RE = pyRe(String.raw`^\s*(?:from\s+fastapi\b|import\s+fastapi\b)`);
const DJANGO_IMPORT_RE = pyRe(String.raw`^\s*(?:from\s+django\b|import\s+django\b)`);
const VIEW_DECORATOR_RE = pyRe(String.raw`^\s*@[\w.]+\.(route|get|post|put|patch|delete|api_route)\s*\(`);
const HTML_RESPONSE_CLASS_RE = pyRe(String.raw`\bresponse_class\s*=\s*(?:[\w.]*\.)?HTMLResponse\b`);
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
/** Indices of the `return` lines of the file's Flask views and HTML FastAPI path operations (core._view_returns). */
export function viewReturns(ctx) {
  const code = ctx.lines.map((_, i) => (ctx.cmask[i] ? "" : ctx.mcode(i)));
  const flask = code.some((c) => FLASK_IMPORT_RE.test(c));
  const fastapi = !flask && code.some((c) => FASTAPI_IMPORT_RE.test(c));
  const out = new Set();
  const stack = [];
  let pending = false, operation = false, openBrackets = 0, continued = 0;
  code.forEach((c, i) => {
    const body = pyLstrip(c);
    if (!body) return;
    if (openBrackets > 0 && continued < TAINT_JOIN_MAX_LINES) {
      openBrackets += bracketDepth(c);
      continued++;
      if (operation && HTML_RESPONSE_CLASS_RE.test(c)) pending = true;
      return;
    }
    openBrackets = 0;
    operation = false;
    const indent = c.length - body.length;
    while (stack.length && indent <= stack[stack.length - 1][0]) stack.pop();
    if (body.startsWith("@")) {
      const d = VIEW_DECORATOR_RE.exec(c);
      if (d && (d[1] === "route" || flask)) pending = true;
      else if (d && fastapi) {
        operation = true;
        if (HTML_RESPONSE_CLASS_RE.test(c)) pending = true;
      }
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

/* Route handlers (core._route_params): the parameters a web framework fills
   from the request are sources in the handler's body — a Flask view's URL
   rule variables but int / float / uuid / any(…) ones, a FastAPI path
   operation's parameters but what it injects or validates to no free text,
   a Django view's URL parameters but the conventional int / slug names. */
const ROUTE_DECORATOR_RE = pyRe(String.raw`^\s*@[\w.]+\.(route|get|post|put|patch|delete|options|head|api_route|websocket)\s*\(`);
const ROUTE_RULE_RE = pyRe(String.raw`\(\s*[rRuU]?(["'])(.*?)\1`, "g");
const FLASK_VAR_RE = pyRe(String.raw`<(?:(\w+)(?:\([^()<>]*\))?:)?(\w+)>`, "g");
const FLASK_SAFE_CONVERTERS = new Set(["int", "float", "uuid", "any"]);
const DEF_HEAD_RE = pyRe(String.raw`^\s*(?:async\s+)?def\s+\w+\s*\(`);
const PARAM_RE = pyRe(String.raw`\s*\*{0,2}\s*([A-Za-z_]\w*)\s*`, "y");
const FASTAPI_INJECTED_RE = pyRe(String.raw`(?<![\w.])(?:[\w.]*\.)?(?:Depends|Security)\s*\(`);
const FASTAPI_FRAMEWORK_TYPES = new Set([
  "Response", "BackgroundTasks", "SecurityScopes", "Request", "WebSocket", "HTTPConnection",
  "fastapi.Response", "fastapi.BackgroundTasks", "fastapi.security.SecurityScopes", "fastapi.Request",
  "fastapi.WebSocket", "starlette.requests.Request", "starlette.requests.HTTPConnection",
  "starlette.websockets.WebSocket", "starlette.responses.Response", "starlette.background.BackgroundTasks"]);
const SAFE_TYPES = new Set([
  "int", "float", "bool", "complex", "None", "UUID", "uuid.UUID", "UUID1", "UUID3", "UUID4", "UUID5",
  "pydantic.UUID4", "Decimal", "decimal.Decimal", "datetime", "datetime.datetime", "date", "datetime.date",
  "time", "datetime.time", "timedelta", "datetime.timedelta", "AwareDatetime", "NaiveDatetime", "PastDate",
  "FutureDate", "PastDatetime", "FutureDatetime", "StrictInt", "StrictFloat", "StrictBool", "PositiveInt",
  "NegativeInt", "NonNegativeInt", "NonPositiveInt", "PositiveFloat", "NegativeFloat", "NonNegativeFloat",
  "NonPositiveFloat", "FiniteFloat"]);
const TYPE_ARG_RE = pyRe(String.raw`(?:typing(?:_extensions)?\.)?(\w+)\s*\[(.*)\]\s*\Z`, "ys");
const CONSTRAINED_NUMBER_RE = pyRe(String.raw`(?:pydantic\.)?con(?:int|float|decimal)\s*\(`, "y");
const TYPE_ALL_MEMBERS = new Set(["Union", "List", "list", "Set", "set", "FrozenSet", "frozenset", "Sequence",
  "Tuple", "tuple", "Iterable", "Collection"]);
const DJANGO_ID_RE = pyRe(String.raw`(?:pk|id|slug|year|month|day|\w+_(?:id|pk|slug))\Z`, "y");
const DEP_ALIAS_NAME_RE = pyRe(String.raw`(?:[\w.]*\.)?\w*Deps?\Z`, "y");
const DEP_ALIAS_DEF_RE = pyRe(String.raw`(?<![^\n])([A-Za-z_]\w*)[ \t]*(?::[ \t]*[\w.]+[ \t]*)?=[ \t]*(?:typing(?:_extensions)?\.)?Annotated[ \t]*\[[^\n]*\b(?:Depends|Security)\s*\(`, "g");
const ENUM_DEFAULT_RE = pyRe(String.raw`([A-Za-z_][\w.]*)\.[A-Za-z_]\w*\Z`, "y");
const ROUTE_TYPE_DEPTH = 8;
/** Python re's match(): `re` (sticky) at the start of `s`. */
const matchAt = (re, s) => { re.lastIndex = 0; return re.exec(s); };

/** `text` split at the `sep` characters outside brackets and string literals (core._top_split). */
export function topSplit(text, sep) {
  const parts = [];
  let depth = 0, start = 0, i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      const j = text.indexOf(ch, i + 1);
      if (j < 0) break;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
    else if (ch === sep && depth === 0) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
    i++;
  }
  parts.push(text.slice(start));
  return parts;
}
/** [[name, annotation, default]] of the parameters of the def whose joined text is `sig` (core._signature_params). */
export function signatureParams(sig) {
  const m = DEF_HEAD_RE.exec(sig);
  if (!m) return [];
  const out = [];
  const head = m[0].length;
  for (const part of topSplit(sig.slice(head, callClose(sig, head)), ",")) {
    const pm = matchAt(PARAM_RE, part);
    if (!pm) continue;
    const end = pm[0].length;
    if (end < part.length && part[end] !== ":" && part[end] !== "=") continue;
    let ann = "", dflt = "";
    const rest = part.slice(end);
    if (rest.startsWith(":")) {
      const pieces = topSplit(rest.slice(1), "=");
      ann = pieces[0];
      dflt = pieces.slice(1).join("=");
    } else if (rest.startsWith("=")) dflt = rest.slice(1);
    out.push([pm[1], pyStrip(ann), pyStrip(dflt)]);
  }
  return out;
}
/** Does FastAPI validate a value of annotation `ann` to no free text? (core._safe_type) */
export function safeType(ann, depth = 0) {
  ann = pyStrip(ann);
  if (!ann || depth > ROUTE_TYPE_DEPTH) return false;
  const union = topSplit(ann, "|");
  if (union.length > 1) return union.every((member) => safeType(member, depth + 1));
  if (SAFE_TYPES.has(ann) || matchAt(CONSTRAINED_NUMBER_RE, ann)) return true;
  const m = matchAt(TYPE_ARG_RE, ann);
  if (!m) return false;
  const kind = m[1], args = topSplit(m[2], ",");
  if (kind === "Literal") return true;
  if (["Optional", "Annotated", "Required", "NotRequired"].includes(kind)) return safeType(args[0], depth + 1);
  if (TYPE_ALL_MEMBERS.has(kind)) return args.filter((a) => pyStrip(a) !== "...").every((a) => safeType(a, depth + 1));
  return false;
}
function fastapiParams(params, aliases = new Set()) {
  const out = [];
  for (const [name, ann, dflt] of params) {
    if (name === "self" || name === "cls" || FASTAPI_INJECTED_RE.test(ann) || FASTAPI_INJECTED_RE.test(dflt)) continue;
    if (FASTAPI_FRAMEWORK_TYPES.has(ann) || aliases.has(ann) || matchAt(DEP_ALIAS_NAME_RE, ann)) continue;
    if (ann && (safeType(ann) || enumDefault(ann, dflt))) continue;
    out.push(name);
  }
  return out;
}
/** Is `dflt` a member of the class `ann` names (an Enum's value)? (core._enum_default) */
function enumDefault(ann, dflt) {
  const m = matchAt(ENUM_DEFAULT_RE, dflt);
  return !!m && m[1] === ann;
}
function flaskParams(rule, params) {
  const free = new Set();
  FLASK_VAR_RE.lastIndex = 0;
  for (let m; (m = FLASK_VAR_RE.exec(rule || ""));) if (!FLASK_SAFE_CONVERTERS.has(m[1] || "string")) free.add(m[2]);
  return params.filter(([name]) => free.has(name)).map(([name]) => name);
}
function djangoParams(params) {
  const names = params.map(([name]) => name);
  const first = names[0] === "self" && names[1] === "request" ? 2 : names[0] === "request" ? 1 : 0;
  if (!first) return [];
  return params.slice(first).filter(([name, ann]) => !matchAt(DJANGO_ID_RE, name) && !(ann && safeType(ann)))
    .map(([name]) => name);
}
/** Map: index of a route handler's def line -> names of the parameters the framework fills from the request (core._route_params). */
export function routeParams(ctx) {
  const code = ctx.lines.map((_, i) => (ctx.cmask[i] ? "" : ctx.mcode(i)));
  const flask = code.some((c) => FLASK_IMPORT_RE.test(c));
  const fastapi = !flask && code.some((c) => FASTAPI_IMPORT_RE.test(c));
  const django = code.some((c) => DJANGO_IMPORT_RE.test(c));
  const aliases = new Set();
  if (fastapi) {
    const all = code.join("\n");
    DEP_ALIAS_DEF_RE.lastIndex = 0;
    for (let m; (m = DEP_ALIAS_DEF_RE.exec(all)) !== null;) aliases.add(m[1]);
  }
  const joined = (i) => {
    const parts = [code[i]];
    let depth = bracketDepth(code[i]), j = i;
    while (depth > 0 && j + 1 < code.length && j + 1 <= i + TAINT_JOIN_MAX_LINES) {
      j++;
      parts.push(code[j]);
      depth += bracketDepth(code[j]);
    }
    return [parts.join(" "), j];
  };
  const out = new Map();
  let routes = [];
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    const body = pyLstrip(c);
    if (!body) { i++; continue; }
    if (body.startsWith("@")) {
      const [text, last] = joined(i);
      const d = ROUTE_DECORATOR_RE.exec(text);
      if (d && (d[1] === "route" || (flask && ["get", "post", "put", "patch", "delete"].includes(d[1])))) {
        ROUTE_RULE_RE.lastIndex = d[0].length - 1;
        const rule = ROUTE_RULE_RE.exec(text);
        routes.push(["flask", rule ? rule[2] : ""]);
      } else if (d && fastapi) routes.push(["fastapi", ""]);
      i = last + 1;
      continue;
    }
    if (DEF_HEAD_RE.test(c)) {
      const [text, last] = joined(i);
      const params = signatureParams(text);
      let names = [];
      for (const [framework, rule] of routes) {
        names.push(...(framework === "fastapi" ? fastapiParams(params, aliases) : flaskParams(rule, params)));
      }
      if (!routes.length && django) names = djangoParams(params);
      if (names.length) out.set(i, [...new Set(names)]);
      routes = [];
      i = last + 1;
      continue;
    }
    routes = [];
    i++;
  }
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
