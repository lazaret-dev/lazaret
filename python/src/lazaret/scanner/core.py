#!/usr/bin/env python3
"""Lazaret CLI — static security & quality scanner for Python and JavaScript.

Usage:
    lazaret <directory> [options]          (or: python -m lazaret ...)

Options:
    --out-dir DIR   Directory for the default reports (default: the scan root)
    --html PATH     Write HTML project report (default: <out-dir>/lazaret-report.html)
    --json PATH     Write JSON report (default: <out-dir>/lazaret-report.json)
    --no-html       Skip HTML report
    --no-json       Skip JSON report
    --exclude NAME  Extra directory name to skip (repeatable)
    --ci            Exit with code 1 if the quality gate fails
    -q, --quiet     Only print the summary (no per-issue lines)

Reports are written under the scan root (or --out-dir), never the current
working directory; writability and collisions are checked before scanning
(exit 3 on a problem), and pre-existing files not produced by Lazaret are
never silently overwritten (--force-overwrite to override).

Taint-config rules that fail validation (unknown category, empty pattern) are
never silently dropped: each produces a warning naming the file, the rule and
the reason. With an explicit --taint-config (or --strict-taint-config) they
make the scan exit 4, so CI cannot silently lose coverage.

No dependencies — runs on stock python3. Same ruleset as the Lazaret dashboard.
"""
import argparse
import datetime
import html as html_mod
import json
import os
import re
import sys

try:
    from lazaret.scanner import flow as lazaret_flow  # interprocedural / cross-file taint (optional)
except Exception:  # pragma: no cover
    lazaret_flow = None

from lazaret.scanner import reports as lazaret_report  # report paths: pre-scan validation, atomic writes


def configure_stdio():
    """Never crash while printing. Reports use characters such as the check
    and cross marks; a Windows console shows them fine, but redirected output
    (a pipe, a file, CI logs) defaults to the ANSI code page (e.g. cp1252),
    which cannot encode them, and print() would raise UnicodeEncodeError
    mid-report. There, write UTF-8 instead. Everywhere, replace anything a
    stream can't encode rather than raising. An explicit PYTHONIOENCODING is
    respected. Called at the start of every CLI entry point."""
    for stream, errors in ((sys.stdout, "replace"), (sys.stderr, "backslashreplace")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            redirected_on_windows = (sys.platform == "win32" and not stream.isatty()
                                     and not os.environ.get("PYTHONIOENCODING"))
            if redirected_on_windows:
                reconfigure(encoding="utf-8", errors=errors)
            else:
                reconfigure(errors=errors)
        except (OSError, ValueError):
            pass

# ---------------- Rules (mirrors lazaret.html) ----------------
SEV_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
TYPE_LABEL = {"VULN": "Vulnerability", "HOTSPOT": "Security Hotspot",
              "BUG": "Bug", "SMELL": "Code Smell"}

def R(id, name, type, sev, langs, pat, msg, why, fix, ref, skip=None, need=None, flags=0):
    return {"id": id, "name": name, "type": type, "sev": sev, "langs": langs,
            "re": re.compile(pat, flags), "msg": msg, "why": why, "fix": fix, "ref": ref,
            "skip": re.compile(skip, re.I) if skip else None,
            "need": re.compile(need, re.I) if need else None}

RULES = [
R("S-EVAL-PY", "Dynamic code execution", "VULN", "CRITICAL", ("py",),
  r"(?<![\w.])(eval|exec)\s*\(",
  "Use of eval/exec enables arbitrary code execution.",
  "If any part of the evaluated string derives from user input, an attacker can run arbitrary code in your process.",
  "Replace with safe parsing (ast.literal_eval) or an explicit dispatch table.",
  "CWE-95 · OWASP A03: Injection"),
R("S-EVAL-JS", "Dynamic code execution", "VULN", "CRITICAL", ("js",),
  r"(?<![\w.])eval\s*\(",
  "Use of eval enables arbitrary code execution.",
  "If any part of the evaluated string derives from user input, an attacker can run arbitrary code.",
  "Replace with JSON.parse or an explicit dispatch table.",
  "CWE-95 · OWASP A03: Injection"),
R("S-NEWFUNC", "Function constructor", "VULN", "CRITICAL", ("js",),
  r"new\s+Function\s*\(",
  "new Function() compiles strings into code, equivalent to eval.",
  "String-built functions can execute attacker-controlled input.",
  "Define functions statically or use a whitelisted dispatch map.",
  "CWE-95 · OWASP A03"),
# G12: see scan_file()'s sql_sink_analyzer — the S-SQL-PY regex is only the
# fast path; the analyzer adds whole-argument analysis (cur.execute(sql % x)
# with no space, %-interpolation and .format() on template variables assigned
# earlier in the file, and string concatenation) that a line regex cannot see.
R("S-SQL-PY", "SQL built from strings", "VULN", "BLOCKER", ("py",),
  r"\.(execute|executemany)\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\+|\.format))",
  "SQL query built with string formatting/concatenation.",
  "Interpolating values into SQL enables SQL injection — the classic path to full database compromise.",
  'Use parameterized queries: cursor.execute("SELECT … WHERE id = %s", (user_id,)).',
  "CWE-89 · OWASP A03"),
R("S-SQL-JS", "SQL built from strings", "VULN", "BLOCKER", ("js",),
  r"\.(query|execute)\s*\(\s*(`[^`]*\$\{|\"[^\"]*\"\s*\+|'[^']*'\s*\+|\w+\s*\+\s*[\"'`])",
  "SQL query built with template literal or concatenation.",
  "Interpolating values into SQL enables SQL injection.",
  "Use placeholders: db.query('SELECT … WHERE id = ?', [id]).",
  "CWE-89 · OWASP A03"),
R("S-OSCMD-PY", "OS command execution", "VULN", "CRITICAL", ("py",),
  r"os\.(system|popen)\s*\(",
  "os.system/os.popen runs shell commands.",
  "Any user-influenced portion of the command allows shell injection.",
  "Use subprocess.run([...]) with a list of args and shell=False.",
  "CWE-78 · OWASP A03"),
R("S-SHELL-TRUE", "subprocess with shell=True", "VULN", "CRITICAL", ("py",),
  r"shell\s*=\s*True",
  "shell=True passes the command through the shell.",
  "Shell metacharacters in user input become command injection.",
  "Pass args as a list with shell=False.",
  "CWE-78"),
R("S-EXEC-JS", "Shell exec", "HOTSPOT", "CRITICAL", ("js",),
  r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|\w+\s*[,)+])",
  "child_process exec with dynamic command string.",
  "Dynamic command strings passed to a shell risk command injection.",
  "Use execFile/spawn with an argument array.",
  "CWE-78 · OWASP A03"),
R("S-PICKLE", "Unsafe deserialization (pickle)", "VULN", "CRITICAL", ("py",),
  r"pickle\.loads?\s*\(",
  "pickle.load(s) executes code embedded in the payload.",
  "Unpickling untrusted data is remote code execution by design.",
  "Use JSON or another data-only format for untrusted input.",
  "CWE-502 · OWASP A08"),
R("S-YAML", "Unsafe yaml.load", "VULN", "CRITICAL", ("py",),
  r"yaml\.load\s*\((?![^)]*(SafeLoader|safe_load))",
  "yaml.load without SafeLoader can instantiate arbitrary objects.",
  "Full YAML loading executes constructors from the document.",
  "Use yaml.safe_load() or Loader=yaml.SafeLoader.",
  "CWE-502"),
R("S-SECRET", "Hardcoded credential", "VULN", "BLOCKER", ("py", "js"),
  r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
  "Credential appears to be hardcoded in source.",
  "Secrets in code leak through version control, logs, and builds; rotation requires a deploy.",
  "Load secrets from environment variables or a secrets manager, and rotate this one now.",
  "CWE-798 · OWASP A07",
  # Verdict-integrity fix (audit C2): skip tokens used to match bare
  # substrings anywhere on the line. Word-bounded now; the bare `<...>`
  # pattern is gone — a real credential on the same line as an angle-bracket
  # generic no longer blinds the rule.
  skip=r"(environ|process\.env|getenv|config\[|\bimport\b|\bplaceholder\b|\bexample\b|\bdummy\b|\bsample\b|\bmock\b|\bmocked\b|\bxxxx+\b|\{\{)",
  flags=re.I),
R("S-WEAKHASH-PY", "Weak hash algorithm", "VULN", "MAJOR", ("py",),
  r"hashlib\.(md5|sha1)\s*\(",
  "MD5/SHA-1 are cryptographically broken.",
  "Collisions are practical; unusable for passwords or signatures.",
  "Use SHA-256+ for integrity; bcrypt/scrypt/argon2 for passwords.",
  "CWE-327/328"),
R("S-WEAKHASH-JS", "Weak hash algorithm", "VULN", "MAJOR", ("js",),
  r"createHash\s*\(\s*[\"'](md5|sha1)[\"']",
  "MD5/SHA-1 are cryptographically broken.",
  "Collisions are practical; unusable for passwords or signatures.",
  "Use sha256+ for integrity; bcrypt/scrypt/argon2 for passwords.",
  "CWE-327/328"),
R("S-VERIFY", "TLS verification disabled", "VULN", "MAJOR", ("py",),
  r"verify\s*=\s*False|_create_unverified_context",
  "Certificate verification is disabled.",
  "Disabling TLS verification allows trivial man-in-the-middle attacks.",
  "Keep verify=True; add the internal CA to the trust store instead.",
  "CWE-295 · OWASP A02"),
R("S-HTTP", "Cleartext HTTP URL", "HOTSPOT", "MINOR", ("py", "js"),
  r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
  "URL uses unencrypted http://.",
  "Data sent over HTTP can be read or altered in transit.",
  "Use https:// unless this is a deliberate local/dev endpoint.",
  "CWE-319 · OWASP A02"),
R("S-RANDOM", "Non-crypto randomness for secret", "HOTSPOT", "MAJOR", ("py", "js"),
  r"(random\.(random|randint|choice|randrange|getrandbits)|Math\.random)\s*\(",
  "PRNG used in a security-sensitive value.",
  "random/Math.random are predictable; generated tokens can be guessed.",
  "Use secrets module (Python) or crypto.randomBytes / crypto.getRandomValues (JS).",
  "CWE-338",
  need=r"(token|secret|password|otp|nonce|session|key|reset|csrf)"),
R("S-INNERHTML", "HTML injection sink", "HOTSPOT", "MAJOR", ("js",),
  r"\.(innerHTML|outerHTML)\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(",
  "Assigning raw HTML — potential XSS sink.",
  "If the value contains user input, scripts can be injected into the page.",
  "Use textContent, or sanitize with DOMPurify before inserting HTML.",
  "CWE-79 · OWASP A03"),
R("S-DANGER", "dangerouslySetInnerHTML", "HOTSPOT", "MAJOR", ("js",),
  r"dangerouslySetInnerHTML",
  "React raw-HTML escape hatch in use.",
  "Bypasses React's XSS protection.",
  "Render as text, or sanitize the HTML first.",
  "CWE-79"),
R("S-TIMEOUT-STR", "setTimeout with string", "VULN", "MAJOR", ("js",),
  r"set(Timeout|Interval)\s*\(\s*[\"'`]",
  "String argument to setTimeout/setInterval is implied eval.",
  "The string is compiled and executed like eval.",
  "Pass a function reference instead.",
  "CWE-95"),
R("S-LOCALSTORAGE", "Secret in localStorage", "HOTSPOT", "MAJOR", ("js",),
  r"localStorage\.setItem\s*\(\s*[\"'][^\"']*(token|jwt|password|secret|auth)",
  "Sensitive value stored in localStorage.",
  "localStorage is readable by any script on the page (XSS steals it).",
  "Prefer httpOnly cookies for session tokens.",
  "CWE-522", flags=re.I),
R("S-JWT-NONE", "JWT 'none' algorithm", "VULN", "BLOCKER", ("js", "py"),
  r"algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']",
  "JWT verification accepts the 'none' algorithm.",
  "Attackers can forge unsigned tokens that pass verification.",
  "Pin an explicit algorithm list, e.g. ['HS256'] or ['RS256'].",
  "CWE-347", flags=re.I),
R("S-CORS", "CORS wildcard", "HOTSPOT", "MAJOR", ("js", "py"),
  r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*",
  "CORS allows all origins.",
  "Any website can call this API with the user's credentials context.",
  "Whitelist specific origins.",
  "OWASP A05"),
R("S-DEBUG", "Debug mode enabled", "HOTSPOT", "MAJOR", ("py",),
  r"debug\s*=\s*True",
  "debug=True — never in production.",
  "Flask/Django debug mode exposes an interactive console and stack traces.",
  "Drive debug from an environment variable, defaulting to off.",
  "CWE-489 · OWASP A05"),
R("S-BIND-ALL", "Binding to all interfaces", "HOTSPOT", "MINOR", ("py", "js"),
  r"[\"']0\.0\.0\.0[\"']",
  "Service binds to 0.0.0.0 (all interfaces).",
  "Exposes the service on every network interface, including public ones.",
  "Bind to 127.0.0.1 unless external access is intended.",
  "CWE-668"),
R("S-MKTEMP", "Insecure temp file", "VULN", "MAJOR", ("py",),
  r"tempfile\.mktemp\s*\(",
  "tempfile.mktemp is race-condition prone.",
  "The name can be claimed by an attacker between creation and use.",
  "Use tempfile.NamedTemporaryFile or mkstemp.",
  "CWE-377"),
R("B-BARE-EXCEPT", "Bare except", "BUG", "MAJOR", ("py",),
  r"^\s*except\s*:",
  "Bare except: catches everything, including SystemExit/KeyboardInterrupt.",
  "Hides real failures and makes the process unkillable.",
  "Catch the specific exception types you expect.",
  "Reliability"),
R("B-EQEQ", "Loose equality", "BUG", "MINOR", ("js",),
  r"[^=!<>]==[^=]|[^!]!=[^=]",
  "== / != perform type coercion.",
  "'' == 0 is true; coercion causes subtle logic bugs.",
  "Use === and !==.",
  "Reliability",
  skip=r"^\s*(//|\*|/\*)"),
R("Q-TODO", "TODO/FIXME marker", "SMELL", "INFO", ("py", "js", "sql"),
  r"\b(TODO|FIXME|XXX|HACK)\b",
  "Unresolved TODO/FIXME comment.",
  "Tracked work living only in comments tends to be forgotten.",
  "File a ticket and link it, or resolve it.",
  "Maintainability"),
R("Q-CONSOLE", "console.log left in code", "SMELL", "MINOR", ("js",),
  r"console\.(log|debug)\s*\(",
  "Debug logging left in code.",
  "Noisy output and possible data leakage in production.",
  "Remove, or use a leveled logger.",
  "Maintainability"),
R("Q-VAR", "var declaration", "SMELL", "MINOR", ("js",),
  r"\bvar\s+[A-Za-z_$]",
  "var is function-scoped and hoisted.",
  "Block-scoped declarations prevent shadowing bugs.",
  "Use let or const.",
  "Maintainability"),
# ---- Secret token signatures (Gitleaks-style) ----
R("S-TOKEN", "Known secret token format", "VULN", "BLOCKER", ("py", "js"),
  r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}"
  r"|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35}"
  r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}",
  "String matches a known secret format (AWS/GitHub/Slack/Stripe/Google key, private key, or JWT).",
  "Provider-format tokens in source are live credentials until proven otherwise.",
  "Remove it, rotate the credential immediately, and load it from a secrets manager.",
  "CWE-798 · OWASP A07"),
# ---- Additional vulnerability classes ----
R("S-SSTI", "Template injection risk", "VULN", "CRITICAL", ("py",),
  r"render_template_string\s*\(\s*(?![\"'])",
  "render_template_string with a non-literal template.",
  "User input compiled as a Jinja2 template is server-side template injection → RCE.",
  "Pass data as template parameters; never build template source from input.",
  "CWE-1336 · OWASP A03"),
R("S-XML", "XML parsing without a hardened parser", "HOTSPOT", "MINOR", ("py",),
  r"(?:^|\s)(?:import\s+xml\.(?:etree|dom|sax)|from\s+xml\.(?:etree|dom|sax))",
  "Stdlib XML parsers are unsafe for untrusted input.",
  "xml.etree/dom/sax are vulnerable to entity-expansion and (historically) XXE attacks.",
  "Parse untrusted XML with a hardened parser such as defusedxml or lazaret.safexml.",
  "CWE-611"),
R("S-MARKSAFE", "mark_safe usage", "HOTSPOT", "MAJOR", ("py",),
  r"mark_safe\s*\(",
  "mark_safe bypasses Django's HTML escaping.",
  "If the value contains user input, this is an XSS vector.",
  "Escape user data; use format_html for building markup.",
  "CWE-79"),
R("S-AUTOESCAPE", "Template autoescape disabled", "VULN", "MAJOR", ("py",),
  r"autoescape\s*=\s*False",
  "Template autoescaping is turned off.",
  "Every rendered variable becomes a potential XSS vector.",
  "Leave autoescape on; mark trusted fragments individually.",
  "CWE-79"),
R("S-PARAMIKO", "SSH host key verification disabled", "VULN", "MAJOR", ("py",),
  r"AutoAddPolicy|WarningPolicy",
  "SSH host keys accepted without verification.",
  "Enables man-in-the-middle attacks on SSH connections.",
  "Use RejectPolicy with a managed known_hosts file.",
  "CWE-295"),
R("S-CLEARTEXT-PROTO", "Cleartext protocol module", "HOTSPOT", "MINOR", ("py",),
  r"(?:^|\s)(?:import\s+(?:telnetlib|ftplib)|from\s+(?:telnetlib|ftplib))",
  "Telnet/FTP transmit credentials in cleartext.",
  "Anyone on the network path can capture the credentials.",
  "Use SSH/SFTP (e.g. paramiko) instead.",
  "CWE-319"),
R("S-CHMOD", "Overly permissive file mode", "VULN", "MAJOR", ("py",),
  r"chmod\s*\([^,)]*,\s*0o?7[67]7",
  "File made world-writable (777/767).",
  "Any local user or process can modify the file.",
  "Use the least permissive mode that works (e.g. 0o600/0o644).",
  "CWE-732"),
R("S-WEAKCIPHER-PY", "Weak cipher or mode", "VULN", "MAJOR", ("py",),
  r"\b(?:DES|DES3|ARC4|Blowfish)\.new|MODE_ECB",
  "DES/RC4/Blowfish/ECB are cryptographically weak.",
  "These ciphers/modes are breakable or leak plaintext structure.",
  "Use AES-GCM (cryptography library, AESGCM).",
  "CWE-327"),
R("S-WEAKCIPHER-JS", "Weak cipher", "VULN", "MAJOR", ("js",),
  r"createCipheriv\s*\(\s*[\"'](?:des|des-ede3?|rc4|aes-\d+-ecb)",
  "DES/RC4/ECB are cryptographically weak.",
  "These ciphers/modes are breakable or leak plaintext structure.",
  "Use aes-256-gcm.",
  "CWE-327", flags=re.I),
R("S-PROTO", "Prototype pollution sink", "VULN", "MAJOR", ("js",),
  r"\[\s*[\"']__proto__[\"']\s*\]|\.__proto__\s*[=.[]|constructor\s*\[\s*[\"']prototype[\"']\s*\]",
  "Write access to __proto__/prototype.",
  "Attacker-controlled keys can pollute Object.prototype and change app behavior globally.",
  "Block __proto__/constructor/prototype keys in merges; use Object.create(null) maps.",
  "CWE-1321"),
R("S-NOSQL", "MongoDB $where operator", "VULN", "MAJOR", ("js",),
  r"\$where",
  "$where evaluates JavaScript inside the database.",
  "User input in $where is NoSQL injection with code execution.",
  "Use query operators ($eq, $in, …) instead.",
  "CWE-943"),
R("S-VM-JS", "vm module code execution", "HOTSPOT", "MAJOR", ("js",),
  r"vm\.runIn(?:New|This)?Context|require\s*\(\s*[\"']vm[\"']",
  "Node vm module is not a security sandbox.",
  "Code can escape the vm context and reach the host process.",
  "Don't run untrusted code in-process; use isolated workers/containers.",
  "CWE-94"),
R("S-SPAWN-SHELL", "child_process with shell:true", "VULN", "CRITICAL", ("js",),
  r"shell\s*:\s*true",
  "shell:true routes the command through a shell.",
  "Shell metacharacters in arguments become command injection.",
  "Use execFile/spawn with an args array and shell:false.",
  "CWE-78"),
# ---- Supply-chain / obfuscation indicators ----
R("SC-EVAL-DECODE", "Decoded payload execution", "VULN", "BLOCKER", ("py", "js"),
  r"\b(?:eval|exec|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from|"
  r"base64\.b64decode|b64decode|codecs\.decode|zlib\.decompress|marshal\.loads)\s*\(",
  "Code decoded (base64/escape) and immediately executed.",
  "Decode-then-execute is the signature pattern of malware droppers and supply-chain implants.",
  "Treat as hostile until proven otherwise; inspect the decoded payload.",
  "CWE-506 · Supply chain"),
R("SC-PACKER", "Packed JavaScript (p,a,c,k,e,d)", "VULN", "CRITICAL", ("js",),
  r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e",
  "Dean Edwards packer signature — self-decoding packed code.",
  "Legitimate modern packages ship minified, not packed; packing hides intent.",
  "Unpack and review the payload before trusting this file.",
  "CWE-506 · Supply chain"),
R("SC-MARSHAL", "Marshalled bytecode execution", "VULN", "CRITICAL", ("py",),
  r"marshal\.loads\s*\(|exec\s*\(\s*compile\s*\(",
  "Executing marshalled/compiled bytecode blobs.",
  "Bytecode blobs evade source review — a common Python malware technique.",
  "Inspect the blob's origin; refuse opaque executable data in source trees.",
  "CWE-506 · Supply chain"),
# ---- SQL (.sql scripts, stored procedures, migrations) ----
R("SQL-XPCMD", "OS command execution via SQL", "VULN", "CRITICAL", ("sql",),
  r"\bxp_cmdshell\b",
  "xp_cmdshell runs operating-system commands from SQL Server.",
  "Enables full OS command execution from the database; a top post-exploitation target.",
  "Keep xp_cmdshell disabled; use a vetted, sandboxed job runner instead.",
  "CWE-78 · OWASP A03", flags=re.I),
R("SQL-DYNAMIC", "Dynamic SQL from concatenation", "VULN", "BLOCKER", ("sql",),
  r"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+"
  r"|EXECUTE\s+IMMEDIATE\b[^;]*\|\|"
  r"|sp_executesql\b[^;]*\+"
  r"|EXEC\s*\(\s*['\"][^']*['\"]\s*\+"
  r"|SET\s+@\w+\s*=[^;]*['\"][^;]*(?:\+|\|\|)",
  "Dynamic SQL built by concatenating variables into the statement.",
  "String-built SQL executed with EXEC / EXECUTE IMMEDIATE / sp_executesql is SQL injection inside the database.",
  "Use parameterized dynamic SQL (sp_executesql with @params, or bind variables).",
  "CWE-89 · OWASP A03", flags=re.I),
R("SQL-CRED", "Hardcoded database credential", "VULN", "BLOCKER", ("sql",),
  r"(?:IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]|PASSWORD\s*=?\s*['\"][^'\"]+['\"]|IDENTIFIED\s+BY\s+PASSWORD)",
  "Credential embedded in a SQL script.",
  "Passwords in DDL scripts leak through version control and backups.",
  "Provision credentials out-of-band (secrets manager / vault), not in checked-in SQL.",
  "CWE-798 · OWASP A07",
  # Verdict-integrity fix (audit C2): word-bounded placeholder noise words, so
  # a real credential on a line that merely mentions "example" is not skipped.
  skip=r"\bplaceholder\b|\bexample\b|\bdummy\b|\bmock\b|\bxxxx+\b", flags=re.I),
R("SQL-GRANT-ALL", "Excessive privilege grant", "HOTSPOT", "MAJOR", ("sql",),
  r"\bGRANT\s+ALL\b|\bWITH\s+GRANT\s+OPTION\b",
  "GRANT ALL / WITH GRANT OPTION hands over broad privileges.",
  "Violates least privilege; a compromised account inherits everything.",
  "Grant only the specific privileges the role needs.",
  "CWE-732 · OWASP A01", flags=re.I),
R("SQL-GRANT-PUBLIC", "Grant to PUBLIC", "HOTSPOT", "MAJOR", ("sql",),
  r"\bGRANT\b[^;]*\bTO\s+PUBLIC\b",
  "Privilege granted to PUBLIC (every user).",
  "PUBLIC grants apply to all current and future accounts, including low-trust ones.",
  "Grant to a specific role instead of PUBLIC.",
  "CWE-732 · OWASP A01", flags=re.I),
R("SQL-FILE", "Filesystem access from SQL", "VULN", "CRITICAL", ("sql",),
  r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b|\bLOAD_FILE\s*\(|\bLOAD\s+DATA\s+INFILE\b",
  "SQL reads/writes the server filesystem (OUTFILE / LOAD_FILE).",
  "A classic data-exfiltration and webshell-drop primitive in SQL injection exploitation.",
  "Disable FILE privilege; never build these paths from untrusted input.",
  "CWE-73 · OWASP A03", flags=re.I),
R("SQL-OPENROWSET", "Ad-hoc remote data access", "HOTSPOT", "MAJOR", ("sql",),
  r"\b(?:OPENROWSET|OPENQUERY|OPENDATASOURCE)\s*\(",
  "OPENROWSET/OPENQUERY perform ad-hoc external connections.",
  "Can reach arbitrary hosts/files and is abused for lateral movement.",
  "Disable Ad Hoc Distributed Queries; use configured linked servers with least privilege.",
  "CWE-610", flags=re.I),
R("SQL-FK-OFF", "Integrity checks disabled", "HOTSPOT", "MAJOR", ("sql",),
  r"SET\s+FOREIGN_KEY_CHECKS\s*=\s*0|NOCHECK\s+CONSTRAINT|SET\s+CONSTRAINTS\s+ALL\s+DEFERRED",
  "Referential-integrity enforcement is turned off.",
  "Disabling constraints allows orphaned/inconsistent data to be written.",
  "Re-enable checks immediately after the bulk operation; scope it tightly.",
  "CWE-20", flags=re.I),
R("SQL-TRUSTWORTHY", "TRUSTWORTHY database", "HOTSPOT", "MAJOR", ("sql",),
  r"SET\s+TRUSTWORTHY\s+ON",
  "TRUSTWORTHY ON enables privilege escalation paths in SQL Server.",
  "Combined with impersonation it can lead to sysadmin escalation.",
  "Leave TRUSTWORTHY OFF; sign modules instead.",
  "CWE-269", flags=re.I),
R("SQL-NOLOCK", "Dirty-read hint", "SMELL", "MINOR", ("sql",),
  r"WITH\s*\(\s*NOLOCK\s*\)|READ\s+UNCOMMITTED",
  "NOLOCK / READ UNCOMMITTED permits dirty reads.",
  "Returns uncommitted, possibly inconsistent data; a common source of subtle bugs.",
  "Use an appropriate isolation level (e.g. READ COMMITTED SNAPSHOT).",
  "Reliability", flags=re.I),
R("SQL-SELECT-STAR", "SELECT *", "SMELL", "MINOR", ("sql",),
  r"\bSELECT\s+\*",
  "SELECT * fetches all columns.",
  "Breaks silently on schema changes and moves unneeded data.",
  "List the columns you actually need.",
  "Maintainability", flags=re.I),
]

TEXT_RULES = [
R("B-EMPTY-CATCH", "Empty catch block", "BUG", "MAJOR", ("js",),
  r"catch\s*(\([^)]*\))?\s*\{\s*\}",
  "Exception swallowed by empty catch.",
  "Errors vanish silently, making failures undiagnosable.",
  "Handle the error or at least log it.",
  "Reliability"),
R("B-EXCEPT-PASS", "except: pass", "BUG", "MAJOR", ("py",),
  r"except[^\n:]*:\s*\n\s*pass\b",
  "Exception swallowed with pass.",
  "Errors vanish silently, making failures undiagnosable.",
  "Handle the error or at least log it.",
  "Reliability"),
# SQL-DELETE-NOWHERE / SQL-UPDATE-NOWHERE used to be tempered-dot patterns
# ((?:(?!\bWHERE\b|;).)*; with re.S) applied over the whole file. On
# adversarial input (thousands of unterminated DELETE statements, no ';')
# every match attempt scans to EOF and backtracks: O(starts × file) — 51 s CPU
# on 280 KB, extrapolating to ~40 min at the 2 MB file cap (audit F11). The
# patterns below are deliberately statement-anchored and linear: after the
# DELETE/UPDATE keyword they match ONE identifier and at most one SET keyword,
# never scanning to EOF. The "no WHERE before the statement ends" decision is
# made by the linear per-statement pre-scan in scan_sql_nowhere() — one
# O(n) pass over the file — not by the regex.
R("SQL-DELETE-NOWHERE", "DELETE without WHERE", "BUG", "MAJOR", ("sql",),
  r"\bDELETE\s+FROM\s+[\w.\"\[\]`]+",
  "DELETE has no WHERE clause — it removes every row.",
  "An unqualified DELETE wipes the whole table; usually a mistake outside teardown scripts.",
  "Add a WHERE clause, or use TRUNCATE deliberately if a full wipe is intended.",
  "CWE-665", flags=re.I),
R("SQL-UPDATE-NOWHERE", "UPDATE without WHERE", "BUG", "MAJOR", ("sql",),
  r"\bUPDATE\s+[\w.\"\[\]`]+\s+SET\b",
  "UPDATE has no WHERE clause — it changes every row.",
  "An unqualified UPDATE rewrites the entire table.",
  "Add a WHERE clause to scope the update.",
  "CWE-665", flags=re.I),
]

# ---------------- Taint tracking (lightweight, intra-file) ----------------
# Sources: user input and decode functions. Sinks: dangerous calls.
TAINT_SOURCES = {
    "py": re.compile(r"request\.(args|form|values|json|data|cookies|headers|files|get_json)"
                     r"|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\("),
    "js": re.compile(r"req\.(query|body|params|headers|cookies)|process\.argv"
                     r"|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams"
                     r"|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\("),
}
# (id-suffix, sink regex, category, severity, cwe, fix)
TAINT_SINKS = {
    "py": [
        ("CMD", re.compile(r"os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\("),
         "command injection", "CRITICAL", "CWE-78",
         "Validate/allowlist the value; pass args as a list with shell=False."),
        ("CODE", re.compile(r"(?<![\w.])(eval|exec)\s*\("),
         "code injection", "CRITICAL", "CWE-95",
         "Never execute untrusted strings; use safe parsing."),
        ("SQL", re.compile(r"\.(execute|executemany)\s*\("),
         "SQL injection", "BLOCKER", "CWE-89",
         "Use parameterized queries."),
        ("PATH", re.compile(r"(?<![\w.])open\s*\(|send_file\s*\(|send_from_directory\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        ("SSRF", re.compile(r"requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\("),
         "server-side request forgery", "MAJOR", "CWE-918",
         "Allowlist target hosts and schemes; block internal addresses."),
        ("REDIR", re.compile(r"(?<![\w.])redirect\s*\("),
         "open redirect", "MAJOR", "CWE-601",
         "Allowlist redirect targets or use relative paths."),
        ("SSTI", re.compile(r"render_template_string\s*\("),
         "template injection", "CRITICAL", "CWE-1336",
         "Pass data as template parameters, never into template source."),
    ],
    "js": [
        ("CMD", re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\("),
         "command injection", "CRITICAL", "CWE-78",
         "Use execFile/spawn with an args array; validate the value."),
        ("CODE", re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("),
         "code injection", "CRITICAL", "CWE-95",
         "Never execute untrusted strings; use JSON.parse or a dispatch map."),
        ("SQL", re.compile(r"\.(query|execute)\s*\("),
         "SQL injection", "BLOCKER", "CWE-89",
         "Use placeholders with a parameter array."),
        ("PATH", re.compile(r"\.(sendFile|download)\s*\(|readFile(Sync)?\s*\(|createReadStream\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        ("SSRF", re.compile(r"\bfetch\s*\(|axios(\.(get|post|put|delete|request))?\s*\(|https?\.(get|request)\s*\("),
         "server-side request forgery", "MAJOR", "CWE-918",
         "Allowlist target hosts and schemes; block internal addresses."),
        ("REDIR", re.compile(r"\.redirect\s*\("),
         "open redirect", "MAJOR", "CWE-601",
         "Allowlist redirect targets or use relative paths."),
        ("XSS", re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
         "cross-site scripting", "MAJOR", "CWE-79",
         "Escape/sanitize before rendering; prefer textContent."),
    ],
}
ASSIGN_RE = {
    "py": re.compile(r"^\s*([A-Za-z_]\w*)\s*=(?![=])\s*(.+)"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)"),
}

STRING_LIT_RE = re.compile(r"\"[^\"]*\"|'[^']*'|`[^`]*`")

# ---------------- Sanitizer model (SonarQube / Semgrep style) ----------------
# Values passed through a sanitizer stop being tainted. "full" sanitizers
# (numeric coercion) cleanse every sink; "partial" sanitizers (keyed by sink
# suffix) cleanse one category. Body pattern allows one level of nested parens
# so int(request.args.get("id")) is recognized.
_SAN_BODY = r"(?:[^()]|\([^()]*\))*"
_FULL_SAN = {
    "py": re.compile(r"(?:int|float|bool|complex|uuid\.UUID|ipaddress\.ip_address)\s*\(" + _SAN_BODY + r"\)"),
    "js": re.compile(r"(?:parseInt|parseFloat|Number)\s*\(" + _SAN_BODY + r"\)"),
}
_PARTIAL_SAN = {
    "py": {
        "CMD": re.compile(r"(?:shlex|pipes)\.quote\s*\(" + _SAN_BODY + r"\)"),
        "XSS": re.compile(r"(?:html\.escape|markupsafe\.escape|cgi\.escape|bleach\.clean|escape)\s*\(" + _SAN_BODY + r"\)"),
        "PATH": re.compile(r"(?:os\.path\.basename|basename|secure_filename)\s*\(" + _SAN_BODY + r"\)"),
    },
    "js": {
        "XSS": re.compile(r"(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\(" + _SAN_BODY + r"\)"),
        "SQL": re.compile(r"(?:mysql2?|pool|connection|conn|db)\.escape\s*\(" + _SAN_BODY + r"\)"),
        "PATH": re.compile(r"path\.basename\s*\(" + _SAN_BODY + r"\)"),
        "CMD": re.compile(r"(?:shellQuote|shell_quote)\s*\(" + _SAN_BODY + r"\)"),
    },
}

def _neutralize(text, lang, suffix=None):
    """Strip sanitizer calls so their sanitized content stops counting as taint."""
    text = _FULL_SAN[lang].sub(" ", text)
    if suffix and suffix in _PARTIAL_SAN.get(lang, {}):
        text = _PARTIAL_SAN[lang][suffix].sub(" ", text)
    return text

# SQL suffix ↔ flow category, for applying shared config to the intra-file engine
_SUFFIX_BY_CATEGORY = {
    "SQL injection": "SQL", "command injection": "CMD", "code injection": "CODE",
    "template injection": "SSTI", "path traversal": "PATH",
    "server-side request forgery": "SSRF", "open redirect": "REDIR",
    "cross-site scripting": "XSS",
}
_CAT_META = {  # category -> (severity, cwe, fix) for intra-file sink rows
    "SQL injection": ("BLOCKER", "CWE-89", "Use parameterized queries with placeholders."),
    "command injection": ("CRITICAL", "CWE-78", "Pass args as a list with shell=False / use execFile."),
    "code injection": ("CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."),
    "template injection": ("CRITICAL", "CWE-1336", "Pass data as template parameters."),
    "path traversal": ("MAJOR", "CWE-22", "Confine the path to an allowed base directory."),
    "server-side request forgery": ("MAJOR", "CWE-918", "Allowlist hosts/schemes."),
    "open redirect": ("MAJOR", "CWE-601", "Allowlist redirect targets."),
    "cross-site scripting": ("MAJOR", "CWE-79", "Escape/sanitize before rendering."),
}

#: Exit code for a taint config passed via --taint-config whose rules failed
#: validation (unknown category, empty pattern, malformed section). Distinct
#: from the quality-gate exit 1, argparse's exit 2 and EXIT_OUTPUT's 3.
EXIT_TAINT_CONFIG = 4

#: The complete set of sink categories a taint config may use (sorted for
#: stable warning/report text). Kept in sync with _CAT_META / _SUFFIX_BY_CATEGORY.
VALID_CATEGORIES = tuple(sorted(_CAT_META))

# Validation warnings from the most recent apply_taint_config() call: every
# rule the loader refused. Rules are never silently dropped — a custom sink
# that fails validation must not quietly become inert while the scan still
# reports PASSED (the bug this fixes). The CLI drains these after loading.
_TAINT_CONFIG_WARNINGS = []


def _taint_config_warn(msg):
    _TAINT_CONFIG_WARNINGS.append(msg)


def get_taint_config_warnings():
    """Warnings from the last apply_taint_config() call — rules that were
    rejected rather than applied. Each names the rule and the reason, and
    lists the valid categories. The CLI prefixes each with the file path."""
    return list(_TAINT_CONFIG_WARNINGS)


def _dedupe(msgs):
    """First-occurrence de-duplication of warning messages (both taint
    engines report the same rejected rule; print each rejection once)."""
    seen, out = set(), []
    for m in msgs:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def apply_taint_config(cfg):
    """Extend the intra-file taint model (sources/sinks/sanitizers) from a
    config dict — the same file consumed by the interprocedural engine.

    Invalid rules are not silently dropped: each one records a warning (see
    get_taint_config_warnings()) naming the rule and the reason, and listing
    the valid categories. The CLI prefixes each warning with the config file
    path. Message texts match lazaret_flow.configure() on purpose, so the
    CLI can dedupe the two engines' identical rejections.
    """
    del _TAINT_CONFIG_WARNINGS[:]
    if not isinstance(cfg, dict):
        _taint_config_warn(
            f"top level is {type(cfg).__name__}, not an object — nothing applied")
        return
    for key in cfg:
        if key not in ("python", "javascript") and not str(key).startswith("_"):
            _taint_config_warn(
                f"unknown top-level section {key!r} — expected 'python' or "
                f"'javascript'; rule skipped")
    for lang_key, lang in (("python", "py"), ("javascript", "js")):
        section = cfg.get(lang_key, {}) or {}
        if not isinstance(section, dict):
            _taint_config_warn(
                f"section '{lang_key}' is {type(section).__name__}, "
                f"not an object — section ignored")
            continue
        for pat in section.get("sources", []):
            # 48033f94: an auto-loaded config from the scanned repo must never
            # crash the scan (re.PatternError at :643 was a lost-results, exit-1
            # crash). A source pattern that is not a valid regex is rejected
            # like any other invalid rule: warning + skip — never applied
            # uncompiled, never raised.
            try:
                new_re = re.compile(TAINT_SOURCES[lang].pattern + "|" + pat)
            except re.error as exc:
                _taint_config_warn(
                    f"{lang_key}.sources pattern {pat!r} is not a valid regex "
                    f"({exc}) — rule skipped")
                continue
            TAINT_SOURCES[lang] = new_re
        sinks = section.get("sinks", [])
        if not isinstance(sinks, list):
            _taint_config_warn(
                f"{lang_key}.sinks is {type(sinks).__name__}, not a list — "
                f"section ignored")
            sinks = []
        for idx, sk in enumerate(sinks, 1):
            if not isinstance(sk, dict):
                _taint_config_warn(
                    f"{lang_key} sink #{idx} is not an object — rule skipped")
                continue
            cat, pattern = sk.get("category"), sk.get("pattern")
            if not cat:
                _taint_config_warn(
                    f"{lang_key} sink #{idx} (pattern {pattern!r}) has no "
                    f"'category' — rule skipped; valid categories: "
                    f"{', '.join(VALID_CATEGORIES)}")
                continue
            if cat not in _CAT_META:
                _taint_config_warn(
                    f"{lang_key} sink #{idx} (pattern {pattern!r}) has unknown "
                    f"category {cat!r} — rule skipped; valid categories: "
                    f"{', '.join(VALID_CATEGORIES)}")
                continue
            if not pattern:
                _taint_config_warn(
                    f"{lang_key} sink #{idx} (category {cat!r}) has an empty "
                    f"'pattern' — rule skipped")
                continue
            suffix = _SUFFIX_BY_CATEGORY[cat]
            sev, cwe, fix = _CAT_META[cat]
            # 48033f94: invalid sink regex — reject the rule (warning + skip)
            # instead of crashing the scan.
            try:
                sink_re = re.compile(pattern)
            except re.error as exc:
                _taint_config_warn(
                    f"{lang_key} sink #{idx} (category {cat!r}) pattern "
                    f"{pattern!r} is not a valid regex ({exc}) — rule skipped")
                continue
            TAINT_SINKS[lang].append((suffix, sink_re, cat, sev, cwe, fix))
        san = section.get("sanitizers", {}) or {}
        if not isinstance(san, dict):
            _taint_config_warn(
                f"{lang_key}.sanitizers is {type(san).__name__}, not an "
                f"object — section ignored")
            continue
        for name in san.get("full", []):
            # 48033f94: re.escape(name) cannot fail for a str, but a non-str
            # (int, None) entry previously raised TypeError at re.escape, and
            # the compound regex could still fail to compile — reject with a
            # warning instead of crashing.
            try:
                new_re = re.compile(
                    _FULL_SAN[lang].pattern + "|" + re.escape(name)
                    + r"\s*\(" + _SAN_BODY + r"\)")
            except (re.error, TypeError) as exc:
                _taint_config_warn(
                    f"{lang_key}.sanitizers.full entry {name!r} is not a valid "
                    f"sanitizer name ({exc}) — rule skipped")
                continue
            _FULL_SAN[lang] = new_re
        partial = san.get("partial", {}) or {}
        if not isinstance(partial, dict):
            _taint_config_warn(
                f"{lang_key}.sanitizers.partial is {type(partial).__name__}, "
                f"not an object — section ignored")
            continue
        for name, cats in partial.items():
            if not isinstance(cats, (list, tuple)):
                _taint_config_warn(
                    f"{lang_key} sanitizer {name!r} has {type(cats).__name__} "
                    f"categories, not a list — rule skipped")
                continue
            for cat in cats:
                suf = _SUFFIX_BY_CATEGORY.get(cat)
                if not suf:
                    _taint_config_warn(
                        f"{lang_key} sanitizer {name!r} lists unknown category "
                        f"{cat!r} — category ignored; valid categories: "
                        f"{', '.join(VALID_CATEGORIES)}")
                    continue
                # 48033f94: reject an invalid partial-sanitizer rule (warning
                # + skip) instead of letting re.compile/re.escape raise —
                # re.escape() of a non-str name must be inside the try too.
                try:
                    add = re.escape(name) + r"\s*\(" + _SAN_BODY + r"\)"
                    base = _PARTIAL_SAN[lang].get(suf)
                    new_re = re.compile((base.pattern + "|" + add) if base else add)
                except (re.error, TypeError) as exc:
                    _taint_config_warn(
                        f"{lang_key} sanitizer {name!r} (category {cat!r}) "
                        f"could not be compiled ({exc}) — rule skipped")
                    continue
                _PARTIAL_SAN[lang][suf] = new_re

def taint_scan(path, lines, lang):
    if lang not in TAINT_SOURCES:   # SQL and others: pattern rules only, no taint flow
        return []
    issues = []
    tainted = {}   # var -> (line_no, frozenset(sink suffixes it is sanitized/clean for))
    src = TAINT_SOURCES[lang]
    partial_cats = list(_PARTIAL_SAN.get(lang, {}))

    def has_var(text_code, suf):
        """A carrier var still poses danger for suffix suf if present and not clean for it."""
        for v, (_, clean) in tainted.items():
            if suf not in clean and re.search(r"\b%s\b" % re.escape(v), text_code):
                return True
        return False

    for i, line in enumerate(lines):
        if is_comment(line, lang):
            continue
        m = ASSIGN_RE[lang].match(line)
        if m:
            name, rhs = m.group(1), m.group(2)
            base = STRING_LIT_RE.sub("", _neutralize(rhs, lang))  # full sanitizers stripped
            is_tainted = bool(src.search(base)) or has_var(base, None)
            if is_tainted:
                clean = set()
                for suf in partial_cats:
                    neut = STRING_LIT_RE.sub("", _neutralize(rhs, lang, suf))
                    if not src.search(neut) and not has_var(neut, suf):
                        clean.add(suf)
                if name not in tainted:
                    tainted[name] = (i + 1, frozenset(clean))
        for suffix, sink_re, cat, sev, cwe, fix in TAINT_SINKS[lang]:
            sm = sink_re.search(line)
            if not sm:
                continue
            # neutralize full + this-category sanitizers in the sink's arguments
            rest = _neutralize(line[sm.end():], lang, suffix)
            rest_code = STRING_LIT_RE.sub("", rest)
            carriers = [v for v in tainted
                        if suffix not in tainted[v][1]
                        and re.search(r"\b%s\b" % re.escape(v), rest_code)]
            if not carriers and not src.search(rest_code):
                continue
            what = (f"untrusted data via '{carriers[0]}' (tainted at line {tainted[carriers[0]][0]})"
                    if carriers else "untrusted data")
            issues.append(mk_issue(
                {"id": f"T-{suffix}", "name": f"Tainted flow → {cat}", "type": "VULN", "sev": sev,
                 "msg": f"Possible {cat}: {what} reaches this sink.",
                 "why": "Data from user input or a decode function flows into a dangerous call "
                        "without visible sanitization (lightweight intra-file taint tracking).",
                 "fix": fix, "ref": f"{cwe} · Taint analysis"}, path, i + 1, lines))
    return issues

# ---------------- Obfuscation / entropy heuristics ----------------
import math

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())

ENTROPY_VALUE_RE = re.compile(r"[=:]\s*[\"']([A-Za-z0-9+/=_\-]{20,})[\"']")
B64_BLOB_RE = re.compile(r"[\"'][A-Za-z0-9+/]{200,}={0,2}[\"']")
CHARCODE_RE = re.compile(r"String\.fromCharCode")
OBF_IDENT_RE = re.compile(r"\b_0x[0-9a-f]{4,}\b")
# Verdict-integrity fix (audit C2/G2): the bare word `test` matched anywhere on
# the line — including in a comment — and silently disabled every entropy/secret
# check on it. REMOVED: `test` must not gate entropy detection at all. The
# remaining tokens are word-bounded so substrings (`latest`, `attested`,
# `detest`) no longer suppress.
SECRET_SKIP_RE = re.compile(r"environ|process\.env|getenv|\bplaceholder\b|\bexample\b|"
                            r"\bdummy\b|\bsample\b|\bmock\b|\bredacted\b|\bxxxx+\b", re.I)

def entropy_secretish(v):
    """True only if a high-entropy literal actually looks like a credential, not a
    URL/path, a dotted name, or a CamelCase/snake_case identifier. This filters the
    common S-ENTROPY false positives (route strings, TypeVar bounds, class names)."""
    if v.count("/") >= 2 or v.startswith("/") or " " in v or "\\" in v:
        return False                                  # path, URL, or sentence
    core = v.replace("_", "").replace("-", "").replace(".", "")
    if core.isalpha():
        return False                                  # identifier / CamelCase / word
    # real tokens carry digits or base64 symbols, not just letters+separators
    if not (any(c.isdigit() for c in v) or any(c in "+=" for c in v)):
        return False
    return shannon_entropy(v) > 4.0

# ---------------- Inline suppression ----------------
SUPPRESS_RE = re.compile(r"(?:#|//|--)\s*(?:nosec|NOSONAR|lazaret-ignore)\b(?::?\s*([\w,\s-]+))?", re.I)

# Verdict integrity (audit C2/H6): findings from these rule families are never
# suppressible by markers in the scanned code. Supply-chain indicators (SC-*)
# and interprocedural taint findings (X-*) describe the artifact's own attempt
# to hide; a dependency has no trusted reviewer to vouch for a `nosec` marker,
# so dep mode never honors suppression either (card G1/G2).
UNSUPPRESSIBLE_PREFIXES = ("SC-", "X-")


def string_literal_mask(line, lang=None):
    """Per-character boolean mask: True where a character is inside a string
    literal on this line (verdict-integrity fix, audit C2).

    Line-local, best-effort quote tracking: ' and " with backslash escapes for
    every language; ` only for JavaScript (template literals). When lang is
    unknown, backticks are treated as quotes — over-masking a marker is the
    fail-closed direction (a missed suppression surfaces a finding; a false
    suppression hides one).
    """
    mask = [False] * len(line)
    backtick_ok = (lang or "js") == "js"
    quote = None
    j = 0
    while j < len(line):
        ch = line[j]
        if quote is None:
            if ch in "\"'":
                quote = ch
            elif ch == "`" and backtick_ok:
                quote = "`"
        elif ch == "\\":
            mask[j] = True
            if j + 1 < len(line):
                mask[j + 1] = True
            j += 2
            continue
        elif ch == quote:
            quote = None
        else:
            mask[j] = True
        j += 1
    return mask


def marker_in_comment(line, lang=None):
    """The SUPPRESS_RE match on this line if it lives in real comment text —
    i.e. at least one character of the marker's span is outside every string
    literal — else None. A `-- nosec` inside a string (the audit PoC
    `os.system("rm -rf / -- nosec")`) returns None and does not suppress."""
    mask = string_literal_mask(line, lang)
    for m in SUPPRESS_RE.finditer(line):
        if any(not mask[k] for k in range(m.start(), m.end())):
            return m
    return None


def is_suppressed(issue, lines, lang=None, dep=False):
    # Suppression markers are reviewer annotations. The scanned code itself
    # must not be able to forge them (audit C2/G1: a marker inside a string
    # literal made a CRITICAL finding vanish and the gate PASSED), and
    # dependency/registry mode has no reviewer at all (G2: `// nosec` cleared
    # SC-EVAL-DECODE on a live implant). Never suppress supply-chain or
    # interprocedural findings, and never in dep mode.
    if dep or str(issue.get("rule", "")).startswith(UNSUPPRESSIBLE_PREFIXES):
        return False
    for ln in (issue["line"] - 1, issue["line"] - 2):
        if not (0 <= ln < len(lines)):
            continue
        if ln == issue["line"] - 2 and not lines[ln].strip().startswith(("#", "//")):
            continue  # previous line counts only if it is a standalone comment
        m = marker_in_comment(lines[ln], lang)
        if m:
            ids = m.group(1)
            if not ids or issue["rule"].upper() in [s.strip().upper() for s in ids.split(",")]:
                return True
    return False

# ---------------- Binary / compiled-artifact detection ----------------
# Source packages (sdists, npm tarballs, repos) should ship reviewable source,
# not prebuilt binaries. Smuggled binaries are a primary supply-chain vector:
# malicious code inside a compiled blob never appears in the source you review.
# Wheels legitimately ship compiled extensions, so presence there is inventory,
# not alarm. Detection is by content (magic bytes), not just file extension.

EXEC_MAGIC = [
    (b"\x7fELF", "ELF binary (Linux/Unix executable or shared object)"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary (macOS)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary (macOS)"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary (macOS)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit binary (macOS)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary or Java .class"),
    (b"\x00asm", "WebAssembly module"),
    (b"dex\n", "Android DEX bytecode"),
]
COMPILED_EXTS = {".so", ".pyd", ".dll", ".dylib", ".node", ".a", ".lib", ".o",
                 ".obj", ".exe", ".pyc", ".pyo", ".class", ".wasm",
                 ".dex", ".jar", ".msi", ".dmg"}
# Recognized benign binary assets — data, not code. Not flagged.
BENIGN_MAGIC = [b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"BM",
                b"\x00\x00\x01\x00", b"wOFF", b"wOF2", b"ID3", b"%PDF",
                b"II*\x00", b"MM\x00*", b"\x1a\x45\xdf\xa3", b"ftyp"]
NESTED_ARCHIVE_MAGIC = [(b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"),
                        (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
                        (b"7z\xbc\xaf\x27\x1c", "7-zip"), (b"Rar!", "rar")]

def byte_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)

def looks_binary(sample):
    """Heuristic text/binary classification from a leading byte sample."""
    if not sample:
        return False
    if b"\x00" in sample[:1024]:
        return True
    textset = set(range(0x20, 0x7f)) | {9, 10, 12, 13, 27}
    nontext = sum(1 for b in sample if b not in textset)
    return nontext / len(sample) > 0.30

def classify_binary(path, data, size, context):
    """Return a supply-chain issue dict for a suspicious non-source file, or None.

    context: 'sdist' | 'npm' | 'wheel' | 'repo'
    data:    leading bytes of the file (>= a few KB is ideal for entropy)
    size:    full file size in bytes
    """
    header = data[:512]
    ext = os.path.splitext(path)[1].lower()

    def issue(rid, name, sev, msg, why, fix):
        return {"rule": rid, "name": name, "type": "HOTSPOT", "sev": sev, "msg": msg,
                "why": why, "fix": fix, "ref": "CWE-506 · Supply chain",
                "file": path, "line": 1, "snippet": [], "snipStart": 1}

    is_bin = looks_binary(data[:2048])
    # 1) executable / compiled artifact (by magic, or extension as fallback)
    desc = next((d for sig, d in EXEC_MAGIC if header.startswith(sig)), None)
    if desc is None and is_bin and header.startswith(b"MZ"):
        desc = "Windows PE executable/DLL"
    if desc is None and ext in COMPILED_EXTS:
        desc = f"compiled artifact ({ext})"
    if desc:
        if context == "wheel":
            return issue("SC-BINARY", "Binary artifact in package", "INFO",
                f"Bundled binary: {desc}.",
                "Wheels legitimately ship compiled extensions. Listed for inventory; "
                "verify it matches the project's published, reproducible build.",
                "Cross-check against the upstream build; prefer building from source in sensitive contexts.")
        where = {"sdist": "a source distribution", "npm": "an npm package",
                 "repo": "the source tree"}.get(context, "the package")
        return issue("SC-BINARY", "Binary artifact in package", "CRITICAL",
            f"Executable/compiled binary in {where}: {desc}.",
            "Source packages should contain buildable source, not prebuilt binaries. "
            "Smuggled binaries are a primary supply-chain compromise vector — malicious "
            "code inside a compiled blob never appears in reviewable source.",
            "Confirm the binary's provenance; build from source instead of trusting a prebuilt blob.")
    # 2) nested archive — a known way to hide a second-stage payload from review
    if header[257:262] == b"ustar":
        return issue("SC-NESTED-ARCHIVE", "Nested archive in package", "MINOR",
            "Embedded tar archive inside the package.",
            "Nested archives can conceal second-stage payloads from source review.",
            "Extract and inspect the archive's contents.")
    for sig, kind in NESTED_ARCHIVE_MAGIC:
        if header.startswith(sig):
            if context == "wheel" and kind == "zip":
                break
            return issue("SC-NESTED-ARCHIVE", "Nested archive in package", "MINOR",
                f"Embedded {kind} archive inside the package.",
                "Nested archives can conceal second-stage payloads from source review "
                "(a known supply-chain evasion technique).",
                "Extract and inspect the archive's contents.")
    # 3) recognized benign asset (image/font/media/pdf) -> ignore
    if any(header.startswith(sig) for sig in BENIGN_MAGIC) or b"ftyp" in header[:16]:
        return None
    # 4) opaque high-entropy blob -> possible packed/encrypted payload
    if is_bin and size >= 1024:
        ent = byte_entropy(data[:8192])
        if ent > 7.2:
            return issue("SC-OPAQUE-BLOB", "High-entropy binary blob", "MAJOR",
                f"Opaque high-entropy file ({size} bytes, entropy {ent:.1f}/8).",
                "Encrypted or packed data shipped in a package can be a second-stage "
                "payload that is decoded and executed at runtime.",
                "Identify what this file is and why it ships; reject unexplained binary blobs.")
    return None

# ---------------- Truncation accounting (verdict integrity, audit C2/G16) ----------------
# Every place scanning is cut short must emit a signal, never a silent skip:
# a file that was not scanned cannot be a data point for a clean verdict.
# SC-* findings fail the "No supply-chain indicators" gate condition, so a
# truncated scan can never report PASSED.

def truncated_issue(path, detail, sev="CRITICAL", rule="SC-TRUNCATED", name="Scan truncated"):
    """Issue dict for a file/limit that stopped the scan early. `detail` names
    the concrete limit and numbers (e.g. '11644385 bytes declared')."""
    return {"rule": rule, "name": name, "type": "HOTSPOT", "sev": sev,
            "msg": f"File not fully scanned: {detail}.",
            "why": ("Scanning stopped early, so a clean verdict for this file is not "
                    "evidence of anything — the unscanned bytes are exactly where a "
                    "hostile artifact would put its payload (audit C2/G16: declared "
                    "sizes and entry counts are attacker-controlled and were used to "
                    "skip files with zero signal)."),
            "fix": "Review the file manually or raise the limit and re-scan.",
            "ref": "CWE-506 · Supply chain", "file": path, "line": 1,
            "snippet": [], "snipStart": 1}

LONG_LINE = 160
FN_LEN_LIMIT = 60
FN_CX_LIMIT = 12
EXTS = {".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
        ".mjs": "js", ".cjs": "js", ".sql": "sql"}
# G10: only .git and __pycache__ are skipped by default. The former is VCS
# metadata (never shippable source), the latter is generated bytecode. Every
# other classic "build output" directory — dist, build, migrations, vendor,
# coverage — is the most-published, most-shipped code there is (npm packages
# are *published from* dist/; migrations ARE the production SQL), and .git/
# can hold committed-then-deleted secrets. Skipping them by default made the
# hardcoded-credential and SQLi rules blind to exactly their best use case.
# They remain available as opt-in skips via --exclude (and keep their dep-dir
# behavior via --deps), and skipped trees are counted and reported, never
# silently dropped.
SKIP_DIRS = {".git", "__pycache__"}
# Legacy convenience names kept for --exclude / dep-marker interplay; they are
# NOT skipped unless explicitly listed.
OPTIN_SKIP_DIRS = ["node_modules", "venv", ".venv", "env", "dist", "build",
                   ".next", "coverage", "vendor", "site-packages", ".tox",
                   ".mypy_cache", ".pytest_cache", "migrations"]

# G10: skipped-directory accounting — every pruned tree is counted here and
# surfaced as INFO findings, never silently dropped. Reset per scan.
_SKIPPED_TREES = []   # [(relpath, file_count, byte_count)]

def _reset_scan_state():
    global _SKIPPED_TREES
    _SKIPPED_TREES = []

def _count_skipped_tree(root, tree_path):
    """Record a pruned directory with its file count and total size for the
    INFO blind-spot accounting surfaced after the scan."""
    n_files, n_bytes = 0, 0
    for dp, _dns, fns in os.walk(tree_path):
        for fn in fns:
            n_files += 1
            try:
                n_bytes += os.path.getsize(os.path.join(dp, fn))
            except OSError:
                pass
    rel = os.path.relpath(tree_path, root) if os.path.isabs(tree_path) else tree_path
    _SKIPPED_TREES.append((rel, n_files, n_bytes))

def skipped_tree_issues():
    """INFO issues summarizing the trees pruned by SKIP_DIRS/--exclude so the
    coverage gap is visible instead of silent."""
    out = []
    for rel, n_files, n_bytes in _SKIPPED_TREES:
        out.append({
            "rule": "Q-SKIPPED-TREE", "name": "Skipped directory (not scanned)",
            "type": "SMELL", "sev": "INFO",
            "msg": f"Directory {rel} was skipped ({n_files} files, {n_bytes} bytes unread).",
            "why": "Skipped trees are invisible to every rule — the classic hiding places "
                   "(dist, build, .git) hold published code and committed-then-deleted "
                   "secrets. Generated trees you own are fine to skip on purpose; "
                   "unexpected entries here are blind spots.",
            "fix": "Only exclude generated trees you control; remove the exclusion "
                   "otherwise so the tree is scanned.",
            "ref": "Maintainability",
            "file": rel, "line": 1, "snippet": "", "snipStart": 0})
    return out

# ---------------- Scanning ----------------
def is_comment(line, lang):
    t = line.strip()
    if lang == "py":
        return t.startswith("#")
    if lang == "sql":
        return t.startswith("--") or t.startswith("/*") or t.startswith("*")
    return t.startswith("//") or t.startswith("*") or t.startswith("/*")

# Line-level matchers for redacting credentials that appear on CONTEXT lines
# of a snippet (audit L1: a finding's ±2-line context can carry a DIFFERENT
# secret than the one flagged — e.g. an S-SECRET at line 3 whose context
# window includes the AWS key at line 4). Secret rules whose regex has no
# "skip" noise filter run raw; S-SECRET re-uses its own assignment regex so
# the same detection contract applies on context lines.
_SECRET_LINE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}"
               r"|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35}"
               r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"),
    re.compile(r"(?:IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]|PASSWORD\s*=?\s*['\"][^'\"]+['\"]"
               r"|IDENTIFIED\s+BY\s+PASSWORD)"),
    re.compile(r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
               r"private[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']", re.I),
]


def _redact_context_line(line):
    """Replace every credential-looking match on a context line with
    [redacted], preserving surrounding code. Returns the new line, or the
    original line if nothing matched."""
    out = line
    for pat in _SECRET_LINE_PATTERNS:
        out = pat.sub("[redacted]", out)
    return out


def redact_secret_snippet(rid, snippet, flagged_idx, raw_line):
    """Redact a secret-bearing snippet copy.

    Two things happen, on a COPY (the caller's `snippet` is never mutated):

    1. The FLAGGED line is replaced by the REDACT_PLACEHOLDER plus its
       length, so two scans of the same line redact to the same text and
       baselines still match (fingerprint() hashes the flagged line; the
       placeholder is deterministic for a stable rule + secret length).
    2. Every OTHER line in the context window is scanned with the
       line-level secret matchers: a snippet around a flagged S-SECRET
       commonly contains a SECOND credential the flagged rule didn't match
       (my probe: S-SECRET at line 3, AKIA… at line 4 in the same snippet).
       Only the matched substring is replaced; surrounding code stays
       readable.
    """
    out = list(snippet)
    for i in range(len(out)):
        if i == flagged_idx:
            out[i] = (REDACT_PLACEHOLDER.replace("{RULE}", rid)
                      + f" ({len(raw_line)} chars)")
        elif isinstance(out[i], str):
            out[i] = _redact_context_line(out[i])
    return out


def mk_issue(rule_or_dict, path, line_no, lines):
    r = rule_or_dict
    start = max(0, line_no - 3)
    snippet = lines[start:min(len(lines), line_no + 2)]
    # L1 (artifact hygiene): the flagged line of a SECRET-rule finding is
    # redacted at creation time, so EVERY sink — terminal excerpt, JSON/HTML
    # report, SARIF region, the registry Store blob — persists the
    # placeholder, never the credential. Previously only issue_excerpt()
    # (terminal) honored REDACT_SECRETS while reports shipped the raw line.
    # Additionally, ANY rule's ±2-line context window is swept for
    # secret-shaped substrings (a snippet around an os.system finding
    # routinely contains the file's actual credentials on adjacent lines).
    if REDACT_SECRETS and 0 <= line_no - 1 < len(lines):
        if r["id"] in SECRET_RULES:
            snippet = redact_secret_snippet(
                r["id"], snippet, line_no - 1 - start, lines[line_no - 1])
        else:
            snippet = [_redact_context_line(l) if isinstance(l, str) else l
                       for l in snippet]
    return {"rule": r["id"], "name": r["name"], "type": r["type"], "sev": r["sev"],
            "msg": r["msg"], "why": r["why"], "fix": r["fix"], "ref": r["ref"],
            "file": path, "line": line_no,
            "snippet": snippet,
            "snipStart": start + 1}

def extract_functions(lines, lang):
    fns = []
    if lang not in ("py", "js"):   # function/complexity metrics don't apply to SQL
        return fns
    if lang == "py":
        cx_re = re.compile(r"\b(if|elif|for|while|and|or|except|case)\b")
        for i, line in enumerate(lines):
            m = re.match(r"^(\s*)(?:async\s+)?def\s+(\w+)", line)
            if not m:
                continue
            indent = len(m.group(1))
            end = i + 1
            while end < len(lines):
                l = lines[end]
                if l.strip() and not is_comment(l, "py") and (len(l) - len(l.lstrip())) <= indent:
                    break
                end += 1
            body = "\n".join(lines[i:end])
            fns.append({"name": m.group(2), "line": i + 1, "len": end - i,
                        "cx": 1 + len(cx_re.findall(body))})
    else:
        # G4 fix: the old implementation restarted a forward 800-line window
        # scan for EVERY fn_re match — on minified/adversarial JS that is
        # O(lines × 800 × line_length) (20 s CPU for a 1.5 MB file, audit G4)
        # plus a body-string copy per function (memory blowup). This version
        # walks the brace structure ONCE with a stack. Old semantics are
        # preserved deliberately: each header's scan started at the first
        # character of its LINE, so a header claims the first '{' at/after its
        # line start (including its own, for `name(…){`-style matches), and
        # two headers on nested lines share a '{' exactly as their independent
        # scans both counted it. Function span = claimed '{' .. balancing '}'.
        content = "\n".join(lines)
        starts = [0]                      # line -> start offset (sorted)
        find = content.find
        pos = find("\n")
        while pos != -1:
            starts.append(pos + 1)
            pos = find("\n", pos + 1)
        starts.append(len(content) + 1)   # sentinel
        cx_re = re.compile(r"\b(if|for|while|case|catch)\b|&&|\|\||\?[^.:]")
        fn_re = re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?"
            r"(?:function|\([^)]*\)\s*=>|\w+\s*=>)|(\w+)\s*\([^)]*\)\s*\{)")
        # headers: first match per line (old semantics)
        headers = []                      # (line_i, name)
        for i, line in enumerate(lines):
            m = fn_re.search(line)
            if m:
                name = m.group(1) or m.group(2) or m.group(3) or "(anonymous)"
                headers.append((i, name))
        # per-line complexity counts — tokens cannot span '\n' except the
        # two-char '?x' (which '\n' satisfies); per-line counting is the
        # linear-time equivalent of the old body-copy findall.
        cx_prefix = [0]
        for line in lines:
            cx_prefix.append(cx_prefix[-1] + len(cx_re.findall(line)))
        # brace positions (one regex pass, no per-char Python loop)
        opens = [m.start() for m in re.finditer(r"\{", content)]
        # one brace walk: stack of (open_pos, owner header indices).
        from bisect import bisect_left, bisect_right
        matched = {}                      # header idx -> (open_pos, close_pos)
        stack, waiting, hi = [], [], 0
        for bm in re.finditer(r"[{}]", content):
            bpos = bm.start()
            while hi < len(headers) and starts[headers[hi][0]] <= bpos:
                waiting.append(hi)        # header's line has begun: it claims
                hi += 1                   # the next '{' it sees (old semantics)
            if bm.group() == "{":
                stack.append((bpos, waiting))
                waiting = []
            elif stack:
                open_pos, owners = stack.pop()
                for h in owners:
                    matched[h] = (open_pos, bpos)
        for h, (i, name) in enumerate(headers):
            nlines = len(lines)
            window_end_off = starts[min(nlines, i + 800)]   # old 800-line cap
            k = bisect_left(opens, starts[i])
            if k == len(opens) or opens[k] >= window_end_off:
                continue          # no '{' in window: old `started` never set
            if h in matched and matched[h][1] < window_end_off:
                close_pos = matched[h][1]
                end = bisect_right(starts, close_pos) - 1  # line of closing '}'
            else:
                # opened but never closed within the window: the old scan
                # ran to the window end and reported that truncated span.
                end = min(nlines, i + 800) - 1
            fns.append({"name": name, "line": i + 1, "len": end - i + 1,
                        "cx": 1 + cx_prefix[end + 1] - cx_prefix[i]})
    return fns

DEP_RULE_PREFIXES = ("SC-", "S-TOKEN", "S-SECRET")

# ---------------- SQL sink analysis (G12) ----------------
# The line-rule S-SQL-PY only sees formatting applied to a literal *inside*
# the execute() call. Three common idioms escape a single-line regex, so
# scan_file() runs this analyzer on every execute()/executemany() line:
#   1. cur.execute(sql % user_input)  — %-interpolation with no space after %
#      (the old pattern required one), or "…" + x concatenation, in the call
#   2. cur.execute(SQL.format(x))     — .format()/f-string on a variable
#   3. cur.execute(sql)               — where `sql` was assigned a %-or-{}
#      template or built by interpolation/concatenation earlier in the file
# Calls with a parameter tuple — execute(q, (x,)) / execute("…%s", (x,)) —
# are the SAFE idiom and are never flagged here.
SQL_CALL_RE = re.compile(r"\.(execute|executemany)\s*\(")
SQL_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
SQL_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(\+=|=)(?!=)\s*(.+?)\s*$")
SQL_LIT_RE = re.compile(r"^(?:[rbu]*)[\"'](.*)[\"']$", re.S)

def _split_top_level(argstr):
    """Split an argument string on top-level commas (respecting nested
    brackets and quotes) to isolate the SQL text argument from the parameter
    tuple that follows it."""
    parts, depth, cur, quote = [], 0, [], None
    for ch in argstr:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts

def _sql_build_method(arg):
    """How an execute() argument (or an assigned expression) builds a string:
    'format' (.format(…)/f-string), 'percent' (x % y), 'concat' ("…" + x),
    or None when the argument is a plain literal/identifier."""
    if re.search(r"\.format\s*\(", arg) or arg.lstrip().startswith(("f\"", "f'")):
        return "format"
    # a `%` binary op with a string/identifier left side (not numeric modulo)
    if re.search(r"(?:[\"'][^\"']*[\"']|\b[A-Za-z_]\w*)\s*%\s*[^=%\s]", arg):
        return "percent"
    # concatenation with a literal on one side
    if re.search(r"[\"'][^\"']*[\"']\s*\+", arg) or re.search(r"\+\s*[\"']", arg):
        return "concat"
    return None

def _sql_template_map(lines):
    """varname → how its value is built, from earlier simple assignments:
    literal templates ('percent' when they contain %, 'format' when they
    contain {}), or %-/.format/concat expressions."""
    tmap = {}
    for ln in lines:
        mm = SQL_ASSIGN_RE.match(ln)
        if not mm:
            continue
        var, op, rhs = mm.group(1), mm.group(2), mm.group(3)
        if op == "+=":
            tmap[var] = tmap.get(var, "concat")
            continue
        build = _sql_build_method(rhs)
        if build:
            tmap[var] = build
            continue
        lit = SQL_LIT_RE.match(rhs.strip())
        if lit:
            t = lit.group(1)
            tmap[var] = "percent" if "%" in t else "format" if "{" in t else "static"
    return tmap

def sql_sink_analyzer(path, lines, issues):
    """Whole-argument analysis of execute()/executemany() calls (G12).
    Appends S-SQL-PY issues to `issues` (deduped against the line-rule pass
    by line number); safe parameterized calls are skipped."""
    tmap = _sql_template_map(lines)
    flagged = {i["line"] for i in issues if i.get("rule") == "S-SQL-PY"}
    for i, line in enumerate(lines):
        if i + 1 in flagged:
            continue
        for m in SQL_CALL_RE.finditer(line):
            arg_str = _paren_slice(line, m.end() - 1)
            if arg_str is None:
                continue
            parts = [p for p in _split_top_level(arg_str)]
            first = parts[0].strip() if parts else ""
            second = parts[1].strip() if len(parts) > 1 else ""
            if not first:
                continue
            # SAFE: parameterized call — literal/identifier first argument and
            # a tuple/list/dict of parameters after the top-level comma
            if len(parts) >= 2 and second and second[0] in "([{":
                continue
            build = _sql_build_method(first)
            if build is None and SQL_IDENT_RE.fullmatch(first):
                build = tmap.get(first)
                if build in (None, "static"):
                    continue
            if build:
                issues.append(_sql_issue(path, i + 1, lines, first, build))

def _paren_slice(line, open_idx):
    """Content of the balanced parenthesized group starting at open_idx (the
    index of '('), or None if unbalanced."""
    depth, quote = 0, None
    for j in range(open_idx, len(line)):
        ch = line[j]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line[open_idx + 1:j]
    return None

def _sql_issue(path, line_no, lines, arg, build):
    how = {"percent": "%-interpolation", "format": ".format()/f-string",
           "concat": "concatenation"}.get(build, "string-building")
    return mk_issue(
        {"id": "S-SQL-PY", "name": "SQL built from strings", "type": "VULN", "sev": "BLOCKER",
         "msg": f"SQL query built with {how} into execute().",
         "why": "Interpolating values into SQL enables SQL injection — the classic path to full database compromise.",
         "fix": 'Use parameterized queries: cursor.execute("SELECT … WHERE id = %s", (user_id,)).',
         "ref": "CWE-89 · OWASP A03"},
        path, line_no, lines)

# ---------------- Linear SQL *-NOWHERE scan (F11) ----------------
# SQL-DELETE-NOWHERE / SQL-UPDATE-NOWHERE are fired by this linear pass, NOT
# by the generic TEXT_RULES finditer (their entry regexes match only the
# statement head and never scan toward EOF). One O(n) pass per file: head
# matches come from the cheap anchored regexes; statement ends come from the
# precomputed ';' offsets (a match with no later ';' never fired the old
# pattern either, so it is skipped — and that is what bounds the work); the
# WHERE check runs on the bounded statement slice only.
_SQL_NOWHERE_RULES = {r["id"]: r for r in TEXT_RULES
                      if r["id"] in ("SQL-DELETE-NOWHERE", "SQL-UPDATE-NOWHERE")}
_SQL_NOWHERE_SKIP = frozenset(_SQL_NOWHERE_RULES)
_SQL_WHERE_RE = re.compile(r"\bWHERE\b", re.I)


def scan_sql_nowhere(path, content, issues, lines):
    """Emit SQL-DELETE-NOWHERE / SQL-UPDATE-NOWHERE in one linear pass.

    Reproduces the original tempered-dot finditer semantics exactly:
      * a match starts at a DELETE/UPDATE head, consumes up to the next ';'
        and is aborted by a WHERE in between (WHERE'd statements do not
        fire, but heads nested after the WHERE can still match);
      * finditer is non-overlapping, so every head before a reported match's
        ';' is consumed by that match (20k unterminated heads before one
        real statement produce ONE issue, at the first head's line);
      * heads after a WHERE-aborted statement are still tried (the old
        engine retried from the next character).
    Cost is O(n) with bisect lookups over precomputed ';', WHERE and newline
    offsets (audit finding F11: 51 s CPU on 280 KB of unterminated DELETEs,
    ~40 min extrapolated to the 2 MB file cap; 735 s reproduced pre-fix).
    """
    import bisect
    semis = None    # lazily: ';' offsets, ascending
    wheres = None   # lazily: \bWHERE\b offsets, ascending
    nl = None       # lazily: '\n' offsets, ascending
    for rid, r in _SQL_NOWHERE_RULES.items():
        skip_to = -1   # heads starting before this offset are consumed/masked
        for m in r["re"].finditer(content):
            if m.start() < skip_to:
                continue
            if semis is None:
                semis = [i for i, ch in enumerate(content) if ch == ";"]
                wheres = [w.start() for w in _SQL_WHERE_RE.finditer(content)]
                nl = [i for i, ch in enumerate(content) if ch == "\n"]
            k = bisect.bisect_left(semis, m.end())
            if k == len(semis):
                continue   # no ';' ahead: the old pattern could never match
            semi = semis[k]
            w = bisect.bisect_left(wheres, m.end())
            if w < len(wheres) and wheres[w] < semi:
                # WHERE before the ';': old match aborted at the WHERE; the
                # engine retried from the next character, so later heads
                # (nested after WHERE) still get their own attempts.
                skip_to = m.end()
                continue
            line_no = bisect.bisect_left(nl, m.start()) + 1
            issues.append(mk_issue(r, path, line_no, lines))
            skip_to = semi  # non-overlapping: heads before the ';' are spent


def scan_file(path, content, lang, dep=False):
    """Scan one file. dep=True → dependency mode: only supply-chain and
    secret rules run (quality/bug rules would be pure noise in vendored code)."""
    issues = []
    lines = content.split("\n")
    for i, line in enumerate(lines):
        for r in RULES:
            if lang not in r["langs"]:
                continue
            if dep and not r["id"].startswith(DEP_RULE_PREFIXES):
                continue
            # equality checks shouldn't match inside string literals
            target = STRING_LIT_RE.sub("\"\"", line) if r["id"] == "B-EQEQ" else line
            if not r["re"].search(target):
                continue
            if r["need"] and not r["need"].search(line):
                continue
            if r["skip"] and r["skip"].search(line):
                continue
            if is_comment(line, lang) and r["id"] not in ("Q-TODO", "S-TOKEN"):
                continue
            issues.append(mk_issue(r, path, i + 1, lines))
        if not dep and len(line) > LONG_LINE:
            issues.append(mk_issue(
                {"id": "Q-LONGLINE", "name": "Line too long", "type": "SMELL", "sev": "MINOR",
                 "msg": f"Line exceeds {LONG_LINE} characters.",
                 "why": "Very long lines hurt readability and reviews.",
                 "fix": "Break the line up for readability.", "ref": "Maintainability"},
                path, i + 1, lines))
        # --- obfuscation heuristics (strong supply-chain indicators) ---
        if line.count("\\x") >= 8:
            issues.append(mk_issue(
                {"id": "SC-HEXSTR", "name": "Hex-escaped string blob", "type": "HOTSPOT", "sev": "MAJOR",
                 "msg": f"String built from {line.count(chr(92) + 'x')} hex escapes — obfuscation indicator.",
                 "why": "Dense \\xNN escaping hides strings (URLs, commands) from review and grep.",
                 "fix": "Decode and review the string; legitimate code rarely needs this.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines))
        if lang == "js" and CHARCODE_RE.search(line) and len(re.findall(r"\b\d{2,3}\b", line)) >= 10:
            issues.append(mk_issue(
                {"id": "SC-CHARCODE", "name": "Char-code string building", "type": "HOTSPOT", "sev": "MAJOR",
                 "msg": "String assembled from character codes — obfuscation indicator.",
                 "why": "fromCharCode chains hide payloads from static review.",
                 "fix": "Decode and review what string is being built.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines))
        if B64_BLOB_RE.search(line) and "sourceMappingURL" not in line:
            issues.append(mk_issue(
                {"id": "SC-B64", "name": "Large base64 blob", "type": "HOTSPOT", "sev": "MAJOR",
                 "msg": "Base64 blob (200+ chars) embedded in code.",
                 "why": "Embedded encoded blobs can carry second-stage payloads.",
                 "fix": "Decode and verify the content; move legitimate assets to data files.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines))
        # --- entropy-based secret detection ---
        if not is_comment(line, lang) and not SECRET_SKIP_RE.search(line):
            em = ENTROPY_VALUE_RE.search(line)
            if em and entropy_secretish(em.group(1)) and not any(
                    x["line"] == i + 1 and x["rule"] in ("S-TOKEN", "S-SECRET") for x in issues):
                issues.append(mk_issue(
                    {"id": "S-ENTROPY", "name": "High-entropy string", "type": "HOTSPOT", "sev": "MAJOR",
                     "msg": "High-entropy string literal — possible hardcoded secret.",
                     "why": "Random-looking constants are usually keys or tokens.",
                     "fix": "If it is a secret, rotate it and load it from the environment.",
                     "ref": "CWE-798 · OWASP A07"}, path, i + 1, lines))
    # file-level: javascript-obfuscator identifier signature
    if lang == "js":
        obf = OBF_IDENT_RE.findall(content)
        if len(set(obf)) >= 5:
            first_line = content[:content.find(obf[0])].count("\n") + 1
            issues.append(mk_issue(
                {"id": "SC-OBF-IDENT", "name": "Obfuscated identifier pattern", "type": "HOTSPOT",
                 "sev": "CRITICAL",
                 "msg": f"{len(set(obf))} '_0x…' identifiers — javascript-obfuscator signature.",
                 "why": "This naming pattern is produced by obfuscation tools; in a dependency it is "
                        "a classic indicator of a compromised or malicious package.",
                 "fix": "Diff against the package's published repository; consider removing the dependency.",
                 "ref": "CWE-506 · Supply chain"}, path, first_line, lines))
    for r in TEXT_RULES:
        # *-NOWHERE SQL rules are fired by scan_sql_nowhere() (linear pass),
        # not here — their regexes match only the statement head.
        if lang not in r["langs"] or dep or r["id"] in _SQL_NOWHERE_SKIP:
            continue
        for m in r["re"].finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            issues.append(mk_issue(r, path, line_no, lines))
    if not dep and lang == "sql":
        try:
            scan_sql_nowhere(path, content, issues, lines)
        except Exception:
            pass
    if not dep:
        issues.extend(taint_scan(path, lines, lang))
    # G12: whole-argument SQL-sink analysis (Python only) — catches
    # execute(sql % x) with no space after %, .format() on a template variable,
    # and execute(name) where name was built by interpolation/concatenation.
    if lang == "py":
        try:
            sql_sink_analyzer(path, lines, issues)
        except Exception:
            pass
    if dep:
        return [i for i in issues if not is_suppressed(i, lines, lang=lang, dep=True)]
    for fn in extract_functions(lines, lang):
        if fn["len"] > FN_LEN_LIMIT:
            issues.append(mk_issue(
                {"id": "Q-FN-LONG", "name": "Function too long", "type": "SMELL", "sev": "MAJOR",
                 "msg": f"Function \"{fn['name']}\" is {fn['len']} lines long (limit {FN_LEN_LIMIT}).",
                 "why": "Long functions do too much and resist testing and reuse.",
                 "fix": "Extract cohesive blocks into helper functions.",
                 "ref": "Maintainability"}, path, fn["line"], lines))
        if fn["cx"] > FN_CX_LIMIT:
            issues.append(mk_issue(
                {"id": "Q-FN-CX", "name": "High cyclomatic complexity", "type": "SMELL", "sev": "MAJOR",
                 "msg": f"Function \"{fn['name']}\" has complexity ~{fn['cx']} (limit {FN_CX_LIMIT}).",
                 "why": "Highly branched code is hard to reason about and to cover with tests.",
                 "fix": "Split branches into smaller functions; use early returns or lookup tables.",
                 "ref": "Maintainability"}, path, fn["line"], lines))
    return [i for i in issues if not is_suppressed(i, lines, lang=lang)]

DEP_MARKERS = {"node_modules", "site-packages", "bower_components", "vendor",
               "venv", ".venv"}
INSTALL_HOOK_RE = re.compile(
    r"curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b", re.I)
# G11: npm lifecycle scripts — the command list above is a bypassable denylist
# (`npx --yes evil`, `node ./scripts/payload.js`, `git clone … && make` contain
# none of those tokens). Presence of *any* install-time script is itself worth
# a finding: it runs with user privileges on `npm install` before the package
# is reviewed. The pattern list is only a severity escalator.
NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare",
                         "prepublish", "prepublishOnly", "prepack", "postpack",
                         "prepackOnly", "postpublish", "prebundle", "postbundle")
PY_LIFECYCLE_SECTIONS = ("build-system", "tool.poetry", "project")

def _sc_install_hook_issue(path, line_no, lines, script, cmd, suspicious):
    sev = "CRITICAL" if suspicious else "MAJOR"
    if suspicious:
        msg = f'"{script}" script runs a network-fetch/eval command at install time.'
        why = ("Install hooks execute automatically on npm install — the most common "
               "supply-chain compromise vector — and this one fetches or executes "
               "remote code.")
    else:
        msg = f'"{script}" lifecycle script runs code at install time: {cmd!r}.'
        why = ("Install hooks execute automatically with user privileges on "
               "npm install/publish, before anyone reviews the package. npm itself "
               "recommends --ignore-scripts unless the hook is essential.")
    return mk_issue(
        {"id": "SC-INSTALL-HOOK", "name": "Suspicious install hook", "type": "HOTSPOT",
         "sev": sev, "msg": msg, "why": why,
         "fix": f"Review the {script} script; use --ignore-scripts in CI if unneeded.",
         "ref": "CWE-506 · Supply chain"}, path, line_no, lines)

def _sc_manifest_depth_issue(path):
    """48033f94: a pathologically deep-nested manifest (e.g. 60k+ '[' bytes)
    blows json.loads' recursion limit. The old code crashed the CLI (exit 1,
    results lost) and in registry mode suppressed every other finding in the
    package (scan recorded as 'error' instead of reporting). Both are wins for
    a hostile repo, so this is reported as a CRITICAL supply-chain finding —
    never a crash, never a silent skip."""
    return mk_issue(
        {"id": "SC-MANIFEST-DEPTH", "name": "Hostile manifest nesting depth",
         "type": "HOTSPOT", "sev": "CRITICAL",
         "msg": "Manifest is too deeply nested to parse (recursion limit hit).",
         "why": ("A manifest nested this deep cannot be produced by any real "
                 "build tool — it exists purely to crash or blind security "
                 "scanners. Treating it as data would silently drop every "
                 "other finding in the package."),
         "fix": "Reject this package/file at your ingestion boundary; investigate the source.",
         "ref": "CWE-506 · Supply chain"}, path, 1, [])

def _json_loads_manifest(path, content):
    """json.loads for manifest-shaped, attacker-controlled content: returns
    (data, depth_issue). data is None on any parse failure — normal JSON
    errors yield [] issues (an unparseable manifest has nothing to check),
    while RecursionError yields the SC-MANIFEST-DEPTH finding so a hostile
    file can neither crash the scan nor hide behind the 'unparseable' path."""
    try:
        return json.loads(content), None
    except (json.JSONDecodeError, AttributeError):
        return None, None
    except RecursionError:
        return None, _sc_manifest_depth_issue(path)

def scan_manifest(path, content):
    """Check package.json / pyproject.toml install hooks — the primary
    supply-chain attack vector.

    G11: mere *presence* of a lifecycle script is flagged (MAJOR); a hook whose
    command matches the fetch/eval pattern list escalates to CRITICAL. The old
    behavior (pattern-only) was a denylist every `npx evil-pkg` or
    `node ./scripts/payload.js` sailed through. Also covers setup.py and
    binding.gyp via scan_file()/scan_gyp() (see collect_files)."""
    data, depth_issue = _json_loads_manifest(path, content)
    if depth_issue:
        return [depth_issue]
    if not isinstance(data, dict):
        return []
    issues, lines = [], content.split("\n")
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in NPM_LIFECYCLE_SCRIPTS:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            suspicious = bool(INSTALL_HOOK_RE.search(cmd))
            line_no = next((i + 1 for i, l in enumerate(lines) if f'"{hook}"' in l), 1)
            issues.append(_sc_install_hook_issue(path, line_no, lines, hook, cmd, suspicious))
    return issues

def scan_gyp(path, content):
    """G11: binding.gyp custom build actions run arbitrary commands at
    `node-gyp rebuild` (i.e. `npm install` of any native module). Flag each
    action whose command matches the fetch/eval patterns, and any action at
    all as MAJOR — same policy as package.json lifecycle scripts."""
    data, depth_issue = _json_loads_manifest(path, content)
    if depth_issue:
        return [depth_issue]
    if not isinstance(data, dict):
        return []
    issues, lines = [], content.split("\n")
    actions = []
    for target in data.get("targets", []) if isinstance(data.get("targets"), list) else []:
        if isinstance(target, dict):
            for act in target.get("actions", []) if isinstance(target.get("actions"), list) else []:
                if isinstance(act, dict) and isinstance(act.get("action"), list):
                    actions.append([str(a) for a in act["action"]])
    for act in actions:
        cmd = " ".join(act)
        suspicious = bool(INSTALL_HOOK_RE.search(cmd))
        line_no = next((i + 1 for i, l in enumerate(lines) if any(a and a in l for a in act)), 1)
        issues.append(_sc_install_hook_issue(path, line_no, lines,
                                             "binding.gyp action", cmd, suspicious))
    return issues

def detect_encoding(head):
    """M17: BOM/UTF-16 sniff. Returns {'encoding': codec or None, 'reported':
    bool} — reported=True when the file is NOT plain UTF-8 (a UTF-16 BOM, or
    null bytes that betray UTF-16 without BOM), so the caller decodes with the
    right codec and emits a Q-ENCODING finding instead of reading mojibake."""
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return {"encoding": "utf-16", "reported": True}
    if head.startswith(b"\xef\xbb\xbf"):
        return {"encoding": "utf-8-sig", "reported": True}
    if b"\x00" in head:
        return {"encoding": "utf-16", "reported": True}
    return {"encoding": "utf-8", "reported": False}

def collect_files(root, extra_excludes, include_deps=False):
    """Returns (files, manifests, binary_issues). With include_deps, dependency
    directories (node_modules, venv, vendor…) are also walked; their files are
    marked dep=True and scanned only with supply-chain/secret rules. Compiled
    binary artifacts (.so/.pyd/.dll/.node/.exe…) are flagged via classify_binary
    regardless of size."""
    skip = SKIP_DIRS | set(extra_excludes)
    if include_deps:
        skip -= DEP_MARKERS
    found, manifests, binary_issues = [], [], []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        in_dep = any(part in DEP_MARKERS for part in rel_dir.split(os.sep))
        # G10: path-based skip. A directory is pruned when its name is in
        # `skip` (so a directory named dist is skipped but a *file* named dist
        # is not); every prune is counted so the blind spot is visible.
        prune = []
        for d in list(dirnames):
            if d in skip:
                _count_skipped_tree(root, os.path.join(dirpath, d))
                prune.append(d)
            elif d in DEP_MARKERS and not include_deps:
                _count_skipped_tree(root, os.path.join(dirpath, d))
                prune.append(d)
        dirnames[:] = sorted(d for d in dirnames if d not in prune)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            ext = os.path.splitext(fn)[1].lower()
            # compiled artifacts: flag by header regardless of size
            if ext in COMPILED_EXTS:
                try:
                    size = os.path.getsize(full)
                    with open(full, "rb") as f:
                        head = f.read(8192)
                except OSError:
                    continue
                bi = classify_binary(rel, head, size, "repo")
                if bi:
                    binary_issues.append(bi)
                continue
            try:
                if os.path.getsize(full) > 2_000_000:
                    # Verdict integrity (audit C2/G16): a silent `continue` here
                    # made an oversize file invisible — no scan, no signal, and
                    # a clean gate. Emit SC-TRUNCATED instead. The file is NOT
                    # added to `found` (metrics stay honest: we did not scan it).
                    binary_issues.append(truncated_issue(
                        rel, f"{os.path.getsize(full):,} bytes exceeds the 2,000,000-byte "
                        "file limit"))
                    continue
            except OSError:
                continue
            if fn == "package.json":
                try:
                    with open(full, encoding="utf-8", errors="replace") as f:
                        manifests.append({"path": rel, "content": f.read()})
                except OSError:
                    pass
                continue
            if fn == "binding.gyp":  # G11: node-gyp actions run at install time
                try:
                    with open(full, encoding="utf-8", errors="replace") as f:
                        manifests.append({"path": rel, "content": f.read()})
                except OSError:
                    pass
                continue
            if ext not in EXTS:
                continue
            # M17: sniff before reading as UTF-8 — errors="replace" alone turns
            # a UTF-16 source into mojibake every rule then misses.
            try:
                with open(full, "rb") as f:
                    head = f.read(4)
            except OSError:
                continue
            enc = detect_encoding(head)
            if enc["encoding"] is None:
                continue
            try:
                with open(full, encoding=enc["encoding"], errors="strict") as f:
                    content = f.read()
            except (OSError, LookupError, UnicodeDecodeError):
                try:
                    with open(full, encoding=enc["encoding"], errors="replace") as f:
                        content = f.read()
                except (OSError, LookupError):
                    continue
            if enc["reported"]:
                binary_issues.append(mk_issue(
                    {"id": "Q-ENCODING", "name": "Non-UTF-8 source encoding", "type": "SMELL",
                     "sev": "INFO",
                     "msg": f"Source file is not UTF-8 (detected {enc['encoding']}); decoded explicitly.",
                     "why": "A non-UTF-8 source read as UTF-8 decodes to mojibake, hiding every "
                            "pattern-based finding — a UTF-16 eval() scans clean.",
                     "fix": "Re-save the file as UTF-8 so tooling reads it as written.",
                     "ref": "Maintainability"}, rel, 1, content.split("\n")))
            found.append({"path": rel, "content": content, "lang": EXTS[ext], "dep": in_dep})
    return found, manifests, binary_issues

# ---------------- Metrics / ratings ----------------
def compute_metrics(all_files):
    files = [f for f in all_files if not f.get("dep")]  # deps excluded from quality metrics
    ncloc = comments = 0
    win_map = {}
    for f in files:
        code = []
        for i, l in enumerate(f["content"].split("\n")):
            t = l.strip()
            if not t:
                continue
            if is_comment(l, f["lang"]):
                comments += 1
                continue
            ncloc += 1
            code.append((t, i, f["path"]))
        for i in range(len(code) - 5):
            key = "".join(c[0] for c in code[i:i + 6])
            win_map.setdefault(key, []).append(code[i:i + 6])
    dup = set()
    for occ in win_map.values():
        if len(occ) > 1:
            for win in occ:
                for _, i, p in win:
                    dup.add((p, i))
    dup_pct = round(100 * len(dup) / ncloc, 1) if ncloc else 0.0
    return {"files": len(files), "depFiles": len(all_files) - len(files),
            "ncloc": ncloc, "comments": comments, "dupPct": dup_pct}

def worst_sev_rating(issues, types):
    sevs = {i["sev"] for i in issues if i["type"] in types}
    for sev, rating in (("BLOCKER", "E"), ("CRITICAL", "D"), ("MAJOR", "C"), ("MINOR", "B")):
        if sev in sevs:
            return rating
    return "A"

def maintainability_rating(issues, ncloc):
    smells = sum(1 for i in issues if i["type"] == "SMELL")
    per100 = 100 * smells / ncloc if ncloc else 0
    for limit, rating in ((5, "A"), (10, "B"), (20, "C"), (40, "D")):
        if per100 <= limit:
            return rating
    return "E"

def build_result(root, files, issues):
    issues.sort(key=lambda i: (SEV_ORDER[i["sev"]], i["file"], i["line"]))
    metrics = compute_metrics(files)
    counts = {t: sum(1 for i in issues if i["type"] == t) for t in TYPE_LABEL}
    ratings = {"security": worst_sev_rating(issues, ("VULN",)),
               "reliability": worst_sev_rating(issues, ("BUG",)),
               "maintainability": maintainability_rating(issues, metrics["ncloc"])}
    conds = [
        {"label": "No blocker issues",
         "ok": not any(i["sev"] == "BLOCKER" for i in issues)},
        {"label": "No critical vulnerabilities",
         "ok": not any(i["type"] == "VULN" and i["sev"] in ("CRITICAL", "BLOCKER") for i in issues)},
        {"label": "Duplication < 10%", "ok": metrics["dupPct"] < 10},
        {"label": "Maintainability ≥ C", "ok": ratings["maintainability"] in "ABC"},
    ]
    per_file = {}
    for i in issues:
        per_file[i["file"]] = per_file.get(i["file"], 0) + 1
    supply = sum(1 for i in issues if i["rule"].startswith("SC-"))
    conds.append({"label": "No supply-chain indicators", "ok": supply == 0})
    cross_file = sum(1 for i in issues if i["rule"].startswith("X-"))
    conds.append({"label": "No cross-file taint flows", "ok": cross_file == 0})
    return {"project": os.path.abspath(root),
            "scannedAt": datetime.datetime.now().isoformat(timespec="seconds"),
            "pass": all(c["ok"] for c in conds), "conditions": conds,
            "metrics": metrics, "counts": counts, "ratings": ratings,
            "supplyChain": supply, "crossFile": cross_file,
            "perFile": per_file, "issues": issues}

# ---------------- Terminal output ----------------
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else str(s)

SEV_COLOR = {"BLOCKER": "41;97", "CRITICAL": "31", "MAJOR": "33", "MINOR": "36", "INFO": "34"}

# C0-terminal (audit H1: terminal escape-sequence injection) — every string
# that might derive from scanned content, archive member names, registry
# metadata or config paths is passed through sanitize_term() before it reaches
# a terminal/CI log. safe_excerpt always did this for the code excerpt; the
# file-path header, the issue messages and the registry print paths did not.
# The mapped set: every C0 control byte except TAB (0x09) and LF (0x0a),
# plus CR (0x0d) and DEL (0x7f). Built with chr() so the table is exact and
# readable; ESC (0x1b) and BEL (0x07) — the two bytes the audit PoC used to
# forge SGR colors and hijack the terminal title — are inside these ranges.
_SANITIZE_TERM_CHARS = (
    "".join(chr(n) for n in range(0x00, 0x09))      # NUL … BS
    + "".join(chr(n) for n in (0x0b, 0x0c))         # VT, FF
    + "".join(chr(n) for n in range(0x0d, 0x20))    # CR, SO … US (incl. ESC)
    + chr(0x7f)                                     # DEL
)
_SANITIZE_TERM_TAB = str.maketrans(
    {ch: "·" for ch in _SANITIZE_TERM_CHARS})


def sanitize_term(s):
    """Neutralize terminal-control bytes in a string before printing.

    Hostile package content reaches the terminal via file paths (archive
    member names, walked repo paths), issue messages (X-FLOW source/sink
    paths, install-hook command text), registry metadata and config paths.
    Every C0 control byte except newline and tab, plus CR and DEL, maps to
    '·' — the line terminator is preserved so a multi-line message still
    prints as multiple lines (the existing behaviour), and tab is printable
    structure (safe_excerpt keeps tabs too). Same contract as safe_excerpt
    for a full string, without the truncation.

    Applied to every print() that interpolates such a value; safe_excerpt
    (the truncated single-line variant) already covers the code excerpt.
    Ordering at the call sites matters: sanitize the ARGUMENT of c(), never
    its result — sanitizing the result would strip the SGR sequences
    Lazaret itself emits and leave the color wrapper unclosed.
    """
    return str(s).translate(_SANITIZE_TERM_TAB)

# Rules whose flagged line reveals a credential. The flagged LINE is redacted
# in every persistent artifact by default (see redact_secret_snippet — audit
# L1: the old --redact-secrets flag only sanitized the TERMINAL excerpt while
# JSON/HTML/SARIF reports and the registry DB embedded the full line);
# --no-redact-secrets is the opt-out for audit workflows that need to see the
# secret in the report.
SECRET_RULES = {"S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"}
REDACT_SECRETS = True
REDACT_PLACEHOLDER = "[redacted: secret rule {RULE}]"
REDACT_FINGERPRINT = "[redacted: secret rule "   # marker of an already-redacted line
EXCERPT_WIDTH = 100   # overridable via --excerpt-width

def safe_excerpt(text, width=None):
    """Sanitize a source line for terminal display. Scanned code may be hostile
    (esp. packages), so strip ANSI/control bytes that could rewrite the terminal
    — ESC, CR, BS, BEL, NUL — replacing them with '·'. Tabs become spaces, the
    line is trimmed and truncated with an ellipsis."""
    if width is None:
        width = EXCERPT_WIDTH
    text = text.replace("\t", " ").strip()
    if not text:
        return ""
    out = []
    for ch in text[:width]:
        o = ord(ch)
        if ch == " " or 0x20 <= o < 0x7f or (o > 0xa0 and ch.isprintable()):
            out.append(ch)
        else:
            out.append("·")
    return "".join(out) + ("…" if len(text) > width else "")

def issue_excerpt(issue, width=None):
    """Sanitized excerpt of an issue's flagged source line ('' if unavailable)."""
    snip = issue.get("snippet") or []
    idx = issue["line"] - issue.get("snipStart", issue["line"])
    if not (0 <= idx < len(snip)):
        return ""
    if REDACT_SECRETS and issue.get("rule") in SECRET_RULES:
        # mk_issue already replaced the flagged line with the placeholder;
        # this guard keeps old/unredacted issues (e.g. a not-yet-redacted
        # report fed back through print paths) from leaking via the excerpt.
        return "[redacted]"
    return safe_excerpt(snip[idx], width)

def redact_result(res):
    """Defensive sweep over a scan result: no credential may survive into a
    report artifact.

    Two layers (audit L1):
    * Any SECRET-rule issue still carrying an unredacted flagged line
      (embedded from an unpatched engine path) is redacted in place via
      redact_secret_snippet.
    * EVERY issue's snippet — secret rule or not — has its context lines
      swept with the line-level secret matchers: a snippet around an
      os.system finding routinely contains the file's actual credentials on
      adjacent lines, and those would otherwise ship to the JSON/HTML
      report verbatim. Only matched substrings are replaced; surrounding
      code stays readable.

    mk_issue is the primary fix; this is the belt-and-braces pass so a leak
    requires BOTH mk_issue to miss AND this sweep to miss.
    """
    for i in res.get("issues", []):
        if not REDACT_SECRETS:
            break
        snip = i.get("snippet")
        if not isinstance(snip, list):
            continue
        idx = i["line"] - i.get("snipStart", i["line"])
        secret = i.get("rule") in SECRET_RULES
        if secret and 0 <= idx < len(snip) and isinstance(snip[idx], str) \
                and REDACT_FINGERPRINT not in snip[idx]:
            i["snippet"] = redact_secret_snippet(i["rule"], snip, idx, snip[idx])
            continue
        # non-secret rule (or already-redacted secret): sweep context lines
        cleaned = [(_redact_context_line(l) if isinstance(l, str) else l)
                   for l in snip]
        if cleaned != snip:
            i["snippet"] = cleaned
    return res

def print_report(res, quiet):
    m, ct, rt = res["metrics"], res["counts"], res["ratings"]
    print()
    print(c("1", f"Lazaret scan — {sanitize_term(res['project'])}"))
    print(f"  {m['files']} files · {m['ncloc']} lines of code · {m['dupPct']}% duplication")
    print()
    gate = c("42;30", " PASSED ") if res["pass"] else c("41;97", " FAILED ")
    print(f"  Quality gate: {gate}")
    for cond in res["conditions"]:
        mark = c("32", "✓") if cond["ok"] else c("31", "✗")
        # audit H1: a gate condition label can embed a scanned file path
        # ("Taint analysis incomplete → <file>", build_result) — hostile repo.
        print(f"    {mark} {sanitize_term(cond['label'])}")
    print()
    print(f"  Vulnerabilities   {ct['VULN']:>4}   Security rating        {rt['security']}")
    print(f"  Security hotspots {ct['HOTSPOT']:>4}")
    print(f"  Bugs              {ct['BUG']:>4}   Reliability rating     {rt['reliability']}")
    print(f"  Code smells       {ct['SMELL']:>4}   Maintainability rating {rt['maintainability']}")
    sc = res.get("supplyChain", 0)
    print(f"  Supply-chain      {sc:>4}   (obfuscation/install-hook indicators)")
    xf = res.get("crossFile", 0)
    if xf:
        print(f"  Cross-file flows  {c('31', xf):>4}   (interprocedural taint)")
    if m.get("depFiles"):
        print(f"  Dependency files scanned: {m['depFiles']}")
    if "newIssues" in res:
        print(f"  New issues vs baseline: {c('1', res['newIssues'])}")
    print()
    if not quiet and res["issues"]:
        print(c("1", "  Issues"))
        cur_file = None
        for i in sorted(res["issues"], key=lambda i: (i["file"], SEV_ORDER[i["sev"]], i["line"])):
            if i["file"] != cur_file:
                cur_file = i["file"]
                # audit H1: the path header is attacker-controlled (repo walk
                # path, or an archive member name in registry mode). Sanitize
                # the ARGUMENT of c(), never its result — the SGR wrapper
                # Lazaret emits must survive.
                print(f"\n  {c('4', sanitize_term(cur_file))}")
            sev_txt = f"{i['sev']:<8}"
            prefix = f"    L{i['line']:<5} {sev_txt} [{i['rule']}] "
            # audit H1: i['msg'] is static text for most rules but embeds
            # attacker data for several (X-FLOW source/sink paths, the
            # SC-INSTALL-HOOK {cmd!r}, SCA bundle fields). Sanitized inside
            # the f-string, AFTER the colored severity span — sanitizing the
            # whole colored string would strip c()'s own SGR reset.
            print(f"    L{i['line']:<5} {c(SEV_COLOR[i['sev']], sev_txt)} [{i['rule']}] {sanitize_term(i['msg'])}")
            ex = issue_excerpt(i)
            if ex:
                print(" " * len(prefix) + c('2', '» ' + ex))   # aligned under the message
        print()

# ---------------- HTML report ----------------
def esc(s):
    return html_mod.escape(str(s), quote=True)

RATING_COLOR = {"A": "#00aa55", "B": "#7dc94a", "C": "#f0c000", "D": "#ed7d20", "E": "#d4380d"}

HTML_CSS = """
:root{--border:#dde3ea;--muted:#6b7785;--navy:#1a2634;
--blocker:#c4160f;--critical:#d4380d;--major:#e08a00;--minor:#8a9aa8;--info:#4b9fd5;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f3f5f7;color:#1f2933}
header{background:var(--navy);color:#fff;padding:14px 24px}
header .logo{font-size:17px;font-weight:700}header .logo span{color:#4b9fd5}
header .meta{font-size:12px;color:#9fb0c0;margin-top:2px}
.wrap{max-width:1150px;margin:0 auto;padding:20px 24px 60px}
.panel{background:#fff;border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:18px}
h2{font-size:15px;margin-bottom:12px}
.gate{display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.gate-badge{font-size:15px;font-weight:700;color:#fff;padding:8px 18px;border-radius:6px}
.gate-badge.pass{background:#00aa55}.gate-badge.fail{background:#d4380d}
.cond{font-size:12px;padding:4px 10px;border-radius:12px;border:1px solid var(--border)}
.cond.ok{border-color:#bfe8d2;background:#eefaf3;color:#0a7a44}
.cond.ko{border-color:#f3c4bb;background:#fdf0ee;color:#b32d16}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.card .num{font-size:26px;font-weight:700}.card .lbl{font-size:12px;color:var(--muted);margin-top:2px}
.rating{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:50%;
color:#fff;font-size:13px;font-weight:700;margin-left:8px;vertical-align:3px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 10px;border-bottom:1px solid var(--border);text-align:left}
th{color:var(--muted);font-size:12px}td.n{text-align:right;font-variant-numeric:tabular-nums}
details{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;background:#fff;overflow:hidden}
summary{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}summary:hover{background:#f7f9fb}
.sev{font-size:10.5px;font-weight:700;color:#fff;padding:2px 8px;border-radius:10px;flex-shrink:0}
.sev.BLOCKER{background:var(--blocker)}.sev.CRITICAL{background:var(--critical)}
.sev.MAJOR{background:var(--major)}.sev.MINOR{background:var(--minor)}.sev.INFO{background:var(--info)}
.itype{font-size:11px;color:var(--muted);border:1px solid var(--border);padding:1px 8px;border-radius:10px;flex-shrink:0}
.imsg{flex:1;font-weight:600;font-size:13px}
.iloc{font:11.5px var(--mono);color:var(--muted);flex-shrink:0}
.body{border-top:1px solid var(--border);padding:12px 14px;background:#fbfcfd}
.snippet{font:12px/1.6 var(--mono);background:#1a2634;color:#d7e0ea;border-radius:6px;padding:10px 0;margin-bottom:10px;overflow-x:auto}
.snippet .ln{display:flex}.snippet .no{width:52px;text-align:right;padding-right:12px;color:#5d7186;flex-shrink:0}
.snippet .hl{background:#5c2b29}.snippet code{white-space:pre}
.why{margin-bottom:8px}.why b{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.refs{font-size:12px;color:var(--muted)}
footer{max-width:1150px;margin:0 auto;padding:0 24px 30px;font-size:11.5px;color:var(--muted)}
"""

def rating_badge(r):
    return f'<span class="rating" style="background:{RATING_COLOR[r]}">{r}</span>'

def html_report(res):
    m, ct, rt = res["metrics"], res["counts"], res["ratings"]
    gate_cls = "pass" if res["pass"] else "fail"
    gate_txt = "Quality Gate: Passed" if res["pass"] else "Quality Gate: Failed"
    conds = "".join(
        f'<span class="cond {"ok" if c["ok"] else "ko"}">{"✓" if c["ok"] else "✗"} {esc(c["label"])}</span>'
        for c in res["conditions"])
    cards = f"""
<div class="card"><div class="num">{ct['VULN']}{rating_badge(rt['security'])}</div><div class="lbl">Vulnerabilities · Security</div></div>
<div class="card"><div class="num">{ct['HOTSPOT']}</div><div class="lbl">Security Hotspots</div></div>
<div class="card"><div class="num">{ct['BUG']}{rating_badge(rt['reliability'])}</div><div class="lbl">Bugs · Reliability</div></div>
<div class="card"><div class="num">{ct['SMELL']}{rating_badge(rt['maintainability'])}</div><div class="lbl">Code Smells · Maintainability</div></div>
<div class="card"><div class="num">{m['dupPct']}%</div><div class="lbl">Duplication</div></div>
<div class="card"><div class="num">{m['ncloc']}</div><div class="lbl">Lines of Code</div></div>
<div class="card"><div class="num">{m['files']}</div><div class="lbl">Files Scanned</div></div>"""
    file_rows = "".join(
        f"<tr><td>{esc(f)}</td><td class='n'>{n}</td></tr>"
        for f, n in sorted(res["perFile"].items(), key=lambda kv: -kv[1]))
    file_table = (f"<table><tr><th>File</th><th style='text-align:right'>Issues</th></tr>{file_rows}</table>"
                  if file_rows else "<p>No issues in any file. 🎉</p>")
    items = []
    for i in res["issues"]:
        snippet = "".join(
            f'<div class="ln{" hl" if i["snipStart"] + k == i["line"] else ""}">'
            f'<span class="no">{i["snipStart"] + k}</span><code>{esc(l) or " "}</code></div>'
            for k, l in enumerate(i["snippet"]))
        items.append(f"""
<details><summary><span class="sev {i['sev']}">{i['sev']}</span>
<span class="itype">{TYPE_LABEL[i['type']]}</span>
<span class="imsg">{esc(i['msg'])}</span>
<span class="iloc">{esc(i['file'])}:{i['line']}</span></summary>
<div class="body"><div class="snippet">{snippet}</div>
<div class="why"><b>Why it matters</b><div>{esc(i['why'])}</div></div>
<div class="why"><b>How to fix</b><div>{esc(i['fix'])}</div></div>
<div class="refs">Rule {i['rule']} · {esc(i['ref'])}</div></div></details>""")
    issues_html = "\n".join(items) if items else "<p>No issues found. 🎉</p>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lazaret Report — {esc(os.path.basename(res['project']))}</title>
<style>{HTML_CSS}</style></head><body>
<header><div class="logo">Code<span>Guard</span> · Project Report</div>
<div class="meta">{esc(res['project'])} · scanned {esc(res['scannedAt'])}</div></header>
<div class="wrap">
<div class="panel"><div class="gate"><div class="gate-badge {gate_cls}">{gate_txt}</div>{conds}</div>
<div class="cards">{cards}</div></div>
<div class="panel"><h2>Issues by file</h2>{file_table}</div>
<div class="panel"><h2>All issues ({len(res['issues'])})</h2>{issues_html}</div>
</div>
<footer>Generated by Lazaret CLI. Pattern- and heuristic-based static analysis — not a substitute for a full security audit.</footer>
</body></html>"""

# ---------------- SARIF output ----------------
SARIF_LEVEL = {"BLOCKER": "error", "CRITICAL": "error", "MAJOR": "warning",
               "MINOR": "note", "INFO": "note"}

def _html_report_marked(res):
    """html_report() output with the Lazaret provenance meta-tag injected
    into <head>, so report files produced by this tool are recognizable and
    can be safely re-written by a later run (no-clobber-by-provenance)."""
    return html_report(res).replace(
        '<meta name="viewport"',
        lazaret_report.HTML_ENGINE_MARKER + '\n<meta name="viewport"',
        1)

def sarif_report(res):
    # L1: sarif_report receives the result AFTER redact_result has swept it,
    # and it emits no snippet text — but it does embed issue msg/why/fix
    # strings from the result. Defensively sweep here too so a future caller
    # that skips the main() pass cannot ship an unredacted result into SARIF.
    redact_result(res)
    rules_seen, results = {}, []
    for i in res["issues"]:
        rules_seen.setdefault(i["rule"], {
            "id": i["rule"], "name": i["name"],
            "shortDescription": {"text": i["name"]},
            "fullDescription": {"text": i["why"]},
            "help": {"text": i["fix"]}})
        results.append({
            "ruleId": i["rule"], "level": SARIF_LEVEL[i["sev"]],
            "message": {"text": i["msg"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": i["file"].replace(os.sep, "/")},
                "region": {"startLine": i["line"]}}}]})
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Lazaret", "version": "2.0.0",
                                          "informationUri": "https://example.invalid/lazaret",
                                          "rules": list(rules_seen.values())}},
                      "results": results}]}

# ---------------- Baseline (new-code focus) ----------------
def fingerprint(issue):
    idx = issue["line"] - issue["snipStart"]
    snippet = issue.get("snippet") or []
    line_text = snippet[idx].strip() if 0 <= idx < len(snippet) else ""
    return f"{issue['rule']}|{issue['file']}|{line_text}"
# NOTE: redaction (audit L1) happens at mk_issue time, BEFORE this
# fingerprint is computed — the placeholder text is deterministic for a
# given (rule, secret length), so same-engine baselines still match; a
# pre-redaction-era baseline (with raw secret lines) simply won't match a
# secret fingerprint any more, and those issues surface as new — the safe
# direction for a security tool.

def apply_baseline(res, baseline_path):
    # G17 (artifact hygiene): a baseline is a REPORT-shaped file that CI may
    # gate on. Any file in the scanned repo can become a baseline argument
    # (relative --baseline paths resolve inside the repo), so the baseline
    # must be provenance-checked exactly like a report destination: an
    # arbitrary attacker-supplied JSON with attacker-computed fingerprints
    # can otherwise zero `newIssues` and make a CI gate pass (audit probe:
    # a forged-but-real-shaped baseline printed "New issues vs baseline: 0"
    # while the scan had 2 live findings).
    if lazaret_report is None:
        print("warning: baseline validation unavailable (lazaret_report not "
              "importable); baseline ignored", file=sys.stderr)
        return
    if not lazaret_report.is_our_report(baseline_path, "json"):
        # audit H1: baseline_path may resolve inside the scanned repo; the
        # message text is sanitized before it reaches the terminal.
        print(f"warning: baseline {sanitize_term(baseline_path)} is not a report produced by "
              f"this engine (no matching engine marker, or wrong shape) — "
              f"treating it as untrusted: all current findings are counted "
              f"as new", file=sys.stderr)
        for i in res["issues"]:
            i["new"] = True
        res["newIssues"] = len(res["issues"])
        res["baselineUntrusted"] = True
        return
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            prev = json.load(fh)
    except (OSError, json.JSONDecodeError, RecursionError) as exc:
        # audit H1: {exc} can echo hostile baseline content (JSONDecodeError
        # position text); sanitize both interpolations.
        print(f"warning: could not read baseline {sanitize_term(baseline_path)}: "
              f"{sanitize_term(exc)}", file=sys.stderr)
        return
    # 48033f94: validate the baseline's shape before using it. A baseline is
    # attacker-adjacent input (it usually comes from the scanned repo or CI
    # artifacts); {"issues":"not-a-list"} raised TypeError and a top-level
    # list raised AttributeError, both crashing the CLI after the scan had
    # already run — losing every result.
    if not isinstance(prev, dict):
        # audit H1: the baseline path can resolve inside the scanned repo.
        print(f"warning: baseline {sanitize_term(baseline_path)}: top level is "
              f"{type(prev).__name__}, not an object — expected "
              f'{{"issues": [...]}}; baseline ignored', file=sys.stderr)
        return
    issues = prev.get("issues", [])
    if not isinstance(issues, list):
        # audit H1: sanitize the repo-adjacent baseline path before printing.
        print(f"warning: baseline {sanitize_term(baseline_path)}: 'issues' is "
              f"{type(issues).__name__}, not a list — baseline ignored",
              file=sys.stderr)
        return
    known, skipped = set(), 0
    for i in issues:
        # Each baseline entry must at least look like an issue (rule/file/line
        # keys); a malformed entry is skipped with a warning, not a crash.
        try:
            known.add(fingerprint(i))
        except (KeyError, TypeError, AttributeError):
            skipped += 1
    if skipped:
        # audit H1: sanitize the repo-adjacent baseline path before printing.
        print(f"warning: baseline {sanitize_term(baseline_path)}: {skipped} malformed "
              f"issue entrie(s) skipped (expected objects with "
              f"rule/file/line)", file=sys.stderr)
    new_count = 0
    for i in res["issues"]:
        i["new"] = fingerprint(i) not in known
        new_count += i["new"]
    res["newIssues"] = new_count

# ---------------- Main ----------------
def main():
    configure_stdio()
    global REDACT_SECRETS, EXCERPT_WIDTH
    ap = argparse.ArgumentParser(prog="lazaret", description="Lazaret — security & quality scanner for Python/JS projects.")
    ap.add_argument("directory", help="Project directory to scan")
    ap.add_argument("--out-dir", metavar="DIR",
                    help="Directory for the default reports (default: the scan root). "
                         "Must already exist and be writable.")
    ap.add_argument("--html", default=None, metavar="PATH",
                    help="Write HTML project report (default: <out-dir>/lazaret-report.html)")
    ap.add_argument("--json", default=None, metavar="PATH",
                    help="Write JSON report (default: <out-dir>/lazaret-report.json)")
    ap.add_argument("--no-html", action="store_true")
    ap.add_argument("--no-json", action="store_true")
    ap.add_argument("--force-overwrite", action="store_true",
                    help="Overwrite an existing report file even if it was not "
                         "produced by Lazaret (still refuses directories, "
                         "symlinks and special files)")
    ap.add_argument("--exclude", action="append", default=[], metavar="NAME",
                    help="Extra directory name to skip (repeatable)")
    ap.add_argument("--deps", action="store_true",
                    help="Also scan dependency dirs (node_modules, venv, vendor) for "
                         "supply-chain indicators: obfuscation, secrets, install hooks")
    ap.add_argument("--sarif", metavar="PATH",
                    help="Write SARIF 2.1.0 report (GitHub code scanning)")
    ap.add_argument("--baseline", metavar="PATH",
                    help="Previous JSON report; issues not in it are marked new")
    ap.add_argument("--taint-config", metavar="PATH",
                    help="JSON taint spec adding custom sources/sinks/sanitizers "
                         "(Semgrep-style). Auto-loads .lazaret-taint.json from the scan root.")
    ap.add_argument("--strict-taint-config", action="store_true",
                    help="Treat taint-config rules rejected by validation (unknown "
                         "category, empty pattern) as fatal — exit 4 even for the "
                         "auto-loaded .lazaret-taint.json. Always on for an "
                         "explicit --taint-config.")
    ap.add_argument("--ci", action="store_true", help="Exit 1 if the quality gate fails")
    ap.add_argument("--no-redact-secrets", action="store_true",
                    help="Opt OUT of secret redaction in reports: keep the matched line "
                         "for credential findings (S-SECRET/S-TOKEN/SQL-CRED/S-ENTROPY). "
                         "By default the flagged line is replaced with a placeholder in "
                         "every artifact — terminal, JSON/HTML/SARIF reports — so scans of "
                         "your own code do not persist credentials into CI artifacts.")
    ap.add_argument("--excerpt-width", type=int, default=EXCERPT_WIDTH, metavar="N",
                    help=f"Chars of the matched line to show under each finding (default {EXCERPT_WIDTH})")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    REDACT_SECRETS = not args.no_redact_secrets
    EXCERPT_WIDTH = args.excerpt_width

    if not os.path.isdir(args.directory):
        print(f"error: {sanitize_term(args.directory)} is not a directory", file=sys.stderr)
        sys.exit(2)

    # Report destinations (JSON/HTML/SARIF): resolve under the scan root (or
    # --out-dir) — never bare CWD-relative names — and validate BEFORE
    # scanning, so an unwritable/read-only output location fails fast with a
    # clear message instead of a post-scan PermissionError that throws away a
    # completed scan, and a pre-existing file is never silently clobbered.
    try:
        if args.out_dir:
            lazaret_report.validate_out_dir(args.out_dir)
        paths = lazaret_report.report_paths(args, args.directory)
        if args.no_json:
            paths.pop("json")
        if args.no_html:
            paths.pop("html")
        if not args.sarif:
            paths.pop("sarif")
        if paths:
            lazaret_report.validate_report_paths(
                paths, strict=args.force_overwrite)
    except lazaret_report.ReportPathError as exc:
        # audit H1: {exc} echoes the operator-supplied path, which may sit
        # under the scanned repo (--out-dir / report names); sanitize it.
        print(f"error: {sanitize_term(exc)}", file=sys.stderr)
        sys.exit(lazaret_report.EXIT_OUTPUT)

    # taint config: explicit flag, else auto-load .lazaret-taint.json from root.
    # Validation is fail-loud: rules that fail validation (unknown category,
    # empty pattern, malformed section) produce warnings naming the file, the
    # rule and the reason — never silently dropped. And when the config came
    # from an explicit --taint-config, rejected rules make the scan exit 4, so
    # CI cannot silently lose coverage; --strict-taint-config extends that to
    # the auto-loaded project config.
    cfg_path = args.taint_config
    if not cfg_path:
        default_cfg = os.path.join(args.directory, ".lazaret-taint.json")
        cfg_path = default_cfg if os.path.isfile(default_cfg) else None
    if cfg_path:
        flow_warnings = []
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = json.load(fh)
            apply_taint_config(cfg)
            if lazaret_flow is not None:
                lazaret_flow.configure(
                    cfg, on_warn=lambda msg: flow_warnings.append(msg))
            # audit H1: cfg_path may be the auto-loaded
            # <scan-root>/.lazaret-taint.json (repo content).
            print(f"  Loaded taint config: {sanitize_term(cfg_path)}")
        except (OSError, json.JSONDecodeError, RecursionError) as exc:
            # 1149e3e5: the auto-loaded path is scanned-repo content — a
            # ~60KB deep-nested .lazaret-taint.json raised RecursionError,
            # which is NOT a JSONDecodeError, crashing the CLI mid-scan
            # (probe: rc=1 with Traceback before this guard). Treated like
            # any unreadable config: warn and scan without it.
            # audit H1: both the path and {exc} (JSONDecodeError position
            # text can echo hostile config bytes) are sanitized.
            print(f"warning: could not load taint config {sanitize_term(cfg_path)}: "
                  f"{sanitize_term(exc)}", file=sys.stderr)
        # both engines validate the same rules; their messages match on purpose
        # so the CLI can surface each rejection exactly once, prefixed with
        # the config file path.
        rejected = _dedupe(get_taint_config_warnings() + flow_warnings)
        for msg in rejected:
            # audit H1: msg embeds rejected rule names/patterns verbatim from
            # the auto-loaded config = repo content; sanitize both halves.
            print(f"warning: {sanitize_term(cfg_path)}: {sanitize_term(msg)}", file=sys.stderr)
        if rejected:
            strict = bool(args.taint_config) or args.strict_taint_config
            if strict:
                # audit H1: sanitize the config path (see above).
                print(f"error: {len(rejected)} taint-config rule(s) rejected in "
                      f"{sanitize_term(cfg_path)} — fix them (see warnings above) or the custom "
                      f"detection they define will not run", file=sys.stderr)
                sys.exit(EXIT_TAINT_CONFIG)

    files, manifests, binary_issues = collect_files(args.directory, args.exclude,
                                                    include_deps=args.deps)
    if not files and not manifests and not binary_issues:
        print("No Python or JavaScript files found.", file=sys.stderr)
        sys.exit(2)

    issues = list(binary_issues)
    for f in files:
        issues.extend(scan_file(f["path"], f["content"], f["lang"], dep=f.get("dep", False)))
    for mf in manifests:
        # binding.gyp manifests are handled by scan_gyp (G11); package.json by
        # scan_manifest.
        if os.path.basename(mf["path"]) == "binding.gyp":
            issues.extend(scan_gyp(mf["path"], mf["content"]))
        else:
            issues.extend(scan_manifest(mf["path"], mf["content"]))
    # G10: skipped-directory accounting — INFO findings make the coverage gap
    # visible instead of silent.
    issues.extend(skipped_tree_issues())
    if lazaret_flow is not None:
        # The interprocedural engine predates Python 3.12's ast changes
        # (ast.Num/ast.Str removed) and raises AttributeError on
        # multi-function files there. That is a defect of the flow engine
        # itself (tracked separately); the CLI must degrade to the intra-file
        # engine rather than crash mid-scan, and say so instead of hiding it.
        try:
            issues.extend(lazaret_flow.analyze(files))
        except Exception as exc:
            # audit H1: {exc} can carry content parsed out of scanned files
            # (the flow engine raises on hostile input); sanitize it.
            print(f"warning: interprocedural taint analysis skipped "
                  f"({type(exc).__name__}: {sanitize_term(exc)})", file=sys.stderr)
    res = build_result(args.directory, files, issues)
    # L1: belt-and-braces — no SECRET-rule issue may reach a report or the
    # baseline fingerprinter with its raw flagged line, whichever engine
    # path produced it.
    redact_result(res)
    if args.baseline:
        apply_baseline(res, args.baseline)
    print_report(res, args.quiet)

    # Writes are validated (writability + no-clobber) before the scan; each
    # write re-checks and is atomic (temp file + rename), so a mid-write
    # crash never leaves a half-written report behind.
    try:
        if args.sarif:
            sarif_path = lazaret_report.write_report(
                paths["sarif"],
                lambda: lazaret_report.sarif_renderer(sarif_report(res)),
                kind="sarif", strict=args.force_overwrite)
            print(f"  SARIF report: {sanitize_term(sarif_path)}")
        if not args.no_json:
            json_path = lazaret_report.write_report(
                paths["json"],
                lambda: lazaret_report.json_renderer(res),
                kind="json", strict=args.force_overwrite)
            print(f"  JSON report: {sanitize_term(json_path)}")
        if not args.no_html:
            html_path = lazaret_report.write_report(
                paths["html"],
                lambda: _html_report_marked(res),
                kind="html", strict=args.force_overwrite)
            print(f"  HTML report: {sanitize_term(html_path)}")
    except lazaret_report.ReportPathError as exc:
        # Only reachable if the pre-scan checks raced with an external
        # change (TOCTOU); the scan itself already ran and printed above.
        # audit H1: sanitize the echoed path before it reaches the terminal.
        print(f"error: {sanitize_term(exc)}", file=sys.stderr)
        sys.exit(lazaret_report.EXIT_OUTPUT)
    print()
    if args.ci and not res["pass"]:
        sys.exit(1)
    # 48033f94: a hostile-depth manifest (SC-MANIFEST-DEPTH) is a CRITICAL
    # supply-chain finding by design; make sure the exit code reflects it,
    # mirroring --ci (scan completes, reports are written — then signal).
    if any(i.get("sev") == "CRITICAL" and i.get("rule", "").startswith("SC-")
           for i in res["issues"]):
        sys.exit(1)

if __name__ == "__main__":
    main()
