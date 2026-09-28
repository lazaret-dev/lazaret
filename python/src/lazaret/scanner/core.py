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

Exit codes: 0 scan ok (also when the gate fails without --ci); 1 quality gate
failed with --ci, or a hostile manifest (SC-MANIFEST-DEPTH); 2 usage error
(unknown option; target missing, not a directory, unreadable or empty);
3 report output error; 4 taint config rejected; 5 internal error.

Reports are written under the scan root (or --out-dir), never the current
working directory; writability and collisions are checked before scanning
(exit 3 on a problem), and pre-existing files not produced by Lazaret are
never silently overwritten (--force-overwrite to override).

Taint-config rules that fail validation (unknown category, empty pattern,
wrong type, unsafe regex) are never silently dropped: each produces a warning
naming the file, the rule and the reason. An explicit --taint-config that has
rejected rules, or that cannot be loaded at all, makes the scan exit 4, so CI
cannot silently lose coverage; a repository config (--trust-repo-config) does
the same only with --strict-taint-config.

No dependencies — runs on stock python3. Same ruleset as the Lazaret dashboard.
"""
import argparse
import bisect
import datetime
import errno
import html as html_mod
import io
import json
import keyword
import os
import posixpath
import re
import sys
import threading
import time
import unicodedata
import warnings

try:
    from lazaret.scanner import flow as lazaret_flow  # interprocedural / cross-file taint (optional)
except Exception:  # pragma: no cover
    lazaret_flow = None

from lazaret.scanner import reports as lazaret_report  # report paths: pre-scan validation, atomic writes
from lazaret.scanner import taintspec  # taint-config validation shared by both taint engines
from lazaret.scanner import _unicode13  # the Unicode every engine reads source text in


def configure_stdio():
    """Never crash while printing, and print the same bytes on every platform.

    Reports use characters such as the check and cross marks. Redirected
    output (a pipe, a file, CI logs) otherwise takes its encoding from the
    host: the ANSI code page on Windows (cp1252, which can't encode them —
    print() would raise mid-report), and the locale elsewhere (ASCII under a
    bare C locale). So redirected output is always written as UTF-8, unless
    PYTHONIOENCODING explicitly asks for something else. A terminal keeps its
    own encoding (the Windows console is Unicode already). Everywhere,
    characters a stream can't encode are replaced rather than raised. Called
    at the start of every CLI entry point."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream, errors in ((sys.stdout, "replace"), (sys.stderr, "backslashreplace")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                reconfigure(encoding="utf-8", errors=errors)
            else:
                reconfigure(errors=errors)
        except (OSError, ValueError):
            pass

# ---------------- Rules (mirrors lazaret.html) ----------------
SEV_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
TYPE_LABEL = {"VULN": "Vulnerability", "HOTSPOT": "Security Hotspot",
              "BUG": "Bug", "SMELL": "Code Smell"}

# ---- Provider token formats in linear time (S-TOKEN, secret redaction) ----
# The token pattern's JWT alternative, eyJ[A-Za-z0-9_\-]{10,}\.eyJ…, backtracks
# quadratically: on a run of "eyJeyJ…" every "eyJ" rescans the run to its end
# looking for the "." ('//' + 'eyJ' * 60,000: 21.2 s in S-TOKEN and as long
# again in snippet redaction, one regex call the time budget can't stop). A
# left boundary would make the regex linear but would stop matching a JWT
# glued to a preceding [A-Za-z0-9_-] character (an AWS key followed by one,
# say), so the pattern text stays and _TokenPattern matches exactly its
# language — the same leftmost matches, the same spans — in linear time, like
# the npm engine's findSecretToken (js/src/lib/redact.js). The other
# alternatives are linear as written and run as one regex. A JWT match starts
# at the first "eyJ" of a [A-Za-z0-9_-] run that is followed by ".eyJ" and ten
# more run characters, at least 13 characters before the run's end; every
# later "eyJ" of that run needs the same run end, so runs are examined once
# each, the candidate runs found by a C-speed look-ahead from each run start.
# _TokenPattern has the part of re.Pattern the scanner uses (pattern, flags,
# search, finditer, sub with a literal replacement).
_JWT_ALT = r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"
_JWT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_JWT_RUN_RE = re.compile(r"[A-Za-z0-9_\-]*")
_JWT_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9_\-])(?=[A-Za-z0-9_\-]{13,}\.eyJ[A-Za-z0-9_\-]{10})")
_TOKEN_ALTS = (       # S-TOKEN, in pattern order
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}", r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"sk_live_[A-Za-z0-9]{16,}", r"AIza[0-9A-Za-z_\-]{35}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", _JWT_ALT)
_TOKEN_REDACT_ALTS = (    # the redaction list's first pattern (_SECRET_LINE_PATTERNS[0])
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36,}", r"github_pat_[A-Za-z0-9_]{22,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}", r"sk_live_[A-Za-z0-9]{16,}", r"AIza[0-9A-Za-z_\-]{35}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)", _JWT_ALT)


def _jwt_in_run(s, start, run_end):
    """(start, end) of the leftmost JWT-alternative match beginning in
    s[start:run_end], where run_end ends that [A-Za-z0-9_-] run; else None."""
    if run_end - start < 13 or not s.startswith(".eyJ", run_end):
        return None
    tail = _JWT_RUN_RE.match(s, run_end + 4).end()
    if tail - (run_end + 4) < 10:
        return None
    p = s.find("eyJ", start, run_end - 10)         # the "eyJ" plus ten run characters fit
    return (p, tail) if p >= 0 else None


def _jwt_search(s, pos):
    """(start, end) of the leftmost JWT-alternative match at or after pos."""
    if 0 < pos < len(s) and s[pos - 1] in _JWT_CHARS and s[pos] in _JWT_CHARS:
        run_end = _JWT_RUN_RE.match(s, pos).end()  # pos is inside a run: its rest counts
        hit = _jwt_in_run(s, pos, run_end)
        if hit:
            return hit
        pos = run_end
    for m in _JWT_CANDIDATE_RE.finditer(s, pos):
        hit = _jwt_in_run(s, m.start(), _JWT_RUN_RE.match(s, m.start()).end())
        if hit:
            return hit
    return None


class _TokenMatch:
    __slots__ = ("string", "_span")

    def __init__(self, string, span):
        self.string, self._span = string, span

    def start(self, group=0):
        return self._span[0]

    def end(self, group=0):
        return self._span[1]

    def span(self, group=0):
        return self._span

    def group(self, group=0):
        return self.string[self._span[0]:self._span[1]]

    __getitem__ = group


class _TokenPattern:
    """The regex "|".join(alternatives), the last one the JWT alternative,
    matched in linear time (see above)."""

    def __init__(self, alternatives):
        assert alternatives[-1] == _JWT_ALT
        self.pattern = "|".join(alternatives)
        self.flags = re.compile(self.pattern).flags
        self._others = re.compile("|".join(alternatives[:-1]))

    def _spans(self, s, pos):
        # Leftmost-first over both parts; a part's next match is recomputed
        # only once the scan has passed its start (a match at a position does
        # not depend on where the search began), so each part scans the
        # string once. The two never tie: their first characters differ.
        other = jwt = None
        fresh_other = fresh_jwt = False
        while True:
            if not fresh_other or (other is not None and other[0] < pos):
                m = self._others.search(s, pos)
                other, fresh_other = (m.span() if m else None), True
            if not fresh_jwt or (jwt is not None and jwt[0] < pos):
                jwt, fresh_jwt = _jwt_search(s, pos), True
            best = other if jwt is None or (other is not None and other[0] < jwt[0]) else jwt
            if best is None:
                return
            yield best
            pos = best[1]                          # matches are never empty

    def search(self, string, pos=0):
        span = next(self._spans(string, pos), None)
        return None if span is None else _TokenMatch(string, span)

    def finditer(self, string, pos=0):
        return (_TokenMatch(string, span) for span in self._spans(string, pos))

    def sub(self, repl, string):
        """re.sub with a literal replacement string."""
        parts, pos = [], 0
        for a, b in self._spans(string, 0):
            parts += (string[pos:a], repl)
            pos = b
        return string if not parts else "".join(parts) + string[pos:]


_TOKEN_PATTERN = _TokenPattern(_TOKEN_ALTS)
_TOKEN_REDACT_PATTERN = _TokenPattern(_TOKEN_REDACT_ALTS)


def R(id, name, type, sev, langs, pat, msg, why, fix, ref, skip=None, need=None, flags=0):
    return {"id": id, "name": name, "type": type, "sev": sev, "langs": langs,
            "re": pat if isinstance(pat, _TokenPattern) else re.compile(pat, flags),
            "msg": msg, "why": why, "fix": fix, "ref": ref,
            "skip": re.compile(skip, re.I) if skip else None,
            "need": re.compile(need, re.I) if need else None}

# Inline imports that evaluate to a module (SC-EVAL-DECODE prefix grammar):
# `__import__("mod")` / `importlib.import_module("mod")`.
_INLINE_IMPORT = (r"__import__\(\s*['\"][\w.]+['\"]\s*\)"
                  r"|importlib\.import_module\(\s*['\"][\w.]+['\"]\s*\)")


def _module_ref(name):
    """Pattern for module `name` written by name or imported inline."""
    return (rf"(?:{name}|__import__\(\s*['\"]{name}['\"]\s*\)"
            rf"|importlib\.import_module\(\s*['\"]{name}['\"]\s*\))")


# Indirect calls of eval and Function (review of the adversarial analysis:
# `(0, eval)(atob(p))`, `eval.call(null, atob(p))`, `window['eval'](atob(p))`
# and `globalThis["ev" + "al"](atob(p))` ran a decoded payload unseen): the
# comma operator's `(0, eval)(…)`, `eval.call(thisArg, …)`,
# `eval.apply(thisArg, […])` and `eval.bind(…)(…)`, `Reflect.apply(eval,
# thisArg, […])`, and a
# computed member named by a string literal, whole or cut into pieces joined
# with + (`window['eval']`, `self["Func" + "tion"]`). Each alternative ends
# where the payload argument begins; SC-EVAL-DECODE and the dependency decode
# flow take them as sinks.
_SPLIT_LITERAL = r"(?:['\"`]\s*\+\s*['\"`])?"
# `(0, window.eval)`: a global object may name them, no other receiver
# (TypeScript's CommonJS output calls every imported function as
# `(0, module_1.name)(…)`, and typebox exports one named Function)
_GLOBAL_OBJECT = r"(?:(?:window|globalThis|self|global|top|parent|frames)\s*\.\s*)?"
_EVAL_BY_NAME = r"\[\s*['\"`](?:" + _SPLIT_LITERAL.join("eval") + "|" + _SPLIT_LITERAL.join("Function") + r")['\"`]\s*\]"
_INDIRECT_EVAL = (
    r"\(\s*(?:void\s+)?[\w$.]+\s*,\s*" + _GLOBAL_OBJECT + r"(?:eval|Function)\s*\)\s*\("
    r"|\b(?:eval|Function)\s*\.\s*(?:call|apply)\s*\(\s*(?:void\s+)?[\w$.]*\s*,\s*\[?"
    r"|\b(?:eval|Function)\s*\.\s*bind\s*\([^()]*\)\s*\("
    r"|\bReflect\s*\.\s*apply\s*\(\s*" + _GLOBAL_OBJECT + r"(?:eval|Function)\s*,\s*(?:void\s+)?[\w$.]*\s*,\s*\["
    r"|" + _EVAL_BY_NAME + r"\s*\(")


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
  _module_ref("os") + r"\s*\.\s*(system|popen)\s*\(",     # also __import__("os").system(
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
# Review fix: method names are not child_process calls. A receiver of this. /
# self. / super. (or a #private name), a definition prefix (async, static,
# get, set, function) and a definition shape — `name(params) {`, the
# parameter list followed by a block, as in a class body or an object
# literal — are excluded (56 false positives, all CRITICAL, in npm's own
# lib/: `async exec (args) {`, `return this.exec(args)`). Free calls
# (`exec(cmd)`, a destructured `const { exec } = require('child_process')`)
# and calls on any other receiver (`cp.exec(…)`, `child_process.exec(…)`,
# `require('child_process').exec(…)`) are still flagged.
R("S-EXEC-JS", "Shell exec", "HOTSPOT", "CRITICAL", ("js",),
  r"(?<![#$])(?<!\bthis\.)(?<!\bself\.)(?<!\bsuper\.)(?<!\basync\s)(?<!\bstatic\s)(?<!\bget\s)"
  r"(?<!\bset\s)(?<!\bfunction\s)\b(exec|execSync)\s*\((?![^()]*\)\s*\{)"
  r"\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|\w+\s*[,)+])",
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
  # the look-ahead stops at the next yaml.load as well as at ')' — it used to
  # rescan to the end of the line from every call ('yaml.load(' * 50k +
  # 'SafeLoader': 7 s). An outer call whose only SafeLoader belongs to a
  # nested yaml.load is now (correctly) flagged.
  r"yaml\.load\s*\((?!(?:(?!yaml\.load)[^)])*(?:SafeLoader|safe_load))",
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
# The optional '[' carries its own whitespace: `\s*\[?\s*` let the two \s*
# split a run of spaces every way ('algorithm=' + 60,000 spaces: 16.7 s).
R("S-JWT-NONE", "JWT 'none' algorithm", "VULN", "BLOCKER", ("js", "py"),
  r"algorithms?\s*[:=]\s*(?:\[\s*)?[\"']none[\"']",
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
# The pattern (text: _TOKEN_ALTS) runs in linear time; see _TokenPattern.
R("S-TOKEN", "Known secret token format", "VULN", "BLOCKER", ("py", "js"),
  _TOKEN_PATTERN,
  "String matches a known secret format (AWS/GitHub/Slack/Stripe/Google key, private key, or JWT).",
  "Provider-format tokens in source are live credentials until proven otherwise.",
  "Remove it, rotate the credential immediately, and load it from a secrets manager.",
  "CWE-798 · OWASP A07"),
# Review fix (shared semantics 5): Trojan Source. Bidi embedding/override/
# isolate controls reorder how a line DISPLAYS without changing how it is
# parsed. Flagged anywhere on a line, comment lines included.
R("S-BIDI", "Trojan Source bidi control", "VULN", "CRITICAL", ("py", "js", "sql"),
  r"[\u202a-\u202e\u2066-\u2069]",
  "Bidirectional control character in source (Trojan Source)",
  "Bidi override and isolate characters make code display in a different order than the "
  "compiler reads it, so reviewers approve logic that is not what runs (CVE-2021-42574).",
  "Remove the control characters; where a string really needs one, write it as an escape "
  "sequence (e.g. \\u202e) so it is visible.",
  "CWE-451 · CVE-2021-42574"),
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
  r"chmod\s*\([^,()]*,\s*0o?7[67]7",
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
# Review fix (shared semantics 13): execSync and vm.runIn*Context are sinks
# too, the decoder may be member-prefixed (`globalThis.atob`, `window.atob`,
# `base64.b64decode`), and bytes.fromhex / unhexlify are decoders. scan_file
# also matches this rule over a statement split across lines (`eval(\n
# atob(…))`, `exec(  # comment\n b64decode(…))`); dependency mode adds a
# decode-to-variable-to-sink flow (see _dep_decode_flow).
# A prefix segment may also be an inline import — `__import__("base64").` or
# `importlib.import_module("zlib").` (review: `exec(__import__("base64")
# .b64decode("…"))` was missed) — and a module-qualified decoder may name its
# module that way (`eval(__import__('codecs').decode(…))`). Every segment ends
# at a '.', so the prefix stays linear-time.
# `exec(compile(b64decode(…), …))` is the same thing with Python's compile()
# in between; it used to be caught only by SC-MARSHAL's `exec(compile(`.
R("SC-EVAL-DECODE", "Decoded payload execution", "VULN", "BLOCKER", ("py", "js"),
  r"(?:\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\s*\(|" + _INDIRECT_EVAL + r")"
  r"\s*(?:compile\s*\(\s*)?"
  r"(?:(?:[\w$]+|" + _INLINE_IMPORT + r")\s*\.\s*)*"
  r"(?:atob|unescape|decodeURIComponent|Buffer\s*\.\s*from|b64decode|"
  + _module_ref("codecs") + r"\s*\.\s*decode|" + _module_ref("zlib") + r"\s*\.\s*decompress|"
  + _module_ref("marshal") + r"\s*\.\s*loads|fromhex|unhexlify)\s*\(",
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
# Marshalled bytecode that is run, or that comes from bytes embedded or
# decoded in the code itself: `exec(marshal.load(f))`,
# `FunctionType(marshal.loads(b), …)`, `marshal.loads(b"\xe3…")`,
# `marshal.loads(zlib.decompress(base64.b64decode(…)))`. Loading marshal data
# on its own is ordinary: pytest's assertion-rewrite cache, jinja2's bytecode
# cache and setuptools all call marshal.load(f), and jinja2 builds code objects
# (0.1.1 flagged every one of them, making all three SUSPICIOUS). A payload
# decoded into a variable, marshalled and run later is the decode flow's
# SC-EVAL-DECODE; `exec(compile(src, path, "exec"))` runs source text and is
# not here either (--full still reports exec() as S-EVAL-PY).
R("SC-MARSHAL", "Marshalled bytecode execution", "VULN", "CRITICAL", ("py",),
  r"\b(?:exec|eval|FunctionType)\s*\(\s*" + _module_ref("marshal") + r"\s*\.\s*loads?\s*\("
  r"|\b" + _module_ref("marshal") + r"\s*\.\s*loads\s*\(\s*(?:b['\"]|"
  r"(?:(?:[\w$]+|" + _INLINE_IMPORT + r")\s*\.\s*)*"
  r"(?:b64decode|b32decode|b85decode|a85decode|decodebytes|decompress|fromhex|unhexlify|a2b_\w+|decode)\s*\()",
  "Marshalled bytecode is run, or loaded from bytes embedded or decoded in the code.",
  "Bytecode blobs evade source review — a common Python malware technique.",
  "Inspect the blob's origin; refuse opaque executable data in source trees.",
  "CWE-506 · Supply chain"),
R("SQL-XPCMD", "OS command execution via SQL", "VULN", "CRITICAL", ("sql",),
  r"\bxp_cmdshell\b",
  "xp_cmdshell runs operating-system commands from SQL Server.",
  "Enables full OS command execution from the database; a top post-exploitation target.",
  "Keep xp_cmdshell disabled; use a vetted, sandboxed job runner instead.",
  "CWE-78 · OWASP A03", flags=re.I),
R("SQL-DYNAMIC", "Dynamic SQL from concatenation", "VULN", "BLOCKER", ("sql",),
  # Review fix: every unbounded [^;]* used to restart at each statement head
  # ('SET @a = ' + 20k quotes: 7.6 s). The scans below stop at the next head
  # of the same kind, and the SET form scans to its FIRST quote, so each
  # character is examined a bounded number of times. A line matches iff the
  # old pattern matched, except `SET @a = 'x' SET @b = 1 + 2` (two
  # statements without ';'), which no longer counts as one.
  r"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+"
  r"|EXECUTE\s+IMMEDIATE\b(?:(?!EXECUTE\s+IMMEDIATE\b)[^;])*\|\|"
  r"|sp_executesql\b(?:(?!sp_executesql\b)[^;])*\+"
  r"|EXEC\s*\(\s*['\"][^']*['\"]\s*\+"
  r"|SET\s+@\w+\s*=(?:(?!SET\s+@)[^;'\"])*['\"](?:(?!SET\s+@)[^;])*(?:\+|\|\|)",
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
  r"\bGRANT\b(?:(?!\bGRANT\b)[^;])*\bTO\s+PUBLIC\b",   # linear: stops at the next GRANT
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
# linear: the optional parameter list carries its trailing whitespace (the
# old `\s*(…)?\s*` split a whitespace run every way: 'catch' + 150,000
# newlines took 21.7 s in one regex call, which the time budget can't stop)
R("B-EMPTY-CATCH", "Empty catch block", "BUG", "MAJOR", ("js",),
  r"catch\s*(?:\([^()]*\)\s*)?\{\s*\}",
  "Exception swallowed by empty catch.",
  "Errors vanish silently, making failures undiagnosable.",
  "Handle the error or at least log it.",
  "Reliability"),
R("B-EXCEPT-PASS", "except: pass", "BUG", "MAJOR", ("py",),
  # linear: the old `:\s*\n\s*` backtracked over every newline run, and
  # `except[^\n:]*` restarted at each 'except' on a long line
  r"except(?:(?!except)[^\n:])*:[^\S\n]*\n\s*pass\b",
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
# Review fix (shared semantics 12): a Python annotated assignment
# `x: T = source` binds x (the optional `: T` part), and a JS destructuring
# declaration binds every name in its pattern (_JS_DESTRUCT_RE below) —
# `target: str = request.args.get("next")` and `const { file } = req.query`
# used to leave their names untainted.
ASSIGN_RE = {
    "py": re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=\n]*)?=(?![=])\s*(.+)"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)"),
}
# one-level object / array pattern: `{ a, b: c, d = 1, ...e }` / `[a, , b = 2, ...c]`
_JS_DESTRUCT_RE = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(\{[^{}]*\}|\[[^\[\]]*\])\s*=(?![=>])\s*(.+)")
_JS_BINDING_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _destructured_names(pattern):
    """Names bound by a one-level JS destructuring pattern:
    `{ a, b: c, d = 1, ...e }` -> [a, c, d, e]; `[a, , b = 2, ...c]` -> [a, b, c]."""
    names = []
    for part in pattern[1:-1].split(","):
        part = part.strip()
        if part.startswith("..."):
            part = part[3:].strip()
        elif pattern[0] == "{" and ":" in part:
            part = part.split(":", 1)[1].strip()
        part = part.split("=", 1)[0].strip()
        if _JS_BINDING_RE.fullmatch(part):
            names.append(part)
    return names


def _assignment(line, lang):
    """(names bound, right-hand side) of an assignment line, or (None, None).
    A Python keyword never counts as a name (`else: x = …` is not an
    annotated assignment to `else`)."""
    m = ASSIGN_RE[lang].match(line)
    if m:
        name = m.group(1)
        if lang == "py" and (keyword.iskeyword(name) or (
                keyword.issoftkeyword(name) and line[m.end(1):].lstrip().startswith(":"))):
            return None, None
        return [name], m.group(2)
    if lang == "js":
        dm = _JS_DESTRUCT_RE.match(line)
        if dm:
            names = _destructured_names(dm.group(1))
            if names:
                return names, dm.group(2)
    return None, None

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

#: Exit code for a taint config passed via --taint-config that cannot be
#: loaded or whose rules failed validation (unknown category, empty pattern,
#: malformed section, unsafe regex) — or a repository config under
#: --strict-taint-config. Distinct from the quality-gate exit 1, the usage
#: exit 2, EXIT_OUTPUT's 3 and the internal-error exit 5.
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


def apply_taint_config(cfg, allow_sanitizers=True):
    """Extend the intra-file taint model (sources/sinks/sanitizers) from a
    config — the same file consumed by the interprocedural engine.

    *cfg* is a parsed config (validated here) or a taintspec.TaintSpec the
    caller already validated. Both engines validate through
    lazaret.scanner.taintspec, so they accept exactly the same rules and
    report rejections with identical texts (the CLI prints each once).
    Invalid rules are not silently dropped: each one records a warning (see
    get_taint_config_warnings()) naming the rule and the reason. User regexes
    are guarded (length cap, static backtracking check, and each match sees
    at most taintspec.MAX_MATCH_TEXT characters of a line).
    allow_sanitizers=False (a config from the scanned repository): its
    sanitizers are ignored, never applied.
    """
    del _TAINT_CONFIG_WARNINGS[:]
    spec = (cfg if isinstance(cfg, taintspec.TaintSpec)
            else taintspec.validate(cfg, allow_sanitizers=allow_sanitizers))
    _TAINT_CONFIG_WARNINGS.extend(spec.warnings)
    for lang_key, lang in (("python", "py"), ("javascript", "js")):
        ls = spec.lang(lang_key)
        if ls.sources:
            TAINT_SOURCES[lang] = taintspec.extend_pattern(TAINT_SOURCES[lang],
                                                           ls.sources)
        for gp, cat in ls.sinks:
            sev, cwe, fix = _CAT_META[cat]
            TAINT_SINKS[lang].append((_SUFFIX_BY_CATEGORY[cat], gp, cat, sev, cwe, fix))
        for name in ls.full:
            # names are validated call names; re.escape makes them literal
            _FULL_SAN[lang] = re.compile(
                _FULL_SAN[lang].pattern + "|" + re.escape(name)
                + r"\s*\(" + _SAN_BODY + r"\)")
        for name, cats in ls.partial.items():
            add = re.escape(name) + r"\s*\(" + _SAN_BODY + r"\)"
            for cat in sorted(cats):
                suf = _SUFFIX_BY_CATEGORY[cat]
                base = _PARTIAL_SAN[lang].get(suf)
                _PARTIAL_SAN[lang][suf] = re.compile(
                    (base.pattern + "|" + add) if base else add)


#: The scanned repository's own taint config (never auto-trusted).
REPO_TAINT_CONFIG = ".lazaret-taint.json"
#: Largest taint-config file read (bytes).
TAINT_CONFIG_MAX_BYTES = 1_000_000


def _read_taint_config(path, from_repo):
    """(cfg, None) or (None, reason) for a taint-config file.

    Only a regular file is read (a FIFO would hang the open); a repository
    config must not be a symlink either. Reads are bounded; bad UTF-8,
    invalid JSON, huge integers and deep nesting are reasons, not crashes."""
    try:
        st = os.lstat(path) if from_repo else os.stat(path)
    except OSError as exc:
        return None, str(exc.strerror or exc)
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        return None, ("not a regular file (symlinks and special files are "
                      "not followed)" if from_repo else "not a regular file")
    if st.st_size > TAINT_CONFIG_MAX_BYTES:
        return None, (f"{st.st_size} bytes exceeds the "
                      f"{TAINT_CONFIG_MAX_BYTES}-byte limit")
    try:
        with open(path, "rb") as fh:
            data = fh.read(TAINT_CONFIG_MAX_BYTES + 1)
        return json_loads_bounded(data.decode("utf-8")), None
    except (OSError, ValueError, MemoryError) as exc:
        # ValueError covers JSONDecodeError, UnicodeDecodeError, the int-digit
        # limit and JsonTooDeep (1149e3e5: a deep-nested config).
        return None, str(exc)


def load_taint_config_for_scan(explicit_path, scan_root, trust_repo=False,
                               strict=False):
    """Load the taint config for one CLI scan; return report notes (issues).

    * --taint-config PATH: trusted fully (sources, sinks, sanitizers).
    * <scan-root>/.lazaret-taint.json: scanned-repository content, so it is
      loaded only with --trust-repo-config, and then may add sources and
      sinks but NOT sanitizers (ignored with a note) — a repository must not
      be able to declare its own code safe. Without the flag a one-line note
      says it was found and not loaded. A used repository config is recorded
      in the report as a Q-TAINT-CONFIG INFO note naming the file.
    Validation is fail-loud: rejected rules print warnings naming the file,
    the rule and the reason; with an explicit --taint-config (or strict,
    i.e. --strict-taint-config) rejected rules exit EXIT_TAINT_CONFIG (4).
    A config that cannot be loaded at all (missing, unreadable, not a
    regular file, too large, bad UTF-8, invalid JSON, too deep, an integer
    past the digit limit) is the same: `error:` and exit 4 for an explicit
    --taint-config or with strict, a warning for a trusted repository
    config (the scan then runs with the built-in model only).
    """
    if explicit_path:
        path, from_repo = explicit_path, False
    else:
        path = os.path.join(scan_root, REPO_TAINT_CONFIG)
        if not os.path.lexists(path):
            return []
        if not trust_repo:
            # audit H1: the path is under the scanned repo — sanitize.
            print(f"  note: {sanitize_term_line(path)} found but not loaded — a "
                  f"scanned repository's taint config is untrusted; pass "
                  f"--trust-repo-config to use its sources/sinks")
            return []
        from_repo = True
    cfg, err = _read_taint_config(path, from_repo)
    if err is not None:
        # audit H1: both the path and the reason (JSONDecodeError position
        # text can echo hostile config bytes) are sanitized.
        # An explicit --taint-config that cannot be loaded must not degrade
        # into a scan without the rules CI asked for (exit 4, like rejected
        # rules); a repository config only warns unless --strict-taint-config.
        fatal = not from_repo or strict
        print(f"{'error' if fatal else 'warning'}: could not load taint config "
              f"{sanitize_term_line(path)}: {sanitize_term_line(err)}", file=sys.stderr)
        if fatal:
            sys.exit(EXIT_TAINT_CONFIG)
        return []
    spec = taintspec.validate(cfg, allow_sanitizers=not from_repo)
    apply_taint_config(spec)
    if lazaret_flow is not None:
        lazaret_flow.configure(spec)
    # audit H1: path may be the repo's own config (repo content).
    print(f"  Loaded taint config: {sanitize_term_line(path)}"
          + (" (from the scanned repository: sources and sinks only)"
             if from_repo else ""))
    rejected = _dedupe(spec.warnings)
    for msg in rejected + _dedupe(spec.notes):
        # audit H1: msg embeds rejected rule names/patterns verbatim.
        print(f"warning: {sanitize_term_line(path)}: {sanitize_term_line(msg)}",
              file=sys.stderr)
    if rejected and (not from_repo or strict):
        print(f"error: {len(rejected)} taint-config rule(s) rejected in "
              f"{sanitize_term_line(path)} — fix them (see warnings above) or the "
              f"custom detection they define will not run", file=sys.stderr)
        sys.exit(EXIT_TAINT_CONFIG)
    if not from_repo:
        return []
    n = spec.counts()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            cfg_lines = fh.read(TAINT_CONFIG_MAX_BYTES).split("\n")
    except OSError:
        cfg_lines = []
    note = mk_issue(
        {"id": "Q-TAINT-CONFIG", "name": "Taint rules loaded from the scanned repository",
         "type": "HOTSPOT", "sev": "INFO",
         "msg": (f"Custom taint rules from the repository's own {REPO_TAINT_CONFIG} "
                 f"were used (--trust-repo-config): {n['sources']} source(s), "
                 f"{n['sinks']} sink(s)"
                 + (f"; {spec.ignored_sanitizers} sanitizer rule(s) ignored"
                    if spec.ignored_sanitizers else "") + "."),
         "why": "A repository-supplied taint config changes what this scan "
                "looks for. Sources and sinks from it are applied; sanitizers "
                "never are, so the repository cannot declare its own code safe.",
         "fix": "Review the file; to trust it fully (including sanitizers), "
                "pass it explicitly with --taint-config.",
         "ref": "Taint configuration provenance"},
        REPO_TAINT_CONFIG, 1, cfg_lines)
    return [note]


# Identifier runs for carrier matching. A variable v "appears" in a text iff
# it equals one of these maximal runs — the old per-variable `\bv\b` regex
# test, done as one findall + set lookups. (One compiled regex per tainted
# variable thrashed re's 512-pattern cache: an a1=a0 … a1000=a999 chain took
# 20 s.) For JS, `$` counts as an identifier character.
_IDENT_RUN_RE = {"py": re.compile(r"\w+"), "js": re.compile(r"[\w$]+")}


def taint_scan(path, lines, lang, ctx=None):
    if lang not in TAINT_SOURCES:   # SQL and others: pattern rules only, no taint flow
        return []
    if ctx is None or ctx.lines is not lines:
        ctx = _FileCtx(lines, lang, jsx=jsx_reading(path))
    # Each line is matched with its comment text removed: `/**/const d =
    # req.query.x` is an assignment, and `x = 1  // req.query` is not a source.
    # (Match text: NFKC for Python, decoded identifier escapes for JS.)
    cmask = ctx.cmask
    issues = []
    tainted = {}   # var -> (line_no, frozenset(clean sink suffixes), taint order)
    src = TAINT_SOURCES[lang]
    partial_cats = list(_PARTIAL_SAN.get(lang, {}))
    ident_re = _IDENT_RUN_RE[lang]

    def carriers_in(text_code, suf):
        """Tainted vars present in text_code that still pose danger for sink
        suffix suf (None: any), in the order they were tainted."""
        if not tainted:
            return []
        found = [v for v in set(ident_re.findall(text_code))
                 if v in tainted and suf not in tainted[v][1]]
        found.sort(key=lambda v: tainted[v][2])
        return found

    for i in range(len(lines)):
        if cmask[i]:
            continue
        line = ctx.mcode(i)
        if not line or line.isspace():
            continue
        if not i & 63:
            ctx.check_time()
        names, rhs = _assignment(line, lang)
        if names:
            base = STRING_LIT_RE.sub("", _neutralize(rhs, lang))  # full sanitizers stripped
            is_tainted = bool(src.search(base)) or bool(carriers_in(base, None))
            if is_tainted:
                clean = set()
                for suf in partial_cats:
                    neut = STRING_LIT_RE.sub("", _neutralize(rhs, lang, suf))
                    if not src.search(neut) and not carriers_in(neut, suf):
                        clean.add(suf)
                for name in names:
                    if name not in tainted:
                        tainted[name] = (i + 1, frozenset(clean), len(tainted))
        for suffix, sink_re, cat, sev, cwe, fix in TAINT_SINKS[lang]:
            sm = sink_re.search(line)
            if not sm:
                continue
            # neutralize full + this-category sanitizers in the sink's arguments
            rest = _neutralize(line[sm.end():], lang, suffix)
            rest_code = STRING_LIT_RE.sub("", rest)
            carriers = carriers_in(rest_code, suffix)
            if not carriers and not src.search(rest_code):
                continue
            what = (f"untrusted data via '{carriers[0]}' (tainted at line {tainted[carriers[0]][0]})"
                    if carriers else "untrusted data")
            issues.append(mk_issue(
                {"id": f"T-{suffix}", "name": f"Tainted flow → {cat}", "type": "VULN", "sev": sev,
                 "msg": f"Possible {cat}: {what} reaches this sink.",
                 "why": "Data from user input or a decode function flows into a dangerous call "
                        "without visible sanitization (lightweight intra-file taint tracking).",
                 "fix": fix, "ref": f"{cwe} · Taint analysis"}, path, i + 1, lines, sm.start()))
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
# Marker grammar (review fix, shared semantics 2): `#`, `//` or `--`, optional
# spaces/tabs, then nosec / NOSONAR / lazaret-ignore (case-insensitive, whole
# word). If what follows (after optional spaces and ':') is a comma-separated
# list of rule IDs, the marker suppresses only those rules; anything else —
# nothing, trailing whitespace, or a free-text reason such as "- reviewed by
# bob" — makes it a blanket marker for the line. The marker counts only when
# its introducer ('#', '//', '--') lies inside a real comment as the per-file
# comment lexer sees it (so `--` works in .sql comments, `#` in Python ones,
# and nothing inside a string, a template literal or code such as `x --nosec`
# or a JS `#private` field does). It applies to its own line, or to the next
# line when it sits on a standalone comment line. The marker is ASCII: re.I
# would also take `noſec` or `lazaret-ıgnore` (ſ is s and ı is i to it),
# which the npm engine's case folding does not; for a marker, matching less
# is what fails closed.
_RULE_ID_SRC = r"(?:S|T|SC|X|SQL|B|Q)-[A-Z0-9]+(?:-[A-Z0-9]+)*"
SUPPRESS_RE = re.compile(
    r"(?:#|//|--)[ \t]*(?:nosec|NOSONAR|lazaret-ignore)\b"
    r"(?:[ \t]*:?[ \t]*(" + _RULE_ID_SRC + r"(?:[ \t]*,[ \t]*" + _RULE_ID_SRC + r")*))?",
    re.I)

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


def _find_marker(line, spans):
    """The first ASCII SUPPRESS_RE match on `line` whose introducer lies
    inside one of the line's comment spans, else None. `spans` is sorted and
    non-overlapping, and matches come in order, so one moving index answers
    every containment test (review: testing every span for every match was
    O(matches × spans), 20 s for one 200 KB line)."""
    if not spans:
        return None
    k, n = 0, len(spans)
    for m in SUPPRESS_RE.finditer(line):
        p = m.start()
        while k < n and spans[k][1] <= p:
            k += 1
        if k == n:
            return None
        if spans[k][0] <= p and m.group().isascii():
            return m
    return None


def _marker_rules(m):
    """None for a blanket marker, else the frozenset of rule IDs it names."""
    ids = m.group(1)
    if not ids:
        return None
    return frozenset(s.strip().upper() for s in ids.split(","))


def marker_in_comment(line, lang=None):
    """The suppression marker on this line if it lives in real comment text
    (the line lexed on its own), else None. A `-- nosec` inside a string
    (the audit PoC `os.system("rm -rf / -- nosec")`) returns None."""
    return _find_marker(line, _comment_layout(line, [line], lang)[1].get(0))


_NO_MARKER = object()


def _suppressed_in(issue, ctx):
    rule = str(issue.get("rule", "")).upper()
    ln = issue["line"] - 1
    for k in (ln, ln - 1):
        if not (0 <= k < len(ctx.lines)):
            continue
        if k != ln and not ctx.cmask[k]:
            continue  # the line above counts only if it is a standalone comment
        ids = ctx.marker(k)
        if ids is _NO_MARKER:
            continue
        if ids is None or rule in ids:
            return True
    return False


def is_suppressed(issue, lines, lang=None, dep=False):
    # Suppression markers are reviewer annotations. The scanned code itself
    # must not be able to forge them (audit C2/G1: a marker inside a string
    # literal made a CRITICAL finding vanish and the gate PASSED; review: a
    # `# nosec"""` closing a docstring, a `// NOSONAR` inside a template
    # literal and `os.system(x) --nosec` in Python did the same), and
    # dependency/registry mode has no reviewer at all (G2: `// nosec` cleared
    # SC-EVAL-DECODE on a live implant). Never suppress supply-chain or
    # interprocedural findings, and never in dep mode. Suppression never
    # crosses files: the marker must be in `lines`, the finding's own file.
    if dep or str(issue.get("rule", "")).startswith(UNSUPPRESSIBLE_PREFIXES):
        return False
    ctx = _active_ctx(lines)
    if ctx is None or ctx.lang != lang:
        ctx = _FileCtx(lines, lang)
    return _suppressed_in(issue, ctx)

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
                 ".dex", ".jar", ".msi", ".dmg",
                 ".jsc"}              # V8 bytecode (bytenode): JavaScript no one can read
# Recognized benign binary assets — data, not code. Not flagged.
BENIGN_MAGIC = [b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"BM",
                b"\x00\x00\x01\x00", b"wOFF", b"wOF2", b"ID3", b"%PDF",
                b"II*\x00", b"MM\x00*", b"\x1a\x45\xdf\xa3", b"ftyp",
                # JPEG 2000 (codestream, JP2), Photoshop, Apple icons, DirectDraw,
                # OpenType / TrueType collections, PostScript, GIMP, SGI, Sun raster,
                # FITS, QOI, Radiance HDR, FLAC, cursors
                b"\xff\x4f\xff\x51", b"\x00\x00\x00\x0cjP  ", b"8BPS", b"icns", b"DDS ",
                b"OTTO", b"ttcf", b"%!PS", b"\xc5\xd0\xd3\xc6", b"gimp xcf", b"\x01\xda",
                b"\x59\xa6\x6a\x95", b"SIMPLE  =", b"qoif", b"#?RADIANCE", b"fLaC",
                b"\x00\x00\x02\x00"]
# Formats identified by a signature that isn't at offset 0, or by extension
# because their magic is too generic to trust alone.
# Document and asset formats that are zip or gzip containers by design.
CONTAINER_DOCUMENT_EXTS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".odg", ".epub",
                           ".dia", ".svgz", ".ora", ".kmz", ".3mf", ".xmind", ".vsdx"}
FONT_EXTS = {".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot", ".pfb", ".pcf", ".bdf"}
#: MPEG transport stream video (a camera's AVCHD .mts): the extensions it shares
#: with TypeScript (.ts, .mts), and Blu-ray's .m2ts
MPEG_TS_EXTS = (".ts", ".mts", ".m2ts")


def is_benign_media(header, ext):
    if any(header.startswith(sig) for sig in BENIGN_MAGIC) or b"ftyp" in header[:16]:
        return True
    if header[36:40] == b"acsp":                       # ICC color profile
        return True
    if ext in MPEG_TS_EXTS and _mpeg_ts(header):        # video
        return True
    return ext in FONT_EXTS and header[:4] in (b"\x00\x01\x00\x00", b"true", b"typ1")
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

# Characters that cannot occur in text: bytes of invalid UTF-8 sequences
# (decoded with surrogateescape to U+DC80..U+DCFF) and C0 controls other than
# whitespace and ESC, NUL included.
_NON_TEXT_CHARS_RE = re.compile("[\udc80-\udcff\x00-\x08\x0e-\x1a\x1c-\x1f\x7f]")
_NON_TEXT_SHARE = 0.30


def looks_binary(sample):
    """Heuristic text/binary classification from a leading byte sample.

    Only bytes that cannot be text count: invalid UTF-8 and C0 control
    characters (NUL included). Valid non-ASCII UTF-8 is text however much of
    it there is (an accented package description, CJK comments), and a single
    NUL inside a comment does not turn a source file into a "binary" that is
    never scanned. Callers must not use this to decide whether a file with a
    source extension or a manifest name gets scanned: those are always
    scanned as text (see decode_source)."""
    if not sample:
        return False
    sample = bytes(sample)
    text = sample.decode("utf-8", "surrogateescape")
    bad = len(_NON_TEXT_CHARS_RE.findall(text))
    return bad / len(sample) > _NON_TEXT_SHARE


def _mpeg_ts(header):
    """MPEG transport stream (.ts / .mts video): sync byte every 188 bytes.
    Shares the .ts and .mts extensions with TypeScript."""
    return len(header) >= 377 and header[0] == header[188] == header[376] == 0x47


# ---------------- Source decoding for archive members (registry, MCP) ----------------
def _text_is_plausible(text):
    """Does a UTF-16 guess (NUL in the first four bytes, no BOM) read as
    text? A UTF-8 file with a NUL near the top (`/*\\0*/eval(…)`) decodes to
    CJK-looking garbage under UTF-16; real UTF-16 source is mostly ASCII."""
    if not text:
        return False
    sample = text[:2048]
    plain = sum(1 for ch in sample if " " <= ch <= "~" or ch in "\t\r\n")
    return plain / len(sample) >= 0.70


def _undecodable_share(text):
    if not text:
        return 0.0
    sample = text[:65536]
    bad = sample.count("�") + len(_NON_TEXT_CHARS_RE.findall(sample))
    return bad / len(sample)


def decode_member(path, data, lang=None):
    """Decode one archive member (registry) or one file named by an MCP
    caller the way its runtime reads it. -> (text, extra_issues).

    Same decoding as a project scan (decode_source: BOM, BOM-less UTF-16
    only when it reads as text, PEP 263 cookies for Python incl. UTF-7 ->
    SC-UTF7) and the same Q-ENCODING / SC-UTF7 findings (encoding_issues).
    One addition for verdict integrity: a member that does not decode to
    anything text-like (more than 30% invalid bytes or control characters)
    adds SC-TRUNCATED — it was "scanned" only as mojibake, so the scan of it
    proves nothing. Never raises on content. `lang`: the language the
    member runs as when its name does not say (a Python script by its #!
    line keeps its coding cookie); by default, its extension's."""
    data = bytes(data or b"")
    ext = os.path.splitext(path)[1].lower()
    if lang is None:
        lang = "py" if ext in (".py", ".pyw") else EXTS.get(ext)
    text, info = decode_source(data, lang)
    extra = encoding_issues(path, text, info)
    share = _undecodable_share(text)
    if share > _NON_TEXT_SHARE and not (ext in MPEG_TS_EXTS and _mpeg_ts(data[:512])):
        extra.append(truncated_issue(
            path, f"content is not decodable as text ({share:.0%} invalid bytes or "
                  f"control characters), so no rule could read it"))
    return text, extra

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
        return issue("SC-BINARY", "Binary artifact in package", "MAJOR",
            f"Executable/compiled binary in {where}: {desc}.",
            "Prebuilt binaries can't be reviewed as source, and smuggled binaries are a "
            "known compromise vector. Many legitimate packages ship some (Windows "
            "launcher stubs, test fixtures), so on its own this is a capability to "
            "review, not evidence of malice.",
            "Confirm the binary's provenance; build from source instead of trusting a prebuilt blob.")
    # 2) nested archive — a known way to hide a second-stage payload from review
    #    (document formats that are zip/gzip containers by design are data)
    if ext in CONTAINER_DOCUMENT_EXTS:
        return None
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
    if is_benign_media(header, ext):
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
FN_HEADER_SCAN_LIMIT = 2000   # chars of a JS line searched for a function header
EXTS = {".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
        ".mts": "js", ".cts": "js", ".mjs": "js", ".cjs": "js", ".sql": "sql"}
# G10 + review item 8: what the project walk never source-scans.
#   * .git (exactly that name) is always pruned — VCS metadata, never
#     shippable source (and reported as a Q-SKIPPED-TREE blind spot).
#   * __pycache__ is not source-scanned, but every .pyc directly in it is
#     checked (see _check_pycache): an unchecked-hash pyc runs on import
#     whatever the .py next to it says (SC-PYC-UNCHECKED), and a pyc without
#     its source is unreviewable (SC-PYC-ORPHAN).
#   * dependency trees are pruned unless --deps (then walked, their files
#     marked dep=True): node_modules / bower_components / site-packages
#     always, vendor / venv / .venv / env only when they LOOK like a
#     dependency tree (DEP_TREE_MARKERS) — a first-party app/vendor/ helper
#     module used to be pruned by name alone, hiding it from every rule.
#   * --exclude NAME prunes any directory of that name (explicit, always).
# Every other classic "build output" directory — dist, build, migrations,
# coverage — is scanned: npm packages are *published from* dist/, migrations
# ARE the production SQL. Pruned trees are counted and reported, never
# silently dropped.
SKIP_DIRS = {".git", "__pycache__"}     # never source-scanned (see above)
ALWAYS_PRUNE_DIRS = frozenset({".git"})
PYCACHE_DIR = "__pycache__"
DEP_TREE_DIRS = frozenset({"node_modules", "bower_components", "site-packages"})
# name -> (marker names directly inside, marker suffixes directly inside)
DEP_TREE_MARKERS = {
    "venv": (("pyvenv.cfg",), ()),
    ".venv": (("pyvenv.cfg",), ()),
    "env": (("pyvenv.cfg",), ()),
    "vendor": (("modules.txt", "autoload.php", "package.json"), (".dist-info", ".egg-info")),
}
# Legacy convenience names kept for reference; they are NOT skipped unless
# listed with --exclude.
OPTIN_SKIP_DIRS = ["node_modules", "venv", ".venv", "env", "dist", "build",
                   ".next", "coverage", "vendor", "site-packages", ".tox",
                   ".mypy_cache", ".pytest_cache", "migrations"]

# G10: skipped-directory accounting. collect_files() fills this for callers of
# the legacy (files, manifests, binary_issues) API that then call
# skipped_tree_issues(); it is RESET at the start of every collect_files()
# call, so repeated scans in one process (the MCP server) never leak one
# scan's pruned trees into the next. scan_project() does not use it at all.
_SKIPPED_TREES = []   # [(relpath, file_count, byte_count)]

def _reset_scan_state():
    global _SKIPPED_TREES
    _SKIPPED_TREES = []

def _tree_stats(tree_path):
    """(file_count, byte_count) of a pruned tree, walked iteratively without
    following symlinks (a pruned tree can be arbitrarily deep or hostile)."""
    n_files, n_bytes = 0, 0
    stack = [tree_path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if _stat.S_ISDIR(st.st_mode) and not _is_reparse_point(st):
                stack.append(e.path)
            else:
                n_files += 1
                if _stat.S_ISREG(st.st_mode):
                    n_bytes += st.st_size
    return n_files, n_bytes

def _count_skipped_tree(root, tree_path, rel=None, into=None):
    """Record a pruned directory with its file count and total size for the
    INFO blind-spot accounting surfaced after the scan. `rel` is the
    root-relative display path (review item 5: it used to be cwd-relative,
    e.g. './app/vendor', when the root was given as a relative path)."""
    n_files, n_bytes = _tree_stats(tree_path)
    if rel is None:
        rel = _fs_display(os.path.relpath(tree_path, root))
    (_SKIPPED_TREES if into is None else into).append((rel, n_files, n_bytes))

def _skipped_issue(rel, n_files, n_bytes):
    return {
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
        "file": rel, "line": 1, "snippet": [], "snipStart": 1}

def skipped_tree_issues(skipped=None):
    """INFO issues summarizing the pruned trees (.git, dependency trees,
    --exclude) so the coverage gap is visible instead of silent. `skipped`
    defaults to the trees recorded by the most recent collect_files()."""
    return [_skipped_issue(*t) for t in (_SKIPPED_TREES if skipped is None else skipped)]

# ---------------- Comment lexer (review fix: shared semantics 1) ----------------
# is_comment() used to be a line-local prefix test: any JS/SQL line starting
# with "/*" or "*" counted as a comment, so `/**/eval(atob(…))`, a minified
# bundle opening with a `/*! lib | MIT */` banner, `/* x */ GRANT ALL … TO
# PUBLIC;` or a `  * eval(…)` continuation line were skipped by every rule.
# Comment state is now tracked ACROSS lines by a small lexer that knows the
# language's strings and comments; a line is a comment line only if every
# non-whitespace character on it is inside a comment.
#
# Fail closed where the same text reads two ways (review): a character is a
# comment only if BOTH readings of its language say so, so code that some
# runtime executes is never hidden as a comment, and a string can never pass
# for a comment holding a suppression marker. Each file is lexed twice and
# the comment spans (and, for JavaScript, the '…' "…" string spans; for
# SC-HOMOGLYPH, every literal's span) are intersected:
#   py : the lexer below, and again with f-strings (and t-strings) as
#        Python 3.12+ reads them (PEP 701): a replacement field may hold
#        strings in the same quotes, comments and newlines, and nothing in an
#        f-string is a comment. Python's own tokenizer is not used: it differs
#        across the supported versions (a comment line in a triple-quoted
#        f-string's field is a COMMENT on 3.12+ only; an unterminated string
#        ends a line on 3.10/3.11 and fails the whole file on 3.12+), and the
#        npm engine cannot run it.
#   js : the lexer below, and again reading JSX (not in .ts files, where
#        TypeScript parses none): in element text `//` and `/*` are text
#        (`<p>see /api/*</p>` opened a block comment that hid the rest of the
#        file) and attribute strings have no escapes; `{…}` holds code again.
#        An element starts at `<` + a tag name (or `>`) where an expression may
#        start: the regex positions below, after `default`, `)` or `]`. Text
#        no JSX toolchain accepts ends that reading at once (a `>` or `}` in
#        element text, anything but attributes in a tag), so a TypeScript
#        `<T>(x: T) => x` is code again at its `=>`.
#   sql: the lexer below (standard SQL), and again as MySQL reads it:
#        backslash escapes in '…' and "…", `…` quoted names, and `/*! … */`
#        (`/*M! … */`) is code MySQL executes (a mysqldump line
#        `('O\'Brien','src/*.js');` opened a comment that hid the next GRANT).
#
# Lexer semantics (mirrored by the JS engine):
#   py : '#' to end of line; '…' "…" end at end of line unless the newline is
#        backslash-escaped; '''…''' """…""" span lines; backslash escapes.
#   js : '//' to end of line; '/* … */' spans lines; '…' "…" as in py;
#        `…` template literals span lines (${…} is not re-lexed); a '/' that
#        starts a regex literal (previous significant code character is
#        start-of-file or one of ( , = : [ ! & | ? { } ; + - * % < > ~ ^, or
#        the previous word is return/typeof/instanceof/in/of/new/delete/void/
#        throw/case/do/else/yield/await) consumes the literal /…/ up to its
#        closing '/' on the same line (escapes and [classes] honoured); with no
#        closing '/' on the line it is a plain division, and so is every
#        later '/' on that line.
#   sql: '--' to end of line; '/* … */' spans lines; '…' and "…" span lines,
#        no backslash escapes ('' is two adjacent strings, same result).
#   other/unknown (lang None): '#' and '//' line comments, '/* … */', and
#        '…' "…" `…` strings ending at end of line (lexed once).
# Unterminated block comments and strings run to end of file.

_LEX_NEXT = {
    "py": re.compile(r"[#'\"]"),
    "js": re.compile(r"[/'\"`]"),
    "sql": re.compile(r"--|/\*|['\"]"),
    None: re.compile(r"#|/[/*]|['\"`]"),
}
_LEX_LINE_STR = {q: re.compile(q + r"(?:[^" + q + r"\\\n]|\\.)*" + q + "?", re.S)
                 for q in ("'", '"', "`")}
_LEX_STR = {
    ("py", "'"): _LEX_LINE_STR["'"], ("py", '"'): _LEX_LINE_STR['"'],
    ("py", "'''"): re.compile(r"'''(?:[^'\\]|\\.|'(?!''))*(?:'''|\Z)", re.S),
    ("py", '"""'): re.compile(r'"""(?:[^"\\]|\\.|"(?!""))*(?:"""|\Z)', re.S),
    ("js", "'"): _LEX_LINE_STR["'"], ("js", '"'): _LEX_LINE_STR['"'],
    ("js", "`"): re.compile(r"`(?:[^`\\]|\\.)*`?", re.S),
    ("sql", "'"): re.compile(r"'[^']*'?"), ("sql", '"'): re.compile(r'"[^"]*"?'),
    (None, "'"): _LEX_LINE_STR["'"], (None, '"'): _LEX_LINE_STR['"'],
    (None, "`"): _LEX_LINE_STR["`"],
}
# SQL as MySQL reads it
_LEX_MYSQL_NEXT = re.compile(r"--|/\*|['\"`]")
_LEX_MYSQL_STR = {"'": re.compile(r"'(?:[^'\\]|\\.)*'?", re.S),
                  '"': re.compile(r'"(?:[^"\\]|\\.)*"?', re.S),
                  "`": re.compile(r"`[^`]*`?")}
_JS_REGEX_LIT_RE = re.compile(r"/(?![*/])(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/")
_JS_REGEX_PREV = frozenset("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_KEYWORDS = frozenset((
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await"))


def _is_word_char(ch):
    return ch.isalnum() or ch in "_$"


def _js_regex_allowed(prev, tail, keywords=_JS_REGEX_KEYWORDS):
    """May a '/' after this code start a regex literal? `prev` is the last
    significant code character ('' at start of file), `tail` the last few
    code characters ending at it."""
    if prev == "" or prev in _JS_REGEX_PREV:
        return True
    if _is_word_char(prev):
        k = len(tail)
        while k > 0 and _is_word_char(tail[k - 1]):
            k -= 1
        if k == 0 and len(tail) >= 11:     # word longer than any keyword
            return False
        return tail[k:] in keywords
    return False


def _intersect_spans(a, b):
    """The (start, end) spans covered by both `a` and `b` (each sorted and
    non-overlapping)."""
    out = []
    i = j = 0
    while i < len(a) and j < len(b):
        s = max(a[i][0], b[j][0])
        e = min(a[i][1], b[j][1])
        if s < e:
            out.append((s, e))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def _lex_comment_spans(content, lang, strings=None, jsx=True, literals=None):
    """Absolute (start, end) spans of every comment in `content`: the spans
    both readings of the language agree on (see the lexer notes above).
    Linear: each reading finds the next interesting character with a regex
    and consumes strings and comments with bounded matches. If `strings`
    is a list, the '…' / "…" literal spans both JavaScript readings agree on
    are appended to it; if `literals` is, the spans of every literal both
    readings agree on: strings of any kind (f-strings, templates) and regex
    literals. jsx=False: a .ts file (no JSX reading)."""
    lang = lang if lang in ("py", "js", "sql") else None
    if lang is None or (lang == "js" and not jsx):
        return _lex_pass(content, lang, strings, literals=literals)
    sa = None if strings is None else []
    sb = None if strings is None else []
    la = None if literals is None else []
    lb = None if literals is None else []
    a = _lex_pass(content, lang, sa, literals=la)
    b = (_lex_js_jsx(content, sb, lb) if lang == "js"
         else _lex_pass(content, lang, sb, second=True, literals=lb))
    if strings is not None:
        strings.extend(_intersect_spans(sa, sb))
    if literals is not None:
        literals.extend(_intersect_spans(la, lb))
    return _intersect_spans(a, b)


def _lex_pass(content, lang, strings=None, second=False, literals=None):
    """One reading of `content`: the lexer above, or with `second` the other
    reading of Python (PEP 701 f-strings) or SQL (MySQL)."""
    mysql = second and lang == "sql"
    nxt = _LEX_MYSQL_NEXT if mysql else _LEX_NEXT[lang]
    fstrings = second and lang == "py"
    spans = []
    n = len(content)
    pos = 0
    prev, tail = "", ""        # js: last significant code char / trailing code text
    no_regex_until = -1        # js: a regex literal failed to close before here
    while pos < n:
        m = nxt.search(content, pos)
        if m is None:
            break
        k = m.start()
        if lang == "js" and k > pos:
            seg = content[pos:k].rstrip()
            if seg:
                prev, tail = seg[-1], seg[-11:]
        ch = content[k]
        two = content[k:k + 2]
        if ((ch == "#" and lang in ("py", None)) or (two == "//" and lang in ("js", None))
                or (two == "--" and lang == "sql")):
            e = content.find("\n", k)
            e = n if e < 0 else e
            spans.append((k, e))
            pos = e
            continue
        if two == "/*" and lang != "py":
            if mysql and (content.startswith("!", k + 2) or content.startswith("M!", k + 2)):
                pos = k + 2                # MySQL executes /*! … */: its text is code
                continue
            e = content.find("*/", k + 2)
            e = n if e < 0 else e + 2
            spans.append((k, e))
            pos = e
            continue
        if ch == "/":                      # js only: regex literal or division
            if k >= no_regex_until and _js_regex_allowed(prev, tail):
                rm = _JS_REGEX_LIT_RE.match(content, k)
                if rm:
                    pos = rm.end()
                    prev, tail = '"', ""
                    if literals is not None:
                        literals.append((k, pos))
                    continue
                # no closing '/' on this line: the rest of the line holds no
                # regex literal either (one failed attempt per line keeps the
                # lexer linear on input like "=/[" repeated)
                no_regex_until = content.find("\n", k)
                no_regex_until = n if no_regex_until < 0 else no_regex_until
            pos = k + 1
            prev, tail = "/", "/"
            continue
        fstring, raw = _py_fstring_prefix(content, k) if fstrings else (False, False)
        if fstring:
            pos = _py_fstring_end(content, k, raw)
            if literals is not None:
                literals.append((k, pos))
            continue
        if mysql:
            sm = _LEX_MYSQL_STR[ch].match(content, k)
        else:
            key = ch * 3 if lang == "py" and content.startswith(ch * 3, k) else ch
            sm = _LEX_STR[(lang, key)].match(content, k)
        pos = max(sm.end() if sm else k + 1, k + 1)
        prev, tail = '"', ""
        if strings is not None and ch != "`":
            strings.append((k, pos))
        if literals is not None:
            literals.append((k, pos))
    return spans


# ---- Python f-strings as 3.12+ reads them (PEP 701) ----
_PY_FSTRING_PREFIXES = frozenset(("f", "fr", "rf", "t", "tr", "rt"))
_FSTR_TEXT_STOP = {q: re.compile("[{}\\\\\n" + q + "]") for q in ("'", '"')}
_FSTR_FIELD_STOP = re.compile(r"[#'\"(){}\[\]:]")


def _py_name_char(ch):
    """A character that may continue a Python name, for prefix purposes:
    ASCII letters, digits and '_', and every non-ASCII character."""
    return ch == "_" or not ch.isascii() or ch.isalnum()


def _py_fstring_prefix(s, k):
    """(is an f-/t-string, raw) for the string literal whose quote is at
    s[k]: the name characters right before the quote must be exactly a
    prefix (`if"x"` is a keyword and a plain string)."""
    j = k
    while j > 0 and k - j <= 2 and _py_name_char(s[j - 1]):
        j -= 1
    if k - j > 2 or (j > 0 and _py_name_char(s[j - 1])):
        return False, False
    p = s[j:k].lower()
    return p in _PY_FSTRING_PREFIXES, "r" in p


def _py_fstring_end(s, k, raw):
    """Index just past the f-string whose opening quote is at s[k], as the
    3.12+ tokenizer reads it: its replacement fields are code (strings in
    any quotes, comments, newlines, nested f-strings), a format spec ends at
    '}' or at the f-string's own closing quote, `{{` `}}` are text, a
    backslash hides the next character but not a brace, and `\\N{…}` is one
    escape. A single-quoted f-string also ends, unterminated, at a newline
    in its text; len(s) when nothing ends it."""
    n = len(s)
    q = s[k]
    ql = 3 if s.startswith(q * 3, k) else 1
    # frames: ["S", quote, qlen, raw] the text of an f-string; ["P", …] a
    # format spec (with its f-string's quote); ["F", depth, quote, qlen,
    # raw] a replacement field's code, depth counting ( [ {
    stack = [["S", q, ql, raw]]
    i = k + ql
    named = False                      # after \N{: the next '}' ends that escape
    while stack:
        fr = stack[-1]
        if fr[0] != "F":
            q, ql, rw = fr[1], fr[2], fr[3]
            m = _FSTR_TEXT_STOP[q].search(s, i)
            if m is None:
                return n
            i = m.start()
            c = s[i]
            if c == q:
                if ql == 3 and not s.startswith(q * 3, i):
                    i += 1
                    continue
                i += ql
                while stack.pop()[0] != "S":        # its fields and specs end with it
                    pass
                named = False
            elif c == "\n":
                if fr[0] == "P":
                    stack.pop()                     # a newline ends a format spec
                elif ql == 1:                       # unterminated: ends at the newline
                    while stack.pop()[0] != "S":
                        pass
                else:
                    i += 1
                named = False
            elif c == "\\":
                nx = s[i + 1:i + 2]
                if nx == "{" or nx == "}":
                    i += 1                          # the brace is read on its own
                elif not rw and nx == "N" and s.startswith("{", i + 2):
                    i += 3
                    named = True
                else:
                    i += 2
            elif c == "{":
                if fr[0] == "S" and s.startswith("{", i + 1):
                    i += 2                          # '{{'
                else:
                    stack.append(["F", 0, q, ql, rw])
                    i += 1
                named = False
            elif named:                             # '}' closing \N{…}
                named = False
                i += 1
            elif fr[0] == "P":
                stack.pop()                         # the field reads this '}'
            else:                                   # '}}', or a stray '}'
                i += 2 if s.startswith("}", i + 1) else 1
            continue
        m = _FSTR_FIELD_STOP.search(s, i)
        if m is None:
            return n
        i = m.start()
        c = s[i]
        if c == "#":                                # a comment: to end of line
            e = s.find("\n", i)
            if e < 0:
                return n
            i = e
        elif c == "'" or c == '"':
            is_f, sraw = _py_fstring_prefix(s, i)
            ql = 3 if s.startswith(c * 3, i) else 1
            if is_f:
                stack.append(["S", c, ql, sraw])
                i += ql
            else:
                sm = _LEX_STR[("py", c * ql)].match(s, i)
                i = max(sm.end() if sm else i + 1, i + 1)
        elif c in "([{":
            fr[1] += 1
            i += 1
        elif c == ")" or c == "]":
            fr[1] = max(fr[1] - 1, 0)
            i += 1
        elif c == "}":
            i += 1
            if fr[1]:
                fr[1] -= 1
            else:
                stack.pop()                         # the field ends
        else:                                       # ':'
            if not fr[1]:
                stack.append(["P", fr[2], fr[3], fr[4]])
            i += 1
    return i


# ---- JavaScript read as JSX ----
_JSX_JS_NEXT = re.compile(r"[/'\"`{}<]")
_JSX_FILE_NEXT = re.compile(r"[/'\"`<]")       # the file's own code: its braces need no count
_JSX_TEXT_NEXT = re.compile(r"[{}<>]")
_JSX_WS_RE = re.compile(r"[ \t\n\r\f\v]*")
_JSX_NAME_RE = re.compile(r"[A-Za-z0-9_$.:\-\x80-\U0010ffff]*")
_JSX_KEYWORDS = _JS_REGEX_KEYWORDS | {"default"}


def _jsx_name_start(ch):
    return ch.isascii() and (ch.isalpha() or ch in "_$") or not ch.isascii()


def _jsx_tag_at(s, j):
    """Where the tag name (or the '>' of a fragment) starts when a '<' ends
    just before s[j], else -1."""
    j = _JSX_WS_RE.match(s, j).end()
    if j < len(s) and (s[j] == ">" or _jsx_name_start(s[j])):
        return j
    return -1


def _lex_js_jsx(content, strings=None, literals=None):
    """JavaScript comment spans in the JSX reading (see the lexer notes):
    the base lexer, plus elements, whose text and attribute strings hold
    no comments and whose `{…}` hold code again."""
    spans = []
    n = len(content)
    pos = 0
    prev, tail = "", ""
    no_regex_until = -1
    # frames: ["js", depth] code (the bottom frame is the file, the others a
    # `{…}` inside JSX, depth counting its own braces); ["tag"] an opening
    # tag's attributes; ["text"] an element's children
    stack = [["js", 0]]

    def element_done():
        nonlocal prev, tail
        if stack[-1][0] == "js":
            prev, tail = '"', ""

    while pos < n:
        fr = stack[-1]
        kind = fr[0]
        if kind == "js":
            m = (_JSX_JS_NEXT if len(stack) > 1 else _JSX_FILE_NEXT).search(content, pos)
            if m is None:
                break
            k = m.start()
            if k > pos:
                seg = content[pos:k].rstrip()
                if seg:
                    prev, tail = seg[-1], seg[-11:]
            ch = content[k]
            two = content[k:k + 2]
            if two == "//":
                e = content.find("\n", k)
                e = n if e < 0 else e
                spans.append((k, e))
                pos = e
            elif two == "/*":
                e = content.find("*/", k + 2)
                e = n if e < 0 else e + 2
                spans.append((k, e))
                pos = e
            elif ch == "/":
                pos = k + 1
                if k >= no_regex_until and _js_regex_allowed(prev, tail):
                    rm = _JS_REGEX_LIT_RE.match(content, k)
                    if rm:
                        pos = rm.end()
                        prev, tail = '"', ""
                        if literals is not None:
                            literals.append((k, pos))
                        continue
                    no_regex_until = content.find("\n", k)
                    no_regex_until = n if no_regex_until < 0 else no_regex_until
                prev, tail = "/", "/"
            elif ch == "{":
                fr[1] += 1
                pos = k + 1
                prev, tail = "{", "{"
            elif ch == "}":
                pos = k + 1
                if fr[1]:
                    fr[1] -= 1
                elif len(stack) > 1:
                    stack.pop()                     # a `{…}` inside JSX ends
                    continue
                prev, tail = "}", "}"
            elif ch == "<":
                t = -1
                if prev in (")", "]") or _js_regex_allowed(prev, tail, _JSX_KEYWORDS):
                    t = _jsx_tag_at(content, k + 1)
                if t >= 0:
                    stack.append(["tag"])
                    pos = _JSX_NAME_RE.match(content, t).end()
                else:
                    pos = k + 1
                    prev, tail = "<", "<"
            else:                                   # a string or template literal
                sm = _LEX_STR[("js", ch)].match(content, k)
                pos = max(sm.end() if sm else k + 1, k + 1)
                prev, tail = '"', ""
                if strings is not None and ch != "`":
                    strings.append((k, pos))
                if literals is not None:
                    literals.append((k, pos))
            continue
        if kind == "tag":
            j = _JSX_WS_RE.match(content, pos).end()
            if j >= n:
                break
            c = content[j]
            two = content[j:j + 2]
            if two == "/>":
                stack.pop()
                pos = j + 2
                element_done()
                continue
            if c == ">":
                stack[-1] = ["text"]
                pos = j + 1
                continue
            if two == "//" or two == "/*":          # comments may sit between attributes
                e = content.find("\n" if two == "//" else "*/", j + 2)
                e = n if e < 0 else (e if two == "//" else e + 2)
                spans.append((j, e))
                pos = e
                continue
            if c == "{":
                stack.append(["js", 0])
                pos = j + 1
                prev, tail = "{", "{"
                continue
            if c == '"' or c == "'":                # no escapes in JSX attribute strings
                e = content.find(c, j + 1)
                e = n if e < 0 else e + 1
                if strings is not None:
                    strings.append((j, e))
                if literals is not None:
                    literals.append((j, e))
                pos = e
                continue
            if c == "=":
                pos = j + 1
                continue
            if _jsx_name_start(c):
                pos = _JSX_NAME_RE.match(content, j).end()
                continue
            t = _jsx_tag_at(content, j + 1) if c == "<" else -1
            if t >= 0:                              # an element as an attribute value
                stack.append(["tag"])
                pos = _JSX_NAME_RE.match(content, t).end()
                continue
            abort = j
        else:                                       # element text
            m = _JSX_TEXT_NEXT.search(content, pos)
            if m is None:
                break
            k = m.start()
            c = content[k]
            if c == "{":
                stack.append(["js", 0])
                pos = k + 1
                prev, tail = "{", "{"
                continue
            if c == "<":
                j = _JSX_WS_RE.match(content, k + 1).end()
                if content.startswith("/", j):      # a closing tag
                    j = _JSX_WS_RE.match(content, j + 1).end()
                    j = _JSX_NAME_RE.match(content, j).end()
                    j = _JSX_WS_RE.match(content, j).end()
                    if content.startswith(">", j):
                        stack.pop()
                        pos = j + 1
                        element_done()
                        continue
                else:
                    t = _jsx_tag_at(content, k + 1)
                    if t >= 0:
                        stack.append(["tag"])
                        pos = _JSX_NAME_RE.match(content, t).end()
                        continue
            abort = k
        # not JSX after all: back to the code around it, from this character
        while stack[-1][0] != "js":
            stack.pop()
        pos = abort
        prev, tail = "<", "<"
    return spans


def _line_starts(content):
    return [0] + [m.end() for m in re.finditer("\n", content)]


def _comment_spans(content, lang, strings=None, jsx=True, literals=None):
    return _lex_comment_spans(content, lang, strings, jsx, literals)


def _cut_spans(line, spans):
    """`line` without the text of `spans` (sorted, disjoint, relative to it)."""
    if not spans:
        return line
    parts, p = [], 0
    for a, b in spans:
        parts.append(line[p:a])
        p = b
    parts.append(line[p:])
    return "".join(parts)


def _comment_layout(content, lines, lang, strings=None, jsx=True, literals=None):
    """(mask, spans, code) for the lines of `content`:
    mask[i]  — line i is a comment line (has non-whitespace, all of it in comments);
    spans    — {i: [(start, end), …]} comment spans relative to line i;
    code     — line i with its comment text removed (strings kept).
    jsx=False: JavaScript without the JSX reading (a .ts file). `strings`,
    `literals`: lists the lexer's literal spans are appended to (see
    _lex_comment_spans)."""
    n = len(lines)
    mask = [False] * n
    by_line = {}
    spans = _comment_spans(content, lang, strings, jsx, literals)
    if not spans:
        return mask, by_line, lines
    starts = _line_starts(content)
    for s, e in spans:
        i = bisect.bisect_right(starts, s) - 1
        while i < n:
            ls = starts[i]
            le = ls + len(lines[i])
            a, b = max(s, ls) - ls, min(e, le) - ls
            if b > a:
                by_line.setdefault(i, []).append((a, b))
            if e <= le + 1:
                break
            i += 1
    code = list(lines)
    for i, sp in by_line.items():
        line = lines[i]
        parts, p = [], 0
        for a, b in sp:
            parts.append(line[p:a])
            p = b
        parts.append(line[p:])
        c = "".join(parts)
        code[i] = c
        mask[i] = not c.strip() and bool(line.strip())
    return mask, by_line, code


def comment_mask(lines, lang, jsx=True):
    """Per-line booleans: True for a comment line of this file (comment state
    carried across lines — see the lexer notes above). jsx=False for a .ts
    file (see jsx_reading)."""
    return _comment_layout("\n".join(lines), lines, lang, jsx=jsx)[0]


def jsx_reading(path):
    """Is a JavaScript-family file also read as JSX? Every one but .ts, .mts
    and .cts: TypeScript parses no JSX there (`<T>x` is a type assertion)."""
    return not str(path).lower().endswith((".ts", ".mts", ".cts"))


def is_comment(line, lang):
    """Single-line form of comment_mask() for callers without file context:
    the line is lexed on its own (no block comment or template open at its
    start). A ` * foo` line is therefore NOT a comment here — only
    comment_mask() over the whole file knows a block comment is open."""
    t = line.strip()
    if not t:
        return False
    if lang == "py":
        return t.startswith("#")
    return comment_mask([line], lang)[0]


def source_lines(content, lang):
    """content -> lines exactly as scan_file numbers them: CRLF/CR are
    normalized to LF, and for JavaScript U+2028/U+2029 (ECMAScript line
    terminators) also end a line."""
    content = normalize_newlines(content)
    if lang == "js" and ("\u2028" in content or "\u2029" in content):
        content = content.replace("\u2028", "\n").replace("\u2029", "\n")
    return content.split("\n")


# ---------------- Match text (review fix: shared semantics 5) ----------------
# Rules match each line in the form the language runtime reads it, so
# Unicode spellings of the same code cannot slip past ASCII patterns:
#   py : a line containing non-ASCII is matched in its NFKC-normalized form —
#        Python NFKC-normalizes identifiers, so `ｅｘｅｃ(…)` and
#        `os.ｓｙｓｔｅｍ(…)` run as exec / os.system;
#   js : identifier escapes \uXXXX and \u{X…} outside '…'/"…" string
#        literals are decoded when they denote an identifier character
#        (`\u0065val(` is eval), and U+FEFF — JavaScript whitespace that
#        Python's \s does not match — becomes a space (`eval\ufeff(`).
# Line numbers never change; snippets still show the original text.
_JS_UESC_RE = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})")


#: Identifier characters since Unicode 15.1 only (ZWNJ, ZWJ and the two
#: katakana middle dots): Python 3.13+ and current Node say so, 3.10-3.12 not.
_LATER_ID_CONTINUE = frozenset((0x200C, 0x200D, 0x30FB, 0xFF65))


def _js_ident_char(m):
    """The identifier character a JS \\u escape denotes, else None: the same
    on every Python and Node (Unicode 13.0's characters, see _unicode13)."""
    cp = int(m.group(1) or m.group(2), 16)
    if cp > 0x10FFFF:
        return None
    ch = chr(cp)
    if ch == "$" or cp in _LATER_ID_CONTINUE:
        return ch
    return ch if _unicode13.assigned(cp) and ("a" + ch).isidentifier() else None


def _py_match_text(text):
    return text if text.isascii() else unicodedata.normalize("NFKC", text)


class _ScanBudgetExceeded(Exception):
    """Raised inside scan_file when the per-file time budget is spent."""


_TLS = threading.local()      # the scan_file context active on this thread


class _Redactor:
    """One file's redaction facts, shared by every snippet built from its
    lines: the lines of its PEM private-key blocks, its entropy literals
    (_SecretLiterals) and each line as any snippet may show it. scan_file's
    context is one; encoding_issues and redact_file_issues build their own,
    so a finding made outside scan_file redacts the file's secrets too."""

    def __init__(self, lines):
        self.lines = lines
        self._red = {}
        self._pem = None
        self._secrets = None

    def secrets(self):
        """This file's entropy-flagged literals (see _SecretLiterals)."""
        if self._secrets is None:
            self._secrets = _SecretLiterals(self.lines)
        return self._secrets

    def redacted(self, k):
        """Line k as any snippet may show it: whole-line [redacted] inside a
        PEM key block, else with secret patterns and this file's entropy
        literals replaced. Computed once per line, not once per finding
        whose snippet shows it (review: 3000 findings on one 45 KB line
        re-ran the redaction 15000 times)."""
        r = self._red.get(k)
        if r is None:
            if self._pem is None:
                self._pem = _pem_block_lines(self.lines)
            if k in self._pem:
                r = REDACTED
            else:
                r = self.secrets().redact(_redact_context_line(self.lines[k]))
            self._red[k] = r
        return r


class _FileCtx(_Redactor):
    """Per-file facts computed once and shared by every rule, the suppression
    check and mk_issue: the comment layout, the normalized match text of each
    line, parsed suppression markers and the redaction caches."""

    def __init__(self, lines, lang, content=None, deadline=None, jsx=True):
        super().__init__(lines)
        self.lang = lang
        self.content = "\n".join(lines) if content is None else content
        self._strings = [] if lang == "js" else None      # '…' "…" spans (absolute)
        self._literals = [] if lang in ("js", "py") else None   # every literal's span (absolute)
        self.cmask, self.cspans, self.code = _comment_layout(
            self.content, lines, lang, self._strings, jsx, self._literals)
        self.deadline = deadline
        self._markers = {}
        self._mlines = None
        self._mcode = {}
        self._starts = None
        self._str_starts = None
        self._lit_ends = None

    @property
    def mlines(self):
        """The text each line is matched in (see "Match text" above)."""
        if self._mlines is None:
            if self.lang == "py":
                self._mlines = [_py_match_text(l) for l in self.lines]
            elif self.lang == "js":
                self._mlines = [self._js_text(i, False) for i in range(len(self.lines))]
            else:
                self._mlines = self.lines
        return self._mlines

    def mcode(self, i):
        """Match text of line i with its comment text removed."""
        if self.code is self.lines:
            return self.mlines[i]
        v = self._mcode.get(i)
        if v is None:
            if self.lang == "py":
                v = _py_match_text(self.code[i])
            elif self.lang == "js":
                v = self._js_text(i, True)
            else:
                v = self.code[i]
            self._mcode[i] = v
        return v

    def names_code(self, i):
        """Line i as names are read in it (SC-HOMOGLYPH): its match text
        with its comments removed and every literal blanked, by the spans
        both readings of the file agree on: strings of any kind (a template
        or f-string with its fields), regex literals. So a regex's
        escapes are not decoded into names (ajv's /http[s\\u017F]?/), a
        character class like [a-z\\u0430-\\u044f] and a docstring's lines are
        not names, and a quote escaped in a string ends nothing."""
        line = self.lines[i]
        if self._literals is None:
            return self.mcode(i)
        if self._starts is None:
            self._starts = _line_starts(self.content)
        if self._lit_ends is None:
            self._lit_ends = [e for _, e in self._literals]
        base = self._starts[i]
        end = base + len(line)
        k = bisect.bisect_right(self._lit_ends, base)       # the first literal ending after base
        parts, p = [], 0
        while k < len(self._literals) and self._literals[k][0] < end:
            a, b = max(self._literals[k][0], base) - base, min(self._literals[k][1], end) - base
            parts.append(line[p:a])
            parts.append(" " * (b - a))
            p = b
            k += 1
        if not parts:
            return self.mcode(i)
        parts.append(line[p:])
        blanked = "".join(parts)
        if self.lang == "js":
            return self._js_text(i, True, blanked)
        return _py_match_text(_cut_spans(blanked, self.cspans.get(i, ())))

    def _js_text(self, i, drop_comments, line=None):
        """Line i's match text; `line`: line i with some of its text blanked
        (the same length) to read instead."""
        if line is None:
            line = self.lines[i]
            plain = self.code[i] if drop_comments else line
        else:
            plain = _cut_spans(line, self.cspans.get(i, ())) if drop_comments else line
        if "\\u" not in line:
            return plain.replace("\ufeff", " ") if "\ufeff" in plain else plain
        if self._starts is None:
            self._starts = _line_starts(self.content)
        if self._str_starts is None:
            self._str_starts = [a for a, _ in self._strings]
        base = self._starts[i]
        cuts = list(self.cspans.get(i, ())) if drop_comments else []
        edits = [(a, b, "") for a, b in cuts]
        c, ncuts = 0, len(cuts)             # cuts are sorted: one moving index
        for m in _JS_UESC_RE.finditer(line):
            while c < ncuts and cuts[c][1] <= m.start():
                c += 1
            if c < ncuts and cuts[c][0] <= m.start():
                continue
            k = bisect.bisect_right(self._str_starts, base + m.start()) - 1
            if k >= 0 and self._strings[k][1] > base + m.start():
                continue                          # inside a '…' or "…" literal
            ch = _js_ident_char(m)
            if ch is not None:
                edits.append((m.start(), m.end(), ch))
        if not edits:
            out = plain
        else:
            edits.sort()
            parts, p = [], 0
            for a, b, rep_ in edits:
                if a < p:
                    continue
                parts.append(line[p:a])
                parts.append(rep_)
                p = b
            parts.append(line[p:])
            out = "".join(parts)
        return out.replace("\ufeff", " ") if "\ufeff" in out else out

    def marker(self, k):
        """Parsed suppression marker of line k: _NO_MARKER, None (blanket)
        or a frozenset of rule IDs. Parsed once per line."""
        v = self._markers.get(k, self)
        if v is self:
            m = _find_marker(self.lines[k], self.cspans.get(k))
            v = _NO_MARKER if m is None else _marker_rules(m)
            self._markers[k] = v
        return v

    def suppressed(self, issue, dep=False):
        if dep or str(issue.get("rule", "")).startswith(UNSUPPRESSIBLE_PREFIXES):
            return False
        return _suppressed_in(issue, self)

    def check_time(self):
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise _ScanBudgetExceeded()


def _active_ctx(lines):
    ctx = getattr(_TLS, "ctx", None)
    return ctx if ctx is not None and ctx.lines is lines else None

# Line-level matchers for redacting credentials that appear on CONTEXT lines
# of a snippet (audit L1: a finding's ±2-line context can carry a DIFFERENT
# secret than the one flagged — e.g. an S-SECRET at line 3 whose context
# window includes the AWS key at line 4). Secret rules whose regex has no
# "skip" noise filter run raw; S-SECRET re-uses its own assignment regex so
# the same detection contract applies on context lines.
_SECRET_LINE_PATTERNS = [
    # provider token formats (S-TOKEN's list, plus fine-grained github_pat_);
    # a PEM private-key header is redacted through its END marker or, when
    # the key continues on later lines, to end of line (see _pem_block_lines).
    # Linear-time matcher, text in _TOKEN_REDACT_ALTS (see _TokenPattern).
    _TOKEN_REDACT_PATTERN,
    # SQL credentials — case-insensitive like the SQL-CRED rule (review fix:
    # lowercase `identified by '…'` leaked through other findings' context)
    re.compile(r"(?:IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]|PASSWORD\s*=?\s*['\"][^'\"]+['\"]"
               r"|IDENTIFIED\s+BY\s+PASSWORD)", re.I),
    re.compile(r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
               r"private[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']", re.I),
    # credentials in a URL's userinfo: scheme://user:password@host, scheme://token@host
    re.compile(r"(?<=://)[^/\s@'\"]+(?=@)"),
]
REDACTED = "[redacted]"
_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def _redact_context_line(line):
    """Replace every credential-looking match on a context line with
    [redacted], preserving surrounding code. Returns the new line, or the
    original line if nothing matched."""
    out = line
    for pat in _SECRET_LINE_PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


def _pem_block_lines(lines):
    """Indices of the lines of multi-line PEM private keys that follow the
    BEGIN line, through the END line — or through the last line when no END
    follows (review fix: an S-TOKEN on `-----BEGIN RSA PRIVATE KEY-----`
    redacted the header while the next two key lines shipped in its
    snippet). Such lines are redacted whole; the BEGIN line itself is
    handled by the pattern list."""
    out = set()
    inside = False
    for k, line in enumerate(lines):
        if not isinstance(line, str):
            continue
        if inside:
            out.add(k)
            if "-----END" in line and _PEM_END_RE.search(line):
                inside = False
        elif "PRIVATE KEY-----" in line:
            m = _PEM_BEGIN_RE.search(line)
            inside = bool(m) and not _PEM_END_RE.search(line, m.end())
    return out


_SECRET_RUN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


class _SecretLiterals:
    """The high-entropy literals S-ENTROPY would flag in one file, redacted
    as substrings wherever they appear (review fix: a literal redacted in its
    own S-ENTROPY finding shipped raw in a neighbouring finding's snippet).
    Candidates are the literals ENTROPY_VALUE_RE finds on any line not
    matching SECRET_SKIP_RE, comment lines included, that pass
    entropy_secretish()."""

    def __init__(self, lines):
        self.lits = set()
        for line in lines:
            if not isinstance(line, str) or ("=" not in line and ":" not in line):
                continue
            if SECRET_SKIP_RE.search(line):
                continue
            for m in ENTROPY_VALUE_RE.finditer(line):
                if entropy_secretish(m.group(1)):
                    self.lits.add(m.group(1))
        self.by_prefix = {}
        for lit in self.lits:
            self.by_prefix.setdefault(lit[:20], []).append(lit)

    def redact(self, text):
        if not self.lits or not isinstance(text, str):
            return text
        hits = []
        for m in _SECRET_RUN_RE.finditer(text):
            run, base = m.group(), m.start()
            if run in self.lits:
                hits.append((base, m.end()))
                continue
            for p in range(len(run) - 19):
                for lit in self.by_prefix.get(run[p:p + 20], ()):
                    if run.startswith(lit, p):
                        hits.append((base + p, base + p + len(lit)))
        if not hits:
            return text
        hits.sort()
        parts, pos = [], 0
        for a, b in hits:
            if b <= pos:
                continue
            parts.append(text[pos:max(a, pos)])
            parts.append(REDACTED)
            pos = b
        parts.append(text[pos:])
        return "".join(parts)


def _redact_lines(lines, secrets=None):
    """Redacted copies of a list of lines: PEM blocks whole, then the
    pattern list and the file's entropy literals."""
    pem = _pem_block_lines(lines)
    out = []
    for k, l in enumerate(lines):
        if not isinstance(l, str):
            out.append(l)
        elif k in pem:
            out.append(REDACTED)
        else:
            l = _redact_context_line(l)
            out.append(secrets.redact(l) if secrets is not None else l)
    return out


def _redact_text(text, secrets=None):
    """Redaction for free text that may copy source (issue msg, hook cmd)."""
    if not isinstance(text, str):
        return text
    if "\n" in text:
        return "\n".join(_redact_lines(text.split("\n"), secrets))
    text = _redact_context_line(text)
    return secrets.redact(text) if secrets is not None else text


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
       readable. Lines of a PEM key block that starts in the snippet are
       redacted whole.
    """
    out = _redact_lines(snippet)
    if 0 <= flagged_idx < len(out):
        out[flagged_idx] = (REDACT_PLACEHOLDER.replace("{RULE}", rid)
                            + f" ({len(raw_line)} chars)")
    return out


# ---------------- Hex-escape decoding (SC-HEXSTR) ----------------
# Obfuscation means escaping characters that did not need it: "\x65\x76\x61\x6c"
# spells "eval". Binary data (NUL bytes, byte-order marks, UTF-8 sequences,
# protocol bytes) legitimately *needs* escapes and is never flagged.
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
HEX_MIN_ESCAPES = 8
HEX_PRINTABLE_SHARE = 0.75
_LETTER_RUN_RE = re.compile(r"[A-Za-z]{3}")
HIDDEN_TEXT_DANGER_RE = re.compile(
    r"https?://|\b(?:eval|exec|execSync|compile|__import__|import|require|child_process|"
    r"subprocess|system|popen|spawn|powershell|cmd\.exe|curl|wget|base64|b64decode|atob|"
    r"Function|fromCharCode|marshal|pickle)\b|/bin/(?:ba)?sh", re.I)


def hex_hidden_text(line):
    r"""The readable text hidden in a line's \xNN escapes, or None when the
    escapes encode binary data (or there are too few to matter)."""
    codes = [int(h, 16) for h in _HEX_ESCAPE_RE.findall(line)]
    if len(codes) < HEX_MIN_ESCAPES:
        return None
    printable = [c for c in codes if 0x20 <= c < 0x7F]
    if len(printable) / len(codes) < HEX_PRINTABLE_SHARE:
        return None
    text = "".join(map(chr, printable))
    # Readable means words: palette bytes and punctuation tables that happen to
    # fall in the printable range ("-95479:37", "!$*-:=?[]") are data.
    letters = sum(ch.isalpha() for ch in text)
    if not _LETTER_RUN_RE.search(text) or letters / len(text) < 0.4:
        return None
    return text


# Fewer escapes than HEX_MIN_ESCAPES still hide a name when the name is the
# point (analyst gap): global["\x72\x65\x71\x75\x69\x72\x65"]("child_process")
# spells require in 7 escapes, "\x65val" eval in one. Nothing needs to escape
# a letter, digit or "_" of such a name, so a string literal in which a
# dangerous name (HIDDEN_TEXT_DANGER_RE) has one of those written as an
# escape — \xNN, \uNNNN, \u{N…}, \UNNNNNNNN or a three-digit octal escape of a
# printable ASCII character — is SC-HEXSTR, CRITICAL, whatever the count.
# Punctuation escapes do not count (serializers write "/" as \u002F:
# "https:\u002F\u002F…" hides no URL), a literal whose escapes are mostly
# binary data is data (b"\x00\x04\x65xec" is a packet), and an escape after
# an odd run of backslashes is an escaped backslash and text.
_NAME_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|U([0-9A-Fa-f]{8})|([0-7]{3}))")


def hex_hidden_name(line):
    r"""(name, column) for the first string literal on this line whose
    escape sequences spell part of a dangerous name ("\x65val",
    global["\x72\x65\x71…"]), else None: the name as decoded, and the
    column of its first escaped letter, digit or "_"."""
    if "\\" not in line:
        return None
    for lit in STRING_LIT_RE.finditer(line):
        if "\\" in lit.group():
            found = _hidden_name_in(lit.group()[1:-1], lit.start() + 1)
            if found is not None:
                return found
    return None


def _hidden_name_in(seg, offset):
    pieces, esc_at, esc_col = [], [], []
    pos = size = total = printable = 0
    for m in _NAME_ESCAPE_RE.finditer(seg):
        start = run = m.start()
        while run > 0 and seg[run - 1] == "\\":
            run -= 1
        if (start - run) % 2:
            continue                        # "\\x65": an escaped backslash, then text
        total += 1
        digits = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        code = int(digits, 16) if digits is not None else int(m.group(5), 8)
        if code > 0x10FFFF:
            continue                        # no character: left as written
        ch = chr(code)
        pieces.append(seg[pos:start])
        size += start - pos
        if 0x20 <= code < 0x7F:
            printable += 1
            if ch.isalnum() or ch == "_":
                esc_at.append(size)
                esc_col.append(offset + start)
        pieces.append(ch)                   # every escape decoded: b"\x00\x65val" holds the word eval
        size += 1
        pos = m.end()
    if not esc_at or printable / total < HEX_PRINTABLE_SHARE:
        return None
    pieces.append(seg[pos:])
    text = "".join(pieces)
    for m in HIDDEN_TEXT_DANGER_RE.finditer(text):
        k = bisect.bisect_left(esc_at, m.start())
        if k < len(esc_at) and esc_at[k] < m.end():
            return m.group(), esc_col[k]
    return None


# ---------------- Look-alike identifiers (SC-HOMOGLYPH) ----------------
# A name spelled with letters from another alphabet that look like Latin ones
# reads as a name it is not (the homoglyph half of Trojan Source,
# CVE-2021-42694): `const \u0435val = eval; \u0435val(x)`, with a Cyrillic e
# (U+0435), calls eval where no reviewer sees eval called, and isAdm\u0456n
# (a Cyrillic i) is not isAdmin. _LOOKALIKES maps the letters drawn like a
# Latin letter in common fonts: Cyrillic, Greek capitals, omicron and lunate
# sigma, Armenian o and u, Latin alpha and script g. Not every confusable:
# Greek alpha, nu and rho, the variables of scientific code, are left out.
# JavaScript also takes NFKC's compatibility forms as names of their own
# (fullwidth \uff45val is not eval there; Python reads it as eval) and allows
# the invisible U+200C / U+200D inside a name. A name whose skeleton
# (look-alikes mapped, invisibles dropped) is an ASCII name it is not is
# SC-HOMOGLYPH: CRITICAL when it reads as a code-execution or network name
# (_LOOKALIKE_TARGETS) or as another name in the file (three characters or
# more), MAJOR when it mixes ASCII letters with look-alikes. Anything else —
# a Cyrillic word — is left alone. Names are read where the lexer reads code
# (_FileCtx.names_code): not in comments, strings (a template or f-string
# whole, fields too) or regex literals, whose escapes are not names either:
# ajv's /http[s\u017F]?/ holds no name "s\u017f", nor a class like
# [a-zA-Z\u0430-\u044f] a name "Z\u0430". (This file writes every
# such character as an escape.)
_LOOKALIKES = dict(zip(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u04bb\u0501\u051b\u051d\u04cf"   # Cyrillic
    "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0405\u0406\u0408\u04ae\u051a\u051c\u04c0"
    "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u03dc"   # Greek
    "\u03bf\u03f2\u03f3"
    "\u0585\u057d"                                                                                  # Armenian
    "\u0251\u0261",                                                                                 # Latin (IPA)
    "aeopcyxsijhdqwl" "ABEKMHOPCTXSIJYQWI" "ABEZHIKMNOPTYXF" "ocj" "ou" "ag"))
_LOOKALIKE_TARGETS = frozenset((
    "eval", "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork", "Function",
    "require", "import", "__import__", "import_module", "compile", "system", "popen", "Popen",
    "check_output", "check_call", "getoutput", "child_process", "subprocess", "os", "vm",
    "runInThisContext", "runInNewContext", "runInContext", "atob", "b64decode", "fromCharCode",
    "globalThis", "window", "global", "process", "Buffer", "setTimeout", "setInterval", "getattr",
    "builtins", "__builtins__", "marshal", "pickle", "fetch", "urlopen", "socket"))
_NAME_RUN_RE = re.compile(r"[\w$\u200c\u200d]+")
_ASCII_WORD_RE = re.compile(r"[A-Za-z0-9_$]+")
_ASCII_LETTER_RE = re.compile(r"[A-Za-z]")
_INVISIBLE_IN_NAMES = frozenset("\u200c\u200d")


def lookalike_name(code, lang, words):
    """(name, reads_as, severity, other, detail, column) for the first name
    in `code` (a line as _FileCtx.names_code reads it: comments removed,
    literals blanked) that reads as an ASCII name it is not (see above),
    else None. `words()` gives the file's ASCII words; it is called only
    when a look-alike name is found."""
    if code.isascii():
        return None
    for m in _NAME_RUN_RE.finditer(code):
        name = m.group()
        if name.isascii() or (m.start() and code[m.start() - 1] == "\\"):
            continue                        # after an escape left as written (\uFF07 is no name)
        seen = unicodedata.normalize("NFKC", name) if lang == "js" else name
        skeleton = "".join(_LOOKALIKES.get(ch, ch) for ch in seen if ch not in _INVISIBLE_IN_NAMES)
        if not skeleton or skeleton == name or not skeleton.isascii() or skeleton[0].isdigit():
            continue
        if skeleton in _LOOKALIKE_TARGETS:
            severity, other = "CRITICAL", False
        elif len(skeleton) >= 3 and skeleton in words():
            severity, other = "CRITICAL", True
        elif _ASCII_LETTER_RE.search(name):
            severity, other = "MAJOR", False
        else:
            continue
        parts = []
        for ch in name:
            if ch.isascii():
                continue
            if ch in _INVISIBLE_IN_NAMES:
                part = f"an invisible U+{ord(ch):04X}"
            else:
                shown = unicodedata.normalize("NFKC", ch) if lang == "js" else ch
                part = f"U+{ord(ch):04X} for {''.join(_LOOKALIKES.get(c, c) for c in shown)!r}"
            if part not in parts:
                parts.append(part)
        return name, skeleton, severity, other, ", ".join(parts), m.start()
    return None


_LOOKALIKE_WHY = (
    "A name written with letters from another alphabet that look like Latin ones, or with an "
    "invisible character inside it, is not the name a reviewer reads: `const eval = eval` with "
    "a Cyrillic e (U+0435) makes a second eval that runs where no one sees eval called, and an "
    "isAdmin with a Cyrillic i is not isAdmin (CVE-2021-42694, the homoglyph half of Trojan "
    "Source).")


def lookalike_issue(found, path, line_no, lines):
    name, skeleton, severity, other, detail, col = found
    where = ", another name in this file," if other else ""
    return mk_issue(
        {"id": "SC-HOMOGLYPH", "name": "Look-alike identifier", "type": "HOTSPOT", "sev": severity,
         "msg": f"{name!r} reads as {skeleton!r}{where} but is spelled with {detail}.",
         "why": _LOOKALIKE_WHY,
         "fix": "Rename it with the letters it appears to have, and find out why it was written this way.",
         "ref": "CWE-1007 · CVE-2021-42694"}, path, line_no, lines, col)


# ---------------- Invisible-character payload (SC-HIDDEN-UNICODE) ----------------
# A run of invisible characters carries bytes no reviewer or diff can see:
# variation selectors (U+FE00-FE0F, U+E0100-E01EF) or tag characters
# (U+E0000-E007F). GlassWorm (Oct 2025, 150+ repos across npm and VS Code) hid
# its payload in variation selectors and decoded it with a codePointAt map into
# eval; tag characters smuggle instructions past a reviewer and an AI reading
# the file. The only ordinary runs are a flag emoji (a U+1F3F4 base, tag
# letters, the U+E007F terminator), left alone, and a lone emoji variation
# selector (U+FE0F), one character and below the run threshold. A run in a file
# that runs code from a string (eval, Function, exec) is CRITICAL (the GlassWorm
# shape), else MAJOR.
_HIDDEN_RUN_RE = re.compile("[\U0000FE00-\U0000FE0F\U000E0000-\U000E01EF]{2,}")
_FLAG_EMOJI_BASE = "\U0001F3F4"
_TAG_START = "\U000E0000"
_TAG_END = "\U000E007F"
_HIDDEN_EXEC_RE = re.compile(
    r"(?<![\w$.])(?:eval|Function|execSync|exec|runInThisContext|runInNewContext|runInContext)\s*\(")


def _hidden_flag_emoji(line, m):
    """The run m is a flag emoji's tag sequence (a U+1F3F4 base, tag letters,
    the U+E007F terminator): an ordinary run, left alone."""
    run = m.group()
    return (m.start() > 0 and line[m.start() - 1] == _FLAG_EMOJI_BASE
            and run.endswith(_TAG_END) and all(_TAG_START <= c <= _TAG_END for c in run))


def hidden_unicode_run(line):
    """(col, run) for the first run of invisible carrier characters in `line`
    that is not a flag emoji, else None."""
    for m in _HIDDEN_RUN_RE.finditer(line):
        if not _hidden_flag_emoji(line, m):
            return m.start(), m.group()
    return None


_HIDDEN_UNICODE_WHY = (
    "Invisible characters in source carry bytes that no review or diff shows: a variation selector or a "
    "tag character has no business in code. GlassWorm hid a payload in variation selectors and decoded it "
    "into eval; tag characters smuggle instructions past a reviewer and an AI reading the file. Only a flag "
    "emoji and a single emoji variation selector are ordinary.")


def _hidden_unicode_issue(path, line_no, lines, col, run, runs_code):
    tags = any(_TAG_START <= c <= _TAG_END for c in run)
    varsel = any(not (_TAG_START <= c <= _TAG_END) for c in run)
    what = ("variation selectors and tag characters" if tags and varsel
            else "tag characters" if tags else "variation selectors")
    return mk_issue(
        {"id": "SC-HIDDEN-UNICODE", "name": "Invisible-character payload", "type": "HOTSPOT",
         "sev": "CRITICAL" if runs_code else "MAJOR",
         "msg": f"A run of {len(run)} invisible {what} carries hidden data in the code"
                + (", and the file runs code from a string." if runs_code else "."),
         "why": _HIDDEN_UNICODE_WHY,
         "fix": "Show the characters as escape sequences and decode what they spell; if it is a payload, do not run the file.",
         "ref": "CWE-506 · Supply chain"}, path, line_no, lines, col)


_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _token_has_material(rule_re, line, lines, i):
    """A "-----BEGIN ... PRIVATE KEY-----" header alone is not a key: libraries
    keep the header as a constant to recognize key files. Require base64 key
    material after it, on the same line or the next two."""
    match = rule_re.search(line)
    if not match or not match.group(0).startswith("-----BEGIN"):
        return True
    following = [line[match.end():]] + lines[i + 1:i + 3]
    return any(_PEM_BODY_RE.search(text) for text in following)


# ---------------- Snippets (review fix: shared semantics 7) ----------------
# A finding used to copy its ±2 context lines whole: a 22.5 KB one-line file
# produced a 34 MB JSON and a 34 MB HTML report. Every snippet line is now
# clipped to SNIPPET_MAX characters. The flagged line is windowed around the
# match: the window starts SNIPPET_LEAD characters before the match column
# (never past the point where it would run off the end), and "…" marks each
# side that was cut. Other lines keep their start.
SNIPPET_MAX = 240
SNIPPET_LEAD = 60
ELLIPSIS = "\u2026"


def clip_snippet_line(text, col=None):
    """`text` clipped to at most SNIPPET_MAX characters (see above)."""
    if not isinstance(text, str) or len(text) <= SNIPPET_MAX:
        return text
    start = 0 if col is None else max(0, col - SNIPPET_LEAD)
    start = min(start, len(text) - (SNIPPET_MAX - 1))
    head = ELLIPSIS if start > 0 else ""
    end = start + SNIPPET_MAX - len(head)
    if end < len(text):
        return head + text[start:end - 1] + ELLIPSIS
    return head + text[start:]


def mk_issue(rule_or_dict, path, line_no, lines, col=None, redactor=None):
    """Issue dict for rule `rule_or_dict` at 1-based `line_no` of `lines`.
    `col` (0-based character offset of the match on the flagged line, if
    known) centres the flagged line's snippet window on the match.
    `redactor` (a _Redactor, or scan_gyp's _LineRedactor, over these same
    `lines`) supplies the file's entropy literals and PEM blocks and caches
    each redacted line for a producer of many findings in one file; by
    default the active scan_file context does, when it is scanning `lines`."""
    r = rule_or_dict
    start = max(0, line_no - 3)
    stop = min(len(lines), line_no + 2)
    flag = line_no - 1
    snippet = []
    # L1 (artifact hygiene): the flagged line of a SECRET-rule finding is
    # redacted at creation time, so EVERY sink — terminal excerpt, JSON/HTML
    # report, SARIF region, the registry Store blob — persists the
    # placeholder, never the credential. Previously only issue_excerpt()
    # (terminal) honored REDACT_SECRETS while reports shipped the raw line.
    # Additionally, ANY rule's ±2-line context window is swept for
    # secret-shaped substrings (a snippet around an os.system finding
    # routinely contains the file's actual credentials on adjacent lines).
    # Redaction runs on the whole line, before clipping, so a clip boundary
    # can never cut a secret into a no-longer-matching fragment.
    # The message is redacted too: some embed source text (an install hook's
    # command line, a hex-decoded preview) — review: a PAT in a `prepare`
    # script reached the terminal, JSON, HTML and SARIF through msg.
    msg = r["msg"]
    if redactor is None or redactor.lines is not lines:
        redactor = _active_ctx(lines)
    ctx = redactor if REDACT_SECRETS else None
    if REDACT_SECRETS:
        msg = _redact_text(msg, ctx.secrets() if ctx is not None else None)
    redact = REDACT_SECRETS and 0 <= flag < len(lines)
    pem = _pem_block_lines(lines) if redact and ctx is None else ()
    for k in range(start, stop):
        l = lines[k]
        if not isinstance(l, str):
            snippet.append(l)
            continue
        if redact:
            if k == flag and r["id"] in SECRET_RULES:
                l = REDACT_PLACEHOLDER.replace("{RULE}", r["id"]) + f" ({len(l)} chars)"
            elif ctx is not None:
                l = ctx.redacted(k)
            else:
                l = REDACTED if k in pem else _redact_context_line(l)
        snippet.append(clip_snippet_line(l, col if k == flag else None))
    return {"rule": r["id"], "name": r["name"], "type": r["type"], "sev": r["sev"],
            "msg": msg, "why": r["why"], "fix": r["fix"], "ref": r["ref"],
            "file": path, "line": line_no,
            "snippet": snippet,
            "snipStart": start + 1}


# ---------------- Per-file finding cap (review fix: shared semantics 7) ----------------
# Findings identical on (rule, file, line, msg) are reported ONCE (the first,
# i.e. leftmost, one is kept): they are indistinguishable in every report —
# same line, same snippet text. Then at most CAP_PER_RULE findings per (file,
# rule) are kept, in line order, for every rule that is not a security rule;
# the rest are replaced by ONE Q-CAPPED INFO finding per capped rule at the
# first omitted line, which carries how many it replaces ("omitted") and
# their type ("omittedType"; the maintainability rating counts them). Security
# findings (S-, T-, SC-, X-, SQL- rules) are never capped (but are
# deduplicated: distinct taint flows on one line keep their distinct
# messages). Review: the cap used to cover INFO/MINOR/SMELL
# rules only, so a 1.95 MB one-line `try{}catch(e){}` x 130k file gave 130,001
# MAJOR B-EMPTY-CATCH findings and an 87.7 MB JSON report (120k lines: 66.7 MB).
CAP_PER_RULE = 200
_NEVER_CAPPED_PREFIXES = ("S-", "T-", "SC-", "X-", "SQL-")


def _cappable(issue):
    return not str(issue.get("rule", "")).startswith(_NEVER_CAPPED_PREFIXES)


def dedupe_issues(issues):
    """`issues` without repeats of the same (rule, file, line, msg); the first
    of each is kept, order is preserved."""
    seen, out = set(), []
    for i in issues:
        key = (i.get("rule"), i.get("file"), i.get("line"), i.get("msg"))
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


def cap_issues(path, issues, lines):
    """`issues` (one file's findings) deduplicated, then with the per-rule cap
    applied (see above)."""
    issues = dedupe_issues(issues)
    counts, dropped, omitted = {}, set(), {}
    order = sorted(range(len(issues)), key=lambda k: issues[k].get("line", 0))
    for k in order:
        i = issues[k]
        if not _cappable(i):
            continue
        rid = i["rule"]
        counts[rid] = counts.get(rid, 0) + 1
        if counts[rid] > CAP_PER_RULE:
            dropped.add(k)
            o = omitted.setdefault(rid, [0, i["line"], i["type"]])
            o[0] += 1
    if not dropped:
        return issues
    out = [i for k, i in enumerate(issues) if k not in dropped]
    for rid, (n, first, typ) in omitted.items():
        note = mk_issue(
            {"id": "Q-CAPPED", "name": "Findings capped", "type": "SMELL", "sev": "INFO",
             "msg": f"{n} more {rid} findings omitted",
             "why": "Findings of one rule that repeat hundreds of times in one file are capped "
                    "so reports stay readable; security findings are never capped.",
             "fix": f"Fix or deliberately suppress the {rid} pattern in this file, then re-scan "
                    "to see the remaining occurrences.",
             "ref": "Maintainability"}, path, first, lines)
        # what the note stands for: the maintainability rating counts the
        # omitted findings, not the note (see maintainability_rating)
        note["omitted"] = n
        note["omittedType"] = typ
        out.append(note)
    return out


def extract_functions(lines, lang):
    fns = []
    if lang not in ("py", "js"):   # function/complexity metrics don't apply to SQL
        return fns
    if lang == "py":
        # A def ends at the first later line that is non-blank, not a
        # comment, and indented no deeper than the def. Review fix: that was
        # a forward scan per def — O(defs × lines) (300 nested defs over
        # 30 000 blank lines: 0.85 s, quadratic). One pass with a stack of
        # open defs gives the same spans; complexity is summed per line.
        cx_re = re.compile(r"\b(if|elif|for|while|and|or|except|case)\b")
        def_re = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)")
        cx_prefix = [0]
        for line in lines:
            cx_prefix.append(cx_prefix[-1] + len(cx_re.findall(line)))
        found = []                        # (line_i, name) in source order
        spans = {}                        # line_i -> end (exclusive)
        stack = []                        # (indent, line_i), indents increasing
        for k, l in enumerate(lines):
            m = def_re.match(l)
            t = l.strip()
            if t and not t.startswith("#"):
                ind = len(m.group(1)) if m else len(l) - len(l.lstrip())
                while stack and stack[-1][0] >= ind:
                    spans[stack.pop()[1]] = k
            if m:
                found.append((k, m.group(2)))
                stack.append((len(m.group(1)), k))
        for _ind, k in stack:
            spans[k] = len(lines)
        for i, name in found:
            end = spans[i]
            fns.append({"name": name, "line": i + 1, "len": end - i,
                        "cx": 1 + cx_prefix[end] - cx_prefix[i]})
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
        # Review fix: `(\w+)\s*\([^)]*\)\s*\{` restarted inside every \w run
        # and every unclosed '(' scan ran to the end of the line — O(n²): a
        # benign 32 KB hex literal took 12.7 s. The name must now start a
        # word run (?<!\w), parameter lists stop at the next '(' ([^()]*), and
        # only the first FN_HEADER_SCAN_LIMIT characters of a line are
        # searched for its (first) header.
        fn_re = re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?"
            r"(?:function|\([^()]*\)\s*=>|\w+\s*=>)|(?<!\w)(\w+)\s*\([^()]*\)\s*\{)")
        # headers: first match per line (old semantics)
        headers = []                      # (line_i, name)
        for i, line in enumerate(lines):
            m = fn_re.search(line, 0, FN_HEADER_SCAN_LIMIT)
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
# `(.+)$` + rstrip() in the caller: the old lazy `(.+?)\s*$` retried `\s*$`
# at every character of a long whitespace run (quadratic).
SQL_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(\+=|=)(?!=)\s*(.+)$")
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
        var, op, rhs = mm.group(1), mm.group(2), mm.group(3).rstrip()
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

#: Review fix (quadratic hot spot): per line, at most this many execute()
#: calls are analyzed and each argument string is cut to SQL_ARG_MAX chars.
#: '.execute(' * 4000 on one line took 3.3 s — every call re-scanned the rest
#: of the line for its closing paren and re-split it.
SQL_CALLS_PER_LINE = 64
SQL_ARG_MAX = 10000
_PAREN_TOKEN_RE = re.compile(r"[()\"']")


# SC-CHARCODE: String.fromCharCode building text from character codes that
# are written in the code: ten or more 2-3 digit numbers inside the call's
# own parentheses (`fromCharCode(104,116,116,112,…)`, also through .apply /
# .call), or a name the call uses that the same line assigns an array of ten
# or more printable-ASCII codes (`k=[104,116,…];…fromCharCode(...k)`). It
# used to count numbers anywhere on the line, so every fromCharCode on a long
# minified line fired: binary parsers (`fromCharCode(255&e)`,
# `fromCharCode(...u.subarray(0,l))`) and UTF-16 surrogate encoders
# (`fromCharCode(e>>>10&1023|55296)`); and any such array anywhere on the line
# (npm:extract-youtube's 98 KB line) counted for every call on it.
CHARCODE_NUM_RE = re.compile(r"\b\d{2,3}\b")
_CHARCODE_TABLE_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*\[((?:\s*[0-9]{2,3}\s*,){9,}\s*[0-9]{2,3})\s*\]")
# a bare name (not `o.k`; `...k` is a spread)
_CHARCODE_NAME_RE = re.compile(r"(?<![\w$])(?:(?<=\.\.\.)|(?<!\.))[A-Za-z_$][\w$]*")
_CHARCODE_CALL_TAIL_RE = re.compile(r"\s*(?:\.\s*(?:apply|call)\s*)?\(")
CHARCODE_ARGS_MAX = 4000        # chars of one call's arguments searched
# Chars of argument scanning per line; past it a call's arguments are taken to
# run CHARCODE_ARGS_MAX chars (over-counting, never under-counting), so a line
# of 50,000 unclosed calls stays linear.
CHARCODE_SCAN_BUDGET = 200_000


def _call_args_end(line, k, stop):
    """Index of the ')' that closes the '(' at k, or None before `stop`.
    Scanned from k itself, skipping ' " ` strings (with backslash escapes):
    the quote state of a whole minified line is not reliable (a quote in a
    regex or template literal), but the arguments of one call are short."""
    depth, quote, j = 0, None, k
    while j < stop:
        c = line[j]
        if quote is not None:
            if c == "\\":
                j += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def _charcode_col(line):
    """Column of the String.fromCharCode call that makes `line` SC-CHARCODE,
    or None (see above). Linear: one pass over the numbers, bounded argument
    scans."""
    if CHARCODE_RE.search(line) is None:
        return None
    nums = [m.start() for m in CHARCODE_NUM_RE.finditer(line)]
    if len(nums) < 10:                                    # a code table has ten too
        return None
    tables = {m.group(1) for m in _CHARCODE_TABLE_RE.finditer(line)
              if all(32 <= int(v) <= 126 for v in re.findall(r"[0-9]+", m.group(2)))}
    refs = [m.start() for m in _CHARCODE_NAME_RE.finditer(line) if m.group() in tables] if tables else []
    budget = CHARCODE_SCAN_BUDGET
    for m in CHARCODE_RE.finditer(line):
        t = _CHARCODE_CALL_TAIL_RE.match(line, m.end())
        if t is None:
            continue
        k = t.end() - 1                                   # the '('
        stop = min(len(line), k + CHARCODE_ARGS_MAX)
        end = _call_args_end(line, k, stop) if budget > 0 else None
        e = stop if end is None else end
        budget -= e - k
        if (bisect.bisect_left(nums, e) - bisect.bisect_left(nums, k) >= 10
                or bisect.bisect_left(refs, e) > bisect.bisect_left(refs, k)):
            return m.start()
    return None


def _paren_close_map(line):
    """{index of '(' : index of its matching ')'} for one line, in one pass.
    Quotes are tracked from the start of the line (a '(' inside a string
    literal has no entry); same pairing as _paren_slice otherwise."""
    close, stack, quote = {}, [], None
    for m in _PAREN_TOKEN_RE.finditer(line):
        ch, j = m.group(), m.start()
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            stack.append(j)
        elif stack:
            close[stack.pop()] = j
    return close


def sql_sink_analyzer(path, lines, issues, ctx=None):
    """Whole-argument analysis of execute()/executemany() calls (G12).
    Appends S-SQL-PY issues to `issues` (deduped against the line-rule pass
    by line number); safe parameterized calls are skipped. `ctx` (scan_file's
    per-file context) supplies the normalized match text and the time budget."""
    match_lines = ctx.mlines if ctx is not None and ctx.lines is lines else lines
    tmap = _sql_template_map(match_lines)
    flagged = {i["line"] for i in issues if i.get("rule") == "S-SQL-PY"}
    for i, line in enumerate(match_lines):
        if i + 1 in flagged or ".execute" not in line:
            continue
        if ctx is not None:
            ctx.check_time()
        close = None
        for n_call, m in enumerate(SQL_CALL_RE.finditer(line)):
            if n_call >= SQL_CALLS_PER_LINE:
                break
            if close is None:
                close = _paren_close_map(line)
            j = close.get(m.end() - 1)
            if j is None:
                continue
            arg_str = line[m.end():j][:SQL_ARG_MAX]
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


def normalize_newlines(text):
    """Line endings as text mode reads them: \r\n and a lone \r become \n.
    Project files are read in text mode already; registry archives are decoded
    from bytes, so a package authored on Windows would otherwise leave "\r" on
    every line. Twin of normalizeNewlines in js/src/lib/fs.js."""
    return text.replace("\r\n", "\n").replace("\r", "\n") if "\r" in text else text


#: Per-file time backstop (review fix, shared semantics 14): when the pattern
#: rules on one file have run this many seconds (checked between lines and
#: between passes), the file's scan stops with an SC-TRUNCATED finding. The
#: quadratic regexes themselves are fixed; this only bounds what is left.
SCAN_TIME_BUDGET = 30.0


def scan_file(path, content, lang, dep=False):
    """Scan one file. dep=True → dependency mode: only supply-chain and
    secret rules run (quality/bug rules would be pure noise in vendored code).
    The text is read in Unicode 13.0 on every Python (see _unicode13): a code
    point it leaves unassigned is scanned, and shown, as U+FFFD."""
    lines = source_lines(_unicode13.pin(content), lang)
    content = "\n".join(lines)
    ctx = _FileCtx(lines, lang, content, time.monotonic() + SCAN_TIME_BUDGET, jsx_reading(path))
    outer = getattr(_TLS, "ctx", None)
    _TLS.ctx = ctx
    try:
        issues = []
        try:
            _scan_file(path, content, lines, lang, dep, ctx, issues)
        except _ScanBudgetExceeded:
            issues.append(truncated_issue(path, "scan time budget exceeded"))
        return cap_issues(path, [i for i in issues if not ctx.suppressed(i, dep=dep)], lines)
    finally:
        _TLS.ctx = outer


# Rules that also run on comment lines.
_COMMENT_LINE_RULES = frozenset(("Q-TODO", "S-TOKEN", "S-BIDI"))

# ---------------- Decode -> execute across lines (review fix, shared semantics 13) ----------------
# SC-EVAL-DECODE is matched per line, so `eval(\n  atob(…))` and
# `exec(  # nosec\n  base64.b64decode(…))` (the second also dodging the
# "SC-* is unsuppressible" rule by never producing a finding) were missed.
# When a line names a sink and leaves parentheses open (or ends with the
# sink's name), it is joined — comment text removed — with up to
# SC_JOIN_MAX_LINES following lines until the parentheses balance, and the
# rule is matched on the joined statement. A match must begin on the first
# line; the finding is reported there.
SC_JOIN_MAX_LINES = 8
SC_JOIN_MAX_CHARS = 4000        # of following-line text added to one join
_SC_SINK_NAMES = ("eval", "exec", "execSync", "Function",
                  "runInContext", "runInThisContext", "runInNewContext")
_SC_SINK_WORD_RE = re.compile(r"\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\b|" + _EVAL_BY_NAME)


def _paren_balance(code):
    t = STRING_LIT_RE.sub("", code)
    return t.count("(") - t.count(")")


def _joined_eval_decode(ctx, i, rule_re):
    """Column (on line i) of an SC-EVAL-DECODE match over the statement that
    starts on line i and continues on the next lines, or None."""
    code = ctx.mcode(i)
    if not _SC_SINK_WORD_RE.search(code):
        return None
    depth = _paren_balance(code)
    if depth <= 0 and not code.rstrip().endswith(_SC_SINK_NAMES):
        return None
    parts, added = [code], 0
    for k in range(i + 1, min(len(ctx.lines), i + 1 + SC_JOIN_MAX_LINES)):
        if ctx.cmask[k]:
            continue
        nxt = ctx.mcode(k)
        parts.append(nxt)
        added += len(nxt)
        depth += _paren_balance(nxt)
        if (depth <= 0 and nxt.strip()) or added > SC_JOIN_MAX_CHARS:
            break
    m = rule_re.search(" ".join(parts))
    return m.start() if m and m.start() < len(code) else None


# Dependency mode also follows a decoded value through variables: a name
# assigned from a decode call (atob, Buffer.from(…, 'base64'), b64decode,
# bytes.fromhex, codecs.decode, unhexlify, zlib.decompress — member prefixes
# allowed), or from an expression naming such a variable, that later appears
# in the arguments of eval / exec / execSync / execFile(Sync) / spawn(Sync) /
# Function / new Function / vm.runIn*Context is SC-EVAL-DECODE at the sink.
# Statements on one line are processed left to right (`const d = atob(p);
# eval(d)`). Names are never un-tainted (over-approximation is the safe
# direction for third-party code). Project mode covers this with T-CODE/T-CMD.
# A decode call written directly in a sink's arguments counts too
# (`cp.exec(atob(p))`, which the per-line rule no longer sees for aliases).
#
# `exec` and `eval` are sinks when called bare (`exec(d)`, JavaScript names
# imported from child_process), on a global object (`window.eval`,
# `globalThis.eval`), on Python's builtins, or on child_process itself, a
# require("child_process") call or a name assigned from one. Any other
# method call is not code execution: `re.exec(t)` / `/…/.exec(t)` is
# RegExp.prototype.exec (the `for (re.lastIndex = 0; (m = re.exec(t));)`
# loop of every bundler's output), `session.exec(q)` a database call. The
# other sink names are distinctive and count on any receiver.
_DECODE_CALL_RE = re.compile(
    r"(?:\batob|\bb64decode|\.\s*fromhex|\bunhexlify|\b" + _module_ref("codecs") + r"\s*\.\s*decode"
    r"|\b" + _module_ref("zlib") + r"\s*\.\s*decompress)\s*\("
    r"|\bBuffer\s*\.\s*from\s*\([^;\n]{0,300}?['\"`]base64['\"`]")
# The receiver starts at an identifier boundary: without (?<![\w$]) every
# position inside a long identifier retried the whole rest of it ('a' * 20,000
# on one line: 4.8 s).
_DECODE_SINK_RE = re.compile(
    r"(?:(?<![\w$])(require\s*\(\s*['\"`][ \w:]*['\"`]\s*\)|[A-Za-z_$][\w$]*)\s*\.\s*)?"
    r"(?<![\w$])(eval|exec|execSync|execFile|execFileSync|spawn|spawnSync|Function"
    r"|runIn(?:This|New)?Context)\s*\(")
_GLOBAL_EVAL_RECEIVERS = frozenset(("window", "globalThis", "self", "global", "top", "parent",
                                    "frames", "builtins", "__builtins__"))
# The indirect calls of eval / Function (_INDIRECT_EVAL) as sinks of the
# flow: each match ends at the call's '(' (a thisArg in the arguments names
# no decoded value). Matched on the line as written, since a computed
# member's name is a string literal; a match must start outside one.
_INDIRECT_SINK_RE = re.compile(
    r"\(\s*(?:void\s+)?[\w$.]+\s*,\s*" + _GLOBAL_OBJECT + r"(?:eval|Function)\s*\)\s*\("
    r"|\b(?:eval|Function)\s*\.\s*(?:call|apply)\s*\("
    r"|\b(?:eval|Function)\s*\.\s*bind\s*\([^()]*\)\s*\("
    r"|\bReflect\s*\.\s*apply\s*\((?=\s*" + _GLOBAL_OBJECT + r"(?:eval|Function)\s*,)"
    r"|" + _EVAL_BY_NAME + r"\s*\(")
_CHILD_PROCESS_RE = re.compile(r"['\"`](?:node:)?child_process['\"`]")
_CP_ALIAS_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*"
    r"['\"`](?:node:)?child_process['\"`]\s*\)"
    r"|\bimport\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['\"`](?:node:)?child_process['\"`]")


def _child_process_aliases(content):
    """Names bound to the child_process module in this file."""
    if "child_process" not in content:
        return frozenset()
    return frozenset(m.group(1) or m.group(2) for m in _CP_ALIAS_RE.finditer(content))


def _is_code_sink(code, m, cp_aliases):
    """Is this _DECODE_SINK_RE match (found in the string-blanked text of
    `code`) a call that runs code? See the comment above _DECODE_CALL_RE."""
    name = m.group(2)
    if name not in ("eval", "exec"):
        return True
    if m.group(1) is None:
        j = m.start(2) - 1
        while j >= 0 and code[j] in " \t":
            j -= 1
        return j < 0 or code[j] != "."        # `foo().exec(` / `/re/.exec(`: a method
    recv = code[m.start(1):m.end(1)]
    if recv.startswith("require"):
        return name == "exec" and _CHILD_PROCESS_RE.search(recv) is not None
    if recv in _GLOBAL_EVAL_RECEIVERS:
        return name == "eval" or recv in ("builtins", "__builtins__")
    return name == "exec" and (recv == "child_process" or recv in cp_aliases)
_DEP_ASSIGN_RE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])([^;]*)")
DEP_SINK_ARGS_MAX = 1000        # chars of a sink's arguments searched for decoded names


def _blank_strings(code):
    """`code` with the contents of its string literals replaced by spaces
    (same length, quotes kept) so identifiers inside strings do not count."""
    return STRING_LIT_RE.sub(lambda m: m.group()[0] + " " * (len(m.group()) - 2) + m.group()[-1],
                             code)


# A decoded value taints names for DEP_FLOW_WINDOW characters from the
# decode (a dropper decodes and runs its payload together). Names are
# tracked without scopes, so without a bound one ordinary decode in a large
# bundle spread through helper parameters to thousands of names: npm:pullfrog's
# 7.8 MB dist/index.js loads undici's WebAssembly parser with
# `mod = …compile(Buffer.from(…, "base64"))` at line 7310, and esbuild's
# `__importStar(mod)` helper carried the mark to 6,216 names, every spawn in
# the file among them.
DEP_FLOW_WINDOW = 10_000
# `function exec(`, `function* exec(`, `def exec(`: a definition (on the 24 chars before the name)
_FN_DEF_BEFORE_RE = re.compile(r"(?:^|[^\w$])(?:function\s*\*?|def)\s*$")


def _dep_decode_flow(path, ctx, issues):
    rule = next(r for r in RULES if r["id"] == "SC-EVAL-DECODE")
    ident_re = _IDENT_RUN_RE.get(ctx.lang, _IDENT_RUN_RE["js"])
    have = {i["line"] for i in issues if i["rule"] == "SC-EVAL-DECODE"}
    cp_aliases = _child_process_aliases(ctx.content) if ctx.lang == "js" else frozenset()
    decoded = {}                      # name -> (line of the decode, its offset in the file)
    offset = 0                        # offset of line i in the file
    for i in range(len(ctx.lines)):
        base, offset = offset, offset + len(ctx.lines[i]) + 1
        if ctx.cmask[i]:
            continue
        code = ctx.mcode(i)
        if not code or code.isspace():
            continue
        if not i & 63:
            ctx.check_time()
        has_decode = _DECODE_CALL_RE.search(code) is not None
        if not decoded and not has_decode:
            continue
        blank = _blank_strings(code)
        events = [(m.start(), 0, m) for m in _DEP_ASSIGN_RE.finditer(blank)]
        events += [(m.start(), 1, m) for m in _DECODE_SINK_RE.finditer(blank)]
        events += [(m.start(), 2, m) for m in _INDIRECT_SINK_RE.finditer(code)
                   if blank[m.start()] == code[m.start()]]
        events.sort(key=lambda e: (e[0], e[1]))
        close = None

        def live(a, b, at):
            """Decodes behind the decoded names in blank[a:b], still in reach at `at`."""
            return [decoded[v] for v in set(ident_re.findall(blank, a, b))
                    if v in decoded and at - decoded[v][1] <= DEP_FLOW_WINDOW]

        for n, (pos, kind, m) in enumerate(events):
            if n and not n & 255:     # one long line can hold thousands of statements
                ctx.check_time()
            at = base + pos
            if kind == 0:
                a, b = m.span(2)
                if _DECODE_CALL_RE.search(code, a, b):
                    decoded[m.group(1)] = (i + 1, at)
                    continue
                src = live(a, b, at)
                if src:
                    decoded[m.group(1)] = max(src, key=lambda d: d[1])
                continue
            if i + 1 in have:
                continue
            if kind == 1:
                if not _is_code_sink(code, m, cp_aliases):
                    continue
                if _FN_DEF_BEFORE_RE.search(blank[max(0, m.start(2) - 24):m.start(2)]):
                    continue                  # a definition, not a call
            if close is None:
                close = _paren_close_map(blank)
            closed = close.get(m.end() - 1)
            if closed is not None and blank[closed + 1:closed + 2 + DEP_SINK_ARGS_MAX].lstrip()[:1] == "{":
                continue                      # `exec(a, b) {`: a method definition
            end = min(len(blank) if closed is None else closed, m.end() + DEP_SINK_ARGS_MAX)
            src = live(m.end(), end, at)
            if src:
                msg = (f"Decoded payload (assigned at line {min(d[0] for d in src)}) "
                       f"reaches a code-execution sink.")
            elif _DECODE_CALL_RE.search(code, m.end(), end):
                msg = "Decoded payload reaches a code-execution sink in the same call."
            else:
                continue
            have.add(i + 1)
            issues.append(mk_issue(dict(rule, msg=msg), path, i + 1, ctx.lines, m.start()))


def _scan_file(path, content, lines, lang, dep, ctx, issues):
    cmask, mlines = ctx.cmask, ctx.mlines
    rules = [r for r in RULES if lang in r["langs"]
             and (not dep or r["id"].startswith(DEP_RULE_PREFIXES))]
    secret_lines = set()          # lines with S-TOKEN / S-SECRET (S-ENTROPY dedupe)
    file_words = []               # the file's ASCII words, read when a look-alike name needs them

    def words():
        if not file_words:
            file_words.append(frozenset(_ASCII_WORD_RE.findall(content)))
        return file_words[0]
    runs_code = []                # whether the file runs code from a string (SC-HIDDEN-UNICODE severity)

    def file_runs_code():
        if not runs_code:
            runs_code.append(_HIDDEN_EXEC_RE.search(content) is not None)
        return runs_code[0]
    for i, line in enumerate(lines):
        ctx.check_time()
        if not line or line.isspace():
            # no rule or heuristic matches whitespace alone; only the length rule applies
            if not dep and len(line) > LONG_LINE:
                issues.append(mk_issue(
                    {"id": "Q-LONGLINE", "name": "Line too long", "type": "SMELL", "sev": "MINOR",
                     "msg": f"Line exceeds {LONG_LINE} characters.",
                     "why": "Very long lines hurt readability and reviews.",
                     "fix": "Break the line up for readability.", "ref": "Maintainability"},
                    path, i + 1, lines))
            continue
        mline = mlines[i]
        for r in rules:
            if cmask[i] and r["id"] not in _COMMENT_LINE_RULES:
                continue
            # equality checks shouldn't match inside string literals
            target = STRING_LIT_RE.sub("\"\"", mline) if r["id"] == "B-EQEQ" else mline
            m = r["re"].search(target)
            col = m.start() if m else None
            if col is None and r["id"] == "SC-EVAL-DECODE" and not cmask[i]:
                col = _joined_eval_decode(ctx, i, r["re"])
            if col is None:
                continue
            if r["need"] and not r["need"].search(mline):
                continue
            if r["skip"] and r["skip"].search(mline):
                continue
            if r["id"] == "S-TOKEN" and not _token_has_material(r["re"], mline, mlines, i):
                continue
            if r["id"] in ("S-TOKEN", "S-SECRET"):
                secret_lines.add(i)
            issues.append(mk_issue(r, path, i + 1, lines, col))
        if not dep and len(line) > LONG_LINE:
            issues.append(mk_issue(
                {"id": "Q-LONGLINE", "name": "Line too long", "type": "SMELL", "sev": "MINOR",
                 "msg": f"Line exceeds {LONG_LINE} characters.",
                 "why": "Very long lines hurt readability and reviews.",
                 "fix": "Break the line up for readability.", "ref": "Maintainability"},
                path, i + 1, lines))
        # --- obfuscation heuristics (strong supply-chain indicators) ---
        hidden = hex_hidden_text(line)
        if hidden is not None:
            dangerous = bool(HIDDEN_TEXT_DANGER_RE.search(hidden))
            preview = hidden if len(hidden) <= 60 else hidden[:57] + "..."
            issues.append(mk_issue(
                {"id": "SC-HEXSTR", "name": "Hex-escaped readable text", "type": "HOTSPOT",
                 "sev": "CRITICAL" if dangerous else "MAJOR",
                 "msg": f"Hex escapes hide readable text: {preview!r}.",
                 "why": ("Escaping ordinary printable characters serves no purpose except hiding "
                         "them from review and search; this text "
                         + ("names code execution, a download, or a URL." if dangerous
                            else "is readable once decoded.")),
                 "fix": "Decode the string and review what it does.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines,
                _HEX_ESCAPE_RE.search(line).start()))
        else:
            name = hex_hidden_name(line)
            if name is not None:
                issues.append(mk_issue(
                    {"id": "SC-HEXSTR", "name": "Hex-escaped readable text", "type": "HOTSPOT",
                     "sev": "CRITICAL", "msg": f"Escape sequences hide a name: {name[0]!r}.",
                     "why": ("Nothing needs to escape a letter of a name like this one: writing it as "
                             "escape sequences only hides it from review and search, and this one "
                             "names code execution, a download, or a URL."),
                     "fix": "Decode the string and review what it does.",
                     "ref": "CWE-506 · Supply chain"}, path, i + 1, lines, name[1]))
        if lang in ("js", "py") and not cmask[i]:
            code = ctx.mcode(i)
            if not code.isascii():
                found = lookalike_name(ctx.names_code(i), lang, words)
                if found is not None:
                    issues.append(lookalike_issue(found, path, i + 1, lines))
            if not dep and _runs_download_through_shell(code):
                issues.append(mk_issue(_PIPE_SHELL_RULE, path, i + 1, lines, _EXEC_CALL_RE.search(code).start()))
        if not line.isascii():
            hrun = hidden_unicode_run(line)
            if hrun is not None:
                issues.append(_hidden_unicode_issue(path, i + 1, lines, hrun[0], hrun[1], file_runs_code()))
        cm_col = _charcode_col(line) if lang == "js" else None
        if cm_col is not None:
            issues.append(mk_issue(
                {"id": "SC-CHARCODE", "name": "Char-code string building", "type": "HOTSPOT", "sev": "MAJOR",
                 "msg": "String assembled from character codes — obfuscation indicator.",
                 "why": "fromCharCode chains hide payloads from static review.",
                 "fix": "Decode and review what string is being built.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines, cm_col))
        bm = B64_BLOB_RE.search(line)
        if bm and "sourceMappingURL" not in line:
            issues.append(mk_issue(
                {"id": "SC-B64", "name": "Large base64 blob", "type": "HOTSPOT", "sev": "MAJOR",
                 "msg": "Base64 blob (200+ chars) embedded in code.",
                 "why": "Embedded encoded blobs can carry second-stage payloads.",
                 "fix": "Decode and verify the content; move legitimate assets to data files.",
                 "ref": "CWE-506 · Supply chain"}, path, i + 1, lines, bm.start()))
        # --- entropy-based secret detection ---
        # (review fix: the S-TOKEN/S-SECRET dedupe was an any() over every
        # issue so far, per line — 15.7 s on 20k lines; now a set lookup)
        if not cmask[i] and i not in secret_lines and not SECRET_SKIP_RE.search(line):
            em = ENTROPY_VALUE_RE.search(line)
            # the file's literal index holds exactly the entropy_secretish()
            # literals of non-skip lines — computed once, shared with redaction
            if em and em.group(1) in ctx.secrets().lits:
                issues.append(mk_issue(
                    {"id": "S-ENTROPY", "name": "High-entropy string", "type": "HOTSPOT", "sev": "MAJOR",
                     "msg": "High-entropy string literal — possible hardcoded secret.",
                     "why": "Random-looking constants are usually keys or tokens.",
                     "fix": "If it is a secret, rotate it and load it from the environment.",
                     "ref": "CWE-798 · OWASP A07"}, path, i + 1, lines, em.start(1)))
    # file-level: javascript-obfuscator identifier signature
    if lang == "js":
        obf = OBF_IDENT_RE.findall(content)
        if len(set(obf)) >= 5:
            first_off = content.find(obf[0])
            first_line = content[:first_off].count("\n") + 1
            issues.append(mk_issue(
                {"id": "SC-OBF-IDENT", "name": "Obfuscated identifier pattern", "type": "HOTSPOT",
                 "sev": "CRITICAL",
                 "msg": f"{len(set(obf))} '_0x…' identifiers — javascript-obfuscator signature.",
                 "why": "This naming pattern is produced by obfuscation tools; in a dependency it is "
                        "a classic indicator of a compromised or malicious package.",
                 "fix": "Diff against the package's published repository; consider removing the dependency.",
                 "ref": "CWE-506 · Supply chain"}, path, first_line, lines,
                first_off - content.rfind("\n", 0, first_off) - 1))
    if dep:
        _dep_decode_flow(path, ctx, issues)
        return
    mcontent = content if mlines is lines else "\n".join(mlines)
    starts = None
    for r in TEXT_RULES:
        # *-NOWHERE SQL rules are fired by scan_sql_nowhere() (linear pass),
        # not here — their regexes match only the statement head.
        if lang not in r["langs"] or r["id"] in _SQL_NOWHERE_SKIP:
            continue
        last = None
        for n, m in enumerate(r["re"].finditer(mcontent)):
            if not n & 255:           # the time backstop also holds inside one rule
                ctx.check_time()
            if starts is None:        # review fix: was content[:pos].count("\n") per match
                starts = _line_starts(mcontent)
            line_no = bisect.bisect_right(starts, m.start())
            if line_no == last:       # same (rule, line, msg): reported once (cap_issues)
                continue
            last = line_no
            issues.append(mk_issue(r, path, line_no, lines, m.start() - starts[line_no - 1]))
    ctx.check_time()
    if lang == "sql":
        try:
            scan_sql_nowhere(path, content, issues, lines)
        except Exception:
            pass
    ctx.check_time()
    issues.extend(taint_scan(path, lines, lang, ctx))
    # G12: whole-argument SQL-sink analysis (Python only) — catches
    # execute(sql % x) with no space after %, .format() on a template variable,
    # and execute(name) where name was built by interpolation/concatenation.
    # (Project mode only, like every non-supply-chain rule; it used to run
    # in dependency mode too, unlike the JS engine.)
    if lang == "py":
        try:
            sql_sink_analyzer(path, lines, issues, ctx)
        except _ScanBudgetExceeded:
            raise
        except Exception:
            pass
    ctx.check_time()
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

DEP_MARKERS = {"node_modules", "site-packages", "bower_components", "vendor",
               "venv", ".venv"}
INSTALL_HOOK_RE = re.compile(
    r"curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b", re.I)
# G11: npm lifecycle scripts — the command list above is a bypassable denylist
# (`npx --yes evil`, `node ./scripts/payload.js`, `git clone … && make` contain
# none of those tokens). Presence of *any* install-time script is itself worth
# a finding: it runs with user privileges on `npm install` before the package
# is reviewed. The pattern list is only a severity escalator.
# Scripts npm runs when a package is installed as a dependency. Publisher-side
# scripts (prepack, prepublishOnly, postpublish, ...) only ever run on the
# maintainer's machine while packaging a release, so they are not install hooks.
NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
# In a checked-out project (not a registry tarball), `npm install` also runs
# the prepare family (preprepare, prepare, postprepare).
NPM_PREPARE_SCRIPTS = ("preprepare", "prepare", "postprepare")
NPM_LOCAL_INSTALL_SCRIPTS = NPM_INSTALL_SCRIPTS + NPM_PREPARE_SCRIPTS
NPM_LIFECYCLE_SCRIPTS = NPM_LOCAL_INSTALL_SCRIPTS   # backwards-compatible name
PY_LIFECYCLE_SECTIONS = ("build-system", "tool.poetry", "project")

def _sc_install_hook_issue(path, line_no, lines, script, cmd, suspicious, sev=None, redactor=None):
    sev = sev or ("CRITICAL" if suspicious else "MAJOR")
    if suspicious:
        msg = f'"{script}" script runs a network-fetch/eval command at install time.'
        why = ("Install hooks execute automatically on npm install — the most common "
               "supply-chain compromise vector — and this one fetches or executes "
               "remote code.")
    else:
        msg = f'"{script}" script runs code at install time: {cmd!r}.'
        why = ("Install hooks run automatically with user privileges on npm install, "
               "before anyone reviews the package. Many legitimate packages use one "
               "(to fetch a platform binary, for example), so on its own this is a "
               "capability to review, not evidence of malice.")
        if sev == "INFO":
            why = ("A prepare-family script runs on `npm install` in this checkout; it "
                   "is the project's own build step (husky, patch-package, a compile), "
                   "listed for inventory. Suspicious commands here stay CRITICAL.")
    issue = mk_issue(
        {"id": "SC-INSTALL-HOOK", "name": "Install hook", "type": "HOTSPOT",
         "sev": sev, "msg": msg, "why": why,
         "fix": f"Review the {script} script; use --ignore-scripts in CI if unneeded.",
         "ref": "CWE-506 · Supply chain"}, path, line_no, lines, redactor=redactor)
    issue["cmd"] = cmd   # lets the registry follow the hook to the script it runs
    return issue

# Nesting limit for manifests (package.json, binding.gyp): deeper documents are
# SC-MANIFEST-DEPTH. Measured explicitly (json_depth_exceeds) instead of
# waiting for json.loads to hit the interpreter's recursion limit, which sits
# near 995 levels on Python 3.10/3.11 and near 10,000 on 3.12+ — so the same
# manifest used to be a finding on one interpreter and parse on another, and
# disagree with the npm engine (pycompat.js MAX_JSON_DEPTH, the same 500).
MAX_MANIFEST_DEPTH = 500
MANIFEST_DEPTH_MSG = (f"Manifest is too deeply nested to parse (more than "
                      f"{MAX_MANIFEST_DEPTH} levels).")
_JSON_STRING_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?', re.S)   # unterminated: to the end
_NOT_BRACKET_RE = re.compile(r"[^\[\]{}]+")


def json_depth_exceeds(text, limit=MAX_MANIFEST_DEPTH):
    """True if `text` nests [ / { deeper than `limit`, counting only brackets
    outside JSON (double-quoted) strings — twin of the npm engine's
    jsonDepthExceeds. Linear: the strings and everything but brackets are
    stripped by two non-backtracking regexes, and the remaining brackets are
    walked only when there are more openers than the limit."""
    brackets = _NOT_BRACKET_RE.sub("", _JSON_STRING_RE.sub("", text))
    if brackets.count("[") + brackets.count("{") <= limit:
        return False
    depth = 0
    for ch in brackets:
        if ch in "[{":
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return False


class JsonTooDeep(ValueError):
    """A JSON document nested deeper than the limit json_loads_bounded was given."""


def json_loads_bounded(text, limit=MAX_MANIFEST_DEPTH, **kwargs):
    """json.loads for input that may be hostile (scanned-repo content, stored
    results, registry responses, config files): anything nested deeper than
    `limit` raises JsonTooDeep (a ValueError) before parsing starts. The limit
    is ours, not the interpreter's (STRUCTURE.md rule 6): json.loads runs out of
    recursion near 995 levels on 3.10/3.11, near 10,000 on 3.12/3.13 and, on
    3.14, only when the C stack does (a different depth on each OS). bytes are
    decoded the way json.loads decodes them."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode(json.detect_encoding(text), "surrogatepass")
    if json_depth_exceeds(text, limit):
        raise JsonTooDeep(f"JSON nested deeper than {limit} levels")
    try:
        return json.loads(text, **kwargs)
    except RecursionError:              # backstop: the caller's stack was already deep
        raise JsonTooDeep(f"JSON nested too deeply to parse (limit {limit} levels)") from None


def _sc_manifest_depth_issue(path):
    """48033f94: a pathologically deep-nested manifest (e.g. 60k+ '[' bytes)
    blows json.loads' recursion limit. The old code crashed the CLI (exit 1,
    results lost) and in registry mode suppressed every other finding in the
    package (scan recorded as 'error' instead of reporting). Both are wins for
    a hostile repo, so this is reported as a CRITICAL supply-chain finding —
    never a crash, never a silent skip. Anything nested deeper than
    MAX_MANIFEST_DEPTH gets it, whatever the interpreter's recursion limit."""
    return mk_issue(
        {"id": "SC-MANIFEST-DEPTH", "name": "Hostile manifest nesting depth",
         "type": "HOTSPOT", "sev": "CRITICAL",
         "msg": MANIFEST_DEPTH_MSG,
         "why": ("A manifest nested this deep cannot be produced by any real "
                 "build tool — it exists purely to crash or blind security "
                 "scanners. Treating it as data would silently drop every "
                 "other finding in the package."),
         "fix": "Reject this package/file at your ingestion boundary; investigate the source.",
         "ref": "CWE-506 · Supply chain"}, path, 1, [])


def manifest_unparseable_issue(path, reason):
    """SC-MANIFEST-UNPARSEABLE (MAJOR): a ROOT package.json / binding.gyp the
    scanner cannot read. npm may still read it (it strips a byte-order mark,
    for one) and run its install hooks, so "nothing to check" is not a clean
    result. The registry turns this into an INCOMPLETE verdict."""
    name = os.path.basename(path.replace("\\", "/")) or path
    return mk_issue(
        {"id": "SC-MANIFEST-UNPARSEABLE", "name": "Unparseable manifest",
         "type": "HOTSPOT", "sev": "MAJOR",
         "msg": f"{name} could not be parsed ({reason}); its install hooks could not be checked.",
         "why": ("Package managers are more forgiving than a strict parser in places (a "
                 "byte-order mark, number formats), so a manifest the scanner cannot read "
                 "may still run install scripts when the package is installed. An "
                 "unreadable root manifest is reported instead of treated as empty."),
         "fix": "Make the manifest valid JSON (binding.gyp: a Python/JSON literal) and "
                "review its scripts by hand.",
         "ref": "CWE-506 · Supply chain"}, path, 1, [])


def is_root_manifest(path):
    """A manifest at the top of the scanned tree / package (no directory part)."""
    return os.path.dirname(path.replace("\\", "/").lstrip("/")) in ("", ".")


def _json_int(text):
    # JavaScript parses every JSON number as a double, so a 5000-digit
    # integer is fine for npm (it becomes Infinity); int() would raise
    # ValueError past sys.int_info.str_digits_check_threshold.
    return int(text) if len(text) <= 1000 else float(text)


# json.loads' message for the closing bracket after a trailing comma on Python
# 3.10-3.12 (3.13+ says "Illegal trailing comma" and points at the comma).
_JSON_TRAILING_COMMA_AT = {"Expecting property name enclosed in double quotes": "}",
                           "Expecting value": "]"}


def json_error_where(exc):
    """"line L column C" of a json.JSONDecodeError, the same on every Python.
    3.13+ reports a trailing comma (`{"a": 1,}`, `[1, ]`) at the comma and
    3.10-3.12 at the bracket after it; this says the comma on every version,
    as the npm engine's pyjson.js does. Any other error is where json.loads
    puts it."""
    doc, pos = exc.doc, exc.pos
    if doc[pos:pos + 1] == _JSON_TRAILING_COMMA_AT.get(exc.msg):
        j = pos - 1
        while j >= 0 and doc[j] in " \t\n\r":
            j -= 1
        if j >= 0 and doc[j] == ",":
            pos = j
    lineno = doc.count("\n", 0, pos) + 1              # as JSONDecodeError counts them
    colno = pos - doc.rfind("\n", 0, pos)
    return f"line {lineno} column {colno}"


def load_manifest(path, content, python_literal=False):
    """Parse manifest-shaped, attacker-controlled text the way the package
    manager does. -> (data, issues).

    A leading UTF-8 BOM is stripped first (npm does). data is None when the
    text cannot be parsed; issues then holds SC-MANIFEST-DEPTH for a document
    nested deeper than MAX_MANIFEST_DEPTH (checked before parsing, so the
    result does not depend on the interpreter's recursion limit or on where
    a syntax error sits), or SC-MANIFEST-UNPARSEABLE when the manifest
    is at the root (a nested unreadable manifest is not a hook npm runs).
    A top level that is not an object counts as unparseable too.
    python_literal: also accept Python literal syntax (binding.gyp / .gypi:
    gyp reads them as Python, so single quotes, comments and trailing commas
    are normal there)."""
    data, issues, _ = _load_manifest(path, content, python_literal)
    return data, issues


def _load_manifest(path, content, python_literal=False, locate=None):
    """load_manifest, plus -> where: with `locate` (a key), for every dict of
    the result that holds that key, {id(d): (d, offset)} where offset is the
    position in the BOM-stripped text of the key token the parser kept (the
    last of equal keys). The parse itself is the same: json.loads (with an
    object_pairs_hook building the same dicts) or ast.literal_eval of the
    ast.parse tree."""
    if not isinstance(content, str):
        return None, ([manifest_unparseable_issue(path, "not text")]
                      if is_root_manifest(path) else []), {}
    text = content[1:] if content.startswith("\ufeff") else content
    if json_depth_exceeds(text):
        return None, [_sc_manifest_depth_issue(path)], {}
    reason, where, built, hook = None, {}, [], None
    if locate is not None:
        def hook(pairs):
            d = dict(pairs)
            built.append((d, pairs))
            return d
    try:
        data = json.loads(text, parse_int=_json_int, object_pairs_hook=hook)
    except RecursionError:              # backstop: a deep caller stack
        return None, [_sc_manifest_depth_issue(path)], {}
    except (ValueError, TypeError) as exc:
        data = None
        reason = (f"{type(exc).__name__}: {json_error_where(exc)}"
                  if isinstance(exc, json.JSONDecodeError) else type(exc).__name__)
    if data is not None and locate is not None:
        where = _json_key_offsets(text, built, locate)
    if data is None and python_literal:
        import ast
        try:
            src = text.strip()
            tree = ast.parse(src, mode="eval")     # what ast.literal_eval(src) parses
            data = ast.literal_eval(tree)
            reason = None
            if locate is not None:
                where = _ast_key_offsets(tree, data, locate, src, len(text) - len(text.lstrip()))
        except RecursionError:
            return None, [_sc_manifest_depth_issue(path)], {}
        except (ValueError, TypeError, SyntaxError, MemoryError, OverflowError) as exc:
            data = None
            reason = reason or type(exc).__name__
    if not isinstance(data, dict):
        if data is not None:
            reason = f"top level is a {type(data).__name__}, not an object"
        return None, ([manifest_unparseable_issue(path, reason or "unparseable")]
                      if is_root_manifest(path) else []), {}
    return data, [], where


# (named apart from _script_key_lines's _JSON_TOKEN_RE, which shadowed it)
_JSON_OBJ_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[{}]', re.S)
_JSON_COLON_RE = re.compile(r"[ \t\n\r]*:")


def _json_key_offsets(text, built, key):
    """_load_manifest's `where` for a document json.loads parsed: its
    object_pairs_hook saw every object (`built`: (dict, pairs)) in the order
    the objects close, and in valid JSON the keys are exactly the strings
    followed by ':'."""
    objects, stack = [], []
    for m in _JSON_OBJ_TOKEN_RE.finditer(text):
        c = text[m.start()]
        if c == "{":
            stack.append([])
        elif c == "}":
            if not stack:
                return {}
            objects.append(stack.pop())
        elif stack and _JSON_COLON_RE.match(text, m.end()):
            stack[-1].append(m.start())
    if len(objects) != len(built):
        return {}                        # not reachable for text json.loads accepted
    where = {}
    for (d, pairs), offsets in zip(built, objects):
        if len(offsets) != len(pairs):
            return {}
        last = None
        for k, (name, _) in enumerate(pairs):
            if name == key:
                last = k
        if last is not None:
            where[id(d)] = (d, offsets[last])
    return where


_PY_NEWLINE_RE = re.compile(r"\r\n|\r|\n")


def _ast_key_offsets(tree, data, key, src, base):
    """_load_manifest's `where` for a document ast.literal_eval built from
    `tree` (parsed from src, which starts at offset `base` of the text). The
    tree is walked alongside the data; a dict keeps the first of equal keys
    with the last value, so the key token wanted is the last equal one. ast
    positions are (line, UTF-8 byte column) with \\r\\n, \\r and \\n all
    ending a line."""
    import ast
    starts = [0] + [m.end() for m in _PY_NEWLINE_RE.finditer(src)]

    def offset(node):
        a = starts[node.lineno - 1]
        head = src[a:a + node.col_offset].encode("utf-8", "surrogatepass")[:node.col_offset]
        return base + a + len(head.decode("utf-8", "surrogatepass"))

    where, stack = {}, [(tree.body, data)]
    while stack:
        node, value = stack.pop()
        if isinstance(node, ast.Dict) and isinstance(value, dict):
            last = {}
            for k, v in zip(node.keys, node.values):
                last[ast.literal_eval(k)] = (k, v)
            for name, (k, v) in last.items():
                if isinstance(name, str) and name == key:
                    where[id(value)] = (value, offset(k))
                stack.append((v, value[name]))
        elif isinstance(node, (ast.List, ast.Tuple)) and isinstance(value, (list, tuple)):
            stack.extend(zip(node.elts, value))
    return where


def _json_loads_manifest(path, content):
    """Backwards-compatible wrapper: (data, depth_issue). data is None on any
    parse failure; depth_issue is SC-MANIFEST-DEPTH for too-deep input.
    New code uses load_manifest, which also reports unparseable roots."""
    data, issues = load_manifest(path, content)
    depth = next((i for i in issues if i["rule"] == "SC-MANIFEST-DEPTH"), None)
    return data, depth

_NODE_E_RE = re.compile(r"""node\s+-e\s+(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|(\S+))""")
_LOCAL_REQUIRE_RE = re.compile(r"""require\(\s*\\?["'](\.{1,2}/[^"'\\]+)\\?["']\s*\)""")
_INLINE_DANGER_RE = re.compile(
    r"https?|fetch|child_process|exec|spawn|eval|Function|Buffer|atob|base64|net\.|dgram|process\.env")


def _hook_is_suspicious(cmd):
    """Does an install-hook command fetch or evaluate code? `node -e` alone is
    not evidence: core-js's `node -e "try{require('./postinstall')}catch(e){}"`
    only loads a file shipped in the package (which is scanned like any other)."""
    if not INSTALL_HOOK_RE.search(cmd):
        return False
    remainder = cmd
    for m in _NODE_E_RE.finditer(cmd):
        code = next(g for g in m.groups() if g is not None)
        if _LOCAL_REQUIRE_RE.search(code) and not _INLINE_DANGER_RE.search(
                _LOCAL_REQUIRE_RE.sub("", code)):
            remainder = remainder.replace(m.group(0), " ")
    return bool(INSTALL_HOOK_RE.search(remainder))


# ---- Following a hook command to the files it runs (registry) ----
_HOOK_SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")", ";;", "|&"}
_HOOK_REDIRECTS = {">", ">>", "<", "<<", ">&", "<&", "&>", ">|"}
_HOOK_WRAPPERS = {"env", "cross-env", "exec", "command", "nohup", "time", "nice", "sudo",
                  "cross-env-shell", "dotenv"}
_NODE_NAMES = {"node", "nodejs", "node.exe"}
_SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "ash", "sh.exe", "bash.exe"}
_PYTHON_NAME_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|py)(?:\.exe)?$", re.I)
_NODE_CODE_FLAGS = {"-e", "--eval", "-p", "--print"}
_NODE_PRELOAD_FLAGS = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
_NODE_VALUE_FLAGS = _NODE_PRELOAD_FLAGS | {"-C", "--conditions", "--input-type", "--env-file",
                                           "--title", "--inspect-port", "--redirect-warnings",
                                           "--report-dir", "--diagnostic-dir", "--cpu-prof-dir",
                                           "--heap-prof-dir", "--watch-path"}
_SCRIPT_EXT_RE = re.compile(r"\.(?:c|m)?js$|\.sh$|\.py$", re.I)
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _hook_tokens(cmd):
    """Shell-like tokenization of an npm script: quotes respected, operators
    (&& || ; | & parentheses) as their own tokens. Never raises."""
    import shlex
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:                     # unbalanced quotes: best effort
        return re.findall(r"&&|\|\||[;|&()]|[^\s;|&()]+", cmd)


def _local_module(value):
    return bool(value) and (value.startswith(("./", "../", "/")) or bool(_SCRIPT_EXT_RE.search(value)))


def _node_script(args):
    """-> (script, preloads, code) for `node [flags] script [args]`: code is
    the inline code of -e / --eval / -p / --print (None when there is none)."""
    preloads, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return (args[i + 1] if i + 1 < len(args) else None), preloads, None
        if a.startswith("-") and a != "-":
            name, eq, val = a.partition("=")
            if name in _NODE_CODE_FLAGS:
                return None, preloads, (val if eq else (args[i + 1] if i + 1 < len(args) else ""))
            if name in _NODE_VALUE_FLAGS:
                value = val if eq else (args[i + 1] if i + 1 < len(args) else "")
                if name in _NODE_PRELOAD_FLAGS and _local_module(value):
                    preloads.append(value)
                i += 1 if eq else 2
                continue
            i += 1
            continue
        return a, preloads, None
    return None, preloads, None


def _interpreter_script(args, inline_flags=("-c",)):
    """-> (script, inline_code) for `sh|python [flags] script` / `-c code`."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in inline_flags:
            return None, (args[i + 1] if i + 1 < len(args) else "")
        if a == "-m" and i + 1 < len(args):                     # python -m pkg.mod
            return args[i + 1].replace(".", "/") + ".py", None
        if a in ("-o", "-O", "-W", "-X") and i + 1 < len(args):
            i += 2
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        return a, None
    return None, None


# Following a hook is bounded (review: a 16 MB hook of `cd a;` took hours, one
# of `env ` minutes, and one of `cd a && node b.js && …` made gigabytes of
# targets): a hook longer than HOOK_MAX_CHARS is not followed, at most
# HOOK_MAX_COMMANDS commands (those in `sh -c` / `env -S` code too) and
# HOOK_MAX_TARGETS scripts are, and a script path longer than HOOK_MAX_PATH is
# dropped. follow_hook says when a limit stopped it; the registry then counts
# the release as not fully scanned (a real hook is a line or two).
HOOK_MAX_CHARS = 100_000
HOOK_MAX_COMMANDS = 1000
HOOK_MAX_TARGETS = 100
HOOK_MAX_PATH = 4096
_REDIRECT_TOKEN_RE = re.compile(r"\d?[<>]{1,2}&?\d?")
_DUP_FD_RE = re.compile(r"&\d$")
_FD_NUMBER_RE = re.compile(r"[0-9]+")
# A wrapper's options that take a value (the next word, `--name=value`, or the
# rest of a short option: `-Cdir`), the ones among them that change the
# directory the command runs in, and those whose value is a command line.
_WRAPPER_VALUE_OPTIONS = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "sudo": frozenset({"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
                       "-C", "--close-from", "-D", "--chdir", "-r", "--role", "-t", "--type",
                       "-T", "--command-timeout", "-U", "--other-user"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "exec": frozenset({"-a"}),
    "time": frozenset({"-f", "--format", "-o", "--output"}),
    "dotenv": frozenset({"-e", "-v", "-p"}),
}
_WRAPPER_CHDIR_OPTIONS = {"env": frozenset({"-C", "--chdir"}), "sudo": frozenset({"-D", "--chdir"})}
_WRAPPER_COMMAND_OPTIONS = {"env": frozenset({"-S", "--split-string"})}


class _HookWalk:
    """What following one hook has used, and whether a limit stopped it."""
    __slots__ = ("commands", "complete")

    def __init__(self):
        self.commands, self.complete = 0, True


def _apply_path(comps, path):
    """posixpath.normpath's loop for relative `path`, applied to the list of
    components kept so far (in place): '' and '.' are dropped, and '..'
    removes the component before it unless there is none or it is '..' too.
    normpath(a + '/' + b) is b applied to a's components, so a `cd` costs only
    its own length (the whole path was normalized again at every one)."""
    for comp in path.split("/"):
        if comp in ("", "."):
            continue
        if comp != ".." or not comps or comps[-1] == "..":
            comps.append(comp)
        else:
            comps.pop()
    return comps


def _hook_cd(where, dest):
    """The directory after `cd dest` from `where` ((set, components): set is
    False while no `cd` has named a directory), or None for a destination
    the walk cannot follow (~, -, $VAR). An absolute path counts from the
    package root."""
    if not dest or dest in ("~", "-") or dest.startswith(("$", "~")):
        return None
    dest = dest.replace("\\", "/")
    if dest.startswith("/"):
        raw = dest.lstrip("/")
        return raw not in ("", "."), _apply_path([], raw)
    comps = _apply_path(list(where[1]), dest)
    return bool(comps), comps


def _hook_segment_targets(tokens, depth, walk):
    """Targets of one tokenized command line; tracks `cd` across segments."""
    targets = []
    state = (False, [])                       # the directory `cd` moved to
    joined = {}

    def join(path, where=None):
        """core's normpath(join(cwd, path)) when a `cd` has set a directory
        (`where`: this command's own, from env -C / sudo -D)."""
        path = path.replace("\\", "/")
        is_set, comps = where if where is not None else state
        if not is_set or path.startswith("/"):
            return path
        if where is not None:
            return "/".join(_apply_path(list(comps), path)) or "."
        if path not in joined:              # (cleared at every cd)
            joined[path] = "/".join(_apply_path(list(comps), path)) or "."
        return joined[path]

    def flush(seg):
        nonlocal state
        words, skip = [], False
        for tok in seg:
            if skip:
                skip = False
                continue
            if tok in _HOOK_REDIRECTS or _REDIRECT_TOKEN_RE.fullmatch(tok):
                skip = not _DUP_FD_RE.search(tok)
                if words and _FD_NUMBER_RE.fullmatch(words[-1]):
                    words.pop()                 # 2>/dev/null: the 2 is the redirect's
                continue
            words.append(tok)
        if not words:
            return
        if walk.commands >= HOOK_MAX_COMMANDS:
            walk.complete = False
            return
        walk.commands += 1
        # env assignments and wrappers (with their options) in front
        i, where = 0, None
        while i < len(words):
            word = words[i]
            if _ENV_ASSIGN_RE.match(word):
                i += 1
                continue
            name = word.lower()
            if name not in _HOOK_WRAPPERS:
                break
            i += 1
            values = _WRAPPER_VALUE_OPTIONS.get(name, frozenset())
            while i < len(words) and words[i].startswith("-") and (words[i] != "-" or name == "env"):
                opt = words[i]
                i += 1
                if opt == "--":
                    break
                if opt.startswith("--"):
                    key, eq, value = opt.partition("=")
                    if key not in values:
                        continue
                    if not eq:
                        value = words[i] if i < len(words) else ""
                        i += 1
                elif opt[:2] in values:
                    key, value = opt[:2], opt[2:]
                    if not value:
                        value = words[i] if i < len(words) else ""
                        i += 1
                else:
                    continue
                if key in _WRAPPER_CHDIR_OPTIONS.get(name, ()):
                    where = _hook_cd(where or state, value) or where
                elif key in _WRAPPER_COMMAND_OPTIONS.get(name, ()):
                    if depth < 2:                   # env -S "node x.js": a command line
                        targets.extend(join(t, where) for t in _hook_targets(value, depth + 1, walk))
                    return
        if i >= len(words):
            return
        head = words[i].replace("\\", "/")
        base = head.rsplit("/", 1)[-1].lower()
        if base in ("cd", "pushd"):
            dest = next((w for w in words[i + 1:] if not w.startswith("-")), "")
            moved = _hook_cd(state, dest)
            if moved is not None:
                state = moved
                joined.clear()
            return
        script, extra, code = None, [], None
        if base in _NODE_NAMES:
            script, extra, code = _node_script(words[i + 1:])
        elif base in _SHELL_NAMES or _PYTHON_NAME_RE.match(base):
            script, inline = _interpreter_script(words[i + 1:])
            if inline and depth < 2 and base in _SHELL_NAMES:
                targets.extend(join(t, where) for t in _hook_targets(inline, depth + 1, walk))
        elif head.startswith(("./", "../")) or ("/" in head and not head.startswith("/")) \
                or _SCRIPT_EXT_RE.search(head):
            script = head                       # executed directly (shebang)
        for t in [script] + extra:
            if t:
                targets.append(join(t, where))
        if code:                                # node -e "require('./x')", from this directory
            targets.extend(join(m.group(1), where) for m in _LOCAL_REQUIRE_RE.finditer(code))

    seg = []
    for tok in tokens:
        if tok in _HOOK_SEPARATORS or (tok and set(tok) <= set(";&|()")):
            flush(seg)
            seg = []
        else:
            seg.append(tok)
    flush(seg)
    return targets


def _hook_targets(cmd, depth=0, walk=None):
    walk = walk if walk is not None else _HookWalk()
    targets = []
    variants = [cmd]
    if "\\" in cmd:
        variants.append(cmd.replace("\\", "/"))   # cmd.exe: backslash is a path separator
    for variant in variants:
        targets += _hook_segment_targets(_hook_tokens(variant), depth, walk)
    return targets


def follow_hook(cmd):
    """(targets, complete) for an install hook command: the package-relative
    files it runs, in order and without duplicates — `node install.js`,
    `node ./scripts/x.mjs`, `node install` (no extension: resolve like Node),
    `node --no-warnings x.js`, `node -r ./preload.js x.js`,
    `cd scripts && node x.js`, `sh ./install.sh`, `./install.sh`,
    `python setup_helper.py`, `node scripts\\x.js`,
    `node -e "require('./postinstall')"`, `env -C sub node x.js`,
    `sudo -u me node x.js`, `2>/dev/null node x.js` — and False for complete
    when a limit stopped the walk (see HOOK_MAX_CHARS). The command is
    tokenized like a shell (quotes, && || ; | operators, env assignments,
    cd, wrappers and their options)."""
    if not isinstance(cmd, str) or not cmd.strip():
        return [], True
    if len(cmd) > HOOK_MAX_CHARS:
        return [], False
    walk = _HookWalk()
    targets = _hook_targets(cmd, 0, walk)
    # `node -e` anywhere in the command (`npx node -e …` too), as written
    for m in _NODE_E_RE.finditer(cmd):
        code = next(g for g in m.groups() if g is not None)
        targets += _LOCAL_REQUIRE_RE.findall(code)
    seen, out = set(), []
    for t in targets:
        if t and t not in seen and t not in ("-", "."):
            if len(t) > HOOK_MAX_PATH:
                walk.complete = False
                continue
            seen.add(t)
            out.append(t)
    if len(out) > HOOK_MAX_TARGETS:
        out, walk.complete = out[:HOOK_MAX_TARGETS], False
    return out, walk.complete


def hook_script_targets(cmd):
    """The files an install hook runs (follow_hook's targets)."""
    return follow_hook(cmd)[0]


# ---------------- Install-script and import-time inspection ----------------
# (The registry's tests, here so that --deps project scans run them too.)
# An install hook is a capability; what makes it hostile is what the script it
# runs does. Escalate only on the patterns malicious install scripts share:
# shipping environment/credential data over the network, or talking to
# throwaway exfiltration endpoints. Downloading a platform binary from the
# registry (esbuild, puppeteer) is not either. The same test applies to the
# Python code pip runs at install time (an sdist's setup.py, an in-tree PEP 517
# backend) and to shell scripts a hook runs.
_NETWORK_RE = re.compile(
    r"""\b(?:https?\.(?:get|request)|fetch\s*\(|axios|XMLHttpRequest|net\.connect|dns\.resolve|"""
    r"""require\(\s*["'](?:node:)?(?:https?|net|dgram|tls)["']\s*\)|"""
    r"""from\s+["'](?:node:)?(?:https?|net|dgram|tls)["'])"""
    # Python
    r"""|\burllib\.request\b|\burlopen\s*\(|\burlretrieve\s*\(|\bhttp\.client\b|"""
    r"""\bHTTPS?Connection\s*\(|\bsocket\.(?:socket|create_connection)\s*\(|"""
    r"""\brequests\.(?:get|post|put|patch|request|Session)\b|\bimport\s+(?:requests|httpx|aiohttp|urllib3)\b|"""
    r"""\bfrom\s+(?:requests|httpx|aiohttp|urllib3|urllib\.request|http\.client)\s+import\b|"""
    r"""\bhttpx\.\w+\s*\(|\baiohttp\.ClientSession\b|\bsmtplib\b|\bftplib\b"""
    # shell: a download tool pointed at a URL, netcat to a host and port, bash's /dev/tcp.
    # Each option is parsed one way only (a value never starts like an option
    # or the URL) and their number is bounded: the old `(?:-{1,2}[\w-]+(?:[ =]
    # \S+)?\s+)*` could split `--a-b` and pair values two ways, so 18 options
    # took over 20 s, and `curl -a ` x 20000 was quadratic — a hostile install
    # script could hang the scan.
    r"""|\b(?:curl|wget)\s+(?:-{1,2}\w[\w-]*(?:=\S*|\s+(?!-{1,2}\w)(?!["']?https?:)\S+)?\s+){0,24}"""
    r"""["']?https?://"""
    r"""|\b(?:nc|ncat|netcat)\s+(?:-\w+\s+){0,8}[\w.-]+\s+\d{2,5}\b|/dev/tcp/""", re.M)
_SECRET_SOURCE_RE = re.compile(
    r"""JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries|values)\(\s*process\.env|"""
    r"""\.npmrc|[/\\]\.ssh\b|~/\.ssh\b|id_rsa|id_ed25519|\.aws[/\\]|~/\.aws\b|\.git-credentials|"""
    r"""\.docker[/\\]config\.json|\.kube[/\\]config|Local Storage[/\\]leveldb|\.pypirc|\.netrc\b|"""
    # Python: the whole environment, not one variable
    r"""\bdict\(\s*os\.environ\s*\)|\bos\.environ\.(?:items|keys|values|copy)\(\s*\)|"""
    r"""json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\b(?:str|repr)\(\s*os\.environ\s*\)|"""
    r"""\{\s*\*\*\s*os\.environ|\burlencode\(\s*(?:dict\(\s*)?os\.environ|\bos\.environb\b"""
    # shell: the whole environment piped or redirected somewhere
    r"""|(?:^|[\s;&(`])(?:env|printenv|set)\s*(?:\|(?!\|)|>)|\$\(\s*(?:env|printenv)\s*\)|`\s*(?:env|printenv)\s*`""",
    re.I | re.M)
_EXFIL_SERVICES = (
    r"""pastebin\.com|\bngrok|webhook\.site|"""
    r"""discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|"""
    r"""\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin|pipedream\.net|"""
    r"""transfer\.sh|\.onion\b""")
_EXFIL_DEST_RE = re.compile(r"""https?://(?:\d{1,3}\.){3}\d{1,3}\b|""" + _EXFIL_SERVICES, re.I)
_EXFIL_SERVICE_RE = re.compile(_EXFIL_SERVICES, re.I)      # the named ones, no raw IPs
# `curl … | sh` / `wget … | bash`, read in one left-to-right pass: a pipe into
# a shell after curl or wget in the same command (no `|`, `;`, `&` or line
# break between them). The regex it replaces, `\b(?:curl|wget)\b[^\n|;&]*\|…`,
# rescanned the rest of the command from every `curl`, so a line of 100,000
# of them never finished.
_PIPE_SCAN_RE = re.compile(r"""\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|[\n|;&]|\b(?:curl|wget)\b""")


def _pipes_download_to_shell(text):
    download = False
    for m in _PIPE_SCAN_RE.finditer(text):
        token = m.group(0)
        if token[0] == "|" and len(token) > 1:           # | sh, | sudo bash
            if download:
                return True
            download = False
        elif token in ("\n", "|", ";", "&"):
            download = False
        else:                                            # curl / wget
            download = True
    return False


# A download handed to a shell or an interpreter without a pipe: through a
# command substitution (`sh -c "$(curl …)"`, `node -e "$(curl …)"`,
# `eval "$(wget -qO- …)"`) or a process substitution (`source <(curl …)`,
# `bash <(curl …)`). Read one row at a time, as a command is; a row with no
# `$(curl`, `` `curl `` or `<(curl` (or wget) is not searched.
_DL_SUBST_RE = re.compile(
    r"""\b(?:(?:ba|z|da|k)?sh|node(?:js)?|bun|python[\d.]*|perl|ruby|php|pwsh|powershell)(?:\.exe)?"""
    r"""(?:[ \t]+-[\w-]+){0,6}?[ \t]+-(?:c|e|E|p|r|-eval|-print|Command|command)[ \t]+(?:["'][ \t]*)?"""
    r"""(?:\$\(|`)[ \t]*(?:curl|wget)\b"""
    r"""|\beval[ \t]+(?:["'][ \t]*)?(?:\$\(|`)[ \t]*(?:curl|wget)\b"""
    r"""|(?:\b(?:(?:ba|z|da|k)?sh|source|node(?:js)?|python[\d.]*)|(?:^|[ \t;&|(])\.)[ \t]+<\([ \t]*(?:curl|wget)\b""")
_DL_SUBST_NEEDLE_RE = re.compile(r"""(?:\$\(|`|<\()[ \t]*(?:curl|wget)""")


def runs_substituted_download(row):
    """Does this row hand a download to a shell or an interpreter through a
    command or process substitution (see above)?"""
    return (("curl" in row or "wget" in row) and _DL_SUBST_NEEDLE_RE.search(row) is not None
            and _DL_SUBST_RE.search(row) is not None)


# the reason each received-code category adds (see _received_code_kind)
_DL_CATEGORY_REASON = {
    "run": "runs code it receives over the network",
    "deserialize": "deserializes data it receives over the network",
    "import": "loads a module named by data it receives over the network",
}


def install_script_risk(text):
    """Reasons an install-time script looks hostile ([] if none)."""
    reasons = []
    network = bool(_NETWORK_RE.search(text))
    if network and _SECRET_SOURCE_RE.search(text):
        reasons.append("reads environment variables or credential files and sends data over the network")
    dest = _EXFIL_DEST_RE.search(text)
    if dest:
        reasons.append(f"contacts an address typical of data exfiltration ({dest.group(0)[:40]})")
    if _pipes_download_to_shell(text):
        reasons.append("pipes a download into a shell")
    substituted = (("curl" in text or "wget" in text)
                   and any(runs_substituted_download(row) for row in text.split("\n")))
    received = _received_code_kind(text)
    if substituted:
        reasons.append(_DL_CATEGORY_REASON["run"])
    elif received is not None:
        reasons.append(_DL_CATEGORY_REASON[received[1]])
    return reasons


# ---------------- Import-time inspection ----------------
# Code that runs when a package is loaded — what an npm package's main, bin
# and exports reach, a wheel's top-level packages and modules — gets a weaker
# version of the install-script test: a MAJOR finding (a weak indicator,
# WARN), never CRITICAL, and only on shapes ordinary SDKs don't share.
# Harvesting means the whole environment serialized, or a credential store
# read (SSH private keys, git credentials, browser local storage): reading
# the variables it needs, or listing them (Object.keys(process.env),
# os.environ.copy() for a subprocess), is everyday SDK and CLI code, and so
# is reading a tool's own config (.npmrc, .pypirc, .netrc, ~/.aws: npm
# clients, setuptools, distlib and cloud SDKs do, next to their network
# code — .pypirc alone fired on 5 of 12,278 installed modules). It counts
# only next to a network call or a named exfiltration service in the same
# file. An address alone never counts: cloud SDKs read 169.254.169.254, and
# Telegram, ngrok or pastebin clients name their own service. A download piped
# into a shell counts only on a line that hands it to an exec call (a CLI's
# help text often shows `curl … | sh`).
_IMPORT_HARVEST_RE = re.compile(
    r"""JSON\.stringify\(\s*process\.env\s*[,)]|"""
    r"""\bjson\.dumps\(\s*(?:dict\(\s*)?os\.environ\s*[,)]|\b(?:str|repr)\(\s*os\.environ\s*\)|"""
    r"""\burlencode\(\s*(?:dict\(\s*)?os\.environ\s*[,)]|"""
    r"""[/\\]\.ssh[/\\]id_|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.git-credentials|"""
    r"""(?i:Local Storage)[/\\]leveldb""")
_EXEC_CALL_RE = re.compile(
    r"""\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn|system|popen|Popen|run|call|"""
    r"""check_call|check_output|getoutput|getstatusoutput)\s*\(""")
# Every match of _IMPORT_HARVEST_RE contains one of these (the pattern is
# case-sensitive but for "Local Storage", and its "leveldb" is not): a text
# with none of them is not searched. The search took 8 of the 60 seconds of a
# --deps scan of a large node_modules, which runs it on every file.
_IMPORT_HARVEST_NEEDLES = ("process.env", "os.environ", "id_", ".git-credentials", "leveldb")


def import_time_risk(text):
    """-> (reasons, line): why code that runs on import looks hostile by
    the weaker test above ([] if not), and the 1-based line of the first
    sign. `text` has \\n line endings."""
    reasons, line = [], None
    harvest = (_IMPORT_HARVEST_RE.search(text)
               if any(needle in text for needle in _IMPORT_HARVEST_NEEDLES) else None)
    if harvest and (_NETWORK_RE.search(text) or _EXFIL_SERVICE_RE.search(text)):
        reasons.append("reads credentials or the whole environment and sends data over the network")
        line = text.count("\n", 0, harvest.start()) + 1
    if "curl" in text or "wget" in text:
        for i, row in enumerate(text.split("\n")):
            if _runs_download_through_shell(row):
                reasons.append("runs a downloaded script through a shell")
                line = line or i + 1
                break
    received = _received_code_kind(text)
    if received is not None:
        reasons.append(_DL_CATEGORY_REASON[received[1]])
        line = line or received[0]
    dropped = _downloads_and_runs_file(text)
    if dropped is not None:
        reasons.append("downloads a file and then runs it")
        line = line or dropped
    return reasons, line


def _runs_download_through_shell(row):
    """Does this line hand a download piped into a shell, or substituted into
    a shell's or an interpreter's command line, to an exec call
    (`execSync("curl … | sh")`, `os.system("wget -qO- … | bash")`,
    `execSync('bash -c "$(curl -fsSL …)"')`)? A CLI's help text showing
    `curl … | sh` does not."""
    return (("curl" in row or "wget" in row) and _EXEC_CALL_RE.search(row) is not None
            and (_pipes_download_to_shell(row) or runs_substituted_download(row)))


# ---------------- Code that runs what it receives over the network ----------------
# TrapDoor-style import-time code downloads code and runs it:
# subprocess.run(['node', '-e', urlopen(u).read().decode()]), exec(requests.get(u)
# .text), eval(body) after https.get's data events, new Function(await r.text()).
# The pipe test above sees none of these: no shell, no curl. runs_received_code
# follows a value received over the network — a download, a socket's or a
# server's data — through the names it is assigned to, callback parameters,
# `with … as` and `for` bindings and the functions that return it, to a runner
# that takes it whole as code: eval / exec / new Function / vm, a shell
# (os.system, execSync, a shell=True call), or an interpreter's inline code
# (['node', '-e', code], [sys.executable, '-c', code], `python -c "{code}"`).
# A value put into a larger string (`npm i pkg@${version}`, '(' + text + ')')
# is not code received, and neither is a file it was saved to. A string
# literal's contents are read as code too (a program for `node -e` is written
# in one, and quotes do not always pair as the language pairs them). Install
# scripts fail on it (install_script_risk), import-time code gets the weaker
# SC-IMPORT-RISK (import_time_risk). On 66,000 installed JavaScript and Python
# files (npm, pnpm, yarn, typescript, webpack, next, jest, the AI SDKs, pip,
# setuptools, requests, httpx, the CPython library) it found nothing.
#
# Bounds: a value is followed for _DL_WINDOW rows; a call's arguments are read
# for _DL_ARG_SPAN characters, and so is each argument's value (after its
# leading whitespace, `await`s and parentheses); a row longer than
# _DL_LONG_ROW is minified code, where only a download written straight into
# a runner counts (a runner that starts within _DL_LOOKBACK characters before
# a network name). Only rows near a network name, or naming a value followed,
# are read. A row is read in one pass over its brackets, and no pattern
# backtracks more than a bounded amount, so a text costs about one pass over
# it whatever it holds: a large bundle, or a text built to make the follower
# work. The patterns and name sets live in received_spec.json (see the loader
# below); the assertions in its alternative pairs are literal (\b, (?<![\w$.])).


def _dl_alternatives(pairs, tail=""):
    """(exact, candidate) regexes from (assertion, body) alternatives. The
    candidate leaves out the leading assertions, so re skips ahead by the
    first character (several times faster on a large bundle); an exact match
    starts where a candidate one does, and _dl_finditer confirms each."""
    group = "(?:{})" if tail else "{}"
    return (re.compile(group.format("|".join(a + b for a, b in pairs)) + tail),
            re.compile(group.format("|".join(b for _a, b in pairs)) + tail))


def _dl_finditer(pair, row, pos=0, endpos=None):
    """The exact regex's matches in `row` that start in [pos, endpos) — as
    finditer would give them — found through the candidate regex (whose match
    must end by endpos)."""
    exact, cand = pair
    end = len(row) if endpos is None else endpos
    while True:
        m = cand.search(row, pos, end)
        if m is None:
            return
        e = exact.match(row, m.start())
        if e is None:
            pos = m.start() + 1
            continue
        yield e
        pos = e.end() if e.end() > e.start() else e.start() + 1


# The received-code detector's shared data — name sets, character sets and
# limits — is authored once in received_spec.json and loaded by both engines
# (the npm engine reads its synced copy, js/src/lib/received-spec.json). A
# needle or a limit is edited in that one file; scripts/sync-received-spec.py
# copies it to the npm package and tests/architecture/test_received_spec.py
# fails if the copies drift. The patterns themselves are still defined below.
with open(os.path.join(os.path.dirname(__file__), "received_spec.json"), encoding="utf-8") as _dl_spec_f:
    _DL_SPEC = json.load(_dl_spec_f)
_DL_SPEC_ARRAYS, _DL_SPEC_CHARS, _DL_SPEC_LIMITS = _DL_SPEC["arrays"], _DL_SPEC["charstrings"], _DL_SPEC["limits"]
_DL_SPEC_PATTERNS, _DL_SPEC_ALTS = _DL_SPEC["patterns"], _DL_SPEC["alternatives"]
_DL_RE_FLAGS = {"i": re.I, "m": re.M, "s": re.S}


def _dl_flags(spec):
    f = 0
    for ch in spec:
        f |= _DL_RE_FLAGS[ch]
    return f


def _dl_re(name):
    """A plain received-code pattern, compiled from the spec."""
    p = _DL_SPEC_PATTERNS[name]
    return re.compile(p["src"], _dl_flags(p["flags"]))


def _dl_group(name):
    """An (exact, candidate) alternative pair built from the spec (see
    _dl_alternatives); `extends` prepends another group's pairs."""
    g = _DL_SPEC_ALTS[name]
    base = _DL_SPEC_ALTS[g["extends"]]["pairs"] if "extends" in g else []
    pairs = [tuple(pr) for pr in list(base) + g["pairs"]]
    return _dl_alternatives(pairs, g.get("tail", ""))


# Every source match, and every import of a network module, holds a network
# needle; every runner a run needle; a deserializer a deserial needle
# (pickle / marshal / a full yaml.load / node-serialize unserialize, CWE-502);
# a dynamic import an import needle (import(x), require(x), __import__(x),
# importlib.import_module(x)). Only rows holding one are read. The patterns and
# name sets are the spec's; the notes there say what each matches.
_DL_SOURCE = _dl_group("_DL_SOURCE")            # a value received over the network
_DL_SOURCE_RE, _DL_SOURCE_CANDIDATE_RE = _DL_SOURCE
_DL_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_NEEDLES"])
_DL_NEEDLE_RE = re.compile("|".join(re.escape(n) for n in sorted(_DL_NEEDLES, key=lambda n: (-len(n), n))))
_DL_RUN_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_RUN_NEEDLES"])
_DL_DESERIAL_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_DESERIAL_NEEDLES"])
_DL_IMPORT_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_IMPORT_NEEDLES"])
_DL_SINK_NEEDLES = _DL_RUN_NEEDLES + _DL_DESERIAL_NEEDLES + _DL_IMPORT_NEEDLES   # the file-level gate
_DL_MODULE_VALUE_RE = _dl_re("_DL_MODULE_VALUE_RE")
_DL_FUNCTION_VALUE_RE = _dl_re("_DL_FUNCTION_VALUE_RE")
_DL_IMPORT_RE = _dl_re("_DL_IMPORT_RE")
_DL_PY_NET_MODULES = frozenset(_DL_SPEC_ARRAYS["_DL_PY_NET_MODULES"])
_DL_LONG_ROW = _DL_SPEC_LIMITS["_DL_LONG_ROW"]
_DL_WINDOW = _DL_SPEC_LIMITS["_DL_WINDOW"]
_DL_ARG_SPAN = _DL_SPEC_LIMITS["_DL_ARG_SPAN"]
_DL_LOOKBACK = _DL_SPEC_LIMITS["_DL_LOOKBACK"]
_DL_NAMED_SEARCHES = _DL_SPEC_LIMITS["_DL_NAMED_SEARCHES"]   # names looked up by a search each; the rest via an index
_DL_PHASES = _DL_SPEC_LIMITS["_DL_PHASES"]                   # readings of a row's quotes begun at a call's '('
_DL_CHAIN_RE = _dl_re("_DL_CHAIN_RE")
_DL_HEAD_RE = _dl_re("_DL_HEAD_RE")
_DL_WORD_RUN_RE = _dl_re("_DL_WORD_RUN_RE")
_DL_STR_RE = _dl_re("_DL_STR_RE")
_DL_TEMPLATE_HOLE_RE = _dl_re("_DL_TEMPLATE_HOLE_RE")
_DL_FSTRING_HOLE_RE = _dl_re("_DL_FSTRING_HOLE_RE")
_DL_PREFIX_CHARS = frozenset(_DL_SPEC_CHARS["_DL_PREFIX_CHARS"])
_DL_BIND_RE = _dl_re("_DL_BIND_RE")
_DL_PARAMS_RE = _dl_re("_DL_PARAMS_RE")
_DL_FN_HEADER_RE = _dl_re("_DL_FN_HEADER_RE")
_DL_NAME_RE = _dl_re("_DL_NAME_RE")
_DL_DEFAULT_RE = _dl_re("_DL_DEFAULT_RE")
_DL_DOT_RE = _dl_re("_DL_DOT_RE")
_DL_NOT_NAMES = frozenset(_DL_SPEC_ARRAYS["_DL_NOT_NAMES"])
_DL_RUNNER = _dl_group("_DL_RUNNER")            # a call that runs its argument as code
_DL_RUNNER_RE, _DL_RUNNER_CANDIDATE_RE = _DL_RUNNER
_DL_SHELL_TRUE_RE = _dl_re("_DL_SHELL_TRUE_RE")
_DL_SHELL_CALL_RE = _dl_re("_DL_SHELL_CALL_RE")
_DL_SHELL_ARG_RE = _dl_re("_DL_SHELL_ARG_RE")
_DL_RUNNER_SHELL = _dl_group("_DL_RUNNER_SHELL")   # the runners plus run-family calls (when the file has shell=True)
_DL_RUNNER_SHELL_RE, _DL_RUNNER_SHELL_CANDIDATE_RE = _DL_RUNNER_SHELL
_DL_DESERIAL = _dl_group("_DL_DESERIAL")        # a deserializer that runs code embedded in its argument (CWE-502)
_DL_DESERIAL_RE, _DL_DESERIAL_CANDIDATE_RE = _DL_DESERIAL
_DL_IMPORT_SINK = _dl_group("_DL_IMPORT_SINK")  # a dynamic import of a received specifier
_DL_IMPORT_SINK_RE, _DL_IMPORT_SINK_CANDIDATE_RE = _DL_IMPORT_SINK
_DL_FROM_IMPORT_RE = _dl_re("_DL_FROM_IMPORT_RE")   # a Python from-import line: the bare import( sink is skipped there
_DL_BARE_IMPORT_RE = _dl_re("_DL_BARE_IMPORT_RE")
_DL_ALIAS_RE = _dl_re("_DL_ALIAS_RE")           # a runner-alias definition (name = a direct code-runner reference)
_DL_ALIAS_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_ALIAS_NEEDLES"])
_DL_ALIAS_MAX = _DL_SPEC_LIMITS["_DL_ALIAS_MAX"]       # a file's alias names, at most
_DL_DEFINING = tuple(_DL_SPEC_ARRAYS["_DL_DEFINING"])
_DL_INTERP = _dl_group("_DL_INTERP")            # an interpreter given inline code as argv (['node','-e',CODE])
_DL_INTERP_RE, _DL_INTERP_CANDIDATE_RE = _DL_INTERP
_DL_EMBED_RE = _dl_re("_DL_EMBED_RE")           # ... or written into its command line (`node -e ${code}`)
_DL_LEAD_RE = _dl_re("_DL_LEAD_RE")
_DL_CALLEE_RE = _dl_re("_DL_CALLEE_RE")
_DL_CALLEE_CHARS = frozenset(_DL_SPEC_CHARS["_DL_CALLEE_CHARS"])
_DL_BRACKET_RE = _dl_re("_DL_BRACKET_RE")


def _dl_lhs_names(lhs):
    """The names an assignment's left side binds (a member chain stays whole)."""
    lhs = lhs.strip()
    if lhs[:1] in "{[":
        return [n for n in _DL_NAME_RE.findall(lhs) if n not in _DL_NOT_NAMES]
    out = []
    for part in lhs.split(","):
        part = _DL_DOT_RE.sub(".", part.strip())
        if part and part not in _DL_NOT_NAMES:
            out.append(part)
    return out


def _dl_defined_here(row, i):
    """Is the call at row[i] the name in a definition: def exec(…),
    function exec(…), async exec(…)?"""
    j = i
    while j > 0 and row[j - 1].isspace():
        j -= 1
    if j == i:
        return False
    for word in _DL_DEFINING:
        s = j - len(word)
        if s >= 0 and row.startswith(word, s) and (s == 0 or not (row[s - 1] == "_" or row[s - 1].isalnum())):
            return True
    return False


def _dl_any(offsets, lo, hi):
    """Is one of the sorted offsets in [lo, hi)?"""
    i = bisect.bisect_left(offsets, lo)
    return i < len(offsets) and offsets[i] < hi


def _dl_within(starts, ends, lo, hi):
    """Is one of the spans (sorted, not overlapping) inside [lo, hi)?"""
    i = bisect.bisect_left(starts, lo)
    return i < len(starts) and ends[i] <= hi


class _DlTaint:
    """The names holding a received value, with the row each was last bound
    on (followed for _DL_WINDOW rows), and the names that carry the network
    wherever they are used (network modules, functions returning a received
    value). `heads` holds their first names: a row naming none of them uses
    none."""

    def __init__(self, always):
        self.always = set(always)
        self.at = {}
        self.heads = {n.split(".")[0] for n in self.always}

    def name_live(self, name, row):
        """Is `name` such a name at `row`?"""
        if name in self.always:
            return True
        t = self.at.get(name)
        return t is not None and row - t <= _DL_WINDOW

    def live(self, chain, row):
        """Is `chain`, or a chain it is a property of, such a name at `row`?"""
        acc = None
        for part in _DL_DOT_RE.split(chain):
            acc = part if acc is None else acc + "." + part
            if self.name_live(acc, row):
                return True
        return False


def _dl_carried(row, i, taint, k):
    """Does the value at row[i] begin with a received value — a source or a
    tainted name (None: sources only) — seen through await, parentheses and
    up to three wrapping calls (compile(code, …), Buffer.from(body, 'base64'))?
    It is read for _DL_ARG_SPAN characters after the whitespace, `await`s
    and parentheses it starts with."""
    i = _DL_LEAD_RE.match(row, i).end()
    limit = min(len(row), i + _DL_ARG_SPAN)
    for n in range(4):
        if n:
            i = _DL_LEAD_RE.match(row, i, limit).end()
        m = _DL_CALLEE_RE.match(row, i, limit)
        if m is None:
            return False
        if _DL_SOURCE_RE.search(row, i, m.end()) or (taint is not None and taint.live(m.group("chain"), k)):
            return True
        if m.group("call") is None:
            return False
        i = m.end()
    return False


class _DlCode:
    """row[lo:hi] read as code: its text with each string literal's contents
    blanked (the quotes kept, so offsets hold), and the literals' spans. A
    literal's contents are read as code too, on demand: quotes do not always
    pair as the language pairs them (an apostrophe in a comment, a regex
    literal), and a program for `node -e` is written in one. Each read once,
    on demand: its brackets matched (each opener's closer, the commas
    directly inside it, the innermost '(' open at given offsets), its member
    chains with those a name reaches, and its template literals and f-strings
    interpolating a live chain. Brackets match whatever their kind; offsets
    are the row's."""
    __slots__ = ("row", "lo", "hi", "lit_s", "lit_e", "code", "close", "opener", "commas", "open_paren", "es",
                 "inner", "by", "live", "holes")

    def __init__(self, row, lo, hi):
        self.row, self.lo, self.hi = row, lo, hi
        parts, self.lit_s, self.lit_e, at = [], [], [], lo
        for m in _DL_STR_RE.finditer(row, lo, hi):
            s, e = m.span()
            parts.append(row[at:s + 1])
            parts.append(" " * (e - s - 2))
            at = e - 1
            self.lit_s.append(s)
            self.lit_e.append(e)
        parts.append(row[at:hi])
        self.code = "".join(parts)
        self.close = self.opener = self.commas = None
        self.open_paren, self.es, self.inner = {}, {}, {}
        self.by, self.live, self.holes = None, [], None

    def literal_at(self, p):
        """The index of the literal whose contents hold offset p, else -1."""
        i = bisect.bisect_right(self.lit_s, p) - 1
        return i if i >= 0 and self.lit_s[i] < p < self.lit_e[i] - 1 else -1

    def segment_at(self, p):
        """The code holding offset p: this, or a literal's contents read as code."""
        i = self.literal_at(p)
        if i < 0:
            return self
        seg = self.inner.get(i)
        if seg is None:
            seg = self.inner[i] = _DlCode(self.row, self.lit_s[i] + 1, self.lit_e[i] - 1)
        return seg.segment_at(p)

    def brackets(self, queries=()):
        """Match the brackets, once; `queries`: sorted offsets to find the
        innermost open '(' at (in open_paren; None where there is none)."""
        if self.close is not None:
            return
        close, opener, commas, answers = {}, {}, {}, self.open_paren
        stack, parens, qi, lo = [], [], 0, self.lo
        for m in _DL_BRACKET_RE.finditer(self.code):
            q, ch = m.start() + lo, m.group()
            while qi < len(queries) and queries[qi] <= q:
                answers[queries[qi]] = parens[-1] if parens else None
                qi += 1
            if ch == ",":
                if stack:
                    commas.setdefault(stack[-1], []).append(q)
            elif ch in "([{":
                stack.append(q)
                if ch == "(":
                    parens.append(q)
            elif stack:
                o = stack.pop()
                if parens and parens[-1] == o:
                    parens.pop()
                close[o] = q
                opener[q] = o
        for p in queries[qi:]:
            answers[p] = parens[-1] if parens else None
        self.close, self.opener, self.commas = close, opener, commas

    def expr_start(self, j):
        """Where the expression a '(' at offset j is applied to starts —
        `https.get` for `https.get(`, `fetch(u).then` for `fetch(u).then(`, a
        group of brackets skipped whole — or None when that runs into a ')'
        or ']' without an opener. Each offset is walked once."""
        memo, code, lo, n = self.es, self.code, self.lo, len(self.code)
        path, q = [], j
        while True:
            res = memo.get(q, memo)
            if res is not memo:
                break
            path.append(q)
            r = q - lo
            if r == 0:
                res = q
                break
            ch = code[r - 1]
            if ch in _DL_CALLEE_CHARS:
                q -= 1
            elif ch == ")" or ch == "]":
                o = self.opener.get(q - 1)
                if o is None:
                    res = None
                    break
                q = o
            elif (ch == " " or ch == "\t") and ((r < n and code[r] == ".") or (r >= 2 and code[r - 2] == ".")):
                q -= 1                                  # `a . b`, a chain's indentation
            else:
                res = q
                break
        for p in path:
            memo[p] = res
        return res

    def index(self, taint, k):
        """Index the member chains, and find those the taint reaches at row k."""
        self.by = by = _dl_chain_index(self.code, self.lo)
        self.live = sorted(s for name, offs in by.items() if taint.name_live(name, k) for s in offs)

    def bound(self, name):
        """`name` is now live: the chains it starts are too."""
        for s in self.by.get(name, ()):
            bisect.insort(self.live, s)

    def live_holes(self, taint, k):
        """(starts, ends) of the template literals and f-strings that
        interpolate a chain the taint reaches at row k."""
        if self.holes is None:
            starts, ends, row = [], [], self.row
            for s, e in zip(self.lit_s, self.lit_e):
                if row[s] == "`":
                    holes = _DL_TEMPLATE_HOLE_RE.findall(row, s, e)
                else:
                    pre = row[max(self.lo, s - 2):s]
                    while pre and pre[0] not in _DL_PREFIX_CHARS:
                        pre = pre[1:]
                    if "f" not in pre and "F" not in pre:
                        continue
                    holes = _DL_FSTRING_HOLE_RE.findall(row, s, e)
                if holes and any(taint.live(c.group(), k) for c in _DL_CHAIN_RE.finditer(" ".join(holes))):
                    starts.append(s)
                    ends.append(e)
            self.holes = (starts, ends)
        return self.holes


def _dl_chain_index(code, lo=0):
    """The member chains of `code` (strings blanked) by the names they start
    with — 'r' and 'r.text' for r.text — as {name: [offset, …]}."""
    by = {}
    for m in _DL_CHAIN_RE.finditer(code):
        c, s = m.group(), m.start() + lo
        if "." not in c:
            by.setdefault(c, []).append(s)
            continue
        acc = None
        for part in _DL_DOT_RE.split(c):
            acc = part if acc is None else acc + "." + part
            by.setdefault(acc, []).append(s)
    return by


class _DlNamed:
    """The rows where a name stands whole ([\\w$]+ runs are names). The first
    _DL_NAMED_SEARCHES names are each found by a search of the text; the
    rest from an index of its names, built once."""

    def __init__(self, text, rows, starts):
        self.text, self.rows, self.starts = text, rows, starts
        self.searches, self.index = 0, None

    def find(self, name):
        head = name.split(".")[0]
        if _DL_WORD_RUN_RE.fullmatch(head) is None:
            return ()
        if self.index is None and self.searches < _DL_NAMED_SEARCHES:
            self.searches += 1
            esc = re.escape(head)
            rx = re.compile(esc + r"(?<![\w$]" + esc + r")(?![\w$])")
            out, text, starts = [], self.text, self.starts
            m = rx.search(text)
            while m is not None:
                k = bisect.bisect_right(starts, m.start()) - 1
                out.append(k)
                if k + 1 >= len(starts):
                    break
                m = rx.search(text, starts[k + 1])
            return out
        if self.index is None:
            index = {}
            for k, row in enumerate(self.rows):
                for word in set(_DL_WORD_RUN_RE.findall(row)):
                    index.setdefault(word, []).append(k)
            self.index = index
        return self.index.get(head, ())


def _dl_import_names(rows, cand):
    """The names a network module is imported under, on the rows `cand`."""
    out = set()
    for k in sorted(cand):
        row = rows[k]
        if "import" not in row or len(row) > _DL_LONG_ROW:
            continue
        for m in _DL_IMPORT_RE.finditer(row):
            if m.group("py") is not None:
                for item in m.group("py").split(","):
                    parts = item.split()
                    if parts and parts[0] in _DL_PY_NET_MODULES:
                        out.add(parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0])
                continue
            items = m.group("pyfrom") if m.group("pyfrom") is not None else m.group("esn")
            if items is None:
                out.add(m.group("es"))
                continue
            for item in items.split(","):
                parts = item.split()
                if parts:
                    out.add(parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0])
    return out


def _dl_header(row):
    """What a row says about the function a `return` below it belongs to:
    the function's name on a function header, '' on a minified row (the
    search stops there), None on any other row."""
    if len(row) > _DL_LONG_ROW:
        return ""
    h = _DL_FN_HEADER_RE.search(row)
    return None if h is None else (h.group("py") or h.group("js") or h.group("var"))


def _dl_row_above(rows, k):
    """The nearest non-blank row above k (in the window), unless minified."""
    for j in range(k - 1, max(-1, k - _DL_WINDOW - 1), -1):
        if rows[j].strip():
            return j if len(rows[j]) <= _DL_LONG_ROW else None
    return None


class _DlRow:
    """One row (or a minified row's stretch) as runs_received_code reads it:
    its code (quotes paired from its start) for what it binds, and for its
    runners' arguments, quotes paired from each call's '(': the row's own
    pairing where that is in step, else a reading begun at the '(' (at most
    _DL_PHASES of those), as a language pairs them wherever the row's
    earlier quotes are something else (an apostrophe in a comment, a regex
    literal's quote)."""
    __slots__ = ("reader", "k", "row", "taint", "hi", "top", "phases", "src_s", "src_e", "dirty", "indexed")

    def __init__(self, reader, k, row, lo, hi, taint, sources, top=True):
        self.reader, self.k, self.row, self.taint, self.hi = reader, k, row, taint, hi
        self.top = _DlCode(row, lo, hi) if top else None
        self.phases = [self.top] if top else []
        self.src_s = [s for s, _e in sources]            # (start, end) of the sources read, sorted
        self.src_e = [e for _s, e in sources]
        self.dirty = False                               # can a chain here be live?
        self.indexed = []                                # the codes whose chains are indexed

    def live(self, seg):
        """The sorted offsets of seg's chains the taint reaches (indexed on first use)."""
        if seg.by is None:
            seg.index(self.taint, self.k)
            self.indexed.append(seg)
        return seg.live

    def bound(self, name):
        """`name` is now live: the chains it starts are too."""
        for seg in self.indexed:
            seg.bound(name)

    def phase_at(self, o):
        """The code a call's '(' at offset o is read in: one where it is not
        in a literal, else a reading begun there (None past _DL_PHASES)."""
        for ph in self.phases:
            if ph.lo <= o < ph.hi and ph.literal_at(o) < 0:
                return ph
        if len(self.phases) - (self.top is not None) >= _DL_PHASES:
            return None
        ph = _DlCode(self.row, o, self.hi)
        self.phases.append(ph)
        return ph

    def runs(self, r, taint):
        """Is the runner call `r` handed a received value (taint None: a
        download only) — as an argument, or written into an interpreter's
        command line?"""
        row, k = self.row, self.k
        if _dl_defined_here(row, r.start()):
            return False                                # def exec(…), function exec(…)
        if _DL_SHELL_CALL_RE.fullmatch(r.group()) and not self.reader.shell_within(k, row, r.end()):
            return False                                # run(…) without shell=True
        o = r.end() - 1
        if o >= self.hi:
            return False                                # its '(' is past what is read
        ph = self.phase_at(o)
        if ph is None:
            return False
        ph.brackets()
        end = min(ph.hi, o + 1 + _DL_ARG_SPAN)
        c = ph.close.get(o)
        close = c if c is not None and c < end else None
        if close is not None and row[close + 1:close + 3].lstrip()[:1] == "{":
            return False                                # a method definition: exec(x) {
        starts, ends = [o + 1], []
        for x in ph.commas.get(o, ()):
            if x >= end:
                break
            ends.append(x)
            starts.append(x + 1)
        ends.append(end if close is None else close)
        src_s, src_e = self.src_s, self.src_e
        if taint is not None and self.dirty:
            live, holes = self.live(ph), ph.live_holes(taint, k)
        else:
            live, holes = (), ((), ())
        # each argument's value, read to its end, or where the call's are cut, as
        # _dl_carried reads it; one with nothing received in it is not read
        last = len(starts) - 1
        for i, (s, e) in enumerate(zip(starts, ends)):
            if close is None and i == last:
                e = min(self.hi, _DL_LEAD_RE.match(row, s).end() + _DL_ARG_SPAN)
            if (_dl_any(src_s, s, e) or _dl_any(live, s, e)) and _dl_carried(row, s, taint, k):
                return True
        s, e = starts[0], ends[0]
        if _DL_EMBED_RE.match(row, s, e) is None:
            return False
        return _dl_within(src_s, src_e, s, e) or _dl_any(live, s, e) or _dl_within(holes[0], holes[1], s, e)


class _DlReader:
    """runs_received_code's pass over the rows: what each row binds, and
    whether it runs a received value."""

    def __init__(self, text, rows, starts, taint, sources, runners, named, seeds, sinks):
        self.text, self.rows, self.starts, self.taint = text, rows, starts, taint
        self.sources, self.runners, self.named, self.seeds = sources, runners, named, seeds
        # extra sink families to scan, as (category, alternatives): deserialize
        # and dynamic import, each added only when the file names one
        self.sinks = sinks
        self.aliases = {}                                # runner-alias name -> [definition rows]
        self.alias_call = None                           # a call of any runner alias, or None
        self.until = -1
        self.headers = {}                                # row -> _dl_header, as read
        self.last_top = (-1, None)                       # the row read last, and its code
        self.shell_row, self.shell = -1, ()              # offsets of `shell=True` on that row

    def shell_within(self, k, row, i):
        """Does a `shell=True` start within _DL_ARG_SPAN characters after row[i]?"""
        if self.shell_row != k:
            self.shell_row, self.shell = k, [m.start() for m in _DL_SHELL_ARG_RE.finditer(row)]
        return _dl_any(self.shell, i, i + _DL_ARG_SPAN + 1)

    def short_row(self, k, row):
        """Read a row of ordinary length; the category it runs a received value
        as (see runs_received_code), or None."""
        taint, rows = self.taint, self.rows
        heads = taint.heads
        found = bool(heads) and not heads.isdisjoint(_DL_HEAD_RE.findall(row))
        hot = k in self.sources
        above = _dl_row_above(rows, k) if row.lstrip()[:1] == "." else None
        if not (hot or found or (above is not None and (above in self.sources or (
                bool(heads) and not heads.isdisjoint(_DL_HEAD_RE.findall(rows[above])))))):
            return None                                  # names nothing received: binds and runs none
        srcs = [m.span() for m in _dl_finditer(_DL_SOURCE, row)] if hot else []
        rd = _DlRow(self, k, row, 0, len(row), taint, srcs)
        rd.dirty = found
        top = rd.top
        # [kind, lo, hi, match or names, continued, code]: what a fact binds from
        # row[lo:hi], its sources anywhere there, its chains in the code it is in
        facts = []
        semi = -1
        binds = _DL_BIND_RE.finditer(row) if ("=" in row or "as" in row or "for" in row or "return" in row) else ()
        for m in binds:
            seg = top.segment_at(m.start())
            if m.group("ann") is not None or m.group("lhs") or m.group("ret") is not None:
                lo = m.end()
                if semi < lo:
                    semi = row.find(";", lo)
                    semi = len(row) if semi < 0 else semi
                kind, lo, hi = ("return" if m.group("ret") is not None else "bind"), lo, semi
            elif m.group("with"):
                kind, lo, hi = "with", 0, m.start()
            else:
                kind, lo, hi = "for", m.end(), len(row)
            facts.append([kind, lo, hi, m, False, seg])
        params, queries = [], {}
        for m in (_DL_PARAMS_RE.finditer(row) if ("=>" in row or "function" in row or "lambda" in row) else ()):
            ps = m.group("fp") or m.group("ap") or m.group("one") or m.group("lp") or ""
            names = [n for n in _DL_NAME_RE.findall(_DL_DEFAULT_RE.sub("", ps)) if n not in _DL_NOT_NAMES]
            if names:
                seg = top.segment_at(m.start())
                params.append((m.start(), names, seg))
                queries.setdefault(id(seg), (seg, []))[1].append(m.start())
        for seg, offsets in queries.values():
            seg.brackets(offsets)
        first = len(row) - len(row.lstrip())
        for p, names, seg in params:
            j = seg.open_paren.get(p)
            start = None if j is None else seg.expr_start(j)
            if start is None:
                continue
            continued = seg is top and start <= first < j and row[first] == "."
            facts.append(["param", start, j, names, continued, seg])
        # which facts hold a received value; binding their names can feed the others
        above_by, above_live = None, False
        if above is not None and any(f[4] for f in facts):
            if above in self.sources:
                above_live = True
            else:
                j, code = self.last_top
                if j == above and code.by is not None:
                    above_by = code.by                   # (read just now: its chains are indexed)
                else:
                    a_row = rows[above]
                    above_by = _dl_chain_index(_DlCode(a_row, 0, len(a_row)).code)
                above_live = any(taint.name_live(n, k) for n in above_by)
        added = []
        pending = facts
        for _ in range(3):
            grew = False
            rest = []
            for f in pending:
                lo, hi, seg = f[1], f[2], f[5]
                if not (_dl_within(rd.src_s, rd.src_e, lo, hi) or (f[4] and above_live)
                        or (rd.dirty and _dl_any(rd.live(seg), lo, hi))):
                    rest.append(f)
                    continue
                names, how = self._names(f, row, k)
                for name in names:
                    if how == "always":
                        if name in taint.always:
                            continue
                        taint.always.add(name)
                        added.append(name)
                    elif taint.at.get(name) != k:
                        taint.at[name] = k
                        self.until = max(self.until, k + _DL_WINDOW)
                    else:
                        continue
                    grew = rd.dirty = True
                    taint.heads.add(name.split(".")[0])
                    rd.bound(name)
                    if above_by is not None and name in above_by:
                        above_live = True
            pending = rest
            if not grew:
                break
        for name in added:
            for r in self.named.find(name):
                if r > k:
                    self.seeds[r] = 1
        self.last_top = (k, top)
        # its runners, with what it binds
        for r in _dl_finditer(self.runners, row):
            if rd.runs(r, taint):
                return "run"
        for r in _dl_finditer(_DL_INTERP, row):
            if _dl_carried(row, r.end(), taint, k):
                return "run"
        from_import = bool(self.sinks) and _DL_FROM_IMPORT_RE.match(row) is not None
        for cat, sink in self.sinks:                      # deserialize, import
            for r in _dl_finditer(sink, row):
                if from_import and _DL_BARE_IMPORT_RE.fullmatch(r.group()):
                    continue                              # a Python from-import list, not import()
                if rd.runs(r, taint):
                    return cat
        if self.alias_call is not None:                   # a call of a runner alias near its definition
            for r in self.alias_call.finditer(row):
                if _dl_alias_near(self.aliases[r.group(1)], k) and rd.runs(r, taint):
                    return "run"
        return None

    def _names(self, f, row, k):
        """(names, how) a fact that holds a received value binds: how is
        'value' (followed for _DL_WINDOW rows) or 'always'."""
        kind = f[0]
        if kind == "param":
            return f[3], "value"
        m = f[3]
        if kind == "bind":
            names = [m.group("ann")] if m.group("ann") is not None else _dl_lhs_names(m.group("lhs"))
            names = [n for n in names if n not in _DL_NOT_NAMES]
            if len(names) == 1 and "." not in names[0]:
                lo, hi = f[1], f[2]
                if _DL_MODULE_VALUE_RE.match(row, lo, hi):
                    return names, "always"
                if len(names[0]) >= 3 and _DL_FUNCTION_VALUE_RE.match(row, lo, hi):
                    return names, "always"             # const load = (u) => fetch(u)
            return names, "value"
        if kind == "with":
            return [m.group("with")], "value"
        if kind == "for":
            return _dl_lhs_names(m.group("for")), "value"
        # return VALUE: the function whose header is nearest above carries it
        fn = self.function_above(k)
        return ([fn] if fn and len(fn) >= 3 else []), "always"

    def function_above(self, k):
        """The function a `return` on row k belongs to: the name on the
        nearest function header at or above it within _DL_WINDOW rows ('' past
        a minified row), else None."""
        headers, rows = self.headers, self.rows
        for j in range(k, max(-1, k - _DL_WINDOW - 1), -1):
            h = headers.get(j, headers)
            if h is headers:
                h = headers[j] = _dl_header(rows[j])
            if h is not None:
                return h
        return None

    def long_row(self, k, row):
        """Read a minified row: only a download written straight into a
        sink's arguments, a sink that starts within _DL_LOOKBACK characters
        before a network name (the stretches merged: one pass at most). The
        category it runs a received value as, or None."""
        stretches = []
        for n in _DL_NEEDLE_RE.finditer(row):
            lo = max(0, n.start() - _DL_LOOKBACK)
            if stretches and lo <= stretches[-1][1]:
                stretches[-1][1] = n.start()
            else:
                stretches.append([lo, n.start()])
        families = [("run", self.runners)] + list(self.sinks)
        from_import = bool(self.sinks) and _DL_FROM_IMPORT_RE.match(row) is not None
        for lo, hi in stretches:
            end = min(len(row), hi + 3 * _DL_ARG_SPAN)     # a sink's name, its arguments, the last one's value
            rd = None
            search_end = min(end, hi + _DL_ARG_SPAN)
            for cat, family in families:
                for r in _dl_finditer(family, row, lo, search_end):
                    if r.start() >= hi:
                        break
                    if from_import and cat == "import" and _DL_BARE_IMPORT_RE.fullmatch(r.group()):
                        continue                           # a Python from-import list, not import()
                    if rd is None:
                        rd = _DlRow(self, k, row, lo, end, None,
                                    [m.span() for m in _dl_finditer(_DL_SOURCE, row, lo, end)], top=False)
                    if rd.runs(r, None):
                        return cat
            for r in _dl_finditer(_DL_INTERP, row, lo, search_end):
                if r.start() >= hi:
                    break
                if _dl_carried(row, r.end(), None, k):
                    return "run"
        return None


def _dl_runner_aliases(rows):
    """{name: [definition rows]} for names bound to a direct code-runner
    reference (see _DL_ALIAS_RE): a call of one within _DL_WINDOW rows below
    its definition is a runner. Window-scoped like a received value, so a
    short name reused far away (`const F = Function` in a bundle) is not a
    runner everywhere. Read from rows naming a runner and holding '='; at
    most _DL_ALIAS_MAX names are kept."""
    defs = {}
    for k, row in enumerate(rows):
        if "=" not in row or len(row) > _DL_LONG_ROW or not any(nd in row for nd in _DL_ALIAS_NEEDLES):
            continue
        for m in _DL_ALIAS_RE.finditer(row):
            name = m.group("alias")
            if name in _DL_NOT_NAMES:
                continue
            if name not in defs:
                if len(defs) >= _DL_ALIAS_MAX:
                    continue
                defs[name] = []
            defs[name].append(k)
    return defs


def _dl_alias_near(def_rows, k):
    """Is a definition row at or within _DL_WINDOW rows above k?"""
    i = bisect.bisect_right(def_rows, k) - 1
    return i >= 0 and k - def_rows[i] <= _DL_WINDOW


def _received_code_kind(text, extra_always=()):
    """(1-based line, category) for the first place code runs, deserializes or
    imports a value it received over the network (see runs_received_code), or
    None. Category is 'run', 'deserialize' or 'import'.

    extra_always: names known from another file of the same package to hold or
    return a received value (the Python-only cross-file follower,
    _cross_file_received_issues). They are seeded exactly like this file's own
    network-module import names, so a sink that runs one fires. Empty by
    default, so single-file behaviour — and the npm twin, which never passes it
    — is unchanged, and the parity corpus still agrees."""
    if not any(n in text for n in _DL_SINK_NEEDLES):
        return None
    if not extra_always and not any(n in text for n in _DL_NEEDLES):
        return None
    rows = text.split("\n")
    starts, at = [], 0
    for row in rows:
        starts.append(at)
        at += len(row) + 1
    near = set()                                        # rows holding a network name
    m = _DL_NEEDLE_RE.search(text)
    while m is not None:
        k = bisect.bisect_right(starts, m.start()) - 1
        near.add(k)
        m = _DL_NEEDLE_RE.search(text, starts[k + 1]) if k + 1 < len(starts) else None
    taint = _DlTaint(list(_dl_import_names(rows, near) if "import" in text else ()) + list(extra_always))
    sources = {k for k in near
               if len(rows[k]) > _DL_LONG_ROW or next(_dl_finditer(_DL_SOURCE, rows[k]), None) is not None}
    if not taint.always and not sources:
        return None
    named = _DlNamed(text, rows, starts)
    seeds = bytearray(len(rows))                        # rows where a received value can start
    for r in sources:
        seeds[r] = 1
    for name in taint.always:
        for r in named.find(name):
            seeds[r] = 1
    aliases = _dl_runner_aliases(rows) if any(nd in text for nd in _DL_ALIAS_NEEDLES) else {}
    alias_call = None
    if aliases:                                         # a call of a runner alias, near its definition, is a runner
        alias_call = re.compile(r"""(?<![\w$.])(""" + "|".join(re.escape(n) for n in sorted(aliases)) + r""")\s*\(""")
        for name, def_rows in aliases.items():
            for r in named.find(name):
                seeds[r] = 1
    shell_on = "shell" in text and _DL_SHELL_TRUE_RE.search(text) is not None
    runners = _DL_RUNNER_SHELL if shell_on else _DL_RUNNER
    sinks = []                                          # the extra sink families this file names
    if any(n in text for n in _DL_DESERIAL_NEEDLES):
        sinks.append(("deserialize", _DL_DESERIAL))
    if any(n in text for n in _DL_IMPORT_NEEDLES):
        sinks.append(("import", _DL_IMPORT_SINK))
    reader = _DlReader(text, rows, starts, taint, sources, runners, named, seeds, sinks)
    reader.aliases, reader.alias_call = aliases, alias_call
    # Rows are read in order, from a seed on for _DL_WINDOW rows (and as long
    # as a value is bound): a row outside every such stretch can neither bind
    # a received value nor run one, so it is skipped.
    k = seeds.find(1)
    k = len(rows) if k < 0 else k
    while k < len(rows):
        row = rows[k]
        if len(row) > _DL_LONG_ROW:
            cat = reader.long_row(k, row)
            if cat:
                return k + 1, cat
        else:
            if seeds[k]:
                reader.until = max(reader.until, k + _DL_WINDOW)
            cat = reader.short_row(k, row)
            if cat:
                return k + 1, cat
        nk = k + 1
        if nk > reader.until:
            nk = seeds.find(1, nk)
            nk = len(rows) if nk < 0 else nk
        k = nk
    return None


def runs_received_code(text):
    """The 1-based line where code runs, deserializes or dynamically imports a
    value it received over the network (see the section comment), else None.
    `text` has \\n line endings."""
    res = _received_code_kind(text)
    return res[0] if res is not None else None


# ---------------- Download to a file, then run the file ----------------
# A weaker, MAJOR-only signal (SC-IMPORT-RISK, never CRITICAL, and never
# escalating an install hook): a received value written to a file, and that
# same file then run — subprocess.run([sys.executable, dropped]), os.system(p),
# require(p), spawn('node', [p]). This shape is statically identical to what a
# prebuilt-binary installer does (node-pre-gyp / prebuild-install /
# node-gyp-build / esbuild download a platform binary and then run it), so it
# is deliberately not part of install_script_risk (which escalates a hook to
# CRITICAL): it is a capability to review, not a verdict.
# Kept precise by three requirements: a real network source within the window,
# a file WRITE naming a path, and a RUN of that same path (a name, or the same
# string literal) in the window after it. `text` costs one pass: only rows near
# a write are read, and each search is bounded.
# a received value written to a file, naming the path (a download-to-file API,
# or a write whose window holds a source); the run of that path is the opener
# of an interpreter/exec/require/import/subprocess call. Both patterns and the
# path-token grammar are in the spec (p4, urlretrieve, is a download-to-file on
# its own and needs no separate source).
_DL_FILE_WRITE_RE = _dl_re("_DL_FILE_WRITE_RE")
_DL_FILE_WRITE_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_FILE_WRITE_NEEDLES"])
_DL_PATHRUN_SINK_RE = _dl_re("_DL_PATHRUN_SINK_RE")
_DL_PATHRUN_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_PATHRUN_NEEDLES"])


def _dl_norm_path(tok):
    """A path token with its surrounding quotes and a leading "./" dropped, so
    a name and the literal that names the same file compare equal."""
    if tok[:1] in "\"'":
        tok = tok[1:-1]
        while tok[:2] == "./":
            tok = tok[2:]
    return tok


def _dl_path_token(m):
    """The normalized path token a _DL_FILE_WRITE_RE match names."""
    return _dl_norm_path(next(g for g in m.groups() if g is not None))


def _dl_region_names_path(region, path):
    """Does `region` (a run sink's arguments) name the file `path` — as the
    same identifier, or as a string literal for the same file?"""
    for m in _DL_NAME_RE.finditer(region):
        if m.group() == path:
            return True
    for m in _DL_STR_RE.finditer(region):
        if _dl_norm_path(m.group()) == path:
            return True
    return False


def _downloads_and_runs_file(text):
    """The 1-based line where a received value is written to a file that is then
    run (see the section comment), else None. MAJOR only."""
    if (not any(n in text for n in _DL_NEEDLES) or not any(n in text for n in _DL_FILE_WRITE_NEEDLES)
            or not any(n in text for n in _DL_PATHRUN_NEEDLES)):
        return None
    rows = text.split("\n")
    # rows holding a network source (a plain write must be near a real download;
    # urlretrieve is a download-to-file on its own)
    src = sorted(k for k, row in enumerate(rows)
                 if len(row) <= _DL_LONG_ROW and next(_dl_finditer(_DL_SOURCE, row), None) is not None)
    for k, row in enumerate(rows):
        if len(row) > _DL_LONG_ROW or not any(n in row for n in _DL_FILE_WRITE_NEEDLES):
            continue
        near_src = _dl_any(src, k - _DL_WINDOW, k + _DL_WINDOW + 1)
        for wm in _DL_FILE_WRITE_RE.finditer(row):
            if wm.group("p4") is None and not near_src:
                continue                                 # a plain write needs a download in its window
            path = _dl_path_token(wm)
            if not path:
                continue
            hit = _dl_pathrun_after(rows, k, path)
            if hit is not None:
                return hit + 1
    return None


def _dl_pathrun_after(rows, k, path):
    """The row index in [k, k+_DL_WINDOW] that runs the file named `path`
    (the same name, or the same string literal in a run sink's arguments),
    else None."""
    end = min(len(rows), k + _DL_WINDOW + 1)
    for j in range(k, end):
        row = rows[j]
        if len(row) > _DL_LONG_ROW or not any(n in row for n in _DL_PATHRUN_NEEDLES):
            continue
        for sm in _DL_PATHRUN_SINK_RE.finditer(row):
            if _dl_region_names_path(row[sm.end():sm.end() + _DL_ARG_SPAN], path):
                return j
    return None


# SC-PIPE-SHELL: a project's own code that runs a download piped into a shell
# (analyst gap: a bin script running `curl … | bash` passed a project scan,
# while the registry's import-time test catches it in a package). The same
# line test as the import-time one; a dependency's code gets that test
# instead (SC-IMPORT-RISK), so this rule is for first-party code.
_PIPE_SHELL_RULE = {
    "id": "SC-PIPE-SHELL", "name": "Download piped into a shell", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "Code runs a downloaded script through a shell.",
    "why": ("Piping a download into a shell runs whatever the server sends at that moment, with the "
            "program's privileges: nothing pins or checks it, so the server, or anyone who can change "
            "what it serves, decides what runs. Installers publish the line for people to paste once, "
            "after reading the script; code that runs it hands every run to that server."),
    "fix": "Download a pinned version, check its checksum or signature, and run that file; or drop the download.",
    "ref": "CWE-494 · Supply chain"}


# ---------------- Dependency drives your AI agent (SC-AGENT-HIJACK) ----------------
# A dependency that launches the user's own AI coding agent in an autonomous
# mode, to do the attacker's bidding, is the s1ngularity / Nx attack (Aug
# 2025, the first weaponized-AI-agent malware): a postinstall spawned
# `claude --dangerously-skip-permissions`, `gemini --yolo` and
# `q --trust-all-tools` with a prompt telling the agent to search the disk for
# secrets, wallets and SSH keys and write them out. A package has no reason to
# run your agent, and none at all to run it with the flag that turns off every
# confirmation. Dependency-only: an install-hook script or import-time code
# that hands a known agent CLI, with such a flag, to an exec/spawn call (your
# own automation driving your agent is your business). The bypass FLAG is the
# signal — on 118k real files only the agent tools themselves name these flags,
# and never next to an exec call — and a known agent name confirms it.
_AGENT_NAMES = r"claude|gemini|codex|aider|cline|opencode|cursor-agent|amazon-?q|qchat|q"
# In code a spawned binary is a string literal (a spawn target, "claude", or a
# command string, "claude --yolo"): require a quote before it, so a minified
# variable that happens to be named q is not one (a real false positive:
# @anthropic-ai/claude-code's minified cli.js packs a `q` variable, the flag
# string and an exec on one line). An install-hook COMMAND is a bare shell
# string, so there the binary is a shell token instead.
_AGENT_BIN_SRC = r"""(?<=["'])(?:""" + _AGENT_NAMES + r""")(?=["'\s])"""
_AGENT_BIN_CMD_SRC = r"(?<![\w./-])(?:" + _AGENT_NAMES + r")(?![\w./-])"
_AGENT_FLAG_SRC = (r"--(?:dangerously-skip-permissions|yolo|trust-all-tools"
                   r"|dangerously-bypass-approvals-and-sandbox|full-auto|yes-always|allow-all-tools)(?![\w-])"
                   r"|--(?:approval-mode|permission-mode)[=\s]+(?:yolo|bypassPermissions)")
_AGENT_BIN_RE = re.compile(_AGENT_BIN_SRC)
_AGENT_BIN_CMD_RE = re.compile(_AGENT_BIN_CMD_SRC)
_AGENT_FLAG_RE = re.compile(_AGENT_FLAG_SRC)


def agent_hijack(text):
    """-> (agent, flag, line) for the first line of dependency code that hands
    a known AI-agent CLI, with a flag that turns off its confirmations, to an
    exec/spawn call (see above), else None. `text` has \\n line endings."""
    if _AGENT_FLAG_RE.search(text) is None:
        return None
    for i, row in enumerate(text.split("\n")):
        if _EXEC_CALL_RE.search(row) is None:
            continue
        flag = _AGENT_FLAG_RE.search(row)
        binm = _AGENT_BIN_RE.search(row)
        if flag is not None and binm is not None:
            return binm.group().strip("'\""), flag.group(), i + 1
    return None


def agent_hijack_in_command(cmd):
    """-> (agent, flag) when an install-hook COMMAND launches the agent
    directly (the shell is the exec, so no exec call is needed), else None."""
    flag = _AGENT_FLAG_RE.search(cmd)
    binm = _AGENT_BIN_CMD_RE.search(cmd)
    if flag is not None and binm is not None:
        return binm.group().strip("'\""), flag.group()
    return None


_AGENT_HIJACK_WHY = (
    "A dependency that runs your AI coding agent hands the attacker your agent's access to your machine "
    "and accounts, and a flag like --dangerously-skip-permissions or --yolo runs it with every "
    "confirmation turned off: the s1ngularity / Nx attack spawned the agent from a postinstall hook to "
    "search the disk for secrets, wallets and SSH keys and write them out (the first weaponized-AI-agent "
    "malware). No package needs to launch your agent.")


def _agent_hijack_issue(path, line_no, lines, agent, flag, col=None, redactor=None):
    return mk_issue(
        {"id": "SC-AGENT-HIJACK", "name": "Dependency drives your AI agent", "type": "HOTSPOT", "sev": "CRITICAL",
         "msg": f"Dependency launches the {agent!r} AI agent with {flag} — running your coding agent "
                f"with its confirmations turned off.",
         "why": _AGENT_HIJACK_WHY,
         "fix": "Do not install or run this package; read what it tells the agent to do. Report it to the registry.",
         "ref": "CWE-506 · Supply chain"}, path, line_no, lines, col, redactor)


def dependency_agent_issue(path, text):
    """SC-AGENT-HIJACK (CRITICAL) for a dependency's file that launches an AI
    agent in an autonomous mode (agent_hijack), else None."""
    found = agent_hijack(text)
    if found is None:
        return None
    agent, flag, line = found
    lines = text.split("\n")
    return _agent_hijack_issue(path, line, lines, agent, flag, redactor=_Redactor(lines))


def node_candidates(rel):
    """Files Node tries for a path it is asked to run or load."""
    rel = rel.rstrip("/")
    return [rel, rel + ".js", rel + ".cjs", rel + ".mjs", rel + ".json", rel + ".node",
            rel + "/index.js", rel + "/index.cjs", rel + "/index.mjs", rel + "/index.json"]


# ---------------- Scripts by their #! line ----------------
# A file with no source extension still runs as code when its #! line names
# an interpreter: a package's bin/cli, a hook's ./setup. The line is the
# first line only (the kernel reads no further): `[ \t]`, never `\s`, which
# took the interpreter from the next line of `#!/usr/bin/env` + newline.
_SHEBANG_RE = re.compile(r"^#![ \t]*(\S+)(?:[ \t]+(?:-\S+[ \t]+)*(\S+))?")
#: Interpreters that run a script as JavaScript (or TypeScript).
_SHEBANG_JS_NAMES = frozenset({"node", "nodejs", "bun", "deno", "ts-node", "tsx"})


def shebang_lang(text):
    """'js' | 'py' | 'sh' | None: the language a script runs as, by its #!
    line (`#!/usr/bin/env node`, `#!/usr/bin/env -S deno run`,
    `#!/usr/bin/python3`, `#!/bin/sh`)."""
    m = _SHEBANG_RE.match(text)
    if not m:
        return None
    prog = m.group(1).rsplit("/", 1)[-1].lower()
    if prog == "env" and m.group(2):
        prog = m.group(2).rsplit("/", 1)[-1].lower()
    if prog in _SHEBANG_JS_NAMES:
        return "js"
    if _PYTHON_NAME_RE.match(prog):
        return "py"
    if prog in _SHELL_NAMES:
        return "sh"
    return None


def script_source_lang(head):
    """'js' or 'py' for a file without a source extension whose leading
    bytes `head` make it a JavaScript or Python script by its #! line: it
    runs as code, so project and --deps scans read it as source (they used
    to classify it by magic bytes only, so `bin/cli` or a hook's `./setup`
    was never read). None otherwise — shell scripts too: no rule reads
    shell."""
    head = bytes(head[:HEADER_SAMPLE_BYTES])
    if not head.startswith(b"#!") or looks_binary(head):
        return None
    lang = shebang_lang(head.decode("utf-8", "replace"))
    return lang if lang in ("js", "py") else None


_JSON_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\],:]')


def _script_key_lines(text):
    """{script name: 1-based line of its key} for the keys of the top-level
    "scripts" object of `text`, a JSON document that parsed. Keys are
    compared decoded (`"post\\u0069nstall"` too), and a repeated key or
    "scripts" object counts where it last appears, as the parser keeps the
    last one. Twin of the locator in the npm engine's scanManifest."""
    found, depth, containers = {}, 0, []
    top_key, in_scripts, expect_key = None, False, False
    line, pos = 1, 0
    for m in _JSON_TOKEN_RE.finditer(text):
        tok = m.group()
        if tok[0] == '"':
            if expect_key and (depth == 1 or (depth == 2 and in_scripts)):
                key = json.loads(tok)
                if depth == 1:
                    top_key = key
                    if key == "scripts":
                        found = {}                  # a later "scripts" replaces an earlier one
                else:
                    line += text.count("\n", pos, m.start())
                    pos = m.start()
                    found[key] = line
            expect_key = False
        elif tok in "{[":
            if depth == 1 and tok == "{":
                in_scripts = top_key == "scripts"   # at depth 1, "{" is the value of top_key
            containers.append(tok)
            depth += 1
            expect_key = tok == "{"
        elif tok in "}]":
            containers.pop()
            depth -= 1
            if depth < 2:
                in_scripts = False
            expect_key = False
        elif tok == ",":
            expect_key = containers[-1] == "{"
    return found


def is_dependency_manifest(path):
    """A manifest inside an installed-dependency directory (node_modules/, ...)
    belongs to a package that came from a registry: only the scripts npm runs
    for an installed dependency apply to it, not `prepare`."""
    parts = path.replace("\\", "/").split("/")[:-1]
    return any(part in DEP_MARKERS for part in parts)


def scan_manifest(path, content, registry=False):
    """Check package.json / pyproject.toml install hooks — the primary
    supply-chain attack vector.

    G11: mere *presence* of a lifecycle script is flagged (MAJOR); a hook whose
    command matches the fetch/eval pattern list escalates to CRITICAL. The old
    behavior (pattern-only) was a denylist every `npx evil-pkg` or
    `node ./scripts/payload.js` sailed through. Also covers setup.py and
    binding.gyp via scan_file()/scan_gyp() (see collect_files).

    Shared semantics 3: a leading BOM is stripped before parsing; an
    unparseable ROOT manifest is SC-MANIFEST-UNPARSEABLE (MAJOR). registry /
    dependency manifests count preinstall, install, postinstall; a project
    checkout also counts preprepare, prepare, postprepare, and there a
    prepare-family hook that is not suspicious is INFO (the project's own
    build step, e.g. `husky install`), while a suspicious one stays CRITICAL."""
    data, issues = load_manifest(path, content)
    if data is None:
        return issues
    body = content[1:] if content.startswith("\ufeff") else content
    lines = body.split("\n")
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        key_lines = None
        for hook in (NPM_INSTALL_SCRIPTS if registry else NPM_LOCAL_INSTALL_SCRIPTS):
            cmd = scripts.get(hook)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            suspicious = _hook_is_suspicious(cmd)
            sev = "INFO" if (not registry and hook in NPM_PREPARE_SCRIPTS
                             and not suspicious) else None
            # the hook's key inside "scripts", not the first line naming it
            # (review: a dependency called "install" took the finding)
            if key_lines is None:
                key_lines = _script_key_lines(body)
            line_no = key_lines.get(hook) or next(
                (i + 1 for i, l in enumerate(lines) if f'"{hook}"' in l), 1)
            issues.append(_sc_install_hook_issue(path, line_no, lines, hook, cmd,
                                                 suspicious, sev=sev))
    return issues


# gyp command expansions run a command while node-gyp configures the build:
# '<!(cmd)', '<!@(cmd)', and the same in gyp's later phases, '>!(cmd)' and
# '^!(cmd)'; '<!([argv…])' runs an argv list without a shell, and
# '<!pymod_do_main(module args)' imports `module` from the gyp file's
# directory and calls its DoMain. (gyp: pylib/gyp/input.py, ExpandVariables.)
_GYP_EXPANSION_RE = re.compile(r"[<>^]!@?(?:pymod_do_main)?\(")
# Any expansion or variable reference inside a command — '<(var)',
# '<!(cmd)', '<@(list)', '<|(file)' — whose value only gyp knows. Following
# the command, '<(module_root_dir)' and '<(DEPTH)' stand for the directory
# of the root binding.gyp, and any other one for a path outside the package.
_GYP_REFERENCE_RE = re.compile(r"[<>^](?:!?@?|\|)?(?:[-a-zA-Z0-9_.]+)?\(")
_GYP_ROOT_VARIABLES = frozenset({"module_root_dir", "DEPTH"})
# The ubiquitous benign form: print an include path of a dependency.
_GYP_NODE_REQUIRE_RE = re.compile(
    r"""node\s+-[ep]\s+(?:"|')\s*require\(\s*\\?["'][\w@./-]+\\?["']\s*\)(?:\.[\w$]+)*\s*;?\s*(?:"|')""")
# Bounds on one gyp document (review: scan_gyp was quadratic — 8,000 actions
# took 11.4 s, 4,000 expansions in one 60 KB string 29.5 s — and a document
# with more values than the walk visits was reported clean). Past either
# limit the walk stops and the file gets SC-TRUNCATED. Characters are code
# points, as Python counts them (the npm engine counts the same way).
_GYP_MAX_NODES = 100_000                 # values visited
_GYP_MAX_COMMAND_CHARS = 2_000_000       # characters of action/expansion commands examined
#: SC-INSTALL-HOOK findings listed per gyp file; the rest are summed up in one
#: more finding at the highest severity among them.
GYP_MAX_HOOK_FINDINGS = 100


# str() refuses an int of more than 4300 digits (a long hex literal in an
# action raised ValueError out of scan_gyp); such an int is shown in hex,
# as the npm engine shows it (pycompat.js pyIntStr).
_INT_STR_LIMIT = 10 ** 4300


def _gyp_str(value):
    """str(value) for an action argument, never refusing a large int."""
    try:
        return str(value)
    except ValueError:
        return _gyp_repr(value)


def _gyp_repr(value):
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) < _INT_STR_LIMIT:
            try:
                return repr(value)
            except ValueError:             # a lower sys.set_int_max_str_digits()
                pass
        return hex(value)
    if isinstance(value, list):
        return "[" + ", ".join(_gyp_repr(v) for v in value) + "]"
    if isinstance(value, tuple):
        return "(" + ", ".join(_gyp_repr(v) for v in value) + ("," if len(value) == 1 else "") + ")"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_gyp_repr(k)}: {_gyp_repr(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (set, frozenset)):
        return "{" + ", ".join(_gyp_repr(v) for v in value) + "}" if value else "set()"
    return repr(value)


def _gyp_closing_parens(text):
    """{offset of '(': offset of its balanced ')'}, in one pass (a stack)."""
    close, opened = {}, []
    for m in re.finditer(r"[()]", text):
        if text[m.start()] == "(":
            opened.append(m.start())
        elif opened:
            close[opened.pop()] = m.start()
    return close


def _gyp_expansion_commands(text):
    """(command, is_pymod) for every expansion in `text`, in order: the
    command up to its balanced closing parenthesis, or to the end of the
    string. The closing parenthesis of every '(' is found in one pass, not by
    a scan per expansion."""
    close = _gyp_closing_parens(text)
    for m in _GYP_EXPANSION_RE.finditer(text):
        i = m.end() - 1                  # its '('
        j = close.get(i)
        yield (text[i + 1:] if j is None else text[i + 1:j]), "pymod_do_main" in m.group()


def _gyp_hook_command(cmd, kind):
    """The shell command an expansion's `cmd` runs, as follow_hook reads it:
    the expansions and variables in it replaced ('<(module_root_dir)' and
    '<(DEPTH)' by '.', any other by '/_', a path outside the package), an
    argv list ('[…]') joined, and `pymod_do_main(module args)` as
    `python -m module args`."""
    close = _gyp_closing_parens(cmd)
    out, pos = [], 0
    for m in _GYP_REFERENCE_RE.finditer(cmd):
        if m.start() < pos:
            continue                     # inside one replaced already
        i = m.end() - 1
        j = close.get(i, len(cmd) - 1)
        variable = m.group() in ("<(", ">(", "^(")
        out.append(cmd[pos:m.start()])
        out.append("." if variable and cmd[i + 1:j].strip() in _GYP_ROOT_VARIABLES else "/_")
        pos = j + 1
    out.append(cmd[pos:])
    flat = "".join(out)
    if kind == "pymod":
        return "python -m " + flat
    if flat.lstrip().startswith("["):
        import ast
        import shlex
        try:
            argv = ast.literal_eval(flat.strip())
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return flat
        if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
            return shlex.join(argv)
    return flat


def _gyp_package_files(follow):
    """The files of the package an expansion's command runs (a script, a
    `require('./x')`; not a tool, a path outside the package or a JSON file),
    as a frozenset (empty when none)."""
    targets, _complete = follow_hook(follow)
    return frozenset(t for t in targets
                     if not t.replace("\\", "/").startswith("/") and not t.lower().endswith(".json"))


def _gyp_commands(data):
    """-> (commands, truncated): (command, kind, node) for every action/rule
    command (kind "action", node: the dict holding "action") and every command
    expansion (kind "expansion", or "pymod" for pymod_do_main, whose command
    is its module and arguments; node None) anywhere in a parsed gyp document
    (targets, conditions, target_defaults, variables ...), and why the walk
    stopped early (None if it did not). Bounded walk, no recursion."""
    out, stack, seen, chars = [], [data], 0, 0
    truncated = None
    while stack:
        if seen >= _GYP_MAX_NODES:
            truncated = f"more than {_GYP_MAX_NODES} values in the gyp document"
            break
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "action" and isinstance(value, (list, tuple)):
                    cmd = " ".join(_gyp_str(a) for a in value)
                    out.append((cmd, "action", node))
                    chars += len(cmd)
                stack.append(key)
                stack.append(value)
        elif isinstance(node, (list, tuple, set, frozenset)):
            stack.extend(node)
        elif isinstance(node, str) and _GYP_EXPANSION_RE.search(node):
            for cmd, pymod in _gyp_expansion_commands(node):
                out.append((cmd, "pymod" if pymod else "expansion", None))
                chars += len(cmd)
                if chars > _GYP_MAX_COMMAND_CHARS:
                    break
        if chars > _GYP_MAX_COMMAND_CHARS:
            truncated = f"more than {_GYP_MAX_COMMAND_CHARS} characters of gyp commands"
            break
    out.reverse()
    return out, truncated


class _LineRedactor:
    """mk_issue's redaction of one file's lines when no scan context is
    active (PEM key blocks whole, the secret patterns on other lines, no
    entropy literals), computed once per line instead of once per finding
    (review: a gyp file with thousands of actions re-ran it for every one)."""

    def __init__(self, lines):
        self.lines = lines
        self._pem = None
        self._red = {}

    def secrets(self):
        return None

    def redacted(self, k):
        r = self._red.get(k)
        if r is None:
            if self._pem is None:
                self._pem = _pem_block_lines(self.lines)
            r = REDACTED if k in self._pem else _redact_context_line(self.lines[k])
            self._red[k] = r
        return r


_GYP_EXPANSION_FILE_WHY = (
    "A binding.gyp command expansion runs while node-gyp configures the build, on npm install, with no "
    "install script needed. This one runs a file of the package: it is listed for inventory, and in a "
    "dependency Lazaret follows it to that file and checks it like an install script (CRITICAL when it "
    "ships the environment or credentials off the machine, or runs code it downloads).")


def scan_gyp(path, content):
    """G11: binding.gyp custom build actions run arbitrary commands at
    `node-gyp rebuild` (i.e. `npm install` of any native module). Flag each
    action whose command matches the fetch/eval patterns, and any action at
    all as MAJOR — same policy as package.json lifecycle scripts.

    gyp files are Python literals (single quotes, comments, trailing commas),
    so both JSON and Python-literal syntax are accepted. Actions and rules
    are found anywhere in the document (conditions, target_defaults ...).
    Command expansions ('<!(cmd)', '>!(cmd)', '^!(cmd)', '<!([argv])',
    '<!pymod_do_main(module)') also run at configure time: they are flagged
    CRITICAL when the command fetches or evaluates code, and listed as INFO
    inventory when it runs a file of the package (`node index.js`,
    `node -p "require('./lib/x')"`, a pymod_do_main module) — the Miasma
    trick: a payload run from binding.gyp, with no install script. Such a
    finding's `cmd` is the command as it runs (see _gyp_hook_command), so
    a --deps scan and the registry follow it to that file and escalate it to
    CRITICAL when the file fails the install-script test. The usual
    `<!(node -p "require('node-addon-api').include")` and pkg-config calls
    are not findings. An unparseable ROOT binding.gyp is
    SC-MANIFEST-UNPARSEABLE.

    An action's finding is on the line of its own "action" key; an
    expansion's on the first line holding its command. At most
    GYP_MAX_HOOK_FINDINGS are listed, then one finding sums up the rest; a
    document past the walk's bounds (_GYP_MAX_NODES values,
    _GYP_MAX_COMMAND_CHARS of commands) is SC-TRUNCATED, never silently
    clean. Linear in the size of the file."""
    data, issues, where = _load_manifest(path, content, python_literal=True, locate="action")
    if data is None:
        return issues
    body = content[1:] if content.startswith("\ufeff") else content
    lines = body.split("\n")
    commands, truncated = _gyp_commands(data)
    hooks = []                           # (cmd shown, kind, node, suspicious, command followed, sev)
    listed = set()                       # the files the listed INFO expansions run
    for cmd, kind, node in commands:
        if kind == "action":
            hooks.append((cmd, kind, node, bool(INSTALL_HOOK_RE.search(cmd)), None, None))
            continue
        suspicious = bool(INSTALL_HOOK_RE.search(_GYP_NODE_REQUIRE_RE.sub(" ", cmd)))
        follow = _gyp_hook_command(cmd, kind)
        if not suspicious:
            runs = _gyp_package_files(follow)
            if not runs or runs in listed:
                continue                 # the usual include-path queries; a file listed already
            listed.add(runs)
        shown = f"pymod_do_main({cmd})" if kind == "pymod" else cmd
        hooks.append((shown, kind, node, suspicious, follow, None if suspicious else "INFO"))
    newlines = [m.start() for m in re.finditer("\n", body)] if hooks else []
    first_line = {}

    def line_of(cmd, kind, node):
        if kind == "action":
            at = where.get(id(node))
            return 1 if at is None else bisect.bisect_left(newlines, at[1]) + 1
        if not cmd or "\n" in cmd:
            return 1                     # no single line holds it
        if cmd not in first_line:
            at = body.find(cmd)
            if at < 0:                   # written with \' or \" in a quoted string
                at = next((a for a in (body.find(cmd.replace("'", "\\'")), body.find(cmd.replace('"', '\\"')))
                           if a >= 0), -1)
            first_line[cmd] = 1 if at < 0 else bisect.bisect_left(newlines, at) + 1
        return first_line[cmd]

    redactor = _LineRedactor(lines)
    for cmd, kind, node, suspicious, follow, sev in hooks[:GYP_MAX_HOOK_FINDINGS]:
        issue = _sc_install_hook_issue(
            path, line_of(cmd, kind, node), lines,
            "binding.gyp action" if kind == "action" else "binding.gyp command expansion",
            cmd, suspicious, sev=sev, redactor=redactor)
        if follow is not None:
            issue["cmd"] = follow        # what a --deps scan and the registry follow
        if sev == "INFO":
            issue["why"] = _GYP_EXPANSION_FILE_WHY
        issues.append(issue)
    rest = hooks[GYP_MAX_HOOK_FINDINGS:]
    if rest:
        n_bad = sum(1 for h in rest if h[3])
        issues.append(mk_issue(
            {"id": "SC-INSTALL-HOOK", "name": "Install hook", "type": "HOTSPOT",
             "sev": "CRITICAL" if n_bad else ("MAJOR" if any(h[5] != "INFO" for h in rest) else "INFO"),
             "msg": (f"{len(rest)} more binding.gyp actions and command expansions run code at "
                     f"install time ({n_bad} of them fetch or evaluate code); only the first "
                     f"{GYP_MAX_HOOK_FINDINGS} are listed."),
             "why": ("Each action and command expansion in a binding.gyp runs a command during "
                     "`node-gyp rebuild` (npm install). A file with this many is listed in part "
                     "so the report stays readable; this finding carries the highest severity "
                     "among the ones not listed."),
             "fix": "Review every action and command expansion in the file; use --ignore-scripts "
                    "in CI if unneeded.",
             "ref": "CWE-506 · Supply chain"},
            path, line_of(rest[0][0], rest[0][1], rest[0][2]), lines, redactor=redactor))
    if truncated:
        issues.append(truncated_issue(path, truncated))
    return issues

import codecs as _codecs
import pathlib as _pathlib
import stat as _stat
import traceback as _traceback
import urllib.parse as _urlparse

import lazaret as _lazaret_pkg   # __version__ (the package root imports nothing)

# ---------------- File collection (the project walk) ----------------
# The walk is the attack surface a hostile repository controls completely, so:
#   * only REGULAR files are ever opened (lstat + S_ISREG, and O_NOFOLLOW |
#     O_NONBLOCK + fstat at open time): a FIFO named b.py used to hang the
#     scan forever, a symlink to /dev/urandom exhausted memory, and a symlink
#     to a host file pulled that file into the report;
#   * symlinks are never followed; each one inside the tree is an INFO
#     Q-SYMLINK finding; unreadable entries are INFO Q-UNREADABLE findings;
#   * reads are bounded (size cap + 1 for scanned files, a header sample for
#     everything else);
#   * the walk is iterative (os.walk recursed: a 1,100-deep tree raised
#     RecursionError on 3.10/3.11);
#   * paths in findings are root-relative and valid UTF-8 (a non-UTF-8 file
#     name crashed the HTML writer after the scan).

def _env_int(var, default):
    """A positive integer from the environment, else `default` (parsed like
    the registry scanner's LAZARET_* limits)."""
    try:
        value = int(os.environ.get(var, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


#: Files that would be source-scanned or parsed as manifests and are larger
#: than this are not read: they get an SC-TRUNCATED finding instead. Every
#: other file is classified from a header sample whatever its size. The old
#: 2,000,000 made `--deps` report SC-TRUNCATED (CRITICAL) for ordinary
#: single-file bundles: typescript's lib/typescript.js (9.1 MB) and _tsc.js
#: (6.2 MB), @babel/standalone's babel.js (5.3 MB). The scan is linear; an
#: 8 MB bundle takes about 5 s. Env LAZARET_MAX_SOURCE_BYTES (shared with
#: lazaret-registry) or --max-source-bytes; the MCP server uses the same value.
SOURCE_SIZE_CAP = _env_int("LAZARET_MAX_SOURCE_BYTES", 16_000_000)
#: Bytes read from every non-source regular file for magic-byte classification.
HEADER_SAMPLE_BYTES = 512
MANIFEST_NAMES = ("package.json", "binding.gyp")
#: gyp files, whatever their name: binding.gyp pulls others in ('includes':
#: ['build/common.gypi']) and node-gyp runs their actions and command
#: expansions too, so every one is parsed by scan_gyp (as the registry does).
GYP_EXTS = (".gyp", ".gypi")
#: AppleDouble / AppleSingle metadata ("._name" files macOS writes on non-HFS
#: volumes and into tarballs). Starts with a NUL, so it can never be Python or
#: JavaScript source; it is classified like any other non-source file.
APPLE_DOUBLE_MAGIC = (b"\x00\x05\x16\x07", b"\x00\x05\x16\x00")
#: PEP 263 encoding declaration (Python source), on raw bytes.
_PY_COOKIE_RE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_PY_BLANK_RE = re.compile(rb"^[ \t\f]*(?:#.*)?$")
_UTF7_NAMES = frozenset({"utf-7", "utf7", "u7", "unicode-1-1-utf-7"})


class ScanTargetError(ValueError):
    """The scan target is missing, not a directory, unreadable or has nothing
    to scan. A usage error: the CLI exits 2."""


class _NotRegularFile(OSError):
    """Raised by _read_prefix when the path is not a regular file at open time."""


def _fs_display(path):
    """A path as valid UTF-8 text, the same on every host. On POSIX a name is
    bytes; it is shown as those bytes read as UTF-8, with anything that isn't
    UTF-8 as a backslash escape ('bad\\xff.py') — never as the host locale
    would decode it (under a Latin-1 locale os.scandir says 'bad\u00ffy.py'
    for the same file). Windows names are Unicode already; only unpaired
    surrogates need escaping there."""
    if os.name != "nt":
        return os.fsencode(path).decode("utf-8", "backslashreplace")
    try:
        path.encode("utf-8")
        return path
    except UnicodeEncodeError:
        return path.encode("utf-8", "backslashreplace").decode("utf-8")


def _safe_text(s):
    """Any str as valid UTF-8 text (lone surrogates become escapes)."""
    s = str(s)
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _is_reparse_point(st):
    """Windows junctions / mount points are not symlinks to os.lstat on older
    Pythons; treat any reparse-point directory like a symlink (never followed)."""
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)   # FILE_ATTRIBUTE_REPARSE_POINT


_SPECIAL_KIND = ((_stat.S_ISFIFO, "a named pipe (FIFO)"), (_stat.S_ISSOCK, "a socket"),
                 (_stat.S_ISCHR, "a character device"), (_stat.S_ISBLK, "a block device"))


def _special_kind(mode):
    return next((name for test, name in _SPECIAL_KIND if test(mode)), "not a regular file")


_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)
               | getattr(os, "O_BINARY", 0))


def _read_prefix(path, limit):
    """Read at most `limit` bytes of a REGULAR file without following a
    symlink or blocking on a FIFO swapped in after the lstat (O_NOFOLLOW |
    O_NONBLOCK, then fstat). Raises OSError (incl. _NotRegularFile)."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise _NotRegularFile(f"{_special_kind(st.st_mode)}")
        chunks, remaining = [], limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _coverage_issue(rule, name, path, msg, why, fix, ref="Maintainability"):
    return {"rule": rule, "name": name, "type": "SMELL", "sev": "INFO",
            "msg": msg, "why": why, "fix": fix, "ref": ref,
            "file": path, "line": 1, "snippet": [], "snipStart": 1}


def symlink_issue(path, target):
    """Q-SYMLINK: a symbolic link inside the tree (never followed)."""
    target = _safe_text(target)
    if len(target) > 200:
        target = target[:197] + "..."
    return _coverage_issue(
        "Q-SYMLINK", "Symbolic link (not followed)", path,
        f"Symbolic link {path} -> {target} was not followed; its target was not scanned.",
        "Following links would let a repository pull files from outside the scanned tree "
        "(host credentials, /dev/urandom) into the scan and its reports, or loop forever. "
        "The link target is not part of the tree under review.",
        "If the target belongs to the project, scan it directly.",
        "CWE-59 · Scan coverage")


def unreadable_issue(path, reason):
    """Q-UNREADABLE: an entry that could not be read (permissions, special file)."""
    return _coverage_issue(
        "Q-UNREADABLE", "Unreadable entry (not scanned)", path,
        f"{path} could not be read ({_safe_text(reason)}); it was not scanned.",
        "An entry the scanner cannot read is invisible to every rule. Special files "
        "(named pipes, sockets, devices) are never opened: reading one can hang or "
        "exhaust the scan.",
        "Fix the permissions (or remove the special file) and re-scan.",
        "Scan coverage")


def scan_error_issue(path, exc):
    """SC-TRUNCATED for a file (or directory) whose scan raised: the run goes
    on without its findings, and like any file not fully scanned it fails the
    gate. It was an INFO note (Q-SCAN-ERROR), so a file whose scan died took
    its CRITICAL findings with it and the gate passed (review B3: a 6 MB
    string line overflowed the npm engine's regex stack)."""
    issue = truncated_issue(path, f"its scan failed ({type(exc).__name__}), so its findings are missing")
    issue["why"] = ("An internal error stopped this scan; the rest of the project is still "
                    "scanned and reported, but nothing in this file was checked, so the result "
                    "can't clear it.")
    issue["fix"] = ("Review the file manually and report the error (re-run with LAZARET_DEBUG=1 "
                    "for a traceback).")
    return issue


def _pyc_issue(rid, name, sev, path, msg, why, fix):
    return {"rule": rid, "name": name, "type": "HOTSPOT", "sev": sev, "msg": msg,
            "why": why, "fix": fix, "ref": "CWE-506 · Supply chain",
            "file": path, "line": 1, "snippet": [], "snipStart": 1}


# ---------------- .pth files (SC-PTH-EXEC) ----------------
# site.py executes every line of a .pth file in site-packages that starts
# with 'import' at EVERY interpreter start. The registry has checked archive
# members with this since the beginning; project and --deps scans now run
# the same check on every .pth file they meet (review: a directory holding
# only evil.pth exited 2, "nothing to scan"). A .pth file is not a source
# file: no other rule runs on it, and it is not counted in the metrics.
PTH_EXT = ".pth"
_PTH_EXEC_RE = re.compile(
    r"\b(?:exec|eval|compile)\s*\(|\b(?:b64decode|b32decode|b85decode|a85decode|fromhex|unhexlify)\b"
    r"|\.decode\s*\(|\bmarshal\.loads\b|\bzlib\.decompress\b|\bcodecs\.decode\b|\\x[0-9a-fA-F]{2}")


_PTH_IMPORT = ("import ", "import\t")


def pth_issues(path, text):
    """SC-PTH-EXEC: site.py executes every line of a .pth file in
    site-packages that starts with 'import' at EVERY interpreter start — no
    import of the package needed. CRITICAL when the line also executes or
    decodes code, MAJOR otherwise (setuptools' distutils shim and namespace
    .pth files are this shape: listed for review). The registry's check
    (lazaret.registry.repo) and the project walk share this one helper's
    semantics; the npm engine's twin is js/src/lib/pth.js.

    Lines are taken both ways site.py splits them: at \\n, \\r and \\r\\n
    (iterating the file: 3.10, 3.11, early 3.12 releases), and with
    str.splitlines() (3.13+ and recent 3.12 releases), which also breaks at
    \\v, \\f, \\x1c-\\x1e, \\x85, U+2028 and U+2029 — review: `# path
    notes\\fimport sys; …` gave no finding while python3.13 ran its import.
    A finding is reported at the physical (\\n) line holding the statement,
    once per line."""
    out, lines = [], normalize_newlines(text).split("\n")
    for i, line in enumerate(lines):
        if not (line.startswith(_PTH_IMPORT)
                or any(part.startswith(_PTH_IMPORT) for part in line.splitlines())):
            continue
        hostile = bool(_PTH_EXEC_RE.search(line))
        out.append(mk_issue(
            {"id": "SC-PTH-EXEC", "name": "Code in a .pth file", "type": "HOTSPOT",
             "sev": "CRITICAL" if hostile else "MAJOR",
             "msg": (".pth line runs code at every Python start"
                     + (" and executes or decodes a payload." if hostile else ".")),
             "why": ("site.py executes .pth lines that start with 'import' whenever the "
                     "interpreter starts, whether or not the package is imported — a "
                     "persistence and execution vector that needs no install hook."),
             "fix": "Find out why the package ships executable .pth code; remove it if unexplained.",
             "ref": "CWE-506 · Supply chain"}, path, i + 1, lines))
    return out


def pyc_issues(path, header, has_source):
    """SC-PYC-UNCHECKED / SC-PYC-ORPHAN for one .pyc in a __pycache__ dir.
    `header` is at least the first 8 bytes; `has_source` whether the
    matching <module>.py sits next to the __pycache__ directory."""
    out = []
    if (len(header) >= 8 and header[2:4] == b"\r\n"
            and int.from_bytes(header[4:8], "little") == 0b01):
        out.append(_pyc_issue(
            "SC-PYC-UNCHECKED", "Unchecked-hash bytecode", "CRITICAL", path,
            f"{path} is an unchecked-hash .pyc (PEP 552): Python imports it without "
            "checking the source.",
            "An unchecked-hash .pyc is loaded on import even when the .py next to it says "
            "something else, so code that was never reviewed runs while the reviewed "
            "source looks benign.",
            "Delete the __pycache__ directory, keep bytecode out of version control and "
            "rebuild from reviewed source."))
    if not has_source:
        out.append(_pyc_issue(
            "SC-PYC-ORPHAN", "Bytecode without source", "MAJOR", path,
            f"{path} has no matching source file.",
            "Bytecode without its source cannot be reviewed, and a .pyc can be run "
            "directly (python file.pyc) or loaded by a custom importer.",
            "Delete the file, or restore the source it was compiled from and review it."))
    return out


def detect_encoding(head):
    """M17 / FIX-SPEC 4: BOM / UTF-16 sniff of a file's first bytes.

    Returns {'encoding': codec, 'reported': bool, 'bom': n}: BOM FF FE ->
    utf-16-le, FE FF -> utf-16-be, EF BB BF -> utf-8-sig; otherwise a NUL in
    the first 4 bytes betrays BOM-less UTF-16 (NUL at index 1 or 3 ->
    utf-16-le, else utf-16-be). reported=True for every non-plain-UTF-8 case
    (-> Q-ENCODING); bom is the number of BOM bytes to drop before decoding.
    The old sniff returned the generic 'utf-16' codec for BOM-less input,
    whose decoder raises UnicodeError ('UTF-16 stream does not start with
    BOM') — which escaped and killed the whole scan (review item 1)."""
    if head.startswith(b"\xff\xfe"):
        return {"encoding": "utf-16-le", "reported": True, "bom": 2}
    if head.startswith(b"\xfe\xff"):
        return {"encoding": "utf-16-be", "reported": True, "bom": 2}
    if head.startswith(b"\xef\xbb\xbf"):
        return {"encoding": "utf-8-sig", "reported": True, "bom": 0}
    first = head[:4]
    if b"\x00" in first:
        le = first[1:2] == b"\x00" or first[3:4] == b"\x00"
        return {"encoding": "utf-16-le" if le else "utf-16-be", "reported": True, "bom": 0}
    return {"encoding": "utf-8", "reported": False, "bom": 0}


def _python_cookie(data):
    """PEP 263 encoding declaration of Python source bytes: (name, line_no) or
    (None, None). Same rule as the interpreter's tokenizer: line 1, or line 2
    when line 1 is blank or a comment."""
    lines = re.split(rb"\r\n|\r|\n", data, maxsplit=2)[:2]
    for idx, line in enumerate(lines):
        m = _PY_COOKIE_RE.match(line)
        if m:
            return m.group(1).decode("ascii"), idx + 1
        if not _PY_BLANK_RE.match(line):
            break
    return None, None


#: Coding-cookie names only newer Pythons know (3.13: windows_31j; 3.14: 874,
#: ms874, windows_874, cseuckr, iso_8859_8_e, iso_8859_8_i), resolved on every
#: supported version so a file decodes the same whichever Python scans it
#: (normalized as encodings.normalize_encoding does, on the lower-cased name).
CODEC_ALIAS_EXTRAS = {"windows_31j": "cp932", "874": "cp874", "ms874": "cp874",
                      "windows_874": "cp874", "cseuckr": "euc_kr",
                      "iso_8859_8_e": "iso8859-8", "iso_8859_8_i": "iso8859-8",
                      # 3.14.x patch releases (3.14.7 has them, 3.14.0 does not)
                      "cp01140": "cp1140", "csibm01140": "cp1140", "ibm01140": "cp1140",
                      "ebcdic_us_37_euro": "cp1140", "cp00858": "cp858", "csibm00858": "cp858",
                      "ibm00858": "cp858", "pc_multilingual_850_euro": "cp858"}
#: Codecs that decode with the host's code page (Windows only): unknown here.
HOST_CODECS = frozenset(("mbcs", "oem"))
#: Single-byte tables that differ between supported Pythons, as the newest has
#: them (3.13 maps palmos 0x9B to U+203A; 3.10-3.12 to U+009B).
CHARMAP_FIXES = {"palmos": {0x9B: "\u203a"}}
#: Multi-byte codecs the npm engine decodes with the runtime's TextDecoder.
#: With these, the single-byte codecs (scripts/make_codec_tables.py writes
#: it Python's tables), UTF-7, Latin-1, ASCII and the escape codecs, both
#: engines decode what a cookie names; any other codec (UTF-32, ISO-2022-KR,
#: Shift_JIS-2004, …) is read as UTF-8 by both, with SC-TRUNCATED.
_TEXTDECODER_CODECS = frozenset((
    "utf-16", "utf-16-le", "utf-16-be", "shift_jis", "cp932", "euc_jp", "iso2022_jp",
    "gbk", "gb2312", "cp936", "gb18030", "big5", "cp950", "euc_kr", "cp949"))


def _codec_key(name):
    """A codec name as encodings.normalize_encoding sees it (lower case)."""
    return re.sub(r"[^a-z0-9.]+", "_", name.lower()).strip("_")


def _normal_codec(name):
    """Codec for a cookie name as the interpreter resolves it (utf-8-* and
    latin-1-* spellings fold to their base codec), or None if Python has no
    such text codec. The same on every supported Python and host
    (CODEC_ALIAS_EXTRAS, HOST_CODECS)."""
    short = name[:12].lower().replace("_", "-")
    if short == "utf-8" or short.startswith("utf-8-"):
        return "utf-8"
    if short in ("latin-1", "iso-8859-1", "iso-latin-1") or short.startswith(
            ("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        return "iso8859-1"
    key = _codec_key(name)
    extra = CODEC_ALIAS_EXTRAS.get(key) or CODEC_ALIAS_EXTRAS.get(key.replace(".", "_"))
    if extra:
        return extra
    try:
        info = _codecs.lookup(name)
    except LookupError:
        return None
    if not getattr(info, "_is_text_encoding", True):
        return None                     # rot13, hex, zlib… are not text encodings
    return None if info.name in HOST_CODECS else info.name


def charmap_table(codec):
    """What each byte decodes to in the single-byte (charmap) codec `codec`: a
    256-character string, U+FFFE for a byte it leaves undefined, as the newest
    supported Python has it (CHARMAP_FIXES); None for any other codec."""
    try:
        info = _codecs.lookup(codec)
    except LookupError:
        return None
    mod = sys.modules.get(getattr(info.incrementaldecoder, "__module__", "") or "")
    table = getattr(mod, "decoding_table", None)
    if not isinstance(table, str) or len(table) != 256:
        return None
    fix = CHARMAP_FIXES.get(info.name)
    return table.translate(fix) if fix else table


def _decoded_by_both_engines(codec):
    return (codec in ("utf-7", "ascii", "iso8859-1", "charmap") or codec in _TEXTDECODER_CODECS
            or codec in ESCAPE_CODECS or charmap_table(codec) is not None)


#: Codecs that decode escape sequences before Python reads the code: in a file
#: that declares one, '\u000a' in a comment is a newline and '\u0065' is 'e'
#: (SC-ESCAPE-CODEC). Both engines decode them (_decode_escapes).
ESCAPE_CODECS = ("unicode-escape", "raw-unicode-escape")
#: A \N escape: an N after an odd run of backslashes (linear: a run is
#: tried only from the character before it).
_NAMED_ESCAPE_RE = re.compile(rb"(?:^|[^\\])(?:\\\\)*\\N")


def _decode_escapes(body, codec):
    """`body` as Python's unicode_escape or raw_unicode_escape decodes it, or
    None where the npm engine (encoding.js decodeEscapes) cannot decode it
    exactly as Python does: a \\N{name} escape (it has no Unicode name table)
    or an escape Python rejects, such as a short \\x or a backslash at the end
    (the interpreter would not run the file)."""
    if codec == "unicode-escape" and _NAMED_ESCAPE_RE.search(body):
        return None
    with warnings.catch_warnings():     # "invalid escape sequence" (kept as written)
        warnings.simplefilter("ignore")
        try:
            return body.decode(codec)
        except UnicodeDecodeError:
            return None


#: A surrogate code point: never text on its own (see decode_source).
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def decode_source(data, lang=None):
    """Decode the bytes of a source file the way its interpreter would read
    them. Returns (text, info):

      info = {"encoding": codec label, "reported": bool (-> Q-ENCODING),
              "utf7": bool (-> SC-UTF7), "cookieLine": n or None,
              "escapes": True for an escape codec (-> SC-ESCAPE-CODEC),
              "undecoded": True when the codec is not decoded (-> SC-TRUNCATED)}

    FIX-SPEC 4 (BOM / NUL sniff) first; for Python source without a BOM or
    NUL, FIX-SPEC 15: a PEP 263 cookie naming a codec other than UTF-8 decodes
    with that codec (Q-ENCODING); UTF-7 additionally sets utf7 (a UTF-7
    '+AAo-' is a newline, so code can hide inside a comment), and so do the
    escape codecs ('\\u000a'). An unknown codec
    decodes as UTF-8 with replacement, and so does a codec the npm engine
    cannot decode exactly as Python does (undecoded: the file is not fully
    scanned). Never raises on content. Line endings are normalized to \\n, as
    text mode reads them. A surrogate code point left by the codec (UTF-7
    '+2AA-', unicode_escape '\\udc80') becomes U+FFFD, as in the npm engine's
    decoders: text holding one cannot be written as UTF-8 (review: the HTML
    report raised UnicodeEncodeError after the JSON was written, exit 5) and
    the flow engine could not parse it."""
    enc = detect_encoding(data[:4])
    if (enc["reported"] and not enc["bom"] and enc["encoding"].startswith("utf-16")
            and not _text_is_plausible(data[:4096].decode(enc["encoding"], "replace"))):
        # A NUL near the top of a UTF-8 file (`/*\0*/eval(…)`) is not UTF-16:
        # decoded that way the payload turns into CJK-looking garbage that no
        # rule reads. Accept the BOM-less UTF-16 guess only when it reads as
        # text (real UTF-16 source is mostly ASCII).
        enc = {"encoding": "utf-8", "reported": False, "bom": 0}
    codec, body = enc["encoding"], data[enc["bom"]:]
    info = {"encoding": codec, "reported": enc["reported"], "utf7": False, "cookieLine": None}
    if lang == "py" and not enc["reported"]:
        name, line_no = _python_cookie(data)
        if name is not None:
            real = _normal_codec(name)
            if real is None:
                info.update(encoding=name, reported=True, cookieLine=line_no)
            elif real != "utf-8":
                info.update(encoding=real, reported=True, cookieLine=line_no,
                            utf7=(real == "utf-7"
                                  or name.lower().replace("_", "-") in _UTF7_NAMES))
                if real in ESCAPE_CODECS:
                    info["escapes"] = True
                if _decoded_by_both_engines(real):
                    codec = real
                else:           # read as UTF-8, as the npm engine can only read it
                    info["undecoded"] = True
    text = _decode_escapes(body, codec) if codec in ESCAPE_CODECS else None
    if codec in ESCAPE_CODECS and text is None:
        info["undecoded"] = True        # read as UTF-8, as the npm engine can only read it
        codec = "utf-8"
    if text is None:
        try:
            text = body.decode(codec)
        except Exception:               # malformed input or a misbehaving codec:
            try:                        # never abort the scan over content
                text = body.decode(codec, "replace")
            except Exception:
                text = body.decode("utf-8", "replace")
    fix = CHARMAP_FIXES.get(codec)
    if fix:
        text = text.translate(fix)
    if not text.isascii():
        text = _SURROGATE_RE.sub("\ufffd", text)
    return normalize_newlines(text), info


def encoding_issues(path, text, info):
    """Q-ENCODING (and SC-UTF7) findings for a decoded source file. Their
    snippets are redacted with the file's own entropy literals and PEM
    blocks, as scan_file's are (review: a UTF-8-BOM settings.py showed the
    SEED literal its S-ENTROPY finding redacted in the Q-ENCODING snippet)."""
    if not info["reported"]:
        return []
    lines = text.split("\n")
    red = _Redactor(lines)
    out = [mk_issue(
        {"id": "Q-ENCODING", "name": "Non-UTF-8 source encoding", "type": "SMELL",
         "sev": "INFO",
         "msg": f"Source file is not UTF-8 (detected {info['encoding']}); decoded explicitly.",
         "why": "A non-UTF-8 source read as UTF-8 decodes to mojibake, hiding every "
                "pattern-based finding — a UTF-16 eval() scans clean.",
         "fix": "Re-save the file as UTF-8 so tooling reads it as written.",
         "ref": "Maintainability"}, path, 1, lines, redactor=red)]
    if info["utf7"]:
        out.append(mk_issue(
            {"id": "SC-UTF7", "name": "UTF-7 source encoding", "type": "HOTSPOT",
             "sev": "CRITICAL",
             "msg": "Python source declares UTF-7; code can hide in comments.",
             "why": "In UTF-7, '+AAo-' decodes to a newline: text that every editor, diff "
                    "and reviewer shows as a comment becomes executable code when Python "
                    "reads the file. No legitimate project needs a UTF-7 source file.",
             "fix": "Re-save the file as UTF-8 and review the decoded text (the findings "
                    "for this file are reported against it).",
             "ref": "CWE-506 · Supply chain"}, path, info["cookieLine"] or 1, lines,
            redactor=red))
    if info.get("escapes"):
        out.append(mk_issue(
            {"id": "SC-ESCAPE-CODEC", "name": "Escape-sequence source encoding", "type": "HOTSPOT",
             "sev": "CRITICAL",
             "msg": f"Python source declares {info['encoding']}; code can hide in escape sequences.",
             "why": "Python decodes this file's escape sequences before it reads the code: "
                    "'\\u000a' is a newline and '\\u0065' is 'e', so text that every editor, "
                    "diff and reviewer shows as a comment or a string escape becomes executable "
                    "code. No legitimate project needs this source encoding.",
             "fix": "Re-save the file as UTF-8 and review the decoded text (the findings "
                    "for this file are reported against it).",
             "ref": "CWE-506 · Supply chain"}, path, info["cookieLine"] or 1, lines,
            redactor=red))
    if info.get("undecoded"):
        out.append(truncated_issue(
            path, f"its source encoding ({info['encoding']}) is not decoded by Lazaret; "
                  f"the file was read as UTF-8"))
    return out


def _dep_tree_kind(name, path):
    """True when directory `name` at `path` is a dependency tree: always for
    node_modules / bower_components / site-packages; for vendor / venv /
    .venv / env only when a marker (DEP_TREE_MARKERS) sits directly inside."""
    if name in DEP_TREE_DIRS:
        return True
    markers = DEP_TREE_MARKERS.get(name)
    if markers is None:
        return False
    names, suffixes = markers
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.name in names or (suffixes and e.name.endswith(suffixes)):
                    return True
    except OSError:
        pass
    return False


def _check_pycache(rel_dir, path, parent_names, out):
    """__pycache__ is not source-scanned; every .pyc directly inside is
    checked (PEP 552 flags, matching source). Symlinks -> Q-SYMLINK."""
    try:
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError as exc:
        out.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
        return
    for e in entries:
        rel = os.path.join(rel_dir, e.name)
        disp = _fs_display(rel)
        try:
            st = e.stat(follow_symlinks=False)
        except OSError as exc:
            out.append(unreadable_issue(disp, exc.strerror or type(exc).__name__))
            continue
        if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
            out.append(symlink_issue(disp, _readlink(e.path)))
            continue
        if not (_stat.S_ISREG(st.st_mode) and e.name.endswith(".pyc")):
            continue
        try:
            header = _read_prefix(e.path, 16)
        except OSError as exc:
            out.append(unreadable_issue(disp, exc.strerror or str(exc) or type(exc).__name__))
            continue
        module = e.name.split(".", 1)[0]
        has_source = (module + ".py") in parent_names or (module + ".pyw") in parent_names
        out.extend(pyc_issues(disp, header, has_source))


def _readlink(path):
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        return "?"
    return link_target_text(target) if os.name == "nt" else target


def link_target_text(target):
    """A Windows link target as the user wrote it. Windows stores an absolute
    target in the NT namespace (\\??\\C:\\x), and os.readlink returns it as
    \\\\?\\C:\\x (\\\\?\\UNC\\server\\share\\x for a share); the npm engine
    (libuv) gives C:\\x and \\\\server\\share\\x. Same undoing as libuv, so
    both engines name the target the same way (cross-platform rule 2)."""
    if not isinstance(target, str) or not target.startswith("\\\\?\\"):
        return target
    rest = target[4:]
    if len(rest) >= 2 and rest[0].isascii() and rest[0].isalpha() and rest[1] == ":" \
            and (len(rest) == 2 or rest[2] == "\\"):
        return rest                                       # \\?\C:\x -> C:\x
    if rest[:4].upper() == "UNC\\":
        return "\\\\" + rest[4:]                             # \\?\UNC\s\sh -> \\s\sh
    return target


def _collect_file(path, rel, st, in_dep, col):
    """Classify and read one regular file (see the section comment)."""
    name = os.path.basename(rel)
    disp = _fs_display(rel)
    ext = os.path.splitext(name)[1].lower()
    size = st.st_size
    manifest = name in MANIFEST_NAMES or ext in GYP_EXTS
    pth = not manifest and ext == PTH_EXT
    lang = None if manifest or pth else EXTS.get(ext)
    issues = col["issues"]
    if not manifest and not pth and lang is None:
        # FIX-SPEC 9: every non-source regular file is classified by magic
        # bytes from a header sample (repo mode used to look at a fixed list
        # of extensions only: an ELF named `helper` or `logo.png` passed) —
        # unless its #! line makes it a Node or Python script: then it is
        # source (script_source_lang).
        head = _read_prefix(path, HEADER_SAMPLE_BYTES)
        lang = script_source_lang(head)
        if lang is None:
            bi = classify_binary(disp, head, size, "repo")
            if bi:
                issues.append(bi)
            return
    if lang is not None and ext in MPEG_TS_EXTS:
        head = _read_prefix(path, HEADER_SAMPLE_BYTES)
        if _mpeg_ts(head):                  # a video (a camera's .mts), not TypeScript
            bi = classify_binary(disp, head, size, "repo")
            if bi:
                issues.append(bi)
            return
    # FIX-SPEC 9: the size cap applies only to files that would be read whole.
    # Verdict integrity (audit C2/G16): an oversize file is an SC-TRUNCATED
    # finding, never a silent skip, and it is not added to the scanned files.
    if size > SOURCE_SIZE_CAP:
        issues.append(truncated_issue(
            disp, f"{size:,} bytes exceeds the {SOURCE_SIZE_CAP:,}-byte file limit"))
        return
    data = _read_prefix(path, SOURCE_SIZE_CAP + 1)
    if len(data) > SOURCE_SIZE_CAP:      # grew between the lstat and the read
        issues.append(truncated_issue(
            disp, f"read exceeded the {SOURCE_SIZE_CAP:,}-byte file limit"))
        return
    if manifest:
        col["manifests"].append({"path": disp, "dep": in_dep,
                                 "content": normalize_newlines(data.decode("utf-8", "replace"))})
        return
    if pth:                # only the .pth check runs on it (decoded as the registry does)
        col["pth"].append(disp)
        issues.extend(pth_issues(disp, data.decode("utf-8-sig", "replace")))
        return
    if data[:4] in APPLE_DOUBLE_MAGIC:
        bi = classify_binary(disp, data[:HEADER_SAMPLE_BYTES], size, "repo")
        if bi:
            issues.append(bi)
        return
    text, info = decode_source(data, lang)
    issues.extend(encoding_issues(disp, text, info))
    col["files"].append({"path": disp, "content": text, "lang": lang, "dep": in_dep})


def _collect(root, excludes=(), include_deps=False):
    """Walk `root` iteratively. Returns {"files", "manifests", "pth", "issues",
    "skipped"}: files = [{path, content, lang, dep}], manifests = [{path,
    content, dep}], pth = paths of the .pth files checked, issues = collection
    findings (binary classification, SC-TRUNCATED, Q-ENCODING/SC-UTF7,
    SC-PYC-*, SC-PTH-EXEC, Q-SYMLINK, Q-UNREADABLE), skipped = [(rel,
    n_files, n_bytes)] pruned trees. Paths are root-relative
    (os.sep separators) and valid UTF-8. Raises ScanTargetError when the root
    itself cannot be listed."""
    excludes = set(excludes or ())
    col = {"files": [], "manifests": [], "pth": [], "issues": [], "skipped": []}
    issues = col["issues"]
    seen_dirs = set()
    stack = [("", False)]
    while stack:
        rel_dir, in_dep = stack.pop()
        full_dir = os.path.join(root, rel_dir) if rel_dir else root
        try:
            with os.scandir(full_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
            st_dir = os.stat(full_dir) if not rel_dir else None
        except OSError as exc:
            if not rel_dir:
                raise ScanTargetError(
                    f"cannot read directory {_fs_display(str(root))}: "
                    f"{exc.strerror or type(exc).__name__}") from None
            issues.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
            continue
        if st_dir is not None and st_dir.st_ino:
            seen_dirs.add((st_dir.st_dev, st_dir.st_ino))
        names = {e.name for e in entries}
        subdirs = []
        for e in entries:
            rel = os.path.join(rel_dir, e.name) if rel_dir else e.name
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                issues.append(unreadable_issue(_fs_display(rel), exc.strerror or type(exc).__name__))
                continue
            mode = st.st_mode
            if _stat.S_ISLNK(mode) or (_stat.S_ISDIR(mode) and _is_reparse_point(st)):
                issues.append(symlink_issue(_fs_display(rel), _readlink(e.path)))
            elif _stat.S_ISDIR(mode):
                subdirs.append((e, rel, st))
            elif not _stat.S_ISREG(mode):
                issues.append(unreadable_issue(_fs_display(rel), _special_kind(mode)))
            else:
                try:
                    _collect_file(e.path, rel, st, in_dep, col)
                except OSError as exc:
                    reason = (str(exc) if isinstance(exc, _NotRegularFile)
                              else exc.strerror or type(exc).__name__)
                    issues.append(unreadable_issue(_fs_display(rel), reason))
                except Exception as exc:        # one file must never kill the walk
                    issues.append(scan_error_issue(_fs_display(rel), exc))
        push = []
        for e, rel, st in subdirs:
            name = e.name
            if name in ALWAYS_PRUNE_DIRS or name in excludes:
                _count_skipped_tree(root, e.path, _fs_display(rel), col["skipped"])
                continue
            if name == PYCACHE_DIR:
                try:
                    _check_pycache(rel, e.path, names, issues)
                except Exception as exc:
                    issues.append(scan_error_issue(_fs_display(rel), exc))
                continue
            key = (st.st_dev, st.st_ino)
            if st.st_ino and key in seen_dirs:
                issues.append(unreadable_issue(_fs_display(rel),
                                               "directory already visited (filesystem loop)"))
                continue
            if st.st_ino:
                seen_dirs.add(key)
            dep = in_dep or _dep_tree_kind(name, e.path)
            if dep and not in_dep and not include_deps:
                _count_skipped_tree(root, e.path, _fs_display(rel), col["skipped"])
                continue
            push.append((rel, dep))
        stack.extend(reversed(push))       # pop order = sorted, depth-first (like os.walk)
    return col


def collect_files(root, extra_excludes, include_deps=False):
    """Legacy API: returns (files, manifests, binary_issues) — binary_issues
    being every collection finding (see _collect) — and records the pruned
    trees for skipped_tree_issues() (reset per call). With include_deps,
    dependency trees are walked too; their files are marked dep=True and
    scanned only with supply-chain/secret rules. New callers: scan_project()."""
    _reset_scan_state()
    col = _collect(root, extra_excludes, include_deps=include_deps)
    _SKIPPED_TREES.extend(col["skipped"])
    return col["files"], col["manifests"], col["issues"]


def _scan_manifest_entry(mf):
    """binding.gyp and every other .gyp / .gypi file -> scan_gyp (G11);
    package.json -> scan_manifest. A manifest inside a detected dependency
    tree gets the registry hook set."""
    if os.path.splitext(mf["path"])[1].lower() in GYP_EXTS:
        return scan_gyp(mf["path"], mf["content"])
    dep = mf.get("dep")
    if dep is None:
        dep = is_dependency_manifest(mf["path"])
    return scan_manifest(mf["path"], mf["content"], registry=dep)


# ---------------- --deps: what a dependency runs ----------------
# A --deps scan read a dependency's files with the supply-chain rules only,
# and the registry's two tests of what runs did not run on them: the
# install-script test (install_script_risk) on the scripts a dependency's
# install hook runs, and the weaker import-time test (import_time_risk) on
# its code. An installed package whose postinstall sent the environment to a
# server, or whose code did so when loaded, passed with an ordinary MAJOR
# "install hook" finding, or with nothing. Now:
#   * each install hook of a dependency's manifest — package.json scripts,
#     binding.gyp actions, and binding.gyp command expansions that run a file
#     of the package (scan_gyp's INFO findings) — is followed to the files
#     it runs (follow_hook, then Node's resolution: the file, with an
#     extension, the directory's package.json "main", its index file), only
#     to regular files inside the scan root, through no link and nothing an
#     exclusion pruned; the hook escalates to CRITICAL when one of them fails
#     install_script_risk, as in the registry. A file it runs that the walk
#     did not read as source (node runs lib/install.dat as JavaScript) is
#     read and scanned as a dependency's JavaScript; a shell script is only
#     tested; a hook the walk cannot follow to the end is SC-TRUNCATED.
#   * a dependency whose package root holds a binding.gyp and whose
#     package.json names no install or preinstall script gets the hook npm
#     runs for it, `node-gyp rebuild` (MAJOR, _implicit_gyp_hooks), as the
#     registry lists it.
#   * every JavaScript or Python file of a dependency that no hook runs gets
#     import_time_risk: SC-IMPORT-RISK (MAJOR). On a real node_modules of
#     14,286 JavaScript files (webpack, next, jest, eslint, typescript ...)
#     it found nothing.
# Twin of the npm engine's js/src/deps.js.
_DEP_IMPORT_RISK_WHY = (
    "An installed package's code runs with the application's privileges when it is loaded "
    "or its command runs. Collecting credentials or the whole environment next to a network "
    "call is the shape of an import-time stealer; SDKs read the few variables they need. A "
    "weaker indicator than the same code in an install script: the file may have a reason.")
_DRIVE_RE = re.compile(r"[A-Za-z]:")


def _tree_join(base, target):
    """A hook's `target` joined with the directory `base` ('/'-separated,
    relative to the scan root), normalized; None when it is absolute (a file
    of the machine, not of the tree) or leaves the scan root."""
    target = target.replace("\\", "/")
    if target.startswith("/") or _DRIVE_RE.match(target):
        return None
    joined = posixpath.normpath(posixpath.join(base or ".", target))
    if joined in (".", "..") or joined.startswith("../"):
        return None
    return joined


class _DependencyTree:
    """What a --deps scan knows of the tree, to follow a dependency's install
    hook: the files it read (by '/'-separated path) and, for the others, the
    disk under the scan root — regular files only, reached through no link
    and no directory an exclusion prunes."""

    def __init__(self, root, files, manifests, excludes):
        self.root = os.fspath(root)
        self.sources = {f["path"].replace(os.sep, "/"): f for f in files}
        self.manifests = {m["path"].replace(os.sep, "/"): m for m in manifests}
        self.excludes = set(excludes or ()) | ALWAYS_PRUNE_DIRS
        self.regular = {}                   # rel -> is a regular file (not read as source)
        self.read = {}                      # rel -> its text, read here (None: not text)

    def is_file(self, rel):
        if rel in self.sources or rel in self.manifests:
            return True
        if rel not in self.regular:
            self.regular[rel] = self._on_disk(rel)
        return self.regular[rel]

    def _on_disk(self, rel):
        parts = rel.split("/")
        if any(p in self.excludes or p in ("", ".", "..") for p in parts[:-1]):
            return False
        path = self.root
        try:
            for k, part in enumerate(parts):
                path = os.path.join(path, part)
                st = os.lstat(path)
                if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
                    return False
                if k < len(parts) - 1 and not _stat.S_ISDIR(st.st_mode):
                    return False
            return _stat.S_ISREG(st.st_mode)
        except (OSError, ValueError):       # ValueError: a NUL in the name
            return False

    def resolve(self, path):
        """The file Node runs for `path` (LOAD_AS_FILE, then LOAD_AS_DIRECTORY:
        its package.json "main", its index file), or None. Twin of the
        registry's _ArtifactScan._resolve."""
        candidates = node_candidates(path)
        found = next((c for c in candidates[:6] if self.is_file(c)), None)
        if found:
            return found
        manifest = self.manifests.get(posixpath.join(path.rstrip("/"), "package.json"))
        if manifest is not None:
            data, _problems = load_manifest(manifest["path"], manifest["content"])
            main = data.get("main") if isinstance(data, dict) else None
            if isinstance(main, str) and main.strip():
                target = _tree_join(path.rstrip("/"), main)
                if target is not None:
                    found = next((c for c in node_candidates(target) if self.is_file(c)), None)
                    if found:
                        return found
        return next((c for c in candidates[6:] if self.is_file(c)), None)


# ---------------- Cross-file received code (Python engine only) ----------------
# A dropper can split the network source and the code-runner across two files of
# one package, so neither file alone trips the single-file detector:
#     _net.py:      def pull(): return requests.get(URL).text
#     __init__.py:  from ._net import pull; exec(pull())
# This follower runs only in the Python engine, over a package's own dependency
# files, and is deliberately kept out of the twinned flow.py: the npm engine
# stays single-file with an honest gate. Per package it collects each module's
# TAINTED EXPORTS — a module-level name that holds, or a function that returns, a
# value received over the network — resolves a sibling module's import of one,
# then re-runs the single-file detector with that name seeded (extra_always). It
# fires only when the value genuinely came from another file, at the single-file
# severity (SC-IMPORT-RISK, MAJOR, never escalating an install hook). Bounded:
# one pass per file, exports followed one hop, within one package.

_XF_DEF_RE = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\(")
_XF_ASSIGN_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)[ \t]*=(?![=])(?P<rhs>.*)$")
_XF_RETURN_RE = re.compile(r"^[ \t]*return[ \t](?P<expr>.*)$")
_XF_FROM_RE = re.compile(
    r"^[ \t]*from[ \t]+(?P<mod>\.+[\w.]*|[\w.]+)[ \t]+import[ \t]+(?P<names>\*|\([^()]*\)|.+?)[ \t]*$", re.M)
_XF_DEP_MARKERS = ("site-packages", "dist-packages", "vendor")


def _xf_expr_carries(expr, tainted):
    """Does `expr` hold a received value — a network source, or a name in
    `tainted` used as the head of a member chain?"""
    if next(_dl_finditer(_DL_SOURCE, expr), None) is not None:
        return True
    return any(m.group() in tainted for m in _DL_HEAD_RE.finditer(expr))


def _xf_tainted_exports(text):
    """The module-level names of `text` that hold, or are functions that return,
    a value received over the network. One indentation-aware pass; a function
    body is followed for _DL_WINDOW rows."""
    if not any(n in text for n in _DL_NEEDLES):
        return frozenset()
    rows = text.split("\n")
    exports, module_taint, local = set(), set(), set()
    fn = None                                   # (name, last body row) of the open top-level def
    for k, row in enumerate(rows):
        stripped = row.strip()
        if not stripped:
            continue
        indent = len(row) - len(row.lstrip())
        if fn is not None and (indent == 0 or k > fn[1]):
            fn, local = None, set()
        d = _XF_DEF_RE.match(row)
        if d is not None:
            if indent == 0:
                fn, local = (d.group("name"), k + _DL_WINDOW), set()
            continue
        if fn is not None:
            r = _XF_RETURN_RE.match(row)
            if r is not None and _xf_expr_carries(r.group("expr"), local | module_taint):
                exports.add(fn[0])
                continue
        a = _XF_ASSIGN_RE.match(row)
        if a is not None and len(a.group("rhs")) <= _DL_LONG_ROW and _xf_expr_carries(
                a.group("rhs"), module_taint if indent == 0 else local | module_taint):
            if indent == 0:
                module_taint.add(a.group("name"))
                exports.add(a.group("name"))
            elif fn is not None:
                local.add(a.group("name"))
    return frozenset(exports)


def _xf_py_module(path):
    """(top package, dotted module, is_package) for a dependency .py file under
    site-packages / dist-packages / vendor, else None. __init__.py is its own
    package; another file is <pkg>…<stem>."""
    parts = path.replace(os.sep, "/").split("/")
    idx = max((len(parts) - 1 - parts[::-1].index(m) for m in _XF_DEP_MARKERS if m in parts), default=-1)
    rel = parts[idx + 1:] if 0 <= idx < len(parts) - 1 else []
    if not rel or not rel[-1].endswith(".py"):
        return None
    stem = rel[-1][:-3]
    is_pkg = stem == "__init__"
    mod_parts = rel[:-1] if is_pkg else rel[:-1] + [stem]
    if not mod_parts:
        return None
    return rel[0], ".".join(mod_parts), is_pkg


def _xf_resolve(mod_spec, pkg_parts):
    """Resolve an import's module spec (absolute 'a.b', or relative '.a' / '..a')
    against the importing module's package parts, to a dotted module or None."""
    dots = len(mod_spec) - len(mod_spec.lstrip("."))
    rest = mod_spec[dots:]
    if dots == 0:
        return rest or None
    keep = len(pkg_parts) - (dots - 1)
    if keep < 0:
        return None
    target = pkg_parts[:keep] + (rest.split(".") if rest else [])
    return ".".join(target) or None


def _xf_imported_taint(text, module, is_pkg, exports):
    """{local name: source module} for names this module imports, from a sibling
    module of the same top package, that are that sibling's tainted exports."""
    if "import" not in text:
        return {}
    pkg_parts = module.split(".") if is_pkg else module.split(".")[:-1]
    top = module.split(".")[0]
    seeds = {}
    for m in _XF_FROM_RE.finditer(text):
        target = _xf_resolve(m.group("mod"), pkg_parts)
        if target is None or target.split(".")[0] != top:
            continue
        exp = exports.get(target)
        if not exp:
            continue
        names = m.group("names").strip()
        if names == "*":
            for name in exp:
                seeds[name] = target
            continue
        for item in names.strip("()").split(","):
            parts = item.split()
            if not parts:
                continue
            local = parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0]
            if parts[0] in exp:
                seeds[local] = target
    return seeds


def _xf_issue(path, line, text, cat, srcs):
    lines = text.split("\n")
    where = ", ".join(srcs)
    msg = (f"Dependency code {_DL_CATEGORY_REASON[cat]}; the value is received in "
           f"another file of the package ({where}).")
    return mk_issue(
        {"id": "SC-IMPORT-RISK", "name": "Risky import-time code", "type": "HOTSPOT", "sev": "MAJOR",
         "msg": msg, "why": _DEP_IMPORT_RISK_WHY,
         "fix": f"Read both files: what does {where} receive, and what runs it here?",
         "ref": "CWE-506 · Supply chain"}, path, line, lines, redactor=_Redactor(lines))


def _xf_python_pass(files, skip):
    """The Python half of the cross-file follower (see _cross_file_received_issues)."""
    groups = {}
    for f in files:
        if not f.get("dep") or f["lang"] != "py":
            continue
        info = _xf_py_module(f["path"])
        if info is not None:
            groups.setdefault(info[0], []).append((info[1], info[2], f))
    out = []
    for members in groups.values():
        if len(members) < 2:                    # cross-file needs at least two files
            continue
        try:
            exports = {module: _xf_tainted_exports(f["content"]) for module, _pkg, f in members}
            if not any(exports.values()):
                continue
            for module, is_pkg, f in members:
                if f["path"].replace(os.sep, "/") in skip:
                    continue
                seeds = _xf_imported_taint(f["content"], module, is_pkg, exports)
                if not seeds:
                    continue
                res = _received_code_kind(f["content"], extra_always=set(seeds))
                if res is not None:
                    out.append(_xf_issue(f["path"], res[0], f["content"], res[1], sorted(set(seeds.values()))))
        except Exception:                       # one package must never kill the scan
            continue
    return out


# --- JavaScript cross-file: require()/import of a sibling module's export ---
# The same idea for an npm package's own files. Export detection is deliberately
# liberal (a function that fetches and returns is a "tainted export" — many real
# HTTP libraries do exactly that): the finding is held precise by the sink side,
# which fires only when the imported value is actually RUN (eval / Function /
# child_process / a deserializer / a dynamic import), so a package that merely
# returns received data over its API is not flagged. One hop, within one package.
_XF_JS_FUNC_RE = re.compile(r"\bfunction[ \t]*\*?[ \t]*(?P<name>[A-Za-z_$][\w$]*)[ \t]*\(")
_XF_JS_ASSIGN_RE = re.compile(r"\b(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?![=])(?P<rhs>.*)$")
_XF_JS_EXPORT_DECL_RE = re.compile(
    r"\bexport[ \t]+(?:default[ \t]+)?(?:async[ \t]+)?"
    r"(?:function[ \t]*\*?[ \t]*|(?:const|let|var)[ \t]+)(?P<name>[A-Za-z_$][\w$]*)")
_XF_JS_EXPORT_LIST_RE = re.compile(r"\bexport[ \t]*\{(?P<names>[^{}]*)\}")
_XF_JS_MODEXP_OBJ_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*\{(?P<names>[^{}]*)\}")
_XF_JS_MODEXP_PROP_RE = re.compile(
    r"\b(?:module\s*\.\s*exports|exports)\s*\.\s*(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?![=])(?P<rhs>[^\n]*)")
_XF_JS_EXPORT_DEFAULT_RE = re.compile(r"\bexport[ \t]+default[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*;?[ \t]*$", re.M)
_XF_JS_MODEXP_ALL_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*(?P<name>[A-Za-z_$][\w$]*)[ \t]*;?[ \t]*$", re.M)
_XF_JS_REQ_DESTR_RE = re.compile(
    r"\b(?:const|let|var)[ \t]*\{(?P<names>[^{}]*)\}[ \t]*=[ \t]*require\([ \t]*['\"](?P<mod>[^'\"]+)['\"]")
_XF_JS_REQ_NS_RE = re.compile(
    r"\b(?:const|let|var)[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*require\([ \t]*['\"](?P<mod>[^'\"]+)['\"]")
_XF_JS_IMP_NAMED_RE = re.compile(
    r"\bimport[ \t]*(?:[A-Za-z_$][\w$]*[ \t]*,[ \t]*)?\{(?P<names>[^{}]*)\}[ \t]*from[ \t]*['\"](?P<mod>[^'\"]+)['\"]")
_XF_JS_IMP_NS_RE = re.compile(
    r"\bimport[ \t]*\*[ \t]*as[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*from[ \t]*['\"](?P<mod>[^'\"]+)['\"]")
_XF_JS_IMP_DEFAULT_RE = re.compile(
    r"\bimport[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:,[ \t]*\{[^{}]*\})?[ \t]*from[ \t]*['\"](?P<mod>[^'\"]+)['\"]")


def _xf_js_mask_line(row):
    """`row` with each string literal's contents blanked (quotes kept) and a
    trailing // comment cut, so a source inside a string or comment is not read."""
    masked = _DL_STR_RE.sub(lambda m: m.group()[0] + " " * (len(m.group()) - 2) + m.group()[-1]
                            if len(m.group()) >= 2 else m.group(), row)
    i = masked.find("//")
    return masked[:i] if i >= 0 else masked


def _xf_js_destr(names):
    """[(export/property name, local name)] for a `{ a, b as c, d: e }` list."""
    out = []
    for item in names.split(","):
        parts = item.replace(":", " ").replace(" as ", " ").split()
        if len(parts) == 1:
            out.append((parts[0], parts[0]))
        elif len(parts) >= 2:
            out.append((parts[0], parts[1]))
    return out


def _xf_js_tainted_exports(text):
    """(named exports, default_tainted) of a JS module that hold or return a
    value received over the network. Liberal by design (the sink side keeps the
    finding precise). One indexed pass; a function body is read for _DL_WINDOW rows."""
    if not any(n in text for n in _DL_NEEDLES):
        return frozenset(), False
    rows = [_xf_js_mask_line(r) for r in text.split("\n")]
    src_rows = [k for k, r in enumerate(rows) if next(_dl_finditer(_DL_SOURCE, r), None) is not None]
    ret_rows = [k for k, r in enumerate(rows) if "return" in r]

    def near(idx, a, b):
        i = bisect.bisect_left(idx, a)
        return i < len(idx) and idx[i] < b

    tainted = set()
    for k, row in enumerate(rows):
        end = k + _DL_WINDOW
        for m in _XF_JS_FUNC_RE.finditer(row):
            if near(src_rows, k, end) and near(ret_rows, k, end):
                tainted.add(m.group("name"))
        m = _XF_JS_ASSIGN_RE.search(row)
        if m is not None:
            rhs = m.group("rhs")
            rhs_src = next(_dl_finditer(_DL_SOURCE, rhs), None) is not None
            if "=>" in rhs or rhs.lstrip().startswith(("function", "async")):
                if rhs_src or (near(src_rows, k, end) and (near(ret_rows, k, end) or "=>" in rhs)):
                    tainted.add(m.group("name"))
            elif rhs_src:
                tainted.add(m.group("name"))
    masked = "\n".join(rows)
    named, default = set(), False
    for m in _XF_JS_EXPORT_DECL_RE.finditer(masked):
        if m.group("name") in tainted:
            named.add(m.group("name"))
    for m in _XF_JS_EXPORT_LIST_RE.finditer(masked):
        for exp, local in _xf_js_destr(m.group("names")):
            if exp in tainted:                          # export { local as exp }
                named.add(local)
    for m in _XF_JS_MODEXP_OBJ_RE.finditer(masked):
        for exp, local in _xf_js_destr(m.group("names")):
            if local in tainted:                        # module.exports = { exp: local }
                named.add(exp)
    for m in _XF_JS_MODEXP_PROP_RE.finditer(masked):
        local = m.group("rhs").strip().rstrip(";").strip()
        if local in tainted or next(_dl_finditer(_DL_SOURCE, m.group("rhs")), None) is not None:
            named.add(m.group("name"))
    for m in _XF_JS_EXPORT_DEFAULT_RE.finditer(masked):
        default = default or m.group("name") in tainted
    for m in _XF_JS_MODEXP_ALL_RE.finditer(masked):
        default = default or m.group("name") in tainted
    return frozenset(named), default


def _xf_js_package(path):
    """The npm package root ('/'-separated) a dependency file lives in
    (node_modules/<name> or node_modules/@scope/<name>, innermost), else None."""
    parts = path.replace(os.sep, "/").split("/")
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] == "node_modules":
            if parts[i + 1].startswith("@") and i + 2 < len(parts):
                return "/".join(parts[:i + 3])
            return "/".join(parts[:i + 2])
    return None


def _xf_js_norm(rel):
    """A package-relative JS path as a module key: extension dropped, /index dropped."""
    for ext in (".js", ".cjs", ".mjs", ".jsx", ".json"):
        if rel.endswith(ext):
            rel = rel[:-len(ext)]
            break
    return rel[:-6] if rel.endswith("/index") else rel


def _xf_js_seeds(text, exports_of):
    """{local name (or ns.member): module spec} seeded from this file's imports of
    a sibling module's tainted exports. exports_of(spec) -> (named, default)|None.
    Read on the raw text: the module specifier and imported names are string and
    identifier tokens the require()/import patterns need whole."""
    seeds = {}
    masked = text

    def named_import(mod, pairs):
        info = exports_of(mod)
        if info is not None:
            for exp, local in pairs:
                if exp in info[0]:
                    seeds[local] = mod

    def namespace(mod, ns):
        info = exports_of(mod)
        if info is not None:
            for e in info[0]:
                seeds[ns + "." + e] = mod
            if info[1]:
                seeds[ns] = mod

    for m in _XF_JS_REQ_DESTR_RE.finditer(masked):
        named_import(m.group("mod"), _xf_js_destr(m.group("names")))
    for m in _XF_JS_IMP_NAMED_RE.finditer(masked):
        named_import(m.group("mod"), _xf_js_destr(m.group("names")))
    for m in _XF_JS_REQ_NS_RE.finditer(masked):
        namespace(m.group("mod"), m.group("ns"))
    for m in _XF_JS_IMP_NS_RE.finditer(masked):
        namespace(m.group("mod"), m.group("ns"))
    for m in _XF_JS_IMP_DEFAULT_RE.finditer(masked):
        info = exports_of(m.group("mod"))
        if info is not None and info[1]:
            seeds[m.group("name")] = m.group("mod")
    return seeds


def _xf_js_pass(files, skip):
    """The JavaScript half of the cross-file follower (see _cross_file_received_issues)."""
    groups = {}
    for f in files:
        if not f.get("dep") or f["lang"] != "js":
            continue
        root = _xf_js_package(f["path"])
        if root is not None:
            groups.setdefault(root, []).append(f)
    out = []
    for root, members in groups.items():
        if len(members) < 2:
            continue
        try:
            exports = {}
            for f in members:
                rel = f["path"].replace(os.sep, "/")[len(root) + 1:]
                exports[_xf_js_norm(rel)] = _xf_js_tainted_exports(f["content"])
            if not any(named or default for named, default in exports.values()):
                continue
            for f in members:
                if f["path"].replace(os.sep, "/") in skip:
                    continue
                impdir = posixpath.dirname(f["path"].replace(os.sep, "/")[len(root) + 1:])
                seeds = _xf_js_seeds(f["content"], lambda mod: exports.get(
                    _xf_js_norm(posixpath.normpath(posixpath.join(impdir, mod)))) if mod.startswith(".") else None)
                if not seeds:
                    continue
                res = _received_code_kind(f["content"], extra_always=set(seeds))
                if res is not None:
                    out.append(_xf_issue(f["path"], res[0], f["content"], res[1], sorted(set(seeds.values()))))
        except Exception:                       # one package must never kill the scan
            continue
    return out


def _cross_file_received_issues(files, skip_paths=()):
    """SC-IMPORT-RISK (MAJOR) for each dependency file that runs a value received
    over the network in another file of the same package (see the section
    comment), in Python and in npm packages. Skips files already flagged
    single-file. Best-effort: a package that raises is skipped."""
    skip = set(skip_paths)
    return _xf_python_pass(files, skip) + _xf_js_pass(files, skip)


def dependency_checks(root, files, manifests, issues, excludes=(), should_stop=None):
    """The --deps checks of what dependencies run (see the section comment),
    after the files and manifests were scanned: escalates the SC-INSTALL-HOOK
    findings of dependency manifests in `issues` in place and returns
    (new_issues, extra_files, stopped): the findings to add, the files read
    and scanned here (to add to the scanned files), and should_stop's reason
    when it stopped the checks (None otherwise)."""
    tree = _DependencyTree(root, files, manifests, excludes)
    dep_manifests = {m["path"] for m in manifests if m.get("dep")}
    out, extra, run = [], [], set()
    followed_to_end = {}                    # manifest -> SC-TRUNCATED issue added for it
    out.extend(_implicit_gyp_hooks(tree, manifests))
    for issue in issues:
        if issue["rule"] != "SC-INSTALL-HOOK" or not issue.get("cmd") or issue["file"] not in dep_manifests:
            continue
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, extra, stopped
        try:
            _follow_dependency_hook(tree, issue, out, extra, run, followed_to_end)
        except Exception as exc:            # one manifest must never kill the run
            out.append(scan_error_issue(issue["file"], exc))
    for f in files:
        if not f.get("dep") or f["lang"] not in ("js", "py") or f["path"].replace(os.sep, "/") in run:
            continue
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, extra, stopped
        try:
            found = dependency_import_issue(f["path"], f["content"])
            agent = dependency_agent_issue(f["path"], f["content"])
        except Exception as exc:
            found, agent = scan_error_issue(f["path"], exc), None
        if found is not None:
            out.append(found)
        if agent is not None:
            out.append(agent)
    # Cross-file received code (Python engine only): a value received in one file
    # of a package and run in another. Skips files already flagged single-file.
    if should_stop is None or not should_stop():
        flagged = {i["file"].replace(os.sep, "/") for i in out if i["rule"] == "SC-IMPORT-RISK"}
        out.extend(_cross_file_received_issues(files, flagged))
    return out, extra, None


def _is_package_root(directory):
    """Is `directory` ('/'-separated) an installed npm package's own root:
    node_modules/<name> or node_modules/@scope/<name>?"""
    parts = directory.split("/")
    return len(parts) >= 2 and (parts[-2] == "node_modules" or (
        len(parts) >= 3 and parts[-3] == "node_modules" and parts[-2].startswith("@")))


def _implicit_gyp_hooks(tree, manifests):
    """SC-INSTALL-HOOK (MAJOR) for each dependency npm builds with node-gyp:
    for a package whose root holds a binding.gyp, and whose package.json
    names no install or preinstall script (and does not set "gypfile":
    false), npm runs `node-gyp rebuild` on install — the hook the registry
    lists as "install (implicit)" (_ArtifactScan._implicit_gyp_hook). A
    package with no install script at all ran its binding.gyp's actions and
    command expansions without a hook finding."""
    out = []
    for m in manifests:
        rel = m["path"].replace(os.sep, "/")
        if not m.get("dep") or posixpath.basename(rel) != "package.json":
            continue
        base = posixpath.dirname(rel)
        gyp = posixpath.join(base, "binding.gyp")
        if not _is_package_root(base) or gyp not in tree.manifests:
            continue
        data, _problems = load_manifest(m["path"], m["content"])
        if not isinstance(data, dict) or data.get("gypfile") is False:
            continue
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        if any(isinstance(scripts.get(h), str) and scripts[h].strip() for h in ("install", "preinstall")):
            continue
        out.append(_sc_install_hook_issue(tree.manifests[gyp]["path"], 1, [], "install (implicit)",
                                          "node-gyp rebuild", False))
    return out


def _follow_dependency_hook(tree, issue, out, extra, run, followed_to_end):
    manifest = issue["file"]
    base = posixpath.dirname(manifest.replace(os.sep, "/"))
    direct = agent_hijack_in_command(issue["cmd"])         # the hook runs the agent itself
    if direct is not None:
        m = tree.manifests.get(manifest.replace(os.sep, "/"))
        if m is not None:
            mlines = m["content"].split("\n")
            out.append(_agent_hijack_issue(manifest, issue["line"], mlines, direct[0], direct[1],
                                           redactor=_Redactor(mlines)))
    targets, complete = follow_hook(issue["cmd"])
    if not complete and manifest not in followed_to_end:
        followed_to_end[manifest] = True
        out.append(truncated_issue(manifest, (
            f"its install hook is more than Lazaret follows ({HOOK_MAX_COMMANDS:,} commands, "
            f"{HOOK_MAX_TARGETS} scripts, {HOOK_MAX_CHARS:,} characters, "
            f"{HOOK_MAX_PATH:,}-character paths)")))
    for target in targets:
        path = _tree_join(base, target)
        rel = tree.resolve(path) if path is not None else None
        if rel is None:
            continue
        text = _dependency_script_text(tree, rel, "sh" if rel.endswith(".sh") else "js", out, extra, run)
        reasons = install_script_risk(text) if text else []
        if reasons and issue["sev"] not in ("BLOCKER", "CRITICAL"):
            msg = f"Install hook runs {target}, which {'; and '.join(reasons)}."
            issue["sev"] = "CRITICAL"
            issue["msg"] = _redact_text(msg) if REDACT_SECRETS else msg
        agent = dependency_agent_issue(rel.replace("/", os.sep), text) if text else None
        if agent is not None:
            out.append(agent)


def _dependency_script_text(tree, rel, as_lang, out, extra, run):
    """Text of a file an install hook runs, or None when it cannot be read
    as text (an SC-TRUNCATED finding then says why)."""
    run.add(rel)
    if rel in tree.sources:
        return tree.sources[rel]["content"]
    if rel in tree.manifests:
        return tree.manifests[rel]["content"]
    if rel not in tree.read:
        tree.read[rel] = _read_dependency_script(tree, rel, as_lang, out, extra)
    return tree.read[rel]


def _read_dependency_script(tree, rel, as_lang, out, extra):
    """A file an install hook runs that the walk did not read as source:
    read it, and scan it as a dependency's JavaScript (node runs
    lib/install.dat as JavaScript) unless it is a shell script."""
    disp = rel.replace("/", os.sep)
    try:
        data = _read_prefix(os.path.join(tree.root, *rel.split("/")), SOURCE_SIZE_CAP + 1)
    except OSError as exc:
        reason = str(exc) if isinstance(exc, _NotRegularFile) else exc.strerror or type(exc).__name__
        out.append(truncated_issue(disp, f"it runs at install time but could not be read ({reason})"))
        return None
    if len(data) > SOURCE_SIZE_CAP:
        out.append(truncated_issue(disp, f"it runs at install time but is larger than the "
                                         f"{SOURCE_SIZE_CAP:,}-byte file limit"))
        return None
    if looks_binary(data[:2048]):
        out.append(truncated_issue(disp, "it runs at install time but is not text, so it could not be scanned"))
        return None
    if as_lang == "sh" or shebang_lang(data[:HEADER_SAMPLE_BYTES].decode("utf-8", "replace")) == "sh":
        return normalize_newlines(data.decode("utf-8", "replace"))
    text, decode_issues = decode_member(disp, data, lang="js")
    out.extend(decode_issues)
    out.extend(scan_file(disp, text, "js", dep=True))
    extra.append({"path": disp, "content": text, "lang": "js", "dep": True})
    return text


def dependency_import_issue(path, text):
    """SC-IMPORT-RISK (MAJOR) for a dependency's JavaScript or Python file
    that fails the import-time test (import_time_risk), else None."""
    reasons, line = import_time_risk(text)
    if not reasons:
        return None
    lines = text.split("\n")
    return mk_issue(
        {"id": "SC-IMPORT-RISK", "name": "Risky import-time code", "type": "HOTSPOT", "sev": "MAJOR",
         "msg": f"Dependency code {'; and '.join(reasons)}.", "why": _DEP_IMPORT_RISK_WHY,
         "fix": "Read the file: what does it collect, and where does it send it?",
         "ref": "CWE-506 · Supply chain"}, path, line, lines, redactor=_Redactor(lines))


def redact_file_issues(issues, files):
    """Apply each scanned file's redaction to the findings numbered by its
    scan lines (source_lines: scan_file's and the flow engine's), in place.

    redact_result sweeps snippets with the secret patterns only, and a PEM
    block only when its BEGIN line is in the same snippet: a finding built
    from raw lines outside scan_file lacked the file's entropy literals and
    PEM blocks (review: the X-CMD snippet of a flow showed the `seed = "…"`
    literal S-ENTROPY redacted, in the JSON and the HTML report). Per file,
    the literal set and the file-wide PEM set are built once; every snippet
    line that is still the raw text of its file line becomes that line as
    mk_issue would show it (a line its builder already redacted or clipped
    is left alone), and msg / cmd get the file's literals. One file's lines
    are held at a time."""
    if not REDACT_SECRETS:
        return issues
    by_path = {f["path"]: f for f in files}
    groups = {}
    for i in issues:
        if i.get("file") in by_path:
            groups.setdefault(i["file"], []).append(i)
    for path, group in groups.items():
        f = by_path[path]
        red = _Redactor(source_lines(f["content"], f.get("lang")))
        for i in group:
            for key in ("msg", "cmd"):
                v = i.get(key)
                if isinstance(v, str):
                    nv = _redact_text(v, red.secrets())
                    if nv != v:
                        i[key] = nv
            snip, start = i.get("snippet"), i.get("snipStart")
            if not isinstance(snip, list) or not isinstance(start, int):
                continue
            out = None
            for k, line in enumerate(snip):
                j = start - 1 + k
                if isinstance(line, str) and 0 <= j < len(red.lines) and line == red.lines[j]:
                    shown = red.redacted(j)
                    if shown != line:
                        if out is None:
                            out = list(snip)
                        out[k] = shown
            if out is not None:
                i["snippet"] = out
    return issues


def scan_project(root, exclude=(), include_deps=False, taint_config=None,
                 redact_secrets=True, extra_issues=(), should_stop=None):
    """The complete project scan, shared by the CLI (main) and the MCP server:
    collect -> scan files -> manifests / binding.gyp -> collection findings
    (binary, pyc, encoding, symlink, unreadable, truncated) -> interprocedural
    flow analysis (guarded: a failure degrades to the intra-file engine with a
    visible warning) -> pruned-tree notes -> metrics / quality gate ->
    secret-redaction sweep. Prints nothing; safe to call repeatedly in one
    process (no per-scan module state leaks between calls).

    root            directory to scan (str)
    exclude         directory names to prune (like --exclude)
    include_deps    walk dependency trees too (like --deps)
    taint_config    optional, already-parsed taint spec (dict) applied before
                    scanning; rejected rules are returned as warnings. The CLI
                    loads and validates its config itself (SEAM: flow-sca's
                    taint-config block in main()) and passes None. NOTE: the
                    taint tables are process-global; a spec applied here stays
                    applied for later scans in the same process.
    redact_secrets  redact credentials in snippets (default on; REDACT_SECRETS
                    is restored afterwards)
    extra_issues    findings produced before the scan that belong in the
                    result (e.g. the CLI's Q-TAINT-CONFIG notes)
    should_stop     optional callable, checked before each file and manifest
                    (the MCP server's time budget and cancellation). It may
                    raise to abort the scan, or return a reason string to stop
                    early: the files not reached are then reported by one
                    SC-TRUNCATED finding (so a partial scan can never pass the
                    gate), the cross-file pass is skipped, and the result
                    carries "incomplete": True and "incompleteReason".

    Returns the build_result() dict — project, scannedAt, pass, conditions,
    metrics, counts, ratings, supplyChain, crossFile, perFile, issues — plus
    "warnings": [str] (degraded-analysis notes; the CLI prints them).
    Raises ScanTargetError (usage error) when root does not exist, is not a
    directory, cannot be read, or holds nothing to scan.
    """
    global REDACT_SECRETS
    root = os.fspath(root)
    if not os.path.exists(root):
        raise ScanTargetError(f"{_fs_display(root)} does not exist")
    if not os.path.isdir(root):
        raise ScanTargetError(f"{_fs_display(root)} is not a directory")
    saved_redact = REDACT_SECRETS
    REDACT_SECRETS = bool(redact_secrets)
    try:
        warnings = []
        # --- SEAM (flow-sca): library callers' taint spec ------------------
        if taint_config is not None:
            flow_warnings = []
            apply_taint_config(taint_config)
            if lazaret_flow is not None:
                lazaret_flow.configure(taint_config,
                                       on_warn=lambda msg: flow_warnings.append(msg))
            warnings.extend(f"taint config: {m}" for m in
                            _dedupe(get_taint_config_warnings() + flow_warnings))
        col = _collect(root, exclude, include_deps=include_deps)
        files, manifests = col["files"], col["manifests"]
        if not files and not manifests and not col["pth"] and not col["issues"]:
            raise ScanTargetError(
                f"nothing to scan under {_fs_display(root)}: no Python, JavaScript or "
                f"SQL sources, package manifests or other files to check")
        issues = list(extra_issues) + list(col["issues"])
        numbered = []       # findings numbered by their file's scan lines (redact_file_issues)
        scanned, stopped = [], None
        for f in files:
            stopped = should_stop() if should_stop is not None else None
            if stopped:
                break
            try:
                found = scan_file(f["path"], f["content"], f["lang"], dep=f.get("dep", False))
                issues.extend(found)
                numbered.extend(found)
            except Exception as exc:        # one file must never kill the run
                issues.append(scan_error_issue(f["path"], exc))
            scanned.append(f)
        for mf in manifests:
            if not stopped and should_stop is not None:
                stopped = should_stop()
            if stopped:
                break
            try:
                issues.extend(_scan_manifest_entry(mf))
            except Exception as exc:
                issues.append(scan_error_issue(mf["path"], exc))
        if not stopped:
            # --deps: what the dependencies run (install hooks, import-time code)
            found, extra, dep_stopped = dependency_checks(root, files, manifests, issues, exclude, should_stop)
            issues.extend(found)
            numbered.extend(found)
            files.extend(extra)
            scanned.extend(extra)
            if dep_stopped:
                stopped = dep_stopped
                issues.append(truncated_issue(
                    ".", f"{stopped}: what the dependencies run was not checked to the end"))
        else:
            issues.append(truncated_issue(
                ".", f"{stopped}: {len(files) - len(scanned)} of {len(files)} files "
                     f"not scanned"))
            files = scanned
        # G10: skipped-directory accounting — INFO findings make the coverage
        # gap visible instead of silent.
        issues.extend(skipped_tree_issues(col["skipped"]))
        if lazaret_flow is not None and not stopped:
            # The interprocedural engine can fail on input it does not
            # understand; degrade to the intra-file engine rather than crash
            # mid-scan, and say so instead of hiding it.
            try:
                flows = lazaret_flow.analyze(files)
                issues.extend(flows)
                numbered.extend(flows)
            except Exception as exc:
                warnings.append(f"interprocedural taint analysis skipped "
                                f"({type(exc).__name__}: {_safe_text(exc)})")
        # the flow engine copies raw source lines into its snippets: give
        # them (and every scan_file finding) the file's own redaction
        redact_file_issues(numbered, files)
        res = build_result(root, files, issues)
        res["warnings"] = warnings
        if stopped:
            res.update(incomplete=True, incompleteReason=stopped)
        # L1: belt-and-braces — no SECRET-rule issue may reach a report or
        # the baseline fingerprinter with its raw flagged line.
        redact_result(res)
        return res
    finally:
        REDACT_SECRETS = saved_redact

# ---------------- Metrics / ratings ----------------
def compute_metrics(all_files):
    files = [f for f in all_files if not f.get("dep")]  # deps excluded from quality metrics
    ncloc = comments = 0
    win_map = {}
    for f in files:
        code = []
        flines = _unicode13.pin(f["content"]).split("\n")
        try:
            cmask = comment_mask(flines, f["lang"], jsx_reading(f["path"]))
        except Exception:       # its scan failed the same way (SC-TRUNCATED): count its lines
            cmask = None        # as code rather than lose the whole report (review B3)
        for i, l in enumerate(flines):
            t = l.strip()
            if not t:
                continue
            if cmask is not None and cmask[i]:
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

#: INFO scan-coverage notes. Typed SMELL for display, but they describe what
#: the scanner could not look at, not the code: they do not count toward the
#: maintainability rating (a single symlink in a small project used to be
#: enough to fail "Maintainability >= C").
COVERAGE_RULES = frozenset({"Q-SKIPPED-TREE", "Q-SYMLINK", "Q-UNREADABLE",
                            # analysis-coverage notes from the flow engine and the
                            # taint-config loader (Python-only; the npm engine has
                            # neither)
                            "Q-FLOW-SKIPPED", "Q-FLOW-INCOMPLETE", "Q-FLOW-RECURSION",
                            "Q-TAINT-CONFIG"})

def _rated_smells(issue):
    """How many code smells a SMELL finding counts for in the rating: one,
    except a Q-CAPPED note, which counts the findings it stands for when
    they are smells (and nothing when they are bugs). The rating is then
    what it would be without the cap (review: 2000 over-long lines listed
    as 200 Q-LONGLINE + one Q-CAPPED rated C and passed; they are E)."""
    if issue.get("rule") == "Q-CAPPED" and isinstance(issue.get("omitted"), int):
        return issue["omitted"] if issue.get("omittedType") == "SMELL" else 0
    return 1


def maintainability_rating(issues, ncloc):
    smells = sum(_rated_smells(i) for i in issues
                 if i["type"] == "SMELL" and i.get("rule") not in COVERAGE_RULES)
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
    # INFO supply-chain entries are inventory (e.g. a project's own prepare
    # hook, shared semantics 3), not indicators.
    supply = sum(1 for i in issues if i["rule"].startswith("SC-") and i["sev"] != "INFO")
    conds.append({"label": "No supply-chain indicators", "ok": supply == 0})
    cross_file = sum(1 for i in issues if i["rule"].startswith("X-"))
    conds.append({"label": "No cross-file taint flows", "ok": cross_file == 0})
    return {"project": _fs_display(os.path.abspath(os.fspath(root))),
            "scannedAt": datetime.datetime.now().isoformat(timespec="seconds"),
            "pass": all(c["ok"] for c in conds), "conditions": conds,
            "metrics": metrics, "counts": counts, "ratings": ratings,
            "supplyChain": supply, "crossFile": cross_file,
            "perFile": per_file, "issues": issues}

# ---------------- Terminal output ----------------
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if _stdout_is_tty() else str(s)


def _stdout_is_tty():
    """sys.stdout is a terminal. False when there is no stdout at all: with
    file descriptor 1 closed at start (`lazaret dir >&-`) sys.stdout is None,
    and isatty() raised AttributeError (exit 5, no reports)."""
    try:
        return sys.stdout is not None and sys.stdout.isatty()
    except (AttributeError, OSError, ValueError):
        return False

SEV_COLOR = {"BLOCKER": "41;97", "CRITICAL": "31", "MAJOR": "33", "MINOR": "36", "INFO": "34"}

# C0-terminal (audit H1: terminal escape-sequence injection) — every string
# that might derive from scanned content, archive member names, registry
# metadata or config paths is passed through sanitize_term() before it reaches
# a terminal/CI log. safe_excerpt always did this for the code excerpt; the
# file-path header, the issue messages and the registry print paths did not.
# The mapped set: every C0 control byte except TAB (0x09) and LF (0x0a),
# plus CR (0x0d), DEL (0x7f), the C1 controls U+0080–U+009F (0x9b is a
# one-byte CSI introducer on many terminals, 0x9d an OSC) and the bidi
# embedding/override/isolate controls U+202A–U+202E, U+2066–U+2069 (they
# reorder what the terminal shows — Trojan Source). The npm engine's
# sanitizeTerm maps exactly the same set. Built with chr() so the table is
# exact and readable; ESC (0x1b) and BEL (0x07) — the two bytes the audit
# PoC used to forge SGR colors and hijack the terminal title — are inside
# these ranges.
_BIDI_CONTROLS = (
    "".join(chr(n) for n in range(0x202a, 0x202f))  # LRE RLE PDF LRO RLO
    + "".join(chr(n) for n in range(0x2066, 0x206a))  # LRI RLI FSI PDI
)
_SANITIZE_TERM_CHARS = (
    "".join(chr(n) for n in range(0x00, 0x09))      # NUL … BS
    + "".join(chr(n) for n in (0x0b, 0x0c))         # VT, FF
    + "".join(chr(n) for n in range(0x0d, 0x20))    # CR, SO … US (incl. ESC)
    + "".join(chr(n) for n in range(0x7f, 0xa0))    # DEL, C1 controls (incl. CSI)
    + _BIDI_CONTROLS
)
_SANITIZE_TERM_TAB = str.maketrans(
    {ch: "·" for ch in _SANITIZE_TERM_CHARS})


def sanitize_term(s):
    """Neutralize terminal-control bytes in a string before printing.

    Hostile package content reaches the terminal via file paths (archive
    member names, walked repo paths), issue messages (X-FLOW source/sink
    paths, install-hook command text), registry metadata and config paths.
    Every C0 control byte except newline and tab, plus CR, DEL, the C1
    controls and the bidi controls (_SANITIZE_TERM_CHARS), maps to
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


#: Line breaks sanitize_term keeps (\n) or does not know (U+2028, U+2029);
#: every other line break (\r, \v, \f, \x1c-\x1e, \x85) is a control
#: character it already maps.
_LINE_BREAKS_TAB = str.maketrans({"\n": "·", "\u2028": "·", "\u2029": "·"})


def sanitize_term_line(s):
    """sanitize_term for a value printed inside one line of output — a
    path, a link target, a finding's message: line breaks become '·' too,
    so the value cannot start a line of its own (review: a file named
    `zz\\n\\n  Quality gate:  PASSED \\n::notice::…\\n  x.py` printed a fake
    "PASSED" line and a GitHub workflow command at column 0). Twin of the
    npm engine's sanitizeTermLine."""
    return str(s).translate(_SANITIZE_TERM_TAB).translate(_LINE_BREAKS_TAB)

# Rules whose flagged line reveals a credential. The flagged LINE is redacted
# in every persistent artifact by default (see redact_secret_snippet — audit
# L1: the old --redact-secrets flag only sanitized the TERMINAL excerpt while
# JSON/HTML/SARIF reports and the registry DB embedded the full line);
# --no-redact-secrets is the opt-out for audit workflows that need to see the
# secret in the report.
SECRET_RULES = {"S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"}
REDACT_SECRETS = True


class forced_redaction:
    """Redaction on for the duration of a `with` block, whatever
    REDACT_SECRETS says, and the old value restored after (review P2).

    For results that are stored: the registry's state DB must never hold a
    raw credential line, so its scans run under this, and the opt-outs
    (--no-redact-secrets, LAZARET_NO_REDACT) keep working for project scans
    only. Redaction happens when each finding is created, from the whole
    file (PEM blocks, the file's high-entropy literals), which a later sweep
    over the stored snippets cannot redo; hence forcing it for the whole
    scan rather than cleaning up afterwards. Scans run one at a time in a
    process (the MCP server has a single tool thread), so a module-level
    switch is safe here."""

    def __enter__(self):
        global REDACT_SECRETS
        self._saved = REDACT_SECRETS
        REDACT_SECRETS = True
        return self

    def __exit__(self, *exc):
        global REDACT_SECRETS
        REDACT_SECRETS = self._saved
        return False


REDACT_PLACEHOLDER = "[redacted: secret rule {RULE}]"
REDACT_FINGERPRINT = "[redacted: secret rule "   # marker of an already-redacted line
EXCERPT_WIDTH = 100   # overridable via --excerpt-width

def safe_excerpt(text, width=None):
    """Sanitize a source line for terminal display. Scanned code may be hostile
    (esp. packages), so strip ANSI/control bytes that could rewrite the terminal
    — ESC, CR, BS, BEL, NUL, C1 controls, bidi controls and anything else
    str.isprintable() rejects — replacing them with '·'. Tabs become spaces,
    the line is trimmed and truncated with an ellipsis. (Twin of the npm
    engine's safeExcerpt; the bidi controls are named explicitly there and
    here so the result does not hang on a Unicode database's category.)"""
    if width is None:
        width = EXCERPT_WIDTH
    text = text.replace("\t", " ").strip()
    if not text:
        return ""
    out = []
    for ch in text[:width]:
        o = ord(ch)
        if ch == " " or 0x20 <= o < 0x7f or (
                o > 0xa0 and ch.isprintable() and ch not in _BIDI_CONTROLS):
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
    requires BOTH mk_issue to miss AND this sweep to miss. The sweep also
    clips every snippet line to SNIPPET_MAX characters (issues built outside
    mk_issue, e.g. by the flow engine, get the same size bound).
    """
    for i in res.get("issues", []):
        if REDACT_SECRETS:
            # free-text fields that can copy source: the message, and the
            # install-hook command kept for the registry (`cmd`)
            for key in ("msg", "cmd"):
                v = i.get(key)
                if isinstance(v, str):
                    nv = _redact_text(v)
                    if nv != v:
                        i[key] = nv
        snip = i.get("snippet")
        if not isinstance(snip, list):
            continue
        if not REDACT_SECRETS:
            clipped = [clip_snippet_line(l) for l in snip]
            if clipped != snip:
                i["snippet"] = clipped
            continue
        idx = i["line"] - i.get("snipStart", i["line"])
        secret = i.get("rule") in SECRET_RULES
        if secret and 0 <= idx < len(snip) and isinstance(snip[idx], str) \
                and REDACT_FINGERPRINT not in snip[idx]:
            i["snippet"] = [clip_snippet_line(l) for l in
                            redact_secret_snippet(i["rule"], snip, idx, snip[idx])]
            continue
        # non-secret rule (or already-redacted secret): sweep context lines
        cleaned = [clip_snippet_line(l) for l in _redact_lines(snip)]
        if cleaned != snip:
            i["snippet"] = cleaned
    return res

def print_report(res, quiet):
    m, ct, rt = res["metrics"], res["counts"], res["ratings"]
    print()
    print(c("1", f"Lazaret scan — {sanitize_term_line(res['project'])}"))
    print(f"  {m['files']} files · {m['ncloc']} lines of code · {m['dupPct']}% duplication")
    print()
    gate = c("42;30", " PASSED ") if res["pass"] else c("41;97", " FAILED ")
    print(f"  Quality gate: {gate}")
    for cond in res["conditions"]:
        mark = c("32", "✓") if cond["ok"] else c("31", "✗")
        # audit H1: a gate condition label can embed a scanned file path
        # ("Taint analysis incomplete → <file>", build_result) — hostile repo.
        print(f"    {mark} {sanitize_term_line(cond['label'])}")
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
                print(f"\n  {c('4', sanitize_term_line(cur_file))}")
            sev_txt = f"{i['sev']:<8}"
            prefix = f"    L{i['line']:<5} {sev_txt} [{i['rule']}] "
            # audit H1: i['msg'] is static text for most rules but embeds
            # attacker data for several (X-FLOW source/sink paths, the
            # SC-INSTALL-HOOK {cmd!r}, SCA bundle fields). Sanitized inside
            # the f-string, AFTER the colored severity span — sanitizing the
            # whole colored string would strip c()'s own SGR reset.
            print(f"    L{i['line']:<5} {c(SEV_COLOR[i['sev']], sev_txt)} [{i['rule']}] {sanitize_term_line(i['msg'])}")
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
<header><div class="logo">Laza<span>ret</span> · Project Report</div>
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

#: SARIF run-level base for every repo-relative artifactLocation.
SARIF_SRCROOT = "%SRCROOT%"
LAZARET_INFORMATION_URI = "https://lazaret.dev"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def sarif_uri(path):
    """A report path as a SARIF artifactLocation: (uri, uriBaseId or None).

    Review item 8: the uri used to be the raw path — 'my dir/a#1%2.py'
    verbatim, so '#' started a fragment and '%2.' was a broken escape. Now a
    root-relative path becomes a percent-encoded relative reference (RFC
    3986, '/' separators) resolved against %SRCROOT%; an absolute path
    becomes a file: URI."""
    p = _safe_text(path)
    if os.path.isabs(p):
        return _pathlib.Path(p).as_uri(), None
    if os.sep != "/":
        p = p.replace(os.sep, "/")
    return _urlparse.quote(p, safe="/"), SARIF_SRCROOT


def _root_uri(root):
    uri = _pathlib.Path(os.path.abspath(os.fspath(root))).as_uri()
    return uri if uri.endswith("/") else uri + "/"


def sarif_report(res, root=None):
    """SARIF 2.1.0 log for a scan result. `root` is the scan root (defaults
    to res['project']); it becomes originalUriBaseIds['%SRCROOT%']."""
    # L1: sarif_report receives the result AFTER redact_result has swept it,
    # and it emits no snippet text — but it does embed issue msg/why/fix
    # strings from the result. Defensively sweep here too so a future caller
    # that skips the main() pass cannot ship an unredacted result into SARIF.
    redact_result(res)
    rules_seen, rule_index, results = {}, {}, []
    for i in res["issues"]:
        if i["rule"] not in rules_seen:
            rule_index[i["rule"]] = len(rules_seen)
            rules_seen[i["rule"]] = {
                "id": i["rule"], "name": i["name"],
                "shortDescription": {"text": i["name"]},
                "fullDescription": {"text": i["why"]},
                "help": {"text": i["fix"]}}
        uri, base = sarif_uri(i["file"])
        loc = {"uri": uri}
        if base:
            loc["uriBaseId"] = base
        try:
            line = max(1, int(i.get("line") or 1))
        except (TypeError, ValueError):
            line = 1
        results.append({
            "ruleId": i["rule"],
            "ruleIndex": rule_index[i["rule"]],
            "level": SARIF_LEVEL[i["sev"]],
            "message": {"text": i["msg"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": loc,
                "region": {"startLine": line}}}]})
    return {"$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Lazaret",
                                          "version": _lazaret_pkg.__version__,
                                          "informationUri": LAZARET_INFORMATION_URI,
                                          "rules": list(rules_seen.values())}},
                      "originalUriBaseIds": {SARIF_SRCROOT: {
                          "uri": _root_uri(res["project"] if root is None else root)}},
                      "results": results}]}

# ---------------- Baseline (new-code focus) ----------------
def fingerprint(issue):
    # One definition shared with the report writer (which signs these
    # fingerprints when $LAZARET_BASELINE_KEY is set): rule | path with
    # forward slashes (portable across OSes) | stripped flagged line.
    return lazaret_report.fingerprint(issue)
# NOTE: redaction (audit L1) happens at mk_issue time, BEFORE this
# fingerprint is computed — the placeholder text is deterministic for a
# given (rule, secret length), so same-engine baselines still match; a
# pre-redaction-era baseline (with raw secret lines) simply won't match a
# secret fingerprint any more, and those issues surface as new — the safe
# direction for a security tool.


def _baseline_untrusted(res, baseline_path, reason):
    """Count every current finding as new and say why the baseline was not
    trusted."""
    # audit H1: baseline_path may resolve inside the scanned repo; the
    # message text is sanitized before it reaches the terminal.
    print(f"warning: baseline {sanitize_term_line(baseline_path)} {reason} — "
          f"treating it as untrusted: all current findings are counted "
          f"as new", file=sys.stderr)
    for i in res["issues"]:
        i["new"] = True
    res["newIssues"] = len(res["issues"])
    res["baselineUntrusted"] = True


def apply_baseline(res, baseline_path, scan_root=None):
    """Mark res["issues"] new/not-new against a previous JSON report.

    Trust (G17): a baseline is a REPORT-shaped file that CI may gate on, and
    the engine marker is a public constant — a hand-written 5-line file
    carrying it used to zero `newIssues` ("New issues vs baseline: 0") while
    the scan had live findings. So:
      * $LAZARET_BASELINE_KEY set: reports are HMAC-signed over their
        fingerprints, and a baseline is trusted only if its signature
        verifies with that key (wherever it lives).
      * no key: a baseline inside the scanned tree (*scan_root*) is
        untrusted — the scanned repository could have planted it; outside
        the tree the engine-marker check applies.
    An untrusted baseline counts every finding as new (fail closed)."""
    if lazaret_report is None:
        print("warning: baseline validation unavailable (lazaret_report not "
              "importable); baseline ignored", file=sys.stderr)
        return
    if not lazaret_report.is_our_report(baseline_path, "json"):
        _baseline_untrusted(
            res, baseline_path,
            "is not a report produced by this engine (no matching engine "
            "marker, or wrong shape)")
        return
    key = lazaret_report.baseline_key()
    if (key is None and scan_root is not None
            and lazaret_report.path_is_inside(baseline_path, scan_root)):
        _baseline_untrusted(
            res, baseline_path,
            f"is inside the scanned tree and ${lazaret_report.BASELINE_KEY_ENV} "
            f"is not set (the scanned repository could have planted it) — "
            f"keep baselines outside the scanned tree (e.g. in $RUNNER_TEMP) "
            f"or set {lazaret_report.BASELINE_KEY_ENV} so reports are signed")
        return
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            prev = json_loads_bounded(fh.read())
    except (OSError, ValueError, MemoryError) as exc:
        # ValueError covers JSONDecodeError, UnicodeDecodeError, the
        # int-digit limit and JsonTooDeep. audit H1: {exc} can echo hostile baseline content
        # (JSONDecodeError position text); sanitize both interpolations.
        print(f"warning: could not read baseline {sanitize_term_line(baseline_path)}: "
              f"{sanitize_term_line(exc)}", file=sys.stderr)
        return
    # 48033f94: validate the baseline's shape before using it. A baseline is
    # attacker-adjacent input (it usually comes from the scanned repo or CI
    # artifacts); {"issues":"not-a-list"} raised TypeError and a top-level
    # list raised AttributeError, both crashing the CLI after the scan had
    # already run — losing every result.
    if not isinstance(prev, dict):
        # audit H1: the baseline path can resolve inside the scanned repo.
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: top level is "
              f"{type(prev).__name__}, not an object — expected "
              f'{{"issues": [...]}}; baseline ignored', file=sys.stderr)
        return
    issues = prev.get("issues", [])
    if not isinstance(issues, list):
        # audit H1: sanitize the repo-adjacent baseline path before printing.
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: 'issues' is "
              f"{type(issues).__name__}, not a list — baseline ignored",
              file=sys.stderr)
        return
    if key is not None:
        ok, why = lazaret_report.verify_signature(prev, key)
        if not ok:
            _baseline_untrusted(res, baseline_path, f"is not trusted: {why}")
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
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: {skipped} malformed "
              f"issue entrie(s) skipped (expected objects with "
              f"rule/file/line)", file=sys.stderr)
    new_count = 0
    for i in res["issues"]:
        i["new"] = fingerprint(i) not in known
        new_count += i["new"]
    res["newIssues"] = new_count

# ---------------- Main ----------------
# Exit codes (FIX-SPEC 10): 0 scan ok (or the gate failed without --ci);
# 1 gate failed with --ci, or a hostile manifest (SC-MANIFEST-DEPTH — the only
# finding that forces a non-zero exit without --ci); 2 usage error (unknown
# option; missing, non-directory, unreadable or empty target); 3 report output
# error (lazaret_report.EXIT_OUTPUT); 4 taint config rejected
# (EXIT_TAINT_CONFIG); 5 internal error — never a raw traceback, and never
# confusable with "gate failed".
EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 5


_LINE_BREAKS_SPACE = str.maketrans({"\n": " ", "\u2028": " ", "\u2029": " "})


def _internal_error(exc):
    """Report an uncaught exception as `error: internal: …` and exit 5. The
    traceback is printed only with LAZARET_DEBUG=1."""
    debug = os.environ.get("LAZARET_DEBUG") == "1"
    try:
        if debug:
            _traceback.print_exc()
        detail = sanitize_term(_safe_text(exc)).translate(_LINE_BREAKS_SPACE)
        if len(detail) > 500:
            detail = detail[:497] + "..."
        print(f"error: internal: {type(exc).__name__}" + (f": {detail}" if detail else ""),
              file=sys.stderr)
        if not debug:
            print("  (this is a Lazaret bug, not a scan result; set LAZARET_DEBUG=1 "
                  "for a traceback)", file=sys.stderr)
    except Exception:
        pass
    sys.exit(EXIT_INTERNAL)


class _PipeSafeStdout:
    """sys.stdout while the CLI runs. The terminal report is printed before
    the reports are written, so a reader that went away turned the scan into
    `error: internal: BrokenPipeError`, exit 5, and no JSON or HTML report
    (review: `lazaret --ci dir | head -n 2`). Once a write or flush fails
    that way, stdout is pointed at the null device (so the flush at exit
    cannot fail either, which would make the exit status 120) and the rest of
    the output is dropped; the scan writes its reports and exits with its
    own code."""

    def __init__(self, stream):
        self._stream = stream
        self.gone = False

    def _drop(self):
        self.gone = True
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(devnull, self._stream.fileno())
            finally:
                os.close(devnull)
        except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
            pass

    def _gone_error(self, exc):
        """The reader went away: EPIPE (BrokenPipeError) on POSIX, EINVAL
        from Windows for a pipe closed at the other end, or a closed file."""
        if isinstance(exc, OSError):
            return exc.errno in (errno.EPIPE, errno.EINVAL)
        return getattr(self._stream, "closed", False) is True

    def write(self, text):
        if not self.gone:
            try:
                return self._stream.write(text)
            except (OSError, ValueError) as exc:
                if not self._gone_error(exc):
                    raise
                self._drop()
        return len(text)

    def flush(self):
        if not self.gone:
            try:
                self._stream.flush()
            except (OSError, ValueError) as exc:
                if not self._gone_error(exc):
                    raise
                self._drop()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def main(argv=None):
    """`lazaret` console entry point. argv defaults to sys.argv[1:]. Any
    uncaught exception becomes `error: internal: …` with exit 5 (review item
    4: a non-UTF-8 file name crashed the HTML writer with a traceback and
    exit 1 — indistinguishable from a failed gate). A closed stdout never
    stops the scan (see _PipeSafeStdout)."""
    configure_stdio()
    real_stdout = sys.stdout
    guard = _PipeSafeStdout(real_stdout) if real_stdout is not None else None
    if guard is not None:
        sys.stdout = guard
    try:
        return _main(argv)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        _internal_error(exc)
    finally:
        if guard is not None:
            try:
                guard.flush()                # the buffered tail, while it is still guarded
            except Exception:                # (a full disk: the output is lost, the exit code is not)
                pass
            if sys.stdout is guard:
                sys.stdout = real_stdout


def _positive_int(text):
    """argparse type: an integer above zero."""
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive number of bytes, got {text!r}")
    return value


def _main(argv=None):
    global REDACT_SECRETS, EXCERPT_WIDTH, SOURCE_SIZE_CAP
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
                         "(Semgrep-style); trusted fully. A file that can't be "
                         "loaded (missing, unreadable, invalid JSON, too deep) or "
                         "has rules rejected by validation exits 4.")
    ap.add_argument("--trust-repo-config", action="store_true",
                    help="Load the scanned repository's own .lazaret-taint.json "
                         "(sources and sinks only — its sanitizers are ignored). "
                         "Without this flag the file is noted and not loaded.")
    ap.add_argument("--strict-taint-config", action="store_true",
                    help="Treat taint-config rules rejected by validation (unknown "
                         "category, empty pattern), and a config that can't be "
                         "loaded, as fatal — exit 4 even for the repository's "
                         ".lazaret-taint.json. Always on for an explicit "
                         "--taint-config.")
    ap.add_argument("--ci", action="store_true", help="Exit 1 if the quality gate fails")
    ap.add_argument("--no-redact-secrets", action="store_true",
                    help="Opt OUT of secret redaction in reports: keep the matched line "
                         "for credential findings (S-SECRET/S-TOKEN/SQL-CRED/S-ENTROPY). "
                         "By default the flagged line is replaced with a placeholder in "
                         "every artifact — terminal, JSON/HTML/SARIF reports — so scans of "
                         "your own code do not persist credentials into CI artifacts.")
    ap.add_argument("--excerpt-width", type=int, default=EXCERPT_WIDTH, metavar="N",
                    help=f"Chars of the matched line to show under each finding (default {EXCERPT_WIDTH})")
    ap.add_argument("--max-source-bytes", type=_positive_int, metavar="BYTES",
                    help=f"Largest source file or manifest read (default {SOURCE_SIZE_CAP:,}, env "
                         f"LAZARET_MAX_SOURCE_BYTES); a larger one is not scanned and gets "
                         f"SC-TRUNCATED, which fails the gate")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    REDACT_SECRETS = not args.no_redact_secrets
    EXCERPT_WIDTH = args.excerpt_width
    if args.max_source_bytes:
        SOURCE_SIZE_CAP = args.max_source_bytes

    # Usage errors (exit 2) before anything else: a missing target, a file
    # instead of a directory. (An unreadable or empty directory is reported
    # by scan_project, also exit 2.)
    target_disp = sanitize_term_line(_fs_display(args.directory))
    if not os.path.exists(args.directory):
        print(f"error: {target_disp} does not exist (expected a directory to scan)",
              file=sys.stderr)
        sys.exit(EXIT_USAGE)
    if not os.path.isdir(args.directory):
        print(f"error: {target_disp} is not a directory (lazaret scans a project "
              f"directory; for single files use the MCP scan_files tool)", file=sys.stderr)
        sys.exit(EXIT_USAGE)

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
        print(f"error: {sanitize_term_line(exc)}", file=sys.stderr)
        sys.exit(lazaret_report.EXIT_OUTPUT)

    # taint config: --taint-config (trusted), else the repo's own
    # .lazaret-taint.json only with --trust-repo-config (sources/sinks only).
    # Fail-loud validation; exit 4 on rejected rules when strict. Returns
    # the report notes (Q-TAINT-CONFIG) for a used repository config.
    taint_notes = load_taint_config_for_scan(
        args.taint_config, args.directory, trust_repo=args.trust_repo_config,
        strict=args.strict_taint_config)

    # ---- the project scan: one pipeline shared with the MCP server --------
    # (collect -> scan -> manifests -> collection findings -> flow ->
    # skipped-tree notes -> gate -> redaction; see scan_project). The taint
    # config above is already applied, so none is passed here.
    try:
        res = scan_project(args.directory, args.exclude, include_deps=args.deps,
                           redact_secrets=REDACT_SECRETS, extra_issues=taint_notes)
    except ScanTargetError as exc:
        print(f"error: {sanitize_term_line(exc)}", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    for warning in res.get("warnings", ()):
        # audit H1: a warning can carry content parsed out of scanned files
        # (the flow engine raises on hostile input); sanitize it.
        print(f"warning: {sanitize_term_line(warning)}", file=sys.stderr)

    # ---- SEAM (flow-sca): baseline block ---------------------------------
    if args.baseline:
        apply_baseline(res, args.baseline, scan_root=args.directory)
    print_report(res, args.quiet)

    # Writes are validated (writability + no-clobber) before the scan; each
    # write re-checks and is atomic (temp file + rename), so a mid-write
    # crash never leaves a half-written report behind.
    try:
        if args.sarif:
            sarif_path = lazaret_report.write_report(
                paths["sarif"],
                lambda: lazaret_report.sarif_renderer(sarif_report(res, root=args.directory)),
                kind="sarif", strict=args.force_overwrite)
            print(f"  SARIF report: {sanitize_term_line(sarif_path)}")
        if not args.no_json:
            json_path = lazaret_report.write_report(
                paths["json"],
                lambda: lazaret_report.json_renderer(res),
                kind="json", strict=args.force_overwrite)
            print(f"  JSON report: {sanitize_term_line(json_path)}")
        if not args.no_html:
            html_path = lazaret_report.write_report(
                paths["html"],
                lambda: _html_report_marked(res),
                kind="html", strict=args.force_overwrite)
            print(f"  HTML report: {sanitize_term_line(html_path)}")
    except lazaret_report.ReportPathError as exc:
        # Only reachable if the pre-scan checks raced with an external
        # change (TOCTOU); the scan itself already ran and printed above.
        # audit H1: sanitize the echoed path before it reaches the terminal.
        print(f"error: {sanitize_term_line(exc)}", file=sys.stderr)
        sys.exit(lazaret_report.EXIT_OUTPUT)
    except OSError as exc:
        # disk full, quota, a directory removed mid-run: an output error (3),
        # not an internal one.
        print(f"error: could not write a report: {sanitize_term_line(_safe_text(exc))}",
              file=sys.stderr)
        sys.exit(lazaret_report.EXIT_OUTPUT)
    print()
    if args.ci and not res["pass"]:
        sys.exit(EXIT_GATE)
    # 48033f94: a hostile-depth manifest (SC-MANIFEST-DEPTH) exists only to
    # crash or blind scanners, so it forces exit 1 even without --ci (scan
    # completes, reports are written — then signal). It is the ONLY such
    # finding: every other one, CRITICAL SC-* included, leaves the exit code
    # to --ci (review item 6: any CRITICAL SC-* used to exit 1 without --ci,
    # contradicting the documented "0 without --ci").
    if any(i.get("rule") == "SC-MANIFEST-DEPTH" for i in res["issues"]):
        sys.exit(EXIT_GATE)
    return EXIT_OK

if __name__ == "__main__":
    main()
