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

No dependencies — stock python3 and the native engine every wheel carries
(lazaret/_native/; engine.py), which runs the detectors and the per-file
rules. Same ruleset as the Lazaret dashboard.
"""
import argparse
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
import types
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
from lazaret.scanner import ghworkflow  # GitHub Actions workflows: the worms' shapes, hardening (SC-WORKFLOW-*)
from lazaret.scanner import gitlabci  # GitLab CI files: hardening (SC-GITLAB-*)
from lazaret.scanner import frameworks  # web framework models shared by both taint engines
from lazaret.scanner import _native, engine  # the native engine: every detector below


# ---------------- The engine's detectors ----------------
# Since the Rust-first refactor the native engine (engine.py, the Rust crate
# rust/crates/lazaret-engine) is the only implementation of the supply-chain
# tests and of the per-file rules. These are its answers under the names
# the rest of the scanner, the registry and the tests call them by. Each
# raises _native.NativeError when the engine cannot answer (its work budget
# spent on a hostile input); the scans turn that into SC-TRUNCATED.

def _ask(call, text, **args):
    """The engine's answer to `call` on `text`."""
    return _native.call(call, args, text)


def _tuple(value):
    """A JSON array as a tuple (None stays None)."""
    return None if value is None else tuple(value)


def install_script_risk(text, shell=True, command=False, lang=None):
    """The reasons an install script is risky (read as a shell program too
    unless `shell` is false; `command`: a hook's command line; `lang`: the
    script's language when known, "js" or "py")."""
    return engine.install_script_risk(text, shell, command, lang)


def import_time_risk(text, lang=None):
    """(reasons, line): the import-time test of a dependency's file."""
    return engine.import_time_risk(text, lang)


def import_time_severity(reasons):
    """'CRITICAL' when one of the reasons is a strong one, else 'MAJOR'."""
    return _ask("import_time_severity", "", reasons=list(reasons))


def follow_hook(cmd):
    """(the package files an install hook's command runs, whether the walk
    read all of it)."""
    targets, complete = _ask("follow_hook", cmd)
    return targets, complete


def hook_script_targets(cmd):
    """The files an install hook runs (follow_hook's targets)."""
    return follow_hook(cmd)[0]


def _hook_tokens(cmd):
    """The words of a hook's command, as the follower reads them."""
    return _ask("hook_tokens", cmd)


def node_candidates(rel):
    """The files `node rel` may run, in Node's order."""
    return _ask("node_candidates", rel)


def shebang_lang(text):
    """'js', 'py' or 'sh' by the script's #! line, else None."""
    return _ask("shebang_lang", text)


def decoded_view(text, lang=None):
    """`text` with what it decodes as it runs written out (hex, base64, char
    codes, string arrays, its own decoders; in JavaScript and Python, `lang`,
    its literals read as the runtime reads them)."""
    return _ask("decoded_view", text, **({"lang": lang} if lang else {}))


def string_array_line(text, lang=None):
    """The line of the string array the decoded view read, else None."""
    return _ask("string_array_line", text, **({"lang": lang} if lang else {}))


def spawned_scripts(text, lang=None):
    """[(base, path)] of the package scripts `text` starts with node or python."""
    return engine.spawned_scripts(text, lang)


def self_publish_at(text):
    """The offset of code that publishes packages with a token, else -1."""
    return _ask("self_publish_at", text)


def runs_dll(text):
    """The DLL an install script runs, else None."""
    return _ask("runs_dll", text)


def join_string_pieces(text):
    """`text` with literal pieces joined with + written as one."""
    return _ask("join_string_pieces", text)


def _received_code_kind(text, extra_always=(), extra_runners=()):
    """(line, kind) of code received over the network and run, else None."""
    args = {}
    if extra_always:
        args["extra_always"] = sorted(extra_always)
    if extra_runners:
        args["extra_runners"] = sorted(extra_runners)
    return _tuple(_native.call("received_code_kind", args, text))


def runs_received_code(text):
    """The line of code received over the network and run, else None."""
    return _ask("runs_received_code", text)


def _downloads_and_runs(text):
    """(line, interpreter) of a download written to a file and run, else None."""
    return _tuple(_ask("downloads_and_runs", text))


def _decodes_and_runs(text):
    """(line, interpreter) of a decoded payload written to a file and run, else None."""
    return _tuple(_ask("decodes_and_runs", text))


def powershell_risk(text):
    """The reasons PowerShell in `text` is risky."""
    return _ask("powershell_risk", text)


def stager_at(text):
    """The offset of a stager (a download run in memory), else -1."""
    return _ask("stager_at", text)


def reverse_shell_at(text):
    """The offset of a reverse shell, else -1."""
    return _ask("reverse_shell_at", text)


def local_data_sent_at(text):
    """(offset, kind, what, in_address) of the first send of data read from
    the machine, else None."""
    return _tuple(_ask("local_data_sent_at", text))


def runs_own_source_at(text):
    """The offset of a runner of code read from the file itself or a data
    file next to it, else -1."""
    return _ask("runs_own_source_at", text)


def reads_own_source(text):
    """Does `text` read its own source?"""
    return _ask("reads_own_source", text)


def persistence_reasons(text):
    """The places `text` writes to that run code later (persistence)."""
    return _ask("persistence_reasons", text)


def dumps_workflow_secrets(text):
    """Does `text` write a workflow that dumps the repository's secrets?"""
    return _ask("dumps_workflow_secrets", text)


def _pipes_download_to_shell(text):
    """Does `text` pipe a download into a shell?"""
    return _ask("pipes_download_to_shell", text)


def runs_substituted_download(row):
    """Does the row run a download substituted into a command line?"""
    return _ask("runs_substituted_download", row)


def offscreen_code(line, lang):
    """(column, blanks, hidden code, runs code) of code pushed past the
    screen's edge, else None."""
    return _tuple(_ask("offscreen_code", line, lang=lang))


def _lex_comment_spans(content, lang, strings=None, jsx=True, literals=None):
    """Absolute (start, end) spans of every comment in `content`; with
    `strings` and `literals` lists, the spans of the string literals and of
    every literal are appended to them. jsx=False: a .ts file."""
    if lang == "cfg":                       # a config or data file (configsecrets)
        return configsecrets.comment_spans(content)
    args = {"jsx": jsx, "strings": strings is not None, "literals": literals is not None}
    if lang in ("py", "js", "sql", "go", "rs"):
        args["lang"] = lang
    got = _native.call("lex_comment_spans", args, content)
    if strings is not None:
        strings.extend(tuple(s) for s in got["strings"])
    if literals is not None:
        literals.extend(tuple(s) for s in got["literals"])
    return [tuple(s) for s in got["comments"]]


def secret_endpoint_at(text):
    """(offset, reason) of a request to a webhook whose secret is written in
    the code, else None."""
    return _tuple(_ask("secret_endpoint_at", text))


def credential_sweep_at(text):
    """(offset, names) of three or more credential folders named in one
    place, else None."""
    return _tuple(_ask("credential_sweep_at", text))


def exec_command_reasons(text):
    """The reasons the command lines `text` hands a shell give."""
    return _ask("exec_command_reasons", text)


def dns_beacon_at(text, host=True):
    """The offset of a DNS lookup of a name built from the machine's
    identity, else -1 (host=False: without another read of the identity)."""
    return _native.call("dns_beacon_at", {} if host else {"host": False}, text)


def miner_at(text):
    """The offset of a cryptocurrency miner's wallet and pool, else -1."""
    return _ask("miner_at", text)


def raw_ip_connect(text):
    """The hard-coded address a raw socket connects to, else None."""
    return _ask("raw_ip_connect", text)


def capture_service(text):
    """The data-capture service `text` names (the matched text), else None."""
    return _ask("capture_service", text)


def exfil_signs(text):
    """The exfiltration signs of `text` (its view of the machine's data and
    where it goes)."""
    return _ask("exfil_signs", text)


def service_reasons(text):
    """The programs `text` sets to start at login or boot."""
    return _ask("service_reasons", text)


def wallet_swap_at(text):
    """(offset, reason) of a wallet address swapped for the script's own,
    else None."""
    return _tuple(_ask("wallet_swap_at", text))


def sh_reasons(text):
    """The reasons a shell text, read as a program, sends data, downloads
    and runs code or beacons (as an install hook's command is read)."""
    return _ask("sh_reasons", text)


def sh_parse(text):
    """The simple commands of a shell text, each with its words, the
    substitutions in each word, its redirections, whether it is piped in and
    out, what follows it, and its program: (word index or None, name,
    negated)."""
    out = []
    for words, subs, redirs, pipe_in, pipe_out, after, program in _ask("sh_parse", text):
        out.append(types.SimpleNamespace(words=words, subs=[tuple(x) for x in subs],
                                         redirs=[tuple(x) for x in redirs], pipe_in=pipe_in, pipe_out=pipe_out,
                                         after=after, program=tuple(program)))
    return out


def _shell_text(text):
    """Is `text` a shell program?"""
    return _ask("shell_text", text)


def _code_text(text):
    """Is `text` code (not a shell program)?"""
    return _ask("code_text", text)


def _sh_literal_value(text, i):
    """The value of the string literal at text[i], else None."""
    return _ask("sh_literal_value", text, at=i)


def dead_drop_at(text):
    """(offset, host) of the machine's name sent to an address fetched at
    run time, else None."""
    return _tuple(_ask("dead_drop_at", text))


def agent_hijack(text):
    """(agent, flag, line) of an AI coding agent launched in an autonomous
    mode, else None."""
    return _tuple(_ask("agent_hijack", text))


def agent_hijack_in_command(cmd):
    """(agent, flag) of an AI coding agent launched in an autonomous mode
    by a command line, else None."""
    return _tuple(_ask("agent_hijack_in_command", cmd))


def hook_command_risk(cmd, output_kept=False):
    """The reasons an install hook's command, read as a program, is risky."""
    return _native.call("hook_command_risk", {"output_kept": True} if output_kept else {}, cmd)


def _hook_is_suspicious(cmd):
    """Is an install hook's command suspicious on its face?"""
    return _ask("hook_is_suspicious", cmd)


def _import_code(text, lang):
    """`text` as the import-time test reads it (what runs at import)."""
    return _ask("import_code", text, lang=lang)


def hex_hidden_name(line):
    """(name, column) of a dangerous name written in escapes, else None."""
    return _tuple(_ask("hex_view", line)[0])


def hex_hidden_text(line):
    """Readable text hidden in escapes, else None."""
    return _ask("hex_view", line)[1]


def lookalike_name(code, lang, words):
    """(name, what it reads as, severity, another name of the file reads so,
    detail, column) of a look-alike name, else None (`words`: the file's
    names, or a function giving them)."""
    names = words() if callable(words) else words
    args = {"words": sorted(names)}
    if lang is not None:
        args["lang"] = lang
    return _tuple(_native.call("lookalike_view", args, code))


def scan_rules(path, content, lang):
    """The rules part of project mode's scan of one file (the pattern rules,
    the families, the whole-text rules), before the passes that follow."""
    args = {"lang": lang, "jsx": jsx_reading(path), "redact": bool(REDACT_SECRETS), "neumaier": False}
    return engine._issues(path, _native.call("scan_rules", args, content))


def scan_file(path, content, lang, dep=False):
    """The findings of one file: in dependency mode the engine's, in project
    mode the engine's rules part and the passes that follow (engine.scan_file)."""
    return engine.scan_file(path, content, lang, dep)


def _cross_file_received_issues(files, skip_paths=(), who="Dependency code", one_package=False, site_groups=None):
    """The cross-file follower's findings (engine.cross_file_issues)."""
    return engine.cross_file_issues(files, skip_paths, who, one_package, site_groups)


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
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}", r"sk_live_[A-Za-z0-9]{16,}", r"AIza[0-9A-Za-z_\-]{35}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", _JWT_ALT)
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
R("S-SECRET", "Hardcoded credential", "VULN", "BLOCKER", ("py", "js", "go", "rs"),
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
R("Q-TODO", "TODO/FIXME marker", "SMELL", "INFO", ("py", "js", "sql", "go", "rs"),
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
R("S-TOKEN", "Known secret token format", "VULN", "BLOCKER", ("py", "js", "go", "rs"),
  _TOKEN_PATTERN,
  "String matches a known secret format (AWS/GitHub/Slack/Stripe/Google key, private key, or JWT).",
  "Provider-format tokens in source are live credentials until proven otherwise.",
  "Remove it, rotate the credential immediately, and load it from a secrets manager.",
  "CWE-798 · OWASP A07"),
# Review fix (shared semantics 5): Trojan Source. Bidi embedding/override/
# isolate controls reorder how a line DISPLAYS without changing how it is
# parsed. Flagged anywhere on a line, comment lines included.
R("S-BIDI", "Trojan Source bidi control", "VULN", "CRITICAL", ("py", "js", "sql", "go", "rs"),
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
  r"(?:[^{}]|\{[^{}]*\})*\}\s*\)?|[A-Za-z_$][\w$]*)\s*\(\s*"
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

# Validation warnings from the most recent apply_taint_config() call: every
# rule the loader refused. Rules are never silently dropped — a custom sink
# that fails validation must not quietly become inert while the scan still
# reports PASSED (the bug this fixes). The CLI drains these after loading.
_TAINT_CONFIG_WARNINGS = []


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


_DISGUISED_WHY = ("A source file is read, reviewed and diffed as text; a program under a source file's "
                  "name hides from that review and from every rule that reads code. No build ships one: "
                  "compiled code goes in files named for what they are (.so, .pyd, .node, .exe).")
_DISGUISED_FIX = ("Treat the package or tree that ships it as compromised: find what loads or runs the "
                  "file, and remove it.")
#: The leading bytes disguised_binary reads: an oversized source file's prefix
#: is read this far (the header test reads the first 512).
DISGUISE_SAMPLE_BYTES = 2048


def disguised_binary(path, data):
    """SC-BINARY, CRITICAL, for a program under a source file's name (0.1.8):
    an executable's or a compiled module's bytes (EXEC_MAGIC, a Windows PE)
    in a file named as source code: a registry or guard member, a file of a
    directory scan (`--deps` too) or one an MCP client names. Unlike a
    binary named for what it is (classify_binary: inventory in a wheel, a
    capability to review elsewhere) it is a disguise, in a wheel too:
    num2words 0.5.15's `_build.py` is a Windows executable. Else None.
    Twin: js/src/lib/binary.js disguisedBinary."""
    data = bytes(data or b"")
    header = data[:512]
    desc = next((d for sig, d in EXEC_MAGIC if header.startswith(sig)), None)
    if desc is None and header.startswith(b"MZ"):
        desc = "Windows PE executable/DLL"
    if desc is None or not looks_binary(data[:DISGUISE_SAMPLE_BYTES]):
        return None
    return {"rule": "SC-BINARY", "name": "Binary artifact in package", "type": "HOTSPOT", "sev": "CRITICAL",
            "msg": f"{os.path.basename(path)} is not source code but a program: {desc}.",
            "why": _DISGUISED_WHY, "fix": _DISGUISED_FIX, "ref": "CWE-506 · Supply chain",
            "file": path, "line": 1, "snippet": [], "snipStart": 1}


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
FN_LEN_LIMIT = 60
FN_CX_LIMIT = 12
FN_HEADER_SCAN_LIMIT = 2000   # chars of a JS line searched for a function header
EXTS = {".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
        ".mts": "js", ".cts": "js", ".mjs": "js", ".cjs": "js", ".sql": "sql",
        ".go": "go", ".rs": "rs"}
#: The languages a package's files (registry and guard scans) and a
#: dependency tree's (--deps) are read in. A project's own Go and Rust files
#: are read (S-4: its secrets, tokens, bidi controls and the families every
#: text gets); a package's wait for the engine's Go and Rust detectors, and
#: are classified as any other file until then.
DEP_LANGS = frozenset({"py", "js", "sql"})


def dep_source_lang(ext):
    """The language a package's or a dependency tree's file with extension
    `ext` is read in as source, or None."""
    lang = EXTS.get(ext)
    return lang if lang in DEP_LANGS else None


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


def scan_file_after_rules(path, content, lang, rules):
    """scan_file in project mode with its first part already read: `rules`,
    the findings scan_rules gives for the file (the native engine's,
    engine.py), then the passes that follow them, the suppression markers
    and the cap, as scan_file runs them."""
    def scan(path, content, lines, lang, dep, ctx, issues):
        issues.extend(rules)
        _project_passes(path, content, lines, lang, ctx, issues)
    return _scan_source(path, content, lang, False, scan)


def _project_passes(path, content, lines, lang, ctx, issues):
    """Project mode's passes after the rules part: SQL's *-NOWHERE scan, the
    intra-file taint, Python's SQL sinks, function length and complexity."""
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


def _scan_source(path, content, lang, dep, scan, finish=True):
    """`scan` of one file as scan_file reads it, then, when `finish`,
    without what a marker suppresses and capped."""
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


def _autorun_script_risk(text, lang=None):
    """install_script_risk for what a settings file runs, but for writing an
    agent's or editor's settings: an agent's own hooks manage them (a
    WorktreeCreate hook copies settings.local.json into the new worktree).
    `lang`: a script's language, when known."""
    return [r for r in install_script_risk(text, lang=lang) if not r.startswith(_AGENT_SETTINGS_REASON)]


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
        found = _autorun_script_risk(text, engine.script_lang(rel))
        if len(set(OBF_IDENT_RE.findall(text))) >= 5:
            found.append("is obfuscated")
        if found:
            return found, target
        # (0.1.8) the scripts it starts (spawned_scripts): a loader that fetches
        # a runtime and runs a file of the tree with it
        for where, path in spawned_scripts(normalize_newlines(text), engine.script_lang(rel)):
            srel = _tree_join(posixpath.dirname(rel) if where == "dir" else base, path)
            stext = read(srel) if srel is not None else None
            more = _autorun_script_risk(stext, engine.script_lang(srel)) if stext else []
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


#: The CI files' hardening checks (0.1.9: ghworkflow.hardening and
#: gitlabci.hardening): the practices a pipeline should follow, not the shapes
#: of one that was tampered with. They are reported, and only a CRITICAL one
#: (a pull_request_target job that runs a pull request's code, a file included
#: over plain http) counts against the gate's supply-chain condition: most
#: repositories run an action at a version tag or set no permissions, and that
#: condition is for indicators (build_result).
HARDENING_RULES = frozenset({
    "SC-WORKFLOW-UNPINNED", "SC-WORKFLOW-PR-CHECKOUT", "SC-WORKFLOW-CACHE", "SC-WORKFLOW-PERMISSIONS",
    "SC-WORKFLOW-OIDC-INSTALL", "SC-WORKFLOW-PIPE-SHELL",
    "SC-GITLAB-INCLUDE", "SC-GITLAB-IMAGE", "SC-GITLAB-PIPE-SHELL", "SC-GITLAB-MR-TEXT", "SC-GITLAB-TOKEN-INSTALL"})


def workflow_issues(path, lines):
    """SC-WORKFLOW-SECRETS / SC-WORKFLOW-BACKDOOR for a GitHub Actions workflow
    (ghworkflow.is_workflow(path)) whose text is lines, and its hardening
    checks (HARDENING_RULES)."""
    out = []
    text = "\n".join(lines)
    for kind, line, d in ghworkflow.findings(text):
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
    for kind, line, d in ghworkflow.hardening(text):
        out.append(mk_issue(ghworkflow.hardening_rule(kind, d), path, line, lines))
    return out


def gitlab_issues(path, lines):
    """A GitLab CI file's hardening checks (gitlabci.is_gitlab_ci(path);
    HARDENING_RULES)."""
    return [mk_issue(gitlabci.hardening_rule(kind, d), path, line, lines)
            for kind, line, d in gitlabci.hardening("\n".join(lines))]


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
    (read: see autorun_issues), a GitHub Actions workflow the
    SC-WORKFLOW-* checks and a GitLab CI file the SC-GITLAB-* ones."""
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
            elif gitlabci.is_gitlab_ci(path):
                issues.extend(gitlab_issues(path, lines))
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


# ---------------- The per-line pass's findings ----------------

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


def _json_loads_manifest(path, content):
    """Backwards-compatible wrapper: (data, depth_issue). data is None on any
    parse failure; depth_issue is SC-MANIFEST-DEPTH for too-deep input.
    New code uses load_manifest, which also reports unparseable roots."""
    data, issues = load_manifest(path, content)
    depth = next((i for i in issues if i["rule"] == "SC-MANIFEST-DEPTH"), None)
    return data, depth


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


# ---------------- Install-script and import-time inspection ----------------
# (The registry's tests, here so that --deps project scans run them too. The
# tests themselves are the native engine's since the Rust-first refactor:
# install_script_risk and import_time_risk above. What stays here are the
# values the registry and the workflow checks read, which
# make_rust_tables.py --check holds equal to the rule pack's.)
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
# of them never finished. The shell may be named by its path (`| /bin/bash`,
# `| /usr/bin/env sh`: the 2025 Go typosquats' `wget -O - … | /bin/bash &`).
_PIPE_SCAN_RE = re.compile(r"""\|\s*(?:sudo\s+)?(?:[\w.~-]*/)*(?:env\s+)?(?:ba|z|da|k)?sh\b|[\n|;&]|\b(?:curl|wget)\b""")


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


# ---------------- Import-time inspection ----------------
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
# a string array (_SA_TECHNIQUE_REASON). Since rule set 2.17, what no client
# sends (the whole environment, a credential store) and what local commands
# print about the machine count wherever they are sent, and a raw socket's
# hard-coded public address is an IP address.
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
    "reads credentials or the whole environment and sends data over the network",
    "sends what local commands report about the machine over the network",
    "reads local files and sends them to an IP address",
    "collects files from several credential folders", "sends the machine's user or host name to an address it hides",
    "sends the machine's user or host name in a DNS lookup",
    "sends the machine's user or host name to an address it fetches",
    "runs a cryptocurrency miner", "swaps the cryptocurrency wallet addresses",
    "hides its code in a string array", "runs a program it extracts from inside another file")


# ---------------- Download to a file, then run the file ----------------


def _downloads_and_runs_file(text):
    """The 1-based line where a received value is written to a file that is then
    run (the engine's downloads_and_runs), else None. MAJOR only, except in the
    Python code pip runs to install an sdist (the registry)."""
    res = _downloads_and_runs(text)
    return None if res is None else res[0]


# ---------------- Dependency drives your AI agent (SC-AGENT-HIJACK) ----------------


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


# ---------------- Scripts by their #! line ----------------
# A file with no source extension still runs as code when its #! line names
# an interpreter: a package's bin/cli, a hook's ./setup. The line is the
# first line only (the kernel reads no further): `[ \t]`, never `\s`, which
# took the interpreter from the next line of `#!/usr/bin/env` + newline.
_SHEBANG_RE = re.compile(r"^#![ \t]*(\S+)(?:[ \t]+(?:-\S+[ \t]+)*(\S+))?")


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
    gate (engine.error_issue gives the engine's spent work budget its own
    words, and this for any other error). It was an INFO note (Q-SCAN-ERROR), so a file whose scan died took
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
# the engine's reason for a line _PTH_EXEC_RE matches
_PTH_PAYLOAD = "executes or decodes a payload"


def pth_issues(path, text):
    """SC-PTH-EXEC: site.py executes every line of a .pth file in
    site-packages that starts with 'import' at EVERY interpreter start — no
    import of the package needed. CRITICAL when the line's code executes or
    decodes a payload, or does what the install-script and import-time tests
    look for (the engine's pth_line_risk, which reads `exec('…')` of a plain
    literal as the literal's code: coverage's a1_coverage.pth); MAJOR
    otherwise (setuptools' distutils shim and namespace .pth files are this
    shape: listed for review). The registry's check (lazaret.registry.repo)
    and the project walk share this one helper's semantics; the npm engine's
    twin is js/src/lib/pth.js.

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
        try:
            reasons = _ask("pth_line_risk", line)
        except _native.NativeError:
            reasons = [_PTH_PAYLOAD]        # (no answer: judged as the worst)
        if not reasons:
            tail = "."
        elif _PTH_PAYLOAD in reasons:
            tail = " and executes or decodes a payload."
        else:
            tail = ", and it " + "; and ".join(reasons) + "."
        out.append(mk_issue(
            {"id": "SC-PTH-EXEC", "name": "Code in a .pth file", "type": "HOTSPOT",
             "sev": "CRITICAL" if reasons else "MAJOR",
             "msg": ".pth line runs code at every Python start" + tail,
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
    lang = None if manifest or pth else dep_source_lang(ext) if in_dep else EXTS.get(ext)
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
        if lang is not None:             # its first bytes still tell a program (as in the registry)
            try:
                head = _read_prefix(path, DISGUISE_SAMPLE_BYTES)
            except OSError:              # not read: the SC-TRUNCATED stands alone, as before
                head = b""
            disguised = disguised_binary(disp, head)
            if disguised:
                issues.append(disguised)
        return
    data = _read_prefix(path, SOURCE_SIZE_CAP + 1)
    if len(data) > SOURCE_SIZE_CAP:      # grew between the lstat and the read
        issues.append(truncated_issue(
            disp, f"read exceeded the {SOURCE_SIZE_CAP:,}-byte file limit"))
        disguised = disguised_binary(disp, data) if lang is not None else None
        if disguised:
            issues.append(disguised)
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
    # read as the registry reads a member (0.1.8): bytes that don't decode to
    # anything text-like are SC-TRUNCATED, not mojibake no rule can read
    text, extra = decode_member(disp, data, lang)
    issues.extend(extra)
    disguised = disguised_binary(disp, data)     # a program under a source file's name (0.1.8)
    if disguised:
        issues.append(disguised)
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
                    issues.append(engine.error_issue(_fs_display(rel), exc))
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
                    issues.append(engine.error_issue(_fs_display(rel), exc))
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


# ---------------- Cross-file received code (the engine's cross_file, 0.1.8) ----------------
# The follower is the native engine's (engine.cross_file_issues); what stays
# here is how a --deps scan groups the dependency files into packages.
_XF_DEP_MARKERS = ("site-packages", "dist-packages", "vendor")


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
            out.append(engine.error_issue(issue["file"], exc))
    # the import-time test for each dependency file, a batch at a time (the
    # engine reads a batch on threads); a file it could not answer about is
    # SC-TRUNCATED (engine.error_issue)
    assets = _deps_web_assets(tree, files)
    todo = [f for f in files
            if f.get("dep") and f["lang"] in ("js", "py") and f["path"].replace(os.sep, "/") not in run
            and f["path"].replace(os.sep, "/") not in assets]
    for start in range(0, len(todo), engine.BATCH):
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, extra, stopped
        chunk = todo[start:start + engine.BATCH]
        try:
            risks = engine.import_time_risks([(f["content"], f["lang"]) for f in chunk])
        except Exception:                   # each file is then read on its own below
            risks = [None] * len(chunk)
        for f, risk in zip(chunk, risks):
            try:
                if engine.unanswered(risk):
                    raise risk
                found = dependency_import_issue(f["path"], f["content"], f["lang"], risk=risk)
                agent = dependency_agent_issue(f["path"], f["content"])
            except Exception as exc:
                found, agent = engine.error_issue(f["path"], exc), None
            if found is not None:
                out.append(found)
            if agent is not None:
                out.append(agent)
    # Cross-file received code (0.1.8): a value received in one file of a
    # package and run in another, by the native engine's follower (it reads
    # the packages on threads: engine.cross_file_issues). Reached
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
        targets += [(base if where == "dir" else root, t) for where, t in spawned_scripts(f["content"], "js")]
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
        reasons = engine.install_script_risk(text, lang=engine.script_lang(rel)) if text else []
        if reasons and issue["sev"] not in ("BLOCKER", "CRITICAL"):
            msg = f"Install hook runs {target}, which {'; and '.join(reasons)}."
            issue["sev"] = "CRITICAL"
            issue["msg"] = _redact_text(msg) if REDACT_SECRETS else msg
        agent = dependency_agent_issue(rel.replace("/", os.sep), text) if text else None
        if agent is not None:
            out.append(agent)
        # the scripts it starts with node or python (0.1.8, spawned_scripts)
        for started, stext in _started_dependency_scripts(tree, rel, text, base, out, extra, run):
            more = engine.install_script_risk(stext, lang=engine.script_lang(started)) if stext else []
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
    found, seen, queue = [], {rel}, [(rel, text, 0)]
    while queue and len(seen) <= _SPAWN_MAX_FILES:
        cur, cur_text, depth = queue.pop(0)
        if not cur_text or depth >= _SPAWN_MAX_DEPTH:
            continue
        for where, path in engine.spawned_scripts(cur_text, engine.script_lang(cur)):
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
        # Files a batch at a time (the engine reads a batch on threads:
        # engine.py; a project file's rules part there, the rest of its scan
        # in core); should_stop is checked before each batch.
        batch = engine.BATCH
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
                    issues.append(engine.error_issue(f["path"], exc))
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
                issues.append(engine.error_issue(cf["path"], exc))
            checked += 1
        for mf in manifests:
            if not stopped and should_stop is not None:
                stopped = should_stop()
            if stopped:
                break
            try:
                issues.extend(_scan_manifest_entry(mf))
            except Exception as exc:
                issues.append(engine.error_issue(mf["path"], exc))
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
#: The languages whose duplication is measured (windows of six code lines
#: that repeat). A project's Go and Rust files count in the files, lines of
#: code and comments, but not yet in the duplication: the gate's 10% was set
#: on Python and JavaScript, and with these windows Go's standard library
#: measures 2 to 13% and popular crates 4 to 54% (repetitive tests, an API
#: written for each type, a file per platform), and this repository's Python
#: and JavaScript under 1%. Go and Rust need a measure of their own.
DUP_LANGS = frozenset({"py", "js", "sql"})


def compute_metrics(all_files):
    files = [f for f in all_files if not f.get("dep")]  # deps excluded from quality metrics
    ncloc = comments = measured = 0
    win_map = {}
    for f in files:
        code = []
        dup_lang = f.get("lang") is None or f["lang"] in DUP_LANGS
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
            if dup_lang:
                measured += 1
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
    dup_pct = round(100 * len(dup) / measured, 1) if measured else 0.0
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
    # hook, shared semantics 3), not indicators; nor is a CI file's hardening
    # check below CRITICAL (HARDENING_RULES).
    supply = sum(1 for i in issues if i["rule"].startswith("SC-") and i["sev"] != "INFO"
                 and (i["rule"] not in HARDENING_RULES or i["sev"] == "CRITICAL"))
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
    run = {"tool": {"driver": {"name": "Lazaret",
                               "version": _lazaret_pkg.__version__,
                               "informationUri": LAZARET_INFORMATION_URI,
                               "rules": list(rules_seen.values())}},
           "originalUriBaseIds": {SARIF_SRCROOT: {
               "uri": _root_uri(res["project"] if root is None else root)}},
           "results": results}
    src = res.get("source")
    if isinstance(src, dict) and src.get("uri") and src.get("commit"):
        # a github: or gitlab: scan: the files are the repository's at that commit
        run["versionControlProvenance"] = [{"repositoryUri": src["uri"], "revisionId": src["commit"],
                                            "mappedTo": {"uriBaseId": SARIF_SRCROOT}}]
    return {"$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [run]}


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


def main(argv=None, source=None):
    """`lazaret` console entry point. argv defaults to sys.argv[1:]. Any
    uncaught exception becomes `error: internal: …` with exit 5 (review item
    4: a non-UTF-8 file name crashed the HTML writer with a traceback and
    exit 1 — indistinguishable from a failed gate). A closed stdout never
    stops the scan (see _PipeSafeStdout). `source`: the source block of a
    `github:` or `gitlab:` scan (registry/sourcescan.py; set_source)."""
    configure_stdio()
    real_stdout = sys.stdout
    guard = _PipeSafeStdout(real_stdout) if real_stdout is not None else None
    if guard is not None:
        sys.stdout = guard
    try:
        return _main(argv, source)
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


def set_source(res, source):
    """A `github:` or `gitlab:` scan's result (registry/sourcescan.py, N-5):
    the source and its commit name the project instead of the temporary
    folder they were read into, and `source` says what was read (spec, the
    repository's address, the ref asked for, commit, files, bytes) and what
    was not (complete, incomplete, notes). A checkout not read whole makes
    the result incomplete, as a capped scan's is."""
    res["project"] = source["spec"]
    res["source"] = dict(source)
    if not source.get("complete", True):
        gaps = "; ".join(f"{reason}: {detail}" for reason, detail in source.get("incomplete", ())[:3])
        why = f"the checkout of {source['spec']} was not read whole ({gaps})"
        res["incomplete"] = True
        res["incompleteReason"] = f"{res['incompleteReason']}; {why}" if res.get("incompleteReason") else why


def _main(argv=None, source=None):
    global REDACT_SECRETS, EXCERPT_WIDTH, SOURCE_SIZE_CAP
    ap = argparse.ArgumentParser(prog="lazaret", description="Lazaret — security & quality scanner for Python/JS projects.")
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
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    try:
        engine.require()
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
    if source is not None:
        set_source(res, source)

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
