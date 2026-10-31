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
import io
import json
import keyword
import ntpath
import os
import posixpath
import re
import sys
import types

try:
    from lazaret.scanner import flow as lazaret_flow  # interprocedural / cross-file taint (optional)
except Exception:  # pragma: no cover
    lazaret_flow = None

from lazaret.scanner import reports as lazaret_report  # report paths: pre-scan validation, atomic writes
from lazaret.scanner import taintspec  # taint-config validation shared by both taint engines
from lazaret.scanner import _unicode13  # the Unicode every engine reads source text in
from lazaret.scanner import configsecrets  # config and data files: credentials only
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


def install_script_risk(text, shell=True, command=False, lang=None, path=None):
    """The reasons an install script is risky (read as a shell program too
    unless `shell` is false; `command`: a hook's command line; `lang`: the
    script's language when known, "js" or "py"; `path`: its file's name,
    when known: a TypeScript file's text is read in its dialect, TS-STRIP)."""
    return engine.install_script_risk(text, shell, command, lang, path=path)


def install_script_severity(reasons):
    """'CRITICAL' when one of the install-script reasons is a strong one, else
    'MAJOR' when every reason is a weaker one (RA-12: TLS certificate
    verification turned off); None for no reasons (the caller's own severity
    stands). The severity of every finding the install-script test decides
    (an install hook, an sdist's setup.py, a start-up module, a .pth line, a
    build script, an editor's or agent's settings, an agent doc)."""
    return _ask("install_script_severity", "", reasons=list(reasons))


def import_time_risk(text, lang=None, declared=None, own=None, path=None):
    """(reasons, line): the import-time test of a dependency's file; `declared` and `own`, its package's names when
    known (engine.import_time_risks); `path`, the file's name when known (a .ts, .mts, .cts or .tsx file's text is read
    in its dialect alone: TS-STRIP)."""
    return engine.import_time_risk(text, lang, declared, own, path=path)


def js_refusal(text, path=None):
    """The parser's refusal of a JavaScript-family text whose tree the supply-chain tests read, (line, reason), or
    None (engine.js_refusal); `path`, the file's name when known (a TypeScript file is read in its dialect)."""
    return engine.js_refusal(text, path)


def import_time_severity(reasons):
    """'CRITICAL' when one of the reasons is a strong one, else 'MAJOR'."""
    return _ask("import_time_severity", "", reasons=list(reasons))


def follow_hook(cmd):
    """(the package files an install hook's command runs, whether the walk
    read all of it)."""
    targets, complete = _ask("follow_hook", cmd)
    return targets, complete


def hook_runs_only_files(cmd):
    """Does an install hook's command run files of the package and nothing else, all of it read (NEW-HOOK-FP)?"""
    return _ask("hook_runs_only_files", cmd)


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


def scan_file(path, content, lang, dep=False):
    """The findings of one file: the engine's, in dependency mode and in
    project mode (where the passes after the rules read a taint
    configuration too: engine.scan_file)."""
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
# crates.io's API tokens (0.1.9, R-4): "cio" and 32 letters and digits, a whole run of them (in a run of base64 or
# a longer name, a "cio" is chance). The whole-run alternatives start with their literal and look behind it: the same
# language as a leading (?<!…), but Python's re then has a first character to look for (V-2: with one alternative led
# by a look-behind, which re tries at every position, the alternatives' regex ran about five times slower).
_CRATES_TOKEN_ALT = r"cio(?<![A-Za-z0-9]cio)[A-Za-z0-9]{32}(?![A-Za-z0-9])"
# npm's access tokens (V-2): "npm_" and 36 letters and digits, a whole run of them, as crates.io's
_NPM_TOKEN_ALT = r"npm_(?<![A-Za-z0-9]npm_)[A-Za-z0-9]{36}(?![A-Za-z0-9])"
# Anthropic's keys and tokens (V-2): "sk-ant-", a kind of three to five letters and two digits (an API key's api03, an
# admin key's admin01, an OAuth token's oat01…) or usr (the Console's personal API keys, sk-ant-usr-: S-TOKEN-USR),
# "-" and 40 to 200 of [A-Za-z0-9_-], a whole run of them
_ANTHROPIC_TOKEN_ALT = (r"sk-ant-(?<![A-Za-z0-9_\-]sk-ant-)(?:[a-z]{3,5}[0-9]{2}|usr)-"
                        r"[A-Za-z0-9_\-]{40,200}(?![A-Za-z0-9_\-])")
# OpenAI's keys (V-2): "sk-", 20 to 90 of [A-Za-z0-9_-] (a project's, a service account's or an admin's key names its
# kind first: "proj-", "svcacct-", "admin-"), "T3BlbkFJ" (the base64 of "OpenAI", which OpenAI's keys carry) and 20 to
# 74 more, a whole run of them
_OPENAI_TOKEN_ALT = r"sk-(?<![A-Za-z0-9_\-]sk-)[A-Za-z0-9_\-]{20,90}T3BlbkFJ[A-Za-z0-9_\-]{20,74}(?![A-Za-z0-9_\-])"
_JWT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_JWT_RUN_RE = re.compile(r"[A-Za-z0-9_\-]*")
_JWT_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9_\-])(?=[A-Za-z0-9_\-]{13,}\.eyJ[A-Za-z0-9_\-]{10})")
_TOKEN_ALTS = (       # S-TOKEN, in pattern order
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}", r"sk_live_[A-Za-z0-9]{16,}", r"AIza[0-9A-Za-z_\-]{35}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", _CRATES_TOKEN_ALT, _NPM_TOKEN_ALT, _ANTHROPIC_TOKEN_ALT, _OPENAI_TOKEN_ALT,
    _JWT_ALT)
_TOKEN_REDACT_ALTS = (    # the redaction list's first pattern (_SECRET_LINE_PATTERNS[0])
    r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36,}", r"github_pat_[A-Za-z0-9_]{22,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}", r"sk_live_[A-Za-z0-9]{16,}", r"AIza[0-9A-Za-z_\-]{35}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)", _CRATES_TOKEN_ALT, _NPM_TOKEN_ALT,
    _ANTHROPIC_TOKEN_ALT, _OPENAI_TOKEN_ALT, _JWT_ALT)


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
    if s.find(".eyJ", pos) < 0:                    # (every match holds one, after pos)
        return None
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


def R(id, name, type, sev, langs, pat, msg, why, fix, ref, skip=None, need=None, flags=0, skip_flags=re.I):
    return {"id": id, "name": name, "type": type, "sev": sev, "langs": langs,
            "re": pat if isinstance(pat, _TokenPattern) else re.compile(pat, flags),
            "msg": msg, "why": why, "fix": fix, "ref": ref,
            "skip": re.compile(skip, skip_flags) if skip else None,
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


# (Q-2, 0.1.9) each of the random module's generators; and on a line naming none of the words S-RANDOM needs, any
# call of one is S-WEAKRAND, a review hotspot (Bandit's B311, Sonar's S2245): none of BenchmarkPython's 99
# weak-randomness cases names one of those words where it calls the generator.
_RANDOM_FNS = ("random|randint|randrange|choice|choices|sample|shuffle|uniform|triangular|getrandbits|randbytes|gauss|"
               "normalvariate|lognormvariate|betavariate|expovariate|gammavariate|paretovariate|vonmisesvariate|"
               "weibullvariate|binomialvariate")
_SECRET_WORDS = r"(token|secret|password|otp|nonce|session|key|reset|csrf)"

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
# G12: the S-SQL-PY regex is only the fast path; project mode's SQL-sink pass
# (the engine's: project.rs) adds whole-argument analysis (cur.execute(sql % x)
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
# `require('child_process').exec(…)`) are still flagged, but not a call on
# a regex (0.1.9): a literal the lexer reads as one (`/…/g.exec(s)`), or a
# name the file assigns a whole regex and nothing else (_ASSIGN_NAME_RE,
# _REGEX_CTOR_RE): the engine's scanfile.rs exec_js_regex. RegExp's `exec`
# in a matching loop (`while ((m = re.exec(s)))`) was CRITICAL. Where a
# receiver came from is not read: another file can hand one child_process
# (`require('./a').exec(cmd)`).
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
# (0.1.9, G-4 and R-4: Go's `apiKey := "…"` and `var secret string = "…"`, Rust's
# `const API_KEY: &str = "…"`, `static SECRET: &'static str = "…"`, a byte or raw string)
R("S-SECRET", "Hardcoded credential", "VULN", "BLOCKER", ("py", "js", "go", "rs"),
  r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)"
  r"\s*(?::=|[:=]|:\s*&(?:'static\s+)?(?:str|\[u8\])\s*=|[ \t]+string\s*=)\s*(?:b|rb|r#*|br#*)?[\"'][^\"']{4,}[\"']",
  "Credential appears to be hardcoded in source.",
  "Secrets in code leak through version control, logs, and builds; rotation requires a deploy.",
  "Load secrets from environment variables or a secrets manager, and rotate this one now.",
  "CWE-798 · OWASP A07",
  # Verdict-integrity fix (audit C2): skip tokens used to match bare
  # substrings anywhere on the line. Word-bounded now; the bare `<...>`
  # pattern is gone — a real credential on the same line as an angle-bracket
  # generic no longer blinds the rule.
  # (SECRET-FP, 0.1.9) the skip words at a word's edge, `_`, `-`, a digit and a case change ending a word as a blank
  # does (\b never saw PLACEHOLDER_API_KEY): case-sensitive, each word in its three spellings
  skip=r"([Ee]nviron|ENVIRON|process\.env|[Gg]et[Ee]nv|GETENV|config\[|\bimport\b|\bIMPORT\b|(?<![A-Za-z0-9])(?:placeholder|example|dummy|sample|mock|mocked|redacted|fake|canary|made[_\-]?up|PLACEHOLDER|EXAMPLE|DUMMY|SAMPLE|MOCK|MOCKED|REDACTED|FAKE|CANARY|MADE[_\-]?UP|[xX]{4,}|xxxx+)(?![a-z])|(?<![A-Z0-9])(?:Placeholder|Example|Dummy|Sample|Mock|Mocked|Redacted|Fake|Canary|Made[_\-]?[Uu]p)(?![a-z])|\{\{)",
  flags=re.I, skip_flags=0),
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
  r"(random\.(" + _RANDOM_FNS + r")|Math\.random)\s*\(",
  "PRNG used in a security-sensitive value.",
  "random/Math.random are predictable; generated tokens can be guessed.",
  "Use secrets module (Python) or crypto.randomBytes / crypto.getRandomValues (JS).",
  "CWE-338",
  need=_SECRET_WORDS),
R("S-WEAKRAND", "Pseudo-random generator", "HOTSPOT", "MINOR", ("py",),
  r"(?<![\w.])random\.(?:" + _RANDOM_FNS + r")\s*\(",
  "The random module's generator in use.",
  "random is a Mersenne Twister: what it gives next can be worked out from what it gave, so a value an attacker must "
  "not guess (a token, a password, a session or reset key) made with it can be guessed.",
  "Use the secrets module (secrets.token_urlsafe, secrets.choice) or random.SystemRandom where the value must not be "
  "guessed; random is fine for simulations, sampling and tests.",
  "CWE-330",
  skip=_SECRET_WORDS),
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
# (Q-3, 0.1.9) a parser set to resolve external entities, no longer every import of xml.etree, xml.dom or xml.sax:
# since Python 3.7.1 none resolves an external entity unless told to, and Expat 2.4.1 refuses entity bombs, so the
# import flagged safe code (all 20 of BenchmarkPython's safe XXE cases; its 8 real ones turn the feature on).
R("S-XML", "XML external entities enabled", "VULN", "MAJOR", ("py",),
  r"setFeature\s*\(\s*(?:[\w.]*\.)?feature_external_(?:ges|pes)\s*,\s*(?:True|1)\s*\)"
  r"|setFeature\s*\(\s*[rRuU]?[\"']http://xml\.org/sax/features/external-(?:general|parameter)-entities[\"']"
  r"\s*,\s*(?:True|1)\s*\)|\bresolve_entities\s*=\s*True\b",
  "XML parser set to resolve external entities.",
  "With external entities on, a document can make the parser read local files or fetch URLs (XXE) and put what they "
  "hold in what it parses.",
  "Leave them off (xml.sax and xml.dom's default since Python 3.7.1; resolve_entities=False with lxml), or parse "
  "untrusted XML with defusedxml or lazaret.safexml.",
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
# made by the linear per-statement pre-scan of project mode's SQL pass (the
# engine's sql_nowhere: project.rs) — one O(n) pass over the file — not by
# the regex.
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
# Project mode's intra-file taint is the engine's (0.1.9, Q-1: taint.rs; its
# model, the sources, sinks, sanitizers, guards and framework shapes, is the
# rule pack's). A taint configuration (--taint-config, a trusted
# .lazaret-taint.json, scan_project's taint_config) adds sources, sinks and
# sanitizers: validated here (taintspec), kept as the part of the model each
# call is given (taint_args), and joined to the pack's in the engine as they
# were joined to core's tables. Applied configurations add up, process-wide,
# as those tables did.
_TAINT_CONFIGURED = {lang: {"sources": [], "sinks": [], "full": [], "partial": []} for lang in ("py", "js")}


def taint_args(lang):
    """The configured part of the taint model for a file of `lang` (the
    engine's `"taint"` argument: {"sources": [pattern], "sinks": [[pattern,
    category]], "full": [name], "partial": [[name, [category]]]}), or None
    when nothing is configured for it."""
    part = _TAINT_CONFIGURED.get(lang)
    if part is None or not any(part.values()):
        return None
    return {key: [list(v) if isinstance(v, list) else v for v in values] for key, values in part.items()}


def taint_scan(path, lines, lang):
    """The intra-file taint's findings (T-*) in a file's lines, before the
    suppression markers and the cap, with the configured part of the model:
    the engine's pass alone (taint_scan), which its scan_file runs in
    project mode."""
    if lang not in ("py", "js"):
        return []
    args = {"lang": lang, "jsx": jsx_reading(path), "redact": bool(REDACT_SECRETS), "neumaier": False}
    configured = taint_args(lang)
    if configured:
        args["taint"] = configured
    return engine._issues(path, _native.call("taint_scan", args, "\n".join(lines)))


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
    at most taintspec.MAX_MATCH_TEXT characters of a line: the engine holds
    them to it). allow_sanitizers=False (a config from the scanned
    repository): its sanitizers are ignored, never applied. What is applied
    is the part of the model every later call is given (taint_args).
    """
    del _TAINT_CONFIG_WARNINGS[:]
    spec = (cfg if isinstance(cfg, taintspec.TaintSpec)
            else taintspec.validate(cfg, allow_sanitizers=allow_sanitizers))
    _TAINT_CONFIG_WARNINGS.extend(spec.warnings)
    for lang_key, lang in (("python", "py"), ("javascript", "js")):
        ls = spec.lang(lang_key)
        part = _TAINT_CONFIGURED[lang]
        part["sources"].extend(g.pattern for g in ls.sources)
        part["sinks"].extend([g.pattern, cat] for g, cat in ls.sinks)
        # names are validated call names; the engine escapes them (literal)
        part["full"].extend(ls.full)
        part["partial"].extend([name, sorted(cats)] for name, cats in ls.partial.items())


#: The scanned repository's own taint config (never auto-trusted).
REPO_TAINT_CONFIG = ".lazaret-taint.json"
#: Largest taint-config file read (bytes).
TAINT_CONFIG_MAX_BYTES = 1_000_000


def _read_taint_config(path, from_repo, raw=None):
    """(cfg, None) or (None, reason) for a taint-config file.

    Only a regular file is read (a FIFO would hang the open); a repository
    config must not be a symlink either. Reads are bounded; bad UTF-8,
    invalid JSON, huge integers and deep nesting are reasons, not crashes.

    A repository config is opened once, its last component not followed
    (O_NOFOLLOW | O_NONBLOCK), and what the descriptor is decides (fstat):
    a link or a special file swapped in after it was found is not read
    (LZ-03). `raw`, a list, is given the bytes read (the Q-TAINT-CONFIG
    note's lines are these, not a second read)."""
    import stat as _stat
    if from_repo:
        nofollow = hasattr(os, "O_NOFOLLOW")
        if not nofollow:            # (Windows) a link refused by lstat; the file opened kept only beside it
            try:
                st = os.lstat(path)
            except OSError as exc:
                return None, str(exc.strerror or exc)
            if not _stat.S_ISREG(st.st_mode) or _is_reparse_point(st):
                return None, "not a regular file (symlinks and special files are not followed)"
        try:
            fd = (os.open(path, _OPEN_FLAGS) if nofollow
                  else _open_verified(os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(path)))), path))
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                return None, "not a regular file (symlinks and special files are not followed)"
            return None, str(exc.strerror or exc)
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                return None, "not a regular file (symlinks and special files are not followed)"
            if st.st_size > TAINT_CONFIG_MAX_BYTES:
                return None, (f"{st.st_size} bytes exceeds the "
                              f"{TAINT_CONFIG_MAX_BYTES}-byte limit")
            data = _read_fd(fd, TAINT_CONFIG_MAX_BYTES + 1)
        except OSError as exc:
            return None, str(exc.strerror or exc)
        finally:
            os.close(fd)
    else:
        try:
            st = os.stat(path)
        except OSError as exc:
            return None, str(exc.strerror or exc)
        if not _stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_size > TAINT_CONFIG_MAX_BYTES:
            return None, (f"{st.st_size} bytes exceeds the "
                          f"{TAINT_CONFIG_MAX_BYTES}-byte limit")
        try:
            with open(path, "rb") as fh:
                data = fh.read(TAINT_CONFIG_MAX_BYTES + 1)
        except OSError as exc:
            return None, str(exc)
    if raw is not None:
        raw.append(data)
    try:
        return json_loads_bounded(data.decode("utf-8")), None
    except (ValueError, MemoryError) as exc:
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
    raw = []
    cfg, err = _read_taint_config(path, from_repo, raw)
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
    # the bytes loaded, as text mode read them before (LZ-03: no second open)
    cfg_lines = raw[0][:TAINT_CONFIG_MAX_BYTES].decode("utf-8", errors="replace").replace("\r\n", "\n") \
        .replace("\r", "\n").split("\n") if raw else []
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
# (SECRET-FP, 0.1.9) the words at a word's edge (`_`, `-`, a digit, a case change: PLACEHOLDER_API_KEY), each in its
# three spellings, and a line naming a public key (`publicKey`, `PUBLIC_KEY`, `pubkey`; not `public` alone, which is a
# TypeScript field's modifier)
SECRET_SKIP_RE = re.compile(r"[Ee]nviron|ENVIRON|process\.env|[Gg]et[Ee]nv|GETENV|(?<![A-Za-z0-9])(?:placeholder|example|dummy|sample|mock|mocked|redacted|fake|canary|made[_\-]?up|PLACEHOLDER|EXAMPLE|DUMMY|SAMPLE|MOCK|MOCKED|REDACTED|FAKE|CANARY|MADE[_\-]?UP|[xX]{4,}|xxxx+)(?![a-z])|(?<![A-Z0-9])(?:Placeholder|Example|Dummy|Sample|Mock|Mocked|Redacted|Fake|Canary|Made[_\-]?[Uu]p)(?![a-z])|(?:[Pp]ublic|PUBLIC)[_\- ]?(?:[Kk]ey|KEY)|[Pp]ub[Kk]ey|PUBKEY|[Pp]ub_[Kk]ey|PUB_KEY")

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
    return _suppressed_in(issue, _FileCtx(lines, lang))


# ---------------- Binary / compiled-artifact detection ----------------
# Source packages (sdists, npm tarballs, repos) should ship reviewable source,
# not prebuilt binaries. Smuggled binaries are a primary supply-chain vector:
# malicious code inside a compiled blob never appears in the source you review.
# Wheels legitimately ship compiled extensions, so presence there is inventory,
# not alarm. Detection is by content (magic bytes), not just file extension.

COMPILED_EXTS = {".so", ".pyd", ".dll", ".dylib", ".node", ".a", ".lib", ".o",
                 ".obj", ".exe", ".pyc", ".pyo", ".class", ".wasm",
                 ".dex", ".jar", ".war", ".ear", ".apk", ".msi", ".dmg",
                 ".jsc"}              # V8 bytecode (bytenode): JavaScript no one can read
#: MPEG transport stream video (a camera's AVCHD .mts): the extensions it shares
#: with TypeScript (.ts, .mts), and Blu-ray's .m2ts
MPEG_TS_EXTS = (".ts", ".mts", ".m2ts")


#: The engine reads a path's folders as os.path does here: "\\" separates them on Windows (binary.rs)
_WINDOWS_PATHS = os.sep == "\\"


def _bytes_text(data):
    """`data` as the engine reads a file's bytes: latin-1 text, a character per byte."""
    return bytes(data or b"").decode("latin-1")


def looks_binary(sample):
    """Heuristic text/binary classification from a leading byte sample.

    Only bytes that cannot be text count: invalid UTF-8 and C0 control
    characters (NUL included). Valid non-ASCII UTF-8 is text however much of
    it there is (an accented package description, CJK comments), and a single
    NUL inside a comment does not turn a source file into a "binary" that is
    never scanned. Callers must not use this to decide whether a file with a
    source extension or a manifest name gets scanned: those are always
    scanned as text (see decode_source). The engine's (BR-7 step 3 d:
    binary.rs)."""
    if not sample:
        return False
    return _native.call("binary_check", {"check": "looks"}, _bytes_text(sample))


def _mpeg_ts(header):
    """MPEG transport stream (.ts / .mts video): sync byte every 188 bytes.
    Shares the .ts and .mts extensions with TypeScript (binary.rs)."""
    return _native.call("binary_check", {"check": "mpeg_ts"}, _bytes_text(bytes(header[:377])))


# ---------------- Source decoding for archive members (registry, MCP) ----------------
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
    line keeps its coding cookie); by default, its extension's. The engine's
    (BR-7 step 4 b: decode/), in one call."""
    data = bytes(data or b"")
    if lang is None:
        ext = os.path.splitext(path)[1].lower()
        lang = "py" if ext in (".py", ".pyw") else EXTS.get(ext)
    args = {"issues": True, "redact": bool(REDACT_SECRETS), "name": path, "windows": _WINDOWS_PATHS}
    if lang:
        args["lang"] = lang
    got = _native.call("decode_source", args, _bytes_text(data))
    return got["text"], engine._issues(path, got["issues"])


def decode_go_member(path, data):
    """decode_member for a .go file, and what the Go reader reads of it -> (text, extra_issues, go_text): the bytes
    as the Go toolchain reads them where that is not the text (UTF-16 or UTF-32, whose NULs Go refuses; a lone
    "\\r", white space to Go and a line end to the rules), the text otherwise (F-06: the engine's decode::go_text).
    One call."""
    data = bytes(data or b"")
    args = {"issues": True, "redact": bool(REDACT_SECRETS), "name": path, "windows": _WINDOWS_PATHS, "lang": "go"}
    got = _native.call("decode_source", args, _bytes_text(data))
    return got["text"], engine._issues(path, got["issues"]), got.get("goText", got["text"])

#: classify_binary's `props` when its caller does not look beside the file (FP-GRADLE-WRAPPER)
_NOT_GIVEN = object()


def classify_binary(path, data, size, context, whole=None, walked=None, props=_NOT_GIVEN):
    """Return a supply-chain issue dict for a suspicious non-source file (a list
    of two for a keystore that is an opaque blob too), or None:
    SC-BINARY for an executable or a compiled artifact (by its magic bytes, or
    its extension when its bytes are binary, FP-BINARY-BY-NAME: inventory in a
    wheel, a capability to review elsewhere),
    SC-NESTED-ARCHIVE for an archive inside the package, SC-OPAQUE-BLOB for a
    high-entropy binary blob; nothing for an image or document file. The
    engine's (BR-7 step 3 d: binary.rs).

    FP-OPAQUE-MEDIA: a near-random file is a sound, video, image or font, and
    quiet, when its bytes are that format from start to end (walked by its
    structure: media.rs), and a keystore read to its end is a credential file
    (S-SECRET, listed only; with SC-OPAQUE-BLOB beside it when it holds more
    bytes no structure reads than a keystore does). Both need the whole file:
    `whole` when `data` is it (it is handed over only when the first bytes
    call for it), or `walked`, a walk of it as its stream passed
    (media_stream_file's answer). Without either, a file that would need them
    is judged by its first bytes: an opaque blob stays one.

    FP-GRADLE-WRAPPER: a Gradle wrapper jar (gradle/wrapper/gradle-wrapper.jar)
    is judged by its checksum against Gradle's published wrapper checksums
    (gradle.rs), with `props`, the bytes of the gradle-wrapper.properties
    beside it (its first GRADLE_PROPERTIES_MAX_BYTES and one more, so that a
    longer one is told; None: there are none; {"error": why}: it is there and
    was not read; not given, as None when `data` is the whole jar, else the
    jar is judged as any jar). Given `props` without the whole jar, it was not
    read whole.

    context: 'sdist' | 'npm' | 'wheel' | 'repo'
    data:    leading bytes of the file (>= a few KB is ideal for entropy; the
             first 8,192 are read), or all of it with `whole`
    size:    full file size in bytes
    whole:   `data` is the whole file (None: when it holds `size` bytes)
    """
    args = {"path": path, "size": size, "context": context, "windows": _WINDOWS_PATHS, "neumaier": False}
    if walked is not None:
        args["walked"] = walked
    if props is not _NOT_GIVEN:
        args["props"] = (None if props is None else {"error": str(props.get("error", ""))} if isinstance(props, dict)
                         else _bytes_text(bytes(props)))
    data = bytes(data or b"")
    if whole is None:
        whole = len(data) == size
    if whole and walked is None:
        if len(data) <= 8192 or "props" in args:
            got = _native.call("binary_classify", dict(args, whole=True), _bytes_text(data))
        else:
            got = _native.call("binary_classify", dict(args, more=True), _bytes_text(data[:8192]))
            if isinstance(got, dict) and "need" in got:
                got = _native.call("binary_classify", dict(args, whole=True), _bytes_text(data))
    else:
        got = _native.call("binary_classify", args, _bytes_text(data[:8192]))
    if isinstance(got, dict) and got.get("need") == "wrapper":
        # (a Gradle wrapper jar its caller gave no properties for: judged with none)
        got = _native.call("binary_classify", dict(args, whole=True, props=None), _bytes_text(data))
    if isinstance(got, list) and got and isinstance(got[0], list):
        return engine._issues(path, got)          # (a keystore that is an opaque blob too: both findings)
    return None if got is None else engine._issues(path, [got])[0]


def gradle_wrapper_path(path):
    """FP-GRADLE-WRAPPER: whether classify_binary judges a file at `path` as a Gradle wrapper jar, by its checksum
    with the gradle-wrapper.properties beside it (gradle/wrapper/gradle-wrapper.jar)."""
    got = _native.call("binary_classify", {"path": path, "size": 0, "context": "repo", "windows": _WINDOWS_PATHS,
                                           "neumaier": False, "more": True}, "")
    return isinstance(got, dict) and got.get("need") == "wrapper"


def classify_needs_whole(path, data, size, context):
    """FP-OPAQUE-MEDIA: whether classify_binary needs a file's whole bytes, or a walk of them, to judge it (a
    keystore, or a near-random file whose first bytes start a format the engine walks), from its first bytes."""
    got = _native.call("binary_classify", {"path": path, "size": size, "context": context, "windows": _WINDOWS_PATHS,
                                           "neumaier": False, "more": True}, _bytes_text(bytes(data or b"")[:8192]))
    return isinstance(got, dict) and got.get("need") == "whole"


#: A file walked as its stream passes is read this many bytes at a time (media_stream).
MEDIA_CHUNK = 1 << 20


def media_stream(state, offset, chunk, eof):
    """FP-OPAQUE-MEDIA: the next chunk of a file walked by its structure as its stream passes: `state` None at its
    start, else the last answer's; `offset` where the chunk starts (where the last ended, or the answer's `next`, when
    the bytes between are passed over); `eof` with its last (an empty chunk at its end will do) -> {"state", "next",
    "end": None while it runs, else {"is": kind}, {"not": kind, "why"} or {"unknown": True}}. The engine's
    (media::feed)."""
    return _native.call("media_stream", {"state": state, "offset": offset, "eof": bool(eof)}, _bytes_text(bytes(chunk)))


def media_walk(data):
    """FP-OPAQUE-MEDIA: what a whole file is, walked by its structure to its end: {"is": kind}, {"not": kind, "why"}
    or {"unknown": True}. The engine's (media::walk)."""
    return _native.call("media_walk", {}, _bytes_text(bytes(data)))


def media_stream_file(read_at, size=None):
    """The end of a walk of a file (of `size` bytes) read through `read_at(offset, n)` (its bytes from `offset`, at
    most `n`, b"" at its end), MEDIA_CHUNK at a time, passing over what the walk skips (media_stream), never past the
    file's end: a part that runs past it is a file cut short (its size not given, the byte before where the walk
    goes on is read to tell)."""
    state, offset = None, 0
    while True:
        chunk = read_at(offset, MEDIA_CHUNK)
        got = media_stream(state, offset, chunk, not chunk)
        if got["end"] is not None:
            return got["end"]
        state = got["state"]
        end, nxt = offset + len(chunk), got["next"]
        if nxt > end and (nxt > size if size is not None else not read_at(nxt - 1, 1)):
            # (the file ends before where the walk goes on: it is cut short there)
            return media_stream(state, end, b"", True)["end"]
        offset = max(end, nxt)


def media_stream_chunks(chunks):
    """The end of a walk of a file whose bytes come as `chunks` (an iterable of bytes, in order, to its end), each
    fed whole: a stream that cannot pass over bytes (an archive's member); None when it ended without an answer."""
    state, offset = None, 0
    for chunk in chunks:
        if not chunk:
            continue
        got = media_stream(state, offset, chunk, False)
        if got["end"] is not None:
            return got["end"]
        state = got["state"]
        offset += len(chunk)
    return media_stream(state, offset, b"", True)["end"]


def model_sniff(path, data):
    """FP-MODEL-FILES: whether a file whose first bytes are `data` (the first 512 are read) may be a model file, one
    to hand model_file whole. The engine's (pickle::sniff)."""
    return _native.call("model_sniff", {"path": path, "windows": _WINDOWS_PATHS}, _bytes_text(bytes(data or b"")[:512]))


def model_file(path, data, size=None, limit=None, pieces=None, last=True):
    """FP-MODEL-FILES: a model file (a PyTorch checkpoint, a pickle, joblib's, numpy's .npy/.npz) read for what its
    pickles would run, never unpickled -> None when it is not one, else {"kind", "issues" (SC-PICKLE-CODE,
    SC-PICKLE-GLOBAL, SC-TRUNCATED), "imports" ([[module, name, how]]: the globals of no known kind, for
    model_own_issues), "opaque" (its archive holds more than its format: SC-NESTED-ARCHIVE stays)}. `data`: the file
    whole, or its first bytes when it is larger (`size`) than the scan reads (`limit`). Or, for a zip model file read
    by range whatever its size, `pieces` ([(offset, bytes)], its first bytes among them) of a file of `size` bytes:
    {"need": [[offset, length]]} until it has the ranges it reads (its end records, its central directory, its pickle
    members), unless `last` (what it still needs is SC-TRUNCATED). The engine's (pickle/)."""
    if pieces is not None:
        pieces = [(off, bytes(b)) for off, b in pieces]
        args = {"path": path, "size": size, "windows": _WINDOWS_PATHS, "pieces": [[off, len(b)] for off, b in pieces],
                "last": bool(last)}
        got = _native.call("model_file", args, _bytes_text(b"".join(b for _, b in pieces)))
        if got is not None and "need" in got:
            return {"need": got["need"]}
    else:
        data = bytes(data or b"")
        args = {"path": path, "size": len(data) if size is None else size, "windows": _WINDOWS_PATHS}
        if limit is not None:
            args["limit"] = limit
        got = _native.call("model_file", args, _bytes_text(data))
    if got is None:
        return None
    return {"kind": got["kind"], "issues": engine._issues(path, got["issues"]), "imports": got["imports"],
            "opaque": got["opaque"], "calls": got.get("calls", [])}


def model_own_issues(models, files):
    """FP-MODEL-FILES, once the scan knows its files: SC-PICKLE-GLOBAL as INFO for each global of the scanned package's
    own modules a model file imports (importing one runs that module's code, which the scan reads, when the file is
    loaded), and SC-PICKLE-GLOBAL, MAJOR, for each call with text a model file holds (whatever the scan's source says
    of the class: which file a module name is when the file is loaded is the loading program's import path, the
    external re-review of Oct 27). `models`: [[path, dep, imports, calls]] (model_file's, collect_file's); `files`:
    the scan's files, [[path, dep]] (its Python files are its modules, a dependency's its package's). The engine's
    (pickle::own_imports)."""
    if not models:
        return []
    got = _native.call("model_own", {"models": models, "files": files})
    return [engine._issues(p, [row])[0] for p, row in got]


def model_own_files(models, files):
    """model_own_issues' files from the scan's [{path, content, dep}]: [[path, dep]]."""
    return [[f["path"], bool(f.get("dep", False))] for f in files]


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
    num2words 0.5.15's `_build.py` is a Windows executable. Else None. The
    engine's (BR-7 step 3 d: binary.rs)."""
    got = _native.call("binary_disguised", {"path": path, "windows": _WINDOWS_PATHS},
                       _bytes_text(bytes(data or b"")[:DISGUISE_SAMPLE_BYTES]))
    return None if got is None else engine._issues(path, [got])[0]


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
#: text gets); a package's are read by the engine's readers where the
#: package is a Go module or a crate (registry/repo.py PACKAGE_CODE; with
#: --deps, a Go or cargo vendor tree: VENDOR_CODE), and classified as any
#: other file elsewhere.
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
#     dependency tree (a marker inside: pyvenv.cfg, modules.txt, …) — a
#     first-party app/vendor/ helper module used to be pruned by name alone,
#     hiding it from every rule.
# These decisions are the engine's since 0.1.9 (collect.rs, BR-7 step 4 e).
#   * --exclude NAME prunes any directory of that name (explicit, always).
# Every other classic "build output" directory — dist, build, migrations,
# coverage — is scanned: npm packages are *published from* dist/, migrations
# ARE the production SQL. Pruned trees are counted and reported, never
# silently dropped.
SKIP_DIRS = {".git", "__pycache__"}     # never source-scanned (see above)
ALWAYS_PRUNE_DIRS = frozenset({".git"})
PYCACHE_DIR = "__pycache__"
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

def _tree_stats_at(tree, parts):
    """_tree_stats of the folder `parts` of a _Root, read from its descriptor: a folder that is a link or no folder
    now is not counted further (nothing in a pruned tree is read)."""
    n_files, n_bytes = 0, 0
    stack = [tuple(parts)]
    while stack:
        cur = stack.pop()
        try:
            entries = tree.listdir(cur)
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if _stat.S_ISDIR(st.st_mode) and not _is_reparse_point(st):
                stack.append(cur + (e.name,))
            else:
                n_files += 1
                if _stat.S_ISREG(st.st_mode):
                    n_bytes += st.st_size
    return n_files, n_bytes

def _count_skipped_tree(root, tree_path, rel=None, into=None):
    """Record a pruned directory with its file count and total size for the
    INFO blind-spot accounting surfaced after the scan. `rel` is the
    root-relative display path (review item 5: it used to be cwd-relative,
    e.g. './app/vendor', when the root was given as a relative path).
    `root` a _Root: `tree_path` is the folder's names below it (LZ-03)."""
    if isinstance(root, _Root):
        n_files, n_bytes = _tree_stats_at(root, tree_path)
        if rel is None:
            rel = _fs_display(os.path.join(*tree_path))
        (_SKIPPED_TREES if into is None else into).append((rel, n_files, n_bytes))
        return
    n_files, n_bytes = _tree_stats(tree_path)
    if rel is None:
        rel = _fs_display(os.path.relpath(tree_path, root))
    (_SKIPPED_TREES if into is None else into).append((rel, n_files, n_bytes))

def _skipped_issue(rel, n_files, n_bytes):
    return collect_issue("skipped_tree", rel, files=n_files, bytes=n_bytes)

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


class _Redactor:
    """One file's lines, for the findings built from them outside the
    engine's scan of the file (encoding_issues, the package checks, the
    agent-hijack and import-risk findings): mk_issue with one redacts their
    snippets and messages with the file's entropy literals too, as the engine
    redacts the findings of its own scans. The redaction is the engine's
    (BR-7 step 3 c, 0.1.9: redact.rs); the lines are handed to it joined,
    once per call (mk_issues: once for all of a file's findings)."""

    def __init__(self, lines):
        self.lines = lines
        self._text = None

    @property
    def text(self):
        if self._text is None:
            self._text = _lines_text(self.lines)
        return self._text


def _lines_text(lines):
    """`lines` joined as the engine reads a file's lines (anything that is
    not a string reads as an empty line)."""
    return "\n".join(l if isinstance(l, str) else "" for l in lines)


class _FileCtx:
    """A file's facts for is_suppressed, computed once: the comment layout
    and the parsed suppression markers. (A source or config file's scan is
    the engine's, with its own: filectx.rs.)"""

    def __init__(self, lines, lang, content=None, jsx=True):
        self.lines = lines
        self.lang = lang
        self.content = "\n".join(lines) if content is None else content
        self.cmask, self.cspans, self.code = _comment_layout(self.content, lines, lang, None, jsx)
        self._markers = {}

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

# The redaction of snippets and messages (FIX-SPEC 6, audit L1) is the
# engine's (BR-7 step 3 c, 0.1.9: redact.rs and findings.rs), for the
# findings it makes and for the ones the packages still build: a secret
# rule's flagged line becomes REDACT_PLACEHOLDER and its length; on every
# other line, the lines of a PEM private key's block are redacted whole and
# the matches of the line patterns below (and, for a file's own findings, its
# entropy literals: the strings S-ENTROPY would flag, wherever they appear)
# become [redacted]. The patterns stay here as data: the rule pack's check
# and the dashboard's tests compare theirs with them.
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
               r"private[_-]?key)\s*(?::=|[:=]|:\s*&(?:'static\s+)?(?:str|\[u8\])\s*=|[ \t]+string\s*=)\s*"
               r"(?:b|rb|r#*|br#*)?[\"'][^\"']{4,}[\"']", re.I),
    # credentials in a URL's userinfo: scheme://user:password@host, scheme://token@host
    re.compile(r"(?<=://)[^/\s@'\"]+(?=@)"),
]
REDACTED = "[redacted]"


def _redact_context_line(line):
    """`line` with every match of the line patterns replaced by [redacted]
    (the engine's: redact.rs)."""
    return _native.call("redact_text", {"mode": "line"}, line)


def _pem_block_lines(lines):
    """Indices of the lines of multi-line PEM private keys that follow the
    BEGIN line, through the END line, or through the last line when no END
    follows (the engine's: findings.rs). Such lines are redacted whole."""
    return {k for k in _native.call("pem_lines", {}, _lines_text(lines)) if isinstance(lines[k], str)}


def _redact_text(text, context=None):
    """Redaction for free text that may copy source (an issue's msg, a hook's
    cmd): the PEM blocks whole, then the line patterns, and with `context`
    (a file's lines) the file's entropy literals (the engine's: redact.rs)."""
    if not isinstance(text, str):
        return text
    args = {"mode": "text", "neumaier": False}
    if context is not None:
        args["context"] = _lines_text(context)
    return _native.call("redact_text", args, text)


# ---------------- Snippets (review fix: shared semantics 7) ----------------
# A finding used to copy its ±2 context lines whole: a 22.5 KB one-line file
# produced a 34 MB JSON and a 34 MB HTML report. Every snippet line is now
# clipped to SNIPPET_MAX characters. The flagged line is windowed around the
# match: the window starts SNIPPET_LEAD characters before the match column
# (never past the point where it would run off the end), and "…" marks each
# side that was cut. Other lines keep their start. Redaction runs on the
# whole line, before clipping, so a clip boundary can never cut a secret into
# a no-longer-matching fragment. The engine clips (findings.rs).
SNIPPET_MAX = 240
SNIPPET_LEAD = 60
ELLIPSIS = "…"


def clip_snippet_line(text, col=None):
    """`text` clipped to at most SNIPPET_MAX characters (see above)."""
    if not isinstance(text, str) or len(text) <= SNIPPET_MAX:
        return text
    return _native.call("clip_line", {"col": col if isinstance(col, int) else None}, text)


_RULE_TEXTS = ("id", "name", "type", "sev", "msg", "why", "fix", "ref")


def mk_issue(rule_or_dict, path, line_no, lines, col=None, redactor=None):
    """Issue dict for rule `rule_or_dict` at 1-based `line_no` of `lines`
    (mk_issues, for one finding)."""
    return mk_issues(path, lines, [(rule_or_dict, line_no, col)], redactor)[0]


def mk_issues(path, lines, items, redactor=None):
    """An issue dict for each of `items` ((rule, line_no, col)), findings of
    the file `path` whose lines are `lines`, made by the engine (redact.rs;
    the lines handed over once). A finding's snippet is its ±2 lines, each
    clipped; `col` (the 0-based character offset of the match on the flagged
    line, or None) centres the flagged line's window on the match. With
    REDACT_SECRETS, the flagged line of a secret rule is the placeholder and
    the other lines and the message are redacted: with the file's entropy
    literals too when `redactor` is a _Redactor over these same `lines` (the
    engine makes a scanned file's findings, with the same redaction)."""
    items = [tuple(it) for it in items]
    if not items:
        return []
    context = redactor is not None and redactor.lines is lines
    rows = [[{k: r[k] for k in _RULE_TEXTS}, line_no, col if isinstance(col, int) else None]
            for r, line_no, col in items]
    got = _native.call("issue_make", {"items": rows, "redact": bool(REDACT_SECRETS), "context": context,
                                      "neumaier": False},
                       redactor.text if context else _lines_text(lines))["issues"]
    out = []
    for (r, line_no, _), a in zip(items, got):
        out.append({"rule": r["id"], "name": r["name"], "type": r["type"], "sev": r["sev"],
                    "msg": a[4] if isinstance(r["msg"], str) else r["msg"], "why": r["why"], "fix": r["fix"],
                    "ref": r["ref"], "file": path, "line": line_no, "snippet": a[9], "snipStart": a[10]})
    return out


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
        # omitted findings, not the note (the engine's rating: result.rs)
        note["omitted"] = n
        note["omittedType"] = typ
        out.append(note)
    return out


def extract_functions(lines, lang):
    """[{"name", "line", "len", "cx"}] of a Python or JavaScript file's
    functions, as the function metrics (Q-FN-LONG, Q-FN-CX) read them: the
    engine's (functions; project.rs)."""
    if lang not in ("py", "js"):   # function/complexity metrics don't apply to SQL
        return []
    return [{"name": name, "line": line, "len": length, "cx": cx}
            for name, line, length, cx in _native.call("functions", {"lang": lang}, "\n".join(lines))]


def normalize_newlines(text):
    """Line endings as text mode reads them: \r\n and a lone \r become \n.
    Project files are read in text mode already; registry archives are decoded
    from bytes, so a package authored on Windows would otherwise leave "\r" on
    every line. Twin of normalizeNewlines in js/src/lib/fs.js."""
    return text.replace("\r\n", "\n").replace("\r", "\n") if "\r" in text else text


# ---------------- Config and data files (credentials only) ----------------
# .env, JSON, YAML, TOML, INI, .properties, shell, PEM keys, Dockerfiles,
# .npmrc / .pypirc, Terraform variables (configsecrets.is_config_file): read
# as text and checked by the two credential rules, never as code. The reading
# is the engine's (config.rs, BR-7 step 3: scan_config_file).


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
# its tool runs is MAJOR: the tool may read it more leniently. The reading and
# the judgment are the engine's (autorun.rs), the reading of the tree's files
# this module's.
#: How many times a settings file's issues are asked for at most: each answer that is not the issues names the files
#: of the tree the engine has yet to read (the files a command runs, then the scripts those start)
_AUTORUN_ROUNDS = 64


def autorun_issues(path, lines, read=None):
    """SC-AUTORUN findings for a settings file (autorun.config_kind(path) is
    not None) whose text is lines; read(rel) returns the text of a file of
    the tree ('/'-separated, root-relative) or None, to follow a command into
    the files it runs (None: the commands alone are judged). The engine reads
    the file and judges each command (BR-7 step 2: `autorun_issues`); it names
    the files of the tree it follows a command into, and they are read here."""
    text = "\n".join(lines)
    files = {}
    for _ in range(_AUTORUN_ROUNDS):
        got = _native.call("autorun_issues", {"path": path, "follow": read is not None, "files": files}, text)
        if "issues" in got:
            return mk_issues(path, lines, [(rule, line, None) for line, rule in got["issues"]])
        for rel in got["need"]:
            files[rel] = read(rel)
    got = _native.call("autorun_issues", {"path": path, "follow": False}, text)
    return mk_issues(path, lines, [(rule, line, None) for line, rule in got["issues"]])


def agentdoc_kind(path):
    """The kind of AI-agent skill or instruction file `path` names ("agent
    skill", "agent instructions", "agent command", "agent definition",
    "editor rules"), or None (the engine's agentdoc.is_agent_doc; RA-3)."""
    return _native.call("agentdoc_kind", {}, path)


def agentdoc_issues(path, lines, read=None, dep=None):
    """SC-AGENT-SKILL findings for an agent skill or instruction file
    (agentdoc_kind(path) is not None; RA-3): the commands and code it tells the
    agent to run (the hook-command test; a Python or JavaScript block the
    install-script test), a script of its folder such a command runs (followed
    via read(rel), as autorun_issues), a password-protected archive, a paste
    host or public raw IP, hidden text, or an order to send data out. `dep`:
    the file is a dependency's (CRITICAL / MAJOR), False the project's own
    (INFO: listed, never counted); None, a file under a dependency folder
    (node_modules, site-packages, ...) is a dependency's. The engine reads the
    file (`agentdoc_issues`); [] for a clean one."""
    text = "\n".join(lines)
    files = {}
    args = {"path": path, "follow": read is not None, "files": files}
    if dep is not None:
        args["dep"] = bool(dep)
    for _ in range(_AUTORUN_ROUNDS):
        got = _native.call("agentdoc_issues", args, text)
        if "issues" in got:
            return mk_issues(path, lines, [(rule, line, None) for line, rule in got["issues"]])
        for rel in got["need"]:
            files[rel] = read(rel)
    got = _native.call("agentdoc_issues", dict(args, follow=False), text)
    return mk_issues(path, lines, [(rule, line, None) for line, rule in got["issues"]])


# ---------------- CI files (SC-WORKFLOW-*, SC-GITLAB-*) ----------------
#: The CI files' hardening checks (0.1.9; the engine's ci/workflow.rs and
#: ci/gitlab.rs since BR-7): the practices a pipeline should follow, not the shapes
#: of one that was tampered with. They are reported, and only a CRITICAL one
#: (a pull_request_target job that runs a pull request's code, a file included
#: over plain http) counts against the gate's supply-chain condition: most
#: repositories run an action at a version tag or set no permissions, and that
#: condition is for indicators (build_result).
#: HARDENING_RULES: the pack's since BR-7 step 4 (a), which grades the result in the engine; read when first asked
#: for (module __getattr__, below), so that importing core needs no engine


def ci_issues(path, lines):
    """The issues of a CI file whose text is lines: a GitHub Actions workflow's
    SC-WORKFLOW-* (the worms' shapes, then the hardening checks) or a GitLab CI
    file's SC-GITLAB-* (HARDENING_RULES); nothing for another file. The engine
    reads the file (BR-7: `ci_issues`) and answers each issue's line and rule;
    the path is asked first, so another file's text is not handed over."""
    if _native.call("ci_kind", {}, path) is None:
        return []
    return mk_issues(path, lines, [(rule, line, None)
                                   for line, rule in _native.call("ci_issues", {"path": path}, "\n".join(lines))])


def tree_reader(files, configs, disk=None):
    """read(rel) for autorun_issues: the text of a scanned source or config
    file ('/'-separated, root-relative; a path node would load resolves as
    node_candidates does), with \\n line endings, or None. `disk`: read(rel)
    of a file the walk did not keep (a dependency's shell script that its
    agent skill runs: _disk_reader), tried for rel itself when no scanned
    file answers."""
    texts = {}
    for f in list(files) + list(configs):
        texts.setdefault(f["path"].replace(os.sep, "/"), f["content"])

    def read(rel):
        for cand in node_candidates(rel):
            if cand in texts:
                return normalize_newlines(texts[cand])
        if disk is not None:
            text = disk(rel)
            if text is not None:
                return normalize_newlines(text)
        return None
    return read


def scan_config_file(path, content, read=None, dep=None):
    """Credentials in a config or data file (see configsecrets): S-TOKEN on
    every line, S-SECRET outside comments. Nothing else runs — it is not
    code. Suppression markers work in the file's comments, as in code. An
    editor's or AI agent's settings that run commands also get SC-AUTORUN
    (read: see autorun_issues), a GitHub Actions workflow the
    SC-WORKFLOW-* checks and a GitLab CI file the SC-GITLAB-* ones, and an
    AI agent's skill or instruction file SC-AGENT-SKILL instead of the
    credential pass (see agentdoc_issues; `dep` as there: a --deps tree's
    file is a dependency's). The engine reads the file (BR-7 step 3:
    `scan_config`), and names the files of the tree a settings file's
    commands run; they are read here."""
    files = {}
    args = {"path": path, "follow": read is not None, "files": files,
            "redact": bool(REDACT_SECRETS), "neumaier": False}
    if dep is not None:
        args["dep"] = bool(dep)
    args = engine._budget(args)
    try:
        for _ in range(_AUTORUN_ROUNDS):
            got = _native.call("scan_config", args, content)
            if "issues" in got:
                return engine._issues(path, got["issues"])
            for rel in got["need"]:
                files[rel] = read(rel)
        got = _native.call("scan_config", dict(args, follow=False), content)
        return engine._issues(path, got["issues"])
    except _native.NativeError as exc:
        return [engine.error_issue(path, exc)]


# ---------------- The per-line pass's findings ----------------

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
    sev = sev or install_script_severity(reasons or []) or "MAJOR"
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


def load_manifest(path, content):
    """Parse a package.json, attacker-controlled text, the way npm does:
    -> (data, issues). The data the registry's and --deps' decisions read
    (json.loads' own); the findings a manifest gets are the engine's
    (scan_manifest, scan_gyp: rust/crates/lazaret-engine/src/manifest/, which
    reads it as this does, and a .gyp file as gyp does).

    A leading UTF-8 BOM is stripped first (npm does). data is None when the
    text cannot be parsed; issues then holds SC-MANIFEST-DEPTH for a document
    nested deeper than MAX_MANIFEST_DEPTH (checked before parsing, so the
    result does not depend on the interpreter's recursion limit or on where
    a syntax error sits), or SC-MANIFEST-UNPARSEABLE when the manifest
    is at the root (a nested unreadable manifest is not a hook npm runs).
    A top level that is not an object counts as unparseable too."""
    root = is_root_manifest(path)
    if not isinstance(content, str):
        return None, ([manifest_unparseable_issue(path, "not text")] if root else [])
    text = content[1:] if content.startswith("\ufeff") else content
    if json_depth_exceeds(text):
        return None, [_sc_manifest_depth_issue(path)]
    reason = None
    try:
        data = json.loads(text, parse_int=_json_int)
    except RecursionError:              # backstop: a deep caller stack
        return None, [_sc_manifest_depth_issue(path)]
    except (ValueError, TypeError) as exc:
        data = None
        reason = (f"{type(exc).__name__}: {json_error_where(exc)}"
                  if isinstance(exc, json.JSONDecodeError) else type(exc).__name__)
    if not isinstance(data, dict):
        if data is not None:
            reason = f"top level is a {type(data).__name__}, not an object"
        return None, ([manifest_unparseable_issue(path, reason or "unparseable")] if root else [])
    return data, []


def _json_loads_manifest(path, content):
    """Backwards-compatible wrapper: (data, depth_issue). data is None on any
    parse failure; depth_issue is SC-MANIFEST-DEPTH for too-deep input.
    New code uses load_manifest, which also reports unparseable roots."""
    data, issues = load_manifest(path, content)
    depth = next((i for i in issues if i["rule"] == "SC-MANIFEST-DEPTH"), None)
    return data, depth


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
# a string array (_SA_TECHNIQUE_REASON) or JS-Confuser's string concealing
# (_JC_TECHNIQUE_REASON, D-11). Since rule set 2.17, what no client
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
    "hides its code in a string array", "hides its strings in one long string",
    "runs a program it extracts from inside another file",
    "pipes code it decodes into", "installs packages the release does not depend on",
    "rewrites another package's code", "deletes the user's files")


# ---------------- Download to a file, then run the file ----------------


def _downloads_and_runs_file(text):
    """The 1-based line where a received value is written to a file that is then
    run (the engine's downloads_and_runs), else None. MAJOR only, except in the
    Python code pip runs to install an sdist (the registry)."""
    res = _downloads_and_runs(text)
    return None if res is None else res[0]


# ---------------- Dependency drives your AI agent (SC-AGENT-HIJACK) ----------------


def _agent_hijack_issue(path, line_no, lines, agent, flag, context=False):
    """SC-AGENT-HIJACK (CRITICAL) at line `line_no` of `lines`, for the agent
    and flag agent_hijack or agent_hijack_in_command found: the engine's
    (deps.rs); `context`, the file's entropy literals redacted too."""
    answer = _native.call("agent_issue", {"agent": agent, "flag": flag, "line": line_no, "context": bool(context),
                                          "redact": bool(REDACT_SECRETS), "neumaier": False}, _lines_text(lines))
    return engine._issues(path, [answer])[0]


_ASK = object()


def dependency_agent_issue(path, text, found=_ASK):
    """SC-AGENT-HIJACK (CRITICAL) for a dependency's file that launches an AI
    agent in an autonomous mode (agent_hijack), else None. `found`: the
    engine's answer, when the caller asked for it already (a batch:
    engine.agent_hijacks)."""
    if found is _ASK:
        found = agent_hijack(text)
    if found is None:
        return None
    agent, flag, line = found
    return _agent_hijack_issue(path, line, text.split("\n"), agent, flag, context=True)


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


def _script_key_lines(text, section="scripts"):
    """{key: 1-based line of the key} for the keys of the top-level object
    `section` ("scripts", "dependencies", …) of a JSON document that parsed,
    as scan_manifest places its findings (the engine's: manifest::key_lines;
    for the tests)."""
    return _native.call("manifest_check", {"check": "key_lines", "section": section}, text)


def scan_manifest(path, content, registry=False, hooks=None):
    """Check package.json install hooks — the primary supply-chain attack
    vector — and its dependencies from an insecure source. The engine's
    (BR-7 step 3 b: rust/crates/lazaret-engine/src/manifest/, the
    `scan_manifest` call).

    G11: mere *presence* of a lifecycle script is flagged (MAJOR); a hook whose
    command does what malicious hooks do, read as a program
    (hook_command_risk, 0.1.8), escalates to CRITICAL. The command's download
    and evaluation tools (INSTALL_HOOK_RE) are only a hint in the MAJOR
    finding's message: tokens a binary installer shares. Each finding's
    `cmd` is the command, which the registry and --deps follow.

    Shared semantics 3: a leading BOM is stripped before parsing; an
    unparseable ROOT manifest is SC-MANIFEST-UNPARSEABLE (MAJOR). registry /
    dependency manifests count preinstall, install, postinstall; a project
    checkout also counts preprepare, prepare, postprepare, and there a
    prepare-family hook with neither a reason nor a hint is INFO (the
    project's own build step, e.g. `husky install`), while a hostile one
    stays CRITICAL. `hooks`: the scripts that run, when they are not npm's
    (a VS Code extension's vscode:uninstall, 0.1.9, E-1; none for a
    package.json the tool that installs it never reads for scripts).

    SC-DEP-URL (D-14): npm installs a dependency from wherever its spec says.
    One given as a plain-http URL (http:, git+http:) is fetched with no
    integrity, and one at a raw IP address names no registry and no domain
    (five of the benchmark's in-sample releases; none of the popular npm
    set's 801). A package installed from a registry is read for the fields npm
    installs from, a project's own manifest for its devDependencies too; only
    a package's root manifest counts in a registry or --deps scan, and none
    whose `hooks` are not npm's. MAJOR (WARN in the registry). `registry`
    None: a manifest under a dependency folder (DEP_MARKERS) is a
    dependency's (the engine's: collect.rs)."""
    if not isinstance(content, str):
        return load_manifest(path, content)[1]
    args = engine._budget({"path": path, "registry": None if registry is None else bool(registry),
                           "redact": bool(REDACT_SECRETS),
                           "hooks": list(hooks) if hooks is not None else None})
    try:
        return engine._issues(path, _native.call("scan_manifest", args, content)["issues"])
    except _native.NativeError as exc:
        return [engine.error_issue(path, exc)]


def dependency_url_risk(spec):
    """What makes a dependency's spec risky to fetch: ["a plain-http URL",
    "a raw IP address (HOST)"], the ones that apply; [] for none (the
    engine's: manifest::dependency_url_risk; for the tests)."""
    if not isinstance(spec, str):
        return []
    return _native.call("manifest_check", {"check": "dep_url_risk"}, spec)


#: SC-INSTALL-HOOK findings listed per gyp file; the rest are summed up in one
#: more finding at the highest severity among them.
GYP_MAX_HOOK_FINDINGS = 100


def scan_gyp(path, content):
    """G11: binding.gyp custom build actions run arbitrary commands at
    `node-gyp rebuild` (i.e. `npm install` of any native module), and its
    command expansions ('<!(cmd)', '>!(cmd)', '^!(cmd)', '<!([argv])',
    '<!pymod_do_main(module)') while node-gyp configures the build. The
    engine's (BR-7 step 3 b: rust/crates/lazaret-engine/src/manifest/gyp.rs,
    the `scan_gyp` call; the file is read as JSON or else as the Python
    literal gyp reads, single quotes, comments and trailing commas allowed).
    An action whose command looks hostile read as a program
    (hook_command_risk) is CRITICAL, any other MAJOR; an expansion is
    CRITICAL when its command looks hostile (its value is what it prints, so
    a request it prints is kept), MAJOR when it runs a download or evaluation
    tool (INSTALL_HOOK_RE: a hint), and INFO inventory when it runs a file of
    the package (`node index.js`, a pymod_do_main module): the Miasma trick,
    a payload run from binding.gyp with no install script. Such a finding's
    `cmd` is the command as it runs, so a --deps scan and the registry follow
    it to that file and escalate it to CRITICAL when the file fails the
    install-script test. The usual `<!(node -p "require('node-addon-api').include")`
    and pkg-config calls are not findings. An unparseable ROOT binding.gyp is
    SC-MANIFEST-UNPARSEABLE. At most GYP_MAX_HOOK_FINDINGS are listed, then
    one finding sums up the rest; a document past the walk's bounds is
    SC-TRUNCATED, never silently clean. Linear in the size of the file."""
    if not isinstance(content, str):
        return load_manifest(path, content)[1]
    args = engine._budget({"path": path, "redact": bool(REDACT_SECRETS)})
    try:
        return engine._issues(path, _native.call("scan_gyp", args, content)["issues"])
    except _native.NativeError as exc:
        return [engine.error_issue(path, exc)]

import stat as _stat
import traceback as _traceback

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
#     name crashed the HTML writer after the scan);
#   * every folder and file under the root is reached from the root folder's
#     descriptor a component at a time, no link followed (_Root, LZ-03): the
#     walk and every reader after it, never a path resolved again, so a tree
#     changed while it is read cannot lead a read outside the root; what the
#     walk found that is a link or no folder when opened is SC-TRUNCATED.

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
        return _read_fd(fd, limit)
    finally:
        os.close(fd)


def _read_fd(fd, limit, st=None):
    """At most `limit` bytes of the file open at `fd`, which must be a
    REGULAR file (fstat, or `st` where the caller has it; _NotRegularFile
    otherwise). The caller closes it."""
    st = os.fstat(fd) if st is None else st
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


#: Can a file be opened beneath a directory, a component at a time, no link followed (`_open_beneath`)? POSIX's
#: os.open with dir_fd, O_NOFOLLOW and O_DIRECTORY; Windows has none of them (`_open_verified` there).
_ANCHORED_OPEN = (os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and os.scandir in os.supports_fd
                  and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))
_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOCTTY", 0)
              | getattr(os, "O_CLOEXEC", 0))


class _OutsideRoot(OSError):
    """_open_beneath: what was opened is not beneath the directory it was to be found under."""


class _Unlocatable(_OutsideRoot):
    """_open_verified, _Root: this platform cannot say where a file or folder opened is, so it is not read."""


class _PathChanged(OSError):
    """_open_beneath: a directory of the path is a symbolic link now, or no directory (it changed after the path was
    resolved and checked)."""


def _open_beneath(root, path):
    """An fd (O_RDONLY) of `path`, a resolved path under the directory `root` (both as os.path.realpath gives them:
    the MCP server's path tools, LZ-03), opened beneath `root` and only there: one resolution, then an anchored open.
    `root` is opened (O_DIRECTORY | O_NOFOLLOW), then each directory of `path` below it from the one before
    (dir_fd, O_DIRECTORY | O_NOFOLLOW), and the file itself with `_OPEN_FLAGS` (O_NOFOLLOW | O_NONBLOCK: a FIFO cannot
    hang the call). A part of the path swapped for a symbolic link or a file after it was resolved makes the open fail
    (_PathChanged), and nothing outside `root` is opened, whatever the tree does meanwhile. The caller fstats the fd
    (it may be a directory or a special file) and closes it.

    Where the platform has no such open (Windows: no dir_fd, no O_NOFOLLOW): `_open_verified`. `root` None: no
    directory to stay under (`path` opened with `_OPEN_FLAGS`). FileNotFoundError for a path that is not there;
    _NotRegularFile for a special file that cannot be opened (a socket); OSError otherwise."""
    if root is None:
        return os.open(path, _OPEN_FLAGS)
    rel = os.path.relpath(path, root)
    parts = [] if rel == os.curdir else rel.split(os.sep)
    if any(p in ("", os.curdir, os.pardir) for p in parts):
        raise _OutsideRoot("it is not under the allowed root")
    if not _ANCHORED_OPEN:
        return _open_verified(root, path)
    fd = os.open(root, _DIR_FLAGS)
    if not parts:
        return fd                                   # (the root itself: a directory, which the caller's fstat says)
    try:
        for part in parts[:-1]:
            try:
                below = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise _PathChanged(exc.errno, f"{_fs_display(part)} on its path is a symbolic link or no "
                                                  f"directory now: it changed after the path was checked") from None
                raise
            os.close(fd)
            fd = below
        try:
            return os.open(parts[-1], _OPEN_FLAGS, dir_fd=fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise _PathChanged(exc.errno, "it is a symbolic link now: it changed after the path was "
                                              "checked") from None
            if exc.errno == errno.ENOTDIR:
                raise _PathChanged(exc.errno, "a directory on its path is no directory now: it changed after the "
                                              "path was checked") from None
            try:                                    # (a socket, which cannot be opened: what it is, for the message)
                mode = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False).st_mode
            except OSError:
                raise exc from None
            if not _stat.S_ISREG(mode) and not _stat.S_ISDIR(mode) and not _stat.S_ISLNK(mode):
                raise _NotRegularFile(_special_kind(mode)) from None
            raise
    finally:
        os.close(fd)


def _open_verified(root, path):
    """`_open_beneath` where a file cannot be opened beneath a directory's fd (Windows): `path` is opened (links
    followed), and kept only when the file opened is under `root` by the final path of its handle (Windows'
    GetFinalPathNameByHandleW; /proc/self/fd or F_GETPATH elsewhere): what is read is the file checked, or nothing
    (_OutsideRoot). A platform that cannot say where an opened file is reads nothing this way."""
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):            # (O_NOFOLLOW, where there is one)
            raise _PathChanged(exc.errno, "it is a symbolic link now: it changed after the path was checked") from None
        raise
    try:
        where = _opened_path(fd)
        if where is None:
            raise _Unlocatable("this platform cannot tell where the file opened is, so it is not read")
        where = os.path.normcase(where)
        try:
            inside = os.path.commonpath([where, root]) == root
        except ValueError:                          # (another drive)
            inside = False
        if not inside:
            raise _OutsideRoot("the file opened is outside the allowed root: its path changed after it was checked")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _opened_path(fd):
    """The path of the file open at `fd` as the system names it now, or None where it cannot say."""
    if os.name == "nt":
        return _windows_final_path(fd)
    if sys.platform == "darwin":
        import fcntl
        try:
            name = fcntl.fcntl(fd, 50, bytes(1024))                     # F_GETPATH (MAXPATHLEN)
        except OSError:
            return None
        return os.fsdecode(name.split(b"\0", 1)[0]) or None
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None


def _windows_final_path(fd):
    """GetFinalPathNameByHandleW of the file open at `fd` (FILE_NAME_NORMALIZED, VOLUME_NAME_DOS), without its \\\\?\\
    prefix (link_target_text: C:\\x, \\\\server\\share\\x)."""
    import msvcrt
    return _windows_handle_path(msvcrt.get_osfhandle(fd))


def _windows_handle_path(handle):
    import ctypes
    from ctypes import wintypes
    final = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    final.restype = wintypes.DWORD
    size = 1024
    while size <= 1 << 16:
        buf = ctypes.create_unicode_buffer(size)
        got = final(handle, buf, size, 0)
        if not got:
            return None
        if got < size:
            return link_target_text(buf.value)
        size = got + 1
    return None


def _windows_folder_path(path):
    """The final path of the folder `path` names, its links followed (CreateFileW with FILE_FLAG_BACKUP_SEMANTICS, which
    opens a folder; then GetFinalPathNameByHandleW), or None where it cannot be told. OSError when it cannot be
    opened."""
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                       wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    # FILE_READ_ATTRIBUTES; FILE_SHARE_READ | WRITE | DELETE; OPEN_EXISTING; FILE_FLAG_BACKUP_SEMANTICS
    handle = create(path, 0x80, 0x7, None, 3, 0x02000000, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _windows_handle_path(handle)
    finally:
        kernel32.CloseHandle(handle)


def _folder_final_path(path):
    """Where the folder `path` names is, its links followed, as the system names it now (Windows: _windows_folder_path;
    elsewhere the folder opened and asked, as _opened_path asks a file), or None where the system cannot say. OSError
    when it cannot be opened."""
    if os.name == "nt":
        return _windows_folder_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        return _opened_path(fd)
    finally:
        os.close(fd)


_ROOT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_CHANGED_WHY = ("it changed while the tree was read (a symbolic link, another file or kind of file, or nothing where "
                "the walk had found a folder or a file), so it was not read")

#: The deepest folder the walk enters, in folders below the root (LZ-03's review, H3): a folder nested deeper is not read
#: (SC-TRUNCATED, "nested deeper than 512 folders", the result incomplete). It is above anything real: a path of 512
#: folders is longer than Linux's PATH_MAX (4,096 bytes) once its names average eight characters, so a project that is
#: written, built and installed by tools that open files by path stays far below it, nested node_modules included (the
#: walk before LZ-03 stopped at PATH_MAX by accident). What it bounds is a tree made to be deep (a tarball of a few
#: kilobytes can hold thousands of levels): the walk's cost and the descriptors `_Root` keeps open on the way down.
#: The npm package's walk has the same cap, its twin (js/src/lib/collect.js MAX_WALK_DEPTH): the same findings and
#: result for a tree deeper than it whose paths the system allows (test_js_parity_core; that package reads by path,
#: and a path too long for the system is SC-TRUNCATED there, its result incomplete: TOO_LONG_WHY).
MAX_WALK_DEPTH = 512
_TOO_DEEP_WHY = f"it is nested deeper than {MAX_WALK_DEPTH} folders, so it was not read"


class _TooDeep(OSError):
    """_Root: a folder nested deeper than MAX_WALK_DEPTH below the root is not opened."""


def _file_record(st):
    """What the walk keeps of a regular file it listed (`st`, its lstat): (st_dev, st_ino, st_size, st_mtime_ns,
    st_ctime_ns). The size and times tell a file deleted and made again under its name, which can reuse its inode (ext4
    does), or written in place, from the file the walk listed (LZ-03's re-check 2, N5)."""
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _unwritten(st, then, inode_known):
    """Is `st` unwritten since `then` (st_size, st_mtime_ns, st_ctime_ns, or () where none was kept)? Its change time
    is compared only where both have an inode: a listing without one (Windows' DirEntry.stat) has a change time of its
    own making, which an fstat need not share."""
    if not then:
        return True
    size, mtime, ctime = then
    return st.st_size == size and st.st_mtime_ns == mtime and (not inode_known or st.st_ctime_ns == ctime)


def _same_file(st, expect):
    """Is `st` (an lstat or an fstat) the regular file `expect` (_file_record: as the walk's lstat gave it), unwritten
    since? Where an inode is not known (0: Windows' DirEntry.stat), its kind, size and modification time are compared."""
    if not _stat.S_ISREG(st.st_mode):
        return False
    dev, ino = expect[:2]
    known = bool(ino and st.st_ino)
    if known and (st.st_dev, st.st_ino) != (dev, ino):
        return False
    return _unwritten(st, expect[2:], known)


def _same_entry(st, rec):
    """Is `st` (an lstat) the entry `rec`, (st_dev, st_ino, its kind: S_IFMT) as the walk's listing gave them, and a
    regular file's size and times (_file_record) after them, unwritten since? Where an inode is not known (0: Windows'
    DirEntry.stat), its kind (and a regular file's size and modification time) are compared."""
    dev, ino, kind = rec[:3]
    if _stat.S_IFMT(st.st_mode) != kind:
        return False
    known = bool(ino and st.st_ino)
    if known and (st.st_dev, st.st_ino) != (dev, ino):
        return False
    return _unwritten(st, rec[3:], known)


def _name_keys(name):
    """What a disk that takes some names for one compares `name` by (LZ-03's re-check, N1): APFS's and ext4 casefold's
    reading (NFD, then case folded, on the engine's Unicode: repo.case_fold's), NTFS's (upper case), each also with
    the trailing dots and spaces Windows drops from a name."""
    out = set()
    for n in {name, name.rstrip(". ") or name}:
        try:
            out.add(("fold", engine.case_fold(n, "NFD")))
        except (ValueError, _native.NativeError):      # (a name the engine cannot read as text)
            out.add(("fold", n.lower()))
        out.add(("upper", n.upper()))
    return frozenset(out)


#: An 8.3 short name, as Windows gives one to a file on NTFS or FAT (PROGRA~1 for Program Files): a few letters, ~ and
#: a number, and at most three letters of an extension. Any name the walk listed in its folder may be the one it
#: stands for: the letters before the ~ can be a hash's, and the extension's are the long one's with spaces left out
#: and characters 8.3 cannot hold made `_` (`run.c++` is RUN~1.C__; LZ-03's re-check 2, N4).
_SHORT_NAME = re.compile(r"[^.~]{1,6}~[0-9]{1,6}(?:\.[^.]{1,3})?\Z")


class _Entry:
    """A folder's entry as `_Root.listdir` gives it: its `name` and what lstat said of it (`stat(follow_symlinks=False)`
    and `is_dir(follow_symlinks=False)`, read while the folder was open; the OSError, raised again, where it failed)."""

    __slots__ = ("name", "_st")

    def __init__(self, name, st):
        self.name, self._st = name, st

    def stat(self, follow_symlinks=False):
        if isinstance(self._st, BaseException):
            raise self._st
        return self._st

    def is_dir(self, follow_symlinks=False):
        return not isinstance(self._st, BaseException) and _stat.S_ISDIR(self._st.st_mode)


class _Root:
    """The scanned tree, read from its root folder's descriptor (LZ-03, the external security report of Oct 27,
    CWE-367): the project walk and every reader after it (the --deps and install-hook readers, the vendored-code
    readers, the pruned trees' counts, --verify-secrets' lines, the MCP server's budget count) reach a folder or a
    file under the root a component at a time from the root's descriptor (dir_fd, O_DIRECTORY | O_NOFOLLOW; a file
    O_NOFOLLOW | O_NONBLOCK), never by a path the system resolves again; nothing outside the root is opened, whatever
    the tree does meanwhile.

    What the walk found is held to what it found. A folder it found (`found`) that is a symbolic link, no folder or
    gone when it is opened again, and a regular file it listed (`files`: its device and inode) that is a link, another
    kind of file (a folder, a FIFO), another file (another inode) or gone when it is opened or looked at again
    (`open`'s fstat, `is_regular`, `listdir_after`), changed while the tree was read: the caller or this records it
    (`changed_at`), and the scan says it was not read (SC-TRUNCATED, the result incomplete), whichever reader asks (the
    walk, or one after it; LZ-03's review, H1 and H2). A reader's names are held to the walk's listing as the disk
    reads them (`_canon`; LZ-03's re-check, N1): on a disk that takes some names for one (macOS's and Windows' ignore
    case and Unicode form, Windows knows a file by an 8.3 name too), a package's text can name a file the walk listed
    by another spelling, which the disk opens; such a name is the walk's entry it reaches, by identity, and a name
    that reaches something the walk did not list there, or nothing where the walk listed one it is one name with, is
    a change. What the walk did not find (a file a hook names that was not there) is looked at as it is then. A file
    that cannot be opened and is still the file the walk listed (permission denied) is unreadable, as before. A
    folder deeper than MAX_WALK_DEPTH is not opened (_TooDeep; the walk records it in `too_deep`).

    `path` is the root as given (what is shown, and joined to where there is no such open); `fd` an open folder
    descriptor of it (the MCP server's, opened beneath its allowed root: `own` says whether this closes it), else the
    root is opened here, a link in its own path followed (the command line's folder may be one). Folders are kept
    open so that reaching one costs a bounded number of opens whatever the tree's shape (LZ-03's review, H3: a deep
    "comb" cost N²/2 opens): the `_KEEP` used last, and every `_STRIDE`-th on the way to the last one opened (`_spine`),
    so a folder is opened from one at most `_STRIDE` levels above it, and at most MAX_WALK_DEPTH / _STRIDE + _KEEP
    (48) are open besides the root's. A folder is opened afresh from its parent when it is listed, and the walk lets
    the kept ones go when it is done (`forget`), so the readers after it reach each folder by the name it has then. A
    kept folder that is renamed meanwhile, even out of the root, is still the one read through its descriptor, and
    only what is in it is reached (no link below it is followed): nothing that was not under the root when it was
    opened, unless something is put into it after it left.

    Where the platform has no such open (Windows: no dir_fd, no scandir of a descriptor), the tree is read by path,
    and checked: every folder is lstat'ed (a link or a file where a folder was is _PathChanged) and listed only when
    its final path, its links followed (CreateFileW with FILE_FLAG_BACKUP_SEMANTICS, GetFinalPathNameByHandleW), is
    under `within` (the root's real path); every file is opened and read only when its handle's final path is
    (_open_verified), so no file outside the root is read. A folder swapped between that check and its listing can
    still show its names there (not its files' contents): the gap docs/DESIGN.md states."""

    _KEEP = 16
    _STRIDE = 16

    def __init__(self, path, fd=None, own=None, within=None):
        self.path = os.fspath(path)
        self.changed = []                   # the display paths of what changed while the tree was read
        self.too_deep = []                  # the display paths of the folders the walk did not enter (MAX_WALK_DEPTH)
        self.found = set()                  # the folders the walk found (names): one no folder later changed
        self.files = {}                     # folder (names) -> {name: _file_record}: the regular files it listed
        self.names = {}                     # folder (names) -> {name: (st_dev, st_ino, kind[, size, mtime, ctime]) or
        #                                     None}: all it listed (a regular file's size and times after its kind)
        self._keys = {}                     # folder (names) -> {name: _name_keys(name)}, made when first asked
        self._dirs = collections.OrderedDict()
        self._spine = []                    # [(depth, names, fd)]: every _STRIDE-th folder on the way to the last one
        self._own = fd is None if own is None else own
        self.fd = self.within = None
        if _ANCHORED_OPEN:
            self.fd = os.open(self.path, _ROOT_FLAGS) if fd is None else fd
            return
        # (`within` as the caller resolved it when it checked it: never resolved again here)
        self.within = os.path.normcase(os.path.realpath(self.path) if within is None else within)
        if within is not None:
            where = _folder_final_path(self.path)
            if where is None:
                raise _Unlocatable("this platform cannot tell where the folder is, so it is not read")
            if os.path.normcase(where) != self.within:
                raise _PathChanged(errno.ELOOP, "the folder changed after it was checked")

    def forget(self):
        """Let the folders kept open go: what is read next is reached from the root again, by the names it has now."""
        for fd in self._dirs.values():
            os.close(fd)
        self._dirs.clear()
        for _depth, _names, fd in self._spine:
            os.close(fd)
        self._spine.clear()

    def close(self):
        self.forget()
        if self._own and self.fd is not None:
            os.close(self.fd)
        self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:                   # (interpreter shutdown)
            pass

    @staticmethod
    def parts(rel):
        """A root-relative path ('/'- or os.sep-separated) as a tuple of names; ValueError for one that leaves the root."""
        rel = os.fspath(rel)
        names = tuple(p for p in (rel.replace("/", os.sep) if os.sep != "/" else rel).split(os.sep) if p not in ("", "."))
        if any(p == ".." for p in names) or (os.name == "nt" and any(":" in p for p in names)):
            raise ValueError(f"not a path under the root: {rel!r}")
        return names

    def changed_at(self, rel):
        """Record that `rel` (a display path, or names) changed while it was read: it is reported not read."""
        self.changed.append(_fs_display(os.path.join(*rel) if isinstance(rel, tuple) else rel))

    def listed(self, parts, entries):
        """The walk listed the folder `parts` ([_Entry]): the regular files in it are what it found there, and its
        names those a reader's names in it are held to (_canon)."""
        files, names = {}, {}
        for e in entries:
            try:
                st = e.stat()
            except OSError:
                names[e.name] = None
                continue
            names[e.name] = (st.st_dev, st.st_ino, _stat.S_IFMT(st.st_mode))
            if _stat.S_ISREG(st.st_mode):
                files[e.name] = rec = _file_record(st)
                names[e.name] += rec[2:]
        self.files[tuple(parts)] = files
        self.names[tuple(parts)] = names

    def _walked(self, parts):
        """The _file_record of the regular file the walk listed at `parts` (names as it listed them: _canon), or
        None."""
        return self.files.get(parts[:-1], {}).get(parts[-1]) if parts else None

    def _canon(self, parts):
        """A reader's names `parts` (from a package's text: a hook's command, vendor/modules.txt, an agent skill) as
        the walk listed them, so that what it reads is held to what the walk found (LZ-03's re-check, N1). A name not
        in the walk's listing of its folder is looked up (_alias); the names below a folder the walk did not list are
        kept as they are. _PathChanged (recorded) where the tree changed."""
        out = ()
        for k, name in enumerate(parts):
            listing = self.names.get(out)
            if listing is None:
                return out + parts[k:]
            if name not in listing:
                name = self._alias(out, name, listing, parts)
                if name is None:
                    return out + parts[k:]
            out += (name,)
        return out

    def _alias(self, folder, name, listing, whole):
        """The name the walk listed in `folder` that `name`, not among them, reaches on this disk, or None where it
        reaches nothing and reached nothing when the walk listed the folder. What it reaches is held to the walk's
        entries by identity (device and inode; where the walk's listing has none, Windows', by the entry it is one name
        with, as it is now). It reaches something the walk did not list there (another file, a link, a folder put in
        the entry's place or beside it), or nothing where the walk listed a name it is one with (_like: in case,
        Unicode form, Windows' trailing dots and spaces, an 8.3 name) while one of those is gone or another now, or
        the folder changed while this looked: the tree changed. That is recorded (`whole`, the reader's names, to
        this one: once for every path a reader asks below it) and _PathChanged."""
        where = self._dir(folder)
        like = self._like(folder, name, listing)
        before = self._stamp(where) if like else None
        try:
            st = self._lstat_in(where, name)
        except FileNotFoundError:
            st = None
        if st is not None:
            got = self._entry_of(where, st, listing, like)
            # (LZ-03's re-check 2, N3: the entry it reaches must be one the disk could take the name for, or, where
            # no listed name is (a folding this does not model), still the walk's entry under the walk's own name)
            if got is not None and (got in like or (not like and self._still_entry(where, got, listing[got]))):
                return got
        elif not like:
            return None
        else:
            for n in like:                  # (a disk that tells them apart: each still the entry the walk listed,
                try:                        # and the folder unchanged meanwhile: its times, which every entry made,
                    now = self._lstat_in(where, n)      # renamed or removed in it changes)
                except OSError:
                    break
                if listing[n] is not None and not _same_entry(now, listing[n]):
                    break
            else:
                if self._stamp(where) == before:
                    return None
        self.changed_at(whole[:len(folder) + 1])
        raise _PathChanged(errno.ESTALE, "it is not what the walk found there now")

    def _entry_of(self, where, st, listing, like):
        """The name of the walk's entry that `st` (the lstat of what a name not in `listing` reaches) is, or None."""
        if st.st_ino and any(rec and rec[1] for rec in listing.values()):
            hits = [n for n, rec in listing.items() if rec and rec[1] and _same_entry(st, rec)]
            return min(hits, key=lambda n: (n not in like, n)) if hits else None   # (hard links: one file)
        hits = []                           # (Windows: the entry it is one name with, by identity as it is now)
        for n in like:
            try:
                now = self._lstat_in(where, n)
            except OSError:
                continue
            if listing[n] is not None and _same_entry(now, listing[n]) and \
                    _same_entry(st, (now.st_dev, now.st_ino, _stat.S_IFMT(now.st_mode))):
                hits.append(n)
        return hits[0] if len(hits) == 1 else None

    def _still_entry(self, where, name, rec):
        """Is the walk's `name` in the folder `where` still its entry `rec`?"""
        try:
            return rec is not None and _same_entry(self._lstat_in(where, name), rec)
        except OSError:
            return False

    def _like(self, folder, name, listing):
        """The names the walk listed in `folder` that a disk could take `name` for (_name_keys; for a name shaped as
        an 8.3 short name, any: Windows makes a short name's extension from the long one's with characters left out
        or replaced, LZ-03's re-check 2, N4)."""
        keys = self._keys.get(folder)
        if keys is None:
            keys = self._keys[folder] = {n: _name_keys(n) for n in listing}
        if _SHORT_NAME.match(name.upper()):
            return sorted(keys)
        want = _name_keys(name)
        return sorted(n for n, k in keys.items() if k & want)

    @staticmethod
    def _stamp(where):
        st = os.fstat(where) if _ANCHORED_OPEN else os.lstat(where)
        return st.st_mtime_ns, st.st_ctime_ns

    @staticmethod
    def _lstat_in(where, name):
        if not _ANCHORED_OPEN:
            return os.lstat(os.path.join(where, name))
        return os.stat(name, dir_fd=where, follow_symlinks=False)

    def _keep(self, parts, fd):
        old = self._dirs.pop(parts, None)
        if old is not None and old != fd:
            os.close(old)
        self._dirs[parts] = fd
        while len(self._dirs) > self._KEEP:
            os.close(self._dirs.popitem(last=False)[1])

    def _dir(self, parts, fresh=False):
        """The folder `parts` below the root: a descriptor (kept: the caller does not close it), or its path where there
        is no anchored open. `fresh`: opened again from its parent even where it is kept (what is listed is the folder
        its name names now). _PathChanged when a component is a link or no folder now, or a folder the walk found is
        gone; _TooDeep for a folder deeper than MAX_WALK_DEPTH. It is opened from the deepest folder kept on its way
        (the spine's, or one of the last used within _STRIDE levels of it), each folder below opened from the one before
        and kept in turn (every _STRIDE-th on the spine, the others with the last used)."""
        if len(parts) > MAX_WALK_DEPTH:
            raise _TooDeep(errno.ENAMETOOLONG, f"it is nested deeper than {MAX_WALK_DEPTH} folders")
        if not _ANCHORED_OPEN:
            path = os.path.join(self.path, *parts)
            for n in range(1, len(parts) + 1):     # (each folder on the way: no link followed, as beneath an fd)
                try:
                    st = os.lstat(os.path.join(self.path, *parts[:n]))
                except FileNotFoundError:
                    if parts[:n] not in self.found:
                        raise
                    self._lost(parts[:n])
                    raise _PathChanged(errno.ENOENT, f"{_fs_display(os.path.join(*parts[:n]))} is gone now") from None
                if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st) or not _stat.S_ISDIR(st.st_mode):
                    self._lost(parts[:n])
                    raise _PathChanged(errno.ENOTDIR, f"{_fs_display(os.path.join(*parts[:n]))} is a symbolic link "
                                                      f"or no folder now")
            where = _folder_final_path(path)
            if where is None:
                raise _Unlocatable("this platform cannot tell where the folder is, so it is not read")
            where = os.path.normcase(where)
            try:
                inside = os.path.commonpath([where, self.within]) == self.within
            except ValueError:
                inside = False
            if not inside:
                self._lost(parts, below=True)
                raise _PathChanged(errno.ELOOP, "the folder is outside the root now: it changed while it was read")
            return path
        if not parts:
            return self.fd
        if fresh:
            old = self._dirs.pop(parts, None)
            if old is not None:
                os.close(old)
        else:
            fd = self._dirs.get(parts)
            if fd is not None:
                self._dirs.move_to_end(parts)
                return fd
        n, spine = len(parts), self._spine
        while spine:                        # (the spine's folders on the way to `parts` stay; the others are let go)
            depth, names, fd = spine[-1]
            if (depth < n or (depth == n and not fresh)) and parts[:depth] == names:
                break
            spine.pop()
            os.close(fd)
        if spine and spine[-1][0] == n:
            return spine[-1][2]
        start, k = (spine[-1][2], spine[-1][0]) if spine else (self.fd, 0)
        for m in range(n - 1, max(k, n - 1 - self._STRIDE), -1):
            fd = self._dirs.get(parts[:m])
            if fd is not None:
                self._dirs.move_to_end(parts[:m])
                start, k = fd, m
                break
        fd, at = start, k
        try:
            for part in parts[k:]:
                at += 1
                fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
                if at % self._STRIDE == 0:
                    spine.append((at, parts[:at], fd))
                else:
                    self._keep(parts[:at], fd)
        except OSError as exc:
            gone = exc.errno == errno.ENOENT and parts[:at] in self.found
            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK) or gone:
                self._lost(parts[:at])
                raise _PathChanged(exc.errno, f"{_fs_display(os.path.join(*parts[:at]))} is "
                                              f"{'gone' if gone else 'a symbolic link or no folder'} now") from None
            raise
        return fd

    def _lost(self, parts, below=False):
        """The folder `parts` is a link, no folder or gone (beneath the root) now: where the walk found a folder there,
        it changed while the tree was read, whichever reader asks (recorded: SC-TRUNCATED). `below`: one of the folders
        on its way changed, which one unknown (the deepest the walk found is recorded)."""
        for n in range(len(parts), 0, -1) if below else (len(parts),):
            if parts[:n] in self.found:
                self.changed_at(parts[:n])
                return

    def listdir(self, parts=()):
        """[_Entry] of the folder `parts`, each lstat'ed while it is open. The folder itself is opened afresh (a
        descriptor of it kept from before is let go): what is listed is the folder its name names now, and a folder
        that is a link or no folder now is _PathChanged."""
        parts = tuple(parts)
        where = self._dir(parts, fresh=True)
        out = []
        with os.scandir(where) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError as exc:
                    st = exc
                out.append(_Entry(e.name, st))
        return out

    def listdir_after(self, parts):
        """listdir, for a reader after the walk: a regular file the walk listed in that folder that is gone from it,
        or another file or kind of file now, changed while the tree was read (recorded)."""
        parts = self._canon(tuple(parts))
        entries = self.listdir(parts)
        listed = self.files.get(parts)
        if listed:
            now = {e.name: e for e in entries}
            for name, expect in listed.items():
                e = now.get(name)
                try:
                    same = e is not None and _same_file(e.stat(), expect)
                except OSError:
                    same = False
                if not same:
                    self.changed_at(parts + (name,))
        return entries

    def lstat(self, parts):
        """lstat of `parts` (the root's own for ())."""
        parts = tuple(parts)
        if not parts:
            return os.fstat(self.fd) if _ANCHORED_OPEN else os.stat(self.path)
        where = self._dir(parts[:-1])
        if not _ANCHORED_OPEN:
            return os.lstat(os.path.join(where, parts[-1]))
        return os.stat(parts[-1], dir_fd=where, follow_symlinks=False)

    def is_regular(self, parts):
        """Is `parts` a regular file now (lstat; no link followed on the way)? A regular file the walk listed there
        that is gone, a link, another kind of file or another file now changed while the tree was read: recorded, and
        False (a folder on its way that changed is recorded by `_dir`)."""
        try:
            parts = self._canon(tuple(parts))
        except (OSError, ValueError):       # (_PathChanged: recorded)
            return False
        expect = self._walked(parts)
        try:
            st = self.lstat(parts)
        except _PathChanged:
            return False
        except FileNotFoundError:
            if expect is not None:
                self.changed_at(parts)
            return False
        except (OSError, ValueError):       # (ValueError: a NUL in the name)
            return False
        if expect is not None and not _same_file(st, expect):
            self.changed_at(parts)
            return False
        return _stat.S_ISREG(st.st_mode) and not _is_reparse_point(st)

    def readlink(self, parts):
        parts = tuple(parts)
        where = self._dir(parts[:-1])
        if not _ANCHORED_OPEN:
            return os.readlink(os.path.join(where, parts[-1]))
        return os.readlink(parts[-1], dir_fd=where)

    def open(self, parts, expect=None):
        """A descriptor of the file `parts` (O_NOFOLLOW | O_NONBLOCK); the caller closes it. _PathChanged when it, or a
        folder on its way, is a link or no folder now. (Without an anchored open, the file is kept only when the final
        path of what was opened is under the root, which bounds it whatever its folders are now: _open_verified. A
        file is opened only where the walk, or a reader's lstat of every folder on its way, found it.)

        `expect`: the regular file it must be, a _file_record or the lstat of it the walk made; without one, the file
        the walk listed there, if it did. The descriptor's fstat must be that file: another kind of file (a folder, a
        FIFO), another file or nothing there now is _PathChanged (LZ-03's review, H2); an open that fails otherwise
        (permission denied) is raised as it is only while the entry is still that file."""
        return self._opened(parts, expect)[0]

    def _opened(self, parts, expect):
        """(open's descriptor, its fstat where it was taken, else None)."""
        parts = tuple(parts)
        if expect is None:
            parts = self._canon(parts)
            expect = self._walked(parts)
        elif isinstance(expect, os.stat_result):
            expect = _file_record(expect)
        try:
            fd = self._open(parts)
        except _PathChanged:
            raise
        except OSError:
            if expect is not None:
                self._still(parts, expect)
            raise
        if expect is None:
            return fd, None
        try:
            st = os.fstat(fd)
        except BaseException:
            os.close(fd)
            raise
        if not _same_file(st, expect):
            os.close(fd)
            raise _PathChanged(errno.ESTALE, "it is another file or kind of file now")
        return fd, st

    def _still(self, parts, expect):
        """_PathChanged unless `parts` is still the regular file `expect` (by lstat; nothing said where that fails)."""
        try:
            st = self.lstat(parts)
        except _PathChanged:
            raise
        except FileNotFoundError:
            raise _PathChanged(errno.ENOENT, "it is gone now") from None
        except OSError:
            return
        if not _same_file(st, expect):
            raise _PathChanged(errno.ESTALE, "it is another file or kind of file now")

    def _open(self, parts):
        if not _ANCHORED_OPEN:
            try:
                return _open_verified(self.within, os.path.join(self.path, *parts))
            except _Unlocatable:
                raise
            except _OutsideRoot:            # (a file the walk found under the root: it changed)
                raise _PathChanged(errno.ELOOP, "it is outside the root now: it changed while it was read") from None
        where = self._dir(parts[:-1])
        try:
            return os.open(parts[-1], _OPEN_FLAGS, dir_fd=where)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise _PathChanged(exc.errno, "it is a symbolic link now") from None
            raise

    def read(self, parts, limit, expect=None):
        """At most `limit` bytes of the regular file `parts` (_read_prefix's reading, from the root's descriptor; held
        to `expect`, or to what the walk listed there, as `open` says)."""
        fd, st = self._opened(parts, expect)
        try:
            return _read_fd(fd, limit, st)
        finally:
            os.close(fd)


def _as_root(root):
    """(a _Root for `root`, whether the caller opened it and closes it): `root` itself when it is one."""
    return (root, False) if isinstance(root, _Root) else (_Root(root), True)


def changed_issues(tree):
    """SC-TRUNCATED for each part of the tree that changed while it was read (`_Root.changed`), once each, and for each
    folder the walk did not enter, nested deeper than MAX_WALK_DEPTH (`_Root.too_deep`)."""
    return [truncated_issue(rel, _CHANGED_WHY) for rel in dict.fromkeys(tree.changed)] + \
        [truncated_issue(rel, _TOO_DEEP_WHY) for rel in dict.fromkeys(tree.too_deep)]


def tree_incomplete(tree):
    """Why a scan of `tree` is incomplete for what changed while it was read or was nested too deep: [reason]."""
    out = []
    changed, deep = len(dict.fromkeys(tree.changed)), len(dict.fromkeys(tree.too_deep))
    if changed:
        out.append(f"{changed} part{'s' if changed != 1 else ''} of the tree changed while it was read and "
                   f"{'were' if changed != 1 else 'was'} not read")
    if deep:
        out.append(f"{deep} folder{'s' if deep != 1 else ''} nested deeper than {MAX_WALK_DEPTH} folders "
                   f"{'were' if deep != 1 else 'was'} not read")
    return out


def _read_sibling(path, name, limit):
    """FP-GRADLE-WRAPPER: the first `limit` bytes of the regular file `name` beside `path` (a Gradle wrapper jar's
    gradle-wrapper.properties; the engine asks one byte more than it reads, so that a longer file is told) as latin-1
    text, False when there is no such regular file, or {error} (a symbolic link among them: Java follows it, the scan
    does not, and the engine judges the jar as one whose properties were not read). `path`: a path, or (a _Root, the
    file's names), the file beside it read from the root's descriptor as the walk's other readers read (LZ-03)."""
    try:
        data = (path[0].read(path[1][:-1] + (name,), limit) if isinstance(path, tuple)
                else _read_prefix(os.path.join(os.path.dirname(path), name), limit))
        return _bytes_text(data)
    except (_NotRegularFile, FileNotFoundError, NotADirectoryError):
        return False
    except OSError as exc:
        return {"error": exc.strerror or type(exc).__name__}


def collect_issue(kind, path, **args):
    """A coverage note the collection's I/O finds, the engine's (collect.rs): "unreadable" (reason), "symlink"
    (target) or "skipped_tree" (files, bytes)."""
    return engine._issues(path, [_native.call("collect_issue", dict(args, kind=kind, path=path))])[0]


def symlink_issue(path, target):
    """Q-SYMLINK: a symbolic link inside the tree (never followed)."""
    return collect_issue("symlink", path, target=str(target))


def unreadable_issue(path, reason):
    """Q-UNREADABLE: an entry that could not be read (permissions, special file)."""
    return collect_issue("unreadable", path, reason=str(reason))


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


def pth_issues(path, text):
    """SC-PTH-EXEC: site.py executes every line of a .pth file in
    site-packages that starts with 'import' at EVERY interpreter start — no
    import of the package needed. CRITICAL when the line's code executes or
    decodes a payload, or does what the install-script and import-time tests
    look for (the engine's pth_line_risk, which reads `exec('…')` of a plain
    literal as the literal's code: coverage's a1_coverage.pth); MAJOR
    otherwise (setuptools' distutils shim and namespace .pth files are this
    shape: listed for review). The registry's check (lazaret.registry.repo)
    and the project walk share it; the engine reads the file (BR-7 step 3 d:
    binary.rs), for the npm package's walk too.

    Lines are taken both ways site.py splits them: at \\n, \\r and \\r\\n
    (iterating the file: 3.10, 3.11, early 3.12 releases), and with
    str.splitlines() (3.13+ and recent 3.12 releases), which also breaks at
    \\v, \\f, \\x1c-\\x1e, \\x85, U+2028 and U+2029 — review: `# path
    notes\\fimport sys; …` gave no finding while python3.13 ran its import.
    A finding is reported at the physical (\\n) line holding the statement,
    once per line."""
    return engine._issues(path, _native.call("pth_issues", {"redact": bool(REDACT_SECRETS), "neumaier": False}, text))


#: A .pth file too large to read whole is read this many bytes at a time (pth_stream).
PTH_CHUNK = 1 << 20


def pth_stream(state, chunk, end):
    """The next chunk of a .pth file too large to read whole (FP-MODEL-FILES, John's decision of Oct 21: a 200 MB
    `model.pth` checkpoint is judged by the lines site.py runs, streamed): `state` None at its start, else the last
    answer's; `end` with its last (an empty chunk at its end will do) -> {"state", "lines": [[line, its bytes from
    its first import start, latin-1]], "cuts": [why a line could not be kept: SC-TRUNCATED]}. Byte-wise, whatever the
    decoding: a line starting "import " or "import\t", or a part of one str.splitlines() splits off, as pth_issues
    reads them; at most PTH_MAX_LINE bytes a line and PTH_MAX_KEPT in all. The engine's (binary::pth_stream)."""
    return _native.call("pth_stream", {"state": state, "end": bool(end)}, _bytes_text(bytes(chunk)))


def pth_stream_file(read):
    """{"lines", "cuts"} of a .pth file read to its end through `read()` (its next bytes, b"" at its end),
    PTH_CHUNK at a time (pth_stream)."""
    state, lines, cuts = None, [], []
    while True:
        chunk = read()
        got = pth_stream(state, chunk, not chunk)
        state = got["state"]
        lines += got["lines"]
        cuts += got["cuts"]
        if not chunk:
            return {"lines": lines, "cuts": cuts}


def pth_kept_issues(path, lines):
    """pth_issues for the lines pth_stream kept ([[line, latin-1 text]]), at their lines. The engine's
    (binary::pth_kept_issues)."""
    if not lines:
        return []
    return engine._issues(path, _native.call("pth_kept", {"lines": lines, "redact": bool(REDACT_SECRETS),
                                                          "neumaier": False}))


def pyc_issues(path, header, has_source):
    """SC-PYC-UNCHECKED / SC-PYC-ORPHAN for one .pyc in a __pycache__ dir.
    `header` is at least the first 8 bytes; `has_source` whether the
    matching <module>.py sits next to the __pycache__ directory. The
    engine's (BR-7 step 3 d: binary.rs)."""
    return engine._issues(path, _native.call("pyc_issues", {"path": path, "has_source": bool(has_source)},
                                             _bytes_text(bytes(header[:16]))))


def decode_source(data, lang=None):
    """Decode the bytes of a source file the way its interpreter would read
    them. Returns (text, info):

      info = {"encoding": codec label, "reported": bool (-> Q-ENCODING),
              "utf7": bool (-> SC-UTF7), "cookieLine": n or None,
              "escapes": True for an escape codec (-> SC-ESCAPE-CODEC),
              "undecoded": True when the codec is not decoded (-> SC-TRUNCATED)}

    The engine's (BR-7 step 4 b: decode/). FIX-SPEC 4 (BOM / NUL sniff)
    first, a BOM-less UTF-16 guess kept only when it reads as text; for
    Python source without a BOM or NUL, FIX-SPEC 15: a PEP 263 cookie naming
    a codec other than UTF-8 decodes with that codec (Q-ENCODING), as Python
    decodes it, for every text codec Python has (the CJK and ISO-2022 codecs
    included); UTF-7 additionally sets utf7 (a UTF-7 '+AAo-' is a newline,
    so code can hide inside a comment), and so do the escape codecs
    ('\\u000a'). An unknown codec decodes as UTF-8 with replacement, and so do
    idna, punycode and undefined, and an escape codec's file Python would
    not read or that uses \\N{name} (undecoded: the file is not fully
    scanned). Never raises on content. Line endings are normalized to \\n, as
    text mode reads them, and a surrogate code point the codec leaves (UTF-7
    '+2AA-', unicode_escape '\\udc80') becomes U+FFFD."""
    got = _native.call("decode_source", {"lang": lang} if lang else {}, _bytes_text(data))
    return got["text"], got["info"]


def encoding_issues(path, text, info):
    """Q-ENCODING, SC-UTF7 and SC-ESCAPE-CODEC for a decoded source file (and
    SC-TRUNCATED for a codec not decoded), from decode_source's text and
    info. Their snippets are redacted with the file's own entropy literals
    and PEM blocks, as scan_file's are. The engine's (decode/mod.rs)."""
    if not info["reported"]:
        return []
    return engine._issues(path, _native.call("encoding_issues", {"info": info, "redact": bool(REDACT_SECRETS)}, text))


def _dep_arg(in_dep):
    """The walk's dependency tree as the engine reads it: false, true, or a Go or cargo vendor tree's [kind, path]."""
    if isinstance(in_dep, tuple):
        return [in_dep[0], _fs_display(in_dep[1])]
    return bool(in_dep)


def _dep_of(value, rel):
    """A folder's dependency tree as the engine names it, as the walk keeps it: a vendor tree its kind and its path
    (`rel`, the folder's)."""
    return (value[0], rel) if isinstance(value, list) else bool(value)


def _regular(path):
    try:
        return _stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _listing(path):
    """[[name, is a folder]] of a folder's entries (no link followed), or None when it cannot be listed."""
    try:
        with os.scandir(path) as it:
            return [[_fs_display(e.name), e.is_dir(follow_symlinks=False)] for e in it]
    except OSError:
        return None


def _listing_at(tree, parts):
    """_listing of the folder `parts` of a _Root (a probe: None when it cannot be listed, a link now among them)."""
    try:
        return [[_fs_display(e.name), e.is_dir(follow_symlinks=False)] for e in tree.listdir(parts)]
    except OSError:
        return None


def _regular_at(tree, parts):
    try:
        return _stat.S_ISREG(tree.lstat(parts).st_mode)
    except (OSError, ValueError):
        return False


def _dir_plan(rel_dir, in_dep, listed, paths, excludes, include_deps):
    """collect_dir until it needs nothing more: the probes of the folders it asks about (their entries; a vendor
    folder's .cargo-checksum.json files). `paths[k]`: entry k's path, or (a _Root, its names) (LZ-03)."""
    answers = {"lists": [], "cargo": []}
    while True:
        got = _native.call("collect_dir", {"dir": _fs_display(rel_dir), "dep": _dep_arg(in_dep), "entries": listed,
                                           "excludes": excludes, "includeDeps": bool(include_deps),
                                           "windows": _WINDOWS_PATHS, "answers": answers})
        need = got.get("need")
        if need is None:
            return got
        for k in need["lists"]:
            at = paths[k]
            answers["lists"].append([k, _listing_at(*at) if isinstance(at, tuple) else _listing(at)])
        for k, dirs in need["cargo"]:
            at = paths[k]
            answers["cargo"].append([k, [d for d in dirs
                                         if (_regular_at(at[0], at[1] + (d, ".cargo-checksum.json"))
                                             if isinstance(at, tuple)
                                             else _regular(os.path.join(at, d, ".cargo-checksum.json")))]])


def _dep_tree_kind(name, path):
    """True when directory `name` at `path` is a dependency tree: always for
    node_modules / bower_components / site-packages; for vendor / venv /
    .venv / env only when a marker sits directly inside; "go" or "cargo" for a
    vendor directory of Go's or cargo's (the engine's: collect.rs). `path` may
    be (a _Root, the folder's names) (LZ-03)."""
    got = _dir_plan("", False, [[_fs_display(name), "dir", None, False]], [path], [], True)
    for _k, action, extra in got["do"]:
        if action == "walk":
            dep = extra[1]
            return dep[0] if isinstance(dep, list) else dep
    return False


_SPECIAL_CODES = ((_stat.S_ISFIFO, "fifo"), (_stat.S_ISSOCK, "socket"), (_stat.S_ISCHR, "char"),
                  (_stat.S_ISBLK, "block"))


def _check_pycache(rel_dir, path, parent_names, out):
    """__pycache__ is not source-scanned; every .pyc directly inside is
    checked (PEP 552 flags, matching source; the engine's: collect.rs).
    Symlinks -> Q-SYMLINK. `path`: (a _Root, the folder's names): read from
    the root's descriptor (LZ-03); a folder or a .pyc that changed while it
    was read is recorded (_Root.changed_at) and not read."""
    tree, parts = path
    try:
        entries = tree.listdir(parts)
    except _PathChanged:
        tree.changed_at(rel_dir)
        return
    except OSError as exc:
        out.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
        return
    listed, paths = [], {}
    for e in entries:
        name = _fs_display(e.name)
        try:
            st = e.stat(follow_symlinks=False)
        except OSError as exc:
            listed.append([name, "error", exc.strerror or type(exc).__name__])
            continue
        if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
            listed.append([name, "link", _readlink((tree, parts + (e.name,)))])
        elif _stat.S_ISREG(st.st_mode):
            listed.append([name, "file", st.st_size])
            paths[name] = (parts + (e.name,), st)
        else:
            listed.append([name, "special", "other"])
    headers = {}
    while True:
        got = _native.call("collect_pycache", {"dir": _fs_display(rel_dir), "entries": listed,
                                               "parent": sorted(_fs_display(n) for n in parent_names),
                                               "windows": _WINDOWS_PATHS, "answers": {"headers": headers}})
        if "need" not in got:
            break
        for name in got["need"]:
            try:
                headers[name] = _bytes_text(tree.read(paths[name][0], 16, expect=paths[name][1]))
            except _PathChanged as exc:
                tree.changed_at(paths[name][0])
                headers[name] = {"error": exc.strerror or str(exc)}
            except OSError as exc:
                headers[name] = {"error": exc.strerror or str(exc) or type(exc).__name__}
    out.extend(engine._issues(path, [row])[0] for path, row in got["issues"])


def _readlink(path):
    try:
        target = path[0].readlink(path[1]) if isinstance(path, tuple) else os.readlink(path)
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


def _open_regular(path, expect=None):
    """A descriptor of the REGULAR file `path` (O_NOFOLLOW | O_NONBLOCK; the caller closes it), as _read_prefix opens
    one: `path` a path, or (a _Root, the file's names), opened from the root's descriptor and held to `expect` as
    _Root.open holds it (LZ-03). Raises OSError (incl. _NotRegularFile, _PathChanged)."""
    fd = path[0].open(path[1], expect) if isinstance(path, tuple) else os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise _NotRegularFile(f"{_special_kind(st.st_mode)}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_ranges(path, ranges, expect=None):
    """[(offset, bytes)] of the REGULAR file `path` for [[offset, length]] (fewer bytes where it is shorter), read
    as _read_prefix reads (no symlink followed, no FIFO blocked on; a _Root's file from its descriptor, held to
    `expect`: _open_regular). Raises OSError (incl. _NotRegularFile, _PathChanged)."""
    fd = _open_regular(path, expect)
    try:
        out = []
        for off, length in ranges:
            os.lseek(fd, off, os.SEEK_SET)           # (lseek and read: os.pread is not Windows')
            chunks, remaining = [], length
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            out.append((off, b"".join(chunks)))
        return out
    finally:
        os.close(fd)


def _stream_pth(path, expect=None):
    """pth_stream_file for the REGULAR file `path`, read as _read_prefix reads one (_open_regular). Raises OSError
    (incl. _NotRegularFile, _PathChanged)."""
    fd = _open_regular(path, expect)
    try:
        return pth_stream_file(lambda: os.read(fd, PTH_CHUNK))
    finally:
        os.close(fd)


def _stream_media(path, expect=None):
    """media_stream_file for the REGULAR file `path`, read as _read_prefix reads one (_open_regular; FP-OPAQUE-MEDIA:
    a file too large to read whole, walked by its structure). Raises OSError (incl. _NotRegularFile, _PathChanged)."""
    fd = _open_regular(path, expect)
    try:
        st = os.fstat(fd)

        def read_at(offset, n):
            os.lseek(fd, offset, os.SEEK_SET)          # (lseek and read: os.pread is not Windows')
            return os.read(fd, n)
        return media_stream_file(read_at, st.st_size)
    finally:
        os.close(fd)


def _collect_file(path, rel, st, in_dep, col):
    """Classify and read one regular file (the engine's decisions: collect.rs, collect_file, asked again with what
    it needs read; a zip model file's ranges, read by range: FP-MODEL-FILES). `path`: (a _Root, the file's names), read
    from the root's descriptor (LZ-03) and held to `st`, the walk's lstat of it: _PathChanged (the file is a link,
    another kind of file, another file or gone now, or a folder on its way is a link or no folder) is the caller's to
    record, and nothing of it is kept."""
    disp = _fs_display(rel)
    args = {"rel": disp, "name": _fs_display(os.path.basename(rel)), "size": st.st_size, "dep": _dep_arg(in_dep),
            "cap": SOURCE_SIZE_CAP, "configCap": configsecrets.CONFIG_SCAN_CAP, "windows": _WINDOWS_PATHS,
            "neumaier": False, "redact": bool(REDACT_SECRETS), "ranges": True}
    answers, text, pieces = {}, "", []
    while True:
        got = _native.call("collect_file", dict(args, answers=answers), text)
        need = got.get("need")
        if need is None:
            break
        what = need["read"]
        if what in ("pth", "media"):             # (a file too large to read whole, in chunks: a .pth file's lines
            try:                                 # pth_stream, another's structure media_stream)
                answers[what] = _stream_pth(path, st) if what == "pth" else _stream_media(path, st)
            except _PathChanged:
                raise
            except OSError as exc:
                answers[what] = {"error": str(exc) if isinstance(exc, _NotRegularFile)
                                 else exc.strerror or type(exc).__name__}
            continue
        if what == "sibling":                    # (FP-GRADLE-WRAPPER: the file beside it, a wrapper's properties)
            answers[what] = _read_sibling(path, need["name"], need["limit"])
            continue
        if what == "ranges":                     # (every range read so far, their bytes as the text)
            try:
                pieces.extend(_read_ranges(path, need["ranges"], st))
            except _PathChanged:
                raise
            except OSError as exc:
                answers[what] = {"error": str(exc) if isinstance(exc, _NotRegularFile)
                                 else exc.strerror or type(exc).__name__}
                continue
            answers[what] = [[off, len(b)] for off, b in pieces]
            answers["rounds"] = answers.get("rounds", 0) + 1
            text = _bytes_text(b"".join(b for _, b in pieces))
            continue
        try:
            data = _bytes_text(path[0].read(path[1], need["limit"], expect=st) if isinstance(path, tuple)
                               else _read_prefix(path, need["limit"]))
        except _PathChanged:
            raise
        except OSError as exc:
            if what == "sample":                 # not read: the SC-TRUNCATED stands alone, as before
                answers[what] = ""
                continue
            answers[what] = {"error": str(exc) if isinstance(exc, _NotRegularFile)
                             else exc.strerror or type(exc).__name__}
            continue
        if what == "data":                       # a file read whole goes as the call's text, not in its JSON
            answers[what], text = True, data
        else:
            answers[what] = data
    col["issues"].extend(engine._issues(p, [row])[0] for p, row in got["issues"])
    if "file" in got:
        f = got["file"]
        entry = {"path": f["path"], "content": f["content"], "lang": f["lang"], "dep": f["dep"]}
        if "vendor" in f:
            entry["vendor"] = f["vendor"]          # (its module or crate is read whole: _vendored_code)
        if "goContent" in f:
            entry["goContent"] = f["goContent"]    # (F-06: the Go reader's text, where Go reads the bytes otherwise)
        col["files"].append(entry)
    if "manifest" in got:
        m = got["manifest"]
        col["manifests"].append({"path": m["path"], "dep": m["dep"], "content": m["content"]})
    if "config" in got:
        col["configs"].append(got["config"])
    if got.get("pth"):
        col["pth"].append(disp)
    if "model" in got:                           # (FP-MODEL-FILES: a model file read; its imports and calls, model_own_issues')
        col["models"].append([disp, bool(in_dep), got["model"]["imports"], got["model"].get("calls", [])])
    for key in ("holder", "resolver"):           # (FP-B64-PROTOBUF: what the descriptors' pass reads, b64_descriptor_pass)
        if key in got:
            col[key + "s"].append(got[key])


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
    listed. What each entry is to the walk is the engine's (collect.rs:
    collect_dir); listing, the folders' identities, reading and counting are
    this package's.

    `root` is a path or a _Root: every folder and file is reached from the
    root's descriptor (LZ-03). A folder or a file the walk found that is a
    link or no folder by the time it is opened is recorded (_Root.changed_at)
    and not read; with a path for `root`, those are SC-TRUNCATED findings in
    `issues` (scan_project, which gives a _Root, reports them itself)."""
    excludes = sorted(_fs_display(x) for x in set(excludes or ()))
    col = {"files": [], "manifests": [], "pth": [], "issues": [], "skipped": [], "configs": [], "models": [],
           "holders": [], "resolvers": []}
    issues = col["issues"]
    try:
        tree, own = _as_root(root)
    except OSError as exc:
        raise ScanTargetError(f"cannot read directory {_fs_display(str(root))}: "
                              f"{exc.strerror or type(exc).__name__}") from None
    try:
        _walk(tree, excludes, include_deps, col)
        _go_vendor_data(tree, col, excludes)    # (F-06; its modules.txt read through the same root)
        if own:
            col["issues"].extend(changed_issues(tree))      # (_go_vendor_data gave col a new list)
    finally:
        if own:
            tree.close()
    return col


def _walk(tree, excludes, include_deps, col):
    try:
        _walk_tree(tree, excludes, include_deps, col)
    finally:
        tree.forget()                   # (the readers after the walk reach each folder by the name it has then)


def _walk_tree(tree, excludes, include_deps, col):
    issues = col["issues"]
    seen_dirs = set()
    stack = [("", False, ())]
    while stack:
        rel_dir, in_dep, parts = stack.pop()
        try:
            entries = tree.listdir(parts)
            st_dir = tree.lstat(()) if not rel_dir else None
        except _PathChanged:
            if not rel_dir:
                raise ScanTargetError(f"cannot read directory {_fs_display(tree.path)}: it changed while it was "
                                      f"read") from None
            tree.changed_at(rel_dir)
            continue
        except OSError as exc:
            if not rel_dir:
                raise ScanTargetError(
                    f"cannot read directory {_fs_display(tree.path)}: "
                    f"{exc.strerror or type(exc).__name__}") from None
            issues.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
            continue
        if st_dir is not None and st_dir.st_ino:
            seen_dirs.add(f"{st_dir.st_dev}:{st_dir.st_ino}")
        tree.listed(parts, entries)
        listed, stats = [], []
        for e in entries:
            name = _fs_display(e.name)
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                listed.append([name, "error", exc.strerror or type(exc).__name__])
                stats.append(None)
                continue
            stats.append(st)
            mode = st.st_mode
            if _stat.S_ISLNK(mode) or (_stat.S_ISDIR(mode) and _is_reparse_point(st)):
                listed.append([name, "link", _readlink((tree, parts + (e.name,)))])
            elif _stat.S_ISDIR(mode):
                key = f"{st.st_dev}:{st.st_ino}" if st.st_ino else None
                listed.append([name, "dir", key, key in seen_dirs])
            elif not _stat.S_ISREG(mode):
                listed.append([name, "special", next((c for test, c in _SPECIAL_CODES if test(mode)), "other")])
            else:
                listed.append([name, "file", st.st_size])
        got = _dir_plan(rel_dir, in_dep, listed, [(tree, parts + (e.name,)) for e in entries], excludes,
                        include_deps)
        seen_dirs.update(got["seen"])
        names = {e.name for e in entries}
        push = []
        for k, action, extra in got["do"]:
            e = entries[k]
            rel = os.path.join(rel_dir, e.name) if rel_dir else e.name
            at = parts + (e.name,)
            if action == "issue":
                issues.append(engine._issues(extra[0], [extra[1]])[0])
            elif action == "file":
                try:
                    _collect_file((tree, at), rel, stats[k], in_dep, col)
                except _PathChanged:
                    tree.changed_at(rel)
                except OSError as exc:
                    reason = (str(exc) if isinstance(exc, _NotRegularFile)
                              else exc.strerror or type(exc).__name__)
                    issues.append(unreadable_issue(_fs_display(rel), reason))
                except Exception as exc:        # one file must never kill the walk
                    issues.append(engine.error_issue(_fs_display(rel), exc))
            elif action == "skip":
                _count_skipped_tree(tree, at, _fs_display(rel), col["skipped"])
            elif len(at) > MAX_WALK_DEPTH:      # (a folder to walk or a __pycache__ to check, too deep to enter:
                tree.too_deep.append(_fs_display(rel))  # SC-TRUNCATED, the result incomplete)
            elif action == "pycache":
                try:
                    _check_pycache(rel, (tree, at), names, issues)
                except Exception as exc:
                    issues.append(engine.error_issue(_fs_display(rel), exc))
            else:                               # "walk"
                tree.found.add(at)
                push.append((rel, in_dep or _dep_of(extra[1], rel), at))
        stack.extend(reversed(push))       # pop order = sorted, depth-first (like os.walk)


#: The findings of a file's reading that a file found to be data takes with it (_go_vendor_data).
_READING_RULES = frozenset({"Q-ENCODING", "SC-UTF7", "SC-ESCAPE-CODEC", "SC-TRUNCATED"})


def _go_vendor_data(root, col, excludes=()):
    """(F-06) A Go vendor tree's .go files that are data: one in a testdata/ folder, or a folder named with "_" or
    "." first, of a package vendor/modules.txt does not list and no Go file read imports. `go mod vendor` copies a
    package's files and the files its //go:embed patterns match, which may be .go files below it; it lists every
    package a build imports, and a main module whose go.mod says `go 1.23` or later builds no other, while one below
    that builds a vendored package modules.txt does not list when an import names it (cmd/go's importFromModules).
    So a candidate folder an import of a file read names (the project's Go or a vendor tree's) is code, and the files
    of its package are read and their imports followed in turn (go_imports); the rest is not read as Go, as the
    registry reads a module's unimported testdata/ (_package_code): its entries are dropped from col's files, and
    their reading's findings (_READING_RULES) from col's issues. A vendor tree whose modules.txt cannot be read, or
    lists no package, keeps every file."""
    roots = sorted({_slash(f["vendor"]) for f in col["files"] if f.get("vendor") and f["lang"] == "go"},
                   key=len, reverse=True)
    if not roots:
        return
    tree = _DependencyTree(root, col["files"], col["manifests"], excludes)
    listed = {}
    for top in roots:
        text = _vendor_text(tree, f"{top}/modules.txt")
        listed[top] = (frozenset(engine.go_vendored_packages(text)) or None) if text is not None else None

    def candidate(path):
        """The folder (below its vendor tree, its import path) of a file that is data unless an import names it."""
        rel = _slash(path)
        top = next((t for t in roots if rel.startswith(t + "/")), None)
        if top is None or listed[top] is None or not rel.endswith(".go"):
            return None
        folder = posixpath.dirname(rel[len(top) + 1:])
        if (any(d == "testdata" or d[:1] in ("_", ".") for d in folder.split("/"))
                and folder not in listed[top]):
            return folder
        return None
    folders = {}                                # folder -> its entries, while no import names it
    read = []
    for f in col["files"]:
        folder = candidate(f["path"]) if f.get("vendor") and f["lang"] == "go" else None
        if folder is not None:
            folders.setdefault(folder, []).append(f)
        elif f["lang"] == "go":
            read.append(f)
    named = set()
    while read and folders:
        imports, refused = set(), False
        for paths in engine.go_imports([(f["path"], f.get("goContent", f["content"])) for f in read]):
            if paths is None:
                refused = True                  # (a file the parser refuses may import any of them: all are code)
            else:
                imports.update(paths)
        read = []
        for folder in sorted(set(folders) if refused else set(folders) & imports):
            named.add(folder)
            read.extend(folders.pop(folder))

    def data(path):
        folder = candidate(path)
        return folder is not None and folder not in named
    col["files"] = [f for f in col["files"] if not (f.get("vendor") and f["lang"] == "go" and data(f["path"]))]
    col["issues"] = [i for i in col["issues"] if not (i["rule"] in _READING_RULES and data(i["file"]))]


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
    return scan_manifest(mf["path"], mf["content"], registry=mf.get("dep"))


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
#     runs for it, `node-gyp rebuild` (MAJOR), as the registry lists it.
#   * every JavaScript or Python file of a dependency that no hook runs gets
#     import_time_risk: SC-IMPORT-RISK (MAJOR). On a real node_modules of
#     14,286 JavaScript files (webpack, next, jest, eslint, typescript ...)
#     it found nothing. (The detection round) But not a web app's static
#     assets, which run in a browser, not in Node or Python: a JavaScript
#     file in a _next, static or public directory of its package that none
#     of its npm package's entry points reach — main, module, bin and
#     exports, then the local files they require and import and the scripts
#     they start — is left out of the import-time test and the cross-file
#     follower, as the registry leaves it out of what runs.
#     litellm's proxy UI ships a Next.js export whose chunk of guardrail test
#     prompts (one shows `curl … | sh`) the test read as code, CRITICAL; a
#     package whose main points into static/ is still read.
# The decisions are the engine's (BR-7 step 3e: rust/crates/lazaret-engine/src/deps.rs; both packages made them until
# then): its deps_hooks call follows the hooks and deps_files says which files are assets, which the import-time and
# agent checks read and with what names, and how site-packages groups into distributions. This module reads the tree
# for them (_DependencyTree): each call asks for what it needs to know — whether a path is a file it may read, a
# manifest's text, what a file a hook runs does (read here, scanned when it is a dependency's JavaScript the walk did
# not read: those findings are this module's), what a JavaScript file loads, a directory's entries, a file's head —
# and is asked again with the answers, until it answers. The npm package's js/src/deps.js reads the tree the same way.

#: How many times a --deps call is asked at most: each answer that is not the call's names what it has yet to know
#: of the tree (the files a hook runs, then the scripts those start, …)
_DEPS_ROUNDS = 4096
#: what a file a hook runs does, when the engine could not say (its checks are then taken to have spent their budget:
#: the hook's manifest is SC-TRUNCATED)
_DEPS_UNANSWERED = {"exhausted": ["risk", "agent", "obfuscated", "spawned"]}


def _slash(path):
    """A path '/'-separated, as the engine's --deps calls take it."""
    return path.replace(os.sep, "/")


class _DependencyTree:
    """What a --deps scan knows of the tree, to answer what the engine's --deps
    calls ask (deps.rs): the files it read (by '/'-separated path) and, for
    the others, the disk under the scan root — regular files only, reached
    through no link and no directory an exclusion prunes. `pruned`: the
    directories the walk pruned (their '/'-separated paths), when nothing in
    them is to be read either (a project's own hooks: project_hook_checks,
    where a dependency tree is not read without --deps); `project`: a file
    a hook runs is then read, not scanned. `root`: a path or the scan's _Root,
    whose descriptor every read starts from (LZ-03): a file found to be one
    that is a link or behind one when it is read is recorded as changed."""

    def __init__(self, root, files, manifests, excludes, pruned=(), project=False):
        self.tree, _own = _as_root(root)
        self.root = self.tree.path
        self.sources = {_slash(f["path"]): f for f in files}
        self.manifests = {_slash(m["path"]): m for m in manifests}
        self.excludes = set(excludes or ()) | ALWAYS_PRUNE_DIRS
        self.pruned = {_slash(p) for p in pruned}
        self.project = project
        self.regular = {}                   # rel -> is a regular file (not read as source)
        self.read = {}                      # rel -> (findings, the file as scanned or None, text) of a file read here

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
        if self._in_pruned(parts):
            return False
        # (a link, or a file, on the way: _PathChanged; the file itself: lstat. A file the walk listed that is gone,
        # a link, another kind of file or another file now is recorded as changed: LZ-03's review, H1)
        return self.tree.is_regular(tuple(parts))

    def _in_pruned(self, parts):
        """Is one of the folders of `parts` (a path's, split at '/') a tree the
        walk pruned?"""
        return bool(self.pruned) and any("/".join(parts[:k]) in self.pruned for k in range(1, len(parts)))

    def ask(self, call, args, should_stop=None):
        """The engine's answer to the --deps call `call` (deps_hooks,
        deps_files), what it asks of the tree answered here, round after
        round -> (its answer, should_stop's reason when it stopped the
        rounds: None otherwise). Raises _native.NativeError when the engine
        could not answer."""
        known = {"stat": {}, "manifest": {}, "script": [], "targets": {}, "list": {}, "head": [], "under": {}}
        for _ in range(_DEPS_ROUNDS):
            stopped = should_stop() if should_stop is not None else None
            if stopped:
                return None, stopped
            got = _native.call(call, dict(args, known=known))
            if "need" not in got:
                return got, None
            self._answer(got["need"], known)
        raise _native.NativeError(f"{call}: still asking after {_DEPS_ROUNDS} rounds")

    def _answer(self, need, known):
        for rel in need["stat"]:
            known["stat"][rel] = self.is_file(rel)
        for rel in need["manifest"]:
            m = self.manifests.get(rel)
            known["manifest"][rel] = m["content"] if m is not None else None
        scripts = [(rel, release) + self._script_text(rel) for rel, release in need["script"]]
        base = {"project": self.project, "redact": bool(REDACT_SECRETS), "neumaier": False}
        facts = iter(engine.call_answers([("deps_script", dict(base, rel=rel, **({"own": release} if release else {})),
                                           text) for rel, release, _disk, text in scripts if text]))
        for rel, release, disk, text in scripts:
            f = next(facts) if text else None
            known["script"].append([rel, release, disk, _DEPS_UNANSWERED if engine.unanswered(f) else f])
        js = [rel for rel in need["targets"] if (self.sources.get(rel) or {}).get("lang") == "js"]
        found = dict(zip(js, engine.call_answers([("deps_targets", {}, self.sources[rel]["content"]) for rel in js])))
        for rel in need["targets"]:
            f = found.get(rel)
            known["targets"][rel] = {"targets": [], "exhausted": True} if engine.unanswered(f) else f
        for folder in need["list"]:
            known["list"][folder] = self._entries(folder)
        for folder in need["under"]:
            known["under"][folder] = self._under(folder)
        for path, cap in need["head"]:
            try:
                data = self.tree.read(self.tree.parts(path), cap + 1)
            except _PathChanged:
                self.tree.changed_at(self.tree.parts(path))
                known["head"].append([path, cap, None])
            except (OSError, ValueError):
                known["head"].append([path, cap, None])
            else:
                known["head"].append([path, cap, [data[:cap].decode("utf-8", "replace"), len(data) > cap]])

    def _entries(self, folder):
        """[[name, a real directory]] of a directory of the tree, or None when
        it can't be listed (no link is followed to tell a directory, or to
        reach it). The engine asks for folders of the walk's files' paths (a
        site-packages folder), so one that is a link or behind one now
        changed while the tree was read: recorded, and not listed."""
        try:
            entries = self.tree.listdir_after(self.tree.parts(folder))
        except _PathChanged:
            self.tree.changed_at(self.tree.parts(folder))
            return None
        except (OSError, ValueError):
            return None
        out = []
        for e in sorted(entries, key=lambda e: e.name):
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                out.append([e.name, False])
                continue
            out.append([e.name, _stat.S_ISDIR(st.st_mode) and not _is_reparse_point(st)])
        return out

    def _under(self, folder):
        """Every path below the directory `folder` is_file answers True for:
        the walk's files, and the disk's regular files below it, reached
        through no link and into nothing an exclusion or the walk pruned."""
        prefix = folder + "/"
        out = {rel for rel in self.sources if rel.startswith(prefix)}
        out.update(rel for rel in self.manifests if rel.startswith(prefix))
        parts = folder.split("/")
        if any(p in self.excludes or p in ("", ".", "..") for p in parts) or self._in_pruned(parts + [""]):
            return sorted(out)
        try:                                # (the folder itself: a real directory, reached through no link)
            st = self.tree.lstat(tuple(parts))
            if not _stat.S_ISDIR(st.st_mode) or _is_reparse_point(st):
                return sorted(out)
        except (OSError, ValueError):
            return sorted(out)
        stack = [(tuple(parts), folder)]
        while stack:
            where, rel = stack.pop()
            try:
                entries = self.tree.listdir_after(where)
            except _PathChanged:            # (a folder found here, a link or no folder now)
                self.tree.changed_at(where)
                continue
            except OSError:
                continue
            for e in entries:
                sub = f"{rel}/{e.name}"
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
                    continue
                if _stat.S_ISDIR(st.st_mode):
                    if e.name not in self.excludes and sub not in self.pruned:
                        stack.append((where + (e.name,), sub))
                elif _stat.S_ISREG(st.st_mode):
                    out.add(sub)
        return sorted(out)

    def _script_text(self, rel):
        """(read from the disk, text) of a file a hook runs: the walk's source
        or manifest, else read here once (None: it can't be read as text; an
        SC-TRUNCATED finding then says why)."""
        if rel in self.sources:
            return False, self.sources[rel]["content"]
        if rel in self.manifests:
            return False, self.manifests[rel]["content"]
        if rel not in self.read:
            self.read[rel] = self._read_script(rel)
        return True, self.read[rel][2]

    def _read_script(self, rel):
        """A file a hook runs that the walk did not read as source, read ->
        (the findings of reading it, the file as scanned or None, its text or
        None): scanned as a dependency's JavaScript (node runs lib/install.dat
        as JavaScript) unless it is a shell script, or a project's own hook
        runs it (only read, to test what the hook runs)."""
        disp = rel.replace("/", os.sep)
        try:
            data = self.tree.read(self.tree.parts(rel), SOURCE_SIZE_CAP + 1)
        except OSError as exc:
            if isinstance(exc, _PathChanged):
                self.tree.changed_at(disp)
            reason = str(exc) if isinstance(exc, _NotRegularFile) else exc.strerror or type(exc).__name__
            return [truncated_issue(disp, f"it runs at install time but could not be read ({reason})")], None, None
        if len(data) > SOURCE_SIZE_CAP:
            return [truncated_issue(disp, f"it runs at install time but is larger than the "
                                          f"{SOURCE_SIZE_CAP:,}-byte file limit")], None, None
        if looks_binary(data[:2048]):
            return [truncated_issue(disp, "it runs at install time but is not text, so it could not be scanned")], \
                None, None
        if rel.endswith(".sh") or shebang_lang(data[:HEADER_SAMPLE_BYTES].decode("utf-8", "replace")) == "sh":
            return [], None, normalize_newlines(data.decode("utf-8", "replace"))
        text, decode_issues = decode_member(disp, data, lang="js")
        if self.project:
            return list(decode_issues), None, text
        return (list(decode_issues) + engine.scan_file(disp, text, "js", dep=True),
                {"path": disp, "content": text, "lang": "js", "dep": True}, text)

    def take(self, got, hooks, out, extra=None):
        """deps_hooks' answer applied: each of `hooks` (the SC-INSTALL-HOOK
        findings followed) gets its new severity and message, `out` the
        findings in order (a file read here: the findings of reading it, and
        the file as scanned to `extra`) -> the files the hooks run."""
        for issue, change in zip(hooks, got["hooks"]):
            if change:
                issue["sev"], issue["msg"] = change
        for item in got["out"]:
            if item[0] == "read":
                findings, scanned, _text = self.read[item[1]]
                out.extend(findings)
                if scanned is not None and extra is not None:
                    extra.append(scanned)
            else:
                out.extend(engine._issues(item[1].replace("/", os.sep), [item[2]]))
        return set(got["run"])


def _hook_rows(hooks):
    """SC-INSTALL-HOOK findings as deps_hooks takes them: [manifest, line, severity, command]."""
    return [[_slash(i["file"]), i["line"], i["sev"], i["cmd"]] for i in hooks]


# ---------------- Go modules and crates: the readers' findings, and --deps's vendor trees (0.1.9, Part C) ----------------
# The engine's Go reader (go_package) and Rust reader (rs_crate) read a module or a crate whole, for what its code does
# and when it runs. The registry (registry/repo.py) reads a module zip, a .crate and the crate inside an sdist with them;
# a --deps scan reads a Go project's vendor/ (`go mod vendor`: vendor/modules.txt) and a Rust project's (`cargo vendor`:
# a .cargo-checksum.json in each crate's directory) the same way: the file rules in dependency mode on each .go and .rs
# file a build compiles (never_built: not the others), and the reader on each vendored module (the paths
# vendor/modules.txt lists) or crate (each directory of the vendor tree). A vendor tree of cargo's is a dependency tree
# now: without --deps it is pruned, as node_modules is. Twin of the npm engine's js/src/deps.js (vendoredCode).
#: The most a reader takes of one module or crate, in characters: it holds all of it at once (registry/repo.py's too).
PACKAGE_CODE_CHARS = 300_000_000
#: The use-time share of a module or a crate (SC-USE-RISK): no file over USE_RISK_MAX_CHARS, USE_RISK_CHARS in all,
#: smallest first (registry/repo.py's numbers for a release file).
USE_RISK_MAX_CHARS = 8_000_000
USE_RISK_CHARS = 24_000_000
VENDOR_CODE = {"go": ".go", "cargo": ".rs"}
_VENDOR_TEXT_CAP = 4 << 20                  # a modules.txt or a Cargo.toml read, at most
_CGO_EXTS = (".c", ".h")


def never_built(kind, rel):
    """Is `rel` ('/'-separated, below a Go module's root for "go", a crate's
    for "crate") a file the file rules leave out as no build of a dependent
    compiles it (goread/rsread never_built): a Go *_test.go file, a name
    with "_" or "." first, one under testdata/ or below a vendor/ folder's
    own folders; a crate's tests/, benches/ and examples/. A test file's
    name ends in `_test.go` exactly, as Go reads it: `x_TEST.go` is built.
    A package in vendor/ itself (`m/vendor`) is the module's and is built;
    one in testdata/ is built when an import names it: the Go reader is
    given those files (go_testdata) and reads such a package (F-06); a
    vendor tree's are its modules.txt's (_go_vendor_data)."""
    if kind == "go":
        parts = rel.split("/")
        name, dirs = parts[-1], parts[:-1]
        return (name[:1] in ("_", ".") or name.endswith("_test.go") or "testdata" in dirs
                or "vendor" in dirs[:-1])
    if kind == "crate":
        return rel.split("/", 1)[0] in ("tests", "benches", "examples")
    return False


def go_testdata(rel):
    """Is `rel` ('/'-separated, below a Go module's root) a .go file that only
    its testdata/ folder keeps from the file rules (never_built)? Such a file
    is given to the Go reader all the same: a package in testdata/ is built
    when an import names it, and the reader reads it then, and the file
    rules too (F-06)."""
    parts = rel.split("/")
    name, dirs = parts[-1], parts[:-1]
    return (name.lower().endswith(".go") and "testdata" in dirs and "vendor" not in dirs[:-1]
            and not (name[:1] in ("_", ".") or name.endswith("_test.go")))


_LAYOUT_ROOT_RE = re.compile(r"^(?:[A-Za-z]:)?/+")


def _layout_path(value):
    """A path a Cargo.toml names, relative to the crate's root as the
    registry reads it (base.finish_member_path): drive roots and leading
    slashes off, normalized; None for one with a `..` or none at all."""
    if not isinstance(value, str) or len(value) > 512:
        return None
    rest = value.replace("\\", "/")
    while True:
        stripped = _LAYOUT_ROOT_RE.sub("", rest)
        if stripped == rest:
            break
        rest = stripped
    if ".." in rest.split("/"):
        return None
    norm = posixpath.normpath(rest) if rest else ""
    return None if norm in ("", ".") else norm


def cargo_layout(manifest, members):
    """(the build script, the library's root, whether it is a procedural
    macro) of a vendored crate whose Cargo.toml text is `manifest` and whose
    .rs files are `members` (paths below its root): what the engine reads of
    the manifest (engine.cargo_layout, the npm package's too), resolved as
    the registry's crates.Crates.layout resolves its reading: `build.rs`
    unless `build` names another file or is false, `src/lib.rs` unless
    `lib.path` names another, each only when the crate has it."""
    said = engine.cargo_layout(manifest or "")
    present = set(members or ())
    build, lib = said.get("build"), said.get("lib")
    script = None if build is False else (_layout_path(build) if isinstance(build, str) else "build.rs")
    root = _layout_path(lib) if isinstance(lib, str) else "src/lib.rs"
    root = root if root in present else None
    return (script if script in present else None, root, root is not None and said.get("proc_macro") is True)


def package_reader_issues(answer, order):
    """The findings of a reader's answer (engine.go_package, engine.rs_crate,
    asked with `what` and the files' names: the engine makes them, readers.rs,
    BR-7 step 3 f) for the files `order` (their paths, in the order the
    reader was given them) -> (issues, what its use-time step read). A build
    script and a procedural macro are SC-INSTALL-HOOK, CRITICAL for any
    reason; what runs at start (Go's init code, #[ctor]) the import-time
    test; the strong reasons of the rest SC-USE-RISK; //go:generate
    SC-GO-GENERATE (INFO)."""
    issues = [engine._issues(order[k] if 0 <= k < len(order) else order[0], [issue])[0]
              for k, issue in answer.get("issues") or []]
    read = answer.get("useRead") or {}
    return issues, {key: int(read.get(key, 0)) for key in ("files", "ofFiles", "chars", "ofChars")}


def _vendor_text(tree, rel):
    """The text of a regular file of the tree ('/'-separated rel), read
    through no link, at most _VENDOR_TEXT_CAP bytes; None otherwise."""
    if not tree.is_file(rel):
        return None
    try:
        data = tree.tree.read(tree.tree.parts(rel), _VENDOR_TEXT_CAP + 1)
    except _PathChanged:
        tree.tree.changed_at(tree.tree.parts(rel))
        return None
    except (OSError, ValueError):
        return None
    return None if len(data) > _VENDOR_TEXT_CAP else data.decode("utf-8", "replace")


def _disk_reader(root, files, manifests, excludes=()):
    """read(rel) of a regular file of the tree the walk did not keep (a
    dependency's shell or PowerShell script its agent skill runs, RA-3): read
    through no link and into nothing an exclusion prunes (_DependencyTree), at
    most SOURCE_SIZE_CAP bytes, as text; None for another (binary, too large,
    missing)."""
    tree = _DependencyTree(root, files, manifests, excludes)

    def read(rel):
        if not tree.is_file(rel):
            return None
        try:
            data = tree.tree.read(tree.tree.parts(rel), SOURCE_SIZE_CAP + 1)
        except _PathChanged:
            tree.tree.changed_at(tree.tree.parts(rel))
            return None
        except (OSError, ValueError):
            return None
        if len(data) > SOURCE_SIZE_CAP or looks_binary(data[:2048]):
            return None
        return data.decode("utf-8", "replace")
    return read


_B64_MARKS = {}


def b64_mark(name):
    """What the descriptors' pass reads a file of this name as (b64_descriptor_pass): "holder" (a kind that holds
    script the file scan does not read: _SCRIPT_HOLDER_EXTS), "resolver" (it says where modules are: tsconfig*.json,
    jsconfig*.json, _B64_RESOLVER_CONFIGS), or None. The engine's collect_file says so for a walk (collect.rs)."""
    if not _B64_MARKS:
        _B64_MARKS.update(holders=frozenset(engine.pack_value("_SCRIPT_HOLDER_EXTS")),
                          resolvers=frozenset(engine.pack_value("_B64_RESOLVER_CONFIGS")))
    low = posixpath.basename(_slash(name)).lower()
    if os.path.splitext(low)[1] in _B64_MARKS["holders"]:
        return "holder"
    if (low.startswith(("tsconfig", "jsconfig")) and low.endswith(".json")) or low in _B64_MARKS["resolvers"]:
        return "resolver"
    return None


def b64_descriptor_pass(issues, files, manifests, holders, resolvers, read, stopped, package, unread=()):
    """FP-B64-PROTOBUF (the review of Oct 27): drop from `issues`, in place, the SC-B64 findings of JavaScript files
    whose every run is a protobuf file's descriptor handed to its runtime's loader and used only as generated code
    uses it, decided over the whole scan by the engine (b64_descriptors: protodesc/usage.rs). `files` and `manifests`:
    the scan's, as collected; `holders`, `resolvers`: the paths of the files that may hold script or say where modules
    are (collect_file's "holder" and "resolver"), read by `read(rel)` ('/'-separated; None when it cannot be read);
    `stopped`: the scan stopped before its end; `package`: a package's scan; `unread`: the paths of what it did not
    read whole besides its SC-TRUNCATED, Q-UNREADABLE and Q-SYMLINK findings' ("." for the scan). Fails closed: when
    the engine cannot answer every finding stays, and the reason is returned (None otherwise)."""
    js = {}
    for f in files:
        if f.get("lang") == "js" and isinstance(f.get("content"), str):
            js.setdefault(_slash(f["path"]), f["content"])
    found = [i for i in issues if i.get("rule") == "SC-B64" and _slash(i.get("file") or "") in js
             and isinstance(i.get("line"), int)]
    # (a finding can be dropped only in a file that calls the loader's fileDesc: when none does, every one stays
    # and the scan's text need not be handed over)
    if not any("fileDesc" in js[_slash(i["file"])] for i in found):
        return None
    try:
        kinds = set(engine.pack_value("_B64_DESCRIPTOR_UNREAD"))
        args = {
            "files": [[p, t] for p, t in js.items()],
            "holders": [[_slash(h), read(_slash(h))] for h in holders],
            "manifests": [[_slash(m["path"]), m["content"]] for m in manifests
                          if posixpath.basename(_slash(m["path"])) == "package.json"],
            "configs": [[_slash(c), read(_slash(c))] for c in resolvers],
            "findings": [[_slash(i["file"]), i["line"]] for i in found],
            "unread": sorted({_slash(i.get("file") or ".") for i in issues if i.get("rule") in kinds}
                             | {_slash(x) for x in unread}),
            "stopped": bool(stopped), "package": bool(package)}
        got = _native.call("b64_descriptors", args)["findings"]
        if len(got) != len(found):
            raise ValueError(f"{len(got)} answers for {len(found)} findings")
    except Exception as exc:                    # every finding stays
        return f"SC-B64: protobuf descriptors were not checked ({type(exc).__name__}: {_safe_text(exc)})"
    drop = {id(i) for i, (_, _, why) in zip(found, got) if why is None}
    issues[:] = [i for i in issues if id(i) not in drop]
    return None


def _vendored_modules(text):
    """The module paths vendor/modules.txt says are vendored, longest first
    (engine.go_vendored_modules: a `# path version …` line followed by its
    annotations and packages)."""
    return engine.go_vendored_modules(text) if text else []


def _cgo_texts(tree, folder):
    """[(rel, text)] of the .c and .h files directly in `folder` (a vendored
    Go package's directory, '/'-separated): what the Go reader reads with its
    cgo preambles. Regular files only, through no link, each at most
    SOURCE_SIZE_CAP bytes."""
    where = tree.tree.parts(folder) if folder else ()
    out = []
    try:
        names = sorted(e.name for e in tree.tree.listdir_after(where)
                       if os.path.splitext(e.name)[1].lower() in _CGO_EXTS)
    except _PathChanged:                    # (the folder of files the walk read: a link or no folder now)
        tree.tree.changed_at(where)
        return out
    except OSError:
        return out
    for name in names:
        rel = f"{folder}/{name}" if folder else name
        if not tree.is_file(rel):
            continue
        try:
            data = tree.tree.read(where + (name,), SOURCE_SIZE_CAP + 1)
        except _PathChanged:
            tree.tree.changed_at(where + (name,))
            continue
        except (OSError, ValueError):
            continue
        if len(data) <= SOURCE_SIZE_CAP and not looks_binary(data[:HEADER_SAMPLE_BYTES]):
            out.append((rel, data.decode("utf-8", "replace")))
    return out


def _vendored_code(tree, files, should_stop=None):
    """The readers on a --deps scan's vendored Go modules and crates (see the
    section comment) -> (issues, stopped): each module vendor/modules.txt
    lists (a file of none is read with its package's directory), each crate
    of a cargo vendor tree. A module or a crate over PACKAGE_CODE_CHARS is
    SC-TRUNCATED, and so is one the engine could not answer about. A Go file
    is given as the Go toolchain reads it (goContent, where that is not its
    content), and every package given is one modules.txt lists, built
    (`listed`: one in testdata/ too; _go_vendor_data dropped the others)."""
    units = {}
    listed = {}
    for f in files:
        top = f.get("vendor")
        if not top or f["lang"] not in ("go", "rs"):
            continue
        path, top = f["path"].replace(os.sep, "/"), top.replace(os.sep, "/")
        below = path[len(top) + 1:]
        if f["lang"] == "go":
            if top not in listed:
                listed[top] = _vendored_modules(_vendor_text(tree, f"{top}/modules.txt"))
            module = next((m for m in listed[top] if below == m or below.startswith(m + "/")), None)
            unit = module if module is not None else posixpath.dirname(below)
            units.setdefault(("go", top, unit, module), []).append(f)
        else:
            units.setdefault(("rs", top, below.split("/", 1)[0], None), []).append(f)
    out = []
    for (lang, top, unit, module), members in sorted(units.items(), key=lambda kv: kv[0][:3]):
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, stopped
        base = f"{top}/{unit}" if unit else top
        members = sorted(members, key=lambda f: f["path"].replace(os.sep, "/"))
        named = [(f["path"], f["path"].replace(os.sep, "/")[len(base) + 1:], f.get("goContent", f["content"]))
                 for f in members]
        if lang == "go":
            for folder in sorted({posixpath.dirname(f["path"].replace(os.sep, "/")) for f in members}):
                named.extend((_fs_display(rel.replace("/", os.sep)), rel[len(base) + 1:], text)
                             for rel, text in _cgo_texts(tree, folder))
        order = [p for p, _r, _t in named]
        size = sum(len(t) for _p, _r, t in named)
        what = "module" if lang == "go" else "crate"
        if size > PACKAGE_CODE_CHARS:
            out.append(truncated_issue(order[0], f"the vendored {what}'s code ({size:,} characters) is more than the "
                                                 f"reader takes at once ({PACKAGE_CODE_CHARS:,}), so it was not read"))
            continue
        try:
            if lang == "go":
                answer = engine.go_package([(r, t) for _p, r, t in named], module=module,
                                           use_file_chars=USE_RISK_MAX_CHARS, use_chars=USE_RISK_CHARS,
                                           what=what, names=order, listed=True)
            else:
                script, lib, proc_macro = cargo_layout(_vendor_text(tree, f"{base}/Cargo.toml"),
                                                       [r for _p, r, _t in named])
                answer = engine.rs_crate([(r, t) for _p, r, t in named], build=script, proc_macro=proc_macro, lib=lib,
                                         use_file_chars=USE_RISK_MAX_CHARS, use_chars=USE_RISK_CHARS,
                                         what=what, names=order)
        except Exception as exc:                # one module must never kill the run
            out.append(engine.error_issue(order[0], exc))
            continue
        out.extend(package_reader_issues(answer, order)[0])
    return out, None


# ---------------- Cross-file received code (the engine's cross_file, 0.1.8) ----------------
# The follower is the native engine's (engine.cross_file_issues), and so is how a --deps scan groups the dependency
# files into packages (deps_files: a distribution's .dist-info/RECORD lists the top-level modules and packages it
# installs into site-packages, which are one package to the follower, as a registry scan reads a release).


def dependency_checks(root, files, manifests, issues, excludes=(), should_stop=None):
    """The --deps checks of what dependencies run (see the section comment),
    after the files and manifests were scanned: escalates the SC-INSTALL-HOOK
    findings of dependency manifests in `issues` in place and returns
    (new_issues, extra_files, stopped): the findings to add, the files read
    and scanned here (to add to the scanned files), and should_stop's reason
    when it stopped the checks (None otherwise)."""
    tree = _DependencyTree(root, files, manifests, excludes)
    dep_manifests = {m["path"] for m in manifests if m.get("dep")}
    hooks = [i for i in issues if i["rule"] == "SC-INSTALL-HOOK" and i.get("cmd") and i["file"] in dep_manifests]
    out, extra, run = [], [], set()
    args = {"project": False, "hooks": _hook_rows(hooks), "redact": bool(REDACT_SECRETS), "neumaier": False,
            "manifests": [[_slash(m["path"]), bool(m.get("dep"))] for m in manifests]}
    got, stopped = None, None
    if dep_manifests:                       # (npm's implicit node-gyp hooks, then each hook)
        try:
            got, stopped = tree.ask("deps_hooks", args, should_stop)
        except _native.NativeError as exc:  # (the run goes on: each hook's manifest says why)
            out.extend(engine.error_issue(path, exc) for path in dict.fromkeys(i["file"] for i in hooks))
    if stopped:
        return out, extra, stopped
    if got is not None:
        run = tree.take(got, hooks, out, extra)
    # the import-time and agent checks for each dependency file no hook runs, a batch at a time (the engine reads a
    # batch on threads), given the names of the package it is in (D-12b, D-9c); a file it could not answer about is
    # SC-TRUNCATED (engine.error_issue). (the detection round) a web app's static assets are left out
    dep = [f for f in files if f.get("dep") and f["lang"] in ("js", "py")]
    plan = {"assets": [], "todo": [], "groups": []}
    try:
        if dep:
            plan, stopped = _deps_plan(tree, dep, run, should_stop)
    except _native.NativeError:             # (every file is read then: none is taken for an asset)
        plan, stopped = {"assets": [], "groups": [], "todo": [[_slash(f["path"]), None] for f in dep
                                                              if _slash(f["path"]) not in run]}, None
    if stopped:
        return out, extra, stopped
    assets = set(plan["assets"])
    names = {rel: named for rel, named in plan["todo"]}
    todo = [f for f in dep if _slash(f["path"]) in names]
    for start in range(0, len(todo), engine.BATCH):
        if should_stop is not None:
            stopped = should_stop()
            if stopped:
                return out, extra, stopped
        chunk = todo[start:start + engine.BATCH]
        try:
            answers = engine.dep_file_issues([(f["content"], f["lang"], names[_slash(f["path"])], f["path"])
                                              for f in chunk])
        except _native.NativeError as exc:
            answers = [exc] * len(chunk)
        for f, answer in zip(chunk, answers):
            if engine.unanswered(answer):
                out.append(engine.error_issue(f["path"], answer))
            else:
                out.extend(engine._issues(f["path"], [a for a in answer[:2] if a is not None]))
                if len(answer) > 2 and answer[2]:
                    # (BIG-BUNDLE-TAIL: the file not read whole, beside what was found)
                    out.append(truncated_issue(f["path"], answer[2]))
    # (0.1.9, Part C) the vendored Go modules' and crates' code, by the
    # engine's readers (_vendored_code)
    found, stopped = _vendored_code(tree, files, should_stop)
    out.extend(found)
    if stopped:
        return out, extra, stopped
    # Cross-file received code (0.1.8): a value received in one file of a
    # package and run in another, by the native engine's follower (it reads
    # the packages on threads: engine.cross_file_issues). Reached
    # only when the checks above did not stop (each returns early on
    # should_stop), so no extra should_stop call here — it is a bounded pass.
    # Skips the files already flagged CRITICAL single-file (a MAJOR one can
    # still be found running what another file received).
    flagged = {_slash(i["file"]) for i in out if i["rule"] == "SC-IMPORT-RISK" and i["sev"] == "CRITICAL"}
    code = [f for f in files if _slash(f["path"]) not in assets] if assets else files
    out.extend(engine.cross_file_issues(code, flagged, site_groups=dict(plan["groups"])))
    return out, extra, None


def _deps_plan(tree, dep, run=(), should_stop=None):
    """deps_files' answer for a --deps scan's dependency JavaScript and
    Python files `dep` (in the walk's order) after the hooks ran the files
    `run`: ({"assets": the web app's static assets, "todo": [[path, names]]
    the files the import-time and agent checks read, with their package's
    names, "groups": [[path, group]] the site-packages distributions} (paths
    '/'-separated), should_stop's reason when it stopped the rounds)."""
    args = {"files": [[_slash(f["path"]), f["lang"]] for f in dep], "run": sorted(run)}
    return tree.ask("deps_files", args, should_stop)


# ---------------- A project's own install hooks (SC-INSTALL-HOOK, 0.1.9) ----------------
# A project scan judged the project's own install hooks by their command alone; only a dependency's hooks were
# followed (--deps, above). The tensorlake worm (Mini Shai-Hulud, October 2026) committed `"preinstall": "node
# lib/setup.mjs"` to the project's own typescript/package.json, with an obfuscated loader beside it. Now each install
# hook of every package.json that is not a dependency's (NPM_LOCAL_INSTALL_SCRIPTS) is followed as a dependency's is:
# to the files it runs (follow_hook, from the manifest's folder, by Node's resolution, into nothing the walk pruned:
# no dependency tree without --deps), then to the scripts those start (spawned_scripts, the same limits). The hook
# is CRITICAL when one of them fails the install-script test (install_script_risk), else when one is obfuscated
# (the engine's is_obfuscated, as SC-AUTORUN): the test's reasons come first, in the dependency follow's messages. A file the walk
# did not read as source is read, not scanned; one that can't be read as text, like a hook too long to follow, is
# SC-TRUNCATED. The follow is the engine's (deps_hooks, as a dependency's), the reading of the tree this module's.

def project_hook_checks(root, files, manifests, issues, excludes=(), skipped=(), should_stop=None):
    """The follow of a project's own install hooks (see the section
    comment), after the manifests were scanned: escalates the SC-INSTALL-HOOK
    findings of the package.json files that are not a dependency's in
    `issues` in place. -> (new_issues, stopped): the findings to add
    (SC-TRUNCATED, Q-ENCODING), with should_stop's reason when it stopped the
    checks (None: not stopped). `skipped`: the walk's pruned trees,
    [(rel, files, bytes)]."""
    own = {m["path"] for m in manifests
           if not m.get("dep") and posixpath.basename(_slash(m["path"])) == "package.json"}
    hooks = [i for i in issues if i["rule"] == "SC-INSTALL-HOOK" and i.get("cmd") and i["file"] in own]
    out = []
    if not hooks:
        return out, None
    tree = _DependencyTree(root, files, manifests, excludes, [rel for rel, *_counts in skipped], project=True)
    args = {"project": True, "hooks": _hook_rows(hooks), "redact": bool(REDACT_SECRETS), "neumaier": False}
    try:
        got, stopped = tree.ask("deps_hooks", args, should_stop)
    except _native.NativeError as exc:      # one manifest must never kill the run
        out.extend(engine.error_issue(path, exc) for path in dict.fromkeys(i["file"] for i in hooks))
        return out, None
    if stopped:
        return out, stopped
    tree.take(got, hooks, out)
    return out, None


def dependency_import_issue(path, text, lang=None, names=None):
    """SC-IMPORT-RISK (MAJOR, or CRITICAL: import_time_severity) for a
    dependency's JavaScript or Python file (`lang` 'js' or 'py') that fails
    the import-time test (`names`: its package's (declared, own), when
    known), else None: the engine's (deps.rs, dep_file_issues). Raises
    _native.NativeError when the engine could not answer."""
    answer = engine.dep_file_issues([(text, lang, names, path)])[0]
    if engine.unanswered(answer):
        raise answer
    return engine._issues(path, [answer[0]])[0] if answer[0] is not None else None


def redact_file_issues(issues, files):
    """Apply each scanned file's redaction to the findings numbered by its
    scan lines (source_lines) that were built outside the engine's scan of
    it: the flow engine's and the dependency checks' (scan_project passes
    those; the engine redacts its own), in place.

    redact_result sweeps snippets with the secret patterns only, and a PEM
    block only when its BEGIN line is in the same snippet: a finding built
    from raw lines outside scan_file lacked the file's entropy literals and
    PEM blocks (review: the X-CMD snippet of a flow showed the `seed = "…"`
    literal S-ENTROPY redacted, in the JSON and the HTML report). The engine
    reads each file once, with all of its findings (redact.rs redact_file):
    every snippet line that is still the raw text of its file line becomes
    that line as the file's own findings show it (a line its builder already
    redacted or clipped is left alone), and msg / cmd get the file's
    literals."""
    if not REDACT_SECRETS:
        return issues
    by_path = {f["path"]: f for f in files}
    groups = {}
    for i in issues:
        if i.get("file") in by_path:
            groups.setdefault(i["file"], []).append(i)
    for path, group in groups.items():
        f = by_path[path]
        lines = source_lines(f["content"], f.get("lang"))
        rows, raw = [], []
        for i in group:
            snip, start = i.get("snippet"), i.get("snipStart")
            at = []                                         # (k, j): snippet line k is still file line j's raw text
            if isinstance(snip, list) and isinstance(start, int):
                at = [(k, start - 1 + k) for k, line in enumerate(snip)
                      if isinstance(line, str) and 0 <= start - 1 + k < len(lines) and line == lines[start - 1 + k]]
            raw.append(at)
            rows.append([[j for _k, j in at], *(i.get(k) if isinstance(i.get(k), str) else None for k in ("msg", "cmd"))])
        got = _native.call("redact_file", {"issues": rows, "neumaier": False}, "\n".join(lines))["issues"]
        for i, at, (shown, msg, cmd) in zip(group, raw, got):
            if at:
                snip = list(i["snippet"])
                for (k, _j), line in zip(at, shown):
                    snip[k] = line
                shown = snip
            _apply_redaction([i], [(shown if at else None, msg, cmd)])
    return issues


def _apply_redaction(issues, got):
    """The engine's [snippet, msg, cmd] for each of `issues` put in place
    where they changed."""
    for i, (snip, msg, cmd) in zip(issues, got):
        for key, v in (("msg", msg), ("cmd", cmd)):
            if isinstance(v, str) and v != i.get(key):
                i[key] = v
        if isinstance(snip, list) and snip != i.get("snippet"):
            i["snippet"] = snip


def scan_project(root, exclude=(), include_deps=False, taint_config=None,
                 redact_secrets=True, extra_issues=(), should_stop=None, shown=None, allow_empty=False,
                 merge_issues=(), extra_files=(), extra_configs=0, collected=None, opened=None):
    """The complete project scan, shared by the CLI (main) and the MCP server:
    collect -> scan files -> manifests / binding.gyp -> what the project's own
    install hooks run (project_hook_checks) -> --deps' dependency checks ->
    collection findings
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
    shown           optional dict (--show-secrets): filled with each finding's
                    flagged line as read, {(file, line): text}, for the
                    terminal alone (print_report); the result stays redacted
    allow_empty     a root holding nothing to scan is not an error (a
                    repository's checkout whose twin trees hold what is read:
                    scan_twins)
    merge_issues    findings of the same commit read in other trees (a
                    repository checkout's twin trees: scan_twins), merged
                    with this scan's by merge_findings before the grading
    extra_files     files of the same commit read in other trees (each as
                    `collected` gives it), counted in the metrics with this
                    scan's own; extra_configs: how many config files they
                    read
    collected       optional dict: given the files this scan counted in its
                    metrics ("files": [{path, content, lang, dep, …}]) and
                    the paths of the config files it read ("configs")
    opened          optional _Root of `root`, opened by the caller (the MCP
                    server opens the folder it checked beneath its allowed
                    root); else the root is opened here. Every read under it
                    starts from its descriptor (LZ-03): a part of the tree
                    that changed while it was read (a link or no folder where
                    the walk found a folder or a file) is SC-TRUNCATED, not
                    read, and the result is incomplete.

    Returns the build_result() dict — project, scannedAt, pass, conditions,
    metrics, counts, ratings, supplyChain, crossFile, perFile, issues — plus
    "warnings": [str] (degraded-analysis notes; the CLI prints them).
    Raises ScanTargetError (usage error) when root does not exist, is not a
    directory, cannot be read, or holds nothing to scan.
    """
    root = os.fspath(root)
    if opened is None:
        if not os.path.exists(root):
            raise ScanTargetError(f"{_fs_display(root)} does not exist")
        if not os.path.isdir(root):
            raise ScanTargetError(f"{_fs_display(root)} is not a directory")
        try:
            tree = _Root(root)
        except OSError as exc:
            raise ScanTargetError(f"cannot read directory {_fs_display(root)}: "
                                  f"{exc.strerror or type(exc).__name__}") from None
    else:
        tree = opened
    try:
        return _scan_project(tree, root, exclude, include_deps, taint_config, redact_secrets, extra_issues,
                             should_stop, shown, allow_empty, merge_issues, extra_files, extra_configs, collected)
    finally:
        if opened is None:
            tree.close()


def _scan_project(tree, root, exclude, include_deps, taint_config, redact_secrets, extra_issues, should_stop, shown,
                  allow_empty, merge_issues, extra_files, extra_configs, collected):
    global REDACT_SECRETS
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
        col = _collect(tree, exclude, include_deps=include_deps)
        files, manifests, configs = col["files"], col["manifests"], col["configs"]
        if not files and not manifests and not configs and not col["pth"] and not col["issues"] and not col["models"] \
                and not tree.changed and not tree.too_deep and not allow_empty:
            raise ScanTargetError(
                f"nothing to scan under {_fs_display(root)}: no Python, JavaScript or "
                f"SQL sources, package manifests or other files to check")
        issues = list(extra_issues) + list(col["issues"])
        # (FP-MODEL-FILES) the globals of the project's own modules, or a dependency's, its model files import
        issues.extend(model_own_issues(col["models"], model_own_files(col["models"], files)))
        # findings numbered by their file's scan lines and built outside the engine's scan of it, which redacted
        # its own with the file's redaction (mk_issue's): the flows' and the dependency checks' (redact_file_issues)
        numbered = []
        scanned, stopped = [], None
        # (Q-4) what each project Python file imports from the others that the taint pass follows calls into
        try:
            helpers = engine.taint_helpers([(f["path"], f["content"]) for f in files
                                            if f["lang"] == "py" and not f.get("dep", False)])
        except Exception as exc:                # the files are then read with their own helpers alone
            helpers = {}
            warnings.append(f"taint pass: the helpers other files define were not read "
                            f"({type(exc).__name__}: {_safe_text(exc)})")
        # Files a batch at a time (the engine reads a batch on threads, each
        # file whole: engine.py); should_stop is checked before each batch.
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
                # (each project file's line metrics from the same reading: compute_metrics, Q-1 step 4)
                results, line_metrics = engine.scan_files_metrics(
                    [(f["path"], f["content"], f["lang"], f.get("dep", False)) for f in chunk], helpers)
            except Exception:                   # a batch that failed: each file again, on its own
                results = line_metrics = None
            for n, f in enumerate(chunk):
                if line_metrics is not None and line_metrics[n] is not None:
                    f["lineMetrics"] = line_metrics[n]
                try:
                    found = (results[n] if results is not None
                             else scan_file(f["path"], f["content"], f["lang"], dep=f.get("dep", False)))
                    issues.extend(found)
                except Exception as exc:        # one file must never kill the run
                    issues.append(engine.error_issue(f["path"], exc))
                scanned.append(f)
            k += len(chunk)
        checked = 0                         # config and data files: credentials only
        read = tree_reader(files, configs)  # what an editor's or agent's settings run (SC-AUTORUN)
        dep_read = None                     # what a dependency's agent skill runs: its scripts, from the disk too
        for cf in configs:
            if not stopped and should_stop is not None:
                stopped = should_stop()
            if stopped:
                break
            if cf.get("dep") and dep_read is None:
                dep_read = tree_reader(files, configs, disk=_disk_reader(tree, files, manifests, exclude))
            try:
                issues.extend(scan_config_file(cf["path"], cf["content"], dep_read if cf.get("dep") else read,
                                               dep=bool(cf.get("dep"))))
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
            # the project's own install hooks: what they run (project_hook_checks)
            found, hook_stopped = project_hook_checks(tree, files, manifests, issues, exclude, col["skipped"],
                                                      should_stop)
            issues.extend(found)
            if hook_stopped:
                stopped = hook_stopped
                issues.append(truncated_issue(
                    ".", f"{stopped}: what the project's install hooks run was not checked to the end"))
            else:
                # --deps: what the dependencies run (install hooks, import-time code)
                found, extra, dep_stopped = dependency_checks(tree, files, manifests, issues, exclude, should_stop)
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
        # FP-B64-PROTOBUF: the SC-B64 findings that are protobuf descriptors generated code alone uses, over the
        # whole scan (its files, and what else could read them or remap their loader)
        if any(i.get("rule") == "SC-B64" for i in issues):
            disk = _disk_reader(root, files, manifests, exclude)
            note = b64_descriptor_pass(issues, files, manifests, col["holders"], col["resolvers"],
                                       lambda rel: disk(rel), stopped, package=False)
            if note:
                warnings.append(note)
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
        # LZ-03: what changed while the tree was read was not read (_Root)
        changed = changed_issues(tree)
        issues.extend(changed)
        if merge_issues:
            issues = merge_findings(issues, merge_issues)
        res = build_result(root, files + list(extra_files), issues)
        if collected is not None:
            collected.setdefault("files", []).extend(files)
            collected.setdefault("configs", []).extend(cf["path"] for cf in configs[:checked])
        res["metrics"]["configFiles"] = checked + extra_configs
        res["warnings"] = warnings
        why = ([stopped] if stopped else []) + tree_incomplete(tree)
        if why:
            res.update(incomplete=True, incompleteReason="; ".join(why))
        if shown is not None:
            shown.update(flagged_lines(res["issues"], files + manifests + configs))
        # L1: belt-and-braces — no SECRET-rule issue may reach a report or
        # the baseline fingerprinter with its raw flagged line.
        redact_result(res)
        return res
    finally:
        REDACT_SECRETS = saved_redact


# ---------------- Metrics, ratings, the gate ----------------
# (BR-7 step 4 (a): the engine's, result.rs, for both packages: the counts, the ratings, the gate's conditions and
# the duplication across a project's files; what stays here is the project's path, the time, and asking the engine
# for each file's line metrics, which a project scan has from its own reading)


def _metrics_files(all_files):
    """Each file as the engine's result reads it: [dep, lang, line metrics] (metrics.rs: lines of code, comment lines,
    measured lines, the windows' keys), or the text in their place when the engine could not give them (its
    non-blank lines then count as code: review B3)."""
    own = [k for k, f in enumerate(all_files) if not f.get("dep")]
    answers = {k: all_files[k].get("lineMetrics") for k in own}
    todo = [k for k in own if answers[k] is None]
    for k, got in zip(todo, engine.file_metrics([(all_files[k].get("path"), all_files[k].get("content"),
                                                  all_files[k].get("lang")) for k in todo])):
        answers[k] = got
    rows = []
    for k, f in enumerate(all_files):
        if f.get("dep"):
            rows.append([True, f.get("lang"), ""])
        else:
            got = answers[k]
            rows.append([False, f.get("lang"), list(got) if got is not None else str(f.get("content") or "")])
    return rows


def _finding_rows(issues):
    """What the engine's result reads of each finding: [rule, type, severity, file, line, omitted, omittedType] (a
    Q-CAPPED note's last two: the maintainability rating counts the smells it stands for)."""
    def omitted(i):
        n = i.get("omitted")
        return n if isinstance(n, int) and not isinstance(n, bool) else None
    return [[i["rule"], i["type"], i["sev"], i["file"], i["line"], omitted(i),
             i.get("omittedType") if isinstance(i.get("omittedType"), str) else None] for i in issues]


def compute_metrics(all_files):
    """files, lines of code, comment lines and duplication of a project's own files (the engine's: result.rs), its
    dependencies' left out: the share of measured lines of code in a window of six consecutive ones that occurs twice
    or more across them, and `dupLeftOut`, the lines of code of the languages it does not measure (Go, Rust: N-13)."""
    return _native.call("project_metrics", {"files": _metrics_files(all_files)})


def regrade(res):
    """`res` graded again from its issues, after something changed their severities or types (`--verify-secrets`: a live
    credential is a BLOCKER vulnerability, verifyscan): the order of its issues, the counts, the security and reliability
    ratings, the gate's two conditions on severities and the gate (the engine's: result.rs). The other conditions are
    left as they are."""
    issues = res["issues"]
    got = _native.call("regrade", {"issues": _finding_rows(issues),
                                   "conditions": [[c["label"], c["ok"]] for c in res["conditions"]]})
    issues[:] = [issues[k] for k in got["order"]]
    res["counts"] = got["counts"]
    res["ratings"].update(got["ratings"])
    for cond, now in zip(res["conditions"], got["conditions"]):
        cond["ok"] = now["ok"]
    res["pass"] = got["pass"]
    return res


def build_result(root, files, issues):
    """A scan's result: its issues in their order, the gate and its conditions, the metrics, counts and ratings, the
    supply-chain indicators and cross-file flows, the issues by file (the engine's: result.rs). `issues` is put in
    that order where it is."""
    got = _native.call("result", {"issues": _finding_rows(issues), "files": _metrics_files(files)})
    issues[:] = [issues[k] for k in got["order"]]
    return {"project": _fs_display(os.path.abspath(os.fspath(root))),
            "scannedAt": datetime.datetime.now().isoformat(timespec="seconds"),
            "pass": got["pass"], "conditions": got["conditions"],
            "metrics": got["metrics"], "counts": got["counts"], "ratings": got["ratings"],
            "supplyChain": got["supplyChain"], "crossFile": got["crossFile"],
            "perFile": got["perFile"], "issues": issues}


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
# reorder what the terminal shows — Trojan Source). ESC (0x1b) and BEL
# (0x07) — the two bytes the audit PoC used to forge SGR colors and hijack
# the terminal title — are inside these ranges. The engine maps them, for
# both packages (report.rs, BR-7 step 4 c).
def sanitize_term(s):
    """Neutralize terminal-control characters in a string before printing.

    Hostile package content reaches the terminal via file paths (archive
    member names, walked repo paths), issue messages (X-FLOW source/sink
    paths, install-hook command text), registry metadata and config paths.
    Every C0 control character except newline and tab, plus CR, DEL, the C1
    controls (0x9b is a one-byte CSI, 0x9d an OSC) and the bidi embedding,
    override and isolate controls (Trojan Source), maps to '·' (audit H1). The
    engine's (report.rs, BR-7 step 4 c), as the npm package's sanitizeTerm.

    Applied to every print() that interpolates such a value. Ordering at the
    call sites matters: sanitize the ARGUMENT of c(), never its result —
    sanitizing the result would strip the SGR sequences Lazaret itself emits
    and leave the color wrapper unclosed.
    """
    return _term("text", s)


_TERM_FALLBACK = {"text": re.compile(r"[^\x20-\x7e\t\n]"), "line": re.compile(r"[^\x20-\x7e]")}


def _term(mode, s, **args):
    """The engine's term call; without an engine (its own error printed, the library's path in it) every character
    but printable ASCII (and TAB and LF in "text" mode) is '·'."""
    if not _native.available():
        return _TERM_FALLBACK.get(mode, _TERM_FALLBACK["line"]).sub("·", str(s))
    return _native.call("term", dict(args, mode=mode), str(s))["text"]


def sanitize_term_line(s):
    """sanitize_term for a value printed inside one line of output — a
    path, a link target, a finding's message: line breaks (\\n, U+2028,
    U+2029) become '·' too, so the value cannot start a line of its own
    (review: a file named `zz\\n\\n  Quality gate:  PASSED \\n::notice::…\\n  x.py`
    printed a fake "PASSED" line and a GitHub workflow command at column 0).
    The engine's (report.rs)."""
    return _term("line", s)

# Rules whose flagged line reveals a credential. The flagged LINE is redacted
# in every persistent artifact by default (see mk_issue and redact_result — audit
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
    (esp. packages), so ANSI/control characters that could rewrite the
    terminal — ESC, CR, BS, BEL, NUL, C1 controls, bidi controls and anything
    else str.isprintable() rejects — become '·'. Tabs become spaces, the line
    is trimmed and truncated with an ellipsis. The engine's (report.rs)."""
    return _term("excerpt", text, width=EXCERPT_WIDTH if width is None else width)

SHOW_SECRETS_NOT_A_TERMINAL = ("note: --show-secrets shows credentials on a terminal only, and the output is not one: "
                               "they stay redacted")


def show_secrets_on(asked, stream=None):
    """--show-secrets: True when it was asked for and `stream` (stdout) is a
    terminal; asked for elsewhere (a pipe, a file, a CI log), a note on
    stderr says the credentials stay redacted."""
    if not asked:
        return False
    stream = sys.stdout if stream is None else stream
    try:
        tty = bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        tty = False
    if not tty:
        print(SHOW_SECRETS_NOT_A_TERMINAL, file=sys.stderr)
    return tty


def flagged_lines(issues, entries):
    """{(file, line): that line of the file as read, unredacted} for each of
    `issues` in a file of `entries` ([{path, content, lang?}]: its scan lines,
    source_lines): what --show-secrets prints in place of the redacted
    excerpt. Kept apart from the result, for the terminal alone: it never
    reaches a report, the baseline, the registry's store or an MCP answer."""
    by_path = {e["path"]: e for e in entries if isinstance(e.get("content"), str)}
    lines_of, out = {}, {}
    for i in issues:
        path, ln = i.get("file"), i.get("line")
        e = by_path.get(path)
        if e is None or not isinstance(ln, int) or ln < 1:
            continue
        lines = lines_of.get(path)
        if lines is None:
            lines = lines_of[path] = source_lines(e["content"], e.get("lang"))
        if ln <= len(lines):
            out[(path, ln)] = lines[ln - 1]
    return out


def issue_excerpt(issue, width=None, shown=None):
    """Sanitized excerpt of an issue's flagged source line ('' if unavailable).
    `shown` (--show-secrets: flagged_lines' {(file, line): text}) gives the
    line as read, unredacted, where it has it: for the terminal alone. A
    secret rule's line is "[redacted]" (unless --no-redact-secrets). The
    engine's (report.rs)."""
    raw = shown.get((issue.get("file"), issue.get("line"))) if shown else None
    return _native.call("issue_excerpt", {"issue": issue, "width": EXCERPT_WIDTH if width is None else width,
                                          "redact": bool(REDACT_SECRETS), "shown": raw})["text"]

def redact_result(res):
    """Defensive sweep over a scan result: no credential may survive into a
    report artifact.

    Two layers (audit L1):
    * Any SECRET-rule issue still carrying an unredacted flagged line
      (embedded from an unpatched engine path) gets the placeholder.
    * EVERY issue's snippet — secret rule or not — has its context lines
      swept with the line-level secret matchers: a snippet around an
      os.system finding routinely contains the file's actual credentials on
      adjacent lines, and those would otherwise ship to the JSON/HTML
      report verbatim. Only matched substrings are replaced; surrounding
      code stays readable.

    mk_issue is the primary fix; this is the belt-and-braces pass so a leak
    requires BOTH mk_issue to miss AND this sweep to miss. The sweep also
    clips every snippet line to SNIPPET_MAX characters (issues built outside
    mk_issue, e.g. by the flow engine, get the same size bound). The engine
    sweeps (redact.rs redact_issues), the whole result in one call."""
    issues = [i for i in res.get("issues", []) if isinstance(i, dict)]
    if not issues:
        return res
    rows = []
    for i in issues:
        snip = i.get("snippet")
        rows.append([i.get("rule"), i.get("line"), i.get("snipStart"), snip if isinstance(snip, list) else None,
                     *(i.get(k) if isinstance(i.get(k), str) else None for k in ("msg", "cmd"))])
    got = _native.call("redact_issues", {"issues": rows, "redact": bool(REDACT_SECRETS)})["issues"]
    _apply_redaction(issues, got)
    return res

def report_text_chunks(res, quiet, shown=None, color=False):
    """The terminal summary in pieces (the engine's: report.rs): the gate, the ratings and the counts, then (unless
    `quiet`) the findings by file, each with its flagged line (`shown`: --show-secrets' lines as read)."""
    issues = res.get("issues") or []
    doc = dict(res)
    doc["issues"] = []
    frame = _native.call("text_frame", {"doc": doc, "count": len(issues), "quiet": bool(quiet), "color": color})
    yield frame["head"]
    if not quiet and issues:
        order = _native.call("text_order", {"rows": [[i.get("file"), i.get("sev"), i.get("line")] for i in issues]})
        ordered = [issues[k] for k in order["order"]]
        last = None
        for k in range(0, len(ordered), lazaret_report.BATCH):
            batch = ordered[k:k + lazaret_report.BATCH]
            got = _native.call("text_items", {
                "issues": batch, "file": last, "color": color, "width": EXCERPT_WIDTH, "redact": bool(REDACT_SECRETS),
                "shown": [shown.get((i.get("file"), i.get("line"))) if shown else None for i in batch]})
            last = got["file"]
            yield got["text"]
    yield frame["tail"]


def print_report(res, quiet, shown=None):
    """The terminal summary, colored on a terminal."""
    for piece in report_text_chunks(res, quiet, shown, _stdout_is_tty()):
        print(piece, end="")


# ---------------- HTML report ----------------
def html_chunks(res, marked=False, windows=os.name == "nt"):
    """The HTML report in pieces (the engine's: report.rs): the gate, the cards, the findings by file, then every
    finding with its snippet; `marked`: with the Lazaret provenance meta tag in its <head>, so report files
    produced by this tool are recognizable and can be safely re-written by a later run. `windows`: the OS whose
    path rules the project's name is read by (this one's)."""
    marker = [lazaret_report.ENGINE_MARKER, lazaret_report.ENGINE_VERSION] if marked else None
    return lazaret_report.framed(
        "html_frame", res, {"windows": windows, "marker": marker},
        lambda batch, first: _native.call("html_items", {"issues": batch, "first": first})["text"])


def html_report(res):
    return "".join(html_chunks(res))


def _html_report_marked(res):
    return "".join(html_chunks(res, marked=True))


# ---------------- SARIF output ----------------
def sarif_chunks(res, root=None, marked=True, windows=os.name == "nt"):
    """The SARIF 2.1.0 log of a scan result in pieces (the engine's: report.rs): the rules in the order of their
    first finding, each finding's location below %SRCROOT%, the scan root (`root`; res['project'] by default).
    `marked`: with the marker in a top-level property bag, first; `windows`: the OS whose path rules the paths are
    read by (this one's)."""
    # L1: the result has been swept by redact_result already; the log embeds the findings' msg/why/fix, so it is
    # swept again here, so that a caller that skips the main() pass cannot ship an unredacted result.
    redact_result(res)
    issues = [i for i in res.get("issues", []) if isinstance(i, dict)]
    rules, known = [], []
    for k in range(0, len(issues), lazaret_report.BATCH):
        got = _native.call("sarif_rules", {"issues": issues[k:k + lazaret_report.BATCH], "known": known})["rules"]
        rules += got
        known += [r["id"] for r in got]
    frame = _native.call("sarif_frame", {
        "rules": rules,
        "root": (ntpath if windows else posixpath).abspath(os.fspath(res["project"] if root is None else root)),
        "windows": windows, "version": _lazaret_pkg.__version__, "source": res.get("source"),
        "marker": [lazaret_report.ENGINE_MARKER, lazaret_report.ENGINE_VERSION] if marked else None,
        "count": len(issues)})
    yield frame["head"]
    for k in range(0, len(issues), lazaret_report.BATCH):
        yield _native.call("sarif_items", {"issues": issues[k:k + lazaret_report.BATCH], "rules": known,
                                           "windows": windows, "first": k == 0})["text"]
    yield frame["tail"]


def sarif_report(res, root=None):
    """SARIF 2.1.0 log for a scan result, as a dict (sarif_chunks' text, without the marker)."""
    return json.loads("".join(sarif_chunks(res, root, marked=False)))


# ---------------- Baseline (new-code focus) ----------------
def fingerprint(issue):
    # rule | path with forward slashes (portable across OSes) | stripped flagged line: the engine's (baseline.rs),
    # which the report writer signs when $LAZARET_BASELINE_KEY is set
    return lazaret_report.fingerprint(issue)
# NOTE: redaction (audit L1) happens at mk_issue time, BEFORE this
# fingerprint is computed — the placeholder text is deterministic for a
# given (rule, secret length), so same-engine baselines still match; a
# pre-redaction-era baseline (with raw secret lines) simply won't match a
# secret fingerprint any more, and those issues surface as new — the safe
# direction for a security tool.


def apply_baseline(res, baseline_path, scan_root=None):
    """Mark res["issues"] new/not-new against a previous JSON report (the engine's: baseline.rs).

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
    An untrusted baseline counts every finding as new (fail closed).

    N-15: a signed baseline that verifies accepts the findings it holds that no marker can accept (SC-*, X-*): each
    gets "accepted", the result "acceptedIssues", and the gate's conditions on findings are judged without them. What
    stays here: whether the file is one of our reports, where it is, its bytes, and printing the warnings."""
    issues = res["issues"]
    args = {"path": str(baseline_path), "ours": lazaret_report.is_our_report(baseline_path, "json"),
            "inside": scan_root is not None and lazaret_report.path_is_inside(baseline_path, scan_root),
            "key": lazaret_report.baseline_key(), "fingerprints": lazaret_report.fingerprints(issues),
            "issues": _finding_rows(issues),
            "conditions": [[c["label"], c["ok"]] for c in res.get("conditions") or []]}
    data = ""
    if args["ours"]:
        try:
            with open(baseline_path, "rb") as fh:
                data = fh.read().decode("latin-1")
        except (OSError, MemoryError) as exc:
            args["error"] = str(exc)
    got = _native.call("baseline_apply", args, data)
    for line in got["warnings"]:
        print(line, file=sys.stderr)
    if "new" in got:
        for i, new in zip(issues, got["new"]):
            i["new"] = new
        res["newIssues"] = got["newIssues"]
    if got.get("untrusted"):
        res["baselineUntrusted"] = True
    if "accepted" in got:
        for i, accepted in zip(issues, got["accepted"]):
            if accepted:
                i["accepted"] = True
        res["acceptedIssues"] = got["acceptedIssues"]
        for cond, now in zip(res["conditions"], got["conditions"]):
            cond["ok"] = now["ok"]
        res["pass"] = got["pass"]


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


#: `lazaret --help`'s examples (the other forms are the top-level command's: lazaret._cli)
SCAN_EXAMPLES = """examples:
  lazaret .                                 scan this project: lazaret-report.json and .html here
  lazaret . --ci                            exit 1 when the quality gate fails (CI)
  lazaret . --deps                          also read node_modules, venv and vendor (supply chain)
  lazaret . --out-dir reports --no-html     the JSON report alone, in reports/
  lazaret . --sarif lazaret.sarif           a SARIF report too, for GitHub code scanning
  lazaret . --baseline last-report.json     mark what is new since that report
  lazaret github:owner/repo                 a GitHub repository at its default branch's head
  lazaret github:owner/repo@v1.2.0          at a tag, branch or commit (gitlab:group/project too)
  lazaret extension.vsix                    a VS Code extension (--extensions: the installed ones)
  lazaret hook                              the staged files: the commit-time gate
  lazaret guard npm install left-pad        what a package manager is about to install
  lazaret-registry --help                   registry releases, watching, new GitHub repositories
"""

def main(argv=None, source=None, twins=(), overlaid=None):
    """`lazaret` console entry point. argv defaults to sys.argv[1:]. Any
    uncaught exception becomes `error: internal: …` with exit 5 (review item
    4: a non-UTF-8 file name crashed the HTML writer with a traceback and
    exit 1 — indistinguishable from a failed gate). A closed stdout never
    stops the scan (see _PipeSafeStdout). `source`: the source block of a
    `github:` or `gitlab:` scan (registry/sourcescan.py; set_source);
    `twins`, `overlaid`: its checkout's twin trees and the files each was
    given of the commit's others (scan_twins)."""
    configure_stdio()
    real_stdout = sys.stdout
    guard = _PipeSafeStdout(real_stdout) if real_stdout is not None else None
    if guard is not None:
        sys.stdout = guard
    try:
        return _main(argv, source, twins, overlaid)
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


def merge_findings(issues, more):
    """`issues` and `more`, the findings of one commit read in two trees (a repository checkout's root and its twin
    trees: scan_twins), each finding once: those of a (rule, file, line) come from the tree whose finding there is the
    most severe, the first's on a tie. -> the merged list."""
    def key(issue):
        return issue.get("rule"), issue.get("file"), issue.get("line")

    def worst(group):
        return min(SEV_ORDER.get(i.get("sev"), len(SEV_ORDER)) for i in group)
    have, extra = {}, {}
    for n, issue in enumerate(issues):
        have.setdefault(key(issue), []).append(n)
    for issue in more:
        extra.setdefault(key(issue), []).append(issue)
    drop, add = set(), []
    for k, group in extra.items():
        if k not in have:
            add.extend(group)
        elif worst(group) < worst([issues[n] for n in have[k]]):
            drop.update(have[k])
            add.extend(group)
    return [issue for n, issue in enumerate(issues) if n not in drop] + add


def scan_twins(twins, exclude=(), include_deps=False, redact_secrets=True, shown=None, overlaid=None):
    """The scans of a repository checkout's twin trees (registry/sources.py, MAC-TESTS): the paths of the commit that
    the disk held as one name with another path, each tree holding them at their paths in the commit and scanned as
    its own project, so that every rule that goes by path (a workflow, a package.json, an agent's settings) reads them
    as the commit's own. Each tree was also given the commit's other files that it could hold (`overlaid`: {tree: those
    paths}), so that what a rule reads across files is there: a finding in one of those is the root's again, or found
    with more beside it, and merge_findings keeps it once. -> (the trees' findings, merged, at their paths in the
    commit; {path: the tree its own file is in}; why a scan was not whole, [str]; how many trees held something to
    read; what the trees hold of their own for the metrics, {"files": [file], "configs": how many config files}). A
    tree holding nothing Lazaret reads adds nothing."""
    issues, where, why, read, own = [], {}, [], 0, {"files": [], "configs": 0}
    for twin in twins:
        given, collected = (overlaid or {}).get(twin, set()), {}
        try:
            got = scan_project(twin, exclude, include_deps=include_deps, redact_secrets=redact_secrets, shown=shown,
                               collected=collected)
        except ScanTargetError:
            continue
        read += 1
        own["files"].extend(f for f in collected.get("files", ()) if f.get("path") not in given)
        own["configs"] += sum(1 for path in collected.get("configs", ()) if path not in given)
        for issue in got["issues"]:
            if isinstance(issue.get("file"), str) and issue["file"] not in given:
                where.setdefault(issue["file"], twin)
        issues = merge_findings(issues, got["issues"])
        if got.get("incomplete"):
            why.append(got.get("incompleteReason") or "the scan stopped early")
    return issues, where, why, read, own


def _main(argv=None, source=None, twins=(), overlaid=None):
    global REDACT_SECRETS, EXCERPT_WIDTH, SOURCE_SIZE_CAP
    ap = argparse.ArgumentParser(prog="lazaret", description="Lazaret — security & quality scanner for Python/JS projects.",
                                 epilog=SCAN_EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
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
                    help="Previous JSON report; issues not in it are marked new. Signed "
                         "($LAZARET_BASELINE_KEY), it accepts the SC-* and X-* findings it "
                         "holds: the gate does not count them")
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
    ap.add_argument("--show-secrets", action="store_true",
                    help="Show each finding's flagged line unredacted on the terminal (only when "
                         "the output is a terminal). The reports and the baseline stay redacted.")
    ap.add_argument("--verify-secrets", action="store_true",
                    help="After the scan, ask each secret's provider whether it is live (GitHub, Slack, Stripe, npm, "
                         "OpenAI and Anthropic tokens, AWS key pairs): each credential goes to its own provider "
                         "alone, over HTTPS. A live one is a BLOCKER. Off by default.")
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
    shown = {} if show_secrets_on(args.show_secrets) else None      # (the terminal's alone: never in the result)
    twin_issues, twin_files, twin_why, twins_read, twin_own = scan_twins(
        twins, args.exclude, include_deps=args.deps, redact_secrets=REDACT_SECRETS, shown=shown, overlaid=overlaid)
    try:
        res = scan_project(args.directory, args.exclude, include_deps=args.deps,
                           redact_secrets=REDACT_SECRETS, extra_issues=taint_notes, shown=shown,
                           allow_empty=twins_read > 0, merge_issues=twin_issues, extra_files=twin_own["files"],
                           extra_configs=twin_own["configs"])
    except ScanTargetError as exc:
        print(f"error: {sanitize_term_line(exc)}", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    if twin_why:
        why = "; ".join(twin_why)
        res["incomplete"] = True
        res["incompleteReason"] = f"{res['incompleteReason']}; {why}" if res.get("incompleteReason") else why
    for warning in res.get("warnings", ()):
        # audit H1: a warning can carry content parsed out of scanned files
        # (the flow engine raises on hostile input); sanitize it.
        print(f"warning: {sanitize_term_line(warning)}", file=sys.stderr)
    if source is not None:
        set_source(res, source)
    if args.verify_secrets:
        # V-1 (John's decision 4): only when asked; each credential to its own provider, after a note that says where
        from lazaret.scanner import verifyscan
        verifyscan.verify_findings(args.directory, res, roots=twin_files)

    # ---- SEAM (flow-sca): baseline block ---------------------------------
    if args.baseline:
        apply_baseline(res, args.baseline, scan_root=args.directory)
    print_report(res, args.quiet, shown)

    # Writes are validated (writability + no-clobber) before the scan; each
    # write re-checks and is atomic (temp file + rename), so a mid-write
    # crash never leaves a half-written report behind.
    try:
        if args.sarif:
            sarif_path = lazaret_report.write_report(
                paths["sarif"],
                lambda: sarif_chunks(res, root=args.directory),
                kind="sarif", strict=args.force_overwrite)
            print(f"  SARIF report: {sanitize_term_line(sarif_path)}")
        if not args.no_json:
            json_path = lazaret_report.write_report(
                paths["json"],
                lambda: lazaret_report.json_chunks(res),
                kind="json", strict=args.force_overwrite)
            print(f"  JSON report: {sanitize_term_line(json_path)}")
        if not args.no_html:
            html_path = lazaret_report.write_report(
                paths["html"],
                lambda: html_chunks(res, marked=True),
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


_PACK_SETS = {"HARDENING_RULES": "HARDENING_RULES"}


def __getattr__(name):
    """The rule pack's sets core still names (HARDENING_RULES), read from the engine when first asked for."""
    if name in _PACK_SETS:
        value = frozenset(engine.pack_value(_PACK_SETS[name]))
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    main()
