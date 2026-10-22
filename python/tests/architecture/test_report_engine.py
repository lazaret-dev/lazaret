"""Reports are the engine's (BR-7 step 4 (c), 0.1.9).

core made a scan's JSON, SARIF, HTML and terminal forms (reports.json_renderer, sarif_report and
reports.sarif_renderer, html_report and _html_report_marked, print_report) and the terminal's sanitizers
(sanitize_term, sanitize_term_line, safe_excerpt, issue_excerpt), and the npm package its own (its JSON
JSON.stringify's, with no \\u escapes; its HTML page that JSON in a <pre>; its terminal summary a shorter one). The
engine makes them for both (rust/crates/lazaret-engine/src/report.rs: the term, issue_excerpt, report_json,
report_items, sarif_*, html_* and text_* calls), as core made them, a frame and its findings in batches.

Held here to core's code as it was (below: what this replaced, word for word but its docstrings, with what it read
of the process as arguments: whether stdout is a terminal, and the OS's path rules, so the Windows forms are held
too), on generated results whose every text is hostile (controls, C1 and bidi characters, line separators, HTML's
special characters, lone surrogates, astral characters, names a JavaScript object reorders); and the npm package's
renderers on the WebAssembly build to the library's, byte for byte. All content is inert.
"""
import contextlib
import html as html_mod
import io
import json
import ntpath
import os
import pathlib
import posixpath
import random
import unittest
import urllib.parse as _urlparse

import lazaret as _lazaret_pkg
from lazaret.scanner import _native, core
from lazaret.scanner import reports as lazaret_report
from lazaret.scanner.core import redact_result
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

if not _native.available():
    raise unittest.SkipTest(f"the reports are the native engine's ({_native.load_error()})")

# ---------------------------------------------------------------- core's code as it was (56e2c18)

SEV_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
TYPE_LABEL = {"VULN": "Vulnerability", "HOTSPOT": "Security Hotspot",
              "BUG": "Bug", "SMELL": "Code Smell"}
SEV_COLOR = {"BLOCKER": "41;97", "CRITICAL": "31", "MAJOR": "33", "MINOR": "36", "INFO": "34"}
SECRET_RULES = {"S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"}
REDACT_SECRETS = True
EXCERPT_WIDTH = 100
#: what core read of the process: is stdout a terminal (c), and the OS's path rules (os.path, pathlib.Path)
COLOR = False
PATH, PURE = posixpath, pathlib.PurePosixPath


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else str(s)


def _safe_text(s):
    s = str(s)
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "backslashreplace").decode("utf-8")


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
    return str(s).translate(_SANITIZE_TERM_TAB)


#: Line breaks sanitize_term keeps (\n) or does not know (U+2028, U+2029);
#: every other line break (\r, \v, \f, \x1c-\x1e, \x85) is a control
#: character it already maps.
_LINE_BREAKS_TAB = str.maketrans({"\n": "·", "\u2028": "·", "\u2029": "·"})


def sanitize_term_line(s):
    return str(s).translate(_SANITIZE_TERM_TAB).translate(_LINE_BREAKS_TAB)

def safe_excerpt(text, width=None):
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

def issue_excerpt(issue, width=None, shown=None):
    raw = shown.get((issue.get("file"), issue.get("line"))) if shown else None
    if isinstance(raw, str):
        return safe_excerpt(raw, width)
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

def verification_line(v):
    cred, found = v.get("credentials", {}), v.get("findings", {})
    asked = sum(cred.get(k, 0) for k in ("live", "rejected", "unknown"))
    text = (f"Secrets verified  {cred.get('live', 0)} live, {cred.get('rejected', 0)} rejected, {cred.get('unknown', 0)} unknown "
            f"(of {asked} asked about)")
    if found.get("notVerified"):
        n = found["notVerified"]
        text += f"; {n} secret finding{'s' if n != 1 else ''} no provider can be asked about"
    return text


def print_report(res, quiet, shown=None):
    m, ct, rt = res["metrics"], res["counts"], res["ratings"]
    print()
    print(c("1", f"Lazaret scan — {sanitize_term_line(res['project'])}"))
    configs = f" · {m['configFiles']} config files" if m.get("configFiles") else ""
    left = f" ({m['dupLeftOut']} lines of Go and Rust not measured)" if m.get("dupLeftOut") else ""
    print(f"  {m['files']} files · {m['ncloc']} lines of code · {m['dupPct']}% duplication{left}{configs}")
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
    if isinstance(res.get("verification"), dict):
        print(f"  {verification_line(res['verification'])}")
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
            ex = issue_excerpt(i, shown=shown)
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
    dup_left = f" ({m['dupLeftOut']} lines of Go and Rust not measured)" if m.get("dupLeftOut") else ""
    cards = f"""
<div class="card"><div class="num">{ct['VULN']}{rating_badge(rt['security'])}</div><div class="lbl">Vulnerabilities · Security</div></div>
<div class="card"><div class="num">{ct['HOTSPOT']}</div><div class="lbl">Security Hotspots</div></div>
<div class="card"><div class="num">{ct['BUG']}{rating_badge(rt['reliability'])}</div><div class="lbl">Bugs · Reliability</div></div>
<div class="card"><div class="num">{ct['SMELL']}{rating_badge(rt['maintainability'])}</div><div class="lbl">Code Smells · Maintainability</div></div>
<div class="card"><div class="num">{m['dupPct']}%</div><div class="lbl">Duplication{dup_left}</div></div>
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
    verified = (f'<p class="verified">{esc(verification_line(res["verification"]))}</p>'
                if isinstance(res.get("verification"), dict) else "")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lazaret Report — {esc(PATH.basename(res['project']))}</title>
<style>{HTML_CSS}</style></head><body>
<header><div class="logo">Laza<span>ret</span> · Project Report</div>
<div class="meta">{esc(res['project'])} · scanned {esc(res['scannedAt'])}</div></header>
<div class="wrap">
<div class="panel"><div class="gate"><div class="gate-badge {gate_cls}">{gate_txt}</div>{conds}</div>
<div class="cards">{cards}</div>{verified}</div>
<div class="panel"><h2>Issues by file</h2>{file_table}</div>
<div class="panel"><h2>All issues ({len(res['issues'])})</h2>{issues_html}</div>
</div>
<footer>Generated by Lazaret CLI. Pattern- and heuristic-based static analysis — not a substitute for a full security audit.</footer>
</body></html>"""


# ---------------- SARIF output ----------------
SARIF_LEVEL = {"BLOCKER": "error", "CRITICAL": "error", "MAJOR": "warning",
               "MINOR": "note", "INFO": "note"}

def _html_report_marked(res):
    return html_report(res).replace(
        '<meta name="viewport"',
        lazaret_report.HTML_ENGINE_MARKER + '\n<meta name="viewport"',
        1)

#: SARIF run-level base for every repo-relative artifactLocation.
SARIF_SRCROOT = "%SRCROOT%"
LAZARET_INFORMATION_URI = "https://lazaret.dev"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def sarif_uri(path):
    p = _safe_text(path)
    if PATH.isabs(p):
        return PURE(p).as_uri(), None
    if PATH.sep != "/":
        p = p.replace(PATH.sep, "/")
    return _urlparse.quote(p, safe="/"), SARIF_SRCROOT


def _root_uri(root):
    uri = PURE(os.fspath(root)).as_uri()
    return uri if uri.endswith("/") else uri + "/"


def sarif_report(res, root=None):
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
        result = {
            "ruleId": i["rule"],
            "ruleIndex": rule_index[i["rule"]],
            "level": SARIF_LEVEL[i["sev"]],
            "message": {"text": i["msg"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": loc,
                "region": {"startLine": line}}}]}
        if isinstance(i.get("verified"), dict):
            result["properties"] = {"verified": dict(i["verified"])}       # (--verify-secrets: no part of the credential)
        results.append(result)
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


def mark_result(res):
    out = {lazaret_report.ENGINE_MARKER: lazaret_report.ENGINE_VERSION}
    out.update(res)
    return out


def ref_json_renderer(res):
    return json.dumps(mark_result(res), indent=2)


def ref_sarif_renderer(sarif):
    out = {"properties": {lazaret_report.ENGINE_MARKER: lazaret_report.ENGINE_VERSION}}
    out.update(sarif)
    return json.dumps(out, indent=2)


def ref_text(res, quiet, shown, color):
    global COLOR
    COLOR, buf = color, io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            print_report(res, quiet, shown)
    finally:
        COLOR = False
    return buf.getvalue()


@contextlib.contextmanager
def os_rules(windows):
    global PATH, PURE
    PATH, PURE = (ntpath, pathlib.PureWindowsPath) if windows else (posixpath, pathlib.PurePosixPath)
    try:
        yield
    finally:
        PATH, PURE = posixpath, pathlib.PurePosixPath


# ---------------------------------------------------------------- generated results

#: every kind of character the forms treat apart: controls kept and mapped, C1 and bidi controls, line
#: separators, HTML's and URIs' special characters, Latin-1, CJK, an astral character, combining and format
#: characters, lone surrogates (all assigned since Unicode 13: the same on every Python). Low ones only, at random:
#: a str holding a valid surrogate pair as two characters (only a "surrogatepass" decode makes one) reaches the
#: engine as the character they encode, as json.loads reads them.
ALPHABET = (list("abcdefghij XYZ019_-./") + ["\t", "\n", "\r", "\x1b", "\x07", "\x00", "\x7f", "\x85", "\x9b",
            "\u202e", "\u2066", "\u2028", "\u2029", "\u00a0", "\u00e9", "\u4e2d", "\U0001f600", "\udc80", "\udcff",
            "&", "<", ">", '"', "'", "#", "%", "\\", "~", "\u0301", "\ufeff", "\u200b", "\u2026", "·"])
RULES = ["S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY", "S-EVAL-PY", "SC-PTH-EXEC", "Q-CAPPED", "B-EQEQ", "X-FLOW"]
#: file names: relative, nested, a JavaScript object's integer-like keys, absolute, Windows', hostile
FILES = ["a.py", "src/b c.js", "7", "10", "0", "caf\u00e9.py", "/abs/x y.py", "C:\\w\\x.py", "\\\\srv\\share\\y.py",
         "sub\\z.py", "d#1%2.py", "z\u4e2d/q.sql", "e\x1b[2J.py", "n\nl.py", "s\ud800.py"]
PROJECTS = ["/home/u/proj", "/tmp/a b/caf\u00e9", "/x/\x1b[2Jp\u2028q", "/r/&<>\"'"]
WIN_PROJECTS = ["C:\\Users\\u\\proj", "D:\\a b\\caf\u00e9", "\\\\srv\\share\\p"]


def text(rng, n):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, n)))


def issue(rng):
    line = rng.randint(1, 60)
    start = max(1, line - rng.randint(0, 3))
    i = {"rule": rng.choice(RULES), "name": text(rng, 12), "type": rng.choice(list(TYPE_LABEL)),
         "sev": rng.choice(list(SEV_ORDER)), "file": rng.choice(FILES), "line": line, "msg": text(rng, 40),
         "why": text(rng, 30), "fix": text(rng, 20), "ref": text(rng, 10),
         "snippet": [text(rng, rng.choice([5, 60, 300])) for _ in range(rng.randint(0, 7))], "snipStart": start}
    if rng.random() < 0.1:
        i["verified"] = {"provider": "example", "live": rng.random() < 0.5}
    if rng.random() < 0.1:
        i["omitted"], i["omittedType"] = rng.randint(1, 9), "SMELL"
    if rng.random() < 0.1:
        i["cmd"] = text(rng, 20)
    return i


def result(rng, n, projects=PROJECTS):
    issues = [issue(rng) for _ in range(n)]
    per_file = {}
    for i in issues:
        per_file[i["file"]] = per_file.get(i["file"], 0) + 1
    res = {"project": rng.choice(projects), "scannedAt": "2026-10-16T08:00:00", "pass": rng.random() < 0.5,
           "conditions": [{"label": text(rng, 20), "ok": rng.random() < 0.5} for _ in range(rng.randint(0, 6))],
           "metrics": {"files": rng.randint(0, 99), "depFiles": rng.choice([0, 3]), "ncloc": rng.randint(0, 9999),
                       "comments": rng.randint(0, 99), "dupPct": rng.choice([0.0, 12.5, 3.3, 100.0, 1e-05, 0.1]),
                       "dupLeftOut": rng.choice([0, 20]), "configFiles": rng.choice([0, 2])},
           "counts": {t: rng.randint(0, 12000) for t in TYPE_LABEL},
           "ratings": {k: rng.choice("ABCDE") for k in ("security", "reliability", "maintainability")},
           "supplyChain": rng.choice([0, 3, 12345]), "crossFile": rng.choice([0, 2]), "perFile": per_file,
           "issues": issues}
    if rng.random() < 0.3:
        res["newIssues"] = rng.randint(0, 9)
    if rng.random() < 0.3:
        res["verification"] = {"credentials": {"live": rng.randint(0, 3), "rejected": 0, "unknown": rng.randint(0, 2)},
                               "findings": {"notVerified": rng.choice([0, 1, 3])}}
    if rng.random() < 0.2:
        res["source"] = {"uri": "https://example.invalid/r", "commit": "abc123"}
    if rng.random() < 0.2:
        res["warnings"] = [text(rng, 10)]
    return redact_result(res)            # (as every caller has it: the SARIF form sweeps it again)


def results(seed, count, projects=PROJECTS):
    rng = random.Random(seed)
    out = [result(rng, rng.choice([0, 0, 1, 3, 40]), projects) for _ in range(count)]
    out.append(result(rng, 4500, projects))                         # three batches of findings
    return out


def shown_lines(rng, res):
    return {(i["file"], i["line"]): text(rng, 50) for i in res["issues"] if rng.random() < 0.3}


class FormTests(unittest.TestCase):
    """The engine's forms (core's calls of it) against core's code as it was."""

    @classmethod
    def setUpClass(cls):
        cls.results = results(5, 200)

    def test_json(self):
        for k, res in enumerate(self.results):
            with self.subTest(k):
                self.assertEqual(lazaret_report.json_renderer(res), ref_json_renderer(res))
        doc = {"version": "2.1.0", "runs": [{"results": [{"x": 1.5}]}], "issues": "not a list"}
        self.assertEqual(lazaret_report.sarif_renderer(doc), ref_sarif_renderer(doc))
        self.assertEqual(lazaret_report.json_renderer({"pass": True}), ref_json_renderer({"pass": True}))

    def test_sarif(self):
        for windows, res_set in ((False, self.results), (True, results(6, 60, WIN_PROJECTS))):
            for k, res in enumerate(res_set):
                with self.subTest(windows=windows, k=k), os_rules(windows):
                    root = res["project"]
                    self.assertEqual("".join(core.sarif_chunks(res, root, windows=windows)),
                                     ref_sarif_renderer(sarif_report(res, root)))
                    self.assertEqual(core.sarif_report(res, root) if not windows else sarif_report(res, root),
                                     sarif_report(res, root))

    def test_html(self):
        for windows, res_set in ((False, self.results), (True, results(7, 60, WIN_PROJECTS))):
            for k, res in enumerate(res_set):
                with self.subTest(windows=windows, k=k), os_rules(windows):
                    self.assertEqual("".join(core.html_chunks(res, windows=windows)), html_report(res))
                    self.assertEqual("".join(core.html_chunks(res, marked=True, windows=windows)),
                                     _html_report_marked(res))

    def test_terminal(self):
        rng = random.Random(8)
        for k, res in enumerate(self.results):
            shown = shown_lines(rng, res) if k % 2 else None
            for quiet in (False, True):
                for color in (False, True):
                    with self.subTest(k=k, quiet=quiet, color=color):
                        self.assertEqual("".join(core.report_text_chunks(res, quiet, shown, color)),
                                         ref_text(res, quiet, shown, color))

    def test_sanitizers(self):
        rng = random.Random(9)
        cases = ([text(rng, 80) for _ in range(3000)] + [chr(n) for n in range(0x300)]
                 + ["", "   ", "\t\t x \t", "x\ud800", "\ud800 y", "\U000100ff"])
        for s in cases:
            with self.subTest(s=s):
                self.assertEqual(core.sanitize_term(s), sanitize_term(s))
                self.assertEqual(core.sanitize_term_line(s), sanitize_term_line(s))
                for width in (100, 5, 1, 0, -3):
                    self.assertEqual(core.safe_excerpt(s, width), safe_excerpt(s, width))

    def test_excerpts(self):
        global REDACT_SECRETS
        rng = random.Random(10)
        for k, res in enumerate(self.results[:60]):
            shown = shown_lines(rng, res)
            for i in res["issues"]:
                for redact in (True, False):
                    saved, core.REDACT_SECRETS, REDACT_SECRETS = core.REDACT_SECRETS, redact, redact
                    try:
                        with self.subTest(k=k, redact=redact):
                            for width in (100, 7):
                                self.assertEqual(core.issue_excerpt(i, width, shown), issue_excerpt(i, width, shown))
                                self.assertEqual(core.issue_excerpt(i, width), issue_excerpt(i, width))
                    finally:
                        core.REDACT_SECRETS, REDACT_SECRETS = saved, True

    def test_the_comparison_can_fail(self):
        """Control: a result whose dupPct is an int is written as a float (as core's dict never held one), and a
        renderer that dropped a finding would be caught."""
        res = dict(self.results[0], metrics=dict(self.results[0]["metrics"], dupPct=12))
        self.assertIn('"dupPct": 12.0', lazaret_report.json_renderer(res))
        res = next(r for r in self.results if r["issues"])
        fewer = dict(res, issues=res["issues"][1:])
        self.assertNotEqual(lazaret_report.json_renderer(fewer), ref_json_renderer(res))


#: the npm package's forms of each result, on the WebAssembly build (js/src/report.js)
NODE_FORMS = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const r = await import(pathToFileURL(process.argv[1]).href);
const results = JSON.parse(readFileSync(0, "utf8"));
const lines = (res, opts) => { const got = []; r.printReport(res, { out: (l) => got.push(l), ...opts }); return got.join("\\n") + "\\n"; };
process.stdout.write(JSON.stringify(results.map((res) => ({
  json: r.jsonRenderer(res), html: r.htmlRenderer(res), sarif: r.sarifRenderer(res, res.project),
  text: lines(res, {}), color: lines(res, { color: true }), quiet: lines(res, { quiet: true }),
}))));
"""


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class NpmTests(unittest.TestCase):
    def test_the_npm_forms_are_the_python_packages(self):
        """Through JSON, as the npm package holds a result: a float such as 100.0 is 100, an object puts "7" and "10"
        before "a.py"; the forms are the same bytes all the same."""
        import subprocess
        res_set = results(11, 40)
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", NODE_FORMS,
                            os.path.join(_support.REPO_ROOT, "js", "src", "report.js")], input=json.dumps(res_set),
                           capture_output=True, encoding="utf-8", errors="surrogatepass", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        forms = json.loads(p.stdout)
        self.assertEqual(len(forms), len(res_set))
        for k, (res, got) in enumerate(zip(res_set, forms)):
            with self.subTest(k):
                self.assertEqual(got["json"], lazaret_report.json_renderer(res))
                self.assertEqual(got["html"], core._html_report_marked(res))
                self.assertEqual(got["sarif"], "".join(core.sarif_chunks(res, res["project"])))
                self.assertEqual(got["text"], "".join(core.report_text_chunks(res, False)))
                self.assertEqual(got["color"], "".join(core.report_text_chunks(res, False, None, True)))
                self.assertEqual(got["quiet"], "".join(core.report_text_chunks(res, True)))


if __name__ == "__main__":
    unittest.main()
