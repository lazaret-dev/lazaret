"""GitHub Actions workflows the Shai-Hulud worms planted (0.1.7).

Shai-Hulud (September 2025) pushed a workflow that sends `${{ toJSON(secrets) }}`
— every secret of the repository — to webhook.site on each push; its second
wave (November 2025) wrote one that saves them as a build artifact, and a
`discussion.yaml` that echoes a discussion's body on a self-hosted runner it
had registered on the victim's machine, so anyone who could open a discussion
ran commands there; the 2026 waves kept the secrets dump. core.scan_config_file
reports these shapes in .github/workflows/*.yml (SC-WORKFLOW-SECRETS,
SC-WORKFLOW-BACKDOOR).

Workflows are YAML, and Lazaret has no YAML library (it depends on nothing),
so this module reads the outline a workflow needs: each `key: value` line
with the keys above it (a sequence item counts as "-"), block scalars
(`run: |`) and the values of flow collections, quoted scalars and comments.
It is not a YAML parser — anchors, tags, multi-line flow collections and
complex keys are read as plain text — and it is twinned, rule for rule, in
js/src/lib/ghworkflow.js.
"""
import re

_BLOCK_RE = re.compile(r"[|>][-+0-9]{0,3}\Z")
#: Code points between `${{` and `}}` an expression may have (_expressions)
EXPR_MAX = 500
_SECRETS_RE = re.compile(r"\btoJSON\s*\(\s*secrets\s*\)", re.I)
# event text anyone who can open an issue, a discussion or a pull request writes
# (GitHub's list of untrusted input, and the discussion the backdoor reads)
_UNTRUSTED_RE = re.compile(
    r"\bgithub\.head_ref\b|\bgithub\.event\.(?:discussion|issue|comment|pull_request|review|review_comment"
    r"|head_commit|commits|pages|workflow_run)\b[\w.\[\]*-]{0,200}?\.(?:title|body|message|name|email|ref"
    r"|label|head_branch|page_name|default_branch)\b")
_NETWORK_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?://|/dev/tcp/", re.I)
_EVENT_WORD_RE = re.compile(r"[A-Za-z_]+")
#: Events that start a workflow with text anyone can write, and who that is
OUTSIDER_EVENTS = (
    ("discussion", "open a discussion"), ("discussion_comment", "comment on a discussion"),
    ("issues", "open an issue"), ("issue_comment", "comment on an issue"),
    ("pull_request_target", "open a pull request"), ("pull_request", "open a pull request"),
    ("pull_request_review", "review a pull request"),
    ("pull_request_review_comment", "comment on a pull request's code"))


def is_workflow(path):
    """Is `path` ('/' or os separators) a workflow: .github/workflows/*.yml|yaml?"""
    parts = path.replace("\\", "/").split("/")
    return (len(parts) >= 3 and parts[-3].lower() == ".github" and parts[-2].lower() == "workflows"
            and parts[-1].lower().endswith((".yml", ".yaml")))


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _quoted_end(s):
    """End (exclusive) of the quoted scalar that opens s, or -1 when it does
    not close on this line."""
    q = s[0]
    j = 1
    while j < len(s):
        c = s[j]
        if q == '"' and c == "\\":
            j += 2
            continue
        if c == q:
            if q == "'" and s.startswith("''", j):
                j += 2
                continue
            return j + 1
        j += 1
    return -1


def _comment_at(s):
    """Where a comment starts in s (a '#' after a space or a tab), or len(s)."""
    best = len(s)
    for sep in (" #", "\t#"):
        k = s.find(sep)
        if 0 <= k < best:
            best = k
    return best


def _value(s):
    """(text, quoted) of a scalar written at the start of s: a quoted one's
    content (escapes kept; to the end of the line when it does not close
    there), or a plain one up to its comment."""
    if s.startswith(('"', "'")):
        end = _quoted_end(s)
        return (s[1:end - 1] if end > 0 else s[1:]), True
    return s[:_comment_at(s)].rstrip(" \t"), False


def _split(body):
    """-> (key, value): a `key: value` line's key (None when the line is not
    one) and its value text; the key's quotes and the comment removed."""
    if body.startswith(('"', "'")):
        end = _quoted_end(body)
        if end < 0:
            return None, body
        rest = body[end:].lstrip(" \t")
        if rest.startswith(":") and (len(rest) == 1 or rest[1] in " \t"):
            return body[1:end - 1], rest[1:].lstrip(" \t")
        return None, body
    if body.startswith(("[", "{", "#", "?")):
        return None, body
    cut = _comment_at(body)
    k = body.find(": ", 0, cut)
    kt = body.find(":\t", 0, cut)
    if kt >= 0 and (k < 0 or kt < k):
        k = kt
    if k < 0:
        head = body[:cut].rstrip()
        if head.endswith(":"):
            return head[:-1].rstrip(), ""
        return None, body
    return body[:k].rstrip(), body[k + 2:].lstrip(" \t")


def _expressions(t):
    """The text of each `${{ … }}` in a line t: what re.finditer(r"\\$\\{\\{(.{0,500}?)\\}\\}", t)
    finds — the first `}}` after a `${{`, when it closes within EXPR_MAX code
    points — read in one pass (the pattern searches up to 500 characters from
    every `${{`)."""
    out = []
    i = t.find("${{")
    close = -1
    while i >= 0:
        if close < i + 3:
            close = t.find("}}", i + 3)
            if close < 0:
                break
        if close - (i + 3) <= EXPR_MAX:
            out.append(t[i + 3:close])
            i = t.find("${{", close + 2)
        else:
            i = t.find("${{", i + 1)
    return out


def outline(text):
    """The workflow's lines as records {line, path, key, value, block}: path
    is the tuple of keys above ('-' for a sequence item), key the line's key
    (None for a scalar line: a sequence item's value, a continuation), value
    its value's text, block the (line, text) of a block scalar (`run: |`)."""
    records, stack, block = [], [], None
    for n, raw in enumerate(text.split("\n"), 1):
        if block is not None:
            if not raw.strip(" \t"):
                continue
            if _indent(raw) > block[0]:
                block[1]["block"].append((n, raw.strip(" \t")))
                continue
            block = None
        ind = _indent(raw)
        body = raw[ind:].rstrip(" \t")
        if not body or body.startswith("#"):
            continue
        if ind == 0 and (body in ("---", "...") or body.startswith("--- ")):
            stack = []
            continue
        while body == "-" or body.startswith(("- ", "-\t")):
            # an item closes what is deeper and the item before it; a key at
            # its own indentation is the sequence's (`steps:` / `- run: x`)
            while stack and (stack[-1][0] > ind or (stack[-1][0] == ind and stack[-1][1] == "-")):
                stack.pop()
            stack.append((ind, "-"))
            rest = body[1:]
            gap = len(rest) - len(rest.lstrip(" \t"))
            ind, body = ind + 1 + gap, rest.lstrip(" \t")
        if not body or body.startswith("#"):
            continue
        key, rest = _split(body)
        while stack and stack[-1][0] >= ind:
            stack.pop()
        path = tuple(name for _, name in stack)
        value, quoted = _value(rest)
        rec = {"line": n, "path": path, "key": key, "value": value, "block": []}
        records.append(rec)
        if key is not None:
            stack.append((ind, key))
            if not quoted and _BLOCK_RE.match(value):
                rec["value"] = ""
                block = (ind, rec)
    return records


def _text(rec):
    """A record's value with its block scalar, one line per line."""
    lines = [rec["value"]] if rec["value"] else []
    return "\n".join(lines + [t for _, t in rec["block"]])


def _lines(rec):
    """(line, text) of a record's value and of its block scalar's lines."""
    out = [(rec["line"], rec["value"])] if rec["value"] else []
    return out + rec["block"]


def _events(records):
    """The names of the events that start the workflow (its `on:`)."""
    names = []
    for r in records:
        if r["path"] == () and r["key"] in ("on", "true"):
            names += _EVENT_WORD_RE.findall(r["value"])
        elif r["path"] == ("on",) and r["key"] is not None:
            names.append(r["key"])
        elif r["path"] == ("on", "-") and r["key"] is None:
            names += _EVENT_WORD_RE.findall(r["value"])
    return names


def findings(text):
    """-> [(kind, line, detail)] for a workflow's text: kind 'secrets'
    (detail {"where", "how"}: how None when nothing sends them out) or
    'backdoor' (detail {"job", "expr", "event", "act"})."""
    records = outline(text)
    out = []
    # every secret handed to a job's environment or a script
    sends = None
    for r in records:
        if r["key"] == "uses" and r["value"].startswith("actions/upload-artifact"):
            sends = sends or "an artifact upload"
        elif r["key"] == "run" or (r["key"] is None and r["path"][-1:] == ("run",)):
            if _NETWORK_RE.search(_text(r)):
                sends = sends or "a network command"
    for r in records:
        if "with" in r["path"]:
            continue
        if r["path"][-1:] == ("env",) and r["key"] is not None:
            where = "a job's environment"
        elif r["key"] == "run" or (r["key"] is None and r["path"][-1:] == ("run",)):
            where = "a script"
        else:
            continue
        for line, t in _lines(r):
            if _SECRETS_RE.search(t):
                out.append(("secrets", line, {"where": where, "how": sends}))
                break
    # a backdoor: event text in a command on a self-hosted runner
    events = _events(records)
    outsider = next(((e, act) for e, act in OUTSIDER_EVENTS if e in events), None)
    if outsider is None:
        return out
    hosted = {}
    for r in records:
        if len(r["path"]) >= 2 and r["path"][0] == "jobs" and (
                (len(r["path"]) == 2 and r["key"] == "runs-on") or r["path"][2:3] == ("runs-on",)):
            if "self-hosted" in _text(r).lower():
                hosted[r["path"][1]] = True
    for r in records:
        path = r["path"]
        if len(path) < 4 or path[0] != "jobs" or path[1] not in hosted or path[2:4] != ("steps", "-"):
            continue
        if not (r["key"] == "run" and len(path) == 4) and not (r["key"] is None and path[4:] == ("run",)):
            continue
        for line, t in _lines(r):
            m = next((u for e in _expressions(t) for u in [_UNTRUSTED_RE.search(e)] if u), None)
            if m is not None:
                out.append(("backdoor", line, {"job": path[1], "expr": m.group(), "event": outsider[0],
                                               "act": outsider[1]}))
                break
    return out
