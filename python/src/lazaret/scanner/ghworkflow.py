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
    return _outline(text, False)


def _outline(text, items):
    """outline(text); with `items`, each record also says whether it is the
    first of a sequence item ("item": the line began with '- ', or the '-'
    stood alone on the one before) — hardening() tells one step from the
    next by it. outline() leaves the field out, as the twin does."""
    records, stack, block = [], [], None
    fresh = False
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
            fresh = False
            continue
        while body == "-" or body.startswith(("- ", "-\t")):
            # an item closes what is deeper and the item before it; a key at
            # its own indentation is the sequence's (`steps:` / `- run: x`)
            while stack and (stack[-1][0] > ind or (stack[-1][0] == ind and stack[-1][1] == "-")):
                stack.pop()
            stack.append((ind, "-"))
            fresh = True
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
        if items:
            rec["item"] = fresh
        fresh = False
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


# ---------------- Hardening checks (0.1.9) ----------------
# Not the worms' shapes: the practices GitHub's security guidance and the
# CI/CD review of Oct 2, 2026 name — actions pinned to a commit, no
# pull_request_target job running a pull request's code, no build cache in a
# release, read-only tokens, and no OIDC token in a job that installs
# dependencies. hardening() reports them apart from findings(), because the
# scanners turn a finding into an issue by its kind (core.workflow_issues;
# the twin's workflowIssues): hardening_rule() gives the rule for each kind,
# so wiring them in is a loop over these two (see docs/0.1.9-progress.md).
_HEX = "0123456789abcdefABCDEF"
_DIGITS = "0123456789"
_PR_HEAD_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.head_ref|refs/pull/|\bpull/(?:\d|\$\{\{)")
_PR_CHECKOUT_CMD_RE = re.compile(r"\bgit\s+(?:checkout|fetch|switch|pull|merge|cherry-pick)\b")
_GH_PR_CHECKOUT_RE = re.compile(r"\bgh\s+pr\s+checkout\b")
_WRITE_SCOPE_RE = re.compile(r"([A-Za-z-]+)\s*:\s*write\b")
# where a command can start in a line of a script: at its start, after ; & | (, after then/do/else/sudo/time/
# exec/command, and after VAR=value words (a value without quotes: it stops at the next operator, so that a
# long line of `a=b;a=b;…` is read once)
_CMD = (r"(?:^|[;&|(]|\b(?:then|do|else|sudo|time|exec|command)\s)\s*"
        r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()]*\s+)*")
# a command that runs dependencies' code: install hooks, build scripts
_INSTALL_RE = re.compile(
    _CMD + r"((?:npm\s+(?:ci|install|i|add)|pnpm\s+(?:install|i|add)|yarn\s+(?:install|add)"
    r"|bun\s+(?:install|i|add)|pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+(?:sync|add|pip\s+install)"
    r"|poetry\s+install|pipenv\s+install|bundle\s+install|composer\s+(?:install|update)"
    r"|cargo\s+(?:build|fetch|install)|go\s+(?:get|install|build|mod\s+download))(?![\w-])"
    r"|yarn(?=\s*(?:$|[;&|)])))")
_PUBLISH_RE = re.compile(
    _CMD + r"((?:npm|pnpm|bun)\s+publish\b|yarn\s+(?:npm\s+)?publish\b|twine\s+upload\b|uv\s+publish\b"
    r"|poetry\s+publish\b|cargo\s+publish\b|gh\s+release\s+create\b|docker\s+push\b"
    r"|vsce\s+publish\b|ovsx\s+publish\b|gem\s+push\b|dotnet\s+nuget\s+push\b|helm\s+push\b)")
#: Actions that publish a release (compared in lower case, with or without a path after the name)
PUBLISH_ACTIONS = (
    "pypa/gh-action-pypi-publish", "softprops/action-gh-release", "ncipollo/release-action",
    "goreleaser/goreleaser-action", "actions/create-release", "actions/attest-build-provenance", "actions/attest",
    "rust-lang/crates-io-auth-action", "js-devtools/npm-publish", "slsa-framework/slsa-github-generator",
    "sigstore/gh-action-sigstore-python")
#: Actions whose job is to restore a cache
CACHE_ACTIONS = ("actions/cache", "swatinem/rust-cache")
#: Setup actions and the input that turns their cache on: (action, input, on unless it is false).
#: setup-node is its own case: it caches when asked to (`cache:`) and may by itself (package-manager-cache)
SETUP_CACHES = (
    ("actions/setup-node", "cache", False), ("actions/setup-python", "cache", False),
    ("actions/setup-go", "cache", True), ("actions/setup-java", "cache", False),
    ("actions/setup-dotnet", "cache", False), ("ruby/setup-ruby", "bundler-cache", False),
    ("astral-sh/setup-uv", "enable-cache", True))
#: Actions of GitHub's own: a version tag is a smaller risk there than anywhere else
FIRST_PARTY = ("actions/", "github/")


def _is_hex(s, n):
    return len(s) == n and all(c in _HEX for c in s)


def _in_actions(name, names):
    """Is the action `name` (lower case) one of `names`, or a path inside one?"""
    return any(name == a or name.startswith(a + "/") for a in names)


def _action_ref(value):
    """(kind, name, ref, pinned) of a `uses:` value, kind 'action', 'docker'
    or 'workflow' (a reusable one); None for a local path (`./…`)."""
    v = value.strip(" \t")
    if not v or v == "." or v.startswith(("./", "../")):
        return None
    if v.startswith("docker://"):
        name, at, digest = v[9:].partition("@")
        pinned = at == "@" and digest.startswith("sha256:") and _is_hex(digest[7:], 64)
        return "docker", name, digest if at else "", pinned
    name, at, ref = v.partition("@")
    kind = "workflow" if "/.github/workflows/" in name else "action"
    return kind, name, ref if at else "", at == "@" and _is_hex(ref, 40)


def _tag_like(ref):
    """Does ref read as a version tag (`v4`, `1.2.3`)?"""
    return ref != "" and (ref[0] in _DIGITS or (ref[0] == "v" and ref[1:2] != "" and ref[1] in _DIGITS))


def _steps(records):
    """[(job, [records])]: the steps of every job, in order. `records` must
    come from _outline(text, True): a step starts at the record that begins
    its sequence item."""
    steps = []
    for r in records:
        p = r["path"]
        if len(p) >= 4 and p[0] == "jobs" and p[2] == "steps" and p[3] == "-":
            if (len(p) == 4 and r["item"]) or not steps or steps[-1][0] != p[1]:
                steps.append((p[1], []))
            steps[-1][1].append(r)
    return steps


def _step_uses(recs):
    """(value, line) of a step's `uses:`, or None."""
    for r in recs:
        if r["key"] == "uses" and len(r["path"]) == 4:
            return r["value"], r["line"]
    return None


def _step_with(recs):
    """{input: (value, line)} of a step's `with:`."""
    out = {}
    for r in recs:
        p = r["path"]
        if len(p) == 5 and p[4] == "with" and r["key"] is not None and r["key"] not in out:
            out[r["key"]] = (r["value"], r["line"])
    return out


def _step_run_lines(recs):
    """[(line, text)] of a step's script."""
    out = []
    for r in recs:
        p = r["path"]
        if (r["key"] == "run" and len(p) == 4) or (r["key"] is None and len(p) == 5 and p[4] == "run"):
            out += _lines(r)
    return out


def _permissions(records):
    """{owner: (present, [(scope, line)] granted write, line of an id-token
    grant or None)} for the `permissions:` of the workflow (owner `()`) and of
    each job (owner `('jobs', id)`), in one pass over the records. `write-all`
    is scope 'all' (and grants the token); a flow mapping is read for its
    `scope: write` pairs. An owner with no `permissions:` is not in the table:
    use _grants()."""
    table = {}
    for r in records:
        p, key = r["path"], r["key"]
        if key == "permissions" and (not p or (len(p) == 2 and p[0] == "jobs")):
            entry = table.setdefault(p, [False, [], None])
            entry[0] = True
            if r["value"] == "write-all":
                entry[1].append(("all", r["line"]))
                entry[2] = entry[2] or r["line"]
            elif r["value"].startswith("{"):
                for m in _WRITE_SCOPE_RE.finditer(r["value"]):
                    entry[1].append((m.group(1), r["line"]))
                    if m.group(1) == "id-token":
                        entry[2] = entry[2] or r["line"]
        elif (key is not None and r["value"] == "write" and p[-1:] == ("permissions",)
              and (len(p) == 1 or (len(p) == 3 and p[0] == "jobs"))):
            entry = table.setdefault(p[:-1], [False, [], None])
            entry[1].append((key, r["line"]))
            if key == "id-token":
                entry[2] = entry[2] or r["line"]
    return table


def _grants(table, owner):
    """(present, scopes, token line) of one owner in _permissions()'s table."""
    return tuple(table.get(owner, (False, [], None)))


def _release_why(table, steps, events):
    """Why this workflow is a release (it publishes something), or None."""
    if "release" in events:
        return "it runs when a release is published"
    if any(entry[2] is not None for owner, entry in table.items() if not owner or len(owner) == 2):
        return "it asks for an OIDC token"
    for _job, recs in steps:
        use = _step_uses(recs)
        ref = _action_ref(use[0]) if use is not None else None
        if ref is not None and _in_actions(ref[1].lower(), PUBLISH_ACTIONS):
            return f"it uses {ref[1]}"
        for _line, t in _step_run_lines(recs):
            m = _PUBLISH_RE.search(t)
            if m:
                return f"it runs `{m.group(1)}`"
    return None


def _cache_of(recs):
    """(line, what, explicit) for a step that restores a cache, or None."""
    use = _step_uses(recs)
    ref = _action_ref(use[0]) if use is not None else None
    if ref is None:
        return None
    name = ref[1].lower()
    if _in_actions(name, CACHE_ACTIONS):
        return use[1], ref[1], True
    withs = _step_with(recs)
    for action, key, default in SETUP_CACHES:
        if name != action:
            continue
        value, line = withs.get(key, ("", use[1]))
        if value not in ("", "false"):
            return line, f"{ref[1]} with {key}: {value}", True
        if value == "" and action == "actions/setup-node":
            if withs.get("package-manager-cache", ("", 0))[0] != "false":
                return use[1], f"{ref[1]} (it may cache unless package-manager-cache: false)", False
        elif value == "" and default:
            return use[1], f"{ref[1]} (it caches unless {key}: false)", False
        return None
    return None


def hardening(text):
    """-> [(kind, line, detail)], by line, for a workflow's text:
    'unpinned' {"uses", "kind", "ref", "first", "tag"}: a `uses:` that is not a
    full commit SHA (an action or a reusable workflow) or an image digest;
    'pr-checkout' {"job", "via", "expr"}: a pull_request_target job that checks
    out the pull request's code; 'cache' {"job", "what", "explicit", "why"}: a
    release workflow that restores a cache; 'perms' {"scopes"}: write permissions
    for the whole workflow; 'perms-missing' {"jobs"}: no top-level permissions
    and jobs without their own; 'oidc-install' {"job", "from", "command"}: a
    job that can ask for an OIDC token and installs dependencies."""
    records = _outline(text, True)
    events = _events(records)
    steps = _steps(records)
    jobs = [r["key"] for r in records if r["path"] == ("jobs",) and r["key"] is not None]
    out = []
    # write permissions for every job; or none stated, and jobs that state none
    table = _permissions(records)
    present, scopes, token = _grants(table, ())
    if scopes:
        out.append(("perms", scopes[0][1], {"scopes": [s for s, _ in scopes]}))
    elif not present:
        bare = [j for j in jobs if not _grants(table, ("jobs", j))[0]]
        if bare:
            where = next((r["line"] for r in records if r["path"] == () and r["key"] == "jobs"), 1)
            out.append(("perms-missing", where, {"jobs": bare}))
    # actions, reusable workflows and images that are not pinned
    for r in records:
        p = r["path"]
        if r["key"] != "uses" or not ((len(p) == 4 and p[0] == "jobs" and p[2] == "steps" and p[3] == "-")
                                      or (len(p) == 2 and p[0] == "jobs")):
            continue
        ref = _action_ref(r["value"])
        if ref is not None and not ref[3]:
            kind, name, tag, _pinned = ref
            out.append(("unpinned", r["line"], {
                "uses": r["value"], "kind": kind, "ref": tag,
                "first": kind == "action" and name.lower().startswith(FIRST_PARTY), "tag": _tag_like(tag)}))
    # a pull_request_target job that checks out the pull request
    if "pull_request_target" in events:
        for job, recs in steps:
            hit = None
            use = _step_uses(recs)
            ref = _action_ref(use[0]) if use is not None else None
            if ref is not None and ref[1].lower() == "actions/checkout":
                withs = _step_with(recs)
                for name in ("ref", "repository"):
                    value, line = withs.get(name, ("", 0))
                    m = _PR_HEAD_RE.search(value)
                    if m:
                        hit = (line, "with " + name, m.group())
                        break
            if hit is None:
                for line, t in _step_run_lines(recs):
                    m = _GH_PR_CHECKOUT_RE.search(t)        # always the pull request's branch
                    if m is None and _PR_CHECKOUT_CMD_RE.search(t):
                        m = _PR_HEAD_RE.search(t)
                    if m:
                        hit = (line, "a command", m.group())
                        break
            if hit is not None:
                out.append(("pr-checkout", hit[0], {"job": job, "via": hit[1], "expr": hit[2]}))
    # a cache in a release
    why = _release_why(table, steps, events)
    if why is not None:
        for job, recs in steps:
            found = _cache_of(recs)
            if found is not None:
                out.append(("cache", found[0], {"job": job, "what": found[1], "explicit": found[2], "why": why}))
    # a job with an OIDC token that installs dependencies
    by_job = {}
    for job, recs in steps:
        by_job.setdefault(job, []).append(recs)
    for job in jobs:
        j_present, _scopes, j_token = _grants(table, ("jobs", job))
        grant, source = (j_token, "job") if j_present else (token, "workflow")
        if grant is None:
            continue
        hit = None
        for recs in by_job.get(job, ()):
            for line, t in _step_run_lines(recs):
                m = _INSTALL_RE.search(t)
                if m and "--ignore-scripts" not in t:
                    hit = (line, m.group(1))
                    break
            if hit is not None:
                break
        if hit is not None:
            out.append(("oidc-install", hit[0], {"job": job, "from": source, "command": hit[1]}))
    out.sort(key=lambda f: (f[1], f[0]))
    return out


_UNPINNED_WHY = (
    "A tag or a branch can be moved to other code after you reviewed it: in March 2025 the tags of "
    "tj-actions/changed-files were rewritten to a commit that printed the secrets of every workflow that used "
    "it into its build log. A full commit SHA, or an image digest, can't be moved.")
_UNPINNED_FIX = (
    "Pin it to the full 40-character commit SHA and keep the version in a comment "
    "(`uses: owner/repo@<sha> # v4.1.0`); let Dependabot or Renovate propose the updates. "
    "For an image, pin `@sha256:…`.")
_PR_CHECKOUT_WHY = (
    "pull_request_target runs the base repository's workflow with its secrets and a token that can write, so "
    "that a workflow can answer a pull request from a fork. Running the fork's code there lets anyone who can "
    "open a pull request run commands with that access (the \"pwn request\").")
_CACHE_WHY = (
    "A cache entry can be written by any job that can write to the repository's cache, and the next run "
    "restores it as it is: a poisoned entry changes the build that gets published without any change to the "
    "source.")
_PERMS_WHY = (
    "A job should get only the access it uses. A workflow-level `permissions:` with a write scope hands it to "
    "every job, the ones that run third-party actions and install dependencies among them.")
_OIDC_WHY = (
    "Dependencies run code while they install and build, with the job's permissions. An OIDC token is what a "
    "package registry's trusted publishing and a cloud account's federation take as proof of identity, so code "
    "that can request one can publish or deploy as the workflow.")


def hardening_rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as
    core.mk_issue takes them — for one hardening() finding."""
    if kind == "unpinned":
        what = "the image" if d["kind"] == "docker" else ("the reusable workflow" if d["kind"] == "workflow" else "")
        pin = "a digest" if d["kind"] == "docker" else "a full commit SHA"
        small = d["kind"] == "action" and d["first"] and d["tag"]
        return {
            "id": "SC-WORKFLOW-UNPINNED", "name": "Workflow runs something not pinned to a commit",
            "type": "HOTSPOT", "sev": "MINOR" if small else "MAJOR",
            "msg": f"The workflow runs {what + ' ' if what else ''}{d['uses']}, which is not pinned to {pin}: "
                   f"whoever controls that ref can change what runs in your pipeline.",
            "why": _UNPINNED_WHY, "fix": _UNPINNED_FIX, "ref": "CWE-829 · Supply chain"}
    if kind == "pr-checkout":
        return {
            "id": "SC-WORKFLOW-PR-CHECKOUT", "name": "pull_request_target job checks out the pull request",
            "type": "HOTSPOT", "sev": "CRITICAL",
            "msg": f"The job \"{d['job']}\" runs on pull_request_target and checks out the pull request's code "
                   f"({d['via']}: {d['expr']}): whatever it then installs, builds or runs gets the repository's "
                   f"secrets and a token that can write.",
            "why": _PR_CHECKOUT_WHY,
            "fix": ("Run a pull request's code under `pull_request` (no secrets, a read-only token). If a job needs "
                    "secrets, check out only the base branch and treat the pull request's files as data: never "
                    "install, build or run them."),
            "ref": "CWE-94 · Supply chain"}
    if kind == "cache":
        return {
            "id": "SC-WORKFLOW-CACHE", "name": "Release workflow restores a build cache",
            "type": "HOTSPOT", "sev": "MAJOR" if d["explicit"] else "MINOR",
            "msg": f"The job \"{d['job']}\" restores a cache ({d['what']}) in a workflow where {d['why']}: what "
                   f"the cache holds runs with the release's token.",
            "why": _CACHE_WHY,
            "fix": ("Build the release without restored caches: no actions/cache, `cache:` off in the setup "
                    "actions, `package-manager-cache: false` for setup-node. The build is slower, and its inputs "
                    "are the ones in the commit."),
            "ref": "CWE-345 · Supply chain"}
    if kind == "perms":
        scopes = ["write-all" if s == "all" else s for s in d["scopes"]]
        return {
            "id": "SC-WORKFLOW-PERMISSIONS", "name": "Workflow grants write permissions to every job",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"The workflow's token has write access in every job ({', '.join(scopes)}): a step in any job, "
                   f"or any action it runs, can use it.",
            "why": _PERMS_WHY,
            "fix": ("Set `permissions: contents: read` at the top of the workflow and grant a write scope only in "
                    "the job that needs it."),
            "ref": "CWE-250 · Supply chain"}
    if kind == "perms-missing":
        names = ", ".join(f"\"{j}\"" for j in d["jobs"][:3]) + (f" and {len(d['jobs']) - 3} more"
                                                                if len(d["jobs"]) > 3 else "")
        who = f"the job {names} has" if len(d["jobs"]) == 1 else f"the jobs {names} have"
        return {
            "id": "SC-WORKFLOW-PERMISSIONS", "name": "Workflow sets no permissions",
            "type": "HOTSPOT", "sev": "MINOR",
            "msg": f"The workflow sets no top-level `permissions:`, and {who} none of its own: the token gets the "
                   f"repository's default permissions, which can include write access.",
            "why": _PERMS_WHY,
            "fix": "Set `permissions: contents: read` at the top of the workflow and grant more only where a job needs it.",
            "ref": "CWE-250 · Supply chain"}
    return {
        "id": "SC-WORKFLOW-OIDC-INSTALL", "name": "Job that installs dependencies can request an OIDC token",
        "type": "HOTSPOT", "sev": "MAJOR",
        "msg": f"The job \"{d['job']}\" can request an OIDC token ({'its own permissions' if d['from'] == 'job' else 'the workflow permissions'}) "
               f"and runs `{d['command']}`: an install script or build hook of a dependency can request it too.",
        "why": _OIDC_WHY,
        "fix": ("Install and build in a job without `id-token: write`, upload the result as an artifact, and "
                "publish from a separate job that only downloads it and installs nothing."),
        "ref": "CWE-250 · Supply chain"}
