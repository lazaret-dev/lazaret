"""GitLab CI files: the supply-chain checks of the CI/CD review, in GitLab's terms (0.1.9, S-3).

`.gitlab-ci.yml` runs whatever it includes, pulls, downloads and expands with the
project's variables, so these are the places a pipeline can be turned:

- `include:` of a file from a URL (it can't be pinned), of a file from another
  project at a branch, a tag or no ref, and of a CI/CD component at a version
  that is not a full commit SHA (`@1.2.3`, `@~latest`, `@main`);
- an `image:` or a service without a digest (`image: python:3.12`);
- a script that fetches a script and runs it unread (`curl … | sh`);
- a script that hands text anyone can write (a merge request's title and
  description, a commit message, a branch name) to `eval`, to `sh -c "…"`, or
  to the place of a command, where the shell reads it as code;
- a job that holds a publishing credential (`id_tokens:`, `secrets:`, a
  registry token variable) and installs dependencies, whose install scripts
  and build hooks then run with it.

Like ghworkflow.py, this reads the outline of the YAML (ghworkflow.records),
not YAML: anchors, `extends:`, `!reference` and multi-line flow collections
are read as the plain text they are. A job's scripts are the ones written under
it; what it inherits through `extends:` is read where it is written. The
checks are offline, and twinned, rule for rule, in js/src/lib/gitlabci.js. The
online checks (a component's own repository, a project's ref) are not here.
"""
import re

from . import ghworkflow

#: The keys that hold a job's commands
SCRIPT_KEYS = ("before_script", "script", "after_script")
# keys a file can set for every job, at its top (`default:` is the current way)
_GLOBAL_KEYS = ("image", "services", "before_script", "after_script")
# top-level keys that are not jobs
_NOT_JOBS = ("variables", "stages", "include", "workflow", "cache", "spec", "inputs")
_HEX = "0123456789abcdefABCDEF"
_DIGITS = "0123456789"

# a version tag of a component: 1.2.3, v1.2.3, 1.2.3-rc.1
_EXACT_RE = re.compile(r"\Av?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?\Z")
# text anyone who can open a merge request, push a commit or a branch writes
_MR_VAR = (r"\$\{?(?:CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS)"
           r"|CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|REF_NAME|BRANCH|TAG_MESSAGE)"
           r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b\}?")
_MR_VAR_RE = re.compile(_MR_VAR)
# a command that is one of those variables
_COMMAND_VAR_RE = re.compile(ghworkflow.COMMAND_START + "(" + _MR_VAR + ")")
# `eval` and `sh -c`: the commands that read an argument as code; their arguments are read one at a time:
# a double-quoted string (the shell expands the variable, eval or sh reads the result), a single-quoted
# one (it stays a variable's name, which is safe) or a bare word
_EVAL_RE = re.compile(ghworkflow.COMMAND_START + r"eval\b")
_SHELL_C_RE = re.compile(
    ghworkflow.COMMAND_START + r"(?:[\w./-]*/)?(?:ba|z|da|k|a|c)?sh(?:\s+-[A-Za-z]+)*\s+-[A-Za-z]*c(?![A-Za-z])")
_ARG_RE = re.compile(r"\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s;&|\"']+)")
# credentials that publish: a registry's token variable, a job's OIDC token
_TOKEN_VAR_RE = re.compile(
    r"\$\{?(?:NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_[A-Z_]{0,30}TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN"
    r"|GEM_HOST_API_KEY|RUBYGEMS_API_KEY|CI_JOB_JWT(?:_V2)?)\b\}?")


def is_gitlab_ci(path):
    """Is `path` ('/' or os separators) a GitLab CI file: `.gitlab-ci.yml`, a
    `*.gitlab-ci.yml`, or a .yml/.yaml under a `.gitlab` directory (the usual
    place of included files)?"""
    parts = path.replace("\\", "/").split("/")
    name = parts[-1].lower()
    if name.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")) or name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return True
    return name.endswith((".yml", ".yaml")) and any(p.lower() == ".gitlab" for p in parts[:-1])


def _is_hex(s, n):
    return len(s) == n and all(c in _HEX for c in s)


def _is_url(s):
    return s[:8].lower() == "https://" or s[:7].lower() == "http://"


def _tag_like(ref):
    """Does ref read as a version tag (1.2, v1.2)?"""
    return ref != "" and (ref[0] in _DIGITS or (ref[0] == "v" and ref[1:2] != "" and ref[1] in _DIGITS))


def _unquote(s):
    s = s.strip(" \t")
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    return s


def _split_top(s, sep, maxsplit=-1):
    """s split at `sep` outside quotes and brackets, at most `maxsplit` times."""
    out, depth, quote, start = [], 0, "", 0
    for i, c in enumerate(s):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth = max(depth - 1, 0)
        elif c == sep and depth == 0 and len(out) != maxsplit:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def _flow_item(s):
    s = s.strip(" \t")
    if not s.startswith("{"):
        return _unquote(s)
    out = {}
    for pair in _split_top(s[1:-1] if s.endswith("}") else s[1:], ","):
        kv = _split_top(pair, ":", 1)
        if len(kv) == 2:
            out.setdefault(_unquote(kv[0]), _unquote(kv[1]))
    return out


def flow_items(text):
    """The items of a flow collection written on one line: `[a, {k: v}]` gives
    "a" and a dict of the map's values; `{k: v}` gives that dict; a scalar gives
    itself."""
    t = text.strip(" \t")
    if t.startswith("["):
        body = t[1:-1] if t.endswith("]") else t[1:]
        return [_flow_item(x) for x in _split_top(body, ",") if x.strip(" \t")]
    if t.startswith("{"):
        return [_flow_item(t)]
    return [_unquote(t)] if t else []


def parse_image(value):
    """(name, tag, digest) of an image reference: `registry:5000/app:1.2@sha256:…`
    gives ("registry:5000/app", "1.2", "sha256:…")."""
    name, _, digest = value.strip(" \t").partition("@")
    cut = name.rfind(":")
    if cut > name.rfind("/"):
        return name[:cut], name[cut + 1:], digest
    return name, "", digest


def mr_text(text):
    """(variable, how) for a script line that hands text anyone can write — a
    merge request's title or description, a commit message, a branch name — to
    code: "eval", "a `sh -c` string" or "the place of a command"; or None.
    A variable inside single quotes, or an argument of an ordinary command, is
    data and does not count."""
    if _MR_VAR_RE.search(text) is None:
        return None
    m = _COMMAND_VAR_RE.search(text)
    if m:
        return m.group(1), "the place of a command"
    for pattern, how, limit in ((_EVAL_RE, "eval", None), (_SHELL_C_RE, "a `sh -c` string", 1)):
        pos = 0
        while True:
            m = pattern.search(text, pos)
            if m is None:
                break
            pos, taken = m.end(), 0
            while limit is None or taken < limit:
                arg = _ARG_RE.match(text, pos)
                if arg is None:
                    break
                pos, taken = arg.end(), taken + 1
                word = arg.group(1)
                found = None if word.startswith("'") else _MR_VAR_RE.search(word)
                if found:
                    return found.group(), how
    return None


def _lines(r):
    """[(line, text)] of one record's own text: its value, and its block scalar. A value
    that is a flow list (`script: ["a", "b"]`) is its strings."""
    if r["value"].startswith("["):
        return [(r["line"], x) for x in flow_items(r["value"]) if isinstance(x, str)] + list(r["block"])
    return ([(r["line"], r["value"])] if r["value"] else []) + list(r["block"])


def _item_lines(r):
    """_lines for a sequence item: a script line that has `: ` in it reads as a
    key, so the line is put back together."""
    if r["key"] is None:
        return _lines(r)
    head = r["key"] + ": " + r["value"] if r["value"] else r["key"] + ":"
    return [(r["line"], head)] + list(r["block"])


def _jobs(records):
    """{owner: job}: for every job (and `default`, which stands for the settings
    of the whole file, and for the top-level keys that are the same) its commands
    by section, the images and services it names, and whether it holds an OIDC
    token (`id_tokens:`) or secrets (`secrets:`). "loose" are the lines of a
    list under a hidden key (`.setup: &setup` + `- npm ci`), which jobs pull in
    with an alias."""
    jobs = {}
    for r in records:
        path, key = r["path"], r["key"]
        if not path:
            if key not in _GLOBAL_KEYS:
                continue
            owner, rest = "default", ()
        elif path[0] in _GLOBAL_KEYS:
            owner, rest = "default", path
        elif path[0] in _NOT_JOBS:
            continue
        else:
            owner, rest = path[0], path[1:]
        job = jobs.get(owner)
        if job is None:
            job = jobs[owner] = {"scripts": {k: [] for k in SCRIPT_KEYS}, "loose": [], "images": [],
                                 "id_tokens": None, "secrets": None}
        if not rest:
            value = r["value"]
            if key in SCRIPT_KEYS:
                job["scripts"][key].extend(_lines(r))
            elif key == "image" and value:
                for item in (flow_items(value) if value.startswith("{") else [value]):
                    name = item.get("name", "") if isinstance(item, dict) else item
                    if name:
                        job["images"].append((r["line"], name, "image"))
            elif key == "services" and value.startswith("["):
                for item in flow_items(value):
                    name = item.get("name", "") if isinstance(item, dict) else item
                    if name:
                        job["images"].append((r["line"], name, "service"))
            elif key == "id_tokens" and job["id_tokens"] is None:
                job["id_tokens"] = r["line"]
            elif key == "secrets" and job["secrets"] is None:
                job["secrets"] = r["line"]
        elif rest[0] in SCRIPT_KEYS and len(rest) >= 2 and all(x == "-" for x in rest[1:]):
            job["scripts"][rest[0]].extend(_item_lines(r))
        elif rest == ("image",) and key == "name" and r["value"]:
            job["images"].append((r["line"], r["value"], "image"))
        elif rest == ("services", "-") and key in (None, "name") and r["value"]:
            job["images"].append((r["line"], r["value"], "service"))
        elif owner.startswith(".") and key is None and rest and all(x == "-" for x in rest):
            job["loose"].extend(_lines(r))
    return jobs


def _includes(records):
    """[(line, item)] for what `include:` names: an item is a string (`- 'https://…'`)
    or a dict of the item's fields (`remote`, `project`, `ref`, `component` …)."""
    items, cur, single = [], None, None
    for r in records:
        path, key = r["path"], r["key"]
        if not path:
            if key == "include":
                cur = single = None
                if r["value"].startswith(("[", "{")):
                    items.extend((r["line"], it) for it in flow_items(r["value"]))
                elif r["value"]:
                    items.append((r["line"], _unquote(r["value"])))
            continue
        if path[0] != "include":
            continue
        if path == ("include",) and key is not None:                  # include:\n  remote: …
            if single is None:
                single = (r["line"], {})
                items.append(single)
            single[1].setdefault(key, r["value"])
        elif path == ("include", "-"):
            if r["item"]:
                if key is None:
                    items.append((r["line"], r["value"]))
                    cur = None
                else:
                    cur = (r["line"], {key: r["value"]})
                    items.append(cur)
            elif cur is not None and key is not None:
                cur[1].setdefault(key, r["value"])
    return items


def _section_lines(job, sections):
    return [x for k in sections for x in job["scripts"][k]]


def _effective(jobs, name):
    """The commands a job runs, in order: its before_script (the file's default
    one when it has none), its script, its after_script (the same)."""
    job, base = jobs[name], jobs.get("default")
    def pick(k):
        own = job["scripts"][k]
        return own if own or base is None else base["scripts"][k]
    return pick("before_script") + job["scripts"]["script"] + pick("after_script")


def hardening(text):
    """-> [(kind, line, detail)], by line, for a GitLab CI file's text:
    'include-remote' {"url", "http"}: an include from a URL; 'include-project'
    {"project", "ref", "tag"}: a project's file at a branch, a tag or no ref;
    'include-component' {"component", "ref", "exact"}: a component not pinned to
    a commit; 'image' {"job", "image", "where", "tag", "official"}: an image or
    a service without a digest; 'pipe-to-shell' {"job", "command"}: a script
    that fetches a script and runs it unread; 'mr-text' {"job", "variable",
    "how"}: text anyone can write handed to code; 'token-install' {"job",
    "grant", "command"}: a job with a publishing credential that installs
    dependencies."""
    records = ghworkflow.records(text, True, True)
    jobs = _jobs(records)
    out = []
    for line, item in _includes(records):
        fields = item if isinstance(item, dict) else {"remote": item} if _is_url(item) else {}
        remote = fields.get("remote", "")
        if remote:
            out.append(("include-remote", line, {"url": remote, "http": remote[:7].lower() == "http://"}))
        elif "project" in fields:
            ref = fields.get("ref", "")
            if not _is_hex(ref, 40) and ref not in ("$CI_COMMIT_SHA", "${CI_COMMIT_SHA}"):
                out.append(("include-project", line, {"project": fields["project"], "ref": ref, "tag": _tag_like(ref)}))
        elif "component" in fields:
            name, _, ref = fields["component"].partition("@")
            if not _is_hex(ref, 40):
                out.append(("include-component", line, {
                    "component": name, "ref": ref, "exact": _EXACT_RE.search(ref) is not None}))
    for owner, job in jobs.items():
        for line, value, where in job["images"]:
            if value.startswith(("$CI_REGISTRY_IMAGE", "${CI_REGISTRY_IMAGE")):         # an image the project built
                continue
            name, tag, digest = parse_image(value)
            if digest.startswith("sha256:") and _is_hex(digest[7:], 64):
                continue
            out.append(("image", line, {"job": owner, "image": value, "where": where, "tag": tag, "official": "/" not in name}))
    for owner, job in jobs.items():
        sections = [job["scripts"][k] for k in SCRIPT_KEYS] + [job["loose"]]
        for kind, check in (("pipe-to-shell", ghworkflow.pipe_to_shell), ("mr-text", mr_text)):
            hit = None
            for section in sections:
                for line, t in ghworkflow.logical_lines(section):
                    found = check(t)
                    if found is not None:
                        hit = (line, found)
                        break
                if hit is not None:
                    break
            if hit is None:
                continue
            if kind == "pipe-to-shell":
                out.append((kind, hit[0], {"job": owner, "command": hit[1]}))
            else:
                out.append((kind, hit[0], {"job": owner, "variable": hit[1][0], "how": hit[1][1]}))
    base = jobs.get("default")
    for owner, job in jobs.items():
        if owner == "default":
            continue
        lines = _effective(jobs, owner)
        grant = None
        if job["id_tokens"] is not None:
            grant = "its id_tokens"
        elif base is not None and base["id_tokens"] is not None:
            grant = "the default id_tokens"
        elif job["secrets"] is not None:
            grant = "its secrets"
        else:
            for _line, t in lines:
                m = _TOKEN_VAR_RE.search(t)
                if m:
                    grant = m.group()
                    break
        if grant is None:
            continue
        for line, t in lines:
            found = ghworkflow.install_command(t)
            if found is not None:
                out.append(("token-install", line, {"job": owner, "grant": grant, "command": found}))
                break
    out.sort(key=lambda f: (f[1], f[0]))
    return out


_INCLUDE_WHY = (
    "An included file becomes part of the pipeline: its jobs run with the project's variables, its secrets and its "
    "runners. A file from a URL can't be pinned to a commit or a hash, so it can change between two pipelines with "
    "no change in the repository (a new file at that address, a domain that expired and was bought, a man in the "
    "middle on plain HTTP). A branch moves with every push to it, and a tag can be moved too.")
_INCLUDE_FIX = (
    "Copy the file into the repository, or include it from a project at a full commit SHA (`ref: <sha>`) or a "
    "component at one (`component: gitlab.com/group/project/name@<sha>`), where a change is a commit you can "
    "review; let Renovate propose the updates.")
_IMAGE_WHY = (
    "A tag names whatever image its owner pushed last, and `latest` or any tag a maintainer can push again lets "
    "them, or an attacker with their account, change the image your jobs run in, with the job's variables and "
    "token. A digest (`@sha256:…`) names one image.")
_IMAGE_FIX = (
    "Pin it to a digest and keep the tag next to it for readers (`image: python:3.12@sha256:<digest>`); let "
    "Renovate propose the updates.")
_MR_WHY = (
    "A variable holds the text as it is, but `eval` and `sh -c` read their argument again as shell code. A merge "
    "request's title and description, a commit message and a branch name can hold `$(…)` and backticks, and "
    "whoever can open a merge request or push a branch writes them: they can run commands in the job, with its "
    "variables and token.")
_MR_FIX = (
    "Don't pass these through `eval` or `sh -c`. As an argument of a command (`\"$CI_COMMIT_TITLE\"`) the text is "
    "data; inside a script that you run, read it from the environment, and check it against a short pattern first.")
_TOKEN_WHY = (
    "Dependencies run code while they install and build, with the job's variables. An OIDC token (`id_tokens`), a "
    "registry's token and the secrets a job fetches are what a registry, a cloud account or a signing service "
    "takes as proof of identity, so code that can read one can publish or deploy as the pipeline.")
_TOKEN_FIX = (
    "Install and build in a job without the credential, pass the result on as an artifact, and publish from a "
    "separate job that only downloads it and installs nothing.")


def hardening_rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as
    core.mk_issue takes them — for one hardening() finding."""
    if kind == "include-remote":
        return {
            "id": "SC-GITLAB-INCLUDE", "name": "Pipeline includes a file from a URL",
            "type": "HOTSPOT", "sev": "CRITICAL" if d["http"] else "MAJOR",
            "msg": f"The pipeline includes {d['url']}: GitLab fetches it every time a pipeline runs"
                   + (", over plain HTTP, so that anyone on the path can change it, and" if d["http"] else ", and")
                   + " whoever controls that address decides what the pipeline does.",
            "why": _INCLUDE_WHY, "fix": _INCLUDE_FIX, "ref": "CWE-829 · Supply chain"}
    if kind == "include-project":
        at = "no ref (its default branch)" if d["ref"] == "" else f"the ref \"{d['ref']}\""
        return {
            "id": "SC-GITLAB-INCLUDE", "name": "Pipeline includes a project's file that is not pinned to a commit",
            "type": "HOTSPOT", "sev": "MINOR" if d["tag"] else "MAJOR",
            "msg": f"The pipeline includes a file from {d['project']} at {at}, not a full commit SHA: whoever can push "
                   f"to that ref changes what runs in your pipeline.",
            "why": _INCLUDE_WHY, "fix": _INCLUDE_FIX, "ref": "CWE-829 · Supply chain"}
    if kind == "include-component":
        at = "its latest version" if d["ref"] in ("", "~latest") else f"the version \"{d['ref']}\""
        return {
            "id": "SC-GITLAB-INCLUDE", "name": "Pipeline uses a component that is not pinned to a commit",
            "type": "HOTSPOT", "sev": "MINOR" if d["exact"] else "MAJOR",
            "msg": f"The pipeline uses the component {d['component']} at {at}, not a full commit SHA: whoever "
                   f"publishes to it changes what runs in your pipeline.",
            "why": _INCLUDE_WHY, "fix": _INCLUDE_FIX, "ref": "CWE-829 · Supply chain"}
    if kind == "image":
        small = d["official"] and d["tag"] not in ("", "latest")
        who = "The file's default settings use" if d["job"] == "default" else f"The job \"{d['job']}\" " + (
            "starts the service" if d["where"] == "service" else "runs")
        return {
            "id": "SC-GITLAB-IMAGE", "name": "Pipeline runs an image not pinned to a digest",
            "type": "HOTSPOT", "sev": "MINOR" if small else "MAJOR",
            "msg": f"{who} {d['image']}, which is not pinned to a digest: whoever controls that tag can change what "
                   f"runs in your pipeline.",
            "why": _IMAGE_WHY, "fix": _IMAGE_FIX, "ref": "CWE-829 · Supply chain"}
    if kind == "pipe-to-shell":
        return {
            "id": "SC-GITLAB-PIPE-SHELL", "name": "Pipeline runs a script it downloads without reading it",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"The job \"{d['job']}\" fetches a script and runs it as it arrives (`{d['command']}`): it runs "
                   f"whatever that address serves at that moment.",
            "why": ghworkflow.PIPE_SHELL_WHY, "fix": ghworkflow.PIPE_SHELL_FIX, "ref": "CWE-494 · Supply chain"}
    if kind == "mr-text":
        return {
            "id": "SC-GITLAB-MR-TEXT", "name": "Script runs text anyone can write as code",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"The job \"{d['job']}\" puts {d['variable']} in {d['how']}: it is text of a merge request, a commit "
                   f"or a branch, which anyone who can open one writes, and the shell reads it as commands.",
            "why": _MR_WHY, "fix": _MR_FIX, "ref": "CWE-94 · Supply chain"}
    return {
        "id": "SC-GITLAB-TOKEN-INSTALL", "name": "Job that installs dependencies holds a publishing credential",
        "type": "HOTSPOT", "sev": "MAJOR",
        "msg": f"The job \"{d['job']}\" holds a publishing credential ({d['grant']}) and runs `{d['command']}`: an "
               f"install script or build hook of a dependency runs with it.",
        "why": _TOKEN_WHY, "fix": _TOKEN_FIX, "ref": "CWE-250 · Supply chain"}
