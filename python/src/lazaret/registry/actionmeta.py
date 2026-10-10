"""What a GitHub Action runs, read from its action.yml (0.1.9, N-4).

The runner (actions/runner) fetches an action's repository at the commit its
`uses:` resolves to, the archive GitHub serves for it (`git archive`: no path
marked `export-ignore` is in it), and reads `action.yml`, else `action.yaml`,
in the action's directory. What it runs from there:

- a JavaScript action (`runs.using: node20`, …): `runs.pre`, `runs.main` and
  `runs.post`, each `node <the action's directory>/<path>`, with the job's
  environment: its token when given, every secret the workflow hands it, and
  the runner's own (ACTIONS_RUNTIME_TOKEN; ACTIONS_ID_TOKEN_REQUEST_TOKEN when
  the job may ask for an OIDC token);
- a composite action (`using: composite`): its steps, in the job. A `run:` step
  runs in the job's workspace, so a path there is the user's repository's;
  only one built from `github.action_path` (GITHUB_ACTION_PATH) names a file of
  the action. Its `shell:` says what reads the script (bash, sh, pwsh, python,
  or a command with `{0}`). A step's `uses:` is another action, which
  registry/actions.py checks on its own;
- a Docker action (`using: docker`): the image `runs.image` names, pulled
  (`docker://…`) or built from a Dockerfile of the action's directory, which is
  the build context; `runs.entrypoint` (and `pre-entrypoint`,
  `post-entrypoint`) or the Dockerfile's ENTRYPOINT and CMD say what it runs.

This module reads those (`read`, `dockerfile`) and says how a command or a
script of an action is judged (`judge`); the registry's artifact scan follows
them to the files of the commit (repo.py, artifact "action"). Like
scanner/ghworkflow.py, which it reads action.yml with, it is an outline of the
YAML, not a parser: anchors, tags and flow collections over several lines are
read as text, as the workflow checks read them.
"""

import json
import posixpath
import re
from collections import namedtuple

from lazaret.scanner import core as _core
from lazaret.scanner import ghworkflow

__all__ = ["ACTION_DIR", "METADATA", "Meta", "Step", "read", "commands", "step_shell", "substitute", "in_action",
           "dockerfile", "context_file", "judge", "routine", "strong", "MAX_METADATA_BYTES"]

#: The names the runner looks for in an action's directory, in its order
METADATA = ("action.yml", "action.yaml")
#: An action.yml larger than this is not read (the runner's own limit is GitHub's file size; a real one is a few KB)
MAX_METADATA_BYTES = 256 * 1024
#: A Dockerfile larger than this is not read
MAX_DOCKERFILE_BYTES = 256 * 1024
#: The action's directory, as a command of a composite step names it: an absolute path the hook follower keeps
#: (a path in the job's workspace stays relative, and is not the action's)
ACTION_DIR = "/__lazaret_action__"
#: Steps, and commands in one step, read at most
MAX_STEPS = 200
MAX_COMMANDS = 500

Meta = namedtuple("Meta", "using runs steps")
# line: the step's first line; run: its script (None for a `uses:` step), run_line: the line its script starts on;
# shell: what reads it, as written; workdir: its working-directory; uses: the action it runs
Step = namedtuple("Step", "line run run_line shell workdir uses")

# ${{ github.action_path }} (and github['action_path']), $GITHUB_ACTION_PATH, ${GITHUB_ACTION_PATH},
# PowerShell's $env:GITHUB_ACTION_PATH and cmd's %GITHUB_ACTION_PATH%
_ACTION_PATH_RE = re.compile(
    r"\$\{\{\s*github\s*(?:\.\s*action_path|\[\s*'action_path'\s*\])\s*\}\}"
    r"|\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b|\$env:GITHUB_ACTION_PATH\b|%GITHUB_ACTION_PATH%", re.I)
_QUOTED_DIR_RE = re.compile("([\"'])" + re.escape(ACTION_DIR) + r"\1")


def _scalar(rec):
    return rec["value"].strip() if rec is not None else ""


def _block_text(lines, rec):
    """A record's value with its block scalar, the block's lines as written (their indentation kept, less the
    block's own: a Python step's code and a shell here-document need it)."""
    if not rec["block"]:
        return rec["value"]
    first, last = rec["block"][0][0], rec["block"][-1][0]
    body = [lines[n - 1].rstrip("\r") for n in range(first, last + 1)]
    indent = min((len(b) - len(b.lstrip(" \t")) for b in body if b.strip()), default=0)
    text = "\n".join(b[indent:] for b in body)
    return (rec["value"] + "\n" + text) if rec["value"] else text


def read(text):
    """-> Meta(using, runs, steps) of an action.yml: `using` in lower case ('' when there is none), `runs` the
    scalar keys under `runs:` ({key: (value, line)}, as written), `steps` a composite action's steps."""
    lines = text.split("\n")
    runs, steps, using = {}, [], ""
    current = None
    for r in ghworkflow.records(text):
        p = r["path"]
        if p == ("runs",) and r["key"] is not None and r["key"] != "steps":
            runs.setdefault(r["key"], (_scalar(r) if not r["block"] else _block_text(lines, r).strip(), r["line"]))
            continue
        if p[:3] != ("runs", "steps", "-") or len(steps) > MAX_STEPS:
            continue
        if p == ("runs", "steps", "-") and (r["item"] or current is None):
            current = {"line": r["line"], "run": None, "run_line": None, "shell": "", "workdir": "", "uses": ""}
            steps.append(current)
        if len(p) != 3 or r["key"] is None:
            continue
        if r["key"] == "run" and current["run"] is None:
            current["run"] = _block_text(lines, r)
            current["run_line"] = r["block"][0][0] if r["block"] and not r["value"] else r["line"]
        elif r["key"] == "shell":
            current["shell"] = _scalar(r)
        elif r["key"] == "working-directory":
            current["workdir"] = _scalar(r)
        elif r["key"] == "uses":
            current["uses"] = _scalar(r)
    if "using" in runs:
        using = runs["using"][0].strip().lower()
    return Meta(using, runs, [Step(**s) for s in steps[:MAX_STEPS]])


def step_shell(shell):
    """What reads a `run:` step's script: 'sh' (bash, sh, the default on Linux and macOS), 'ps' (pwsh,
    powershell), 'py' (python), 'js' (node), 'cmd', or 'other' (a command of the step's own, `perl {0}`)."""
    word = (shell or "").strip().split(" ", 1)[0].lower() if shell else ""
    word = posixpath.basename(word.replace("\\", "/"))
    if word in ("", "bash", "sh", "zsh", "dash", "ksh"):
        return "sh"
    if word in ("pwsh", "powershell", "pwsh.exe", "powershell.exe"):
        return "ps"
    if word.startswith("python"):
        return "py"
    if word in ("node", "node.exe", "bun", "deno"):
        return "js"
    if word in ("cmd", "cmd.exe"):
        return "cmd"
    return "other"


def powershell_command(script):
    """A PowerShell step's script as the command line that runs it (`pwsh -Command "…"`), which is how the
    hook test reads PowerShell: its lines joined with `;`."""
    lines = [line.strip() for line in script.split("\n") if line.strip() and not line.strip().startswith("#")]
    return 'pwsh -Command "' + "; ".join(lines).replace("\\", "\\\\").replace('"', '\\"') + '"'


def substitute(text):
    """`text` with the action's directory written as ACTION_DIR (a quoted one unquoted: it has no space)."""
    return _QUOTED_DIR_RE.sub(ACTION_DIR, _ACTION_PATH_RE.sub(ACTION_DIR, text))


def commands(run, workdir=""):
    """The command lines of a `run:` step's shell script, each one the hook follower can read alone: its lines
    with their `\\` continuations joined, each after the `cd` that came before it (a later line runs where an
    earlier `cd` went), the action's directory written as ACTION_DIR. -> (commands, complete)."""
    out, joined, cwd = [], [], None
    workdir = substitute(workdir or "").strip()
    if workdir:
        cwd = workdir
    for raw in substitute(run).split("\n"):
        line = raw.rstrip()
        if line.endswith("\\") and not line.endswith("\\\\"):
            joined.append(line[:-1])
            continue
        joined.append(line)
        cmd = " ".join(part.strip() for part in joined).strip()
        joined = []
        if not cmd or cmd.startswith("#"):
            continue
        m = re.match(r"^(?:pushd|cd)\s+(\S+)\s*$", cmd)
        if m:
            cwd = m.group(1).strip("\"'")
            continue
        out.append(f"cd {cwd} && {cmd}" if cwd else cmd)
        if len(out) >= MAX_COMMANDS:
            return out, False
    if joined:
        cmd = " ".join(part.strip() for part in joined).strip()
        if cmd:
            out.append(f"cd {cwd} && {cmd}" if cwd else cmd)
    return out, True


def in_action(target):
    """The path of a file of the action a follower's target names (relative to the action's directory), or None
    for a target in the job's workspace or anywhere else."""
    t = target.replace("\\", "/").lstrip("/")
    head = ACTION_DIR.lstrip("/")
    if t == head or not t.startswith(head + "/"):
        return None
    rest = posixpath.normpath(t[len(head) + 1:])
    return None if rest in (".", "") or rest.startswith("../") or rest == ".." else rest


# ---------------------------------------------------------------- Dockerfiles
_INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$", re.S)
_FROM_FLAG_RE = re.compile(r"^--[A-Za-z-]+=\S*\s+")
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_ARG_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?-[^}]*)?\}?")


def _docker_lines(text):
    """(line, instruction text) of a Dockerfile: comments dropped, `\\` continuations joined."""
    out, start, parts = [], None, []
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not parts and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if parts and line.lstrip().startswith("#"):
            continue                                     # a comment inside a continued instruction
        if start is None:
            start = n
        if line.rstrip().endswith("\\"):
            parts.append(line.rstrip()[:-1])
            continue
        parts.append(line)
        out.append((start, " ".join(p.strip() for p in parts)))
        start, parts = None, []
    if parts:
        out.append((start, " ".join(p.strip() for p in parts)))
    return out


def _words(arg):
    """An instruction's arguments: the exec form's JSON array, else the words of the shell form."""
    a = arg.strip()
    if a.startswith("["):
        try:
            got = _core.json_loads_bounded(a, limit=4)
        except ValueError:
            got = None
        if isinstance(got, list) and all(isinstance(w, str) for w in got):
            return got, True
    return a.split(), False


Docker = namedtuple("Docker", "bases entrypoint cmd copies workdir")
# bases: [(line, image, pinned, alias)] of the FROM lines naming an image (not `scratch`, not an earlier stage);
# entrypoint, cmd: (line, words, exec form) of the final stage's, or None; copies: [(sources, dest, workdir)] of the
# final stage's COPY and ADD from the build context, in order


def dockerfile(text):
    """-> Docker of a Dockerfile's text."""
    args, stages, bases = {}, set(), []
    entrypoint = cmd = None
    copies, workdir = [], "/"
    for line, body in _docker_lines(text)[:5000]:
        m = _INSTRUCTION_RE.match(body)
        if not m:
            continue
        word, arg = m.group(1).upper(), m.group(2).strip()
        if word == "ARG":
            name, _eq, value = arg.partition("=")
            args.setdefault(name.strip(), value.strip().strip("\"'") if _eq else None)
        elif word == "FROM":
            rest = arg
            while _FROM_FLAG_RE.match(rest):
                rest = _FROM_FLAG_RE.sub("", rest, count=1)
            parts = rest.split()
            image = parts[0] if parts else ""
            alias = parts[2].lower() if len(parts) >= 3 and parts[1].lower() == "as" else None
            image = _ARG_REF_RE.sub(lambda a: args.get(a.group(1)) or a.group(0), image)
            if image and image.lower() != "scratch" and image.lower() not in stages:
                bases.append((line, image, bool(_DIGEST_RE.search(image)), alias))
            if alias:
                stages.add(alias)
            entrypoint = cmd = None                       # a new stage: the final one's are what run
            copies, workdir = [], "/"
        elif word == "WORKDIR":
            wd = arg.strip("\"'")
            workdir = posixpath.normpath(wd if wd.startswith("/") else posixpath.join(workdir, wd))
        elif word in ("COPY", "ADD"):
            rest = arg
            external = False
            while rest.startswith("--"):
                flag, _sp, rest = rest.partition(" ")
                if flag.startswith("--from="):
                    external = True
                rest = rest.strip()
            words, _exec = _words(rest)
            if len(words) >= 2 and not external and not any("://" in w for w in words[:-1]):
                copies.append((words[:-1], words[-1], workdir))
        elif word == "ENTRYPOINT":
            words, exec_form = _words(arg)
            entrypoint = (line, words, exec_form)
        elif word == "CMD":
            words, exec_form = _words(arg)
            cmd = (line, words, exec_form)
    return Docker(bases, entrypoint, cmd, copies, workdir)


def context_file(path, copies, is_file, is_dir):
    """The file of the build context (the action's directory) that a final image holds at `path`, by the
    COPY and ADD lines that put it there (the last one wins), or None. `is_file(rel)` / `is_dir(rel)` say
    what the context holds."""
    path = posixpath.normpath(path)
    for sources, dest, workdir in reversed(copies):
        target = posixpath.normpath(dest if dest.startswith("/") else posixpath.join(workdir, dest))
        into_dir = len(sources) > 1 or dest.endswith("/")
        for src in sources:
            s = posixpath.normpath(src).lstrip("/")
            s = "" if s in (".", "") else s
            if s == ".." or s.startswith("../"):
                continue
            if s and is_file(s):
                # a file goes to dest itself, or into it when dest is a directory (written with a trailing /, or
                # one the image already has: both are read)
                if path == posixpath.join(target, posixpath.basename(s)) or (not into_dir and path == target):
                    return s
            elif s == "" or is_dir(s):
                prefix = "/" if target == "/" else target + "/"     # a directory's contents go into dest
                if path.startswith(prefix):
                    cand = posixpath.join(s, path[len(prefix):]) if s else path[len(prefix):]
                    if is_file(cand):
                        return cand
    return None


# ---------------------------------------------------------------- what counts in an action
#: What CI code does as its job: a token or a variable sent to the service it works with, a file uploaded,
#: another program started, a package published. In an npm install hook each is a sign; in an action it is what
#: the action is for, so it is not counted (the whole environment sent still is).
ROUTINE = ("uploads a local file over the network", "starts another program", "publishes a package to a registry",
           "reads files outside the package and sends them over the network")
_ENV_SENT = "sends environment variables over the network"
#: Why a script piped into a shell matters (the workflow check's words)
PIPE_SHELL_WHY = ghworkflow.PIPE_SHELL_WHY
_WHOLE_ENV = "(the whole environment)"
#: A script fetched and run as it arrives: MAJOR in an action, as SC-WORKFLOW-PIPE-SHELL rates it in a workflow
#: (setup actions install rustup, poetry or a linter that way), not CRITICAL as in an npm install hook
FETCH_AND_RUN = ("pipes a download into a shell", "runs a downloaded script through a shell",
                 "downloads a script and runs it with", "downloads a file and then runs it",
                 "carries a script that downloads and runs code", "runs PowerShell that downloads and runs code")
_LOOPBACK_RE = re.compile(r"^contacts an address typical of data exfiltration \((?:https?://)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                          r"|localhost|\[::1\]|0\.0\.0\.0)(?:[:/)]|$)", re.I)


def routine(reason):
    """Is `reason` what CI code does as its job (ROUTINE; a named variable sent; a loopback address)?"""
    if reason.startswith(ROUTINE):
        return True
    if reason.startswith(_ENV_SENT):
        return _WHOLE_ENV not in reason
    return bool(_LOOPBACK_RE.match(reason))


def strong(reason):
    """Is `reason` one no action needs: the import-time test's strong shapes, and the whole environment sent?"""
    return reason.startswith(_core._STRONG_IMPORT_REASONS) or (reason.startswith(_ENV_SENT) and _WHOLE_ENV in reason)


def judge(reasons):
    """(severity, the reasons that count) of a test's reasons for an action's code or command: (None, []) when
    none counts; CRITICAL for a shape no action needs (strong, and not a script fetched and run), else MAJOR."""
    counted = [r for r in reasons if not routine(r)]
    if not counted:
        return None, []
    hostile = any(strong(r) and not r.startswith(FETCH_AND_RUN) for r in counted)
    return ("CRITICAL" if hostile else "MAJOR"), counted


def unquote_json(value):
    """A JSON string's value (a step's `shell` or an image written in quotes), else `value`."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            return json.loads(value)
        except ValueError:
            return value[1:-1]
    return value
