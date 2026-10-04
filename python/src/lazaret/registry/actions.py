"""What a workflow's `uses:` lines really point to (0.1.9, S-2, the online half).

The offline checks (`scanner/ghworkflow.py`, `hardening`) say that a `uses:`
is not pinned. These ask GitHub what each one points to, each action once:

- **impostor commit**: a pin (a full commit SHA) that is in no branch and no
  tag of the repository it names. GitHub resolves a commit of any fork in the
  network under the parent's name, so `actions/checkout@<a commit pushed to a
  fork>` runs the fork's code while the repository's page shows nothing.
- **a tag that moved**: a version tag (`v4.1.0`; not the floating `v4`) that
  points to another commit than when it was first seen (the tj-actions shape).
  What was seen is kept in a small file, the pin book; the first sighting is
  no finding.
- **a tag off the branches**: a tag whose commit is in none of the repository's
  branches that were compared.
- **a pin that does not match its comment**: `@<sha> # v4.1.0`, where v4.1.0
  points to another commit, or to none.
- **the action's own `action.yml`**: a Docker image not pinned to a digest; for
  a composite action, the `uses:` of its steps that are not pinned, and each of
  those checked the same way, two levels deep.

What it cannot tell is said, not skipped: a request GitHub refused (the rate
limit, 60 an hour without `GITHUB_TOKEN`, which is read-only and goes to
`api.github.com` only), the call budget, an expression in a ref, a private
repository, are reported as `incomplete`, and an action that was not checked
is not cleared. The rules are `sources.py`'s: HTTPS to `api.github.com` only,
every name from the workflow validated before it is put in a URL, a response
byte-budgeted and read as JSON with limits, nothing run and nothing written but
the pin book.

    python -m lazaret.registry.actions [--no-pins | --pins FILE] [--accept-moved]
                                       [--max-calls N] WORKFLOW...

prints the report as JSON; exit 1 for a finding, 3 when something could not be
checked, 2 for a usage error.
"""

import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
from collections import namedtuple

from lazaret.registry import sources as _sources
from lazaret.scanner import core as _core
from lazaret.scanner import ghworkflow

__all__ = ["Finding", "Report", "PinBook", "Auditor", "Use", "parse_use", "audit_text", "rule", "default_pins_path"]

SourceError = _sources.SourceError

CALLS_ANONYMOUS = 45        # GitHub allows 60 an hour without a token: some is left for the user's other tools
CALLS_TOKEN = 400
MAX_BRANCHES = 8            # branches compared with a commit, after the default branch
MAX_DEPTH = 2               # an action's steps' actions, and theirs
MAX_USES = 300              # distinct actions looked at in one run
MAX_ACTION_YML = 256 * 1024
PIN_ENTRIES = 5000
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024

Finding = namedtuple("Finding", "kind line uses detail")
Use = namedtuple("Use", "line value kind owner repo path ref pinned comment")

_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_COMMENT_RE = re.compile(r"\s#(.*)$")
_COMMENT_TAG_RE = re.compile(r"^(?:ratchet:\S+@|tag=|version:\s*)?(v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.+-]*)?)(?:\s|$)")
_EXACT_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


def default_pins_path():
    explicit = os.environ.get("LAZARET_ACTIONS_PINS")
    if explicit:
        return explicit
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "lazaret", "actions-pins.json")


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _exact_version(tag):
    """A tag that names one release (v4.1.0), as opposed to a floating one (v4, latest) that moves by design."""
    return bool(_EXACT_VERSION_RE.match(tag))


def _comment_tag(comment):
    """The version tag a pin's comment names (`# v4.1.0`, `# tag=v4.1.0`, `# ratchet:o/r@v4.1.0`), or None."""
    m = _COMMENT_TAG_RE.match((comment or "").strip())
    return m.group(1) if m else None


# ------------------------------------------------------------------ the uses: lines
def parse_use(line, value, comment=""):
    """-> (Use, None) for a `uses:` the GitHub API can be asked about, or
    (None, why): `why` is None when nothing needs to be looked up (a local
    path, an image: the offline check reads those), else what was not checked
    and why."""
    parsed = ghworkflow.parse_uses(value)
    if parsed is None or parsed[0] == "docker":
        return None, None
    kind, name, ref, pinned = parsed
    parts = name.split("/")
    if len(parts) < 2 or not _sources._GH_OWNER_RE.fullmatch(parts[0]) or not _sources._GH_REPO_RE.fullmatch(parts[1]) \
            or parts[1] in (".", ".."):
        return None, f"{value}: not owner/repo[/path]@ref"
    path = parts[2:]
    if len("/".join(path)) > 200 or any(p in (".", "..") or not _PATH_SEGMENT_RE.fullmatch(p) for p in path):
        return None, f"{value}: the path in the repository is not one that can be looked up"
    if not ref:
        return None, f"{value}: no ref"
    try:
        _sources._check_ref(ref)
    except SourceError:
        return None, f"{value}: the ref is an expression or not a valid ref, so it cannot be looked up"
    return Use(line, value, kind, parts[0], parts[1], "/".join(path), ref.lower() if pinned else ref,
               pinned, comment or ""), None


def uses_of(text):
    """[(line, value, comment)] of a workflow's `uses:` lines."""
    lines = text.split("\n")
    out = []
    for line, value in ghworkflow.uses(text):
        m = _COMMENT_RE.search(lines[line - 1]) if line - 1 < len(lines) else None
        out.append((line, value, m.group(1).strip() if m else ""))
    return out


# ------------------------------------------------------------------ what was seen
class PinBook:
    """Where version tags pointed when they were first seen: {`owner/repo@tag`:
    {sha, first, last[, moved: {to, at}]}} in a JSON file of the user's cache
    directory. A tag that moves keeps its first entry (the alert stays until
    the move is accepted: `accept`), and the file is only a record: if it is
    missing, nothing is found moved, never the other way round."""
    VERSION = 1

    def __init__(self, path):
        if path and os.path.exists(path) and not os.path.isfile(path):
            path = None                         # /dev/null, a folder: no book, and never written over
        self.path = path
        self.entries = {}
        self.dirty = False
        self.problem = None
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    loaded = json.load(f)
                tags = loaded.get("tags") if isinstance(loaded, dict) and loaded.get("version") == self.VERSION else None
                if isinstance(tags, dict):
                    self.entries = {k: v for k, v in tags.items() if self._ok(k, v)}
                else:
                    self.problem = "the pin book is not one this version reads; it was started again"
            except (OSError, ValueError, RecursionError):
                self.problem = "the pin book could not be read; it was started again"

    @staticmethod
    def _ok(key, entry):
        return (isinstance(key, str) and isinstance(entry, dict) and isinstance(entry.get("sha"), str)
                and _SHA40_RE.match(entry["sha"]) and isinstance(entry.get("first"), str)
                and isinstance(entry.get("last"), str))

    @staticmethod
    def key(owner, repo, tag):
        return f"{owner.lower()}/{repo.lower()}@{tag}"

    def see(self, key, sha, now):
        """Records a sighting. -> the entry the tag was first seen with when it now
        points elsewhere, else None."""
        entry = self.entries.get(key)
        if entry is None:
            self.entries[key] = {"sha": sha, "first": _iso(now), "last": _iso(now)}
            self.dirty = True
            return None
        if entry["sha"] == sha:
            if entry.get("moved") is not None:
                entry.pop("moved")
                self.dirty = True
            entry["last"] = _iso(now)
            self.dirty = True
            return None
        entry["moved"] = {"to": sha, "at": _iso(now)}
        self.dirty = True
        return dict(entry)

    def accept(self, key, sha, now):
        """Takes the tag's present commit as the one it is meant to have."""
        self.entries[key] = {"sha": sha, "first": _iso(now), "last": _iso(now)}
        self.dirty = True

    def save(self):
        if not self.path or not self.dirty:
            return
        items = sorted(self.entries.items(), key=lambda kv: kv[1]["last"])[-PIN_ENTRIES:]
        folder = os.path.dirname(self.path) or "."
        try:
            os.makedirs(folder, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".pins-", dir=folder)
        except OSError:
            return                              # a book that can't be written finds less, nothing else
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": self.VERSION, "tags": dict(items)}, f, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ------------------------------------------------------------------ the report
class Report:
    def __init__(self):
        self.findings = []
        self.incomplete = []        # (uses, why): not checked, so not cleared
        self.notes = []             # (uses, what): worth saying, not a finding
        self.resolved = {}          # `uses:` value -> the commit it points to now
        self.actions = {}           # `owner/repo[/path]@ref` -> what its action.yml runs
        self.calls = []
        self.checked = 0

    @property
    def complete(self):
        return not self.incomplete

    def to_json(self):
        return {"checked": self.checked, "complete": self.complete,
                "findings": [{"kind": f.kind, "line": f.line, "uses": f.uses, "detail": f.detail} for f in self.findings],
                "incomplete": [list(i) for i in self.incomplete], "notes": [list(n) for n in self.notes],
                "resolved": dict(self.resolved), "actions": dict(self.actions), "calls": list(self.calls)}


class _Stop(Exception):
    """GitHub will answer no more (the rate limit, a refused token) or the call budget is spent."""


class _Resolution:
    def __init__(self):
        self.sha = None
        self.kind = None            # 'commit' (a pin), 'tag' or 'branch'
        self.problems = []          # (kind, detail)
        self.notes = []


def _branch_rank(name):
    """Release branches first: a release tag is on one."""
    low = name.lower()
    return (0 if low.startswith(("releases/", "release/", "release-", "releases-")) or re.match(r"v?\d", low) else 1, name)


class Auditor:
    """Asks GitHub about `uses:` values. `http` is `sources.Client`'s network
    seam (tests give it fixed answers); `pins` a PinBook or None."""

    def __init__(self, env=None, http=None, pins=None, max_calls=None, now=None, accept_moved=False):
        env = os.environ if env is None else env
        token = _sources._token("github", env)
        self.client = _sources.Client("github", token=token, http=http)
        self.max_calls = max_calls if max_calls is not None else (CALLS_TOKEN if token else CALLS_ANONYMOUS)
        self.pins, self.accept_moved = pins, accept_moved
        self.now = now if now is not None else time.time
        self.report = Report()
        self.token = bool(token)
        self.stopped = None
        self._memo = {}
        self._done = {}
        self._actions = {}

    # ---- the API
    def _get(self, path, what, accept="application/vnd.github+json", max_bytes=None, missing=False):
        """The body of GET `path`, or None for a 404 or 422 when `missing`. Raises _Stop
        when GitHub will answer no more, SourceError for anything else."""
        url = f"https://{_sources.GITHUB_API}{path}"
        if url in self._memo:
            return self._memo[url]
        if self.stopped:
            raise _Stop(self.stopped)
        if len(self.client.calls) >= self.max_calls:
            hint = "" if self.token else "; GITHUB_TOKEN (read-only) raises it"
            self.stopped = f"the budget of {self.max_calls} API calls is spent{hint}"
            raise _Stop(self.stopped)
        try:
            raw = self.client.get(url, what, accept=accept, max_bytes=max_bytes or _sources.MAX_TREE_BYTES)
        except SourceError as exc:
            status = getattr(exc, "status", None)
            if missing and status in (404, 422):
                self._memo[url] = None
                return None
            if status == 401 or "rate limit" in str(exc):
                self.stopped = str(exc)
                raise _Stop(self.stopped) from None
            raise
        self._memo[url] = raw
        return raw

    def _json(self, path, what, missing=False):
        raw = self._get(path, what, missing=missing)
        return None if raw is None else _sources._json(raw, what)

    @staticmethod
    def _base(owner, repo):
        return f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"

    def repo_info(self, owner, repo):
        what = f"looking up {owner}/{repo}"
        doc = self._json(self._base(owner, repo), what, missing=True)
        if doc is None:
            return None
        if not isinstance(doc, dict) or not isinstance(doc.get("default_branch"), str):
            raise SourceError(f"{what}: unexpected answer")
        return doc

    def _named(self, owner, repo, what):
        """[(name, commit sha)] of the first 100 tags or branches."""
        path = f"{self._base(owner, repo)}/{what}?per_page=100"
        doc = self._json(path, f"listing the {what} of {owner}/{repo}")
        if not isinstance(doc, list):
            raise SourceError(f"listing the {what} of {owner}/{repo}: unexpected answer")
        out = []
        for e in doc:
            commit = e.get("commit") if isinstance(e, dict) else None
            sha = commit.get("sha") if isinstance(commit, dict) else None
            if isinstance(e, dict) and isinstance(e.get("name"), str) and isinstance(sha, str) and _SHA40_RE.match(sha):
                out.append((e["name"], sha))
        return out, len(doc)

    def ref_commit(self, owner, repo, ref):
        """('tag' | 'branch', commit sha) of a ref name, or None when there is no such ref."""
        for kind, space in (("tag", "tags"), ("branch", "heads")):
            what = f"resolving {owner}/{repo}@{ref}"
            doc = self._json(f"{self._base(owner, repo)}/git/ref/{space}/{urllib.parse.quote(ref, safe='/')}", what,
                             missing=True)
            if doc is None or isinstance(doc, list):
                continue
            obj = doc.get("object") if isinstance(doc, dict) else None
            for _ in range(4):                  # an annotated tag points to a tag object, which points to the commit
                typ, sha = (obj.get("type"), obj.get("sha")) if isinstance(obj, dict) else (None, None)
                if not isinstance(sha, str) or not _SHA40_RE.match(sha):
                    raise SourceError(f"{what}: unexpected answer")
                if typ == "commit":
                    return kind, sha
                if typ != "tag":
                    raise SourceError(f"{what}: the ref points to a {typ}, not a commit")
                tag_doc = self._json(f"{self._base(owner, repo)}/git/tags/{sha}", what)
                obj = tag_doc.get("object") if isinstance(tag_doc, dict) else None
            raise SourceError(f"{what}: too many tag objects in a row")
        return None

    def _compare(self, owner, repo, base, sha):
        """GitHub's status of `sha` against the branch `base`: identical, ahead, behind, diverged, or 'unrelated'."""
        what = f"comparing {sha[:12]} with {owner}/{repo}@{base}"
        doc = self._json(f"{self._base(owner, repo)}/compare/{urllib.parse.quote(base, safe='/')}...{sha}?per_page=1",
                         what, missing=True)
        if doc is None:
            return "unrelated"
        status = doc.get("status") if isinstance(doc, dict) else None
        if status not in ("identical", "ahead", "behind", "diverged"):
            raise SourceError(f"{what}: unexpected answer")
        return status

    def _exists(self, owner, repo, sha):
        return self._json(f"{self._base(owner, repo)}/commits/{sha}?per_page=1", f"looking up {owner}/{repo}@{sha[:12]}",
                          missing=True) is not None

    def reachable(self, owner, repo, sha, tag_tips=True):
        """Is `sha` in the history of a tag or a branch of the repository? -> ('yes', where),
        ('no', complete) with `complete` True when every tag tip and every branch was looked at,
        or ('missing', None) when there is no such commit. With `tag_tips` False the commit is
        looked for in the branches only (a tag's own commit is the tip of that tag)."""
        tags, tag_count = self._named(owner, repo, "tags") if tag_tips else ([], 0)
        for name, tip in tags:
            if tip == sha:
                return "yes", f"tag {name}"
        info = self.repo_info(owner, repo)
        default = info["default_branch"] if info else None
        branches, branch_count = self._named(owner, repo, "branches")
        names = [n for n, _ in branches if n != default]
        order = ([default] if default else []) + sorted(names, key=_branch_rank)
        compared = skipped = 0
        for name in order[:1 + MAX_BRANCHES]:
            try:
                _sources._check_ref(name)
            except SourceError:
                skipped += 1                    # a name that cannot go in a URL is not looked at
                continue
            if self._compare(owner, repo, name, sha) in ("behind", "identical"):
                return "yes", f"branch {name}"
            compared += 1
        if not self._exists(owner, repo, sha):
            return "missing", None
        complete = (tag_count < 100 and branch_count < 100 and default is not None
                    and skipped == 0 and compared == len(order))
        return "no", complete

    # ---- one action
    def _resolve(self, use):
        res = _Resolution()
        owner, repo, ref = use.owner, use.repo, use.ref
        if use.pinned:
            res.sha, res.kind = ref, "commit"
            where, extra = self.reachable(owner, repo, ref)
            if where == "no":
                res.problems.append(("impostor", {"sha": ref, "complete": extra}))
            elif where == "missing":
                res.sha = None
                res.notes.append(f"{ref[:12]} is not a commit of {owner}/{repo} or of a fork of it that GitHub shows "
                                 f"(the repository may be private, renamed or gone)")
            return res
        got = self.ref_commit(owner, repo, ref)
        if got is None:
            res.notes.append(f"{ref} is neither a tag nor a branch of {owner}/{repo} (the repository may be private, "
                             f"renamed or gone)")
            return res
        res.kind, res.sha = got
        if res.kind == "tag":
            if self.pins is not None and _exact_version(ref):
                key = PinBook.key(owner, repo, ref)
                if self.accept_moved:
                    self.pins.accept(key, res.sha, self.now())
                else:
                    was = self.pins.see(key, res.sha, self.now())
                    if was is not None:
                        res.problems.append(("tag-moved", {"tag": ref, "was": was["sha"], "now": res.sha,
                                                           "first": was["first"]}))
            where, extra = self.reachable(owner, repo, res.sha, tag_tips=False)
            if where == "no":
                res.problems.append(("off-branch", {"tag": ref, "sha": res.sha, "complete": extra}))
        return res

    def _check(self, use):
        key = (use.owner.lower(), use.repo.lower(), use.ref)
        if key not in self._done:
            try:
                self._done[key] = self._resolve(use)
            except SourceError as exc:          # asked once: a second line naming it gets the same answer
                self._done[key] = exc
                raise
            self.report.checked += 1
        got = self._done[key]
        if isinstance(got, SourceError):
            raise got
        return got

    def _comment_findings(self, use, res):
        """A pin whose comment names a version tag that points elsewhere."""
        tag = _comment_tag(use.comment)
        if not use.pinned or tag is None or not _exact_version(tag):
            return []
        got = self.ref_commit(use.owner, use.repo, tag)
        if got is not None and got[0] == "tag" and got[1] == use.ref:
            if self.pins is not None:
                self.pins.see(PinBook.key(use.owner, use.repo, tag), use.ref, self.now())
            return []
        return [("pin-mismatch", {"tag": tag, "tag_sha": got[1] if got is not None and got[0] == "tag" else None,
                                  "pin": use.ref})]

    def _action_yml(self, use, sha):
        key = (use.owner.lower(), use.repo.lower(), use.path, sha)
        if key in self._actions:
            return self._actions[key]
        text = None
        for name in ("action.yml", "action.yaml"):
            path = f"{use.path}/{name}" if use.path else name
            raw = self._get(f"{self._base(use.owner, use.repo)}/contents/{urllib.parse.quote(path, safe='/')}?ref={sha}",
                            f"reading {use.owner}/{use.repo}/{path}@{sha[:12]}", accept="application/vnd.github.raw+json",
                            max_bytes=MAX_ACTION_YML, missing=True)
            if raw is not None:
                text = raw.decode("utf-8", "replace")
                break
        self._actions[key] = text
        return text

    def _audit_use(self, use, line, via, depth):
        """Findings for one `uses:`, reported at the workflow's `line`."""
        rep = self.report
        res = self._check(use)
        chain = list(via)
        for kind, detail in res.problems + self._comment_findings(use, res):
            rep.findings.append(Finding(kind, line, use.value, dict(detail, owner=use.owner, repo=use.repo,
                                                                    via=chain)))
        for note in res.notes:
            rep.notes.append((use.value, note))
        if res.sha is None:
            return
        rep.resolved.setdefault(use.value, res.sha)
        if use.kind != "action" or depth > MAX_DEPTH:
            return
        text = self._action_yml(use, res.sha)
        if text is None:
            rep.notes.append((use.value, "no action.yml or action.yaml at that commit (a reusable workflow, or the "
                                         "path is wrong)"))
            return
        records = ghworkflow.outline(text)
        runs = {r["key"]: r["value"] for r in records if r["path"] == ("runs",) and r["key"] is not None}
        using = runs.get("using", "")
        rep.actions[f"{use.owner}/{use.repo}{'/' + use.path if use.path else ''}@{use.ref}"] = {
            "using": using, "pre": "pre" in runs, "post": "post" in runs}
        chain = chain + [use.value]
        if using.startswith("docker"):
            image = runs.get("image", "")
            if image.startswith("docker://"):
                parsed = ghworkflow.parse_uses(image)
                if parsed is not None and not parsed[3]:
                    rep.findings.append(Finding("docker-unpinned", line, use.value, {
                        "image": image, "owner": use.owner, "repo": use.repo, "via": list(via)}))
            elif image:
                rep.notes.append((use.value, f"builds its image from {image} in the repository: the Dockerfile's FROM "
                                             f"lines are not read yet"))
        for nested_line, value in [(r["line"], r["value"]) for r in records
                                   if r["key"] == "uses" and r["path"] == ("runs", "steps", "-")]:
            parsed = ghworkflow.parse_uses(value)
            if parsed is None:
                continue
            if not parsed[3]:
                rep.findings.append(Finding("nested-unpinned", line, use.value, {
                    "nested": value, "kind": parsed[0], "owner": use.owner, "repo": use.repo, "via": list(via),
                    "first": parsed[0] == "action" and parsed[1].lower().startswith(ghworkflow.FIRST_PARTY),
                    "tag": bool(re.match(r"v?\d", parsed[2]))}))
            nested, why = parse_use(line, value)
            if nested is None:
                if why:
                    rep.incomplete.append((value, f"inside {use.value}: {why}"))
                continue
            if depth < MAX_DEPTH and len(self._done) < MAX_USES:
                self._audit_use(nested, line, chain, depth + 1)

    def audit(self, uses):
        """Checks `uses`, [(line, value, comment)], and returns the Report."""
        rep = self.report
        stopped = None
        for line, value, comment in uses:
            use, why = parse_use(line, value, comment)
            if use is None:
                if why:
                    rep.incomplete.append((value, why))
                continue
            if stopped is not None:
                rep.incomplete.append((value, f"not checked: {stopped}"))
                continue
            if len(self._done) >= MAX_USES and (use.owner.lower(), use.repo.lower(), use.ref) not in self._done:
                rep.incomplete.append((value, f"not checked: more than {MAX_USES} different actions"))
                continue
            try:
                self._audit_use(use, line, (), 0)
            except _Stop as exc:
                stopped = str(exc)
                rep.incomplete.append((value, f"not checked: {stopped}"))
            except SourceError as exc:
                rep.incomplete.append((value, str(exc)))
        rep.findings = sorted(set_unique(rep.findings), key=lambda f: (f.line, f.kind, f.uses))
        rep.calls = list(self.client.calls)
        if self.pins is not None:
            if self.pins.problem:
                rep.notes.append(("", self.pins.problem))
            self.pins.save()
        return rep


def set_unique(findings):
    """The findings without repeats (an action used on two lines of one run is checked once)."""
    seen, out = set(), []
    for f in findings:
        key = (f.kind, f.line, f.uses, json.dumps(f.detail, sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def audit_text(text, **kw):
    """The Report for one workflow's text; `kw` are Auditor's."""
    return Auditor(**kw).audit(uses_of(text))


# ------------------------------------------------------------------ the rules
_IMPOSTOR_WHY = (
    "GitHub lets a commit that exists only in a fork be named under the original repository: "
    "`uses: owner/repo@<sha>` runs it, and the repository's own page does not show the commit. An attacker can fork "
    "an action, push a commit there, and pass the original's name with that commit's SHA off as a pinned release.")
_MOVED_WHY = (
    "A version tag names one release and should never point to another commit. In March 2025 the tags of "
    "tj-actions/changed-files were rewritten to a commit that printed every secret of the workflows that used it "
    "into their logs; the workflows that pinned a commit were not affected, the ones that trusted the tag were.")
_OFF_BRANCH_WHY = (
    "A release tag normally points to a commit on one of the repository's branches. One that does not may be a "
    "commit that was pushed to a fork, or to a branch that was deleted afterwards, and then given the release's name.")
_MISMATCH_WHY = (
    "A pin's comment says which release it is, and reviewers trust it. If the tag points to another commit than the "
    "pin, either the pin is stale or wrong, or the tag was moved, and nobody looking at the comment would see it.")
_DOCKER_WHY = (
    "A Docker action pulls its image when it runs: a tag on an image can be moved, and then the workflow runs "
    "other code than the one reviewed, with the job's token and secrets. An image digest can't be moved.")
_NESTED_WHY = (
    "A composite action runs the actions its steps name, with the job's token and secrets. Pinning the action to a "
    "commit does not pin what it uses: a tag in its action.yml can still be moved.")


def rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as core.mk_issue takes
    them — for one Finding's kind and detail."""
    who = f"{d['owner']}/{d['repo']}"
    via = f" (through {' > '.join(d['via'])})" if d.get("via") else ""
    if kind == "impostor":
        sure = d["complete"]
        if sure:
            msg = (f"The commit {d['sha'][:12]} of {who}{via} is in none of its branches and at the tip of none of its "
                   f"tags: it is an impostor commit, one pushed to a fork.")
        else:
            msg = (f"The commit {d['sha'][:12]} of {who}{via} was found in none of the tags and branches that were "
                   f"looked at (the first 100 tags and {MAX_BRANCHES + 1} branches at most): it may be an impostor "
                   f"commit from a fork, or on a branch that was not compared.")
        return {
            "id": "SC-ACTION-IMPOSTOR", "name": "Pinned commit is not in the action's repository",
            "type": "HOTSPOT", "sev": "CRITICAL" if sure else "MAJOR", "msg": msg, "why": _IMPOSTOR_WHY,
            "fix": ("Open the commit on GitHub and check that it belongs to the repository's own history. Pin the "
                    "commit of a release you have read instead, and read the action's code before it runs."),
            "ref": "CWE-829 · Supply chain"}
    if kind == "tag-moved":
        return {
            "id": "SC-ACTION-TAG-MOVED", "name": "Version tag of an action points to another commit",
            "type": "HOTSPOT", "sev": "CRITICAL",
            "msg": f"The tag {d['tag']} of {who}{via} pointed to {d['was'][:12]} when it was first seen "
                   f"({d['first']}) and points to {d['now'][:12]} now.",
            "why": _MOVED_WHY,
            "fix": (f"Do not run it. Compare {d['was'][:12]} and {d['now'][:12]} on GitHub; if the new commit is a "
                    f"change you can account for, pin that commit by its SHA, and accept the move "
                    f"(`--accept-moved`)."),
            "ref": "CWE-494 · Supply chain"}
    if kind == "off-branch":
        sure = d["complete"]
        return {
            "id": "SC-ACTION-OFF-BRANCH", "name": "Tag of an action points outside the repository's branches",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"The tag {d['tag']} of {who}{via} points to {d['sha'][:12]}, which is in none of "
                   + ("its branches." if sure else f"the branches compared ({MAX_BRANCHES + 1} at most) or at the tip "
                                                   "of any of the first 100 tags."),
            "why": _OFF_BRANCH_WHY,
            "fix": f"Check the commit on GitHub, and pin the SHA of a release you have read (now {d['sha']}).",
            "ref": "CWE-829 · Supply chain"}
    if kind == "pin-mismatch":
        what = (f"points to {d['tag_sha'][:12]}" if d["tag_sha"] else "is not a tag of the repository")
        return {
            "id": "SC-ACTION-PIN-MISMATCH", "name": "Pinned commit does not match its version comment",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"{who}{via} is pinned to {d['pin'][:12]} with the comment {d['tag']}, but {d['tag']} {what}.",
            "why": _MISMATCH_WHY,
            "fix": ("Find out which is right: if the tag is, update the pin to its commit; if the pin is, correct "
                    "the comment, and check that the tag was not moved."),
            "ref": "CWE-1357 · Supply chain"}
    if kind == "docker-unpinned":
        return {
            "id": "SC-ACTION-DOCKER-UNPINNED", "name": "Docker action runs an image not pinned to a digest",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"The action {who}{via} runs the image {d['image']}, which is not pinned to a digest.",
            "why": _DOCKER_WHY,
            "fix": "Use a version of the action that pins the image `@sha256:…`, or a different action.",
            "ref": "CWE-829 · Supply chain"}
    small = d.get("kind") == "action" and d.get("first") and d.get("tag")
    return {
        "id": "SC-ACTION-NESTED-UNPINNED", "name": "Action's own steps use something not pinned to a commit",
        "type": "HOTSPOT", "sev": "MINOR" if small else "MAJOR",
        "msg": f"The composite action {who}{via} uses {d['nested']}, which is not pinned to a commit.",
        "why": _NESTED_WHY,
        "fix": "Use a version of the action that pins what it uses, or a different action.",
        "ref": "CWE-829 · Supply chain"}


# ------------------------------------------------------------------ the command
def main(argv=None):
    """python -m lazaret.registry.actions [--no-pins | --pins FILE] [--accept-moved] [--max-calls N] WORKFLOW..."""
    _core.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = ("usage: python -m lazaret.registry.actions [--no-pins | --pins FILE] [--accept-moved] "
             "[--max-calls N] WORKFLOW...")
    pins_path, use_pins, accept, max_calls, files = default_pins_path(), True, False, None, []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--no-pins":
            use_pins = False
        elif a == "--accept-moved":
            accept = True
        elif a in ("--pins", "--max-calls") and i + 1 < len(argv):
            i += 1
            if a == "--pins":
                pins_path = argv[i]
            elif argv[i].isdigit():
                max_calls = int(argv[i])
            else:
                print(usage, file=sys.stderr)
                return 2
        elif a.startswith("--"):
            print(usage, file=sys.stderr)
            return 2
        else:
            files.append(a)
        i += 1
    if not files:
        print(usage, file=sys.stderr)
        return 2
    rep_all = []
    code = 0
    pins = PinBook(pins_path) if use_pins else None
    for path in files:
        try:
            with open(path, "rb") as f:
                text = f.read(MAX_WORKFLOW_BYTES + 1)
        except OSError as exc:
            print(f"error: {path}: {exc.strerror or type(exc).__name__}", file=sys.stderr)
            return 2
        if len(text) > MAX_WORKFLOW_BYTES:
            print(f"error: {path}: larger than {MAX_WORKFLOW_BYTES // 1024} KB", file=sys.stderr)
            return 2
        try:
            rep = audit_text(text.decode("utf-8", "replace"), pins=pins, max_calls=max_calls, accept_moved=accept)
        except SourceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        doc = rep.to_json()
        doc["file"] = path
        doc["rules"] = [rule(f.kind, f.detail) for f in rep.findings]
        rep_all.append(doc)
        if rep.findings:
            code = max(code, 1)
        elif not rep.complete and code == 0:
            code = 3
    print(json.dumps(rep_all, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
