"""What a workflow's `uses:` lines really point to (0.1.9, S-2, the online half).

The offline checks (`scanner/ghworkflow.py`, `hardening`) say that a `uses:`
is not pinned. These ask GitHub what each one points to, each action once:

- **impostor commit** (RA-4, `actionrefs.py`): the commit a `uses:` runs, pinned
  by its SHA or named by a tag, that none of the repository's branches holds.
  GitHub resolves a commit of any fork in the network under the parent's name,
  so `actions/checkout@<a commit pushed to a fork>` runs the fork's code while
  the repository's page shows nothing, and a tag of the parent can be moved onto
  such a commit (actions-cool/issues-helper, May 2026: every tag). Each commit is
  compared with the default branch, then the likeliest other branches, within a
  budget of compares; a check that could not finish is `incomplete`, never the
  finding. A pin may name an annotated tag's object rather than a commit
  (`actions/github-script@d746ffe…`, the object of v9.0.0): the runner runs the
  commit it tags, so that commit is the one checked, here and below, and the
  report says which tag object the pin is (`tag_objects`, and a note). Asking
  (`git/tags/{sha}`) costs a call for each pinned SHA the default branch's
  compare does not hold, and with the branch check off for each pinned SHA; a
  pin GitHub does not answer it for is checked as a commit, as before. A
  commit no branch holds may be a release that was tagged and never merged
  (FP-IMPOSTOR-TAG: mmastrac/mmm-matrix@3edd85c…, held by the tag v1.0.5 and
  by none of its 5 branches): for that answer, and only then, one more
  question, whether exactly one of the repository's own exact version tags
  (v4.1.0, not v4 or latest) points to that commit
  (`GET /repos/{o}/{r}/tags`: one to `actionrefs.TAG_PAGES` calls, once per
  repository per command, out of the call budget). No such tag:
  SC-ACTION-IMPOSTOR, CRITICAL. Two or more version tags at that one commit
  are the shape of tags moved onto one commit (actions-cool's), not a release
  kept by its tag: CRITICAL whatever the pin book says. One tag found while
  the listing did not reach every tag (a full last page) may have a second
  among the rest: CRITICAL as well. The one tag, every tag read, and its
  record at that commit carries SC-ACTION-TAG-ONLY's own mark, given at that
  commit before the command began: a note, no finding. No such mark (a first
  sighting, a record another check wrote, no pin book): SC-ACTION-TAG-ONLY,
  MAJOR, and the record marked, so that a later command says whether the tag
  stayed. A tag the pin book saw at another commit (or flagged moved), a
  commit a tag was moved onto and the move accepted (`moved_from`, or a mark
  given at another commit: accepting silences SC-ACTION-TAG-MOVED, never
  this, and the commit stays CRITICAL until its record is deleted by hand), a
  listing that failed or was refused, a record that could not be read or
  kept: CRITICAL, with a note. The files of one command share its start, the
  records as they were before it and the listings (`Run`).
- **a tag that moved**: a version tag (`v4.1.0`; not the floating `v4`) that
  points to another commit than when it was first seen (the tj-actions shape):
  MAJOR, and CRITICAL when the commit it moved to is in none of the branches.
  What was seen is kept in a small file, the pin book, or with `--db` in the
  registry's database (the table action_tags); the first sighting is no finding.
- **a pin that does not match its comment**: `@<sha> # v4.1.0`, where v4.1.0
  points to another commit, or to none, or where the pin is the tag object of
  another name.
- **the action's own `action.yml`**: a Docker image not pinned to a digest; for
  a composite action, the `uses:` of its steps that are not pinned, and each of
  those checked the same way, two levels deep.
- **the action's own code, at the commit it resolves to** (N-4): the archive
  the runner fetches (GitHub's archive of the commit, from
  `codeload.github.com`, or through the API with a token) is scanned as the
  action runs (`repo.scan_action`): a JavaScript action's `pre`, `main` and
  `post` scripts and the modules they load by the import-time test; a
  composite action's steps as install hooks are read, with the action's own
  scripts they run; a Docker action's Dockerfile, its base images (one not
  pinned to a digest is `docker-unpinned`) and the script its entrypoint runs.
  What it finds is a `code` finding with the scan's own rule; an archive not
  read whole leaves the action `incomplete`. `--no-code` skips it.

What it cannot tell is said, not skipped: a request GitHub refused (the rate
limit, 60 an hour without `GITHUB_TOKEN`, which is read-only and goes to
`api.github.com` only), the call budget, an expression in a ref, a private
repository, are reported as `incomplete`, and an action that was not checked
is not cleared. The rules are `sources.py`'s: HTTPS to `api.github.com` only,
every name from the workflow validated before it is put in a URL, a response
byte-budgeted and read as JSON with limits, nothing run and nothing written but
the pin book (or the database's action_tags).

    python -m lazaret.registry.actions [--no-pins | --pins FILE | --db DSN] [--accept-moved]
                                       [--max-calls N] [--no-code] WORKFLOW...

prints the report as JSON; exit 1 for a finding of MAJOR or above, 3 when
something could not be checked, 2 for a usage error. A MINOR finding is listed
and does not change the exit: a GitHub-owned action at a version tag, an
official Docker image at one, and a binary one of GitHub's own actions ships
(actions/setup-node's externals/7zr.exe, the 7-Zip it extracts Node with on
Windows), where any strong finding of their code still counts in full.
"""

import copy
import json
import os
import re
import sys
import tempfile
import time
import urllib.parse
from collections import namedtuple

from lazaret.registry import actionrefs as _refs
from lazaret.registry import repo as _repo
from lazaret.registry import sources as _sources
from lazaret.scanner import core as _core
from lazaret.scanner import ghworkflow

__all__ = ["Finding", "Report", "PinBook", "Run", "Auditor", "Use", "parse_use", "audit_text", "rule",
           "default_pins_path"]

SourceError = _sources.SourceError

CALLS_ANONYMOUS = 45        # GitHub allows 60 an hour without a token: some is left for the user's other tools
CALLS_TOKEN = 400
MAX_DEPTH = 2               # an action's steps' actions, and theirs
MAX_USES = 300              # distinct actions looked at in one run
MAX_ACTION_YML = 256 * 1024
PIN_ENTRIES = 5000
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
MAX_CODE_SCANS = 60         # actions' archives fetched and scanned in one run (N-4)
MAX_CODE_BYTES = 1024 ** 3  # bytes of those archives in one run
MAX_CODE_FINDINGS = 20      # findings reported for one action's code; the rest are counted in a note
VERSION_TAGS_LISTED = 10    # version tags named in an impostor's detail (FP-IMPOSTOR-TAG); the rest are counted
#: the severities that make the command exit 1 (a MINOR finding is listed only)
COUNTED = ("MAJOR", "CRITICAL", "BLOCKER")
#: weak findings of an action's code that are MINOR in GitHub's own actions (ghworkflow.FIRST_PARTY): the tools they
#: ship (a binary: actions/setup-node's externals/7zr.exe). A strong finding of their code is not lowered
FIRST_PARTY_SMALL = frozenset({"SC-BINARY"})
#: Docker's official images (`alpine`, `docker.io/library/python`): at a version tag, a smaller risk than another's
_OFFICIAL_IMAGE_RE = re.compile(r"^(?:(?:docker\.io|index\.docker\.io|registry-1\.docker\.io)/)?(?:library/)?"
                                r"[a-z0-9]+(?:[._-][a-z0-9]+)*:v?\d[\w.-]*$")

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


def _version_order(tag):
    """A sort key of exact version tags: by their numbers (compared as digit strings: no int of any length), a
    pre-release before its release, then by name."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(.*)$", tag)
    if not m:
        return ((), True, tag, tag)
    nums = tuple((len(g.lstrip("0")), g.lstrip("0")) for g in m.groups()[:3])
    return (nums, m.group(4) == "", m.group(4), tag)


def _tag_span(names, count):
    """Version tags for a message: a few named, more as the first … the last of those listed."""
    shown = ", ".join(names) if len(names) <= 3 else f"{names[0]} … {names[-1]}"
    return shown + (f" (and {count - len(names)} more)" if count > len(names) else "")


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

    def record(self, key):
        """-> the tag's record ({sha, first, last[, moved]}), or None."""
        entry = self.entries.get(key)
        return copy.deepcopy(entry) if entry is not None else None

    def see(self, key, sha, now, tag_only=False):
        """Records a sighting. -> the entry the tag was first seen with when it now
        points elsewhere, else None (actionrefs.sighting; `tag_only`: SC-ACTION-TAG-ONLY's)."""
        self.entries[key], was = _refs.sighting(self.entries.get(key), sha, now, tag_only)
        self.dirty = True
        return was

    def accept(self, key, sha, now, tag_only=False):
        """Takes the tag's present commit as the one it is meant to have (actionrefs.accepted:
        the commit it moved from is kept)."""
        self.entries[key] = _refs.accepted(self.entries.get(key), sha, now, tag_only)
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
        self.branches = {}          # `uses:` value -> the branch of its repository found to hold that commit (RA-4)
        self.tag_objects = {}       # `uses:` value -> {tag, object, commit}: a pin that names an annotated tag's object
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
                "resolved": dict(self.resolved), "branches": dict(self.branches),
                "tag_objects": dict(self.tag_objects), "actions": dict(self.actions), "calls": list(self.calls)}


class _Stop(Exception):
    """GitHub will answer no more (the rate limit, a refused token) or the call budget is spent."""


class _CodeLimit(Exception):
    """The run's budget for actions' archives (MAX_CODE_SCANS, MAX_CODE_BYTES) is spent."""


class _Resolution:
    def __init__(self):
        self.sha = None
        self.kind = None            # 'commit' (a pin), 'tag' or 'branch'
        self.problems = []          # (kind, detail)
        self.notes = []
        self.where = None           # the branch found to hold the commit (RA-4)
        self.unsettled = []         # what was not checked of it: each an `incomplete` of the uses: line
        # a pin: the tag object it names (actionrefs.TagObject; `sha` is then its commit), and whether it is known to
        # be one or a commit (True; False: it could not be told, said in `unsettled`, and `sha` is not reported as
        # resolved; None: not a pin)
        self.tag_object = None
        self.peeled = None
        self.branch_error = None    # the SourceError the branch check stopped on
        self.stopped = False        # the branch check was refused (_Stop), and said so in `unsettled`


class Run:
    """What the Auditors of one command share, over its workflow files and with one pin book (FP-IMPOSTOR-TAG):
    `started`, the command's start (the first Auditor's clock: a tag's `tag_only` mark made before it is an earlier
    command's); `before`, each tag's record as it was before the command first wrote to it (Auditor._book_record);
    `listed`, the repositories' tag listings (actionrefs.Branches.tags: one per repository for the command). An Auditor
    made without one has its own: the run is then that Auditor's."""

    def __init__(self):
        self.started = None
        self.before = {}
        self.listed = {}


class Auditor:
    """Asks GitHub about `uses:` values. `http` is `sources.Client`'s network
    seam (tests give it fixed answers); `pins` a PinBook or None; `run` the Run
    the command's other Auditors share (one is made when it is not given)."""

    def __init__(self, env=None, http=None, pins=None, max_calls=None, now=None, accept_moved=False, code=True,
                 run=None):
        env = os.environ if env is None else env
        token = _sources._token("github", env)
        self.client = _sources.Client("github", token=token, http=http)
        self.max_calls = max_calls if max_calls is not None else (CALLS_TOKEN if token else CALLS_ANONYMOUS)
        self.pins, self.accept_moved = pins, accept_moved
        self.now = now if now is not None else time.time
        # the command's start, the records as they were before it wrote to them, the tag listings (FP-IMPOSTOR-TAG)
        self.run = run if run is not None else Run()
        if self.run.started is None:
            self.run.started = _iso(self.now())
        self._started, self._before = self.run.started, self.run.before
        self.report = Report()
        self.token = bool(token)
        self.stopped = None
        # RA-4: is each commit in its repository's branches (actionrefs.Branches; its answers kept per repository
        # and commit for the run); LAZARET_NO_ACTION_BRANCHES=1 turns it off
        self.branch_check = _refs.enabled(env)
        self.branches = _refs.Branches(self._json, listed=self.run.listed)
        self._memo = {}
        self._done = {}
        self._actions = {}
        # the actions' own code (N-4): scanned once per action and commit; the last archive is kept for the
        # next action of the same repository and commit; the engine's answers are shared between scans
        self.code = code
        self._code = {}
        self._archive = None
        self._archives, self._archive_bytes = 0, 0
        self._engine_memo = _repo.new_memo() if code else None

    def api_calls(self):
        """The calls made to the API (the budget counts these; an archive from codeload is not one)."""
        head = f"https://{_sources.GITHUB_API}/"
        return sum(1 for c in self.client.calls if c.startswith(head))

    # ---- the API
    def _get(self, path, what, accept="application/vnd.github+json", max_bytes=None, missing=False):
        """The body of GET `path`, or None for a 404 or 422 when `missing`. Raises _Stop
        when GitHub will answer no more, SourceError for anything else."""
        url = f"https://{_sources.GITHUB_API}{path}"
        if url in self._memo:
            return self._memo[url]
        self._may_call()
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

    def _may_call(self):
        """Raises _Stop when GitHub will answer no more or the budget of API calls is spent."""
        if self.stopped:
            raise _Stop(self.stopped)
        if self.api_calls() >= self.max_calls:
            hint = "" if self.token else "; GITHUB_TOKEN (read-only) raises it"
            self.stopped = f"the budget of {self.max_calls} API calls is spent{hint}"
            raise _Stop(self.stopped)

    def _json(self, path, what, missing=False):
        raw = self._get(path, what, missing=missing)
        return None if raw is None else _sources._json(raw, what)

    @staticmethod
    def _base(owner, repo):
        return f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"

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

    def _branch_answer(self, use, res):
        """RA-4: the branch check of the commit `res.sha` (actionrefs.Branches.check) -> its Answer, or None when it
        was not made (LAZARET_NO_ACTION_BRANCHES) or could not finish on an error, the rate limit or the call budget
        (said in res.unsettled, never a finding). A repository that cannot be seen is raised: the action is not
        checked at all."""
        if not self.branch_check:
            return None
        label = f"{use.owner}/{use.repo}"
        try:
            return self.branches.check(use.owner, use.repo, res.sha, pinned=use.pinned)
        except _Stop as exc:
            res.stopped = True
            res.unsettled.append(f"whether {res.sha[:12]} is in {label}'s branches was not checked: {exc}")
        except SourceError as exc:
            if getattr(exc, "status", None) == 404:
                raise
            res.branch_error = exc
            res.unsettled.append(f"whether {res.sha[:12]} is in {label}'s branches could not be settled: {exc}")
        return None

    @staticmethod
    def _pinned_tag(res, obj):
        """The pin is the tag object `obj`: its commit is what runs, so what the scan checks (the report says so
        once for the use: _audit_use)."""
        res.tag_object, res.sha, res.peeled = obj, obj.commit, True

    def _ask_tag_object(self, use, res):
        """Is the pin a tag object? Asked (actionrefs.Branches.tag_object, kept for the run: an answer the branch
        check already has costs nothing) where the branch check did not answer it: not made
        (LAZARET_NO_ACTION_BRANCHES), or stopped on an error or a refusal before it could. Sets res.peeled; a question
        that fails is said in res.unsettled. Raises _Stop when GitHub answers no more: the run then says the use was
        not checked."""
        try:
            obj = self.branches.tag_object(use.owner, use.repo, use.ref)
        except SourceError as exc:
            res.peeled = False
            if exc is not res.branch_error:     # (the branch check stopped on it: said once)
                res.unsettled.append(f"whether {use.ref[:12]} is a commit or a tag object of {use.owner}/{use.repo} "
                                     f"could not be settled: {exc}")
            return
        res.peeled = True
        if obj is not None:
            self._pinned_tag(res, obj)

    @staticmethod
    def _pinned_answer(use, res, answer):
        """What the branch check's answer says of a pin: the tag object it names, or that it is a commit (a branch
        holds it, GitHub shows it as one, or git/tags said it is no tag object), or that this could not be told
        (GitHub did not answer git/tags, and the commit check did not settle it)."""
        if answer.tag_object is not None:
            Auditor._pinned_tag(res, answer.tag_object)
            return
        res.peeled = answer.tag_error is None or answer.state in ("in", "out")
        if answer.tag_error is not None and answer.state in ("out", "unsettled"):
            res.notes.append(f"whether {use.ref[:12]} is a tag object of {use.owner}/{use.repo} could not be asked "
                             f"({answer.tag_error}): it was checked as a commit")

    def _tag_seen(self, use, res):
        """An exact version tag's sighting in the pin book (or the database's): -> the tag-moved detail when it
        points elsewhere than when first seen, else None. A record that could not be kept is res.unsettled."""
        if res.kind != "tag" or self.pins is None or not _exact_version(use.ref):
            return None
        key = PinBook.key(use.owner, use.repo, use.ref)
        try:
            was = self._book_write(key, res.sha)
        except _refs.BookError as exc:
            res.unsettled.append(str(exc))
            return None
        if was is None:
            return None
        return {"tag": use.ref, "was": was["sha"], "now": res.sha, "first": was["first"]}

    def _book_record(self, key):
        """The pin book's record of the tag `key` as it was before this run first wrote to it: a dict, None, or the
        BookError reading it raised (asked once). Taken before each of the run's writes, so that a record made (or a
        move cleared) earlier in the run is never taken for one an earlier run left."""
        if key not in self._before:
            try:
                entry = self.pins.record(key)
            except _refs.BookError as exc:
                entry = exc
            self._before[key] = copy.deepcopy(entry) if isinstance(entry, dict) else entry
        return self._before[key]

    def _book_write(self, key, sha, tag_only=False):
        """A sighting of the tag `key` at `sha` in the pin book, the record before it kept first (_book_record); with
        --accept-moved, the tag's present commit is taken as the one it is meant to have (PinBook.accept, which keeps
        the commit it moved from). `tag_only`: SC-ACTION-TAG-ONLY's sighting, which marks the record (`tag_only`).
        -> the record it was first seen with when it now points elsewhere, else None. Raises BookError."""
        self._book_record(key)
        if self.accept_moved:
            self.pins.accept(key, sha, self.now(), tag_only=tag_only)
            return None
        return self.pins.see(key, sha, self.now(), tag_only=tag_only)

    def _held_by_tag(self, use, res, answer):
        """RA-4's `out` answer (FP-IMPOSTOR-TAG): does exactly one of the repository's own exact version tags point to
        the commit res.sha (actionrefs.Branches.tags: one listing a repository for the command)? -> ("impostor",
        extra) when that is not proven, or the tag is not known to have stayed: the commit is an impostor (CRITICAL;
        `extra`, for its detail, names the version tags found at it), and a note says why where tags were found or
        could not all be read; ("tag-only", detail) when the one tag's record at the commit has no SC-ACTION-TAG-ONLY
        mark from before the command (a first sighting, a record `_tag_seen`, `_comment_findings` or an accept wrote,
        a mark made in this command, one that names no commit), or there is no pin book: MAJOR, and the record marked
        (`tag_only`: this commit and the time), so that a later command says whether the tag stayed; ("held", note)
        when the record carries that mark, given at this commit before the command began, with no move flagged and
        none accepted onto it (no finding). A mark given at another commit than the record's is a move onto it that
        an accept recorded nowhere (an older version's, whose database update leaves the mark): CRITICAL. Two or more
        version tags at one commit no branch holds are the shape of tags moved onto one commit (the actions-cool
        shape), never a release commit kept by its tag: CRITICAL whatever the pin book says. One found while the
        listing did not reach every tag (a full last page) may have a second among those not read: CRITICAL too. A
        record whose commit a tag was moved onto, the move accepted (`moved_from`), is CRITICAL: accepting a move
        silences SC-ACTION-TAG-MOVED, never this. A refusal (_Stop: the rate limit, the call budget) is a note here
        as well; GitHub answering no more (self.stopped) then leaves this use and the rest of the run "not checked",
        as any refusal does (_audit_use, audit)."""
        label, short = f"{use.owner}/{use.repo}", res.sha[:12]
        stands = "the commit is reported as in none of the branches"
        try:
            listed = self.branches.tags(use.owner, use.repo)
        except _Stop as exc:
            self.stopped = self.stopped or str(exc)         # (never swallowed: the run stops on it as on any refusal)
            res.notes.append(f"whether a version tag of {label} points to {short} was not asked ({exc}): {stands}")
            return "impostor", {}
        except SourceError as exc:
            res.notes.append(f"whether a version tag of {label} points to {short} could not be asked ({exc}): "
                             f"{stands}")
            return "impostor", {}
        names = sorted({n for n in listed.at.get(res.sha, ()) if _exact_version(n)}, key=_version_order)
        pages = f"{listed.pages} page{'' if listed.pages == 1 else 's'} of {_refs.TAG_PAGE}"
        if not names:
            if listed.more:
                res.notes.append(f"none of the {listed.read} tags of {label} read ({pages}) is a version tag at "
                                 f"{short}, and it has more, which were not read: {stands}")
            return "impostor", {}
        found = {"version_tags": names[:VERSION_TAGS_LISTED], "version_tag_count": len(names)}
        if len(names) > 1:
            res.notes.append(f"{len(names)} version tags of {label} point to {short}, "
                             f"{_tag_span(found['version_tags'], len(names))}: the shape of tags moved onto one "
                             f"commit, not a release commit kept by its tag: {stands}")
            return "impostor", found
        tag = names[0]
        if listed.more:
            res.notes.append(f"the version tag {tag} of {label} points to {short}, but not every tag was read "
                             f"({listed.read} in {pages}, and it has more), so another version tag may point to it "
                             f"as well: {stands}")
            return "impostor", found
        detail = {"sha": res.sha, "ref": use.ref, "tag": tag, "branches": answer.branches,
                  "compared": list(answer.compared), "recorded": False}
        if res.tag_object is not None:
            detail["tag_object"] = res.tag_object.tag
        if self.pins is None:
            return "tag-only", detail
        key = PinBook.key(use.owner, use.repo, tag)
        before, failed, was = self._book_record(key), None, None
        if isinstance(before, _refs.BookError):
            failed = before
            if str(before) not in res.unsettled:
                res.unsettled.append(str(before))
        rec = before if isinstance(before, dict) else None
        elsewhere = rec is not None and rec.get("sha") != res.sha        # first seen at another commit: it moved
        flagged = rec is not None and not elsewhere and bool(rec.get("moved"))     # moved away, the move not accepted
        onto = rec is not None and not elsewhere and bool(rec.get("moved_from"))   # moved onto it, the move accepted
        mark_sha, mark_at = _refs.mark_of(rec)
        # a mark given at another commit than the record's: the record was moved onto this commit by an accept that
        # kept no `moved_from` (an older version's, whose update of the database's row leaves the mark): as `onto`
        unrecorded = rec is not None and not elsewhere and mark_sha is not None and mark_sha != res.sha
        clean = failed is None and not (elsewhere or flagged or onto or unrecorded)
        # the note only where SC-ACTION-TAG-ONLY's own mark, given at this commit before the command began, is on a
        # record at this commit that nothing speaks against (a record another check wrote, or a later one, has none)
        held = clean and mark_sha == res.sha and mark_at < self._started
        if not (flagged and not self.accept_moved):
            try:                            # (not when back at its first commit: a sighting would clear the move)
                # (see keeps a moved tag's first commit and adds `moved`; the mark is written on a MAJOR only)
                was = self._book_write(key, res.sha, tag_only=clean and not held)
            except _refs.BookError as exc:
                failed = failed or exc
                if str(exc) not in res.unsettled:
                    res.unsettled.append(str(exc))
        if elsewhere or was is not None:
            seen = rec if elsewhere else was                # (was: recorded at another commit earlier in the command)
            why = f"the pin book first saw it at {str(seen.get('sha'))[:12]} ({seen.get('first')}): it moved"
        elif flagged:
            to = rec["moved"] if isinstance(rec.get("moved"), dict) else {}
            why = (f"the pin book saw it at {str(to.get('to'))[:12]} since ({to.get('at')})"
                   + ("" if self.accept_moved else ", a move not accepted"))
        elif onto:
            frm = rec["moved_from"] if isinstance(rec.get("moved_from"), dict) else {}
            why = (f"it was moved onto it (from {str(frm.get('sha'))[:12]}, accepted {frm.get('at')}): accepting a "
                   f"move does not make it a release commit kept by its tag")
        elif unrecorded:
            why = (f"it was moved onto it from {mark_sha[:12]}, where SC-ACTION-TAG-ONLY was given ({mark_at}), by "
                   f"an accept that kept no record of the move (an older version's): accepting a move does not make "
                   f"it a release commit kept by its tag")
        elif failed is not None:
            why = "its record in the pin book could not be read or kept"
        else:
            why = None
        if why is not None:
            res.notes.append(f"the version tag {tag} of {label} points to {short}, but {why}: {stands}")
            return "impostor", found
        if held:
            return "held", (f"only the tag {tag} of {label} holds {short}, {_none_of(answer.branches)}: a release "
                            f"commit kept by its tag, seen at it since {rec.get('first')}")
        detail["recorded"] = True
        return "tag-only", detail

    # ---- one action
    def _resolve(self, use):
        res = _Resolution()
        owner, repo, ref = use.owner, use.repo, use.ref
        if use.pinned:
            res.sha, res.kind = ref, "commit"
        else:
            got = self.ref_commit(owner, repo, ref)
            if got is None:
                res.notes.append(f"{ref} is neither a tag nor a branch of {owner}/{repo} (the repository may be "
                                 f"private, renamed or gone)")
                return res
            res.kind, res.sha = got
        moved = self._tag_seen(use, res)
        # a pin and a tag are checked alike (an imposter can be pinned by its SHA too); a branch's head is its own
        answer = self._branch_answer(use, res) if res.kind != "branch" else None
        if use.pinned:
            # a pin may name a tag object: the branch check asks when the default branch does not hold the pin; not
            # made (LAZARET_NO_ACTION_BRANCHES) or stopped before it could, it is asked here
            if answer is not None:
                self._pinned_answer(use, res, answer)
            else:
                try:
                    self._ask_tag_object(use, res)
                except _Stop:
                    if not res.stopped:
                        raise                   # not said of this use yet: the run says it, and of the uses after it
                    res.peeled = False          # (said: the branch check was refused)
        if answer is not None:
            if answer.state == "in":
                res.where = answer.where
            elif answer.state == "out":
                # held by one of the repository's own version tags (FP-IMPOSTOR-TAG)? Not asked of a tag the pin book
                # found moved: that stays CRITICAL whatever the tags say
                held = self._held_by_tag(use, res, answer) if moved is None else ("impostor", {})
                if held[0] == "impostor":
                    detail = {"sha": res.sha, "ref": ref, "tag": res.kind == "tag", "branches": answer.branches}
                    if res.tag_object is not None:
                        detail["tag_object"] = res.tag_object.tag
                    detail.update(held[1])          # (the version tags found at it, when any were)
                    res.problems.append(("impostor", detail))
                elif held[0] == "tag-only":
                    res.problems.append(held)
                else:
                    res.notes.append(held[1])
            elif answer.state == "missing" and use.pinned and res.tag_object is None and answer.tag_error is None:
                res.sha = None
                res.notes.append(f"{ref[:12]} is not a commit of {owner}/{repo} or of a fork of it that GitHub shows "
                                 f"(the repository may be private, renamed or gone)")
            elif answer.state == "missing" and use.pinned and res.tag_object is None:
                res.sha = None                  # (perhaps a tag object, which GitHub did not say)
                res.unsettled.append(f"GitHub does not show {ref[:12]} as a commit of {owner}/{repo}, and whether it "
                                     f"is a tag object could not be asked: {answer.tag_error}")
            elif answer.state == "missing":
                what = (f"the tag object {res.tag_object.tag} ({ref[:12]})" if res.tag_object is not None
                        else f"the tag {ref}")
                res.unsettled.append(f"GitHub does not show the commit {res.sha[:12]} {what} of "
                                     f"{owner}/{repo} points to, so whether it is in the branches is not settled")
            else:
                res.unsettled.append(f"whether {res.sha[:12]} is in {owner}/{repo}'s branches is not settled: "
                                     f"{answer.why}")
        if moved is not None:
            moved["fork"] = answer is not None and answer.state == "out"
            res.problems.append(("tag-moved", moved))
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
        """A pin whose comment names a version tag that points elsewhere, or whose tag object is another tag's. A
        pin that names a tag object is the commit it tags, and the object's name is compared with the comment; a pin
        not known to be a commit or a tag object (the question failed: the use is incomplete) is no mismatch."""
        tag = _comment_tag(use.comment)
        if not use.pinned or tag is None or not _exact_version(tag):
            return []
        got = self.ref_commit(use.owner, use.repo, tag)
        tag_sha = got[1] if got is not None and got[0] == "tag" else None
        obj, commit = res.tag_object, res.sha or use.ref
        if obj is None and tag_sha != commit and res.peeled is False:
            return []
        if tag_sha != commit or (obj is not None and obj.tag != tag):
            detail = {"tag": tag, "tag_sha": tag_sha, "pin": use.ref}
            if obj is not None:
                detail.update(pin_tag=obj.tag, pin_commit=obj.commit)
            return [("pin-mismatch", detail)]
        if self.pins is not None:
            key = PinBook.key(use.owner, use.repo, tag)
            self._book_record(key)
            try:
                self.pins.see(key, commit, self.now())
            except _refs.BookError as exc:
                self.report.incomplete.append((use.value, str(exc)))
        return []

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

    # ---- the action's own code (N-4)
    @staticmethod
    def _label(use):
        return f"{use.owner}/{use.repo}{'/' + use.path if use.path else ''}@{use.ref}"

    def _fetch_archive(self, use, sha):
        """The archive GitHub serves for the commit (what the runner fetches), checked against it. Raises
        _CodeLimit past the run's budget, _Stop when GitHub will answer no more, SourceError otherwise."""
        key = (use.owner.lower(), use.repo.lower(), sha)
        if self._archive is not None and self._archive[0] == key:
            return self._archive[1]
        if self._archives >= MAX_CODE_SCANS:
            raise _CodeLimit(f"its code was not scanned: more than {MAX_CODE_SCANS} actions' archives in one run")
        if self._archive_bytes >= MAX_CODE_BYTES:
            raise _CodeLimit(f"its code was not scanned: the run's {MAX_CODE_BYTES // 1024 ** 2} MB of actions' "
                             f"archives are spent")
        if self.token:
            self._may_call()                    # (with a token, the archive comes through the API)
        try:
            data = self.client.archive(_sources.Source("github", f"{use.owner}/{use.repo}", sha), sha)
        except SourceError as exc:
            if getattr(exc, "status", None) == 401 or "rate limit" in str(exc):
                self.stopped = str(exc)
                raise _Stop(self.stopped) from None
            raise
        self._archives += 1
        self._archive_bytes += len(data)
        claimed = _sources.archive_commit(data)
        if claimed is not None and claimed != sha:
            raise SourceError(f"the archive of {use.owner}/{use.repo}@{sha[:12]} says it is for commit {claimed}")
        self._archive = (key, data)
        return data

    def _code_of(self, use, sha):
        """repo.scan_action's result for the action at `sha`, once per action and commit; ("incomplete", why)
        when the archive could not be fetched or the run's budget is spent."""
        key = (use.owner.lower(), use.repo.lower(), sha, use.path)
        if key not in self._code:
            try:
                data = self._fetch_archive(use, sha)
            except _CodeLimit as exc:
                self._code[key] = ("incomplete", str(exc))
            except SourceError as exc:
                self._code[key] = ("incomplete", f"its code could not be fetched: {exc}")
            else:
                self._code[key] = _repo.scan_action(data, use.path, memo=self._engine_memo)
        return self._code[key]

    def _audit_code(self, use, sha, line, via):
        """The action's code at `sha` (N-4): each supply-chain finding of the scan a `code` finding (at most
        MAX_CODE_FINDINGS, the strongest first), a Dockerfile's base image not pinned to a digest a
        `docker-unpinned` one, what it runs in the action's entry of the report, and a scan that did not
        read it whole `incomplete`."""
        rep = self.report
        got = self._code_of(use, sha)
        entry = rep.actions.setdefault(self._label(use), {})
        if isinstance(got, tuple):
            entry["code"] = {"commit": sha, "verdict": "INCOMPLETE", "reason": got[1]}
            rep.incomplete.append((use.value, got[1]))
            return
        action = got.get("action") or {}
        entry["code"] = {"commit": sha, "verdict": got["verdict"], "reason": got["verdictReason"],
                         "files": got["filesScanned"], "runs": dict(action.get("runs") or {})}
        counted = [i for i in got["issues"] if i["rule"].startswith("SC-") and i["rule"] not in _repo.TRUNCATION_RULES
                   and i["sev"] != "INFO"]
        counted.sort(key=lambda i: (i["sev"] not in _repo.STRONG_SEVERITIES, str(i["file"]), i["line"]))
        for i in counted[:MAX_CODE_FINDINGS]:
            rep.findings.append(Finding("code", line, use.value, {
                "owner": use.owner, "repo": use.repo, "path": use.path, "sha": sha, "via": list(via),
                "rule": i["rule"], "name": i["name"], "sev": i["sev"], "msg": i["msg"], "why": i.get("why") or "",
                "fix": i.get("fix") or "", "ref": i.get("ref") or "", "file": i["file"], "at": i["line"]}))
        if len(counted) > MAX_CODE_FINDINGS:
            rep.notes.append((use.value, f"{len(counted) - MAX_CODE_FINDINGS} more findings in its code are not "
                                         f"listed"))
        for how, path in action.get("missing") or ():
            rep.notes.append((use.value, f"its {how} names {path}, which is not in the commit: the runner fails "
                                         f"there"))
        for note in action.get("notes") or ():
            rep.notes.append((use.value, note))
        for dockerfile, at, image, pinned in action.get("bases") or ():
            if not pinned:
                rep.findings.append(Finding("docker-unpinned", line, use.value, {
                    "image": image, "dockerfile": f"{dockerfile}:{at}", "owner": use.owner, "repo": use.repo,
                    "via": list(via)}))
        if got["verdict"] == "INCOMPLETE":
            why = [i["msg"] for i in got["issues"] if i["rule"] in _repo.TRUNCATION_RULES][:3]
            rep.incomplete.append((use.value, f"its code at {sha[:12]} was not read whole: " + " ".join(why)))

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
        for why in res.unsettled:
            rep.incomplete.append((use.value, why))
        if res.sha is None:
            return
        if res.peeled is not False:             # (a pin not known to be a commit or a tag object resolves to nothing)
            rep.resolved.setdefault(use.value, res.sha)
        obj = res.tag_object
        if obj is not None and use.value not in rep.tag_objects:
            rep.tag_objects[use.value] = {"tag": obj.tag, "object": obj.sha, "commit": obj.commit}
            through = f", through {obj.depth} tag objects" if obj.depth > 1 else ""
            rep.notes.append((use.value, f"pinned to the tag object {obj.tag} ({obj.sha}) of the commit "
                                         f"{obj.commit}{through}: the runner runs that commit, and it is the one "
                                         f"checked"))
        if res.where is not None:
            rep.branches.setdefault(use.value, res.where)
        if self.stopped:
            # GitHub answers no more: what is left of it would be refused, so it is not checked, and says so
            if not any(u == use.value for u, _ in rep.incomplete):
                rep.incomplete.append((use.value, f"not checked: {self.stopped}"))
            return
        if use.kind != "action" or depth > MAX_DEPTH:
            return
        text = self._action_yml(use, res.sha)
        if text is None:
            if res.peeled is not False:         # (a pin that may be a tag object of no commit: incomplete already)
                rep.notes.append((use.value, "no action.yml or action.yaml at that commit (a reusable workflow, or "
                                             "the path is wrong)"))
            return
        records = ghworkflow.outline(text)
        runs = {r["key"]: r["value"] for r in records if r["path"] == ("runs",) and r["key"] is not None}
        using = runs.get("using", "")
        rep.actions[self._label(use)] = {"using": using, "pre": "pre" in runs, "post": "post" in runs}
        chain = chain + [use.value]
        if using.startswith("docker"):
            image = runs.get("image", "")
            if image.startswith("docker://"):
                parsed = ghworkflow.parse_uses(image)
                if parsed is not None and not parsed[3]:
                    rep.findings.append(Finding("docker-unpinned", line, use.value, {
                        "image": image, "owner": use.owner, "repo": use.repo, "via": list(via)}))
            elif image and not self.code:
                rep.notes.append((use.value, f"builds its image from {image} in the repository: its Dockerfile is "
                                             f"read with the action's code, which was not asked for (--no-code)"))
        if self.code:
            self._audit_code(use, res.sha, line, via)
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
        if not self.branch_check and rep.checked:
            rep.notes.append(("", f"whether each action's commit is in its repository's branches was not checked "
                                  f"({_refs.OFF_ENV} is set)"))
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
    "an action, push a commit there, and pass the original's name with that commit's SHA off as a pinned release; "
    "and a tag of the repository can be moved onto that commit. In May 2026 every tag of actions-cool/issues-helper "
    "(and 15 of actions-cool/maintain-one-comment) was moved to such a commit, put in through an attacker's fork; the "
    "workflows pinned to a commit of the repository's own history were not affected. A release is a commit one of "
    "the repository's branches holds; this one is in none of them.")
_TAG_ONLY_WHY = (
    "GitHub serves a commit pushed to any fork under the original repository's name, and a tag of the repository can "
    "be moved onto such a commit (in May 2026 every tag of actions-cool/issues-helper was), so a commit none of the "
    "branches holds is checked as an impostor. This one is the commit one of the repository's own version tags, and "
    "no other, points to: what a release commit that was tagged and never merged into a branch looks like, as "
    "JavaScript actions that build dist/ only on the release commit often are. So it is not known to be a fork's; "
    "but a tag can be moved by whoever can push to the repository, so the tag says where the repository points now, "
    "not that the commit is the release it was when first tagged.")
_MOVED_WHY = (
    "A version tag names one release and should never point to another commit. In March 2025 the tags of "
    "tj-actions/changed-files were rewritten to a commit that printed every secret of the workflows that used it "
    "into their logs, and in May 2026 those of actions-cool/issues-helper to a commit from a fork; the workflows that "
    "pinned a commit were not affected, the ones that trusted the tag were. A maintainer may retag a release; a tag "
    "moved to a commit the repository's branches do not hold is not that.")
_MISMATCH_WHY = (
    "A pin's comment says which release it is, and reviewers trust it. If the tag points to another commit than the "
    "pin, either the pin is stale or wrong, or the tag was moved, and nobody looking at the comment would see it.")
_DOCKER_WHY = (
    "A Docker action pulls its image when it runs: a tag on an image can be moved, and then the workflow runs "
    "other code than the one reviewed, with the job's token and secrets. An image digest can't be moved.")
_CODE_WHY = (
    "An action's code runs in the job with its token, the secrets the workflow hands the action and the runner's "
    "own tokens. The tj-actions/changed-files and reviewdog/action-setup compromises (March 2025) were in that code: "
    "a release whose script printed the job's secrets into its log.")
_CODE_FIX = "Read the code at that commit before the workflow runs it; pin a commit you have read."
_NESTED_WHY = (
    "A composite action runs the actions its steps name, with the job's token and secrets. Pinning the action to a "
    "commit does not pin what it uses: a tag in its action.yml can still be moved.")
_FROM_FORK = "a commit from a fork, reached through the repository's name"


def _compared(n):
    """What the branch check compared, for a message."""
    if not n:
        return "its branches were compared"
    return "its one branch was compared" if n == 1 else f"each of its {n} branches was compared"


def _none_of(n):
    """The branches that do not hold a commit, for a note."""
    if not n:
        return "none of its branches"
    return "not its one branch" if n == 1 else f"none of its {n} branches"


def rule(kind, d):
    """The issue rule — id, name, type, sev, msg, why, fix, ref, as core.mk_issue takes
    them — for one Finding's kind and detail."""
    who = f"{d['owner']}/{d['repo']}"
    via = f" (through {' > '.join(d['via'])})" if d.get("via") else ""
    if kind == "impostor":
        ref = d.get("ref") or d["sha"]
        if d.get("tag_object"):
            named = f"{who}@{ref}{via}, the tag object {d['tag_object']}, points to the commit {d['sha']}: the commit"
        elif d.get("tag"):
            named = f"{who}@{ref}{via} points to the commit {d['sha']}: the commit"
        else:
            named = f"{who}@{ref}{via}: the commit"
        count = d.get("version_tag_count") or 0
        many = (f" {count} version tags of the repository point to it "
                f"({_tag_span(list(d.get('version_tags') or ()), count)}): the shape of tags moved onto one commit."
                if count > 1 else "")
        return {
            "id": "SC-ACTION-IMPOSTOR", "name": "Action's commit is not in its repository's branches",
            "type": "HOTSPOT", "sev": "CRITICAL",
            "msg": f"{named} is not in {who}'s branches: {_FROM_FORK} ({_compared(d.get('branches'))}).{many}",
            "why": _IMPOSTOR_WHY,
            "fix": ("Do not run it. Open the commit on GitHub: its page says when it does not belong to any branch of "
                    "the repository. Pin the commit of a release you have read, from the repository's own history; "
                    + ("a tag that points to a fork's commit was moved or made by whoever can push to the repository: "
                       "tell its owner and GitHub." if d.get("tag") else "and read the action's code before it runs.")),
            "ref": "CWE-829 · Supply chain"}
    if kind == "tag-only":
        ref = d.get("ref") or d["sha"]
        if d.get("tag_object"):
            named = f"{who}@{ref}{via}, the tag object {d['tag_object']}, points to the commit {d['sha']}: the commit"
        elif ref != d["sha"]:
            named = f"{who}@{ref}{via} points to the commit {d['sha']}: the commit"
        else:
            named = f"{who}@{ref}{via}: the commit"
        compared = d.get("compared") or []
        listed = f": {', '.join(compared)}" if compared else ""
        recorded = bool(d.get("recorded"))
        pinned = bool(d.get("tag_object")) or ref == d["sha"]
        return {
            "id": "SC-ACTION-TAG-ONLY", "name": "Action's commit is held only by a tag, not a branch",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": (f"{named} is in none of {who}'s branches ({_compared(d.get('branches'))}{listed}), but the "
                    f"repository's own version tag {d['tag']}, and no other, points to it: as far as the tags show, "
                    f"a release commit tagged and never merged, so it is not known to be a fork's; but a tag can be "
                    f"moved by whoever can push to the repository. "
                    + ("A later run with the pin book says whether the tag stayed at it." if recorded
                       else "Without a pin book, whether the tag stays at it is not known.")),
            "why": _TAG_ONLY_WHY,
            "fix": ("Read the action's code at this commit before the workflow runs it; "
                    + ("keep the pin if it is the release you meant. " if pinned
                       else "if it is the release you meant, pin that commit by its SHA. ")
                    + ("The pin book now records the tag at this commit: a later run says whether it stayed (a tag "
                       "that stays is then a note, one that moved is CRITICAL)." if recorded
                       else "Run with a pin book (without --no-pins), so that a later run can say whether the tag "
                            "stayed at this commit.")),
            "ref": "CWE-829 · Supply chain"}
    if kind == "tag-moved":
        fork = bool(d.get("fork"))
        return {
            "id": "SC-ACTION-TAG-MOVED", "name": "Version tag of an action points to another commit",
            "type": "HOTSPOT", "sev": "CRITICAL" if fork else "MAJOR",
            "msg": f"The tag {d['tag']} of {who}{via} pointed to {d['was'][:12]} when it was first seen "
                   f"({d['first']}) and points to {d['now'][:12]} now"
                   + (f", which is in none of its branches: {_FROM_FORK}." if fork else "."),
            "why": _MOVED_WHY,
            "fix": (f"Do not run it. Compare {d['was'][:12]} and {d['now'][:12]} on GitHub; if the new commit is a "
                    f"change you can account for, pin that commit by its SHA, and accept the move "
                    f"(`--accept-moved`)."),
            "ref": "CWE-494 · Supply chain"}
    if kind == "pin-mismatch":
        what = (f"points to {d['tag_sha'][:12]}" if d["tag_sha"] else "is not a tag of the repository")
        pinned, but = d["pin"][:12], f"{d['tag']} {what}"
        if d.get("pin_tag"):
            pinned = f"the tag object {d['pin_tag']} ({d['pin'][:12]}, of the commit {d['pin_commit'][:12]})"
            if d["pin_tag"] != d["tag"]:
                but = f"the tag object's name is {d['pin_tag']}, and {but}"
        return {
            "id": "SC-ACTION-PIN-MISMATCH", "name": "Pinned commit does not match its version comment",
            "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"{who}{via} is pinned to {pinned} with the comment {d['tag']}, but {but}.",
            "why": _MISMATCH_WHY,
            "fix": ("Find out which is right: if the tag is, update the pin to its commit; if the pin is, correct "
                    "the comment, and check that the tag was not moved."),
            "ref": "CWE-1357 · Supply chain"}
    if kind == "docker-unpinned":
        image = d["image"].removeprefix("docker://")
        official = bool(_OFFICIAL_IMAGE_RE.match(image))
        if d.get("dockerfile"):
            msg = (f"The action {who}{via} builds its image from {image} ({d['dockerfile']}), which is not pinned to "
                   f"a digest.")
        else:
            msg = f"The action {who}{via} runs the image {d['image']}, which is not pinned to a digest."
        return {
            "id": "SC-ACTION-DOCKER-UNPINNED", "name": "Docker action runs an image not pinned to a digest",
            "type": "HOTSPOT", "sev": "MINOR" if official else "MAJOR",
            "msg": msg + (" It is one of Docker's official images, at a version tag." if official else ""),
            "why": _DOCKER_WHY,
            "fix": "Use a version of the action that pins the image `@sha256:…`, or a different action.",
            "ref": "CWE-829 · Supply chain"}
    if kind == "code":
        path = f"/{d['path']}" if d.get("path") else ""
        return {
            "id": d["rule"], "name": d["name"], "type": "HOTSPOT", "sev": _code_severity(d),
            "msg": f"In the code of {who}{path} at {d['sha'][:12]}{via}, {d['file']}:{d['at']}: {d['msg']}",
            "why": d["why"] or _CODE_WHY, "fix": d["fix"] or _CODE_FIX, "ref": d["ref"] or "CWE-506 · Supply chain"}
    small = d.get("kind") == "action" and d.get("first") and d.get("tag")
    return {
        "id": "SC-ACTION-NESTED-UNPINNED", "name": "Action's own steps use something not pinned to a commit",
        "type": "HOTSPOT", "sev": "MINOR" if small else "MAJOR",
        "msg": f"The composite action {who}{via} uses {d['nested']}, which is not pinned to a commit.",
        "why": _NESTED_WHY,
        "fix": "Use a version of the action that pins what it uses, or a different action.",
        "ref": "CWE-829 · Supply chain"}


def _code_severity(d):
    """A code finding's severity: its scan's, but MINOR for a weak FIRST_PARTY_SMALL one in GitHub's own action."""
    first = f"{d.get('owner', '')}/{d.get('repo', '')}".lower().startswith(ghworkflow.FIRST_PARTY)
    return "MINOR" if first and d["sev"] == "MAJOR" and d["rule"] in FIRST_PARTY_SMALL else d["sev"]


def counted(rules):
    """Do these rules hold a finding that makes the command exit 1 (MAJOR or above)?"""
    return any(r["sev"] in COUNTED for r in rules)


# ------------------------------------------------------------------ the command
def main(argv=None):
    """python -m lazaret.registry.actions [--no-pins | --pins FILE | --db DSN] [--accept-moved] [--max-calls N]
    [--no-code] WORKFLOW..."""
    _core.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = ("usage: python -m lazaret.registry.actions [--no-pins | --pins FILE | --db DSN] [--accept-moved] "
             "[--max-calls N] [--no-code] WORKFLOW...")
    pins_path, use_pins, accept, max_calls, files, scan_code = default_pins_path(), True, False, None, [], True
    db, books = None, set()           # (the book kinds asked for: one at most)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--no-pins":
            use_pins = False
            books.add(a)
        elif a == "--no-code":
            scan_code = False
        elif a == "--accept-moved":
            accept = True
        elif a in ("--pins", "--max-calls", "--db") and i + 1 < len(argv):
            i += 1
            if a == "--pins":
                pins_path = argv[i]
                books.add(a)
            elif a == "--db":
                db = argv[i]
                books.add(a)
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
    if not files or len(books) > 1:
        print(usage, file=sys.stderr)
        return 2
    store = None
    if db is not None:
        # RA-4: the tags' records in the registry's database (action_tags), beside its scans
        try:
            store = _repo.Store(db)
        except (_repo.StoreConfigError, RuntimeError, ValueError) as exc:
            print(f"error: --db: {exc}", file=sys.stderr)
            return 2
    try:
        pins = _refs.StoreBook(store) if store is not None else PinBook(pins_path) if use_pins else None
        return _run(files, pins, max_calls, accept, scan_code)
    finally:
        if store is not None:
            store.close()


def _run(files, pins, max_calls, accept, scan_code):
    """The command's audit of each workflow file: prints the reports, -> the exit code. The files' Auditors share one
    Run (FP-IMPOSTOR-TAG): the command's start, the pin book's records as they were before it, the tag listings; so a
    record one file's audit makes is never taken in another's for one an earlier command left."""
    rep_all = []
    code = 0
    run = Run()
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
            rep = audit_text(text.decode("utf-8", "replace"), pins=pins, max_calls=max_calls, accept_moved=accept,
                             code=scan_code, run=run)
        except SourceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        doc = rep.to_json()
        doc["file"] = path
        doc["rules"] = [rule(f.kind, f.detail) for f in rep.findings]
        rep_all.append(doc)
        if counted(doc["rules"]):
            code = max(code, 1)
        elif not rep.complete and code == 0:
            code = 3
    print(json.dumps(rep_all, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
