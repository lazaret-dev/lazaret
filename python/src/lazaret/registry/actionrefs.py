"""Is an action's commit in its repository's own history, and did its tag move? (0.1.9, RA-4)

The action scan's shared helper (`registry/actions.py`, for every `uses: owner/repo@ref` it resolves: a workflow's
own, and those of a composite action's steps; pinned to a commit or named by a tag).

GitHub serves each commit of a repository's fork network under the parent's name: a commit pushed to a fork is
`owner/repo@<sha>` too, and a tag of the parent can be moved onto it. In May 2026 every tag of
actions-cool/issues-helper, and 15 of actions-cool/maintain-one-comment, were moved to an imposter commit put in
through an attacker's fork; the workflows pinned to a full SHA of the real history were not affected. So the question
asked of a commit is whether one of the repository's own branches holds it. A tag cannot answer it (the tag is what
was moved), and neither can a pin: an imposter can be pinned by its SHA too.

`Branches.check(owner, repo, sha)` asks GitHub's compare API, `GET /repos/{owner}/{repo}/compare/{branch}...{sha}`:
`behind` or `identical` means the branch holds the commit. The default branch is asked first, after the repository's
own record (most commits an action is pinned to are on it: two calls in all); then the repository's other branches,
one page of at most BRANCH_PAGE (a branch whose head is the commit needs no compare), the likeliest first: release
branches and version names (`releases/v2`, `release-1.x`, `v1`), then `main` and `master`, then the rest by name.
At most MAX_COMPARES compares are made for one commit, the default branch's included; one more call (the commit
itself) is made before a commit is called an imposter, so that a commit GitHub does not have is not one. The answer:

- `in`: a branch holds it (`where` names the branch);
- `out`: every branch was compared, none holds it, and GitHub has the commit: a commit from a fork, reached through
  the repository's name (SC-ACTION-IMPOSTOR, CRITICAL, in the action scan);
- `missing`: GitHub has no such commit (the runner would fail on it; the scan says so in a note);
- `unsettled`: the check could not finish (`why`): the compare budget was spent with branches left, the repository
  has more branches than one page lists, a branch name that cannot go in a URL, no default branch to compare. Never
  CRITICAL: the action scan reports it as `incomplete` (exit 3: an action that was not checked is not cleared), as it
  reports the rate limit, its call budget and an API error, which reach it as exceptions (`_Stop`, SourceError).

An answer, an error's included, is kept per (repository, commit) for the run: the same commit named by a tag, by a
pin and by another action of the repository is asked about once.

The tags: an exact version tag's commit (v4.1.0; not a floating v4 or latest, which move by design) is recorded the
first time the scan sees it, in the pin book (`actions.PinBook`, a JSON file of the user's cache directory) or, with
`--db`, in the registry's database beside its scans (`StoreBook`: the table action_tags). A tag seen later at
another commit moved: SC-ACTION-TAG-MOVED, MAJOR, and CRITICAL when the commit it moved to is in none of the
branches. A floating tag moved onto a fork's commit is found by the branch check itself.

LAZARET_NO_ACTION_BRANCHES=1 turns the branch check off (an offline run, and the test suite's default, as the
provenance and predecessor checks are off there); the report says that it was not made.
"""

import re
import time
import urllib.parse
from collections import namedtuple

from lazaret.registry import sources as _sources

__all__ = ["Answer", "Branches", "StoreBook", "BookError", "sighting", "branch_rank", "enabled", "MAX_COMPARES",
           "BRANCH_PAGE", "OFF_ENV"]

SourceError = _sources.SourceError

OFF_ENV = "LAZARET_NO_ACTION_BRANCHES"
#: compare calls for one commit at most, the default branch's included
MAX_COMPARES = 9
#: the branches listed (one page: a repository with more is not listed whole)
BRANCH_PAGE = 100
#: the compare statuses that mean the branch holds the commit
HOLDS = ("behind", "identical")
_STATUSES = ("identical", "ahead", "behind", "diverged")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

#: state: 'in' | 'out' | 'missing' | 'unsettled'; where: the branch that holds it; compared: the branches compared;
#: branches: how many the repository has (as listed); why: what kept an unsettled check from finishing
Answer = namedtuple("Answer", "state where compared branches why")


def enabled(env):
    """Is the branch check on (LAZARET_NO_ACTION_BRANCHES unset in `env`)?"""
    return not (env or {}).get(OFF_ENV)


def branch_rank(name):
    """The order the branches after the default one are compared in: a release branch or a version name first (a
    release's commit is on one), then main and master, then the rest by name."""
    low = name.lower()
    if low.startswith(("releases/", "release/", "release-", "releases-")) or re.match(r"v?\d", low):
        return (0, name)
    return (1 if low in ("main", "master") else 2, name)


def _ref_ok(name):
    try:
        _sources._check_ref(name)
        return True
    except SourceError:
        return False


class Branches:
    """The branch check, for one run. `get(path, what, missing=False)` is the caller's GitHub API (a path under
    https://api.github.com; the parsed JSON, or None for a 404 or 422 when `missing`); it raises SourceError for an
    answer it cannot use and its own exception when GitHub will answer no more, neither of which is caught here."""

    def __init__(self, get, max_compares=None):
        self._get = get
        self.max_compares = MAX_COMPARES if max_compares is None else max_compares
        self._answers = {}
        self.compares = 0           # compare calls made in the run

    def check(self, owner, repo, sha):
        """-> the Answer for the commit `sha` of owner/repo (kept for the run). Raises SourceError when the
        repository cannot be looked up (status 404: private, renamed or gone) or GitHub's answer cannot be used."""
        key = (owner.lower(), repo.lower(), sha.lower())
        got = self._answers.get(key)
        if got is None:
            try:
                got = self._settle(owner, repo, sha.lower())
            except SourceError as exc:          # asked once: the same commit again gets the same answer
                self._answers[key] = exc
                raise
            self._answers[key] = got
        if isinstance(got, SourceError):
            raise got
        return got

    @staticmethod
    def _base(owner, repo):
        return f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"

    def _compare(self, base, label, branch, sha):
        what = f"comparing {sha[:12]} with {label}@{branch}"
        self.compares += 1
        doc = self._get(f"{base}/compare/{urllib.parse.quote(branch, safe='/')}...{sha}?per_page=1", what,
                        missing=True)
        if doc is None:
            return "unrelated"                  # no common history, or no such commit
        status = doc.get("status") if isinstance(doc, dict) else None
        if status not in _STATUSES:
            raise SourceError(f"{what}: unexpected answer")
        return status

    def _settle(self, owner, repo, sha):
        base, label = self._base(owner, repo), f"{owner}/{repo}"
        info = self._get(base, f"looking up {label}", missing=True)
        if info is None:
            err = SourceError(f"looking up {label}: not found (the repository may be private, renamed or gone)")
            err.status = 404
            raise err
        default = info.get("default_branch") if isinstance(info, dict) else None
        if default is not None and not isinstance(default, str):
            raise SourceError(f"looking up {label}: unexpected answer")
        compared = []
        if default and _ref_ok(default):
            compared.append(default)
            if self._compare(base, label, default, sha) in HOLDS:
                return Answer("in", default, compared, None, None)
        what = f"listing the branches of {label}"
        listing = self._get(f"{base}/branches?per_page={BRANCH_PAGE}", what)
        if not isinstance(listing, list):
            raise SourceError(f"{what}: unexpected answer")
        heads = []
        for e in listing:
            commit = e.get("commit") if isinstance(e, dict) else None
            tip = commit.get("sha") if isinstance(commit, dict) else None
            if isinstance(e, dict) and isinstance(e.get("name"), str) and isinstance(tip, str):
                heads.append((e["name"], tip.lower()))
        for name, tip in heads:
            if tip == sha:
                return Answer("in", name, compared, len(heads), None)
        others = sorted({n for n, _ in heads if n != default}, key=branch_rank)
        bad = [n for n in others if not _ref_ok(n)]
        left = [n for n in others if n not in bad]
        while left and len(compared) < self.max_compares:
            name = left.pop(0)
            compared.append(name)
            if self._compare(base, label, name, sha) in HOLDS:
                return Answer("in", name, compared, len(heads), None)
        total = len(set(n for n, _ in heads) | ({default} if default else set()))
        why = []
        if left:
            why.append(f"{len(compared)} of its {total} branches were compared ({self.max_compares} compares a "
                       f"commit at most), {len(left)} were not")
        if len(listing) >= BRANCH_PAGE:
            why.append(f"it has more than the {BRANCH_PAGE} branches one page lists")
        if bad:
            why.append(f"{len(bad)} branch name(s) cannot be put in a URL")
        if not default or default not in compared:
            why.append("its default branch could not be compared")
        if why:
            return Answer("unsettled", None, compared, total, "; ".join(why))
        if self._get(f"{base}/commits/{sha}", f"looking up {label}@{sha[:12]}", missing=True) is None:
            return Answer("missing", None, compared, total, None)
        return Answer("out", None, compared, total, None)


# ------------------------------------------------------------------ the tags' records
def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sighting(entry, sha, now):
    """A tag seen at the commit `sha` at the time `now`: -> (its record after the sighting, the record it was first
    seen with when it now points elsewhere, else None). A record is {sha, first, last[, moved: {to, at}]}: a tag that
    moved keeps its first commit (the alert stays until the move is accepted) and says where it went."""
    stamp = iso(now)
    if entry is None:
        return {"sha": sha, "first": stamp, "last": stamp}, None
    if entry["sha"] == sha:
        kept = {k: v for k, v in entry.items() if k != "moved"}
        kept["last"] = stamp
        return kept, None
    moved = dict(entry, moved={"to": sha, "at": stamp})
    return moved, dict(moved)


class BookError(Exception):
    """A tag's record could not be read or written; the tag's move was not checked."""


class StoreBook:
    """The pin book in the registry's database (`python -m lazaret.registry.actions --db DSN`): a row of
    action_tags for each version tag (Store.action_tag, Store.save_action_tag), keyed by the repository (owner/repo,
    lower-cased) and the tag, written at each sighting (save() has nothing left to do). The same interface as
    actions.PinBook; a database error is a BookError, which the action scan reports as incomplete."""

    problem = None

    def __init__(self, store):
        self.store = store

    @staticmethod
    def _split(key):
        repo, _, tag = key.partition("@")
        return repo, tag

    def _entry(self, repo, tag):
        entry = self.store.action_tag(repo, tag)
        if entry is not None and not (isinstance(entry.get("sha"), str) and _SHA40_RE.match(entry["sha"])):
            return None                         # (a row this version did not write: started again)
        return entry

    def see(self, key, sha, now):
        repo, tag = self._split(key)
        try:
            entry, was = sighting(self._entry(repo, tag), sha, now)
            self.store.save_action_tag(repo, tag, entry)
        except Exception as exc:                # noqa: BLE001  (sqlite3's, the wire client's, a dropped session)
            raise BookError(f"the tag {tag} of {repo} could not be recorded in the registry's database "
                            f"({type(exc).__name__}: {exc}), so whether it moved was not checked") from None
        return was

    def accept(self, key, sha, now):
        repo, tag = self._split(key)
        stamp = iso(now)
        try:
            self.store.save_action_tag(repo, tag, {"sha": sha, "first": stamp, "last": stamp})
        except Exception as exc:                # noqa: BLE001
            raise BookError(f"the move of the tag {tag} of {repo} could not be accepted in the registry's database "
                            f"({type(exc).__name__}: {exc})") from None

    def save(self):
        """Every sighting is written as it is made."""
