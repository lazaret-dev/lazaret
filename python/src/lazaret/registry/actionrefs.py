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

A pin may name an annotated tag's object, not a commit (vercel/next.js pins `actions/github-script@d746ffe…`, the
object of its tag v9.0.0, which tags the commit 3a2844b…): GitHub Actions runs the commit the object tags, and the
compare API does not take the object for that commit (John's run of Oct 18: none of the 9 compares held d746ffe…,
though the default branch holds its commit). A SHA a branch's compare holds is a commit, so the question is asked of a
pin, by `check(..., pinned=True)`, only when the default branch's compare does not hold it (or there is no default
branch to compare): `GET /repos/{owner}/{repo}/git/tags/{sha}`, one call, before any other branch is listed or
compared. 404: not a tag object, the check goes on as for any commit. 200: the object's commit, through nested tag
objects (MAX_TAG_DEPTH in all), is checked in its place (its own MAX_COMPARES, after the pin's one compare), and the
Answer names the object (`tag_object`, a TagObject); a commit of none of the branches is `out` as any other. A 200 that
cannot be followed to a commit (a tag of a tree, more tag objects than that, an answer that cannot be read) is a
SourceError: the pin's commit is unknown, never `in`. GitHub not answering (an HTTP error other than 404, the network)
is no answer either way: the pin is checked as a commit, as before the question was asked, and the Answer says the
question failed (`tag_error`); a commit called `out` is then one GitHub's commits endpoint shows as itself.

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

__all__ = ["Answer", "TagObject", "Branches", "StoreBook", "BookError", "sighting", "branch_rank", "enabled",
           "MAX_COMPARES", "BRANCH_PAGE", "MAX_TAG_DEPTH", "OFF_ENV"]

SourceError = _sources.SourceError

OFF_ENV = "LAZARET_NO_ACTION_BRANCHES"
#: compare calls for one commit at most, the default branch's included
MAX_COMPARES = 9
#: the branches listed (one page: a repository with more is not listed whole)
BRANCH_PAGE = 100
#: tag objects followed from a pin to the commit it tags at most, the pin's own included (a tag of a tag of ...)
MAX_TAG_DEPTH = 4
#: the compare statuses that mean the branch holds the commit
HOLDS = ("behind", "identical")
_STATUSES = ("identical", "ahead", "behind", "diverged")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

#: state: 'in' | 'out' | 'missing' | 'unsettled'; where: the branch that holds it; compared: the branches compared;
#: branches: how many the repository has (as listed); why: what kept an unsettled check from finishing;
#: tag_object: the TagObject a pin named, whose commit the answer is for (else None); tag_error: why whether the pin is
#: a tag object could not be asked (GitHub did not answer: it was checked as a commit), else None
Answer = namedtuple("Answer", "state where compared branches why tag_object tag_error", defaults=(None, None))
#: a pinned SHA that names an annotated tag's object, not a commit: sha (the pin), tag (the name the object carries),
#: commit (the commit it tags), depth (the tag objects followed to it, the pin's included)
TagObject = namedtuple("TagObject", "sha tag commit depth")


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
        self._tags = {}             # (owner, repo, sha) -> TagObject, None (not one) or the SourceError asking raised
        self.compares = 0           # compare calls made in the run

    def check(self, owner, repo, sha, pinned=False):
        """-> the Answer for the commit `sha` of owner/repo (kept for the run). `pinned`: `sha` is a workflow's pin,
        which may name a tag object (`tag_object`). Raises SourceError when the repository cannot be looked up (status
        404: private, renamed or gone) or GitHub's answer cannot be used."""
        key = (owner.lower(), repo.lower(), sha.lower())
        got = self._answers.get(key)
        if got is None:
            try:
                got = self._settle(owner, repo, sha.lower(), pinned)
            except SourceError as exc:          # asked once: the same commit again gets the same answer
                self._answers[key] = exc
                raise
            self._answers[key] = got
        if isinstance(got, SourceError):
            raise got
        return got

    def tag_object(self, owner, repo, sha):
        """-> the TagObject when the pinned `sha` of owner/repo names an annotated tag's object, None when it does not
        (`GET /repos/{o}/{r}/git/tags/{sha}` answers 404: a commit, or nothing GitHub has); kept for the run, an
        error's included. One call, and one more for each tag object it points to (MAX_TAG_DEPTH in all). Raises
        SourceError for any other answer (an error, a tag of a tree or a blob, more tag objects than that, an answer
        that cannot be read): whether the pin is a commit is then not known. One whose first call GitHub did not answer
        (an HTTP status other than 404, the network) has `unanswered` set: the pin may still be a commit."""
        key = (owner.lower(), repo.lower(), sha.lower())
        if key not in self._tags:
            try:
                self._tags[key] = self._peel(owner, repo, sha.lower())
            except SourceError as exc:
                self._tags[key] = exc
                raise
        got = self._tags[key]
        if isinstance(got, SourceError):
            raise got
        return got

    def _peel(self, owner, repo, sha):
        base, label = self._base(owner, repo), f"{owner}/{repo}"
        what = f"looking up the tag object {sha[:12]} of {label}"
        try:
            doc = self._get(f"{base}/git/tags/{sha}", what)
        except SourceError as exc:
            if getattr(exc, "status", None) == 404:
                return None                     # not a tag object: a commit, or nothing GitHub has
            err = SourceError(str(exc))
            err.status, err.unanswered = getattr(exc, "status", None), True
            raise err from None
        if not isinstance(doc, dict) or doc.get("sha", sha) != sha:
            raise SourceError(f"{what}: unexpected answer")
        name = doc.get("tag")
        if not isinstance(name, str) or not name:
            raise SourceError(f"{what}: unexpected answer")
        for depth in range(1, MAX_TAG_DEPTH + 1):
            obj = doc.get("object") if isinstance(doc, dict) else None
            typ, target = (obj.get("type"), obj.get("sha")) if isinstance(obj, dict) else (None, None)
            if not isinstance(target, str) or not _SHA40_RE.match(target):
                raise SourceError(f"{what}: unexpected answer")
            if typ == "commit":
                if target == sha:
                    raise SourceError(f"{what}: unexpected answer")
                return TagObject(sha, name, target, depth)
            if typ != "tag":
                raise SourceError(f"{what}: it tags a {typ}, not a commit")
            if depth == MAX_TAG_DEPTH:
                break
            try:
                doc = self._get(f"{base}/git/tags/{target}", f"looking up the tag object {target[:12]} of {label}")
            except SourceError as exc:
                if getattr(exc, "status", None) == 404:     # (not the repository's 404: the scan goes on)
                    raise SourceError(f"{what}: the tag object {target[:12]} it tags is not there") from None
                raise
            if not isinstance(doc, dict) or doc.get("sha", target) != target:
                raise SourceError(f"{what}: unexpected answer for the tag object {target[:12]} it tags")
        raise SourceError(f"{what}: more than {MAX_TAG_DEPTH} tag objects in a row")

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

    def _settle(self, owner, repo, sha, pinned=False):
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
        failed = None
        if pinned:
            # a pin may name a tag object, which runs as the commit it tags and which no compare takes for that commit:
            # asked before the branches are listed (one call), and its commit checked in its place
            try:
                obj = self.tag_object(owner, repo, sha)
            except SourceError as exc:
                if not getattr(exc, "unanswered", False):
                    raise
                obj, failed = None, str(exc)    # GitHub did not answer: checked as a commit, as before
            if obj is not None:
                return self.check(owner, repo, obj.commit)._replace(tag_object=obj)
        answer = self._others(base, label, sha, default, compared)
        return answer._replace(tag_error=failed) if failed else answer

    def _others(self, base, label, sha, default, compared):
        """The check past the default branch: the branches listed, compared, and the commit looked up."""
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
        doc = self._get(f"{base}/commits/{sha}", f"looking up {label}@{sha[:12]}", missing=True)
        if doc is None:
            return Answer("missing", None, compared, total, None)
        shown = doc.get("sha") if isinstance(doc, dict) else None
        if isinstance(shown, str) and shown.lower() != sha:
            # (not the commit asked about: a SHA GitHub takes for another commit, as it may a tag object's)
            return Answer("unsettled", None, compared, total, f"GitHub shows it as the commit {shown[:12]}")
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
