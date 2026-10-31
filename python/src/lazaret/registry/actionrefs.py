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
  the repository's name (SC-ACTION-IMPOSTOR, CRITICAL, in the action scan), unless one of the repository's own
  version tags holds it (below);
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

A commit no branch holds may still be a release: one that was tagged and never merged into a branch, as JavaScript
actions that build `dist/` only on the release commit often are (John's run of Oct 18: mmastrac/mmm-matrix@3edd85c…,
held by the lightweight tag v1.0.5 and by none of the repository's 5 branches). So for an `out` answer, and only
then, the action scan asks whether one of the repository's own exact version tags (v4.1.0; not v4 or latest) points
to that very commit: `Branches.tags`, `GET /repos/{owner}/{repo}/tags?per_page=100` (each tag's name and
`commit.sha`, which for an annotated tag is the commit it tags), at most TAG_PAGES pages (a page that is not full is
the last, so every tag was read; a full last page means more may exist: the Link header is not read), one listing a
repository for the command (the listings are shared by the Auditors of one command's workflow files), an error's
included. The outcomes, in the action scan (the pin book's records, below): no exact version tag points to it,
SC-ACTION-IMPOSTOR (CRITICAL) as before. Two or more exact version tags at the one commit are the shape of tags moved
onto one commit (actions-cool's), not a release kept by its tag: SC-ACTION-IMPOSTOR whatever the pin book says. Only
the tags read count, so one found while the listing did not reach every tag may have a second among the rest:
SC-ACTION-IMPOSTOR as well. Exactly one, every tag read, and the pin book's record of it at this commit carries the
mark only SC-ACTION-TAG-ONLY writes (`tag_only`: the commit it was given at, this one, and when), made before the
command began: a note and no finding. Exactly one and no such mark (a first sighting, a record another check wrote, a
mark that names no commit, no pin book): SC-ACTION-TAG-ONLY (MAJOR: a tag can be moved by whoever can push), and the
record gets the mark, so that a later command says whether the tag stayed. A tag the pin book saw at another commit,
or whose move was not accepted, a commit a tag was moved onto and the move accepted (`moved_from`, or a mark at
another commit than the record's: an older version's accept, which kept no `moved_from`; accepting a move does not
make a release), a listing that failed or was refused, and a record that could not be read or kept leave the commit
SC-ACTION-IMPOSTOR, with a note; a commit a tag was moved onto stays so until its record is deleted by hand.

The tags: an exact version tag's commit (v4.1.0; not a floating v4 or latest, which move by design) is recorded the
first time the scan sees it (a use named by it, a pin's comment that names it, a tag that holds an `out` commit), in
the pin book (`actions.PinBook`, a JSON file of the user's cache directory) or, with
`--db`, in the registry's database beside its scans (`StoreBook`: the table action_tags). A tag seen later at
another commit moved: SC-ACTION-TAG-MOVED, MAJOR, and CRITICAL when the commit it moved to is in none of the
branches. A floating tag moved onto a fork's commit is found by the branch check itself. A record is {sha, first,
last[, moved: {to, at}][, tag_only: {sha, at}][, moved_from: {sha, at}]} (`sighting`, `accepted`, `mark_of`).

LAZARET_NO_ACTION_BRANCHES=1 turns the branch check off (an offline run, and the test suite's default, as the
provenance and predecessor checks are off there); the report says that it was not made.
"""

import re
import time
import urllib.parse
from collections import namedtuple

from lazaret.registry import sources as _sources

__all__ = ["Answer", "TagObject", "Tags", "Branches", "StoreBook", "BookError", "sighting", "accepted", "mark_of",
           "branch_rank", "enabled",
           "MAX_COMPARES", "BRANCH_PAGE", "MAX_TAG_DEPTH", "TAG_PAGE", "TAG_PAGES", "OFF_ENV"]

SourceError = _sources.SourceError

OFF_ENV = "LAZARET_NO_ACTION_BRANCHES"
#: compare calls for one commit at most, the default branch's included
MAX_COMPARES = 9
#: the branches listed (one page: a repository with more is not listed whole)
BRANCH_PAGE = 100
#: tag objects followed from a pin to the commit it tags at most, the pin's own included (a tag of a tag of ...)
MAX_TAG_DEPTH = 4
#: the tags listed of a repository whose commit is `out` (Branches.tags): pages of TAG_PAGE, TAG_PAGES pages at most
TAG_PAGE = 100
TAG_PAGES = 3
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
#: a repository's tags as listed (Branches.tags): at, {commit sha: [the names of the tags at it, as listed]} (an
#: annotated tag at the commit it tags); read, how many were listed; pages, how many pages were read; more, whether it
#: may have more than were read (the last page read was full)
Tags = namedtuple("Tags", "at read pages more")


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

    def __init__(self, get, max_compares=None, listed=None):
        self._get = get
        self.max_compares = MAX_COMPARES if max_compares is None else max_compares
        self._answers = {}
        self._tags = {}             # (owner, repo, sha) -> TagObject, None (not one) or the SourceError asking raised
        # (owner, repo) -> Tags, or the SourceError listing them raised; `listed` shares them with other Branches (the
        # Auditors of one command's workflow files)
        self._listed = {} if listed is None else listed
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

    def tags(self, owner, repo):
        """-> the Tags of owner/repo: `GET /repos/{o}/{r}/tags?per_page=100` (each tag's name and `commit.sha`, the
        commit an annotated tag tags: no call for each tag), then `&page=2` and on while a page is full, TAG_PAGES pages
        at most; a page that is not full is the last, so every tag was read, and a full last page means the repository
        may have more (`more`): whether every tag was read is told by a short page, not by the Link header, which is
        not read. Kept per repository (as `listed` shares them: for the command), an error's included. The scan asks it
        only for a commit whose answer is `out` (is the commit held by a version tag of the repository?). Raises
        SourceError for an answer it cannot use; an entry it cannot read is left out (it can only hide a tag, never
        name one), and the caller's exception when GitHub will answer no more is not caught (nor kept)."""
        key = (owner.lower(), repo.lower())
        if key not in self._listed:
            try:
                self._listed[key] = self._list_tags(owner, repo)
            except SourceError as exc:
                self._listed[key] = exc
                raise
        got = self._listed[key]
        if isinstance(got, SourceError):
            raise got
        return got

    def _list_tags(self, owner, repo):
        base, label = self._base(owner, repo), f"{owner}/{repo}"
        at, read = {}, 0
        for page in range(1, TAG_PAGES + 1):
            what = f"listing the tags of {label}" + (f" (page {page})" if page > 1 else "")
            listing = self._get(f"{base}/tags?per_page={TAG_PAGE}" + (f"&page={page}" if page > 1 else ""), what)
            if not isinstance(listing, list):
                raise SourceError(f"{what}: unexpected answer")
            read += len(listing)
            for e in listing:
                commit = e.get("commit") if isinstance(e, dict) else None
                sha = commit.get("sha") if isinstance(commit, dict) else None
                name = e.get("name") if isinstance(e, dict) else None
                if isinstance(name, str) and name and isinstance(sha, str) and _SHA40_RE.match(sha.lower()):
                    names = at.setdefault(sha.lower(), [])
                    if name not in names:
                        names.append(name)
            if len(listing) < TAG_PAGE:
                return Tags(at, read, page, False)
        return Tags(at, read, TAG_PAGES, True)

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


#: the scan's time form, iso()'s
ISO_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


def mark_of(entry):
    """A record's SC-ACTION-TAG-ONLY mark (FP-IMPOSTOR-TAG) -> (the commit it was given at, when), or (None, None)
    for a record without one. A mark that names no commit, or not in the scan's time form, is not one (None, None);
    one that names a commit other than the record's is returned as it is: the caller takes it for a move onto the
    record's commit that an accept recorded nowhere (an older version's --accept-moved, whose update of the database's
    row leaves the mark)."""
    mark = entry.get("tag_only") if isinstance(entry, dict) else None
    sha = mark.get("sha") if isinstance(mark, dict) else None
    at = mark.get("at") if isinstance(mark, dict) else None
    if not (isinstance(sha, str) and _SHA40_RE.match(sha) and isinstance(at, str) and ISO_RE.match(at)):
        return None, None
    return sha, at


def _marked(new, sha, stamp):
    """`new` with SC-ACTION-TAG-ONLY's mark at `sha`: a mark the record already has there is kept (the first time it
    was given), any other (none, malformed, at another commit) is replaced."""
    if mark_of(new)[0] != sha:
        new["tag_only"] = {"sha": sha, "at": stamp}
    return new


def sighting(entry, sha, now, tag_only=False):
    """A tag seen at the commit `sha` at the time `now`: -> (its record after the sighting, the record it was first
    seen with when it now points elsewhere, else None). A record is {sha, first, last[, moved: {to, at}][, tag_only:
    {sha, at}][, moved_from: {sha, at}]}: a tag that moved keeps its first commit (the alert stays until the move is
    accepted) and says where it went. `tag_only` (FP-IMPOSTOR-TAG): the sighting is SC-ACTION-TAG-ONLY's, of the tag
    as the one version tag of a commit no branch holds; the record at `sha` keeps the commit and the time it was first
    given (`tag_only`), the mark a later run's note needs. Any other sighting keeps the record's marks as they are and
    adds none."""
    stamp = iso(now)
    if entry is None:
        new = {"sha": sha, "first": stamp, "last": stamp}
    elif entry["sha"] == sha:
        new = {k: v for k, v in entry.items() if k != "moved"}
        new["last"] = stamp
    else:
        moved = dict(entry, moved={"to": sha, "at": stamp})
        return moved, dict(moved)
    return (_marked(new, sha, stamp) if tag_only else new), None


def accepted(entry, sha, now, tag_only=False):
    """A tag's record after its present commit `sha` is accepted at `now` (--accept-moved): started again at `sha`.
    Where the record was at another commit, the commit the tag moved from is kept (`moved_from`: {sha, at}): a commit a
    tag was moved onto is never taken for a release commit kept by its tag (FP-IMPOSTOR-TAG), accepted or not. At the
    same commit, the record's marks (`tag_only`, `moved_from`) are kept as they are; `tag_only` as in `sighting`."""
    stamp = iso(now)
    new = {"sha": sha, "first": stamp, "last": stamp}
    if entry is not None and entry.get("sha") != sha:
        new["moved_from"] = {"sha": entry.get("sha"), "at": stamp}
    elif entry is not None:
        new.update({k: entry[k] for k in ("tag_only", "moved_from") if k in entry})
    return _marked(new, sha, stamp) if tag_only else new


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

    def record(self, key):
        """-> the tag's record ({sha, first, last[, moved]}) or None; a database error is a BookError."""
        repo, tag = self._split(key)
        try:
            return self._entry(repo, tag)
        except Exception as exc:                # noqa: BLE001  (as see's)
            raise BookError(f"the tag {tag} of {repo} could not be read from the registry's database "
                            f"({type(exc).__name__}: {exc})") from None

    def see(self, key, sha, now, tag_only=False):
        repo, tag = self._split(key)
        try:
            entry, was = sighting(self._entry(repo, tag), sha, now, tag_only)
            self.store.save_action_tag(repo, tag, entry)
        except Exception as exc:                # noqa: BLE001  (sqlite3's, the wire client's, a dropped session)
            raise BookError(f"the tag {tag} of {repo} could not be recorded in the registry's database "
                            f"({type(exc).__name__}: {exc}), so whether it moved was not checked") from None
        return was

    def accept(self, key, sha, now, tag_only=False):
        repo, tag = self._split(key)
        try:
            self.store.save_action_tag(repo, tag, accepted(self._entry(repo, tag), sha, now, tag_only))
        except Exception as exc:                # noqa: BLE001
            raise BookError(f"the move of the tag {tag} of {repo} could not be accepted in the registry's database "
                            f"({type(exc).__name__}: {exc})") from None

    def save(self):
        """Every sighting is written as it is made."""
