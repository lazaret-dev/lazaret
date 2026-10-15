"""Finding new public GitHub repositories, and scanning the likely-hostile ones (GH-NEW-REPOS; John's scope of Oct 14:
every new public repository, filtered; specs/lazaret-github-new-repos-plan-2026-10-14.md).

    lazaret-registry discover --ecosystem github --resume [--scan] [--max-calls N] [--github-filters FILE]

1. List. GitHub's `GET /repositories?since=<id>` gives every public repository in the order it was created, 100 a
   page, paged by the last ID seen. The cursor (discovery_cursors, eco "github") is that ID, stored after each page,
   so a run that stops repeats at most one page. The first run finds the newest repository (a search on `since`,
   about 32 requests) and starts there. A repository created private and made public later keeps its old ID and is
   not listed (GH Archive's PublicEvent, phase 2).
2. Filter, from the listing alone (no request of its own):
   - a look-alike of a popular repository: `lookalike.github_lookalike`, Go's rules for an owner (one change from a
     popular repository's owner, its separators changed, "-go" and the like added; a popular repository's owner is
     never one), against popular_names.json's "github" targets and the "go" targets on github.com;
   - a copy of a popular repository under another owner, not a fork, whose description is the original's
     (impersonation), when popular_names.json's "github" section carries the originals' descriptions;
   - a campaign marker (campaign_markers.json: the Shai-Hulud worms' exfiltration repositories), the name or the
     description compared with case and separators folded away: such a repository is the finding itself, since it
     publishes its victims' stolen credentials, so it is reported when listed, with its URL, and never downloaded;
   - John's own patterns (--github-filters FILE: JSON, {"include": {"full_name": [regex, …], "description": […]},
     "exclude": {…}}; an exclude match drops a repository whatever else it matched, a campaign marker's aside).
   A repository something matched is a candidate (github_candidates).
3. Wait for content. A new repository is almost always empty. A candidate's content is checked
   (`GET /repos/{owner}/{repo}`) when it is due, CHECK_HOURS after it was listed: with some (`size` above 0) it is
   ready; gone or made private (404), or still empty after the last check, it is dropped, and `last_error` says why.
4. Scan (--scan). The default branch's head through sources.checkout and the project scan, stored as eco "github",
   `owner/repo` as the name and the commit as the version (profile "project"). The verdict is the registry's
   (decide_verdict) over the project scan's supply-chain findings, a CI file's hardening check counted only at
   CRITICAL (core.HARDENING_RULES), as the gate counts them: an unpinned action alone does not make a repository
   WARN. A checkout not read whole counts as a truncated part, so the verdict is INCOMPLETE at best.

Budgets: --max-calls (DEFAULT_MAX_CALLS) across what is due first (the checks and scans) and then the listing, so a
listing that has fallen behind does not keep a candidate waiting; and GitHub's: the run stops when
X-RateLimit-Remaining falls to RATE_FLOOR, or on a rate-limit answer (403 or 429), keeping its cursor and its
candidates for the next run. GITHUB_TOKEN is required (60 requests an hour without one cannot keep up) and goes only
to api.github.com (sources.Client). Static only: an archive is read into a temporary folder and removed, nothing
runs, and no secret is verified (a sweep never logs in with strangers' credentials).
"""
import datetime
import json
import os
import re
import time
import urllib.parse

from lazaret.registry import lookalike, sources
from lazaret.registry import repo as _repo
from lazaret.scanner import core

__all__ = ["DiscoveryError", "Budget", "Filters", "run", "frontier", "scan_repository", "load_markers",
           "load_patterns", "CHECK_HOURS", "DEFAULT_MAX_CALLS", "RATE_FLOOR", "ECO"]

UTC = datetime.timezone.utc
ECO = "github"
REPOSITORIES = f"https://{sources.GITHUB_API}/repositories"
#: hours after a candidate was listed at which its content is checked; empty after the last, it is dropped
CHECK_HOURS = (1, 6, 24, 72)
DEFAULT_MAX_CALLS = 1000
#: GitHub requests left unspent: the run stops when X-RateLimit-Remaining falls to this
RATE_FLOOR = 25
#: the first `since` the newest-repository search tries (it doubles until a page comes back empty)
FRONTIER_START = 1 << 30
#: the requests a scan makes at least (the commit, the archive, the tree): a scan starts only with these left
SCAN_CALLS = 3
LIST_BYTES = 8 * 1024 * 1024           # one page of /repositories
REPO_BYTES = 1024 * 1024               # one /repos/{owner}/{repo}
MAX_TEXT = 1000                        # characters of a name or description the filters read
PROFILE = "project"
MARKERS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaign_markers.json")
_FOLD_RE = re.compile(r"[^0-9a-z]+")


class DiscoveryError(ValueError):
    """The run cannot start (no token, a filters file that is not one): a usage error."""


def _iso(t):
    return t.astimezone(UTC).isoformat(timespec="seconds")


def _fold(text):
    return _FOLD_RE.sub("", text.lower()) if isinstance(text, str) else ""


# ---------------------------------------------------------------- budgets
class Budget:
    """The run's calls (--max-calls) and GitHub's hourly budget, read from each answer's headers."""

    def __init__(self, calls):
        self.left, self.stopped = calls, None

    def can(self, n=1):
        return self.stopped is None and self.left >= n

    def spend(self, n=1):
        self.left -= n

    def read(self, headers):
        remaining = (headers or {}).get("x-ratelimit-remaining", "")
        if self.stopped is None and remaining.isdigit() and int(remaining) <= RATE_FLOOR:
            reset = headers.get("x-ratelimit-reset", "")
            when = f", until {time.strftime('%H:%M UTC', time.gmtime(int(reset)))}" if reset.isdigit() else ""
            self.stopped = f"GitHub's rate limit is nearly spent ({remaining} requests left{when})"

    def refused(self, exc):
        """A rate-limit answer stops the run: True when `exc` (a SourceError) is one."""
        if getattr(exc, "status", None) in (403, 429) and "rate limit" in str(exc):
            self.stopped = str(exc)
            return True
        return False


def _get(client, budget, url, what, max_bytes):
    """One API call, charged to the budget, its answer parsed (sources' bounded JSON reader)."""
    headers = {}
    budget.spend()
    try:
        raw = client.get(url, what, accept="application/vnd.github+json", max_bytes=max_bytes, reply_headers=headers)
    finally:
        budget.read(headers)
    return sources._json(raw, what)


def list_page(client, budget, since):
    """The public repositories created after repository `since`, as GitHub lists them (at most 100): the items
    that are what a listing's item is (a positive integer id, a full_name that is an owner and a repository by
    GitHub's rules, sources.parse_source's: the name goes into URLs later), in order."""
    doc = _get(client, budget, f"{REPOSITORIES}?since={int(since)}", "listing new repositories", LIST_BYTES)
    if not isinstance(doc, list):
        raise sources.SourceError("listing new repositories: the answer is not a list")
    out = []
    for item in doc:
        if not isinstance(item, dict):
            continue
        rid, full = item.get("id"), item.get("full_name")
        if isinstance(rid, int) and not isinstance(rid, bool) and rid > 0 and _repository(full):
            out.append(item)
    return out


def _repository(full):
    """Is `full` owner/repo by GitHub's rules (sources.parse_source, no ref)?"""
    if not isinstance(full, str) or "@" in full:
        return False
    try:
        sources.parse_source(f"github:{full}")
    except sources.SourceError:
        return False
    return True


def frontier(client, budget):
    """The ID of the newest public repository, or None when the budget ran out first: the largest `since` that
    still lists something, found by doubling FRONTIER_START until a page comes back empty, then halving."""
    lo, hi = 0, FRONTIER_START
    while True:
        if not budget.can():
            return None
        page = list_page(client, budget, hi)
        if not page:
            break
        lo, hi = max(i["id"] for i in page), hi * 2
    while hi - lo > 1:
        if not budget.can():
            return None
        mid = (lo + hi) // 2
        page = list_page(client, budget, mid)
        if page:
            lo = max(lo, max(i["id"] for i in page))
        else:
            hi = mid
    return lo


# ---------------------------------------------------------------- filters
def load_markers(path=MARKERS):
    """campaign_markers.json -> [(field, folded text, the marker as written, the campaign)]."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    out = []
    for m in doc.get("markers") or ():
        if isinstance(m, dict) and m.get("field") in ("name", "description") and _fold(m.get("text")):
            out.append((m["field"], _fold(m["text"]), m["text"], m.get("campaign") or m["text"]))
    return out


def load_patterns(path):
    """--github-filters FILE -> {"include": {field: [compiled]}, "exclude": {…}}; DiscoveryError for a file that is
    not one (its fields: full_name and description)."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        raise DiscoveryError(f"--github-filters: cannot read {path}: {exc}") from None
    if not isinstance(doc, dict) or set(doc) - {"include", "exclude"}:
        raise DiscoveryError('--github-filters: expected {"include": {…}, "exclude": {…}}')
    return {kind: _compiled(kind, doc.get(kind) or {}) for kind in ("include", "exclude")}


def _compiled(kind, part):
    """One part of a --github-filters file, its regular expressions compiled."""
    if not isinstance(part, dict) or set(part) - {"full_name", "description"}:
        raise DiscoveryError(f"--github-filters: {kind!r} takes full_name and description lists")
    out = {}
    for field, pats in part.items():
        if not isinstance(pats, list) or not all(isinstance(p, str) for p in pats):
            raise DiscoveryError(f"--github-filters: {kind}.{field} must be a list of regular expressions")
        try:
            out[field] = [re.compile(p) for p in pats]
        except re.error as exc:
            raise DiscoveryError(f"--github-filters: {kind}.{field}: {exc}") from None
    return out


class Filters:
    """What the listing alone tells of a repository (see the module's notes)."""

    def __init__(self, markers=None, patterns=None, tables=None):
        self.markers = load_markers() if markers is None else markers
        self.patterns = patterns or {}
        self.tables, self.copies = tables if tables is not None else lookalike._load()["github"]

    def match(self, item):
        """-> (what matched: a list of texts, the campaign marker matched or None)."""
        full = item["full_name"][:MAX_TEXT]
        desc = item.get("description") if isinstance(item.get("description"), str) else ""
        desc = desc[:MAX_TEXT]
        marker = self._marker(full.partition("/")[2], desc)
        if marker:
            return [marker[0]], marker[1]
        texts = {"full_name": full, "description": desc}
        if self._hits("exclude", texts):
            return [], None
        return self._lookalike(full) + self._copy(full, desc, item.get("fork")) + self._hits("include", texts), None

    def _marker(self, name, desc):
        """(the text, the marker) of the campaign marker the name or description is, else None."""
        fields = {"name": _fold(name), "description": _fold(desc)}
        for field, folded, text, campaign in self.markers:
            if fields[field] == folded:
                return f"campaign marker: {field} {text!r} ({campaign})", text
        return None

    def _lookalike(self, full):
        hit = lookalike.github_lookalike(full, data=self.tables)
        if not hit:
            return []
        target, part, mine, _theirs, how = hit
        return [f"look-alike: its {part} {mine!r} {how} ({target.removeprefix('github.com/')})"]

    def _copy(self, full, desc, fork):
        """A popular repository's name and description under another owner (not a fork)."""
        owner, _, name = full.partition("/")
        mine = " ".join(desc.split()).lower()
        if fork or not mine:
            return []
        for their_owner, their_desc in self.copies.get(name.lower(), ()):
            if their_owner != owner.lower() and mine == " ".join(their_desc.split()).lower():
                return [f"copy: {their_owner}/{name}'s name and description under another owner"]
        return []

    def _hits(self, kind, texts):
        """The --github-filters patterns of `kind` that match, one text a field."""
        found = []
        for field, pats in (self.patterns.get(kind) or {}).items():
            hit = next((p for p in pats if p.search(texts[field])), None)
            if hit is not None:
                found.append(f"pattern: {field} matches {hit.pattern!r}")
        return found


# ---------------------------------------------------------------- content and scans
def _due(listed, checks):
    """When a candidate listed at `listed` (ISO text) with `checks` checks made is checked next, or None after the
    last."""
    if checks >= len(CHECK_HOURS):
        return None
    return _iso(datetime.datetime.fromisoformat(listed) + datetime.timedelta(hours=CHECK_HOURS[checks]))


def check(store, client, budget, cand):
    """A due candidate's content: -> its new state ("ready", "waiting" or "dropped")."""
    what = f"checking github:{cand['full_name']}"
    try:
        owner, repo = (urllib.parse.quote(p, safe="") for p in cand["full_name"].split("/"))
        doc = _get(client, budget, f"https://{sources.GITHUB_API}/repos/{owner}/{repo}", what, REPO_BYTES)
    except sources.SourceError as exc:
        return _check_failed(store, budget, cand, exc)
    return _checked(store, cand, doc if isinstance(doc, dict) else {})


def _check_failed(store, budget, cand, exc):
    """A check GitHub answered with an error: gone (404) is dropped, a rate limit stops the run, anything else is
    due again next run."""
    if budget.refused(exc):
        raise exc
    if getattr(exc, "status", None) == 404:
        store.update_github_candidate(cand["repo_id"], state="dropped", next_check=None,
                                      checks=cand["checks"] + 1, last_error="gone or made private")
        return "dropped"
    store.update_github_candidate(cand["repo_id"], last_error=str(exc)[:500])
    return "waiting"


def _checked(store, cand, doc):
    """What a check found: content (ready), made private or still empty after the last check (dropped), or not
    yet (waiting, the next check set)."""
    checks = cand["checks"] + 1
    size = doc.get("size") if isinstance(doc.get("size"), int) else 0
    fields = {"checks": checks, "size": size,
              "pushed_at": doc.get("pushed_at") if isinstance(doc.get("pushed_at"), str) else None,
              "default_branch": doc.get("default_branch") if isinstance(doc.get("default_branch"), str) else None,
              "last_error": None}
    if doc.get("private"):
        store.update_github_candidate(cand["repo_id"], state="dropped", next_check=None,
                                      **{**fields, "last_error": "made private"})
        return "dropped"
    if size > 0:
        store.update_github_candidate(cand["repo_id"], state="ready", next_check=None, **fields)
        return "ready"
    nxt = _due(cand["listed_at"], checks)
    if nxt is None:
        store.update_github_candidate(cand["repo_id"], state="dropped", next_check=None,
                                      **{**fields, "last_error": f"still empty {CHECK_HOURS[-1]} hours after it "
                                                                f"was listed"})
        return "dropped"
    store.update_github_candidate(cand["repo_id"], state="waiting", next_check=nxt, **fields)
    return "waiting"


def scan_repository(full_name, ref=None, *, env=None, http=None, shown=None):
    """github:full_name at `ref` (the default branch's head when None), fetched and scanned as a project: -> (the
    registry result, the checkout's API calls). `shown` (--show-secrets): filled with each finding's flagged line as
    read, for the terminal alone (core.scan_project)."""
    ck = sources.checkout(f"github:{full_name}" + (f"@{ref}" if ref else ""), env=env, http=http)
    try:
        return result(full_name, ck, shown), len(ck.calls)
    finally:
        ck.cleanup()


def result(full_name, ck, shown=None):
    """The registry's result for a checkout (the shape Store.save_scan and print_scan take)."""
    issues, truncated, reason_more = _project_issues(ck, shown)
    counted = [i for i in issues if i["rule"] not in core.HARDENING_RULES or i["sev"] == "CRITICAL"]
    verdict, reason, strong, weak = _repo.decide_verdict(counted, truncated)
    if reason_more:
        reason += "; not read whole: " + "; ".join(reason_more)
    sev_counts = {s: 0 for s in core.SEV_ORDER}
    for i in issues:
        sev_counts[i["sev"]] += 1
    return {"ecosystem": ECO, "name": full_name, "version": ck.commit, "artifact": "repository",
            "archiveBytes": ck.bytes, "filesScanned": ck.files, "binaryArtifacts": 0, "profile": PROFILE,
            "sevCounts": sev_counts, "supplyChain": strong + weak, "strongIndicators": strong,
            "weakIndicators": weak, "truncated": truncated, "verdict": verdict, "verdictReason": reason,
            "issues": core.redact_result({"issues": issues})["issues"], "artifacts": [],
            "location": f"https://github.com/{full_name}/tree/{ck.commit}",
            "scannedAt": datetime.datetime.now(UTC).isoformat(timespec="seconds")}


def _project_issues(ck, shown=None):
    """The project scan of a checkout: (its findings, the parts not read whole, why)."""
    issues, truncated, why = [], len(ck.incomplete), [detail for _kind, detail in ck.incomplete]
    try:
        res = core.scan_project(ck.root, shown=shown)
    except core.ScanTargetError:
        return issues, truncated, why                  # (nothing in it Lazaret reads)
    if res.get("incomplete"):
        truncated += 1
        why.insert(0, res.get("incompleteReason") or "the scan stopped early")
    return list(res["issues"]), truncated, why


def _scan(store, budget, cand, env, http, out):
    """Scan a ready candidate and store it: -> its result, or None (a failure, kept in last_error)."""
    try:
        res, calls = scan_repository(cand["full_name"], env=env, http=http)
    except sources.SourceError as exc:
        budget.spend(SCAN_CALLS)
        if budget.refused(exc):
            raise
        if getattr(exc, "status", None) == 404:
            store.update_github_candidate(cand["repo_id"], state="dropped", last_error="gone or made private")
        else:
            store.update_github_candidate(cand["repo_id"], last_error=str(exc)[:500])
        out["errors"].append(f"github:{cand['full_name']}: {exc}")
        return None
    except Exception as exc:                                        # noqa: BLE001
        # (one repository the scan fails on never ends the run; it stays ready for the next)
        budget.spend(SCAN_CALLS)
        store.update_github_candidate(cand["repo_id"], last_error=f"{type(exc).__name__}: {exc}"[:500])
        out["errors"].append(f"github:{cand['full_name']}: {type(exc).__name__}: {exc}")
        return None
    budget.spend(calls)
    pid, _ = store.add_package(ECO, cand["full_name"])
    store.save_scan(pid, res)
    store.update_github_candidate(cand["repo_id"], state="scanned", commit_sha=res["version"],
                                  verdict=res["verdict"], last_error=None)
    return res


# ---------------------------------------------------------------- the run
def run(store, *, scan=False, max_calls=DEFAULT_MAX_CALLS, filters=None, env=None, http=None, now=None):
    """One `discover --ecosystem github --resume` run. -> a dict: listed, pages, caughtUp, matches (filter kind ->
    count), candidates (full names kept), campaigns ([(full_name, marker, url)]), checked ({state: count}),
    scans (results), errors, stopped (why the run stopped early, or None), cursor (the ID listed up to), first
    (True on the first run, which only finds where to start). DiscoveryError without GITHUB_TOKEN."""
    env = os.environ if env is None else env
    token = sources._token("github", env)
    if not token:
        raise DiscoveryError("github discovery needs GITHUB_TOKEN (read-only): without one GitHub allows 60 "
                             "requests an hour, too few to keep up with new repositories")
    now = now or datetime.datetime.now(UTC)
    filters = filters or Filters()
    client = sources.Client("github", token=token, http=http)
    budget = Budget(max_calls)
    out = {"listed": 0, "pages": 0, "caughtUp": False, "matches": {}, "candidates": [], "campaigns": [],
           "checked": {}, "scans": [], "errors": [], "stopped": None, "cursor": None, "first": False}
    try:
        _due_work(store, client, budget, scan, env, http, now, out)
        _listing(store, client, budget, filters, now, out)
    except sources.SourceError as exc:
        if not budget.refused(exc) and budget.stopped is None:
            out["errors"].append(str(exc))
            out["stopped"] = f"GitHub answered with an error: {exc}"
    out["stopped"] = out["stopped"] or _why_stopped(out, budget, max_calls)
    return out


def _why_stopped(out, budget, max_calls):
    """Why a run that met no error stopped before it caught up, or None."""
    if budget.stopped is not None:
        return budget.stopped
    if out["first"] and out["cursor"] is None:
        return f"the run's budget of {max_calls} calls (--max-calls) was spent before the newest repository was found"
    if not out["caughtUp"] and not out["first"]:
        return f"the run's budget of {max_calls} calls (--max-calls) was spent"
    return None


def _due_work(store, client, budget, scan, env, http, now, out):
    """The candidates' due checks, then (with --scan) the ready candidates' scans."""
    for cand in store.github_candidates(states=("waiting",), due_by=_iso(now)):
        if not budget.can():
            return
        state = check(store, client, budget, cand)
        out["checked"][state] = out["checked"].get(state, 0) + 1
    if not scan:
        return
    for cand in store.github_candidates(states=("ready",)):
        if not budget.can(SCAN_CALLS):
            return
        res = _scan(store, budget, cand, env, http, out)
        if res is not None:
            out["scans"].append(res)


def _keep(store, item, matched, listed_at, out):
    """A listed repository a filter matched becomes a candidate: waiting for content, or reported (a campaign's)."""
    found, campaign = matched
    if not found:
        return
    for text in found:
        kind = text.split(":", 1)[0]
        out["matches"][kind] = out["matches"].get(kind, 0) + 1
    full = item["full_name"]
    desc = item.get("description") if isinstance(item.get("description"), str) else None
    if campaign:
        store.add_github_candidate(item["id"], full, desc, item.get("fork"), found, listed_at, "reported", None)
        out["campaigns"].append((full, campaign, f"https://github.com/{full}"))
    else:
        store.add_github_candidate(item["id"], full, desc, item.get("fork"), found, listed_at, "waiting",
                                   _due(listed_at, 0))
        out["candidates"].append(full)


def _listing(store, client, budget, filters, now, out):
    """New repositories from the cursor on, each page's candidates kept, then the cursor."""
    stored = store.discovery_cursor(ECO)
    since = int(stored[0]) if stored and str(stored[0]).isdigit() else None
    if since is None:
        out["first"] = True
        top = frontier(client, budget)
        if top is not None:
            store.save_discovery_cursor(ECO, top, now)
            out["cursor"] = top
        return
    out["cursor"] = since
    listed_at = _iso(now)
    while budget.can():
        page = list_page(client, budget, since)
        if not page:
            out["caughtUp"] = True
            return
        out["pages"] += 1
        for item in page:
            out["listed"] += 1
            _keep(store, item, filters.match(item), listed_at, out)
        since = max(since, max(i["id"] for i in page))
        store.save_discovery_cursor(ECO, since, now)
        out["cursor"] = since
