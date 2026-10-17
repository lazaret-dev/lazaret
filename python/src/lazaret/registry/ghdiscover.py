"""Finding new public GitHub repositories, and scanning the likely-hostile ones (GH-NEW-REPOS; John's scope of Oct 14:
every new public repository, filtered; specs/lazaret-github-new-repos-plan-2026-10-14.md).

    lazaret-registry discover --ecosystem github --resume [--scan] [--max-calls N] [--github-filters FILE]
                              [--github-archive] [--github-scan-all [--max-scans N]]

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

GH Archive (--github-archive; GH-SCAN-ALL, 0.1.9, ghevents.py): the hourly files of GitHub's public events, read in
order from the cursor "gharchive" (the last hour read; the first run starts at the last complete hour), at most
ARCHIVE_HOURS a run, an hour GH Archive has not published yet waited for (ARCHIVE_GIVE_UP hours after it ended,
passed over as a gap of GH Archive's, and said so). A push (or a branch or tag created) makes
a waiting candidate ready without its content check, and a repository made public (PublicEvent: GitHub's listing
never shows one created private) goes through the filters, its name alone. No request to GitHub.

Every new repository (--github-scan-all, which reads GH Archive and scans): a new repository GH Archive saw get code
is queued for a scan, when it is newer than the listing's cursor at scan-all's first run (the cursor
"github-scan-all") and the listing has judged it: a campaign repository is reported and never downloaded, one your
excludes match is kept as excluded, and one pushed before the listing reached it waits as pending until it does.
A repository made public is queued too, its name judged. The scans (--max-scans, SCAN_ALL_MAX_SCANS by default) go
to the filters' ready candidates first, then to the queue newest first; the queue keeps the QUEUE_MAX newest and
the rest are skipped, counted: some ten thousand repositories are created an hour, more than one token's requests
can scan, so the run says what share it covered. A repository is scanned once, at the first push seen.

Where the hourly files come from is --github-events-url (env LAZARET_GITHUB_EVENTS_URL; ghevents.source): GH Archive
by default, which has missed most events since 2025 (a run says so when an hour it read is thin), or OpenDigger's
mirror of the same files (ghevents.MIRROR). A repository gone, made private or empty when its scan comes (GitHub's
404 or 409) is dropped and counted, not an error of the run. A long run says on stderr where it is (`progress`).

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

from lazaret.registry import ghevents, lookalike, sources
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
#: --github-scan-all: scans a run makes unless --max-scans says; the queue's size (the newest kept); how long a
#: repository pushed before the listing reached it waits for the listing (hours)
SCAN_ALL_MAX_SCANS = 100
QUEUE_MAX = 1000
PENDING_HOURS = 72
#: GH Archive: hours read a run at most; the cursors (the last hour read; the listing's cursor when scan-all began)
ARCHIVE_HOURS = 3
#: an hour still not published this many hours after it ended is passed over (GH Archive has gaps), counted
ARCHIVE_GIVE_UP = 6
ARCHIVE_ECO = "gharchive"
SCAN_ALL_ECO = "github-scan-all"
#: the listing says on stderr how far it is every this many pages
LISTING_PROGRESS_EVERY = 25
#: a scan's answers that mean the repository is gone, made private (404) or empty (409: no commit to read)
GONE = (404, 409)
#: what a queued repository's `filters` says
ALL_PUSHED = "all: got code (GH Archive)"
ALL_PUBLIC = "all: made public (GH Archive)"
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

    def judged(self, full, desc):
        """What scan-all asks of a repository GH Archive names: -> ("campaign", the marker's text and the marker),
        ("excluded", None) or (None, None)."""
        full, desc = full[:MAX_TEXT], (desc or "")[:MAX_TEXT]
        marker = self._marker(full.partition("/")[2], desc)
        if marker:
            return "campaign", marker
        if self._hits("exclude", {"full_name": full, "description": desc}):
            return "excluded", None
        return None, None

    def excluded(self, item):
        """Do your excludes match a listed repository (and no campaign marker)?"""
        desc = item.get("description") if isinstance(item.get("description"), str) else ""
        return self.judged(item["full_name"], desc)[0] == "excluded"

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
        if getattr(exc, "status", None) in GONE:
            # (deleted, made private or empty since it was kept: churn, not a failure of the run)
            store.update_github_candidate(cand["repo_id"], state="dropped", last_error="gone, made private or empty")
            out["gone"] += 1
            return None
        store.update_github_candidate(cand["repo_id"], last_error=str(exc)[:500], **_failed_state(cand))
        out["errors"].append(f"github:{cand['full_name']}: {exc}")
        return None
    except Exception as exc:                                        # noqa: BLE001
        # (one repository the scan fails on never ends the run; a filter's stays ready for the next, scan-all's
        # is dropped: the queue moves on)
        budget.spend(SCAN_CALLS)
        store.update_github_candidate(cand["repo_id"], last_error=f"{type(exc).__name__}: {exc}"[:500],
                                      **_failed_state(cand))
        out["errors"].append(f"github:{cand['full_name']}: {type(exc).__name__}: {exc}")
        return None
    budget.spend(calls)
    pid, _ = store.add_package(ECO, cand["full_name"])
    store.save_scan(pid, res)
    store.update_github_candidate(cand["repo_id"], state="scanned", commit_sha=res["version"],
                                  verdict=res["verdict"], last_error=None)
    return res


def _failed_state(cand):
    """A failed scan's state change: scan-all's queued repository is dropped, a filter's candidate stays ready."""
    return {"state": "dropped"} if cand["state"] == "queued" else {}


# ---------------------------------------------------------------- GH Archive (--github-archive, --github-scan-all)
def _archive(store, filters, scan_all, now, out, http, base=ghevents.DEFAULT_SOURCE, say=lambda text: None):
    """The GH Archive hours not read yet (at most ARCHIVE_HOURS, each one complete), applied in order; then
    scan-all's queue and pending repositories kept within their bounds. A file that cannot be read stops the
    archive's part of the run (its cursor kept), not the run."""
    host = urllib.parse.urlsplit(base).hostname
    info = out["archive"] = {"hours": [], "events": 0, "pushed": 0, "ready": 0, "public": 0, "next": None,
                             "unpublished": False, "error": None, "missing": [], "source": host, "thin": False,
                             "default": base == ghevents.DEFAULT_SOURCE}
    if scan_all:
        out["queue"] = {"queued": 0, "pending": 0, "promoted": 0, "excluded": 0, "skipped": 0, "left": 0,
                        "since": _scan_all_start(store)}
    stored = store.discovery_cursor(ARCHIVE_ECO)
    try:
        hour = ghevents.parse_hour(stored[0]) + datetime.timedelta(hours=1) if stored else None
    except ValueError:
        hour = None
    if hour is None:                                # (the first run: the last complete hour)
        hour = now.astimezone(UTC).replace(minute=0, second=0, microsecond=0) - datetime.timedelta(hours=1)
    listed_to = _listing_cursor(store)
    for _ in range(ARCHIVE_HOURS):
        if hour + datetime.timedelta(hours=1) > now:
            break                                   # (not over yet)
        say(f"events: reading the hour {ghevents.hour_name(hour)} UTC from {host}…")
        try:
            body = ghevents.fetch(hour, http, base)
        except ghevents.ArchiveError as exc:
            info["error"] = str(exc)
            out["errors"].append(f"GH Archive: {exc}")
            break
        if body is None:
            if now - (hour + datetime.timedelta(hours=1)) < datetime.timedelta(hours=ARCHIVE_GIVE_UP):
                info["unpublished"] = True
                break
            info["missing"].append(ghevents.hour_name(hour))     # (a gap of GH Archive's: the next hour is read)
            store.save_discovery_cursor(ARCHIVE_ECO, ghevents.hour_name(hour), hour)
            hour += datetime.timedelta(hours=1)
            continue
        try:
            events = ghevents.read(body, keep=_keep_push(store, scan_all, out))
        except ghevents.ArchiveError as exc:
            info["error"] = f"{ghevents.hour_name(hour)}: {exc}"
            out["errors"].append(f"GH Archive: {info['error']}")
            break
        _apply(store, filters, scan_all, events, listed_to, now, out)
        store.save_discovery_cursor(ARCHIVE_ECO, ghevents.hour_name(hour), hour)
        info["hours"].append(ghevents.hour_name(hour))
        info["events"] += events.events
        info["thin"] = info["thin"] or events.events < ghevents.THIN_HOUR
        hour += datetime.timedelta(hours=1)
    info["next"] = ghevents.hour_name(hour)
    if scan_all:
        queue = out["queue"]
        queue["skipped"] += store.prune_github_candidates("queued", keep=QUEUE_MAX)
        queue["skipped"] += store.prune_github_candidates(
            "pending", before=_iso(now - datetime.timedelta(hours=PENDING_HOURS)))


def _listing_cursor(store):
    stored = store.discovery_cursor(ECO)
    return int(stored[0]) if stored and str(stored[0]).isdigit() else None


def _scan_all_start(store):
    """The listing's cursor when scan-all first ran (a repository newer than it is new), stored then."""
    stored = store.discovery_cursor(SCAN_ALL_ECO)
    if stored and str(stored[0]).isdigit():
        return int(stored[0])
    start = _listing_cursor(store)
    if start is not None:
        store.save_discovery_cursor(SCAN_ALL_ECO, start)
    return start


def _keep_push(store, scan_all, out):
    """Which repositories' pushes an hour keeps: scan-all's new ones and the filters' waiting candidates."""
    since = out["queue"]["since"] if scan_all and out["queue"] else None
    waiting = {c["repo_id"] for c in store.github_candidates(states=("waiting",))}
    return lambda rid: (since is not None and rid > since) or rid in waiting


def _apply(store, filters, scan_all, events, listed_to, now, out):
    """One hour's events: the filters' waiting candidates that got code made ready, the repositories made public
    through the filters (scan-all: queued), and with scan-all the new repositories that got code queued."""
    info, queue = out["archive"], out["queue"]
    states = store.github_candidate_states(set(events.pushed) | set(events.public))
    for rid, state in states.items():
        if state == "waiting" and rid in events.pushed:
            name, at = events.pushed[rid]
            store.update_github_candidate(rid, state="ready", next_check=None, pushed_at=at, last_error=None)
            info["ready"] += 1
    rows = []
    listed_at = _iso(now)
    for rid, (name, at) in events.public.items():
        if rid in states:
            continue
        info["public"] += 1
        if scan_all:
            _judge(store, filters, rid, name, None, ALL_PUBLIC, "queued", at or listed_at, rows, out)
            continue
        item = {"id": rid, "full_name": name, "description": None, "fork": False}
        matched = filters.match(item)
        _keep(store, item, matched, at or listed_at, out)
        if matched[0] and not matched[1] and rid in events.pushed_ids:
            store.update_github_candidate(rid, state="ready", next_check=None, pushed_at=at)
    if scan_all and queue["since"] is not None:
        for rid, (name, at) in events.pushed.items():
            if rid <= queue["since"] or rid in states or rid in events.public:
                continue
            info["pushed"] += 1
            desc = (events.created.get(rid) or (None, None, None))[1]
            state = "queued" if listed_to is not None and rid <= listed_to else "pending"
            _judge(store, filters, rid, name, desc, ALL_PUSHED, state, at or listed_at, rows, out)
    store.add_github_candidates(rows)


def _judge(store, filters, rid, name, desc, why, state, at, rows, out):
    """A repository scan-all would queue: a campaign marker reports it (never downloaded), your excludes keep it
    out, anything else is a row of `state` (queued, or pending until the listing reaches it)."""
    queue = out["queue"]
    verdict, marker = filters.judged(name, desc)
    if verdict == "campaign":
        rows.append((rid, name, desc, False, [marker[0]], at, "reported", None))
        out["campaigns"].append((name, marker[1], f"https://github.com/{name}"))
        return
    if verdict == "excluded":
        rows.append((rid, name, desc, False, ["excluded by your patterns"], at, "excluded", None))
        queue["excluded"] += 1
        return
    rows.append((rid, name, desc, False, [why], at, state, None))
    queue[state] += 1


# ---------------------------------------------------------------- the run
def run(store, *, scan=False, max_calls=DEFAULT_MAX_CALLS, filters=None, env=None, http=None, now=None,
        archive=False, scan_all=False, max_scans=None, archive_http=None, events_url=None, progress=None):
    """One `discover --ecosystem github --resume` run. -> a dict: listed, pages, caughtUp, matches (filter kind ->
    count), candidates (full names kept), campaigns ([(full_name, marker, url)]), checked ({state: count}),
    scans (results), errors, stopped (why the run stopped early, or None), cursor (the ID listed up to), first
    (True on the first run, which only finds where to start), archive (what GH Archive's hours gave, or None), and
    queue (scan-all's: queued, pending, skipped, left). `archive` reads GH Archive (ghevents; `archive_http` its
    network seam), `scan_all` makes every new repository that gets code a candidate (it reads GH Archive and
    scans), `max_scans` caps the run's scans (SCAN_ALL_MAX_SCANS with scan_all), `events_url` is where the hourly
    files come from (ghevents.source's form; GH Archive by default), `progress(text)` hears where a long run is,
    and `gone` counts the scans of repositories gone, made private or empty. DiscoveryError without GITHUB_TOKEN
    or with an events URL that is not one."""
    env = os.environ if env is None else env
    token = sources._token("github", env)
    if not token:
        raise DiscoveryError("github discovery needs GITHUB_TOKEN (read-only): without one GitHub allows 60 "
                             "requests an hour, too few to keep up with new repositories")
    now = now or datetime.datetime.now(UTC)
    filters = filters or Filters()
    client = sources.Client("github", token=token, http=http)
    budget = Budget(max_calls)
    archive, scan = archive or scan_all, scan or scan_all
    if scan_all and max_scans is None:
        max_scans = SCAN_ALL_MAX_SCANS
    try:
        events_url = ghevents.source(events_url) if events_url else ghevents.DEFAULT_SOURCE
    except ValueError as exc:
        raise DiscoveryError(f"--github-events-url: {exc}") from None
    say = progress or (lambda text: None)
    out = {"listed": 0, "pages": 0, "caughtUp": False, "matches": {}, "candidates": [], "campaigns": [],
           "checked": {}, "scans": [], "errors": [], "stopped": None, "cursor": None, "first": False,
           "archive": None, "queue": None, "gone": 0}
    try:
        _checks(store, client, budget, now, out)
        if archive:
            _archive(store, filters, scan_all, now, out, archive_http, events_url, say)
        if scan:
            _scans(store, budget, max_scans, env, http, out, say)
        _listing(store, client, budget, filters, now, out, scan_all, say)
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


def _checks(store, client, budget, now, out):
    """The candidates' due content checks."""
    for cand in store.github_candidates(states=("waiting",), due_by=_iso(now)):
        if not budget.can():
            return
        state = check(store, client, budget, cand)
        out["checked"][state] = out["checked"].get(state, 0) + 1


def _scans(store, budget, max_scans, env, http, out, say=lambda text: None):
    """The scans (--scan): the ready candidates, oldest first, then scan-all's queue, newest first, at most
    `max_scans` in all."""
    made = 0
    queue = out["queue"]
    cap = "" if max_scans is None else f" of at most {max_scans}"
    for states, newest in ((("ready",), False), (("queued",), True)):
        limit = None if max_scans is None else max(0, max_scans - made)
        for cand in store.github_candidates(states=states, newest_first=newest, limit=limit):
            if (max_scans is not None and made >= max_scans) or not budget.can(SCAN_CALLS):
                break
            made += 1
            say(f"scanning {made}{cap}: github:{cand['full_name']}…")
            res = _scan(store, budget, cand, env, http, out)
            if res is not None:
                out["scans"].append(res)
    if queue is not None:
        queue["left"] = len(store.github_candidates(states=("queued",), limit=QUEUE_MAX + 1))


def _scan_all_listed(store, item, matched, held, filters, listed_at, out):
    """A listed repository with scan-all on: a pending one (pushed before the listing reached it) is queued,
    reported or excluded as the listing judges it; one your excludes match is kept as excluded; a filter's match is
    a candidate, ready at once when GH Archive saw it get code."""
    found, campaign = matched
    queue = out["queue"]
    if held == "pending":
        if campaign:
            store.update_github_candidate(item["id"], state="reported", filters=_repo.db_json(found))
            out["campaigns"].append((item["full_name"], campaign, f"https://github.com/{item['full_name']}"))
        elif filters.excluded(item):
            store.update_github_candidate(item["id"], state="excluded",
                                          filters=_repo.db_json(["excluded by your patterns"]))
        elif found:
            store.update_github_candidate(item["id"], state="ready", filters=_repo.db_json(found))
            out["candidates"].append(item["full_name"])
        else:
            store.update_github_candidate(item["id"], state="queued")
        if queue is not None:
            queue["promoted"] += 1
        return
    if held is not None:
        return
    if not found and filters.excluded(item):
        desc = item.get("description") if isinstance(item.get("description"), str) else None
        store.add_github_candidate(item["id"], item["full_name"], desc, item.get("fork"),
                                   ["excluded by your patterns"], listed_at, "excluded", None)
        return
    _keep(store, item, matched, listed_at, out)


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


def _listing(store, client, budget, filters, now, out, scan_all=False, say=lambda text: None):
    """New repositories from the cursor on, each page's candidates kept, then the cursor. With scan-all, what the
    listing judges is kept for GH Archive's pushes too: excluded and campaign repositories, and the pending ones
    (pushed before the listing reached them) queued or reported."""
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
        held = store.github_candidate_states(i["id"] for i in page) if scan_all else {}
        for item in page:
            out["listed"] += 1
            matched = filters.match(item)
            if scan_all:
                _scan_all_listed(store, item, matched, held.get(item["id"]), filters, listed_at, out)
            else:
                _keep(store, item, matched, listed_at, out)
        since = max(since, max(i["id"] for i in page))
        store.save_discovery_cursor(ECO, since, now)
        out["cursor"] = since
        if out["pages"] % LISTING_PROGRESS_EVERY == 0:
            say(f"listing: {out['pages']} pages, {out['listed']:,} new repositories, up to ID {since}…")
