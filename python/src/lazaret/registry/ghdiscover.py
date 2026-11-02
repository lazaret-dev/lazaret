"""Finding new public GitHub repositories, and scanning the likely-hostile ones (GH-NEW-REPOS; John's scope of Oct 14:
every new public repository, filtered; specs/lazaret-github-new-repos-plan-2026-10-14.md).

    lazaret-registry discover --ecosystem github --resume [--scan] [--max-calls N] [--github-filters FILE]
                              [--github-archive] [--github-scan-all [--max-scans N] [--max-graphql-calls N]
                                                  [--graphql-concurrency N] [--graphql-seconds N]]

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

Every new repository (--github-scan-all, which asks GitHub's GraphQL API, reads GH Archive and scans): a new
repository, one newer than the listing's cursor at scan-all's first run (the cursor "github-scan-all"), that got
code is queued for a scan once the listing has judged it: a campaign repository is reported and never downloaded,
one your excludes match is kept as excluded, one a filter keeps is a candidate as above, and one GH Archive saw
pushed before the listing reached it waits as pending until it does. Which new repositories got code is asked of
GitHub's GraphQL API (GH-SCAN-GQL, below); GH Archive gives the repositories made public, which the listing never
shows (queued, their names judged), and a push it sees still queues a new repository as before. The scans
(--max-scans, SCAN_ALL_MAX_SCANS by default) go to the filters' ready candidates first, then to the queue:
LATE_SCAN_SHARE of its scans, rounded up, to its late finds (code GraphQL found at an ask LATE_HOURS or more after
the listing: the 6, 24 and 72 hours' asks; github_candidates' late_at), the first found first, for their pushes,
hours old when found, would lose to each new hour's (John, Oct 20); the rest newest push first, late finds among
them, a share not used going to the other. The queue keeps the QUEUE_MAX newest pushes and, apart, the QUEUE_MAX
late finds found last, and the rest are skipped, counted: some ten thousand repositories are created an hour, more
than one token's requests can scan, so the run says what share it covered. A repository is scanned once, when it is
first seen with code. Its own workflow hygiene (SCAN_ALL_HYGIENE_RULES: an action not pinned, the token's
permissions, a cache in a release, an OIDC token where dependencies install) is its owner's configuration, not a sign
that it is hostile, so scan-all lists it as INFO (SCANALL-HYGIENE; John, Oct 21: "INFO in scan-all only"), each such
finding's message saying so and what a project scan grades it, and the verdict's reason how many: stored, reported,
and no verdict set, as below CRITICAL it never set one (item 4). A filter's candidate, `lazaret-registry scan github:`
and every other scan grade them as before.

GraphQL (GH-SCAN-GQL, 0.1.9; John's choice of Oct 18, when GH Archive's hour 2026-10-17-4 held 6,044 events and no
PushEvent or CreateEvent at all, so that three hours queued nothing that got code, and OpenDigger's mirror sent his
Mac some 1.5 KB/s): each listed repository scan-all asks about (one no filter, exclude or campaign marker kept) is
kept with the listing's `node_id` (github_listed) and asked about right after its page, one call for the page,

    POST https://api.github.com/graphql   {"query": GRAPHQL_QUERY, "variables": {"ids": [at most 100 node IDs]}}

and, while it has no code, again at CHECK_HOURS after it was listed, in each run after the scans and before the
listing, GRAPHQL_BATCH a call: GRAPHQL_DUE_SHARE of the run's calls, and of its GraphQL seconds, go to the due ones
listed longest ago, oldest first (the nearest their last check, and the first LISTED_MAX would evict), so that fresh
pages cannot starve them, and the rest newest first. The answer, node by node, every field asked for there and of
its type: isEmpty false, queued for a scan (ALL_GRAPHQL) as of when its code arrived, pushedAt held to [createdAt,
now] (the run's time when it is not known), as GH Archive queued a push as of its time; what the asks find is
scanned from the next run on, as what the listing finds is, so that the queue's newest first takes fresh and late
finds by their push time, neither starved; the name GraphQL gives is judged again (a repository renamed to a
campaign marker is reported, never downloaded); isEmpty true, asked again; a null node that NOT_FOUND errors alone
name, or isPrivate true, gone, dropped and counted. A fork is queued once it was pushed to after it was made
(pushedAt later than createdAt; at the same time it is not: an untouched fork's pushedAt is its parent's), as GH
Archive queued a fork only on a push to it; until then it is kept and asked again as an empty one is. A repository
is dropped for its age only when its last scheduled ask (CHECK_HOURS[-1], PENDING_HOURS) answered that it has no
code, counted (expired). Fail closed: an error that names a node, a null node no error names, a node whose fields
are missing, of another type, out of range (a time UTC cannot hold) or another repository's (databaseId), an error
of the whole query, an answer without the list asked for, an HTTP error, a body over GRAPHQL_BYTES or not JSON: no
repository is dropped or taken as empty; each stays waiting, to be asked at the next run however long that takes,
and the run says so. A row GitHub could not answer about (its own error or fields) waits 1, 2, 4 ... hours, at most
GRAPHQL_BACKOFF_MAX_HOURS, before its next ask (github_listed's `fails`, reset by an answer), never dropped for it:
LISTED_MAX alone bounds it. A batch of which nothing could be read (an error of the whole query, or an answer not as
asked) is asked in halves, and the halves that fail so in halves, level by level, down to single rows
(GRAPHQL_SPLIT_DEPTH levels, within the run's calls and seconds): the rows GitHub cannot answer about, alone, are
backed off so, and the rest answered (a row that fails the whole query costs some 15 calls). Two levels in a row of
which nothing could be read are GitHub's failure, or a failing row in every group: a control call elsewhere, about
repositories that exist, tells which (`_control`: about one GitHub answered about this run, or an earlier run found
empty or a fork, its answer only read; or else about the newest due rows not asked yet this run); answered, those
groups are isolated on, and the asking goes on; not, or with no such repository to ask about, they wait as they were
for GitHub to answer another call, and the batch counts as GitHub's failure (a call about no repository would prove
nothing: GitHub can answer it while it fails every query about repositories). A batch's call that GitHub ended at its
own time limit for a call (a 502 or 504, GRAPHQL_TIMEOUTS; John, Oct 20: two 502s in ten calls of some 8 s) is no
failure of the call: its rows are asked again in halves, isolated as above, which end sooner, and a failure of a half
is the failure it would have been. GRAPHQL_FAILURES such batches in a row, their control calls failing too, or
GRAPHQL_FAILURES failures of the call (an HTTP error, a body not JSON or over the budget), stop the GraphQL part, with
nothing backed off; so does GRAPHQL_RUN_SECONDS spent in it (its wall clock, below). GraphQL's
own rate limit (rateLimit.remaining or the X-RateLimit-Remaining header, the lower, at GRAPHQL_RATE_FLOOR, a
RATE_LIMITED error or an error that speaks of a rate limit, a 403 with no points left) stops the GraphQL part: the
listing goes on, its repositories kept unasked for the next run. A secondary rate limit (a Retry-After on any
answer, 200 included, an error about a secondary rate limit, a 429, another 403), which GitHub counts over the
token's REST and GraphQL calls alike, stops the run as REST's rate limit does. REST's own limits stop REST's calls
alone (Budget.stopped): GraphQL spends none of them, so its asks go on, after the checks or the scans stopped too; a
REST refusal that is a secondary limit (one with a Retry-After, or a 429 that does not say REST's requests are
spent: sources' SourceError.limits) stops them as well (Budget.shared). A header or a time not understood is
unknown, never an error of the run. Budgets: --max-graphql-calls (DEFAULT_MAX_GRAPHQL_CALLS: a 1,000-page listing's
calls and 3,000 calls asking again), counted apart from --max-calls; GitHub's GraphQL points (5,000 an hour; such a
call costs 1); the repositories waiting for code keep the LISTED_MAX newest: one evicted past it is counted and said
on stderr. A listing item without a usable node ID cannot be asked about: it becomes a candidate of the REST content
checks (ALL_NO_NODE), counted and said on stderr. Only node IDs go into a query, as its variables; the token goes to
api.github.com alone (sources.Client.post: https, no redirect followed, GRAPHQL_SECONDS in all). A github_listed or
github_candidates made by an earlier version gets the columns added since (fails, late_at) when the database is
opened. Two runs at once on one Postgres database write github_listed's rows locked in repo_id order, and a batch
rolled back for a deadlock is done again (Store._pg_batch).

Calls at once, paced (GH-SCAN-GQL-SPEED, 0.1.9; John's go-ahead of Oct 20, when a run's 907 seconds were 903.6
waiting for GitHub's answers, a call of 100 node IDs some 3.5 s and GitHub's time linear in the repositories asked, so
that 900 GraphQL seconds asked some 250 calls, 25,000 repositories, while a catch-up listing adds some 85,000 a run):
up to --graphql-concurrency calls (DEFAULT_GRAPHQL_CONCURRENCY, 1, one at a time as before; at most
GRAPHQL_CONCURRENCY_MAX, 8) are in flight at once, each call's HTTP on a thread of its own (`_Calls`, the standard
library's threads), while the run goes on with the next batch or the listing's next page. GitHub's CPU-time limit
(below) holds a token's GraphQL calls to some 60 seconds of response time a minute, which one call at a time of 3.5 s
already spends but cannot pass (its calls do not overlap, and CPU time is less than response time): so one at a time
is not paced. With several at once the run paces its calls (`_paced`): it keeps the response seconds of its calls
that ended in the last GRAPHQL_CPU_WINDOW seconds of its clock, and starts no call while those, with an estimate for
each call in flight and for the call itself (the recent calls' median, or the call's own time so far, the more),
would pass GRAPHQL_CPU_PER_MINUTE (50, a margin under GitHub's 60, as the REST listing shares GitHub's 90): it waits
for a call in flight to end, or, none in flight, until enough of those calls leave the window. At 3.5 s a call that
is some 14 calls a minute, fewer than one at a time's 17: more at once help only while GitHub answers fast. A call in
flight is counted at the median until it passes it, so a sudden slowdown of GitHub's can pass a minute's 50 s, by
each call in flight's time over the median (at most the concurrency times GitHub's 10 s for a call): GitHub then
answers with a secondary limit, and the run stops cleanly; so raise the concurrency only while calls are fast. At a
Ctrl-C the run waits for the calls in flight to end (each has GRAPHQL_SECONDS, a minute, in all); a second Ctrl-C
exits at once. Everything else stays on the run's thread: each answer is read and stored there, in the order the calls
end, and each batch's follow-up after it (isolation, a control call, the streak), so that the database, SQLite or
Postgres, is written from one thread as before. The due asks start in the order above (a quarter oldest listed first,
the rest newest first); their answers may end in another order without changing what is asked or stored. A run makes one
call at a time until an answer was read with GitHub's points left in it, and again after any other answer (a failure of
the call, a rate limit, an error of the whole query, GitHub's time limit): no call starts until the calls then in flight
have ended, their answers read and stored (nothing lost, nothing stored twice), and then one at a time until a call
started since is read. A follow-up that makes calls of its own lets every call in flight end first and makes its calls
one at a time, so isolation and control calls are as above. No call starts once the run's calls are spent
(--max-graphql-calls counts a call as it starts), nor its GraphQL seconds, nor after a stop, nor while GitHub's points
left (the latest answer's), less one for each call in flight, would be at GRAPHQL_RATE_FLOOR. The GraphQL seconds
(--graphql-seconds, GRAPHQL_RUN_SECONDS by default, at most GRAPHQL_RUN_SECONDS_MAX) and the due share's quarter of them
are the GraphQL part's wall clock while calls are in flight or it waits for GitHub's CPU-time limit, not the sum of the
calls' times, which would make calls at once gain nothing; a call in flight when they run out still ends and is stored,
as one call could before. A failure of a call started before the last failure counted was in flight with it and is not
counted again: GRAPHQL_FAILURES still means that many failures, each of a call started after the one before was seen.
The transports are safe for it: urllib's makes a connection for each call, and the native one's shared client
(pratique's) hands each call a connection of its own, or a stream of its own on GitHub's HTTP/2 connection.

What GitHub's documentation says (read Oct 18, 2026): the endpoint, a POST whose JSON body holds `query`, and the
token as `Authorization: bearer` (docs.github.com/en/graphql/guides/forming-calls-with-graphql); Repository's
databaseId (Int), nameWithOwner (String!), isEmpty, isFork, isPrivate (Boolean!), createdAt (DateTime!), pushedAt
(DateTime) and diskUsage (Int, kilobytes) (docs.github.com/en/graphql/reference/repos); `nodes(ids: [ID!]!)`,
"Lookup nodes by a list of IDs", returning [Node]!, with no maximum stated for `ids` (read in
docs.github.com/en/enterprise-server@3.3/graphql/reference/queries: github.com's page of queries did not show the
entry when fetched), so a call asks about 100, the most a connection's `first` or `last` takes, far under the
500,000 nodes a call may request; 5,000 points an hour for a user, a call's cost 1 at least,
`rateLimit { cost remaining resetAt }`, an exceeded primary limit answered 200 with an error and
X-RateLimit-Remaining 0, X-RateLimit-Resource always `graphql`, secondary limits (100 concurrent requests shared
with the REST API, 2,000 points a minute) answered 200 or 403, Retry-After to be waited for, and a call over 10
seconds ended with a 502 or 504 (docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api;
the same page read again Oct 21 for its limit on compute: "No more than 90 seconds of CPU time per 60 seconds of real
time is allowed", "No more than 60 seconds of this CPU time may be for the GraphQL API", and "You can roughly estimate
the CPU time by measuring the total response time for your API requests").
Not in the documentation: an error's `type` (RATE_LIMITED, NOT_FOUND) and `path` (["nodes", i]) are the shapes
GitHub sends; anything else is not understood, and fails closed as above.

Where the hourly files come from is --github-events-url (env LAZARET_GITHUB_EVENTS_URL; ghevents.source): GH Archive
by default, which has missed most events since 2025 (a run says so when an hour it read is thin), or OpenDigger's
mirror of the same files (ghevents.MIRROR), which sent John's Mac some 1.5 KB/s on Oct 18 (a 335 MB hour): too slow
to use from there, so scan-all asks GraphQL instead. A repository gone, made private or empty when its scan comes
(GitHub's 404 or 409) is dropped and counted, not an error of the run. A long run says on stderr where it is
(`progress`).

Budgets: --max-calls (DEFAULT_MAX_CALLS) across what is due first (the checks and scans) and then the listing, so a
listing that has fallen behind does not keep a candidate waiting; and GitHub's: the run stops when
X-RateLimit-Remaining falls to RATE_FLOOR, or on a rate-limit answer (403 or 429), keeping its cursor and its
candidates for the next run (GraphQL's calls and points are their own, above). GITHUB_TOKEN is required (60
requests an hour without one cannot keep up) and goes only to api.github.com (sources.Client). Static only: an
archive is read into a temporary folder and removed, nothing runs, and no secret is verified (a sweep never logs in
with strangers' credentials).
"""
import bisect
import datetime
import json
import math
import os
import queue
import re
import statistics
import threading
import time
import urllib.parse
from collections import deque

from lazaret.registry import ghevents, lookalike, sources
from lazaret.registry import repo as _repo
from lazaret.scanner import core

__all__ = ["DiscoveryError", "Budget", "Filters", "run", "frontier", "scan_repository", "load_markers",
           "load_patterns", "read_nodes", "CHECK_HOURS", "DEFAULT_MAX_CALLS", "DEFAULT_MAX_GRAPHQL_CALLS",
           "DEFAULT_GRAPHQL_CONCURRENCY", "RATE_FLOOR", "ECO"]

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
#: GH-SCAN-GQL (John, Oct 20): a late find, code GitHub's GraphQL API found at an ask this many hours or more after
#: the listing (the 6, 24 and 72 hours' asks), has this share of the queue's scans in a run, rounded up, the first
#: found first: pushed hours before it is found, it would lose the newest-push-first queue to each new hour's finds.
#: The late finds are bounded apart, the QUEUE_MAX found last kept
LATE_HOURS = CHECK_HOURS[1]
LATE_SCAN_SHARE = 0.25
#: GH Archive: hours read a run at most; the cursors (the last hour read; the listing's cursor when scan-all began)
ARCHIVE_HOURS = 3
#: an hour still not published this many hours after it ended is passed over (GH Archive has gaps), counted
ARCHIVE_GIVE_UP = 6
ARCHIVE_ECO = "gharchive"
SCAN_ALL_ECO = "github-scan-all"
#: the listing says on stderr how far it is every this many pages
LISTING_PROGRESS_EVERY = 25
#: the parts of a checkout not read that a scan's verdict reason names (the rest counted)
SHOWN_GAPS = 5
#: a scan's answers that mean the repository is gone, made private (404) or empty (409: no commit to read)
GONE = (404, 409)
#: SCANALL-HYGIENE (John's decision of Oct 21, "INFO in scan-all only"): the CI hardening checks that are a
#: repository's own workflow configuration, its owner's risk and no sign that the repository is hostile. In scan-all's
#: own repositories (repo._scan_all_row: a filter "all: …") such a finding below CRITICAL is listed as INFO, its
#: message saying so and what a project scan grades it (HYGIENE_NOTE), and the verdict's reason counts them. Exactly
#: these four: SC-WORKFLOW-PR-CHECKOUT, SC-WORKFLOW-SECRETS and every other rule are graded as before, and so is
#: every finding of a filter's candidate, of `lazaret-registry scan github:`, of `lazaret scan` and of a package scan
SCAN_ALL_HYGIENE_RULES = frozenset({"SC-WORKFLOW-UNPINNED", "SC-WORKFLOW-PERMISSIONS", "SC-WORKFLOW-CACHE",
                                    "SC-WORKFLOW-OIDC-INSTALL"})
HYGIENE_NOTE = " (scan-all: the owner's workflow configuration, {sev} in a project scan: listed, not counted)"
#: what a queued repository's `filters` says
ALL_PUSHED = "all: got code (GH Archive)"
ALL_PUBLIC = "all: made public (GH Archive)"
ALL_GRAPHQL = "all: got code (GraphQL)"
#: GH-SCAN-GQL: GitHub's GraphQL API, asked which of scan-all's listed repositories got code (the module's notes)
GRAPHQL = f"https://{sources.GITHUB_API}/graphql"
GRAPHQL_QUERY = ("query($ids:[ID!]!){nodes(ids:$ids){...on Repository{databaseId nameWithOwner isEmpty isFork "
                 "isPrivate createdAt pushedAt diskUsage}}rateLimit{cost remaining resetAt}}")
#: node IDs a call asks about
GRAPHQL_BATCH = 100
#: GraphQL calls a run makes unless --max-graphql-calls says: a 1,000-page listing's and 3,000 asking again
DEFAULT_MAX_GRAPHQL_CALLS = 4000
#: GraphQL's points left unspent: the GraphQL part stops when rateLimit.remaining falls to this
GRAPHQL_RATE_FLOOR = 100
#: GraphQL calls that may fail in a run (an HTTP error, a body that is not JSON or over the budget) before it asks
#: no more; and batches in a row of which nothing could be read, not even in halves and quarters
GRAPHQL_FAILURES = 3
GRAPHQL_BYTES = 1024 * 1024            # one answer (100 repositories' fields are some 25 KB)
GRAPHQL_SECONDS = 60.0                 # one call, in all (sources.Client.post)
#: the seconds a run's GraphQL part may take unless --graphql-seconds says (at most GRAPHQL_RUN_SECONDS_MAX), then it
#: starts no call: its wall clock while calls are in flight (from the start of a call while none was to the end of
#: the last one in flight, what their answers store included) and while it waits for GitHub's CPU-time limit (below),
#: not the sum of the calls' times, which would make calls at once gain nothing (GH-SCAN-GQL-SPEED)
GRAPHQL_RUN_SECONDS = 900.0
GRAPHQL_RUN_SECONDS_MAX = 3600.0
#: the share of a run's GraphQL calls (started), and of its GraphQL seconds (that wall clock), for the due asks,
#: oldest listed first (the nearest their last check, and the first LISTED_MAX would evict): the rest go newest first,
#: so fresh pages cannot starve them
GRAPHQL_DUE_SHARE = 0.25
#: GH-SCAN-GQL-SPEED (John, Oct 20): GraphQL calls a run makes at once unless --graphql-concurrency says, and the most
#: it takes. GitHub's time is per repository asked about (a call of 100 some 3.5 s: 25 ids 1.0 s, 50 ids 1.9 s), and
#: GitHub's CPU-time limit (below) holds a token's GraphQL calls to some 60 seconds of response time a minute, which
#: one call at a time of 3.5 s already spends: so 1, one at a time, as before, by default; more at once only help
#: while GitHub answers fast, and a sudden slowdown of GitHub's can pass its limit (below)
DEFAULT_GRAPHQL_CONCURRENCY = 1
GRAPHQL_CONCURRENCY_MAX = 8
#: GitHub's secondary limit on compute (the documentation below): "No more than 90 seconds of CPU time per 60 seconds
#: of real time", "No more than 60 seconds of this CPU time may be for the GraphQL API", which "you can roughly
#: estimate ... by measuring the total response time for your API requests". One call at a time cannot spend more
#: than 60 s of response time in 60 s (its calls do not overlap), and CPU time is less than response time, so it is not
#: paced (John's runs at some 60 s a minute never met the limit; pacing them to 50 cost 16 to 30% of their calls). With
#: several at once the run keeps its GraphQL calls' response seconds over the last GRAPHQL_CPU_WINDOW seconds of its
#: clock, and starts no call while those, with an estimate for the calls in flight and the call itself (its time so
#: far, or the recent median call's, the more), would pass GRAPHQL_CPU_PER_MINUTE: a margin under GitHub's 60, as the
#: REST listing's calls share the 90. A call is counted at the median when it starts, so a sudden slowdown of GitHub's
#: can pass it, by each call in flight's time over the median (at most the concurrency times GitHub's 10 s); GitHub
#: then answers with a secondary limit, which stops the run cleanly
GRAPHQL_CPU_PER_MINUTE = 50.0
GRAPHQL_CPU_WINDOW = 60.0
#: the calls' response times the median estimate is of (the most recent)
GRAPHQL_CPU_RECENT = 25
#: what GitHub answers a call it ended at its own time limit (10 seconds, the documentation below: 502 or 504): such
#: a batch is asked again in halves, which end sooner, and counts as a failure of the call only when they fail too
GRAPHQL_TIMEOUTS = (502, 504)
#: a batch of which nothing could be read is split in halves this many times at most, down to single rows (100 rows:
#: 7), to find the rows GitHub cannot answer about; those wait 1, 2, 4 … hours, at most this many, before the next ask
GRAPHQL_SPLIT_DEPTH = 7
GRAPHQL_BACKOFF_MAX_HOURS = 72
#: a batch none of whose halves and quarters could be read is told from GitHub failing by a control call elsewhere,
#: about a repository GitHub answered about (this run's, of the last this many; or one an earlier run found empty or a
#: fork), or about the newest due rows not asked yet (looked for in this many pages of them)
GRAPHQL_CONTROL_KNOWN = 5
GRAPHQL_CONTROL_PAGES = 3
#: the clock the GraphQL part's seconds are counted on, and how it waits for GitHub's CPU-time limit (seams for the
#: tests)
_clock = time.monotonic
_sleep = time.sleep
#: listed repositories kept waiting for code (the newest: some three days of new repositories still empty). One is
#: dropped for its age only when its last scheduled ask (CHECK_HOURS[-1]) answered "no code"; one never answered
#: waits until it is, or until this bound evicts it (counted, and said on stderr)
LISTED_MAX = 500_000
#: the run says on stderr how far the GraphQL part is every this many calls
GRAPHQL_PROGRESS_EVERY = 25
_NODE_ID_RE = re.compile(r"[A-Za-z0-9_=+/-]{1,200}")
#: what a listing item without a node ID becomes: a candidate of the REST content checks (fail closed)
ALL_NO_NODE = "all: listed without a node ID (REST content checks)"
#: the fields a node must have, every one, to be read (GRAPHQL_QUERY's)
NODE_FIELDS = ("databaseId", "nameWithOwner", "isEmpty", "isFork", "isPrivate", "createdAt", "pushedAt", "diskUsage")
LIMITED = "GitHub's GraphQL API says the call was rate limited"
SECONDARY = "GitHub's GraphQL API says a secondary rate limit was exceeded"
_RATE_LIMIT_RE = re.compile(r"rate.?limit", re.I)
_SECONDARY_RE = re.compile(r"secondary rate.?limit", re.I)
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


def _header_int(text, digits=12):
    """A header's count or time (ASCII digits, at most `digits` of them) -> an int, or None for anything else ("²",
    a sign, a 30-digit number): a value not understood is unknown, never an error of the run."""
    text = str(text or "").strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= digits else None


def _epoch(seconds):
    """Seconds since 1970 -> that time (aware, UTC), or None (None given, or out of range)."""
    if seconds is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------- budgets
class Budget:
    """The run's calls (--max-calls) and GitHub's hourly budget, read from each answer's headers. `stopped` says why
    the run's REST calls stopped; `shared` why GraphQL's must stop too (a secondary rate limit, which GitHub counts
    over REST and GraphQL alike), REST's own hourly limit being REST's alone."""

    def __init__(self, calls):
        self.left, self.stopped, self.shared = calls, None, None

    def can(self, n=1):
        return self.stopped is None and self.left >= n

    def spend(self, n=1):
        self.left -= n

    def read(self, headers):
        remaining = _header_int((headers or {}).get("x-ratelimit-remaining"))
        if self.stopped is None and remaining is not None and remaining <= RATE_FLOOR:
            reset = _epoch(_header_int(headers.get("x-ratelimit-reset")))
            when = f", until {reset:%H:%M} UTC" if reset is not None else ""
            self.stopped = f"GitHub's rate limit is nearly spent ({remaining} requests left{when})"

    def refused(self, exc):
        """A rate-limit answer stops the run: True when `exc` (a SourceError) is one (sources._explain's words: a
        429, or a 403 with a Retry-After or no requests left). It stops GraphQL's asks too (`shared`) when it is a
        secondary limit, which GitHub counts over REST and GraphQL alike: one with a Retry-After, or a 429 that does
        not say REST's requests are spent. A 403 without a Retry-After is REST's own hourly limit (or, with no
        headers known, taken as one): GraphQL asks on."""
        status = getattr(exc, "status", None)
        if status in (403, 429) and "rate limit" in str(exc):
            self.stopped = str(exc)
            limits = getattr(exc, "limits", None) or {}
            spent = _header_int(limits.get("x-ratelimit-remaining")) == 0
            if "retry-after" in limits or (status == 429 and not spent):
                self.shared = self.stopped
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


def scan_repository(full_name, ref=None, *, env=None, http=None, shown=None, scan_all=False):
    """github:full_name at `ref` (the default branch's head when None), fetched and scanned as a project: -> (the
    registry result, the checkout's API calls). `shown` (--show-secrets): filled with each finding's flagged line as
    read, for the terminal alone (core.scan_project). `scan_all`: the repository is scan-all's own (`result`)."""
    ck = sources.checkout(f"github:{full_name}" + (f"@{ref}" if ref else ""), env=env, http=http)
    try:
        return result(full_name, ck, shown, scan_all=scan_all), len(ck.calls)
    finally:
        ck.cleanup()


def result(full_name, ck, shown=None, scan_all=False):
    """The registry's result for a checkout (the shape Store.save_scan and print_scan take). With `scan_all` (a
    repository scan-all queued, not a filter's candidate nor `scan github:`), its own workflow hygiene is listed as
    INFO (SCANALL-HYGIENE, `_hygiene_listed`): the result's `hygieneInfo` counts it by rule, and the verdict's reason
    says so. Below CRITICAL it was never counted (core.HARDENING_RULES, below): the verdict is the same either way."""
    issues, truncated, reason_more = _project_issues(ck, shown)
    hygiene = _hygiene_listed(issues) if scan_all else {}
    counted = [i for i in issues if i["rule"] not in core.HARDENING_RULES or i["sev"] == "CRITICAL"]
    verdict, reason, strong, weak = _repo.decide_verdict(counted, truncated)
    if reason_more:
        reason += "; not read whole: " + "; ".join(reason_more)
    if hygiene:
        reason += "; " + hygiene_said(hygiene)
    sev_counts = {s: 0 for s in core.SEV_ORDER}
    for i in issues:
        sev_counts[i["sev"]] += 1
    return {"ecosystem": ECO, "name": full_name, "version": ck.commit, "artifact": "repository",
            "archiveBytes": ck.bytes, "filesScanned": ck.files, "binaryArtifacts": 0, "profile": PROFILE,
            "sevCounts": sev_counts, "supplyChain": strong + weak, "strongIndicators": strong,
            "weakIndicators": weak, "truncated": truncated, "verdict": verdict, "verdictReason": reason,
            "issues": core.redact_result({"issues": issues})["issues"], "artifacts": [],
            "location": f"https://github.com/{full_name}/tree/{ck.commit}", "hygieneInfo": hygiene,
            "scannedAt": datetime.datetime.now(UTC).isoformat(timespec="seconds")}


def _hygiene_listed(issues):
    """SCANALL-HYGIENE: a scan-all repository's own workflow hygiene (SCAN_ALL_HYGIENE_RULES at MAJOR or MINOR) made
    INFO in `issues`, each message saying so and what a project scan grades it, and the findings put back in their
    severities' order (core.SEV_ORDER; the order is otherwise kept) -> {rule: findings made INFO}. A CRITICAL one
    (the engine grades none of the four so today) would still count."""
    listed = {}
    for i in issues:
        if i["rule"] in SCAN_ALL_HYGIENE_RULES and i["sev"] in ("MAJOR", "MINOR"):
            i["msg"] = str(i["msg"]).rstrip() + HYGIENE_NOTE.format(sev=i["sev"])
            i["sev"] = "INFO"
            listed[i["rule"]] = listed.get(i["rule"], 0) + 1
    if listed:
        issues.sort(key=lambda i: core.SEV_ORDER.get(i["sev"], len(core.SEV_ORDER)))
    return dict(sorted(listed.items()))


def hygiene_said(listed, by_rule=True):
    """What a scan-all report says of the workflow hygiene `_hygiene_listed` made INFO."""
    n = sum(listed.values())
    rules = f" ({', '.join(f'{rule} {k}' for rule, k in sorted(listed.items()))})" if by_rule else ""
    return (f"{n} workflow hygiene finding{'' if n == 1 else 's'} listed as INFO, as the owner's configuration"
            f"{rules}")


def _project_issues(ck, shown=None):
    """The project scan of a checkout and of its twin trees (core.scan_twins: the paths a disk that ignores case held
    as one name with another, each read at its path in the commit): (their findings, the parts not read whole, why). A
    file of the commit that the checkout could not write is a part not read (`sources.not_covered`, as `lazaret scan
    github:…` counts it): it was left out of the verdict before (MAC-TESTS)."""
    gaps = sources.not_covered(ck)
    truncated = len(gaps)
    why = [detail for _kind, detail in gaps[:SHOWN_GAPS]] + ([f"and {len(gaps) - SHOWN_GAPS} more"]
                                                              if len(gaps) > SHOWN_GAPS else [])
    twin_issues, _where, twin_why, _read, _own = core.scan_twins(ck.twins, shown=shown,
                                                                 overlaid=ck.overlaid)    # (MAC-TESTS: sources._Writer)
    truncated += len(twin_why)
    why = twin_why + why
    try:
        res = core.scan_project(ck.root, shown=shown)
    except core.ScanTargetError:
        return twin_issues, truncated, why              # (nothing in it Lazaret reads)
    if res.get("incomplete"):
        truncated += 1
        why.insert(0, res.get("incompleteReason") or "the scan stopped early")
    return core.merge_findings(list(res["issues"]), twin_issues), truncated, why


def _scan(store, budget, cand, env, http, out):
    """Scan a ready candidate and store it: -> its result, or None (a failure, kept in last_error). One of scan-all's
    own (repo._scan_all_row, as `list` tells them) gets scan-all's result (`result`: SCANALL-HYGIENE)."""
    try:
        res, calls = scan_repository(cand["full_name"], env=env, http=http, scan_all=_repo._scan_all_row(cand))
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
                        "since": _scan_all_start(store), "lateScanned": 0, "lateLeft": 0, "lateSkipped": 0}
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
        _bound_queue(store, now, out["queue"], left=False)


def _bound_queue(store, now, queue, left=True):
    """Scan-all's queue kept at the QUEUE_MAX newest pushes, its late finds apart at the QUEUE_MAX found last, and
    its pending repositories PENDING_HOURS, the rest skipped and counted (lateSkipped: the late finds of them);
    with `left`, what the queue holds then."""
    late = store.prune_github_candidates("queued", keep=QUEUE_MAX, late=True)
    queue["skipped"] += store.prune_github_candidates("queued", keep=QUEUE_MAX, late=False) + late
    queue["lateSkipped"] += late
    queue["skipped"] += store.prune_github_candidates(
        "pending", before=_iso(now - datetime.timedelta(hours=PENDING_HOURS)))
    if left:
        _queue_left(store, queue)


def _queue_left(store, queue):
    """What scan-all's queue holds: in all, and of late finds."""
    queue["lateLeft"] = len(store.github_candidates(states=("queued",), late=True, limit=QUEUE_MAX + 1))
    queue["left"] = queue["lateLeft"] + len(store.github_candidates(states=("queued",), late=False,
                                                                    limit=QUEUE_MAX + 1))


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


# ---------------------------------------------------------------- GraphQL (--github-scan-all: which got code)
def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _time(text):
    """GraphQL's DateTime (ISO 8601) -> that time (aware, UTC), or None for anything else: not a time, or one that
    cannot be held in UTC ("9999-12-31T23:59:59-23:59")."""
    if not isinstance(text, str) or len(text) > 40:
        return None
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (t if t.tzinfo is not None else t.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _rate(doc):
    """GraphQL's rateLimit -> {remaining, cost, reset (ISO text or None)}, or None when it is not one."""
    if not isinstance(doc, dict) or not _int(doc.get("remaining")) or doc["remaining"] < 0:
        return None
    reset = _time(doc.get("resetAt"))
    return {"remaining": doc["remaining"], "cost": doc.get("cost") if _int(doc.get("cost")) else None,
            "reset": _iso(reset) if reset else None}


def _rate_limited(errors):
    """Why an answer's errors say the call was rate limited (LIMITED, or SECONDARY for a secondary limit), or None:
    an error of type RATE_LIMITED (or its extensions' code or type), or one whose message speaks of a rate limit."""
    for e in errors:
        if not isinstance(e, dict):
            continue
        ext = e.get("extensions") if isinstance(e.get("extensions"), dict) else {}
        text = e.get("message") if isinstance(e.get("message"), str) else ""
        if "RATE_LIMITED" in (e.get("type"), ext.get("code"), ext.get("type")) or _RATE_LIMIT_RE.search(text):
            return f"{SECONDARY if _SECONDARY_RE.search(text) else LIMITED} ({text[:200] or 'RATE_LIMITED'})"
    return None


class _CallError(str):
    """An unanswered verdict's reason that is the whole call's (an error of the whole query, an answer not as asked, a
    failure of the call), not the row's: such a row is kept as it was, never backed off."""


def read_nodes(doc, rows):
    """GraphQL's answer (parsed JSON) for `rows`, in the order their node IDs were asked -> (a verdict for each row:
    ("code", {"name", "pushed_at", "size"}), ("empty", None), ("fork", None), ("gone", why) or ("unanswered", why);
    the rate limit (`_rate`) or None; why GitHub's GraphQL API says the call was rate limited (`_rate_limited`), or
    None). Fail closed: an error that names no node, or an answer without the list asked for, leaves every row
    unanswered; an error that names a node leaves that one unanswered, but a null node whose errors are all
    NOT_FOUND is gone; a null node no error names is unanswered."""
    n = len(rows)

    def every(why):
        return [("unanswered", _CallError(why))] * n
    if not isinstance(doc, dict):
        return every("the answer is not a JSON object"), None, None
    data = doc.get("data") if isinstance(doc.get("data"), dict) else None
    rate = _rate(data.get("rateLimit")) if data else None
    errors = doc.get("errors")
    errors = [] if errors is None else errors
    if not isinstance(errors, list):
        return every("the answer's errors are not a list"), rate, None
    limited = _rate_limited(errors)
    if limited:
        return every("rate limited"), rate, limited
    named = {}
    for e in errors:
        path = e.get("path") if isinstance(e, dict) else None
        if not (isinstance(path, list) and len(path) >= 2 and path[0] == "nodes" and _int(path[1])
                and 0 <= path[1] < n):
            kind = e.get("type") if isinstance(e, dict) and isinstance(e.get("type"), str) else "an error"
            return every(f"an error of the whole query ({kind[:100]})"), rate, None
        named.setdefault(path[1], []).append(e.get("type") if isinstance(e.get("type"), str) else "?")
    nodes = data.get("nodes") if data else None
    if not isinstance(nodes, list) or len(nodes) != n:
        return every("a partial answer: not the list of the nodes asked about"), rate, None
    return [_node(nodes[i], rows[i], named.get(i)) for i in range(n)], rate, None


def _node(node, row, errors):
    """One node of GraphQL's answer, for the listed repository `row` (read_nodes): every field asked for there and
    of its type, or unanswered."""
    if errors:
        if node is None and all(kind == "NOT_FOUND" for kind in errors):
            return "gone", "not found"
        return "unanswered", "GitHub's error for it: " + ", ".join(sorted(set(errors)))[:200]
    if node is None:
        return "unanswered", "null, and no error names it"
    if not isinstance(node, dict):
        return "unanswered", "not an object"
    if any(field not in node for field in NODE_FIELDS):
        return "unanswered", "a field asked for is missing"
    name, flags = node["nameWithOwner"], [node[k] for k in ("isEmpty", "isFork", "isPrivate")]
    created, pushed, size = _time(node["createdAt"]), node["pushedAt"], node["diskUsage"]
    when = None if pushed is None else _time(pushed)
    if not (_int(node["databaseId"]) and node["databaseId"] == row["repo_id"] and _repository(name)
            and all(isinstance(f, bool) for f in flags) and created is not None
            and (pushed is None or when is not None) and (size is None or (_int(size) and size >= 0))):
        return "unanswered", "its fields are not the ones asked for (of another type, or another repository's)"
    empty, fork, private = flags
    if private:
        return "gone", "made private"
    if empty:
        return "empty", None
    if fork and not (when is not None and when > created):
        return "fork", None                     # (no push of its own: its code is its parent's)
    return "code", {"name": name, "pushed_at": _iso(when) if when else None, "created_at": _iso(created),
                    "size": size}


def _next_ask(listed, now):
    """When a listed repository with no code yet is asked again: the first of CHECK_HOURS after it was listed still to
    come, or None when none is (its last scheduled ask has answered)."""
    t0 = datetime.datetime.fromisoformat(listed)
    for hours in CHECK_HOURS:
        t = t0 + datetime.timedelta(hours=hours)
        if t > now:
            return _iso(t)
    return None


def _backoff(fails, now):
    """When a repository GitHub could not answer about `fails` times in a row is asked again: 1, 2, 4 … hours on, at
    most GRAPHQL_BACKOFF_MAX_HOURS (never dropped for it)."""
    return _iso(now + datetime.timedelta(hours=min(2 ** min(max(fails, 1) - 1, 16), GRAPHQL_BACKOFF_MAX_HOURS)))


def _code_time(detail, now):
    """When a repository's code arrived, which its place in the queue follows (newest first, as GH Archive's pushes
    by their time): GraphQL's pushedAt held to [createdAt, now]; the finding run's time when it is not known."""
    pushed, created = _time(detail.get("pushed_at")), _time(detail.get("created_at"))
    if pushed is None:
        return _iso(now)
    if created is not None and pushed < created:
        pushed = created
    return _iso(min(pushed, now))


def _key(row):
    return row["listed_at"], row["repo_id"]


def _spawn(work, name):
    """A thread of its own for one GraphQL call's HTTP (GH-SCAN-GQL-SPEED), started -> the thread (a seam for the
    tests, which choose when calls are answered)."""
    thread = threading.Thread(target=work, name=name, daemon=True)
    thread.start()
    return thread


def _outcome(work):
    """What `work` gave: (its value, None), or (None, what it raised), to be raised on the run's thread."""
    try:
        return work(), None
    except BaseException as exc:                                        # noqa: BLE001
        return None, exc


class _Calls:
    """The GraphQL calls in flight (GH-SCAN-GQL-SPEED): each call's HTTP on a thread of its own, `width` at most at once
    (the caller's count), and what it got handed back to the run's thread in the order the calls end (`next`). Only the
    HTTP runs on those threads: an answer is read and stored on the run's thread. With a width of 1 a call is made on
    the run's thread itself, with no thread at all, as before."""

    def __init__(self, width):
        self.width = width
        self.done = queue.SimpleQueue()         # (ticket, outcome), as the calls end
        self.threads = {}                       # ticket -> its thread, until its outcome is taken
        self.made = deque()                     # (a width of 1: the call just made on the run's thread)

    def start(self, ticket, work):
        if self.width == 1:
            self.made.append((ticket, _outcome(work)))
            return

        def call():
            self.done.put((ticket, _outcome(work)))
        self.threads[ticket] = _spawn(call, f"lazaret-graphql-{ticket}")

    def next(self, block):
        """The next call that ended -> (its ticket, its outcome); None when none has (and `block` is false) or none is
        in flight. Its thread has ended once this returns."""
        if self.made:
            return self.made.popleft()
        if not self.threads:
            return None
        try:
            ticket, outcome = self.done.get(block=block)
        except queue.Empty:
            return None
        self.threads.pop(ticket).join()
        return ticket, outcome

    def close(self):
        """Every thread joined (a call ends within its own time, GRAPHQL_SECONDS), what they got dropped: after an
        error of the run, whose rows those calls leave as they were."""
        threads, self.threads = list(self.threads.values()), {}
        for thread in threads:
            thread.join()


class _Asker:
    """GH-SCAN-GQL: which of scan-all's listed repositories got code, asked of GitHub's GraphQL API (the module's
    notes). `keep` stores a listing page's new repositories, `first` asks about them (a call for the page), `due`
    asks about those whose next ask is due (GRAPHQL_DUE_SHARE of the calls and of the time for the oldest listed,
    oldest first, then newest first), GRAPHQL_BATCH a call, a batch of which nothing could be read isolated
    (`_isolate`), and `finish` keeps the set bounded. What it did is out["graphql"]: listed (kept), asked (in
    `calls` calls; `fresh` just listed, `again`), code (queued; late, of them late finds: LATE_HOURS), empty, forks
    (with no push of their own), gone, unanswered, isolated (GitHub could not answer about them: backed off),
    campaigns and excluded (by the name GraphQL gave), expired (no code at the last scheduled ask), over (evicted
    past LISTED_MAX), aged (still waiting, listed over PENDING_HOURS ago), noNode (listing items without a node ID,
    sent to the REST content checks), points and reset (GitHub's), failed (transport and HTTP failures), unreadable
    (calls of which nothing could be read) and error, timeouts (calls GitHub ended at its own time limit, asked again
    in halves), seconds (the GraphQL part's wall clock while calls were in flight or it waited for GitHub's CPU-time
    limit) of runSeconds (--graphql-seconds), paced and pacedSeconds (those waits, and their time), concurrency (the
    calls it may make at once) and atOnce (the most it made), stopped (why it asked no more), waiting (due, not
    asked) and kept (all waiting).

    Calls at once (GH-SCAN-GQL-SPEED): a batch's call is started (`ask`) and its HTTP made on a thread of its own
    (`_Calls`), up to `concurrency` at once, while the run goes on (the next batch, the listing's next page); every
    answer is read and stored on the run's thread, in the order the calls end (`_ended`), and its batch's follow-up
    (`_after`: isolation, a control call, the streak) after it, in that order. One call at a time until an answer was
    read with GitHub's points left in it, and again after any other answer (a failure, a limit, an error of the whole
    query, GitHub's time limit) until the calls then in flight have ended and a call started since has been read; a
    follow-up that makes calls of its own lets every call in flight end first and makes them one at a time, as at a
    concurrency of 1, so isolation and control calls keep their order and meaning. No call starts once the run's calls
    (--max-graphql-calls, counted as calls start) or seconds are spent or the part stopped, nor while GitHub's points
    left, less one for each call in flight, would be at GRAPHQL_RATE_FLOOR, nor, with several at once, while
    GitHub's CPU-time limit would be passed (`_paced`): the calls' response seconds in the last minute, with an
    estimate for those in flight and for the call, at most GRAPHQL_CPU_PER_MINUTE (`paced` counts the waits,
    `pacedSeconds` their time, which counts towards the GraphQL seconds, `runSeconds`). A failure of a call started
    before the last one counted is not counted again (they were in flight together): GRAPHQL_FAILURES still means that
    many failures, each of a call started after the one before was seen."""

    def __init__(self, store, client, budget, filters, now, out, calls, say=lambda text: None, concurrency=1,
                 seconds=None):
        self.store, self.client, self.budget, self.filters = store, client, budget, filters
        self.now, self.out = now, out
        self.calls, self.left, self.say = calls, calls, say
        self.since = out["queue"]["since"]
        self.streak, self.answered, self.suspect = 0, set(), []     # (suspect: (rows, level) isolation left)
        self.seen, self.known = set(), []               # (the rows asked about this run; those GitHub answered)
        self.width = max(1, int(concurrency))
        self.pool = _Calls(self.width)
        # (the calls started and not read yet, by ticket: their rows, batch kind or None, probe, what, strikes when
        # started; the batches read whose follow-up is still to come; a follow-up's own calls' outcomes)
        self.flight, self.later, self.results = {}, deque(), {}
        self.strikes, self.closed_at, self.open, self.broken = 0, 0, False, False
        self.busy, self.began = 0.0, None               # (the GraphQL part's wall clock: spent, and since when now)
        self.run_seconds = GRAPHQL_RUN_SECONDS if seconds is None else seconds
        # (GitHub's CPU-time limit: (end, response seconds) of the calls that ended in the window, oldest first; the
        # recent calls' response seconds, for the median estimate)
        self.ended, self.recent = [], deque(maxlen=GRAPHQL_CPU_RECENT)
        self.info = out["graphql"] = {
            "listed": 0, "asked": 0, "fresh": 0, "again": 0, "calls": 0, "code": 0, "empty": 0, "forks": 0, "gone": 0,
            "unanswered": 0, "isolated": 0, "late": 0, "campaigns": 0, "excluded": 0, "expired": 0, "aged": 0,
            "over": 0, "noNode": 0, "points": None, "reset": None, "failed": 0, "unreadable": 0, "timeouts": 0,
            "error": None, "seconds": 0.0, "concurrency": self.width, "atOnce": 0, "paced": 0, "pacedSeconds": 0.0,
            "runSeconds": self.run_seconds, "stopped": None, "waiting": 0, "kept": 0}

    def keep(self, items):
        """A listing page's repositories scan-all asks about, stored unasked (before the cursor moves past them) ->
        their rows; one kept already (a page listed again) is left as it is. One without a usable node ID cannot be
        asked: it becomes a candidate of the REST content checks (ALL_NO_NODE), counted and said."""
        listed_at = _iso(self.now)
        known = self.store.github_listed_known(i["id"] for i in items)
        rows = []
        for item in items:
            if item["id"] in known or self.since is None or item["id"] <= self.since:
                continue
            desc = item.get("description") if isinstance(item.get("description"), str) else None
            nid = item.get("node_id")
            if not isinstance(nid, str) or not _NODE_ID_RE.fullmatch(nid):
                self.store.add_github_candidate(item["id"], item["full_name"], desc, item.get("fork"), [ALL_NO_NODE],
                                                listed_at, "waiting", _due(listed_at, 0))
                self.info["noNode"] += 1
                continue
            rows.append({"repo_id": item["id"], "node_id": nid, "full_name": item["full_name"],
                         "description": desc[:MAX_TEXT] if desc else None, "fork": bool(item.get("fork")),
                         "listed_at": listed_at, "state": "unasked", "next_check": listed_at, "checks": 0, "fails": 0})
        self.store.add_github_listed([(r["repo_id"], r["node_id"], r["full_name"], r["description"], r["fork"],
                                       r["listed_at"], r["state"], r["next_check"]) for r in rows])
        self.info["listed"] += len(rows)
        return rows

    def first(self, rows):
        for k in range(0, len(rows), GRAPHQL_BATCH):
            if not self.ask(rows[k:k + GRAPHQL_BATCH], fresh=True):
                return

    def _due_rows(self, now, **where):
        """A page of the rows due by `now` (github_listed's `before`, `after`, `oldest_first`) -> (the key of its last
        row, or None when there is none; its rows the candidates do not hold). One the candidates hold since (GH
        Archive's push queued it) is theirs: deleted here."""
        rows = self.store.github_listed(due_by=now, limit=10 * GRAPHQL_BATCH, **where)
        if not rows:
            return None, []
        held = self.store.github_candidate_states(r["repo_id"] for r in rows)
        if held:
            self.store.save_github_listed(deletes=held)
        return _key(rows[-1]), [r for r in rows if r["repo_id"] not in held]

    def due(self):
        """The listed repositories whose next ask is due by now (an unasked one at once, one with no code yet at
        CHECK_HOURS, one GitHub could not answer about after its backoff): GRAPHQL_DUE_SHARE of the run's calls and of
        its GraphQL seconds for the oldest listed, oldest first (the nearest their last check, and the first
        LISTED_MAX would evict), then the rest of them newest first with what is left, GRAPHQL_BATCH a call. The share
        is of the calls started and of the GraphQL part's wall clock; calls still in flight when it returns are read as
        they end (`poll`, `finish`)."""
        now = _iso(self.now)
        reserve = max(1, int(self.calls * GRAPHQL_DUE_SHARE)) if self.calls else 0
        seconds = GRAPHQL_DUE_SHARE * self.run_seconds
        start, started, after, boundary = self.info["calls"], self._seconds(), None, None

        def share_left():
            return self.info["calls"] - start < reserve and self._seconds() - started < seconds
        while share_left():
            after, rows = self._due_rows(now, after=after, oldest_first=True)
            if after is None:
                return                                  # (every due row was asked oldest first)
            for batch in self._batches(rows):
                if not self._room():                    # (room first: the share is judged on the clock as it is then)
                    return
                if not share_left():
                    break
                if not self.ask(batch):
                    return
                boundary = _key(batch[-1])
            else:
                boundary = after
        before = None
        while True:
            before, rows = self._due_rows(now, before=before, after=boundary)
            if before is None:
                return
            for batch in self._batches(rows):
                if not self.ask(batch):
                    return

    def _batches(self, rows):
        """A page of due rows in batches of GRAPHQL_BATCH, read as they are asked: one asked about since the page
        was read (by a control call) is left out."""
        batch = []
        for row in rows:
            if row["repo_id"] not in self.seen:
                batch.append(row)
            if len(batch) == GRAPHQL_BATCH:
                yield batch
                batch = []
        if batch:
            yield batch

    def ask(self, rows, fresh=False):
        """One batch (at most GRAPHQL_BATCH rows): its call started when the run may make one (`_room`) -> whether the
        GraphQL part goes on. With calls at once (the module's notes) the run goes on while it is in flight; one at a
        time, its answer and its follow-up (`_after`) come before this returns."""
        if not self._room():
            return False
        self.seen.update(r["repo_id"] for r in rows)
        self._start(rows, "fresh" if fresh else "again")
        self._collect(wait=None if self.open else "all")
        return self.info["stopped"] is None

    def poll(self):
        """The calls that ended since, read and followed up (`_collect`), without waiting: the listing asks before each
        page, so that a secondary limit one of them met stops it too."""
        self._collect()

    def _after(self, rows, kind, got):
        """A batch's follow-up, once its call was read (`_ended`): when nothing of it could be read, its isolation
        (`_isolate`); and when GitHub ended it at its own time limit (GRAPHQL_TIMEOUTS), its halves asked so too
        (they end sooner), a failure of theirs counted as the batch's own. Groups isolation leaves (two levels of
        halves in a row of which nothing could be read) are isolated on when a control call elsewhere is answered
        (`_control`), and else wait for GitHub to answer another call (`_answering`); GRAPHQL_FAILURES batches in a
        row of which nothing could be read, nor of their halves and quarters, nor their control calls, stop the
        GraphQL part, as GitHub's failure, not their rows': those are left as they were."""
        info = self.info
        info["asked"] += len(rows)
        info[kind] += len(rows)
        read, self.broken = got == "read", False
        if got in ("whole", "timeout"):
            read, left = self._isolate([rows])
            self.suspect += left
        info["unanswered"] += sum(1 for r in rows if r["repo_id"] not in self.answered)
        whole = got == "whole" or (got == "timeout" and not self.broken)    # (a half that failed: that failure)
        if read:
            self._answering()
        elif whole and self._control():
            self._answering()                           # (GitHub answers: its rows' fault, isolated on)
        elif whole:
            self.streak += 1
            if self.streak >= GRAPHQL_FAILURES and info["stopped"] is None:
                # (GitHub's failure, not the rows': none backed off, the groups waiting left as they were)
                info["stopped"] = (f"{self.streak} batches in a row of which nothing could be read, not even in "
                                   f"halves and quarters, nor a call elsewhere (the last: {info['error']})")

    def _control(self):
        """A batch of which nothing could be read, nor of its halves and quarters: GitHub failing, or rows it cannot
        answer about in every quarter? A call elsewhere, about repositories that exist, tells: about one GitHub
        answered about (`_known`; its answer only read), or else about the newest due rows not asked yet this run
        (an ask like another, without isolation). With neither, it cannot tell: the batch counts as GitHub's
        failure (a call that names no repository proves nothing: GitHub can answer it while failing every query
        about repositories). -> whether GitHub answered it."""
        known = self._known()
        if known is not None:
            return self._ask([known], probe=True) == "read"
        rows = self._unasked_due()
        if not rows:
            return False
        self.seen.update(r["repo_id"] for r in rows)
        got = self._ask(rows)
        if got is not None:
            self.info["asked"] += len(rows)
            self.info["again"] += len(rows)
            self.info["unanswered"] += sum(1 for r in rows if r["repo_id"] not in self.answered)
        return got == "read"

    def _known(self):
        """A repository GitHub answered about (repo_id and node_id): of this run's answers the last, or else one an
        earlier run's answer left waiting as empty or a fork (github_listed's newest such, looked for in
        GRAPHQL_CONTROL_PAGES pages), or None."""
        before = None
        for _ in range(0 if self.known else GRAPHQL_CONTROL_PAGES):
            rows = self.store.github_listed(before=before, limit=10 * GRAPHQL_BATCH)
            row = next((r for r in rows if r["state"] in ("empty", "fork")), None)
            if row is not None:
                self.known.append({"repo_id": row["repo_id"], "node_id": row["node_id"]})
                break
            if len(rows) < 10 * GRAPHQL_BATCH:
                break
            before = _key(rows[-1])
        return self.known[-1] if self.known else None

    def _unasked_due(self):
        """At most GRAPHQL_BATCH of the newest due rows not asked yet this run (a few pages looked at)."""
        now, before, rows = _iso(self.now), None, []
        for _ in range(GRAPHQL_CONTROL_PAGES):
            before, page = self._due_rows(now, before=before)
            if before is None:
                break
            rows += [r for r in page if r["repo_id"] not in self.seen]
            if len(rows) >= GRAPHQL_BATCH:
                break
        return rows[:GRAPHQL_BATCH]

    def _answering(self):
        """GitHub answered a call: the streak of batches of which nothing could be read ends, and the groups
        isolation left waiting (`_isolate`) are isolated on from where they were, GitHub's answers to others telling
        that they hold rows it cannot answer about; any of them it answers now no longer counts as unanswered."""
        self.streak = 0
        waiting, self.suspect = self.suspect, []
        ids = {row["repo_id"] for group, _depth in waiting for row in group}
        for group, depth in waiting:
            _read, left = self._isolate([group], depth, up=True)
            self.suspect += left
        self.info["unanswered"] -= len(ids & self.answered)

    def _ask(self, rows, probe=False):
        """One call for `rows` made now, its answer awaited (a follow-up's: isolation, a control call; nothing else is
        in flight then), when the run may make it -> None (it may not: stopped, its calls or its seconds spent),
        "read" (something of the answer could be read), "whole" (nothing: an error of the whole query, or an answer
        not as asked), "failed" (a transport or HTTP failure, or a rate limit). A `probe` (a control call about a
        repository GitHub answered about) has its answer read, not stored."""
        held = False
        while True:
            if not self._may():
                return None
            if self._paced(held):
                break
            held = True
        ticket = self._start(rows, None, probe)
        while ticket in self.flight:
            self._end_next(block=True)
        return self.results.pop(ticket)

    def _may(self):
        """May the run make another call: not stopped, no limit GraphQL shares met (Budget.shared), its calls
        (--max-graphql-calls, counted as they start) and its seconds (--graphql-seconds, the wall clock) not spent?"""
        info = self.info
        if info["stopped"] is not None or self.budget.shared is not None:
            return False
        if self.left <= 0:
            info["stopped"] = f"the run's budget of {self.calls} GraphQL calls (--max-graphql-calls) was spent"
            return False
        if self._seconds() >= self.run_seconds:
            info["stopped"] = f"the GraphQL part's {self.run_seconds:g} seconds for a run were spent"
            return False
        return True

    def _room(self):
        """May a batch's call start now? The calls that ended are read first (`_collect`); not when the run may make no
        more (`_may`); and it waits for calls in flight to end while it has as many as it may (`concurrency`; one, a
        call answered first, until one started since was read with GitHub's points in it: `_ended`) or while GitHub's
        points left (the latest answer's), less one for each call in flight, would be at GRAPHQL_RATE_FLOOR; and then
        for GitHub's CPU-time limit (`_paced`)."""
        held = False
        while True:
            self._collect()
            if not self._may():
                return False
            n, points = len(self.flight), self.info["points"]
            if n and not (self.open and n < self.width and (points is None or points - n > GRAPHQL_RATE_FLOOR)):
                self._collect(wait="one")
            elif self._paced(held):
                return True
            else:
                held = True

    def _paced(self, waiting=False):
        """GitHub's CPU-time limit (GRAPHQL_CPU_PER_MINUTE), with several calls at once: may a call start now
        (`_cpu_wait`)? -> True (always one at a time: its calls cannot overlap); else, having waited (for a call in
        flight to end; or, none in flight, until enough of the window's calls leave it, at most the GraphQL seconds
        left, which the wait counts towards), False. `paced` counts the waits (`waiting`: this one goes on from the one
        before), `pacedSeconds` their time."""
        if self.width == 1:
            return True
        wait = self._cpu_wait()
        if wait <= 0:
            return True
        self.info["paced"] += not waiting
        started = _clock()
        if self.flight:
            self._end_next(block=True)
        else:
            _sleep(min(wait, max(0.0, self.run_seconds - self._seconds())))
            self.busy += _clock() - started             # (the GraphQL part's seconds run while it waits)
            self.info["seconds"] = self.busy
        self.info["pacedSeconds"] += _clock() - started
        return False

    def _cpu_wait(self):
        """Seconds until GitHub's CPU-time limit lets a call start (0: now). Its estimate: the response seconds of the
        calls that ended in the last GRAPHQL_CPU_WINDOW seconds, and for each call in flight and the one to start the
        median of the recent calls' or its own time so far, the more; at most GRAPHQL_CPU_PER_MINUTE, unless no call
        ended in the window and none is in flight. The wait is until enough of those calls leave the window."""
        now = _clock()
        while self.ended and self.ended[0][0] <= now - GRAPHQL_CPU_WINDOW:
            self.ended.pop(0)
        median = statistics.median(self.recent) if self.recent else 0.0
        over = (sum(seconds for _end, seconds in self.ended) + median - GRAPHQL_CPU_PER_MINUTE
                + sum(max(now - flight[5], median) for flight in self.flight.values()))
        if over <= 0 or not (self.ended or self.flight):
            return 0.0
        for end, seconds in self.ended:                 # (the oldest leave the window first)
            over -= seconds
            if over <= 0:
                return end + GRAPHQL_CPU_WINDOW - now
        return self.ended[-1][0] + GRAPHQL_CPU_WINDOW - now if self.ended else GRAPHQL_CPU_WINDOW

    def _collect(self, wait=None):
        """The calls that ended, each read and stored as it ended (`_ended`): with `wait` "one" at least one, "all"
        every call in flight. Then the follow-ups of their batches (`_after`), in the order they ended: one that makes
        calls of its own (isolation, a control call, groups isolated on) first lets every call in flight end, and
        makes them one at a time."""
        while self.flight and self._end_next(block=wait is not None):
            if wait == "one":
                wait = None
        while self.later:
            rows, kind, got = self.later[0]
            if self.flight and (got in ("whole", "timeout") or (got == "read" and self.suspect)):
                while self.flight:
                    self._end_next(block=True)
                continue
            self.later.popleft()
            self._after(rows, kind, got)

    def _end_next(self, block):
        """The next call that ended, read (`_ended`) -> False when none has (and `block` is false)."""
        ended = self.pool.next(block)
        if ended is None:
            if block:
                raise RuntimeError("a GraphQL call in flight was lost")     # (each call hands back what it got)
            return False
        self._ended(*ended)
        return True

    def _seconds(self):
        """The GraphQL part's wall clock while calls were in flight: what was spent, and the time since the calls in
        flight began."""
        return self.busy + (_clock() - self.began if self.began is not None else 0.0)

    def close(self):
        """Every call's thread ended (after an error of the run: what calls still in flight get is not read; their
        rows stay as they were)."""
        self.pool.close()

    def _isolate(self, groups, depth=1, up=False):
        """Groups of rows asked together of which nothing could be read (an error of the whole query, or an answer
        not as asked; or a call GitHub ended at its own time limit, whose halves end sooner): each one's halves asked,
        one at a time, level by level, and the halves of those that fail the same way, down
        to single rows (GRAPHQL_SPLIT_DEPTH levels in all, within the run's calls and seconds), so that the rows
        GitHub cannot answer about are found and backed off, the others answered. A single row that fails so,
        while GitHub answers others (`up`: it just did), is one. Two levels in a row of which nothing could be read
        are GitHub's failure, or more such rows than groups: those groups wait, with their level, for GitHub to
        answer another call (`_answering`). -> (whether anything could be read; the groups that wait)."""
        level, read, dry, alone = list(groups), False, 0, []
        while level and depth <= GRAPHQL_SPLIT_DEPTH:
            failing, read_here = [], False
            for group in level:
                if len(group) == 1:
                    alone.append(group[0])
                    continue
                mid = (len(group) + 1) // 2
                for half in (group[:mid], group[mid:]):
                    got = self._ask(half)
                    if got is None or got == "failed":      # (stopped, or a failure of the call: the rest as it was)
                        self.broken = True
                        self._lone(alone, read or up)
                        return read, []
                    if got == "read":
                        read_here = True
                    else:
                        failing.append(half)
            read, dry = read or read_here, 0 if read_here else dry + 1
            level, depth = failing, depth + 1
            if dry >= 2 and level:
                self._lone(alone, read or up)
                return read, [(group, depth) for group in level]
        alone += [row for group in level for row in group]       # (the depth spent: what is left counts as alone)
        if not (read or up):
            return read, [([row], depth) for row in alone]      # (nothing read at all: told apart later)
        self._lone(alone, True)
        return read, []

    def _lone(self, rows, sure):
        """Single rows that failed the whole query alone: backed off when GitHub answered others (`sure`), else
        left to wait for its next answer to another call, as the groups are."""
        if rows and sure:
            self._backoff(rows, "GitHub could not answer about it: the whole query failed with it, alone")
        elif rows:
            self.suspect += [([row], GRAPHQL_SPLIT_DEPTH) for row in rows]

    def _backoff(self, rows, why):
        """Rows GitHub could not answer about, asked again later (`_backoff`'s wait, growing with their failures in
        a row; never dropped for it, still subject to LISTED_MAX alone), so that the oldest-first share moves on."""
        self.info["isolated"] += len(rows)
        self.store.save_github_listed([(r["repo_id"], r["state"], _backoff(r["fails"] + 1, self.now), r["checks"],
                                        why, r["fails"] + 1) for r in rows])

    def _start(self, rows, kind=None, probe=False):
        """A call for `rows` started (`_Calls`: on a thread of its own at a concurrency over 1, the run's own at 1),
        charged to the run's calls as it starts -> its ticket (its number in the run). `kind` "fresh" or "again": a
        batch's own call, whose follow-up (`_after`) comes once it was read; None: a follow-up's (`_ask`)."""
        info = self.info
        self.left -= 1
        info["calls"] += 1
        ticket = info["calls"]
        if info["calls"] % GRAPHQL_PROGRESS_EVERY == 0:
            self.say(f"GraphQL: {info['calls']} calls, {info['asked']:,} new repositories asked about…")
        what = (f"asking GitHub's GraphQL API about {len(rows)} new repositories" if not probe else
                "asking GitHub's GraphQL API about a repository it answered about (a control call)")
        body = json.dumps({"query": GRAPHQL_QUERY, "variables": {"ids": [r["node_id"] for r in rows]}},
                          separators=(",", ":")).encode("utf-8")
        if not self.flight:
            self.began = _clock()                       # (the wall clock runs while calls are in flight)
        try:
            self.pool.start(ticket, lambda: self._post(what, body))
        except BaseException:
            if not self.flight:
                self.busy, self.began = self._seconds(), None
            raise
        self.flight[ticket] = (rows, kind, probe, what, self.strikes, _clock())
        info["atOnce"] = max(info["atOnce"], len(self.flight))
        return ticket

    def _post(self, what, body):
        """One call's HTTP, and nothing else (on its own thread at a concurrency over 1: sources.Client.post, whose
        transports are safe for it: urllib's makes a connection for each call, the native one's shared client hands
        each call a connection of its own, or a stream of its own on HTTP/2) -> (the answer's body or None, the
        SourceError or None, the answer's headers, when the call began and ended: its response time, which GitHub's
        CPU-time limit is estimated by)."""
        headers, began = {}, _clock()
        try:
            raw = self.client.post(GRAPHQL, what, body, max_bytes=GRAPHQL_BYTES, reply_headers=headers,
                                   seconds=GRAPHQL_SECONDS)
            return raw, None, headers, (began, _clock())
        except sources.SourceError as exc:
            return None, exc, headers, (began, _clock())

    def _ended(self, ticket, outcome):
        """A call that ended, on the run's thread: its answer read and stored (`_answer`); the wall clock stopped when
        it was the last in flight; one at a time after an answer that is not "read", until a call started since is
        read with GitHub's points in it; a batch's follow-up queued, a follow-up's own call's outcome kept; its response
        time kept for GitHub's CPU-time limit (`_cpu_wait`)."""
        rows, kind, probe, what, strikes, _started = self.flight.pop(ticket)
        value = outcome[0]
        if value is not None:
            began, end = value[3]
            bisect.insort(self.ended, (end, end - began))
            self.recent.append(end - began)
        try:
            got = self._answer(rows, kind, probe, what, strikes, outcome)
        finally:
            if not self.flight and self.began is not None:
                self.busy, self.began = self._seconds(), None
                self.info["seconds"] = self.busy
        if got != "read":
            self.open, self.closed_at = False, self.info["calls"]
        elif ticket > self.closed_at and self.info["points"] is not None:
            self.open = True
        if kind is None:
            self.results[ticket] = got
        else:
            self.later.append((rows, kind, got))

    def _answer(self, rows, kind, probe, what, strikes, outcome):
        """What a call got, read and stored (on the run's thread) -> "read", "whole", "failed" (as `_ask` says), or
        "timeout": a batch's own call of more than one row that GitHub ended at its own time limit (GRAPHQL_TIMEOUTS),
        its rows kept as they were for its halves (`_after`), not a failure of the call. A failure is counted
        towards GRAPHQL_FAILURES unless one counted since the call started (`strikes`) was in flight with it."""
        value, error = outcome
        if error is not None:
            raise error                                 # (not GitHub's answer: an error of the run, as before)
        raw, exc, headers, _times = value
        info = self.info
        if exc is None:
            try:
                doc = sources._json(raw, what)
            except sources.SourceError as bad:
                exc = bad
        if exc is not None:
            if (kind is not None and getattr(exc, "status", None) in GRAPHQL_TIMEOUTS and len(rows) > 1
                    and GRAPHQL_SPLIT_DEPTH >= 1):
                self._apply(rows, [("unanswered", _CallError(str(exc)[:500]))] * len(rows))
                info["timeouts"] += 1
                return "timeout"
            self._failed([] if probe else rows, exc, headers, counts=strikes == self.strikes)
            return "failed"
        verdicts, rate, limited = read_nodes(doc, rows)
        if not probe:
            self._apply(rows, verdicts)
        self._points(rate, headers)
        secondary = "retry-after" in headers or (limited or "").startswith(SECONDARY)
        if limited or secondary:
            info["stopped"] = limited or f"{SECONDARY} (Retry-After: {str(headers['retry-after'])[:20]})"
            if secondary:
                self._stop_run(info["stopped"])         # (a secondary limit, answered 200)
            return "failed"
        if verdicts and isinstance(verdicts[0][1], _CallError):
            info["unreadable"] += 1
            info["error"] = verdicts[0][1]
            return "whole"
        return "read"

    def _stop_run(self, why):
        """A secondary rate limit, which GitHub counts over the token's REST and GraphQL calls alike, or a refusal:
        the run stops as on REST's rate limit, its cursor, candidates and waiting rows kept."""
        if self.budget.stopped is None:
            self.budget.stopped = why                   # (GraphQL's own part stopped already: info["stopped"])

    def _failure(self, why, counts=True):
        """A failure of the call: counted (`failed`), and towards GRAPHQL_FAILURES when `counts` (the call started
        after the last failure counted: calls in flight together fail as one)."""
        info = self.info
        info["failed"] += 1
        info["error"] = why
        self.strikes += counts
        if self.strikes >= GRAPHQL_FAILURES and info["stopped"] is None:
            info["stopped"] = f"{info['failed']} GraphQL calls failed (the last: {why})"

    def _failed(self, rows, exc, headers, counts=True):
        """A call GitHub answered with an error, or that failed: its rows stay to be asked, as they were; a refusal
        stops the GraphQL part (and the run, unless it is GraphQL's own hourly limit); GRAPHQL_FAILURES failures do
        too (`_failure`)."""
        info, why = self.info, _CallError(str(exc)[:500])
        self._apply(rows, [("unanswered", why)] * len(rows))
        status = getattr(exc, "status", None)
        if status in (403, 429):
            info["stopped"] = f"GitHub's GraphQL API refused the call: {why}"
            own = status == 403 and _header_int(headers.get("x-ratelimit-remaining")) == 0 \
                and "retry-after" not in headers
            if not own:
                self._stop_run(f"GitHub's GraphQL API refused a call: {why}")
            return
        self._failure(why, counts)

    def _points(self, rate, headers):
        """GitHub's GraphQL points left (the answer's rateLimit and its X-RateLimit-Remaining, the lower): at
        GRAPHQL_RATE_FLOOR the GraphQL part stops. A header not understood is unknown."""
        info, left = self.info, []
        if rate is not None:
            left.append(rate["remaining"])
            info["reset"] = rate["reset"] or info["reset"]
        remaining = _header_int((headers or {}).get("x-ratelimit-remaining"))
        if remaining is not None:
            left.append(remaining)
        reset = _epoch(_header_int((headers or {}).get("x-ratelimit-reset")))
        if info["reset"] is None and reset is not None:
            info["reset"] = _iso(reset)
        if not left:
            return
        info["points"] = min(left)
        if info["points"] <= GRAPHQL_RATE_FLOOR and info["stopped"] is None:
            until = f", until {info['reset'][11:16]} UTC" if info["reset"] else ""
            info["stopped"] = f"GitHub's GraphQL rate limit is nearly spent ({info['points']} points left{until})"

    def _apply(self, rows, verdicts):
        """What the answer said of each row, stored: code queued as of when it arrived (`_code_time`; a row moved to
        the candidates, never lost on the way), no code yet asked again (dropped when its last scheduled ask said
        so), gone dropped; one GitHub could not answer about (its own error, a field of its) backed off; the rest
        (the whole call's failure) kept as they were for the next ask."""
        info, moved, updates, deletes = self.info, [], [], []
        for row, (verdict, detail) in zip(rows, verdicts):
            rid, desc, fork = row["repo_id"], row["description"], bool(row["fork"])
            if verdict != "unanswered":
                self.answered.add(rid)
            if verdict in ("code", "empty", "fork"):
                self.known = (self.known + [{"repo_id": rid, "node_id": row["node_id"]}])[-GRAPHQL_CONTROL_KNOWN:]
            if verdict == "code":
                deletes.append(rid)
                name, found = detail["name"], _code_time(detail, self.now)
                late = self.now - datetime.datetime.fromisoformat(row["listed_at"]) >= \
                    datetime.timedelta(hours=LATE_HOURS)
                judged, marker = self.filters.judged(name, desc)
                if judged == "campaign":
                    moved.append((rid, name, desc, fork, [marker[0]], found, "reported", None))
                    self.out["campaigns"].append((name, marker[1], f"https://github.com/{name}"))
                    info["campaigns"] += 1
                elif judged == "excluded":
                    moved.append((rid, name, desc, fork, ["excluded by your patterns"], found, "excluded", None))
                    info["excluded"] += 1
                else:
                    # (queued as of when its code arrived: fresh and late finds compete by push time; a late
                    # find, at an ask LATE_HOURS or more after the listing, has its share of the scans too)
                    moved.append((rid, name, desc, fork, [ALL_GRAPHQL], found, "queued", None,
                                  _iso(self.now) if late else None))
                    info["code"] += 1
                    info["late"] += late
            elif verdict in ("empty", "fork"):
                info["empty" if verdict == "empty" else "forks"] += 1
                nxt = _next_ask(row["listed_at"], self.now)
                if nxt is None:
                    deletes.append(rid)
                    info["expired"] += 1
                else:
                    updates.append((rid, verdict, nxt, row["checks"] + 1, None, 0))
            elif verdict == "gone":
                deletes.append(rid)
                info["gone"] += 1
            elif isinstance(detail, _CallError):
                updates.append((rid, row["state"], row["next_check"], row["checks"], detail, row["fails"]))
            else:
                updates.append((rid, row["state"], _backoff(row["fails"] + 1, self.now), row["checks"], detail,
                                row["fails"] + 1))
        self.store.add_github_candidates(moved)          # (first: a repository moves, it is never lost on the way)
        self.store.save_github_listed(updates, deletes)

    def finish(self):
        """Every call in flight read and followed up, then the set waiting for code kept at the LISTED_MAX newest
        (the rest evicted, counted), and what is left counted: due and not asked, all, and those listed over
        PENDING_HOURS ago still waiting for an answer."""
        info = self.info
        self._collect(wait="all")
        self.pool.close()
        info["seconds"] = self.busy
        info["over"] += self.store.prune_github_listed(keep=LISTED_MAX)
        info["waiting"] = sum(self.store.github_listed_counts(due_by=_iso(self.now)).values())
        info["kept"] = sum(self.store.github_listed_counts().values())
        info["aged"] = sum(self.store.github_listed_counts(
            listed_before=_iso(self.now - datetime.timedelta(hours=PENDING_HOURS))).values())


# ---------------------------------------------------------------- the run
def run(store, *, scan=False, max_calls=DEFAULT_MAX_CALLS, filters=None, env=None, http=None, now=None,
        archive=False, scan_all=False, max_scans=None, archive_http=None, events_url=None, progress=None,
        max_graphql_calls=DEFAULT_MAX_GRAPHQL_CALLS, graphql_concurrency=None, graphql_seconds=None):
    """One `discover --ecosystem github --resume` run. -> a dict: listed, pages, caughtUp, matches (filter kind ->
    count), candidates (full names kept), campaigns ([(full_name, marker, url)]), checked ({state: count}), scans
    (results), errors, stopped (why the run stopped early, or None), cursor (the ID listed up to), first (True on
    the first run, which only finds where to start), archive (what GH Archive's hours gave, or None), queue
    (scan-all's: queued, pending, skipped, left; lateScanned, lateLeft, lateSkipped, of the late finds) and graphql
    (what GitHub's GraphQL API said of scan-all's listed repositories, `_Asker`; or None). `archive` reads GH
    Archive (ghevents; `archive_http` its network seam), `scan_all` makes every new repository that gets code a
    candidate (it asks GraphQL, reads GH Archive and scans; `max_graphql_calls` the GraphQL calls it may make, apart
    from `max_calls`, `graphql_concurrency` how many at once, DEFAULT_GRAPHQL_CONCURRENCY when None, and
    `graphql_seconds` its wall clock, GRAPHQL_RUN_SECONDS when None; GraphQL's POST goes through the `http` seam
    too, with method="POST", from a thread of its own when calls are made at once),
    `max_scans` caps the run's scans (SCAN_ALL_MAX_SCANS with scan_all), `events_url` is where the hourly files come
    from (ghevents.source's form; GH Archive by default), `progress(text)` hears where a long run is, and `gone`
    counts the scans of repositories gone, made private or empty. DiscoveryError without GITHUB_TOKEN, with an events
    URL that is not one, a concurrency not from 1 to GRAPHQL_CONCURRENCY_MAX, or GraphQL seconds not from 1 to
    GRAPHQL_RUN_SECONDS_MAX."""
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
    width = DEFAULT_GRAPHQL_CONCURRENCY if graphql_concurrency is None else graphql_concurrency
    if not (_int(width) and 1 <= width <= GRAPHQL_CONCURRENCY_MAX):
        raise DiscoveryError(f"--graphql-concurrency takes a number of calls at once, 1 to {GRAPHQL_CONCURRENCY_MAX}")
    if graphql_seconds is not None and not (isinstance(graphql_seconds, (int, float)) and not isinstance(
            graphql_seconds, bool) and 1 <= graphql_seconds <= GRAPHQL_RUN_SECONDS_MAX):
        raise DiscoveryError(f"--graphql-seconds takes a number of seconds, 1 to {GRAPHQL_RUN_SECONDS_MAX:g}")
    say = progress or (lambda text: None)
    out = {"listed": 0, "pages": 0, "caughtUp": False, "matches": {}, "candidates": [], "campaigns": [],
           "checked": {}, "scans": [], "errors": [], "stopped": None, "cursor": None, "first": False,
           "archive": None, "queue": None, "gone": 0, "graphql": None}
    asker, failed = None, False
    try:
        _checks(store, client, budget, now, out)
    except sources.SourceError as exc:
        failed = _rest_stopped(out, budget, exc)
    if archive:                                     # (GH Archive's files: none of GitHub's API calls)
        _archive(store, filters, scan_all, now, out, archive_http, events_url, say)
    if scan_all and out["queue"] is not None and out["queue"]["since"] is not None:
        asker = _Asker(store, client, budget, filters, now, out, max(0, int(max_graphql_calls)), say, width,
                       graphql_seconds)
    try:
        if scan and not failed:
            try:
                _scans(store, budget, max_scans, env, http, out, say)
            except sources.SourceError as exc:
                failed = _rest_stopped(out, budget, exc)
        if asker is not None:
            # (after the scans: what it finds is scanned from the next run on, as what the listing finds is, so that
            # both compete by push time. GraphQL spends none of REST's calls, so a REST stop of the checks or the
            # scans leaves it asking; a limit GraphQL shares, Budget.shared, does not)
            asker.due()
        if not failed:
            try:
                _listing(store, client, budget, filters, now, out, scan_all, say, asker)
            except sources.SourceError as exc:
                _rest_stopped(out, budget, exc)
        if asker is not None:
            asker.finish()                          # (every call in flight read first)
    finally:
        if asker is not None:
            asker.close()                           # (no call's thread outlives the run, an error of it included)
    if scan_all and out["queue"] is not None:
        _bound_queue(store, now, out["queue"])          # (the listing's asks queue too)
    out["stopped"] = out["stopped"] or _why_stopped(out, budget, max_calls)
    return out


def _rest_stopped(out, budget, exc):
    """A REST call's error that ends the run's REST part: a rate limit (Budget.refused), or another error, said. ->
    True."""
    if not budget.refused(exc) and budget.stopped is None:
        out["errors"].append(str(exc))
        out["stopped"] = f"GitHub answered with an error: {exc}"
    return True


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
    """The scans (--scan): the ready candidates, oldest first, then scan-all's queue, at most `max_scans` in all:
    LATE_SCAN_SHARE of the queue's scans, rounded up, for its late finds, the first found first, then the rest
    newest push first, late finds among them (a share not used goes to the other). queue["lateScanned"] counts the
    late finds scanned."""
    made, queue = 0, out["queue"]
    cap = "" if max_scans is None else f" of at most {max_scans}"

    def left():
        return None if max_scans is None else max(0, max_scans - made)

    def picks(kind):
        if kind == "ready":
            return store.github_candidates(states=("ready",), limit=left())
        if kind == "late":                          # (the queue's late share, of the scans the ready ones left)
            share = 0 if left() is None else math.ceil(left() * LATE_SCAN_SHARE)
            return store.github_candidates(states=("queued",), late=True, limit=share) if share else []
        return store.github_candidates(states=("queued",), newest_first=True, limit=left())
    for kind in ("ready", "late", "newest"):
        for cand in picks(kind):
            if (max_scans is not None and made >= max_scans) or not budget.can(SCAN_CALLS):
                break
            made += 1
            say(f"scanning {made}{cap}: github:{cand['full_name']}…")
            if queue is not None and cand.get("late_at"):
                queue["lateScanned"] += 1
            res = _scan(store, budget, cand, env, http, out)
            if res is not None:
                out["scans"].append(res)
    if queue is not None:
        _queue_left(store, queue)


def _scan_all_listed(store, item, matched, held, filters, listed_at, out):
    """A listed repository with scan-all on: a pending one (pushed before the listing reached it) is queued,
    reported or excluded as the listing judges it; one your excludes match is kept as excluded; a filter's match is
    a candidate, ready at once when GH Archive saw it get code. -> True for one GitHub's GraphQL API is to be asked
    about (GH-SCAN-GQL): not seen before, and nothing kept it."""
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
        return False
    if held is not None:
        return False
    if not found and filters.excluded(item):
        desc = item.get("description") if isinstance(item.get("description"), str) else None
        store.add_github_candidate(item["id"], item["full_name"], desc, item.get("fork"),
                                   ["excluded by your patterns"], listed_at, "excluded", None)
        return False
    _keep(store, item, matched, listed_at, out)
    return not found


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


def _goes_on(budget, asker):
    """Does the listing read another page? The GraphQL calls that ended are read first (`_Asker.poll`): a secondary
    limit one of them met stops the run's REST calls too."""
    if asker is not None:
        asker.poll()
    return budget.can()


def _listing(store, client, budget, filters, now, out, scan_all=False, say=lambda text: None, asker=None):
    """New repositories from the cursor on, each page's candidates kept, then the cursor. With scan-all, what the
    listing judges is kept for GH Archive's pushes too: excluded and campaign repositories, and the pending ones
    (pushed before the listing reached them) queued or reported; and the rest of the page (`asker`, GH-SCAN-GQL)
    is kept before the cursor moves past it and asked of GitHub's GraphQL API after, one call for the page (with
    calls at once, GH-SCAN-GQL-SPEED, the listing reads on while it is in flight; `_goes_on`)."""
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
    while _goes_on(budget, asker):
        page = list_page(client, budget, since)
        if not page:
            out["caughtUp"] = True
            return
        out["pages"] += 1
        held = store.github_candidate_states(i["id"] for i in page) if scan_all else {}
        fresh = []
        for item in page:
            out["listed"] += 1
            matched = filters.match(item)
            if scan_all:
                if _scan_all_listed(store, item, matched, held.get(item["id"]), filters, listed_at, out):
                    fresh.append(item)
            else:
                _keep(store, item, matched, listed_at, out)
        rows = asker.keep(fresh) if asker is not None and fresh else []
        since = max(since, max(i["id"] for i in page))
        store.save_discovery_cursor(ECO, since, now)
        out["cursor"] = since
        if rows:
            asker.first(rows)
        if out["pages"] % LISTING_PROGRESS_EVERY == 0:
            say(f"listing: {out['pages']} pages, {out['listed']:,} new repositories, up to ID {since}…")
