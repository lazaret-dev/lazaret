"""SC-YANK-TO-PUSH (RA-10, 0.1.9; John's spec): a crate release published within a day of yanks of the crate's
earlier stable versions by the account that published it.

arrayref's attacker yanked the crate's earlier versions to push its users to the new ones (Wiz): cargo takes no yanked
version for a new resolution (`cargo update`, a new lockfile, `cargo install`), so the yanks moved everyone who resolved
the crate to the attacker's release. A maintainer yanks a broken release, as a rule the one its fix replaces.

crates.io's version records (`GET https://crates.io/api/v1/crates/<name>/versions`: every version, each with its
`audit_actions` — publish, yank, unyank — each with the user and the time) say who yanked what, and when. A release
whose publisher (its publish action's user, else `published_by`) yanked at least YANK_COUNT (2) of the crate's stable
versions earlier than it by SemVer (pre-releases not counted), within YANK_WINDOW (a day) of its publication on either
side, each still yanked (its last yank or unyank a yank), is SC-YANK-TO-PUSH, MAJOR: "its earlier releases were yanked
as it was published". It is compared as the files' weaker indicators are (registry/prior.py): the comparison's test of
the established predecessor (`own`: did the predecessor's own publication come with such yanks, read from the same
document) makes it SC-NEW-INDICATOR, CRITICAL, when it did not; a maintainer who yanks that way as a habit stays
MAJOR. One yank, the broken release a fix replaces, is not one.

The document is asked only when the crate's index file — read for the release anyway: prior.History in a registry
scan, the Cargo guard's read of it — lists YANK_COUNT or more stable versions earlier than the release as yanked, so
most crates cost nothing; one that does costs one request to crates.io's API, paced at one a second (the crates
module's `rate`; the guard's CRATES_API_INTERVAL). Best effort: an answer of another shape, over MAX_VERSIONS_BYTES, a
release it does not list, an API that does not answer, offline, is no finding, never an error of the scan. Off with
the history switches (LAZARET_NO_PRIOR_RELEASE, LAZARET_NO_DEPENDENCY_HISTORY: prior.enabled).

PyPI's yanks (PEP 592) are not read: the JSON API's and the Simple API's `yanked` is a flag or a reason, with no time,
so a yank cannot be placed beside a release's publication."""

import datetime
import json
import re

from lazaret.registry.ecosystems import base as _base
from lazaret.registry.ecosystems.crates import semver_key
from lazaret.scanner import core as lazaret

RULE = "SC-YANK-TO-PUSH"
YANK_COUNT = 2
YANK_WINDOW = datetime.timedelta(days=1)
MAX_VERSIONS_BYTES = 16 * 1024 * 1024     # (a crate's records are about 1.5 KB a version: thousands of versions)
MAX_NAMED = 5
API = "https://crates.io/api/v1/crates/"
_YANKED_LINE_RE = re.compile(r'"yanked"\s*:\s*true')
WHY = ("arrayref's attacker yanked the crate's earlier versions to push its users to the new ones (Wiz): cargo takes no "
       "yanked version for a new resolution, so the yanks moved everyone who resolved the crate to the attacker's "
       "release. A maintainer yanks a broken release, as a rule the one its fix replaces, not the versions before it "
       "as it publishes.")
FIX = ("Keep the version you had (Cargo.lock, or `cargo update --precise`) until the yanks are explained: crates.io "
       "lists who yanked each version and when; read this release before taking it.")


def enabled():
    from lazaret.registry import prior
    return prior.enabled()


def versions_url(name):
    return f"{API}{name}/versions"


def _stable_before(v, mine):
    """Is `v` a stable version (not a pre-release) earlier than the version whose semver_key is `mine`?"""
    k = semver_key(v) if isinstance(v, str) else None
    return k is not None and k[3] == 1 and k < mine


def earlier_yanked(records, version):
    """The crate's stable versions earlier than `version` (by SemVer) its index lists as yanked: index records
    ({"vers", "yanked"}, as the crates module's `records` keeps them, or an index line)."""
    mine = semver_key(version)
    if mine is None:
        return []
    return [r["vers"] for r in records if isinstance(r, dict) and r.get("yanked") is True
            and _stable_before(r.get("vers"), mine)]


def earlier_yanked_text(text, version):
    """earlier_yanked of an index file's text (one JSON object per line; only the lines that say they are yanked are
    parsed, and a line that is not JSON is left out)."""
    records = []
    for line in text.splitlines():
        if not _YANKED_LINE_RE.search(line):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        records.append(rec)
    return earlier_yanked(records, version)


def _user(u):
    """(id, login) of an API user, or None."""
    if not isinstance(u, dict):
        return None
    uid, login = u.get("id"), u.get("login")
    uid = uid if isinstance(uid, int) and not isinstance(uid, bool) else None
    login = login if isinstance(login, str) and login else None
    return None if uid is None and login is None else (uid, login)


def _same(a, b):
    """Are two (id, login) one account: by id when both have one, else by login."""
    if a[0] is not None and b[0] is not None:
        return a[0] == b[0]
    return a[1] is not None and a[1] == b[1]


def _actions(rec):
    acts = rec.get("audit_actions")
    return [a for a in acts if isinstance(a, dict)] if isinstance(acts, list) else []


def _published(rec):
    """(the account that published a version, when), from its publish action, else `published_by` and `created_at`;
    None when either is not known."""
    by = when = None
    for a in _actions(rec):
        if a.get("action") == "publish":
            by, when = _user(a.get("user")), _base.parse_time(a.get("time"))
            break
    by = by or _user(rec.get("published_by"))
    when = when or _base.parse_time(rec.get("created_at"))
    return (by, when) if by is not None and when is not None else None


def _last_yank(rec):
    """(when, who) of a version's last yank when that is its last yank or unyank (it is yanked still), else None."""
    last = None
    for a in _actions(rec):
        if a.get("action") in ("yank", "unyank"):
            t = _base.parse_time(a.get("time"))
            if t is not None and (last is None or t >= last[0]):
                last = (t, a)
    if last is None or last[1].get("action") != "yank":
        return None
    who = _user(last[1].get("user"))
    return None if who is None else (last[0], who)


def records(doc):
    """{version: its record} of crates.io's versions answer; ValueError for an answer of another shape."""
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(versions, list):
        raise ValueError("crates.io: the versions answer has no list of versions")
    return {v["num"]: v for v in versions if isinstance(v, dict) and isinstance(v.get("num"), str)}


def reason(doc, version):
    """(the account that published `version` as (id, login), the stable versions earlier than it that account yanked
    within YANK_WINDOW of its publication, each yanked still, by SemVer; the largest of those spans) when they are
    YANK_COUNT or more, else None (also for a release the answer does not list or whose publisher or time it does not
    give). ValueError for an answer of another shape."""
    recs, mine = records(doc), semver_key(version)
    rec = recs.get(version)
    pub = _published(rec) if rec is not None and mine is not None else None
    if pub is None:
        return None
    by, when = pub
    found, span = [], datetime.timedelta(0)
    for v, r in recs.items():
        if r.get("yanked") is not True or not _stable_before(v, mine):
            continue
        last = _last_yank(r)
        if last is None or not _same(last[1], by) or abs(last[0] - when) > YANK_WINDOW:
            continue
        found.append(v)
        span = max(span, abs(last[0] - when))
    if len(found) < YANK_COUNT:
        return None
    return by, sorted(found, key=semver_key), span


def issue(found):
    """SC-YANK-TO-PUSH (MAJOR) for `reason`'s answer."""
    by, versions, span = found
    who = by[1] or f"the account {by[0]}"
    named = ", ".join(versions[:MAX_NAMED]) + (f" and {len(versions) - MAX_NAMED} more" if len(versions) > MAX_NAMED
                                               else "")
    hours = max(1, -(-int(span.total_seconds()) // 3600))
    return lazaret.mk_issue(
        {"id": RULE, "name": "A release's earlier versions yanked as it was published", "type": "HOTSPOT", "sev": "MAJOR",
         "msg": (f"Its earlier releases were yanked as it was published: {len(versions)} stable versions before it "
                 f"({named}) yanked by {who}, the account that published it, within {hours} hour"
                 f"{'' if hours == 1 else 's'} of its publication.")[:1200],
         "why": WHY, "fix": FIX, "ref": "CWE-506 · Supply chain"},
        "(release)", 1, [])


def _document(fetch, name):
    return fetch.json(versions_url(name), max_bytes=MAX_VERSIONS_BYTES, accept="application/json")


def release_issues(eco, name, version, history, found=()):
    """SC-YANK-TO-PUSH for a crate release in a registry scan, best effort ([] when it cannot say): the crate's index
    read through `history` (the release scan's prior.History, which the comparison and SC-VERSION-INFLATION read it
    through), crates.io's versions answer only when the index lists YANK_COUNT stable versions before the release as
    yanked, through the same History (`own` reads it again for the predecessor, from there). Not asked of a release
    already SUSPICIOUS by `found` (its files' findings): a MAJOR adds nothing to it."""
    from lazaret.registry import prior, repo
    if eco != "crates" or not enabled() or prior.strong(found):
        return []
    try:
        module = repo.registry_module("crates")
        fetch = history.module_fetch(module)
        if len(earlier_yanked(module.records(name, fetch), version)) < YANK_COUNT:
            return []
        got = reason(_document(fetch, name), version)
    except (_base.FetchError, _base.SpecError, ValueError, TypeError, KeyError, AttributeError):
        return []
    return [issue(got)] if got else []


def own(eco, name, history=None, doc=None):
    """The comparison's test of the predecessor for SC-YANK-TO-PUSH (prior.compare's `own`): {RULE: test(prev) -> did
    prev's publication come with such yanks}, from `doc` (crates.io's versions answer in hand: the guard's), else from
    `history` (the registry scan's, which read it for the release); {} for another ecosystem."""
    if eco != "crates" or (doc is None and history is None):
        return {}

    def had(prev):
        from lazaret.registry import repo
        answer = doc if doc is not None else _document(history.module_fetch(repo.registry_module("crates")), name)
        return reason(answer, prev) is not None
    return {RULE: had}
