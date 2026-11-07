"""A look-alike dependency that is an established package is INFO (TYPO-ESTABLISHED, 0.1.9).

SC-TYPOSQUAT (registry/lookalike.py) flags a dependency whose name is one change from one of its registry's
most-downloaded packages, unless the known-name lists hold it. A real package below the lists' cut is flagged as a
squat is: djotls 0.1.0 (October 2026, two hours old) depends on the crate `roman` (Roman numerals, for Djot's ordered
lists: first published 2015, 13 versions), one change from `rowan`, and `roman` is in none of the lists. A squat is
new: it is published for the typo, shortly before the releases that depend on it, or it is an old name someone else
now publishes.

So for each dependency a release's look-alike finding names — those alone: nothing is fetched for a release with
none — the dependency's own history is read, with one request: npm's packument, PyPI's Simple API (JSON), crates.io's
sparse index file. The finding stays, at INFO, its message saying why ("…; it is an established package: first
published 2015, 13 versions."), when the dependency is established, all of:

- its first version published more than MIN_AGE (a year) before the release that depends on it (before now, when the
  release's publish time is not known: an npm version's manifest does not carry it);
- at least MIN_VERSIONS (3) versions (a placeholder or a squat has one or two);
- no new publisher: on npm, an account that published its newest version (its `_npmUser`, else that version's
  `maintainers`) published one of the versions before it. PyPI names no publisher per version (neither the JSON API
  nor the Simple API does), and the crates index names none (crates.io's owners are a second request, to its API,
  which this does not make), so a PyPI project or a crate is judged by its age and versions alone. A crates index
  line without `pubtime` is older than the field (crates.io writes it on every line now), so it counts as old.

Otherwise the finding is MAJOR, as before: a new package, too few versions, a new publisher on npm, or a history that
did not come back (the history switches off, a registry that does not answer, a document over MAX_HISTORY_BYTES, a
dependency past the first MAX_LOOKUPS of a release) — it fails closed, and is never an error of the scan. Not
changed: the release's own name looking like a popular package's, and a dependency named like one of Node's built-in
modules (code that requires the module gets the built-in, so the package is installed for nothing, whatever its
history): lookalike.issues marks neither with KEY.

Each history is read once a run (`RUN`, by ecosystem and name, kept CACHE_SECONDS for a long-lived process), the
first time a release's look-alike dependency asks for it. An INFO finding does not count as an indicator: not for the
verdict (repo.decide_verdict), nor for the comparison with the release before (prior.candidates and
prior.rules_found pass INFO over), nor in the guard's verdicts (`guard_settle`). Off with the dependency history
(LAZARET_NO_DEPENDENCY_HISTORY, an offline scan) or on its own (LAZARET_NO_LOOKALIKE_HISTORY); the tests turn it off
(tests/__init__.py) but its own. Measured on the popular sets: owed (John), `scripts/bench.py lookalikes` on a run's
WARN releases (`run` scans the files alone, so `all` does not see it)."""

import collections
import datetime
import os
import threading
import time
import urllib.parse

from lazaret.registry import lookalike as _lookalike
from lazaret.registry.ecosystems import base as _base

OFF_ENV = "LAZARET_NO_LOOKALIKE_HISTORY"
RULE = "SC-TYPOSQUAT"
KEY = _lookalike.DEPENDENCY_KEY
ECOSYSTEMS = ("npm", "pypi", "crates")
MIN_AGE = datetime.timedelta(days=365)
MIN_VERSIONS = 3
MAX_LOOKUPS = 5                          # look-alike dependencies of one release whose history is read
MAX_HISTORY_BYTES = 16 * 1024 * 1024     # prior.MAX_HISTORY_BYTES: an npm packument of a package with many versions
CACHE_SECONDS = 3600
MAX_CACHED = 4096
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"

#: first: the earliest publish time of a version (None when none has one); undated: a version has none (a crates
#: index line older than `pubtime`), so the package is older than any dated version; versions: how many; publisher:
#: True when an account that published the newest version published an earlier one, False when none did (or npm
#: does not say who did), None when the registry names no publisher (PyPI, crates)
History = collections.namedtuple("History", "first undated versions publisher")


def enabled():
    return not (os.environ.get(OFF_ENV) or os.environ.get("LAZARET_NO_DEPENDENCY_HISTORY"))


def _repo():
    from lazaret.registry import repo
    return repo


# ---- the histories
def _npm_publishers(entry):
    """Who published one version of an npm packument: its `_npmUser`, else its `maintainers` (names only)."""
    if not isinstance(entry, dict):
        return set()
    user = entry.get("_npmUser")
    if isinstance(user, dict) and isinstance(user.get("name"), str) and user["name"]:
        return {user["name"]}
    people = entry.get("maintainers")
    return {m["name"] for m in people if isinstance(m, dict) and isinstance(m.get("name"), str) and m["name"]} \
        if isinstance(people, list) else set()


def npm_history(doc):
    """History of an npm packument (its versions' `time`, each version's publisher), None for one without versions."""
    times = doc.get("time") if isinstance(doc, dict) else None
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(times, dict) or not isinstance(versions, dict):
        return None
    dated = sorted((t, v) for v in versions if isinstance(v, str) for t in (_base.parse_time(times.get(v)),)
                   if t is not None)
    if not dated:
        return None
    newest = _npm_publishers(versions[dated[-1][1]])
    earlier = set().union(*(_npm_publishers(versions[v]) for _t, v in dated[:-1]))
    return History(dated[0][0], False, len(dated), bool(newest & earlier))


def pypi_history(doc):
    """History of a PyPI Simple API JSON document (PEP 691, 700): each version's first upload of a file that is not
    yanked; None for one with no such file."""
    from lazaret.registry import provenance as _provenance
    if not isinstance(doc, dict) or not isinstance(doc.get("versions"), list) or not isinstance(doc.get("files"), list):
        return None
    versions = {v for v in doc["versions"] if isinstance(v, str)}
    first = {}
    for f in doc["files"]:
        if not isinstance(f, dict) or f.get("yanked") or not isinstance(f.get("filename"), str):
            continue
        v, t = _provenance._pypi_version_of(f["filename"], versions), _base.parse_time(f.get("upload-time"))
        if v is not None and t is not None and (v not in first or t < first[v]):
            first[v] = t
    return History(min(first.values()), False, len(first), None) if first else None


def crates_history(records):
    """History of a crate's index lines (crates module's `records`), its yanked versions left out; None for none."""
    live = [r for r in records or () if isinstance(r, dict) and not r.get("yanked")]
    if not live:
        return None
    times = [t for t in (_base.parse_time(r.get("pubtime")) for r in live) if t is not None]
    return History(min(times) if times else None, len(times) < len(live), len(live), None)


def _json(url, accept=None):
    """A registry document over the registry's fetch (repo._fetch), within MAX_HISTORY_BYTES."""
    repo = _repo()
    raw = repo._fetch(url, max_bytes=MAX_HISTORY_BYTES, timeout=repo.METADATA_TIMEOUT,
                      **({"accept": accept} if accept else {}))
    return repo._deep_safe_loads(raw, f"registry response from {url}")


def fetch_history(eco, name, fetch_json=None):
    """The history of the package `name` of `eco`, with one request: npm's packument and PyPI's Simple API over
    `fetch_json(url, accept)` (default: the registry's fetch), a crate's index file over the crates module's own
    fetch (as prior.py reads it, in the guard too). None when it lists no version; the fetch's errors are raised."""
    if eco == "npm":
        return npm_history((fetch_json or _json)(NPM_REGISTRY + urllib.parse.quote(name, safe="@"), None))
    if eco == "pypi":
        return pypi_history((fetch_json or _json)(f"https://pypi.org/simple/{_lookalike.normalize('pypi', name)}/",
                                                  PYPI_SIMPLE_JSON))
    if eco == "crates":
        repo = _repo()
        module = repo.registry_module("crates")
        return crates_history(module.records(name, repo.module_fetch(module)))
    return None


class Cache:
    """Histories by (ecosystem, name) for a run: each read once (a lock for each, so that threads asking for the same
    one wait for its one request), kept `seconds` (a long-lived process, a discovery loop or the MCP server, reads it
    again after that) and at most `size` of them. One that did not come back is kept as None: not asked again."""

    def __init__(self, seconds=CACHE_SECONDS, size=MAX_CACHED):
        self.seconds, self.size = seconds, size
        self.lock = threading.Lock()
        self.kept, self.locks = {}, {}

    def get(self, key, read):
        with self.lock:
            one = self.locks.setdefault(key, threading.Lock())
        with one:
            with self.lock:
                hit = self.kept.get(key)
            if hit is not None and time.monotonic() - hit[0] < self.seconds:
                return hit[1]
            try:
                found = read()
            except Exception:                       # noqa: BLE001 -- unavailable: the finding stays MAJOR
                found = None
            with self.lock:
                self.kept.pop(key, None)
                while len(self.kept) >= self.size:
                    old = next(iter(self.kept))
                    del self.kept[old]
                    self.locks.pop(old, None)
                self.kept[key] = (time.monotonic(), found)
            return found

    def clear(self):
        with self.lock:
            self.kept.clear()
            self.locks.clear()


RUN = Cache()


# ---- the judgement
def established(history, when):
    """Why the package whose history is `history` is established at `when` (the depending release's publish time):
    the words the finding's message gives ("first published 2015, 13 versions"), else None."""
    if history is None or history.versions < MIN_VERSIONS or history.publisher is False:
        return None
    if history.undated:
        since = "before its registry recorded publish times"
    elif history.first is not None and when - history.first > MIN_AGE:
        since = str(history.first.year)
    else:
        return None
    by = ", the newest by an account that published earlier ones" if history.publisher else ""
    return f"first published {since}, {history.versions} versions{by}"


def judge(eco, names, when=None, fetch_json=None, cache=None):
    """{dependency: why it is established} of the look-alike dependencies `names` of one release of `eco` published at
    `when` (None: now): the first MAX_LOOKUPS, each history read once a run (`cache`, default RUN). {} when the history
    is off or `eco` is not one it reads."""
    if eco not in ECOSYSTEMS or not enabled() or not names:
        return {}
    cache = cache if cache is not None else RUN
    when = when or datetime.datetime.now(datetime.timezone.utc)
    out = {}
    for name in sorted(names)[:MAX_LOOKUPS]:
        history = cache.get((eco, _lookalike.normalize(eco, name)), lambda n=name: fetch_history(eco, n, fetch_json))
        why = established(history, when)
        if why:
            out[name] = why
    return out


def flagged(issues):
    """The look-alike findings a dependency's history can make INFO: SC-TYPOSQUAT, MAJOR, naming the dependency."""
    return [i for i in issues if i.get("rule") == RULE and i.get("sev") == "MAJOR" and isinstance(i.get(KEY), str)]


def settle(issue, why):
    """A look-alike dependency's finding made INFO, its message saying why."""
    msg = issue.get("msg") or ""
    issue["sev"] = "INFO"
    issue["msg"] = (msg[:-1] if msg.endswith(".") else msg) + f"; it is an established package: {why}."


# ---- a registry scan
def release_time(eco, resolved):
    """The publish time of the release `resolved` is (a crate's index line's `pubtime`, a PyPI file's first upload), or
    None (npm's version manifest has none)."""
    arts = getattr(resolved, "artifacts", None) or ()
    entries = [a["entry"] for a in arts if isinstance(a, dict) and isinstance(a.get("entry"), dict)]
    if eco == "crates":
        return _base.parse_time(entries[0].get("pubtime")) if entries else None
    if eco == "pypi":
        times = [t for t in (_base.parse_time(e.get("upload_time_iso_8601")) for e in entries) if t is not None]
        return min(times) if times else None
    return None


def release_issues(eco, resolved, issues, per, fetch_json=None):
    """TYPO-ESTABLISHED in a registry scan (repo._release_findings, before the comparison with the release before):
    each look-alike dependency of the release's files' findings `issues` that is an established package made INFO
    (`settle`), and each file that had one given the verdict its scan gives without it (repo.decide_verdict over its
    findings, as scan_members decided it; `per`: the files as scan_package lists them). -> {dependency: why}."""
    found = flagged(issues)
    if not found:
        return {}
    why = judge(eco, {i[KEY] for i in found}, release_time(eco, resolved), fetch_json)
    touched = set()
    for i in found:
        if i[KEY] in why:
            settle(i, why[i[KEY]])
            touched.add(i.get("artifact"))
    if touched:
        repo = _repo()
        for p in per:
            if len(per) > 1 and p.get("filename") not in touched:
                continue
            mine = issues if len(per) == 1 else [i for i in issues if i.get("artifact") == p.get("filename")]
            verdict, reason, strong, weak = repo.decide_verdict(mine, p.get("truncated", 0))
            p.update(verdict=verdict, verdictReason=reason, strongIndicators=strong, weakIndicators=weak)
    return why


# ---- the guard
def guard_kept(result, summarize):
    """What the guard keeps with a scan's verdict for `guard_settle` (guard._scan_one): the scan's weaker indicators'
    count and each look-alike finding in short (as guard.rules_of keeps one), with its line among the indicators
    (`summarize`, guard's) and the dependency it names. {} when no finding names a dependency. Never kept in the
    verdict cache."""
    found = [i for i in result.get("issues") or () if i.get("rule") == RULE and i.get("sev") != "INFO"]
    if not flagged(found):
        return {}
    return {"lookalikes": {"weak": result.get("weakIndicators", 0), "findings": [
        {"rule": i["rule"], "sev": i["sev"], "name": i.get("name", ""), "file": i.get("file", ""),
         "line": i.get("line", 1), "msg": (i.get("msg") or "")[:400], "indicator": summarize({"issues": [i]})[0],
         **({"dependency": i[KEY]} if flagged([i]) else {})} for i in found]}}


def guard_settle(eco, hit, when, fetch_json):
    """The guard's verdict `hit` of a fresh scan with its established look-alike dependencies made INFO: their lines
    left out of the indicators, the rule kept (`rules`, for the comparison with the release before) by a finding that
    stays, and a WARN that rested on them made OK (or its count of weaker indicators lowered). `fetch_json` None:
    nothing is read (offline, or not from the public registry). The hit loses `lookalikes` either way."""
    kept = hit.get("lookalikes")
    hit = {k: v for k, v in hit.items() if k != "lookalikes"}
    if not kept or fetch_json is None:
        return hit
    findings = kept.get("findings") or []
    why = judge(eco, {f["dependency"] for f in findings if f.get("dependency")}, when, fetch_json)
    if not why:
        return hit
    gone = [f for f in findings if f.get("dependency") in why]
    left = [f for f in findings if f.get("dependency") not in why]
    lines = {f.get("indicator") for f in gone}
    out = dict(hit, indicators=[line for line in hit.get("indicators") or () if line not in lines])
    rules = dict(hit.get("rules") or {})
    rules.pop(RULE, None)
    if left:
        rules[RULE] = {k: left[0][k] for k in ("rule", "sev", "name", "file", "line", "msg")}
    out["rules"] = rules
    if hit.get("verdict") == "WARN":
        weak = int(kept.get("weak") or 0) - len(gone)
        out["verdict"], out["reason"] = (
            ("WARN", f"{weak} weaker supply-chain indicator{'' if weak == 1 else 's'} to review") if weak > 0
            else ("OK", "no supply-chain indicators"))
    return out
