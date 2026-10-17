"""SC-NEW-INDICATOR: a release with a weaker supply-chain indicator its established predecessor had none of (0.1.9;
John, Oct 14: "if the latest release has findings then we review the prior release vs it").

A finding a package's releases have long had is how the package is made: a bundler leaves base64 in its output, a
build ships a native library. One that a release brings and the release before it lacked is a change, and a hijacked
release is a change to an established package: the Shai-Hulud worm (September 2025) added a postinstall script that
ran its bundle.js to the packages it republished, and the hijacked Nx releases of August 2025 one that ran
telemetry.js. Such a release is WARN when its payload is not itself recognised.

So when a registry scan of a release finds weaker indicators only (the release would be WARN), it scans the release's
established predecessor, the newest release published at least GAP before it (a release of the attacker's own an hour
earlier is not one; SC-NEW-DEPENDENCY's week), a pre-release only for a pre-release, as it scanned the release's
files, and each weaker indicator's rule the predecessor had no finding of is an SC-NEW-INDICATOR, CRITICAL. The rules
of what a release may well ship anew (NOT_COMPARED: a binary, an opaque blob, a nested archive, code nested past the
parser's bound, as generated code can be) are not compared.
Measured on the popular set (Oct 15: 1,703 benign releases, 42 of them WARN): 41 had a finding of each such rule in
their predecessor; pnpm 12.8.1's new postinstall (`node install.js`, against 11.27.1) was the one SC-NEW-INDICATOR.

Nor is an install hook the install-script test reads clean (NEW-HOOK-FP; John, Oct 15: it stays MAJOR): one whose
command runs files of the package and nothing else, each read, none of them nor what they load with a supply-chain
finding of its own (the registry scan's `readClean`, repo._ArtifactScan._hooks_read_clean). A maintainer's new build
step reads that way, pnpm 12.8.1's among them. A new hook with an indicator of its own is still asked about: one that
runs a program of its own (`npx x`) or code inline, a download or evaluation tool on its face, a file the package does
not hold, or a script with a weaker finding (a hostile one is CRITICAL already, and the release SUSPICIOUS).

The predecessor: npm, by the packument's times; PyPI, by the Simple API's upload times (the first file's of each
release), its files of the same kind as the release's that were flagged (the same name with the version changed, else
the first of the kind); crates, by the index's publish times. Best effort, as SC-NEW-DEPENDENCY is: a registry that
does not answer, a history over MAX_HISTORY_BYTES, no established predecessor, a predecessor's file that does not fit
(MAX_FILES, the per-file download limit, the caller's time) or whose scan was not complete, give no finding, and the
result's `priorRelease` says what was compared or why not. LAZARET_NO_PRIOR_RELEASE=1 turns it off, as
LAZARET_NO_DEPENDENCY_HISTORY=1 (an offline scan) does. The registry's own fetch and scan (`repo`, imported when first
needed: it imports this module). A release scan reads the package's history document once for this comparison,
SC-NEW-DEPENDENCY and SC-VERSION-INFLATION (`History`, RA-7; `version_times` is SC-VERSION-INFLATION's reading of it)."""

import datetime
import os
import time
import urllib.parse

from lazaret.registry.ecosystems import base as _base

OFF_ENV = "LAZARET_NO_PRIOR_RELEASE"
GAP = datetime.timedelta(days=7)
MAX_HISTORY_BYTES = 16 * 1024 * 1024     # an npm packument or a Simple API document of a package with many releases
MAX_FILES = 3                            # the predecessor's files downloaded and scanned
ECOSYSTEMS = ("npm", "pypi", "crates")
RULE = "SC-NEW-INDICATOR"
HOOK_RULE = "SC-INSTALL-HOOK"
#: what a release may well ship anew: not compared (SC-NESTED-CODE: generated code, a new minifier's or a new data
#: table's, nests past the parser's bound too; JS-NEST)
NOT_COMPARED = frozenset({"SC-BINARY", "SC-OPAQUE-BLOB", "SC-NESTED-ARCHIVE", "SC-NESTED-CODE"})
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
WHY = ("A finding a package's releases have long had is how the package is made; one a release brings that its "
       "predecessor had none of is a change, and a hijacked release is a change to an established package: the "
       "Shai-Hulud worm (2025) added a postinstall script that ran its own bundle.js to each package it republished. "
       "Lazaret scanned the newest release published at least a week before this one, as it scanned this one, and it "
       "had no finding of this rule. A maintainer's new build step reads the same way: read what changed.")
FIX = ("Compare this release with the one named (npm diff, or the two archives' listings) and read what the new "
       "finding points at before installing; pin the earlier release until the change is explained.")


def enabled():
    return not (os.environ.get(OFF_ENV) or os.environ.get("LAZARET_NO_DEPENDENCY_HISTORY"))


def _repo():
    from lazaret.registry import repo
    return repo


def candidates(issues):
    """{rule: its first finding} of the weaker indicators of a release's files that its predecessor is asked about;
    {} when one of the findings is strong (the release is SUSPICIOUS without it). An install hook read clean
    (`readClean`) is not one (NEW-HOOK-FP)."""
    repo, out = _repo(), {}
    for i in issues:
        rule = i["rule"]
        if not rule.startswith("SC-") or rule in repo.TRUNCATION_RULES or i["sev"] == "INFO":
            continue
        if i["sev"] in repo.STRONG_SEVERITIES:
            return {}
        if rule not in NOT_COMPARED and not (rule == HOOK_RULE and i.get("readClean") is True):
            out.setdefault(rule, i)
    return out


def established(times, version, versions, prerelease, gap=GAP):
    """(time of `version`, (the newest of `versions` published at least `gap` before it, its time)) from {version:
    time text}; a pre-release only when `version` is one. (None, None) when the time of `version` is unknown."""
    repo = _repo()
    when = repo._iso_time(times.get(version))
    if when is None:
        return None, None
    best = None
    for v in versions:
        if v == version or (prerelease(v) and not prerelease(version)):
            continue
        t = repo._iso_time(times.get(v))
        if t is not None and t <= when - gap and (best is None or t > best[1]):
            best = (v, t)
    return when, best


def _json(url, accept=None):
    repo = _repo()
    raw = repo._fetch(url, max_bytes=MAX_HISTORY_BYTES, timeout=repo.METADATA_TIMEOUT,
                      **({"accept": accept} if accept else {}))
    return repo._deep_safe_loads(raw, f"registry response from {url}")


class History:
    """The registry documents one release's scan reads about its package, each fetched once (RA-7): npm's packument
    (SC-NEW-INDICATOR's predecessor, SC-VERSION-INFLATION's history and SC-NEW-DEPENDENCY's previous release), PyPI's
    Simple API document (the first two; SC-NEW-DEPENDENCY reads PyPI's JSON API), a crate's index file (all three, and
    the predecessor's resolution). Made for one release scan and dropped with it: nothing is kept past it.

    `json` keys a document by URL and Accept. An answer is kept with its size, and a caller with a smaller budget than
    the answer's size gets the TooLarge its own fetch would have raised (SC-NEW-DEPENDENCY's MAX_FEED_BYTES beside the
    history's MAX_HISTORY_BYTES); a failure is kept and raised again, except a TooLarge, which a caller with a larger
    budget asks again. `module_fetch` is a registry module's fetch whose documents (a crate's index lines) are read once
    for each URL, Accept and budget."""

    def __init__(self):
        self._docs = {}
        self._fetches = {}

    def json(self, url, accept=None, max_bytes=MAX_HISTORY_BYTES, fetch=None):
        """The JSON document at `url` (`_json`'s fetch, at `max_bytes`); `fetch(url)`, a fetch of its own whose budget
        is `max_bytes` (repo.http_json), in its place when the document has not been read."""
        repo = _repo()

        def load():
            if fetch is not None:
                return None, fetch(url)                     # (its size: within max_bytes, the fetch's own budget)
            raw = repo._fetch(url, max_bytes=max_bytes, timeout=repo.METADATA_TIMEOUT,
                              **({"accept": accept} if accept else {}))
            return len(raw), repo._deep_safe_loads(raw, f"registry response from {url}")
        key = (url, accept)
        kept = self._docs.get(key)
        if kept is not None:
            budget, got = kept
            if isinstance(got, _base.TooLarge) and budget < max_bytes:
                kept = None                                 # (too large for a smaller budget: asked at this one)
            elif not isinstance(got, Exception) and got[0] is None and max_bytes < budget:
                kept = None                                 # (its size not known, only that it fit a larger budget)
        if kept is None:
            try:
                kept = (max_bytes, load())
            except (_base.FetchError, _base.SpecError, ValueError) as exc:
                kept = (max_bytes, exc)
            self._docs[key] = kept
        budget, got = kept
        if isinstance(got, Exception):
            raise got
        size, doc = got
        if size is not None and size > max_bytes:
            raise _base.TooLarge(f"response exceeds {max_bytes // (1024 * 1024)}MB budget: {url}")
        return doc

    def feed(self, url):
        """`json` at repo.MAX_FEED_BYTES over repo.http_json: SC-NEW-DEPENDENCY's documents."""
        repo = _repo()
        return self.json(url, None, repo.MAX_FEED_BYTES, fetch=lambda u: repo.http_json(u))

    def module_fetch(self, module):
        """repo.module_fetch(module), its documents each read once."""
        if module not in self._fetches:
            self._fetches[module] = _OnceFetch(_repo().module_fetch(module))
        return self._fetches[module]


class _OnceFetch:
    """A registry module's fetch (`base.Fetch`) whose documents (json_lines, json, text) are each read once for a URL,
    Accept and budget (and json_lines' `select`); the rest (a download's `bytes`, a POST) as the fetch's own."""

    def __init__(self, fetch):
        self._fetch, self._kept = fetch, {}

    def __getattr__(self, attr):
        return getattr(self._fetch, attr)

    def _once(self, key, read):
        if key not in self._kept:
            try:
                self._kept[key] = (True, read())
            except (_base.FetchError, _base.SpecError, ValueError) as exc:
                self._kept[key] = (False, exc)
        ok, got = self._kept[key]
        if not ok:
            raise got
        return got

    def json_lines(self, url, max_bytes=_base.MAX_DOCUMENT_BYTES, accept=None, select=None):
        return self._once(("lines", url, max_bytes, accept, select),
                          lambda: self._fetch.json_lines(url, max_bytes=max_bytes, accept=accept, select=select))

    def json(self, url, max_bytes=_base.MAX_DOCUMENT_BYTES, accept=None):
        return self._once(("json", url, max_bytes, accept), lambda: self._fetch.json(url, max_bytes, accept))

    def text(self, url, max_bytes=_base.MAX_DOCUMENT_BYTES, accept=None):
        return self._once(("text", url, max_bytes, accept), lambda: self._fetch.text(url, max_bytes, accept))


def _npm(name, version, _resolved, fetch_json, _history=None):
    """npm: (when, (predecessor, its time), its files) by the packument's times."""
    doc = fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), None)
    times = doc.get("time") if isinstance(doc, dict) else None
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(times, dict) or not isinstance(versions, dict):
        return None, None, []
    when, best = established(times, version, versions, lambda v: "-" in v)
    entry = versions.get(best[0]) if best else None
    tarball = ((entry or {}).get("dist") or {}).get("tarball") if isinstance(entry, dict) else None
    if not isinstance(tarball, str):
        return when, None, []
    return when, best, [{"url": tarball, "container": "tgz", "artifact": "npm", "entry": entry,
                         "filename": tarball.rsplit("/", 1)[-1]}]


def _pypi_files(doc):
    """{version: [its files]} of a Simple API JSON document (PEP 691, 700); a document of another shape (`versions` or
    `files` not a list) lists nothing of what it does not hold as a list."""
    from lazaret.registry import provenance as _provenance
    listed = doc.get("versions") if isinstance(doc, dict) else None
    files = doc.get("files") if isinstance(doc, dict) else None
    versions = set(v for v in listed if isinstance(v, str)) if isinstance(listed, list) else set()
    out = {}
    for f in files if isinstance(files, list) else ():
        if isinstance(f, dict) and isinstance(f.get("filename"), str) and isinstance(f.get("url"), str):
            v = _provenance._pypi_version_of(f["filename"], versions)
            if v is not None:
                out.setdefault(v, []).append(f)
    return out


def _pypi_times(files):
    """{version: the first upload time of its files that are not yanked}."""
    repo, times = _repo(), {}
    for v, entries in files.items():
        live = [t for t in (repo._iso_time(f.get("upload-time")) for f in entries if not f.get("yanked")) if t]
        if live:
            times[v] = min(live).isoformat()
    return times


def _pypi_ref(f):
    """A file of the Simple API as scan_package's artifacts are, or None for one pip does not install."""
    repo = _repo()
    container = repo.pypi_container(f["filename"])
    hashes = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
    if container is None or f.get("yanked") or not isinstance(hashes.get("sha256"), str):
        return None
    return {"url": f["url"], "container": container, "entry": {"digests": {"sha256": hashes["sha256"]}},
            "artifact": "wheel" if f["filename"].endswith(".whl") else "sdist", "filename": f["filename"]}


def _pypi(name, version, _resolved, fetch_json, _history=None):
    """PyPI: (when, (predecessor, its time), its files pip may install) by the Simple API's upload times."""
    repo = _repo()
    files = _pypi_files(fetch_json(f"https://pypi.org/simple/{repo._pep503(name)}/", PYPI_SIMPLE_JSON))
    times = _pypi_times(files)
    when, best = established(times, version, times, lambda v: not repo._PEP440_FINAL_RE.match(v))
    refs = [r for r in map(_pypi_ref, files.get(best[0], ()) if best else ()) if r is not None]
    return when, best, refs


def _crate_entry(resolved):
    """The index's line of the release a crates Resolution is of, or None (bench.py's `prior` has none)."""
    arts = getattr(resolved, "artifacts", None) or ()
    entry = arts[0].get("entry") if arts and isinstance(arts[0], dict) else None
    return entry if isinstance(entry, dict) and isinstance(entry.get("vers"), str) else None


def _crates(name, version, resolved, _fetch_json, history=None):
    """crates: (when, (predecessor, its time), its .crate) by the index's publish times (a yanked release is none),
    over the crates module's own fetch (`history`'s, the release scan's: the index file read once for the records
    and the predecessor's resolution, and for SC-NEW-DEPENDENCY and SC-VERSION-INFLATION)."""
    from lazaret.registry.ecosystems import crates as _crates_module
    repo = _repo()
    module = repo.registry_module("crates")
    fetch = (history or History()).module_fetch(module)
    records = module.records(name, fetch)
    entry = _crate_entry(resolved) or next((r for r in records if r["vers"] == version), None)
    if entry is None:
        return None, None, []
    version = entry["vers"]
    times = {r["vers"]: r["pubtime"] for r in records if r.get("pubtime") and not r.get("yanked")}
    times.setdefault(version, entry.get("pubtime"))
    when, best = established(times, version, times, lambda v: _crates_module.semver_key(v)[3] == 0)
    refs = module.resolve(name, best[0], fetch).artifacts if best else []
    return when, best, refs


_HISTORY = {"npm": _npm, "pypi": _pypi, "crates": _crates}


def _npm_times(name, fetch_json):
    repo = _repo()
    doc = fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), None)
    times = doc.get("time") if isinstance(doc, dict) else None
    if not isinstance(times, dict):
        return {}
    return {v: t for v, t in times.items()
            if isinstance(v, str) and v not in ("created", "modified") and isinstance(t, str)
            and repo._iso_time(t) is not None}


def _pypi_version_times(name, fetch_json):
    repo = _repo()
    return _pypi_times(_pypi_files(fetch_json(f"https://pypi.org/simple/{repo._pep503(name)}/", PYPI_SIMPLE_JSON)))


def _crate_version_times(name, history):
    """A crate's versions that are not yanked, in the index's order (the order they were published), each with its
    `pubtime`, or None for a line without one (published before the index recorded it: older than every line with
    one)."""
    repo = _repo()
    module = repo.registry_module("crates")
    records = module.records(name, history.module_fetch(module))
    return {r["vers"]: (r["pubtime"] if repo._iso_time(r.get("pubtime")) is not None else None) for r in records
            if isinstance(r, dict) and isinstance(r.get("vers"), str) and not r.get("yanked")}


def version_times(eco, name, resolved=None, history=None):
    """{version: its publish time (ISO text), or None} of a package's releases, in the registry's order, from the same
    registry history SC-NEW-INDICATOR reads (RA-7's SC-VERSION-INFLATION uses it): npm's packument times and PyPI's
    Simple API upload times (a version whose time does not parse is left out), the crates index's `pubtime` (None for
    a line without one). Over `history` (the release scan's History: each document read once), else a History of its
    own. Best effort: {} when the history is off, the ecosystem is not one of `ECOSYSTEMS`, or the registry does not
    answer or answers a document of another shape. `resolved` is unused today (the fetch is by name)."""
    if eco not in ECOSYSTEMS or not enabled():
        return {}
    history = history or History()
    try:
        if eco == "npm":
            return _npm_times(name, history.json)
        if eco == "pypi":
            return _pypi_version_times(name, history.json)
        if eco == "crates":
            return _crate_version_times(name, history)
    except (_base.FetchError, _base.SpecError, _base.DigestError, ValueError, TypeError, KeyError, AttributeError):
        return {}                                   # (a document of another shape than the registry's: no history)
    return {}


def _counterpart(p, version, prev, refs):
    """The predecessor's file for one of the release's: the same name with the version changed, else the first of the
    same kind, else None."""
    want = (p.get("filename") or "").replace(version, prev)
    same = [r for r in refs if r.get("filename") == want] or [r for r in refs if r.get("artifact") == p.get("kind")]
    return same[0] if same else None


def counterparts(per, flagged, version, prev, refs):
    """The predecessor's files to scan: one for each of the release's files (`per`) with a finding asked about (the
    one file, when the release has one), at most MAX_FILES."""
    out = []
    for p in per if len(per) == 1 else [p for p in per if p.get("filename") in flagged]:
        found = _counterpart(p, version, prev, refs)
        if found is not None and found not in out:
            out.append(found)
    return out[:MAX_FILES]


def rules_found(issues):
    """The rules a scan's findings name, as the comparison counts them (a supply-chain finding that is not INFO)."""
    return {i["rule"] for i in issues if i["rule"].startswith("SC-") and i["sev"] != "INFO"}


def _scan(eco, name, prev, ref, deadline, cancel, memo):
    """One of the predecessor's files, fetched, checked against its digest and scanned as the release's were: the set
    of rules it has a finding of, or why it was not compared (its scan was not complete)."""
    repo = _repo()
    if deadline is not None and time.monotonic() > deadline:
        return "out of time"
    module = repo.registry_module(eco)
    if module is None:
        data = repo.http_bytes(ref["url"])
        repo.verify_digest(data, ref["entry"], eco, name, prev)
    else:
        data = repo.module_fetch(module).bytes(ref["url"], repo.MAX_DOWNLOAD_BYTES)
        repo._module_digest(module, data, ref["entry"], eco, name, prev)
    stop = time.monotonic() + repo.SCAN_TIMEOUT
    budget = repo.Budget(deadline=stop if deadline is None else min(stop, deadline), cancel=cancel,
                         deadline_detail="the prior release's scan ran out of time")
    r = repo._scan_artifact(data, ref["container"], ref["artifact"], False, budget, memo)
    return f"{ref.get('filename')} was not scanned whole" if r["truncated"] else rules_found(r["issues"])


def _rules_of(prev, files, scan_file):
    """(the rules the predecessor's files have a finding of, None), or (None, why it was not compared)."""
    before = set()
    for ref in files:
        rules = scan_file(ref, prev)
        if isinstance(rules, str):
            return None, rules
        before |= rules
    return before, None


def _age(delta):
    days = int(delta.total_seconds() // 86400)
    return f"{days} day{'' if days == 1 else 's'}"


def _issue(rule, first, prev, age):
    msg = (f"{first['name']} ({rule}) is new in this release: {prev}, published {age} before it, has no finding "
           f"of it. {first['file']}: {first['msg']}")
    return {"rule": RULE, "name": "A weaker indicator new in this release", "type": "HOTSPOT", "sev": "CRITICAL",
            "msg": msg[:1200], "why": WHY, "fix": FIX, "ref": "CWE-506 · Supply chain", "file": first["file"],
            "line": first.get("line", 1), "snippet": list(first.get("snippet") or []),
            "snipStart": first.get("snipStart", 1), **({"artifact": first["artifact"]} if "artifact" in first else {})}


def _compare(eco, name, version, asked, per, ops):
    fetch_json, scan_file, resolved, history = ops
    when, best, refs = _HISTORY[eco](name, version, resolved, fetch_json, history)
    if best is None:
        return [], {"notCompared": "the registry gives no time for this release" if when is None else
                    "no release published a week or more before this one"}
    prev = best[0]
    flagged = {i.get("artifact") for i in asked.values()}
    files = counterparts(per, flagged, version, prev, refs)
    if not files:
        return [], {"version": prev, "notCompared": "no file of it to compare"}
    before, why = _rules_of(prev, files, scan_file)
    if why:
        return [], {"version": prev, "notCompared": why}
    new = sorted(set(asked) - before)
    age = _age(when - best[1])
    summary = {"version": prev, "publishedBefore": age, "files": [r.get("filename") for r in files], "newRules": new}
    return [_issue(rule, asked[rule], prev, age) for rule in new], summary


def compare(eco, name, version, asked, per, fetch_json, scan_file, resolved=None, history=None):
    """The comparison of a release whose findings asked about are `asked` (`candidates`) with its established
    predecessor, over the caller's fetch and scan: `fetch_json(url, accept)` a registry document, `scan_file(ref,
    version)` one of the predecessor's files fetched, checked and scanned -> the rules it has a finding of
    (`rules_found`), or why it was not compared -> (SC-NEW-INDICATOR findings, summary). The registry's errors are a
    summary that says why it was not compared (lazaret guard runs it so, over its own fetcher and scanner). `history`:
    the release scan's History, whose crates index `_crates` reads (one of its own otherwise)."""
    try:
        return _compare(eco, name, version, asked, per, (fetch_json, scan_file, resolved, history))
    except (_base.FetchError, _base.SpecError, _base.DigestError, ValueError) as exc:
        return [], {"notCompared": f"{type(exc).__name__}: {_base.show(str(exc))}"}


def release_issues(eco, name, version, resolved, issues, per, deadline=None, cancel=None, memo=None, history=None):
    """SC-NEW-INDICATOR findings for one release whose files' findings are `issues` (`per`: its files as scan_package
    lists them) -> (findings, summary or None when no comparison was asked for). `history`: the release scan's History
    (the registry's documents read once for the release), else one of its own."""
    if eco not in ECOSYSTEMS or not enabled():
        return [], None
    asked = candidates(issues)
    if not asked:
        return [], None
    history = history or History()
    return compare(eco, name, version, asked, per, history.json,
                   lambda ref, prev: _scan(eco, name, prev, ref, deadline, cancel, memo), resolved, history)
