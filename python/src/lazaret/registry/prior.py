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

A finding of the release's own that is compared too (RA-10's SC-YANK-TO-PUSH, registry/yanks.py: its earlier
releases yanked as it was published) comes with its own test of the predecessor (`own`), read from the registry's
documents: nothing of the predecessor is downloaded for it.

Compiled code new in a release (RA-13; John, Oct 15) is a narrower comparison, asked of a release that is not
SUSPICIOUS whatever its other findings: a release whose files ship compiled code (repo._compiled_code: an ELF, Mach-O
or PE file, or a .so, .pyd, .dylib, .dll, .node or .exe that is not text; the files' `compiledCode`) when its
established predecessor's files of the same kind ship none at all is SC-NEW-COMPILED-CODE, MAJOR, naming a few of the
files, and CRITICAL when the comparison finds an SC-NEW-INDICATOR too. Shai-Hulud's PyPI wave (June 2026) gave pure-
Python bioinformatics and ML packages native extensions that run on import (`ensmallen_*.abi3.so`), beside a .pth
loader; GlassWorm v2 (April 2026) published 73 Open VSX extensions benign and activated six through ordinary updates
that brought .node binaries and a downloader, so 67 of the 73 would pass any one-time scan. Like with like: a release's
sdist with its predecessor's sdist, a wheel with its wheels, a `.vsix` with its `.vsix` files; a predecessor's wheel
whose tags are not pure Python's (an ABI tag other than `none`, or a platform other than `any`) ships compiled code by
its name, and nothing of it is downloaded; else its files of the kind (the counterparts, as below) are scanned, and
the release's compiled code is new when none of them ships any. So a package that always had platform wheels adding
another, or one whose sdist is pure Python and whose wheels are not, is not asked about. Which files of a release are
compiled code is that release's own scan; SC-BINARY (an inventory finding in a wheel, MAJOR elsewhere) stays as it is.

Open VSX's and the Marketplace's releases are compared too (RA-13), by the version history SC-NEW-DEPENDENCY reads for
them (the module's `history`: each version's earliest time across its platforms, whether it is a pre-release), the
predecessor's files resolved as the release's were (each Open VSX file checked against its SHA-256; the Marketplace
publishes none, and its files are scanned unverified, as the release's are). `lazaret guard <editor>` compares an
extension it installs or updates from its gallery the same way (registry/editorguard.py).

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
import json
import os
import time
import urllib.parse

from lazaret.registry.ecosystems import base as _base

OFF_ENV = "LAZARET_NO_PRIOR_RELEASE"
GAP = datetime.timedelta(days=7)
MAX_HISTORY_BYTES = 16 * 1024 * 1024     # an npm packument or a Simple API document of a package with many releases
MAX_FILES = 3                            # the predecessor's files downloaded and scanned
ECOSYSTEMS = ("npm", "pypi", "crates", "openvsx", "vscode")
RULE = "SC-NEW-INDICATOR"
COMPILED_RULE = "SC-NEW-COMPILED-CODE"   # RA-13
COMPILED_NAMED = 3                       # the release's compiled files a finding names
HOOK_RULE = "SC-INSTALL-HOOK"
RELEASE_FILE = "(release)"               # the file of a finding of the release's own, not of one of its files
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
COMPILED_WHY = ("Compiled code runs when it is imported or loaded, and no review of a package's source reads it. "
                "Shai-Hulud's PyPI wave (June 2026) gave pure-Python packages native extensions that run on import "
                "(ensmallen_*.abi3.so); GlassWorm v2 (April 2026) published 73 Open VSX extensions benign and activated "
                "six through ordinary updates that brought .node binaries, so 67 of the 73 would pass any one-time scan. "
                "Lazaret scanned the newest release published at least a week before this one, and its files of the "
                "same kind ship no compiled code. A project that starts building native code reads the same way: read "
                "its changelog.")
COMPILED_FIX = ("Compare this release with the one named and find what builds and loads the new compiled files before "
                "installing; pin the earlier release until they are explained.")


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


def strong(issues):
    """Is a release SUSPICIOUS by its findings (a supply-chain finding of STRONG_SEVERITIES)? Nothing is asked of it."""
    repo = _repo()
    return any(i["rule"].startswith("SC-") and i["rule"] not in repo.TRUNCATION_RULES
               and i["sev"] in repo.STRONG_SEVERITIES for i in issues)


def compiled_files(per):
    """(RA-13) {filename: (its kind, [its compiled code's paths])} of the release's files (`per`) that ship compiled
    code (their `compiledCode`)."""
    return {p.get("filename"): (p.get("kind"), list(p["compiledCode"])) for p in per
            if isinstance(p.get("compiledCode"), list) and p["compiledCode"]}


def compiled_by_name(ref):
    """(RA-13) Does a predecessor's file ship compiled code by its name: a wheel whose tags are not pure Python's (an ABI
    tag other than `none`, or a platform other than `any`: `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`)."""
    name = ref.get("filename") or ""
    if ref.get("artifact") != "wheel" or not name.lower().endswith(".whl"):
        return False
    parts = name[:-len(".whl")].split("-")
    return len(parts) >= 5 and (parts[-2].lower() != "none" or parts[-1].lower() != "any")


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
    budget asks again. `module_fetch` is a registry module's fetch whose documents (a crate's index lines, an extension's
    version history) are read once for each URL, Accept and budget. `fetch`: the base.Fetch module_fetch wraps, in
    place of repo.module_fetch's (lazaret guard's editor run: its own)."""

    def __init__(self, fetch=None):
        self._docs = {}
        self._fetches = {}
        self._given = fetch

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
        """repo.module_fetch(module) (or the fetch given), its documents each read once."""
        if module not in self._fetches:
            self._fetches[module] = _OnceFetch(self._given if self._given is not None else _repo().module_fetch(module))
        return self._fetches[module]


class _OnceFetch:
    """A registry module's fetch (`base.Fetch`) whose documents (json_lines, json, text, and a query POSTed: the
    Marketplace's version history, RA-13) are each read once for a URL, Accept and budget (and json_lines' `select`, a
    POST's body); the rest (a download's `bytes`) as the fetch's own."""

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

    def post_json(self, url, body, max_bytes=_base.MAX_DOCUMENT_BYTES, accept=None):
        return self._once(("post", url, json.dumps(body, sort_keys=True), max_bytes, accept),
                          lambda: self._fetch.post_json(url, body, max_bytes=max_bytes, accept=accept))


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


def _extension(eco):
    """Open VSX, the Marketplace (RA-13): the reader of (when, (predecessor, its time), its files) by the version history
    SC-NEW-DEPENDENCY reads (the module's `history`: a version's earliest time across its platforms, a pre-release or
    not), over the module's fetch (`history`'s, the release scan's: read once for both); the release's own time and
    kind from its resolution when the history does not list it. The predecessor's files are its resolution's (each
    platform's, each Open VSX file with its SHA-256)."""
    def read(name, version, resolved, _fetch_json, history=None):
        module = _repo().registry_module(eco)
        fetch = (history or History()).module_fetch(module)
        entries = module.history(name, fetch)
        times = {e[0]: e[1].isoformat() for e in entries}
        pre = {e[0] for e in entries if e[3]}
        info = getattr(resolved, "info", None)
        info = info if isinstance(info, dict) else {}
        if version not in times and isinstance(info.get("timestamp") or info.get("lastUpdated"), str):
            times[version] = info.get("timestamp") or info.get("lastUpdated")
            if info.get("preRelease") is True:
                pre.add(version)
        when, best = established(times, version, times, lambda v: v in pre)
        refs = module.resolve(name, best[0], fetch).artifacts if best else []
        return when, best, refs
    return read


_HISTORY = {"npm": _npm, "pypi": _pypi, "crates": _crates, "openvsx": _extension("openvsx"),
            "vscode": _extension("vscode")}


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
    """One of the predecessor's files, fetched, checked against its digest and scanned as the release's were: (the set
    of rules it has a finding of, its compiled code's paths), or why it was not compared (its scan was not complete)."""
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
    if r["truncated"]:
        return f"{ref.get('filename')} was not scanned whole"
    return rules_found(r["issues"]), list(r.get("compiledCode") or ())


def _scanned(prev, files, scan_file):
    """([(file, the rules it has a finding of, its compiled code's paths or None: not known)] of the predecessor's
    `files`, None), or (None, why one was not compared). `scan_file` answers (rules, compiled code), the rules alone
    (its compiled code not known), or why."""
    out = []
    for ref in files:
        got = scan_file(ref, prev)
        if isinstance(got, str):
            return None, got
        rules, compiled = got if isinstance(got, tuple) else (got, None)
        out.append((ref, set(rules), None if compiled is None else list(compiled)))
    return out, None


def _compiled_plan(compiled, version, prev, refs):
    """(RA-13) What the comparison reads of the predecessor for the release's files that ship compiled code
    (`compiled_files`), kind by kind, like with like: ({kind: its files of the kind to scan}, the kinds whose files ship
    compiled code by their names (`compiled_by_name`: nothing scanned), the kinds it has no file of (not compared)).
    The files scanned of a kind: a counterpart of each of the release's compiled files (the same name with the version
    changed, else the first of the kind), at most MAX_FILES."""
    scan, by_name, none = {}, set(), set()
    for kind in sorted({k for k, _paths in compiled.values()}, key=str):
        theirs = [r for r in refs if r.get("artifact") == kind]
        if not theirs:
            none.add(kind)
        elif any(compiled_by_name(r) for r in theirs):
            by_name.add(kind)
        else:
            mine = [{"filename": f, "kind": k} for f, (k, _paths) in compiled.items() if k == kind]
            scan[kind] = counterparts(mine, {m["filename"] for m in mine}, version, prev, theirs)
    return scan, by_name, none


def _new_compiled(compiled, plan, scanned):
    """(RA-13) [(the release's file, a path of its compiled code)] of the kinds whose predecessor's files scanned ship
    no compiled code (each of them read, none listing any); [] for a kind one of them ships some of, or whose compiled
    code is not known."""
    code = [(ref, paths) for ref, _rules, paths in scanned]
    out = []
    for kind, files in plan[0].items():
        theirs = [paths for ref, paths in code if any(ref is f for f in files)]
        if not files or len(theirs) < len(files) or any(p is None or p for p in theirs):
            continue
        out += [(f, p) for f, (k, paths) in sorted(compiled.items(), key=lambda kv: str(kv[0])) if k == kind
                for p in paths]
    return out


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


_KIND_WORDS = {"wheel": "wheels", "sdist": "sdist", "npm": "package", "crate": "crate", "vsix": ".vsix files"}


def _compiled_issue(new_code, kinds, prev, age, multi, critical):
    """(RA-13) SC-NEW-COMPILED-CODE for the release's compiled code (`new_code`: [(its file, a path)]) whose kinds of
    file (`kinds`) its predecessor's had none of: MAJOR, CRITICAL beside an SC-NEW-INDICATOR. `multi`: the release has
    more than one file (the finding names the file it is in, as scan_package's file findings do)."""
    paths = list(dict.fromkeys(p for _f, p in new_code))
    files = list(dict.fromkeys(f for f, _p in new_code))
    named = ", ".join(paths[:COMPILED_NAMED]) + (" and others" if len(paths) > COMPILED_NAMED else "")
    msg = (f"Compiled code new in this release: {named}" + (f" (in {len(files)} of its files)" if len(files) > 1 else "")
           + f"; {prev}, published {age} before it, ships none in its "
           + " or ".join(_KIND_WORDS.get(k, f"{k} files") for k in kinds) + "."
           + (" A weaker indicator is new in this release too (SC-NEW-INDICATOR)." if critical else ""))
    first_file, first_path = new_code[0]
    return {"rule": COMPILED_RULE, "name": "Compiled code new in this release", "type": "HOTSPOT",
            "sev": "CRITICAL" if critical else "MAJOR", "msg": msg[:1200], "why": COMPILED_WHY, "fix": COMPILED_FIX,
            "ref": "CWE-506 · Supply chain", "file": f"{first_file}/{first_path}" if multi and first_file else first_path,
            "line": 1, "snippet": [], "snipStart": 1, **({"artifact": first_file} if multi and first_file else {})}


def _compare(eco, name, version, asked, per, ops):
    fetch_json, scan_file, resolved, history, own = ops
    compiled = compiled_files(per)
    when, best, refs = _HISTORY[eco](name, version, resolved, fetch_json, history)
    if best is None:
        return [], {"notCompared": "the registry gives no time for this release" if when is None else
                    "no release published a week or more before this one"}
    prev = best[0]
    of_files = {rule: i for rule, i in asked.items() if rule not in own}
    files = []
    if of_files:
        flagged = {i.get("artifact") for i in of_files.values()}
        files = counterparts(per, flagged, version, prev, refs)
        if not files:
            return [], {"version": prev, "notCompared": "no file of it to compare"}
    plan = _compiled_plan(compiled, version, prev, refs)
    want = list(files)
    for of_kind in plan[0].values():
        want += [f for f in of_kind if f not in want]
    scanned, why = _scanned(prev, want, scan_file)
    if why:
        return [], {"version": prev, "notCompared": why}
    before = set().union(*(rules for ref, rules, _code in scanned if any(ref is f for f in files)))
    before |= {rule for rule, had in own.items() if rule in asked and had(prev)}     # (the release's own: RA-10)
    new = sorted(set(asked) - before)
    new_code = _new_compiled(compiled, plan, scanned)
    age = _age(when - best[1])
    summary = {"version": prev, "publishedBefore": age, "files": [r.get("filename") for r in want], "newRules": new}
    if compiled:
        summary["newCompiledCode"] = list(dict.fromkeys(p for _f, p in new_code))[:COMPILED_NAMED]
    issues = [_issue(rule, asked[rule], prev, age) for rule in new]
    if new_code:
        kinds = sorted({compiled[f][0] for f, _p in new_code}, key=str)
        issues.append(_compiled_issue(new_code, kinds, prev, age, len(per) > 1, bool(new)))
    return issues, summary


def compare(eco, name, version, asked, per, fetch_json, scan_file, resolved=None, history=None, own=None):
    """The comparison of a release whose findings asked about are `asked` (`candidates`) with its established
    predecessor, over the caller's fetch and scan: `fetch_json(url, accept)` a registry document, `scan_file(ref,
    version)` one of the predecessor's files fetched, checked and scanned -> (the rules it has a finding of
    (`rules_found`), its compiled code's paths), the rules alone, or why it was not compared -> (SC-NEW-INDICATOR and
    SC-NEW-COMPILED-CODE findings, summary). The release's files (`per`) that list `compiledCode` are compared for it
    (RA-13: `newCompiledCode` in the summary). The registry's errors are a summary that says why it was not compared
    (lazaret guard runs it so, over its own fetcher and scanner). `history`: the release scan's History, whose crates
    index `_crates` and extension history `_extension` read (one of its own otherwise). `own`: {rule: test(predecessor)
    -> had it} for the release's own findings (not its files': RA-10's SC-YANK-TO-PUSH, registry/yanks.py), compared by
    that test, nothing of the predecessor downloaded for them; a finding of the release's own (its file "(release)")
    without a test is not compared."""
    own = own or {}
    asked = {rule: i for rule, i in asked.items() if rule in own or i.get("file") != RELEASE_FILE}
    if not asked and not compiled_files(per):
        return [], None
    try:
        return _compare(eco, name, version, asked, per, (fetch_json, scan_file, resolved, history, own))
    except (_base.FetchError, _base.SpecError, _base.DigestError, ValueError) as exc:
        return [], {"notCompared": f"{type(exc).__name__}: {_base.show(str(exc))}"}


def release_issues(eco, name, version, resolved, issues, per, deadline=None, cancel=None, memo=None, history=None,
                   own=None):
    """SC-NEW-INDICATOR and SC-NEW-COMPILED-CODE findings for one release whose files' findings are `issues` (`per`:
    its files as scan_package lists them, their `compiledCode`) -> (findings, summary or None when no comparison was
    asked for: the release is SUSPICIOUS, or has no weaker indicator asked about and no compiled code). `history`: the
    release scan's History (the registry's documents read once for the release), else one of its own. `own`: compare's
    tests of the predecessor for the release's own findings among `issues` (SC-YANK-TO-PUSH)."""
    if eco not in ECOSYSTEMS or not enabled() or strong(issues):
        return [], None
    asked = candidates(issues)
    if not asked and not compiled_files(per):
        return [], None
    history = history or History()
    return compare(eco, name, version, asked, per, history.json,
                   lambda ref, prev: _scan(eco, name, prev, ref, deadline, cancel, memo), resolved, history, own)
