"""npm's and PyPI's provenance as findings (0.1.9, NET-1's fifth item; specs/lazaret-provenance-findings-2026-10-06).

A release's files may carry attestations. npm's: the version's document has `dist.attestations` when it does, and
`/-/npm/v1/attestations/<name>@<version>` holds npm's own publish attestation (signed with the registry's key) and
SLSA provenance (signed through Sigstore by the CI that built the tarball). PyPI's (PEP 740): the Simple API's JSON
names a `provenance` URL for each file that has one. The native library checks each attestation (`verify.sigstore`,
over tiny_https's `sigstore`): its signature by its certificate or key, the certificate's chain to Sigstore's CA at a
time a transparency log vouches for, the log entries, and a subject with the file's digest (npm: the tarball's
SHA-512; PyPI: the file's SHA-256). What it proves is who built the file: the CI's source repository (its URI, and
the numeric IDs GitHub puts in the certificate, which a rename keeps), the workflow and the ref.

This module fetches the attestations, compares the release with the one before it, and says what it found:

    SC-PROVENANCE-INVALID       CRITICAL  an attestation that is not about this file, or whose signature is not by
                                          its certificate's or key's: the file is not what was built and signed
    SC-PROVENANCE-DROPPED       MAJOR     the release before had provenance and this one has none: a release made
                                          somewhere else than the project's CI (a stolen token), or a change of how
                                          the project publishes
    SC-PROVENANCE-REPO-CHANGED  MAJOR     both have verified provenance, from different source repositories of
                                          different owners (INFO when the owner is the same: a release repository,
                                          a monorepo split)
    SC-PROVENANCE-UNCHECKED     INFO      an attestation that could not be checked, for a reason that is not the
                                          file's (a log, authority or key the trust here does not know; a form not
                                          read here)

"The release before": npm, the highest version below this one (a pre-release only for a pre-release), from the
registry's abbreviated document; PyPI, the release uploaded last before this one (as SC-NEW-DEPENDENCY's), from the
Simple API. The trust is Sigstore's trusted root and npm's keys, shipped in `sigstore/` (TRUST_FILES; newer copies:
LAZARET_SIGSTORE_ROOT, LAZARET_NPM_KEYS). Best effort, as SC-NEW-DEPENDENCY's history is: a registry that does not
answer leaves the release unflagged, and the result's `provenance` says what was not checked. LAZARET_NO_PROVENANCE=1
turns it off. Standard library, the native library, and the registry's own fetch (`repo` hands it over).

`lazaret guard` runs the same check (`guard_npm`, `check_pypi`) on a release from npm's or PyPI's public registry it
scans, when the release was published less than guard.PROVENANCE_DAYS ago, with its own fetcher, and merges the
findings into the scan's verdict."""

import base64
import binascii
import datetime
import hashlib
import os
import re
import urllib.parse

from lazaret.registry.ecosystems import base as _base
from lazaret.registry.ecosystems import crates as _crates
from lazaret.scanner import core as _core

OFF_ENV = "LAZARET_NO_PROVENANCE"
ROOT_ENV = "LAZARET_SIGSTORE_ROOT"
NPM_KEYS_ENV = "LAZARET_NPM_KEYS"
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigstore")
#: the trust shipped with the package, and the SHA-256 each had when it was taken (Oct 5, 2026: Sigstore's production
#: trusted root, the copy sigstore-python 4.5.0 embeds from Sigstore's TUF repository; npm's `/-/npm/v1/keys`)
TRUST_FILES = {"trusted_root.json": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
               "npm_keys.json": "faf23d8753d5bb79df250f10391ac89b63ecf7743e48487a544a99c847f9c8df"}
MAX_PACKUMENT_BYTES = 16 * 1024 * 1024     # npm's abbreviated document of a package with thousands of versions
MAX_SIMPLE_BYTES = 16 * 1024 * 1024        # PyPI's Simple API JSON of a project with thousands of files
MAX_ATTESTATION_BYTES = 4 * 1024 * 1024    # one attestations document (a real one is tens of kilobytes)
MAX_FILES = 64                             # a PyPI release's files whose provenance is fetched and checked
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
WHY = ("A hijacked account publishes from wherever the token was stolen to, not from the project's CI, so a release "
       "that has none of the provenance the releases before it had was built and uploaded somewhere else. ultralytics "
       "8.3.45 and 8.3.46 (December 2024) were uploaded with a stolen PyPI token and had no attestations; the releases "
       "before them came from the project's own workflow.")
_PEP440_FINAL_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:\.post(\d+))?$")
_HEX_RE = re.compile(r"[0-9a-f]+")


class Unchecked(Exception):
    """An attestation, or a release's provenance, that could not be checked: the message says why."""


def enabled():
    return not os.environ.get(OFF_ENV)


# ---------------------------------------------------------------- the trust
def _read(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8")


def trust():
    """(Sigstore's trusted root, npm's keys) as text: LAZARET_SIGSTORE_ROOT and LAZARET_NPM_KEYS name newer copies,
    else the ones shipped here."""
    root = os.environ.get(ROOT_ENV) or os.path.join(HERE, "trusted_root.json")
    keys = os.environ.get(NPM_KEYS_ENV) or os.path.join(HERE, "npm_keys.json")
    try:
        return _read(root), _read(keys)
    except (OSError, UnicodeDecodeError) as exc:
        raise Unchecked(f"the trust could not be read ({type(exc).__name__})") from None


def shipped_files_intact():
    """[problem] for the trust files shipped here that are not the ones recorded in TRUST_FILES."""
    problems = []
    for name, digest in TRUST_FILES.items():
        try:
            with open(os.path.join(HERE, name), "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != digest:
                    problems.append(f"{name}: not the copy recorded")
        except OSError as exc:
            problems.append(f"{name}: {type(exc).__name__}")
    return problems


# ---------------------------------------------------------------- one document checked
def _printable(text, limit=200):
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


def verify(registry, document, digest_hex):
    """The attestations of one file (`document`: the registry's answer, text; `digest_hex`: the file's SHA-512 for npm,
    SHA-256 for PyPI) checked by the native library -> [{"predicateType", "outcome": "verified" | "invalid" |
    "unchecked", "reason", "signer", "time", "format"}]. Unchecked when nothing in it can be checked (no native
    library, one older than the check, a document that is not attestations)."""
    from lazaret.scanner import _native
    if not _native.available():
        raise Unchecked("no native library")
    root, keys = trust()
    args = {"registry": registry, "document": document, "digest": digest_hex, "root": root,
            "npm_keys": keys if registry == "npm" else None}
    try:
        answer = _native.call("verify.sigstore", args)
    except _native.NativeError as exc:
        if "unknown call" in str(exc):
            raise Unchecked("the native library is older than the check") from None
        raise Unchecked(_printable(str(exc).partition(": ")[2])) from None
    found = answer.get("attestations") if isinstance(answer, dict) else None
    if not isinstance(found, list) or not all(isinstance(a, dict) and a.get("outcome") in ("verified", "invalid", "unchecked")
                                              for a in found):
        raise Unchecked("the check gave an answer it does not give")
    return found


def repository(attestations):
    """The source repository the verified certificate-signed attestations name, {"uri", "id", "owner", "ownerId"} (the
    IDs GitHub's certificates carry, None where there are none), or None. Two that disagree: the first."""
    text = lambda v: v if isinstance(v, str) and v else None                    # noqa: E731
    for a in attestations:
        signer = a.get("signer") if a.get("outcome") == "verified" else None
        if isinstance(signer, dict) and signer.get("kind") == "certificate" and text(signer.get("repository")):
            return {"uri": signer["repository"], "id": text(signer.get("repositoryId")), "owner": text(signer.get("owner")),
                    "ownerId": text(signer.get("ownerId"))}
    return None


def _norm(uri):
    return uri.lower().rstrip("/").removesuffix(".git")


def same_repository(a, b):
    """Do two repositories (see `repository`) name one? By ID when both have one (a rename or a transfer keeps it),
    else by the URI, without case or a trailing `.git` or slash."""
    if a.get("id") and b.get("id"):
        return a["id"] == b["id"]
    return _norm(a["uri"]) == _norm(b["uri"])


def same_owner(a, b):
    """Are two repositories the same owner's (an organization or account)? By the owner's ID when both have one, else
    by the URI's owner part (`https://host/<owner>/...`)."""
    if a.get("ownerId") and b.get("ownerId"):
        return a["ownerId"] == b["ownerId"]
    owner = lambda r: _norm(r.get("owner") or r["uri"].rsplit("/", 1)[0])       # noqa: E731
    return owner(a) == owner(b)


# ---------------------------------------------------------------- npm
def _npm_url(name, version):
    return ("https://registry.npmjs.org/-/npm/v1/attestations/" + urllib.parse.quote(name, safe="@")
            + "@" + urllib.parse.quote(version, safe=""))


def _npm_packument(name):
    return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")


def npm_has_attestations(manifest):
    dist = manifest.get("dist") if isinstance(manifest, dict) else None
    att = dist.get("attestations") if isinstance(dist, dict) else None
    return isinstance(att, dict) and bool(att)


def npm_previous(versions, version):
    """The highest version of `versions` (a dict of npm version documents) below `version`, by SemVer; a pre-release
    only when `version` is one. None when there is none, or `version` is not SemVer."""
    key = _crates.semver_key(version)
    if key is None:
        return None
    best = None
    for v in versions:
        k = _crates.semver_key(v)
        if k is None or k >= key or (k[3] == 0 and key[3] != 0):
            continue
        if best is None or k > best[0]:
            best = (k, v)
    return best[1] if best else None


def _sri_sha512_hex(integrity):
    """An SRI `sha512-<base64>` (npm's `dist.integrity`, possibly several space-separated) -> hex, or None."""
    for part in (integrity or "").split() if isinstance(integrity, str) else ():
        algo, _, b64 = part.partition("-")
        if algo == "sha512":
            try:
                raw = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError):
                return None
            return raw.hex() if len(raw) == 64 else None
    return None


def check_npm(name, version, manifest, sha512_hex, fetch):
    """An npm release's provenance -> the report (see `release_issues`). `fetch(url, max_bytes, accept)` -> bytes."""
    report = {"files": [], "previous": None}
    here = None
    if npm_has_attestations(manifest):
        try:
            doc = fetch(_npm_url(name, version), MAX_ATTESTATION_BYTES, None).decode("utf-8")
            found = verify("npm", doc, sha512_hex)
            report["files"].append({"filename": None, "attestations": found})
            here = repository(found)
        except (Unchecked, _base.FetchError, UnicodeDecodeError) as exc:
            report["files"].append({"filename": None, "unchecked": _printable(exc)})
    else:
        report["files"].append({"filename": None, "attestations": None})
    try:
        doc = _core.json_loads_bounded(fetch(_npm_packument(name), MAX_PACKUMENT_BYTES, NPM_ABBREVIATED))
    except (_base.FetchError, ValueError, _core.JsonTooDeep) as exc:
        report["previousUnchecked"] = _printable(exc)
        return report
    versions = doc.get("versions") if isinstance(doc, dict) else None
    previous = npm_previous(versions, version) if isinstance(versions, dict) else None
    if previous is None:
        return report
    prev_manifest = versions.get(previous)
    prev = {"version": previous, "provenance": npm_has_attestations(prev_manifest)}
    report["previous"] = prev
    if prev["provenance"] and here is not None:
        digest = _sri_sha512_hex((prev_manifest.get("dist") or {}).get("integrity"))
        try:
            if digest is None:
                raise Unchecked("its dist.integrity is not a SHA-512")
            text = fetch(_npm_url(name, previous), MAX_ATTESTATION_BYTES, None).decode("utf-8")
            prev["repository"] = repository(verify("npm", text, digest))
        except (Unchecked, _base.FetchError, UnicodeDecodeError) as exc:
            prev["unchecked"] = _printable(exc)
    return report


def guard_npm(name, version, sha512_hex, fetch):
    """check_npm for a caller with a lockfile's entry and not the version's document (`lazaret guard`): npm's
    abbreviated document of the package, read once, gives the version's and the release's before it. A document that
    cannot be read, or does not list the version, leaves the release unchecked (said)."""
    cache = {}

    def once(url, max_bytes, accept):
        if url not in cache:
            cache[url] = fetch(url, max_bytes, accept)
        return cache[url]
    try:
        doc = _core.json_loads_bounded(once(_npm_packument(name), MAX_PACKUMENT_BYTES, NPM_ABBREVIATED))
    except (_base.FetchError, ValueError, _core.JsonTooDeep) as exc:
        return {"files": [{"filename": None, "unchecked": f"the registry's document of the package could not be "
                                                         f"read ({_printable(exc, 120)})"}], "previous": None}
    versions = doc.get("versions") if isinstance(doc, dict) else None
    manifest = versions.get(version) if isinstance(versions, dict) else None
    if not isinstance(manifest, dict):
        return {"files": [{"filename": None, "unchecked": "the registry's document of the package does not list the "
                                                         "version"}], "previous": None}
    return check_npm(name, version, manifest, sha512_hex, once)


# ---------------------------------------------------------------- PyPI
def _pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _iso(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


_SDIST_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tar.lzma", ".tlz", ".tgz", ".tbz", ".txz", ".tar", ".zip")


def _pypi_version_of(filename, versions):
    """Which of `versions` (a set) a file of the Simple API is of, from its name: a wheel's or an egg's second
    `-`-separated part (`<name>-<version>-…`), an sdist's last before its suffix (`<name>-<version>.tar.gz`). None
    for a name that carries none of them."""
    if filename.endswith((".whl", ".egg")):
        parts = filename.split("-")
        candidate = parts[1] if len(parts) > 2 else None
    else:
        base = next((filename[:-len(x)] for x in _SDIST_SUFFIXES if filename.endswith(x)), None)
        candidate = base.rsplit("-", 1)[1] if base and "-" in base else None
    return candidate if candidate in versions else None


def pypi_previous(files, version):
    """{version: [file entries]} of the Simple API -> the release uploaded last before `version` (its first file's
    time), a pre-release only for a pre-release, a release with a file that is not yanked; None when there is none or
    no time is known."""
    def first(entries):
        times = [t for t in (_iso(f.get("upload-time")) for f in entries) if t is not None]
        return min(times) if times else None
    when = first(files.get(version, ()))
    if when is None:
        return None
    final = lambda v: bool(_PEP440_FINAL_RE.match(v))                           # noqa: E731
    best = None
    for v, entries in files.items():
        if v == version or (not final(v) and final(version)) or all(f.get("yanked") for f in entries):
            continue                     # (a release whose every file is yanked is one pip does not take)
        t = first(entries)
        if t is not None and t < when and (best is None or t > best[1]):
            best = (v, t)
    return best[0] if best else None


def check_pypi(name, version, digests, fetch):
    """A PyPI release's provenance -> the report (see `release_issues`). `digests`: [(filename, SHA-256 hex)] of the
    files scanned. `fetch(url, max_bytes, accept)` -> bytes."""
    report = {"files": [], "previous": None}
    try:
        doc = _core.json_loads_bounded(fetch(f"https://pypi.org/simple/{_pep503(name)}/", MAX_SIMPLE_BYTES, PYPI_SIMPLE_JSON))
    except (_base.FetchError, ValueError, _core.JsonTooDeep) as exc:
        report["unchecked"] = _printable(exc)
        return report
    entries = [f for f in (doc.get("files") if isinstance(doc, dict) else None) or () if isinstance(f, dict)
               and isinstance(f.get("filename"), str)]
    listed = doc.get("versions") if isinstance(doc, dict) else None
    versions = {v for v in listed if isinstance(v, str)} if isinstance(listed, list) else set()
    by_version = {}
    for f in entries:
        v = _pypi_version_of(f["filename"], versions) if versions else None
        if v is not None:
            by_version.setdefault(v, []).append(f)
    by_name = {f["filename"]: f for f in entries}
    if not any(filename in by_name for filename, _ in digests):
        # (none of the files scanned is in the Simple API's answer: what it says of provenance is not about them, so
        # it says nothing of a provenance dropped either)
        report["unchecked"] = "the release's files are not in the Simple API's answer"
        return report
    for i, (filename, sha256_hex) in enumerate(digests):
        entry = by_name.get(filename)
        url = entry.get("provenance") if entry else None
        if not isinstance(url, str) or not url:
            report["files"].append({"filename": filename, "attestations": None})
            continue
        if i >= MAX_FILES:
            report["files"].append({"filename": filename, "unchecked": f"more than {MAX_FILES} files"})
            continue
        try:
            text = fetch(_pypi_provenance_url(name, version, filename, url), MAX_ATTESTATION_BYTES, None).decode("utf-8")
            report["files"].append({"filename": filename, "attestations": verify("pypi", text, sha256_hex)})
        except (Unchecked, _base.FetchError, UnicodeDecodeError) as exc:
            report["files"].append({"filename": filename, "unchecked": _printable(exc)})
    previous = pypi_previous(by_version, version)
    if previous is None:
        return report
    with_provenance = [f for f in by_version[previous] if isinstance(f.get("provenance"), str) and f["provenance"]]
    prev = {"version": previous, "provenance": bool(with_provenance)}
    report["previous"] = prev
    here = next((r for r in (repository(f.get("attestations") or ()) for f in report["files"]) if r), None)
    if with_provenance and here is not None:
        f = with_provenance[0]
        digest = (f.get("hashes") or {}).get("sha256") if isinstance(f.get("hashes"), dict) else None
        try:
            if not (isinstance(digest, str) and len(digest) == 64 and _HEX_RE.fullmatch(digest)):
                raise Unchecked("its file has no SHA-256")
            text = fetch(_pypi_provenance_url(name, previous, f["filename"], f["provenance"]), MAX_ATTESTATION_BYTES,
                         None).decode("utf-8")
            prev["repository"] = repository(verify("pypi", text, digest))
        except (Unchecked, _base.FetchError, UnicodeDecodeError) as exc:
            prev["unchecked"] = _printable(exc)
    return report


def _pypi_provenance_url(name, version, filename, listed):
    """The integrity API's URL for a file. The Simple API's own URL is used when it is that one on pypi.org; else the
    one PEP 740 defines."""
    made = (f"https://pypi.org/integrity/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/"
            f"{urllib.parse.quote(filename, safe='')}/provenance")
    parts = urllib.parse.urlsplit(listed)
    if parts.scheme == "https" and parts.hostname == "pypi.org" and parts.path.startswith("/integrity/") \
            and parts.path.endswith("/provenance") and not parts.query and not parts.fragment:
        return listed
    return made


# ---------------------------------------------------------------- the findings
WHY_UNCHECKED = ("An attestation is checked against Sigstore's trusted root and npm's keys as this Lazaret ships them; one "
                 "signed through a log, authority or key added since, or in a form not read here, cannot be checked. "
                 "That says nothing against the file, which is why this is not SC-PROVENANCE-INVALID.")


def _issue(rule, sev, title, msg, fix, where="(release)"):
    why = WHY_UNCHECKED if rule == "SC-PROVENANCE-UNCHECKED" else WHY
    return _core.mk_issue({"id": rule, "name": title, "type": "HOTSPOT", "sev": sev, "msg": msg, "why": why, "fix": fix,
                           "ref": "CWE-494 · Supply chain"}, where, 1, [])


def _what(attestation):
    signer = attestation.get("signer") or {}
    if signer.get("kind") == "key":
        return f"the registry's key {signer.get('id')}"
    parts = [signer.get("repository") or "an unknown repository"]
    if signer.get("workflow"):
        parts.append(f"workflow {signer['workflow']}")
    return ", ".join(parts)


def release_issues(eco, name, version, report):
    """(issues, the result's `provenance`) for a release from its report."""
    issues = []
    has_any, verified = False, []
    for f in report.get("files", ()):
        where = f.get("filename") or "(release)"
        shown = _printable(where, 120)
        if f.get("unchecked"):
            has_any = True
            issues.append(_issue("SC-PROVENANCE-UNCHECKED", "INFO", "Provenance that could not be checked",
                                 f"The provenance of {shown} could not be checked: {f['unchecked']}.",
                                 "Nothing to do for this release; a newer Lazaret (or LAZARET_SIGSTORE_ROOT) may "
                                 "know the log or authority.", where))
            continue
        for a in f.get("attestations") or ():
            has_any = True
            if a["outcome"] == "verified":
                verified.append(a)
            elif a["outcome"] == "invalid":
                issues.append(_issue("SC-PROVENANCE-INVALID", "CRITICAL", "Provenance that is not about this file",
                                     f"An attestation of {shown} ({_printable(a.get('predicateType'), 80)}) does not "
                                     f"hold for it: {_printable(a.get('reason'))}. The file is not the one that was "
                                     "built and signed.",
                                     "Do not install this release; report it to the registry.", where))
            else:
                issues.append(_issue("SC-PROVENANCE-UNCHECKED", "INFO", "Provenance that could not be checked",
                                     f"An attestation of {shown} ({_printable(a.get('predicateType'), 80)}) could not "
                                     f"be checked: {_printable(a.get('reason'))}.",
                                     "Nothing to do for this release; a newer Lazaret (or LAZARET_SIGSTORE_ROOT) may "
                                     "know the log or authority.", where))
    prev = report.get("previous")
    if prev and prev.get("provenance") and not has_any:
        issues.append(_issue("SC-PROVENANCE-DROPPED", "MAJOR", "A release without the provenance the one before had",
                             f"{version} has no provenance, though {prev['version']}, the release before it, has: it "
                             f"was not published the way {prev['version']} was.",
                             f"Find out how {version} was published before installing it; pin {prev['version']} "
                             "until you have."))
    here = repository(verified)
    there = prev.get("repository") if prev else None
    if here is not None and there and not same_repository(here, there):
        # (a move within the owner's repositories, as projects do for a release repository or a monorepo split, is
        # said and does not count; one to another owner's does)
        moved = same_owner(here, there)
        issues.append(_issue("SC-PROVENANCE-REPO-CHANGED", "INFO" if moved else "MAJOR",
                             "Provenance from another repository",
                             f"{version} was built from {_printable(here['uri'], 120)}, and {prev['version']}, the release "
                             f"before it, from {_printable(there['uri'], 120)}"
                             + (", a repository of the same owner." if moved else ", another owner's."),
                             f"Check that {_printable(here['uri'], 120)} is the project's; pin {prev['version']} until "
                             "you have."))
    summary = {"verified": [{"predicateType": a.get("predicateType"), "signer": a.get("signer"), "time": a.get("time")}
                            for a in verified],
               "files": [{"filename": f.get("filename"),
                          "status": ("unchecked" if f.get("unchecked") else "none" if not f.get("attestations") else
                                     "invalid" if any(a["outcome"] == "invalid" for a in f["attestations"]) else
                                     "verified" if all(a["outcome"] == "verified" for a in f["attestations"]) else
                                     "partly checked")}
                         for f in report.get("files", ())],
               "previous": dict(prev) if prev else None}
    if here is not None:
        summary["repository"] = here["uri"]
    for key in ("unchecked", "previousUnchecked"):
        if report.get(key):
            summary[key] = report[key]
    return issues, summary


def check_release(eco, name, version, resolved, digests, fetch):
    """(issues, the result's `provenance`) for an npm or PyPI release; ([], None) for another registry or with
    LAZARET_NO_PROVENANCE=1. `digests`: [(filename, hex)] of the files scanned (npm: the tarball's SHA-512; PyPI:
    each file's SHA-256)."""
    if not enabled() or eco not in ("npm", "pypi") or not digests:
        return [], None
    if eco == "npm":
        report = check_npm(name, version, resolved[4], digests[0][1], fetch)
    else:
        report = check_pypi(name, version, digests, fetch)
    return release_issues(eco, name, version, report)


def line(summary):
    """What print_scan says of a release's provenance, or None."""
    if not summary:
        return None
    statuses = {f["status"] for f in summary.get("files", ())}
    prev = summary.get("previous") or {}
    if summary.get("repository"):
        signer = next((v["signer"] for v in summary.get("verified", ()) if (v.get("signer") or {}).get("kind") == "certificate"), {})
        how = f" ({signer['workflow']})" if signer.get("workflow") else ""
        return f"Provenance: built from {summary['repository']}{how}, verified"
    if statuses == {"none"}:
        if prev.get("provenance"):
            return f"Provenance: none, though {prev['version']} (the release before) has it"
        return "Provenance: none published"
    if "invalid" in statuses:
        return "Provenance: an attestation does not hold for the file"
    if "unchecked" in statuses or summary.get("unchecked"):
        return "Provenance: could not be checked"
    return None
