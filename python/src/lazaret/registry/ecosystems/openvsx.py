"""Open VSX (0.1.9, E-1's second part): resolving a VS Code extension to its `.vsix` files, one per platform it is
published for, each checked against the SHA-256 the registry publishes beside it before anything is scanned.

    names        `namespace.name`, each part a letter or a digit and then letters, digits or `-` (VS Code's identifier
                 pattern: an extension the editor would not install is not one to scan), at most 128 characters each.
                 Open VSX and the editor compare them without case; `identity` lowercases.
    versions     the base rule (`[A-Za-z0-9._-]`, at most 100 characters); the editor's are SemVer.
    the API      `https://open-vsx.org/api/<namespace>/<name>`: the latest version as Open VSX names it (a pre-release
                 can be the latest: `versionAlias`), `/<version>` for another. `downloads` maps each target platform
                 the version is published for to its `.vsix`; `/api/<namespace>/<name>/<platform>/<version>` is one
                 platform's document, and its `files.sha256` names that file's digest. `verified` says the namespace
                 has an owner and the publisher is one of them; `dependencies` and `bundledExtensions` are the
                 extensions it needs to activate and the members of its pack.
    the gallery  `https://open-vsx.org/vscode/gallery`, the gallery VSCodium's product.json names: VS Code's query
                 (POST `extensionquery`, the Marketplace's protocol) answered in the Marketplace's shape. Read for one
                 thing, the `extensionId` the editor keeps for an extension it installed from there (`gallery_id`).
    the files    the API's file URLs answer with a redirect to the content host, `openvsx.eclipsecontent.org`: the
                 `.vsix`, and `<file>.sha256`, the hex SHA-256 of the `.vsix` and nothing else.
    the archive  a zip; every member whose name begins with `extension` is the extension's, those letters taken off,
                 a `/` after them or not (`base.vsix_member_path`: `repo.canonical_member_path`'s `vsix` rule, and
                 `member_path` here). VS Code writes every entry as a regular file: no link is created.
    what runs    as `lazaret FILE.vsix` reads it (repo.py's `vsix` kind): `main` and `browser` when the editor activates
                 the extension, `vscode:uninstall` only as `node <file>`, npm's scripts never.

Every platform's file is scanned, as every wheel of a PyPI release is: the editor installs the one for its platform,
and a payload can sit in one of them only. A platform the editor does not know is not a file it installs, and is listed
(`skipped`). A file's URL comes from the registry's answer, so it is checked as any request is (https, these two hosts) before it
is taken. Requests to the API are paced (`rate`), as Open VSX asks of anonymous clients; the content host is not.
Nothing is run."""

import hashlib
import re

from lazaret.registry import editorcompat
from lazaret.registry.ecosystems import base

__all__ = ["OpenVSX", "ECOSYSTEM", "API_HOST", "CONTENT_HOST", "API", "GALLERY_QUERY_URL", "TARGET_PLATFORMS",
           "MAX_PART", "gallery_query", "gallery_identifier"]

API_HOST = "open-vsx.org"
CONTENT_HOST = "openvsx.eclipsecontent.org"
API = f"https://{API_HOST}/api"
#: Open VSX's VS Code gallery (VSCodium's `extensionsGallery.serviceUrl` plus `/extensionquery`)
GALLERY_QUERY_URL = f"https://{API_HOST}/vscode/gallery/extensionquery"
#: VS Code's own Accept header for a gallery query
GALLERY_ACCEPT = "application/json;api-version=3.0-preview.1"
MAX_PART = 128
#: The target platforms VS Code installs a `.vsix` for (its TargetPlatform values); `universal` runs on all of them.
TARGET_PLATFORMS = frozenset(("universal", "web", "win32-x64", "win32-arm64", "win32-ia32", "linux-x64", "linux-arm64",
                              "linux-armhf", "alpine-x64", "alpine-arm64", "darwin-x64", "darwin-arm64"))
MAX_PLATFORMS = 32                       # the files of one version that are scanned or listed
MAX_LISTED = 500                         # the extensions it needs, the members of its pack
MAX_DIGEST_BYTES = 1024                  # a `.sha256` file is 64 hex digits
HISTORY_PAGE = 1000                      # the query API's largest page
MAX_HISTORY = 5000                       # the versions' entries (each per platform) a history reads

_PART_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_NAME_CHAR = re.compile(r"[A-Za-z0-9.-]")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_PLATFORM_RE = re.compile(r"[a-z0-9]{1,16}(?:-[a-z0-9]{1,16}){0,3}")
_GALLERY_ID_RE = re.compile(r"[A-Za-z0-9-]{1,100}")


def _text(value, limit=200):
    return value if isinstance(value, str) and len(value) <= limit else None


def gallery_query(name, flags):
    """The body of the query VS Code sends a gallery for one extension by its name (filter type 7) among VS Code's
    (filter type 8), unpublished ones left out (filter type 12, flag 4096), with query `flags`."""
    return {"filters": [{"criteria": [{"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                                      {"filterType": 7, "value": name},
                                      {"filterType": 12, "value": "4096"}],
                         "pageNumber": 1, "pageSize": 1, "sortBy": 0, "sortOrder": 0}],
            "assetTypes": [], "flags": flags}


def gallery_extension(doc, name, label):
    """The extension `name` from a gallery's answer to `gallery_query`, its shape checked: one extension, this one
    (its publisher's and its own name, without case). NotFound when the answer lists none; FetchError otherwise."""
    results = doc.get("results") if isinstance(doc, dict) else None
    first = results[0] if isinstance(results, list) and results else None
    exts = first.get("extensions") if isinstance(first, dict) else None
    if not isinstance(exts, list):
        raise base.FetchError(f"{label}'s answer is not a list of extensions")
    if not exts:
        raise base.NotFound(f"{label} has no such extension")
    ext = exts[0]
    publisher = ext.get("publisher") if isinstance(ext, dict) else None
    pub = publisher.get("publisherName") if isinstance(publisher, dict) else None
    got = ext.get("extensionName") if isinstance(ext, dict) else None
    if not (isinstance(pub, str) and isinstance(got, str) and f"{pub}.{got}".lower() == name.lower()):
        raise base.FetchError(f"{label}'s answer is about another extension")
    return ext


def gallery_identifier(ext, label):
    """The `extensionId` of a gallery's extension entry, as VS Code keeps it (and compares it, as it is); FetchError
    when there is none, or it is not one."""
    value = ext.get("extensionId") if isinstance(ext, dict) else None
    if not (isinstance(value, str) and _GALLERY_ID_RE.fullmatch(value)):
        raise base.FetchError(f"{label}'s answer gives the extension no identifier")
    return value


class OpenVSX(base.Ecosystem):
    id = "openvsx"
    title = "Open VSX"
    hosts = frozenset({API_HOST, CONTENT_HOST})
    artifact_kinds = ("vsix",)
    rate = {API_HOST: 0.5}
    manifest_names = frozenset({"package.json"})

    # ---- names and versions
    def check_name(self, name):
        name = base.ascii_name(name, "extension name", _NAME_CHAR, 2 * MAX_PART + 1, self.id)
        parts = name.split(".")
        if len(parts) != 2 or not all(_PART_RE.fullmatch(p) and len(p) <= MAX_PART for p in parts):
            raise base.SpecError("openvsx: an extension is namespace.name, each part a letter or a digit and then "
                                 "letters, digits or '-'")
        return name

    def identity(self, name):
        return self.check_name(name).lower()

    def _id(self, value):
        """An extension the API names ({"namespace", "extension"}) as `namespace.name`, lowercase; None for one that
        is not an extension's identifier."""
        if not isinstance(value, dict):
            return None
        ns, ext = value.get("namespace"), value.get("extension")
        if not (isinstance(ns, str) and isinstance(ext, str)):
            return None
        try:
            return self.identity(f"{ns}.{ext}")
        except base.SpecError:
            return None

    # ---- the network
    def _document(self, url, fetch, ns, ext, version=None, platform=None):
        """One version's document from the API, its shape checked: an object naming this extension, a version (the
        one asked for, when one was), a target platform (the one asked for, when one was), and the URLs of its file
        and of that file's digest. FetchError otherwise."""
        doc = fetch.json(url, accept="application/json")
        if not isinstance(doc, dict):
            raise base.FetchError("openvsx: the registry's answer is not an object")
        if isinstance(doc.get("error"), str):
            raise base.FetchError(f"openvsx: the registry answered with an error: {base.show(doc['error'])}")
        got_ns, got_ext = doc.get("namespace"), doc.get("name")
        if not (isinstance(got_ns, str) and isinstance(got_ext, str)
                and got_ns.lower() == ns.lower() and got_ext.lower() == ext.lower()):
            raise base.FetchError("openvsx: the registry's answer is about another extension")
        got = doc.get("version")
        try:
            got = self.check_version(got) if isinstance(got, str) else None
        except base.SpecError:
            got = None
        if got is None or (version is not None and got != version):
            raise base.FetchError("openvsx: the registry's answer has no version, a wrong one or another one")
        target = doc.get("targetPlatform", "universal")
        if not isinstance(target, str) or not _PLATFORM_RE.fullmatch(target) or (platform and target != platform):
            raise base.FetchError("openvsx: the registry's answer has no target platform, a wrong one or another one")
        files = doc.get("files")
        if not (isinstance(files, dict) and isinstance(files.get("download"), str)
                and isinstance(files.get("sha256"), str)):
            raise base.FetchError("openvsx: the registry's answer names no file, or no digest for it")
        if doc.get("downloadable") is False:
            raise base.FetchError("openvsx: the registry does not serve this version's file")
        return doc

    def _digest(self, url, fetch):
        text = fetch.text(url, max_bytes=MAX_DIGEST_BYTES).strip()
        if not _SHA256_RE.fullmatch(text):
            raise base.FetchError("openvsx: the digest the registry published is not a SHA-256")
        return text.lower()

    def resolve(self, name, version, fetch):
        ns, ext = self.check_name(name).split(".")
        want = self.check_version(version)
        root = f"{API}/{self.segment(ns)}/{self.segment(ext)}"
        doc = self._document(root + (f"/{self.segment(want)}" if want else ""), fetch, ns, ext, want)
        version = doc["version"]
        downloads = doc.get("downloads")
        if not isinstance(downloads, dict) or not downloads:
            downloads = {doc.get("targetPlatform", "universal"): doc["files"]["download"]}
        artifacts, skipped = [], []
        for platform in sorted(downloads)[:MAX_PLATFORMS]:
            if not (isinstance(downloads[platform], str) and _PLATFORM_RE.fullmatch(platform)):
                raise base.FetchError("openvsx: the registry's answer names a file for a platform that is not one")
            filename = f"{ns}.{ext}-{version}" + ("" if platform == "universal" else f"@{platform}") + ".vsix"
            if platform not in TARGET_PLATFORMS:
                skipped.append({"filename": filename, "packagetype": "vsix", "installable": False, "size": None,
                                "reason": "a target platform the editor does not install"})
                continue
            if platform == doc.get("targetPlatform", "universal"):
                pdoc = doc
            else:
                pdoc = self._document(f"{root}/{self.segment(platform)}/{self.segment(version)}", fetch, ns, ext,
                                      version, platform)
            download = fetch.check_url(pdoc["files"]["download"])
            entry = {"sha256": self._digest(pdoc["files"]["sha256"], fetch), "platform": platform}
            artifacts.append({"url": download, "container": "zip", "artifact": "vsix", "entry": entry,
                              "filename": filename})
        if not artifacts:
            raise base.FetchError("openvsx: the version has no file for a platform the editor installs")
        publisher = doc.get("publishedBy") if isinstance(doc.get("publishedBy"), dict) else {}
        listed = {}
        for key in ("dependencies", "bundledExtensions"):
            value = doc.get(key)
            ids = (self._id(v) for v in value[:MAX_LISTED]) if isinstance(value, list) else ()
            listed[key] = sorted({i for i in ids if i})
        info = {"name": f"{doc['namespace']}.{doc['name']}", "verified": doc.get("verified") is True,
                "unrelatedPublisher": doc.get("unrelatedPublisher") is True,
                "publishedBy": _text(publisher.get("loginName"), 100), "provider": _text(publisher.get("provider"), 40),
                "preRelease": doc.get("preRelease") is True, "deprecated": doc.get("deprecated") is True,
                "timestamp": _text(doc.get("timestamp"), 40), **listed}
        return base.Resolution(version, artifacts, skipped, info)

    def verify(self, data, entry, name, version):
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            return None
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest.lower():
            raise base.DigestError(f"openvsx: the SHA-256 of the download does not match the one Open VSX published "
                                   f"for {base.show(name)} {base.show(version)}")
        return "sha256", actual

    def dependencies(self, resolved, fetch):
        """The extensions a version brings: those it needs to activate (`extensionDependencies`) and the members of its
        pack (`extensionPack`), as the API lists them, `namespace.name` in lowercase."""
        info = getattr(resolved, "info", None)
        if not isinstance(info, dict):
            return None
        return tuple(sorted(set(info.get("dependencies") or ()) | set(info.get("bundledExtensions") or ())))

    # ---- the history (SC-NEW-DEPENDENCY, E-1's third part)
    def _query(self, name, fetch, offset, size, version=None):
        """One page of the query API's answer for every version of `name` (one entry per version and platform), or for
        one `version`'s (its files only, `extensionVersion`): (the entries, how many there are in all). FetchError for
        an answer of another shape."""
        ns, ext = self.check_name(name).split(".")
        url = (f"{API}/-/query?extensionId={self.segment(ns)}.{self.segment(ext)}"
               + (f"&extensionVersion={self.segment(version)}" if version is not None else "&includeAllVersions=true")
               + f"&size={size}&offset={offset}")
        doc = fetch.json(url, accept="application/json")
        entries = doc.get("extensions") if isinstance(doc, dict) else None
        total = doc.get("totalSize") if isinstance(doc, dict) else None
        if not isinstance(entries, list) or not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise base.FetchError("openvsx: the registry's answer to a query is not a list of versions")
        mine = []
        for e in entries[:size]:
            if isinstance(e, dict) and isinstance(e.get("namespace"), str) and isinstance(e.get("name"), str) \
                    and f"{e['namespace']}.{e['name']}".lower() == name.lower():
                mine.append(e)
        return mine, total

    def _entry(self, e):
        """A query entry as the history keeps it: (version, when it was published (an aware datetime), the extensions
        it brings, a pre-release?, who published it), None for one without a version or a time."""
        version, when = e.get("version"), base.parse_time(e.get("timestamp"))
        try:
            version = self.check_version(version) if isinstance(version, str) else None
        except base.SpecError:
            version = None
        if version is None or when is None:
            return None
        brings = set()
        for key in ("dependencies", "bundledExtensions"):
            value = e.get(key)
            brings.update(i for i in ((self._id(v) for v in value[:MAX_LISTED]) if isinstance(value, list) else ()) if i)
        by = e.get("publishedBy") if isinstance(e.get("publishedBy"), dict) else {}
        return version, when, brings, e.get("preRelease") is True, _text(by.get("loginName"), 100)

    def history(self, name, fetch):
        """Every version of `name` the registry lists, newest first as it answers: [(version, when it was published,
        the extensions it brings, a pre-release?, who published it)], one per version (a version's platforms together: the earliest
        time, the extensions any of them brings). At most MAX_HISTORY entries are read."""
        out, seen, offset = [], {}, 0
        while offset < MAX_HISTORY:
            entries, total = self._query(name, fetch, offset, HISTORY_PAGE)
            for e in entries:
                kept = self._entry(e)
                if kept is None:
                    continue
                version, when, brings, pre, by = kept
                if version in seen:
                    old = out[seen[version]]
                    out[seen[version]] = (version, min(old[1], when), old[2] | brings, old[3] or pre, old[4] or by)
                else:
                    seen[version] = len(out)
                    out.append(kept)
            offset += HISTORY_PAGE
            if offset >= total or not entries:
                break
        return out

    def first_published(self, name, fetch, old_enough=None):
        """(when the earliest version the registry lists was published, an aware datetime, who published the versions
        read) of `name`; (None, ()) when it lists none. The query's last page is read first (the oldest, as the
        registry answers newest first). Any version is no older than the first, so when `old_enough` (a test of a
        datetime) says that page's earliest is old enough, that is the answer; else every page is read (at most
        MAX_HISTORY entries), so that an order of the registry's own cannot hide an older version."""
        _first, total = self._query(name, fetch, 0, 1)
        if total == 0:
            return None, ()
        start = max(0, total - HISTORY_PAGE)
        entries, _total = self._query(name, fetch, start, HISTORY_PAGE)
        kept = [k for k in (self._entry(e) for e in entries) if k is not None]
        times = sorted(k[1] for k in kept)
        if start > 0 and not (times and old_enough is not None and old_enough(times[0])):
            kept = self.history(name, fetch)
            times = sorted(k[1] for k in kept)
        return (times[0] if times else None), tuple(sorted({k[4] for k in kept if k[4]}))

    # ---- what an editor chooses among (`lazaret guard code --install-extension`, E-1's fifth part)
    def _candidate(self, e):
        """A query entry as a file the editor may install (editorcompat.Candidate), with its file's, its digest's and
        its manifest's URLs; None for an entry without a version, a platform, or those URLs, or one the registry does
        not serve."""
        try:
            version = self.check_version(e.get("version")) if isinstance(e.get("version"), str) else None
        except base.SpecError:
            version = None
        platform = e.get("targetPlatform", "universal")
        files = e.get("files") if isinstance(e.get("files"), dict) else {}
        if version is None or not (isinstance(platform, str) and _PLATFORM_RE.fullmatch(platform)) \
                or e.get("downloadable") is False \
                or not all(isinstance(files.get(k), str) for k in ("download", "sha256")):
            return None
        engines = e.get("engines") if isinstance(e.get("engines"), dict) else {}
        refs = {"download": files["download"], "sha256": files["sha256"], "manifest": _text(files.get("manifest"), 2048)}
        return editorcompat.Candidate(version, platform, _text(engines.get("vscode"), 100), e.get("preRelease") is True,
                                      base.parse_time(e.get("timestamp")), refs)

    def candidates(self, name, fetch, version=None):
        """The files of `name`'s versions as an editor chooses among them (editorcompat.choose), in rounds: an iterator
        of lists, each holding every file read so far. With `version`, one round: that version's files. Else page by
        page, newest first as the registry answers, at most MAX_HISTORY entries; the caller stops at the first round
        that holds the file it wants. NotFound when the registry lists no file of the extension (or of the version)."""
        offset, out = 0, []
        while offset < MAX_HISTORY:
            entries, total = self._query(name, fetch, offset, HISTORY_PAGE if version is None else MAX_PLATFORMS, version)
            if total == 0 and offset == 0:
                raise base.NotFound("openvsx: the registry has no such extension" if version is None
                                    else "openvsx: the registry has no such version of the extension")
            out.extend(c for c in (self._candidate(e) for e in entries) if c is not None)
            yield list(out)
            if version is not None:
                return
            offset += HISTORY_PAGE
            if offset >= total or not entries:
                return

    def artifact(self, name, candidate, fetch):
        """The file of a candidate as `resolve` gives each platform's: its URL checked, its SHA-256 read from the
        registry (the `.sha256` beside it), for `verify`."""
        ns, ext = self.check_name(name).split(".")
        platform = candidate.platform
        filename = f"{ns}.{ext}-{candidate.version}" + ("" if platform == "universal" else f"@{platform}") + ".vsix"
        download = fetch.check_url(candidate.entry["download"])
        entry = {"sha256": self._digest(candidate.entry["sha256"], fetch), "platform": platform}
        return {"url": download, "container": "zip", "artifact": "vsix", "entry": entry, "filename": filename}

    def manifest(self, name, candidate, fetch):
        """A candidate's package.json as the registry serves it beside the file (what the editor reads of a version
        it does not download: the extensions an installed pack member's newest version brings). FetchError when the
        registry names none."""
        url = candidate.entry.get("manifest")
        if not url:
            raise base.FetchError("openvsx: the registry names no manifest for the version")
        return fetch.json(url, accept="application/json")

    def gallery_id(self, name, fetch):
        """The identifier Open VSX's VS Code gallery gives `name` (its `extensionId`): the one an editor keeps for an
        extension it installed from that gallery, and asks the gallery by when it updates it (`lazaret guard codium
        --update-extensions`). VS Code's query, without versions (flags 0). NotFound when the gallery has no such
        extension; FetchError for an answer without one."""
        name = self.check_name(name)
        doc = fetch.post_json(GALLERY_QUERY_URL, gallery_query(name, 0), accept=GALLERY_ACCEPT)
        return gallery_identifier(gallery_extension(doc, name, "openvsx: the gallery"), "openvsx: the gallery")

    # ---- archives
    def container(self, filename):
        return "zip" if isinstance(filename, str) and filename.lower().endswith(".vsix") else None

    def member_path(self, kind, name, root=None):
        """VS Code unpacks every member whose name begins with `extension`, those letters taken off, and nothing else
        (`base.vsix_member_path`)."""
        return base.vsix_member_path(name)

    def links_extracted(self, kind):
        return False


ECOSYSTEM = OpenVSX()
