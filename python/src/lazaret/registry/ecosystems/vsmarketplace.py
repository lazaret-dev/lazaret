"""The Visual Studio Marketplace (0.1.9, E-1's second part; decision 11 of the 0.1.9 backlog): resolving a VS Code
extension to its `.vsix` files, one per platform it is published for, through the Marketplace's public gallery API,
the way VS Code asks it.

    names        `publisher.name`, VS Code's identifier pattern (as `openvsx.py`'s); the Marketplace and the editor
                 compare them without case, and `identity` lowercases.
    versions     the base rule (`[A-Za-z0-9._-]`, at most 100 characters); the editor's are SemVer.
    the API      POST `https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery`, the query VS Code
                 sends: the extension by its name (filter type 7, `publisher.name`) among VS Code's (filter type 8,
                 `Microsoft.VisualStudio.Code`), unpublished ones left out (filter type 12, flag 4096), with its
                 versions, their files, properties and asset URIs, and its statistics (query flags 1, 2, 16, 128,
                 256); versions that failed the Marketplace's validation are left out (32). With no version asked
                 for, the latest release and the latest pre-release only (65536): VS Code installs the release, so
                 that is the one taken, and the pre-release when no release exists. A version is one entry per
                 target platform it is published for (`targetPlatform`; an entry without one is universal).
    the files    each entry's `Microsoft.VisualStudio.Services.VSIXPackage` file, on the publisher's CDN host
                 (`<publisher>.gallerycdn.vsassets.io`), else the entry's fallback asset URI and that asset name
                 (`<publisher>.gallery.vsassets.io`, as VS Code falls back), its target platform asked for; a URL
                 from the answer is checked as any request is (https, these hosts) before it is taken.
    no digest    the Marketplace publishes no digest for a download (it signs each package, a `.sigzip` that VS
                 Code checks with vsce-sign; that signature is not checked here), so its files are scanned
                 unverified, and the result says so (`registryInfo.digest` is None).
    what it says the publisher, whether its domain is verified, the install count, a pre-release, and the
                 extensions the version needs (`Microsoft.VisualStudio.Code.ExtensionDependencies`) and packs
                 (`Microsoft.VisualStudio.Code.ExtensionPack`), as `publisher.name` in lowercase.
    the archive  as Open VSX's: a zip, and every member whose name begins with `extension` is the extension's
                 (`member_path`).

The Marketplace's terms of use say its extensions may be installed and used only with Microsoft's Visual Studio
products; scanning it is the 0.1.9 backlog's decision 11 (not legal advice). Requests to the API are paced (`rate`).
Every platform's file is scanned, as Open VSX's are; a platform the editor does not install is listed (`skipped`).
Nothing is run."""

import re

from lazaret.registry import editorcompat
from lazaret.registry.ecosystems import base
from lazaret.registry.ecosystems.openvsx import TARGET_PLATFORMS, gallery_extension, gallery_identifier, gallery_query

__all__ = ["Marketplace", "ECOSYSTEM", "API_HOST", "QUERY_URL", "CDN_SUFFIX", "FALLBACK_SUFFIX", "VSIX_ASSET", "QUERY_FLAGS",
           "LATEST_ONLY_FLAG", "MAX_PART"]

API_HOST = "marketplace.visualstudio.com"
QUERY_URL = f"https://{API_HOST}/_apis/public/gallery/extensionquery"
#: VS Code's own Accept header for the query
ACCEPT = "application/json;api-version=3.0-preview.1"
CDN_SUFFIX = ".gallerycdn.vsassets.io"
FALLBACK_SUFFIX = ".gallery.vsassets.io"
VSIX_ASSET = "Microsoft.VisualStudio.Services.VSIXPackage"
DEPENDENCIES = "Microsoft.VisualStudio.Code.ExtensionDependencies"
EXTENSION_PACK = "Microsoft.VisualStudio.Code.ExtensionPack"
PRE_RELEASE = "Microsoft.VisualStudio.Code.PreRelease"
ENGINE = "Microsoft.VisualStudio.Code.Engine"
MANIFEST_ASSET = "Microsoft.VisualStudio.Code.Manifest"
#: IncludeVersions | IncludeFiles | IncludeVersionProperties | ExcludeNonValidated | IncludeAssetUri | IncludeStatistics
QUERY_FLAGS = 1 | 2 | 16 | 32 | 128 | 256
#: IncludeLatestPrereleaseAndStableVersionOnly
LATEST_ONLY_FLAG = 65536
#: filter types: the extension's name, the product it is for, flags to leave out (Unpublished)
FILTER_NAME, FILTER_TARGET, FILTER_EXCLUDE_FLAGS = 7, 8, 12
MAX_PART = 128
MAX_QUERY_BYTES = 32 * 1024 * 1024       # every version of a busy extension, each per platform with its files
MAX_VERSIONS = 20000                     # the entries of one answer that are read
MAX_PLATFORMS = 32                       # the files of one version that are scanned or listed
MAX_LISTED = 500                         # the extensions it needs, the members of its pack

_PART_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_NAME_CHAR = re.compile(r"[A-Za-z0-9.-]")
_PLATFORM_RE = re.compile(r"[a-z0-9]{1,16}(?:-[a-z0-9]{1,16}){0,3}")


def _text(value, limit=200):
    return value if isinstance(value, str) and len(value) <= limit else None


def _properties(entry):
    """A version entry's properties ({key: value}, text only)."""
    props = entry.get("properties")
    out = {}
    if isinstance(props, list):
        for p in props[:200]:
            if isinstance(p, dict) and isinstance(p.get("key"), str) and isinstance(p.get("value"), str):
                out.setdefault(p["key"], p["value"])
    return out


class Marketplace(base.Ecosystem):
    id = "vscode"
    title = "Visual Studio Marketplace"
    #: the API's host, and the publishers' CDN and fallback asset hosts (`<publisher>.…`, Microsoft's domains)
    hosts = frozenset({API_HOST, "*" + CDN_SUFFIX, "*" + FALLBACK_SUFFIX})
    artifact_kinds = ("vsix",)
    rate = {API_HOST: 0.5}
    manifest_names = frozenset({"package.json"})

    # ---- names and versions
    def check_name(self, name):
        name = base.ascii_name(name, "extension name", _NAME_CHAR, 2 * MAX_PART + 1, self.id)
        parts = name.split(".")
        if len(parts) != 2 or not all(_PART_RE.fullmatch(p) and len(p) <= MAX_PART for p in parts):
            raise base.SpecError("vscode: an extension is publisher.name, each part a letter or a digit and then "
                                 "letters, digits or '-'")
        return name

    def identity(self, name):
        return self.check_name(name).lower()

    @staticmethod
    def _ids(text):
        """The extensions a property lists (comma-separated `publisher.name`), lowercase; others left out."""
        out = set()
        if not isinstance(text, str):
            return out
        for item in text.split(",")[:MAX_LISTED]:
            item = item.strip()
            parts = item.split(".")
            if len(parts) == 2 and all(_PART_RE.fullmatch(p) and len(p) <= MAX_PART for p in parts):
                out.add(item.lower())
        return out

    # ---- the network
    def _ask(self, name, fetch, flags):
        """The extension's entry from the gallery's answer to a query with `flags`, its shape checked: one extension,
        this one (its publisher's and its own name, without case). FetchError otherwise."""
        doc = fetch.post_json(QUERY_URL, gallery_query(name, flags), max_bytes=MAX_QUERY_BYTES, accept=ACCEPT)
        return gallery_extension(doc, name, "vscode: the Marketplace")

    def _query(self, name, fetch, latest):
        """The extension's entry with its versions (their files, properties and asset URIs) and statistics: _ask's,
        with version entries. FetchError otherwise."""
        ext = self._ask(name, fetch, QUERY_FLAGS | (LATEST_ONLY_FLAG if latest else 0))
        versions = ext.get("versions")
        if not isinstance(versions, list) or not versions:
            raise base.FetchError("vscode: the Marketplace's answer lists no version")
        return ext

    def resolve(self, name, version, fetch):
        name = self.check_name(name)
        want = self.check_version(version)
        ext = self._query(name, fetch, latest=want is None)
        entries = []
        for v in ext["versions"][:MAX_VERSIONS]:
            if not isinstance(v, dict):
                continue
            try:
                got = self.check_version(v.get("version")) if isinstance(v.get("version"), str) else None
            except base.SpecError:
                got = None
            if got is not None:
                entries.append(v)
        why = None                       # (why a pre-release is taken with no version asked for)
        if want is not None:
            chosen = [v for v in entries if v["version"] == want]
            if not chosen:
                raise base.FetchError("vscode: the Marketplace has no such version of the extension")
        else:
            # (newest first, as the gallery answers; the release VS Code installs, else a pre-release)
            releases = [v for v in entries if _properties(v).get(PRE_RELEASE, "").lower() != "true"]
            pool = releases or entries
            why = None if releases else "the extension has no release"
            if not pool:
                raise base.FetchError("vscode: the Marketplace's answer has no version that is one")
            chosen = [v for v in pool if v["version"] == pool[0]["version"]]
        version = chosen[0]["version"]
        pub, got = ext["publisher"]["publisherName"], ext["extensionName"]
        artifacts, skipped, seen = [], [], set()
        for v in sorted(chosen, key=lambda e: str(e.get("targetPlatform") or "universal"))[:MAX_PLATFORMS]:
            platform = v.get("targetPlatform") or "universal"
            if not isinstance(platform, str) or not _PLATFORM_RE.fullmatch(platform):
                raise base.FetchError("vscode: the Marketplace's answer names a file for a platform that is not one")
            if platform in seen:
                continue
            seen.add(platform)
            filename = f"{pub}.{got}-{version}" + ("" if platform == "universal" else f"@{platform}") + ".vsix"
            if platform not in TARGET_PLATFORMS:
                skipped.append({"filename": filename, "packagetype": "vsix", "installable": False, "size": None,
                                "reason": "a target platform the editor does not install"})
                continue
            artifacts.append({"url": fetch.check_url(self._vsix_url(v, platform)), "container": "zip", "artifact": "vsix",
                              "entry": {"platform": platform}, "filename": filename})
        if not artifacts:
            raise base.FetchError("vscode: the version has no file for a platform the editor installs")
        props = _properties(chosen[0])
        publisher = ext["publisher"]
        installs = None
        stats = ext.get("statistics")
        if isinstance(stats, list):
            for s in stats[:100]:
                if isinstance(s, dict) and s.get("statisticName") == "install" and isinstance(s.get("value"), (int, float)) \
                        and not isinstance(s.get("value"), bool):
                    installs = int(s["value"])
                    break
        brings = {}
        for key, prop in (("dependencies", DEPENDENCIES), ("bundledExtensions", EXTENSION_PACK)):
            brings[key] = sorted(set().union(*(self._ids(_properties(v).get(prop)) for v in chosen)))
        info = {"name": f"{pub}.{got}", "publisher": _text(pub, 100), "publisherDisplayName": _text(publisher.get("displayName"), 100),
                "verified": publisher.get("isDomainVerified") is True, "domain": _text(publisher.get("domain"), 200),
                "installs": installs, "preRelease": props.get(PRE_RELEASE, "").lower() == "true",
                "lastUpdated": _text(chosen[0].get("lastUpdated"), 40), "digest": None, **brings}
        if why and info["preRelease"]:
            info["preReleaseReason"] = why
        return base.Resolution(version, artifacts, skipped, info)

    @staticmethod
    def _vsix_url(entry, platform):
        """The `.vsix` of one version entry: its VSIXPackage file, else its fallback asset URI and that asset's name
        (with the target platform asked for, as VS Code asks)."""
        files = entry.get("files")
        if isinstance(files, list):
            for f in files[:100]:
                if isinstance(f, dict) and f.get("assetType") == VSIX_ASSET and isinstance(f.get("source"), str):
                    return f["source"]
        fallback = entry.get("fallbackAssetUri")
        if not isinstance(fallback, str) or not fallback:
            raise base.FetchError("vscode: the Marketplace's answer names no file for the version")
        return f"{fallback.rstrip('/')}/{VSIX_ASSET}" + ("" if platform == "universal" else f"?targetPlatform={platform}")

    def verify(self, data, entry, name, version):
        """The Marketplace publishes no digest for a download: nothing to check (None), and the result says so."""
        return None

    def dependencies(self, resolved, fetch):
        """The extensions a version brings: those it needs to activate (`extensionDependencies`) and the members of its
        pack (`extensionPack`), as the Marketplace lists them, `publisher.name` in lowercase."""
        info = getattr(resolved, "info", None)
        if not isinstance(info, dict):
            return None
        return tuple(sorted(set(info.get("dependencies") or ()) | set(info.get("bundledExtensions") or ())))

    # ---- the history (SC-NEW-DEPENDENCY, E-1's third part)
    def history(self, name, fetch):
        """Every version of `name` the gallery lists (newest first, as it answers): [(version, when it was published
        (an aware datetime: the entry's lastUpdated), the extensions it brings, a pre-release?, None: the gallery does
        not say who)], one per version (a version's platforms together: the earliest time, the extensions any of
        them brings)."""
        ext = self._query(self.check_name(name), fetch, latest=False)
        out, seen = [], {}
        for v in ext["versions"][:MAX_VERSIONS]:
            if not isinstance(v, dict):
                continue
            try:
                version = self.check_version(v.get("version")) if isinstance(v.get("version"), str) else None
            except base.SpecError:
                version = None
            when = base.parse_time(v.get("lastUpdated"))
            if version is None or when is None:
                continue
            props = _properties(v)
            brings = self._ids(props.get(DEPENDENCIES)) | self._ids(props.get(EXTENSION_PACK))
            pre = props.get(PRE_RELEASE, "").lower() == "true"
            if version in seen:
                old = out[seen[version]]
                out[seen[version]] = (version, min(old[1], when), old[2] | brings, old[3] or pre, None)
            else:
                seen[version] = len(out)
                out.append((version, when, brings, pre, None))
        return out

    def first_published(self, name, fetch, old_enough=None):
        """(when `name` was first published, an aware datetime: the gallery's publishedDate, or its releaseDate when
        that is earlier, its publisher) of the extension; (None, (its publisher,)) when the gallery gives neither.
        One query, without versions (flags 0)."""
        ext = self._ask(self.check_name(name), fetch, 0)
        times = sorted(t for t in (base.parse_time(ext.get(k)) for k in ("publishedDate", "releaseDate")) if t)
        return (times[0] if times else None), (ext["publisher"]["publisherName"],)

    def gallery_id(self, name, fetch):
        """The identifier the gallery gives `name` (its `extensionId`): the one VS Code keeps for an extension it
        installed from the gallery, and asks the gallery by when it updates it (`lazaret guard code
        --update-extensions`). One query, without versions (flags 0). NotFound when the gallery has no such extension;
        FetchError for an answer without one."""
        return gallery_identifier(self._ask(self.check_name(name), fetch, 0), "vscode: the Marketplace")

    # ---- what an editor chooses among (`lazaret guard code --install-extension`, E-1's fifth part)
    def _candidates(self, ext):
        """The version entries of a gallery answer as files the editor may install (editorcompat.Candidate, the entry
        kept): an entry that names no platform is for every one (`undefined`, as VS Code reads it)."""
        out = []
        for v in ext["versions"][:MAX_VERSIONS]:
            if not isinstance(v, dict):
                continue
            try:
                version = self.check_version(v.get("version")) if isinstance(v.get("version"), str) else None
            except base.SpecError:
                version = None
            platform = v.get("targetPlatform") or "undefined"
            if version is None or not (isinstance(platform, str) and _PLATFORM_RE.fullmatch(platform)):
                continue
            props = _properties(v)
            out.append(editorcompat.Candidate(version, platform, _text(props.get(ENGINE), 100),
                                              props.get(PRE_RELEASE, "").lower() == "true",
                                              base.parse_time(v.get("lastUpdated")), v))
        return out

    def candidates(self, name, fetch, version=None):
        """The files of `name`'s versions as an editor chooses among them (editorcompat.choose), in rounds, as VS Code
        asks the gallery: with no version, first the latest release and pre-release, then, when none of those is the
        file it wants, every version; with a version, every version (the gallery has no query for one). NotFound when
        the gallery has no such extension."""
        name = self.check_name(name)
        if version is None:
            yield self._candidates(self._query(name, fetch, latest=True))
        yield self._candidates(self._query(name, fetch, latest=False))

    def artifact(self, name, candidate, fetch):
        """The file of a candidate, as `resolve` gives each platform's (no digest: the Marketplace publishes none)."""
        name = self.check_name(name)
        platform = "universal" if candidate.platform == "undefined" else candidate.platform
        filename = f"{name}-{candidate.version}" + ("" if platform == "universal" else f"@{platform}") + ".vsix"
        return {"url": fetch.check_url(self._vsix_url(candidate.entry, platform)), "container": "zip", "artifact": "vsix",
                "entry": {"platform": platform}, "filename": filename}

    def manifest(self, name, candidate, fetch):
        """A candidate's package.json as the gallery serves it (its Manifest asset, else the fallback asset URI's): what
        the editor reads of a version it does not download."""
        url = None
        files = candidate.entry.get("files")
        if isinstance(files, list):
            for f in files[:100]:
                if isinstance(f, dict) and f.get("assetType") == MANIFEST_ASSET and isinstance(f.get("source"), str):
                    url = f["source"]
                    break
        if url is None:
            fallback = candidate.entry.get("fallbackAssetUri")
            if not isinstance(fallback, str) or not fallback:
                raise base.FetchError("vscode: the Marketplace's answer names no manifest for the version")
            url = f"{fallback.rstrip('/')}/{MANIFEST_ASSET}"
        return fetch.json(url, accept="application/json")

    # ---- archives
    def container(self, filename):
        return "zip" if isinstance(filename, str) and filename.lower().endswith(".vsix") else None

    def member_path(self, kind, name, root=None):
        """VS Code unpacks every member whose name begins with `extension`, those letters taken off, and nothing else
        (`base.vsix_member_path`)."""
        return base.vsix_member_path(name)

    def links_extracted(self, kind):
        return False


ECOSYSTEM = Marketplace()
