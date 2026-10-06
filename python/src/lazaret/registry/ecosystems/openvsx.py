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
    the files    the API's file URLs answer with a redirect to the content host, `openvsx.eclipsecontent.org`: the
                 `.vsix`, and `<file>.sha256`, the hex SHA-256 of the `.vsix` and nothing else.
    the archive  a zip; what is under `extension/` is the extension (`repo.canonical_member_path`'s `vsix` rule, and
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

from lazaret.registry.ecosystems import base

__all__ = ["OpenVSX", "ECOSYSTEM", "API_HOST", "CONTENT_HOST", "API", "TARGET_PLATFORMS", "MAX_PART"]

API_HOST = "open-vsx.org"
CONTENT_HOST = "openvsx.eclipsecontent.org"
API = f"https://{API_HOST}/api"
MAX_PART = 128
#: The target platforms VS Code installs a `.vsix` for (its TargetPlatform values); `universal` runs on all of them.
TARGET_PLATFORMS = frozenset(("universal", "web", "win32-x64", "win32-arm64", "win32-ia32", "linux-x64", "linux-arm64",
                              "linux-armhf", "alpine-x64", "alpine-arm64", "darwin-x64", "darwin-arm64"))
MAX_PLATFORMS = 32                       # the files of one version that are scanned or listed
MAX_LISTED = 500                         # the extensions it needs, the members of its pack
MAX_DIGEST_BYTES = 1024                  # a `.sha256` file is 64 hex digits

_PART_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_NAME_CHAR = re.compile(r"[A-Za-z0-9.-]")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_PLATFORM_RE = re.compile(r"[a-z0-9]{1,16}(?:-[a-z0-9]{1,16}){0,3}")


def _text(value, limit=200):
    return value if isinstance(value, str) and len(value) <= limit else None


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

    # ---- archives
    def container(self, filename):
        return "zip" if isinstance(filename, str) and filename.lower().endswith(".vsix") else None

    def member_path(self, kind, name, root=None):
        """VS Code unpacks what is under `extension/` and nothing else."""
        parts = [x for x in str(name).replace("\\", "/").split("/") if x not in ("", ".")]
        if len(parts) < 2 or parts[0] != "extension":
            return None, None
        return base.finish_member_path("/".join(parts[1:]))

    def links_extracted(self, kind):
        return False


ECOSYSTEM = OpenVSX()
