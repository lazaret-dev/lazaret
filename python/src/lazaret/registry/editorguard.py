"""lazaret guard code --install-extension … (0.1.9, E-1's fifth part): a VS Code extension, and every extension it
brings, checked before the editor installs it.

    lazaret guard code --install-extension ms-python.python
    lazaret guard code --install-extension redhat.java@1.40.0 --install-extension ./my-extension.vsix
    lazaret guard cursor --install-extension rust-lang.rust-analyzer --pre-release
    lazaret guard code --update-extensions
    (and code-insiders, codium, windsurf, kiro and positron)

An extension runs in the editor's extension host with all of the user's access and no sandbox, so the guard does what
the editor's own `--install-extension` does, up to the download, and then has the editor install what it checked:

    which version   the one the editor would install (editorcompat): an extension already installed is left alone
                    unless --force or a version is given, as the editor leaves it; else the newest release (with
                    --pre-release or `@prerelease`, the newest version) that has a file for the editor's platform and
                    whose engines.vscode takes the editor's VS Code version; or the version given.
    what it brings  its extensionDependencies that are not installed and the members of its extensionPack (those its
                    installed version did not list, when it is installed), each at the version the editor would take
                    for it, and what those bring in turn, as the editor walks them (an installed pack member's newest
                    version is read for what it brings); built-in extensions count as installed. A dependency that
                    cannot be installed fails the extension that needs it; a pack member is left out.
                    --do-not-include-pack-dependencies leaves them all out, as the editor does.
    the files       from the registry the editor installs from: the Visual Studio Marketplace for VS Code and VS Code
                    Insiders, Open VSX for the others (each Open VSX file checked against the SHA-256 Open VSX publishes
                    for it first). The editor's product.json, when the guard finds it beside the command, names its
                    gallery and the VS Code version its extensions are checked against (for VSCodium, a product.json in
                    its folder of user data and VSCODE_GALLERY_SERVICE_URL name it too, as VSCodium reads them). An
                    editor that names a gallery the guard does not read (a company's own), or none, is refused unless
                    --gallery says which registry to read: the editor installs its gallery's extension of a name, and
                    the guard would install another registry's, which may be another extension, and would tell that
                    registry the names asked for (EG-8). A `.vsix` named on the command line is read from its file.
    the checks      each file scanned in memory as `lazaret FILE.vsix` scans it (its main and browser modules, and what
                    they load, as what runs when the editor activates it; names like a popular extension's;
                    vscode:uninstall), with the verdict cache, --min-age (the registry's publish time), --trust,
                    --allow-new and --block-warn as for the package managers; and the list of extensions the editor's
                    gallery has found malicious (product.json's controlUrl; the Marketplace's own for its extensions),
                    which the editor applies to what it downloads itself, and not to a file it is given.
    replaced        an extension the gallery's control list says to migrate (`migrateToPreRelease`, a `deprecated`
                    entry with `autoMigrate`, and the product's `defaultChatAgent`: VS Code's Copilot) is not the one
                    the editor installs: it installs the replacement, at its newest version (a pre-release when the
                    list says so), whether the extension was asked for, brought or updated, and so does the guard
                    (EG-7). A `.vsix` given is installed as itself. The list is read once, when first needed. One the
                    list says is malicious is refused first, as the editor refuses it, with no replacement (EG-11).
    the install     nothing is installed when anything is blocked, or under --plan. Otherwise the editor installs the
                    files the guard checked, written to a folder of the user's own (`<editor> --install-extension
                    FILE.vsix`): from VS Code 1.98 on, with --do-not-include-pack-dependencies, so that it fetches
                    nothing itself; before that, those an extension brings first, so that it finds them installed.
                    Then the extensions the editor lists are compared with what was checked: anything else it
                    installed is reported, and the run fails.

`--update-extensions` updates what the editor's own `--update-extensions` updates (VS Code's code read for it, MIT),
checked and installed the same way:

    which ones      each extension the editor lists that came from its gallery, as the editor recorded it when it
                    installed it (the profile's extensions.json: the gallery's identifier for it, whether it follows
                    pre-releases; with --profile, that profile's, and the default's for those installed in every
                    profile). The guard updates them only when it reads the gallery the editor installs from (the one
                    its product.json names, or its own when no product.json is found; --gallery naming another is
                    refused, since every extension installed would be asked for by name: EG-8). The editor asks by that
                    identifier, so one is updated only while the gallery's extension of its name has the same
                    identifier. One installed from a file has no identifier, as a rule (the editor's command line does
                    not wait for the lookup that adds one), until the editor's window matches it to its gallery by
                    name when it opens, and the editor's own --update-extensions passes over it until then; the guard
                    matches it by name, as the window does, so that what the guard installed is updated by it. One
                    installed from a location (`source: resource`) the window does not match, nor does the guard.
    which version   the newest the editor would take for it (its newest release, its newest version when it follows
                    pre-releases, with a file for the editor's platform and an engine for its version), when that is
                    newer than the one installed. Under --min-age a version younger than it is held back, and the
                    newest one old enough is taken if it is newer than the one installed (--allow-new lets it in).
    what it brings  as for an install: its dependencies that are not installed, and the members of its pack that
                    the installed version did not list.

Nothing is installed when anything is blocked, or when a lookup fails (the editor's update is one query, and fails
whole). An extension installed from a file is pinned by the editor, as one installed with `@version` is: the editor
does not update it on its own, so it stays at what was checked until it is updated again (this command, or the
editor's own update, which no guard reaches: `lazaret --extensions` scans what is installed). One installed in every
profile is updated in the default profile, where the editor keeps it, whatever --profile says (EG-16). One that
follows pre-releases is installed with --pre-release, as the editor's own update installs it; the editor records
that it does only when its command line waits for the lookup it makes after installing a file, which as a rule it does
not, so such an extension is then taken for one that follows releases (EG-15)."""

import collections
import hashlib
import io
import os
import platform
import re
import subprocess
import sys
import threading
import types
import urllib.parse
import zipfile

from lazaret.registry import editorcompat, repo
from lazaret.registry import guard as G
from lazaret.registry.ecosystems import base
from lazaret.scanner import core as lazaret

__all__ = ["EDITORS", "GALLERIES", "guard_editor", "parse_args", "Request", "Manifest", "vsix_manifest",
           "read_manifest", "Editor", "read_editor", "installed_extensions", "order_waves", "Origin", "user_data_dir",
           "profile_files", "installed_origins"]

#: The editors whose `--install-extension` the guard wraps: their name, the registry they install from, and their
#: data folder (extensions in `~/<it>/extensions`, unless product.json says otherwise).
EDITORS = {
    "code": ("VS Code", "vscode", ".vscode"),
    "code-insiders": ("VS Code Insiders", "vscode", ".vscode-insiders"),
    "codium": ("VSCodium", "openvsx", ".vscode-oss"),
    "cursor": ("Cursor", "openvsx", ".cursor"),
    "windsurf": ("Windsurf", "openvsx", ".windsurf"),
    "kiro": ("Kiro", "openvsx", ".kiro"),
    "positron": ("Positron", "openvsx", ".positron"),
}
GALLERIES = {"vscode": "the Visual Studio Marketplace", "openvsx": "Open VSX"}
#: The editors' product names (product.json's nameShort), which name their folder of user data, where --profile's
#: profiles are kept, when the guard does not find product.json
USER_DATA_NAMES = {"code": "Code", "code-insiders": "Code - Insiders", "codium": "VSCodium", "cursor": "Cursor",
                   "windsurf": "Windsurf", "kiro": "Kiro", "positron": "Positron"}
#: The gallery a product.json's extensionsGallery.serviceUrl names, by its host.
GALLERY_HOSTS = {"marketplace.visualstudio.com": "vscode", "open-vsx.org": "openvsx"}
#: The editors that read their gallery from a product.json in their folder of user data and from VSCODE_GALLERY_*
#: variables, over their own product.json's, field by field (VSCodium's patches, MIT: its docs/extensions.md and
#: patches/00-settings-gallery.patch, read Oct 7)
USER_GALLERY_EDITORS = ("codium",)
GALLERY_SERVICE_ENV = "VSCODE_GALLERY_SERVICE_URL"
GALLERY_CONTROL_ENV = "VSCODE_GALLERY_CONTROL_URL"
#: The list of extensions Microsoft has found malicious, as VS Code reads it (its product.json's controlUrl).
MARKETPLACE_CONTROL = "https://main.vscode-cdn.net/extensions/marketplace.json"
#: VS Code installs exactly the files it is given, and none of the extensions they bring, from 1.98 on.
PACK_FLAG_SINCE = (1, 98)
MAX_MANIFEST = 4 * 1024 * 1024
MAX_PRODUCT = 2 * 1024 * 1024
MAX_CONTROL = 16 * 1024 * 1024
MAX_BUILTINS = 1000
MAX_PROFILE_FILE = 16 * 1024 * 1024  # a profile's extensions.json, the editor's storage.json
MAX_LISTED = 500                     # the extensions one manifest lists (as the registry modules read them)
MAX_PLANNED = 500                    # the extensions one run looks at
EDITOR_TIMEOUT = 120                 # --version and --list-extensions
#: The files one editor command installs (a command line of `code.cmd` goes through cmd.exe, 8,191 characters at most)
INSTALL_BATCH = 25

VALUE_OPTIONS = ("--install-extension", "--profile", "--extensions-dir", "--user-data-dir")
FLAG_OPTIONS = ("--force", "--pre-release", "--do-not-sync", "--do-not-include-pack-dependencies")
PASSED_VALUES = ("--profile", "--extensions-dir", "--user-data-dir")
UPDATE = "--update-extensions"
NOT_WRAPPED = ("--uninstall-extension", "--install-builtin-extension", "--list-extensions", "--locate-extension")

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*")
#: VS Code's `id@version` (extensionManagementUtil's): a version is MAJOR.MINOR.PATCH[-…], or `prerelease`
_ID_VERSION_RE = re.compile(r"^([^.]+\..+)@((prerelease)|(\d+\.\d+\.\d+(-.*)?))$")
_LISTED_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*)@(\S{1,100})$")
_VSCODE_VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,9})")
_PLATFORM_RE = re.compile(r"[a-z0-9]{1,16}(?:-[a-z0-9]{1,16}){0,3}")
_PRODUCT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,60}")
_GALLERY_ID_RE = re.compile(r"[A-Za-z0-9-]{1,100}")


class Unavailable(Exception):
    """The editor would not install the extension: no such extension or version (`missing`), no file for this
    platform, none for this editor's version, or a file that is not the version the registry named."""

    def __init__(self, message, missing=False):
        super().__init__(message)
        self.missing = missing


# ---------------- the command line ----------------
class Request:
    """One `--install-extension` value: a `.vsix` file (path), or an extension (id, a version or None, pre: @prerelease)."""
    __slots__ = ("text", "path", "id", "version", "pre")

    def __init__(self, text, path=None, ext_id=None, version=None, pre=False):
        self.text, self.path, self.id, self.version, self.pre = text, path, ext_id, version, pre


def parse_args(tool, args, cwd=None):
    """(requests, flags, values) of an editor's command line: the `--install-extension` values (a value ending in
    `.vsix` is a file, relative to the current folder, as the editor reads it; else `id[@version]`), the flags and the
    options passed on; or no request and the flag `--update-extensions`, with the options it passes on. GuardError for
    anything else, for neither, or for both."""
    requests, flags, values = [], set(), {}
    k = 0
    while k < len(args):
        arg = args[k]
        name, eq, value = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if name in FLAG_OPTIONS + (UPDATE,) and not eq:
            flags.add(name)
        elif name in VALUE_OPTIONS:
            if not eq:
                k += 1
                if k >= len(args):
                    raise G.GuardError(f"{tool} {name} needs a value")
                value = args[k]
            if name == "--install-extension":
                requests.append(_request(value, cwd))
            else:
                values[name] = value
        elif name in NOT_WRAPPED:
            raise G.GuardError(f"lazaret guard wraps {tool} --install-extension and {UPDATE}; {name} is not wrapped "
                               f"(yet)")
        else:
            raise G.GuardError(f"lazaret guard {tool}: {lazaret.sanitize_term_line(arg)!r} is not an option the guard "
                               f"passes on ({', '.join(FLAG_OPTIONS + PASSED_VALUES)})")
        k += 1
    if UPDATE in flags:
        if requests:
            # (the editor would install and not update: it reads --install-extension first)
            raise G.GuardError(f"{tool} --install-extension and {UPDATE} together: the editor installs and does not "
                               f"update; run them one at a time")
        given = [f for f in FLAG_OPTIONS if f in flags]
        if given:
            raise G.GuardError(f"{tool} {UPDATE} does not read {', '.join(given)} (it passes on "
                               f"{', '.join(PASSED_VALUES)})")
        return requests, flags, values
    if not requests:
        raise G.GuardError(f"lazaret guard wraps {tool} --install-extension ID[@VERSION] | FILE.vsix, and {tool} "
                           f"{UPDATE}")
    seen = set()
    for r in requests:
        key = r.id or os.path.normcase(r.path)
        if key in seen:
            raise G.GuardError(f"{tool}: {lazaret.sanitize_term_line(r.text)} is named twice")
        seen.add(key)
    return requests, flags, values


def _request(value, cwd):
    if value.lower().endswith(".vsix"):
        return Request(value, path=os.path.join(cwd or os.getcwd(), value))
    m = _ID_VERSION_RE.match(value)
    ext_id, version = (m.group(1), m.group(2)) if m else (value, None)
    if not _ID_RE.fullmatch(ext_id) or len(ext_id) > 257:
        raise G.GuardError(f"{lazaret.sanitize_term_line(value)!r} is not an extension (publisher.name[@version]) or a "
                           f".vsix file")
    return Request(value, ext_id=ext_id.lower(), version=None if version == "prerelease" else version,
                   pre=version == "prerelease")


# ---------------- what an extension says of itself ----------------
class Manifest:
    """What the guard reads of an extension's package.json: its id (publisher.name, lowercase), its version, its
    engines.vscode (None when it gives none), the extensions it needs and the members of its pack (lowercase ids)."""
    __slots__ = ("id", "version", "engine", "deps", "pack")

    def __init__(self, ext_id, version, engine=None, deps=(), pack=()):
        self.id, self.version, self.engine, self.deps, self.pack = ext_id, version, engine, tuple(deps), tuple(pack)


def _ids(value):
    out = []
    if isinstance(value, list):
        for v in value[:MAX_LISTED]:
            if isinstance(v, str) and _ID_RE.fullmatch(v) and v.lower() not in out:
                out.append(v.lower())
    return out


def read_manifest(doc):
    """A package.json's object -> Manifest; ValueError when it does not name an extension."""
    if not isinstance(doc, dict):
        raise ValueError("its package.json is not a JSON object")
    publisher, name, version = doc.get("publisher"), doc.get("name"), doc.get("version")
    if not all(isinstance(x, str) for x in (publisher, name, version)) or not _ID_RE.fullmatch(f"{publisher}.{name}") \
            or not base.VERSION_RE.match(version):
        raise ValueError("its package.json does not name an extension (publisher, name and version)")
    engines = doc.get("engines")
    engine = engines.get("vscode") if isinstance(engines, dict) and isinstance(engines.get("vscode"), str) else None
    return Manifest(f"{publisher}.{name}".lower(), version, engine, _ids(doc.get("extensionDependencies")),
                    _ids(doc.get("extensionPack")))


def vsix_manifest(data):
    """The Manifest of a `.vsix`: its `extension/package.json`, the entry the editor reads by that name when it installs
    the file, by the name yauzl gives an entry (`repo.zip_entry_names`: a Unicode path field's, when one applies).
    ValueError when there is none, when more than one entry is written as the extension's package.json (the editor
    checks the first and the extension runs with the last: `repo.canonical_member_path`'s `vsix` rule, and a twin
    that differs only by case, one file on macOS and Windows), or when it is not an extension's."""
    reason = repo._zip_preflight(data)
    if reason:
        raise ValueError(reason)
    problem, raw = None, b""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos, written = [], 0
            for info in zf.infolist():
                name = repo.zip_entry_names(info)[1]
                if name.endswith("/"):
                    continue
                if name == "extension/package.json":
                    infos.append(info)
                rel = repo.canonical_member_path(name, "vsix")[0]
                # (on macOS and Windows a case twin is written over it too: EG-4)
                written += rel is not None and repo.case_fold(rel) == "package.json"
            if not infos:
                problem = "it has no extension/package.json"
            elif written > 1:
                problem = "more than one of its entries is written as the extension's package.json"
            elif infos[0].file_size > MAX_MANIFEST:
                problem = "its package.json is larger than the guard reads"
            else:
                with zf.open(infos[0]) as f:
                    raw = f.read(MAX_MANIFEST + 1)
    except repo._ZIP_READ_ERRORS as exc:
        raise ValueError(f"it is not a zip the guard can read ({type(exc).__name__})") from None
    if problem is None and len(raw) > MAX_MANIFEST:
        problem = "its package.json is larger than the guard reads"
    if problem:
        raise ValueError(problem)
    doc, _issues = lazaret.load_manifest("package.json", raw.decode("utf-8", errors="replace"))
    return read_manifest(doc)


def _read_json_file(path, limit):
    """A JSON object from a file of at most `limit` bytes; None when it cannot be read or is not one."""
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except (OSError, ValueError):                       # (ValueError: a path with a NUL in it)
        return None
    if len(raw) > limit:
        return None
    doc, _issues = lazaret.load_manifest(os.path.basename(path), raw.decode("utf-8", errors="replace"))
    return doc if isinstance(doc, dict) else None


# ---------------- the editor ----------------
class Editor:
    """The editor the command runs: its executable, its name, the registry the guard reads for it (`gallery`), the
    gallery the editor installs from as it names it (`gallery_host`, and `gallery_where` it is named; None when it
    names none) and which of the guard's registries that is (`gallery_named`, None for another), whether --gallery
    chose the registry (`gallery_given`), the VS Code version its extensions' engines are checked against (None: not
    known), its build date, its target platform, its app folder (where product.json is; None: not found), its built-in
    extensions ({id: version}) and its malicious list's URL."""

    def __init__(self, tool, exe, label, gallery, data_folder):
        self.tool, self.exe, self.label, self.gallery, self.data_folder = tool, exe, label, gallery, data_folder
        self.gallery_named = None
        self.gallery_host = None
        self.gallery_where = None
        self.gallery_given = False
        self.reported = None
        self.version = None
        self.date = None
        self.arch = None
        self.target = "unknown"
        self.app = None
        self.product = {}
        self.builtins = {}
        self.control_url = None
        self.notes = []

    def takes_pack_flag(self):
        """Does the editor's CLI take --do-not-include-pack-dependencies (VS Code 1.98 on)? None when not known."""
        if self.version is None:
            return None
        m = _VSCODE_VERSION_RE.match(self.version)
        return (int(m.group(1)), int(m.group(2))) >= PACK_FLAG_SINCE

    def own_gallery(self):
        """Does the guard read the gallery the editor installs from: the one the editor names (product.json; for
        VSCodium also its own product.json in its folder of user data, and VSCODE_GALLERY_SERVICE_URL), or, when the
        guard found no product.json beside the command, the editor's own (EDITORS)? Then the gallery identifiers the
        editor keeps are the registry's."""
        if self.gallery_host is not None:
            return self.gallery_named == self.gallery
        return self.app is None and self.gallery == EDITORS[self.tool][1]

    def _gallery_said(self):
        if self.gallery_host is None:
            return f"{GALLERIES[EDITORS[self.tool][1]]} (no product.json was found beside the command)"
        named = GALLERIES[self.gallery_named] if self.gallery_named else self.gallery_host
        return f"{named} ({self.gallery_where})"

    def gallery_problem(self, update):
        """Why the guard does not stand in for the editor's gallery, or None (EG-8). The editor installs its gallery's
        extension of a name; the guard reads one of two public registries, whose extension of that name may be another
        (a name a company's private extension has, taken there by someone else), and asking for it tells that registry
        the name. So an editor that names a gallery the guard does not read, or none, is refused unless --gallery says
        which registry to read for the extensions the command names; and --update-extensions, which asks for every
        extension installed, only when the guard reads the editor's own gallery."""
        label = self.label
        if not self.gallery_given:
            if self.gallery_host is not None and self.gallery_named is None:
                return (f"{label} installs from {self.gallery_host} ({self.gallery_where}), a gallery the guard does not "
                        f"read: it would ask another registry for each extension by name, and could install another "
                        f"extension of the same name. --gallery vscode or --gallery openvsx reads one of those for the "
                        f"extensions you name")
            if self.gallery_host is None and self.app is not None:
                return (f"{label}'s product.json names no gallery, so the editor installs no extension by name; "
                        f"--gallery vscode or --gallery openvsx says which registry the guard reads")
        if update and not self.own_gallery():
            if self.gallery_host is None and self.app is not None:
                return (f"{label}'s product.json names no gallery, so its own {UPDATE} updates nothing, and the guard "
                        f"updates only from the gallery the editor installs from")
            return (f"{label} updates its extensions from {self._gallery_said()}, and the guard would read "
                    f"{GALLERIES[self.gallery]}: it would ask that registry for every extension installed, by name, and "
                    f"could install another extension of the same name over one of them. Update them one at a time "
                    f"(--install-extension ID --force)")
        return None


def _vscode_like(text):
    """A version the editor's engines are checked against: 1.50 or later (a fork reporting its own version, 1.7.x
    or 0.x, is not one)."""
    m = _VSCODE_VERSION_RE.match(text or "")
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (1, 50)


def find_app(exe):
    """The editor's app folder (the one holding product.json) from its command: the command's real path is
    `<app>/bin/<tool>` (macOS), `<install>/bin/<tool>` with the app in `<install>/resources/app` (Linux, Windows), or
    `<server>/bin/remote-cli/<tool>` (a remote server). None when none of them holds a product.json."""
    real = os.path.realpath(exe)
    up1 = os.path.dirname(real)
    up2 = os.path.dirname(up1)
    up3 = os.path.dirname(up2)
    for d in (up2, os.path.join(up2, "resources", "app"), up3):
        if os.path.isfile(os.path.join(d, "product.json")):
            return d
    return None


def builtin_extensions(app):
    """{id: version} of the extensions an editor is built with (`<app>/extensions/*/package.json`): installed, as the
    editor counts them, though `--list-extensions` lists only the user's."""
    out = {}
    folder = os.path.join(app, "extensions")
    try:
        names = sorted(os.listdir(folder))[:MAX_BUILTINS]
    except OSError:
        return out
    for n in names:
        doc = _read_json_file(os.path.join(folder, n, "package.json"), MAX_MANIFEST)
        try:
            m = read_manifest(doc)
        except ValueError:
            continue
        out[m.id] = m.version
    return out


def _os_release():
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                return f.read(64 * 1024)
        except OSError:
            continue
    return None


def _gallery_config(ed, env, values, system=None):
    """(serviceUrl, controlUrl, where the service is named) of the gallery the editor installs from, None for what it
    does not name: its product.json's extensionsGallery; for VSCodium (USER_GALLERY_EDITORS), a product.json in its
    folder of user data over that, and VSCODE_GALLERY_SERVICE_URL and VSCODE_GALLERY_CONTROL_URL over both, field by
    field, as VSCodium applies them. GuardError when VSCodium's own product.json is there and cannot be read: the
    gallery it names is not known."""
    text = lambda d, k: d[k] if isinstance(d.get(k), str) and d[k] else None   # noqa: E731
    doc = ed.product.get("extensionsGallery") if isinstance(ed.product.get("extensionsGallery"), dict) else {}
    service, control = text(doc, "serviceUrl"), text(doc, "controlUrl")
    where = "its product.json" if service else None
    if ed.tool not in USER_GALLERY_EDITORS:
        return service, control, where
    path = os.path.join(user_data_dir(ed, env, values, system), "product.json")
    try:
        there = os.path.lexists(path)
    except ValueError:                                  # (a NUL in the folder given)
        there = False
    if there:
        user = _read_json_file(path, MAX_PRODUCT)
        if user is None:
            raise G.GuardError(f"{path} could not be read as a JSON object, and {ed.label} reads the gallery it installs "
                               f"from there")
        udoc = user.get("extensionsGallery") if isinstance(user.get("extensionsGallery"), dict) else {}
        if text(udoc, "serviceUrl"):
            service, where = udoc["serviceUrl"], path
        control = text(udoc, "controlUrl") or control
    if env.get(GALLERY_SERVICE_ENV):
        service, where = env[GALLERY_SERVICE_ENV], GALLERY_SERVICE_ENV
    control = env.get(GALLERY_CONTROL_ENV) or control
    return service, control, where


def read_editor(tool, exe, env, gallery=None, system=None, values=None):
    """The Editor `exe` is: `<exe> --version` (its version, its commit, the architecture its build runs on) and its
    product.json when found (a fork's VS Code version, `vscodeVersion`; its build date; its gallery, `_gallery_config`;
    its malicious list). `values`: the options passed on (--user-data-dir, where VSCodium's own product.json is).
    GuardError when `--version` fails."""
    label, default_gallery, data_folder = EDITORS[tool]
    try:
        proc = subprocess.run([exe, "--version"], env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=EDITOR_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise G.GuardError(f"could not run {tool} --version: {exc}") from None
    if proc.returncode != 0:
        raise G.GuardError(f"{tool} --version failed (exit {proc.returncode})")
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    ed = Editor(tool, exe, label, default_gallery, data_folder)
    ed.reported = lines[0][:100] if lines else None
    ed.arch = lines[2][:20] if len(lines) >= 3 else None
    ed.app = find_app(exe)
    ed.product = (_read_json_file(os.path.join(ed.app, "product.json"), MAX_PRODUCT) or {}) if ed.app else {}
    vscode_version = ed.product.get("vscodeVersion")
    if isinstance(vscode_version, str) and _vscode_like(vscode_version):
        ed.version = vscode_version[:100]
    elif _vscode_like(ed.reported):
        ed.version = ed.reported
    else:
        ed.notes.append(f"{label} reports version {ed.reported or 'nothing'}, not a VS Code version: the extensions' "
                        f"engines are not checked against it (the editor checks each file it installs)")
    if isinstance(ed.product.get("date"), str):
        ed.date = ed.product["date"][:40]
    if isinstance(ed.product.get("dataFolderName"), str) and re.fullmatch(r"\.[A-Za-z0-9._-]{1,60}",
                                                                           ed.product["dataFolderName"]):
        ed.data_folder = ed.product["dataFolderName"]
    service, control, where = _gallery_config(ed, env, values or {}, system)
    if service:
        try:
            host = (urllib.parse.urlsplit(service).hostname or "").lower()
        except ValueError:
            host = ""
        ed.gallery_host = base.show(host or service, 80)
        ed.gallery_where = where if where in ("its product.json", GALLERY_SERVICE_ENV) \
            else lazaret.sanitize_term_line(where)[:300]
        ed.gallery_named = GALLERY_HOSTS.get(host)
    if gallery:
        ed.gallery, ed.gallery_given = gallery, True
        if not ed.own_gallery() and (ed.gallery_host is not None or ed.app is None):
            ed.notes.append(f"{label} installs from {ed._gallery_said()}; the guard reads {GALLERIES[gallery]} in its "
                            f"place, as --gallery says")
    elif ed.gallery_named:
        ed.gallery = ed.gallery_named
    if isinstance(control, str) and control.startswith("https://"):
        ed.control_url = control
    elif ed.gallery == "vscode":
        ed.control_url = MARKETPLACE_CONTROL
    if ed.app:
        ed.builtins = builtin_extensions(ed.app)
    system = sys.platform if system is None else system
    ed.target = editorcompat.target_platform(system, ed.arch or platform.machine(),
                                             _os_release() if system.startswith("linux") else None)
    return ed


def _passed(values):
    out = []
    for name in PASSED_VALUES:
        if name in values:
            out += [name, values[name]]
    return out


def installed_extensions(editor, env, values):
    """{id: version} of the extensions the editor lists as installed (`--list-extensions --show-versions`, with the
    profile and folders given). GuardError when it cannot say."""
    argv = [editor.exe, "--list-extensions", "--show-versions", *_passed(values)]
    try:
        proc = subprocess.run(argv, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=EDITOR_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise G.GuardError(f"could not run {editor.tool} --list-extensions: {exc}") from None
    if proc.returncode != 0:
        tail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()[-1:] or [""]
        raise G.GuardError(f"{editor.tool} --list-extensions failed (exit {proc.returncode}): "
                           f"{lazaret.sanitize_term_line(tail[0])[:300]}")
    out = {}
    for line in (proc.stdout or "").splitlines():
        m = _LISTED_RE.match(line.strip())
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def extensions_folder(editor, env, values):
    """Where the editor keeps its extensions (VS Code's rule): --extensions-dir, else VSCODE_EXTENSIONS, else the
    portable folder's, else `~/<its data folder>/extensions`."""
    if values.get("--extensions-dir"):
        return os.path.abspath(values["--extensions-dir"])
    if env.get("VSCODE_EXTENSIONS"):
        return env["VSCODE_EXTENSIONS"]
    if env.get("VSCODE_PORTABLE"):
        return os.path.join(env["VSCODE_PORTABLE"], "extensions")
    return os.path.join(os.path.expanduser("~"), editor.data_folder, "extensions")


def installed_pack(folder, ext_id, version):
    """The extensionPack of the installed `ext_id` at `version`, read from its folder in the editor's extensions
    folder (`<id>-<version>[-<platform>]`); None when it is not found there."""
    want = f"{ext_id}-{version}".lower()
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return None
    for n in names:
        low = n.lower()
        if low != want and not (low.startswith(want + "-") and _PLATFORM_RE.fullmatch(low[len(want) + 1:])):
            continue
        try:
            m = read_manifest(_read_json_file(os.path.join(folder, n, "package.json"), MAX_MANIFEST))
        except ValueError:
            continue
        if m.id == ext_id and m.version == version:
            return m.pack
    return None


# ---------------- where an installed extension came from (--update-extensions) ----------------
class Origin:
    """What the editor recorded of an installed extension (a profile's extensions.json): its version, the identifier
    its gallery gave it (None: installed from a file and not yet matched to the gallery, or not from one), whether it
    follows pre-releases, how it was installed (`gallery`, `vsix`, `resource`; None when not said), and whether it is
    installed in every profile (`isApplicationScoped`, or `isBuiltin`: the editor keeps it in the default profile)."""
    __slots__ = ("version", "uuid", "pre", "source", "everywhere")

    def __init__(self, version, uuid=None, pre=False, source=None, everywhere=False):
        self.version, self.uuid, self.pre, self.source, self.everywhere = version, uuid, pre, source, everywhere


def user_data_dir(editor, env, values, system=None):
    """The editor's folder of user data (VS Code's rule): VSCODE_PORTABLE's `user-data`, else VSCODE_APPDATA's folder
    of the editor's product name, else --user-data-dir, else that folder in the system's (APPDATA on Windows,
    `~/Library/Application Support` on macOS, XDG_CONFIG_HOME or `~/.config` elsewhere)."""
    if env.get("VSCODE_PORTABLE"):
        return os.path.abspath(os.path.join(env["VSCODE_PORTABLE"], "user-data"))
    name = editor.product.get("nameShort")
    if not (isinstance(name, str) and _PRODUCT_NAME_RE.fullmatch(name)):
        name = USER_DATA_NAMES[editor.tool]
    if env.get("VSCODE_APPDATA"):
        return os.path.abspath(os.path.join(env["VSCODE_APPDATA"], name))
    if values.get("--user-data-dir"):
        return os.path.abspath(values["--user-data-dir"])
    system = sys.platform if system is None else system
    home = os.path.expanduser("~")
    if system.startswith("win") or system == "cygwin":
        appdata = env.get("APPDATA") or os.path.join(env.get("USERPROFILE") or home, "AppData", "Roaming")
    elif system == "darwin":
        appdata = os.path.join(home, "Library", "Application Support")
    else:
        appdata = env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return os.path.abspath(os.path.join(appdata, name))


def _profile_folder(location, home):
    """A stored profile's folder: its location, a folder name under the profiles' folder (`home`), or a file URI as an
    older editor stored it; None for anything else."""
    if isinstance(location, str):
        parts = re.split(r"[\\/]", location)
        if location and ":" not in location and "\x00" not in location and not os.path.isabs(location) \
                and not any(p in ("", ".", "..") for p in parts):
            return os.path.join(home, location)
        return None
    if isinstance(location, dict) and location.get("scheme") == "file" and isinstance(location.get("path"), str) \
            and "\x00" not in location["path"]:
        path = location["path"]
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
            path = path[1:].replace("/", "\\")
        return path if os.path.isabs(path) else None
    return None


def profile_files(editor, env, values):
    """[(path, which)] of the files that record the extensions the editor lists: the default profile's
    `extensions.json`, in its extensions folder (`all`); with --profile NAME, that profile's (`own`, in
    `<user data>/User/profiles/<its folder>`, as the editor's storage.json names it, unless the profile uses the
    default's extensions) and the default's for those installed in every profile (`everywhere`). GuardError when the
    profile is not found."""
    default = os.path.join(extensions_folder(editor, env, values), "extensions.json")
    name = values.get("--profile")
    if not name or name == "Default":                     # (the default profile's name: the editor finds it first)
        return [(default, "all")]
    data = user_data_dir(editor, env, values)
    state = os.path.join(data, "User", "globalStorage", "storage.json")
    doc = _read_json_file(state, MAX_PROFILE_FILE)
    stored = doc.get("userDataProfiles") if isinstance(doc, dict) else None
    for p in stored if isinstance(stored, list) else []:
        if not (isinstance(p, dict) and p.get("name") == name):
            continue
        flags = p.get("useDefaultFlags")
        if isinstance(flags, dict) and flags.get("extensions") is True:
            return [(default, "all")]
        folder = _profile_folder(p.get("location"), os.path.join(data, "User", "profiles"))
        if folder:
            return [(os.path.join(folder, "extensions.json"), "own"), (default, "everywhere")]
        break
    raise G.GuardError(f"{editor.label}'s profile {lazaret.sanitize_term_line(name)!r} was not found in "
                       f"{lazaret.sanitize_term_line(state)}, where the guard reads which file records its extensions")


def _read_profile_file(path):
    """The entries of a profile's extensions.json; [] when there is none (the editor reads none as no extension).
    GuardError when it cannot be read, or is not a JSON list."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PROFILE_FILE + 1)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:                # (ValueError: a NUL in a folder given)
        raise G.GuardError(f"could not read {lazaret.sanitize_term_line(path)}: "
                           f"{getattr(exc, 'strerror', None) or exc}") from None
    if len(raw) > MAX_PROFILE_FILE:
        raise G.GuardError(f"{path} is larger than the guard reads")
    try:
        doc = lazaret.json_loads_bounded(raw.strip() or b"[]")
    except (lazaret.JsonTooDeep, UnicodeDecodeError, ValueError):
        doc = None
    if not isinstance(doc, list):
        raise G.GuardError(f"{path} is not the list of extensions the editor keeps there")
    return doc


def installed_origins(editor, env, values):
    """{(id, version): Origin} of the extensions the profile's files record (profile_files): the gallery identifier
    (`metadata.id`, else `identifier.uuid`, as the editor reads it), `metadata.preRelease` and `metadata.source`. An
    entry the editor would not read is left out. GuardError when a file cannot be read."""
    out = {}
    for path, which in profile_files(editor, env, values):
        for e in _read_profile_file(path)[:MAX_PLANNED * 4]:
            ident = e.get("identifier") if isinstance(e, dict) else None
            ext_id = ident.get("id") if isinstance(ident, dict) else None
            version = e.get("version") if isinstance(e, dict) else None
            if not (isinstance(ext_id, str) and _ID_RE.fullmatch(ext_id) and isinstance(version, str) and version):
                continue
            meta = e.get("metadata") if isinstance(e.get("metadata"), dict) else {}
            everywhere = meta.get("isApplicationScoped") is True or meta.get("isBuiltin") is True
            if (which == "own" and meta.get("isApplicationScoped") is True) or (which == "everywhere" and not everywhere):
                continue
            uuid = meta.get("id") if meta.get("id") is not None else ident.get("uuid")
            uuid = uuid if isinstance(uuid, str) and _GALLERY_ID_RE.fullmatch(uuid) else None
            source = meta.get("source") if isinstance(meta.get("source"), str) else None
            out.setdefault((ext_id.lower(), version),
                           Origin(version, uuid, meta.get("preRelease") is True, source, everywhere))
    return out


# ---------------- one run ----------------
class Item:
    """One extension the run looks at: why (asked for, or which extension brings it), the file chosen and its
    manifest, where the file is written to install it from, its Check."""

    def __init__(self, ext_id, why, dependency=False, bringer=None):
        self.id, self.why, self.dependency, self.bringer = ext_id, why, dependency, bringer
        self.version = None
        self.candidate = None
        self.artifact = None
        self.manifest = None
        self.path = None                     # the file the editor installs (the guard's copy)
        self.source = None                   # a .vsix named on the command line
        self.digest = None
        self.check = None
        self.installed = False               # an installed pack member, walked through for what it brings
        self.downgrade = False
        self.pre = False                     # a pre-release follower: asked for with @prerelease or --pre-release,
        #                                      brought by one, or an update of one (installed with --pre-release)
        self.held = None                     # an update's newer version held back by --min-age (said)
        self.replaces = None                 # the id it is installed in place of (the gallery's control list: EG-7)
        self.everywhere = False              # an update of one installed in every profile (EG-16)


class Run:
    """What one `lazaret guard <editor> --install-extension …` knows: the context, the editor, the registry module and
    its fetch, the extensions installed (and built in), the files' folder, the resolutions made (by id)."""

    def __init__(self, ctx, editor, env, flags, values, installed, scratch, fetch=None):
        self.ctx, self.editor, self.env, self.flags, self.values = ctx, editor, env, flags, values
        self.module = repo.registry_module(editor.gallery)
        self.fetch = fetch if fetch is not None else repo.module_fetch(self.module)
        self.installed = installed
        self.present = dict(editor.builtins, **installed)          # (what the editor counts as installed)
        self.scratch = scratch
        self.folder = extensions_folder(editor, env, values)
        self.resolved = {}                   # id -> Item, or Unavailable (one per id, as the editor installs one: EG-13)
        self.items = []                      # every Item downloaded, to install unless blocked
        self.counter = 0
        self.control = None                  # the gallery's control list, once read (read_control)
        self.control_lock = threading.Lock()
        self.key_locks = {}                  # id -> the lock its resolution holds

    def _read_control(self):
        with self.control_lock:              # (read once, when first needed: the editor reads it when it fetches)
            if self.control is None:
                self.control = read_control(self)
            return self.control

    @property
    def malicious(self):
        """The ids and publishers the gallery's control list says are malicious; None without a list."""
        return self._read_control()[0]

    @property
    def migrate(self):
        """{id: (the id the editor installs in its place, a pre-release of it?)} from the gallery's control list."""
        return self._read_control()[1]

    def listed(self, ext_id):
        """Is `ext_id`, or its publisher, on the gallery's list of malicious extensions?"""
        listed = self.malicious
        return bool(listed) and (ext_id in listed or ext_id.split(".", 1)[0] in listed)

    def replacement(self, ext_id):
        """(the id the editor installs in place of `ext_id`, a pre-release of it?) when its gallery's control list says
        to install another in its place, else None. None too for one the list says is malicious: the editor refuses it
        before it looks for a replacement (checkAndGetCompatibleVersion), so the guard blocks it as itself (EG-11)."""
        target = self.migrate.get(ext_id)
        return None if target is None or self.listed(ext_id) else target

    def replaced(self, ext_id, why):
        """(the id the editor installs for `ext_id`, a pre-release of it?, said) when its gallery's control list says to
        install another in its place (VS Code's checkAndGetCompatibleVersion, EG-7), else None."""
        target = self.replacement(ext_id)
        if target is not None:
            self.note(f"{why}: {self.editor.label}'s gallery says to install {target[0]} in place of {ext_id}, and "
                      f"the editor does")
        return target

    def note(self, line):
        if line not in self.ctx.notes:
            self.ctx.notes.append(line)

    # ---- choosing a file
    def choose(self, ext_id, version=None, pre=False, keep=None):
        """(candidate, artifact) of the file the editor would install (among the candidates `keep` keeps, when it is
        given: --min-age's held back). Unavailable when there is none; FetchError when the registry could not be
        asked."""
        ed, chosen, last = self.editor, None, []
        try:
            for cands in self.module.candidates(ext_id, self.fetch, version):
                last = cands
                chosen = editorcompat.choose([c for c in cands if keep(c)] if keep else cands, ed.target, ed.version,
                                             ed.date, version, pre)
                if chosen is not None:
                    break
        except base.NotFound:
            raise Unavailable(f"not found in {GALLERIES[ed.gallery]}"
                              + (f" (no version {version})" if version else ""), missing=True) from None
        if chosen is None:
            why, missing = self._why_none(last, version, pre)
            raise Unavailable(why, missing=missing)
        return chosen, self.module.artifact(ext_id, chosen, self.fetch)

    def _why_none(self, cands, version, pre):
        """(why no file was chosen, whether the gallery has no such extension or version: the editor finds none, and
        so looks for no replacement, EG-14)."""
        ed = self.editor
        if version is not None:
            cands = [c for c in cands if c.version == version]
            if not cands:
                return f"{GALLERIES[ed.gallery]} has no version {version} of it", True
        elif not pre:
            if cands and all(c.pre for c in cands):
                return "it has no release, only pre-releases (--pre-release installs one)", False
            cands = [c for c in cands if not c.pre]
        if not cands:
            return f"not found in {GALLERIES[ed.gallery]}", True
        if not any(editorcompat.platform_fits(c.platform, ed.target) for c in cands):
            return f"it has no file for {ed.target}", False
        return f"none of its versions is for {ed.label} {ed.version} (their engines.vscode)", False

    # ---- one extension's file
    def fetch_item(self, item):
        """Download the file chosen for `item`, check it against the registry's digest, read its manifest (the
        extension and version it must be), write it to the folder the editor installs from, and scan it. A file that
        cannot be had or checked blocks it (ctx.not_checked), and so does one that is not the version named."""
        ctx, check = self.ctx, item.check
        try:
            data = self.fetch.bytes(item.artifact["url"], repo.MAX_DOWNLOAD_BYTES)
            self.module.verify(data, item.artifact["entry"], item.id, item.version)
        except base.DigestError as exc:
            ctx.block(check, f"not the file {GALLERIES[self.editor.gallery]} published: {exc}")
            return
        except base.TooLarge:
            # (the guard installs the file it scanned, and has none to install: blocked, where the package managers'
            # guards let the tool fetch a file too large to scan as INCOMPLETE)
            ctx.block(check, f"larger than the {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB the guard downloads and "
                             f"scans, so it is not installed")
            return
        except (base.FetchError, repo.FetchError, ValueError) as exc:
            ctx.not_checked(check, exc)
            return
        self._take(item, data)

    def _take(self, item, data):
        """A file's bytes in hand (downloaded, or read from the command line's .vsix): its manifest, its copy for the
        editor, its scan."""
        ctx, check = self.ctx, item.check
        try:
            manifest = vsix_manifest(data)
        except ValueError as exc:
            ctx.not_checked(check, ValueError(f"its package.json could not be read: {exc}"))
            return
        if item.source is None and (manifest.id != item.id or manifest.version != item.version):
            ctx.block(check, f"the file is {manifest.id}@{manifest.version}, not the version the registry named")
            return
        ed = self.editor
        if item.source is None and ed.version and manifest.engine \
                and not editorcompat.engine_ok(manifest.engine, ed.version, ed.date):
            # (the registry said nothing of its engine, or said another one: the editor would refuse the file)
            ctx.not_checked(check, ValueError(f"its engines.vscode ({base.show(manifest.engine, 40)}) is not for "
                                              f"{ed.label} {ed.version}: the editor would not install it"))
            return
        item.manifest = manifest
        item.digest = hashlib.sha256(data).hexdigest()
        check.digest = "sha256:" + item.digest
        with ctx.lock:
            self.counter += 1
            n = self.counter
        item.path = os.path.join(self.scratch, f"{n}-{manifest.id}-{manifest.version}.vsix")
        with open(item.path, "xb") as f:
            f.write(data)
        key = G.VerdictCache.key(self.editor.gallery if item.source is None else "vsix", item.id, item.version,
                                 check.digest)
        hit = ctx.scanner.cached(key)
        if hit is None:
            try:
                with ctx.scanner.holding(len(data)):
                    hit = ctx.scanner.scan(data, "zip", "vsix")
            except G.ScanError as exc:
                ctx.not_checked(check, exc)
                return
        published = item.candidate.when if item.candidate is not None else None
        ctx.scanner.remember(key, hit, published)
        ctx.apply(check, hit)
        if item.source is None:
            ctx.age_check(check, published)

    # ---- what an extension brings
    def brings(self, item):
        """[(id, a dependency?)] of what the editor installs with `item`, as it walks: its dependencies that are not
        installed, and its pack's members (those the installed version of it did not list, when it is installed)."""
        m = item.manifest
        if m is None:
            return []
        out = [(d, True) for d in m.deps if d not in self.present]
        old = None
        if item.id in self.installed:
            old = installed_pack(self.folder, item.id, self.installed[item.id])
            if old is None and m.pack:
                self.note(f"the pack of the installed {item.id} could not be read from {self.folder}: every member "
                          f"of its new version's pack is looked at")
        for p in m.pack:
            if (old is None or p not in old) and all(p != i for i, _d in out):
                out.append((p, False))
        return out

    def resolve_brought(self, ext_id, bringer, dependency, pre):
        """The Item for an extension brought by `bringer`, at the version the editor would take (a pre-release when
        `pre`: the extension that brings it was asked for as one); shared by every walk; Unavailable when there is
        none. An installed one is not downloaded: its newest version's manifest is read for what it brings, as the
        editor reads it. One the gallery's control list replaces is the replacement (EG-7), kept under both ids. One
        Item for an id, whoever brings it and however (the first resolution's), as the editor installs one (EG-13)."""
        asked = ext_id
        target = self.replaced(ext_id, f"{ext_id}, which {bringer.id} brings") if asked not in self.resolved else None
        if target is not None:
            ext_id, pre = target
        key = ext_id
        with self.ctx.lock:
            lock = self.key_locks.setdefault(key, threading.Lock())
        with lock:                           # (one Item for an extension, however many ask for it at once)
            if key in self.resolved:
                self.resolved[asked] = self.resolved[key]
                return self.resolved[key]
            item = Item(ext_id, f"brought by {bringer.id}", dependency, bringer)
            item.pre = pre
            item.replaces = asked if target is not None else None
            try:
                if len(self.items) >= MAX_PLANNED:
                    raise Unavailable(f"the run already looks at {MAX_PLANNED} extensions")
                item.candidate, item.artifact = self.choose(ext_id, None, pre)
                item.version = item.candidate.version
                if ext_id in self.present:
                    item.installed = True
                    item.manifest = read_manifest(self.module.manifest(ext_id, item.candidate, self.fetch))
                else:
                    item.check = self.ctx.add(G.Check(self.editor.gallery, ext_id, item.version, item.why))
                    with self.ctx.lock:
                        self.items.append(item)
                    self.fetch_item(item)
            except Unavailable as exc:
                item = exc
            except (base.FetchError, repo.FetchError, ValueError) as exc:
                if item.check is None:
                    item.check = self.ctx.add(G.Check(self.editor.gallery, ext_id, item.version, item.why))
                self.ctx.not_checked(item.check, exc)
            self.resolved[key] = self.resolved[asked] = item
            return item

    def walk(self, root, known, pre=False):
        """Every extension `root` brings, as the editor walks (level by level here; the same set): [Item], each at its
        newest release (`pre`: its newest version, as for an extension asked for with --pre-release or @prerelease).
        Unavailable when a dependency cannot be installed (the editor fails the extension that needs it); a pack
        member that cannot be is left out, and said."""
        found, level, known = [], [root], set(known)
        while level:
            wanted = collections.OrderedDict()
            for item in level:
                for ext_id, dependency in self.brings(item):
                    if ext_id in known or (self.replacement(ext_id) or ("",))[0] in known:
                        continue                 # (or the one the editor installs in its place: EG-7)
                    was = wanted.get(ext_id)
                    wanted[ext_id] = (item if was is None else was[0], dependency or (was is not None and was[1]))
            jobs = [(lambda i=ext_id, b=by, d=dep: self.resolve_brought(i, b, d, pre)) for ext_id, (by, dep) in wanted.items()]
            G.run_all(jobs)
            level = []
            for ext_id, (by, dep) in wanted.items():
                res = self.resolved[ext_id]
                if isinstance(res, Unavailable):
                    if dep:
                        raise Unavailable(f"it needs {ext_id}, which the editor cannot install: {res}")
                    self.note(f"{ext_id}, in the pack of {by.id}, is left out, as the editor leaves it: {res}")
                    continue
                known.add(ext_id)
                if any(res is f for f in found):
                    continue                 # (two it brings, one of them in the other's place: one install, EG-13)
                known.add(res.id)
                found.append(res)
                level.append(res)
        return found


def _js_truthy(value):
    """Is a JSON value true where JavaScript tests it (`if (value)`): every object and array is, empty or not."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == value and value != 0             # (NaN is false)
    if isinstance(value, str):
        return value != ""
    return True


def read_control(run):
    """What the editor's gallery's control list says (its product.json's controlUrl; Microsoft's for the Marketplace),
    as VS Code reads it (getExtensionsControlManifest): (the ids and publishers it lists as malicious, lowercase; the
    extensions the editor installs another in place of: {id: (the other's id, a pre-release of it?)}, from
    `migrateToPreRelease` (for an engine the editor takes), `deprecated` entries whose extension says `autoMigrate`, and
    the product's `defaultChatAgent`). (None, {}) when there is no list or it could not be read (said): the editor then
    applies none of it."""
    url = run.editor.control_url
    if not url:
        return None, {}
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    eco = types.SimpleNamespace(id="control", hosts=frozenset({host}), rate={})
    try:
        doc = base.Fetch(eco, repo.module_transport).json(url, max_bytes=MAX_CONTROL)
        listed = doc.get("malicious") if isinstance(doc, dict) else None
        if not isinstance(listed, list):
            raise base.FetchError("the answer has no list of malicious extensions")
    except (base.FetchError, repo.FetchError, ValueError) as exc:
        run.note(f"the list of malicious extensions at {host} could not be read ({exc}): not checked against it")
        return None, {}
    malicious = {x.lower() for x in listed if isinstance(x, str)}
    migrate, ed = {}, run.editor
    to_pre = doc.get("migrateToPreRelease")
    for old, info in (to_pre.items() if isinstance(to_pre, dict) else ()):
        engine = info.get("engine") if isinstance(info, dict) else None
        if isinstance(old, str) and isinstance(info, dict) and isinstance(info.get("id"), str) \
                and _ID_RE.fullmatch(info["id"]) and (not engine or not ed.version or (
                    isinstance(engine, str) and editorcompat.engine_ok(engine, ed.version, ed.date))):
            migrate[old.lower()] = (info["id"].lower(), True)
    deprecated = doc.get("deprecated")
    for old, info in (deprecated.items() if isinstance(deprecated, dict) else ()):
        if not isinstance(old, str) or not _js_truthy(info):
            continue
        # (a `deprecated` entry is written over `migrateToPreRelease`'s for its id: `true`, or one with no extension to
        # migrate to, leaves none, EG-12)
        migrate.pop(old.lower(), None)
        ext = info.get("extension") if isinstance(info, dict) else None
        if isinstance(ext, dict) and _js_truthy(ext.get("autoMigrate")) and isinstance(ext.get("id"), str) \
                and _ID_RE.fullmatch(ext["id"]):
            migrate[old.lower()] = (ext["id"].lower(), _js_truthy(ext.get("preRelease")))
    agent = ed.product.get("defaultChatAgent")
    if isinstance(agent, dict) and all(isinstance(agent.get(k), str) and _ID_RE.fullmatch(agent[k])
                                       for k in ("extensionId", "chatExtensionId")):
        # (VS Code installs its chat extension in place of the agent's own, a pre-release outside its stable builds)
        migrate[agent["extensionId"].lower()] = (agent["chatExtensionId"].lower(), ed.product.get("quality") != "stable")
    for old in [k for k, (new, _pre) in migrate.items() if new == k or not _ID_RE.fullmatch(k)]:
        del migrate[old]
    return malicious, migrate


def _check_malicious(run, items):
    listed = run.malicious if items else None
    if not listed:
        return
    host = (urllib.parse.urlsplit(run.editor.control_url).hostname or "").lower()
    for item in items:
        if item.check is None:
            continue
        publisher = item.id.split(".", 1)[0]
        if run.listed(item.id):
            what = "the extension" if item.id in listed else f"its publisher {publisher}"
            run.ctx.block(item.check, f"{what} is on the list of malicious extensions {run.editor.label}'s gallery "
                                      f"keeps ({host})")


def order_waves(items, brings):
    """The installs in the order the editor must make them when it walks what each extension brings itself (before
    VS Code 1.98): [[Item]] waves, each extension after every one it brings among `items`; and those left in a cycle
    (they bring one another), [] when none. `brings`: Item -> the ids it brings."""
    remaining = {i.id: i for i in items}
    waves = []
    while remaining:
        ready = [i for i in remaining.values() if not ((set(brings(i)) - {i.id}) & set(remaining))]
        if not ready:
            return waves, list(remaining.values())
        waves.append(ready)
        for i in ready:
            del remaining[i.id]
    return waves, []


# ---------------- the command ----------------
def guard_editor(ctx, tool, args, gallery=None, fetch=None):
    """lazaret guard <editor> --install-extension … | --update-extensions: -> the exit code (finish's)."""
    requests, flags, values = parse_args(tool, args)
    update = UPDATE in flags
    exe = G.find_tool(tool)
    env = dict(os.environ)
    editor = read_editor(tool, exe, env, gallery, values=values)
    problem = editor.gallery_problem(update)
    if problem:
        raise G.GuardError(problem)
    no_deps = "--do-not-include-pack-dependencies" in flags
    if no_deps and editor.takes_pack_flag() is False:
        raise G.GuardError(f"{editor.label} {editor.version} does not know --do-not-include-pack-dependencies (VS Code "
                           f"1.98 does): it would install what the extensions bring itself, unchecked")
    for line in editor.notes:
        ctx.notes.append(line)
    ctx.say(f"lazaret guard: {editor.label} {editor.reported or '?'}"
            + (f" (VS Code {editor.version})" if editor.version and editor.version != editor.reported else "")
            + f" for {editor.target}; extensions from {GALLERIES[editor.gallery]}")
    installed = installed_extensions(editor, env, values)
    origins = installed_origins(editor, env, values) if update and installed else {}
    ctx.unchecked_hint = ("the editor installed or updated them itself (from its window, or an update of its own); look "
                          "at them, or uninstall them")
    scratch = G.private_scratch("lazaret-guard-ext-")
    try:
        run = Run(ctx, editor, env, flags, values, installed, scratch, fetch)
        roots, failed = _plan_updates(run, origins) if update else _plan_roots(run, requests)
        if failed:
            for line in failed:
                ctx.say(f"lazaret guard: {line}")
            return G.finish(ctx, installed=False, code=G.EXIT_RESOLVE)
        if update and roots:
            ctx.say(f"lazaret guard: {G.plural(len(roots), 'update')} of the {G.plural(len(installed), 'extension')} "
                    f"{editor.label} lists")
            for root in roots:
                ctx.say(f"  {'update':<10} {root.id} " + (f"{installed[root.id]} to {root.version}" if root.id in installed
                                                          else f"{root.version}, {root.why}"))
        elif update:
            ctx.say(f"lazaret guard: no update for the {G.plural(len(installed), 'extension')} {editor.label} lists")
        known = {r.id for r in roots}
        brought = []
        for root in roots:
            if no_deps or root.manifest is None:
                continue
            try:
                pre = "--pre-release" in flags or root.pre
                brought += [b for b in run.walk(root, known, pre) if not b.installed and b not in brought]
            except Unavailable as exc:
                if root.source is None:
                    ctx.say(f"lazaret guard: {root.id} cannot be {'updated' if update else 'installed'}: {exc}")
                    return G.finish(ctx, installed=False, code=G.EXIT_RESOLVE)
                run.note(f"what {root.source} brings is left out, as the editor leaves it when one of them cannot be "
                         f"installed: {exc}")
        to_install = [r for r in roots] + [b for b in brought if b.check is not None]
        _check_malicious(run, to_install)
        if ctx.blocked() or ctx.opts.plan or not to_install:
            return G.finish(ctx, installed=False, code=G.EXIT_OK)
        code = _install(run, to_install, no_deps)
        if code is None:
            return G.finish(ctx, installed=False, code=G.EXIT_RESOLVE)
        after = installed_extensions(editor, env, values)
        planned = {(i.id, i.version) for i in to_install}
        changed = {(k, v) for k, v in after.items() if installed.get(k) != v}
        ctx.unchecked = sorted(f"{k}@{v}" for k, v in changed - planned)
        missing = sorted(f"{k}@{v}" for k, v in planned if after.get(k) != v)
        if missing:
            ctx.notes.append(f"{editor.label} did not install {', '.join(missing[:10])}"
                             + (f", … (+{len(missing) - 10})" if len(missing) > 10 else ""))
        return G.finish(ctx, installed=code == 0, code=code)
    finally:
        G.remove_tree(scratch)


def _plan_roots(run, requests):
    """The Items the command asks for, chosen, fetched and checked; those the editor would leave alone (installed
    already) said and left out. -> (items, the reasons the command cannot be done)."""
    ctx, editor, installed = run.ctx, run.editor, run.present          # (built-in extensions count, as for the editor)
    force, pre = "--force" in run.flags, "--pre-release" in run.flags
    roots, failed, jobs = [], [], []
    for r in requests:
        if r.path is not None:
            item = _file_item(run, r, force)
            if item is not None:
                roots.append(item)
            continue
        have = installed.get(r.id)
        if have is not None and not force and r.version is None:          # (@prerelease too: the editor's rule)
            ctx.say(f"lazaret guard: {r.id} {have} is installed already, and the editor leaves it (--force updates it, "
                    f"or name a version: {r.id}@1.2.3)")
            continue
        if have is not None and r.version is not None and have == r.version:
            ctx.say(f"lazaret guard: {r.id}@{r.version} is installed already")
            continue
        target, ext_id, why = run.replacement(r.id), r.id, "asked for"
        try:
            try:
                candidate, artifact = run.choose(r.id, r.version, r.pre or pre)
            except Unavailable as exc:
                if exc.missing or target is None:
                    raise
            if target is not None:
                # (the editor finds it in its gallery, then installs the replacement, at its newest version, in its
                # place: VS Code's checkAndGetCompatibleVersion, EG-7)
                run.replaced(r.id, r.text)
                ext_id, why = target[0], f"in place of {r.id}"
                have = installed.get(ext_id)
                candidate, artifact = run.choose(ext_id, None, target[1])
        except Unavailable as exc:
            failed.append(f"{r.text} cannot be installed: " + (f"{ext_id}, which the editor installs in its place: "
                                                                if ext_id != r.id else "") + str(exc))
            continue
        except (base.FetchError, repo.FetchError, ValueError) as exc:
            failed.append(f"{r.text} could not be looked up: {exc}")
            continue
        if have is not None and have == candidate.version:
            ctx.say(f"lazaret guard: {ext_id}@{have} is installed already")
            continue
        if any(i.id == ext_id for i in roots):
            continue                             # (the replacement of another asked for, asked for too)
        item = Item(ext_id, why)
        item.candidate, item.artifact, item.version = candidate, artifact, candidate.version
        item.pre = r.pre or pre or (target is not None and target[1])
        item.replaces = r.id if target is not None else None
        item.downgrade = have is not None and editorcompat.version_key(have) > editorcompat.version_key(item.version)
        item.check = ctx.add(G.Check(editor.gallery, ext_id, item.version, why))
        run.items.append(item)
        roots.append(item)
        jobs.append(lambda i=item: run.fetch_item(i))
    G.run_all(jobs)
    return roots, failed


def _file_item(run, request, force):
    """The Item for a `.vsix` named on the command line: read, checked and copied as a downloaded one; None when the
    editor would leave it (a newer version installed, without --force)."""
    ctx = run.ctx
    try:
        size = os.path.getsize(request.path)
        if size > repo.MAX_DOWNLOAD_BYTES:
            raise G.GuardError(f"{request.text} is larger than the {repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB the "
                               f"guard scans")
        with open(request.path, "rb") as f:
            data = f.read(repo.MAX_DOWNLOAD_BYTES + 1)
    except OSError as exc:
        raise G.GuardError(f"{request.text}: {exc.strerror or exc}") from None
    try:
        manifest = vsix_manifest(data)
    except ValueError as exc:
        raise G.GuardError(f"{request.text} is not an extension the editor installs: {exc}") from None
    have = run.present.get(manifest.id)
    if have is not None and not force and editorcompat.version_key(have) > editorcompat.version_key(manifest.version):
        ctx.say(f"lazaret guard: a newer {manifest.id} ({have}) is installed; the editor leaves it (--force installs "
                f"{manifest.version} over it)")
        return None
    if run.editor.version and manifest.engine and not editorcompat.engine_ok(manifest.engine, run.editor.version,
                                                                             run.editor.date):
        raise G.GuardError(f"{request.text} is not for {run.editor.label} {run.editor.version} (its engines.vscode is "
                           f"{lazaret.sanitize_term_line(manifest.engine)})")
    item = Item(manifest.id, f"the file {request.text}")
    item.source, item.version = request.text, manifest.version
    item.downgrade = have is not None and editorcompat.version_key(have) > editorcompat.version_key(manifest.version)
    item.check = ctx.add(G.Check("vsix", manifest.id, manifest.version, f"file {request.text}"))
    run.items.append(item)
    run._take(item, data)
    return item


def _plan_updates(run, origins):
    """The Items for what the editor's --update-extensions would update, chosen, fetched and checked (module
    docstring): of the extensions the editor lists, each from its gallery (`origins`, what the profile recorded), at
    the newest version it would take when that is newer than the one installed. The guard reads the editor's own
    gallery here (Editor.gallery_problem), so the identifiers the editor keeps are compared with the registry's. ->
    (items, the lookups that failed: the editor's update fails whole when its query does)."""
    ctx, editor, installed = run.ctx, run.editor, run.installed
    if len(installed) > MAX_PLANNED:
        raise G.GuardError(f"{editor.label} lists {len(installed)} extensions; the guard looks at {MAX_PLANNED} at most "
                           f"(update them by name: --install-extension ID --force)")
    choices, jobs, unrecorded = {}, [], []

    def look(ext_id, have, origin):
        choices[ext_id] = _update_choice(run, ext_id, have, origin)

    for ext_id, have in sorted(installed.items()):
        origin = origins.get((ext_id, have))
        if origin is None:
            unrecorded.append(ext_id)
            origin = Origin(have)
        if origin.source == "resource" and origin.uuid is None:
            continue                         # (installed from a location: the editor matches it to no gallery)
        jobs.append(lambda i=ext_id, h=have, o=origin: look(i, h, o))
    if unrecorded:
        run.note(", ".join(unrecorded[:10]) + (f", … (+{len(unrecorded) - 10})" if len(unrecorded) > 10 else "")
                 + f": the editor lists {'it' if len(unrecorded) == 1 else 'them'}, and its profile does not record "
                 f"{'it' if len(unrecorded) == 1 else 'them'} at that version: matched to {GALLERIES[editor.gallery]} "
                 f"by name, as releases")
    G.run_all(jobs)
    items, failed = [], []
    for ext_id in sorted(choices):
        kind, value = choices[ext_id] or (None, None)
        if kind == "failed":
            failed.append(value)
        elif kind == "note":
            run.note(value)
        elif kind == "update":
            items.append(value)
    if failed:
        return [], failed
    # (one install of an id: an extension's own update before a replacement of another by it, which would take its
    # release where it follows pre-releases; of two replacements by one id, the first: EG-7, EG-13)
    own, seen, fetches = {i.id for i in items if i.replaces is None}, set(), []
    items = [i for i in items if not ((i.replaces is not None and i.id in own) or i.id in seen or seen.add(i.id))]
    for item in items:
        item.check = ctx.add(G.Check(editor.gallery, item.id, item.version, item.why))
        if item.held:
            item.check.notes.append(item.held)
        run.items.append(item)
        fetches.append(lambda i=item: run.fetch_item(i))
    G.run_all(fetches)
    return items, []


def _old_enough(run, ext_id, pre, candidate, artifact, have):
    """--min-age for an update: (candidate, artifact, None) when `candidate` is old enough (or let in); else the newest
    version old enough, if it is newer than `have` (None: none installed), with the words for what was held back; else
    (None, None, why there is none). FetchError passes."""
    ctx = run.ctx
    if ctx.cutoff is None or candidate.when is None or candidate.when <= ctx.cutoff \
            or ctx.matches(ctx.opts.allow_new, run.editor.gallery, ext_id):
        return candidate, artifact, None
    young, age = candidate.version, G.format_age(ctx.min_age)
    try:
        older, artifact = run.choose(ext_id, None, pre, keep=lambda c: c.when is not None and c.when <= ctx.cutoff)
    except Unavailable:
        older = None
    if older is None or (have is not None
                         and editorcompat.version_key(older.version) <= editorcompat.version_key(have)):
        return None, None, f"{young} is younger than --min-age {age} (--allow-new {ext_id} lets it in)"
    return older, artifact, f"{young} held back: younger than --min-age {age}"


def _update_choice(run, ext_id, have, origin):
    """What --update-extensions does with one installed extension: None (nothing newer, or not the gallery's), ("note",
    why it is left alone), ("failed", the lookup that failed), or ("update", Item). One with a gallery identifier is
    updated only while the gallery's extension of its name has that identifier. One the gallery's control list
    replaces is updated as the editor updates it: by installing the replacement (EG-7)."""
    editor = run.editor
    try:
        candidate, artifact = run.choose(ext_id, None, origin.pre)
    except Unavailable as exc:
        if exc.missing and origin.uuid is None:
            return None                      # (installed from a file, and no extension of the gallery's)
        return "note", f"{ext_id} {have} is not updated: {exc}"
    except (base.FetchError, repo.FetchError, ValueError) as exc:
        return "failed", f"{ext_id} could not be looked up: {exc}"
    if editorcompat.version_key(candidate.version) <= editorcompat.version_key(have):
        return None
    if origin.uuid is not None:
        try:
            gid = run.module.gallery_id(ext_id, run.fetch)
        except base.NotFound:
            gid = None
        except (base.FetchError, repo.FetchError, ValueError) as exc:
            return "failed", f"{ext_id} could not be looked up: {exc}"
        if gid != origin.uuid:
            return "note", (f"{ext_id} {have} is not updated: the extension {GALLERIES[editor.gallery]} has by that "
                            f"name is not the one installed (its gallery identifier is another), and the editor "
                            f"updates the one it installed")
    old_id, old_have, pre = ext_id, have, origin.pre
    target = run.replacement(ext_id)
    try:
        if target is not None:
            # (the editor installs the replacement, at its newest version, in place of the update: EG-7)
            ext_id, pre = target
            have = run.installed.get(ext_id)
            candidate, artifact = run.choose(ext_id, None, pre)
        candidate, artifact, held = _old_enough(run, ext_id, pre, candidate, artifact, have)
    except Unavailable as exc:
        return "note", (f"{old_id} {old_have} is not updated: the editor installs {ext_id} in its place, which it cannot "
                        f"be: {exc}")
    except (base.FetchError, repo.FetchError, ValueError) as exc:
        return "failed", f"{ext_id} could not be looked up: {exc}"
    if candidate is None:
        return "note", f"{old_id} {old_have} is not updated: " + (
            f"the editor installs {ext_id} in its place, and {held}" if target is not None else held)
    if target is None:
        why = f"update from {have}"
    else:
        if have is not None and editorcompat.version_key(candidate.version) <= editorcompat.version_key(have):
            return None                      # (the replacement is installed at that version already)
        run.replaced(old_id, f"the update of {old_id} {old_have}")
        why = f"in place of {old_id} {old_have}"
    item = Item(ext_id, why)
    item.candidate, item.artifact, item.version, item.held = candidate, artifact, candidate.version, held
    item.pre = pre or origin.pre
    item.replaces = old_id if target is not None else None
    item.everywhere = origin.everywhere          # (the editor updates it where it keeps it: EG-16)
    return "update", item


def _install(run, items, no_deps):
    """Have the editor install the checked files: one command from VS Code 1.98 on (it then fetches nothing
    itself), else wave by wave, each extension after what it brings. Those that follow pre-releases are installed
    with --pre-release (EG-15), and an update of one installed in every profile without --profile, in the default
    profile where the editor keeps it (EG-16): a command for each. -> the editor's exit code; None when the install
    cannot be made safely (said)."""
    ctx, editor = run.ctx, run.editor
    flag = editor.takes_pack_flag()
    if flag:
        waves = [items]
    else:
        waves, cycle = order_waves(items, lambda i: [b for b, _d in run.brings(i)] if not no_deps else [])
        if cycle:
            names = ", ".join(sorted(i.id for i in cycle))
            if flag is False:
                ctx.say(f"lazaret guard: {names} bring one another, and {editor.label} {editor.version} installs what "
                        f"an extension brings itself (VS Code 1.98 does not): nothing installed")
                return None
            run.note(f"{names} bring one another; they are installed together")
            waves.append(cycle)
    pre_all = "--pre-release" in run.flags
    for wave in waves:
        groups = collections.OrderedDict()
        for item in wave:
            groups.setdefault((pre_all or item.pre, item.everywhere), []).append(item)
        for (pre, everywhere), members in groups.items():
            for start in range(0, len(members), INSTALL_BATCH):
                batch = members[start:start + INSTALL_BATCH]
                argv = [editor.exe]
                for item in batch:
                    argv += ["--install-extension", item.path]
                argv += _passed({k: v for k, v in run.values.items() if not (everywhere and k == "--profile")})
                if "--force" in run.flags or any(i.downgrade for i in batch):
                    argv.append("--force")
                if pre:
                    argv.append("--pre-release")
                if "--do-not-sync" in run.flags:
                    argv.append("--do-not-sync")
                if flag or no_deps:
                    argv.append("--do-not-include-pack-dependencies")
                proc = G.run_tool(argv, run.env)
                if proc.returncode != 0:
                    return proc.returncode
    return 0
