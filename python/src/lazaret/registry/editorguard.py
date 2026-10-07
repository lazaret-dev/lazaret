"""lazaret guard code --install-extension … (0.1.9, E-1's fifth part): a VS Code extension, and every extension it
brings, checked before the editor installs it.

    lazaret guard code --install-extension ms-python.python
    lazaret guard code --install-extension redhat.java@1.40.0 --install-extension ./my-extension.vsix
    lazaret guard cursor --install-extension rust-lang.rust-analyzer --pre-release
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
                    gallery and the VS Code version its extensions are checked against; --gallery says which registry
                    to use. A `.vsix` named on the command line is read from its file.
    the checks      each file scanned in memory as `lazaret FILE.vsix` scans it (its main and browser modules, and what
                    they load, as what runs when the editor activates it; names like a popular extension's;
                    vscode:uninstall), with the verdict cache, --min-age (the registry's publish time), --trust,
                    --allow-new and --block-warn as for the package managers; and the list of extensions the editor's
                    gallery has found malicious (product.json's controlUrl; the Marketplace's own for its extensions),
                    which the editor applies to what it downloads itself, and not to a file it is given.
    the install     nothing is installed when anything is blocked, or under --plan. Otherwise the editor installs the
                    files the guard checked, written to a folder of the user's own (`<editor> --install-extension
                    FILE.vsix`): from VS Code 1.98 on, with --do-not-include-pack-dependencies, so that it fetches
                    nothing itself; before that, those an extension brings first, so that it finds them installed.
                    Then the extensions the editor lists are compared with what was checked: anything else it
                    installed is reported, and the run fails.

An extension installed from a file is pinned by the editor, as one installed with `@version` is: it does not update
it on its own, so it stays at what was checked. `--update-extensions` is not wrapped yet: an update the editor makes
itself is outside any guard's reach (`lazaret --extensions` scans what is installed)."""

import collections
import hashlib
import io
import os
import platform
import re
import subprocess
import sys
import types
import urllib.parse
import zipfile

from lazaret.registry import editorcompat, repo
from lazaret.registry import guard as G
from lazaret.registry.ecosystems import base
from lazaret.scanner import core as lazaret

__all__ = ["EDITORS", "GALLERIES", "guard_editor", "parse_args", "Request", "Manifest", "vsix_manifest",
           "read_manifest", "Editor", "read_editor", "installed_extensions", "order_waves"]

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
#: The gallery a product.json's extensionsGallery.serviceUrl names, by its host.
GALLERY_HOSTS = {"marketplace.visualstudio.com": "vscode", "open-vsx.org": "openvsx"}
#: The list of extensions Microsoft has found malicious, as VS Code reads it (its product.json's controlUrl).
MARKETPLACE_CONTROL = "https://main.vscode-cdn.net/extensions/marketplace.json"
#: VS Code installs exactly the files it is given, and none of the extensions they bring, from 1.98 on.
PACK_FLAG_SINCE = (1, 98)
MAX_MANIFEST = 4 * 1024 * 1024
MAX_PRODUCT = 2 * 1024 * 1024
MAX_CONTROL = 16 * 1024 * 1024
MAX_BUILTINS = 1000
MAX_LISTED = 500                     # the extensions one manifest lists (as the registry modules read them)
MAX_PLANNED = 500                    # the extensions one run looks at
EDITOR_TIMEOUT = 120                 # --version and --list-extensions
#: The files one editor command installs (a command line of `code.cmd` goes through cmd.exe, 8,191 characters at most)
INSTALL_BATCH = 25

VALUE_OPTIONS = ("--install-extension", "--profile", "--extensions-dir", "--user-data-dir")
FLAG_OPTIONS = ("--force", "--pre-release", "--do-not-sync", "--do-not-include-pack-dependencies")
PASSED_VALUES = ("--profile", "--extensions-dir", "--user-data-dir")
NOT_WRAPPED = ("--update-extensions", "--uninstall-extension", "--install-builtin-extension", "--list-extensions",
               "--locate-extension")

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*")
#: VS Code's `id@version` (extensionManagementUtil's): a version is MAJOR.MINOR.PATCH[-…], or `prerelease`
_ID_VERSION_RE = re.compile(r"^([^.]+\..+)@((prerelease)|(\d+\.\d+\.\d+(-.*)?))$")
_LISTED_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*)@(\S{1,100})$")
_VSCODE_VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,9})")
_PLATFORM_RE = re.compile(r"[a-z0-9]{1,16}(?:-[a-z0-9]{1,16}){0,3}")


class Unavailable(Exception):
    """The editor would not install the extension: no such extension or version, no file for this platform, none
    for this editor's version, or a file that is not the version the registry named."""


# ---------------- the command line ----------------
class Request:
    """One `--install-extension` value: a `.vsix` file (path), or an extension (id, a version or None, pre: @prerelease)."""
    __slots__ = ("text", "path", "id", "version", "pre")

    def __init__(self, text, path=None, ext_id=None, version=None, pre=False):
        self.text, self.path, self.id, self.version, self.pre = text, path, ext_id, version, pre


def parse_args(tool, args, cwd=None):
    """(requests, flags, values) of an editor's command line: the `--install-extension` values (a value ending in
    `.vsix` is a file, relative to the current folder, as the editor reads it; else `id[@version]`), the flags and the
    options passed on. GuardError for anything else, or for no `--install-extension`."""
    requests, flags, values = [], set(), {}
    k = 0
    while k < len(args):
        arg = args[k]
        name, eq, value = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if name in FLAG_OPTIONS and not eq:
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
            raise G.GuardError(f"lazaret guard wraps {tool} --install-extension; {name} is not wrapped (yet)")
        else:
            raise G.GuardError(f"lazaret guard {tool}: {lazaret.sanitize_term_line(arg)!r} is not an option the guard "
                               f"passes on ({', '.join(FLAG_OPTIONS + PASSED_VALUES)})")
        k += 1
    if not requests:
        raise G.GuardError(f"lazaret guard wraps {tool} --install-extension ID[@VERSION] | FILE.vsix")
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
    """The Manifest of a `.vsix` (its `extension/package.json`, the one entry of that name the editor reads);
    ValueError when there is none, two, or one that is not an extension's."""
    reason = repo._zip_preflight(data)
    if reason:
        raise ValueError(reason)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [i for i in zf.infolist() if i.filename == "extension/package.json"]
            if len(infos) != 1:
                raise ValueError("it has no extension/package.json" if not infos else
                                 "it has two extension/package.json entries")
            if infos[0].file_size > MAX_MANIFEST:
                raise ValueError("its package.json is larger than the guard reads")
            with zf.open(infos[0]) as f:
                raw = f.read(MAX_MANIFEST + 1)
    except repo._ZIP_READ_ERRORS as exc:
        raise ValueError(f"it is not a zip the guard can read ({type(exc).__name__})") from None
    if len(raw) > MAX_MANIFEST:
        raise ValueError("its package.json is larger than the guard reads")
    doc, _issues = lazaret.load_manifest("package.json", raw.decode("utf-8", errors="replace"))
    return read_manifest(doc)


def _read_json_file(path, limit):
    """A JSON object from a file of at most `limit` bytes; None when it cannot be read or is not one."""
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError:
        return None
    if len(raw) > limit:
        return None
    doc, _issues = lazaret.load_manifest(os.path.basename(path), raw.decode("utf-8", errors="replace"))
    return doc if isinstance(doc, dict) else None


# ---------------- the editor ----------------
class Editor:
    """The editor the command runs: its executable, its name, the registry it installs from, the VS Code version its
    extensions' engines are checked against (None: not known), its build date, its target platform, its app folder
    (where product.json is; None: not found), its built-in extensions ({id: version}) and its malicious list's URL."""

    def __init__(self, tool, exe, label, gallery, data_folder):
        self.tool, self.exe, self.label, self.gallery, self.data_folder = tool, exe, label, gallery, data_folder
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


def read_editor(tool, exe, env, gallery=None, system=None):
    """The Editor `exe` is: `<exe> --version` (its version, its commit, the architecture its build runs on) and its
    product.json when found (a fork's VS Code version, `vscodeVersion`; its build date; its gallery; its malicious
    list). GuardError when `--version` fails."""
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
    gallery_doc = ed.product.get("extensionsGallery") if isinstance(ed.product.get("extensionsGallery"), dict) else {}
    service = gallery_doc.get("serviceUrl") if isinstance(gallery_doc.get("serviceUrl"), str) else None
    named = GALLERY_HOSTS.get((urllib.parse.urlsplit(service).hostname or "").lower()) if service else None
    if gallery:
        ed.gallery = gallery
    elif named:
        ed.gallery = named
    elif service:
        ed.notes.append(f"{label}'s product.json names a gallery the guard does not read "
                        f"({base.show(urllib.parse.urlsplit(service).hostname or service)}): it reads "
                        f"{GALLERIES[ed.gallery]} (--gallery chooses)")
    control = gallery_doc.get("controlUrl")
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
        self.pre = False                     # asked for with @prerelease (what it brings is taken as pre-releases too)


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
        self.resolved = {}                   # (id, pre) -> Item, or Unavailable
        self.items = []                      # every Item downloaded, to install unless blocked
        self.counter = 0

    def note(self, line):
        if line not in self.ctx.notes:
            self.ctx.notes.append(line)

    # ---- choosing a file
    def choose(self, ext_id, version=None, pre=False):
        """(candidate, artifact) of the file the editor would install. Unavailable when there is none; FetchError when
        the registry could not be asked."""
        ed, chosen, last = self.editor, None, []
        try:
            for cands in self.module.candidates(ext_id, self.fetch, version):
                last = cands
                chosen = editorcompat.choose(cands, ed.target, ed.version, ed.date, version, pre)
                if chosen is not None:
                    break
        except base.NotFound:
            raise Unavailable(f"not found in {GALLERIES[ed.gallery]}"
                              + (f" (no version {version})" if version else "")) from None
        if chosen is None:
            raise Unavailable(self._why_none(last, version, pre))
        return chosen, self.module.artifact(ext_id, chosen, self.fetch)

    def _why_none(self, cands, version, pre):
        ed = self.editor
        if version is not None:
            cands = [c for c in cands if c.version == version]
            if not cands:
                return f"{GALLERIES[ed.gallery]} has no version {version} of it"
        elif not pre:
            if cands and all(c.pre for c in cands):
                return "it has no release, only pre-releases (--pre-release installs one)"
            cands = [c for c in cands if not c.pre]
        if not cands:
            return f"not found in {GALLERIES[ed.gallery]}"
        if not any(editorcompat.platform_fits(c.platform, ed.target) for c in cands):
            return f"it has no file for {ed.target}"
        return f"none of its versions is for {ed.label} {ed.version} (their engines.vscode)"

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
        editor reads it."""
        key = (ext_id, pre)
        if key in self.resolved:
            return self.resolved[key]
        item = Item(ext_id, f"brought by {bringer.id}", dependency, bringer)
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
        self.resolved[key] = item
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
                    if ext_id in known:
                        continue
                    was = wanted.get(ext_id)
                    wanted[ext_id] = (item if was is None else was[0], dependency or (was is not None and was[1]))
            jobs = [(lambda i=ext_id, b=by, d=dep: self.resolve_brought(i, b, d, pre)) for ext_id, (by, dep) in wanted.items()]
            G.run_all(jobs)
            level = []
            for ext_id, (by, dep) in wanted.items():
                res = self.resolved[(ext_id, pre)]
                if isinstance(res, Unavailable):
                    if dep:
                        raise Unavailable(f"it needs {ext_id}, which the editor cannot install: {res}")
                    self.note(f"{ext_id}, in the pack of {by.id}, is left out, as the editor leaves it: {res}")
                    continue
                known.add(ext_id)
                found.append(res)
                level.append(res)
        return found


def _malicious(run):
    """The ids and publishers the editor's gallery lists as malicious (lowercase), from its control URL; None when
    there is no list or it could not be read (said)."""
    url = run.editor.control_url
    if not url:
        return None
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    eco = types.SimpleNamespace(id="control", hosts=frozenset({host}), rate={})
    try:
        doc = base.Fetch(eco, repo.module_transport).json(url, max_bytes=MAX_CONTROL)
        listed = doc.get("malicious") if isinstance(doc, dict) else None
        if not isinstance(listed, list):
            raise base.FetchError("the answer has no list of malicious extensions")
    except (base.FetchError, repo.FetchError, ValueError) as exc:
        run.note(f"the list of malicious extensions at {host} could not be read ({exc}): not checked against it")
        return None
    return {x.lower() for x in listed if isinstance(x, str)}


def _check_malicious(run, items):
    listed = _malicious(run) if items else None
    if not listed:
        return
    host = (urllib.parse.urlsplit(run.editor.control_url).hostname or "").lower()
    for item in items:
        if item.check is None:
            continue
        publisher = item.id.split(".", 1)[0]
        if item.id in listed or publisher in listed:
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
    """lazaret guard <editor> --install-extension …: -> the exit code (finish's)."""
    requests, flags, values = parse_args(tool, args)
    exe = G.find_tool(tool)
    env = dict(os.environ)
    editor = read_editor(tool, exe, env, gallery)
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
    ctx.unchecked_hint = ("the editor installed or updated them itself (from its window, or an update of its own); look "
                          "at them, or uninstall them")
    scratch = G.private_scratch("lazaret-guard-ext-")
    try:
        run = Run(ctx, editor, env, flags, values, installed, scratch, fetch)
        roots, failed = _plan_roots(run, requests)
        if failed:
            for line in failed:
                ctx.say(f"lazaret guard: {line}")
            return G.finish(ctx, installed=False, code=G.EXIT_RESOLVE)
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
                    ctx.say(f"lazaret guard: {root.id} cannot be installed: {exc}")
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
        try:
            candidate, artifact = run.choose(r.id, r.version, r.pre or pre)
        except Unavailable as exc:
            failed.append(f"{r.text} cannot be installed: {exc}")
            continue
        except (base.FetchError, repo.FetchError, ValueError) as exc:
            failed.append(f"{r.text} could not be looked up: {exc}")
            continue
        if have is not None and have == candidate.version:
            ctx.say(f"lazaret guard: {r.id}@{have} is installed already")
            continue
        item = Item(r.id, "asked for")
        item.candidate, item.artifact, item.version, item.pre = candidate, artifact, candidate.version, r.pre
        item.downgrade = have is not None and editorcompat.version_key(have) > editorcompat.version_key(item.version)
        item.check = ctx.add(G.Check(editor.gallery, r.id, item.version, "asked for"))
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


def _install(run, items, no_deps):
    """Have the editor install the checked files: one command from VS Code 1.98 on (it then fetches nothing
    itself), else wave by wave, each extension after what it brings. -> the editor's exit code; None when the
    install cannot be made safely (said)."""
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
    for wave in waves:
        for start in range(0, len(wave), INSTALL_BATCH):
            batch = wave[start:start + INSTALL_BATCH]
            argv = [editor.exe]
            for item in batch:
                argv += ["--install-extension", item.path]
            argv += _passed(run.values)
            if "--force" in run.flags or any(i.downgrade for i in batch):
                argv.append("--force")
            for name in ("--pre-release", "--do-not-sync"):
                if name in run.flags:
                    argv.append(name)
            if flag or no_deps:
                argv.append("--do-not-include-pack-dependencies")
            proc = G.run_tool(argv, run.env)
            if proc.returncode != 0:
                return proc.returncode
    return 0
