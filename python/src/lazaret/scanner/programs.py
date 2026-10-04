"""Where a program Lazaret runs is: the first of PATH's folders that holds it, as a shell finds it, though only among the
folders PATH names by an absolute path. Never the current folder.

Python's shutil.which looks in the current folder first on Windows (3.11 always; later versions unless
NoDefaultCurrentDirectoryInExePath is set) and, on every system, in it for an empty or relative PATH entry; subprocess given a
bare name looks there on Windows too (CreateProcess). A project or repository with a go.exe, git.exe or npm.cmd of its own
would then run in the real tool's place, and `lazaret guard` runs in a project's folder, `lazaret hook` in a repository's
(the Go/Rust review's GO-8, Oct 4, 2026; GitPython's CVE-2023-40590 is the same hazard)."""

import os

#: Windows' own list when PATHEXT is not set
WINDOWS_PATHEXT = ".COM;.EXE;.BAT;.CMD"


def _windows():
    return os.name == "nt"


def folders(path=None):
    """PATH's folders a program is looked up in, in order and once each: those named by an absolute path (on Windows, one with
    a drive or a share). path is a PATH value; None reads the environment's (the system's default path when it has none)."""
    if path is None:
        path = os.environ.get("PATH")
        if path is None:
            try:
                path = os.confstr("CS_PATH")
            except (AttributeError, ValueError):
                path = os.defpath
    seen, found = set(), []
    for d in (path or "").split(os.pathsep):
        if _windows():
            d = d.strip().strip('"')
            drive, rest = os.path.splitdrive(d)
            if not drive or not (rest[:1] in ("\\", "/") or drive[:2] in ("\\\\", "//")):
                continue                        # (a drive and a root, or a share: `C:x` is relative to C:'s current folder)
        elif not d or not os.path.isabs(d):
            continue
        key = os.path.normcase(os.path.normpath(d))
        if key not in seen:
            seen.add(key)
            found.append(d)
    return found


def file_names(name):
    """The file names a program is found under: on Windows, the name with each of PATHEXT's extensions, unless it has one."""
    if not _windows():
        return [name]
    exts = [e for e in (os.environ.get("PATHEXT") or WINDOWS_PATHEXT).split(os.pathsep) if e]
    if any(name.lower().endswith(e.lower()) for e in exts):
        return [name]
    return [name + e for e in exts]


def find(name, path=None):
    """The full path of the program `name` (a bare name: one with a folder in it is refused) in PATH's absolute folders
    (folders), or None when none of them holds it."""
    if not name or os.sep in name or (os.altsep and os.altsep in name) or os.path.dirname(name):
        return None
    for d in folders(path):
        for n in file_names(name):
            p = os.path.join(d, n)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None
