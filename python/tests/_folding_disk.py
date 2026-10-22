"""A disk that ignores case and Unicode normalization, on any machine, for the tests (MAC-TESTS). Nothing here is a
test.

macOS's disk (APFS, case-insensitive by default) and Windows' compare names as one when they differ only in case or
Unicode form, and keep a name as it was first written: a folder holds one of `a.js` and `A.js`. Under
`folding_disk(root)` the calls a writer makes under `root` (os.mkdir, and through it os.makedirs; os.stat, os.lstat;
open; os.link) find a name that folds as one already in its folder, as such a disk does, so a Linux run sees what a
Mac sees: mkdir, an exclusive create and a hard link fail on it, and open(..., "wb") writes over it under its first
name. Names fold as `unicodedata`'s NFD, then str.casefold() (APFS's reading, near enough for test names), or as
`fold` says: a disk that folds names some other way. Paths outside `root` are left alone.

    with folding_disk(root):
        sources.checkout(spec, dest=root, ...)"""

import builtins
import contextlib
import os
import shutil
import tempfile
import unicodedata
from unittest import mock


def apfs_fold(name):
    return unicodedata.normalize("NFD", name).casefold()


def tells_names_apart(folder):
    """Whether the disk that holds `folder` keeps names that differ only in case, or only in Unicode form, apart, as
    Linux's do (macOS's and Windows' do not, by default)."""
    probe = tempfile.mkdtemp(dir=folder)
    try:
        for one, other in (("a", "A"), ("\u00e9", "e\u0301")):
            open(os.path.join(probe, one), "xb").close()
            try:
                open(os.path.join(probe, other), "xb").close()
            except FileExistsError:
                return False
        return True
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@contextlib.contextmanager
def folding_disk(root, fold=apfs_fold):
    roots = {os.path.abspath(root), os.path.realpath(root)}      # (as given, and behind its links: macOS's /var)
    real_open, real_mkdir, real_stat, real_lstat, real_listdir = builtins.open, os.mkdir, os.stat, os.lstat, os.listdir
    real_link = os.link

    def resolve(path):
        if not isinstance(path, (str, os.PathLike)) or isinstance(path, bytes):
            return path
        full = os.path.abspath(os.fspath(path))
        top = next((r for r in roots if full == r or full.startswith(r + os.sep)), None)
        if top is None:
            return path
        at = top
        for part in os.path.relpath(full, top).split(os.sep):
            if part in ("", "."):
                continue
            try:
                names = real_listdir(at)
            except OSError:
                names = []
            key = fold(part)
            at = os.path.join(at, next((n for n in names if fold(n) == key), part))
        return at

    def mkdir(path, mode=0o777, *, dir_fd=None):
        return real_mkdir(resolve(path), mode, dir_fd=dir_fd)

    def stat(path, *, dir_fd=None, follow_symlinks=True):
        return real_stat(resolve(path), dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def lstat(path, *, dir_fd=None):
        return real_lstat(resolve(path), dir_fd=dir_fd)

    def open_(file, *args, **kwargs):
        return real_open(resolve(file), *args, **kwargs)

    def link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
        return real_link(resolve(src), resolve(dst), src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                         follow_symlinks=follow_symlinks)

    with mock.patch.object(os, "mkdir", mkdir), mock.patch.object(os, "stat", stat), \
            mock.patch.object(os, "lstat", lstat), mock.patch.object(builtins, "open", open_), \
            mock.patch.object(os, "link", link):
        yield
