"""Safe report-path handling for the Lazaret CLI.

Contract (card: "CLI writes reports into CWD"):
  1. Default report paths resolve under the scan root (or --out-dir), never
     bare CWD-relative names.
  2. Output writability is checked BEFORE scanning, failing fast with a clear
     message (exit code EXIT_OUTPUT = 3) instead of a post-scan
     PermissionError that throws away the whole scan's results.
  3. A pre-existing file is never silently clobbered. Every report this tool
     writes carries a provenance marker; an existing destination without
     that marker is refused with a clear error, again before the scan runs.
     Overwriting a report from an earlier run of this engine is the intended
     re-scan workflow and stays allowed (--force-overwrite overrides).

Imported by lazaret.scanner.core; stdlib only, unit-testable on its own.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile

JSON_REPORT_NAME = "lazaret-report.json"
HTML_REPORT_NAME = "lazaret-report.html"

#: Provenance markers. A pre-existing destination carrying exactly this
#: key/value pair is one of OUR reports (safe to overwrite — that's the
#: re-scan workflow); anything else is not ours and is refused.
ENGINE_MARKER = "generatedBy"
ENGINE_VERSION = "lazaret-cli-1"

#: Marker embedded in the HTML report's <head> (same pair as above).
HTML_ENGINE_MARKER = f'<meta name="{ENGINE_MARKER}" content="{ENGINE_VERSION}">'

#: Exit code for report-path errors (distinct from the quality-gate exit 1
#: and argparse's exit 2, both already in use by the CLI).
EXIT_OUTPUT = 3

#: How much of an existing file to read when checking provenance. Markers
#: are written at the very start of a report (first key / <head>), so a
#: bounded read is enough for multi-megabyte reports.
MARKER_READ_BYTES = 65536


class ReportPathError(Exception):
    """Anything that makes a report path unusable or unsafe.

    The CLI catches this BEFORE the scan starts and exits EXIT_OUTPUT with a
    clear message, so the user never pays the scan cost only to lose the
    results at write time.
    """


# ---------------------------------------------------------------------------
# Path computation
# ---------------------------------------------------------------------------
def resolve_default_report_paths(scan_root, out_dir=None):
    """Final, absolute paths for the default JSON/HTML reports.

    *scan_root* and *out_dir* are resolved the same way as the scan target
    itself (relative to the current working directory), so the default
    reports land under the scan root or the requested output directory —
    never as bare CWD-relative names, and the outcome for one invocation
    does not depend on which directory the user happens to run from.
    """
    base = os.path.abspath(out_dir if out_dir else scan_root)
    return {
        "json": os.path.join(base, JSON_REPORT_NAME),
        "html": os.path.join(base, HTML_REPORT_NAME),
    }


def report_paths(args, scan_root):
    """Compute final paths for every report file this run may write.

    Applies the flags of an argparse.Namespace as parsed by lazaret.main():
      --out-dir DIR       where the default json/html reports go (must
                          exist and be writable; validated separately)
      --json/--html PATH  explicit report paths; a relative path is taken
                          relative to --out-dir (default: the scan root)
      --sarif PATH        same treatment as --json/--html
    Returns {"json": abs, "html": abs, "sarif": abs or None}.
    """
    out_dir = getattr(args, "out_dir", None)
    base = os.path.abspath(out_dir if out_dir else scan_root)
    paths = resolve_default_report_paths(scan_root, out_dir)
    paths["sarif"] = None
    for key in ("json", "html"):
        user_path = getattr(args, key, None)
        if user_path:
            paths[key] = (os.path.join(base, user_path)
                          if not os.path.isabs(user_path) else user_path)
    sarif = getattr(args, "sarif", None)
    if sarif:
        paths["sarif"] = (os.path.join(base, sarif)
                          if not os.path.isabs(sarif) else sarif)
    return paths


# ---------------------------------------------------------------------------
# Writability probes (never touch existing report content)
# ---------------------------------------------------------------------------
def check_writable_dir(path):
    """True if a new file can be created inside directory *path* right now.

    Probes with a real mkstemp in that directory — the same operation the
    report write will use — so it catches permission problems, read-only
    directories and read-only filesystems exactly like the real write would.
    Creating and replacing a file both only need write access to the
    directory, which is what this tests. os.access() would both special-case
    root and be TOCTOU-prone, hence the real probe.
    """
    try:
        fd, tmp = tempfile.mkstemp(dir=path, prefix=".lazaret-writecheck-")
    except OSError:
        return False
    try:
        os.close(fd)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return True


def writability_error(path):
    """None if a report could be created/replaced at *path*, else a clear
    one-line reason (for a pre-scan ReportPathError message)."""
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    if not os.path.isdir(parent):
        return f"cannot write {path}: directory {parent} does not exist"
    if not check_writable_dir(parent):
        return (f"cannot write {path}: {parent} is not writable "
                f"(permission denied or read-only filesystem)")
    return None


# ---------------------------------------------------------------------------
# Provenance check (no-clobber)
# ---------------------------------------------------------------------------
def is_our_report(path, kind):
    """True if *path* is an existing regular file this engine produced.

    kind is "json", "html" or "sarif". JSON and SARIF reports carry the
    marker as their FIRST key (JSON) / in a top-level property bag (SARIF);
    HTML reports carry the meta-tag marker in their <head>. Anything else is
    NOT ours and must not be overwritten: missing file, directory, symlink
    (never write through a link, wherever it points), special file,
    unreadable file, wrong content, content without our marker, or hostile
    content that fails to parse — including a deeply nested document whose
    json.loads raises RecursionError (NOT a ValueError; card f22ce3c5),
    which is treated exactly like an unreadable file: not ours → refused.

    The file is lstat-ed BEFORE it is opened (card 12c56422): is_our_report
    ran open() on any path that passed the earlier isfile() check, but
    os.path.isfile follows symlinks and a FIFO planted at the default
    report destination passed it (os.path.isfile is True for a FIFO) while
    open() blocked forever on the read — a trivial hang from a hostile
    repo. Now anything that is not a REGULAR file (per lstat, so symlinks
    and specials fail the same check) is refused before any open.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False                   # missing (or unreadable) → not ours
    if not stat.S_ISREG(st.st_mode):
        return False                   # FIFO/socket/device/directory/symlink
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(MARKER_READ_BYTES)
    except OSError:
        return False           # unreadable → treat as not-ours → refuse
    try:
        data = json.loads(head)
    except (ValueError, RecursionError):
        # RecursionError is NOT a ValueError: a hostile repo can pre-plant
        # the default report destination (lazaret-report.json resolves
        # under the scan root) with a ~60k-deep '[' head, and without
        # RecursionError in this tuple the crash escaped pre-scan
        # validation as a traceback with an undefined exit code (card
        # f22ce3c5; same primitive 48033f94/1149e3e5 guarded elsewhere).
        # A parse failure — any parse failure — means not ours → refuse,
        # matching the "unreadable file → not ours" contract above.
        return kind == "html" and HTML_ENGINE_MARKER in head
    if not isinstance(data, dict):
        return False
    if data.get(ENGINE_MARKER) == ENGINE_VERSION:
        return True                       # JSON report (marker is key #1)
    props = data.get("properties")        # SARIF top-level property bag
    return (isinstance(props, dict)
            and props.get(ENGINE_MARKER) == ENGINE_VERSION)


# ---------------------------------------------------------------------------
# Pre-scan validation
# ---------------------------------------------------------------------------
def _validate_path(path, kind, strict):
    """Validate one report destination before the scan.

    strict=True (the --force-overwrite flag) allows replacing an existing
    regular file of ANY provenance, but still refuses directories, symlinks
    and special files — replacing those would damage the filesystem itself,
    not just one file's bytes.

    Device paths (/dev/null, /dev/stdout, …) are refused explicitly even
    where the generic special-file check already catches them (card
    12c56422, audit G17): opening a report path under /dev with write flags
    has no meaningful "atomic temp file + rename" semantics at all, and an
    explicit refusal message beats a generic one for a user who genuinely
    wanted --html /dev/stdout.
    """
    if path.startswith("/dev/"):
        raise ReportPathError(
            f"report path {path} is a device file — write a real file and "
            f"cat it, or redirect stdout")
    if os.path.lexists(path):             # true for dangling symlinks too
        if os.path.islink(path):
            # never write through a link, wherever it points — replacing it
            # is fine but writing through it clobbers the target silently
            raise ReportPathError(
                f"report path {path} is a symlink — refusing to write "
                f"through it")
        if os.path.isdir(path):
            raise ReportPathError(f"report path {path} is a directory")
        if not os.path.isfile(path):
            # fifo, device, socket…
            raise ReportPathError(
                f"report path {path} is a special file — refusing to write it")
        if not strict and not is_our_report(path, kind):
            raise ReportPathError(
                f"refusing to overwrite {path}: the existing file is not a "
                f"Lazaret report from this engine — not produced by this "
                f"or a previous lazaret run. Move it, pick another path, "
                f"or pass --force-overwrite")
    err = writability_error(path)
    if err:
        raise ReportPathError(err)
    return path


def validate_report_paths(paths, strict=False):
    """Validate ALL report destinations before the scan starts.

    *paths* is a dict as returned by report_paths(). Raises ReportPathError
    on the first problem (the CLI turns that into a clear pre-scan failure
    with exit code EXIT_OUTPUT); returns the same dict on success.
    """
    for kind in ("json", "html", "sarif"):
        p = paths.get(kind)
        if p:
            _validate_path(p, kind, strict)
    return paths


def validate_out_dir(out_dir):
    """Validate an explicit --out-dir value before the scan.

    Must exist, be a real directory (not a symlink — reports must not be
    written through a link someone else controls), and be writable.
    """
    path = os.path.abspath(out_dir)
    if os.path.islink(path):
        raise ReportPathError(
            f"output directory {path} is a symlink — refusing to write "
            f"reports through it")
    if not os.path.exists(path):
        raise ReportPathError(
            f"output directory {path} does not exist "
            f"(create it first, or drop --out-dir)")
    if not os.path.isdir(path):
        raise ReportPathError(f"output directory {path} is not a directory")
    if not check_writable_dir(path):
        raise ReportPathError(
            f"output directory {path} is not writable — reports would be "
            f"lost after a full scan")
    return path


# ---------------------------------------------------------------------------
# Writing (atomic, and the no-clobber rule re-checked at write time)
# ---------------------------------------------------------------------------
def _fsync_dir(path):
    """Best-effort fsync of the directory holding *path* so a completed
    report survives a crash. Not supported everywhere — ignore failures.
    """
    try:
        parent = os.path.dirname(os.path.abspath(path)) or os.curdir
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _write_all(fd, data):
    """os.write() may write fewer bytes than asked; loop until done."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def write_report(path, render, kind, strict=False):
    """Write the bytes of *render()* to *path* atomically, then return path.

    Renders to a temporary file in the destination directory, fsyncs it, and
    renames it over the destination (atomic — a crash never leaves a
    half-written report, and the old file stays intact until the new one is
    complete). The destination is re-checked at write time (the pre-scan
    checks can race): unless strict (--force-overwrite) was given, it must
    not exist or be one of OUR earlier reports — otherwise the temp file is
    discarded and ReportPathError is raised, so a race cannot silently
    clobber an unrelated file either.
    """
    rendered = render()
    if isinstance(rendered, str):
        rendered = rendered.encode("utf-8")
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".lazaret-report-",
                               suffix=".tmp")
    try:
        _write_all(fd, rendered)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if not strict and os.path.lexists(path) and not is_our_report(path, kind):
            raise ReportPathError(
                f"refusing to overwrite {path}: the existing file is not a "
                f"Lazaret report from this engine. Move it, pick another "
                f"path, or pass --force-overwrite")
        os.replace(tmp, path)          # atomic; also replaces our old report
        tmp = None
        _fsync_dir(path)
        try:
            # mkstemp creates 0600; reports used to be 0644&~umask — keep
            # that so CI artifact collectors (other uids) can read them.
            os.chmod(path, 0o666 & ~_umask())
        except OSError:
            pass
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return path


# ---------------------------------------------------------------------------
# Renderers (each stamps the provenance marker at the START of the file)
# ---------------------------------------------------------------------------
def _umask():
    """Current umask without changing it (read it via a set-then-restore)."""
    cur = os.umask(0)
    os.umask(cur)
    return cur


def mark_result(res):
    """Copy of the scan result dict with the engine marker as first key."""
    out = {ENGINE_MARKER: ENGINE_VERSION}
    out.update(res)
    return out


def json_renderer(res):
    """JSON report text: the result dict with the marker as key #1."""
    return json.dumps(mark_result(res), indent=2)


def sarif_renderer(sarif):
    """SARIF log text with the marker in a top-level property bag, first."""
    out = {"properties": {ENGINE_MARKER: ENGINE_VERSION}}
    out.update(sarif)
    return json.dumps(out, indent=2)
