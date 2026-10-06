"""`lazaret [scan] FILE.vsix …` and `lazaret [scan] --extensions [PATH …]`
(0.1.9, E-1's first part): the scan of VS Code extensions on this machine.

An extension runs in the editor's extension host, Node with all of the
user's access and no sandbox, so it is read as the registry reads an npm
package (repo.scan_members), with the editor's rules for what runs and when
(artifact kind `vsix`): its `main` and `browser` modules, and the modules
they load, get the import-time test (they run when the editor activates the
extension, at every start for the activation events `*` and
`onStartupFinished`); the rest of its code gets the use-time test; and
`vscode:uninstall`, the one script VS Code runs (`node` and a file, once the
extension has been uninstalled), gets the install-hook test. npm's scripts
never run: the editor runs no `npm install`. `extensionDependencies` and
`extensionPack` are the extensions it brings.

What it scans:
- a `.vsix` file, the extension's package (a zip, of which VS Code installs
  what is under `extension/`): any word of the command line naming one;
- with `--extensions`, the extensions VS Code and its forks have installed:
  the folders of each editor's extensions folder (EDITORS, and the folder
  VSCODE_EXTENSIONS names, VS Code's own setting) that hold a package.json;
  or, given paths, those: an extension's folder (it holds a package.json),
  an extensions folder (its folders are extensions), or a `.vsix` file.

Each extension's result is the registry's (verdict OK, WARN, INCOMPLETE or
SUSPICIOUS, with the findings that decide it), printed as `lazaret-registry
scan` prints a package's, with where it is. `--json PATH` writes them all as
a report, under the scan's rules for an existing file (reports.py).

Exit codes: 0, or 1 with `--ci` when an extension is SUSPICIOUS or
INCOMPLETE; 2 for a command line that is not one or a path that names
nothing to scan (and for a missing native engine); 3 when the report cannot
be written."""

import argparse
import datetime
import hashlib
import json
import os
import sys
import time

from lazaret.registry import repo
from lazaret.scanner import core as lazaret
from lazaret.scanner import engine as _engine
from lazaret.scanner import reports

__all__ = ["main", "EDITORS", "default_folders", "find_targets", "scan_target", "scan_vsix", "scan_folder",
           "UsageError"]

#: The extensions folders of VS Code and the editors built on it, under the user's home: each keeps its
#: extensions in `<home>/<its data folder>/extensions` on every system, a folder per extension
#: (`publisher.name-version[-platform]`). The servers' are on the machine a remote window connects to.
EDITORS = (
    ("VS Code", (".vscode", "extensions")),
    ("VS Code Insiders", (".vscode-insiders", "extensions")),
    ("VSCodium", (".vscode-oss", "extensions")),
    ("Cursor", (".cursor", "extensions")),
    ("Windsurf", (".windsurf", "extensions")),
    ("Kiro", (".kiro", "extensions")),
    ("Positron", (".positron", "extensions")),
    ("VS Code Server", (".vscode-server", "extensions")),
    ("VS Code Server Insiders", (".vscode-server-insiders", "extensions")),
    ("Cursor Server", (".cursor-server", "extensions")),
)
#: The most extensions one run scans (a folder of more is said to be cut short).
MAX_EXTENSIONS = 5_000
VSIX_SUFFIX = ".vsix"


class UsageError(ValueError):
    """The command line names something that cannot be scanned; nothing was scanned."""


def default_folders(env=None, home=None):
    """[(editor, folder)] for the editors' extensions folders that exist here, in EDITORS' order, then
    code-server's (XDG_DATA_HOME or ~/.local/share, code-server/extensions) and the folder
    VSCODE_EXTENSIONS names (VS Code's setting for where it installs extensions); each folder once."""
    env = os.environ if env is None else env
    home = os.path.expanduser("~") if home is None else home
    data = env.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    candidates = [(label, os.path.join(home, *parts)) for label, parts in EDITORS]
    candidates.append(("code-server", os.path.join(data, "code-server", "extensions")))
    if env.get("VSCODE_EXTENSIONS"):
        candidates.append(("VSCODE_EXTENSIONS", env["VSCODE_EXTENSIONS"]))
    out, seen = [], set()
    for label, folder in candidates:
        if not os.path.isdir(folder):
            continue
        key = os.path.normcase(os.path.realpath(folder))
        if key not in seen:
            seen.add(key)
            out.append((label, folder))
    return out


def _is_vsix(path):
    return path.lower().endswith(VSIX_SUFFIX) and os.path.isfile(path)


def _is_extension(folder):
    return os.path.isfile(os.path.join(folder, "package.json"))


def _extensions_in(folder):
    """The extensions of an extensions folder: its folders (or links to folders) that hold a package.json,
    by name. Hidden ones too (an install VS Code did not finish is extracted into `.<id>`): what is on
    the disk is what is scanned."""
    with os.scandir(folder) as entries:
        names = sorted(e.name for e in entries if e.is_dir())
    return [os.path.join(folder, n) for n in names if _is_extension(os.path.join(folder, n))]


def find_targets(paths, extensions, env=None, home=None):
    """([(kind, path, where)], notes): what to scan, kind "vsix" or "folder" and `where` the editor whose
    folder it is in (or None), and what to say about it (nothing installed, an editor's folder that could
    not be read, more than MAX_EXTENSIONS extensions). `paths`: the command line's; `extensions`:
    --extensions was given. UsageError for a path that names nothing to scan."""
    targets, notes = [], []
    if not paths:
        if not extensions:
            raise UsageError("name a .vsix file to scan, or use --extensions for the installed extensions")
        folders = default_folders(env, home)
        if not folders:
            looked = ", ".join(os.path.join("~", *parts) for _l, parts in EDITORS[:3])
            notes.append(f"no installed extensions found (no extensions folder of VS Code or an editor built on "
                         f"it: {looked}, …)")
        for label, folder in folders:
            try:
                found = _extensions_in(folder)
            except OSError as exc:
                notes.append(f"{folder} ({label}) could not be read: {exc.strerror or type(exc).__name__}")
                continue
            targets.extend(("folder", p, label) for p in found)
    for path in paths:
        if _is_vsix(path):
            targets.append(("vsix", path, None))
        elif not extensions:
            raise UsageError(f"{path} is not a .vsix file (scan an extension's folder with --extensions)")
        elif os.path.isdir(path) and _is_extension(path):
            targets.append(("folder", path, None))
        elif os.path.isdir(path):
            try:
                found = _extensions_in(path)
            except OSError as exc:
                raise UsageError(f"{path} could not be read: {exc.strerror or type(exc).__name__}") from None
            if not found:
                raise UsageError(f"{path} holds no extension (no package.json, and no folder with one)")
            targets.extend(("folder", p, None) for p in found)
        else:
            raise UsageError(f"{path}: no such .vsix file or folder")
    if len(targets) > MAX_EXTENSIONS:
        notes.append(f"{len(targets):,} extensions found: the first {MAX_EXTENSIONS:,} are scanned")
        targets = targets[:MAX_EXTENSIONS]
    return targets, notes


def _budget(timeout):
    return repo.Budget(deadline=time.monotonic() + timeout,
                       deadline_detail=f"scan time budget of {timeout:g} s per extension (--scan-timeout) exceeded")


def scan_vsix(path, full=False, timeout=None):
    """Scan a .vsix file -> its result (see _result)."""
    timeout = repo.SCAN_TIMEOUT if timeout is None else timeout
    size = os.path.getsize(path)
    if size > repo.MAX_DOWNLOAD_BYTES:
        return _too_large(path, size)
    with open(path, "rb") as fh:
        data = fh.read(repo.MAX_DOWNLOAD_BYTES + 1)
    if len(data) > repo.MAX_DOWNLOAD_BYTES:
        return _too_large(path, len(data))
    budget = _budget(timeout)
    r = repo._scan_artifact(data, "zip", "vsix", full, budget)
    return _result(r, path, "vsix", len(data), full, digest="sha256:" + hashlib.sha256(data).hexdigest())


def scan_folder(path, full=False, timeout=None, where=None):
    """Scan an installed extension's folder -> its result (see _result)."""
    timeout = repo.SCAN_TIMEOUT if timeout is None else timeout
    budget = _budget(timeout)
    r = repo.scan_members(repo.iter_folder(path, budget=budget), [], "vsix", full, budget)
    return _result(r, path, "folder", budget.used, full, where=where)


def _not_read(path, artifact, detail, full=False):
    """The result for an extension that was not read (INCOMPLETE): `detail` says why."""
    issue = lazaret.truncated_issue(os.path.basename(os.path.normpath(path)), detail)
    r = {"issues": [issue], "filesScanned": 0, "binaryArtifacts": 0, "truncated": 1, "useTime": None,
         "extensionDependencies": [], "startupEvent": None, "manifest": None}
    r["verdict"], r["verdictReason"], r["strongIndicators"], r["weakIndicators"] = repo.decide_verdict(r["issues"], 1)
    return _result(r, path, artifact, 0, full)


def _too_large(path, size):
    """The result for a .vsix over the size limit: not read, so INCOMPLETE."""
    return _not_read(path, "vsix", f"the file is {size:,} bytes, more than the {repo.MAX_DOWNLOAD_BYTES:,}-byte "
                                   f"limit of one archive, so it was not read")


def scan_target(kind, path, full=False, timeout=None, where=None):
    """scan_vsix or scan_folder; a file that cannot be read is INCOMPLETE, not an error."""
    try:
        if kind == "vsix":
            return scan_vsix(path, full, timeout)
        return scan_folder(path, full, timeout, where)
    except OSError as exc:
        return _not_read(path, kind, f"it could not be read ({exc.strerror or type(exc).__name__})", full)


def _result(r, path, artifact, size, full, digest=None, where=None):
    """A scan's result in the registry's shape (repo.scan_package's), with where the extension is."""
    manifest = r.get("manifest") or {}
    name = manifest.get("name")
    publisher = manifest.get("publisher")
    if name:
        name = f"{publisher}.{name}" if publisher else name
    else:
        name = os.path.basename(os.path.normpath(path))
    issues = lazaret.redact_result({"issues": list(r["issues"])})["issues"]
    issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["file"], i["line"]))
    sev_counts = {s: 0 for s in lazaret.SEV_ORDER}
    for i in issues:
        sev_counts[i["sev"]] += 1
    return {"ecosystem": "extension", "name": name, "version": manifest.get("version") or "?",
            "artifact": artifact, "location": path + (f" ({where})" if where else ""), "path": path,
            "editor": where, "archiveBytes": size, "filesScanned": r["filesScanned"],
            "binaryArtifacts": r["binaryArtifacts"], "profile": "full" if full else "supply-chain",
            "sevCounts": sev_counts, "supplyChain": r["strongIndicators"] + r["weakIndicators"],
            "strongIndicators": r["strongIndicators"], "weakIndicators": r["weakIndicators"],
            "truncated": r["truncated"], "verdict": r["verdict"], "verdictReason": r["verdictReason"],
            "issues": issues, "digest": digest, "useTime": r.get("useTime"),
            "extensionDependencies": r.get("extensionDependencies") or [],
            "startupEvent": r.get("startupEvent"),
            "scannedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


def _summary(results):
    counts = {v: 0 for v in repo.VERDICT_RANK}
    for res in results:
        counts[res["verdict"]] = counts.get(res["verdict"], 0) + 1
    shown = ", ".join(f"{n} {v}" for v, n in sorted(counts.items(), key=lambda kv: -repo.VERDICT_RANK[kv[0]]) if n)
    return counts, f"{len(results)} extension{'s' if len(results) != 1 else ''} scanned: {shown or 'none'}"


def _parser():
    ap = argparse.ArgumentParser(
        prog="lazaret",
        description="Lazaret: scan VS Code extensions (a .vsix file, or the extensions VS Code and the "
                    "editors built on it have installed) for malicious code.",
        usage="lazaret [scan] FILE.vsix [FILE.vsix ...] [options]\n"
              "       lazaret [scan] --extensions [FOLDER | FILE.vsix ...] [options]")
    ap.add_argument("--version", action="version",
                    version=f"lazaret {lazaret.VERSION} (engine: {_engine.describe()})")
    ap.add_argument("paths", nargs="*", metavar="PATH", help=argparse.SUPPRESS)
    ap.add_argument("--extensions", action="store_true",
                    help="Scan installed extensions: those of VS Code, VSCodium, Cursor, Windsurf, Kiro, Positron, "
                         "code-server and the VS Code and Cursor servers when no PATH is given, else the "
                         "extension folders, extensions folders and .vsix files given")
    ap.add_argument("--json", metavar="PATH", help="Write the results to PATH as a JSON report")
    ap.add_argument("--force-overwrite", action="store_true",
                    help="Replace an existing file at --json even if Lazaret did not write it")
    ap.add_argument("--ci", action="store_true", help="Exit 1 if an extension is SUSPICIOUS or INCOMPLETE")
    ap.add_argument("--full", action="store_true",
                    help="Run the full ruleset, not just the supply-chain and secret rules")
    ap.add_argument("--scan-timeout", type=float, metavar="SECONDS",
                    help=f"Time budget per extension (default {repo.SCAN_TIMEOUT:g}); past it the verdict is "
                         f"INCOMPLETE")
    ap.add_argument("--max-source-bytes", type=int, metavar="BYTES",
                    help=f"Largest text file scanned as source (default {repo.MAX_MEMBER:,}); a larger one is not "
                         f"fully scanned and the verdict is INCOMPLETE")
    ap.add_argument("-q", "--quiet", action="store_true", help="Print only the extensions that are not OK")
    return ap


def main(argv=None, *, env=None, home=None):
    """The command (see the module's doc). As the project scan's: a reader
    that goes away (`| head`) does not stop the scan or its report
    (core._PipeSafeStdout), and a bug is `error: internal: …`, exit 5, never
    a traceback that looks like a failed gate."""
    lazaret.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_intermixed_args(argv)
    real = sys.stdout
    guard = lazaret._PipeSafeStdout(real) if real is not None else None
    if guard is not None:
        sys.stdout = guard
    try:
        return _run(args, env, home)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:                        # noqa: BLE001 (a bug is not a scan result)
        lazaret._internal_error(exc)
    finally:
        if guard is not None:
            try:
                guard.flush()
            except Exception:                       # noqa: BLE001
                pass
            if sys.stdout is guard:
                sys.stdout = real


def _run(args, env, home):
    paths = list(args.paths)
    if paths and paths[0] == "scan" and not os.path.exists("scan"):
        paths = paths[1:]
    try:
        _engine.require()
    except _engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.max_source_bytes and args.max_source_bytes > 0:
        repo.MAX_MEMBER = args.max_source_bytes
    timeout = args.scan_timeout if args.scan_timeout and args.scan_timeout > 0 else repo.SCAN_TIMEOUT
    try:
        targets, notes = find_targets(paths, args.extensions, env, home)
    except UsageError as exc:
        print(f"lazaret: error: {lazaret.sanitize_term(exc)}", file=sys.stderr)
        return 2
    report = None
    if args.json:
        try:
            report = reports.validate_report_paths({"json": args.json}, strict=args.force_overwrite)["json"]
        except reports.ReportPathError as exc:
            print(f"lazaret: error: {lazaret.sanitize_term(exc)}", file=sys.stderr)
            return reports.EXIT_OUTPUT
    for note in notes:
        print(f"lazaret: {lazaret.sanitize_term(note)}", file=sys.stderr)
    results = []
    for kind, path, where in targets:
        res = scan_target(kind, path, args.full, timeout, where)
        results.append(res)
        if not args.quiet or res["verdict"] != "OK":
            repo.print_scan(res)
    counts, line = _summary(results)
    if results:
        print(f"\n{line}")
    if report is not None:
        doc = {"tool": "lazaret", "version": lazaret.VERSION, "kind": "extensions",
               "scannedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "summary": counts, "notes": notes, "extensions": results}
        try:
            reports.write_report(report, lambda: json.dumps(reports.mark_result(doc), indent=2), "json",
                                 strict=args.force_overwrite)
        except (reports.ReportPathError, OSError) as exc:
            print(f"lazaret: error: the report could not be written: {lazaret.sanitize_term(exc)}", file=sys.stderr)
            return reports.EXIT_OUTPUT
        print(f"JSON report: {lazaret.sanitize_term(report)}")
    if args.ci and any(res["verdict"] in repo.BAD_VERDICTS for res in results):
        return 1
    return 0
