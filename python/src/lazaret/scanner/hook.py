"""`lazaret hook [FILE …]`: the commit-time gate (H-1).

What a commit should not carry: credentials, vulnerabilities and supply-chain
threats. The files named (pre-commit passes the ones being committed), or with
none the files staged for commit, are scanned as `lazaret <dir>` scans a
project, in a temporary tree that keeps their paths: their staged content,
read from git's index (a partly staged file is checked as it will be
committed; a file git doesn't track, or any file outside a repository, as it
is on disk). The gate is `--ci`'s security and supply-chain conditions: no
BLOCKER finding, no CRITICAL vulnerability, no supply-chain indicator and no
cross-file taint flow. Duplication and maintainability, which `--ci` gates
too, are not a commit's business. What prints is what those conditions read:
vulnerabilities of MAJOR and above, supply-chain indicators and cross-file
flows.

A file that can't be read is SC-TRUNCATED, which fails the gate, as in a
project scan. A symbolic link or a submodule is not followed. Nothing is run:
git is asked only to list the index and print its blobs (`cat-file`, so no
filter runs, git-lfs's included).

Exit codes: 0 passed (or nothing to check), 1 the gate failed, 2 usage error,
5 internal error. pre-commit runs it from a mirror repository whose hook
installs Lazaret's wheel by version (integrations/pre-commit); a plain git
hook runs `lazaret hook`.
"""
import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

import lazaret as _lazaret_pkg
from lazaret.scanner import core, engine

#: build_result's conditions this gate keeps (the other two are quality)
GATE = ("No blocker issues", "No critical vulnerabilities", "No supply-chain indicators",
        "No cross-file taint flows")
#: git's empty tree: what a first commit's staged files are compared with
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_CHUNK = 1 << 20


class HookError(Exception):
    """A usage error: the message says what to do."""


def _git(root, *args):
    """Run git, reading only (no optional locks, pathspecs literal) -> its
    stdout, or None when it fails or isn't installed."""
    cmd = ["git", "--no-optional-locks", "--literal-pathspecs"] + (["-C", root] if root else []) + list(args)
    try:
        done = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return None
    return done.stdout if done.returncode == 0 else None


def repo_root(cwd):
    """The top of the git work tree `cwd` is in, or None."""
    out = _git(cwd, "rev-parse", "--show-toplevel")
    if not out:
        return None
    return os.path.realpath(os.fsdecode(out.rstrip(b"\r\n")))


def staged_paths(root):
    """The files staged for commit (added, copied, modified, type-changed;
    a rename is its new path), relative to the work tree's top."""
    base = "HEAD" if _git(root, "rev-parse", "--verify", "-q", "HEAD") is not None else EMPTY_TREE
    out = _git(root, "diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACMT", base)
    if out is None:
        raise HookError("git could not list the staged files")
    return [os.fsdecode(p) for p in out.split(b"\0") if p]


def index_entries(root):
    """{path: (mode, object id)} of the index's merged (stage 0) entries."""
    out = _git(root, "ls-files", "-s", "-z")
    if out is None:
        raise HookError("git could not read the index")
    entries = {}
    for rec in out.split(b"\0"):
        meta, tab, path = rec.partition(b"\t")
        fields = meta.split()
        if tab and len(fields) == 3 and fields[2] == b"0":
            entries[os.fsdecode(path)] = (fields[0].decode("ascii", "replace"), fields[1].decode("ascii", "replace"))
    return entries


def _target(dest, rel):
    """dest/rel, refusing a path that would leave dest."""
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise OSError(f"not a path inside the project: {rel}")
    target = os.path.join(dest, *parts)
    if os.path.commonpath([os.path.realpath(dest), os.path.realpath(os.path.dirname(target))]) != os.path.realpath(dest):
        raise OSError(f"not a path inside the project: {rel}")
    return target


def write_blobs(root, wanted, dest):
    """Write each (object id, path) blob of the index under dest -> [(path,
    why)] for the ones not written. One `git cat-file --batch` reads them all,
    raw (no filter runs), streamed to disk."""
    if not wanted:
        return []
    cmd = ["git", "--no-optional-locks", "-C", root, "cat-file", "--batch"]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return [(rel, f"git could not be run ({exc.strerror or type(exc).__name__})") for _, rel in wanted]

    def feed():
        try:
            for oid, _ in wanted:
                proc.stdin.write(oid.encode("ascii") + b"\n")
            proc.stdin.close()
        except OSError:
            pass
    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    failed = []
    try:
        for oid, rel in wanted:
            fields = proc.stdout.readline().split()
            if len(fields) != 3 or fields[1] != b"blob":
                failed.append((rel, "git could not print it from the index"))
                if not fields:
                    break                       # (git stopped)
                continue
            left = int(fields[2])
            try:
                target = _target(dest, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    while left:
                        chunk = proc.stdout.read(min(left, _CHUNK))
                        if not chunk:
                            raise OSError("git stopped mid-file")
                        out.write(chunk)
                        left -= len(chunk)
            except (OSError, ValueError) as exc:
                failed.append((rel, f"it could not be copied for the scan ({exc})"))
                while left:                     # (stay in step with the stream)
                    chunk = proc.stdout.read(min(left, _CHUNK))
                    if not chunk:
                        break
                    left -= len(chunk)
            proc.stdout.read(1)                 # the newline after each blob
    finally:
        proc.stdout.close()
        writer.join(timeout=5)
        proc.wait()
    return failed


def copy_file(path, dest, rel):
    """Copy a file on disk to dest/rel -> why not, or None."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        return f"it could not be read ({exc.strerror or type(exc).__name__})"
    if stat.S_ISLNK(st.st_mode):
        return ""                               # (a link is not followed: nothing to say)
    if not stat.S_ISREG(st.st_mode):
        return "it is not a regular file"
    try:
        target = _target(dest, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(path, target)
    except (OSError, ValueError) as exc:
        return f"it could not be copied for the scan ({exc.strerror or exc})"
    return None


def gather(files, cwd, dest):
    """Put what the commit holds under dest -> (paths checked, [(path, why
    not)]). `files`: the paths named (relative to cwd), or [] for the staged
    files."""
    root = repo_root(cwd)
    if root is None:
        if not files:
            raise HookError("not in a git repository: name the files to check")
        base = os.path.realpath(cwd)
    else:
        base = root
    if files:
        rels = []
        for f in files:
            given = os.path.join(cwd, f)                # (its folder resolved, not a link it is)
            full = os.path.join(os.path.realpath(os.path.dirname(given)), os.path.basename(given))
            rel = os.path.relpath(full, base)
            if rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
                raise HookError(f"{f} is outside {'the repository' if root else 'this folder'}")
            if os.path.isdir(full) and not os.path.islink(full):
                raise HookError(f"{f} is a folder: name files (lazaret <folder> scans a project)")
            rels.append(rel.replace(os.sep, "/"))
        entries = index_entries(root) if root else {}
        missing = [f for f, rel in zip(files, rels)
                   if rel not in entries and not os.path.lexists(os.path.join(base, *rel.split("/")))]
        if missing:
            raise HookError(f"{missing[0]} does not exist")
    else:
        rels = staged_paths(root)
        entries = index_entries(root)
    blobs, failed, checked = [], [], []
    for rel in dict.fromkeys(rels):
        mode, oid = entries.get(rel, (None, None))
        if mode in ("100644", "100755"):
            blobs.append((oid, rel))
        elif mode is not None:
            continue                            # a link or a submodule: not followed
        else:
            why = copy_file(os.path.join(base, *rel.split("/")), dest, rel)
            if why == "":
                continue                        # (a link on disk)
            if why:
                failed.append((rel, why))
        checked.append(rel)
    failed += write_blobs(root, blobs, dest) if root else []
    return checked, failed


def shown(issue):
    """What the gate's conditions read: vulnerabilities of MAJOR and above,
    supply-chain indicators, cross-file flows."""
    rule, sev = issue["rule"], issue["sev"]
    if rule.startswith("SC-"):
        return sev != "INFO"
    if rule.startswith("X-"):
        return True
    return issue["type"] == "VULN" and core.SEV_ORDER[sev] <= core.SEV_ORDER["MAJOR"]


def report(checked, issues, failed_conditions, quiet):
    c, line = core.c, core.sanitize_term_line
    if not quiet or issues:
        print(f"lazaret hook: {len(checked)} file{'s' if len(checked) != 1 else ''} checked")
    cur = None
    for i in sorted(issues, key=lambda i: (i["file"], core.SEV_ORDER[i["sev"]], i["line"])):
        if i["file"] != cur:
            cur = i["file"]
            print(f"  {c('4', line(cur))}")
        sev = f"{i['sev']:<8}"
        prefix = f"    L{i['line']:<5} {sev} [{i['rule']}] "
        print(f"    L{i['line']:<5} {c(core.SEV_COLOR[i['sev']], sev)} [{i['rule']}] {line(i['msg'])}")
        ex = core.issue_excerpt(i)
        if ex and not quiet:
            print(" " * len(prefix) + c("2", "» " + ex))
    if failed_conditions:
        print(f"  Commit gate: {c('41;97', ' FAILED ')}")
        for label in failed_conditions:
            print(f"    {c('31', '✗')} {line(label)}")
    elif not quiet:
        print(f"  Commit gate: {c('42;30', ' PASSED ')}")


def run(files, cwd=None, quiet=False):
    """Check `files` (or the staged files) -> the exit code."""
    cwd = os.getcwd() if cwd is None else cwd
    with tempfile.TemporaryDirectory(prefix="lazaret-hook-") as tmp:
        dest = os.path.join(tmp, "commit")
        os.mkdir(dest)
        checked, failed = gather(files, cwd, dest)
        not_read = [core.truncated_issue(rel, why) for rel, why in failed]
        if not checked:
            if not quiet:
                print("lazaret hook: nothing to check")
            return core.EXIT_OK
        try:
            res = core.scan_project(dest, extra_issues=not_read)
        except core.ScanTargetError:
            res = core.build_result(dest, [], not_read)      # (nothing Lazaret reads: no finding but these)
    issues = [i for i in res["issues"] if shown(i)]
    failed_conditions = [cond["label"] for cond in res["conditions"]
                         if cond["label"] in GATE and not cond["ok"]]
    report(checked, issues, failed_conditions, quiet)
    return core.EXIT_GATE if failed_conditions else core.EXIT_OK


def main(argv=None):
    """`lazaret hook` (lazaret._cli)."""
    core.configure_stdio()
    ap = argparse.ArgumentParser(
        prog="lazaret hook",
        description="The commit-time gate: credentials, vulnerabilities and supply-chain threats in the "
                    "files being committed (their staged content). Fails on --ci's security and "
                    "supply-chain conditions; duplication and maintainability are not checked.")
    ap.add_argument("--version", action="version", version=f"lazaret {_lazaret_pkg.__version__}")
    ap.add_argument("files", nargs="*", metavar="FILE",
                    help="files to check (pre-commit passes them); default: the files staged for commit")
    ap.add_argument("--staged", action="store_true",
                    help="check the files staged for commit (what no FILE means)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only what fails the gate, and the findings")
    args = ap.parse_args(argv)
    if args.staged and args.files:
        ap.error("--staged checks the staged files: name no FILE with it")
    try:
        engine.require()
    except engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return core.EXIT_USAGE
    try:
        return run(args.files, quiet=args.quiet)
    except HookError as exc:
        print(f"error: {core.sanitize_term_line(str(exc))}", file=sys.stderr)
        return core.EXIT_USAGE
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:                                    # noqa: BLE001
        core._internal_error(exc)


if __name__ == "__main__":
    sys.exit(main())
