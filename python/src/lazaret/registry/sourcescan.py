"""`lazaret [scan] github:owner/repo[@ref]` and `gitlab:group/project[@ref]`
(0.1.9, S-1): the CLI scan of a repository at a commit.

`sources.checkout` resolves the ref to a commit, fetches that commit's archive
and reads it into a fresh directory; this module runs the ordinary scan
(`scanner.core.main`, with every one of its options) on that directory and
removes it afterwards. What it adds to a scan of a folder:

- The report names the commit that was read (`Source:` line), and the report
  files are named for it (`lazaret-github-owner-repo-0123456-report.json`) and
  written to the current directory, not to the scan root, which is a temporary
  directory. `--out-dir`, `--json`, `--html` and `--sarif` still decide where
  they go, and the destination is checked before anything is fetched.
- The report says what it is a report of (N-5, `source_block`): its `project`
  is the source at its commit (`github:owner/repo@<sha>`), not the temporary
  directory, and its `source` names the repository, the ref asked for, the
  commit, what was read and what was not; a checkout not read whole makes the
  result `incomplete`, with the reason. The SARIF report maps its root to the
  repository at that commit (`versionControlProvenance`).
- Fail closed, as everywhere in Lazaret: a checkout that was not read whole (a
  path the archive left out through `export-ignore`, a tree too large to list,
  an archive that hit a byte, file or time budget, a file that could not be
  written) is said so, after the report, and with `--ci` the exit status is 1
  even when the gate passed. `--accept-incomplete` is the one switch that
  scans what was read and exits by the gate alone.
- The token (`GITHUB_TOKEN`, `GITLAB_TOKEN`) and the GitLab host
  (`LAZARET_GITLAB_URL`) come from the environment only (`sources.py`).

Exit codes are the scan's (0 ok, 1 gate, 2 usage, 3 report output, 4 taint
config, 5 internal); a spec that is not one, or a repository that cannot be
fetched, is 2, like any other target that cannot be read.

The options of `core.main` are listed here only to tell its values from the
one thing on the command line that names what to scan; a test holds the list
to the parser's own `--help`."""

import os
import re
import shutil
import sys
import tempfile

from lazaret.registry import sources
from lazaret.scanner import core, reports

__all__ = ["main", "find", "UsageError", "Plan", "VALUE_OPTIONS", "FLAG_OPTIONS", "not_covered", "source_block"]

#: `core.main`'s options that take a value, and those that do not.
VALUE_OPTIONS = ("--out-dir", "--html", "--json", "--exclude", "--sarif", "--baseline", "--taint-config",
                 "--excerpt-width", "--max-source-bytes")
FLAG_OPTIONS = ("--ci", "--deps", "--no-html", "--no-json", "--force-overwrite", "--trust-repo-config",
                "--strict-taint-config", "--no-redact-secrets", "--quiet", "--help", "--version")
SHORT_OPTIONS = {"-q": "--quiet", "-h": "--help"}
ACCEPT = "--accept-incomplete"
PREFIXES = ("github:", "gitlab:")
SHOWN = 8                          # paths named in one line of a warning


class UsageError(ValueError):
    """The command line asks for something that cannot be done; nothing was fetched."""


class Plan:
    """What the command line asks for: `spec` is the source, `argv` the rest
    with the source's place held by None, `opts` the options by their full names."""

    def __init__(self, spec, argv, slot, opts, accept):
        self.spec, self.argv, self.slot, self.opts, self.accept = spec, argv, slot, opts, accept


def _resolve(arg):
    """The full name of the option `arg` spells, as argparse reads it: exactly,
    or as the one option it is a prefix of (`--out` for `--out-dir`). None for
    an unknown or an ambiguous one (core's parser refuses it)."""
    name = arg.split("=", 1)[0]
    if name in SHORT_OPTIONS:
        return SHORT_OPTIONS[name]
    if not name.startswith("--") or len(name) < 3:
        return None
    known = VALUE_OPTIONS + FLAG_OPTIONS
    if name in known:
        return name
    near = [o for o in known if o.startswith(name)]
    return near[0] if len(near) == 1 else None


def _walk(argv):
    """-> (positionals as (index, text), options as {full name: its last value,
    or True for a flag})."""
    positionals, opts, i = [], {}, 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            positionals.extend((j, argv[j]) for j in range(i + 1, len(argv)))
            break
        if a.startswith("-") and a != "-":
            full = _resolve(a)
            if full in VALUE_OPTIONS:
                if "=" in a:
                    value = a.split("=", 1)[1]
                elif i + 1 < len(argv):
                    i += 1
                    value = argv[i]
                else:
                    value = None
                opts[full] = value
            elif full:
                opts[full] = True
        else:
            positionals.append((i, a))
        i += 1
    return positionals, opts


def looks_like_source(text):
    return text[:7].lower() in PREFIXES and not os.path.exists(text)


def find(argv):
    """The source scan `argv` asks for, or None when it is not one (a folder to
    scan, `--help`, a value that merely starts with `github:`). Raises
    UsageError for a source with something else to scan beside it or a spec that
    is not one. `scan` as the first word is dropped, and so is
    `--accept-incomplete`."""
    argv = list(argv)
    accept = ACCEPT in argv
    argv = [a for a in argv if a != ACCEPT]
    if any(_resolve(a) in ("--help", "--version") for a in argv if a.startswith("-")):
        return None
    positionals, opts = _walk(argv)
    named = [(i, a) for i, a in positionals if looks_like_source(a)]
    if not named:
        return None
    slot, spec = named[0]
    first = positionals[0]
    if len(named) > 1 or len(positionals) - (1 if first[1] == "scan" and first[0] != slot else 0) > 1:
        raise UsageError("one source (github:owner/repo[@ref] or gitlab:group/project[@ref]) or one folder "
                         "to scan, not several")
    try:
        src = sources.parse_source(spec)
    except sources.SourceError as exc:
        raise UsageError(str(exc))
    argv[slot] = None
    if first[1] == "scan" and first[0] != slot:
        del argv[first[0]]
        slot -= 1 if first[0] < slot else 0
    return Plan(src, argv, slot, opts, accept)


def _slug(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")[:80] or "source"


def needs_out_dir(opts):
    """Would a report land under `--out-dir` (the scan root, a directory that is
    removed, when none is given)? Yes unless every report that is wanted has an
    absolute path of its own."""
    for key, off in (("--json", "--no-json"), ("--html", "--no-html")):
        if not opts.get(off) and not (opts.get(key) and os.path.isabs(opts[key])):
            return True
    sarif = opts.get("--sarif")
    return bool(sarif and not os.path.isabs(sarif))


def report_defaults(plan, commit, cwd):
    """The options put in front of the user's own, so that argparse's last-one-wins
    leaves the user's in charge: the reports are named for the source and the
    commit, and go to `cwd` unless `--out-dir` says otherwise."""
    opts, name = plan.opts, f"lazaret-{plan.spec.kind}-{_slug(plan.spec.path)}-{commit[:7]}-report"
    front = []
    for key, ext, off in (("--json", ".json", "--no-json"), ("--html", ".html", "--no-html")):
        if key not in opts and not opts.get(off):
            front += [key, name + ext]
    if needs_out_dir(opts) and "--out-dir" not in opts:
        front = ["--out-dir", cwd] + front
    return front


def not_covered(ck):
    """What the commit holds that the scan did not read: the checkout's own
    `incomplete`, and every file that could not be written. A file left out only
    for its size is not here: a scan of a folder does not read one either."""
    gaps = list(ck.incomplete)
    for rel, why in ck.skipped:
        if not why.startswith("larger than"):
            gaps.append(("skipped", f"{rel}: {why}"))
    return gaps


def repository_uri(src, env=None):
    """The repository's address on its host: github.com's, or the GitLab
    instance's (`LAZARET_GITLAB_URL`, checked by `sources.gitlab_base`)."""
    if src.kind == "github":
        return f"https://github.com/{src.path}"
    return f"{sources.gitlab_base(env)}/{src.path}"


def source_block(src, ck, gaps, env=None):
    """The report's `source` (N-5): the spec at its commit, the repository and
    its address, the ref that was asked for (None: the default branch), the
    commit that was read, the files and bytes read, and whether that is all of
    the commit (`gaps`, from `not_covered`). `skipped` lists the files not
    written (too large, in the way of another), `notes` and `anomalies` what the
    checkout said about the archive. No token, no temporary path."""
    return {"spec": sources.spec_text(src, ck.commit), "kind": src.kind, "repository": src.path,
            "ref": src.ref, "commit": ck.commit, "uri": repository_uri(src, env), "files": ck.files,
            "bytes": ck.bytes, "complete": not gaps, "incomplete": [list(g) for g in gaps],
            "skipped": [list(s) for s in ck.skipped], "notes": list(ck.notes),
            "anomalies": [list(a) for a in ck.anomalies]}


def _clean(text):
    return core.sanitize_term_line(text)


def _warn(label, items):
    for text in items[:SHOWN]:
        print(f"warning: {label}: {_clean(text)}", file=sys.stderr)
    if len(items) > SHOWN:
        print(f"warning: {label}: and {len(items) - SHOWN} more", file=sys.stderr)


def _exit_code(exc):
    code = exc.code
    return 0 if code is None else code if isinstance(code, int) else 1


def main(argv=None, *, env=None, http=None):
    """The `lazaret` command for a source on its command line; anything else
    goes to `scanner.core.main` unchanged. `env` and `http` are `sources.checkout`'s (the
    process environment and the network, when None)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        plan = find(argv)
    except UsageError as exc:
        core.configure_stdio()
        print(f"error: {_clean(exc)}", file=sys.stderr)
        return core.EXIT_USAGE
    if plan is None:
        return core.main([a for a in argv if a != ACCEPT])
    core.configure_stdio()
    cwd = os.getcwd()
    spec = sources.spec_text(plan.spec)

    # The report destination, before any request is made: a scan that cannot
    # save its report is not worth the archive's download.
    if needs_out_dir(plan.opts):
        try:
            reports.validate_out_dir(plan.opts.get("--out-dir") or cwd)
        except reports.ReportPathError as exc:
            print(f"error: {_clean(exc)}", file=sys.stderr)
            return reports.EXIT_OUTPUT

    parent = tempfile.mkdtemp(prefix="lazaret-src-")
    try:
        print(f"Fetching {_clean(spec)} ...", file=sys.stderr)
        try:
            ck = sources.checkout(plan.spec, dest=os.path.join(parent, _slug(plan.spec.kind + "-" + plan.spec.path)),
                                  env=env, http=http)
        except sources.SourceError as exc:
            print(f"error: {_clean(exc)}", file=sys.stderr)
            return core.EXIT_USAGE
        except Exception as exc:                    # a bug here is not a scan result
            core._internal_error(exc)
        print(f"Source: {_clean(sources.spec_text(plan.spec, ck.commit))}"
              + (f" (the ref {_clean(plan.spec.ref)})" if plan.spec.ref and plan.spec.ref != ck.commit else ""))
        print(f"  {ck.files} files, {ck.bytes:,} bytes read from the commit's archive")
        _warn("note", ck.notes)
        _warn("archive", [f"{kind} {path}: {detail}" for kind, path, detail in ck.anomalies])
        _warn("skipped", [f"{rel}: {why}" for rel, why in ck.skipped if why.startswith("larger than")])
        front = report_defaults(plan, ck.commit, cwd)
        args = front + [ck.root if a is None else a for a in plan.argv]
        gaps = not_covered(ck)
        try:
            code = core.main(args, source=source_block(plan.spec, ck, gaps, env))
        except SystemExit as exc:
            code = _exit_code(exc)
        if gaps:
            print(f"error: the checkout of {_clean(sources.spec_text(plan.spec, ck.commit))} was not read whole, so this "
                  f"scan does not cover all of the commit:", file=sys.stderr)
            for reason, detail in gaps[:SHOWN]:
                print(f"  {_clean(reason)}: {_clean(detail)}", file=sys.stderr)
            if len(gaps) > SHOWN:
                print(f"  and {len(gaps) - SHOWN} more", file=sys.stderr)
            if plan.accept:
                print(f"  ({ACCEPT}: the exit status is the gate's alone)", file=sys.stderr)
            elif plan.opts.get("--ci"):
                print(f"  (--ci: exit 1; {ACCEPT} scans what was read and exits by the gate alone)", file=sys.stderr)
                if code == core.EXIT_OK:
                    code = core.EXIT_GATE
            else:
                print(f"  (without --ci the exit status is unchanged; --ci fails on this unless {ACCEPT} is given)",
                      file=sys.stderr)
        return code
    finally:
        shutil.rmtree(parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
