#!/usr/bin/env python3
"""Build a source bundle of the Lazaret repository (card 12c56422, audit G21).

The bundle is a whitelist of what the repository IS, not a snapshot of what
happens to be lying around in a working directory:

  top level     README.md, SECURITY.md, STRUCTURE.md, LICENSE
  trees         .github/, scripts/, examples/, docs/, python/, js/

In a git checkout only files git tracks are bundled (`git ls-files`), so a
stray untracked file inside a whitelisted tree (scripts/..t.sh, a local
notes file) stays out; untracked files are listed with a notice. Without git
(an unpacked bundle, a zip download) the trees are walked instead.

Either way, prior-run ARTIFACTS rather than source are SKIPPED with a notice:
reports, SARIF, state DBs, bytecode, AppleDouble ._* files, .DS_Store,
node_modules, .git, build outputs (build/, dist/, *.egg-info), virtualenvs.
Anything on the NEVER list at the top level is a hard error: stale state that
must not ship.

Credential files are never bundled, anywhere, tracked or not: .env and its
variants (a .env.example template is fine), .envrc, .npmrc, .pypirc, .netrc,
.git-credentials, private keys and certificates (*.pem, *.key, *.p12, *.pfx,
id_rsa*, id_dsa*, id_ecdsa*, id_ed25519*). .gitignore lists the same names.

The output is deterministic: members sorted, uid/gid 0 with empty names,
mode 0644 (0755 for executables), every mtime and the gzip header set to
SOURCE_DATE_EPOCH or 0, and no file name in the gzip header. Two runs over
the same files give byte-identical archives.

This is the *source* bundle for sharing the repository. What users install is
the wheel built from python/ (see python/_build/), which contains only the
package, never tests or fixtures.

Usage: python3 scripts/make_bundle.py [output.tgz] [--strict]
       --strict turns every skip into a failure (used by the hygiene test
       to prove the filters fire).

Card 27e1dfda: every file whose basename still says 'codeguard' is treated as
stale pre-rename junk and refused (is_old_name_junk).
"""
import argparse
import fnmatch
import gzip
import io
import os
import stat
import subprocess
import sys
import tarfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOP_FILES = ["README.md", "SECURITY.md", "STRUCTURE.md", "LICENSE"]
REQUIRED = ["README.md", "LICENSE", "python/pyproject.toml",
            "python/src/lazaret/__init__.py", "python/src/lazaret/scanner/core.py"]
TREES = [".github", "scripts", "examples", "docs", "python", "js"]

# Directories that are never source, wherever they appear.
SKIP_DIRS = {"__pycache__", "node_modules", ".venv", "venv", ".tox", ".pytest_cache",
             ".mypy_cache", ".git"}
# Build output is junk only where builds put it. Elsewhere a dist/ or build/
# directory can be real content: tests/fixtures/detection_gaps/dist/ is a
# fixture for the scanner's own dist-skipping logic.
BUILD_OUTPUT_DIRS = {"build", "dist"}
BUILD_ROOTS = {"", "python", "js"}

# Top-level stale state: shipping any of these is a build FAILURE, not a
# skip. base.json = pre-redaction baseline fixture (contains unredacted
# dummies); lazaret-registry.db = prior run state; lazaret-report.* =
# prior-run outputs; bundle.py = the old G10 fixture that deliberately
# contains a hardcoded password.
NEVER_FILE = {"base.json", "lazaret-registry.db",
              "lazaret-report.json", "lazaret-report.html", "bundle.py"}

# Credential files by name (case-insensitive glob on the basename).
CREDENTIAL_NAMES = [".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials",
                    "*.pem", "*.key", "*.p12", "*.pfx",
                    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*"]


def is_old_name_junk(rel):
    """Card 27e1dfda (rename codeguard -> lazaret): a surviving file whose
    basename still carries the pre-rename spelling is a stale twin."""
    return "codeguard" in os.path.basename(rel).lower()


def is_secrets_file(rel):
    """.env and its variants hold real credentials; a .env.example is a template."""
    name = os.path.basename(rel)
    return (name == ".env" or name.startswith(".env.")) and not name.endswith(".example")


def is_credential_file(rel):
    """Any file whose name says it holds credentials or a private key."""
    name = os.path.basename(rel.replace("\\", "/")).lower()
    return is_secrets_file(rel) or any(fnmatch.fnmatchcase(name, pat) for pat in CREDENTIAL_NAMES)


def is_junk(rel):
    """True if rel is a prior-run artifact, machine cruft, or a credential file."""
    parts = rel.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    for i, part in enumerate(parts[:-1]):
        if part in BUILD_OUTPUT_DIRS and "/".join(parts[:i]) in BUILD_ROOTS:
            return True
    if any(p.endswith(".egg-info") for p in parts):
        return True
    if rel.endswith((".pyc", ".pyo")):
        return True
    if any(p.startswith("._") or p == ".DS_Store" for p in parts):
        return True
    if rel.endswith((".db", ".db-wal", ".db-shm")):
        return True
    if rel.endswith((("-report.json", "-report.html", ".sarif"))):
        return True
    if is_credential_file(rel):
        return True
    # NEVER_FILE is TOP-LEVEL only: fixtures/detection_gaps/{dist,skips}/
    # bundle.py and .DS_Store are legitimate G10 fixtures that share a name
    # with top-level junk.
    if len(parts) == 1 and parts[0] in NEVER_FILE:
        return True
    return is_old_name_junk(rel)


def _in_whitelist(rel):
    return rel in TOP_FILES or any(rel.startswith(tree + "/") for tree in TREES)


def _walk(repo):
    """{rel: mode} for every regular file under the whitelist (no git)."""
    found = {}
    for rel in TOP_FILES:
        path = os.path.join(repo, rel)
        if os.path.isfile(path) and not os.path.islink(path):
            found[rel] = None
    for tree in TREES:
        base = os.path.join(repo, tree)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, repo).replace(os.sep, "/")
                found[rel] = "symlink" if os.path.islink(full) else None
    return found


def _git_tracked(repo):
    """{rel: git mode} of the tracked files under the whitelist, or None when
    repo is not a git checkout (or git isn't available)."""
    if not os.path.exists(os.path.join(repo, ".git")):
        return None
    try:
        p = subprocess.run(["git", "-C", repo, "ls-files", "-s", "-z"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    tracked = {}
    for entry in p.stdout.split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        rel = os.fsdecode(path)
        if _in_whitelist(rel):
            tracked[rel] = meta.split()[0].decode("ascii")      # 100644, 100755, 120000, 160000
    return tracked


def collect(strict=False, repo=REPO, use_git=True):
    """Whitelist -> sorted list of repo-relative paths to pack."""
    return [rel for rel, _ in _collect(strict, repo, use_git)]


def _collect(strict, repo, use_git):
    """Sorted [(rel, executable)] to pack."""
    skipped = []
    for rel in REQUIRED:
        if not os.path.isfile(os.path.join(repo, rel)):
            print(f"error: required file missing: {rel}", file=sys.stderr)
            sys.exit(1)
    for name in os.listdir(repo):
        if name in NEVER_FILE or is_secrets_file(name):
            print(f"error: refusing to bundle a repository containing {name}", file=sys.stderr)
            sys.exit(1)
    on_disk = _walk(repo)
    tracked = _git_tracked(repo) if use_git else None
    if tracked is None:
        candidates = on_disk
    else:
        candidates = {}
        for rel, mode in tracked.items():
            if mode == "160000":                       # submodule: not a file
                continue
            if not os.path.lexists(os.path.join(repo, rel)):
                print(f"notice: tracked but missing, not bundled: {rel}", file=sys.stderr)
                continue
            candidates[rel] = "symlink" if mode == "120000" else mode
        for rel in sorted(set(on_disk) - set(tracked)):
            if not is_junk(rel):
                print(f"notice: not tracked by git, not bundled: {rel}", file=sys.stderr)
    out = []
    for rel in sorted(candidates):
        full = os.path.join(repo, rel)
        if candidates[rel] == "symlink" or os.path.islink(full):
            skipped.append(f"symlink: {rel}")
            continue
        if is_junk(rel):
            skipped.append(f"prior-run artifact or credential file: {rel}")
            continue
        mode = candidates[rel]
        if mode in ("100644", "100755"):
            executable = mode == "100755"
        else:
            executable = bool(os.stat(full).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        out.append((rel, executable))
    for msg in skipped:
        if strict:
            print(f"error (strict): skipping {msg}", file=sys.stderr)
            sys.exit(1)
        print(f"skipping {msg}", file=sys.stderr)
    return out


def _epoch():
    try:
        return max(0, int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    except ValueError:
        return 0


def write_bundle(output, members, repo=REPO):
    """Deterministic .tgz of members [(rel, executable)] under lazaret/."""
    mtime = _epoch()
    raw = io.BytesIO()
    # filename="" keeps the output's name out of the gzip header
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for rel, executable in members:
                with open(os.path.join(repo, rel), "rb") as f:
                    data = f.read()
                info = tarfile.TarInfo(f"lazaret/{rel}")
                info.type = tarfile.REGTYPE
                info.size = len(data)
                info.mode = 0o755 if executable else 0o644
                info.mtime = mtime
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tf.addfile(info, io.BytesIO(data))
    with open(output, "wb") as f:
        f.write(raw.getvalue())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("output", nargs="?", default=os.path.join(os.path.dirname(REPO), "lazaret.tgz"))
    ap.add_argument("--strict", action="store_true",
                    help="any skipped junk fails the build (for tests)")
    ap.add_argument("--repo", default=REPO, help=argparse.SUPPRESS)      # tests
    ap.add_argument("--no-git", action="store_true",
                    help="walk the trees instead of asking git which files are tracked")
    args = ap.parse_args(argv)
    members = _collect(args.strict, os.path.abspath(args.repo), not args.no_git)
    write_bundle(args.output, members, os.path.abspath(args.repo))
    print(f"bundle: {args.output} — {len(members)} files, "
          f"{os.path.getsize(args.output)/1024:.0f} KiB")


if __name__ == "__main__":
    main()
