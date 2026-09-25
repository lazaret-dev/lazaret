#!/usr/bin/env python3
"""Build a source bundle of the Lazaret repository (card 12c56422, audit G21).

The bundle is a whitelist of what the repository IS, not a snapshot of what
happens to be lying around in a working directory:

  top level     README.md, SECURITY.md, STRUCTURE.md, LICENSE
  trees         .github/, scripts/, examples/, docs/, python/, js/

Inside those trees, prior-run ARTIFACTS rather than source are SKIPPED with a
notice: reports, SARIF, state DBs, bytecode, AppleDouble files, node_modules,
build outputs (build/, dist/, *.egg-info), virtualenvs. Anything on the NEVER
list at the top level is a hard error: stale state that must not ship.

Secrets files (.env, .env.local, ...) are never bundled, anywhere. A
.env.example template is fine.

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
import os
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


def is_old_name_junk(rel):
    """Card 27e1dfda (rename codeguard -> lazaret): a surviving file whose
    basename still carries the pre-rename spelling is a stale twin."""
    return "codeguard" in os.path.basename(rel).lower()


def is_secrets_file(rel):
    """.env and its variants hold real credentials; a .env.example is a template."""
    name = os.path.basename(rel)
    return (name == ".env" or name.startswith(".env.")) and not name.endswith(".example")


def is_junk(rel):
    """True if rel is a prior-run artifact, machine cruft, or a secrets file."""
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
    if is_secrets_file(rel):
        return True
    # NEVER_FILE is TOP-LEVEL only: fixtures/detection_gaps/{dist,skips}/
    # bundle.py and .DS_Store are legitimate G10 fixtures that share a name
    # with top-level junk.
    if len(parts) == 1 and parts[0] in NEVER_FILE:
        return True
    return is_old_name_junk(rel)


def collect(strict=False, repo=REPO):
    """Whitelist walk -> sorted list of repo-relative paths to pack."""
    out, skipped = [], []
    for rel in REQUIRED:
        if not os.path.isfile(os.path.join(repo, rel)):
            print(f"error: required file missing: {rel}", file=sys.stderr)
            sys.exit(1)
    for name in os.listdir(repo):
        if name in NEVER_FILE or is_secrets_file(name):
            print(f"error: refusing to bundle a repository containing {name}", file=sys.stderr)
            sys.exit(1)
    for rel in TOP_FILES:
        if os.path.isfile(os.path.join(repo, rel)):
            out.append(rel)
    for tree in TREES:
        base = os.path.join(repo, tree)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = sorted(dirs)
            for name in sorted(files):
                rel = os.path.relpath(os.path.join(root, name), repo).replace(os.sep, "/")
                if is_junk(rel):
                    skipped.append(rel)
                    continue
                out.append(rel)
    out = sorted(set(out))
    for rel in skipped:
        msg = f"skipping prior-run artifact: {rel}"
        if strict:
            print(f"error (strict): {msg}", file=sys.stderr)
            sys.exit(1)
        print(msg, file=sys.stderr)
    return out


def _clean(ti):
    """Sanitize tar member metadata: no uid/gid/uname/gname from the build
    machine, normalized mtime: deterministic builds."""
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mtime = 0
    return ti


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("output", nargs="?", default=os.path.join(os.path.dirname(REPO), "lazaret.tgz"))
    ap.add_argument("--strict", action="store_true",
                    help="any skipped junk fails the build (for tests)")
    args = ap.parse_args()
    rels = collect(strict=args.strict)
    with tarfile.open(args.output, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        for rel in rels:
            tf.add(os.path.join(REPO, rel), arcname=f"lazaret/{rel}", filter=_clean)
    print(f"bundle: {args.output} — {len(rels)} files, "
          f"{os.path.getsize(args.output)/1024:.0f} KiB")


if __name__ == "__main__":
    main()
