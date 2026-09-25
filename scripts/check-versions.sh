#!/usr/bin/env sh
# Fails unless the Python and npm package versions agree, and match the
# release tag when there is one.
#
#   scripts/check-versions.sh             the working tree; fails if either
#                                         version file has uncommitted changes
#                                         (a tag records a commit, not your
#                                         working tree)
#   scripts/check-versions.sh REF [TAG]   the version files as committed at REF
#                                         (a tag, commit or branch: v0.1.0, HEAD)
#
# The tag checked is TAG if given, else REF when REF is a release tag name
# (v*), else $GITHUB_REF_NAME when CI runs for a tag push
# (GITHUB_REF_TYPE=tag). With no tag only the two versions are compared.
#
# The Python version's single source is __version__ in
# python/src/lazaret/__init__.py (the build backend reads it from there).
# POSIX sh; works with Git for Windows' sh. CRLF files are fine.
set -eu
cd "$(dirname "$0")/.."

PY_FILE=python/src/lazaret/__init__.py
JS_FILE=js/package.json
ref="${1:-}"
tag="${2:-}"

fail() { echo "error: $*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || fail "node is required to read $JS_FILE"

if [ -n "$ref" ]; then
  git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || fail "unknown git ref: $ref"
  case "$ref" in v[0-9]*) [ -n "$tag" ] || tag="$ref" ;; esac
  where="$ref ($(git rev-parse --short "$ref^{commit}"))"
else
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    dirty=$(git status --porcelain -- "$PY_FILE" "$JS_FILE")
    if [ -n "$dirty" ]; then
      echo "$dirty" >&2
      fail "uncommitted changes to the version files. A release tag points at a
commit, so these changes would not be in it. Commit the version bump first,
or check what a tag would get: scripts/check-versions.sh HEAD"
    fi
  else
    echo "note: not a git checkout; checking the files as they are" >&2
  fi
  where="working tree"
fi
if [ -z "$tag" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  tag="${GITHUB_REF_NAME:-}"
fi

read_file() {   # read_file PATH: the file at $ref, or in the working tree
  if [ -n "$ref" ]; then git show "$ref:$1"; else cat "$1"; fi
}

py=$(read_file "$PY_FILE" | tr -d '\r' \
  | sed -n "s/^__version__[[:space:]]*=[[:space:]]*[\"']\([^\"']*\)[\"'].*/\1/p" | head -n 1)
js=$(read_file "$JS_FILE" | node -e '
  let s = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (d) => { s += d; });
  process.stdin.on("end", () => {
    try {
      const v = JSON.parse(s.replace(/^﻿/, "")).version;
      if (typeof v === "string") process.stdout.write(v);
    } catch (e) {
      process.stderr.write("error: package.json is not valid JSON: " + e.message + "\n");
    }
  });')

echo "python: ${py:-?}  npm: ${js:-?}  ($where)"
[ -n "$py" ] || fail "no __version__ in $PY_FILE ($where)"
[ -n "$js" ] || fail "no \"version\" in $JS_FILE ($where)"
[ "$py" = "$js" ] || fail "version mismatch: python $py, npm $js ($where)"
if [ -n "$tag" ]; then
  if [ "$tag" != "v$py" ]; then
    fail "tag $tag does not match the committed version v$py ($where).
If this tag was already pushed, see docs/RELEASING.md, \"Recovering from a bad tag\"."
  fi
  echo "tag: $tag matches"
fi
echo "versions OK"
