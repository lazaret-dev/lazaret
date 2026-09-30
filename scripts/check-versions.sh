#!/usr/bin/env sh
# Fails unless the Python and npm package versions and the native engine's
# (rust/Cargo.toml's [workspace.package] version, and the two workspace
# entries in rust/Cargo.lock) agree, and match the release tag when there is
# one. The engine ships inside the platform wheels and reports its version
# (`lazaret --version`), so it is released in lockstep too.
#
#   scripts/check-versions.sh             the working tree; fails if any
#                                         version file has uncommitted changes
#                                         (a tag records a commit, not your
#                                         working tree)
#   scripts/check-versions.sh REF [TAG]   the version files as committed at REF
#                                         (a tag, commit or branch: v0.1.0, HEAD)
#
# The tag checked is TAG if given, else REF when REF is a release tag name
# (v*), else $GITHUB_REF_NAME when CI runs for a tag push
# (GITHUB_REF_TYPE=tag). With no tag only the versions are compared. A ref
# from before the native engine (no rust/Cargo.toml) is checked without it.
#
# The Python version's single source is __version__ in
# python/src/lazaret/__init__.py (the build backend reads it from there).
# After changing the Rust version, `cargo update --workspace --offline` in
# rust/ rewrites the two Cargo.lock entries.
# POSIX sh; works with Git for Windows' sh. CRLF files are fine.
set -eu
cd "$(dirname "$0")/.."

PY_FILE=python/src/lazaret/__init__.py
JS_FILE=js/package.json
RUST_FILE=rust/Cargo.toml
LOCK_FILE=rust/Cargo.lock
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
    dirty=$(git status --porcelain -- "$PY_FILE" "$JS_FILE" "$RUST_FILE" "$LOCK_FILE")
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
has_file() {    # has_file PATH: is there such a file at $ref, or in the working tree?
  if [ -n "$ref" ]; then git cat-file -e "$ref:$1" 2>/dev/null; else [ -f "$1" ]; fi
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

rust=-
if has_file "$RUST_FILE"; then
  rust=$(read_file "$RUST_FILE" | tr -d '\r' \
    | sed -n '/^\[workspace\.package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  has_file "$LOCK_FILE" || fail "no $LOCK_FILE ($where): run cargo update --workspace --offline in rust/ and commit it"
  locked=$(read_file "$LOCK_FILE" | tr -d '\r' | awk '
    /^\[\[package\]\]/ { name = "" }
    /^name = "/ { name = $3; gsub(/"/, "", name) }
    /^version = "/ && (name == "lazaret-engine" || name == "lazaret-ffi") { v = $3; gsub(/"/, "", v); print name "=" v }')
fi

echo "python: ${py:-?}  npm: ${js:-?}  rust: ${rust:-?}  ($where)"
[ -n "$py" ] || fail "no __version__ in $PY_FILE ($where)"
[ -n "$js" ] || fail "no \"version\" in $JS_FILE ($where)"
[ -n "$rust" ] || fail "no version under [workspace.package] in $RUST_FILE ($where)"
[ "$py" = "$js" ] || fail "version mismatch: python $py, npm $js, rust $rust ($where)"
if [ "$rust" != - ]; then
  [ "$rust" = "$py" ] || fail "version mismatch: python $py, npm $js, rust $rust ($where)"
  for crate in lazaret-engine lazaret-ffi; do
    have=$(echo "$locked" | sed -n "s/^$crate=//p" | head -n 1)
    [ "$have" = "$rust" ] || fail "$LOCK_FILE has $crate ${have:-missing}, not $rust ($where). Run
cargo update --workspace --offline in rust/ and commit $LOCK_FILE with the version bump."
  done
fi
if [ -n "$tag" ]; then
  if [ "$tag" != "v$py" ]; then
    fail "tag $tag does not match the committed version v$py ($where).
If this tag was already pushed, see docs/RELEASING.md, \"Recovering from a bad tag\"."
  fi
  echo "tag: $tag matches"
fi
echo "versions OK"
