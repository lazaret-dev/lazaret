#!/usr/bin/env sh
# Fails if the Python and npm package versions (or the release tag) disagree.
# The Python version's single source is __version__ in src/lazaret/__init__.py
# (the build backend reads it from there).
set -eu
cd "$(dirname "$0")/.."
py=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' python/src/lazaret/__init__.py)
js=$(node -p "require('./js/package.json').version")
echo "python: $py  npm: $js"
[ -n "$py" ] && [ "$py" = "$js" ] || { echo "version mismatch" >&2; exit 1; }
tag=""
[ "${GITHUB_REF_TYPE:-}" = "tag" ] && tag="$GITHUB_REF_NAME"
if [ -n "$tag" ] && [ "$tag" != "v$py" ]; then
  echo "tag $tag does not match version v$py" >&2; exit 1
fi
