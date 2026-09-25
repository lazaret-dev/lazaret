#!/usr/bin/env sh
# Creates the signed release tag for the commit you are on. It never pushes.
#
#   scripts/tag-release.sh [vX.Y.Z]      (default: v<the committed version>)
#
# Refuses unless:
#   - no tracked file has uncommitted changes (a tag records a commit, not the
#     working tree: v0.1.0 was once pushed pointing at a commit that still said
#     0.0.1, because the bump was never committed);
#   - HEAD is on main as the remote has it (fetched first), so the tag names a
#     reviewed, pushed commit;
#   - the Python and npm versions committed at HEAD agree and match the tag
#     (scripts/check-versions.sh HEAD vX.Y.Z);
#   - the tag exists neither locally nor on the remote.
# Then creates an annotated tag signed with your git signing key (git tag -s).
# Without a working key it stops: it never falls back to an unsigned tag.
# Finally prints the command that pushes this one tag and nothing else.
#
# Environment: RELEASE_REMOTE (default origin), RELEASE_BRANCH (default main).
# POSIX sh; works with Git for Windows' sh.
set -eu
cd "$(dirname "$0")/.."

remote="${RELEASE_REMOTE:-origin}"
branch="${RELEASE_BRANCH:-main}"
recovery='docs/RELEASING.md, "Recovering from a bad tag"'

fail() { echo "error: $*" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not inside a git checkout"

# 1. Nothing uncommitted.
changes=$(git status --porcelain --untracked-files=no)
if [ -n "$changes" ]; then
  echo "$changes" >&2
  fail "uncommitted changes. A tag records a commit, not your working tree: commit
(and push) them, or stash them, then run this again."
fi
untracked=$(git status --porcelain --untracked-files=normal | grep '^??' || true)
if [ -n "$untracked" ]; then
  echo "note: untracked files are not part of the release (they are not in the tagged commit):" >&2
  echo "$untracked" >&2
fi

# 2. HEAD is on main, as the remote has it.
head=$(git rev-parse HEAD)
if git remote get-url "$remote" >/dev/null 2>&1; then
  git fetch --quiet --no-tags "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch" \
    || fail "could not fetch $branch from $remote, so can't confirm HEAD is on it"
  base="refs/remotes/$remote/$branch"
else
  base="refs/heads/$branch"
  echo "note: no remote named $remote; checking against the local $branch branch" >&2
fi
git rev-parse --verify --quiet "$base" >/dev/null || fail "$base does not exist"
if ! git merge-base --is-ancestor "$head" "$base"; then
  fail "HEAD ($(git rev-parse --short HEAD)) is not on $base.
Release tags only name commits already on $branch: merge and push first, then
check out that commit (git switch $branch && git pull) and run this again."
fi

# 3. Committed versions agree and match the tag.
version=$(git show "HEAD:python/src/lazaret/__init__.py" | tr -d '\r' \
  | sed -n "s/^__version__[[:space:]]*=[[:space:]]*[\"']\([^\"']*\)[\"'].*/\1/p" | head -n 1)
[ -n "$version" ] || fail "no __version__ in python/src/lazaret/__init__.py at HEAD"
tag="${1:-v$version}"
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "release tags look like vX.Y.Z, not: $tag" ;;
esac
sh scripts/check-versions.sh HEAD "$tag"

# 4. The tag is new, here and on the remote.
if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
  fail "tag $tag already exists locally ($(git rev-parse --short "$tag^{commit}")).
Tags are never moved silently; if it was pushed by mistake, see $recovery."
fi
if git remote get-url "$remote" >/dev/null 2>&1; then
  on_remote=$(git ls-remote --tags "$remote" "refs/tags/$tag") \
    || fail "could not list the tags on $remote"
  if [ -n "$on_remote" ]; then
    fail "tag $tag already exists on $remote. To re-point it, see $recovery."
  fi
fi

# 5. Signed, annotated tag. No key, no tag.
if ! git tag -s "$tag" -m "Lazaret $tag"; then
  git tag -d "$tag" >/dev/null 2>&1 || true
  fail "git could not sign the tag, so no tag was created (release tags are always signed).
Set up a signing key, then run this again. SSH is simplest:
    git config --global gpg.format ssh
    git config --global user.signingkey ~/.ssh/id_ed25519.pub
or GPG:
    git config --global user.signingkey <KEY-ID>
Add the same key to GitHub as a *signing* key so the tag shows as Verified."
fi
if [ "$(git cat-file -t "$tag")" != "tag" ] \
   || ! git cat-file tag "$tag" | grep -Eq '^-----BEGIN (PGP|SSH) SIGNATURE-----|^-----BEGIN SIGNED MESSAGE-----'; then
  git tag -d "$tag" >/dev/null
  fail "the new tag carried no signature, so it was deleted again"
fi

push_urls=$(git remote get-url --push --all "$remote" 2>/dev/null || true)
echo
echo "Created signed tag $tag -> $(git rev-parse --short HEAD) ($(git log -1 --format=%s HEAD))"
echo "Verify it:  git tag -v $tag"
echo
echo "Push this one tag (never --tags, which pushes every local tag):"
echo "    git push $remote refs/tags/$tag"
if [ -n "$push_urls" ]; then
  echo "That push goes to every push URL of $remote:"
  echo "$push_urls" | sed 's/^/    /'
fi
