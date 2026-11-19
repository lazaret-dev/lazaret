# Releasing Lazaret

The routine for promoting reviewed public source, cutting a release from the
curated GitHub repository, and recovering when a tag or registry publish goes
wrong. The repository boundary is described in
[`../STRUCTURE.md`](../STRUCTURE.md): private
development happens in GitLab, while GitHub contains the reviewed public tree
and is the only authority for public release tags, PyPI and npm.

This file owns the release procedure. Do not duplicate its commands in other
documents. Changes follow [DOCUMENTATION_GUIDE.md](DOCUMENTATION_GUIDE.md).

## Repository and registry bootstrap

These controls already exist. Review them after a change of repository owner,
workflow name, release environment or registry account; do not repeat the
first-publish procedure for an established package.

1. **Accounts and orgs.** The `lazaret-dev` org exists on GitHub and the `lazaret-dev` group on GitLab.
   - GitHub org → Settings → Authentication security → require two-factor authentication. Do the same for the GitLab group (Settings → General → Permissions).
   - GitHub org → Settings → Verified and approved domains → add `lazaret.dev` (DNS TXT record at your registrar).

2. **Configure the private and public repositories.**
   - `lazaret-dev/lazaret` on GitLab is the private full-development repository.
   - `lazaret-dev/lazaret` on GitHub is the curated public repository and the
     source for public release tags, PyPI packages and npm packages.
   - Do not configure one remote to push automatically to both repositories.
     Private GitLab branches, tags and commits must not be mirrored wholesale
     to GitHub.
   - Maintain `public-integration` in GitLab for changes intended for the public
     repository. Before promotion, run the public-scope guard, full-history
     secret scan and proportionate test suite. Push the reviewed result to a
     GitHub feature branch and merge it through a protected pull request.
   - On GitHub, go to **Settings → Advanced Security** and enable private
     vulnerability reporting, Dependabot alerts, secret scanning and push
     protection where available.
   - On GitHub, go to **Settings → Rulesets → Rulesets**. Protect `main` from
     force-pushes and deletion, require pull requests and protected checks, and
     add a tag ruleset for `v*` that restricts creation to release maintainers
     and prevents update and deletion.
   - On GitLab, go to **Settings → Repository → Branch rules**. Protect the
     private development branch and `public-integration`; allow merge requests
     but prevent direct pushes and force-pushes.

3. **Registry identities and trusted publishing.** PyPI and npm both contain
   Lazaret 0.1.10. Public releases come only from the protected GitHub
   repository and `.github/workflows/release.yml`; no registry publishing token
   belongs in either repository.
   - GitHub repo → Settings → Environments → create `pypi` and `npm`. For each, add yourself as a required reviewer and restrict deployments to `v*` tags.
   - PyPI: project `lazaret` → Settings → Publishing → add GitHub publisher: owner `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `pypi`.
   - npm: package `lazaret` → Settings → Trusted publishing → GitHub Actions: organization `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `npm`. Leave **Allow npm publish unchecked**: the publisher is then stage-only, and CI can only stage a release, which goes live after you approve it with 2FA. Then set the package to require 2FA and disallow tokens for publishing.
   - After changing any of those identities, inspect both registry settings and
     run the release workflow only from a reviewed tag. Do not use a manual
     first-publish command as a shortcut.

4. **Domain (lazaret.dev).**
   - At the registrar: turn on auto-renew, the transfer lock, and 2FA on the registrar account. An expired maintainer domain is a known route to hijacking package-registry accounts.
   - Create `security@lazaret.dev` (a forward is fine). It's already referenced in `SECURITY.md`.
   - The reviewed static site source is tracked in `website/`. Deploy that directory to the existing Cloudflare Pages project only after its repository change is reviewed. Do not commit `.wrangler/`, credentials or local environment files, and do not deploy an empty `404.html`; see `website/README.md`.

5. **Verify reserved misspellings (typosquat defense).** The expected reserved
   names are `lazarat`, `lazarett` and `lazeret`. Do not rely on the historical
   2026-09-25 registry status: check the registries each time this control is
   audited.
   ```sh
   python3 scripts/make_typosquat_stubs.py --check
   ```
   It must exit 0 and print `All misspellings are reserved.` If a name is no
   longer controlled by the project, treat that as a registry-security incident
   rather than automatically publishing from a development checkout.

6. **Trademark.** Search "LAZARET" in Classes 9 and 42 at tmsearch.uspto.gov. (`github.com/lazaret` belongs to an unrelated archaeology lab in Nice; that's why the org is `lazaret-dev`.)

## Signing tags (optional)

Release tags don't need a signature: the tag ruleset, environment approvals,
trusted publishing and npm's 2FA stage approval protect a release. The ruleset
must restrict creation of `v*` tags to release maintainers as well as prevent
their update and deletion. If you want tags to show as Verified on GitHub,
configure signing in the public repository; `scripts/tag-release.sh` then signs
automatically. Use the approved release-signing key rather than assuming that a
particular default SSH key is the right one:

```sh
git config gpg.format ssh
git config user.signingkey /absolute/path/to/release-signing-key.pub
git config tag.gpgSign true
```

Then add the same public key to GitHub as a **Signing Key** (Settings → SSH and GPG keys → New SSH key → Key type).

## Promoting reviewed changes to public GitHub

GitLab contains the complete private development repository. GitHub contains
only the reviewed public product. They are not automatic mirrors, and a remote
must never have both repositories as push URLs.

Use separate remotes:

```sh
git remote add gitlab git@gitlab.com:lazaret-dev/lazaret.git
git remote add github-public https://github.com/lazaret-dev/lazaret.git
git fetch gitlab --prune --tags
git fetch github-public --prune --tags
```

Begin a public update from GitHub's current `main`:

```sh
git switch public-integration
git merge --ff-only github-public/main
```

If the local branch does not exist yet:

```sh
git switch --create public-integration github-public/main
```

Apply only changes reviewed for public release. Do not merge private GitLab
`main` into this branch. Before promotion, inspect the complete public diff and
run the release gates:

```sh
git diff --name-status github-public/main...HEAD
git diff --check github-public/main...HEAD
sh scripts/check-secrets.sh
sh scripts/check-versions.sh
```

The public-scope review is a maintainer decision: confirm that the diff contains
only product source and public documentation, no private branches, runner
operations, sample locations, credentials or private infrastructure. Run the
proportionate test suite, confirm that `github-public` has exactly one push URL
and that it is GitHub, and push the reviewed branch to protected
`public-integration` in GitLab. Then create a fresh GitHub branch and pull
request:

```sh
git remote get-url --push --all github-public
git push gitlab public-integration
public_branch="codex/public-release-$(date +%Y%m%d)"
git switch -c "$public_branch"
git push --set-upstream github-public "$public_branch"
gh pr create --repo lazaret-dev/lazaret --base main --head "$public_branch" --fill
```

Release tags are created only after the GitHub pull request passes its protected
checks and is merged. Never use `git push --tags`: it pushes every local tag,
including experiments and tags previously deleted on a server.

## Cutting a release

### Build-machine trust boundary

Published artifacts are built only on GitHub-hosted infrastructure. A release
tag calls `ci.yml` and `wheels.yml`:

- the Linux libraries and sdist use GitHub-hosted Linux runners and pinned
  PyPA manylinux or musllinux images;
- both macOS libraries, including ARM64, use GitHub-hosted macOS runners;
- both Windows libraries use GitHub-hosted Windows runners; and
- the npm WebAssembly package is built on GitHub-hosted Linux.

No public workflow may select a self-hosted runner. Private runner design and
operation belong to private GitLab documentation and are outside the public
release boundary.

1. On a feature branch of the public GitHub repository, bump `__version__` in
   `python/src/lazaret/__init__.py`, `"version"` in `js/package.json`, and
   `version` under `[workspace.package]` in `rust/Cargo.toml`, the native
   engine's version that ships in the platform wheels. Run `cargo update
   --workspace --offline` in `rust/`; it rewrites the workspace entries in
   `rust/Cargo.lock` (`lazaret-archive`, `lazaret-engine`, `lazaret-ffi`,
   `lazaret-net` and `lazaret-verify`; pratique keeps its own version). Commit
   the bump, run `sh scripts/check-versions.sh HEAD`, and merge it into `main`
   through a protected GitHub pull request. Do not push directly to `main`.
2. Tag the commit on `main`, from a clean checkout of it:
   ```sh
   git switch main
   git pull --ff-only github-public main
   RELEASE_REMOTE=github-public sh scripts/tag-release.sh
   # or: RELEASE_REMOTE=github-public sh scripts/tag-release.sh v0.2.0
   ```
   The script refuses uncommitted changes, a HEAD that isn't the tip of public
   GitHub `main`, committed versions that disagree or don't match the tag
   (`scripts/check-versions.sh HEAD vX.Y.Z`), and a tag name that already exists
   locally or on the selected release remote. It creates an annotated tag
   (signed as well if you enabled `tag.gpgSign`; see *Signing tags*) and does not
   push it. `RELEASE_NOT_LATEST=1` is an exceptional recovery control for
   intentionally tagging an older commit on `main`, not part of an ordinary
   release.
3. Push that one tag, with the command the script printed:
   ```sh
   git push github-public refs/tags/v0.2.0
   ```
4. The tag triggers `.github/workflows/release.yml`:
   - `verify-tag` fails the release unless the tagged commit is on `main`, the tag is annotated (not a lightweight tag), and the versions committed at the tag match it;
   - the full test suite runs (`ci.yml`);
   - `build-python` runs `wheels.yml`: the native engine's library for each of eight platforms (Linux x86-64 and ARM64 in PyPA's manylinux_2_28 and musllinux_1_2 images, macOS arm64 and x86-64, Windows x64 and ARM64), built with a pinned Rust and checked against its wheel's tag. A release tag runs the whole Python suite against every library; pull requests do the same except that Intel macOS runs the native-engine tests and every recorded-output snapshot module. It builds the sdist (with the engine's sources) and the eight platform wheels with Lazaret's own stdlib backend (stamped with the tagged commit's time) and checks them against each other; each platform wheel is installed with pip on its platform and run (the musl ones in their images), and the sdist is built by pip on Linux (compiling the engine). There is no pure wheel: elsewhere pip builds from the sdist, which needs Rust. `build-npm` builds the native engine as WebAssembly with the same pinned Rust, runs the npm tests on it and packs the npm tarball (checked to carry `native/lazaret.wasm` and `native/NOTICE`);
   - only when **both** builds succeed do the publish jobs start, each waiting for your approval on its environment (`pypi`, `npm`).
5. PyPI goes live as soon as its job finishes. npm is only *staged*: approve it with 2FA at https://www.npmjs.com/package/lazaret (the **Staged Packages** tab) or with `npm stage approve <stage-id>`. The run's summary page carries a reminder.
6. - [ ] `python3 scripts/make_typosquat_stubs.py --check` still exits 0.
7. Once the release is on PyPI, update and tag the pre-commit mirror
   (https://github.com/lazaret-dev/lazaret-pre-commit, from 0.1.9). pre-commit
   installs a Python hook with `pip install .` at its repository's root, which
   this repository can't serve, so the mirror holds the hook's definition and
   a package that pins the release; a mirror tagged before PyPI has the release
   fails to install:
   ```sh
   python3 scripts/make_pre_commit_mirror.py 0.2.0 ../lazaret-pre-commit
   cd ../lazaret-pre-commit
   git status --short
   git add -- .pre-commit-hooks.yaml pyproject.toml README.md LICENSE
   git diff --cached --check
   git diff --cached
   git commit -m "Lazaret 0.2.0"
   git tag -a v0.2.0 -m v0.2.0
   git push origin main refs/tags/v0.2.0
   ```
   The first time, create the repository empty on GitHub (Apache-2.0; the script writes the LICENSE), clone it next to this one, and protect its tags as this repository's are.

`sh scripts/check-versions.sh` with no arguments checks the working tree and fails if any version file has uncommitted changes; `sh scripts/check-versions.sh <ref>` checks the files as committed at a tag, branch or commit (`sh scripts/check-versions.sh v0.0.1`).

## Sharing a source tarball

The registries get packages built by the release workflow. To send the source itself (to a reviewer, say), build the archive from what git tracks, never with a plain `tar` of your working tree:

```sh
python3 scripts/make_bundle.py lazaret-source-X.Y.Z.tgz
git archive --format=tar.gz --output=lazaret-git-tree-X.Y.Z.tgz vX.Y.Z
```

Run these commands from the curated public checkout. `make_bundle.py` refuses
credential files and skips OS junk and build output (see `STRUCTURE.md`). A
plain `tar` does neither. On macOS it writes extended attributes as separate
`._name` files (AppleDouble), and can pick up untracked files, build output and
caches. If you must use `tar`, run it as `COPYFILE_DISABLE=1 tar
--exclude='._*' …`, and check that `tar -tzf ARCHIVE.tgz | grep -E
'(^|/)\._'` prints nothing.

## Recovering from a bad tag

Re-point a tag only if **nothing was published from it**. PyPI and npm versions are immutable: once a version is public (or staged on npm and approved), release the next patch version instead and leave the tag alone.

### Tag pushed but nothing published

First record the tag object, commit and failed run URL, then confirm the version
is absent from PyPI, public npm and npm staging:

```sh
curl --fail --silent --show-error https://pypi.org/pypi/lazaret/json \
  | python3 -c 'import json,sys; print(*json.load(sys.stdin)["releases"], sep="\n")'
npm view lazaret versions --json
npm stage list lazaret
gh run list --repo lazaret-dev/lazaret --limit 20
```

If the version appears in either public registry, or an npm stage was approved,
do not move the tag. Keep it naming the published source and release the next
patch version. If an unapproved npm stage exists while PyPI has nothing, reject
that stage before considering a re-tag.

Only when nothing was published:

1. On GitHub, open **Settings → Rulesets → Rulesets → the `v*` tag ruleset**,
   set its enforcement status to **Disabled**, and save. This temporary change
   needs explicit maintainer approval.
2. Delete the tag from public GitHub and locally, naming the release remote
   explicitly:

   ```sh
   git push github-public :refs/tags/vX.Y.Z
   git tag -d vX.Y.Z
   git ls-remote --tags github-public refs/tags/vX.Y.Z
   ```

   The final command must print nothing. If GitHub created a Release, remove the
   resulting draft on the Releases page. Leave the failed Actions run in the
   audit history and do not rerun it.
3. Merge the correction into public GitHub `main` through a protected pull
   request, then tag its clean tip:

   ```sh
   git switch main
   git pull --ff-only github-public main
   RELEASE_REMOTE=github-public sh scripts/tag-release.sh vX.Y.Z
   git push github-public refs/tags/vX.Y.Z
   ```

4. Immediately restore the `v*` ruleset to **Active**, confirm it protects tag
   creation, update and deletion, and then approve the release environments.
5. Other clones keep the old local tag. After the replacement is complete, run
   this in each clone:

   ```sh
   git tag -d vX.Y.Z
   git fetch github-public tag vX.Y.Z
   ```

Historical note: `v0.1.0` once named a commit whose files still said `0.0.1`.
The current workflow and `scripts/tag-release.sh` contain version and ancestry
checks to prevent that class of mistake; its incident-specific commands are not
the current procedure.

### One registry published, the other failed

A version can't be re-uploaded, so don't re-point the tag once either registry has it (the tag must keep naming what was published). Finish the other registry from the same run instead:

- **npm failed after PyPI published.** Recover only the tarball that the same
  run built. Download it, record its checksum, inspect its version and stage it
  for the normal 2FA approval; do not rebuild that version from another commit:
  ```sh
  gh run download <run-id> -n npm-dist -D npm-dist
  shasum -a 256 npm-dist/lazaret-X.Y.Z.tgz
  tar -xOf npm-dist/lazaret-X.Y.Z.tgz package/package.json | grep '"version"'   # X.Y.Z
  npm stage publish ./npm-dist/lazaret-X.Y.Z.tgz
  npm stage approve <stage-id>                                                  # asks for 2FA
  ```
  Then merge the workflow fix so the next release stages from CI again.
- **PyPI failed after npm staged but unapproved:** leave npm unapproved and
  rerun the failed job (`gh run rerun <run-id> --failed`), which publishes the
  artifacts that run built. If PyPI cannot be completed, reject the npm stage.
- **PyPI failed after npm was approved:** rerun the failed PyPI job from the
  original run. The public npm version makes the tag immutable even while PyPI
  is incomplete.
- If the package itself is wrong, leave the published version alone and release the next patch version from both.

## Notes

- All actions in the workflows are pinned to full commit SHAs, with the version in a comment. Dependabot opens weekly PRs to bump them, after a 7-day cooldown.
- The publish jobs install nothing. `publish-npm` uses the npm bundled with an exact Node version (`node-version` in `release.yml`, 24.21.0 with npm 11.19.0) and checks it is at least 11.15.0 (`npm stage`; trusted publishing needs 11.5.1). To move to a newer Node, check its bundled npm first (`deps/npm/package.json` in the nodejs/node repository at that version's tag) and update both places in `release.yml`.
- `build-python` pins an exact Python (3.12.14): compressed bytes depend on the interpreter's zlib, so a byte-identical rebuild of a tag needs the same Python.
- The native libraries' pins live in `.github/workflows/wheels.yml` and are bumped by hand (Dependabot only updates actions): `RUST_VERSION` (at or above `rust-version` in `rust/Cargo.toml`; `release.yml` has its own copy for the npm package's WebAssembly build, kept the same, which `test_review_release_workflow.py` checks), and the PyPA images, by digest: the two manylinux_2_28 ones and the two musllinux_1_2 ones, which the install job names again (`docker buildx imagetools inspect quay.io/pypa/manylinux_2_28_x86_64:latest`, and the same for `_aarch64` and `musllinux_1_2_x86_64`, `_aarch64`). The musl jobs install the musl-hosted toolchain of `RUST_VERSION` (`rustup toolchain install 1.95.0-x86_64-unknown-linux-musl --force-non-host`), which runs in the image. A pull request that changes the workflow runs it, so a bump is tested before a tag needs it. GitHub's last Intel macOS image, `macos-15-intel`, goes away in August 2027; the x86-64 macOS library then has to be cross-built on Apple silicon (`docs/RUST_ENGINE.md`, section 4).
- The sdist and the wheels are `Apache-2.0 AND Unicode-3.0` and carry `LICENSE`, `LICENSE-UNICODE` (the Unicode 13.0 table is Unicode data, and so is the engine the dashboard carries, with its notices) and `rust/NOTICE`: the native engine, which every wheel carries and the sdist carries the source of, is Lazaret's own work since P-16 (`docs/RUST_ENGINE.md`, section 11). The npm package is `Apache-2.0 AND Unicode-3.0` too: it carries the native engine as WebAssembly (`native/lazaret.wasm`, with `rust/NOTICE` as `native/NOTICE`), with `js/LICENSE-UNICODE` and `js/NOTICE`. The codec names the npm package and the dashboard list are what Python's codecs answer to, facts about Python, so no package carries CPython's license. The engine takes no translation of CPython code (write from the documentation and Python's answers): `tests/architecture/test_rust_notices.py` fails on an engine file that carries CPython's license or says it is ported from CPython, and `test_notices.py` holds the npm package's notices to its code.
- PyPI and npm both contain Lazaret 0.1.10. Their trusted publishers are bound
  to `lazaret-dev/lazaret` on GitHub, `.github/workflows/release.yml`, and the
  `pypi` or `npm` environment. Verify those identities before changing repository
  ownership, workflow names or environment names.
- npm provenance requires the GitHub repo to be public. So does `verify-tag`, which fetches `main` without credentials.
