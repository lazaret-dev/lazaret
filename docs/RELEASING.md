# Releasing Lazaret

One-time setup for claiming the package names and switching to token-free publishing, then the routine for cutting a release, and what to do when a tag goes out wrong. The repository layout is described in `STRUCTURE.md`.

## First-time setup

Do these in order. Everything here is one-time.

1. **Accounts and orgs.** The `lazaret-dev` org exists on GitHub and the `lazaret-dev` group on GitLab.
   - GitHub org → Settings → Authentication security → require two-factor authentication. Do the same for the GitLab group (Settings → General → Permissions).
   - GitHub org → Settings → Verified and approved domains → add `lazaret.dev` (DNS TXT record at your registrar).
   - Set up a signing key for release tags (see *Signing key* below). `scripts/tag-release.sh` refuses to make an unsigned tag, and the release workflow refuses to publish from one.

2. **Create the repos and push.**
   - Create `lazaret-dev/lazaret` on GitHub (public, empty, no README) and `lazaret-dev/lazaret` on GitLab (empty).
   - Transfer or delete the earlier `johnabooth-afk/lazaret` repo so there's only one GitHub home.
   - Push to both at once from your machine (see *Mirroring to GitLab* below), then confirm the CI workflow passes on GitHub.
   - GitHub repo → Settings → Code security → enable private vulnerability reporting, Dependabot alerts, and secret scanning.
   - GitHub repo → Settings → Rules → Rulesets: protect `main` (no force-push, no deletion) and add a tag ruleset for `v*` (no deletion, no update). On GitLab: Settings → Repository → Protected tags → `v*`, allowed to create: Maintainers.

3. **First PyPI release.** Recommended: add a *pending* trusted publisher on PyPI (Account settings → Publishing → GitHub: owner `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `pypi`), then push the first `v*` tag and let the release workflow create the project. No token is ever created.

   Manual alternative, if you want the name claimed before CI is ready:
   ```sh
   cd python
   python _build/lazaret_build.py dist     # Lazaret's own stdlib build; nothing to install
   twine upload dist/*                     # an upload tool on your machine, not a Lazaret dependency
   ```
   Use a PyPI API token when prompted, never save it to a file in the repo, and delete it after step 5.

4. **First npm release (manual).** npm trusted publishing is configured per package, so the package must exist first.
   ```sh
   cd js
   npm login
   npm publish --access public
   ```
   Also create the `@lazaret` org scope at npmjs.com (free for public packages) to hold future companion packages and block lookalikes.

   **Now do step 7, before anything else.** The misspellings are only safe once they are published.

5. **Switch both registries to trusted publishing (OIDC from GitHub Actions).**
   - GitHub repo → Settings → Environments → create `pypi` and `npm`. For each, add yourself as a required reviewer and restrict deployments to `v*` tags.
   - PyPI: project `lazaret` → Settings → Publishing → add GitHub publisher: owner `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `pypi`.
   - npm: package `lazaret` → Settings → Trusted publishing → GitHub Actions: organization `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `npm`. Leave **Allow npm publish unchecked**: the publisher is then stage-only, and CI can only stage a release, which goes live after you approve it with 2FA. Then set the package to require 2FA and disallow tokens for publishing.
   - Delete any API tokens you created for the first manual releases.

6. **Domain (lazaret.dev).**
   - At the registrar: turn on auto-renew, the transfer lock, and 2FA on the registrar account. An expired maintainer domain is a known route to hijacking package-registry accounts.
   - Create `security@lazaret.dev` (a forward is fine). It's already referenced in `SECURITY.md`.

7. **Reserve likely misspellings (typosquat defense). Blocking: do it right after the first publish (steps 3 and 4).**
   The names: `lazarat`, `lazarett`, `lazeret`. `lazarat` matters most: it's the likeliest misspelling, and it reads like "Lazarus RAT," which is exactly what an attacker would want to publish. As of 2026-09-25, twelve hours and more after 0.0.1 went live, all three were still unclaimed on both registries.
   ```sh
   python3 scripts/make_typosquat_stubs.py --check    # which names are still unclaimed (exit 1 if any)
   python3 scripts/make_typosquat_stubs.py            # or pass your own list of names
   # for each name in build/typosquats/:
   twine upload build/typosquats/lazarat/python/*.whl
   (cd build/typosquats/lazarat/js && npm publish --access public)
   npm deprecate lazarat "Misspelling of lazaret. Run: npm install lazaret"
   python3 scripts/make_typosquat_stubs.py --check    # must now print "All misspellings are reserved."
   ```
   Then on PyPI, open each stub project → Manage → Releases → **Yank** 0.0.1, with the reason "Misspelling of lazaret." Yanked releases stay reserved but pip skips them, so `pip install lazarat` fails instead of quietly installing a stub. On npm, the deprecation shows a warning on install.
   Each stub has no dependencies and no code. Importing or requiring it raises an error pointing to `lazaret`, so a misspelled dependency fails loudly rather than silently. It deliberately does not depend on `lazaret`: a stub that pulls in the real package would hide the typo and leave the misspelled name in people's lockfiles.
   These are one-time manual publishes. Don't add them to CI.
   - [ ] `python3 scripts/make_typosquat_stubs.py --check` exits 0 and prints "All misspellings are reserved."

8. **Trademark.** Search "LAZARET" in Classes 9 and 42 at tmsearch.uspto.gov. (`github.com/lazaret` belongs to an unrelated archaeology lab in Nice; that's why the org is `lazaret-dev`.)

## Signing key

Release tags are signed. SSH signing (git 2.34 or later) reuses the key you already push with:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
# lets `git tag -v` verify your own signatures:
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Add the same public key to GitHub (Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**) and to GitLab (Preferences → SSH Keys → Usage type: Signing), so the tags show as Verified. A GPG key works too: `git config --global user.signingkey <KEY-ID>`.

## Mirroring to GitLab

GitHub is the source of truth; GitLab is a read-only mirror. The simplest setup with no secrets in CI is to push to both from your machine:

```sh
git remote add origin git@github.com:lazaret-dev/lazaret.git
git remote set-url --add --push origin git@github.com:lazaret-dev/lazaret.git
git remote set-url --add --push origin git@gitlab.com:lazaret-dev/lazaret.git
git push origin main                      # goes to both
git push origin refs/tags/v0.1.0          # a release tag: one tag at a time, also to both
```

Never `git push --tags` (or `git push origin main --tags`): it pushes every tag in your local clone, including experiments and tags you deleted on the server, and a pushed `v*` tag starts a release.

Anything merged through the GitHub web UI reaches GitLab the next time you pull and push. On the GitLab project, note in the description that it's a mirror, and disable issues and merge requests so contributions go to GitHub. (GitLab can also pull-mirror automatically, but on gitlab.com that requires a paid tier.)

## Cutting a release

1. Bump `__version__` in `python/src/lazaret/__init__.py` and `"version"` in `js/package.json` in one commit, and get it onto `main` (merge the PR, or push to `main`).
2. Tag the commit on `main`, from a clean checkout of it:
   ```sh
   git switch main && git pull
   sh scripts/tag-release.sh                # or: sh scripts/tag-release.sh v0.2.0
   ```
   The script refuses uncommitted changes, a HEAD that isn't on `origin/main` (it fetches first), committed versions that disagree or don't match the tag (`scripts/check-versions.sh HEAD vX.Y.Z`), and a tag name that already exists locally or on `origin`. It then creates an annotated, signed tag. Without a working signing key it stops; it never makes an unsigned tag. It does not push.
3. Push that one tag, with the command the script printed:
   ```sh
   git push origin refs/tags/v0.2.0         # both push URLs: GitHub and GitLab
   ```
4. The tag triggers `.github/workflows/release.yml`:
   - `verify-tag` fails the release unless the tagged commit is on `main`, the tag is annotated and signed, and the versions committed at the tag match it;
   - the full test suite runs (`ci.yml`);
   - `build-python` builds the wheel and sdist with Lazaret's own stdlib backend (stamped with the tagged commit's time, so rebuilding a tag is byte-identical), and `build-npm` packs the npm tarball;
   - only when **both** builds succeed do the publish jobs start, each waiting for your approval on its environment (`pypi`, `npm`).
5. PyPI goes live as soon as its job finishes. npm is only *staged*: approve it with 2FA at https://www.npmjs.com/package/lazaret (the **Staged Packages** tab) or with `npm stage approve <stage-id>`. The run's summary page carries a reminder.
6. - [ ] `python3 scripts/make_typosquat_stubs.py --check` still exits 0.

`sh scripts/check-versions.sh` with no arguments checks the working tree and fails if either version file has uncommitted changes; `sh scripts/check-versions.sh <ref>` checks the files as committed at a tag, branch or commit (`sh scripts/check-versions.sh v0.0.1`).

## Recovering from a bad tag

Re-point a tag only if **nothing was published from it**. PyPI and npm versions are immutable: once a version is public (or staged on npm and approved), release the next patch version instead and leave the tag alone.

### v0.1.0 (tagged 2026-09-25, pointing at 8b63318)

`v0.1.0` was pushed pointing at `8b63318`, whose version files still say `0.0.1` (the bump was committed afterwards). The release workflow at that commit runs the `versions` check (tag vs. files) inside its test stage, before any build or publish job, so its run should have stopped there with nothing published; step 1 confirms it. The decision is to keep the version number 0.1.0 and re-tag the fixed commit.

1. Confirm nothing went out for 0.1.0:
   ```sh
   npm view lazaret versions --json          # expect ["0.0.1"]
   npm stage list lazaret                    # (after npm login) expect no 0.1.0; if there is one: npm stage reject <stage-id>
   ```
   and https://pypi.org/project/lazaret/#history lists only 0.0.1, and the v0.1.0 run on the Actions tab failed in its test stage. If 0.1.0 is on PyPI or public on npm, stop here and release 0.1.1 instead.
2. Lift the tag protection:
   - GitHub: repo → Settings → Rules → Rulesets → the `v*` tag ruleset → Enforcement status: **Disabled** → Save changes.
   - GitLab: project → Settings → Repository → Protected tags → `v*` → **Unprotect**.
3. Delete the tag everywhere:
   ```sh
   git push origin :refs/tags/v0.1.0        # origin has both push URLs: deletes it on GitHub and GitLab
   git tag -d v0.1.0
   git ls-remote --tags git@github.com:lazaret-dev/lazaret.git refs/tags/v0.1.0   # prints nothing
   git ls-remote --tags git@gitlab.com:lazaret-dev/lazaret.git refs/tags/v0.1.0   # prints nothing
   ```
4. GitHub leftovers:
   - If a GitHub Release named v0.1.0 was created, deleting the tag turns it into a draft: delete it on the Releases page.
   - GitHub served "Source code (zip / tar.gz)" archives for v0.1.0 generated from `8b63318` (0.0.1 code). They disappear with the tag, and the new tag's archives are generated from the new commit, so anything downloaded before now is not what 0.1.0 is. Don't publish checksums of those archives.
   - The failed release run for the old tag can stay in the Actions history; don't re-run it.
5. Get the fixed commit onto `main` and tag it (set up a signing key first if you haven't: see *Signing key*; the release workflow now rejects unsigned tags):
   ```sh
   git switch main && git pull              # main now has the fixes and "Bump version to 0.1.0"
   sh scripts/check-versions.sh HEAD v0.1.0 # expect: python: 0.1.0  npm: 0.1.0 ... tag: v0.1.0 matches
   sh scripts/tag-release.sh v0.1.0
   git push origin refs/tags/v0.1.0
   ```
6. Restore the protection right away:
   - GitHub: the `v*` tag ruleset → Enforcement status: **Active** → Save changes.
   - GitLab: Settings → Repository → Protected tags → protect `v*` again (allowed to create: Maintainers).
7. Approve the `pypi` and `npm` environments in the new release run, then approve the staged npm version.
8. Other clones keep the old tag: `git fetch --tags` never moves an existing tag. On every other machine run `git tag -d v0.1.0 && git fetch origin tag v0.1.0`.

### In general

The same steps with your version: confirm nothing was published, lift the tag protection on GitHub and GitLab, `git push origin :refs/tags/vX.Y.Z` and `git tag -d vX.Y.Z`, delete any GitHub Release, fix `main`, `sh scripts/tag-release.sh vX.Y.Z`, `git push origin refs/tags/vX.Y.Z`, restore the protection.

## Notes

- All actions in the workflows are pinned to full commit SHAs, with the version in a comment. Dependabot opens weekly PRs to bump them, after a 7-day cooldown.
- The publish jobs install nothing. `publish-npm` uses the npm bundled with an exact Node version (`node-version` in `release.yml`, 24.21.0 with npm 11.19.0) and checks it is at least 11.15.0 (`npm stage`; trusted publishing needs 11.5.1). To move to a newer Node, check its bundled npm first (`deps/npm/package.json` in the nodejs/node repository at that version's tag) and update both places in `release.yml`.
- `build-python` pins an exact Python (3.12.14): compressed bytes depend on the interpreter's zlib, so a byte-identical rebuild of a tag needs the same Python.
- PyPI trusted publishing has run for real (v0.0.1). The npm job's staged publish runs for the first time on the next release; the first npm release (step 4) was manual because npm only allows a trusted publisher on a package that already exists.
- npm provenance requires the GitHub repo to be public. So does `verify-tag`, which fetches `main` without credentials.
