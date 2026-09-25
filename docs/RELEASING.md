# Releasing Lazaret

One-time setup for claiming the package names and switching to token-free publishing, then the routine for cutting a release. The repository layout is described in `STRUCTURE.md`.

## First-time setup

Do these in order. Everything here is one-time.

1. **Accounts and orgs.** The `lazaret-dev` org exists on GitHub and the `lazaret-dev` group on GitLab.
   - GitHub org → Settings → Authentication security → require two-factor authentication. Do the same for the GitLab group (Settings → General → Permissions).
   - GitHub org → Settings → Verified and approved domains → add `lazaret.dev` (DNS TXT record at your registrar).

2. **Create the repos and push.**
   - Create `lazaret-dev/lazaret` on GitHub (public, empty, no README) and `lazaret-dev/lazaret` on GitLab (empty).
   - Transfer or delete the earlier `johnabooth-afk/lazaret` repo so there's only one GitHub home.
   - Push to both at once from your machine (see *Mirroring to GitLab* below), then confirm the CI workflow passes on GitHub.
   - GitHub repo → Settings → Code security → enable private vulnerability reporting, Dependabot alerts, and secret scanning.
   - GitHub repo → Settings → Rules → protect `main` and `v*` tags (no force-push, no deletion).

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

5. **Switch both registries to trusted publishing (OIDC from GitHub Actions).**
   - GitHub repo → Settings → Environments → create `pypi` and `npm`. For each, add yourself as a required reviewer and restrict deployments to `v*` tags.
   - PyPI: project `lazaret` → Settings → Publishing → add GitHub publisher: owner `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `pypi`.
   - npm: package `lazaret` → Settings → Trusted publishing → GitHub Actions: organization `lazaret-dev`, repository `lazaret`, workflow `release.yml`, environment `npm`. Then set the package to require 2FA and disallow tokens for publishing.
   - Delete any API tokens you created for the first manual releases.

6. **Domain (lazaret.dev).**
   - At the registrar: turn on auto-renew, the transfer lock, and 2FA on the registrar account. An expired maintainer domain is a known route to hijacking package-registry accounts.
   - Create `security@lazaret.dev` (a forward is fine). It's already referenced in `SECURITY.md`.

7. **Reserve likely misspellings (typosquat defense).** Do this right after steps 3 and 4, before the name gets any attention.
   The names: `lazarat`, `lazarett`, `lazeret`. `lazarat` matters most: it's the likeliest misspelling, and it reads like "Lazarus RAT," which is exactly what an attacker would want to publish.
   ```sh
   python3 scripts/make_typosquat_stubs.py      # or pass your own list of names
   # for each name in build/typosquats/:
   twine upload build/typosquats/lazarat/python/*.whl
   (cd build/typosquats/lazarat/js && npm publish --access public)
   npm deprecate lazarat "Misspelling of lazaret. Run: npm install lazaret"
   ```
   Then on PyPI, open each stub project → Manage → Releases → **Yank** 0.0.1, with the reason "Misspelling of lazaret." Yanked releases stay reserved but pip skips them, so `pip install lazarat` fails instead of quietly installing a stub. On npm, the deprecation shows a warning on install.
   Each stub has no dependencies and no code. Importing or requiring it raises an error pointing to `lazaret`, so a misspelled dependency fails loudly rather than silently. It deliberately does not depend on `lazaret`: a stub that pulls in the real package would hide the typo and leave the misspelled name in people's lockfiles.
   These are one-time manual publishes. Don't add them to CI.

8. **Trademark.** Search "LAZARET" in Classes 9 and 42 at tmsearch.uspto.gov. (`github.com/lazaret` belongs to an unrelated archaeology lab in Nice; that's why the org is `lazaret-dev`.)

## Mirroring to GitLab

GitHub is the source of truth; GitLab is a read-only mirror. The simplest setup with no secrets in CI is to push to both from your machine:

```sh
git remote add origin git@github.com:lazaret-dev/lazaret.git
git remote set-url --add --push origin git@github.com:lazaret-dev/lazaret.git
git remote set-url --add --push origin git@gitlab.com:lazaret-dev/lazaret.git
git push origin main --tags        # goes to both
```

Anything merged through the GitHub web UI reaches GitLab the next time you pull and push. On the GitLab project, note in the description that it's a mirror, and disable issues and merge requests so contributions go to GitHub. (GitLab can also pull-mirror automatically, but on gitlab.com that requires a paid tier.)

## Releasing

```sh
# bump __version__ in python/src/lazaret/__init__.py and "version" in js/package.json, commit, then:
git tag -s v0.0.2 -m "v0.0.2"
git push origin main v0.0.2
```

The tag triggers `.github/workflows/release.yml`: it reruns the full test suite, builds the Python wheel and sdist with Lazaret's own stdlib backend (stamped with the tagged commit's time, so rebuilding a tag is byte-identical), and then waits for your approval on the `pypi` and `npm` environments before publishing each one.

## Notes

- All actions in the workflows are pinned to full commit SHAs, with the version in a comment. Dependabot opens weekly PRs to bump them.
- The release workflow follows the documented trusted-publishing setups for PyPI and npm but hasn't run for real yet. Expect to adjust it on the first tagged release, which is why which is why the first npm release (step 4) is manual.
- npm provenance requires the GitHub repo to be public.
- `LICENSE` files currently carry the standard Apache-2.0 notice. Paste the full license text from https://www.apache.org/licenses/LICENSE-2.0.txt into `LICENSE`, `python/LICENSE`, and `js/LICENSE` before the first release.
