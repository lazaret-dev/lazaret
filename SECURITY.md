# Security policy

Lazaret is a supply-chain security tool, so its own supply chain is held to a high bar:

- **No dependencies, at any layer.** The Python package runs on the standard library alone; its Postgres client (`lazaret.pg`) and safe XML parser (`lazaret.safexml`) are part of it. It builds with its own standard-library backend, and its tests run on plain `unittest`. `tests/architecture/test_stdlib_only.py` fails the build on any non-stdlib import, and `tests/build/test_build_backend.py` checks the wheel declares no dependencies. The npm package has none either.
- **Reproducible builds.** Rebuilding a release tag gives byte-identical wheel and sdist files, on Linux, macOS or Windows and whatever the checkout's line endings, given the same Python (release CI pins an exact one).
- **Token-free publishing.** Releases are published only from GitHub Actions using trusted publishing (OIDC), after manual approval. No long-lived registry tokens exist in the repository or in CI.
- **Checked release tags.** Release tags are annotated and signed (`scripts/tag-release.sh`). The release workflow refuses a tag that is unsigned, not on `main`, or doesn't match the versions committed at it, and publishes to PyPI and npm only if both packages built.
- **Staged npm releases.** CI can only *stage* an npm release. It becomes public after a maintainer approves it with npm 2FA, so even a compromised GitHub account or workflow can't publish to npm on its own.
- **Verifiable artifacts.** PyPI releases carry signed attestations and npm releases carry provenance, linking each artifact to the exact commit and workflow that built it.
- **Pinned CI.** Every GitHub Action is pinned to a full commit SHA; Dependabot proposes updates after a 7-day cooldown. The release jobs use exact tool versions (Node 24.21.0 and the npm it bundles, Python 3.12.14), and the jobs that can mint an OIDC token download and install nothing. The integration tests' Postgres image is pinned by digest. The test matrices deliberately use the latest patch release of each Python and Node line.
- **Nothing hostile ships.** Tests and fixtures are excluded from every published package, and offensive test samples live in a separate private repository. The Python build packs an allowlist of file types and fails on anything else in the source tree (a `.env`, `.DS_Store`, `._*`, editor backups, symlinks); the npm package excludes dotfiles and key files.
- **Misspellings are reserved.** Likely typos of the package name are held by inert stub packages that fail with a pointer to the real one. `python3 scripts/make_typosquat_stubs.py --check` verifies this against PyPI and npm, and the release checklist blocks on it.

## Reporting a vulnerability

Please report privately, not in a public issue:

- GitHub: use "Report a vulnerability" on the repository's Security tab, or
- email security@lazaret.dev.
