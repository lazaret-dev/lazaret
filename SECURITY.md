# Security policy

Lazaret is a supply-chain security tool, so its own supply chain is held to a high bar:

- **No dependencies, at any layer.** The Python package runs on the standard library alone; its Postgres client (`lazaret.pg`) and safe XML parser (`lazaret.safexml`) are part of it. It builds with its own standard-library backend, and its tests run on plain `unittest`. `tests/architecture/test_stdlib_only.py` fails the build on any non-stdlib import, and `tests/build/test_build_backend.py` checks the wheel declares no dependencies. The npm package has none either.
- **Reproducible builds.** Rebuilding a release tag gives byte-identical wheel and sdist files.
- **Token-free publishing.** Releases are published only from GitHub Actions using trusted publishing (OIDC), after manual approval. No long-lived registry tokens exist in the repository or in CI.
- **Staged npm releases.** CI can only *stage* an npm release. It becomes public after a maintainer approves it with npm 2FA, so even a compromised GitHub account or workflow can't publish to npm on its own.
- **Verifiable artifacts.** PyPI releases carry signed attestations and npm releases carry provenance, linking each artifact to the exact commit and workflow that built it.
- **Pinned CI.** Every GitHub Action is pinned to a full commit SHA; Dependabot proposes updates.
- **Nothing hostile ships.** Tests and fixtures are excluded from every published package, and offensive test samples live in a separate private repository.
- **Misspellings are reserved.** Likely typos of the package name are held by inert stub packages that fail with a pointer to the real one.

## Reporting a vulnerability

Please report privately, not in a public issue:

- GitHub: use "Report a vulnerability" on the repository's Security tab, or
- email security@lazaret.dev.
