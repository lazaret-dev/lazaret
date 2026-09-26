# Lazaret: repositories, project structure, and testing

The single reference for how Lazaret is organized: the repositories, the Python package, the npm package, where tests and fixtures live, what ships to the registries, how it builds, and how CI runs. Release procedures are in `docs/RELEASING.md`.

The governing rule throughout: **no external dependencies**. Running, building, and testing Lazaret all work on a stock Python interpreter (and stock Node for the npm package) with nothing installed and no network access.

---

## 1. Repositories

| Repository | Visibility | Holds |
|---|---|---|
| `lazaret-dev/lazaret` (GitHub) | public | the scanner and both published packages; primary, home of release CI |
| `lazaret-dev/lazaret` (GitLab) | mirror | read-only copy; issues and merge requests disabled |
| `lazaret-dev/lazaret-samples` | **private** | offensive test samples; pulled in only for corpus tests, never published |

GitLab is kept in sync by pushing to both remotes from a developer machine (one `git push` with two push URLs on `origin`), so no repository token is stored in CI. Publishing to PyPI and npm uses trusted publishing (OIDC) from GitHub Actions, with no long-lived tokens anywhere.

---

## 2. The main repository

```
lazaret/
├── README.md           product documentation
├── STRUCTURE.md        this file
├── SECURITY.md         security policy and reporting
├── LICENSE             Apache-2.0
├── .github/            workflows (ci.yml, release.yml) and dependabot.yml
├── docs/RELEASING.md   claiming names, trusted publishing, cutting a release
├── examples/           lazaret-taint.example.json, mcp-config.json
├── .gitattributes      LF line endings everywhere (reproducible builds on Windows too)
├── scripts/            check-versions.sh, tag-release.sh, make_bundle.py,
│                       make_typosquat_stubs.py, dashboard_csp.py
├── python/             the PyPI package   (sections 3–4)
└── js/                 the npm package    (section 5)
```

`scripts/check-versions.sh [REF [TAG]]` fails if the Python and npm versions, or a release tag, disagree, so the two packages release in lockstep. Given a ref it reads both version files from that commit (`git show`), so it checks what a tag actually points at; with no ref it reads the working tree and refuses uncommitted changes to either version file. `scripts/tag-release.sh vX.Y.Z` is the only way to cut a tag: it refuses a dirty tree or a commit that isn't on `main`, runs the version check against the tag-to-be, creates an annotated tag, and prints the one-tag push command (see `docs/RELEASING.md`). `scripts/make_bundle.py` builds a source bundle of the repository (for sharing the repo itself, not for installing): only git-tracked files when `.git` exists, never credential files (`.env*`, `.npmrc`, `.pypirc`, `.netrc`, keys, …) or OS junk (`._*`, `.DS_Store`), and byte-for-byte reproducible. Use it (or `git archive`) rather than a plain `tar` of a working tree. `scripts/make_typosquat_stubs.py` builds the defensive stub packages described in `docs/RELEASING.md`; `--check` reports which stub names are still unclaimed. `scripts/dashboard_csp.py` recomputes the dashboard's script hash in its content-security policy (run it after editing the page's script).

---

## 3. Python package

One distribution, `lazaret`, with zero runtime dependencies. `pip install lazaret` installs exactly one package, which users can pin and audit in one place.

```
python/
├── pyproject.toml          [build-system] only: no requirements, in-tree backend
├── _build/lazaret_build.py the build backend (stdlib only; section 7)
├── README.md               PyPI long description
├── LICENSE
├── src/lazaret/
│   ├── __init__.py         __version__ (the single source of the version)
│   ├── __main__.py         python -m lazaret  →  the scanner CLI
│   ├── scanner/
│   │   ├── core.py         rule engine, intra-file taint, scan_project() (the one
│   │   │                   project-scan pipeline, shared by the CLI and MCP), the
│   │   │                   `lazaret` CLI
│   │   ├── flow.py         interprocedural / cross-file taint
│   │   ├── taintspec.py    taint-config validation (shared by both taint engines)
│   │   ├── reports.py      safe report paths, report provenance, baseline signing
│   │   └── sca.py          dependency CVE matching (`lazaret-sca`)
│   ├── registry/
│   │   ├── repo.py         npm / PyPI package auditing (`lazaret-registry`)
│   │   └── schema.sql      PostgreSQL setup for the state DB
│   ├── mcp/server.py       MCP server (`lazaret-mcp`)
│   ├── web/lazaret.html    browser dashboard (package data)
│   ├── pg/                 PostgreSQL wire-protocol client
│   └── safexml/            safe XML parsing
└── tests/                  (section 4)
```

Every CLI works both as an installed command and as a module: `lazaret` / `python -m lazaret`, `lazaret-registry` / `python -m lazaret.registry`, `lazaret-mcp` / `python -m lazaret.mcp`, `lazaret-sca` / `python -m lazaret.scanner.sca`.

### Layering

Dependencies only point inward:

```
mcp  →  registry  →  scanner  →  pg, safexml
```

`pg` and `safexml` are leaf libraries: they import nothing else from Lazaret and refer to themselves with relative imports, so either can later become its own distribution with a copy and a rename. Nothing imports upward: the scanner never imports the registry or the MCP server. `tests/architecture/test_layering.py` enforces this, including that every new subpackage is given a place in the layering.

Until 1.0, `lazaret.pg` and `lazaret.safexml` are provisional APIs and may change between releases.

If a library is ever split out, it gets its own top-level import name (for example `lazaret_safexml`) rather than sharing a `lazaret.*` namespace package, and the scanner vendors it rather than depending on it, so `pip install lazaret` still installs one package.

---

## 4. Python tests

Tests live in `python/tests/`, outside the package, and use plain `unittest`: the whole suite runs on a stock interpreter.

```
tests/
├── __init__.py            puts src/ on sys.path and PYTHONPATH (for subprocesses too)
├── _support.py            shared paths, requires_env(), load_script()
├── _bin/                  launchers equivalent to the installed console scripts,
│                          plus registry_bootstrap.py (the registry with a faked network)
├── fixtures/              inert fixture trees and demo scan inputs (section 6)
├── architecture/          rules about the code: stdlib-only imports, layering,
│                          and JS/Python engine parity
├── build/                 the build backend and the typosquat stubs
├── scanner/               the engine, taint, reports, SCA, dashboard, bundle hygiene,
│                          and the samples-corpus test
├── registry/              registry crash guards, Postgres state backend
├── mcp/                   MCP server hardening
├── pg/                    Postgres client: unit, hostile-server, live integration, auth matrix
└── safexml/               attacks, stdlib compatibility, limits, XML-RPC
    ├── payloads.py        attack documents shared by several test files
    └── _harness.py        every parsing API, and the canary HTTP server
```

Conventions:

- **Unit tests** are named after what they cover (`pg/_scram.py` → `tests/pg/test_scram.py`). Tests that cut across modules are named by concern: attacks, compatibility, hostile servers, crash guards.
- **Every test folder has an `__init__.py`**, so modules get unique dotted names (`tests.pg.test_types`). Test files never import from other test files; shared data goes in a plain module such as `safexml/payloads.py`.
- **Tests run against `src/`**, not an installed copy. `tests/__init__.py` arranges that for the test process and for every subprocess it starts. `tests/build/test_build_backend.py` separately installs the built wheel into an empty directory and runs the scanner from there, which is what proves the wheel itself works.
- **Subprocess tests** run the launchers in `tests/_bin/`, which call the same `main()` functions as the installed console scripts.

### Categories and gating

Unit, adversarial (hostile servers, attack documents, the no-fetch canary), compatibility, architecture, and build tests are self-contained: they start any servers they need on `127.0.0.1`, need no external network, and always run.

Tests that need a live service or the private samples are gated on an environment variable, and skip cleanly when it's unset:

```python
from tests import _support

@_support.requires_env("LAZARET_TEST_PG_DSN")
class IntegrationTests(unittest.TestCase):
    ...
```

| Variable | Enables | Value |
|---|---|---|
| `LAZARET_TEST_PG_DSN` | `tests/pg/test_integration.py`, `tests/pg/test_review_live.py`, the live parts of `tests/registry/test_pg_backend.py`, `test_review_store.py` and `test_review_store_reconnect.py` | a DSN for a user with `CREATEDB` (the registry tests create a scratch database). `test_pg_backend.py` also honors the older `LAZARET_PG_TEST_DSN`, and without either it boots a throwaway cluster if `initdb` is installed |
| `LAZARET_TEST_PG_MATRIX` | `tests/pg/test_auth_matrix.py`, the live TLS cases in `test_review_tls.py` and `test_review_libpq_params.py` | `"<host> <port> <ca.crt path> <unix socket dir>"` for a server configured as in that file's docstring (a few TLS tests also need the `openssl` command and skip without it) |
| `LAZARET_SAMPLES_DIR` | `tests/scanner/test_detection_corpus.py` | path to a checkout of `lazaret-samples` |
| `LAZARET_BENCHMARK` | `tests/registry/test_benchmark.py` | any value; scans 21 real, legitimate npm and PyPI packages over the network and checks none is SUSPICIOUS and each matches its expected verdict |

Tests that depend on file permissions skip themselves when run as root, since root ignores directory permissions (the npm suite re-runs them under `unshare -U` where available).

Regression tests for the September 2026 review are named `test_review_<topic>.py` (Python) and `review-<topic>.test.js` (npm); each was written from the finding's reproduction and fails on the code before the fix.

### Running

```sh
cd python
python -m unittest discover -s tests -t .            # everything; gated tests skip
python -m unittest discover -s tests/safexml -t .    # one component
python -m unittest tests.pg.test_scram               # one file

LAZARET_TEST_PG_DSN=postgresql://user:pw@localhost/lazaret_test \
  python -m unittest tests.pg.test_integration
LAZARET_SAMPLES_DIR=../../lazaret-samples \
  python -m unittest tests.scanner.test_detection_corpus
```

pytest also runs the suite unchanged, for anyone who prefers it, but nothing requires it.

---

## 5. JavaScript package

The npm package `lazaret` is a zero-dependency, ES-module port of the project scanner (the same rules, comment lexer, taint-flow and SQL-sink analyzers, encoding handling, and obfuscation/secret detection as `lazaret.scanner`), tested with Node's built-in `node --test` (Node 22+). Registry auditing, cross-file taint, custom taint specs and SCA are Python-only. The browser dashboard (`python/src/lazaret/web/lazaret.html`) carries a single-file port of this engine.

```
js/
├── package.json          "files": bin/, src/, README.md, LICENSE (tests never ship)
├── bin/lazaret.js        executable shim only
├── src/
│   ├── cli.js            `lazaret check <dir>`; returns an exit code (testable)
│   ├── index.js          public exports
│   ├── report.js         report format (JSON + HTML), terminal output
│   ├── scanner/          rules, scan loop, comment lexer, linear-time matchers,
│   │                     taint, SQL sinks, functions, metrics
│   └── lib/              leaf helpers: fs (collection, report paths), encoding
│                         and codecs (BOM/UTF-16/PEP 263), binary (magic
│                         bytes), redact, issue, supplychain (install hooks),
│                         pyjson/pycompat (Python-compatible JSON and text);
│                         never import src/scanner/
└── test/
    ├── cli.test.js            CLI commands, exit codes, report paths, suppression
    ├── report-format.test.js  the report contract (key order, gate math, redaction)
    ├── architecture.test.js   layering and ship policy
    ├── corpus.test.js         fixtures policy; samples corpus (gated)
    ├── review-*.test.js       regression tests for the review findings
    ├── fixtures/              inert .json/.txt/.md only (enforced)
    ├── lib/                   install-hook classification
    └── scanner/               detection rules, hex decoding, private-key material
```

**The two engines must agree.** `python/tests/architecture/test_js_parity.py` runs both CLIs on every fixture tree, on a synthetic project covering the false-positive fixes, and on an adversarial tree generated at test time (BOM, UTF-16 and UTF-7 files, a NUL near the top of a UTF-8 file, `.github/`, `node_modules/` with and without `--deps`, suppression tricks, a 600-issue file, CRLF, Unicode identifiers, bidi characters, `.pyc` files, symlinks, a deep manifest, a large non-source file). It compares every finding as a multiset of (rule, file, line, severity, message), plus metrics, ratings, the gate and the exit code, and fails on any difference other than the listed Python-only features. `python/tests/scanner/test_review_dashboard_parity.py` holds the dashboard to the same standard. When a rule changes in one engine, it changes in the other in the same commit; the JS twins of Python helpers say so in a comment (`Twin of lazaret.scanner.core....`).

Tests needing a service or the samples checkout are gated with an in-test guard that skips cleanly when the variable is unset:

```js
// test/corpus.test.js
const dir = process.env.LAZARET_SAMPLES_DIR;
test("flags the install-hook corpus", { skip: dir ? false : "LAZARET_SAMPLES_DIR not set" }, () => { /* ... */ });
```

---

## 6. Test samples

Two tiers, in two places.

### Inert fixtures: `python/tests/fixtures/`

Files that *look* malicious or vulnerable so the scanner has something to detect, but do nothing harmful: network references point at reserved addresses (`192.0.2.0/24`, `.invalid` hosts), credentials are dummies, and nothing is ever installed or executed. `tests/fixtures/README.md` states the policy. Because they're inert, they can live in the public repository, but they never ship in any package (section 8).

### Offensive samples: private `lazaret-samples` repository

Functional samples you author, plus curated real-world malware, live only in the private samples repository, because working samples trip GitHub's scanning, contributors' antivirus, and other registries' scanners, and a public repo would make Lazaret a distribution channel for them.

```
lazaret-samples/
├── README.md          what this is, handling rules, who has access
├── USAGE.md           research-only terms
├── manifest.json      one entry per sample: id, path, sha256, lang, category, source, defanged, expect
├── synthetic/         samples you authored, by attack class
│   ├── typosquat/
│   ├── install-hook/
│   └── obfuscation/
└── real/              curated from public corpora, never generated here
    └── <osv-id>/      keyed to the OSV "MAL-" report it came from
```

The manifest is JSON rather than TOML because neither Python 3.10 nor Node can read TOML without a third-party parser. Each entry names its category (`typosquat`, `install-hook`, `obfuscation`, `secrets`, `taint-sql`, `taint-command`, `exfiltration`), must declare `"defanged": true`, and lists the rule IDs the scanner must report (`expect`). Both engines check the same manifest: `python/tests/scanner/test_detection_corpus.py` and `js/test/corpus.test.js` verify every SHA-256, fail if any file under `synthetic/` or `real/` is unlisted, and require each sample to be flagged. Samples are defanged (the payload neutralized, the detectable pattern kept) and stored non-executable, for example as `.txt`. Real malware is handled only inside a disposable VM and never installed; source it from public collections such as the OpenSSF malicious-packages repository or Datadog's malicious-software-packages dataset.

---

## 7. Build

`python/pyproject.toml` declares no build requirements and points at `python/_build/lazaret_build.py`, a PEP 517/660 backend written with `zipfile`, `tarfile`, and `hashlib`. pip uses it for `pip install .` and `pip install -e .`, which therefore work with no network index; release CI runs it directly:

```sh
cd python && python _build/lazaret_build.py dist     # writes the wheel and the sdist
```

Package metadata and the console scripts are defined in that module rather than in a `[project]` table: a backend must honor `[project]` if one exists, and reading TOML on Python 3.10 would need a third-party parser. The version's single source is `__version__` in `src/lazaret/__init__.py`.

The backend packs from an allowlist (`*.py`, `*.sql`, `*.html`, `py.typed` under `src/lazaret/`) and stops with a list of offenders if anything else is there — a stray `.env`, `._*`, `.DS_Store`, `*.orig` or editor swap file can't reach a wheel or sdist built from a working tree. Metadata is version 2.4 with `License-Expression: Apache-2.0` and `License-File: LICENSE` (PEP 639).

Builds are reproducible: file order, timestamps, permissions and the zip "created on" system are fixed, `.gitattributes` keeps line endings LF on every checkout, and release CI stamps artifacts with the tagged commit's time (`SOURCE_DATE_EPOCH`), so rebuilding a tag gives byte-identical files on any OS. `tests/build/test_build_backend.py` checks this, along with the archive contents, the RECORD hashes, the absence of dependencies, and that the installed wheel runs.

---

## 8. What ships to the registries

**PyPI wheel:** only `src/lazaret/` (including `schema.sql` and the dashboard HTML) plus metadata. No tests, no fixtures, no build backend.

**PyPI sdist:** `pyproject.toml`, `_build/`, `src/`, `README.md`, `LICENSE`, `PKG-INFO`. Enough to rebuild the wheel, and no tests. Many projects include tests in the sdist so Linux distributions can run them; Lazaret deliberately doesn't, because its fixtures include entity-bomb documents and lookalike-package files that other scanners may flag on a PyPI release. Distribution packagers can use the tagged GitHub release archive, which has everything.

**npm:** `package.json` `"files"` restricts the tarball to `bin/`, `src/`, `README.md`, and `LICENSE`, and excludes dotfiles and key files inside them (`!**/.*`, `!**/*.pem`, `!**/*.key`, `!**/id_rsa*`, `!**/id_ed25519*`).

Nothing from `lazaret-samples` ever enters any artifact. Credential files are refused by the build backend's allowlist, by npm's `files` negations, and by `scripts/make_bundle.py`.

---

## 9. CI

`.github/workflows/ci.yml`, with every action pinned to a commit SHA:

- **versions**: Python and npm versions (and any release tag) agree.
- **python-unit**: the whole suite on Linux, macOS, and Windows × Python 3.10–3.14. Gated tests skip. The OS matrix matters more than usual: Python bundles different Expat versions on macOS and Windows (which `safexml` depends on), and `pg` has platform-specific paths (Unix sockets, the pgpass permission check, the Windows `APPDATA` location).
- **python-integration**: the live-Postgres tests against a throwaway `postgres:17` service container, pinned by digest.
- **js**: `npm test` on Linux, macOS, and Windows × Node 22 and 24.

Nothing is installed in any job. The test matrix uses floating minor versions on purpose (`3.10`…`3.14`, Node `22`/`24`, to catch new patch releases); the release jobs pin exact versions (Python 3.12.14, Node 24.21.0 with its bundled npm 11.19.0). `.github/workflows/release.yml` runs on a `v*` tag: `verify-tag` checks that the tagged commit is on `main` and that both versions match the tag, then CI reruns, `build-python` and `build-npm` build the artifacts (the npm tarball is packed once and published as built), and each package is published after approval on its `pypi` or `npm` environment. Both publish jobs need both builds, so one registry never gets a release the other can't. npm releases are staged: they go public only after a second approval, with 2FA, on npm itself. Dependabot proposes action updates after a 7-day cooldown.

The auth-matrix and samples-corpus tests don't run in CI yet: the first needs a Postgres container with a custom `pg_hba.conf` and TLS certificate, the second a deploy key for the private samples repository.

---
