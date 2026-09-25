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
├── scripts/            check-versions.sh, make_bundle.py, make_typosquat_stubs.py
├── python/             the PyPI package   (sections 3–4)
└── js/                 the npm package    (section 5)
```

`scripts/check-versions.sh` fails CI if the Python and npm versions, or a release tag, disagree, so the two packages release in lockstep. `scripts/make_bundle.py` builds a source bundle of the repository (for sharing the repo itself, not for installing). `scripts/make_typosquat_stubs.py` builds the defensive stub packages described in `docs/RELEASING.md`.

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
│   │   ├── core.py         rule engine, intra-file taint, the `lazaret` CLI
│   │   ├── flow.py         interprocedural / cross-file taint
│   │   ├── reports.py      safe report-path handling
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
├── architecture/          rules about the code: stdlib-only imports, layering
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
| `LAZARET_TEST_PG_DSN` | `tests/pg/test_integration.py`, the live parts of `tests/registry/test_pg_backend.py` | a DSN for a user with `CREATEDB` (the registry tests create a scratch database). `test_pg_backend.py` also honors the older `LAZARET_PG_TEST_DSN`, and without either it boots a throwaway cluster if `initdb` is installed |
| `LAZARET_TEST_PG_MATRIX` | `tests/pg/test_auth_matrix.py` | `"<host> <port> <ca.crt path> <unix socket dir>"` for a server configured as in that file's docstring |
| `LAZARET_SAMPLES_DIR` | `tests/scanner/test_detection_corpus.py` | path to a checkout of `lazaret-samples` |
| `LAZARET_BENCHMARK` | `tests/registry/test_benchmark.py` | any value; scans 21 real, legitimate npm and PyPI packages over the network and checks none is SUSPICIOUS and each matches its expected verdict |

Tests that depend on file permissions skip themselves when run as root, since root ignores directory permissions.

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

The npm package `lazaret` is zero-dependency and ES-module, tested with Node's built-in `node --test` (Node 22+).

```
js/
├── package.json         "files": bin/, src/, README.md, LICENSE (tests never ship)
├── bin/lazaret.js       executable shim only
├── src/
│   ├── cli.js           CLI logic; returns an exit code rather than calling process.exit
│   └── index.js         public exports
└── test/
    └── cli.test.js
```

As the npm scanner grows, it goes in `src/scanner/`, with any zero-dependency helpers in `src/lib/` (never importing the scanner), and `test/` mirrors `src/`. Tests needing a service or the samples checkout are gated with an in-test guard and named with a suffix so they're recognizable:

```js
// test/scanner/detection.corpus.test.js
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
├── manifest.json      one entry per sample: id, path, sha256, lang, category, source, expect
├── synthetic/         samples you authored, by attack class
│   ├── typosquat/
│   ├── install-hook/
│   └── obfuscation/
└── real/              curated from public corpora, never generated here
    └── <osv-id>/      keyed to the OSV "MAL-" report it came from
```

The manifest is JSON rather than TOML because reading TOML on Python 3.10 would need a third-party parser. Each entry names the rule IDs the scanner must report (`expect`), and `tests/scanner/test_detection_corpus.py` checks every sample's SHA-256 before scanning it. Samples are defanged (the payload neutralized, the detectable pattern kept) and stored non-executable, for example as `.txt`. Real malware is handled only inside a disposable VM and never installed; source it from public collections such as the OpenSSF malicious-packages repository or Datadog's malicious-software-packages dataset.

---

## 7. Build

`python/pyproject.toml` declares no build requirements and points at `python/_build/lazaret_build.py`, a PEP 517/660 backend written with `zipfile`, `tarfile`, and `hashlib`. pip uses it for `pip install .` and `pip install -e .`, which therefore work with no network index; release CI runs it directly:

```sh
cd python && python _build/lazaret_build.py dist     # writes the wheel and the sdist
```

Package metadata and the console scripts are defined in that module rather than in a `[project]` table: a backend must honor `[project]` if one exists, and reading TOML on Python 3.10 would need a third-party parser. The version's single source is `__version__` in `src/lazaret/__init__.py`.

Builds are reproducible: file order, timestamps, and permissions are fixed, and release CI stamps artifacts with the tagged commit's time (`SOURCE_DATE_EPOCH`), so rebuilding a tag gives byte-identical files. `tests/build/test_build_backend.py` checks this, along with the archive contents, the RECORD hashes, the absence of dependencies, and that the installed wheel runs.

---

## 8. What ships to the registries

**PyPI wheel:** only `src/lazaret/` (including `schema.sql` and the dashboard HTML) plus metadata. No tests, no fixtures, no build backend.

**PyPI sdist:** `pyproject.toml`, `_build/`, `src/`, `README.md`, `LICENSE`, `PKG-INFO`. Enough to rebuild the wheel, and no tests. Many projects include tests in the sdist so Linux distributions can run them; Lazaret deliberately doesn't, because its fixtures include entity-bomb documents and lookalike-package files that other scanners may flag on a PyPI release. Distribution packagers can use the tagged GitHub release archive, which has everything.

**npm:** `package.json` `"files"` restricts the tarball to `bin/`, `src/`, `README.md`, and `LICENSE`.

Nothing from `lazaret-samples` ever enters any artifact. `.env` files are refused by `scripts/make_bundle.py` and never reach a package.

---

## 9. CI

`.github/workflows/ci.yml`, with every action pinned to a commit SHA:

- **versions**: Python and npm versions (and any release tag) agree.
- **python-unit**: the whole suite on Linux, macOS, and Windows × Python 3.10–3.14. Gated tests skip. The OS matrix matters more than usual: Python bundles different Expat versions on macOS and Windows (which `safexml` depends on), and `pg` has platform-specific paths (Unix sockets, the pgpass permission check, the Windows `APPDATA` location).
- **python-integration**: the live-Postgres tests against a throwaway `postgres:17` service container.
- **js**: `npm test` on Linux, macOS, and Windows × Node 22 and 24.

Nothing is installed in any job. `.github/workflows/release.yml` reruns CI on a `v*` tag, builds with the stdlib backend, and publishes each package after approval on its `pypi` or `npm` environment. npm releases are staged: they go public only after a second approval, with 2FA, on npm itself.

The auth-matrix and samples-corpus tests don't run in CI yet: the first needs a Postgres container with a custom `pg_hba.conf` and TLS certificate, the second a deploy key for the private samples repository.

---
