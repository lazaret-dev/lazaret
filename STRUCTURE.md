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
├── action.yml          the repository as a GitHub Action (README.md, "In CI")
├── .github/            workflows (ci.yml, release.yml, wheels.yml) and dependabot.yml
├── docs/RELEASING.md   claiming names, trusted publishing, cutting a release
├── docs/RUST_ENGINE.md the native engine: design, recorded outputs, building
├── examples/           lazaret-taint.example.json, mcp-config.json
├── .gitattributes      LF line endings everywhere (reproducible builds on Windows too)
├── scripts/            check-versions.sh, tag-release.sh, make_bundle.py,
│                       make_typosquat_stubs.py, dashboard_csp.py,
│                       make_codec_tables.py, make_unicode_tables.py,
│                       make_rust_tables.py, check_rust_deps.py,
│                       update-popular-names.py,
│                       check_native_library.py, simulate-platforms.sh,
│                       snapshot.py, bench.py, popular/popular.py,
│                       make_pre_commit_mirror.py
├── python/             the PyPI package   (sections 3–4)
├── js/                 the npm package    (section 5)
└── rust/               the native engine  (Cargo workspace, no external crates; NOTICE, LICENSE-PYTHON, LICENSE-UNICODE)
```

`scripts/check-versions.sh [REF [TAG]]` fails if the Python and npm versions, the native engine's (`rust/Cargo.toml`'s workspace version and its two `rust/Cargo.lock` entries), or a release tag disagree, so the packages and the engine release in lockstep. Given a ref it reads the version files from that commit (`git show`), so it checks what a tag actually points at; with no ref it reads the working tree and refuses uncommitted changes to any version file. `scripts/tag-release.sh vX.Y.Z` is the only way to cut a tag: it refuses a dirty tree or a commit that isn't on `main`, runs the version check against the tag-to-be, creates an annotated tag, and prints the one-tag push command (see `docs/RELEASING.md`). `scripts/make_bundle.py` builds a source bundle of the repository (for sharing the repo itself, not for installing): only git-tracked files when `.git` exists, never credential files (`.env*`, `.npmrc`, `.pypirc`, `.netrc`, keys, …) or OS junk (`._*`, `.DS_Store`), and byte-for-byte reproducible. Use it (or `git archive`) rather than a plain `tar` of a working tree. `scripts/make_typosquat_stubs.py` builds the defensive stub packages described in `docs/RELEASING.md`; `--check` reports which stub names are still unclaimed. `scripts/dashboard_csp.py` recomputes the dashboard's script hash in its content-security policy (run it after editing the page's script). `scripts/make_codec_tables.py` writes `js/src/lib/codecs.js` (and the dashboard's copy) from Python's codecs, so both engines decode a coding cookie's codec the same way; `scripts/make_unicode_tables.py` writes the Unicode 13.0 table (`lazaret/scanner/_unicode13.py` and its JS twins) both engines read source text in, so results do not depend on the Python or Node version's Unicode. `scripts/simulate-platforms.sh` runs the Python suite the ways Windows, macOS and a non-root CI runner would see it (section 4, "Cross-platform rules"). `scripts/make_rust_tables.py` keeps the native engine's rule pack (`rust/crates/lazaret-engine/rules/lazaret-rules.json`, the source of the engine's patterns, sets, limits and finding texts) in its canonical form and, on Python 3.10, writes its Unicode 13.0 table; `--check` fails when the pack leaves its canonical form, a pattern stops compiling, its rule set is not the registry's, a value core still keeps differs from it, or the table no longer matches. `scripts/snapshot.py` records the engine's outputs on a test's input set and shows the cases that differ between two recordings (`docs/RUST_ENGINE.md` §5). `scripts/bench.py` runs registry scans of a labelled set of release files and compares two runs (in counts only, for a holdout set; `docs/TESTING.md` §4). `scripts/check_rust_deps.py` fails when `rust/Cargo.lock` or a crate's manifest names anything outside the workspace. `scripts/check_native_library.py LIB TAG [--load]` checks a built native library against the platform tag of the wheel it will ship in (ELF, Mach-O and PE headers read with the standard library: the glibc symbol versions a manylinux tag allows, the minimum macOS, no Visual C++ runtime, the exports), and `--dist DIR` checks a release's sdist and wheels against each other; `wheels.yml` runs both. `scripts/update-popular-names.py` rebuilds the registry's list of popular package names (`lazaret/registry/popular_names.json`) from its two public sources. `scripts/popular/popular.py` pins the popular releases the release gate scans as its second benign set (`scripts/popular/releases.jsonl`, by version and sha256), fetches them into a cache and writes a manifest for `scripts/bench.py` (`docs/TESTING.md`). `scripts/make_pre_commit_mirror.py X.Y.Z DIR` writes the pre-commit mirror of a release (`.pre-commit-hooks.yaml` running `lazaret hook`, and a package that pins `lazaret==X.Y.Z`), which pre-commit installs because Lazaret's own repository can't be a Python hook (`docs/RELEASING.md`).

`rust/` holds the native engine (`docs/RUST_ENGINE.md`): `crates/lazaret-engine` (no `unsafe`, no I/O, no dependencies: a port of CPython's regex engine, JSON, the supply-chain tests, the dependency-mode scan of a file, the rules part of the project-mode scan, the cross-file follower) and `crates/lazaret-ffi` (the C ABI, loaded by `lazaret/scanner/_native.py` with ctypes). `cargo build --release --offline --locked` needs no registry. The engine's translations of CPython code (the regex engine, shlex, the Final_Sigma rule) are under CPython's license as well as Apache-2.0: `rust/NOTICE` lists them with their original notices and a summary of the changes, and `rust/LICENSE-PYTHON` is CPython's LICENSE, unchanged (`docs/RUST_ENGINE.md`, section 11).

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
│   ├── __main__.py         python -m lazaret  →  lazaret._cli
│   ├── _cli.py             the `lazaret` command: `lazaret guard …` goes to the
│   │                       install guard, `lazaret hook …` to the commit-time
│   │                       gate, everything else to the scanner CLI
│   ├── scanner/
│   │   ├── core.py         rule engine, intra-file taint, scan_project() (the one
│   │   │                   project-scan pipeline, shared by the CLI and MCP), the
│   │   │                   `lazaret` CLI
│   │   ├── flow.py         interprocedural / cross-file taint (the engine's
│   │   │                   passes for Python and JavaScript: their findings)
│   │   ├── engine.py       the native engine's calls: the supply-chain tests,
│   │   │                   the scan of a file and the cross-file follower, in
│   │   │                   batches on threads; an unanswered file SC-TRUNCATED
│   │   ├── _native.py      the native engine's ctypes loader
│   │   ├── hook.py         the commit-time gate (`lazaret hook`): the files being
│   │   │                   committed, from git's index, through scan_project();
│   │   │                   fails on --ci's security and supply-chain conditions
│   │   ├── taintspec.py    taint-config validation (shared by both taint engines)
│   │   ├── reports.py      safe report paths, report provenance, baseline signing
│   │   ├── sca.py          dependency CVE matching (`lazaret-sca`)
│   │   └── sca_feeds.py    `lazaret-sca --update-bundle`: the CVE bundle from OSV,
│   │                       CISA KEV and EPSS
│   ├── registry/
│   │   ├── repo.py         npm / PyPI package auditing (`lazaret-registry`)
│   │   ├── guard.py        the install guard (`lazaret guard`, `lazaret-guard`):
│   │   │                   checks what npm / pnpm / yarn / Bun / pip / uv would install
│   │   ├── pmsettings.py   the package managers' registries, indexes and credentials
│   │   └── schema.sql      PostgreSQL setup for the state DB
│   ├── mcp/server.py       MCP server (`lazaret-mcp`)
│   ├── web/lazaret.html    browser dashboard (package data)
│   ├── pg/                 PostgreSQL wire-protocol client
│   └── safexml/            safe XML parsing
└── tests/                  (section 4)
```

Every CLI works both as an installed command and as a module: `lazaret` / `python -m lazaret`, `lazaret-registry` / `python -m lazaret.registry`, `lazaret-mcp` / `python -m lazaret.mcp`, `lazaret-sca` / `python -m lazaret.scanner.sca`, `lazaret-guard` / `python -m lazaret.registry.guard` (or `lazaret guard`), and `lazaret hook` / `python -m lazaret hook`.

### Layering

Dependencies only point inward:

```
mcp  →  registry  →  scanner  →  pg, safexml
```

`lazaret/_cli.py` and `__main__.py` sit above the layers: they hand the command line to the scanner (the project scan or the commit-time gate), or to the install guard in the registry, importing only the one they call.

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
│                          the engine's recorded outputs (snapshots/), and the
│                          npm package's parity with the Python package
├── build/                 the build backend and the typosquat stubs
├── scanner/               the engine, taint, reports, SCA, dashboard, bundle hygiene,
│                          and the samples-corpus test
├── registry/              registry crash guards, Postgres state backend, the install
│                          guard (the real npm, pnpm, yarn, Bun, pip and uv against fake
│                          registries on 127.0.0.1, _guard_support.py; skipped where a
│                          tool is missing)
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
| `LAZARET_TEST_FEEDS` | `LiveFeedsTests` in `tests/scanner/test_sca_feeds.py` | any value; downloads the real OSV, CISA KEV and EPSS feeds and checks the bundle built from them (the rest of that file reads local copies, as a mirror would) |
| `LAZARET_TEST_YARN_BERRY` | the yarn 2+ tests of `tests/registry/test_guard_yarn_bun.py` | the path of yarn 2+'s standalone `yarn.js` (`bin/yarn.js` of the `@yarnpkg/cli-dist` package); the guard's tests of npm, pnpm, yarn 1, Bun and uv run with whichever of those is on PATH, and skip the others |

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

### Cross-platform rules

**Don't depend on the host's defaults.** Code and tests must behave the same on Linux, macOS and Windows, on every supported Python (and Node) version. Never rely on a platform or interpreter default for correctness; make it explicit.

1. **Encoding.** Never assume stdio or file I/O is UTF-8.
   - Every CLI (the four console scripts and every `scripts/*.py` with a `main()`) configures stdout/stderr at startup: redirected output is written as UTF-8 on every platform (Windows' ANSI code page and a bare C locale would otherwise break on `✓`), unless `PYTHONIOENCODING` says otherwise; nothing raises on a character a stream can't encode (`errors="replace"`).
   - Protocols defined as UTF-8 set it explicitly: the MCP server reconfigures stdin/stdout to UTF-8.
   - Text I/O names its encoding: `open(..., encoding="utf-8")` (plus `newline="\n"` when writing files whose bytes matter), `Path.read_text/write_text(encoding=...)`.
   - Tests decode subprocess output explicitly: `encoding="utf-8", errors="replace"`, never a bare `text=True`.
   - File names shown in output are the name's bytes read as UTF-8 (non-UTF-8 bytes as `\xNN` escapes), never whatever the host locale makes of them.
2. **Paths.**
   - Compare resolved paths (`os.path.realpath` on both sides): temp dirs may be symlinks (macOS `/var` → `/private/var`).
   - Build paths with `os.path`/`pathlib`; never hard-code `/tmp/...` or treat `/` as the root; use `tempfile`. Compare relative paths separator-independently.
   - Expect Windows-specific forms (`\\?\` prefixes, drive letters, another drive than the repo's for the temp dir, 8.3 short names like `RUNNER~1`). `os.readlink` returns an absolute target as `\\?\C:\...` where Node gives `C:\...`; both engines show `C:\...` (`core.link_target_text`, the same undoing as libuv).
   - Sort path *strings* (`key=lambda p: p.as_posix()`), not `Path` objects: Windows compares `Path`s case-insensitively, so `ElementTree.py` sorts after `__init__.py` there and before it everywhere else.
   - Paths can be longer than one OS allows: macOS caps a path at 1024 bytes (`ENAMETOOLONG`), so a test that needs a very deep tree skips there (rule 5).
   - A `file:` URI keeps the drive as-is (`file:///C:/...`) and turns a UNC share into the host (`file://server/share/...`), as `pathlib`'s `as_uri()` does; the npm engine's SARIF writer does the same. Compare URIs by the path they name (`fileURLToPath`), not by text: Node's `pathToFileURL` writes `~` as `%7E` on Windows.
3. **Resources.** Close every file, archive, socket and DB connection before deleting what contains it (`with`, or close in `finally`/`addCleanup`). Windows can't delete an open file. `registry.Store` is a context manager; the MCP tools and the registry CLI close theirs on every path (`tests/registry/test_review_store_close.py`).
   - Sockets: on Windows a connection reset discards data that arrived but was not read yet, so a server's last message (PostgreSQL's FATAL before it disconnects) must be read before the next send fails. The pg driver drains whatever is readable before each send.
4. **Line endings.** Treat `\r\n` as a line ending, not as data, when checking output (Windows' text-mode stdout writes `\r\n`). `.gitattributes` keeps checkouts LF.
5. **OS capabilities.** A test that needs something a platform lacks (FIFOs, symlinks without privilege, control characters or non-UTF-8 bytes in file names, chmod-restricted dirs, a non-root user, paths longer than 1024 bytes) skips with an explicit reason (`_support.require_fs_names()` for non-ASCII names). It never fails and never silently passes. OS APIs can also disagree with each other: on the Windows runners Node's `lstat` reported a file symlink as a regular file, so the npm walker also trusts the directory listing's entry type (every reparse point), as the Python walker trusts `st_file_attributes`. Windows also caps a command line at 32,767 characters (WinError 206): large input to a child process goes through stdin or a file.
6. **Interpreter drift.** Correctness must not depend on version-specific behavior (recursion/parser limits, error-message wording, `os.path` semantics). Enforce our own limits explicitly; assert on types and codes, not on the interpreter's message text. JSON is the standing example: `json.loads` runs out of recursion near 995 levels on 3.10/3.11, near 10,000 on 3.12/3.13 and, on 3.14, only when the C stack does (a different depth per OS). So every JSON document a hostile input could shape is depth-checked before it is parsed: manifests by `load_manifest` (SC-MANIFEST-DEPTH), taint configs, baselines, CVE bundles, lockfiles, stored scan results and registry responses by `core.json_loads_bounded()`, which refuses anything deeper than 500 levels with `JsonTooDeep` (a `ValueError`); the MCP server bounds frames at 512, and the pg driver returns JSON deeper than `JSON_MAX_DEPTH` (500) as text.
7. **Time.** Tests wait on events or on `time.monotonic()` deadlines, never on a count of sleeps: `sleep(0.01)` takes far longer than 10 ms on a loaded macOS or Windows runner. Timeouts are generous upper bounds, not expectations.

`tests/architecture/test_portability.py` enforces what a machine can check: text I/O and subprocess decoding name an encoding, nothing asks the host for its encoding, every CLI configures stdio, the MCP server sets UTF-8, no hard-coded `/tmp`/`/var` paths, no `sorted()` of `glob`/`rglob`/`iterdir` results without a `key=`.

**Verification:** work isn't done until the full OS × Python-version matrix passes in CI. Before pushing, simulate what you can on Linux or macOS with `sh scripts/simulate-platforms.sh`: for every installed `python3.X` it runs the suite under a non-UTF-8 locale (Latin-1 if installed — `localedef -i en_US -f ISO-8859-1 en_US.ISO-8859-1` — else ASCII, standing in for Windows' code page), with `TMPDIR` behind a symlink (macOS), and, when run as root, as an unprivileged user (CI runners aren't root). A run that prints a `ResourceWarning` (something left open, rule 3) counts as failed.

---

## 5. JavaScript package

The npm package `lazaret` is a zero-dependency, ES-module project scanner with the same rules and results as `lazaret.scanner`, tested with Node's built-in `node --test` (Node 22+). Since 0.1.8 its rules run in the native engine (`rust/`) compiled to WebAssembly: `native/lazaret.wasm`, built by `npm run build` (`scripts/build-wasm.js`; it needs Rust and its `wasm32-unknown-unknown` target) and loaded by `src/lib/native.js` — the supply-chain tests, `scan_file` in dependency mode, the rules part of project mode, the cross-file follower and the cross-file taint passes for JavaScript and Python (see `docs/RUST_ENGINE.md`). A scan with a megabyte or more to read besides its largest file runs on worker threads (`src/pool.js`, `LAZARET_THREADS`), each with its own instance of the engine; the report is the same. JavaScript keeps the orchestration and what the native engine does not answer yet: the taint-flow and SQL-sink analyzers, the function metrics, the manifest, workflow and settings checks, config-file credentials, encoding handling and the reports. Registry auditing, custom taint specs and SCA are Python-only; the cross-file taint passes, for JavaScript and for Python, are the native engine's in both packages (`src/scanner/flow.js` builds the findings, compared by `python/tests/architecture/test_js_parity_flow.py`). The browser dashboard (`python/src/lazaret/web/lazaret.html`) carries its own single-file port of the project scanner in JavaScript (no dependency mode or supply-chain tests), held to the Python engine by `test_review_dashboard_parity.py`, until it can load the same module.

```
js/
├── package.json          "files": bin/, src/, native/lazaret.wasm, native/NOTICE,
│                         README.md, LICENSE, LICENSE-PYTHON, LICENSE-UNICODE,
│                         NOTICE (tests never ship)
├── bin/lazaret.js        executable shim only
├── native/               built, not committed: lazaret.wasm (the native engine)
│                         and its NOTICE (rust/NOTICE)
├── scripts/build-wasm.js `npm run build`: native/ from ../rust
├── src/
│   ├── cli.js            `lazaret check <dir>`; returns an exit code (testable)
│   ├── index.js          public exports
│   ├── report.js         report format (JSON + HTML), terminal output
│   ├── deps.js           --deps: a dependency's install hooks followed to the
│   │                     files they run; the import-time test on its code
│   ├── pool.js           worker threads for the per-file work (pool-worker.js:
│   │                     a worker, its own instance of the engine)
│   ├── scanner/          the scan loop (the native engine's rules, then the
│   │                     passes it hands to), taint, SQL sinks, functions,
│   │                     metrics, cross-file flows in Python and JavaScript
│   │                     (flow.js: the engine's passes)
│   └── lib/              leaf helpers: native (the WebAssembly engine: its
│                         loader, one call, the rule pack's values), fs
│                         (collection, report paths), encoding and codecs
│                         (BOM/UTF-16/PEP 263), binary (magic bytes), lexer
│                         (the comment layout, the engine's lexers'), redact,
│                         issue, supplychain
│                         (install hooks), autorun and ghworkflow (editor and
│                         agent settings that run commands; the workflows
│                         the worms planted), pyjson/pycompat/pynames
│                         (Python-compatible JSON, literals and text); never
│                         import src/scanner/
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

**The two packages must agree.** `python/tests/architecture/test_js_parity.py` runs both CLIs on every fixture tree, on a synthetic project covering the false-positive fixes, and on an adversarial tree generated at test time (BOM, UTF-16 and UTF-7 files, a NUL near the top of a UTF-8 file, `.github/`, `node_modules/` with and without `--deps`, suppression tricks, a 600-issue file, CRLF, Unicode identifiers, bidi characters, `.pyc` files, symlinks, a deep manifest, a large non-source file). It compares every finding as a multiset of (rule, file, line, severity, message), plus metrics, ratings, the gate and the exit code, and fails on any difference other than a listed Python-only feature (none since the Rust-first refactor's phase 3: until then the Python half of the cross-file taint engine, its `X-*` flows and `Q-FLOW-*` notes on Python files, ran only in the Python package). The cross-file received-code follower runs in both packages since 0.1.8 (the native engine's). `python/tests/scanner/test_review_dashboard_parity.py` holds the dashboard to the same standard. These modules need the WebAssembly build (`npm run build`) and skip without it (`NPM_READY`), so CI's `js` job builds it and names each of them. What the native engine answers is held to its recorded outputs (`test_snapshot_*`, `snapshots/`) and its WebAssembly build to the library (`test_wasm_parity*`; `docs/RUST_ENGINE.md` §5). When a rule changes, it changes in the native engine (`rust/`: its code, or the rule pack `rules/lazaret-rules.json`) with its tests and its reviewed difference in the recorded outputs, and in a JavaScript twin where the npm package still has one; the JS twins of Python helpers say so in a comment (`Twin of lazaret.scanner.core....`).

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
cd python && python _build/lazaret_build.py dist     # writes the sdist and a wheel for this machine (cargo)
```

Package metadata and the console scripts are defined in that module rather than in a `[project]` table: a backend must honor `[project]` if one exists, and reading TOML on Python 3.10 would need a third-party parser. The version's single source is `__version__` in `src/lazaret/__init__.py`.

The backend packs from an allowlist (`*.py`, `*.sql`, `*.html`, `*.json`, `py.typed` under `src/lazaret/`; for the sdist, the engine's sources under `rust/`: the workspace's `Cargo.toml` and `Cargo.lock`, each crate's `Cargo.toml`, `src/**/*.rs` and `rules/*.json`, and the notices) and stops with a list of offenders if anything else is there — a stray `.env`, `._*`, `.DS_Store`, `*.orig` or editor swap file can't reach a wheel or sdist built from a working tree. Metadata is version 2.4 with `License-Expression: Apache-2.0 AND Python-2.0.1 AND Unicode-3.0` and its `License-File`s (PEP 639).

**Every wheel is a platform wheel**: since the Rust-first refactor the native engine is the package's only engine, so there is no pure `py3-none-any` wheel. `python _build/lazaret_build.py dist --platform <tag>=<library>` (repeatable; release CI passes all five) writes, next to the sdist, `lazaret-<version>-py3-none-<tag>.whl` with the library at `lazaret/_native/` (`liblazaret_native.so`, `.dylib`, or `lazaret_native.dll`), where `_native.py` loads it. For the PEP 517 hook, `LAZARET_NATIVE_LIBRARY` and `LAZARET_WHEEL_PLATFORM` do the same; without them (`pip install` from the sdist or a checkout, or the command without `--platform`) the backend compiles the library with cargo (`--release --offline --locked`), checks that it loads in this Python and is this release's, and tags the wheel for this machine — so building from source needs Rust. `pip install -e .` compiles it the same way and puts it in `src/lazaret/_native/`, which is never packed from the tree. Every wheel carries `rust/LICENSE-PYTHON` and `rust/NOTICE` as license files beside `LICENSE` and `LICENSE-UNICODE` and declares `License-Expression: Apache-2.0 AND Python-2.0.1 AND Unicode-3.0`, since part of the engine is a translation of CPython code (and the Unicode 13.0 table is Unicode data); the sdist carries the same files at its root and declares the same. A malformed tag, a library that is not a regular file, a missing notice, or one of the two variables without the other stops the build before anything is written. The sdist never carries a library. A Linux library is built in the manylinux image of its tag, so it needs no newer glibc than the tag promises.

Builds are reproducible: file order, timestamps, permissions and the zip "created on" system are fixed, `.gitattributes` keeps line endings LF on every checkout, and release CI stamps artifacts with the tagged commit's time (`SOURCE_DATE_EPOCH`), so rebuilding a tag gives byte-identical files on any OS. `tests/build/test_build_backend.py` checks this, along with the archive contents, the RECORD hashes, the absence of dependencies, and that the installed wheel runs.

---

## 8. What ships to the registries

**PyPI wheels:** only `src/lazaret/` (including `schema.sql` and the dashboard HTML), the native engine's library (`lazaret/_native/<library>`) and metadata, with the license files (`LICENSE`, `LICENSE-UNICODE`, `LICENSE-PYTHON`, `NOTICE`). No tests, no fixtures, no build backend, nothing else from `rust/`. A release has five platform wheels (Linux x86-64 and ARM64 as manylinux_2_28, macOS arm64 and x86-64, Windows x64) and no pure wheel.

**PyPI sdist:** `pyproject.toml`, `_build/`, `src/`, `README.md`, `LICENSE`, `LICENSE-UNICODE`, `LICENSE-PYTHON`, `NOTICE`, `PKG-INFO`, and the engine's sources under `rust/` (no examples, no `target/`). Enough to build a wheel on any platform with Rust, and no tests. Many projects include tests in the sdist so Linux distributions can run them; Lazaret deliberately doesn't, because its fixtures include entity-bomb documents and lookalike-package files that other scanners may flag on a PyPI release. Distribution packagers can use the tagged GitHub release archive, which has everything.

**npm:** `package.json` `"files"` restricts the tarball to `bin/`, `src/`, `README.md`, `LICENSE`, `LICENSE-PYTHON`, `LICENSE-UNICODE` and `NOTICE`, and excludes dotfiles and key files inside them (`!**/.*`, `!**/*.pem`, `!**/*.key`, `!**/id_rsa*`, `!**/id_ed25519*`).

Nothing from `lazaret-samples` ever enters any artifact. Credential files are refused by the build backend's allowlist, by npm's `files` negations, and by `scripts/make_bundle.py`.

---

## 9. CI

`.github/workflows/ci.yml`, with every action pinned to a commit SHA:

- **versions**: the Python, npm and native engine versions (and any release tag) agree.
- **python-unit**: the whole suite on Linux, macOS, and Windows × Python 3.10–3.14. Gated tests skip. The OS matrix matters more than usual: Python bundles different Expat versions on macOS and Windows (which `safexml` depends on), and `pg` has platform-specific paths (Unix sockets, the pgpass permission check, the Windows `APPDATA` location).
- **python-integration**: the live-Postgres tests against a throwaway `postgres:17` service container, pinned by digest.
- **js**: `npm test` on Linux, macOS, and Windows × Node 22 and 24.
- **rust**: on Linux, macOS, and Windows: `check_rust_deps.py`, `make_rust_tables.py --check` (on Python 3.10, which the Unicode table is made with), `cargo test` and the release build (`--offline --locked`: no crate is fetched), and the WebAssembly build against the library.

Every job that runs Python tests builds the native library first and proves it loads (the engine's own tests skip without it): `python-unit` runs the whole suite on it, the engine's recorded outputs included.

`.github/workflows/wheels.yml` builds what a release publishes to PyPI, on pull requests and pushes to `main` that change what goes into a platform wheel, and when `release.yml` calls it: the native library for each of the five platforms, on its own platform with a pinned Rust (the Linux ones inside PyPA's manylinux_2_28 images, pinned by digest), checked against its wheel's tag, loaded, and the whole Python suite run on it there; the sdist and the five platform wheels from one checkout, checked against each other; each platform wheel installed with pip on its platform and run, and on Linux the sdist built by pip, compiling the engine (`docs/RUST_ENGINE.md`, section 4).

Nothing is installed in any job, apart from the pinned Rust toolchain for the release libraries and, in `wheels.yml`'s last job, Lazaret's own wheels and sdist from the files just built. The test matrix uses floating minor versions on purpose (`3.10`…`3.14`, Node `22`/`24`, to catch new patch releases); the release jobs pin exact versions (Python 3.12.14, Node 24.21.0 with its bundled npm 11.19.0). `.github/workflows/release.yml` runs on a `v*` tag: `verify-tag` checks that the tagged commit is on `main` and that the versions match the tag, then CI reruns, `build-python` (`wheels.yml`) and `build-npm` build the artifacts (the npm tarball is packed once and published as built), and each package is published after approval on its `pypi` or `npm` environment. Both publish jobs need both builds, so one registry never gets a release the other can't. npm releases are staged: they go public only after a second approval, with 2FA, on npm itself. Dependabot proposes action updates after a 7-day cooldown.

The auth-matrix and samples-corpus tests don't run in CI yet: the first needs a Postgres container with a custom `pg_hba.conf` and TLS certificate, the second a deploy key for the private samples repository.

---
