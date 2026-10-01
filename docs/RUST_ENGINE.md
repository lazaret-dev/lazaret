# Lazaret's native scanning engine (Rust)

Status, October 1, 2026: phase 0 and the phase 1 functions are done, current
with the Python engine through 0.1.8's detection (its behaviour pass
included: hook commands read as programs, local data followed to a send,
string arrays and proxy objects in the decoded view), wired into the scanner
behind `--engine`, and built by release CI into platform wheels for five
platforms (§4). Phase 2 is done for dependency mode: `scan_file` of a
registry, guard or `--deps` scan (the supply-chain and credential rules) is
the native engine's whole, findings included; in project mode its rules part
(`scan_rules`) is the engine's, and the Python engine runs the passes that
follow it. Phase 3's cross-file follower is the engine's too (`cross_file`;
§8). Since 0.1.8 the npm package runs the same engine compiled to
WebAssembly (`native/lazaret.wasm`): the supply-chain tests, dependency-mode
`scan_file`, the rules part of project-mode `scan_file` and the cross-file
follower are the native engine's there, and the JavaScript twins of them are
retired. The Python engine (`python/src/lazaret/scanner/`) stays: it is the
reference every answer of the native engine is held to.

## 1. What it is

One native engine, written in Rust, used by both distributions as the
default where it is installed. The Python engine stays as the **reference
implementation**: readable, complete, selectable at run time
(`--engine python`), so anyone can audit a verdict by reproducing it in plain
Python. The two give identical answers, proven by differential tests. The
npm package runs the native engine as WebAssembly (0.1.8), so what it
answers there has no JavaScript twin any more: a detection change lands in
Python and Rust, not three times. What the npm package still does in
JavaScript (source decoding, the comment lexer and the suppression markers,
the manifest and workflow checks, the taint, SQL and function passes of
project mode, reporting) is held to the Python engine by the CLI-level
parity tests (`test_js_parity*`).

Decisions (fixed):

| Topic | Decision |
|---|---|
| Dependencies | **No external crates.** Own regex engine (a port of CPython's sre), JSON, Unicode tables. `Cargo.lock` lists only the workspace; `scripts/check_rust_deps.py` fails CI otherwise. |
| Bindings | **C ABI + ctypes** for Python (no compiled extension, one library per platform serves every Python version); **WebAssembly** for Node (Node's own `WebAssembly`, no imports, no npm dependency). |
| Rule source | **Extract now, flip later.** `scripts/make_rust_tables.py` extracts every module-level value of `core.py` (patterns, sets, limits, and the pattern pieces core composes at run time) into `rust/crates/lazaret-engine/rules/lazaret-rules.json`; `--check` guards drift. Later, `core.py` itself loads the pack. |
| Engine shape | Generic engine plus data: declarative rules come from the pack, the algorithms are named Rust functions, ported function for function. |
| Calls | Whole files, batched: one crossing of the boundary per batch of files, read on threads (`std::thread`), answers in input order. |
| License | Lazaret's code is Apache-2.0; the translations of CPython code (the regex engine, shlex, the Final_Sigma rule) are also under CPython's license, and the Unicode 13.0 tables are Unicode data, under the Unicode License v3, so the crates, the platform wheels and the npm package are `Apache-2.0 AND Python-2.0.1 AND Unicode-3.0` (§11). |

## 2. Using it

- `lazaret --engine rust|python …` and `lazaret-registry --engine …`, or
  `LAZARET_ENGINE`. The default is the native engine where it is installed,
  else Python. `--engine rust` fails (exit 2) when the library is missing,
  rather than scan slowly without saying so. `--version` names the engine:
  `lazaret 0.1.8 (engine: rust 0.1.8)`. The workspace version
  (`rust/Cargo.toml`) is the release the engine ships in.
- The library is `lazaret/_native/<library>` in a platform wheel (Linux
  x86-64 and ARM64 as manylinux_2_28, macOS arm64 from 11.0 and x86-64 from
  10.12, Windows x64), or the file `LAZARET_NATIVE_LIB` names (a development
  build). Other platforms get the pure wheel: the Python engine.
- `python/src/lazaret/scanner/engine.py` sends the supply-chain tests
  through it: the import-time test of every dependency file (`--deps`), of
  every file a registry scan reaches at import time and of the files it runs
  when used (SC-USE-RISK), the install-script test of hook targets and
  install scripts, and the scripts those start (`engine.spawned_scripts`,
  which reads the decoded view: an 11.7 MB obfuscated payload's takes about
  3 s here and 20 s in Python). And `scan_file` in dependency mode (`engine.scan_files`):
  every source file of a registry or guard scan (the archive's members as
  they stream by, a batch at a time: `_ArtifactScan.scan_pending`) and every
  dependency file of a `--deps` scan, each answered with core's issues —
  rule, texts, line, snippet clipped and redacted — in core's order. Files go
  in batches of 64 (`engine.BATCH`: a scan's deadline and `should_stop` are
  checked between batches), on up to 8 threads. **Any call the native engine
  can't answer** (its work budget spent on a hostile file, an error, a
  caught panic) **is answered by the Python engine**, so the native engine
  never loses a finding.
- `scan_file` in project mode (your own files) goes through it in two
  parts (`engine.scan_files`): its rules part — every pattern rule and
  family on every line, the file-level rules and `TEXT_RULES` — is the
  engine's `scan_rules`, in the same batches on the same threads, and core
  runs the passes that follow on the engine's findings (the SQL statements
  without WHERE, taint, the SQL-sink pass, the function metrics), the
  suppression markers and the cap (`core.scan_file_after_rules`). Core scans
  a file the engine doesn't answer.
- The cross-file follower (`engine.cross_file_issues`, for `--deps`,
  registry and guard scans) is one `cross_file` call per scan: the
  dependency files one after another in the text (`[path, lang, length]`
  each in the arguments; `groups`, the package a Python file of a `--deps`
  scan is read in when a distribution's RECORD joins top-level modules:
  `core._xf_site_groups`), each package on its own work budget, on up to 8
  threads, the findings in core's order. A package the engine reports as
  failed (its budget spent, an internal error) is read by core in its place
  (`core._xf_group_issues`), and a refused call by core whole.
- **The npm package** (0.1.8) loads `native/lazaret.wasm` with
  `js/src/lib/native.js` (`npm run build` makes it from `rust/`; the
  published package carries it). Everything the supply-chain tests answer —
  install scripts and the hooks they run, import-time code, received code,
  the decoded view, spawned scripts, persistence, the exfiltration shapes, a
  hook command read as a program — is the engine's, and so are the
  cross-file follower (`crossFileIssues`: each file encoded on its own, its
  length in code points) and `scan_file`: in dependency mode whole
  (`scan_file`, findings capped as core caps them), in project mode its
  rules part (`scan_rules`: every pattern rule and family on every line, the
  file-level rules and `TEXT_RULES`, uncapped and unsuppressed), to which
  the npm engine adds the SQL, taint and function passes, the suppression
  markers and the cap. Core's tables the JavaScript side still reads
  (limits, `RULES` for S-TOKEN) come from the pack too (`packValues`). There
  is no second engine to fall back on: a call that spends its work budget (a
  hostile input) leaves its file SC-TRUNCATED, CRITICAL and so never cleared
  ("reading it spent the engine's work budget" from `scan_file`; "its scan
  failed" from a dependency check), where the Python package would ask its
  Python engine; a package whose follower budget is spent gives no
  cross-file finding (core skips a package whose reading raises). Without
  the module (a checkout that has not run `npm run build`) the CLI scans
  nothing: it exits 2 and says what is missing.
- The npm CLI spreads a scan with a megabyte or more to read besides its
  largest file over worker threads (`js/src/pool.js`, one per core up to 8;
  `LAZARET_THREADS` sets how many, `1` none): each file's scan and `--deps`'
  checks of each dependency file, the follower included, each worker with
  its own instance of the module (compiled once, handed over) and the main
  thread's settings. `run()` stays synchronous (the main thread waits on a
  shared counter, `Atomics.wait`, and reads each worker's port), and the
  answers are taken in the order asked, so the report is the same with any
  number of threads.

## 3. Layout

```
rust/
  Cargo.toml                 workspace; release: lto, codegen-units=1, panic=unwind, strip;
                             wasm: release with panic=abort (the WebAssembly build)
  NOTICE, LICENSE-PYTHON     what is translated from CPython, its notices, CPython's license (§11)
  LICENSE-UNICODE            the Unicode License v3, for generated/unicode13.rs (§11)
  crates/lazaret-engine/     #![forbid(unsafe_code)], no dependencies, no I/O
    rules/lazaret-rules.json the rule pack (generated; embedded; `pack.install` can replace it)
    src/api.rs               the calls by name (JSON args + text -> JSON; `budget`); `batch` on
                             threads; `pack.values` (core's values, for the npm engine)
    src/budget.rs            per-call work budget -> Exhausted (Python: the Python engine
                             answers; npm: SC-TRUNCATED)
    src/pack.rs              the pack: values by core's names, patterns compiled on first use
    src/json.rs, pystr.rs    JSON; Python str semantics on code points ([u32])
    src/unicode.rs           Python 3.10 / Unicode 13.0 predicates (generated/unicode13.rs)
    src/pyre/                CPython's sre: parser, compiler, matcher (see §6)
    src/hooks.rs             shlex, _hook_tokens, follow_hook, node_candidates, node -e, #!
    src/signs.rs             install_script_risk, import_time_risk(+severity), decoded_view
                             (and string_array_line), spawned_scripts, and the detectors they
                             read (exfiltration shapes, wallet swaps, services at login,
                             self-read, persistence, publishing …)
    src/received.rs          the received-code detector (spec-driven), downloads/decodes and runs
    src/crossfile.rs         the cross-file follower (_cross_file_received_issues): what each
                             module defines, imports, exports, sets in the environment, emits
                             and listens for; one call per scan, a budget per package, threads
    src/textgate.rs          a text's character pairs and triples, read once per call: a search
                             whose strings need one the text lacks answers at once
    src/flow.rs              local data followed to where it is sent (local_data_sent_at), a
                             webhook's secret in the code (secret_endpoint_at)
    src/shell.rs             a shell text read as a program (_sh_parse … _sh_reasons), the command
                             lines a script hands a shell (exec_command_reasons)
    src/strarr.rs            javascript-obfuscator's string arrays and proxy objects, for the
                             decoded view
    src/lexer.rs             _lex_comment_spans (its literals matched by hand loops, §6)
    src/filectx.rs           a file as scan_file reads it (_FileCtx): lines, comment layout,
                             match text (NFKC, JS escapes), names
    src/scanfile.rs          scan_file in dependency mode, scan_rules (project mode's rules
                             part), family by family; per-line gates
    src/linear.rs            rule patterns sre runs in more than linear time on some lines,
                             matched by hand in linear time (SQL-DYNAMIC)
    src/findings.rs          mk_issue: texts, snippets, redaction (_SecretLiterals); cap_issues
    src/token.rs             _TokenPattern (S-TOKEN, redaction): JWTs in linear time
    src/normalize.rs         NFC / NFD / NFKC / NFKD (UAX #15, Unicode 13.0 data)
    examples/                profiling tools (profile_calls, profile_scanfile, pattern_times,
                             pattern_stats, show_need)
  crates/lazaret-ffi/        cdylib liblazaret_native: the only `unsafe` (the C ABI; the
                             WebAssembly exports)
  .cargo/config.toml         the WebAssembly build's stack (8 MiB, placed first)
python/src/lazaret/scanner/_native.py   ctypes loader and one call (NativeError, NativeExhausted)
js/src/lib/native.js                    the npm package's loader: WebAssembly, one call, the pack's
                                        values, a wrapper per call the npm engine makes
js/scripts/build-wasm.js                `npm run build`: native/lazaret.wasm and native/NOTICE
                                        (js/native/ is built, not committed)
js/src/pool.js, pool-worker.js          the npm CLI's worker threads, each with its own instance
python/src/lazaret/scanner/engine.py    the engine in use, batching, the Python fallback
python/_build/lazaret_build.py          LAZARET_NATIVE_LIBRARY + LAZARET_WHEEL_PLATFORM: a platform wheel
scripts/make_rust_tables.py             the pack (any Python) and unicode13.rs (3.10); --check
scripts/check_rust_deps.py              Cargo.lock and the manifests hold only the workspace
scripts/check_native_library.py         a built library against its wheel's tag; --dist: the release's wheels
.github/workflows/wheels.yml            the five libraries, the wheels, installed on each platform
python/tests/architecture/test_rust_parity_{regex,hooks,hooks_b,signs,scanfile,lexer,project,
  project_scan,crossfile,hook_commands,hexname,offscreen,lookalike}.py,
  test_wasm_parity{,_signs,_crossfile}.py, test_rust_deps.py, test_rust_pack.py, hooks_corpus.py,
  scanfile_corpus.py
```

FFI protocol: request `[u32 LE name len][name][u32 LE args len][args JSON][text]`
(the text is the rest: a Python str as UTF-8 with surrogates passed through);
answer: JSON in an engine-owned buffer, freed with `lazaret_engine_free`.
Status 0 ok, 1 error, 2 exhausted, 3 panic (caught). The WebAssembly build
(no imports) exports its `memory`, `lazaret_alloc(len)`, `lazaret_call(req,
len)` (it takes the request back) and `lazaret_free(ptr, len)`, with the same
request; the answer is `[u32 LE status][u32 LE length][JSON]`, released with
`lazaret_free(ptr, 8 + length)`. A JavaScript string goes in as WTF-8 (a
lone surrogate as its three bytes), so the engine reads it as Python reads
the same str. The module is built with `panic = "abort"`: a panic traps,
and `native.js` answers it as an error and starts a fresh instance (as it
does after a call that left the memory above 512 MB). Every call may carry
`"budget"` (steps; the default is about 4e9). `batch`:
`{"calls": [[name, args, text], …], "threads": n}` →
`[{"ok": v} | {"error": …, "exhausted"?, "panic"?}]` in input order. Threads
take the next item from an atomic counter; each item has its own budget and
`catch_unwind`; `batch` and `pack.*` are refused inside a batch; under
WebAssembly a batch runs on one thread.

## 4. Building, packaging, CI

```bash
cd rust && cargo build --release --offline --locked      # target/release/liblazaret_native.{so,dylib} / lazaret_native.dll
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
rustup target add wasm32-unknown-unknown                 # once
cd ../js && npm run build                                # native/lazaret.wasm (and native/NOTICE)
```

`npm run build` (`js/scripts/build-wasm.js`) runs `cargo build --profile
wasm --offline --locked --target wasm32-unknown-unknown -p lazaret-ffi`
(the release profile, aborting on a panic; an 8 MiB stack placed first in
memory, so running past it traps) and copies the module (about 2.1 MB) to
`js/native/lazaret.wasm` and `rust/NOTICE` to `js/native/NOTICE`. The npm
tests need it, so CI builds it before them.

A platform wheel: `python python/_build/lazaret_build.py dist/ --platform
<tag>=<built library>` (repeatable; it also writes the sdist and the pure
wheel), or `LAZARET_NATIVE_LIBRARY` and `LAZARET_WHEEL_PLATFORM` for the
PEP 517 hook, gives `lazaret-<v>-py3-none-<tag>.whl`: the pure wheel's files,
`lazaret/_native/<library>`, and `rust/LICENSE-PYTHON` and `rust/NOTICE` as
license files beside the pure wheel's `LICENSE` and `LICENSE-UNICODE`, with
`License-Expression: Apache-2.0 AND Python-2.0.1 AND Unicode-3.0` and
`Root-Is-Purelib: false`. The sdist never carries a library.

**Release builds** (`.github/workflows/wheels.yml`, called by `release.yml`
as `build-python`, and run on pull requests and pushes to main that change
`rust/`, the build backend, `_native.py`, `engine.py`,
`scripts/check_native_library.py` or the workflow):

| Tag | Built on | How |
|---|---|---|
| `manylinux_2_28_x86_64` | ubuntu-24.04 | in `quay.io/pypa/manylinux_2_28_x86_64`, pinned by digest |
| `manylinux_2_28_aarch64` | ubuntu-24.04-arm | in `quay.io/pypa/manylinux_2_28_aarch64`, pinned by digest |
| `macosx_11_0_arm64` | macos-15 | `MACOSX_DEPLOYMENT_TARGET=11.0` |
| `macosx_10_12_x86_64` | macos-15-intel | `MACOSX_DEPLOYMENT_TARGET=10.12` |
| `win_amd64` | windows-2025 | `-C target-feature=+crt-static` (no Visual C++ runtime needed) |

Every library is built with Rust `RUST_VERSION` (1.95.0, the compiler of
the parity runs in §5; the runner's rustup installs it and checks each
component's published SHA-256), `--release --offline --locked`. The Linux
jobs mount that toolchain read-only into the image, so the library links
against the image's glibc 2.28; building on the runner itself would need
its glibc (2.39). Each library is then checked against its tag
(`scripts/check_native_library.py LIB TAG --load`: machine, the glibc and
libgcc_s symbol versions and libraries manylinux allows, no RPATH or
executable stack; the Mach-O minimum macOS and system-only dylibs; a PE DLL
with ASLR and DEP and no Visual C++ or MinGW runtime; the three exports;
then loaded as `_native.py` loads it, reporting the package's version and
answering one call as the Python engine does), and the three parity
modules run against it on its platform (the Linux ones inside the image).
The `dist` job builds the sdist, the pure wheel and the five platform
wheels from one checkout (Python 3.12.14, `SOURCE_DATE_EPOCH`), and
`check_native_library.py --dist` holds each platform wheel to the pure
wheel's files plus its library and license files. The `install` job then
installs each platform wheel with pip, from those files only, on its
platform, and runs `python -m lazaret --version` (`lazaret X (engine: rust
X)`); on Linux x86-64 the pure wheel is installed too and runs the Python
engine. On Linux a build is reproducible: the same commit, toolchain and
image give the same library bytes wherever the checkout is (cargo passes
workspace paths relative). Given the same five libraries, the seven files
are too; the Windows linker, though, stamps a time into the DLL.

The npm package's module is built the same way in `release.yml`'s
`build-npm` job: Rust `RUST_VERSION` with its `wasm32-unknown-unknown`
target (rustup checks the published SHA-256 sums), `npm run build`, its
SHA-256 printed in the log, the npm tests run on it, and the packed tarball
checked to hold `package/native/lazaret.wasm` and `package/native/NOTICE`.
The module imports nothing (an npm test holds it so); built from two
checkout paths with the same commit and toolchain, it came out byte for
byte the same.

Bumping the pins by hand (Dependabot updates the actions only):
`RUST_VERSION` in `wheels.yml` and `release.yml` (the same version), at or
above `rust-version` in `rust/Cargo.toml`; the two manylinux images, by the newest dated tag's
digest (`docker buildx imagetools inspect
quay.io/pypa/manylinux_2_28_x86_64:latest`, or quay.io's tag list). GitHub
retires its last Intel macOS image (macos-15-intel) in August 2027; after
that the x86-64 library becomes a cross build on Apple silicon, checked by
its headers only.

CI (`.github/workflows/ci.yml`, job `rust`, Linux, macOS, Windows):
`check_rust_deps.py`, `make_rust_tables.py --check` (on 3.10), `cargo test`,
the build, the parity modules against the library (they skip where it
is not built, so the job first asserts that it loads), the WebAssembly
build against the library (`test_wasm_parity`, `_signs`, `_crossfile`),
and on Linux the whole Python suite with `LAZARET_ENGINE=rust`. Job `js`
(Node 22 and 24 on the three systems) builds the module with the runner's
Rust, runs `npm test`, and on Node 24 the CLI-level parity modules
(`test_js_parity*`, the npm engine against the Python engine; they too skip
without the module, so the step first asserts that it loads).

Versions: the workspace version is held to the Python and npm packages'
(`scripts/check-versions.sh` reads `rust/Cargo.toml` and the two entries of
`rust/Cargo.lock`), so the engine reports the version of the release it
ships in. A release bump changes all three; `cargo update --workspace
--offline` in `rust/` rewrites the lock file.

## 5. The parity contract

For every input the native engine returns exactly what the Python reference
returns: findings and reasons, lines and offsets (in code points), under the
same limits, with Python `re` semantics for every pattern (Unicode `\w \d \s \b`,
`re.I` case folding, lookarounds, `\Z`). **A detection change lands in
`core.py` with its tests and in the native engine in the same change**, and
the pack is regenerated (`make_rust_tables.py`; `--check` in CI). A pattern
core builds at run time must be built from named module-level pieces (the
extractor only sees values), as `_DV_NAME_HEAD`/`_DV_HELPER_CALL_TAIL` and
`_ENV_COPY_USE_HEAD`/`_ENV_COPY_USE_TAIL` are.

The differential tests (each module under 45 s, as every module is):

| Module | Compares | On |
|---|---|---|
| `test_rust_parity_regex` | every pack pattern and 126 hand-written probes, search/match/fullmatch/finditer/sub/split with pos/endpos | Python 3.10–3.14 |
| `test_rust_parity_hooks`, `_hooks_b` | the 15 fields of `hooks_view` (shlex, hooks, both supply-chain tests with and without a language, decoded view, spawned scripts …) | the hooks corpus (`hooks_corpus.py`, ~44,400 cases, every other one in each module) |
| `test_rust_parity_signs` | the detectors one by one (received code, PowerShell, stagers, reverse shells, self-read, persistence, the exfiltration shapes, services at login, wallet swaps, the string-array technique …) and the data flow on long texts | the same corpus |
| `test_rust_parity_scanfile` | `scan_file(dep=True)` finding for finding (rule, texts, line, snippet clipped and redacted), family by family and in core's order, with every family and variant reached; each line's context (comment line, comment spans, match text with and without comments, names); NFC, NFD, NFKC and NFKD | the scan_file corpus (`scanfile_corpus.py`: curated files for each family, the hooks corpus' curated scripts, 4,000 random files), this repository's sources and fixtures, every 12th standard-library module; every code point Unicode 13.0 assigns, and 20,000 sequences of combining marks, pairs and jamo |
| `test_rust_parity_lexer` | `_lex_comment_spans`: comment spans, '…' / "…" spans, every literal's span | 12,000 dense random texts, read as Python, JavaScript with and without JSX, SQL and an unknown language |
| `test_rust_parity_project` | `scan_rules` (project mode's rules part) against `core.scan_rules`, finding for finding and in core's order | the scan_file corpus, this repository's sources and fixtures, a sample of the standard library, read as your own files |
| `test_rust_parity_project_scan` | the Python package's project mode through the engine (`engine.scan_files`: `scan_rules`, then core's passes, markers and cap) against `core.scan_file`; a file the engine doesn't answer, scanned by core | the scan_file corpus and real files |
| `test_rust_parity_crossfile` | the cross-file follower (`cross_file`) against `core._cross_file_received_issues`, finding for finding and in core's order: every package of the stream in one call on threads, a registry scan's reading (one package, each file named), Windows separators, skipped files, a package that spends its budget read by core | the follower's own cases and a generated stream of 700 packages |
| `test_rust_parity_hook_commands` | a hook's command read as a program (`hook_command_risk`, `_sh_parse`, `_hook_inline_code`), output thrown away and kept | realistic hook commands and a seeded corpus of separators, quotes, substitutions, redirections, network commands, wrappers and non-ASCII text |
| `test_rust_parity_hexname`, `_offscreen`, `_lookalike` | SC-HEXSTR's hidden names and text, SC-OFFSCREEN-CODE, SC-HOMOGLYPH's look-alike names, case by case (columns in code points) | curated lines and seeded random ones (before the npm package ran the engine, these held its JavaScript twins to core) |
| `test_wasm_parity`, `test_wasm_parity_signs`, `_crossfile` | the WebAssembly build the npm package ships against the platform library, call for call, byte for byte: `hooks_view`, `signs_view`, `scan_file` (dependency mode), `scan_rules`, and the npm binding's `cross_file` against the Python package's | the hooks corpus, the scan_file corpus, this repository's files, the follower's stream |

State: zero differences in every field. The WebAssembly parity holds what
differs between the two builds of one source — 32-bit sizes, one thread,
an abort on a panic, and the npm binding (a JavaScript string read as
Python reads the same str, lone surrogates included); with it, the npm
engine answers as the Python reference does. The CLI-level parity modules
(`test_js_parity*`) then compare the two packages' whole reports. On
real files too: the benchmark's 945 registry scans give identical verdicts,
reasons and findings with either engine, and both tests answer identically,
file by file, on 85,415 files (37,784 of installed Python and npm packages,
and every `.py`/`.js` file of the benchmark's 945 archives, the 516
malicious ones included), with no call the native engine couldn't answer.
`scan_file` was compared file by file too, both engines in dependency mode:
on every source file of the benchmark's malicious releases (15,096 files,
525 findings), on every source member of its 429 popular packages (40,065
files, 821 findings) and on the 13,568 distinct files the scanner,
registry, MCP and npm-parity suites hand `scan_file` (25,173 findings,
every family): no difference. The follower too, on the benchmark's 513
malicious and 434 benign releases, read as `--deps` reads them and as a
registry scan does: no difference. The parity modules skip where the
library is not built (`_native.available()`), and the WebAssembly and
CLI-level ones where `js/native/lazaret.wasm` is not (`NPM_READY`), so CI
builds both first (a workflow test holds every such module to a job that
builds the module); the whole Python suite also passes with
`LAZARET_ENGINE=rust` (the fixture trees, project, `--deps` and registry
scans through the native engine).

The npm package's switch to the engine was checked on real trees too (the
CLI before and after, JSON reports compared): a `--deps` scan of an
installed tree (1,155 dependency files), a project of 616 of the
repository's own source and test files, and an 11.5 MB bundle gave the same
findings in the same order, and still do after §7's speedups, with 1, 2
and 3 worker threads; so do the Python CLI's reports on those trees and on
BenchmarkPython (1,230 files) before and after its project mode and its
follower moved to the engine.

Verifying locally, each command within 45 s:

```bash
cd rust && cargo build --release --offline --locked && cargo test --release --offline --locked
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
(cd ../js && npm run build)                                  # the WebAssembly build
cd ../python
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_regex   # ~1 s; repeat per python3.1x
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_hooks   # ~19 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_hooks_b # ~19 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_signs   # ~20 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_scanfile  # ~8 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_project   # ~6 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_project_scan  # ~9 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_crossfile # ~1 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_hook_commands  # ~7 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_lexer tests.architecture.test_rust_parity_hexname \
  tests.architecture.test_rust_parity_offscreen tests.architecture.test_rust_parity_lookalike   # ~3 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity         # ~20 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_signs   # ~11 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_crossfile  # ~1 s
python3 ../scripts/make_rust_tables.py --check && python3 ../scripts/check_rust_deps.py
```

## 6. The regex engine (`pyre/`)

A port of CPython's `re/_parser.py`, `re/_compiler.py` and `_sre/sre_lib.h`
(3.11–3.14 semantics; 3.10-only differences are version-gated in the tests):
the same code words as `re._compiler`, SRE(match) as an explicit context
stack (no recursion), MARK and REPEAT handling, sre's literal-prefix and
charset scans, one budget tick per op. `\B` on an empty string follows
3.10–3.13 (no pack pattern uses `\B`; a test keeps it so).

Answer-preserving speedups sre lacks, each a skip of work that cannot lead to
a match (the soundness argument is in each module's doc, and hand-written
probes in `test_rust_parity_regex` hold it):

- a **first-character filter** (`first.rs`): start positions no possible
  first consuming op accepts are skipped (JUMPs followed out of
  alternatives; a leading lookahead's first op counts; a path that can end
  without consuming gives no filter);
- per-op tables (`prog.rs`): ASCII bitsets for the IN ops and sre's INFO
  charset, tail first-sets for REPEAT_ONE/MIN_REPEAT_ONE and first-sets per
  BRANCH alternative (sre does both only for a literal lead);
- a **required-literal prefilter** (`literal.rs`): strings one of which must
  lie inside every match, from runs of literals and small literal-only sets
  (`(?i)s` is `[s ſ]`), joined across a BRANCH's alternatives and never
  taken from a lookaround (which may look outside `[pos, endpos)`); a text
  holding none of them has no match. Unused under 2 characters or over 64
  strings; about 170 pack patterns get one
  (`cargo run --release --example show_need -- NAME` prints them);
- **leads** (`literal.rs`): the strings every match starts with; a search
  tries only where one starts, found with a two-character filter, and a
  need that is the lead's own strings is not scanned for twice;
- a search's start set (`first.rs`) keeps the zero-width tests a match
  makes before its first character — a one-character lookbehind
  (`(?<![\w$.])` before a name, `(?<![^\n])` at a line's start) and the
  position tests (`\b`, `^`, `$`) — so the matcher is entered at the first
  letter of a name, not at every letter;
- **anchored scans** (`scan.rs`): a literal string — a need, a lead, sre's
  literal prefix (each place it occurs, overlapping ones too: the places
  sre's own scan tries) — is looked for by its character that is rarest in
  source text (a static guess: it changes only how fast, never what is
  found), sixteen characters at a time, and checked only where that
  character is; `pystr`'s find (core's `in` and `find`) the same way, a
  short text character by character;
- a pattern that starts with `^` under MULTILINE is tried only where a
  line starts (every other start fails at its first operation), jumping
  from line to line;
- a **set pattern** — one character of a set of literals and ranges
  (`[/'"`]`, a lexer's next interesting character) or the longest run of
  them (`[ \t\n]*`), with no groups and no IGNORECASE — is answered without
  the matcher (`Simple` in `mod.rs`: search and match only);
- mechanics: the dispatch phase is an inner loop, and matcher buffers are
  pooled per thread.

`Regex::need()` exposes the prefilter's strings: `scan_file` reads them
for all of a file's per-line patterns in one pass (`Gates`, a bit per
pattern and line), and a line holding none of a pattern's strings is not
searched for it (a line whose match text differs from the file's text — NFKC,
decoded escapes, comments cut out — always is). The calls that run many
searches over one whole text (the import-time and install-script tests, the
decoded view, the import-time code) read a **text gate** first
(`textgate.rs`): the text's pairs of characters, and its triples hashed
into a table sized to it, so a need, a needle or a find whose string has a
pair or triple the text lacks answers at once.

Beyond the regex engine, a few patterns core runs on every line or every
token are matched or prefiltered by hand, each written for one pattern text
and used only while the pack holds exactly that text and flags (compared
once per pack; any other text runs as a regex, so a change of the pattern in
core makes the engine slower, never wrong, until the hand code follows):
the lexer's literals (`_LEX_STR`, `_LEX_MYSQL_STR`, `_JS_REGEX_LIT_RE`: each
has one way to match, so a loop gives its match, as each loop's comment
argues), and three necessary conditions `scan_file` tests before a search —
`ENTROPY_VALUE_RE` (a quote, then 20 characters of the literal's class),
`B64_BLOB_RE` (202 characters) and `_SC_SINK_WORD_RE` (a sink's name, or `[`,
blanks, a quote and an `e` or `F`). `test_rust_parity_lexer` fails when one
of the loops is changed (checked by mutating them).

It still loses to sre on patterns that could start almost anywhere
(`_XF_JS_MEMBER_RE`, `_PY_DOC_HEAD_RE`); core only calls those with
`.match(text, pos)`, so their whole-text search time doesn't matter.

## 7. Performance

Single thread, per call, on the hooks corpus (29,795 small cases), best of 3:
the native engine is 3.8× the Python engine over all measured calls (shlex
20×, hook tokens 19×, follow_hook 8×, install_script_risk 3.4×,
import_time_risk 3×, self-read 8×).

On real files, the import-time test over 678 of litellm's modules
(20.7 M characters): Python 15.6 s; native 5.7 s on 1 thread (2.7×), 3.2 s
on 2 threads (4.9×); no difference, no fallback. In 0.1.8, the benchmark's
945 registry scans (516 malicious releases, 429 popular packages; 2 cores,
one engine after the other): 1,097 s with the Python engine, 853 s with the
native one (22% less; 95th percentile 9.5 s → 6.2 s; litellm 40.0 s
→ 30.6 s, playwright-core 18.1 s → 10.7 s), with the same verdicts and
findings for every package. Most of what was left was phase 2
(`scan_file`).

`scan_file` in dependency mode (phase 2), on litellm's 2,643 source files
(44.8 M characters): the Python engine 21.6 s of its registry scan; the
native engine 2.7 s on one thread (8×) and 2.1 s in the registry scan, on 2
threads (10.4×); playwright-core's 39 files (11.7 M characters, bundles)
0.8 s on one thread. On the benchmark's 40,065 popular-package source
files, in the sweep that compared them: 195 s with the Python engine,
18.5 s native (batches of 64 on 2 threads).

With it, the benchmark's 945 registry scans, measured the same way: 1,141 s
with the Python engine, 299 s with the native one (3.8×; 95th percentile
9.7 s → 2.6 s; litellm 42.1 s → 11.4 s, playwright-core 18.1 s → 4.0 s),
with the same verdicts, reasons and findings for every package. In a
profile, litellm's registry scan went from 31.8 s to 12.2 s: what is left
is the import-time test (phase 1, 5.4 s: the per-line gates and prefilters
of `scan_file` are not applied there yet), the cross-file follower (3.4 s,
phase 3) and reading the archive (0.8 s). 0.1.8's detections (the
exfiltration shapes, in all three engines, and the follower's event
emitters, read only where a file's `.emit(` and `.on(` calls are) bring the
945 scans to 306 s (playwright-core 4.5 s). The behaviour pass (data flows, string
arrays and proxy objects, a hook's command read as a program) costs more on
large bundles: playwright-core's registry scan 4.7 s → 11.2 s, litellm's
12.2 s → 16.7 s, next's 10.6 s → 11.0 s (the import-time test of
playwright's two 3 MB bundles: 1.1 s → 4.1 s, the data flow about 1 s of it,
and a bundle it finds a reason in is read twice).

**The last round of 0.1.8** went after what that left. The import-time and
install-script tests no longer search where a pattern cannot match (§6:
leads, start tests, the text gate, anchored scans; and the data flow
answers early when a file reads no local data): on one core, over an
installed npm tree's 1,061 JavaScript files, the import-time test 2.22 s →
0.85 s and the install-script test 2.51 s → 0.98 s; over litellm's 2,471
modules the import-time test 19.3 s → 8.0 s; `received_code_kind` on a 1 MB
bundle 125 ms → 85 ms. The cross-file follower is the engine's
(`cross_file`): the npm tree's 41 packages 1.86 s in core → 0.60 s on one
thread, 0.38 s on two; litellm's modules read as one package 3.1 s → 1.1 s.
And the Python package's project mode reads its rules through `scan_rules`.
On two cores, before and after, with the same reports:

| Two cores | Before | After |
|---|---|---|
| The benchmark's 945 registry scans (their scan time) | 547 s | 305 s |
| … 95th percentile; litellm; playwright-core; next | 3.5 s; 16.6 s; 10.6 s; 10.4 s | 2.2 s; 10.5 s; 5.8 s; 8.9 s |
| Python CLI, `--deps` over the npm tree (1,155 dependency files) | 5.6 s | 2.5 s |
| Python CLI, BenchmarkPython (1,230 files, project mode) | 6.6 s | 5.2 s |
| Python CLI, a 616-file project | 18.1 s | 14.7 s |

The 945 registry scans give the same verdicts, reasons and findings for
every package. What is left in project mode is core's taint and flow
engines (§10, item 1); in litellm's registry scan, the import-time test
still leads. A backtracking engine that must give sre's exact answers can't
skip much more inside one search: the gains were, and are, in not
searching.

**The npm package (WebAssembly).** The same calls take 1.4–1.9× the native
library's time under Node 22's WebAssembly (one thread; compiling and
instantiating the 2.1 MB module takes about 8 ms, once per process).
Against the JavaScript twins it replaced, the CLI's whole run on two cores
(on one thread in parentheses), with the same reports: a `--deps` scan of an
installed tree (1,155 dependency files) 7.6 s → 3.5 s (5.1 s); a project of
616 source and test files 6.1 s → 4.9 s (5.4 s); a tree whose 11.5 MB
bundle is most of the scan 11.8 s → 8.2 s, on one thread (no number of
threads makes one file's scan shorter, so the CLI starts none). Before the
round above, the `--deps` scan was the slower one (9.2 s against the
twins' 8.1 s, one core): its import-time test took 3.5 s in WebAssembly and
1.9 s in the twin, whose regexes V8 compiles to native code. On two cores
the worker threads gain least on a project scan: one thread already keeps
1.4 cores busy (V8's compiler and garbage collector run beside it), and the
cross-file flow analysis (about 1 s of the 616-file project, against 3.8 s
for its per-file scans) runs on the main thread after the per-file scans.
SQL-DYNAMIC, which `re` and pyre run in quadratic time on a line of many
`EXEC("` (13.9 s for one such file), is matched by hand in linear time
(`linear.rs`), as the twin did (`linear.js`).

Tools (`rust/crates/lazaret-engine/examples/`): `profile_calls CASES.json`
(time per call), `pattern_times CASES.json [NAME [REPS]]` (per pattern),
`pattern_stats` (per pattern inside one call; `--features stats`, never
shipped), `profile_scanfile FILES.json [FIRST] [COUNT] [REPS]` (scan_file
over `[[path, lang, text], …]`, with the per-pattern times under
`--features stats`), `profile_one CASES.json CALL [REPS]` (a loop for
callgrind: build with `CARGO_PROFILE_RELEASE_DEBUG=true
CARGO_PROFILE_RELEASE_STRIP=false` into its own `--target-dir`), `show_need
NAME…`. `CASES.json` is the hooks corpus: `python -c "import json; from
tests.architecture.hooks_corpus import corpus; json.dump(corpus(),
open('cases.json', 'w'))"` from `python/` with `PYTHONPATH=src:.`.

## 8. Phases

| Phase | What moves to Rust | State |
|---|---|---|
| 0 | Workspace, bindings, regex engine, Unicode 13.0 tables, the pack | Done (source decoding — BOMs, UTF-16, coding cookies — not started) |
| 1 | The supply-chain tests and what they read | Done, current through 0.1.8; wired into both packages (0.1.8) |
| 2 | Per-file rules (`scan_file`: `RULES`, `TEXT_RULES`, secrets, entropy, homoglyphs, hidden Unicode, off-screen code …), the Python and JS/TS lexers | Dependency mode done and wired in (every family, NFKC, the comment lexer, findings with their snippets and redaction). Project mode: the rules part done (`scan_rules`: every rule of `RULES` with Q-LONGLINE and SC-PIPE-SHELL, the families, `TEXT_RULES`) and wired into both packages (0.1.8); the SQL, taint and function passes that follow it not started |
| 3 | The cross-file follower; archive reading for registry scans | The follower done and wired into both packages (`cross_file`, 0.1.8); archive reading not started |
| 4 (optional) | The taint flow engines | Only if a Rust parser gives identical results |

## 9. Known issues

- `Pack::entry` panics on a name the pack lacks; the FFI and `batch` catch it
  (status 3, and the Python engine answers). A pack-load validation of every
  name the engine reads would turn it into an error at load.
- `_XF_ARROW_ONE_RE` is quadratic on `"x" * 100001` in both engines
  (inherited from core): bound it in `core.py`, and the pack follows.
- The budget (4e9 steps per call) discards an exhausted answer; the Python
  engine then answers, so the budget never changes a finding in the Python
  package. The npm package has no Python engine: there an exhausted call
  leaves its file SC-TRUNCATED (CRITICAL), on hostile input only (no file of
  the corpora or the benchmark comes near the budget). Steps are charged in
  batches of 4,096 per search, so short searches cost nothing against it;
  a call's `budget` argument sets another (the npm tests use a small one).
  `cross_file` gives each package its own budget: in the Python package
  core reads a package that spends it, in the npm package that package
  gives no cross-file finding.
- The WebAssembly build runs on one thread (a `batch` too; the npm CLI's
  parallelism is its worker threads, each with its own instance), and its
  memory only grows: `native.js` starts a fresh instance after a call that
  left it above 512 MB. A panic traps instead of unwinding (the call is an
  error, and the next one gets a fresh instance).
- Core's SQL-DYNAMIC pattern is quadratic under `re` on a line of many
  `EXEC("` (Python: 0.9 s for a 30 KB line, 14 s for 120 KB; core's 30 s
  time budget is checked between lines, so one search is not cut short).
  It is a project-mode rule of `.sql` files. The native engine matches the
  pattern by hand in linear time (`linear.rs`) while the pack holds its
  exact text and flags; bound the pattern in `core.py` and the hand matcher
  can go.
- The native `scan_file` has no time budget (core's `SCAN_TIME_BUDGET`, 30 s
  per file, ends in SC-TRUNCATED): a file it scans is scanned whole, and a
  file that spends its work budget goes to core, under core's time budget.
- S-ENTROPY's Shannon entropy is a `sum()` of floats, which Python adds with
  Neumaier's compensation since 3.12: the binding says which way to add
  (`neumaier`), so a value at 4.0's edge is judged as that Python judges it.
- The messages of findings come from the pack (core's rule dicts, with
  `str.format` templates filled as Python fills them, `!r` as `repr()`); a
  finding text core writes inline is not in the pack, so every text the
  engine shows is a module-level value of core.
- JSON joins adjacent surrogate halves: differential tests normalize both
  sides through JSON before comparing.
- Python 3.10 has no atomic groups or possessive repeats: those regex probes
  are version-gated. The extractor skips integers beyond i64
  (`_INT_STR_LIMIT`); the engine reads none of them.
- The matcher's macros are defined inside its `'main: loop` so that
  `continue 'main` resolves; keep them there.
- Patterns built at run time are compiled into a per-thread cache cleared at
  512 entries, like `re`'s; each thread compiles its own.
- Measuring: single runs vary ±15% on shared machines; compare best of 3, or
  callgrind instruction counts (`examples/profile_one`).

## 10. Next

Done in 0.1.8: **WebAssembly for the npm package** (§2–§5). The npm
package runs the native engine (`native/lazaret.wasm`, dependency-free,
built in release CI with the wheels' compiler); the JavaScript twins of
what it answers are retired (`js/src/lib/hooks.js`, `received.js`,
`shellpipe.js`, `received-spec.json`, `js/src/scanner/linear.js`, the
per-line rules, the families and the dependency decode flow of
`scan.js`); the parity tests compare the native engine with the Python
engine and the WebAssembly build with the native library; the npm package
carries `rust/NOTICE`, `LICENSE-PYTHON` and `LICENSE-UNICODE` (§11). Each
detection change now lands twice (Python and Rust) instead of three times.
Then, also in 0.1.8: the import-time and install-script tests at
`scan_file`'s speed (§6's leads, start tests, text gate and anchored
scans), project mode's rules part in the Python package (`scan_rules`), the
cross-file follower in the engine for both packages (`cross_file`, phase
3), and worker threads in the npm CLI (§2, §7).

1. Project mode's passes after the rules: core's taint, SQL and function
   passes reading a context built from the native one's (as the npm engine
   does), then those passes in the engine, and the npm engine's twins of
   them (`js/src/scanner/`). They are most of what is left of the Python
   package's project scans (§7).
2. The rest of the npm engine's twins: the manifest, workflow and settings
   checks (`supplychain.js`, `ghworkflow.js`, `autorun.js`), the
   config-file credentials; the dashboard keeps its own script until it can
   load the same module.
3. Archive reading for registry scans (phase 3's other half).
4. Flip the source of truth: `core.py` loads the pack at import.
5. Record the engine in reports (JSON and SARIF), next to the version.
6. More single-thread speed if still needed: one pass over a line for the
   checks `scan_file` makes of each character (ASCII, backslash, quotes),
   a faster hash than SipHash, a cheaper `Prog::new` for run-time patterns.
7. Keep the benchmark harness (outside the repository today) with the
   engine, and run the 945 packages with each engine nightly.

## 11. Licensing

The engine is Lazaret's own work under Apache-2.0, except for its
translations of CPython code: pyre's parser, compiler, constants and
matcher (`Lib/re/_parser.py`, `_compiler.py`, `_constants.py`,
`Modules/_sre/sre_lib.h`), parts of `pyre/mod.rs` (`parse_template` and the
Pattern methods of `sre.c`), `shlex_split` in `hooks.rs` (`Lib/shlex.py`),
`capital_sigma` in `unicode.rs` (`handle_capital_sigma` in
`Objects/unicodeobject.c`), and the `_casefix` table in `unicode13.rs`.
Those are derivative works of CPython and are distributed under CPython's
license as well: the PSF License Version 2 and the older licenses of its
stack, among them CNRI's Python 1.6 license, which the SRE files' Secret
Labs notices name.

- `rust/NOTICE` lists them, repeats the originals' notices (Secret Labs AB
  1997-2001 and 1998-2001, the PSF's) and summarizes the changes (section 3
  of the PSF License asks for that when the work is distributed).
- `rust/LICENSE-PYTHON` is CPython 3.14.0's LICENSE, unchanged (a test pins
  its SHA-256; take a newer one whole, never edited).
- Each translated file starts with `// SPDX-License-Identifier: Apache-2.0
  AND Python-2.0.1` and its original's notices.
- `generated/unicode13.rs` is Unicode Character Database 13.0 data, under
  the Unicode License v3 (`rust/LICENSE-UNICODE`, the same text as the
  Python and npm packages' `LICENSE-UNICODE`); its header carries the
  notice, and `rust/NOTICE` says so (0.1.8).
- `rust/Cargo.toml` declares `Apache-2.0 AND Python-2.0.1 AND Unicode-3.0`.
  The platform wheels carry the compiled engine, so they carry
  `LICENSE-PYTHON` and `NOTICE` as license files (`.dist-info/licenses/`)
  beside the pure wheel's `LICENSE` and `LICENSE-UNICODE`, and declare the
  same expression; the pure wheel and the sdist hold none of the translated
  code and are `Apache-2.0 AND Unicode-3.0` (their Unicode table).
  `check_native_library.py --dist` checks the wheels before a release.
- The npm package (0.1.8) carries the compiled engine as
  `native/lazaret.wasm`, with `rust/NOTICE` as `native/NOTICE` (both written
  by `npm run build`), `LICENSE-PYTHON` and `LICENSE-UNICODE`; its own
  `NOTICE` points to them (and names the CPython codec names and Unicode
  tables of its JavaScript), and it declares `Apache-2.0 AND Python-2.0.1 AND
  Unicode-3.0`. Its shlex is the engine's since the JavaScript translation
  (`hooks.js`) was retired. `release.yml` fails a tarball without
  `native/lazaret.wasm` or `native/NOTICE`.

`tests/architecture/test_rust_notices.py` keeps all of this in place, and
fails on a Rust file that says it is ported or translated from CPython
without a notice: a new translation gets a header and a line in
`rust/NOTICE`. The Secret Labs notices say the SRE library "can be
redistributed under CNRI's Python 1.6 license. For any other use, please
contact Secret Labs AB"; Lazaret distributes the translation under
CPython's own terms with every notice kept, the usual reading, and a
commercial use may want a lawyer's view of that sentence.
