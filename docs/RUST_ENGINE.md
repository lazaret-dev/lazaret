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
§8). The JavaScript parser the detectors are to be rebuilt on is too
(`js_parse`, §12): jsparse.py's trees, node for node; and a Python parser
(`py_parse`, §13): Python 3.13's `ast` trees, node for node. Since 0.1.8 the npm
package runs the same engine compiled to
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
  LICENSE-UNICODE            the Unicode License v3, for generated/unicode13.rs and
                             pyparse/unidata.rs (§11)
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
    src/linre/               a linear-time regex engine with re's answers, not yet used by the
                             engine's patterns (§14): parser, sets, programs, lazy DFAs,
                             backtracker, Pike VM, prefilters
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
    src/jsparse/             the JavaScript parser (jsparse.py's trees: §12): scan.rs (literals,
                             character classes, the token patterns by hand), parser.rs (tokens,
                             reads ahead, statements, classes, modules), expr.rs (expressions,
                             patterns, JSX), types.rs (TypeScript's types), tree.rs (the arena),
                             out.rs (JSON)
    src/pyparse/             the Python parser (Python 3.13's ast trees: §13): lexer.rs (tokens,
                             f-strings in pieces), parser.rs (statements, which error Python
                             reports), expr.rs (expressions, targets, arguments, strings),
                             pattern.rs (match patterns), literal.rs (values), unicode.rs and
                             unidata.rs (Unicode 15.1: identifiers, NFKC, \N{} names), limits.rs
                             (Python's nesting limits), tree.rs (the arena), out.rs (JSON)
    examples/                profiling tools (profile_calls, profile_scanfile, pattern_times,
                             pattern_stats, show_need, jsparse_bench, pyparse_bench)
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
scripts/make_pyparse_tables.py          pyparse/unidata.rs (Python 3.13); --check
scripts/check_rust_deps.py              Cargo.lock and the manifests hold only the workspace
scripts/check_native_library.py         a built library against its wheel's tag; --dist: the release's wheels
.github/workflows/wheels.yml            the five libraries, the wheels, installed on each platform
python/tests/architecture/test_rust_parity_{regex,hooks,hooks_b,signs,scanfile,lexer,project,
  project_scan,crossfile,hook_commands,hexname,offscreen,lookalike}.py,
  test_wasm_parity{,_signs,_crossfile,_jsparse,_pyparse}.py, test_jsparse_native{,_b}.py,
  test_pyparse_native{,_b,_c}.py, test_rust_deps.py, test_rust_pack.py, hooks_corpus.py,
  scanfile_corpus.py, jsparse_cases.py, pyparse_cases.py, pyparse_oracle.py,
  test_linre{,_b,_c,_d,_linear}.py, _linre_inputs.py (linre, §14)
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
memory, so running past it traps) and copies the module (about 2.4 MB) to
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
| `test_jsparse_native`, `_b` | the JavaScript parser (`js_parse`, `js_parse_file`) against `jsparse.parse`, node for node as JSON text, key for key; spans (§12) | test_js_parity_parse.py's inputs (snippets, this repository's JavaScript, generated projects, soups, mutations, its linearity cases) and jsparse_cases.py's (the budgets' edges, jsparse.py's bugs, every construct that nests around the depth limit, more soups and mutations) |
| `test_wasm_parity_jsparse` | the parser in the WebAssembly build against the library, byte for byte | the snippets, this repository's JavaScript, soups, every construct that nests at its deepest |
| `test_pyparse_native`, `_b`, `_c` | the Python parser (`py_parse`) against Python 3.13's `ast.parse` (a `python3.13` subprocess; skipped without one), node for node as JSON text, with the errors' lines; spans; its Unicode 15.1 data (§13) | pyparse_cases.py: curated snippets of every construct and error, generated programs, this repository's Python, soups, mutations, every construct that nests at Python's deepest and one deeper, a chain of `not`s in 47 contexts, long inputs; every identifier character and character name |
| `test_wasm_parity_pyparse` | the Python parser in the WebAssembly build against the library, byte for byte | the snippets, this repository's Python, programs, soups, every construct that nests at its deepest |

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
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_jsparse_native      # ~9 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_jsparse_native_b    # ~9 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_jsparse # ~18 s
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
| 4 (optional) | The taint flow engines | The parsers they would read are done (`js_parse`, §12: jsparse.py's trees, node for node; `py_parse`, §13: Python 3.13's ast trees, node for node); the passes on them (scope resolution, data flow, constant folding of strings) not started |

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
8. The detectors on the JavaScript parser (§12): scope resolution, data
   flow and constant folding of strings over its trees, in place of the
   pattern-and-window readings they rebuild; and the same passes over the
   Python parser's trees (§13).
9. linre (§14): decide whether the engine's patterns run on it (`p.re` →
   linre where it accepts the pattern and pyre for the 41 it refuses, or
   those rewritten in `core.py` as §14 suggests).

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
  notice, and `rust/NOTICE` says so (0.1.8). So is `pyparse/unidata.rs`,
  the Python parser's Unicode 15.1 data (§13), written from Python 3.13's
  unicodedata: its header carries the notice and `rust/NOTICE` names it.
  The Python parser is written from Python's grammar and `ast`'s answers,
  not translated from CPython's parser: it is Lazaret's own work.
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

## 12. The JavaScript parser

`src/jsparse/` is a port of `lazaret.scanner.jsparse` (jsparse.py, 0.1.7's
reader for the cross-file flow engine): the first piece of the engine's
Rust-first detectors, whose later passes (scope resolution, data flow,
constant folding of strings) will walk its trees.

**What it reads.** ECMAScript 2025 with JSX and TypeScript — the syntax of
.js .mjs .cjs .jsx .ts .tsx .mts .cts files — into ESTree-shaped trees:
acorn's and acorn-jsx's node types and fields, and jsparse.py's
TSEnumDeclaration, TSModuleDeclaration, TSImportEquals and
TSExportAssignment. TypeScript's types, interfaces, aliases, overload
signatures, abstract members and `declare` statements are read and left
out; Flow's annotations in a .js file are read as TypeScript's. For every
input it builds exactly the tree jsparse.py builds — every node type, field,
value and `line` — or fails with the same JsSyntaxError line and reason.

The calls: `js_parse` (`{"ts": false, "jsx": true}` by default, as
`jsparse.parse`) and `js_parse_file` (`{"path": …}`: the dialect
`jsparse.dialect` picks by the file name), each answering the tree as JSON —
jsparse.py's keys, in its order — or `{"error": {"line": n, "reason":
"…"}}`; `"spans": true` adds each node's `start` and `end` after its `line`.
The answer goes out serialized (`json::Value::Raw`): a tree may nest deeper
than a `Value` should.

**The tree** (`tree.rs`). An arena: `nodes`, a `Vec` of 32-byte `Node`s
addressed by `u32` ids and renumbered after the parse in document order
(pre-order: a child's id is above its parent's, the Program is 0), so what
an abandoned read built (a failed speculative read, a cover grammar's
expression, the expressions inside a type) is not in it. A node holds its
`Kind` (ESTree's type, an enum), `line`, `start` and `end` (code points,
half-open: `start` is where the token its line is taken from starts, so
`line` is always the line of `start`; `end` is past its last token), a small
enumeration `op` (an operator, a declaration's, method's, property's or
literal's kind), boolean `flags`, and four slots. One table,
`tree::fields(kind)`, gives each kind's fields in jsparse.py's order — key,
type (a child, a nullable child, a list, a list with holes, a string, a
flag, an enumeration …) and slot — and drives the JSON writer, `each_child`,
the accessors by key (`child`, `children_of`, `text_of`, `slot`) and
`compact`. Lists live in one `Vec<u32>` (a list id is the index of its
length; list 0 is empty). Strings — names, cooked string values, numbers'
and regexes' text, templates' raw text — are interned: equal names have
equal ids, which scope resolution can compare. A string literal's cooked
value is code points, as the engine's PyStr and jsparse.py's `value`: lone
surrogates kept, an escaped surrogate pair the one character it encodes.
A tree can be as deep as its input is long (member and call chains, binary
operators and `else if` chains are read in loops and nest): walk it with an
explicit stack, as the writer and `compact` do.

**Limits.** `MAX_DEPTH` 256 (statements, expressions, types, JSX: deeper is
"nesting too deep"); `SPECULATION_TOKENS` 4096 tokens per read ahead; all of
a file's reads ahead, peeks included, together `SPECULATION_TOTAL` (16 ×
4096) plus 2 per code point. The parser makes jsparse.py's reads, peeks and
speculative reads in jsparse.py's order, so each budget runs out at the
same token, and what reads differently once it has (a later `let x = 1`
read as an expression) reads the same. Linear time: one token at a time,
and a token, comment or blank run of 48 code points or more is scanned once
and kept by its start, for the reads ahead that cross it again (jsparse.py
scans it again each time: a 1 MB string behind 2,000 `f<` takes it 2.7 s,
the engine 0.04 s). Recursion is bounded by the depth limit (the two chains
jsparse.py recurses on without it are loops here). The deepest stack — a
253-deep nesting of tagged templates, of the 51 constructs that nest —
takes 231 KiB natively (release; the crate's test reads every construct at
its deepest on a 1 MiB thread) and between 64 and 128 KiB in WebAssembly,
whose stack is 8 MiB (§3). Every input gives a tree or an error, never a
panic.

**jsparse.py's bugs, reproduced:**

- `(...a, b)` that is not an arrow function's parameter list raises
  `KeyError: 'line'` (parse_paren_items sets the list's line only when its
  first item is not a rest element): the engine answers `{"error": {"line":
  0, "reason": "KeyError: 'line'"}}`, line 0 saying it is not a
  JsSyntaxError.
- Flow's `?T` (parse_primary_type) and a JSX closing tag's name
  (`_jsx_name_text`) recurse once per `?` and per member, without a depth
  check: a chain of about 13,000 runs out of Python's recursion limit, and
  parse() answers "nesting too deep" at line 1. The engine reads both in
  loops and answers so from `PY_CHAIN_LIMIT` (13,222) on, where Python's
  limit falls for a program's top level parsed from a shallow caller.
  Python's threshold moves with the frames already in use (22 lower from 20
  frames deeper), so a chain within a few dozen of it may be read
  differently: the tests stay clear of that band.
- The speculative reads' re-scans above: time, not a different answer; the
  engine keeps the answer and drops the cost.

**Tests.** `cargo test --release` (`jsparse/tests.rs`): every construct
that nests read at the deepest depth jsparse.py reads and failing one deeper
(the depths are jsparse.py's), all of them on a 1 MiB stack; the budgets at
their edges (a generic arrow function of 2,044 parameters is one, of 2,045
is not; function_type_ahead's 256 tokens; the file's allowance spent);
the KeyError and recursion-limit answers; spans; interned names; 6,000
seeded soups of pieces and arbitrary code points (controls, lone
surrogates, values past U+10FFFF) that must not panic.
`test_jsparse_native` and `_b` compare `js_parse` with `jsparse.parse` as
JSON text (jsparse.py's dicts written as `json.dumps` writes them, without
recursion) on test_js_parity_parse.py's inputs — its snippets, the
repository's JavaScript, 60 seeded projects, 1,500 soups, 300 mutations,
and its two linearity cases, which the engine reads in well under a second
— and on jsparse_cases.py's: 231 more snippets (the budgets' edges, the bugs
above, surrogates, numbers, escapes, regular expressions, templates, ASI,
comments, JSX, TypeScript, Flow, an error at every kind of token), every
construct at 19 depths around the limit, 6,000 soups and 800 mutations;
and the spans (without `start` and `end` the JSON is the same, and `line` is
the line of `start`). `test_wasm_parity_jsparse` holds the WebAssembly build
to the library, byte for byte (a Node script speaking native.js's protocol
answers each call's SHA-256), on those snippets, sources and soups and on
every construct at its deepest and one deeper.

On real files: every .js .mjs .cjs .jsx .ts .tsx .mts .cts file of the 20
npm packages installed on the development machine (24,428 files, 348.8 MB;
typescript's 9.1 MB `lib/typescript.js` the largest), each read in
`jsparse.dialect`'s dialect: identical trees for 24,424, identical errors
for 4 (declaration files' `export = function f(…): T;`, a signature
jsparse.py reads as a function expression), no difference. jsparse.py took
250 s; the engine 12.0 s through the Python binding, its JSON included.

**Throughput**, the release build on one thread, best of three, over those
24,428 files: the parse 62 MB/s (the tree compacted), the parse with its
JSON 46 MB/s; over ordinary module code (puppeteer-core's 362 ESM files,
1.9 MB) 70 and 57 MB/s; over typescript's `lib/` (19.8 MB of bundles and
declaration files) 60 and 50 MB/s (`cargo run --release --example
jsparse_bench -- throughput DIR…`). jsparse.py reads 1.3 MB/s. The parser
adds 0.2 MB to the WebAssembly module (2.25 MB → 2.45 MB).

## 13. The Python parser

`src/pyparse/` reads Python source as Python 3.13's `ast.parse(source)`
does: the second parser the engine's detectors are to be rebuilt on (scope
resolution and data flow over its trees, as over the JavaScript parser's,
§12). It is written from Python's grammar and from what `ast` answers,
which is its oracle: no code of CPython's parser or tokenizer is in it.

**What it reads.** Everything Python 3.13 reads: PEP 701 f-strings (nested
quotes, comments and backslashes in replacement fields, `=` and `!r`,
nested format specifiers), `match` and its patterns, `type` aliases and
type parameters (bounds, constraints, 3.13's defaults, `*Ts`, `**P`),
`except*`, the walrus, positional-only parameters, any decorator
expression, the soft keywords, async forms. For every input it builds the
tree `ast.parse` builds — the same node classes, every field in `_fields`
order and its value, `lineno`, `col_offset`, `end_lineno`, `end_col_offset`
— or fails where Python raises: SyntaxError, IndentationError, TabError,
the error of a NUL, MemoryError and RecursionError for nesting. Python 2 is
refused as Python refuses it. Only what `ast.parse` checks is checked:
`return` outside a function or a starred assignment target alone are
trees, as there (the compiler refuses them later). The text is code points,
as the engine's PyStr: a lone surrogate or a value past U+10FFFF is refused
(Python cannot encode such a str for its tokenizer); a coding declaration
is not read (`ast.parse` of a str ignores it); `from __future__ import
barry_as_FLUFL` makes `<>` the inequality and `!=` an error, as it does
there.

The call: `py_parse` (`{}`; `"spans": true` adds each node's `start` and
`end`, code points, after its positions), answering the tree as JSON —
`{"_type": "Module", "body": […], "type_ignores": []}`, each node's
`_type`, its fields in `_fields` order, then its positions (columns in
UTF-8 bytes, as `ast`'s); a context or an operator `{"_type": "Load"}`; a
Constant's value `null`, `true`, `false`, a string, `{"Ellipsis": true}`,
`{"bytes": "<hex>"}`, `{"int": "<decimal digits>"}` (`"0x…"` past 16,384
bits: converting a longer hexadecimal literal to decimal would take
quadratic time; every decimal literal Python reads, 4,300 digits at most,
is below it), `{"float": "<float.hex()>"}` or `{"complex": [re, im]}` —
or `{"error": {"line": n, "reason": "…"}}`. Line 0 is an error Python
gives no line: a NUL, a text it cannot encode, the MemoryError and the
RecursionError of nesting. The reason is the engine's wording (often
Python's); the line is Python's (below).

**The tree** (`tree.rs`), an arena as the JavaScript parser's: `nodes`, a
`Vec` of 28-byte `Node`s addressed by `u32` ids, in document order
(pre-order, children in field order; the Module is 0). A node holds its
`Kind` (the `ast` class), `start` and `end` (code points, half-open: from
its first token to past its last), a small enumeration `op` (a context, an
operator, a conversion, a constant's type), `flags` (`is_async`, `simple`,
a constant's `kind`), and four slots. One table, `tree::fields(kind)`,
gives each kind's fields in `_fields` order — name, type (a child, a child
or None, a list, a list with Nones for a Dict's keys and `kw_defaults`, a
string, an int, a flag, an enumeration …) and place (a slot, or for
FunctionDef, AsyncFunctionDef, ClassDef and arguments, which have more
fields than slots, an item of an extension list) — and drives the JSON
writer, `each_child`, the accessors by field name (`child`, `children_of`,
`text_of`), `raw`, `parents` and `compact`. Lists live in one `Vec<u32>`.
Strings are interned: names (NFKC, as Python normalizes identifiers),
string values (code points: a `\ud800` escape's lone surrogate is kept),
bytes, ints' digits; equal names have equal ids. A float's value is its
`f64`, correctly rounded as Python rounds it. `line_starts` turns spans into
Python's lines (a line ends at "\r\n", "\r" or "\n"). A tree can be as deep
as its input is long (binary operators, attributes, calls, subscripts):
walk it with an explicit stack, as the writer and `compact` do.

**Reading.** `lexer.rs` turns the whole text into tokens first (f-strings
in pieces, PEP 701's way), up to the first token it refuses. The parser
(`parser.rs`: statements; `expr.rs`: expressions, targets, arguments,
parameters, strings and f-strings; `pattern.rs`: match patterns) reads
them top-down with one token of look-ahead (two or three where the grammar
asks: a keyword argument's `=`, a walrus, `not in`, `is not`), where
Python's PEG parser tries alternatives in order: an assignment's targets
are read as expressions and given their context once the `=` (or `:`, or
an augmented operator) after them says what they are; a `for`'s targets
are primaries read up to the `in`; a statement starting with the soft
keyword `match` is a match statement when its first line ends with `:`;
`with (` reads the parenthesized items first and, if they are none, reads
the parentheses again as an expression — the one place it goes back, at
most once over each token. `literal.rs` gives literals their values
(escapes, `\N{…}` by name, line continuations; ints of any size, floats).

**Which error, and where.** Python's parser takes tokens from its tokenizer
as it needs them, so the error it reports is the first it meets, and then
it may change its mind; the engine reports the same error on the same line:

- a token the tokenizer refuses is the error if the parser reaches it; if
  the parser fails before, its error stands — unless the tokenizer, reading
  the rest of the text, raises an error itself (a bad character, an
  unterminated string, an unmatched bracket, a malformed number: not one
  inside an f-string, and not one it leaves to its parser, as a bad
  unindent, a mix of tabs and spaces, too many indentation levels, a
  backslash before something other than a line break, the end of the text
  in brackets), which takes its place; and a bracket still open there, if
  it was opened on a line before the one the parser stopped on, is
  reported as never closed. Python's generic errors at an INDENT or a
  DEDENT ("unexpected indent", "unexpected unindent") are never replaced;
  its own errors there are ("expected an indented block", "expected
  'except' or 'finally' block"). (A string's escapes are the parser's: a
  bad `\N{…}` further on changes nothing.)
- Where its first pass fails, Python reads again with the rules that word
  its errors (the grammar's `invalid_` rules), which may put the error
  elsewhere: two expressions side by side inside brackets ("Perhaps you
  forgot a comma?", at the first; the second read as Python's
  `expression_without_invalid` reads it — its failing trailers dropped,
  and, where none of it reads, an error inside the brackets it starts with
  is the error), `print x`, `a if b` without `else`, a target that is none
  (at the target, before what follows its `=` is read; an augmented or
  annotated assignment's once what follows begins to read), a mistaken `=`
  or `:=` in an expression, a dict's key after its first item not followed
  by `:` (at the key, whatever follows it) or a key's `:` with no value, an
  f-string's field with no expression or one that reads only in part (after
  its first atom), bytes mixed with str (at the token after the strings),
  an unterminated f-string (on the line it starts). The engine makes those
  checks where its one pass fails, reading ahead as Python's second pass
  reads (`Parser::read_ahead`: the reads go back, and their furthest token
  counts as reached).
- The end of the text is on its last line; `$`, `?` and a backquote are
  tokens the parser refuses, not the tokenizer's errors.

The line is Python's for every error of the curated snippets, every file
of the sweep below and every one of 3,000 seeded mutations (the suite);
over 160,000 more seeded mutations of this repository's Python (141,627 of
them errors) 1 line differs, over 160,000 seeded token soups (156,294
errors) 66 (0.04 %): places where Python's second pass, its memoized reads
included, takes a turn the engine's checks at the failure point do not
follow.

**Limits** (`limits.rs`): Python's, so that what it refuses for nesting is
refused here. Its tokenizer's: 200 open brackets, 99 indentation levels,
149 nested f-strings, a format specifier inside 2 others — the same. Its
parser's stack of 6000 rule calls (a MemoryError): the parser keeps an
estimate of that depth, each construct adding what it costs Python's
parser there; the estimate is exact for the constructs that nest alone
(unary operators: 5,969 deep; `lambda` and `**`: 2,984; conditional
expressions: 5,969; `elif`: 5,965 …) and, where constructs combine, never
under Python's depth. That depth depends on the way Python first reads a
construct, and keeps (its parser memoizes): a bracket a statement or an
assignment's value starts with is first read as a possible assignment
target, a shorter way; an f-string too, but one first read inside an
expression costs 18 rule calls more; a line that starts with `match` and
something a subject can start with is first read as a match statement,
deeper. The estimate follows those ways. Measured with a chain of `not`s
at the innermost point of 1,600 random combinations of 1 to 4 of 53
nesting constructs in 91 statement contexts (1,582 that Python reads), it
never lets the engine read more than Python: as much for 4 %, within 2
levels for 62 %, within 8 for 92 %, at most 36 levels short (of 6,000);
nor in 1,600 more in the 25 contexts where it has no margin; over 300
random repeated nestings (the deepest repeat count read), 212 give the
same count, 88 a smaller one, none a larger. The tree's depth: 9,997 nodes
(Python's C recursion limit less the frames `ast.parse` runs in: a
RecursionError). `pyparse_cases.NESTINGS` pins 41 constructs at Python's
depth, `STRICTER` the 4 where the engine stops earlier (a lambda default
whose default is a lambda: 542 deep where Python reads 596; 98 blocks and
lambda defaults: 648, 660; parentheses in 100 nested f-strings: 95, 96;
comprehensions: 199, 200), and `INNERMOST` 47 contexts of the chain of
`not`s (among them each where an earlier estimate read deeper than
Python). The parser's recursion follows brackets, blocks, f-strings and
lambda defaults — the chains without brackets are loops — so the deepest
input takes a bounded stack: 339 KiB natively (746 nested
lambda defaults, the deepest; release build; `pyparse_bench stack`) — the
crate's test reads every construct at its deepest, parsed and written with
spans, on a 1 MiB thread — and between 64 and 128 KiB in WebAssembly, whose
stack is 8 MiB (a build with a 64 KiB stack traps on some of the 45 deepest
inputs, one with 128 KiB on none; the parity test below runs them all in the
shipped module). Linear time: the tokens are read once (the parenthesized items
of a `with` at most twice); the error pass's reads ahead happen where the
read fails; a `\N{…}` name is found by binary search. Every input gives a
tree or an error, never a panic.

**Unicode 15.1.** Python 3.13 reads identifiers (XID_Start, XID_Continue,
NFKC) and `\N{…}` names with Unicode 15.1; the engine's tables are 13.0
(Python 3.10's, for its regular expressions). `pyparse/unidata.rs`, written
by `scripts/make_pyparse_tables.py` from Python 3.13's unicodedata
(`python3.13 scripts/make_pyparse_tables.py --check` compares), holds the
rest: the identifier classes, NFKC for what Unicode assigned since 13.0
(the 13.0 tables answer for the rest, by Unicode's stability policy), and
every character name and alias `unicodedata.lookup` reads, front-coded in
name order with a word dictionary, plus the names made by rule (Hangul
syllables, CJK unified and compatibility ideographs, Tangut, Khitan, Nushu)
as ranges. `test_pyparse_native_c` holds them to Python 3.13: the tables
current (the script's `--check`), every character an identifier may start
or go on with in a name (the same trees, NFKC included) and 3,000 seeded
ones it may not hold (refused by both), every one of the 138,552 names
`unicodedata.name` gives and every alias in a `\N{…}` escape (the same
strings). Every non-ASCII code point was also compared alone, starting a
name and inside one: no difference.

**Tests.** `cargo test --release` (`pyparse/tests.rs`): 23 constructs at
Python's deepest and refused one deeper, the tokenizer's and the parser's
limits with their errors, all of them on a 1 MiB stack; long inputs
(100,000 statements, 200,000-item lists and calls, 50,000 f-string fields)
in linear time; which error, on which line, where there are several;
values (ints in hexadecimal past 16,384 bits, the 4,300-digit limit,
float.hex, lone surrogates, bytes, `u''`, barry_as_FLUFL); spans and the
accessors; interned NFKC names; 8,000 seeded soups of pieces and arbitrary
code points (controls, NUL, lone surrogates, values past U+10FFFF) that
must not panic and whose answers are JSON. `test_pyparse_native` and `_b`
compare `py_parse` with `ast.parse` run by a `python3.13` subprocess
(`pyparse_oracle.py`, writing ast's trees as the engine writes them,
without recursion) as JSON text, error lines included: 998 curated
snippets (every construct, 256 errors, 125 errors whose line is the point),
400 seeded generated programs, this repository's Python, the spans
(without `start` and `end` the JSON is the same; `lineno` is the line of
`start`), 12,000 seeded soups and 3,000 seeded mutations of this
repository's Python (the same answers; the same lines for every mutation
and for all but 1 in 200 soups at most), every nesting at Python's deepest
and one deeper, the four stricter ones, the 47 contexts of a chain of `not`s
(never longer than Python reads, at most 20 shorter), deep trees and long
inputs;
`test_pyparse_native_c` the Unicode 15.1 data (above). They skip without
Python 3.13 (`LAZARET_PYTHON313` may name one): CI's runners set up 3.10
only, so they skip there and run on the development machine.
`test_wasm_parity_pyparse` holds the WebAssembly build to the library,
byte for byte, on the curated snippets, the repository's Python, programs,
soups, and every construct at its deepest and one deeper, with and without
spans (no trap).

On real files (the sweep script is outside the suite): every .py file of
Python 3.10 to 3.13's standard libraries, `/usr/lib/python3/dist-packages`
and a pip `dist-packages` of 1.6 GB on the development machine — 12,297
files, 190.7 MB, each decoded as Python decodes a source file: identical
trees for 12,296, the same error on the same line for one (an invalid
character in mediapipe's tests), no difference. And every .py file of the
benchmarks on the development machine — the corpus of malicious and benign
packages, the SAST suites, the advisory and rule repositories: 24,021
files, 196.3 MB; 18 of them not UTF-8 nor declaring their coding, read
with their bytes as lone surrogates — identical trees for 23,993, the same
error on the same line for 28 (the 18, which Python cannot encode either;
10 syntax errors), no difference.

**Throughput**, the release build on one thread, best of three, over the
standard library (`/usr/lib/python3.13`: 587 files, 10.7 MB): the parse
59.8 MB/s (the tree compacted), the parse with its JSON 35.5 MB/s; over
the 12,297 files above (190.7 MB) 53.8 and 30.9 MB/s (`cargo run --release
--example pyparse_bench -- throughput DIR…`; `… stack KIB CASES.json` runs
inputs on a stack of that size). Through the Python binding (ctypes, the
text in and the JSON out) the 190.7 MB take 7.1 s, 27 MB/s. The parser and
its Unicode data add 0.58 MB to the WebAssembly module (2.45 MB → 3.03 MB).

## 14. linre, a linear-time regex engine

`src/linre/` is a second regex engine for the engine's patterns: Python's
`re` syntax for str patterns, `re`'s answers, and time linear in the text
whatever the text holds. It is written from `re`'s documented and observed
behaviour, not translated from CPython (whose sources were read for the
rules, as for any reimplementation), so it needs no line in `rust/NOTICE`.
**The engine does not use it yet**: `p.re(…)` returns pyre's patterns, and
what moves to linre is decided after review (§10, item 9). Two calls expose
it: `linre.probe` (pyre.probe's arguments and answer — search, match,
fullmatch, finditer with every group, sub with `<…>` and split, at `pos`
and `endpos`, with `gate` — or `{"error", "refused"}`) and `linre.check`
(`{"names": […]}`, or nothing for the whole pack: each pattern accepted, with
its program's size, its lookarounds and the strings it scans for, or
refused and why).

**What it runs.** Literals and every escape of str patterns; classes with
ranges, negation and `\w \d \s \W \D \S`; `.` with and without DOTALL;
alternation; greedy and lazy `* + ? {m} {m,} {,n} {m,n}`; capturing, named
and non-capturing groups; `^ $ \A \Z \b \B`, with MULTILINE; the flags
`i m s x a u` as arguments, inline at the start and scoped (`(?i:…)`,
`(?-i:…)`); comments; lookbehinds (fixed width, as Python requires) and
lookaheads of bounded width, positive and negative, nested. 616 of the
pack's 657 patterns.

**What it refuses**, when the pattern is compiled, saying why (`Error {
refused: true }`; a pattern Python rejects is an error, with Python's
message): backreferences and conditionals (they need what a group matched);
a lookahead of unbounded width (`(?!\s*\()`: trying it may read the rest of
the text from every position); a repeat other than `?` whose body can match
the empty string (`(a*)*`: sre ends such loops by rules of its own); a
capturing group inside a positive lookaround; atomic groups and possessive
repeats; `\N{…}`; the TEMPLATE flag; a lookaround wider than 1,000
characters or nested more than 8 deep; and a program of more than 30,000
instructions once counted repeats are expanded.

**Answers.** `re`'s: leftmost-first, with greedy and lazy priorities; the
same spans and groups for search, match, fullmatch and finditer (the last
iteration's capture inside a repeat, None for a group the match did not go
through, lastindex the last group closed); finditer's rule after an empty
match; a lookbehind reads before `pos`, nothing reads past `endpos`, and a
match that starts past `endpos` (`match(s, 5, 2)`) answers as sre's does
(an empty pattern and MULTILINE's `$` match there, a one-character repeat
fails); `\b` and `\B` hold nowhere in an empty window at 0 (3.10–3.13, as
pyre); IGNORECASE and ASCII as sre compiles them, with unicode.rs's Unicode
13.0 tables (sre's lower and upper and its case fixes; a class is tested on
the lowercased character, or as written when it holds no cased character;
a range past the Basic Multilingual Plane on the lowercase and on its
uppercase). Where Python versions differ — an astral letter written in a
class under IGNORECASE, which 3.10–3.12 match in neither case, and an
astral range under ASCII and IGNORECASE — linre answers as 3.13 and later,
and pyre, do. A text is code points: a lone surrogate is a character like
any other.

**How it runs.** The parser keeps what `re`'s parser keeps where it changes
an answer (a one-character class is a literal, the item alternatives begin
with is taken out in front, alternatives of single characters become one
class); lowering resolves the flags item by item into character sets
(sorted ranges over all u32 values: the matchers test membership, they
never fold) and zero-width tests. From that, Thompson programs ordered by
priority: forward (with capture slots), fullmatch, reverse, one per
lookaround of more than one character, and the backtracker's copies, in
which a counted repeat of one set is a single `Run`. A search, in order:

1. Prefilters, each skipping only work that cannot match: strings one of
   which every match holds (a text gate answers at once for a text that
   lacks one of each string's character pairs), strings every match starts
   with (found by their rarest character, sixteen at a time), a set of first
   characters, and patterns that are one set or a greedy repeat of one,
   answered by scans alone.
2. Where a lead string or first character is found, an anchored try: the
   backtracker's for the first tries and, while most tries match, for a
   pattern with groups or large counted repeats; the anchored DFA's
   otherwise. The tries spend at most 8 steps per character the scan moves
   on, plus 4 per instruction and 256; past that, step 3 from there.
3. The lazy DFAs. Forward, leftmost-first (the threads after a match are
   cut), to where the match ends; reverse from there to where it starts
   (or the pattern's fixed width). A state is an ordered list of threads
   with facts about the neighbouring character, so one-character
   lookarounds and anchors are decided inside transitions; a longer
   lookaround is tried on the text — a set of states stepped over at most
   its width, nested ones one level deeper — and a state that has one keys
   its transitions by the outcomes. Each DFA keeps at most 2 MB of states;
   a search that would empty them too often gives up to the Pike VM.
4. The groups: the backtracker, in sre's order, on the match's span only,
   visiting each (instruction, position) once; a span too long for its
   visited bits (2 MB) goes to the Pike VM.
5. The Pike VM (threads in priority order, each with its slots) answers
   what the DFAs give up on.

**Complexity.** For a text of n characters and a program of m instructions
(counted repeats expanded): the DFAs read each character a bounded number
of times, one table entry each once the transition is known (a new one
costs O(m)); a lookaround of width w costs O(w·m) where it is tried; the
anchored tries cost at most 8n + 4m + 256 steps in all; the backtracker
visits each (instruction, position) once; the Pike VM is O(n·m). So
O(n·m) at worst: linear in the text for every accepted pattern, whatever
the text. No recursion on the text, and no panic on any text of any u32
values. Compiling costs more than pyre's: the 300 patterns of a scan take
113 ms against pyre's 35 ms.

**Tests.** `cargo test --release` (`linre/tests.rs`, `linre/charset.rs`):
the syntax the pack uses compiles, Python's errors are errors, each refusal
says why; flags inline and as arguments; answers checked against Python's;
the matchers against each other — the public calls, the Pike VM alone and
the backtracker alone (sre's search: a try from each start in turn) — on
35 hand-written patterns and 12,000 seeded random ones (some 8,600 of
which compile), on random texts of letters, the edge characters and lone
surrogates, in windows too; 20,000 seeded garbage patterns and texts of
arbitrary u32 values without a panic; and adversarial texts of 20,000
repetitions read at once. Against Python's `re`, from `python/` (each
module in under 10 s; skipped without the library):

```bash
export LAZARET_NATIVE_LIB=$PWD/../rust/target/release/liblazaret_native.so
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_linre         # ~8 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_linre_b       # ~7 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_linre_c       # ~8 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_linre_d       # ~2 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_linre_linear  # ~3 s
```

- `test_linre`: every accepted pack pattern on the regex corpus
  (`_rust_regex_corpus`), the hand-written texts and the edge characters one
  by one (ſ, K, İ, ı, U+0085, U+00A0, U+001C–U+001F, U+2028, astral letters
  and symbols, lone surrogates), at 0, in windows (inside the text, and past
  each other) and with a text gate: 140,000 texts. And `linre.check`: what
  is refused is refused for a known reason, and at least 90% of the pack is
  accepted.
- `test_linre_b` and `_c` (half of the patterns each): texts sampled from
  each pattern's parse tree (`_linre_inputs.sample`: a branch, a repeat's
  count at or next to its bounds, a class's member — a range's ends, a
  category's members, the edge characters —, a letter's case under
  IGNORECASE, what a lookbehind wants before and a lookahead after), some
  of them mutated: about two thirds of them match, and many others nearly
  do. 80,000 texts.
- `test_linre_d`: pyre's hand-written patterns (each construct `re`
  supports for str patterns: linre runs 120 of the 141 and refuses the rest
  for a known reason), about 100 of linre's own (lookarounds of several
  characters, nested and at a window's ends; anchors; flags; IGNORECASE
  past ASCII; astral characters; counted and lazy repeats at their bounds;
  empty matches; lastindex; the literal scans' corners), and linre against
  pyre on 300 random classes of astral and other letters under IGNORECASE
  and ASCII: 110,000 texts.
- `test_linre_linear`: linear time, below.

Every text goes through search, match, fullmatch, finditer, sub and split
in both, at 0 and in windows: no difference, on Python 3.10, 3.11, 3.12 and
3.13. (The sampler keeps the unbounded repeats of more than one character
short: `re` itself takes exponential time on a near miss of some of them.)

**Linear time.** Pack patterns on texts that make a backtracking matcher
backtrack, through `pyre.probe` and `linre.probe` (all six operations), best
of three:

| Pattern, text | pyre | linre |
|---|---|---|
| `_SVC_LAUNCHCTL_RE`, "launchctl" + " --a" × k + " x" (`-{1,2}[\w-]+` reads "--a" two ways: 2^k paths) | k = 10: 2.1 ms; 12: 7.7 ms; 14: 30 ms; 16: 120 ms | k = 1,000: 0.5 ms; 100,000: 12 ms |
| `_DD_PARAM_RE`, n blanks (two `\s*` in a row, from every start: n³) | n = 100: 5.9 ms; 200: 35 ms; 400: 226 ms | n = 100,000: 2.5 ms; 200,000: 4.9 ms |
| `_JSON_COLON_RE` (`[ \t\n\r]*:`), n blanks (n²) | n = 1,000: 8.3 ms; 2,000: 33 ms; 4,000: 135 ms | n = 100,000: 2.5 ms; 200,000: 4.9 ms |

`_LD_CALLED_RE` (`\s*\(`) and `_DL_JOIN_CHAIN_RE` grow as `_JSON_COLON_RE`
does. The test asserts the growth (pyre: more than eightfold for two more
pieces, more than tenfold for four times the text; linre: less than
eightfold for four times the text) and that linre reads a million
characters of each in under 2 s.

**Measurements.** Every regex call of a scan of the 1,500-file sample (22
MB): the scanner's calls recorded with their texts, `pos`, `endpos` and
text gate, then replayed through both engines in one process, one thread,
release build, three runs. 300 patterns, 1,465,383 calls, the same answers
from both. On the 283 patterns linre accepts: **pyre 6.50 s, linre 2.79 s**
(43%); the 17 it refuses take pyre 0.39 s. By operation, pyre → linre:
search (501,178 calls) 1.44 → 0.54 s; match (685,921) 0.30 → 0.12 s;
finditer (175,360) 4.41 → 2.01 s; sub (34,773) 0.35 → 0.12 s; fullmatch
and split, 1.8 → 1.2 ms and 1.3 → 1.2 ms. The largest gains are on patterns
sre tries at every name or every blank: `_PX_OBJECT_RE`
(`(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*\{`) 795 → 128 ms, `_DD_ASSIGN_RE`
754 → 345 ms, `_DV_CALL_RE` 397 → 66 ms, `_LD_TUPLE_ASSIGN_RE` 393 → 85 ms,
`_PX_USE_RE` 302 → 47 ms, `_LD_PATH_EXPR_RE` (`\s*(?:(?:path|os\s*\.\s*path|…)…`)
164 → 21 ms, `_DL_STR_RE` (`"(?:\\.|[^"\\])*"|…`) 164 → 16 ms.

linre is slower on 118 patterns (on 90 of them in all three runs), which
take pyre 225 ms and linre 252 ms: 78 by more than 1.2×, 10 of those on
more than 1 ms of pyre's time; 42 by more than 1.5×, two on more than
1 ms (`_SC_SINK_WORD_RE`, 1,668 searches, 4.8 → 7.7 ms; `_DEP_ASSIGN_RE`,
977, 3.8 → 5.7 ms); 12 by more than 2×, each on less than 0.1 ms in all,
over a few calls. Why: the first calls of a pattern build its buffers and
its first DFA states, which pyre has no need of (the patterns over 2×, and
the patterns the scanner builds for one name, `name(?<![\w$]name)(?![\w$])`);
fixed costs per call on many short texts (`_NAME_ESCAPE_RE`, 10,814
finditer calls on texts of 7 characters, 9.9 → 13.3 ms; `_LD_NAME_TOKEN_RE`,
10,640 windows of 14 characters, 11.3 → 14.2 ms); and a long match read
three times — forward, reverse, groups — where sre reads it once
(`_DEP_ASSIGN_RE`'s `([^;]*)`). The module adds 178 KB to the WebAssembly
build (2.45 MB → 2.63 MB).

**The pack's 41 refusals, with a rewrite** (`linre.check` lists them):

- *A quote matched again* (10): `_DEPS_LOCAL_DEP_RE`, `_DNS_CMD_SUM_RE`,
  `_DV_ESCAPED_LITERAL_RE`, `_KEYED_READ_RE`, `_KEYED_WRITE_RE`,
  `_LD_HOST_BUILT_RE`, `_LD_PLAIN_LITERAL_RE`, `_ROUTE_RULE_RE`,
  `_XF_EMIT_RE`, `_XF_LISTEN_RE`. The text between the quotes cannot hold
  a quote (or stops at the first one), so one branch per quote character
  gives the same spans and the same text in the groups (the quote's own
  group goes, the others are numbered anew): `(["'])([^"'\\\n]*)\2` is
  `'([^"'\\\n]*)'|"([^"'\\\n]*)"`, `\(\s*[rRuU]?(["'])(.*?)\1` is
  `\(\s*[rRuU]?(?:"([^"\n]*)"|'([^'\n]*)')` (checked with `re` on random
  texts).
- *The same name twice* (3): `_DV_CC_FOR_RE` (`\1`, the loop's variable),
  `_DV_CC_LITERAL_RE` (`\5`, the comprehension's), `_SA_CHECKSUM_RE`
  (`(?P=v)`). Not a regular language: capture the second name too, compare
  the two in code, and on a difference search again from the next start.
- *Blanks before a lookahead's test* (13): `TAINT_SINKS['js'][9][1]`,
  `TAINT_SOURCES['js']`, `_DL_CALLBACK_RE`, `_DL_COMMA_CALL_RE`,
  `_INDIRECT_SINK_RE`, `_KWARG_RE`, `_LD_ALIAS_JS_RE`, `_LD_CLIENT_RE`,
  `_LD_ENV_ALL_RE`, `_LD_FIRST_MEMBER_RE`, `_LD_MEMBER_READ_RE`,
  `_XF_JS_EXPORT_LIST_RE`, `_XF_JS_REQ_NS_RE` (`(?!\s*\()`, `(?![ \t]*\.)`,
  `(?=\s*\()` …): bound the blanks, `(?!\s{0,64}\()`, which answers
  differently only after 64 of them.
- *A lookahead over the rest of an argument list or a string* (10):
  `RULES[7]` (`(?![^()]*\)\s*\{)`), `RULES[9]` and
  `TAINT_SINKS['js'][3][1]` (an argument list), `_DL_DESERIAL[0]`, `[1]`,
  `_DL_DESERIAL_CANDIDATE_RE` and `_DL_DESERIAL_RE` (whose `{0,400}?` is
  bounded but whose `\([^()]*\)` is not), `_NON_HTML_CHAIN_RE` and
  `_NON_HTML_TYPE_RE` (`(?![^"'`]*(?:html|xml|svg))`),
  `_XF_JS_MODEXP_FN_RE` (`\([^()]*\)`): bound them (`[^()]{0,400}`, as
  `_DL_DESERIAL_RE` already bounds its outer loop).
- `RULES[50]` (1) is SQL-DYNAMIC, which the engine already matches by hand
  in linear time (`linear.rs`).
- *An exact rewrite* (2): `_LD_ENV_QUIET_RE`'s
  `npm_(?:package|lifecycle|config)_(?![\w]*(?:auth|token|passw|secret))\w*`
  is `npm_(?:package|lifecycle|config)_(?:(?!auth|token|passw|secret)\w)*`
  (the test at each character of the name, of bounded width; checked with
  `re` on random texts); `_JWT_CANDIDATE_RE`'s empty match before a token
  can take the token in, where only its start is used
  (`(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{13,}\.eyJ[A-Za-z0-9_\-]{10}`).
- *Too large* (2): `RULES[47]` (`(?:[^{}]|\{[^{}]{0,2000}\}){0,2000}`:
  millions of instructions expanded) and `_DV_ARRAY_RE` (up to 64 strings
  of up to 400 characters): unbounded repeats in place of the large counts
  (`(?:[^{}]|\{[^{}]*\})*`) answer differently only past those counts.
