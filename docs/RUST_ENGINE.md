# Lazaret's native scanning engine (Rust)

Status, October 2, 2026: since the Rust-first refactor (phase 1 of §8) the
native engine is Lazaret's only engine. The Python reference engine is
retired — its detectors, the per-file rules and the cross-file follower are
the engine's alone, `--engine` is gone — and the engine is held to its own
recorded outputs (§5) instead of to a Python twin. The rule pack is the
source of the rules. Every wheel carries the engine, and the sdist its
sources, which pip compiles where no platform wheel fits (§4). What the
Python package still does in Python: walking a project, reading archives,
the registry and the guard, the manifest and workflow checks, project
mode's passes after the rules (SQL, function metrics), the suppression
markers and the reports; project mode's taint is the engine's, for
JavaScript and for Python (phase 3: `js_flow`, §16; `py_flow`, §17), in
both packages. Since 0.1.8 the npm
package runs the same engine compiled to WebAssembly
(`native/lazaret.wasm`). The JavaScript parser (`js_parse`, §12: the port
of jsparse.py, held to its trees node for node until phase 3 retired it),
the Python parser (`py_parse`, §13: Python 3.13's `ast` trees, node for
node) and a linear-time regex engine (linre, §14) are in place for the
phases that follow; every pattern of the engine runs on linre (P-16), and the
engine's lexers (§15) read JavaScript and Python for every caller that asks
where a text's comments and literals are.

## 1. What it is

One native engine, written in Rust, used by both distributions. Until the
Rust-first refactor the Python engine was the **reference implementation**,
selectable at run time (`--engine python`), and the two gave identical
answers, proven by differential tests field for field (§5 keeps the
record). Holding the engine to a Python twin meant every detection change
landed twice and the engine could be no better than its twin's structure —
pattern windows where a parser and scopes would do, a backtracking matcher
where a linear one would — so the twin is retired: the Rust engine is the
reference, held to its recorded outputs, and a change to what it finds is a
reviewed difference in those outputs. The npm package runs the same engine
as WebAssembly (0.1.8). What the npm package still does in JavaScript
(source decoding, the suppression markers, the manifest and workflow
checks, the SQL and function passes of project mode, reporting) is held to
the Python package by the CLI-level parity tests (`test_js_parity*`); its
comment layout is the engine's lexers' (§15), and its taint the engine's
passes (§16, §17).

Decisions (fixed):

| Topic | Decision |
|---|---|
| Dependencies | **No external crates.** Own regex engine (linre, §14; until P-16 also a port of CPython's sre), JSON, Unicode tables, parsers. `Cargo.lock` lists only the workspace; `scripts/check_rust_deps.py` fails CI otherwise. |
| Bindings | **C ABI + ctypes** for Python (no compiled extension, one library per platform serves every Python version); **WebAssembly** for Node (Node's own `WebAssembly`, no imports, no npm dependency). |
| Rule source | **The pack is the source.** `rust/crates/lazaret-engine/rules/lazaret-rules.json` holds the engine's patterns, sets, limits and finding texts and is edited by hand (it was extracted from `core.py`, which no longer holds them). `scripts/make_rust_tables.py` keeps it in its canonical form, and `--check` holds it there: every pattern compiles with Python's `re` (the syntax the engine reads), its `rule_set` is the registry's `ENGINE_VERSION`, and the values core still keeps for the Python side (the reasons the registry ranks, the walk's limits) are the pack's. Python reads the pack through the engine (`engine.pack_value`, `engine.pack_pattern`). |
| Engine shape | Generic engine plus data: declarative rules come from the pack, the algorithms are Rust functions (ported from core's, function for function, until the refactor; rebuilt on the parsers in the phases that follow, §8). |
| Calls | Whole files, batched: one crossing of the boundary per batch of files, read on threads (`std::thread`), answers in input order. |
| License | The engine is Lazaret's own work, Apache-2.0, with Unicode data under the Unicode License v3: the crates are `Apache-2.0 AND Unicode-3.0`. Its translations of CPython code are retired (P-16). The platform wheels, the sdist and the npm package are `Apache-2.0 AND Unicode-3.0` too (§11). |

## 2. Using it

- `lazaret …` and `lazaret-registry …` run the native engine; `--version`
  names it: `lazaret 0.1.8 (engine: rust 0.1.8)`. Without the library the
  scanning commands stop with exit code 2 and say what is missing
  (`engine.require`): there is no engine to fall back on. The workspace
  version (`rust/Cargo.toml`) is the release the engine ships in.
- The library is `lazaret/_native/<library>` in a wheel: a platform wheel
  for Linux x86-64 and ARM64 (manylinux_2_28), macOS arm64 from 11.0 and
  x86-64 from 10.12, and Windows x64; anywhere else pip builds a wheel from
  the sdist, compiling the engine with cargo (Rust is needed there: §4).
  An editable install puts it in `src/lazaret/_native/`, and
  `LAZARET_NATIVE_LIB` names another copy (a development build).
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
  checked between batches), on up to 8 threads. **A file the engine can't
  answer about** (its work budget spent on a hostile file, an error, a
  caught panic) **is SC-TRUNCATED**, CRITICAL, so its scan can never be
  cleared: "reading it spent the engine's work budget" for the budget, "its
  scan failed" for an error (`engine.error_issue`), in `scan_file` and in the
  import-time and use-time tests alike, as in the npm package. In a registry
  or guard scan a manifest the engine can't read is SC-TRUNCATED too, and a
  call it can't answer in a later step (the install hooks, the install
  scripts, the import-time code …) marks the release, naming the step, and
  the next step runs: the release is INCOMPLETE, never cleared.
  `engine.WORK_BUDGET` sets the budget (steps of the regex matcher; by
  default the engine's, about 4e9).
- `scan_file` in project mode (your own files) is the engine's too, whole
  (0.1.9, Q-1; `engine.scan_files`, in the same batches on the same
  threads): the rules part — every pattern rule and family on every line,
  the file-level rules and `TEXT_RULES` — then the SQL statements without
  WHERE, the intra-file taint, the SQL-sink pass and the function metrics,
  then the suppression markers and the cap (`project.rs`, `taint.rs`). A
  taint configuration (`--taint-config`, a trusted `.lazaret-taint.json`)
  goes with each Python and JavaScript file's call as its `"taint"`
  argument (`core.taint_args`: what `core.apply_taint_config` validated and
  kept). A file the engine doesn't answer about is SC-TRUNCATED, as in
  dependency mode; no clock bounds the scan, only the work budget, so a
  file gets the same findings on every machine.
- The cross-file follower (`engine.cross_file_issues`, for `--deps`,
  registry and guard scans) is one `cross_file` call per scan: the
  dependency files one after another in the text (`[path, lang, length]`
  each in the arguments; `groups`, the package a Python file of a `--deps`
  scan is read in when a distribution's RECORD joins top-level modules:
  `core._xf_site_groups`), each package on its own work budget, on up to 8
  threads, the findings in the follower's order. A package the engine
  reports as failed (its budget spent, an internal error) gives no
  cross-file finding, and neither does a call the engine refuses, as in the
  npm package.
- **The npm package** (0.1.8) loads `native/lazaret.wasm` with
  `js/src/lib/native.js` (`npm run build` makes it from `rust/`; the
  published package carries it). Everything the supply-chain tests answer —
  install scripts and the hooks they run, import-time code, received code,
  the decoded view, spawned scripts, persistence, the exfiltration shapes, a
  hook command read as a program — is the engine's, and so are the
  cross-file follower (`crossFileIssues`: each file encoded on its own, its
  length in code points) and `scan_file`, whole in both modes (project
  mode's passes since 0.1.9, Q-1: the npm package's `taint.js`, `sql.js`
  and `functions.js` are retired). Core's tables the JavaScript side still reads
  (limits, `RULES` for S-TOKEN) come from the pack too (`packValues`). There
  is no second engine to fall back on: a call that spends its work budget (a
  hostile input) leaves its file SC-TRUNCATED, CRITICAL and so never cleared
  ("reading it spent the engine's work budget" from `scan_file`; "its scan
  failed" from a dependency check), as in the Python package; a package
  whose follower budget is spent gives no cross-file finding. Without
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
  NOTICE                     the engine's notices, and what was CPython's (§11)
  LICENSE-UNICODE            the Unicode License v3, for generated/unicode13.rs and
                             pyparse/unidata.rs (§11)
  crates/lazaret-engine/     #![forbid(unsafe_code)], no I/O; one dependency, lazaret-verify (its SHA-256)
    rules/lazaret-rules.json the rule pack: the source of the rules (embedded; `pack.install` can
                             replace it)
    src/api.rs               the calls by name (JSON args + text -> JSON; `budget`); `batch` on
                             threads; `pack.values` (core's values, for the npm engine)
    src/budget.rs            per-call work budget -> Exhausted (both packages: SC-TRUNCATED)
    src/pack.rs              the pack: values by core's names, patterns compiled on first use
    src/json.rs, pystr.rs    JSON; Python str semantics on code points ([u32])
    src/unicode.rs           Python 3.10 / Unicode 13.0 predicates (generated/unicode13.rs)
    src/pyre.rs              re's calls as the engine's code makes them, on linre (§6)
    src/linre/               a linear-time regex engine with re's answers, which every pattern
                             runs on (§14): parser, sets, programs, lazy DFAs, memoized and
                             swept lookaheads, backtracker, Pike VM, prefilters
    src/scan.rs              pystr's find: a string by its rarest character
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
                             whose strings need one the text lacks answers at once; for a long
                             text, where each pair stands, and what the call's tests read of it
                             more than once (its tokens)
    src/flow.rs              local data followed to where it is sent (local_data_sent_at), a
                             webhook's secret in the code (secret_endpoint_at)
    src/shell.rs             a shell text read as a program (_sh_parse … _sh_reasons), the command
                             lines a script hands a shell (exec_command_reasons), and what a
                             pipeline decodes or downloads and hands a shell or an interpreter
                             on stdin (piped_runs, 0.1.9)
    src/datafmt.rs           a whole file of a data format, read by its structure (a WebAssembly
                             module, a PNG, GIF or WebP image, WAV audio): SC-B64 passes over its
                             base64 (0.1.9)
    src/strarr.rs            javascript-obfuscator's string arrays and proxy objects, for the
                             decoded view
    src/lex/                 the lexers (§15): js.rs (JavaScript, TypeScript, JSX: templates and
                             their holes, regular expressions), py.rs (Python, with pyparse's
                             tokenizer), go.rs and rs.rs (Go and Rust: raw strings, runes and
                             characters, Rust's nested comments and lifetimes), mod.rs (what the
                             detectors ask: comments, strings, literals, two readings
                             intersected), value.rs (literals' values, the runs a runtime joins)
    src/lexer.rs             lex_comment_spans, every caller's: JavaScript, Python, Go and Rust
                             from lex/, SQL (two readings) and any other text by the pack's
                             patterns (§6)
    src/filectx.rs           a file as scan_file reads it (_FileCtx): lines, comment layout,
                             match text (NFKC, JS escapes), names
    src/scanfile.rs          scan_file in dependency mode, scan_rules (project mode's rules
                             part), family by family; per-line gates; scan_file in project mode
                             (scan_project: the rules part, then project.rs)
    src/project.rs           project mode after the rules (core's _project_passes, 0.1.9): SQL
                             statements without WHERE, the SQL built from strings into execute(),
                             the function metrics (functions), then the suppression markers and
                             the cap
    src/metrics.rs           a project file's line metrics (core.compute_metrics' part for one
                             file, 0.1.9, Q-1 step 4): comment lines, lines of code, the windows
                             of six lines of code keyed for the duplication; from the scan's own
                             reading (scan_file with "metrics") or on their own (file_metrics)
    src/taint.rs             project mode's intra-file taint (core.taint_scan, 0.1.9): sources,
                             sinks, sanitizers, guards, scopes, Flask views and route parameters;
                             a taint configuration's sources, sinks and sanitizers for one call
    src/secrets.rs           live secret verification's table and logic (0.1.9, V-1 stage 2):
                             the pack's _VERIFY_PROVIDERS read and checked; `secrets.find` (the
                             credentials of a file's flagged lines; AWS's pairs), `secrets.identify`,
                             `secrets.request` (a call that only authenticates; AWS's signed with
                             Signature Version 4: HMAC over lazaret-verify's SHA-256),
                             `secrets.judge` (live, rejected or unknown, why, whose); each package
                             makes the call
    src/linear.rs            rule patterns sre runs in more than linear time on some lines,
                             matched by hand in linear time (SQL-DYNAMIC)
    src/findings.rs          mk_issue: texts, snippets, redaction (_SecretLiterals); cap_issues
    src/token.rs             _TokenPattern (S-TOKEN, redaction): JWTs in linear time
    src/normalize.rs         NFC / NFD / NFKC / NFKD (UAX #15, Unicode 13.0 data)
    src/jsparse/             the JavaScript parser (a port of jsparse.py: §12): scan.rs (literals,
                             character classes, the token patterns by hand), parser.rs (tokens,
                             reads ahead, statements, classes, modules), expr.rs (expressions,
                             patterns, JSX), types.rs (TypeScript's types), tree.rs (the arena),
                             out.rs (JSON)
    src/jsflow/              project mode's cross-file JavaScript taint (a port of jsflow.py, §16):
                             mod.rs (values, scopes, bindings, declaration and resolution),
                             descs.rs (points-to, call targets, routes, order), eval.rs (one
                             reading of a function), driver.rs (the fixpoint, the output);
                             supply.rs (its supply-chain model: local data followed to a
                             network send, and received data to code run, in an install
                             script or a dependency's code, §18)
    src/jsloads.rs           what a JavaScript module loads when it runs (js_loads, 0.1.9, D-13): the
                             specifiers of its require() calls given a literal outside any function,
                             class body and try statement, of its import and export-from
                             declarations and of its import() calls, on js_parse's tree, with the
                             npm package each names; the registry compares them with package.json
    src/pyflow/              project mode's cross-file Python taint (a port of flow.py's Python
                             pass, §17): mod.rs (the model: modules, functions, classes, names,
                             imports, resolution, the frames), eval.rs (one reading of a
                             function), driver.rs (the files, the fixpoint, the output),
                             frameworks.rs (route parameters), unparse.rs (ast.unparse)
    src/quickhash.rs         a quick hash for maps keyed by the engine's own numbers
    src/pyparse/             the Python parser (Python 3.13's ast trees: §13): lexer.rs (tokens,
                             f-strings in pieces), parser.rs (statements, which error Python
                             reports), expr.rs (expressions, targets, arguments, strings),
                             pattern.rs (match patterns), literal.rs (values), unicode.rs and
                             unidata.rs (Unicode 15.1: identifiers, NFKC, \N{} names), limits.rs
                             (Python's nesting limits), tree.rs (the arena), out.rs (JSON)
    examples/                profiling tools (profile_calls, profile_scanfile, pattern_times,
                             pattern_stats, show_need, jsparse_bench, pyparse_bench, pyflow_bench)
  crates/lazaret-ffi/        cdylib liblazaret_native: Lazaret's only `unsafe` (the C ABI; the
                             WebAssembly exports; natively, the network layer's `lazaret_net_*`
                             and the `verify.*` calls: `verify.go_sumdb`, `verify.sigstore`)
  crates/lazaret-verify/     tiny_https's pure part (no I/O, no `unsafe`, wasm32): signatures,
                             certificate chains, transparency logs, attestations; `gosum`, the
                             Go checksum database's lookup checked in two steps; `provenance`,
                             npm's and PyPI's attestations of a file: verified, invalid or
                             unchecked (NET-1)
  crates/lazaret-net/        the network layer on tiny_https: Lazaret's host rule on every hop,
                             URL limits, budgets, credentials given hop by hop to their own
                             host (tiny_https's hop hook, decision 14); native library only
                             (NET-1, DESIGN.md §5j)
  crates/tiny_https/         the HTTPS/TLS library, taken as it was handed over
                             (scripts/sync_tiny_https.py; LAZARET.md, vendored.sha256); not a
                             default member: `cargo test -p tiny_https` runs its own tests
  .cargo/config.toml         the WebAssembly build's stack (8 MiB, placed first)
python/src/lazaret/scanner/_native.py   ctypes loader and one call (NativeError, NativeExhausted)
python/src/lazaret/scanner/nativenet.py the network layer from Python: the default transport, urllib
                                        behind it (NET-1)
js/src/lib/native.js                    the npm package's loader: WebAssembly, one call, the pack's
                                        values, a wrapper per call the npm engine makes
js/scripts/build-wasm.js                `npm run build`: native/lazaret.wasm and native/NOTICE
                                        (js/native/ is built, not committed)
js/src/pool.js, pool-worker.js          the npm CLI's worker threads, each with its own instance
python/src/lazaret/scanner/engine.py    the engine's calls: batches on threads, the budget, what an
                                        unanswered call becomes (SC-TRUNCATED)
python/_build/lazaret_build.py          every wheel a platform wheel: a named library (release CI) or
                                        one compiled with cargo; the sdist carries rust/
scripts/make_rust_tables.py             the pack's canonical form and checks (any Python) and
                                        unicode13.rs (3.10); --check
scripts/make_pyparse_tables.py          pyparse/unidata.rs (Python 3.13); --check
scripts/check_rust_deps.py              Cargo.lock and the manifests hold only the workspace
scripts/check_native_library.py         a built library against its wheel's tag; --dist: the release's wheels
.github/workflows/wheels.yml            the five libraries, the wheels and the sdist, installed on each
                                        platform (the sdist built by pip on Linux)
python/tests/architecture/test_snapshot_{hooks,signs,scanfile,lexer,hook_commands,small,crossfile,
  js_flow,js_parse,py_flow}.py,         the engine's recorded outputs (§5); scripts/snapshot.py records
  _snapshots.py, snapshots/             and compares them
python/tests/architecture/test_lex.py   the lexers against js_parse's literals and Python 3.13's
                                        tokenize (§15)
python/tests/architecture/test_rust_parity_regex.py, test_wasm_parity{,_signs,_crossfile,_jsparse,
  _jsflow,_pyparse,_pyflow}.py, test_jsparse_native.py, test_pyparse_native{,_b,_c}.py,
  test_rust_deps.py, test_rust_pack.py, hooks_corpus.py, scanfile_corpus.py, crossfile_corpus.py,
  jsparse_cases.py, jsgen.py, pyparse_cases.py, pyparse_oracle.py, pygen.py,
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
`catch_unwind`; `batch`, `pack.*` and `texts.*` are refused inside a batch on
threads; under WebAssembly a batch runs on one thread.

Live secret verification (0.1.9, V-1 stage 2, John's decision 7; `src/secrets.rs`): the provider table is
the pack's `_VERIFY_PROVIDERS` (checked when first read, by the rules `scripts/make_rust_tables.py --check`
holds the pack to: `lazaret.scanner.secretverify.validate`). `secrets.providers` → `[{"id", "label", "host",
"path", "parts"}]`; `secrets.identify` (the text) → the ids whose one-part pattern matches all of it;
`secrets.request` `{"provider": id | "entry": {…}, "parts": {name: text}, "time": "YYYYMMDDTHHMMSSZ"}` →
`{"method", "host", "path", "headers": [[name, value]], "secret_headers": [names], "body"}` or
`{"refused": why}`; `secrets.judge` `{"provider": id | "answers": [rules], "status", "truncated", "secrets"}`
with the body as the text, one code point a byte (at most 64 KiB) → `[outcome, why, who]`; `secrets.find`
`{"lines": [n, …]}` with those lines of one file joined by "\n" as the text → `[{"provider", "parts":
{name: text}, "lines": [n, …]}]`, the credentials the providers name in them (a word, a run of letters,
digits and `_-+/` or a piece of one between slashes, that is all of a one-part provider's format; an id and
a secret of a provider of two parts, AWS's, paired nearest lines first: 8 pairs at most, of 64 ids and 64
secrets), for `lazaret scan --verify-secrets`. The engine has no clock and no network: each package gives
the time and makes the call. JSON in an answer is read as RFC
8259 has it (a key's last value counts, as Python's json keeps it; NaN and Infinity are not numbers, which
Python's json takes, so an answer holding one is unknown where stage 1's Python could read it live). The
engine's JSON reader now refuses a number RFC 8259 does not allow (`01`, `1.`, `.5`), which nothing Lazaret
writes holds. Held to stage 1's Python on 53,760 answers, 2,800 requests (AWS's signatures at random
times among them) and 5,500 texts with no difference. One change from stage 1, on purpose: a part of the
credential is looked for in all of the owner's name an answer gives before it is cut to 80 characters, and
parts that overlap are one `[redacted]` (stage 1 looked in the first 320 characters, so a part over 240
characters long that began in the first 80 kept its start).

The text store (0.1.9, FE-1; `src/texts.rs`): `texts.put` with
`{"lengths": [code points, …]}` and the texts one after another as the text
(Python: `"".join(texts).encode("utf-8", "surrogatepass")`) keeps each text as
the bytes it came as, checked as it is cut, and answers `{"ids": [n, …]}`;
the library's entry point takes them before reading the text into code points,
so a text is not held four times its size. Any call then takes `"text_id": n`
in its arguments in place of a text (alone or in a batch: each call reads the
text into code points on its own thread), and `cross_file` takes
`"text_ids"`, one per file, with no text. `texts.drop` `{"ids": […]}` lets them
go (`{"dropped": n}`), `texts.info` says what the store holds. The store is
the process's, behind a lock, and bounded (`texts::MAX_BYTES`, 1 GiB): a put
past it keeps nothing and is refused, and the caller sends those texts with
its calls as before. A registry scan puts each distinct text once
(`engine.Texts`), names it in every step, and drops its texts when it ends,
in a `finally` (`repo.scan_members`).

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

Every wheel is a platform wheel: there is no pure (py3-none-any) wheel,
since the package has no engine without the library. `python
python/_build/lazaret_build.py dist/ --platform <tag>=<built library>`
(repeatable; it also writes the sdist), or `LAZARET_NATIVE_LIBRARY` and
`LAZARET_WHEEL_PLATFORM` for the PEP 517 hook, gives
`lazaret-<v>-py3-none-<tag>.whl`: the package's files,
`lazaret/_native/<library>`, and `rust/NOTICE` as a license file beside
`LICENSE` and `LICENSE-UNICODE`, with
`License-Expression: Apache-2.0 AND Unicode-3.0` and
`Root-Is-Purelib: false`. The sdist carries the engine's sources under
`rust/` (the workspace's `Cargo.toml` and `Cargo.lock`, each crate's
`Cargo.toml`, `src/**/*.rs` and `rules/*.json`, and the notices; not the
examples, the tests' corpora or `target/`), the license files at its root
too, and the same license fields; never a library.

**From source**: `pip install lazaret-<v>.tar.gz` (what pip does where no
platform wheel fits), `pip install .` in `python/`, or the backend run
without `--platform`, compiles the engine: `cargo build --release --offline
--locked -p lazaret-ffi` in the sdist's (or the checkout's) `rust/`, with
`MACOSX_DEPLOYMENT_TARGET` set to the release wheels' minimum on macOS and
the C runtime linked statically on Windows. Since NET-1 the library holds the
network layer too (`lazaret-net` on tiny_https, whose sources the sdist
carries: its manifest, licence and the test and example sources cargo reads,
not its test data), and building it needs Rust 1.87 or later (tiny_https's
SIMD kernels call the architecture intrinsics as safe functions). The backend then loads the
library to check that it is this release's and loads in this Python, and
tags the wheel for this machine (`linux_x86_64`, `win_amd64`,
`macosx_11_0_arm64` …). Without cargo it stops and says to install Rust
(`rust-version` in `rust/Cargo.toml` or later) or a platform wheel; a build
takes about a minute. `pip install -e .` compiles it the same way and puts
it in `src/lazaret/_native/`, which is never packed from there: after a
change to the engine, install again or point `LAZARET_NATIVE_LIB` at a
fresh build.

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
§5's and §7's measurements; the runner's rustup installs it and checks each
component's published SHA-256), `--release --offline --locked`. The Linux
jobs mount that toolchain read-only into the image, so the library links
against the image's glibc 2.28; building on the runner itself would need
its glibc (2.39). Each library is then checked against its tag
(`scripts/check_native_library.py LIB TAG --load`: machine, the glibc and
libgcc_s symbol versions and libraries manylinux allows, no RPATH or
executable stack; the Mach-O minimum macOS and system-only dylibs; a PE DLL
with ASLR and DEP and no Visual C++ or MinGW runtime; the three exports;
then loaded as `_native.py` loads it, reporting the package's version and
giving one call its known answer), and the whole Python suite runs on it on
its platform (the Linux ones inside the image), the recorded outputs (§5)
among it. The `dist` job builds the sdist and the five platform wheels from
one checkout (Python 3.12.14, `SOURCE_DATE_EPOCH`), and
`check_native_library.py --dist` holds the sdist to the engine's sources
and no library, each platform wheel to the sdist's package files plus its
library and license files, and its METADATA to the sdist's PKG-INFO; a pure
wheel is an error. The `install` job then installs each platform wheel with
pip, from those files only, on its platform, and runs `python -m lazaret
--version` (`lazaret X (engine: rust X)`); on Linux x86-64 pip also builds
the sdist, compiling the engine with the pinned toolchain, and that install
runs too. On Linux a build is reproducible: the same commit, toolchain and
image give the same library bytes wherever the checkout is (cargo passes
workspace paths relative). Given the same five libraries, the six files are
too; the Windows linker, though, stamps a time into the DLL.

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

CI (`.github/workflows/ci.yml`): every job that runs Python tests builds
the library first (the runner's Rust, `--release --offline --locked`) and
asserts that it loads, since the engine's own tests skip without it (a
workflow test holds every such job to that). `python-unit` (Linux, macOS,
Windows; Python 3.10–3.14) runs the whole suite on it, the recorded outputs
included. Job `rust` (the three systems): `check_rust_deps.py`,
`make_rust_tables.py --check` (on 3.10), `cargo test`, the build, and the
WebAssembly build against the library (`test_wasm_parity`, `_signs`,
`_crossfile`, `_jsparse`, `_pyparse`). Job `js` (Node 22 and 24 on the
three systems) builds the module with the runner's Rust, runs `npm test`,
and on Node 24 the CLI-level parity modules (`test_js_parity*`, the npm
package against the Python package; they skip without the module, so the
step first asserts that it loads).

Versions: the workspace version is held to the Python and npm packages'
(`scripts/check-versions.sh` reads `rust/Cargo.toml` and the two entries of
`rust/Cargo.lock`), so the engine reports the version of the release it
ships in. A release bump changes all three; `cargo update --workspace
--offline` in `rust/` rewrites the lock file.

## 5. The recorded outputs

The engine is held to its own answers as they were last reviewed. A
snapshot test runs a seeded input set through the engine and compares its
outputs with `python/tests/architecture/snapshots/<set>.txt`: one hash per
100 outputs (the first 16 hex digits of the SHA-256 of their canonical
JSON), so a change fails with the chunks it moved. **A change to what the
engine finds is a reviewed difference**: record the set with the engine
before and after the change (`scripts/snapshot.py record <set> --out
before.jsonl.gz`, then `--out after.jsonl.gz`), read every case that
differs (`scripts/snapshot.py diff before.jsonl.gz after.jsonl.gz`), and
once the differences are accepted, write the new hashes
(`LAZARET_SNAPSHOT_UPDATE=1` on the snapshot tests) and commit them with
the change, whose diff then names the chunks it moved. `scripts/snapshot.py
sets` lists the sets; `files:LIST` records real files the way
`test_snapshot_scanfile` reads them. The registry's `ENGINE_VERSION` (the
pack's `rule_set`) is bumped with any change to what a verdict records.
A run of a set also fails when the engine built, on the way, a pattern
linre does not run (`linre.refused`, §14), so every pattern the engine
builds is held to linear time.

| Module | Records | On |
|---|---|---|
| `test_snapshot_hooks` | the 17 fields of `hooks_view` (shlex, hooks, both supply-chain tests with and without a language, the decoded view with no language and in JavaScript and Python, spawned scripts …) | the hooks corpus (`hooks_corpus.py`, ~44,400 cases) |
| `test_snapshot_signs` | the detectors one by one (`signs_view`: received code, PowerShell, stagers, reverse shells, self-read, persistence, the exfiltration shapes, services at login, wallet swaps, the string-array technique …), every field reached; the data flow on long texts | the hooks corpus; six long texts |
| `test_snapshot_scanfile` | `scan_file` in dependency mode and `scan_rules` (project mode's rules part), finding for finding, every family and variant reached; each line's context (`file_context`); the same three for Go and Rust files (`*_go_rs`: the rules that list them and the families) | the scan_file corpus (`scanfile_corpus.py`, and its Go and Rust part, `go_rs_corpus`), this repository's fixtures |
| `test_snapshot_project` | `scan_file` in project mode (the rules part, the SQL statements without WHERE, the intra-file taint, the SQL sinks, the function metrics, the suppression markers, the cap), finding for finding, every pass's rules reached; with a taint configuration; each file's function list (`functions`) | the project corpus (`project_corpus.py`: every pass's shapes and their combinations, seeded programs in Python, JavaScript and SQL), the scan_file corpus (its Go and Rust part too), this repository's fixtures |
| `test_snapshot_lexer` | `lex_comment_spans`: comments, strings, every literal (the lexers', §15, for JavaScript and Python) | dense random texts in each language |
| `test_snapshot_hook_commands` | a hook's command read as a program (`hook_command_risk`, `sh_parse`, the reasons), output thrown away and kept | realistic hook commands and a seeded corpus |
| `test_snapshot_small` | SC-HEXSTR's hidden names and text, SC-HOMOGLYPH's look-alike names, SC-OFFSCREEN-CODE | curated and seeded lines |
| `test_snapshot_crossfile` | the cross-file follower (`cross_file`): the stream of packages, side by side, one package, distributions, separators | the follower's generated stream (`crossfile_corpus.py`) |
| `test_snapshot_js_flow` | project mode's cross-file JavaScript taint (`js_flow`, §16): every output in order, with the default model and a configured one; files that are not text, a lowered per-reading limit | the corpus it was held to jsflow.py on: the review's cases, generated projects (`jsgen.py`), token soups |
| `test_snapshot_js_parse` | the JavaScript parser (`js_parse`, §12): each tree's or error's JSON text (its SHA-256: a tree may be deeper than `json.loads` reads), with spans and without | jsparse_cases.py's inputs: the reader's snippets and its own, every construct that nests around the depth limit, soups, generated projects and mutations of them |
| `test_snapshot_py_flow` | project mode's cross-file Python taint (`py_flow`, §17): every output in order, with the default model and a configured one; files that are not text, each limit lowered (and not raised), the frames, a chain whose work counts | the review's cases and generated projects (`pygen.py`), on which it was held to flow.py |

Twins the engine is still compared with, call for call:

| Module | Compares | On |
|---|---|---|
| `test_rust_parity_regex` | pyre (on linre) against Python's `re`: every pack pattern and the hand-written probes (those linre refuses, refused for a known reason), search/match/fullmatch/finditer/sub/split with pos/endpos, `sub`'s templates, `re.escape` | Python 3.10–3.14 |
| `test_wasm_parity`, `test_wasm_parity_signs`, `_crossfile` | the WebAssembly build the npm package ships against the platform library, call for call, byte for byte: `hooks_view`, `signs_view`, `scan_file` (dependency mode), `scan_rules`, and the npm binding's `cross_file` against the Python package's | the hooks corpus, the scan_file corpus, this repository's files, the follower's stream |
| `test_wasm_parity_jsparse` | the parser in the WebAssembly build against the library, byte for byte | the snippets, this repository's JavaScript, soups, every construct that nests at its deepest |
| `test_wasm_parity_jsflow` | the JavaScript taint pass in the WebAssembly build against the library, byte for byte | `test_snapshot_js_flow`'s sets; every construct that nests at its deepest, request data followed through it |
| `test_wasm_parity_project` | project mode in the WebAssembly build against the library, byte for byte (0.1.9, Q-1): `scan_file` with and without a taint configuration, the function lists, the intra-file taint alone | `test_snapshot_project`'s sets; the project corpus |
| `test_wasm_parity_pyflow` | the Python taint pass in the WebAssembly build against the library, byte for byte | `test_snapshot_py_flow`'s sets; every construct that nests at its deepest, `elif` chains at the frames the pass holds |
| `test_pyparse_native`, `_b`, `_c` | the Python parser (`py_parse`) against Python 3.13's `ast.parse` (a `python3.13` subprocess; skipped without one), node for node as JSON text, with the errors' lines; spans; its Unicode 15.1 data (§13) | pyparse_cases.py's inputs; every identifier character and character name |
| `test_wasm_parity_pyparse` | the Python parser in the WebAssembly build against the library, byte for byte | the snippets, this repository's Python, programs, soups, every construct that nests at its deepest |
| `test_linre*` | linre against Python's `re` on the pack's patterns (§14) | the regex corpus and adversarial inputs |

**The parity record (until the refactor).** From 0.1.7 to the Rust-first
refactor the engine was held to the Python engine, field for field, by
differential tests (`test_rust_parity_{hooks,hooks_b,signs,scanfile,lexer,
project,project_scan,crossfile,hook_commands,hexname,offscreen,lookalike}`):
zero differences in every field. On real files too: the benchmark's 945
registry scans gave identical verdicts, reasons and findings with either
engine, and both tests answered identically, file by file, on 85,415 files
(37,784 of installed Python and npm packages, and every `.py`/`.js` file of
the benchmark's 945 archives, the 516 malicious ones included); `scan_file`
in dependency mode on every source file of the benchmark's malicious
releases (15,096 files, 525 findings), every source member of its 429
popular packages (40,065 files, 821 findings) and the 13,568 distinct files
the scanner, registry, MCP and npm-parity suites hand it (25,173 findings,
every family); the follower on the benchmark's 513 malicious and 434 benign
releases: no difference. The recorded outputs start from that engine (tag
`rust-first-baseline`): the refactor's first commits record what it
answered, and the benchmark's outputs were recorded with it on real files
(330,924 outputs) and on installed packages (230,400), to compare each
later phase with.

The parity modules and the snapshot tests skip where the library is not
built (`_native.available()`), and the WebAssembly and CLI-level ones
where `js/native/lazaret.wasm` is not (`NPM_READY`), so CI builds both first.

Verifying locally, each command within 45 s:

```bash
cd rust && cargo build --release --offline --locked && cargo test --release --offline --locked
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
(cd ../js && npm run build)                                  # the WebAssembly build
cd ../python
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_regex   # ~1 s; repeat per python3.1x
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_snapshot_hooks      # each test_snapshot_* module
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_snapshot_signs      # takes 2-25 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_snapshot_scanfile
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_snapshot_lexer tests.architecture.test_snapshot_small \
  tests.architecture.test_snapshot_hook_commands tests.architecture.test_snapshot_crossfile
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_snapshot_js_flow tests.architecture.test_snapshot_js_parse \
  tests.architecture.test_snapshot_py_flow
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity         # ~20 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_signs   # ~11 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_crossfile  # ~1 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_jsparse_native      # ~1 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_jsparse # ~18 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_jsflow  # ~10 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_wasm_parity_pyflow  # ~5 s
python3 ../scripts/make_rust_tables.py --check && python3 ../scripts/check_rust_deps.py
```

## 6. The regex interface (`pyre.rs`)

`pyre` is Python's `re` as the engine's code calls it — compile, search,
match, fullmatch, finditer, findall, sub with a function or a template,
split, `re.escape` — over linre (§14), which runs every pattern in time
linear in the text with `re`'s answers. A pattern linre does not run is an
error, as one Python rejects is. Until P-16 pyre was a port of CPython's
sre (`re/_parser.py`, `re/_compiler.py`, `_sre/sre_lib.h`: its parse, its
program and its backtracking order, with speedups sre lacks — a
first-character filter, per-operation tables, a required-literal
prefilter, leads, anchored scans, set patterns answered without the
matcher), which ran every pattern until phase 2 and those linre refused
until P-16; linre has its own of each. The templates of `sub` follow `re`'s
documented rules (`\1`, `\g<name>`, `\0` and octal escapes, the
character escapes, a bad escape an error), held to Python's by
`test_rust_parity_regex`.

`Regex::need()` gives linre's strings one of which every match holds (or
those every match starts with): `scan_file` reads them for all of a file's
per-line patterns in one pass (`Gates`, a bit per pattern and line), and a
line holding none of a pattern's strings is not searched for it (a line
whose match text differs from the file's text — NFKC, decoded escapes,
comments cut out — always is). The calls that run many searches over one
whole text (the import-time and install-script tests, the decoded view,
the import-time code) read a **text gate** first (`textgate.rs`): the
text's pairs of characters, and its triples hashed into a table sized to
it, so a need, a needle or a find whose string has a pair or triple the
text lacks answers at once. For a text of 64 K to 8 M characters, the gate
also lists where each pair of ASCII characters stands, the first time a
search over the whole text asks for it. A search for a set of strings over
4,096 characters or more of such a text (a lead, a need, a literal prefix)
then visits the places of the pairs its strings have at their rarest
column, in order. It tries each place as a scan tries the places it stops
at, so its answer is the scan's: on a bundle the scans had read the text
some 40 to 60 times. The gate also keeps, until it closes, what a call's
tests make of the whole text more than once (`memo`: the lexers' tokens,
the download tests' lines that hold a write, the assignments three tests
read). `pystr`'s `find` and `in` scan for a string by its rarest character
(`scan.rs`).

Beyond the regex engine, a few patterns core runs on every line or every
token are matched or prefiltered by hand, each written for one pattern text
and used only while the pack holds exactly that text and flags (compared
once per pack; any other text runs as a regex, so a change of the pattern in
core makes the engine slower, never wrong, until the hand code follows):
the SQL lexer's literals and those of a text in no language the lexers read
(`_LEX_STR`, `_LEX_MYSQL_STR`: each has one way to match, so a loop gives its
match, as each loop's comment argues), and three necessary conditions
`scan_file` tests before a search —
`ENTROPY_VALUE_RE` (a quote, then 20 characters of the literal's class),
`B64_BLOB_RE` (202 characters) and `_SC_SINK_WORD_RE` (a sink's name, or `[`,
blanks, a quote and an `e` or `F`). The text follower reads
`_LD_NAME_TOKEN_RE`'s names by hand too (`flow.rs` `NameTokens`, compared at
each use). `test_snapshot_lexer`'s recorded outputs
hold what the loops answer (`test_rust_parity_lexer`, which compared them
with `re` and failed when one was mutated, retired with the Python engine).

## 7. Performance

On linre (§14), the engine's five main per-file calls on the 1,500-file
sample of installed packages (22.3 MB; `scan_file` in dependency mode, the
import-time test, spawned scripts, the data flow, the decoded view; one
thread, each call over every file in turn) take **6.9 s, against 10.5 s on
pyre**: the import-time test 5.08 → 3.05 s, the data flow 1.77 → 1.13 s,
the decoded view 1.20 → 0.75 s, spawned scripts 1.16 → 0.69 s, `scan_file`
1.27 → 1.24 s (its rules were gated and hand-matched already).

What follows was measured before the Rust-first refactor, against the
Python engine it retired. Single thread, per call, on the hooks corpus
(29,795 small cases), best of 3:
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
And the Python package's project mode read its rules through `scan_rules`
(core's passes followed until 0.1.9's Q-1 moved them into the engine).
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
engines (phase 3 of §8); in litellm's registry scan, the import-time test
still leads. A backtracking engine that must give sre's exact answers can't
skip much more inside one search: the gains were in not searching, and
then (above) in not backtracking.

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
SQL-DYNAMIC, which `re` runs (and pyre's sre port ran) in quadratic time on a line of many
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

The original port (0.1.7–0.1.8) moved the Python engine's work into the
engine function for function: the workspace, the bindings, the regex
engine and the Unicode tables; the supply-chain tests and what they read;
the per-file rules (`scan_file` in dependency mode, `scan_rules` in project
mode); the cross-file follower; and WebAssembly for the npm package. The
Rust-first refactor then stopped tying the engine to its Python twin, in
these phases, each checked against the baseline's recorded outputs and the
benchmark:

| Phase | What | State |
|---|---|---|
| 0 | Baseline: the detection round committed (rule set 2.15.0), the engine's outputs recorded on the benchmark's files and on installed packages | Done (tag `rust-first-baseline`) |
| 1 | The Rust engine is the reference: the Python engine, `--engine` and the pure wheel retired; the recorded outputs (§5); the pack as the source of the rules; every wheel a platform wheel, the sdist compiled by pip where none fits; an unanswered file SC-TRUNCATED in both packages | Done |
| 2 | Decoding, lexers and bytes in the engine: source decoding (BOMs, UTF-16, coding cookies), one token substrate for the detectors | Done (tag `rust-first-phase2`): the lexers (§15: every caller's comments and literals, both packages), the self-read on them, the decoded view on string values (§15). Moved: the data flow, the dead drop, the secret endpoints and received code to phase 3 (they follow names: scopes); bytes to phase 4 (with linre over bytes); source decoding to after phase 3 (the packages' decoders already agree, held by their parity tests, and owning the CJK codecs would put their tables in the WebAssembly module) |
| 3 | Parsers, scopes and flow: the detectors on bindings over the JavaScript and Python trees (§12, §13), constant folding of strings, the cross-file follower on them, project mode's passes (taint, SQL, function metrics) in the engine; the npm package's twins of them retired | The parsers done; project mode's JavaScript taint ported onto `js_parse`'s trees (§16: `js_flow`), both packages ask the engine for it, and jsflow.py, jsflow.js and the readers they used are retired (11,357 lines); Python's taint ported onto `py_parse`'s trees (§17: `py_flow`), both packages ask the engine for it (the npm package had no port of it), and flow.py's own pass is retired (1,505 lines); the passes and the parser held to their recorded outputs; the supply-chain data flow and received code on JavaScript's trees (§18: local data sent, reported by the strongest send; received data run, loaded or deserialized, from the script's own address) and on Python's (§19), benchmark-gated; a file written then run, and decoded code run, on both trees (§20); project mode's last passes (the SQL statements without WHERE, the SQL sinks, the function metrics, the intra-file taint, the markers and the cap: `project.rs`, `taint.rs`) in the engine, both packages ask it for the whole of project mode, and core's passes and the npm package's `taint.js`, `sql.js` and `functions.js` are retired (0.1.9, Q-1). Next: the cross-file follower on bindings. The dead drop, the secret endpoints and the self-read stay on the text detectors for now: on the benchmark's JavaScript they fire in few files, and no examined miss comes from their windows |
| 4 | Linear-time matching: the pack's patterns on linre (§14), pyre and the shlex port retired, current Unicode | Every pattern runs on linre (P-16, rule set 2.28.0): the pack's 666, its lexers' tables included, and those the engine builds as it scans. Lookaheads of unbounded width run with a memo, and a sweep where the walks would cost more; a quote matched again as branches; a name matched again and counts past what a program holds are checked in code; two patterns read further than before. pyre's port of sre retired (P-16's second part): pyre is re's interface to linre, a pattern linre does not run is an error (a built one fails its call closed), and a taint configuration's patterns are held to what linre runs. The shlex port is written anew from shlex's documentation, and the Final_Sigma rule and the casefix table come from Unicode's definition and data (P-16's third part): the engine holds no CPython code. Next: current Unicode |
| 5 | One call per file, a content cache (SHA-256), the guard's scan in a child process that fails closed, archive ambiguity checks | Not started |

A parallel track brings Go and Rust up to Python's and JavaScript's level (R-1, G-1, §21, §22): the Rust reader (`rs_crate`) and the Go reader (`go_package`) are built, and the registry, the guard and `--deps` call them (Part C; §23 for what `--deps` reads of a vendored manifest).

## 9. Known issues

- `Pack::entry` panics on a name the pack lacks; the FFI and `batch` catch it
  (status 3: the file is SC-TRUNCATED). A pack-load validation of every name
  the engine reads would turn it into an error at load.
- `_XF_ARROW_ONE_RE` is quadratic on `"x" * 100001` (inherited from core):
  bound it in the pack (a reviewed difference of the recorded outputs).
- The budget (4e9 steps per call) discards an exhausted answer: in both
  packages the call's file is SC-TRUNCATED (CRITICAL), on hostile input only
  (no file of the corpora or the benchmark comes near the budget). linre
  charges a sixteenth of what its automata read (§14); a call's
  `budget` argument sets another (`engine.WORK_BUDGET`
  in Python, `setWorkBudget` in npm; the tests use a small one).
  `cross_file` gives each package its own budget: a package that spends it
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
  exact text and flags; linre runs it in linear time too since P-16, so
  the hand matcher can go.
- The native `scan_file` has no time budget, only its work budget: a file
  it scans is scanned whole, and a file that spends the budget is
  SC-TRUNCATED, in either mode. Core's `SCAN_TIME_BUDGET` (30 s per file,
  ends in SC-TRUNCATED) bounds a config or data file's scan, which is
  still core's (and the npm package's `scanConfigFile`).
- S-ENTROPY's Shannon entropy is a `sum()` of floats, which Python adds with
  Neumaier's compensation since 3.12: the binding says which way to add
  (`neumaier`), so a value at 4.0's edge is judged as that Python judges it.
- The messages of findings come from the pack (the rule dicts core had,
  with `str.format` templates filled as Python fills them, `!r` as
  `repr()`): every text the engine shows is in the pack.
- JSON joins adjacent surrogate halves: the tests that compare answers
  normalize both sides through JSON first.
- Python 3.10 has no atomic groups or possessive repeats: those regex probes
  are version-gated. The pack holds no integer beyond i64.
- Patterns built at run time are compiled into a per-thread cache cleared at
  512 entries, like `re`'s; each thread compiles its own.
- Measuring: single runs vary ±15% on shared machines; compare best of 3, or
  callgrind instruction counts (`examples/profile_one`).

## 10. Next

Done in 0.1.8: **WebAssembly for the npm package** (§2–§4): the npm
package runs the native engine (`native/lazaret.wasm`, dependency-free,
built in release CI with the wheels' compiler), and the JavaScript twins
of what it answers are retired (`js/src/lib/hooks.js`, `received.js`,
`shellpipe.js`, `received-spec.json`, `js/src/scanner/linear.js`, the
per-line rules, the families and the dependency decode flow of `scan.js`);
the import-time and install-script tests at `scan_file`'s speed (§6's
leads, start tests, text gate and anchored scans), project mode's rules
part in the Python package (`scan_rules`), the cross-file follower in the
engine for both packages (`cross_file`), and worker threads in the npm CLI
(§2, §7). Then the Rust-first refactor's phase 1 (§8): the Python engine
retired, the recorded outputs, the pack as the source, platform wheels
only.

1. Run the benchmark (`scripts/bench.py`, in the repository since phase 1)
   against the baseline after each phase, nightly too: attribution, and the
   holdout's aggregates.
2. Phases 2–5 (§8): decoding and the token substrate; the detectors on
   bindings over the parsers' trees (project mode's passes are in the engine
   and the npm engine's twins of them retired since 0.1.9's Q-1); current
   Unicode (the translations of CPython code are retired: every pattern
   runs on linre since P-16, §14, and §11); one call per file, a content
   cache, the guard's scan isolated.
3. The rest of the npm engine's twins: the manifest, workflow and settings
   checks (`supplychain.js`, `ghworkflow.js`, `autorun.js`), the
   config-file credentials; the dashboard keeps its own script until it can
   load the same module.
4. Archive reading for registry scans in the engine, where it reads as the
   registries' own tools do.
5. Record the engine in reports (JSON and SARIF), next to the version.
6. Platform wheels for musllinux and Windows ARM64 (pip compiles the sdist
   there today).

## 11. Licensing

The engine is Lazaret's own work under Apache-2.0, with Unicode data under
the Unicode License v3. Until P-16 (0.1.9) parts of it were translations of
CPython code, distributed under CPython's license as well: pyre, a
translation of sre (`Lib/re/_parser.py`, `_compiler.py`, `_constants.py`,
`Modules/_sre`), whose files carried the SRE library's notices (they
allowed its redistribution under CNRI's Python 1.6 license and asked any
other use to contact Secret Labs AB); `shlex_split` in `hooks.rs`
(`Lib/shlex.py`); `capital_sigma` in `unicode.rs` (`handle_capital_sigma`
in `Objects/unicodeobject.c`); and the `_casefix` table in `unicode13.rs`.
They are retired:

- every pattern runs on linre (§14), written from `re`'s documented and
  observed behaviour, and `pyre.rs` is `re`'s interface to it (P-16's
  first two parts);
- `shlex_split` is written from shlex's documentation (its parsing rules in
  POSIX mode, and `punctuation_chars`), and `test_shell_words.py` holds it
  to Python's shlex on the hooks corpus and on random commands;
- the Final_Sigma rule follows the Unicode Standard's definition (section
  3.13), as `str.lower()` reads it: a character both cased and
  case-ignorable is passed over (a Rust test holds it to Python's answers);
- `re`'s extra case equivalences are derived from Unicode's case mappings,
  the lowercase letters that share an uppercase, by
  `scripts/make_rust_tables.py`, whose `--check` holds them to `re`'s own
  table.

So:

- `rust/NOTICE` says the engine is Lazaret's own and what was CPython's,
  and carries the Unicode notice: `generated/unicode13.rs` is Unicode
  Character Database 13.0 data, and `pyparse/unidata.rs` the Python
  parser's Unicode 15.1 data (§13), each with the notice in its header.
  The Python parser is written from Python's grammar and `ast`'s answers,
  not translated from CPython's parser. `rust/LICENSE-UNICODE` is the same
  text as the Python and npm packages' `LICENSE-UNICODE`.
- `rust/Cargo.toml` declares `Apache-2.0 AND Unicode-3.0`.
- The packages that carry the engine are `Apache-2.0 AND Unicode-3.0`
  too: every wheel carries the compiled engine and the sdist its source,
  each with `NOTICE` as a license file (the wheels'
  `.dist-info/licenses/`, the sdist's root) beside `LICENSE` and
  `LICENSE-UNICODE`; the npm package carries `native/lazaret.wasm` with
  `rust/NOTICE` as `native/NOTICE` (both written by `npm run build`),
  `LICENSE-UNICODE` and its own `NOTICE` (the Unicode tables of its
  JavaScript). The codec names the npm package and the dashboard list to
  read a coding cookie as Python does are what Python's codecs answer to:
  facts about Python, not CPython's code, so no package carries CPython's
  license (until 0.1.9 they carried it, with `Python-2.0.1`).
  `check_native_library.py --dist` checks the sdist and the wheels before a
  release, and `release.yml` fails a tarball without `native/lazaret.wasm`
  or `native/NOTICE`.

`tests/architecture/test_rust_notices.py` keeps this in place: it fails on
an engine file that carries CPython's license or says it is ported or
translated from CPython. A part of CPython that the engine needs is written
from the documentation and held to Python's answers by a test, never
translated.

## 12. The JavaScript parser

`src/jsparse/` is a port of `lazaret.scanner.jsparse` (jsparse.py, 0.1.7's
reader for the cross-file flow engine, retired with its npm twin in phase
3): the first piece of the engine's Rust-first detectors, whose passes
(project mode's taint, §16; scope resolution, data flow and constant
folding of strings for the supply-chain detectors next) walk its trees.

**What it reads.** ECMAScript 2025 with JSX and TypeScript — the syntax of
.js .mjs .cjs .jsx .ts .tsx .mts .cts files — into ESTree-shaped trees:
acorn's and acorn-jsx's node types and fields, and jsparse.py's
TSEnumDeclaration, TSModuleDeclaration, TSImportEquals and
TSExportAssignment. TypeScript's types, interfaces, aliases, overload
signatures, abstract members and `declare` statements are read and left
out; Flow's annotations in a .js file are read as TypeScript's. For every
input it builds exactly the tree jsparse.py built — every node type, field,
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
scanned it again each time: a 1 MB string behind 2,000 `f<` took it 2.7 s,
the engine 0.04 s). Recursion is bounded by the depth limit (the two chains
jsparse.py recursed on without it are loops here). The deepest stack — a
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
that nests read at the deepest depth jsparse.py read and failing one deeper
(the depths are jsparse.py's), all of them on a 1 MiB stack; the budgets at
their edges (a generic arrow function of 2,044 parameters is one, of 2,045
is not; function_type_ahead's 256 tokens; the file's allowance spent);
the KeyError and recursion-limit answers; spans; interned names; 6,000
seeded soups of pieces and arbitrary code points (controls, lone
surrogates, values past U+10FFFF) that must not panic.
Until phase 3 retired jsparse.py (and its npm twin), `test_jsparse_native`
and `_b` compared `js_parse` with `jsparse.parse` as JSON text (jsparse.py's
dicts written as `json.dumps` writes them, without recursion) on the inputs
test_js_parity_parse.py held the twin to — its snippets, the repository's
JavaScript, 60 seeded projects, 1,500 soups, 300 mutations, and its two
linearity cases, which the engine reads in well under a second — and on
jsparse_cases.py's: 231 more snippets (the budgets' edges, the bugs above,
surrogates, numbers, escapes, regular expressions, templates, ASI,
comments, JSX, TypeScript, Flow, an error at every kind of token), every
construct at 19 depths around the limit, 6,000 soups and 800 mutations;
and the spans (without `start` and `end` the JSON is the same, and `line` is
the line of `start`). Since then the trees are held to their recorded ones:
`test_snapshot_js_parse` records each answer's SHA-256 on those inputs (the
mutations now of generated projects, whose text does not change with the
repository's: 9,743 answers, every one jsparse.py's before it retired) and
with spans on the reader's snippets and 12 more projects (84);
`tests/scanner/test_jsparse.py` pins node shapes, lines, literals, ASI,
JSX, TypeScript, the dialects, the errors and linear time on the engine;
`test_jsparse_native` the call's options and bounds (the dialect a path
picks, spans, the depth limit, the answers kept from jsparse.py, linear
time). `test_wasm_parity_jsparse` holds the WebAssembly build to the
library, byte for byte (a Node script speaking native.js's protocol
answers each call's SHA-256), on those snippets, sources and soups and on
every construct at its deepest and one deeper.

On real files: every .js .mjs .cjs .jsx .ts .tsx .mts .cts file of the 20
npm packages installed on the development machine (24,428 files, 348.8 MB;
typescript's 9.1 MB `lib/typescript.js` the largest), each read in
`jsparse.dialect`'s dialect: identical trees for 24,424, identical errors
for 4 (declaration files' `export = function f(…): T;`, a signature
jsparse.py read as a function expression), no difference. jsparse.py took
250 s; the engine 12.0 s through the Python binding, its JSON included.

**Throughput**, the release build on one thread, best of three, over those
24,428 files: the parse 62 MB/s (the tree compacted), the parse with its
JSON 46 MB/s; over ordinary module code (puppeteer-core's 362 ESM files,
1.9 MB) 70 and 57 MB/s; over typescript's `lib/` (19.8 MB of bundles and
declaration files) 60 and 50 MB/s (`cargo run --release --example
jsparse_bench -- throughput DIR…`). jsparse.py read 1.3 MB/s. The parser
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
**The engine runs every one of its patterns on it** (P-16; patterns linre
accepted ran there since the Rust-first refactor's phase 2): pyre (§6) is
`re`'s interface to it, and a pattern linre does not run is an error there,
as one Python rejects is. None of the pack's is (`test_linre`). One the
engine builds as it scans (`rxutil::dynamic`: names escaped into a
template) fails its call closed: the call's budget is spent, so both
packages make the file SC-TRUNCATED, and it is noted (`linre.refused`; a
run of the recorded outputs, §5, fails on one, and none is; it would take
names of tens of thousands of characters). A taint configuration's own
patterns (`rxutil::dynamic_user`) are held to what linre runs when the
configuration is read (`taintspec`: a pattern linre refuses is a rejected
rule, with the reason), and one that is not never matches. Before P-16 the
patterns linre refused ran on pyre's port of sre's backtracking matcher.
A linre search charges the call's work budget a sixteenth of the
characters its automata read (the DFAs, the Pike VM, the backtracker for
groups), as pyre's port charged its scans: a search the text gate answers,
or a scan for the strings the pattern needs, costs nothing, a match that
fails what the DFA read before it died. So the budget still bounds a call,
and no file needs more of it on linre than it did on sre's port (a 9 MB
`typescript.js` needs less than 1e8 of the 4e9 steps on both; charging
every search the whole span it covered, as the first wiring did, spent the
budget on the largest files — `typescript.js`, `pnpm.cjs`, the benchmark's
11 MB obfuscated bundles — in seconds of work). A memoized lookahead's walks
(below) are charged the same way, a step a character. `pyre.probe` runs a
pattern through pyre, as the engine's code does (`sub` with a template
too). Three calls expose linre itself: `linre.probe` (pyre.probe's
arguments and answer — search, match, fullmatch, finditer with every
group, sub with `<…>` and split, at `pos` and `endpos`, with `gate` — or
`{"error", "refused"}`), `linre.check` (`{"names": […]}`, or nothing for
the whole pack: each pattern accepted, with its program's size, its
lookarounds and the strings it scans for, or refused and why) and
`linre.refused` (the patterns the engine built since the last call that
linre refused, at most 64).

**What it runs.** Literals and every escape of str patterns; classes with
ranges, negation and `\w \d \s \W \D \S`; `.` with and without DOTALL;
alternation; greedy and lazy `* + ? {m} {m,} {,n} {m,n}`; capturing, named
and non-capturing groups; `^ $ \A \Z \b \B`, with MULTILINE; the flags
`i m s x a u` as arguments, inline at the start and scoped (`(?i:…)`,
`(?-i:…)`); comments; lookbehinds (fixed width, as Python requires) and
lookaheads of any width, positive and negative, nested; and a
backreference to a group that is one character of a few, none of them
cased (`(["'])…\1`: a quote matched again). All of the pack's 666 patterns,
its lexers' tables included.

**What it refuses**, when the pattern is compiled, saying why (`Error {
refused: true }`; a pattern Python rejects is an error, with Python's
message): other backreferences, and conditionals (they need what a group
matched); a repeat other than `?` whose body can match the empty string
(`(a*)*`: sre ends such loops by rules of its own); a capturing group
inside a positive lookaround; atomic groups and possessive repeats;
`\N{…}`; the TEMPLATE flag; a lookbehind wider than 1,000 characters;
lookarounds nested more than 8 deep; and a program of more than 30,000
instructions once counted repeats are expanded.

**Answers.** `re`'s: leftmost-first, with greedy and lazy priorities; the
same spans and groups for search, match, fullmatch and finditer (the last
iteration's capture inside a repeat, None for a group the match did not go
through, lastindex the last group closed); finditer's rule after an empty
match; a lookbehind reads before `pos`, nothing reads past `endpos`, and a
match that starts past `endpos` (`match(s, 5, 2)`) answers as sre's does
(an empty pattern and MULTILINE's `$` match there, a one-character repeat
fails); `\b` and `\B` hold nowhere in an empty window at 0 (as 3.10–3.13
do); IGNORECASE and ASCII as sre compiles them, with unicode.rs's Unicode
13.0 tables (sre's lower and upper and its case fixes; a class is tested on
the lowercased character, or as written when it holds no cased character;
a range past the Basic Multilingual Plane on the lowercase and on its
uppercase). Where Python versions differ — an astral letter written in a
class under IGNORECASE, which 3.10–3.12 match in neither case, and an
astral range under ASCII and IGNORECASE — linre answers as 3.13 and later
do (as pyre's sre port did). A text is code points: a lone surrogate is a
character like any other.

**How it runs.** The parser keeps what `re`'s parser keeps where it changes
an answer (a one-character class is a literal, the item alternatives begin
with is taken out in front, alternatives of single characters become one
class). A backreference linre runs is rewritten next (`hir.rs`,
`expand_backrefs`): the group heads an item of a sequence, through groups
only, so it matches whenever that item does, and every backreference comes
in a later item; the items from the group's to the last backreference's
become one alternative per character (at most 8), the group's body and
each backreference that character, the group's capture kept. At a given
position the alternatives begin with different characters, so at most one
goes on: sre's path, with its spans and groups. Lowering resolves the
flags item by item into character sets
(sorted ranges over all u32 values: the matchers test membership, they
never fold) and zero-width tests. From that, Thompson programs ordered by
priority: forward (with capture slots), fullmatch, reverse, one per
lookaround of more than one character, and the backtracker's copies, in
which a counted repeat of one set is a single `Run`. A search, in order:

1. Prefilters, each skipping only work that cannot match: strings one of
   which every match holds (a text gate answers at once for a text that
   lacks one of each string's character pairs), strings every match starts
   with (found by their rarest character, sixteen at a time, and kept even
   where those characters are common: each place is checked for a whole
   string before a try, and over a long text the places are the pairs'), a
   set of first characters when they are rare (at most one character in
   twenty-five of source text: past that, a try at each place costs more
   than the DFA's own pass), and patterns that are one set or a greedy
   repeat of one, answered by scans alone.
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
   its transitions by the outcomes. A lookahead that may read more than
   1,000 characters (`(?!\s*\()`, `` (?![^"'`]*(?:html|xml|svg)) ``) would
   read up to the rest of the text wherever it is tried, so its walks are
   memoized (`looks.rs`, `run_memo`): a walk's outcome depends only on the
   set of threads it holds and its position, so after its first 8 steps a
   walk notes each set it holds (named by its character instructions) with
   the runs of positions it held it at, and stops where an earlier walk's
   outcome is known. From inside a run of blanks a walk meets the first
   walk's set after a step or two. A lookahead whose walks meet many sets
   (`(?![ab]*a[ab]{12}c)` on a text of a's and b's: what the last dozen
   characters were) would still walk far from every position, so once its
   walks have taken 4 steps per character of the stretch it is tried on
   (and 4,096 more), it is decided at every position of that stretch at
   once (`sweep`: from the window's end back, the instructions from which a
   path reaches Match at each position) and answered from that. The memos
   last one search, or one finditer (one text, one window end); the DFAs,
   the backtracker and the Pike VM share them. Each DFA keeps at most 2 MB
   of states; a search that would empty them too often gives up to the
   Pike VM.
4. The groups: the backtracker, in sre's order, on the match's span only,
   visiting each (instruction, position) once; a span too long for its
   visited bits (2 MB) goes to the Pike VM.
5. The Pike VM (threads in priority order, each with its slots) answers
   what the DFAs give up on.

**Complexity.** For a text of n characters and a program of m instructions
(counted repeats expanded): the DFAs read each character a bounded number
of times, one table entry each once the transition is known (a new one
costs O(m)); a lookaround of width w ≤ 1,000 costs O(w·m) where it is
tried; a memoized lookahead's walks take some 5n + 4,096 steps at most
(at O(m) each) before it is swept, at O(n·m), and each test after that
reads a bit (a test before the swept stretch walks again, and sweeps
again only after as many steps more); the anchored tries cost at most
8n + 4m + 256 steps in all; the backtracker
visits each (instruction, position) once; the Pike VM is O(n·m). So
O(n·m) at worst: linear in the text for every accepted pattern, whatever
the text. No recursion on the text, and no panic on any text of any u32
values. Compiling: the 300 patterns of a scan take 113 ms (pyre's sre port
took 35 ms; until P-16 each pattern was compiled by both).

**Tests.** `cargo test --release` (`linre/tests.rs`, `linre/charset.rs`):
the syntax the pack uses compiles, Python's errors are errors, each refusal
says why; flags inline and as arguments; answers checked against Python's;
the matchers against each other — the public calls, the Pike VM alone and
the backtracker alone (sre's search: a try from each start in turn) — on
35 hand-written patterns and 12,000 seeded random ones (some 8,600 of
which compile), on random texts of letters, the edge characters and lone
surrogates, in windows too; 20,000 seeded garbage patterns and texts of
arbitrary u32 values without a panic; and adversarial texts of 20,000
repetitions read at once. Since P-16, against the answers recorded from
sre's matcher (pyre's port, before P-16's second part retired it) on the
same seeded inputs, a digest per test, and the matchers against each other:
lookaheads of unbounded width — 25 of the pack's shapes and others
on 400 texts each, in windows too, and 3,000 seeded random patterns with
one (over 1,500 of which compile) — each walked and swept; three that meet
thousands of sets, on texts of 3,000 characters; and one-character
backreferences (15 patterns on 500 texts each; 6 others still refused).
The memoized lookaheads in linear time, four times the text in less than
eight times the time: six that would read the rest of the text from every
position (that test takes 0.2 s; 16.7 s walked without a memo) and the
three of many sets (1.1 s with the agreement part; past 100 s without the
sweep). And the patterns rewritten for P-16
(`rxutil_tests.rs`) against the pack's originals (rule set 2.27.0) on
sre's matcher: the same matches, spans and groups, on texts made to sit
on each side of every limit; the two that read further answer as before
within their old limits. Against Python's `re`, from `python/` (each
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
  each other) and with a text gate: 140,000 texts. And `linre.check`: every
  pattern of the pack is accepted (the recorded-output modules, §5, fail a
  run that built a pattern linre does not run: `linre.refused`).
- `test_linre_b` and `_c` (half of the patterns each): texts sampled from
  each pattern's parse tree (`_linre_inputs.sample`: a branch, a repeat's
  count at or next to its bounds, a class's member — a range's ends, a
  category's members, the edge characters —, a letter's case under
  IGNORECASE, what a lookbehind wants before and a lookahead after), some
  of them mutated: about two thirds of them match, and many others nearly
  do. 80,000 texts.
- `test_linre_d`: the parity test's hand-written patterns (each construct
  `re` supports for str patterns: linre runs 124 of the 141 and refuses the
  rest for a known reason), about 100 of linre's own (lookarounds of
  several characters, nested and at a window's ends; anchors; flags;
  IGNORECASE past ASCII; astral characters; counted and lazy repeats at
  their bounds; empty matches; lastindex; the literal scans' corners), and,
  on Python 3.13 and later, 300 random classes of astral and other letters
  under IGNORECASE and ASCII: 110,000 texts.
- `test_linre_e`: what P-16 added, on the shapes `linre/tests.rs` holds to
  sre's recorded answers: the 25 lookaheads of unbounded width and 600
  random patterns with one, the three of many sets on texts of 1,500
  characters, the 14 one-character backreferences, and the backreferences
  still refused.
- `test_linre_linear`: linear time, below.

Every text goes through search, match, fullmatch, finditer, sub and split
in both, at 0 and in windows: no difference, on Python 3.10, 3.11, 3.12 and
3.13. (The sampler keeps the unbounded repeats of more than one character
short: `re` itself takes exponential time on a near miss of some of them.)

**Linear time.** Pack patterns on texts that make a backtracking matcher
backtrack, through a backtracking matcher (pyre's port of sre when this was
measured, in phase 2; Python's `re` in the test since P-16) and
`linre.probe` (all six operations), best of three:

| Pattern, text | sre (pyre's port) | linre |
|---|---|---|
| `_SVC_LAUNCHCTL_RE`, "launchctl" + " --a" × k + " x" (`-{1,2}[\w-]+` reads "--a" two ways: 2^k paths) | k = 10: 2.1 ms; 12: 7.7 ms; 14: 30 ms; 16: 120 ms | k = 1,000: 0.5 ms; 100,000: 12 ms |
| `_DD_PARAM_RE`, n blanks (two `\s*` in a row, from every start: n³) | n = 100: 5.9 ms; 200: 35 ms; 400: 226 ms | n = 100,000: 2.5 ms; 200,000: 4.9 ms |
| `_JSON_COLON_RE` (`[ \t\n\r]*:`), n blanks (n²) | n = 1,000: 8.3 ms; 2,000: 33 ms; 4,000: 135 ms | n = 100,000: 2.5 ms; 200,000: 4.9 ms |

`_LD_CALLED_RE` (`\s*\(`) and `_DL_JOIN_CHAIN_RE` grow as `_JSON_COLON_RE`
does. The test asserts the growth (`re`: more than eightfold for two more
pieces, more than tenfold for four times the text; linre: less than
eightfold for four times the text) and that linre reads a million
characters of each in under 2 s.

**Measurements** (phase 2, pyre's sre port against linre). Every regex
call of a scan of the 1,500-file sample (22
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

Since P-16 the 17 run on linre too. The five main per-file calls on the
same sample (§7) take 8.11 s against 8.17 s before it (best of three, one
thread, both measured on the same machine on the same day: no difference
past the noise). In instructions on a warm engine,
P-1's way: litellm's `proxy_server.py` 1,134 → 1,123 M (-1%),
playwright-core's `coreBundle.js` 5,140 → 4,852 M (-6%) and
`utilsBundle.js` 7,182 → 6,881 M (-4%).

**The 43 patterns linre refused before P-16**, and four pieces of
patterns the engine builds as it scans, which the strict compile found
(`linre.check` lists no refusal now):

- *A lookahead of unbounded width* (27): `RULES[7]`, `RULES[9]`,
  `RULES[50]` (SQL-DYNAMIC), `TAINT_SINKS['js'][3][1]` and `[9][1]`,
  `TAINT_SOURCES['js']`, `_DL_CALLBACK_RE`, `_DL_COMMA_CALL_RE`,
  `_DL_DESERIAL[0]` and `[1]`, `_DL_DESERIAL_CANDIDATE_RE`,
  `_DL_DESERIAL_RE`, `_INDIRECT_SINK_RE`, `_JWT_CANDIDATE_RE`, `_KWARG_RE`,
  `_LD_ALIAS_JS_RE`, `_LD_CLIENT_RE`, `_LD_ENV_ALL_RE`, `_LD_ENV_QUIET_RE`,
  `_LD_FIRST_MEMBER_RE`, `_LD_MEMBER_READ_RE`, `_NON_HTML_CHAIN_RE`,
  `_NON_HTML_TYPE_RE`, `_SELF_READ_RE`, `_XF_JS_EXPORT_LIST_RE`,
  `_XF_JS_MODEXP_FN_RE`, `_XF_JS_REQ_NS_RE` (blanks before a test,
  `(?!\s*\()`; the rest of an argument list or a string,
  `(?![^()]*\)\s*\{)`, `` (?![^"'`]*(?:html|xml|svg)) ``): run as written,
  their walks memoized.
- *A quote matched again* (10): `_DEPS_LOCAL_DEP_RE`, `_DNS_CMD_SUM_RE`,
  `_DV_ESCAPED_LITERAL_RE`, `_KEYED_READ_RE`, `_KEYED_WRITE_RE`,
  `_LD_HOST_BUILT_RE`, `_LD_PLAIN_LITERAL_RE`, `_ROUTE_RULE_RE`,
  `_XF_EMIT_RE`, `_XF_LISTEN_RE` (`(["'])([^"'\\\n]*)\2`): run as written,
  the backreference as one branch per quote.
- *The same name matched again* (3), and two pieces of the string arrays'
  accessors: `_DV_CC_FOR_RE` (`\1`, the loop's variable),
  `_DV_CC_LITERAL_RE` (`\5`, the comprehension's), `_SA_CHECKSUM_RE`
  (`(?P=v)`), `_SA_ACC_A_HEAD` and `_SA_ACC_B_TAIL` (`(?P=p)`, `(?P=g)`:
  the accessor's parameter, form B's function). Not a regular language:
  each name again is a group of its own (`i_again`, `v_again`, `p2`, `p3`,
  `g2`) that the code compares with the first (`rxutil::finditer_same`,
  `same_groups`). A match whose names differ is no match, and the search
  goes on from the next start, as sre's does where its pattern fails; the
  names are whole identifiers, which the rest of the pattern fixes at a
  start, so the answers are the originals'.
- *Counts larger than a program holds* (3), and two pieces of the decoded
  view's: `RULES[47]` (SC-EVAL-DECODER's decoder body,
  `(?:[^{}]|\{[^{}]{0,2000}\}){0,2000}`: millions of instructions
  expanded), `_DV_ARRAY_RE` (up to 64 strings of up to 400 characters),
  `_PERSIST_WRITE_RE` (`open(`'s arguments before the mode: up to 300
  items, one in brackets up to 200 characters), `_DV_CC_LITERAL_RE`'s lists
  of up to 400 numbers, `_DV_CC_ARRAY_TAIL` (4,096 numbers) and
  `_DV_CC_CALL_TAIL` (20,000 arguments, strings of up to 400 characters):
  unbounded repeats in place of the counts. Where the count is a limit the
  detector keeps, the code checks the match against it
  (`rxutil::finditer_checked`, `search_checked`, `sub_checked`, with the
  pack's `_DV_ARRAY_MAX_ITEMS`, `_DV_ARRAY_MAX_CHARS`,
  `_DV_CC_LITERAL_MAX_INTS`, `_DV_CC_ARRAY_MAX_INTS`, `_DV_CC_CALL_MAX_ITEMS`
  and `_DV_CC_CALL_MAX_CHARS`), and a match past it is no match, the
  search going on from the next start. SC-EVAL-DECODER's body and the
  shell-profile write's arguments keep no limit: they read further than
  before (rule set 2.28.0), and within the old limits answer as before.

## 15. The lexers

`src/lex/` reads a text into its language's tokens once, the way its
runtime reads it, for every caller that asks where its comments and
literals are (`lexer::lex_comment_spans`: `scan_file`'s comment layout and
names, the import-time test's prose, the cross-file follower's comments,
the Python package's project mode and suppression markers, the npm
package's comment layout). Until phase 2 each of those read JavaScript and
Python with regular expressions of its own that paired quotes and slashes:
a template nested in another's `${…}`, a quote inside a regular
expression, threw them off for the rest of the text, and the code in a
template's holes or an f-string's replacement fields was read as text, so
a call there was not a call.

- **JavaScript** (`js.rs`; TypeScript and JSX too): the tokens of
  jsparse's scanner (`jsparse/scan.rs`: strings, template text, regular
  expressions, numbers, names, punctuators), lines ended by LF, CR, U+2028
  and U+2029 as JavaScript ends them (a line comment or a string ends at
  any of them). What the parser decides from the grammar the lexer decides
  from what came before: a `/` begins a regular expression where an
  expression may begin (after a punctuator but `)`, `]`, `}`, `.` and
  `?.`; after `return`, `typeof`, `case` and the other words an expression
  follows; after an `if`/`for`/`while` head's `)` or a block's `}`), and
  divides elsewhere; a template's text runs to its backtick or `${`, the
  hole is code to its `}` (braces counted, templates nested to any depth);
  with JSX, a `<` where an expression may begin, before a name or `>`,
  opens an element (not TypeScript's `<T,>` or `<T extends …>`), whose
  attribute strings, text, `{…}` code and nested elements are read as JSX
  reads them, type arguments after a tag's name as code. A first-line
  hashbang is a comment. Annex B's `<!--` and `-->` are comments in a
  script and code in a module (`x <!--y` is `x < !--y`), and a `.js` file
  does not say which it is: they are read as code, so nothing a module
  runs is taken for a comment. What the runtime would refuse is read so
  that it hides nothing below it: a quote not closed on its line is a
  string to the line's end (a `/*` after it opens no comment), and a `/`
  whose regular expression is not closed on its line divides, as does
  every later `/` on the line (so the lexer stays linear).
- **Python** (`py.rs`): pyparse's tokenizer (Python 3.13's: prefixes,
  triple quotes, line continuations, f-strings in pieces with PEP 701's
  nesting), with t-strings read as Python 3.14 reads them (PEP 750:
  `tokenize_with(src, true)`; the parser stays 3.13's), the comments found
  between its tokens (ended by LF or CR). Past a token it refuses (an
  unterminated string, a stray character …), and in a text it refuses
  whole (a NUL, a lone surrogate), the rest is read plainly (`fallback`:
  strings to their closing quote — one quote's to the end of its line —,
  comments to the end of the line). The import-time test's prose (a string
  statement) ends its line at a CR too.
- **What both readings agree on** (`mod.rs`, `Structure`): where two
  runtimes read a text differently, a span is a comment or a literal only
  if both readings say so, so that what one of them runs is never taken
  for prose. A JavaScript file that may hold JSX (every one but `.ts`,
  `.mts`, `.cts`) is read with JSX and without; Python as 3.12 and later
  read it and as 3.11 did (an f-string a string to its first closing
  quote, and a `t` before a quote a name, as 3.13 reads it).
- **Go** (`go.rs`) and **Rust** (`rs.rs`), since 0.1.9 (S-4: a project's
  `.go` and `.rs` files): Go's `//` and `/* */` comments (no nesting),
  interpreted strings and runes, raw strings in backticks, numbers (hex
  floats, `_`, imaginary) and Unicode names; Rust's nested block comments
  and doc comments, strings over several lines, raw strings (`r#"…"#`),
  byte and C strings, characters told apart from lifetimes and loop labels
  (`'a` is a name, `'x'` a character), raw identifiers, numbers (`1..2`,
  `1.max(2)`, `1.5e-3f64`) and a first-line shebang (`#![…]` is code). An
  interpreted string or a rune not closed on its line ends there; an
  unclosed comment or raw string runs to the end of the text. One reading
  each (`Structure::of`): neither language has a second one that could
  run what the first calls prose. `scan_file` gives them their own `Lang`
  (`filectx.rs`): the rules that list `go` or `rs` (S-SECRET, S-TOKEN,
  S-BIDI, Q-TODO) and the families every text gets. The lexers' fuzzer
  (`examples/fuzz_lex/`, its short gate `lex/tests_fuzz.rs`) builds
  programs from known tokens and mutates them; its first run found a
  quadratic read of `'\'` repeated, fixed.
- **SQL and other text** keep the pack's lexer (`lexer.rs`, §6): SQL read
  as standard SQL and as MySQL reads it, any other text with `#` and `//`
  line comments, `/* … */` and quoted strings.

Every reading is linear and total (any text, no panic, every character in
at most one token). `lex.tokens` (one reading's tokens) and
`lex.structure` (what the detectors ask) expose them; `test_lex.py` holds
the JavaScript lexer's literals to `js_parse`'s literal nodes, span for
span, on the parser's own test inputs (curated snippets, the repository's
JavaScript, generated projects, token soups and mutations), and the Python
lexer's strings, f-strings and comments to Python 3.13's `tokenize`, on
the repository's Python, pyparse's curated cases and generated programs.
On the benchmark's in-sample files (the malicious releases and the popular
packages; never the holdout) the JavaScript lexer reads every literal of
the 26,903 JavaScript-family files that parse (3,154,720 literals) as the
parser does, but for four files' import attributes (`with { type: 'json'
}`: a string the parser keeps no node for), and the Python lexer every
string, f-string and comment of 19,044 Python files as Python 3.13's
`tokenize` does. (The first run found the lexer reading a regular
expression right after `else` as a division in six files: a statement,
so a regular expression, may begin after `else` and `do`.)

**What it changed** (phase 2's review of the recorded outputs, case by
case). On real files nothing: none of the 330,924 outputs on the
benchmark's files and the 230,400 on installed packages' files moved,
and the holdout's counts did not. The recorded outputs' adversarial
corpora moved where the old lexers misread:

- `scan_file` and `scan_rules`, 15 and 16 of 4,257 answers on the
  scan_file corpus: findings gone on a first line that is a hashbang (a
  comment, as Node reads it: 4 and 5), after a Python string prefix
  (`r'` is a string, not code: 2 and 2), in text both readings agree is
  text (a template's, read as JSX text by the other reading: 1 and 1),
  and in a block comment opened in a template's `${…}` (1 in
  `scan_rules`); findings new on look-alike names in a template's holes
  (8 and 8), and one decode-and-run whose comment only one reading saw.
- the import-time test's prose (`import_code`), 1,760 of the 44,893
  `signs_view` answers: 1,522 first-line hashbangs blanked as comments;
  JavaScript line comments that end at a CR, U+2028 or U+2029, so the code
  after them is no longer blanked (about 75); a template's holes and
  regular expressions read as JavaScript reads them; Python comments and
  string statements ending at a CR. The hooks corpus: 3 more
  import-time reasons, each for code the old lexer hid in a comment it ran
  on past a U+2028 or a CR.
- `lex_comment_spans` itself, on its dense random texts: 9,372 of 60,000
  answers, all JavaScript (with and without JSX) and Python; SQL and other
  text unchanged.

**The detectors' own quote scanners.** Several detectors find what is
code with a scanner of their own (`signs::literal_spans`, core's
`_literal_spans`: quotes paired as they come, a template whole), which a
quote or a backtick in a comment or in a regular expression throws off
for the rest of the line, or of the file — an evasion. The self-read
(`runs_own_source_at`: code run from what a file reads back from itself)
now reads a JavaScript or Python text (the import-time test's, whose
language it knows) with the lexers (`prose_spans`: literals and comments
are not code, a template's holes are); a text of no known language (an
install script, a hook's command) is still paired. Its read of a
function's own source (`}).toString()`) counts only where the function
ends in a comment, the payload kept there (`reads_prose`): read correctly,
playwright's bundles serialize functions to run in a page, which the old
pairing had hidden by accident (a quote in a regular expression made 63,000
characters of one bundle a "string"). The data flow, the dead drop and
the secret endpoints keep the pairing: read by the lexers, the names they
follow without scopes meet in minified bundles (playwright's
`mcpBundleImpl.js`: the environment in one function's `e`, a message
spread from another's `e` and sent), so they move to the lexers with
scopes (phase 3; two expected failures in `test_supply_chain_signals.py`
hold the evasions they still have). Of the 561,324 recorded real-file
outputs two moved, both gains: two releases of a compromised
`@emilgroup` package now show the self-read the pairing missed (they decode
a payload from their own `package.json` into a script a systemd user
service runs); the benchmark's and the holdout's counts are unchanged.

**String values, and the decoded view on them.** `value.rs` reads a
literal's value as its runtime does: a JavaScript string or hole-less
template by jsparse's cooking (every escape, line continuations, a pair of
surrogate escapes the one character it encodes), a Python string or bytes
literal by pyparse's reading of its body (prefixes, raw strings, `\N{…}`);
an f-string or a t-string is not a constant. It also finds the runs of
literals a runtime joins into one string: `+` between literals where
nothing binds tighter on either side (`x * 'a' + 'b'` joins only `'b'`,
`'a' + 'b'.trim()` nothing, a tagged template is a call), and Python's
adjacent literals, which its tokenizer joins before any operator (lines
apart only inside brackets or after a backslash; str and bytes never).
The decoded view of a JavaScript or Python text begins there
(`signs::dv_literals`): a literal holding a code escape (`\x41`, `\u0041`,
`\u{41}`, `\101`, Python's `\U…` and `\N{…}`: what obfuscation hides a
name with, not `\n` or `\'`) is written as its value, and a run as one
literal, where the value is printable ASCII without a quote or a
backslash; the line breaks a run spans follow it on its line, so the lines
after it keep their numbers. Where a JavaScript file may hold JSX, only
the runs both readings find. Before, the view unescaped only literals
written wholly in `\x` and `\u` escapes, three or more
(`'child_pro\x63ess'` stayed as written), and joined same-quote literals
on one line by a pattern, inside a string's own text too
(`"it' + 'x"`). As before, joining alone decodes nothing: the view is the
text itself unless an escape, a decoder's call, a string array or a proxy
object is read. Every caller that knows a text's language passes it, in
both packages: the import-time test, an install hook's targets and the
scripts they start (`engine.script_lang`: `.py` Python, `.sh` none, the
rest what node runs), a start-up module, the code a hook's command hands
`node -e` or `python -c`; a text of no known language (a hook's command, a
settings file's) keeps the patterns' reading.

What it changed: on the recorded outputs' corpora, 13 import-time answers
of the hooks corpus's generated cases, all gains (string arrays whose
accessor's base64 alphabet is a literal partly written in escapes, now read;
a `curl` written in escapes); the two new fields of `hooks_view` hold the
views. On real files none of the 561,324 recorded outputs moved; with each
file's language, the decoded view's text changed on 293 files (132 of the
benchmark's, 161 installed: an escape such as `"\x20"` read, members then
named by literals read as members) and the install-script test's reasons,
the scripts a file starts and the string array's line on none. The
benchmark's and the holdout's counts are unchanged. The review found and
fixed, before committing: a literal with an escape JavaScript refuses
(`'\x2'`) read leniently as jsparse's cooking reads it, which let a
generated file's second, broken string array displace its first; and past
a token Python's tokenizer refuses, strings read plainly (no punctuators
known) taken for adjacent ones, which joined a string array's items into
one: Python's gaps are now read character by character (blanks, comments,
continuations).

On the benchmark one release moved: num2words 0.5.15, SUSPICIOUS to
INCOMPLETE. Its `_build.py` is a Windows executable (an `MZ` header) named
as Python, SC-TRUNCATED as undecodable before and after; the look-alike
name the old lexer read in its machine code (`HcЅ`) is gone, and the
release still fails the gate (INCOMPLETE).

## 16. The cross-file JavaScript taint pass

`src/jsflow/` is a port of `lazaret.scanner.jsflow` (jsflow.py, project
mode's interprocedural JavaScript taint since 0.1.7), function for
function, onto `js_parse`'s trees: phase 3's first step (§8). Both packages
ask the engine for it (the Python package's `flow._analyze_js` through
`engine.js_flow`, the npm package's `scanner/flow.js` through
`native.js`'s `jsFlow`), and jsflow.py, its npm twin
(`js/src/scanner/jsflow.js`) and the readers they used (`jsparse.py`,
`js/src/lib/jsparse.js`) are retired: 11,357 lines of Python and
JavaScript.

**The model** (jsflow.py's). Each function gets a summary — which of its
parameters reach which sinks, what its return value carries — computed to
a fixpoint over the call graph, callees first; findings come from a last
pass over every function. `mod.rs`: values (`V`: request data with its
origin and the chain it came by, the parameters it carries, the categories
it is clean for, joined into a string or not, a request or response
object), scopes and bindings (var and function hoisting, block-scoped
`let`, `const` and `class`, parameters, catch clauses, imports), the
declaration and resolution passes. `descs.rs`: what names hold (a
flow-insensitive points-to over functions, classes and their instances,
object literals, modules, built-ins and packages), the functions a call may
reach (by binding, or by name where it cannot tell: at most four), route
handlers, the order the fixpoint reads functions in. `eval.rs`: one
reading of one function (flow-sensitive in it: branches merged, a loop's
body read again when its first reading changed a value), its sources and
sinks, the summaries it reads at calls and commits. `driver.rs`: the files
read, the fixpoint and the reporting pass, the configured part of the
model, and the output.

**What it answers.** `js_flow` (`{"files": [[path, length], …]}`, the
contents concatenated as the text, a length of null for a file whose
content is not text; `sources`, `sinks`, `full`, `partial`: the
configuration taintspec validated; `run_limit`: `[base, steps per node]`,
a lower limit for one function's reading, each part at most the default —
a host can make the pass cheaper, never longer) answers the pass's output
in jsflow.py's order: `["skipped_size", path, n, limit]` (X-FLOW-SKIPPED),
`["issue", category, path, line, source, sink, chain, file]` (`file`: the
index of the path's file in `files`, whose lines give the snippet) and
`["note", rule, name, path, line, msg, why, fix]` (Q-FLOW-SKIPPED,
Q-FLOW-INCOMPLETE); each host builds its findings from them, with their
snippets and redaction (`flow._issue`, `flow._flow_note`,
`flow._skipped_size`, and flow.js's twins of them). Where jsflow.py kept a
dict's insertion order or deduped with `dict.fromkeys`, so does the port —
the order of a call's targets decides which of them a finding names — and
the memoized points-to is filled in the same order (a cycle reads as
unknown while it is open, so what a memo holds depends on what was asked
first).

**Bounds.** jsflow.py's: a work budget per syntax tree node, a per-reading
limit, 50 re-analyses of a function, 2,000,000 code points a file and
8,000,000 a pass. The readings recurse on nested expressions and
statements as jsflow.py's did; the parser's nesting bound keeps the
deepest input of each construct under 512 KiB of stack natively (release;
`jsflow/tests.rs` reads each on a 2 MiB thread). A host's thread may have
less — a worker thread's default is 512 KiB on macOS and 128 KiB on musl —
so natively `js_flow`, `js_parse`, `js_loads` and `py_parse` run on a
thread of the engine's own with an 8 MiB stack (`api::OWN_STACK`; 64 MiB
in a debug build), one per calling thread, made at its first such call and
kept for the next (the engine's caches, compiled patterns among them, are
per thread), ending with the calling thread; a call from a thread of 128
KiB reads the deepest input of every construct (`jsflow/tests.rs`). It
costs about 50 µs a call and 7% of the pass over the 1,490 packages below.
In WebAssembly a call's frames are on Node's own stack (about 1 MB on its
main thread), its larger locals on the module's 8 MiB stack;
`test_wasm_parity_jsflow` reads the deepest input of every construct
there.

**Held to its recorded outputs.** `test_snapshot_js_flow` (§5): every
output, in order, on the corpus the port was held to jsflow.py on (the
review's cases, the engine's own, the caps, seeded generated projects,
token soups), with the default model and a configured one, and the call's
own cases (files that are not text, a lowered limit); the hosts' findings
from it are held to each other by `test_js_parity_flow` (every field of
every finding, the WebAssembly build's answers through flow.js against the
library's through flow.py), and the WebAssembly build's answers to the
library's by `test_wasm_parity_jsflow`. Until jsflow.py retired,
`test_jsflow_reference.py` held the port to it output for output on that
corpus, and so did, before each commit, 1,490 installed npm packages read
as projects (each package's own files, up to 1.5 MB), with the default
model and with configured ones that make `process.env`, `options.*` and
`args` sources (329 and 591 outputs): no difference; the engine took 10 s
where jsflow.py took 125 s.

## 17. The cross-file Python taint pass

`src/pyflow/` is a port of flow.py's Python pass (`_PyProject`,
`_Analyzer`, `_analyze_python`: project mode's interprocedural Python
taint), function for function, onto `py_parse`'s trees (§13): phase 3's
second step (§8). Both packages ask the engine for it (the Python
package's `flow._analyze_python` through `engine.py_flow`, the npm
package's `scanner/flow.js` through `native.js`'s `pyFlow`), and flow.py's
own pass is retired (1,505 lines of Python). The npm package had no port
of it: it now reports the same X-* flows on Python files as the Python
package, and its cross-file gate no longer says a project's Python files
were not analyzed.

**The model** (flow.py's). Every function, method, nested def and each
module's top-level code (a pseudo-function) gets a summary — which
parameters reach which sinks, which reach the return value and what they
are clean for there, a request source it returns — computed to a fixpoint
over the call graph, callees first; a last pass reports a source passed
into a function whose parameter reaches a sink, or reaching a sink as the
value another function returned. Calls are matched only to what they can
name (flow.py's resolution model: imports, re-exports and star imports,
nested defs, constructors, `self` and `super()` through the class and its
project bases, typed locals, an unknown receiver's method by name when at
most four project methods have it). Route handlers (Flask, FastAPI,
Django) get request data in the parameters their framework fills
(`frameworks.rs`, with `unparse.rs` for the annotations' and defaults'
texts, as `ast.unparse` writes them). `mod.rs`: modules, functions,
classes, names, imports, resolution, the frames; `eval.rs`: one reading of
one function, its sources, sinks and sanitizers, the summaries it reads at
calls and commits; `driver.rs`: the files read, the fixpoint and the
reporting pass, the configured part of the model, the notes.

Where flow.py iterated a set — a function's callees and callers, the
functions read again, a value's parameters — its order followed memory
addresses and could change from one run to the next; the port keeps the
order things were added in (a value's parameters: their signature's
order). A call's classification (a source, a sink's category, a
sanitizer, a result that carries no request text) depends only on its
callee's texts, so it is worked out once for each, when the call is
resolved.

**What it answers.** `py_flow` (`{"files": [[path, length], …]}`, the
contents concatenated as the text, a length of null for a file whose
content is not text; `sources`, `sinks`, `full`, `partial`: the
configuration taintspec validated (`full`: the configured full
sanitizers, the built-in ones being the pass's); `max_iters`,
`max_files`, `max_bytes`, `work_limit` and `run_limit` (`[base, steps per
node]`): lower limits, each at most the default) answers the pass's
output in flow.py's order: `["issue", category, path, line, source, sink,
chain, file]` (`file`: the index of the path's file in `files`, whose
lines give the snippet) and `["note", rule, name, path, line, msg, why,
fix]` (Q-FLOW-SKIPPED, Q-FLOW-RECURSION, Q-FLOW-INCOMPLETE); each host
builds its findings from them (`flow._issue`, `flow._flow_note` and
flow.js's twins of them). A file the parser refuses is noted as flow.py
noted it (a syntax error with its line, Python 2, NUL bytes, a lone
surrogate, nesting past the parser's limits).

**Bounds.** flow.py's time budget (120 s for the fixpoint, as much again
for reporting) is a work budget: 1,000,000 steps and 48 per syntax tree
node for the fixpoint, 16 more per node for reporting, 20,000 and 256 per
node of a function for one reading; and 50 readings of a function, 20,000
files and 64,000,000 characters, as before. A step is a node read;
following a long chain of links (a callee's or an attribute's dotted
name: `x()()()…`, `a.b.c…`) and the texts that makes are more steps past
64 (one per 16), so code that would cost its length squared — each link of
a chain read again at the next — is bounded by the budgets too (a chain of
9,000 calls: a Q-FLOW-INCOMPLETE note, in 0.14 s). Python's
recursion limit, where flow.py's recursive reading and collecting stopped
on deeply nested code (a Q-FLOW-RECURSION note: the file, or the functions
it was reading), is kept as a count of the frames flow.py would have held
when run from the `lazaret` command (`FRAMES`: a chain of 986 binary
operators is read, of 987 is not; a module's `elif` chain of 493 is read,
of 494 is not; its definitions are collected up to 991). flow.py's depended
on how deep its caller's stack was (the command, the MCP server, a test);
the engine's does not. Natively the pass runs on the engine's own 8 MiB
stack (§16); in WebAssembly its frames are on Node's own stack, about
1 MB, which the frames keep it within: `test_wasm_parity_pyflow` reads
every construct at its deepest.

**Held to its recorded outputs.** `test_snapshot_py_flow` (§5): every
output, in order, on the review's cases and seeded generated projects
(`pygen.py`: packages importing each other every way, every signature,
classes, routes of each framework, every sink, sanitizers, guards and the
syntax the pass follows), with the default model and a configured one, and
the call's own cases (files that are not text, each limit lowered and
raised, the frames, a chain whose work counts); the hosts' findings from
it are held to each other by `test_js_parity_flow`, and the WebAssembly
build's answers to the library's by `test_wasm_parity_pyflow`. Before the
port was committed it was held to flow.py's pass — its sets iterated in
order, without its time budget (`bench/pyflow_ref.py`) — output for
output, with no difference: on the 73 sets of files the test suite handed
it, on 1,200 more generated projects (5,682 outputs) and the snapshot
corpus (1,075), with both models, and on 455 projects read from the
installed packages and Python 3.13's standard library (each top-level
package or module, up to 1.5 MB: 6,157 files, 70 million characters),
with the default model and with one that makes `os.environ`, `kwargs`,
`config` and the like sources (54 and 676 outputs). On those 455 the
engine took 6.2 s where flow.py's pass took 55 s; on the generated
projects, 0.55 s (the parse included, 6.5 MB/s) where it took 7.7 s.

## 18. The data flow on the JavaScript tree

`src/jsflow/supply.rs` is the JavaScript taint pass's second model: the
supply-chain detectors' data flow — local data a script reads from the
machine, followed to a network send, and data it receives, followed to
code run — on `js_parse`'s trees, with names resolved by scope (phase 3's
third step, §8). The install-script and
import-time tests ask it for every JavaScript text (`signs::local_data_sent`,
for the text and its decoded view): it answers what the text follower
(`flow::local_data_sent_at`) answers — the first send, the kind of data,
what was read, whether only an address held it — and the reasons, their
grading and the destinations are the tests' as before. A text the parser
doesn't read (a fragment, TypeScript it can't, a file over 2 MB) or a
reading past the pass's budget is the text follower's to answer; so is any
text not handed as JavaScript or Python (Python's model is §19).

**Why.** The text follower followed names in a window of text: a quote in a
regular expression or a backtick in a comment opened a string over the
code after it, a name that meant two things in a bundle joined two flows
(playwright's bundle had a "whole environment sent" it didn't earn), 20,000
characters of padding or 5,000 assignments before the payload hid it, and a
name kept for a module (`const r = module.require; r('http')`) was not that
module. On the tree a name is its binding: none of these happen, and code
in a string, or a local object named `process`, is not what it looks like.

**The model.** The pass is jsflow's (§16) with values that carry kinds of
local data instead of request data (`Sc`: the first read of each kind, in
the text follower's names — identity, environment, file, report,
credentials, address), and three object marks: a connection or a request
being written (its `write`, `end`, `send` send), a client the script made
(`axios.create()`: its calls send), and `process.env` itself (a member of it
is one variable). Sources and sends are the text follower's, from the same
tables of the rule pack: an environment variable by its name, the whole
environment (a selection of it by a test that names no secret is not), the
os module's names, a read of a path outside the package (`flow::ld_outside`,
and a path passed in: `dump('/etc')`), what a command prints
(`shell::sh_output_data`), the instance's metadata and a public-IP lookup;
the sends of `_LD_SEND_RE` and its siblings, with the arguments they count
as addresses, resolved by binding (`require`, `import`, `node:` names,
`require` and `module.require` kept under another name, a module's name no
declaration binds), and a URL literal whose host the data continues
(`'https://' + host + '.x.example'`: resolved, so sent). What the pass adds
to follow them: a callback of anything but the script's own functions gets
what the call holds (a read's callback what was read: `exec(c, (e, out) =>
…)`); a parameter written to a closure's variable is in the function's
summary (`res.on('data', d => body += d)`), and so is a parameter of a
function around it written to a variable declared outside that function
(D-15, 0.1.9: `p = body` in the `'end'` callback, `p` the module's: the
value written cannot carry the parameter there); `this.x` and a name no
declaration binds are bindings of their own; what a container's `push`,
`unshift`, `splice` (its items), `set`, `add`, `append` or `fill` is given
the container holds, and so does the target of `Object.assign`,
`Object.defineProperty(ies)`, `Reflect.set` and `Reflect.defineProperty`,
when it is a name (D-3, 0.1.9: only an array's `push` and `unshift` were
followed, so the environment put into a `FormData`, a `Map` or a `Set`
and sent was not seen; a member's container, `o.list.push(x)`, is not
followed: put into the object that holds it, it joined unrelated flows in
vite's bundle and monaco-editor's loader); the script's own wrappers of
exec, of a read and of `process.env[name]` are summaries too
(`run('whoami')`, `getEnv('AWS_SECRET_ACCESS_KEY')`). A child process
doesn't hold what it was given, nor a length the data it measures.

**Copies and holders of the environment** (0.1.9, D-16). process.env's
mark is kept by a name it is given, not by a parameter whose default it
is, an object's member, a copy (`{ ...process.env }`, `Object.assign({},
process.env)`) or what a call returns, and an object's members are read as
the whole object, so a member of such a value read the whole environment:
prisma 8.0.0-rc.21's `getApiBaseUrl(env = process.env)` reads
`env.PRISMA_MANAGEMENT_API_URL`, and the Management API's answers that
address reached were sent in an address of their own (SUSPICIOUS). Now a
member of a value holding the whole environment and no mark is read by its
name (`sc_member`): a variable's (capitals, digits and underscores;
`npm_*`; the proxies', `env_var_name`) is that variable, as process.env's
own member is; one with `env` in it (`env`, `environment`) is all of it;
any other is not the environment (corepack 0.36.0's env file gives `{ env:
<a copy>, path }`, and its caller's `localEnv?.path` is a path). A
parameter is read so too: a value read through a member of it of such a
name, or a method of its own called on it (not one of the built-in ones
that give back what the object holds, `PASS_THROUGH`: `join`, `map`,
`then`, `toString` …), holds the parameter's key with `MEMBER_KEY` set
(`V::through_member`; `key_owner` and `key_index` read the key without
it), and the function's summary keeps, for what it returns (`ret_params`)
and for each sink a parameter reaches (`reach_member`), whether it holds
the parameter only so; a call gives such a parameter its argument without
the whole environment (`sc_through_member`). prisma's telemetry sender
builds its event in `buildTelemetryEvent(payload, config, env)` from
`env.platform`, `env.env.npm_config_user_agent` and
`env.readProjectPackageJson()`, given `{ env: process.env, … }`. The copy
or the holder sent whole, the holder's `env`, and a parameter returned or
sent whole (or beside a member of it) are still the whole environment. A
holder of the environment under another name, read by that name and sent
(`{ data: process.env }`, then `payload.data`, here or in a function given
it), is no longer it.

**A JSON file given require** (0.1.9, D-18) is parsed and runs nothing:
the module-name sink leaves out a `require` whose argument ends in a
literal ending in `.json` (`sc_json_module`; corepack 0.36.0 requires the
package.json of the package manager it downloaded,
`require(path.join(tmpFolder, 'package.json'))`).

**The strongest send.** A value keeps the first read of each kind, and a
credential store (`_CRED_STORE_RE`, not a public key) apart from other
files. A send is reported by the strongest data it carries — the
instance's credentials, the whole environment or a credential store,
which the import-time test grades as a harvest — over what was read
before it, and of several sends the one carrying such data, else the
first. The text follower answered the first read in the payload's text,
so a payload's field order decided its grade: `{ host: os.hostname(), env:
process.env }` was a host name, and psdimporter's report, which runs
`whoami` before it asks the instance's metadata, had no import-time
reason at all.

**Held to** the text follower on real code before it replaced it: on the
benchmark's 20,066 in-sample JavaScript files and 28,125 files of installed
npm packages, the two answer alike except where the text follower was
wrong — a local `process`, code in a template string, a test of a logger —
or the tree reads more: a flow through a closure, a callback, a wrapper,
`this` or an implicit global (the differences, file by file, are reviewed in
the phase's audit). `jsflow::supply::tests` hold each piece; the
`test_supply_chain_signals` case the lexers couldn't pass (a quote in a
regular expression) passes. Of the hooks corpus's 44,893 recorded outputs
two moved: a whole environment sent through a module the code names in hex
is found in the text itself, no longer only in its decoded view; and a
Python snippet handed as JavaScript (the view asks every case as both) is
read as JavaScript, where it sends nothing.

On real files: of the 330,924 outputs recorded on the benchmark's files,
48 import-time answers moved, all of malicious samples. 25 point at the
send itself (`req.write(data)`) instead of the request it writes to; 12
find the flow in the text where the text follower found it only in the
decoded view, or the reverse (an obfuscated payload whose module names
are in its string array); 6 name another kind: the whole environment
for three, where the text follower had the host name of the payload's
first field (osae, slack-astra-app), and another kind of local data for
three; 4 gain a reason they lacked (the whole environment sent by a
postinstall, a flattened telemetry runner and a compromised library's
`env-compat.cjs`; react-milton's file sent to an IP address); one loses
one: a React component that shows the payload's code in a `<pre>` block,
which the text follower read as code (its package is still caught by its
`index.js`). None of the 230,400 outputs recorded on installed packages
moved.

**Received code.** The same reading answers the received-code test
(`received::received_code_kind` on raw text, for the install-script and
import-time tests): data the script receives over the network run as code
(`eval` and its indirect forms, `Function` and the constructors that are
it, `vm`, `Module._compile`, a command line that is the data, an
interpreter given it as code), a module loaded by a name it gives, or a
deserializer given it (`unserialize`, `yaml.load`). What a request
receives — its response, what its callbacks are given, a connection's or a
server's data, a WebSocket's messages, what a `curl` or `wget` command
prints — is received when the script addresses it itself: an address that
isn't its caller's (a parameter, `this`, `arguments` or what is made of
them), or one it read or received (a dead drop's). A request a library
makes for its caller — `load(url)`, `request(options)`,
`` `${this.baseUrl}/x` `` — is not the script's download, and a browser's
XMLHttpRequest isn't followed (jQuery 1.x's script converter and
CoffeeScript's `<script type="text/coffeescript">` loader both run what it
fetches). A response holds what was received, not what was sent. The
script's own downloader called with its own address (`const get = (u) =>
fetch(u)`) returns what is received; a command taken from a constant list
(`for (const c of ['id', 'env']) execSync(c)`) prints what any of them
prints; a variable of the environment holds what the script stores in it.
A command line that runs a fixed program with the data as its argument
(`` `curl …?ip=${ip}` ``, `npm publish --registry=…`) runs no code it
received; an interpreter given it (`node -e`, `sh -c`) does.

Held to the text detector in the same way: on the benchmark's 20,066
in-sample JavaScript files the two agree but for three — two payloads the
tree finds (model-providers' aliased `module.require` and
`Module._compile`; a response's field run by `eval` in a callback) and a
text-detector false positive (a recon script whose commands are
constants; the data flow now reads what they print, the whole
environment, sent) — and on 28,125 installed files they agree. On the
benchmark's files nine more import-time answers moved, all of malicious
samples: those two payloads, that recon script, and six obfuscated
payloads that send the whole environment as well as run what comes back
(found in their decoded view, whose names `o[['post']]` now resolve). Of
the hooks corpus's outputs 27 moved: code in strings, now a stager's
text; Python handed as JavaScript; the third argument of `eval`; and one
obfuscated payload that now also sends the environment. Generated probes
(132) found what the text detector finds and also padding, a runner far
from the request, an aliased require, without its two false positives (a
library's loader, code in a string). Known gaps: an address kept in a
class field (`this.url`, read as a caller's), and an index into a string
array the decoded view didn't resolve.

## 19. The data flow on the Python tree

`src/pyflow/supply.rs` is the Python taint pass's second model, as §18's is
JavaScript's: local data a script reads from the machine, followed to a
network send, and data it receives, followed to code run, on `py_parse`'s
trees. The install-script and import-time tests ask it for every text
handed as Python (`signs::local_data_sent`, `signs::received_code`); a text
the parser doesn't read (Python 2, a fragment, bytes), over 2 MB, or past
the pass's budgets is the text detectors' to answer.

**The model.** The pass is pyflow's (§17) — summaries of the script's own
functions to a fixpoint, `self.x` through the class, module globals — with
values that carry JavaScript's kinds of local data (`Sc`) and marks for
what a value is: a connection (`socket.socket()`,
`http.client.HTTPSConnection`: what it is written is sent, what it reads is
received), an HTTP client the script made (`requests.Session()`,
`httpx.Client()`, `aiohttp.ClientSession()`: its calls send and receive), a
request object (`urllib.request.Request`: handed to a send, its data),
`os.environ` itself (a subscript or `.get` reads one variable), and a
request to the instance's metadata or a public-IP service. Sources are the
text follower's, from the same tables: an environment variable by its name,
the whole environment (`os.environ`, `os.environb`; a comprehension that
selects variables by a test that names no secret is not), the os, socket,
platform and getpass modules' names, a read of a path outside the package
(`open`, `os.listdir`, `glob`, `sqlite3.connect`; `Path(x)` is a path, read
by `read_text()`, `open()`), what a command prints (`check_output`, `run`,
`Popen`, `getoutput`, `os.popen`), the instance's metadata and a public-IP
lookup. Sends: requests' and httpx's `post`, `put`, `patch` (the address
first), `get`, `head`, `delete` (all of it an address), `request` (a
method, then the address), urllib's `urlopen` and `Request` (and Python 2's
`urllib.urlopen`), a session's or a client's calls, a connection's `send`,
`sendall`, `write` and `request`, a DNS lookup of a name composed with a
literal (in the call, or where the function or the module gives the name
its value), a network program given data on its command line (its process
options, `env=` and `cwd=`, are the program's), a URL whose host the data
continues (an f-string, `+`, `%`, `.format`), and an object named `session`
or `client` made where the model doesn't see (the text follower's name
test).

What the pass adds to pyflow's to follow them: a closure's variables (what
the function around it gives them), the globals a function declares
`global`, a thread's, a timer's or an executor's target given its
arguments, what an object's attribute or a container's `append` or `update`
is given (the object holds it), a container of the module's that a function
fills (`INFO['h'] = …`, `DATA.append(…)` where the function binds no such
name: the module's value holds it), a container on `self` or another
object, or in another container, that a method fills (`self.info['h'] = …`,
`self.items.append(…)`), a variable of the function around a def that the
def assigns `nonlocal` or fills, a class's own statements (run when it is
defined; what they assign is the class's attribute, read by `self.x`), a
parameter's default where a call gives none, a lambda's body (a name given
a lambda and called by it: the body, given the call's arguments), what a
lookup answers for a name it is given
(`socket.gethostbyname(socket.gethostname())`: the machine's address), a
variable of the environment the script stores something in, and the
script's own wrappers of exec, of a read, of the environment and of a
download (`run('whoami')`, `env('AWS_SECRET_ACCESS_KEY')`), given their
argument by position or by keyword. A callee is named through an import
alias, an alias of its own (`s = os.system`), `getattr(m, 'x')`, a
namespace's dictionary (`__builtins__.__dict__['exec']`,
`globals()['eval']`), or, in a snippet that leaves out its import, the
library a bare `urlopen` or `check_output` usually comes from (and a star
import's names: `from socket import *`). Not the data: a length, a flag or
a checksum, what a child process was given, what a file holds for what its
path was made of. A digest, characters' codes or a number written out still
are (`md5(host).hexdigest()` is the machine's id).

**Received code.** Python's runners (`exec`, `eval`, and `compile`'s code
run by them; `os.system`, `os.popen`, `subprocess` with `shell=True`; an
interpreter given `-c` and the code, `[sys.executable, '-c', code]`),
importers (`importlib.import_module`, `__import__`) and deserializers
(pickle, marshal, dill, cloudpickle, jsonpickle, `yaml.load` without a
safe loader). What a request receives from the script's own address — a
response's text, content or JSON, a socket's `recv`, what `curl` or `wget`
prints — reaching them is the finding. A request to an address the caller
gives (`def load(u): exec(requests.get(u).text)`, `self.url`) is a
library's, unless the script calls it with its own address
(`load('https://…')`: the parameter's reach, the address of what is run,
is in the summary). A fixed program given received data as its argument
(`os.system('curl -d ' + d)`, `run(['ls', name])`) runs no code it
received, and code in a string is a stager's (the stager test), as in
JavaScript.

**Held to** the text detectors on real code before it replaced them: on the
benchmark's 35,088 in-sample Python files and 9,819 files of installed
packages, the two answer alike but for 44 files: 29 of 13 malicious
releases, 13 of six popular packages and two installed ones. The tree reads
what the text missed (a flow through a closure, a thread's arguments, a
session, a request object given its data afterwards: s3transfer-sl's
setup.py; the reverse shells of ReverseShell 0.1.0, which run what a socket
receives), and drops what the text read wrong (a name that meant two things
in pip's `distlib/util.py`, a method named `fetch` in dulwich, a path
normalized in reportlab, an instance-metadata URL in an address in jax and
an OpenTelemetry detector). Nine of the popular packages' files (litellm's
and inspect-ai's SDK modules) send one variable by the tree's reading, its
key or its host to its service, where the text read none or another: an
SDK's shape, which the import-time and use-time tests don't grade. Of 522
generated probes (six kinds of local data sent five ways, four kinds of
received data run seven ways, each through nine shapes: a function, a
return, a class, a closure, a dictionary, 2,500 lines of padding, triple
quotes in a comment …) the tree finds all, the text detectors 353. A
comparison on the holdout, in aggregate, led to 181 more probes of beacon
shapes, a machine's names sent to a collector. They showed the tree missing
what the text detectors caught in 15 shapes, all since fixed: containers
filled on objects and through closures, class bodies, lookups, digests,
star imports and the others above. Of the 181 the tree finds 159, the text
detectors 136, and every one the text detectors find.
`pyflow::supply::tests` hold each piece; the `test_supply_chain_signals`
case the lexers couldn't pass (triple quotes in a comment) passes. Of the
hooks corpus's outputs 18 moved: JavaScript handed as Python (`fetch` is no
Python call), code in strings (a stager's text) and code in comments. On
the benchmark's files 19 import-time answers moved, all of malicious
samples, and none of the installed packages'. No in-sample verdict moved;
eight malicious releases' findings name more exact data (what `ifconfig`
reports rather than the host name, a public IP address) or gain received
code (ptmpl). On the holdout, two PyPI releases moved from OK to SUSPICIOUS
and two from SUSPICIOUS to OK, each on the install hook's host-name send.
The two lost ones were opened (with the maintainer's approval; they leave
the holdout). They're a dependency-confusion beacon that looks up, in a
loop, a name an f-string composed on the line before, which none of the 15
shapes covered. A lookup now follows its name to that value, and both are
found. On the 745 releases left, 629 are SUSPICIOUS (84.4%; 627 at 3e).

## 20. Droppers and decoded code, on the trees

The supply-chain models of §18 and §19 answer two more questions: code the
script decodes and runs, and a file it writes and then runs (0.1.8's
droppers). Both are new kinds in the models' values (`Sc`): decoded data
(`K_DECODED`), a binary's bytes (`K_BYTES`), a slice of them past their
start (`K_CARVED`), and a file opened to write (`K_WFILE`).

**Decoded code run.** A decoder's result is decoded data. In Python: base64
and its relatives, hex, `codecs.decode`, zlib's, gzip's, bz2's and lzma's
decompressions, `marshal.loads`, a `decrypt`, `decompress` or `fromhex`
method (`Fernet(k).decrypt(d)`), characters made of their codes (`chr(c) for
c in codes`, `map(chr, codes)`; not a single `chr(n)`: numpy's crackfortran
evaluates `chr(params[n])`), an XOR of the data, and a reversal (`s[::-1]`).
In JavaScript: `atob`, `Buffer.from(x, 'base64' | 'base64url' | 'hex')`,
zlib's synchronous decompressions and a `decrypt` method; characters' codes
and the like are the decoded view's to read there. Decoded data that reaches
code run (`eval`, `exec`, `Function`, `vm`, `compile`; an interpreter given
it as code, `node -e`, `[sys.executable, '-c', code]`; a command line that
is the program) is reported with where it was decoded (`decoded_runs_tree`).
A WebAssembly module made from decoded bytes is not code run
(es-module-lexer's, in tsx and vitest).

SC-EVAL-DECODE in dependency scans asks it. The text's reading (a decoded
name followed within `DEP_FLOW_WINDOW` to a sink) finds candidates, and
skips literals: a decode call or a sink in a string, a template's text or a
regular expression is not code. A JavaScript or Python text with a
candidate, or one that writes out a decoder the text's reading doesn't know
(`_TREE_DECODER_SHAPE_RE`: an XOR, characters made of their codes, a
reversal, the rarer base64 relatives, `marshal`, gzip, bz2 and lzma; in
JavaScript zlib's synchronous decompressions and hex) and calls a runner
(`_TREE_RUN_GATE_RE`, an indirect eval), both in code (`FileCtx::in_code`: a
comment's "O(n^2)" is no XOR), or (0.1.8) a Python text that uses a decoder
the text knows (`_TREE_PY_KNOWN_DECODER_RE`: base64, hex, zlib, `codecs`) and
a shell (`_TREE_PY_SHELL_RE`: `os.system`, `os.popen`, `subprocess`, `pty`),
since the text's sinks have no shell for Python while JavaScript's
child_process is one, is read on its tree, whose answer stands: it
drops a candidate whose value never reaches the run and finds what the
window misses. It counts the sinks the text's reading counts (any object's
`execSync`; child_process imported with `await import(…)`, a dynamic import
of a literal being that module in the supply-chain model), and a decode
inside the run's call is "in the same call". Other texts, and texts over the
trees' 2 MB, keep the text's reading. A tree costs several times the text's
reading, and the gate keeps `scan_file` where it was: on the eleven largest
files of the profile (litellm, botocore, playwright-core) 0.63 s against
0.64 s before, best of three, and the import-time test, which asks the
models for every text, 3.21 s against 3.21 s (the hooks every call passes
compare a name's length before its characters).

**A file written, then run.** The models record what the script writes
where: `open(p, 'w…')` and the `write` of what it returns, `Path(p).write_bytes(d)`,
`urlretrieve(url, p)`; `fs.writeFileSync(p, d)`, `fs.createWriteStream(p)`
and what is piped or written to it. A path is matched by keys: its text in
its scope (the function in Python, the binding in JavaScript) and the string
it holds (a literal path, a joined path's literal end). A run of it is an
argument list or a command line naming it (`subprocess.run([sys.executable,
p])`, `execSync('node ' + f)`, `os.system(f'sh {p}')`), read as parts: a
command's start is its program; after an interpreter and its flags, its
script; a constant command line is read as one (`received::command_runs`).
What the file held decides the reason (`signs::dropped_reason`):

- code or a program the script decodes: "writes code it decodes to a file
  and runs it with Python" (or "writes a file it decodes and runs it");
- a program carved out of another file (a slice of a binary read past its
  start, requests-darwin-lite's shape): "runs a program it extracts from
  inside another file (docs/_static/logo.png)", a strong reason;
- a script it downloads, run by an interpreter: "downloads a script and runs
  it with node".

A binary downloaded and run is not reported: installers do that (esbuild
runs `--version` on the binary it fetched). `cmd` runs a batch file (`.bat`,
`.cmd`) as a script and anything else as a program. A file opened to write
and read (`'w+'`, `'a+'`) is read too. The install-script and import-time
tests report the first such run next to the text detectors' reasons of the
kind: one reason per kind, and one that names the interpreter takes the
place of one that names none (the text's "downloads a file and then runs
it" for `cmd /c x.bat`).

**A file written through a parameter** (0.1.9, D-2). In JavaScript a
download most often comes in as a callback's parameter: the request
client's body (`request.get(u, (e, r, body) => …)`), https.get's response,
its chunks gathered in `data` and written in `end`, or piped into
`fs.createWriteStream(p)`; or a helper writes what it is given. A
function's summary keeps the files a parameter is written to
(`Fn::param_files`: the path's keys, where), apart from its eight
categories' 8-bit mask, which is full: when a call gives the parameter a
download, or code the script decodes or carves out, the file is written
(`sc_param_file`), and a parameter of the caller's given to it is written
there through the caller (a helper's summary carries to the callback that
calls it). The write is then known only when the client gives the callback
the download, after the callback that runs the file was read, so a run of
a file no write is known for yet is kept (`Supply::runs`) and matched
against what is written at the end (`late_drops`). A program downloaded
and run stays an installer's; a download written and not run, and what a
callback is given by a read of the package's own file, are not reported.

**Code written into another package's folder** (0.1.9, D-9). The
JavaScript model's values have one more kind, a path in another package's
folder (`K_PKG`, what: the package): `require.resolve('<pkg>…')` (Node's
`require`, or one `createRequire()` made, as ES modules do; the model's
descriptions name no member of `require`, so `sc_require_resolve` reads
the call), `import.meta.resolve('<pkg>…')`, and a path joined
(`path.join`, `path.resolve`) from `node_modules` and a package's name
among its literal parts (`'node_modules', '@scope', 'name'`, or
`'node_modules/name'` in one part; a dot folder such as `.cache` is no
package), carried as every value is, through variables, a function's
return and a list's items. A code file (a literal ending in `.js`, `.cjs`
or `.mjs` in the path's text, or in what the name it is given holds)
written there (`writeFileSync`, `writeFile`, `appendFile*`,
`createWriteStream`) or copied or moved there (`copyFile*`, `rename*`,
`cp*`, their second argument) is `Out::Rewrote` (the write's offset, the
package), and the install-script and import-time tests give each package
"rewrites another package's code (the package)", a strong reason
(`signs::rewrite_reasons`). The API's `install_script_risk` and
`import_time_risk` take the release's name as `own` (`signs::own_release`,
for what the call reads, a command's inline code too): its own package's
code, or one of its scope's, is its own. @dinzid04/libsignal-node 2.2.5
writes over @whiskeysockets/baileys's `lib/Socket/newsletter.js` a second
after it is loaded.

**Held to** `jsflow::supply::tests` and `pyflow::supply::tests` (each
shape above, and its negatives: a binary installer, a whole file copied, text
written, `tarfile.open` and a browser's `open`, another function's local
name, numpy's `chr`, es-module-lexer's WebAssembly) and
`tests/registry/test_droppers.py`. On the benchmark's 55,154 in-sample files
the trees find decoded code run in 44 and a file written then run in 10, all
of malicious releases: requests-darwin-lite's executable carved out of a
documentation PNG, durabletask's and guardrails-ai's downloaded scripts run
with Python, ptmpl's run with bash, @cloudplatform/single-spa's with node,
and code decoded and run in jupyter-calendar-extension, reportgenpub,
litellm 1.82.7's compromised proxy and telnyx. They find none in the popular
packages' files or in 38,363 installed files. Before the fixes above they
found numpy's crackfortran (in the popular packages, in a compromised
package's copy of it and in the installed numpy), vitest's mocker and tsx's
two copies of es-module-lexer. On the benchmark, of the 330,924 outputs
recorded on its files 18 moved, and none of the 230,400 on installed
packages. No popular package is SUSPICIOUS any more: cypress's typings'
look-alike keyword is MAJOR; jiti's bundle, whose decoded value the
text's window followed to an `eval`, is read on its tree, where the value
is never run; and inspect-ai's decode and `new Function` are a web
worker's source, a template literal in a 6 MB bundle, which the text's
reading now skips. Three malicious releases become
SUSPICIOUS (448 of 516): pywhool (an XOR decoder in setup.py, its result
run by `eval(compile(…))`), requests-darwin-lite and quasarlib; five more
gain a reason. The holdout gains two PyPI releases
(631 of 745), both sharing no code with the benchmark.

## 21. The Rust reader (R-1)

`rs_crate` reads a crate's `.rs` files for what their code does when the crate
is built, when it starts and when it is used, so that `lazaret guard cargo` and
the registry can judge a crate instead of marking it INCOMPLETE (the engine had
no Rust detectors). The reader is `crates/lazaret-engine/src/rsread/` and uses
`rsparse` (the items and the token bodies, §3) and `rsparse::hooks` (the build
script's `main`, `#[proc_macro…]`, `#[ctor]`, load sections, `#![no_main]`).

The code of each moment is read with the test that Python's and JavaScript's
code of the same moment gets (§18–§20), with the same reasons and severities:

- the **build script** and a **procedural-macro crate** run on the machine that
  builds a dependent, the analog of an npm install hook and an sdist's
  `setup.py`: the install-script test, every reason CRITICAL (SC-INSTALL-HOOK);
- the **start-up functions** (`#[ctor]`/`#[dtor]`, `#[no_mangle] extern fn main`,
  a `.init_array`-like section, `#![no_main]` with `#[start]`) run before a
  binary's `main`, the analog of import-time code: the import-time test
  (SC-IMPORT-RISK; the strong reasons CRITICAL, the rest MAJOR);
- **everything else** runs when the crate's code is called: the import-time test
  of which only the strong reasons count (SC-USE-RISK).

The reading evaluates the code the way the trees' data flow does, not with
patterns over text. `ast.rs` reads a function body's statements and expressions
from `rsparse`'s tokens (it is not Rust's parser: what it cannot read is one
`Unknown` leaf and the rest is read; nesting is bounded, so no input recurses
past it). A value (`model/val.rs`, shared with Go's reader) is the text the code builds where it builds one
(`format!`, `concat!`, a `+`, a constant, base64 or hex decoded, a byte slice
read as UTF-8; Rust's literals and `format!` are `rsread/lit.rs`), the items of a list, the data it carries (the supply-chain
kinds of §18) and the handle it is (a `Command`, an HTTP request, a `TcpStream`,
a file open for writing). `eval.rs` walks the entry points of each moment,
following the crate's own functions (a few calls deep, within a step budget),
its closures and its methods; then it reads on their own, their parameters not
known, the functions of the moment that reading did not reach: every function
of a build script and of a procedural-macro crate (all of that code runs at
build), and every function a start-up function calls by name, however deep. It
records what the code does: a process started
(`std::process::Command`, read as a shell reads its line, with `sh -c`/`cmd /c`/
`powershell -Command` scripts pulled out), data sent (`std::net`, reqwest, ureq,
minreq, attohttpc, curl, raw sockets), a file written and then run or loaded
(`libloading`), a name looked up (`ToSocketAddrs`, hickory/trust-dns, including
TXT records — the Go DNS-backdoor shape). The sources are std's and the usual
crates' (`env::var`/`vars`, `fs::read`, `dirs`/`home`, `whoami`/`hostname`,
command output, a response). The events and what every language reads the same way (a command's line as a shell reads it, the download a command writes to a file, an environment variable's kind) are `model/events.rs`, and `model/facts.rs` turns the events into what the tests
ask (`signs::ModelFacts`): the strongest send and where data goes, code received
and run, a file written then run (either reason ends ", out of sight (no window, or
its output thrown away)" when the program is started with its window hidden or
no console, or with its output sent to null: GR-8), the commands run, and what only the model
sees (a shell or an interpreter whose stdio is a connection — a reverse shell; a
DNS lookup of a name built from the host name and a public domain, as the text
detector reads a lookup). The tests still read each file's text too, for
the signs a literal shows (a stager, a reverse-shell command, a raw IP), with
comments, tests (`#[cfg(test)]`, `#[test]`) and the code of another moment
blanked.

A crate is read as its compilation units: the build script's files, the
library's (`src/lib.rs` and the modules it declares, `#[path]` included) and the
binaries' (`src/main.rs`, `src/bin/`). `tests/`, `benches/` and `examples/` are
never built into a dependent and are not read. `SC-USE-RISK`'s reading is
bounded as the registry bounds Python and JavaScript (smallest files first,
within a character budget, so every machine reads the same files); `useRead`
says how much it read.

The reading has bounds, and a reading that reaches one says so. `ast.rs` counts
every form it reads within itself against its depth (`MAX_DEPTH`), reads the
operators of one level as a flat chain and a chain of postfix operations up to
`MAX_LINKS`, so no tree is deeper than its bounds; the evaluator's own nesting
stops at `MAX_NEST`, a reading records at most `MAX_EVENTS` events and makes at
most `MAX_CLOSURES` closures, and the text a step copies is charged to its
steps. A reading that runs out of steps, nesting or events is cut short, and the
moment's text is then read by the text test as well, as a Python or JavaScript
file the models cannot read is: code that pads or spends the reading's steps
before its payload hides nothing the text shows. (The bounds, the readings of
every function of a moment and the fallback are the review of Oct 4, RR-1 to
RR-11 in `audits/lazaret-go-rust-code-review-2026-10-04.md`.)

Nothing changes for Python or JavaScript: the install-script and import-time
tests take a model's facts only when one is given (the text path is untouched,
held identical on the benchmark and the recorded snapshots). The registry and
the guard call `rs_crate` on every crate they scan (Part C, `repo.py`'s
`_package_code`); the call takes the request's text as it is, without a copy
of each file (`api::call_owned`). On Ubuntu 24.04's 2,122 packaged crates
whose licences allow it, it reads 34,000 files in 26 s and finds nothing.

## 22. The Go reader (G-1)

`go_package` reads a Go module's files for what their code does when a program
that imports the module's packages starts, and when it is used, so that `lazaret
guard go` and the registry can judge a module instead of marking it INCOMPLETE.
The reader is `crates/lazaret-engine/src/goread/`, on `goparse`'s trees (the
tree `go/parser` builds, §15) and `goparse::hooks`, and on the values, events and
facts it shares with the Rust reader (`model/`).

Go runs nothing at install, but a package's code still runs at moments its user
did not choose. Each is read with the test Python's and JavaScript's code of the
same moment gets:

- **at start**: every `init` function and the initializer of every package-level
  variable that calls something run when any program that imports the package
  starts, the analog of import-time code: the import-time test (SC-IMPORT-RISK;
  the strong reasons CRITICAL, the rest MAJOR). So does a cgo preamble's C with
  a constructor (`__attribute__((constructor))`, `.init_array`), or C that init
  code calls;
- **when used**: everything else, a command's `main` included: the import-time
  test of which only the strong reasons count (SC-USE-RISK);
- `//go:generate` runs only when someone runs `go generate`, and
  `//go:linkname` runs nothing: both are listed in the answer (`generate`,
  `linkname`), never judged.

A module is its packages, one per folder, each read as one unit, as Go compiles
it: a package's functions, methods, types and package-level names are found
across its files, and a call of another of the module's packages (an import of
the module's path, `module` in the call; or, with none given, an import that
ends in one of the module's folders) is followed there. What no build of a
dependent reads is left out: `_test.go` files, files whose names start with `_`
or `.`, `testdata/`, `vendor/` (other modules, read on their own) and files
constrained to `ignore`. A folder whose name starts with `_` or `.` is read: an
import can name it. A `.go` file the parser refuses could not be built, so
nothing in it runs; the answer lists it (`unparsed`) for the text rules.

`eval.rs` evaluates the code as the Rust reader does (§21), on the tree: a value
is the text the code builds (`+`, `fmt.Sprintf` with `fmt`'s verbs,
`strings.Join`, `Replace`, `Repeat`, a string array read by index — the 2025
typosquats' shape —, a byte slice read as a string, `[]byte` and `[]rune`,
base64 with a standard or a custom alphabet, hex, `url.QueryUnescape`,
`strings.Map`), the data it carries and the handle it is. Both branches of an
`if` and every case of a `switch` are read; a loop is read once, or for each
item of a list it knows (a few, or all of them up to 4,096 when its body only
computes: a decoder's loop, `data[i] ^= key[i]`, is run index by index); a
goroutine and a deferred call are read where they are written; a closure sees
and changes its function's names. Package-level variables are read when first
used, constants with their `iota`, and `//go:embed`'s variables hold the bytes a
build puts in them. The APIs it knows are the standard library's (`os/exec`,
`os`, `os/user`, `io`, `bufio`, `net`, `net/http`, `crypto/tls`, `syscall`,
`plugin`, `path/filepath`, `strings`, `bytes`, `strconv`, `fmt`,
`encoding/base64`, `encoding/hex`, `compress/*`, `net/url`) and
`golang.org/x/sys/windows`'s: processes started (with a shell's input set to a
script, and `SysProcAttr`), requests and their bodies, connections, DNS lookups
(TXT records among them: the `shopsprint/decimal` shape), files written, made
executable, renamed and run, plugins and DLLs loaded. The init code's reading
starts from the initializers and the `init` functions in Go's order, then reads
on its own every function they reach by name, however deep.

`cread.rs` reads the C a cgo package compiles in: the preamble (the comment
before `import "C"`, its contents read as C where they are) and the package's
`.c` and `.h` files. It is not a C parser: it reads the calls that run a
program or load a library (`system`, `popen`, the `exec` family,
`posix_spawn`, `WinExec`, `ShellExecute`, `CreateProcess`, `dlopen`,
`LoadLibrary`) with the strings they are given (adjacent literals joined, C's
escapes, a `#define`d string), and whether the C has a constructor.

What every reader shares changed with it (`model/events.rs`): a shell's or
cmd's script is read command by command, so a file one command writes and the
next runs (`wget -O /tmp/x … && bash /tmp/x`, `certutil … %TEMP%\u.exe &&
%TEMP%\u.exe`) is a file written then run, in Rust's reading too; certutil,
bitsadmin and PowerShell's `Invoke-WebRequest -OutFile` downloads are read
wherever they are; and `wget -O -` (standard output) writes no file.

The bounds are the Rust reader's (§21), built in from the start: `goparse`'s
trees are an arena (dropping one recurses into nothing), chains (`a + b + …`,
`if … else if …`) are walked rather than recursed through, the evaluator's
nesting stops at `MAX_NEST`, a reading records at most `MAX_EVENTS` events and
makes at most `MAX_CLOSURES` closures, the text a step copies is charged to its
steps, and a reading cut short has its text read by the text test as well.

Go's standard library and the modules it vendors (`golang.org/x/…`), each
package folder read as a module, give no finding at either moment (717 folders,
6,121 files, 7 s), and neither do Ubuntu 24.04's 1,953 packaged Go modules whose licences allow
it (114,000 files, 49 s). The registry and the guard call `go_package` on every module zip they scan
(Part C), with the text as it came (`api::call_owned`: the copy of each file it made doubled what a
module held; aws-sdk-go v1, 207 million characters, now peaks at 2.4 GB, from 3.0 GB).

## 23. A vendored dependency's manifest (Part C)

`vendor.rs` reads what a `--deps` scan needs of a vendored dependency's manifest, once for both packages (core.py's
`_vendored_code`, the npm package's `deps.js` `vendoredCode`), so that the two CLIs read a Go `vendor/` and a
`cargo vendor` tree alike:

- `cargo_layout` (text: a crate's `Cargo.toml`) -> `{"build": a path, false or null, "lib": a path or null,
  "proc_macro": a boolean or null}`: `package.build` (or `project.build`), `lib.path` and `lib.proc-macro`, read as TOML
  writes them: tables and arrays of tables (whose keys are not these), dotted and quoted keys, inline tables, basic and
  literal strings on one line or several, arrays over several lines and comments. What a string or an array holds is
  never read as a line of its own (a description holding `[lib]` and `proc-macro = true` is a description), a line it
  cannot read is left and the next one read, the first value given wins, and values nested more than 32 deep end the
  reading (cargo refuses a manifest that deep). On the 2,122 crates of Ubuntu 24.04's licence-checked `librust-*-dev`
  packages it says what the registry's reading says (Python's TOML, `crates.Crates.layout`) for every one.
- `go_vendored_modules` (text: a `vendor/modules.txt`) -> the module paths it says are vendored (a `# path version`
  line followed by its annotations or packages; a `# ` line with nothing after it is a replacement `go mod vendor`
  records but does not use), longest first: a file belongs to the module whose path is the longest prefix of its own.

Both are linear in the text, and nothing in them panics on any input (`vendor::tests`).
