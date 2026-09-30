# Lazaret's native scanning engine (Rust)

Status, September 29, 2026: phase 0 and the phase 1 functions are done,
current with the Python engine through 0.1.8's detection, and wired into the
scanner behind `--engine`. The Python engine (`python/src/lazaret/scanner/`)
stays: it is the reference every answer of the native engine is held to.

## 1. What it is

One native engine, written in Rust, used by both distributions as the
default where it is installed. The Python engine stays as the **reference
implementation**: readable, complete, selectable at run time
(`--engine python`), so anyone can audit a verdict by reproducing it in plain
Python. The two give identical answers, proven by differential tests. Once
the npm package runs the native engine (as WebAssembly), the JavaScript twin
(`js/src/lib/*.js`) can be retired.

Decisions (fixed):

| Topic | Decision |
|---|---|
| Dependencies | **No external crates.** Own regex engine (a port of CPython's sre), JSON, Unicode tables. `Cargo.lock` lists only the workspace; `scripts/check_rust_deps.py` fails CI otherwise. |
| Bindings | **C ABI + ctypes** for Python (no compiled extension, one library per platform serves every Python version); **WebAssembly** for Node. |
| Rule source | **Extract now, flip later.** `scripts/make_rust_tables.py` extracts every module-level value of `core.py` (patterns, sets, limits, and the pattern pieces core composes at run time) into `rust/crates/lazaret-engine/rules/lazaret-rules.json`; `--check` guards drift. Later, `core.py` itself loads the pack. |
| Engine shape | Generic engine plus data: declarative rules come from the pack, the algorithms are named Rust functions, ported function for function. |
| Calls | Whole files, batched: one crossing of the boundary per batch of files, read on threads (`std::thread`), answers in input order. |

## 2. Using it

- `lazaret --engine rust|python …` and `lazaret-registry --engine …`, or
  `LAZARET_ENGINE`. The default is the native engine where it is installed,
  else Python. `--engine rust` fails (exit 2) when the library is missing,
  rather than scan slowly without saying so. `--version` names the engine:
  `lazaret 0.1.8 (engine: rust 0.1.8)`. The workspace version
  (`rust/Cargo.toml`) is the release the engine ships in.
- The library is `lazaret/_native/<library>` in a platform wheel, or the
  file `LAZARET_NATIVE_LIB` names (a development build).
- `python/src/lazaret/scanner/engine.py` sends the supply-chain tests
  through it: the import-time test of every dependency file (`--deps`), of
  every file a registry scan reaches at import time and of the files it runs
  when used (SC-USE-RISK), and the install-script test of hook targets and
  install scripts. Files go in batches of 64 (`engine.BATCH`: a scan's
  deadline and `should_stop` are checked between batches), on up to 8
  threads. **Any call the native engine can't answer** (its work budget
  spent on a hostile file, an error, a caught panic) **is answered by the
  Python engine**, so the native engine never loses a finding.
- The per-file rules (`scan_file`), the lexers and the cross-file follower
  are still Python (phases 2 and 3 below).

## 3. Layout

```
rust/
  Cargo.toml                 workspace; release: lto, codegen-units=1, panic=unwind, strip
  crates/lazaret-engine/     #![forbid(unsafe_code)], no dependencies, no I/O
    rules/lazaret-rules.json the rule pack (generated; embedded; `pack.install` can replace it)
    src/api.rs               the calls by name (JSON args + text -> JSON); `batch` on threads
    src/budget.rs            per-call work budget -> Exhausted (the caller uses Python)
    src/pack.rs              the pack: values by core's names, patterns compiled on first use
    src/json.rs, pystr.rs    JSON; Python str semantics on code points ([u32])
    src/unicode.rs           Python 3.10 / Unicode 13.0 predicates (generated/unicode13.rs)
    src/pyre/                CPython's sre: parser, compiler, matcher (see §6)
    src/hooks.rs             shlex, _hook_tokens, follow_hook, node_candidates, node -e, #!
    src/signs.rs             install_script_risk, import_time_risk(+severity), decoded_view,
                             spawned_scripts, and the detectors they read (exfiltration shapes,
                             services at login, self-read, persistence, publishing …)
    src/received.rs          the received-code detector (spec-driven), downloads/decodes and runs
    src/lexer.rs             _lex_comment_spans
    examples/                profiling tools (profile_calls, pattern_times, pattern_stats, show_need)
  crates/lazaret-ffi/        cdylib liblazaret_native: the only `unsafe` (the C ABI)
python/src/lazaret/scanner/_native.py   ctypes loader and one call (NativeError, NativeExhausted)
python/src/lazaret/scanner/engine.py    the engine in use, batching, the Python fallback
python/_build/lazaret_build.py          LAZARET_NATIVE_LIBRARY + LAZARET_WHEEL_PLATFORM: a platform wheel
scripts/make_rust_tables.py             the pack (any Python) and unicode13.rs (3.10); --check
scripts/check_rust_deps.py              Cargo.lock and the manifests hold only the workspace
python/tests/architecture/test_rust_parity_{regex,hooks,signs}.py, test_rust_deps.py
```

FFI protocol: request `[u32 LE name len][name][u32 LE args len][args JSON][text]`
(the text is the rest: a Python str as UTF-8 with surrogates passed through);
answer: JSON in an engine-owned buffer, freed with `lazaret_engine_free`.
Status 0 ok, 1 error, 2 exhausted, 3 panic (caught). The WebAssembly build
exports `lazaret_alloc`, `lazaret_free` and `lazaret_call` with the same
framing (written, not yet compiled). `batch`:
`{"calls": [[name, args, text], …], "threads": n}` →
`[{"ok": v} | {"error": …, "exhausted"?, "panic"?}]` in input order. Threads
take the next item from an atomic counter; each item has its own budget and
`catch_unwind`; `batch` and `pack.*` are refused inside a batch; under
WebAssembly a batch runs on one thread.

## 4. Building, packaging, CI

```bash
cd rust && cargo build --release --offline --locked      # target/release/liblazaret_native.{so,dylib} / lazaret_native.dll
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
```

A platform wheel: `LAZARET_NATIVE_LIBRARY=<built library>
LAZARET_WHEEL_PLATFORM=<tag> python python/_build/lazaret_build.py dist/`
gives `lazaret-<v>-py3-none-<tag>.whl` with `lazaret/_native/<library>`
(`Root-Is-Purelib: false`). Without the two variables the wheel is the pure
one, and the sdist never carries a library. For Linux, build the library in
the manylinux image of the tag (`quay.io/pypa/manylinux_2_28_x86_64` for
`manylinux_2_28_x86_64`) so it needs no newer glibc than the tag promises.

CI (`.github/workflows/ci.yml`, job `rust`, Linux, macOS, Windows):
`check_rust_deps.py`, `make_rust_tables.py --check` (on 3.10), `cargo test`,
the build, the three parity modules against the library (they skip where it
is not built), and on Linux the whole Python suite with `LAZARET_ENGINE=rust`.
Not yet: release builds of the platform wheels, and WebAssembly (installing
`wasm32-unknown-unknown` was refused by the sandboxes' network so far).

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
| `test_rust_parity_hooks` | the 15 fields of `hooks_view` (shlex, hooks, both supply-chain tests with and without a language, decoded view, spawned scripts …) | the hooks corpus (`hooks_corpus.py`, 36,900 cases) |
| `test_rust_parity_signs` | 24 detectors one by one (received code, PowerShell, stagers, reverse shells, self-read, persistence, the exfiltration shapes, services at login …) | the same corpus |

State: zero differences in every field. `hooks_corpus.py` is shared with
the JavaScript parity test, so a new alphabet there tests both twins. On
real files too: the benchmark's 945 registry scans give identical verdicts,
reasons and findings with either engine, and both tests answer identically,
file by file, on 85,415 files (37,784 of installed Python and npm packages,
and every `.py`/`.js` file of the benchmark's 945 archives, the 516
malicious ones included), with no call the native engine couldn't answer. The
parity modules skip where the library is not built (`_native.available()`),
so CI builds it first; the whole Python suite also passes with
`LAZARET_ENGINE=rust` (the fixture trees, `--deps` and registry scans through
the native engine).

Verifying locally, each command within 45 s:

```bash
cd rust && cargo build --release --offline --locked && cargo test --release --offline --locked
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
cd ../python
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_regex   # ~1 s; repeat per python3.1x
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_hooks   # ~27 s
PYTHONPATH=src:. python3 -m unittest tests.architecture.test_rust_parity_signs   # ~8 s
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
- mechanics: the dispatch phase is an inner loop, and matcher buffers are
  pooled per thread.

It still loses to sre on patterns that could start almost anywhere
(`_XF_JS_MEMBER_RE`, `_PY_DOC_HEAD_RE`); core only calls those with
`.match(text, pos)`, so their whole-text search time doesn't matter.

## 7. Performance

Single thread, per call, on the hooks corpus (29,795 small cases), best of 3:
the native engine is 3.8× the Python engine over all measured calls (shlex
20×, hook tokens 19×, follow_hook 8×, install_script_risk 3.4×,
import_time_risk 3×, self-read 8×).

On real files, the import-time test over 678 of litellm's modules (20.7 M
characters): Python 15.6 s; native 5.7 s on 1 thread (2.7×), 3.2 s on 2
threads (4.9×); no difference, no fallback. The benchmark's 945 registry
scans (516 malicious releases, 429 popular packages; 2 cores, one engine
after the other): 1,097 s with the Python engine, 853 s with the native one
(22% less; 95th percentile 9.5 s → 6.2 s; litellm 40.0 s → 30.6 s,
playwright-core 18.1 s → 10.7 s), with the same verdicts and findings for
every package. Most of what is left is phase 2 (`scan_file`), still Python.

Where the targets (≥10× on phases 1–2; litellm and `next`'s tarball under
5 s) need to come from: threads across files (in; a core-count multiplier),
and porting phase 2. Single-thread gains will plateau around 4–6×: a
backtracking engine that must give sre's exact answers can't skip much more.
In `install_script_risk` (callgrind, exclusive) the backtracking core is
about a third, the literal prefilter's scans a tenth, and the rest is
needle scans, hashing and allocation: a flat profile, about 60 patterns
each run once per text.

Tools (`rust/crates/lazaret-engine/examples/`): `profile_calls CASES.json`
(time per call), `pattern_times CASES.json [NAME [REPS]]` (per pattern),
`pattern_stats` (per pattern inside one call; `--features stats`, never
shipped), `profile_one CASES.json CALL [REPS]` (a loop for callgrind: build
with `CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false`
into its own `--target-dir`), `show_need NAME…`. `CASES.json` is the hooks
corpus: `python -c "import json; from tests.architecture.hooks_corpus import
corpus; json.dump(corpus(), open('cases.json', 'w'))"` from `python/` with
`PYTHONPATH=src:.`.

## 8. Phases

| Phase | What moves to Rust | State |
|---|---|---|
| 0 | Workspace, bindings, regex engine, Unicode 13.0 tables, the pack | Done (source decoding — BOMs, UTF-16, coding cookies — not started) |
| 1 | The supply-chain tests and what they read | Done, current through 0.1.8; wired in |
| 2 | Per-file rules (`scan_file`: `RULES`, `TEXT_RULES`, secrets, entropy, homoglyphs, hidden Unicode, off-screen code …), the Python and JS/TS lexers | Only `_lex_comment_spans` |
| 3 | The cross-file follower; archive reading for registry scans | Not started |
| 4 (optional) | The taint flow engines | Only if a Rust parser gives identical results |

## 9. Known issues

- `Pack::entry` panics on a name the pack lacks; the FFI and `batch` catch it
  (status 3, and the Python engine answers). A pack-load validation of every
  name the engine reads would turn it into an error at load.
- `_XF_ARROW_ONE_RE` is quadratic on `"x" * 100001` in both engines
  (inherited from core): bound it in `core.py`, and the pack follows.
- The budget (4e9 steps per call) discards an exhausted answer; the Python
  engine then answers, so the budget never changes a finding.
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

1. Release builds of platform wheels (Linux in the manylinux images, macOS,
   Windows) with provenance, and WebAssembly for the npm package
   (`js/src/lib/native.js`), where `wasm32-unknown-unknown` can be installed.
   With them, hold the workspace version to the packages' in
   `scripts/check-versions.sh` (a bump then also rewrites `Cargo.lock`'s
   two workspace entries). Keep the benchmark harness (outside the
   repository today) in it, and run the 945 packages with each engine
   nightly.
2. Phase 2 (`scan_file`), family by family, each behind the same
   view-and-compare test and each test module under 45 s.
3. Flip the source of truth: `core.py` loads the pack at import.
4. Record the engine in reports (JSON and SARIF), next to the version.
5. More single-thread speed if still needed: one Aho-Corasick pass over all
   patterns' required strings, a faster hash than SipHash, a cheaper
   `Prog::new` for run-time patterns.
