# Rust engine: handoff notes

A transition document for whoever continues the Rust engine work. It
records where the work stands on branch `rust-engine`, what was decided and
why, how to verify it, what the numbers are, and what to do next. It is
transitional: fold what lasts into `docs/RUST_ENGINE.md` (still to be
written) and delete this file.

- **Branch:** `rust-engine`, off `detection-0.1.8` at `0208bbb` ("Docs: 0.1.8
  items 5-11, …").
- **Requirements:** "Rust engine requirements.md" (shipped alongside this
  file in the handoff package). Section numbers below (§4, §5, §11) refer to it.
- **State in one line:** Phase 0 is done. Phase 1's functions are ported with zero
  parity differences on the corpora we have. Single-threaded it runs about 3.8×
  the Python engine. Threaded batching is in. The engine is not yet wired into
  the scanner, packaging, CI or npm.

---

## 1. Decisions the user made (treat as fixed)

| Topic | Decision |
|---|---|
| Dependencies | **No external crates at all.** Own regex engine, JSON, Unicode tables. `Cargo.lock` has only our two crates. |
| Scope of this stint | Phase 0 + start of Phase 1. |
| Bindings | **C ABI + ctypes** for Python (no PyO3, no compiled extension); **WASM** for Node (no napi). |
| Delivery | Git bundle + patch file. |
| Rule source | **"Extract now, flip later."** `scripts/make_rust_tables.py` extracts every module-level value of `core.py` into a JSON rule pack (`rules/lazaret-rules.json`). Later, `core.py` itself should load the pack (as it already loads `received_spec.json`), so there is one source of truth. |
| Engine shape | Generic engine + data. Declarative rules come from the JSON pack, and the algorithms live in named Rust functions. The Rust side loads the pack at runtime (`pack.install` can replace it). |
| Coarse calls + threading | The user asked whether to pass whole files and use threads. Answer given: yes. Use per-file calls that share work, plus a batch that fans files out over `std::thread`, with ordered results. ctypes releases the GIL during a call. |

Standing preferences of the user (from memory, apply them):
- Never put a real `.env` or any secrets/credentials file in a package or
  tarball (`.env.example` is fine).
- Any test run under a shell `timeout` uses **≤ 45 s**. Run suites one module
  at a time. The project rule is the same: every test module under 45 s
  (`docs/TESTING.md` §2). Split a module rather than raise a timeout.
- Commit trailer lines (from the session's attribution rules):
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01BreNxF1NRkp1G1XYAB9YX2`
  (use your own session's lines if they differ).

---

## 2. Layout

```
rust/
  Cargo.toml                    workspace; release: lto, codegen-units=1, panic=unwind, strip
  crates/lazaret-engine/        #![forbid(unsafe_code)], no deps, no I/O
    rules/lazaret-rules.json    the rule pack (generated; embedded with include_str!)
    src/
      api.rs        call table: name + JSON args + text -> JSON; batch (threads)
      budget.rs     per-thread work budget -> Exhausted (caller falls back to Python)
      pack.rs       rule pack: lazy per-entry compile (OnceLock), strs, needles, maps
      json.rs       JSON parse/serialize (strings are [u32] code points; lone surrogates ok)
      pystr.rs      Python str semantics on [u32]: slicing, find, split, strip…; Needles
      unicode.rs    Python 3.10 / Unicode 13 predicates (via generated/unicode13.rs)
      rxutil.rs     runtime-built patterns (thread-local cache, 512 like re's)
      hooks.rs      shlex_split, _hook_tokens, follow_hook, node_candidates, node -e, shebang
      signs.rs      install_script_risk, import_time_risk(+severity), decoded_view, spawned_scripts,
                    powershell/stager/reverse shell/host info/own source/persistence/secrets/…
      received.rs   _received_code_kind (spec-driven), downloads_and_runs, decodes_and_runs, logical
      lexer.rs      _lex_comment_spans (comments/strings/literals, JSX)
      pyre/         port of CPython's sre (see §3)
    examples/       dev tools: profile_calls, profile_one, pattern_times, pattern_stats, show_need
  crates/lazaret-ffi/           cdylib `liblazaret_native.so` — the ONLY unsafe code
python/src/lazaret/scanner/_native.py   ctypes loader + call() (NativeError / NativeExhausted)
scripts/make_rust_tables.py             writes the pack (any Python) and unicode13.rs (3.10 only); --check
python/tests/architecture/
  _rust_regex_corpus.py, test_rust_parity_regex.py   regex engine vs re (3.10–3.14)
  hooks_corpus.py              shared corpus (moved out of test_js_parity_hooks.py)
  test_rust_parity_hooks.py    hooks_view: 15 fields per case vs core
  test_rust_parity_signs.py    signs_view: 15 sign functions per case vs core
```

`core.py` change: inline dynamic regex fragments were hoisted to named
constants (`_HOOK_FALLBACK_TOKEN_RE`, `_DV_*`, `_SPAWN_ASSIGN_*`, `_DL_*`) so
the extractor can see them. The pattern text is identical, and JS parity still passes.

### FFI protocol
Request: `[u32 LE name len][name UTF-8][u32 LE args len][args JSON][text]`. The
text is the rest of the buffer: a Python str encoded `utf-8`/`surrogatepass`.
Answer: JSON in an engine-owned buffer, released with `lazaret_engine_free`. Status
codes: 0 ok, 1 error, 2 exhausted (budget), 3 panic (caught). WASM exports
`lazaret_alloc/free/call` with the same framing.

### Batch
`{"calls": [[name, args, text], …], "threads": n}` returns
`[{"ok": v} | {"error": …, "exhausted"?: true, "panic"?: true}]` in the input
order. Threads pull the next item from an atomic counter. Each item has its own
budget and `catch_unwind`. `batch` and `pack.*` are refused inside a threaded
batch. WASM always runs it on one thread.

---

## 3. The regex engine (`pyre/`) — the core of parity

A port of CPython's `re/_parser.py`, `re/_compiler.py` and
`Modules/_sre/sre_lib.h` (3.11–3.14 semantics; 3.10-only differences are
version-gated in the tests). Text is `[u32]` code points, offsets are code
points, and lone surrogates are allowed.

- `parser.rs` and `compiler.rs` produce the same code words `re._compiler._code`
  produces (INFO blocks, charsets and BIGCHARSET, `re._casefix` fixes, IN_UNI_IGNORE).
- `matcher.rs` is SRE(match) as an explicit context stack (`Ctx` + `Jump`
  continuations, a `Phase` state machine), so there is no recursion and no
  call-stack overflow. MARK push/pop data stack. REPEAT/MAX_UNTIL/MIN_UNTIL with
  `last_ptr` zero-width protection. SRE(search) keeps sre's literal-prefix and
  charset scans. Each dispatched op ticks the thread's budget.
- `\B` on an empty string: we follow 3.10–3.13 (no match). 3.14 matches
  (gh-124130). No pack pattern uses `\B`, and a test asserts that stays true.

### Answer-preserving speedups sre does not have
All of these are skips of work that cannot lead to a match. Each has a soundness
argument in its module doc, plus hand-written probes in `test_rust_parity_regex.py`.

1. **First-character filter** (`first.rs`). A search skips start positions whose
   character none of the pattern's possible first consuming ops accepts. It
   follows JUMPs out of alternatives. A leading positive lookahead's first
   consuming op also counts. Paths that can end without consuming give no filter.
2. **Per-op tables** (`prog.rs`, built once per compiled pattern):
   - ASCII bitsets for IN/IN_IGNORE/IN_UNI_IGNORE;
   - a bitset for sre's own INFO charset scan;
   - tail first-sets for REPEAT_ONE/MIN_REPEAT_ONE, so backtracking skips
     positions where the tail can't start. sre already does this, but only for a
     literal tail.
   - per-BRANCH-alternative first-sets, so alternatives that can't start here are
     skipped. sre already does this, but only for a leading LITERAL or IN.
3. **Required-literal prefilter** (`literal.rs`). From the compiled code, it
   derives strings one of which must lie *inside* every match. These are runs of
   LITERAL / LITERAL_*IGNORE / small literal-only sets (how `(?i)i`, `(?i)s`
   compile: `[i ı]`, `[s ſ]`). Zero-width ops don't break a run. The string set
   for a BRANCH is the union of the alternatives' sets. A run followed by a BRANCH
   joins each alternative's lead (re's parser rewrites `nc|ncat|netcat` as
   `n(?:c|cat|etcat)`). Lookaround contents are never used, because they may lie
   outside `[pos, endpos)`. A search of a text holding none of the strings returns
   no match at once. Requirements whose shortest string is under 2 characters, or
   that have more than 64 strings, are not used. 170 of 287 pack patterns get one.
   `cargo run --release --example show_need -- NAME` prints them. Cost is
   amortized-linear in finditer loops: a found match always extends past the
   string occurrence that let the search through.
4. **Mechanics:**
   - the Dispatch phase is an inner loop, so simple ops don't re-enter the phase
     `match` (the macros `continue 'main`);
   - matcher buffers (marks, data stack, context stack, repeats) are pooled per
     thread across searches (`Buffers`, `SPARE`, `Drop for State`).

Where it still loses to sre: `.match()`-style patterns that start at nearly
every position (e.g. `_XF_JS_MEMBER_RE`, `_PY_DOC_HEAD_RE`). Those are only used
with `.match(text, pos)` in core, so their whole-text search time doesn't matter.

---

## 4. Verifying (commands)

Build and point Python at the library:
```bash
cd rust && cargo build --release          # target/release/liblazaret_native.so
export LAZARET_NATIVE_LIB=$(realpath target/release/liblazaret_native.so)
cd ../python
```
Run each module separately, each within 45 s:
```bash
(cd ../rust && timeout 45 cargo test --release)                  # unit tests (FFI, literal extraction)
for py in python3.10 python3.11 python3.12 python3.13 python3.14; do
  PYTHONPATH=src:. timeout 45 $py -m unittest tests.architecture.test_rust_parity_regex; done   # ~1.2 s each
PYTHONPATH=src:. timeout 45 python3 -m unittest tests.architecture.test_rust_parity_hooks      # ~21 s
PYTHONPATH=src:. timeout 45 python3 -m unittest tests.architecture.test_rust_parity_signs      # ~3.5 s
PYTHONPATH=src:. timeout 45 python3 -m unittest tests.architecture.test_js_parity_hooks        # unchanged JS parity
python3 ../scripts/make_rust_tables.py --check    # pack current with core.py (unicode13.rs check needs 3.10)
```
Last results (this handoff): all pass. There are **zero differences** on 29,800
corpus cases × (15 hooks fields + 15 sign fields). The regex parity covers 370
pack patterns and 126 hand-written ones, across search/match/fullmatch/finditer/
sub/split with pos/endpos, on Python 3.10–3.14. A threaded batch was
smoke-tested equal to the sequential one (40 calls, 4 threads). It has not yet
been run over a full corpus with threads.

The Rust tests skip themselves where the library isn't built
(`_native.available()`), so CI must build it first, or they silently skip.

---

## 5. Performance: numbers and method

**Machine noise is high here (±8–15% run to run). Always compare the best of
3 runs, and use callgrind instruction counts for small changes.**
The container has 2 cores, so threaded numbers from here are not representative.

Hooks corpus, 29,795 cases under 5,000 characters (median 62 chars), total time per
function. Best of 3, both engines. Rust through `api::call` (JSON args), Python
calling core directly.

| call | Rust ms | Python ms | × |
|---|---:|---:|---:|
| shlex_split | 44.7 | 910 | 20.4 |
| hook_tokens | 63.6 | 1,188 | 18.7 |
| follow_hook | 265 | 2,084 | 7.9 |
| install_script_risk | 1,137 | 3,844 | 3.4 |
| import_time_risk | 715 | 2,155 | 3.0 |
| import_time_risk (py) | 725 | 2,425 | 3.3 |
| import_time_risk (js) | 865 | 2,356 | 2.7 |
| received_code_kind | 322 | 702 | 2.2 |
| runs_own_source_at | 39 | 315 | 8.0 |
| persistence_reasons | 80 | 305 | 3.8 |
| stager_at / reverse_shell_at | 50 / 23 | 197 / 101 | 4.0 / 4.3 |
| downloads_and_runs / decodes_and_runs | 21 / 16 | 100 / 59 | 4.8 / 3.7 |
| **all measured calls** | **4,488** | **16,985** | **3.8** |

Pure regex search over the small-case file (`pattern_times` vs the same loop in
Python): 3.0× overall, with every pack pattern's match count equal.

History, to show what moved it:
- first port: ~1.1× on regex, 2.0× on install_script_risk;
- context-stack reuse + first-set filter: 2.1×;
- tables, tail and branch filters, and the dispatch loop: 2.5× regex;
- buffer pool: another −15%;
- literal prefilter, one-pass needles, and prefix+branch joining: the numbers above.

**What the §5 target means.** ≥10× over the benchmark corpus on phases 1–2;
litellm (2,500 modules, ~46 s) under 5 s; `next`'s tarball under 5 s. These are
multi-file wall-clock targets, so the threaded batch counts. Single-thread gains
will plateau somewhere around 4–6×. A backtracking engine that has to give sre's
exact answers can't skip much more work. Reaching 10× needs:
(a) threads across files;
(b) fewer boundary crossings (whole-file calls, batched);
(c) porting phase 2 (`scan_file`), because a registry scan spends most of its time
there, not in phase 1.

Tools (in `rust/crates/lazaret-engine/examples/`, and scripts in the handoff
package's `bench/`):
- `profile_calls CASES.json`: per-call totals (the Rust column above).
- `pattern_times CASES.json [NAME [REPS]]`: per-pattern search time.
- `cargo run --release --features stats --example pattern_stats -- CASES.json CALL`:
  time per pattern *inside* a call. The `stats` feature is off by default; never
  ship it.
- `profile_one CASES.json CALL [REPS]`: a loop for
  `valgrind --tool=callgrind`. Build with
  `CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false` into a
  separate `--target-dir`.
- `show_need NAME…`: what the literal prefilter derived.
- Make `CASES.json` with
  `python -c "import json; from tests.architecture.hooks_corpus import corpus; json.dump(corpus(), open('cases.json','w'))"`
  (run from `python/` with `PYTHONPATH=src:.`).

Where time goes now in install_script_risk (callgrind, exclusive):
- the backtracking core `match_with`: ~34%;
- the literal prefilter scans: ~10–12%;
- the needle scans, `find_str`, hashing (`HashSet<PyStr>` with SipHash), and malloc/free: most of the rest.

The profile is flat: about 60 patterns, each run once per text.

---

## 6. Status against the requirements

| Item | State |
|---|---|
| Phase 0: regex engine with Python `re` semantics, code-point offsets, Unicode 13 | **Done**, differential-tested on 3.10–3.14. |
| Phase 0: single source of truth for patterns | **Half.** The pack is extracted from `core.py` (`--check` guards drift). The "flip" (core loads the pack) is not done. |
| Phase 0: move the benchmark harness (`bench/`) into the repo | **Not done.** The harness and the 945-package corpus were not available in this environment. |
| Phase 1 functions (§2 row 1) | **Ported**, with zero differences on the hooks corpus (29,800) through `hooks_view` and `signs_view`. Not yet run on "every corpus in §4": fixture trees, benchmark corpus, installed trees. |
| Phase 1: ≥10× | Single-thread 3.8×. Threaded batch exists but is unmeasured at scale. |
| `--engine rust\|python`, `LAZARET_ENGINE`, version in `--version` and reports | **Not started.** `_native.py`'s docstring refers to an `engine.py` that doesn't exist yet. |
| Python fallback on NativeError/NativeExhausted | Exceptions exist in `_native.py`. The call sites don't use them yet. |
| Wheels (stdlib build backend) and npm binaries in CI; `scripts/check_rust_deps.py` | **Not started.** `rust/Cargo.toml`'s comment already names `check_rust_deps.py`. |
| WASM / Node loader (`js/src/lib/native.js`) | Exports are written, but **never compiled or run**: installing the wasm32 target was blocked by the proxy (403). |
| Phase 2 (per-file rules, lexers), Phase 3 (cross-file, archives) | Only `_lex_comment_spans` is ported (the lexer is shared with phase 1). The rest is not started. |
| Source decoding (BOM, UTF-16, UTF-7 cookie, PEP 263 codecs, newline normalization) | **Not started.** |
| `docs/RUST_ENGINE.md` | **Missing.** `lib.rs` already refers to it. |

---

## 7. Next steps, in the order I'd take them

1. **Measure the threaded batch for real.** Build a multi-file case set, e.g. the
   `.js`/`.py` files of an installed litellm or next. Run `import_time_risk`
   through `batch` with threads 1, 2, 4, 8 on a machine with cores. Check the
   answers equal the Python engine's, and report wall-clock times.
2. **Wire it in behind `--engine`** (`engine.py`):
   - batch the two per-file loops: `dependency_checks` in `core.py` (dependency
     `.js`/`.py` files, ~line 11451) and the reachable-module loop in
     `registry/repo.py` (~line 1990);
   - chunk batches (~64 files) so `should_stop` / `_deadline` stay responsive;
   - fall back to core for any item whose answer is `exhausted`, `panic` or `error`;
   - keep result order.
   Then run the full Python suite with each engine.
3. **Packaging and CI:**
   - native library into the wheel (`lazaret/_native/<lib>`) via the existing
     stdlib build backend;
   - a CI job that builds it, runs the Rust parity modules (so they don't skip),
     and runs `make_rust_tables.py --check`;
   - `scripts/check_rust_deps.py` asserting `Cargo.lock` holds only our crates;
   - build WASM where the target can be installed, and write `js/src/lib/native.js`.
4. **Phase 2 (`scan_file`),** because registry-scan time is dominated there. Port
   rule families behind the same view-and-compare test pattern. Keep one test
   module per family, each under 45 s.
5. **Flip the source of truth:** `core.py` loads `rules/lazaret-rules.json` at
   import, and `make_rust_tables.py` becomes the tool that edits or validates it.
6. More single-thread speed, if still needed. Candidates, most promising first:
   - a combined one-pass prefilter over all patterns' required strings
     (Aho-Corasick-style over `[u32]` with the fold modes), so each text is
     scanned once for all ~170 requirements;
   - a faster hash than SipHash for the `HashSet<PyStr>` lookups;
   - cheaper `Prog::new`: its 128-character sweeps run for every runtime-built
     pattern, which the rxutil cache compiles once per distinct name.

---

## 8. Known issues and gotchas

- **`Pack::entry` panics on an unknown name.** The FFI and the batch catch it and
  report status 3 / `"panic"`. It is still a panic, and §6 of the requirements
  asks for none. Consider `Result` plus a pack-load validation that every name the
  engine reads exists.
- **Quadratic pattern:** `_XF_ARROW_ONE_RE` on `"x"*100001` is slow in *both*
  engines (inherited from core, not a port bug). §5 says to keep patterns bounded,
  so fix it in `core.py` and the pack together.
- **Budget:** 4e9 steps per call by default. When exhausted, the answer is
  discarded and the caller must use Python, so the budget never changes an
  answer.
- **JSON round-trip:** adjacent surrogate pairs in test texts get combined by
  `json`. The tests normalize both sides through JSON before comparing. Mirror
  that in any new differential test.
- **Python 3.10** lacks atomic groups and possessive repeats, so those probes are
  version-gated. Ints beyond i64 in core (e.g. `_INT_STR_LIMIT`) are skipped by
  the extractor.
- **Macro labels:** the matcher's macros are defined *inside* `'main: loop` so
  that `continue 'main` resolves. Keep them there.
- **`rxutil::dynamic` cache** is per thread and cleared at 512 entries, like re's
  cache. Threads each compile their own copies.
- **Measuring:** single runs on this box vary ±15%. Use best-of-3 or callgrind.
