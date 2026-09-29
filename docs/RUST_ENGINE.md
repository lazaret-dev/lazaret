# Lazaret's Rust scanning engine — requirements (draft)

Status: requirements for a first implementation, September 29, 2026. The
reference implementation is the Python engine (`python/src/lazaret/scanner/`),
which stays.

## 1. Goal

One native scanning engine, written in Rust, used by both distributions
(`pip install lazaret`, `npm install lazaret`) as the default. The Python
engine stays as the **reference implementation**: readable, complete,
selectable at run time (`--engine python`), so anyone can audit a verdict by
reproducing it in plain Python. The two must give identical results, proven
by differential tests in CI. Once the npm package runs the Rust engine, the
JavaScript twin (`js/src/lib/*.js`) is retired.

Why now: Lazaret is days old, so nobody has to migrate; today two engines are
kept in lockstep by hand (146 mirrored patterns and a dozen parity suites);
and the Python engine is the speed limit of `lazaret guard` and registry
scans (litellm, 2,500 modules, takes ~46 s; `next`'s 42 MB tarball ~41 s of
a first guarded install).

## 2. Scope and phases

The **scanning engine** is everything that turns a file's bytes into findings.
It is not the orchestration around it (registry fetching and database, the
guard's package-manager wrapping, the MCP server, SCA advisory matching,
report and dashboard rendering, CLI options), which stays in Python and
JavaScript and calls the engine.

| Phase | What moves to Rust | Done when |
|---|---|---|
| 0 | Workspace, bindings (PyO3/maturin, napi-rs), CI wheels and npm binaries, the differential harness, source decoding (encodings, BOM, UTF-16, the UTF-7 cookie, Python coding cookies, newline normalization), Unicode 13.0 tables, pattern-table generation | `lazaret --engine rust --version` works on Linux, macOS and Windows from a wheel and from npm |
| 1 | The supply-chain tests: `install_script_risk`, `import_time_risk` (+ `import_time_severity`), the received-code detector (`_received_code_kind`, spec-driven), download/decode-and-run, `decoded_view`, `follow_hook` (its shlex-compatible tokenizer), `spawned_scripts`, persistence, self-publish, the exfiltration shapes | function-level parity on every corpus in §4, and ≥10× faster on them |
| 2 | Per-file rules (`scan_file` / `_scan_file`: the 60 `RULES`, `TEXT_RULES`, secrets and entropy, homoglyphs, hidden Unicode and bidi, off-screen code, eval-decode, hex names, `.pth`, workflows, autorun and config secrets), the Python and JS/TS lexers (comment and string spans, statement strings, JSX) | finding-level parity on the fixture trees, the benchmark corpus and installed trees |
| 3 | The cross-file follower (`_cross_file_received_issues`); archive reading for registry scans (tar/gzip/zip/wheel with today's limits: member size, file count, zip-slip, links, special files) | parity on the follower's cases and on registry scans of the benchmark corpus |
| 4 (optional) | The taint flow engines (`flow.py` on Python's `ast`, `jsflow.py`/`jsparse.py`) | only if a Rust parser gives identical results; otherwise they stay Python-only, as now |

The Python engine is about 27,000 lines (`core.py` alone 13,000, with ~350
of the scanner's ~460 regexes); the JavaScript twin about 14,000. Phases 1
and 2 are where the time goes in registry and guard scans.

## 3. The parity contract

For every input, the Rust engine returns exactly what the Python reference
returns:

- **Findings:** rule id, file, line, column, severity, message text and
  snippet, in the same order where order is visible. Metrics, counts and
  derived report fields the same.
- **Python `re` semantics**, for every pattern: backtracking with lookahead
  and lookbehind; Unicode `\w`, `\d`, `\s` and `\b` as Python's `str`
  defines them (`\s` includes U+001C–U+001F and U+0085); `re.I` Unicode case
  folding (ſ folds to s, the Kelvin sign to k, İ …); `re.M` anchors; `\Z`;
  `.` not matching `\n`. The JavaScript twin solved this in
  `js/src/lib/pycompat.js` (`pyRe`): read it for the translation rules and
  the pitfalls already found. Rust's `regex` crate has no lookarounds, so the
  choice is a translation onto `fancy-regex` with Python's classes, a small
  backtracking matcher of our own for the subset the patterns use, or
  `regex` plus hand-written checks; whichever, **no pattern is copied by
  hand**: see generation below.
- **Offsets in code points** (Python `str` indices): lines 1-based, columns
  and message excerpts counted and cut in code points (`s[:40]`).
- **Every limit identical**: the caps on what is examined per text
  (`_DL_WINDOW`, `_CHAT_SECRET_MAX`, `_CRED_SWEEP_SPAN` …), so answers on
  hostile inputs match. The Python tests assert these values; the Rust
  engine exports its own for the same comparison.
- **Unicode 13.0**: source text is pinned to Unicode 13.0 on every runtime
  (`scanner/_unicode13.py`: a later code point is read as U+FFFD; NFKC,
  `isidentifier`, `isalnum` as of 13.0). The Rust engine uses tables
  generated from the same data.
- **Time budgets**: a scan that runs out of budget reports SC-TRUNCATED /
  INCOMPLETE in both engines, but *where* it stops can't be byte-identical;
  parity is defined with budgets off (or generous), and budget behavior is
  tested separately.

**Single source of truth for patterns.** Today the shared spec
(`scanner/received_spec.json`, synced to `js/src/lib/received-spec.json` by
`scripts/sync-received-spec.py`) holds the received-code detector's
patterns; the rest live in `core.py` and are copied into the JavaScript
twin, checked by `PY_TWINS`. For the Rust engine, move every pattern, needle
set and limit into spec files (or extract them from `core.py` with a script)
and generate the Rust tables from them at build time, with a `--check` in CI
like the existing sync script.

## 4. Proving parity (differential tests)

A harness runs both engines on the same inputs and fails on any difference:

1. The inputs of the existing parity suites (`python/tests/architecture/test_js_parity_*.py`): the hooks corpus (~41,000 seeded cases, built from "pieces" alphabets, plus curated cases), the cross-file stream (700 generated packages), the fixture trees, the adversarial tree.
2. The string inputs of the Python unit tests (2,300+ tests), captured once.
3. The benchmark corpus: 945 packages (516 malicious from DataDog's dataset, 429 popular npm and PyPI packages) — identical findings and verdicts. The harness lives outside the repo today (`bench/`: `prepare_corpus.py`, `run_lz.py`, `score_018f.py`); moving it into the repo is part of phase 0.
4. Installed trees: every `.py`/`.js` file under Python `site-packages` and global `node_modules` (the 0.1.8 sweep read 37,783).
5. Fuzzing: `cargo fuzz` / proptest streams from the same pieces alphabets; a difference, a panic or a timeout is a bug.

CI runs 1, 2 and 5 on every change and 3 and 4 nightly. The repository's
test discipline applies: every test module under 45 s (`docs/TESTING.md` §2;
split a module rather than raising a timeout).

## 5. Performance

- ≥10× the Python engine on phases 1–2 over the benchmark corpus; litellm
  under 5 s, `next`'s tarball under 5 s; a first guarded install of next,
  react, react-dom, typescript and eslint (53 s today) under 15 s.
- Linear in input size: no pattern may backtrack without bound (the Python
  patterns are bounded by construction; keep them so, and bound every
  backtracking step in the Rust matcher as well).
- Memory bounded by the per-file limit (16 MB by default,
  `LAZARET_MAX_SOURCE_BYTES`); stream archives.
- Published numbers from the benchmark harness, before and after.

## 6. Safety on hostile input

Every byte the engine reads was written by an attacker.

- `#![forbid(unsafe_code)]` in the engine crate; `unsafe` only inside the
  binding crates' macros.
- No panics (fuzzed); no unbounded recursion; bounded time and memory per
  file.
- No network, no file writes, no processes: the engine reads the bytes it
  is handed and returns findings.
- Few, well-known dependencies (`regex`/`fancy-regex`, `aho-corasick`,
  `memchr`, `pyo3`, `napi`), pinned by `Cargo.lock`, checked with
  `cargo deny` and `cargo audit` in CI; no build script that downloads.
- Reproducible release builds with provenance: PyPI Trusted Publishing with
  attestations, npm provenance.

## 7. Packaging and selection

- Workspace under `rust/`: `crates/lazaret-engine` (pure Rust, no bindings),
  `crates/lazaret-py` (PyO3 module, shipped inside the `lazaret` wheel as
  `lazaret._engine`), `crates/lazaret-node` (napi-rs; per-platform packages
  in the npm package's `optionalDependencies`, as esbuild and swc do; a
  WebAssembly build as the fallback).
- Platform wheels for Linux (manylinux and musllinux, x86_64 and aarch64),
  macOS (x86_64, arm64) and Windows (x64, arm64), built with maturin in CI.
  The sdist still installs without Rust and then runs the Python engine.
- `--engine rust|python` and `LAZARET_ENGINE`; default `rust` when present.
  `lazaret --version` names the engine and its version, and every report
  records them, so a verdict can be reproduced with the other engine.
- The registry's `ENGINE_VERSION` names the rule set, not the
  implementation: both engines carry the same one.

## 8. The Python reference engine

- Stays complete and readable: it is the specification by example.
- A detection change lands in the Python engine with its tests and in the
  Rust engine in the same change; CI fails on any difference.
- `--engine python` reproduces any verdict for an audit.

## 9. Hard parts, known in advance

- Python regex semantics (§3): the biggest risk. Start with the patterns of
  phase 1 and the pycompat rules; measure every pattern against Python on
  the corpora before trusting it.
- Code-point offsets: keep a char-index map, or work on `&[char]` where
  offsets matter.
- The lexers (`_lex_comment_spans`, `_string_literals`,
  `_py_statement_literals`, `_blank`) are character-exact.
- Hook commands are tokenized like CPython's `shlex` (posix,
  punctuation_chars, whitespace_split, no commenters); `js/src/lib/hooks.js`
  re-implements it.
- `decoded_view` decodes hex/base64 and a file's own decoder helpers with
  exact limits (`_DV_*`).
- The received-code detector's two readings (`_dl_logical`) and the row
  windows.
- Budgets and deadlines (§3).

## 10. What to read first

`docs/DESIGN.md` (the detectors and their false-positive bar),
`docs/TESTING.md` (the 45-second discipline, parity, false-positive
sweeps), `docs/STRUCTURE.md`, `python/src/lazaret/scanner/core.py`,
`received_spec.json`, and the JavaScript twin as a worked example of a
second engine held to the first: `js/src/lib/pycompat.js`, `hooks.js`,
`received.js`, `crossfile.js`, with
`python/tests/architecture/test_js_parity_hooks.py`.

## 11. Phase 1 acceptance

- Function-level parity for the phase 1 functions on every input set in §4,
  zero differences.
- ≥10× faster on those functions over the benchmark corpus.
- The Python package runs the Rust engine by default and `--engine python`
  on request; the full Python suite passes with either engine where the
  test isn't engine-specific.
- Wheels and npm binaries build in CI for the platforms in §7.
