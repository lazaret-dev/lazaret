# Lazaret — Testing Process

*The working method for verifying a change. What to run, in what order, how to
keep it fast, and how to survive Windows.*

This is the operational playbook. It complements two documents you should also
know:

- **`STRUCTURE.md` §4** — the test *layout*, categories/gating, the exact
  `python -m unittest` commands, and the authoritative **cross-platform rules**
  (encoding, paths, resources, line endings, OS capabilities, interpreter
  drift, time). Don't duplicate those rules; obey them.
- **`docs/DESIGN.md` §6–§8** — *why* we test this way (the parity invariant, the
  0-false-positive discipline, bounded work).

Everything below is inert by policy: fixtures use `.invalid` / TEST-NET hosts and
nothing is executed (`STRUCTURE.md` §6).

---

## 1. The verification sequence for a change

Run these in order. Stop and fix at the first red; a later green doesn't
redeem an earlier red.

1. **Behavioral suites (both engines).** The Python `test_review_<topic>` and the
   npm `review-<topic>.test.js` for the area you touched. Each regression test
   should fail on the pre-change code and pass after — write it that way.
2. **Engine parity.** `python/tests/architecture/test_js_parity*.py`. This is the
   guard that the two engines still agree; treat a parity failure as "one engine
   is now wrong," not as flakiness. A deliberately Python-only feature must be
   registered in `_python_only` (in `test_js_parity.py`) or it will (correctly)
   break parity. If you touched the install-script or import-time test (or
   anything they read), also the native engine's:
   `python3 scripts/make_rust_tables.py` (then `--check`), build the library,
   and `test_rust_parity_{regex,hooks,signs}.py` (§3).
3. **Fuzz / differential, where the area has one.** The received-code parity
   (`test_js_parity_hooks.py`) runs ~30k generated cases through one Node process
   (while Python reads them: the suite's time is the slower engine's) and diffs
   every one against Python; the cross-file follower's
   (`test_js_parity_crossfile.py`) generates 700 packages from the shapes it
   reads; the hooks/flow parity suites do the same for their areas. Both
   engines must agree on *every* case.
4. **False-positive sweep on real code** (§4). The bar is **zero** new findings.
5. **Bounded-work check** (§5) on an adversarial large input.
6. **Docs** (`README.md`, this doc / `STRUCTURE.md` / `DESIGN.md` if the
   architecture moved, `CHANGELOG.md`), then commit (one logical change, both
   engines together).

Before a **release**, also run the **full cross-subsystem suite** (§6) — it
catches ripple that per-area tests miss.

---

## 2. Running the suites — the 45-second discipline

**The single most useful habit: run suites individually (or in small batches)
with a short timeout (≤45 s each). Never launch one giant run.** The full
scanner suite and the parity suites are large and some spawn Node; a single
`discover` over everything can exceed a reasonable timeout and get killed,
telling you nothing.

```sh
cd python

# one module (fast, precise)
PYTHONPATH=src:. python3 -m unittest tests.scanner.test_review_received_code

# one small subsystem via discover (mcp, safexml, build, pg are quick)
PYTHONPATH=src:. python3 -m unittest discover -s tests/mcp -t .

# a big subsystem in chunks — the scanner suite (~90 files) will NOT finish in
# 45 s as one run, so batch it:
mods=$(ls tests/scanner/test_*.py | sed 's#/#.#g;s#\.py$##' | sed -n '1,23p' | tr '\n' ' ')
PYTHONPATH=src:. python3 -m unittest $mods
```

Notes:

- Tests run against `src/`, not an installed copy — `PYTHONPATH=src:.` (or the
  `tests/__init__.py` path setup) puts both `src/` and the `tests` package on the
  path, for subprocesses too.
- **Environment-gated suites skip cleanly** when their variable is unset
  (`LAZARET_SAMPLES_DIR`, `LAZARET_TEST_PG_DSN`, `LAZARET_TEST_PG_MATRIX`,
  `LAZARET_BENCHMARK`, `LAZARET_TEST_FEEDS` — see `STRUCTURE.md` §4). A local run
  showing `skipped=N` is expected, not a problem; CI supplies what it can.
- **npm side:** `cd js && node --test test/<file>.test.js`, or batch a slice of
  `test/*.test.js`. Don't forget the subdirectories (`test/lib/`,
  `test/scanner/`) — a bare `test/*.test.js` glob misses them.
- The **parity suites** each spawn Node and take ~5–30 s; run the heavy ones
  (`test_js_parity.py` ~20 s, `test_js_parity_limits.py` ~27 s,
  `test_js_parity_hooks.py` ~27 s) alone and batch the light ones.
  `test_js_parity_limits.py` holds the source-size and CRLF comparisons, split
  from `test_js_parity.py` in 0.1.8 when that module reached 45 s; split a
  module the same way when it nears the limit rather than raising a timeout.
- The **native engine's parity modules** need the library built
  (`cd rust && cargo build --release --offline --locked`) and named by
  `LAZARET_NATIVE_LIB`; without it they skip (so every CI job that runs them
  first proves the library loads: `scripts/check_native_library.py LIB TAG
  --load`, or an assertion; `test_review_release_workflow.py` checks that).
  `test_rust_parity_hooks.py`
  (~27 s) runs alone; `_regex` (~1 s) and `_signs` (~8 s) batch. A suite run
  with `LAZARET_ENGINE=rust` sends every supply-chain test of the scanner and
  the registry through the native engine; `=python` keeps them in core.

---

## 3. Engine parity, concretely

`test_js_parity.py` runs *both* CLIs on every fixture tree, a synthetic project,
and an adversarial tree built at test time (BOM, UTF-16/UTF-7, a NUL near the
top, `node_modules/` with and without `--deps`, CRLF, Unicode identifiers, bidi,
`.pyc`, symlinks, a deep manifest, a large non-source file). It compares findings
as a **multiset of (rule, file, line, severity, message)** plus metrics, ratings,
gate and exit code. The `test_js_parity_*` suites compare the lower-level twins
(received-code patterns, the cross-file follower, flow, lexing, gyp, hexname,
lookalike).

The only allowed differences are the documented **Python-only** features
(`_python_only`): the flow engine's AST half (`X-*`, `Q-FLOW-*` on Python
files). (The cross-file received-code follower was the other until 0.1.8; the
npm engine runs its twin now, and `test_js_parity_crossfile.py` compares the
two on the follower's own cases and a generated stream of 700 packages.)
Anything else that differs is a real divergence — fix the engine, not the test.

**The native engine** (Rust, `docs/RUST_ENGINE.md`) has no allowed
differences at all. `test_rust_parity_regex.py` compares its regex engine
with `re` on every rule-pack pattern and 126 hand-written probes (search,
match, fullmatch, finditer, sub, split, with pos/endpos; run it on each
Python 3.10–3.14); `test_rust_parity_hooks.py` compares the 15 fields of
`hooks_view` and `test_rust_parity_signs.py` 24 detectors, case by case, on
`hooks_corpus.py` (~36,900 cases, the corpus `test_js_parity_hooks.py`
uses). `scripts/make_rust_tables.py --check` fails when the pack no longer
matches `core.py`, and `scripts/check_rust_deps.py` when a crate from
outside the workspace appears.

---

## 4. The false-positive sweep (the oracle)

A detection change must add **zero** findings on real, benign, installed code.
This is a **development-time** check, not a committed unit test (it needs real
package trees, which vary by machine), so reconstruct it against whatever is
available:

- **Single-file received-code:** run `core._received_code_kind` /
  `core._downloads_and_runs_file` over a large flat list of real `.py`/`.js`
  files (the reference sweeps used ~66,000 installed files from npm/pnpm/yarn,
  typescript/webpack/next/jest, the AI SDKs, pip/setuptools/requests/httpx, the
  CPython library). Expect 0 hits.
- **Cross-file follower:** run `core._cross_file_received_issues` over **complete
  package trees** (so the source→sink split actually appears), grouped as
  installed — walk real `site-packages` / `dist-packages` (Python) and
  `node_modules` roots (npm). The reference sweeps covered ~88,000 files (≈12k
  across 173 Python packages + ≈76k npm files) at 0 findings.

Method sketch (adapt paths to the host):

```python
# python side: feed real files straight to the detector, no findings expected
from lazaret.scanner import core
issues = core._cross_file_received_issues(files)   # files: [{path,content,lang:'py'|'js',dep:True}]
assert not issues, issues
```

- **Install-script and import-time shapes** (0.1.8's exfiltration shapes, and
  any new strong reason): run `core.import_time_risk` and
  `core.install_script_risk` over every `.py`/`.js` file of the benchmark's
  429 popular packages and over installed trees (the 0.1.8 sweep read 37,783
  files of Python `site-packages`/`dist-packages` and global npm
  `node_modules`), and list every strong reason. Expect none.

List **every** strong reason, not only the ones a change adds: 0.1.8's full
sweep found chromedriver's and phantomjs-prebuilt's installers, which define
`requestBinary()`, read as RequestBin (an exfiltration address) since 0.1.0 —
earlier sweeps had listed only their new reasons. With the native library
built, the same sweep is also a parity check: compare core's answers with the
native `batch` call's, file by file.

Any hit is a candidate false positive you must **explain** before shipping —
either it's a real risk (keep it, add a fixture) or the pattern is too loose
(tighten the *sink* side, not the liberal export side; see `DESIGN.md` §5c).

The corpora also double as timing evidence: the sweeps finish in seconds
(bounded, linear). If a sweep is slow, a bound is missing (§5).

---

## 5. Bounded-work checks

Anything that reads attacker-controlled text gets a test that feeds it a
~100 KB–1 MB adversarial input (many sources, many runners, deep nesting,
minified rows, pathological brackets) and asserts it finishes fast and returns
the right answer. See `test_review_received_code.py::test_bounded_work` and
`::test_new_sinks_stay_bounded` for the shape. The npm regex engine is the
tighter constraint — it overflows its backtrack stack where CPython only slows —
so a pattern that's "fine" in Python can still hang Node; the parity fuzz corpus
and the bounded tests catch it.

---

## 6. The full cross-subsystem pass (before a release)

Before tagging, run **every** subsystem green, individually (§2):
`scanner` (in chunks), `architecture` (incl. all `test_js_parity*`), `registry`,
`mcp`, `pg`, `safexml`, `build`, and the whole `js/test/`. This "lock-it-in"
pass is what catches ripple from a change in a widely-imported module like
`core.py` — it has caught a real regression that per-area tests missed (a
`--deps` stop-budget accounting bug). Budget for it; it's ~2,400 Python tests +
~350 JS tests, but each batch is seconds. With the native library built, run
the Python batches twice, with `LAZARET_ENGINE=rust` and `=python` (CI's
`rust` job does the first on Linux).

Then the release gates themselves: `sh scripts/check-versions.sh HEAD` (the
Python, npm and native engine versions agree), and CI's own `versions` check
runs inside the test stage before any publish job (`docs/RELEASING.md`). The
platform wheels are built, checked (`scripts/check_native_library.py`) and
installed on their five platforms by `wheels.yml`, on any pull request that
changes what goes into them; locally, `python3 scripts/check_native_library.py
rust/target/release/liblazaret_native.so manylinux_2_39_x86_64 --load` (the
tag of the glibc you built on) checks a development build the same way.

---

## 7. Cross-platform, and the Windows quirks

**Correctness must not depend on the host.** The full rulebook is `STRUCTURE.md`
§4 "Cross-platform rules" (seven rules: encoding, paths, resources, line
endings, OS capabilities, interpreter drift, time). `tests/architecture/
test_portability.py` mechanically enforces the checkable parts (stdio is
configured, I/O names an encoding, no hard-coded `/tmp`, no unsorted
`glob`/`iterdir`). Read those. This section is the *process* around them.

**Windows is the strict platform — it fails first.** Almost every
platform-specific bug surfaces on the Windows CI runners before anywhere else,
so **a green Windows job is the strongest single signal** that a change is
cross-platform-clean. The recurring failure classes to expect:

- **Path separators in output.** A finding's *message* or snippet that embeds a
  path renders `\` on Windows and `/` elsewhere — which breaks the parity
  multiset and cross-OS output comparisons. Normalize any path shown in a
  message/finding to `/` (this shipped as a real fix: "normalize the OS path
  separator in the cross-file flow message test"). Sort path *strings* by
  `as_posix()`, never `Path` objects (Windows compares them case-insensitively).
- **`\r\n`.** Windows text-mode stdout writes CRLF; treat it as a line ending,
  not data, when asserting on output. `.gitattributes` keeps checkouts LF.
- **Open-file deletion.** Windows can't delete an open file — close every file,
  archive, socket and DB handle before removing what contains it (`with` /
  `finally` / `addCleanup`). A `ResourceWarning` counts as a failure.
- **Symlink / lstat disagreement.** Node's `lstat` reported a file symlink as a
  regular file on the Windows runners, so the walkers also trust the directory
  entry type / `st_file_attributes` (reparse points). Don't rely on one stat API.
- **Command-line length (WinError 206, 32,767 chars).** Large input to a child
  process goes through stdin or a file, never the argv.
- **Encoding.** Redirected stdout is ANSI/OEM on Windows and bare-C elsewhere;
  every CLI configures UTF-8 output at startup, and tests decode subprocess
  output with an explicit `encoding="utf-8", errors="replace"` — never
  `text=True`.
- **Interpreter drift.** `json.loads` recursion limits differ by version and OS,
  so hostile JSON is depth-checked (`json_loads_bounded`, 500 levels) before
  parsing rather than trusting the interpreter. Assert on types/codes, not on an
  interpreter's message wording.

**You usually can't run Windows locally — simulate it.** Before pushing, run
`sh scripts/simulate-platforms.sh`: for each installed `python3.X` it runs the
suite under a non-UTF-8 locale (Latin-1/ASCII, standing in for Windows' code
page), with `TMPDIR` behind a symlink (macOS's `/var`→`/private/var`), and, when
run as root, as an unprivileged user. It reproduces most Windows/macOS failure
modes on a Linux box. A run that prints a `ResourceWarning` counts as failed.

**The matrix is the real gate.** Work isn't done until the full OS × Python (and
Node) matrix passes in CI. Local green + simulate-platforms green makes that
likely, but the matrix is authoritative — which is why "Windows has passed" is
worth watching for during a release run.

---

## 8. Quick reference

| Goal | Command |
|---|---|
| One Python module | `PYTHONPATH=src:. python3 -m unittest tests.scanner.test_review_received_code` |
| Small subsystem | `PYTHONPATH=src:. python3 -m unittest discover -s tests/mcp -t .` |
| Big subsystem | batch its files (§2), ≤45 s per batch |
| Engine parity | `PYTHONPATH=src:. python3 -m unittest tests.architecture.test_js_parity` (heavy; run alone) |
| Native engine parity | build (`cd rust && cargo build --release --offline --locked`), `export LAZARET_NATIVE_LIB=…`, then `tests.architecture.test_rust_parity_hooks` alone, `_regex` + `_signs` together |
| Rule pack drift | `python3 scripts/make_rust_tables.py --check` (the Unicode table's check needs 3.10) |
| Spec drift | `python3 scripts/sync-received-spec.py --check` + `tests.architecture.test_received_spec` |
| One npm file | `cd js && node --test test/review-received-code.test.js` |
| Simulate other platforms | `sh scripts/simulate-platforms.sh` |
| Version agreement | `sh scripts/check-versions.sh HEAD` |
