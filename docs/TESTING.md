# Lazaret — Testing Process

*The working method for verifying a change. What to run, in what order, how to
keep it fast, and how to survive Windows.*

This is the operational playbook. It complements two documents you should also
know:

- **`STRUCTURE.md` §4** — the test *layout*, categories/gating, the exact
  `python -m unittest` commands, and the authoritative **cross-platform rules**
  (encoding, paths, resources, line endings, OS capabilities, interpreter
  drift, time). Don't duplicate those rules; obey them.
- **`docs/DESIGN.md` §6–§8** — *why* we test this way (the parity invariant
  between the packages, the engine's recorded outputs, the 0-false-positive
  discipline, bounded work).

Everything below is inert by policy: fixtures use `.invalid` / TEST-NET hosts and
nothing is executed (`STRUCTURE.md` §6).

---

## 1. The verification sequence for a change

Run these in order. Stop and fix at the first red; a later green doesn't
redeem an earlier red.

1. **Behavioral suites (both packages).** The Python `test_review_<topic>` and
   the npm `review-<topic>.test.js` for the area you touched. Each regression
   test should fail on the pre-change code and pass after — write it that way.
   The Python suite runs on the native library: build it first (§2).
2. **The engine's recorded outputs.** A change to what the native engine
   finds (`rust/`: its code, or the rule pack) moves its recorded outputs
   (`python/tests/architecture/test_snapshot_*.py`, `snapshots/`): record the
   affected sets with the engine before and after (`scripts/snapshot.py
   record <set> --out before.jsonl.gz`, then `--out after.jsonl.gz`), read
   every case that differs (`scripts/snapshot.py diff before.jsonl.gz
   after.jsonl.gz`), and only then record the new hashes
   (`LAZARET_SNAPSHOT_UPDATE=1` on the snapshot tests) and commit them with
   the change. A failing snapshot test you did not expect is a real change in
   what the engine answers, not flakiness. Then `python3
   scripts/make_rust_tables.py --check` (the pack in its canonical form, every
   pattern compiling, the rule set the registry's), and the WebAssembly build
   against the library (`test_wasm_parity*.py`, §3).
3. **Package parity.** `python/tests/architecture/test_js_parity*.py` (they
   need the npm engine built: `cd js && npm run build`). This is the guard that
   the two packages still agree; treat a parity failure as "one package is now
   wrong," not as flakiness. A deliberately Python-only feature must be
   registered in `_python_only` (in `test_js_parity.py`) or it will (correctly)
   break parity.
4. **False-positive sweep on real code** (§4). The bar is **zero** new findings.
5. **Bounded-work check** (§5) on an adversarial large input.
6. **The benchmark**, for a change to detection: the registry scans of the
   benchmark's releases before and after the change (`scripts/bench.py`,
   §4: every difference read), and the holdout's (`compare
   --aggregate-only`); for a change to what Go or Rust code is read for,
   the Go and Rust sets too (§4).
7. **Docs** (`README.md`, this doc / `STRUCTURE.md` / `DESIGN.md` if the
   architecture moved, `CHANGELOG.md`), then commit (one logical change: the
   native engine with its recorded outputs, the Python side, and a
   JavaScript twin where the npm package still has one, together).

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
  `LAZARET_BENCHMARK`, `LAZARET_TEST_FEEDS`, `LAZARET_TEST_YARN_BERRY` — see
  `STRUCTURE.md` §4). A local run showing `skipped=N` is expected, not a
  problem; CI supplies what it can. The guard's integration tests run the real
  package managers against fake registries on 127.0.0.1 and skip a tool that
  isn't on PATH (CI's runners have npm and yarn 1, not always pnpm, Bun or
  uv); `test_guard_yarn_bun.py` also covers private registries, each tool
  reading its token from its own settings.
- **npm side:** build the engine first (`cd js && npm run build`, again after
  any change under `rust/`; it needs Rust and `rustup target add
  wasm32-unknown-unknown`), then `node --test test/<file>.test.js`, or batch a
  slice of `test/*.test.js`. Don't forget the subdirectories (`test/lib/`,
  `test/scanner/`) — a bare `test/*.test.js` glob misses them. The heaviest
  files (`review-dedupe-cap`, `review-hooks-big-a` and `-b`: ~30 s each) run
  alone.
- The **parity suites** each spawn Node and take ~5–30 s; run the heavy ones
  (`test_js_parity.py` ~16 s, `test_js_parity_limits.py` ~18 s,
  `test_review_final_parity.py` ~20 s) alone and batch the light ones.
  `test_js_parity_limits.py` holds the source-size and CRLF comparisons, split
  from `test_js_parity.py` in 0.1.8 when that module reached 45 s; split a
  module the same way when it nears the limit rather than raising a timeout.
- **The Python suite needs the native library**: since the Rust-first
  refactor it is the package's only engine. Build it (`cd rust && cargo build
  --release --offline --locked`) and name it with `LAZARET_NATIVE_LIB`, or
  install with `pip install -e ./python`, which compiles it and puts it in
  `src/lazaret/_native/`. Without it the scanning tests fail and the engine's
  own tests skip, so every CI job that runs Python tests first proves the
  library loads (`scripts/check_native_library.py LIB TAG --load`, or an
  assertion; `test_review_release_workflow.py` checks that). The snapshot
  modules take 2–25 s each (`test_snapshot_signs` and `_hooks`, the hooks
  corpus' ~44,000 cases, the longest): run those two alone and batch the
  rest. `test_wasm_parity.py` (~20 s), `_signs.py` (~11 s), `_crossfile.py`
  (~1 s), `_jsparse.py` (~18 s), `_jsflow.py` (~10 s), `_pyparse.py` and
  `_pyflow.py` (~5 s) also need the WebAssembly build (`npm run build`), and
  skip without it.
- **The network layer (NET-1).** With the native library the registry's
  requests go through `lazaret-net` (`lazaret/scanner/nativenet.py`). A test
  that fakes urllib's opener (`repo._OPENER`, `repo._module_opener`) asks for
  Python's transport: `@mock.patch.dict(os.environ, _support.PYTHON_TRANSPORT)`
  on the class. `tests.scanner.test_nativenet` runs the native client against
  an HTTPS server Python's `ssl` serves on 127.0.0.1, with a root the `openssl`
  command makes when the module starts (it skips without `openssl`), and
  `cargo test -p lazaret-net` against tiny_https's own TLS 1.3 and HTTP/2
  test server. tiny_https's tests are its own (`cargo test --release -p
  tiny_https --lib` takes about 25 s after a 3-minute build, and its
  `go_vectors`, `cms_vectors`, `sigstore_real`, `sigstore_synthetic` and
  `rekor_real` tests a second each); after taking a new drop
  (`scripts/sync_tiny_https.py`), run them and the gates. The Go checksum
  database's check (`golang.verify_lookup`) is tested on tiny_https's capture
  of the real `sum.golang.org` (`tests.registry.test_golang_sumdb`); the Go
  tests whose lookups are signed with a test key or not at all
  (`test_golang`, `test_registry_go_crates`, the `go-resolve` fuzz target)
  read them unchecked, `verify_lookup` patched in `setUpModule`.
  `tests/__init__.py` turns the provenance check off for the whole suite
  (`LAZARET_NO_PROVENANCE=1`, unless the environment sets it): a scan asks
  the registry for a release's attestations and for the release before it,
  and the tests scan made-up releases that must not reach the network.
  `tests.registry.test_provenance` turns it on over tiny_https's real npm
  and PyPI attestations (sigstore 0.2.0, 2.2.0 and 4.0.0; pypi-attestations
  0.0.30), with the registries' other documents built in their shapes.

---

## 3. Engine parity, concretely

`test_js_parity.py` runs *both* CLIs on every fixture tree, a synthetic project,
and an adversarial tree built at test time (BOM, UTF-16/UTF-7, a NUL near the
top, `node_modules/` with and without `--deps`, CRLF, Unicode identifiers, bidi,
`.pyc`, symlinks, a deep manifest, a large non-source file). It compares findings
as a **multiset of (rule, file, line, severity, message)** plus metrics, ratings,
gate and exit code. The `test_js_parity_*` suites compare what the npm
package still does in JavaScript (flow, parsing, the settings and workflow
readers, gyp, config files, taint) and the CLIs
on each area's trees (lexing, limits, eval, look-alike names).

The only allowed differences are documented **Python-only** features
(`PYTHON_ONLY`, `_python_only`): none since the Rust-first refactor's phase
3, when the flow engine's Python half (`X-*`, `Q-FLOW-*` on Python files)
became the native engine's in both packages. (The cross-file received-code
follower was the other until 0.1.8.)
Anything else that differs is a real divergence — fix the package, not the
test. Since 0.1.8 the npm package's rules are the native engine's
(WebAssembly), so these suites also hold the npm binding: what it passes in,
and how it reads the answers back.

**The native engine** (Rust, `docs/RUST_ENGINE.md` §5) is held to its own
recorded outputs since the Rust-first refactor retired the Python engine it
was held to before (with zero differences, on every field, until then).
`test_snapshot_hooks.py` records the 15 fields of `hooks_view` and
`test_snapshot_signs.py` the detectors one by one on `hooks_corpus.py`
(~44,000 cases: curated cases per area, random texts from each area's
pieces, and 600 generated obfuscated files); `test_snapshot_scanfile.py`
`scan_file` in dependency mode and `scan_rules`, finding for finding, family
by family, and each line's context, on `scanfile_corpus.py` and the
fixtures; `test_snapshot_crossfile.py` the cross-file follower on a
generated stream of 700 packages (side by side, one package, distributions,
separators); `test_snapshot_hook_commands.py` a hook's command read as a
program; `test_snapshot_small.py` the hidden names, look-alike names and
off-screen code; `test_snapshot_lexer.py` the comment lexer's spans on dense
random text in every language; `test_snapshot_js_flow.py`,
`test_snapshot_js_parse.py` and `test_snapshot_py_flow.py` project mode's
cross-file taint passes and the JavaScript parser (on generated projects
among others: `jsgen.py`, `pygen.py`). A hash per 100 outputs: a failure names the
chunks that moved, and `scripts/snapshot.py diff` the cases. The lexers
themselves (`docs/RUST_ENGINE.md` §15) are held to the runtimes' own
readers by `test_lex.py`: the JavaScript lexer's literals to the engine's
JavaScript parser, node for node, and the Python lexer's strings,
f-strings and comments to Python 3.13's `tokenize`.
`test_rust_parity_regex.py` still compares the regex engine with `re` on
every rule-pack pattern and 126 hand-written probes (search, match,
fullmatch, finditer, sub, split, with pos/endpos; run it on each Python
3.10–3.14), `test_shell_words.py` compares the engine's reading of a
command's words with Python's shlex (the hooks corpus and random
commands), and `test_wasm_parity.py`, `_signs.py`, `_crossfile.py`,
`_jsparse.py`, `_jsflow.py`, `_pyparse.py` and `_pyflow.py` hold the WebAssembly build the npm package
ships to the library, call for call and byte for byte, on the same corpora.
`scripts/make_rust_tables.py --check` fails when the pack leaves its
canonical form, a pattern stops compiling, its rule set is not the
registry's, a value core still keeps differs from it, or `re`'s own table
of extra case equivalences is not the one the engine derives from
Unicode's case mappings; and
`scripts/check_rust_deps.py` when a crate from outside the workspace
appears.

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
earlier sweeps had listed only their new reasons.

Any hit is a candidate false positive you must **explain** before shipping —
either it's a real risk (keep it, add a fixture) or the pattern is too loose
(tighten the *sink* side, not the liberal export side; see `DESIGN.md` §5c).

The corpora also double as timing evidence: the sweeps finish in seconds
(bounded, linear). If a sweep is slow, a bound is missing (§5).

**What carries over: the holdout.** The malware benchmark's 516 releases were
read while the detectors were written, so a change measured only on them is
measured in-sample. Score a detection change on the holdout too (`DESIGN.md`
§7: 747 other malicious releases of the same dataset, each marked when it
shares a code file with a benchmark sample), and look at its aggregates only —
the share SUSPICIOUS, by ecosystem and category, by whether a release shares
code with the benchmark, and how much of it rests on a behaviour or a generic
technique rather than a tool's mark or a list. Never open a holdout sample or
the list of its misses: a rule written from one makes the holdout in-sample.
A detector that recognizes the samples it was written from shows up there:
in-sample up, holdout flat.

**The harness.** `scripts/bench.py run MANIFEST OUT.jsonl` scans each
release of a manifest as `lazaret-registry` does (in memory; nothing is
unpacked to disk or run) and writes its verdict and strong findings; it is
resumable and starts no release after `--stop-after` seconds, so loop it
under a 45 s timeout until it prints `DONE`. `scripts/bench.py compare
BEFORE.jsonl AFTER.jsonl` gives the verdicts by category in each run and
every release whose verdict or strong findings moved — read each one —
and `--aggregate-only` gives the counts alone, for the holdout. The
samples themselves are kept outside the repository (`STRUCTURE.md` §6).

**The popular releases: the release gate's benign set.** The benchmark's 429
popular packages are mostly small libraries, and they did not hold the nine
popular releases 0.1.8 made SUSPICIOUS (vite, vitest, monaco-editor,
coverage, numba, future, sympy, ipython, kubernetes: B-1).
`scripts/popular/releases.jsonl` pins 1,703 more: the latest releases, on
Oct 3, 2026, of 1,205 popular npm and PyPI packages the benchmark does not
hold, and on Oct 6, 2026, of the 500 most-downloaded crates (498: two are
under licences the set does not take, MPL-2.0 and CDLA-Permissive-2.0), each
the one file the guard scans (npm's tarball; for PyPI the file pip installs
on Linux x86-64; a crate's `.crate`), by version and sha256.

```
python3 scripts/popular/popular.py fetch --cache DIR --manifest DIR/manifest.jsonl
python3 scripts/bench.py run DIR/manifest.jsonl RUN.jsonl      # looped under a 45 s timeout
python3 scripts/bench.py compare BEFORE.jsonl RUN.jsonl
```

`fetch` downloads them once (about 710 MB; a file already in DIR is hashed
again, other bytes than the pinned ones are refused; `--only crates` takes
one ecosystem's). Run the set before and after a detection change and
before a release, as the benchmark: no release may be SUSPICIOUS, and every
verdict or strong finding that moves is read. 0.1.8 makes the nine
SUSPICIOUS on it, and 0.1.9 none of the npm and PyPI releases (32 WARN, and
1 INCOMPLETE: sharp's 16 MB libvips library, counted as unscanned code) nor
of the crates (16 WARN: 13 for the prebuilt libraries and objects they ship,
the windows and winapi import libraries, ring's and aws-lc-sys's assembly
and wit-bindgen's WebAssembly; 3 for test data, SC-HEXSTR, SC-OPAQUE-BLOB
and SC-NESTED-ARCHIVE). At each release, refresh it:
`popular.py pin --top 800,400,500 --exclude FILE --cache DIR` takes the
latest release of the first 800 npm, 400 PyPI and 500 crates names of
`python/src/lazaret/registry/popular_names.json` (the most downloaded),
less the benchmark's benign names, which FILE lists, and pins those three
ecosystems anew (crates.io's API is asked once a second, so the crates take
about ten minutes; a crate under a licence Apache-2.0 can't take in is left
out, since this set's findings are read); a new release of a popular
package is what this set exists to catch. A fourth count pins extensions
from Open VSX, and an ecosystem given no count, or 0, keeps its pins.
`popular.py pin npm:vite@8.3.2 crates:syn …` adds or moves single
releases, and `popular.py check` validates the file.

**The extensions (E-1's fourth part).** `popular.py pin --top 0,0,0,400
--cache DIR` takes the first 400 names of the extensions' list (`vscode`
in `popular_names.json`: both registries' rankings, in turn) and pins, for
each one Open VSX serves, its newest release that is not a pre-release and
has a file for Linux x86-64 (the `linux-x64` file, else the universal one,
as the editor chooses), checked against the SHA-256 Open VSX publishes
beside it and only under the licences the crates are taken under; a name
only the Marketplace serves is left out (its files have no published
digest to pin by). Open VSX is asked twice a second, and its file URLs
redirect to its content host (the script follows a redirect only to https
on a registry's own host). `fetch --only openvsx --manifest DIR/vsix.jsonl`
and `bench.py run` scan them as `lazaret FILE.vsix` does: no extension may
be SUSPICIOUS, and every WARN is read. The sandbox the 0.1.9 work ran in
cannot reach Open VSX, so the set is pinned and run where it can be.

**The Go and Rust sets (N-2).** No Go registry publishes downloads, and Go's
module proxy can't be reached from everywhere the gate runs, so the Go and
Rust code the gate holds quiet, beside the popular crates, is what a
distribution packages and what Go ships. `scripts/popular/packaged.py`
packs both, each module or crate as its registry serves it (a module zip,
a `.crate`), for `bench.py`:

```
python3 scripts/popular/packaged.py ubuntu --debs DEBS --cache DIR --manifest DIR/ubuntu.jsonl --left-out DIR/left.jsonl
python3 scripts/popular/packaged.py gostd --cache DIR --manifest DIR/gostd.jsonl
python3 scripts/bench.py run DIR/ubuntu.jsonl RUN.jsonl        # looped under a 45 s timeout, as above
```

`ubuntu` takes every `golang-*-dev` and `librust-*-dev` package of Ubuntu
24.04's universe (noble's index, pinned by sha256: the release pocket never
changes; about 575 MB of `.deb`s, fetched once into DEBS and checked
against the index), keeping a package only when its DEP-5 copyright file
names licences Apache-2.0 can take in: of 4,746 packages, 4,040, with 1,953
Go modules and 2,151 crates. `gostd` packs Go's `std`, `cmd` and the
modules they vendor (`go env GOROOT`). The gate is the popular set's: none
SUSPICIOUS, every WARN read. On 0.1.9 (rule set 2.37.0, Go 1.24.7) none is
SUSPICIOUS; Ubuntu's Go modules give 27 WARN and 3 INCOMPLETE (Debian packs
aws-sdk-go-v2 and azure-sdk-for-go each as one tree, past the archive's
20,000 files and the reader's 300 million characters, and go-git-fixtures'
65 MB `data.go` runs past the deadline), its crates 16 WARN, Go's own 3 of
18 (the race detector's and BoringCrypto's `.syso` objects, and SC-B64 on
`stringer`'s name tables of mixed case). Before rule set 2.35.0, SC-B64 was
behind 24 of the 39 Go WARNs and 11 of the 30 crates', on runs that are not
base64 (backlog G-5: `stringer`'s tables, decimal and hex literals,
repeated test strings); what it reports on these sets now is base64 that is
data (keys, certificates, test messages) and `stringer` tables of mixed
case.

**The Go and Rust malicious set** is run offline by John: real samples
can't be fetched from the sandbox (crates.io deletes them; OSV and Go's
proxy are out of its reach), and none is written in it. A sample is a
manifest line with `"kind": "gomod"` (a module zip, `path@version/` inside,
`"container": "zip"`) or `"kind": "crate"` (a `.crate`, `name-version/`
inside, `"container": "tgz"`) and a category other than `"benign"`; the
gate is each one SUSPICIOUS for its documented reason. Until then, the
reader tests' single-technique samples (`goread/tests.rs`,
`rsread/tests.rs`) and the guard tests' are the coverage set.

**VS Code extensions (E-1).** `bench.py` takes a `.vsix` as `"kind": "vsix"`
(`extension/` inside, `"container": "zip"`), scanned as `lazaret FILE.vsix`
scans it. The extensions' benign set (the most-installed Open VSX
extensions, pinned by sha256: `popular.py pin --top 0,0,0,N`, above) is
E-1's part 4, and their malicious set
(GlassWorm's and the other campaigns' samples) is run offline by John, as
the Go and Rust one is: neither registry can be reached from the sandbox.
Until then, `tests/registry/test_vsix.py`'s single-technique fragments are
the coverage set, and the popular set's npm releases wrapped as extensions
(their `package.json` given a publisher and an engine) check that the
editor's rules add no false positive to npm's: on 0.1.9, 782 OK, 19 WARN,
none SUSPICIOUS, none above its npm verdict.

---

## 5. Bounded-work checks

Anything that reads attacker-controlled text gets a test that feeds it a
~100 KB–1 MB adversarial input (many sources, many runners, deep nesting,
minified rows, pathological brackets) and asserts it finishes fast and returns
the right answer. See `test_review_received_code.py::test_bounded_work` and
`::test_new_sinks_stay_bounded` for the shape. The engine's patterns run on
linre, in time linear in the text whatever it holds (P-16): a pattern linre
would not run fails `test_linre` (the pack's) or the recorded-output runs
(one the engine builds as it scans, through `linre.refused`), so write it
another way (`docs/RUST_ENGINE.md` §14 has the ways it was done). What a
detector reads around a match still needs its own bound. The npm package's
remaining JavaScript regexes are the tighter constraint — V8 overflows its
backtrack stack where CPython only slows — and the bounded tests catch it.

---

## 6. The full cross-subsystem pass (before a release)

Before tagging, run **every** subsystem green, individually (§2):
`scanner` (in chunks), `architecture` (incl. all `test_js_parity*`), `registry`,
`mcp`, `pg`, `safexml`, `build`, and the whole `js/test/`. This "lock-it-in"
pass is what catches ripple from a change in a widely-imported module like
`core.py` — it has caught a real regression that per-area tests missed (a
`--deps` stop-budget accounting bug). Budget for it; it's ~2,400 Python tests +
~350 JS tests, but each batch is seconds. The Python batches run on the
native library (build it first, §2).

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
| Engine parity | `cd js && npm run build`, then `PYTHONPATH=src:. python3 -m unittest tests.architecture.test_js_parity` (heavy; run alone) |
| The engine's recorded outputs | build (`cd rust && cargo build --release --offline --locked`), `export LAZARET_NATIVE_LIB=…`, then `tests.architecture.test_snapshot_hooks` and `_signs` alone, the other `test_snapshot_*` in a batch; with `npm run build`, `test_wasm_parity` and `_signs` alone, `_crossfile` in a batch |
| Review a change of outputs | `python3 scripts/snapshot.py record SET --out before.jsonl.gz` (engine before), the same `--out after.jsonl.gz` (after), `python3 scripts/snapshot.py diff before.jsonl.gz after.jsonl.gz`; then `LAZARET_SNAPSHOT_UPDATE=1` on the snapshot test |
| Rule pack checks | `python3 scripts/make_rust_tables.py --check` (the Unicode table's check needs 3.10) |
| One npm file | `cd js && npm run build` once, then `node --test test/review-received-code.test.js` |
| Simulate other platforms | `sh scripts/simulate-platforms.sh` |
| Version agreement | `sh scripts/check-versions.sh HEAD` |
