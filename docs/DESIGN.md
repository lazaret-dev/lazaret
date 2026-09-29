# Lazaret — Design & Contributor Guide

*How Lazaret is built, why it is built that way, and how to work on it without
breaking the things that make it trustworthy.*

This document is for whoever picks Lazaret up next — human or agent. Read it
before changing detection logic. The companion docs: `README.md` covers what the
tool does and how to use it; `STRUCTURE.md` covers where files live, the test
layout, and the cross-platform rules; `docs/TESTING.md` is the operational
testing playbook (what to run, in what order, and the Windows quirks); this
document covers the **design and the invariants**. When they disagree, the code
and the tests are the source of truth — fix the doc.

---

## 1. What Lazaret is

Lazaret is a static security, supply-chain and quality scanner for Python,
JavaScript and SQL projects, plus a registry auditor for npm/PyPI packages. It
ships as **two independently-installable packages that must behave identically**:

- **PyPI `lazaret`** — the Python engine. Standard library only. Console
  scripts: `lazaret` (project scan), `lazaret-registry` (package audit),
  `lazaret-mcp` (MCP server), `lazaret-sca` (CVE bundle + SCA).
- **npm `lazaret`** — the Node engine. Zero runtime dependencies, ES modules.
  It is the **project scanner only** (`lazaret <dir>`); registry auditing,
  custom taint specs, SCA and the MCP server are Python-only.

The name is a quarantine metaphor (a *lazaret* is a quarantine station): you run
untrusted dependencies past it before letting them in.

### Design goals, in priority order

1. **Trustworthy over clever.** A false positive spent is trust spent. Every
   detection change is measured against real-world corpora and must not add
   noise (see §7, the 0-FP discipline).
2. **Deterministic and self-contained.** No network at scan time, no third-party
   libraries, identical results on Linux/macOS/Windows and across Python/Node
   versions. A scan of the same bytes gives the same answer everywhere.
3. **Bounded.** No input — a 50 MB minified bundle, a pathological nest of
   brackets, a file written to defeat the follower — may make the scanner slow.
   Every pass is linear-ish and every search is bounded.
4. **Auditable.** The rules are readable. A reviewer can see why a finding fired.

---

## 2. The prime directive: two engines, one behavior

**The single most important invariant.** Every rule, lexer quirk, taint step,
SQL sink, encoding rule and metric exists in *both* engines and they must agree
on every input — the same finding (rule, file, line, severity, message), the
same metrics, ratings, quality gate and exit code.

- **Held by tests.** `python/tests/architecture/test_js_parity.py` runs both
  CLIs on every fixture tree, a synthetic project, and an adversarial tree
  generated at test time, and compares the results as a multiset. The
  `test_js_parity_*.py` files compare the lower-level twins (the received-code
  detector, the flow engine, lexing, gyp, etc.), often by running thousands of
  cases through one Node process and diffing against the Python answer.
- **When you change one engine, change the twin in the same commit.** The JS
  twin of a Python helper says so in a comment (`Twin of
  lazaret.scanner.core…`). Parity failing is not a flaky test; it means the
  engines have diverged and one of them is now wrong.
- **The browser dashboard** (`python/src/lazaret/web/lazaret.html`) carries a
  third port of the engine and is held to the same findings
  (`test_review_dashboard_parity.py`). Editing the dashboard's inline script
  requires re-running `scripts/dashboard_csp.py` (its CSP pins the script by
  SHA-256).

### The documented Python-only exceptions

Two capabilities run only in the Python engine, by deliberate design, and the
parity test excludes them (`_python_only` in `test_js_parity.py`):

1. **The AST half of the interprocedural flow engine** — `flow.py`'s Python
   analysis is AST-based and has no JS twin; its `X-*` findings and `Q-FLOW-*`
   coverage notes on Python files are Python-only. The JavaScript half of the
   flow engine *is* twinned (`js/src/scanner/flow.js` and `jsflow.js`, on the
   reader `js/src/lib/jsparse.js`).
2. **The cross-file received-code follower** — `core._cross_file_received_issues`
   (SC-IMPORT-RISK whose message contains "another file of the package"). See §5c.

When the npm engine cannot do something the Python engine can, it must say so
honestly rather than silently under-report. This is the **honest-gate pattern**:
the npm gate's cross-file condition reports how many Python files it did not
analyze. Any future Python-only feature follows the same rule — degrade
visibly, and add it to `_python_only` so parity stays green.

---

## 3. Invariants you must not break

These are non-negotiable. A change that violates one is wrong even if its tests
pass, because the test that would have caught it may not exist yet — so hold the
line yourself.

- **Pure standard library (Python) / zero dependencies (npm).** The Python
  package imports nothing outside the stdlib — including its Postgres client
  (`lazaret.pg`, speaks the wire protocol itself) and its XML parser
  (`lazaret.safexml`). `tests/architecture/test_stdlib_only.py` enforces it. The
  npm package has no runtime deps. This is a security property, not a
  preference: fewer moving parts, nothing to compromise, trivially auditable.
- **Unicode 13.0, pinned.** Source text is read in Unicode 13.0 on every Python
  and Node version (`_unicode13.pin`; a later code point is scanned and shown as
  U+FFFD). Results must not depend on the host's Unicode tables. Regenerate
  tables with `scripts/make_unicode_tables.py`; never call `unicodedata`
  directly in scan logic.
- **Bounded, linear work.** No catastrophic backtracking, ever. Patterns are
  written so the regex engine keeps a bounded number of backtrack entries (the
  npm engine's engine overflows its stack on millions). Values are followed for
  a fixed window; call arguments are read for a fixed span; a row longer than a
  threshold is treated as minified and read once. When you add a pattern, add a
  "bounded work" test that feeds it a ~100 KB–1 MB adversarial input and asserts
  it finishes fast (see `test_review_received_code.py::test_bounded_work`).
- **Zero false positives on real code.** Detection changes are swept against the
  real-world corpora before shipping (§7). "It catches the attack" is half the
  bar; "it stays silent on 80,000 real files" is the other half.
- **Secrets are always redacted.** Any finding's snippet, message and the
  registry's stored results are swept for credentials before they reach a
  report, the baseline fingerprinter, or the registry store
  (`_Redactor`, `redact_result`, `redact_file_issues`). A `--no-redact-secrets`
  flag exists but the SECRET-rule lines are redacted regardless.
- **Inert fixtures only.** Everything under `python/tests/fixtures/` looks
  malicious but does nothing: network references point at `.invalid`, TEST-NET
  (`192.0.2.0/24`) or private addresses; credentials are dummies; nothing is
  ever installed or executed. Functional offensive samples live in the private
  `lazaret-samples` repo and reach tests only via `LAZARET_SAMPLES_DIR`. Never
  commit live malware or a fixture that touches the network.

---

## 4. System map

```
lazaret.scanner    rules, taint, cross-file flow, CLI            (lazaret)
lazaret.registry   npm / PyPI package auditing                   (lazaret-registry)
lazaret.mcp        MCP server                                    (lazaret-mcp)
lazaret.scanner.sca_feeds / CVE bundle + SCA                     (lazaret-sca)
lazaret.pg         Postgres wire-protocol client (stdlib only)
lazaret.safexml    safe XML parsing (stdlib only)
```

The heart is `lazaret.scanner.core` (a large single module) and its npm twin
under `js/src/`. The project-scan pipeline is `core.scan_project(root, …)`,
shared by the CLI and the MCP server. In order it:

1. **collects** files and manifests (`_collect`, honouring `--deps`, excludes,
   size caps, binary/pyc/symlink/encoding checks);
2. **scans each file** (`scan_file`) — rules, intra-file taint, SQL sinks,
   obfuscation/secret detection, per its language — and each config or data
   file (`scan_config_file`: `.env`, JSON, YAML, TOML, INI, shell, keys,
   Dockerfiles; `lazaret.scanner.configsecrets` and `js/src/lib/configsecrets.js`)
   for credentials only; config files are not code and count in no code metric;
3. **scans manifests** (`package.json`, `binding.gyp`, …);
4. **runs `--deps` checks** (`dependency_checks`) — what dependencies run at
   install and import time (install hooks followed to the files they run,
   import-time received-code, and the cross-file follower);
5. **runs the interprocedural flow engine** (`lazaret_flow.analyze`), guarded so
   a failure degrades to the intra-file engine with a visible warning;
6. **adds coverage notes** (skipped trees, symlinks, unreadable/truncated);
7. **computes metrics, ratings and the quality gate**, then
8. **sweeps everything for secrets** and returns `build_result(...)`.

`build_result` returns the dict the CLI and MCP serialize: `project`,
`metrics`, `counts`, `ratings`, `supplyChain`, `crossFile`, `perFile`,
`issues`, `warnings`, and (when a stop budget fired) `incomplete`.

---

## 5. The detection engines, in layers

### a. Intra-file rules and taint

Per-file pattern rules (SQL sinks, obfuscation, secrets, look-alike identifiers,
hidden Unicode, packed/hex-escape building, `.pth` execution, UTF-7/escape
codecs, binary artifacts) plus intra-file taint that follows request-shaped
input (`request.*`, `req.*`, `argv`, decoders) through assignments, f-string
and template-literal fields and multi-line statements into sinks (SQL,
command, code, path traversal, SSRF, open redirect, XSS — Flask/Django
responses and a Flask view's return value —, SSTI). Only a sink's injectable
arguments are read; path guards that leave clear path traversal; a taint is
scoped to the function body (by indentation) it was made in, and a
reassignment in the same block replaces it. Containers (`d["k"] = q`,
`xs.append(q)`) take the taint of what is written into them, by literal key;
allowlist checks clear a value where it passed. Framework models (0.1.7):
the parameters a route handler gets from the request are sources — a Flask
view's URL variables, a FastAPI path operation's parameters (not injected
dependencies, not types that validate to no free text), a Django view's URL
parameters. The decisions over a parameter's name, annotation and default
live in `lazaret.scanner.frameworks` and are shared by the intra-file engine
(which reads a handler's signature from text: `_route_params`, twinned in
`js/src/scanner/taint.js`) and the flow engine (which reads it from the AST:
`_request_params`), so both passes agree on what a handler receives. Comments
are **lexed, not guessed** — block-comment/string/template state is tracked
across lines, and a line counts as a comment only if all of it is, and only if
both readings of ambiguous text agree.

### b. Interprocedural / cross-file taint (`flow.py` / `flow.js`)

Whole-program analysis that follows untrusted data through function calls and
across files — a source in one module reaching a sink in another (`X-*`
findings name both ends). Python analysis is AST-based (import resolution,
`self`/`cls`, constructors, a worklist fixpoint composing `f → g → sink`
chains). JavaScript and TypeScript are parsed too (0.1.7): `jsparse.py` reads
ES2025 with JSX, TypeScript and Flow annotations into ESTree trees with every
node's line (linear: one token at a time, bounded reads ahead, a
`JsSyntaxError` past `MAX_DEPTH` nesting), and `jsflow.py` follows them with
the same model — per-function summaries (parameters → sinks, what the
function returns) to a fixpoint over the call graph callees first, scopes
and a flow-insensitive points-to for functions, modules, classes and object
literals, values followed through locals, closures, containers, callbacks
and exported variables. It is deterministic: no wall clock — a work budget
per syntax tree node, a limit per reading of one function and a re-analysis
cap per function bound it, counted identically in both engines. Its twins
are `js/src/lib/jsparse.js` and `js/src/scanner/jsflow.js`, held node for
node and step for step by `test_js_parity_parse.py` and
`test_js_parity_flow.py` (the latter over seeded generated projects,
`tests/architecture/jsgen.py`). This is the engine whose **Python (AST)
half is Python-only** (§2). Custom taint specs
(`--taint-config`, Semgrep-style) feed both the intra-file and cross-file
passes. A repository's own `.lazaret-taint.json` is loaded only with
`--trust-repo-config`, and even then its sanitizers are ignored (a repo could
silence real findings by declaring `str` a sanitizer).

### c. The received-code detector (the recent focus — know this well)

Detects code that **runs, deserializes or dynamically imports a value it
received over the network** — the TrapDoor/dropper shape. Lives in `core.py`
(section comment "Code that runs what it receives over the network") and its
twin `js/src/lib/received.js`.

- **Single-file entry points.** `runs_received_code(text)` /
  `_received_code_kind(text)` → `(1-based line, category)` where category is
  `run` / `deserialize` / `import`; `_downloads_and_runs_file(text)` → the
  weaker MAJOR-only download-to-file-then-run signal.
- **What it follows.** A received value (a download, a socket's or server's
  data) through the names it is assigned to, callback parameters
  (`res.on('data', …)`, `.then(…)`), `with … as` / `for` bindings, and
  functions that return it, to a runner that takes it whole: eval / exec /
  `new Function` / vm / a shell / an interpreter's inline code
  (`['node','-e',code]`), a deserializer (`pickle`/`marshal`/unsafe
  `yaml.load`/node-serialize, CWE-502), or a dynamic import of a received
  specifier. Runners reached under an alias (`const e = eval; e(x)`) or
  indirectly (`(0,eval)(…)`, `eval.call`, `window['eval']`) are followed.
- **Needle-gated and bounded.** A file is read only if it holds a network
  "needle" *and* a sink needle; only rows near a network name (or naming a
  followed value) are read; a value is followed for `_DL_WINDOW` (50) rows; a
  call's arguments and each argument's value are read for `_DL_ARG_SPAN` (400)
  chars; a minified row (`> _DL_LONG_ROW`) is read once. Result: a text costs
  about one pass whatever it holds.
- **Severity policy.** Import-time code → SC-IMPORT-RISK, MAJOR for what
  ordinary code can share and CRITICAL (`import_time_severity`, 0.1.7) for
  the shapes no library needs: code received over the network and run, a
  download run through a shell, hidden or fetching PowerShell, a stager
  string, a reverse shell, credentials sent to a named exfiltration service,
  host information sent to a data-capture service, a download run with the
  Python interpreter. An install script that does any of it → CRITICAL
  (`install_script_risk`). Download-to-file is MAJOR only in npm hooks and
  import-time code (it is also the shape of a legitimate prebuilt-binary
  installer); in the code pip runs to install an sdist it is CRITICAL.
  The import-time test reads code, not prose: a file that fails it is read
  again with its comments (and Python's statement strings — docstrings)
  blanked in place (`_import_code`; line breaks and character counts kept,
  so lines and pattern bounds are unchanged), and PowerShell counts there
  only as an argument of an exec call (`_powershell_run_at`). Both keep the
  lexer off the hot path: it runs only on a file the raw text already fails.
  A file that reads its own source (`reads_own_source`: `open(__file__)`,
  `__doc__`, `readFileSync(__filename)`, a function's `.toString()` …)
  keeps its prose — the comment may be the payload or the C2 address — and
  running what it reads back, or what it reads from a data file next to it,
  is CRITICAL on its own (`runs_own_source_at`; reads, runners and names
  inside string literals don't count, so a code template in a string is not
  one).

**The shared spec.** The detector's data (name sets, character sets, limits) and
**all its patterns** (27 plain regexes + 6 alternation groups, ~57 compiled
patterns total) are authored once in
`python/src/lazaret/scanner/received_spec.json` and compiled by both engines.
`scripts/sync-received-spec.py` copies it to `js/src/lib/received-spec.json`
(run `--check` in CI); `tests/architecture/test_received_spec.py` fails if the
copies drift or if core stops matching the spec. `test_js_parity_hooks.py`
compares the compiled patterns (asserts 57 patterns / 23 sets / 3 maps) and runs
a 30k+ case agreement corpus plus a reach test. **Edit the spec, not the inline
patterns; then sync.** The npm engine loads the spec with `readFileSync` at
import — the build backend ships `.json` from the package so it lands in the
wheel.

**The cross-file follower (Python engine only).** `_cross_file_received_issues`
catches a value received in one file of a dependency package and run in another
(source and sink split across modules) — in both Python and npm packages, under
`--deps`. Design:

1. Per package, `_xf_tainted_exports` / `_xf_js_tainted_exports` collect each
   module's **tainted exports** — a module-level function/value that holds or
   returns a received value, or a class method that returns one. Export
   detection is deliberately *liberal* (many real HTTP libraries fetch and
   return data); it is kept precise by the sink side.
2. Import resolution (`_xf_imported_taint` / `_xf_js_seeds`) resolves a sibling
   `from .mod import name` / `require('./mod')` / `import … from './mod'`
   (named, namespace, default; **one hop**, same package) to those exports, and
   for a tainted class, seeds the `instance.method` chain of instances made in
   the importing file (`c = C(); exec(c.pull())`).
3. The importing file is re-run through `_received_code_kind(text,
   extra_always=<seeds>)` — the seed rides the existing `_DlTaint.always`
   machinery, so no change to the single-file detector's behavior (default
   `extra_always=()` keeps the twin and the parity corpus identical). It fires
   **only** when the value genuinely came from another file; files already
   flagged single-file are skipped.

Robustness: export detection masks strings and comments (including triple-quoted
docstrings — a `requests.get(…)` in documentation is not an export). Bounds are
the follower's own (`_XF_WINDOW` = 25, and hard caps `_XF_MAX_FILES` /
`_XF_MAX_EXPORTS` / `_XF_MAX_SEEDS`), not the single-file detector's. It runs off
the twinned `flow.py` path; the npm engine stays single-file with an honest gate.

### d. Supply-chain / `--deps`

Install hooks (`package.json` scripts, `binding.gyp` actions and command
expansions — the Miasma trick) are followed to the files they run, and checked
like the registry does: CRITICAL when a hook collects the environment/credentials
next to a network call, contacts an exfiltration address, pipes a download into
a shell (SC-PIPE-SHELL), runs received code, or launches an AI coding agent in
autonomous mode (SC-AGENT-HIJACK — the s1ngularity/Nx attack). A package with a
`binding.gyp` and no install script gets the implicit `node-gyp rebuild` hook
(MAJOR). Also: look-alike identifiers (SC-HOMOGLYPH), hidden-Unicode carriers
(SC-HIDDEN-UNICODE), decode-then-execute (SC-EVAL-DECODE, incl. indirect eval).

### e. Registry auditing (`lazaret.registry`) and SCA

`lazaret-registry` fetches and audits an npm/PyPI artifact with the same rule
pack, discovering install hooks and start-up files and running the import-time
checks. `lazaret-sca --update-bundle` builds a CVE bundle from public feeds
(OSV, CISA KEV, EPSS) parsed with `lazaret.safexml`; Lazaret ships no
vulnerability database of its own. The registry always redacts what it stores.

---

## 6. How to add or change a rule — the loop

This is the working method. Follow it; it is why the tool has stayed trustworthy.

1. **Research first.** Understand the real attack/incident and how real code
   uses the same syntax benignly. The second half decides the false-positive
   risk.
2. **Write an inert fixture** that reproduces the miss (hosts `.invalid`,
   nothing executed) and **confirm the current engine misses it.** A test that
   never failed on the old code proves nothing.
3. **Implement in the Python engine.** Keep it needle-gated and bounded.
4. **Twin it in the JS engine with exact parity**, in the same commit. Mark the
   twin (`Twin of lazaret.scanner.core…`). For received-code patterns, edit the
   **shared spec** and sync instead of hand-writing both.
5. **Verify:**
   - the behavioral suites (both engines);
   - **engine parity** — `test_js_parity*` (the differential corpus + the
     pattern twins); a Python-only feature goes in `_python_only`;
   - **a fuzz differential** where relevant (the received-code parity runs
     ~33k cases; both engines must agree on every one);
   - **the false-positive sweep** against the real corpora (§7): the bar is 0
     new findings;
   - **bounded work** on an adversarial ~100 KB–1 MB input.
6. **Update docs** (`README.md` capabilities, `STRUCTURE.md`/this doc if the
   architecture moved, `CHANGELOG.md`).
7. **Commit** (see §9) and deliver.

If a check can't be made green honestly, the change isn't ready. Don't loosen a
parity or FP test to pass — that discards the property it protects.

---

## 7. Testing and the false-positive oracle

`docs/TESTING.md` is the full operational playbook (the verification sequence,
the 45-second per-suite discipline, the FP-sweep method, the Windows quirks).
The essentials:

- **Layout.** `python/tests/{scanner,architecture,registry,mcp,pg,safexml,build}`;
  npm tests under `js/test/` run with `node --test`. `STRUCTURE.md` §4 has the
  detail.
- **Run suites individually with a short timeout (≤45 s each).** The full
  scanner suite and the parity suites are large; run them per-module or in
  small batches, never one giant run. Some spawn Node (parity, dashboard).
- **Environment-gated suites skip cleanly:** `LAZARET_SAMPLES_DIR` (the private
  offensive corpus), `LAZARET_TEST_PG_DSN` (live Postgres),
  `LAZARET_BENCHMARK` (21 real packages over the network), `LAZARET_TEST_FEEDS`
  (live OSV/KEV/EPSS). CI provides what it can; locally they skip.
- **The false-positive oracle.** Detection changes are swept over large sets of
  *real, installed, benign* packages and must add **zero** findings:
  - single-file received-code: ~66,000 installed JS+Python files;
  - the cross-file follower: ~88,000 files (≈12k across 173 installed Python
    packages + ≈76k npm files), scanned as complete packages so cross-file
    shapes actually appear.
  These sweeps run the detector directly over file lists / package trees (see
  the scratch tooling used during development; reconstruct equivalents against
  whatever real `site-packages` / `node_modules` are available). Treat any new
  hit as a candidate FP to explain, not a win.
- **Windows is the strict platform.** Path separators, encoding and the pinned
  Unicode tables surface there first. If CI is green on Windows, the
  cross-platform surface is usually sound.

---

## 8. Performance and safety bounds

Everything that reads attacker-controlled text is bounded. The received-code
detector is the worked example: needle gates decide whether to read a file at
all; a value is followed for a fixed row window; call arguments and their values
are read for a fixed character span; brackets are matched in one pass; no pattern
backtracks more than a bounded amount; a minified row is read once. When you add
anything that scans text, ask "what does this cost on a 50 MB adversarial input?"
and add a `test_*_bounded` that answers it. The npm regex engine is the tighter
constraint — it overflows its backtrack stack where CPython merely slows.

---

## 9. Versioning, release and delivery

- **One version, two files, kept in sync:** `__version__` in
  `python/src/lazaret/__init__.py` and `"version"` in `js/package.json`.
  `scripts/check-versions.sh` fails if they disagree (and, at a tag, if they
  don't match the tag). Pre-1.0; the 0.x API may still change.
- **Release** (`docs/RELEASING.md`): bump both versions in one commit, get it
  onto `main`, `scripts/tag-release.sh vX.Y.Z` (it refuses uncommitted changes,
  a HEAD not on `origin/main`, mismatched versions, or an existing tag), then
  push the tag. The GitHub Actions workflow runs the suite, then publishes to
  PyPI and npm via **trusted publishing (OIDC)** — no long-lived tokens.
  Published versions are immutable; a mistake means releasing the next patch,
  not re-tagging.
- **CHANGELOG.md** started at 0.1.6 (Keep a Changelog). Date each entry at
  release.
- **What ships** is narrow: the wheel/sdist contain only `src/lazaret/`, the npm
  package only `bin/` and `src/`. `scripts/make_bundle.py` builds a reproducible
  source tarball from tracked files only and refuses credential files.
- **Delivery in this project's history** used git-format-patch mailboxes
  (`git am`) applied onto a release branch; a direct contributor just commits to
  a branch and opens a PR. Either way, one logical change per commit, both
  engines together.

---

## 10. Key files, quick reference

| Path | What |
|---|---|
| `python/src/lazaret/scanner/core.py` | The engine: rules, taint, `scan_project`, `--deps`, received-code detector, cross-file follower |
| `python/src/lazaret/scanner/flow.py` | Interprocedural cross-file taint (Python AST; builds the findings of the JS pass) |
| `python/src/lazaret/scanner/jsparse.py`, `jsflow.py` | The JavaScript / TypeScript reader and the JS cross-file pass (twins: `js/src/lib/jsparse.js`, `js/src/scanner/jsflow.js`) |
| `python/src/lazaret/scanner/frameworks.py` | Which route handler parameters Flask / FastAPI / Django fill from the request (shared by both taint passes; twinned in `js/src/scanner/taint.js`) |
| `python/src/lazaret/scanner/received_spec.json` | **Source of truth** for the received-code detector's data + patterns |
| `python/src/lazaret/scanner/sca_feeds.py` | CVE bundle build (OSV/KEV/EPSS) |
| `python/src/lazaret/{registry,mcp,pg,safexml}/` | Registry auditor, MCP server, Postgres client, safe XML |
| `js/src/lib/received.js` | Twin of the received-code detector |
| `js/src/lib/received-spec.json` | Synced copy of the spec (do not edit by hand) |
| `js/src/lib/hooks.js`, `js/src/scanner/flow.js`, `js/src/index.js` | Install-hook checks, flow twin, npm CLI |
| `python/tests/architecture/test_js_parity*.py` | The engine-parity guards |
| `python/tests/architecture/test_received_spec.py` | Spec drift + core-uses-spec guard |
| `scripts/sync-received-spec.py`, `check-versions.sh`, `tag-release.sh` | Sync, version, release tooling |

To orient in `core.py`, search for the banner comments (e.g. "Code that runs
what it receives over the network", "Cross-file received code (Python engine
only)", "Download to a file, then run the file").

---

## 11. Gotchas and hard-won lessons

- **Parity is sacred.** The most common way to break Lazaret is to change one
  engine and forget the twin. Run a parity suite before you believe a
  received-code or flow change is done.
- **Edit the spec, not the patterns.** A received-code pattern change made
  directly in `core.py` or `received.js` will drift; the drift test will fail,
  or worse, one engine will silently diverge. Author in `received_spec.json`,
  sync.
- **Liberal detection + precise sinks.** The cross-file follower over-approximates
  what counts as a tainted export on purpose; it stays at 0 FP because a finding
  requires the value to actually reach a *runner*. Don't try to make export
  detection "precise" — tighten the sink side if you ever see an FP.
- **`should_stop` accounting is load-bearing.** The MCP server passes a time
  budget as `should_stop`; anything that calls it changes the count and can
  swallow a stop. The cross-file pass runs only after the `--deps` loops (which
  return early on stop), so it must not call `should_stop` itself. (This shipped
  as a bug once; `test_review_dependency_checks` guards it.)
- **Mask strings and comments before reading code.** Real libraries carry
  example calls in docstrings; unmasked, they become phantom exports/findings.
- **Bound before you ship.** A pattern that works on the fixtures can still hang
  on a crafted 50 MB row. The bounded-work tests are not optional.
- **Don't fetch at scan time, don't add a dependency, don't touch the host's
  Unicode tables.** Each breaks a core property (§3).

---

## 12. Current state (0.1.6) and backlog

**Shipped through 0.1.6:** the full received-code arc — the three sink families
(deserialization/CWE-502, dynamic import, download-to-file) plus aliases and
indirect eval; the shared spec for data *and* patterns; the cross-file follower
(Python + npm packages, Python engine, honest gate); and the hardening pass
(docstring/comment masking, class-method exports, dedicated bounds). 0 FP on the
real corpora throughout; full cross-subsystem suite green.

**Backlog** (candidates, not commitments — the detector is already
comprehensive, so weigh marginal value against FP risk):

- *Extend cross-file:* multi-hop (A→B→C, FP-gated); class-method edge forms
  (direct `Client().pull()`, namespace `new ns.C()`).
- *New single-file families:* decoded (base64/hex) payloads executed, staged
  multi-step downloads, env-driven import specifiers.
- *Architecture:* whether to port the cross-file follower to the npm engine (the
  pick-two-of-three tradeoff: npm gets cross-file / PyPI stays pure-stdlib /
  built once).
- *Quality:* an adversarial pass on the cross-file follower (evasion + crafted
  FP), and a durable home for this backlog (a `BACKLOG.md` or issues).

Prefer doing detection extensions **reactively** — when a real-world dropper
uses the pattern — over speculatively. The bar that made this tool good is the
false-positive bar; keep it.
