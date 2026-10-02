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

- **PyPI `lazaret`** — the Python package. Standard library only (its
  scanning engine is the native library every wheel carries). Console
  scripts: `lazaret` (project scan), `lazaret-registry` (package audit),
  `lazaret-mcp` (MCP server), `lazaret-sca` (CVE bundle + SCA).
- **npm `lazaret`** — the Node engine. Zero runtime dependencies, ES modules.
  It is the **project scanner only** (`lazaret <dir>`); registry auditing,
  custom taint specs, SCA and the MCP server are Python-only.

Both packages run one **native engine** written in Rust (`rust/`, no
crates): every wheel of the PyPI package carries it as a library, and the
npm package as WebAssembly. Since the Rust-first refactor it is the only
engine — the Python engine it was ported from, and held to until then, is
retired — and it is held to its own recorded outputs (§2,
`docs/RUST_ENGINE.md`).

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
5. **Behaviour, not names** (0.1.8). A strong finding says what code does —
   data read from the machine and sent, code fetched and run, a shell handed
   to a socket, persistence — not which tool wrote it or which sample it was
   written from. A tool's mark (`_0x` names, the packer), a hook's tokens
   (curl, eval, base64) and lists of services are hints and labels, never a
   verdict on their own; a detection written from one sample is written as
   the behaviour it shows, and the holdout (§7) measures whether it carries
   over.

---

## 2. The prime directive: two engines, one behavior

**The single most important invariant.** Every rule, lexer quirk, taint step,
SQL sink, encoding rule and metric behaves the same in *both* packages, and
they must agree on every input — the same finding (rule, file, line,
severity, message), the same metrics, ratings, quality gate and exit code.
Since 0.1.8 most of that is one engine: the npm package runs the native
engine (below) as WebAssembly for the supply-chain tests, the rules of
`scan_file` and the cross-file follower, and keeps JavaScript twins only for
what the native engine does not answer yet (source decoding, the comment
lexer and the suppression markers, the taint, SQL-sink and function passes,
the flow engine, the manifest, workflow and settings checks, config-file
credentials).

- **Held by tests.** `python/tests/architecture/test_js_parity.py` runs both
  CLIs on every fixture tree, a synthetic project, and an adversarial tree
  generated at test time, and compares the results as a multiset. The
  `test_js_parity_*.py` files compare the remaining twins (the flow engine,
  parsing, the settings and workflow readers, etc.)
  and the CLIs on each area's trees, often by running thousands of cases
  through one Node process and diffing against the Python answer. They need
  the npm engine built (`cd js && npm run build`).
- **When you change a part both packages have, change both in the same
  commit:** the native engine is one (`rust/`: its code, or the rule pack,
  with its reviewed difference in the recorded outputs); where the Python
  package still does the work in Python, change it there and in its
  JavaScript twin. The JS twin of a Python helper says so in a comment
  (`Twin of lazaret.scanner.core…`). Parity failing is not a flaky test; it
  means the packages have diverged and one of them is now wrong.
- **The browser dashboard** (`python/src/lazaret/web/lazaret.html`) carries a
  third port of the engine and is held to the same findings
  (`test_review_dashboard_parity.py`). Editing the dashboard's inline script
  requires re-running `scripts/dashboard_csp.py` (its CSP pins the script by
  SHA-256).
- **The native engine** (`rust/crates/lazaret-engine`, 0.1.8) runs core's
  supply-chain tests — the install-script and import-time tests and
  everything they read — `scan_file` in dependency mode, findings included,
  its rules part in project mode (`scan_rules`) and the cross-file follower
  (`cross_file`), with Python `re` semantics (linre, a linear-time engine
  with `re`'s answers, for every pattern it accepts, and its own port of
  sre for the rest) and its patterns and finding texts in a rule pack
  (`rust/crates/lazaret-engine/rules/lazaret-rules.json`, the source of the
  rules). It was ported from core function for function and held to it by
  differential tests on every field (zero differences) until the Rust-first
  refactor retired the Python engine; now it is the only engine. The Python
  package sends all of them through it (`lazaret.scanner.engine`; in
  project mode core runs the passes that follow the rules), and the npm
  package (0.1.8) runs it as WebAssembly (`js/native/lazaret.wasm`,
  `js/src/lib/native.js`). In both, a file the engine can't finish (a spent
  work budget on hostile input, an error) is SC-TRUNCATED, which fails the
  gate, and a package that spends the follower's budget gives no cross-file
  findings. The engine is held to its recorded outputs
  (`test_snapshot_*.py`, `snapshots/`: the ~44,000-case hooks corpus, the
  scan_file corpus, the follower's generated packages …), and
  `test_wasm_parity*.py` hold the WebAssembly build to the library: zero
  differences allowed. **A change to what it finds is a reviewed
  difference**: made in `rust/` (its code, or the pack), its new outputs
  read case by case (`scripts/snapshot.py diff`) and recorded with it, in
  the same commit (`docs/RUST_ENGINE.md` §5).

### Python-only exceptions: none left

Until the Rust-first refactor's phase 3 one capability ran only in the
Python package: the Python half of the interprocedural flow engine
(`flow.py`'s own AST-based pass, with no JS twin; its `X-*` findings and
`Q-FLOW-*` notes on Python files were excluded from the parity tests). Both
halves are the native engine's now, in both packages (`py_flow` and
`js_flow`; `js/src/scanner/flow.js` builds the npm package's findings from
them, as `flow.py` builds the Python package's), and the parity tests
compare those findings too. (The cross-file received-code follower was the
other exception until 0.1.8 — §5c.)

When the npm package cannot do something the Python package can, it must say so
honestly rather than silently under-report. This is the **honest-gate pattern**:
until phase 3 the npm gate's cross-file condition reported how many Python
files it did not analyze. Any future Python-only feature follows the same
rule — degrade visibly, and list it in `PYTHON_ONLY` (`test_js_parity.py`)
so parity stays green.

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
lazaret.registry.guard  pre-install guard for npm/pnpm/yarn/bun/pip/uv   (lazaret guard, lazaret-guard)
lazaret.registry.pmsettings  the package managers' registries, indexes and credentials (guard)
lazaret.mcp        MCP server                                    (lazaret-mcp)
lazaret.scanner.sca_feeds / CVE bundle + SCA                     (lazaret-sca)
lazaret.pg         Postgres wire-protocol client (stdlib only)
lazaret.safexml    safe XML parsing (stdlib only)
```

The heart is `lazaret.scanner.core` (a large single module), the native
engine ported from it (`rust/`), and the npm package under `js/src/`, which
runs that engine as WebAssembly and twins the rest. The project-scan pipeline is `core.scan_project(root, …)`,
shared by the CLI and the MCP server. In order it:

1. **collects** files and manifests (`_collect`, honouring `--deps`, excludes,
   size caps, binary/pyc/symlink/encoding checks);
2. **scans each file** (`scan_file`) — rules, intra-file taint, SQL sinks,
   obfuscation/secret detection, per its language — and each config or data
   file (`scan_config_file`: `.env`, JSON, YAML, TOML, INI, shell, keys,
   Dockerfiles; `lazaret.scanner.configsecrets` and `js/src/lib/configsecrets.js`)
   for credentials; config files are not code and count in no code metric. Two
   kinds get more (0.1.7): an editor's or AI agent's settings that run commands
   on their own (SC-AUTORUN: `lazaret.scanner.autorun`, a JSON-with-comments
   reader that keeps lines, and what each file makes its tool run; the commands
   are followed into the files of the tree they run, read by `tree_reader`, and
   judged by the install-script test), and GitHub Actions workflows
   (SC-WORKFLOW-*: `lazaret.scanner.ghworkflow`, an outline reader of the YAML a
   workflow needs, not a YAML parser); twins `js/src/lib/autorun.js`,
   `js/src/lib/ghworkflow.js`;
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
live in `lazaret.scanner.frameworks`, which the intra-file engine reads (it
takes a handler's signature from text: `_route_params`, twinned in
`js/src/scanner/taint.js`), and in the flow engine's port of them
(`pyflow/frameworks.rs`, which reads a handler's parameters from the tree);
`test_pyflow_frameworks.py` holds the two to the same answers, so both
passes agree on what a handler receives. Comments
are **lexed, not guessed** — block-comment/string/template state is tracked
across lines, and a line counts as a comment only if all of it is, and only if
both readings of ambiguous text agree.

### b. Interprocedural / cross-file taint (`flow.py` / `flow.js`)

Whole-program analysis that follows untrusted data through function calls and
across files — a source in one module reaching a sink in another (`X-*`
findings name both ends). Python is read into its syntax trees (import
resolution, `self`/`cls`, constructors, a worklist fixpoint composing
`f → g → sink` chains): since the Rust-first refactor's phase 3 by the
engine, in both packages (the `py_parse` and `py_flow` calls,
docs/RUST_ENGINE.md §13 and §17), on Python 3.13's trees, within a work
budget per syntax tree node where flow.py's own pass had a time budget; the
port was held to that pass output for output, then it retired, and
`test_snapshot_py_flow.py` holds the engine's outputs to the recorded ones
(over seeded generated projects among others, `tests/architecture/
pygen.py`). JavaScript and TypeScript are parsed too (0.1.7; since phase 3
by the engine, in both packages: the `js_parse` and `js_flow` calls,
docs/RUST_ENGINE.md §12 and §16): the parser reads
ES2025 with JSX, TypeScript and Flow annotations into ESTree trees with every
node's line (linear: one token at a time, bounded reads ahead, an error past
`MAX_DEPTH` nesting), and the pass follows them with the same model — per-function summaries (parameters → sinks, what the
function returns) to a fixpoint over the call graph callees first, scopes
and a flow-insensitive points-to for functions, modules, classes and object
literals, values followed through locals, closures, containers, callbacks
and exported variables. It is deterministic: no wall clock — a work budget
per syntax tree node, a limit per reading of one function and a re-analysis
cap per function bound it. Until phase 3 it was `jsparse.py` and
`jsflow.py` with npm twins (`js/src/lib/jsparse.js`,
`js/src/scanner/jsflow.js`) held to them node for node and step for step;
the engine's port was held to them output for output, then they retired.
Now `test_snapshot_js_parse.py` and `test_snapshot_js_flow.py` hold the
parser's trees and the pass's outputs to the recorded ones, and
`test_js_parity_flow.py` the two packages' findings to each other (over
seeded generated projects among others, `tests/architecture/jsgen.py`).
Custom taint specs (`--taint-config`, Semgrep-style; the Python package's)
feed both the intra-file and cross-file passes. A repository's own `.lazaret-taint.json` is loaded only with
`--trust-repo-config`, and even then its sanitizers are ignored (a repo could
silence real findings by declaring `str` a sanitizer).

### c. The received-code detector (the recent focus — know this well)

Detects code that **runs, deserializes or dynamically imports a value it
received over the network** — the TrapDoor/dropper shape. Lives in `core.py`
(section comment "Code that runs what it receives over the network") and the
native engine's `received.rs` (the npm package runs it as WebAssembly; its
JavaScript twin, `js/src/lib/received.js`, was retired in 0.1.8).

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
  A network call named in a string literal's text is the literal's own code
  (`_dl_in_code`, 0.1.8): the value bound to the literal is text, read on its
  own where something in it runs; a template literal's or an f-string's
  interpolation is the code around it. (xmlhttprequest's program for `node
  -e`, which saves a response to a file, was "received code" before.)
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
  Python interpreter; and (0.1.8) data read from the machine and followed to
  a send (`core.local_data_sent_at`, below) when it goes to a data-capture
  service or a public IP address, or the whole environment, the instance's
  credentials or a credential store to an exfiltration service; a request
  to a webhook whose secret is written in the code (any service: a
  credential in the URL's path, `core.secret_endpoint_at`), credential files
  sent to a raw public IP address, three or more credential folders named in
  one place (a sweep of
  the home folder), the host name sent to a base64-hidden address or in a
  DNS name the code builds, the public IP address sent to a data-capture
  service (an ngrok tunnel's own address counts as one), a reverse shell as
  an argument list or to an ngrok TCP address, and a miner (a Monero wallet
  address with a mining pool's arguments); and (0.1.8) a DNS name built from
  values outside a template (a sum ending in a literal domain, `%` or
  `.format()`, a name assigned up to `_DNS_ASSIGN_SPAN` characters before the
  lookup, a lookup command run from code; in a shell command, `$(whoami)`,
  backquotes, `$USER`, `%USERNAME%`, `$env:COMPUTERNAME` in the name a
  lookup command resolves; not a reserved domain, `_DNS_LOCAL_TLDS`;
  `core.dns_beacon_at`), and the host name sent to an address the code
  fetches at run time from a literal URL — a dead drop: the fetched value
  followed through assignments, destructuring, `with … as`, `for` loops,
  callbacks, `.then()` chains and returns, `_DD_PASSES` levels, to a POST,
  PUT, PATCH or sendBeacon (`core.dead_drop_at`). An install script that
  does any of it → CRITICAL
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

**The second reading (0.1.8).** When the first reading finds nothing, a text of
up to `_DL_LOGICAL_MAX_CHARS` (1,000,000) characters is read once more as
`_dl_logical` rewrites it: a statement a formatter spread over several rows
joined (a call's arguments on the rows below it, a member chain continued on
the next row, a backslash continuation; `_dl_join_rows`, never through a
function's or a block's body), an environment variable read or written by name
read as one name (`environ.P`, `process.env.P`: it carries a value between
statements), members read by name (`getattr(m, 'x')`, `m['x']` as `m.x`;
the detection round: a `getattr` whose name the file builds of literals
joined with `+` and names given such a value once, `_dl_getattr_names`, and a
runner named through the builtins or the global object, `builtins.exec`,
`globalThis.eval`, as the runner), a
call through a comma expression (`(0, ns.fn)(…)`) as the call, and a code
runner handed to a call as its last argument (`p.then(eval)`,
`res.on('data', eval)`) as the call it makes, `(_v)=>eval(_v)`. Each rewrite
keeps the row count (lines map back through `firsts`). A longer text (a
bundle) is read once: the second reading doubled the benign bundles' time and
found nothing there, and a minified payload is the first reading's long-row
pass.

**The detector's data.** Its name sets, character sets, limits and **all its
patterns** (36 plain regexes + 6 alternation groups: 48 compiled patterns)
are in the rule pack (`_DL_*`), the source of the engine's rules since the
Rust-first refactor; they were authored in
`python/src/lazaret/scanner/received_spec.json` through 0.1.8, which core
loaded and the pack was generated from (and, through 0.1.7, the npm
engine's synced copy, `js/src/lib/received-spec.json`). The engine reads
them from the pack, and `test_snapshot_hooks` and `test_snapshot_signs`
hold its answers on the ~44,000-case hooks corpus. **Edit the pack; then
review the recorded outputs' difference.**

**The cross-file follower (both packages since 0.1.8).**
`core._cross_file_received_issues` and the native engine's port of it
(`cross_file`, `rust/crates/lazaret-engine/src/crossfile.rs`; one call per scan,
each package on its own work budget) catch a value received in one file of a
package and run in another — source and sink split across modules — in Python
and npm packages: a dependency's under `--deps` (both packages; the top-level
modules and packages a distribution's `.dist-info/RECORD` lists together are
one package, `_xf_site_groups` / deps.js `siteGroups`), and a release's
in the registry and the guard (`_ArtifactScan._cross_file_code`: one
distribution is one package; the files SC-USE-RISK reads; not once the package
is SUSPICIOUS).
Design:

1. **Each module is read** for what it defines — functions, values, classes
   and their members (static or not; Python class attributes; JS class
   fields), and object literals (`const api = {…}`, `module.exports = {…}`,
   `export default {…}`) as classes of static members; what it imports — by
   name, as a module, by default, `*`; `importlib.import_module` /
   `__import__` / `import()` of a literal name; `require()` of a path built
   from `__dirname`; TypeScript's and Babel's `__importDefault(require(…))`;
   what it exports — `module.exports` and its objects, `exports.x` and
   `exports['x']`, `export …`, `export … from`, `export * from`,
   `module.exports = require(…)` / `= class …`, TypeScript's
   `Object.defineProperty(exports, …)` getters and `exports.default`; the
   environment variables it sets; and the writes into a module-level name's
   member (`CACHE['c'] = …`) or an instance's own (`self.data = …`), read like
   assignments of them. Comments, strings and docstrings are masked first.
2. **A symbol holds a received value** when what it returns or is assigned
   carries a network source or names a symbol that holds one — resolved
   through imports, re-exports and `self.x` / `this.x`, to a fixed point of
   `_XF_ROUNDS` (16) hops — or when its body receives one and hands it to a
   callback: a parameter it calls, or a Promise's resolve. **A function runs
   its parameter** (a runner) when the single-file detector, reading its body
   with the parameters seeded, finds it run as code; and (the detection
   round) a function that hands a parameter to a runner of the package — a
   relay, in another file or its own (`def go(c): execute(c)`) — is one too:
   each function with parameters is read again with the names that name a
   runner in its module as runners, a round per hop (`_XfPackage.runners`).
3. **Each module is then read** by `_received_code_kind(code,
   extra_always=<the names that hold a received value in it>,
   extra_runners=<the names of other files' runners>)`: a function or value
   imported by name, a module's members (`m.pull`, `pkg._net.pull`), a class's
   static members (`C.pull`, `api.pull`), an instance's (`c = C(); c.pull()`,
   `self.c = C(); self.c.pull()`, `C().pull()` rewritten as one name), and an
   environment variable another file set. Seeds ride `_DlTaint.always`;
   runners are runner aliases without the window (and are handed to calls
   like `eval` is, `p.then(execute)`). It fires only when the flow crosses
   files — a file whose own text shows it is the single-file test's — at the
   single-file severity, and the message says which way: the value is
   received in another file, or the function that runs it is.
4. **An event emitter** (0.1.8): a file that emits a received value
   (`bus.emit('code', data)`, found by reading the file with each
   `x.emit('ev',` rewritten to a runner's call) hands it to the listeners of
   that event in other files on the same emitter — what an import of it
   resolves to, a symbol of the module, or a global every file shares
   (`process`). `this`, a parameter or a local is its own file's, so two
   classes' `this.emit` and `this.on` are two emitters (`_xf_emitter_of`). A
   listener's parameter is seeded, and a listener given by name
   (`bus.on('code', eval)`) is read as a call of it with the value
   (`_xf_emitter_seeds`); an emit or a listener in a comment is not one. At
   most `_XF_EMIT_MAX` emits and listeners a file, read only where the file's
   `.emit(` and `.on(` calls are (`_xf_calls`), and a file's comments only
   where an emit meets a listener: playwright-core's 8 MB of bundles, with
   hundreds of emits on their own objects, take 0.02 s.

Export detection is deliberately *liberal* (an HTTP library's functions fetch
and return data); the sink side keeps it precise. Bounds: `_XF_WINDOW` (25 rows
of a body), `_XF_MAX_FILES` (3,000 per package), `_XF_MAX_SYMBOLS` (5,000),
`_XF_MAX_SEEDS` (64 per file), `_XF_OBJECT_ROWS` (400), `_XF_MAX_RUNNERS` (200
bodies tested), a file over `_XF_MAX_CHARS` (2,000,000) not read for what it
defines; litellm's 2,471 modules (34 MB) take 3.6 s in core and 1.1 s in the
native engine (before the Python engine was retired, the two gave the same
answer on the follower's own cases and a generated stream of 700 packages,
finding for finding). `tests/architecture/test_snapshot_crossfile.py` holds
the engine to its recorded outputs on that stream, and
`test_wasm_parity_crossfile.py` the npm binding to the Python one. What it
doesn't follow: §12.

### d. Supply-chain / `--deps`

Install hooks (`package.json` scripts, `binding.gyp` actions and command
expansions — the Miasma trick) are followed to the files they run, and checked
like the registry does: CRITICAL when the hook's command, read as a program,
or a file it runs sends data read from the machine over the network, pipes a
download into a shell (SC-PIPE-SHELL), runs received code, plants persistence,
or launches an AI coding agent in autonomous mode (SC-AGENT-HIJACK — the
s1ngularity/Nx attack). A package with a
`binding.gyp` and no install script gets the implicit `node-gyp rebuild` hook
(MAJOR). Also: look-alike identifiers (SC-HOMOGLYPH), hidden-Unicode carriers
(SC-HIDDEN-UNICODE), decode-then-execute (SC-EVAL-DECODE, incl. indirect eval).
Every other JavaScript and Python file of a dependency gets the import-time
test, but (the detection round) not a web app's static assets: a JavaScript
file in a `_next`, `static` or `public` directory of its package that none of
its npm package's entry points reach — main, module, bin and exports, then
what they require, import or start with node (`_deps_web_assets`; deps.js
`webAssets`) — is left out of it and of the follower (litellm's proxy UI).

Persistence targets (0.1.7): the install-script test also fails on what makes
an AI agent, an editor or GitHub Actions run something later — writing an
agent's or editor's auto-run settings, a workflow, an editor extension, a
self-hosted runner (`core.persistence_reasons`, applied to a hook's own
command too); at import time only a workflow that dumps every secret counts.
(The worms' Bun loader had a rule of its own until 0.1.8, which follows what
a loader starts instead: below.) In the tree, SC-AUTORUN and
SC-WORKFLOW-* read the planted files themselves (see the pipeline above): the
worm's pair (a SessionStart hook and a folder-open task running its loader) is
CRITICAL because the followed loader fails the install-script test; writing
the agent's own settings is not held against an agent's hook.

0.1.8, both engines (and the dashboard for the per-file rules): SC-SELF-PUBLISH
is three signs in one file — a publish command an exec call runs, an assignment
to an object's `name`, a package.json write whose arguments name that object
(`core.self_publish_at`, `hooks.selfPublishAt`); SC-OFFSCREEN-CODE is code after
a run of 150+ blanks that stands in code (`core._code_prefix` closes every quote
and comment before it; the caller drops lines that are only literals and
comments) and reads as code (`core.offscreen_code`). Its blank-run pattern
starts only at a run's start (`(?<![ \t])`): unanchored, 200,000 spaces with no
code after them were quadratic in both engines. The install-script test gained
three reasons: `npm publish`, npm tokens collected, a DLL of the package's own
run with rundll32 / regsvr32 (`core.runs_dll`, which reads the text again with
adjacent string literals joined).

Also 0.1.8, both engines: programs set to start at login or boot are a reason
of the install-script test only (`core.service_reasons`, from
`persistence_reasons`): a systemd unit written (a unit directory and a file
write, with `ExecStart=` in the text or the write on the directory's line) or
`systemctl enable` run, a launchd plist written or `launchctl load` run, a
crontab installed (`crontab file`, a pipe into `crontab -`, python-crontab's
`write()`, a file written under `/etc/cron.d` …), a Run key written (a
registry write — `reg add`, `Set-ItemProperty`, `SetValueEx` … — within
`_SVC_RUNKEY_SPAN` code points of the key's path), a scheduled task
(`schtasks /create` run, `Register-ScheduledTask`, the Schedule.Service COM
object's `RegisterTaskDefinition`), the Startup folder or an XDG autostart
entry written. A line over `_SVC_LINE_MAX` characters (minified code) is not
read as one statement, so a bundle that names a unit directory in one place
and writes a file in another is not one; at import time a library that
manages services is normal, and shell rc files are left out (too many
installers append a PATH line). The self-read
test reads a file back asynchronously too: a `readFile` callback's data, a
`.then()` parameter within `_SELF_READ_THEN_SPAN` of the read, Python's
`with open(p) as f`, when the path names the file itself or a data file next
to it and what was read reaches a code runner. And the decoded view learns a
file's own XOR decoder (`_dv_xor_decoders`): a name called at least
`_DV_XOR_MIN_CALLS` times with base64 or hex literals, whose calls become
printable ASCII (nine in ten) when XORed with one of the file's short string
literals, repeated; the helper's body is never read, and 32 bytes make a false
decoder a chance in 10^13.

**Read as behaviour (0.1.8).** The last round of 0.1.8 audited every strong
detector for whether it names what code does or recognizes the samples it was
written from (goal 5), and replaced the second kind with four readings, in
all three engines:

1. *A hook's command is a program* (`core.hook_command_risk`): the
   install-script test on the command, on the code it hands an interpreter
   inline (`node -e`, `python -c`, `sh -c`, `eval`, `cmd /c`;
   `_SH_MAX_DEPTH` levels), and on its network commands as `_sh_parse` reads
   them (a small shell parser: quotes, escapes, `$(…)` and backquotes, pipes,
   redirections, `&&` `||` `;` `&`, `if` / `while` / `!` in front): a file
   uploaded, what a command reporting on the machine prints, a variable
   naming the user or the host or holding a secret (`_SH_DATA_REASONS`), and
   a beacon (`_SH_BEACON_REASON`: a request whose answer is thrown away, a
   lookup; not one whose exit status decides what runs next).
   `INSTALL_HOOK_RE`'s tokens only hint in the MAJOR finding. The command
   lines a script hands a shell are read the same way
   (`exec_command_reasons`, `_exec_command_lines`).
2. *Exfiltration is a flow* (`core.local_data_sent_at`; Rust `flow.rs`):
   local data (`_ld_sources`) followed through the names given it,
   `_DD_PASSES` levels, to a send; the path a read is given and a child
   process's options are sealed, a value only tested (`_ld_tested`) and a
   callback handed to a request (`_ld_arg_spans` skips function values) are
   not data. The service lists (`_EXFIL_SERVICE_RE`, `capture_service`)
   only label the destination (`_label_sends`) — at import time they and a
   public IP address grade the flow (`_import_time_risk`). Gone with it:
   `_import_harvest_at`, `env_copy_serialized_at`, `sends_host_info` and
   `chat_secret_at` (a webhook's secret is now any service's,
   `secret_endpoint_at`).
3. *The decoded view reads what obfuscators build*: javascript-obfuscator's
   string arrays (`_dv_string_arrays`; Rust `strarr.rs`), the proxy objects
   of its control-flow flattening (`_dv_proxies`) and a file's own
   character-code decoder (`_dv_char_codes`), all without running anything
   and bounded (`_SA_*`, `_PX_*`, `_DV_CC_*`). A string array is read only
   when the rotation reproduces its checksum loop's target, in JavaScript's
   double arithmetic — the guard against a false decoding; rows are kept, so
   a reason found there names a line of the file.
4. *What a script starts is followed* (`spawned_scripts`): node and python,
   the other JavaScript runtimes in a hook (`_JS_RUNTIMES`), any program a
   variable names when it is given a file of code (`_SPAWN_SCRIPT_EXT_RE`, at
   most `_SPAWN_MAX_NAMED` a file), from an ES module's or pathlib's
   directory, and in the decoded view. The registry asks the native engine
   (`engine.spawned_scripts`): an 11.7 MB obfuscated payload's decoded view
   takes about 3 s there and 20 s in Python.

What it replaced: the Bun loader rule; browser shortcuts (now any program's
shortcuts rewritten); SC-EVAL-DECODER's one inline letter shift (now any
function computing code from a long literal); `_0x` names and the packer as
verdicts (MAJOR). The holdout (§7) measures what carried over.

**The detection round (0.1.8).** What the behaviour pass left at WARN or did
not connect, read further, in both engines: the data flow follows a spread
name, a function's own return (`_ld_func_end`: the innermost body that holds
it), a receiver's method and the `.then()` after a call of a function that
returns data, callbacks, constructors (`_LD_CONSTRUCTORS`), threads, merges,
destructured loops and tuples, the machine's modules and HTTP clients under
the script's own names (`_LD_ALIAS_*`, `_LD_CLIENT_*`), and command runners,
`%APPDATA%` files, databases and copies as sources; a parameter holds data
only in its function (scopes), and in a text over `_LD_LONG` a name only
`_LD_NEAR` characters from where it was given it. A wallet swap is a behaviour
(`wallet_swap_at`: wallet patterns of two kinds, the clipboard or the page's
requests intercepted, an address in the code). The decoded view reads
literals written wholly in escapes (`_dv_unescape`; in JavaScript and Python,
since the Rust-first refactor's phase 2, any literal holding a code escape,
and the literals the runtime joins: RUST_ENGINE.md §15) and a proxy name reused
per function (`_dv_proxies`' position lookup), and code built around a
string array the view reads is a sign of its own (`string_array_line`,
`_SA_TECHNIQUE_REASON`: CRITICAL at install, a strong import-time reason) —
the technique, whatever the tool's names. It won back 41 of the holdout's
56 lost verdicts (§12).

### e. Registry auditing (`lazaret.registry`) and SCA

`lazaret-registry` fetches and audits an npm/PyPI artifact with the same rule
pack, discovering install hooks and start-up files and running the import-time
checks. `lazaret-sca --update-bundle` builds a CVE bundle from public feeds
(OSV, CISA KEV, EPSS) parsed with `lazaret.safexml`; Lazaret ships no
vulnerability database of its own. The registry always redacts what it stores.

Python-only registry checks (0.1.8): SC-USE-RISK runs the import-time test on
the files no entry point loads (`_ArtifactScan._use_time_code`) and keeps only
its CRITICAL shapes — skipping tests, examples, docs, demos, benchmarks and a
web app's static assets (USE_RISK_SKIP_DIRS), not reading once the archive is
SUSPICIOUS, smallest files first within USE_RISK_SECONDS. What it doesn't reach
is not SC-TRUNCATED: the file rules read every file. The cross-file follower
reads the same files as one package (`_cross_file_code`, §5c; its SC-IMPORT-RISK
names the file), and scripts that install scripts and import-time code start
with node or python are followed to the package file each runs
(`_started_scripts`, `core.spawned_scripts`) and tested like the one that
started them. SC-NEW-DEPENDENCY
(`new_dependency_issues`, called by `scan_package`) compares a release's
dependencies with the release published before it and looks up the added
ones' first publication: live registry data, best effort, no request for a
release without dependencies; one the package's own people publish does not
count (npm's maintainers; PyPI's owners, maintainers and organization, from
the JSON API's `ownership`). The guard scans each package with
`_scan_artifact`, so it gets SC-USE-RISK and the follower but not the dependency history (it
already scans the new dependency itself, and holds back a release younger
than --min-age).

### f. The install guard (`lazaret.registry.guard`, 0.1.7)

`lazaret guard <tool> <command>` runs the registry auditor's in-memory scan
(`repo._scan_artifact`, same verdicts) on what a package manager is about to
install, and stops the install when anything is SUSPICIOUS, can't be checked,
or is younger than `--min-age`. `lazaret._cli` sends `lazaret guard …` there
(a package manager after `guard`, or only options when no path named `guard`
exists) and everything else to the scanner; it sits above the layers.

Two strategies, by what the tool offers:

- **Lock, check, install** (npm, pnpm, yarn, Bun, uv projects). The tool
  resolves to a lockfile without installing (`--package-lock-only`,
  `--lockfile-only`, yarn 2+'s `--mode=update-lockfile`, bun's
  `--lockfile-only`, `uv add --no-sync`, `uv lock`; scripts off). yarn 1 has
  no such mode: it resolves and installs in a temporary copy of the project
  (its package.json files, yarn.lock, .npmrc and .yarnrc) with
  `--ignore-scripts`, and what that copy installed, read off its
  node_modules, is what gets checked (so yarn 1's lack of os/cpu fields in
  yarn.lock doesn't matter). What the lockfile adds on this machine — minus
  what is installed (npm's and pnpm's hidden lockfiles, node_modules for yarn
  and Bun, the venv's `.dist-info`), minus other platforms (npm-install-checks'
  os/cpu/libc rules, as `node` reports the machine; yarn 2+'s `conditions`) —
  is fetched from the URL the tool will use (the `resolved` URL after npm's
  replace-registry-host rule, a scoped registry from the tool's settings,
  yarn 2+'s `__archiveUrl`) and **verified against the lockfile's digest**:
  the tool accepts only those bytes, so a verdict on them is a verdict on what
  gets installed, and a cached verdict can be reused without a download. yarn
  2+ pins the checksum of the zip it makes of a tarball, not the tarball's, so
  there the tarball is checked against the digest the registry publishes
  (the version document's `dist.integrity`) and the verdict is cached under
  both. Blocked: the files the resolution touched are restored from a
  snapshot (also on Ctrl-C or a crash), and what yarn 2+ fetched into the
  project's `.yarn/` is removed. Not blocked: the user's command runs
  unchanged (for `uv sync` minus `--upgrade`, already in the lockfile), then
  the installed set is diffed against what was checked or noted (for yarn 2+
  and Bun, the final lockfile), and anything else fails the run.
- **A local index** (pip, uv pip, uvx / uv tool, what uv run adds). There is
  no lockfile to read first, so the tool is pointed at an HTTP server on
  127.0.0.1 (`PIP_INDEX_URL`; uv's `UV_INDEX`, its first index, and
  `UV_DEFAULT_INDEX`) that relays the indexes the tool is set to use
  (`pmsettings`: pip's index-url and extra-index-url, merged as pip does;
  uv's from its environment and settings files, the first that has a
  project, as uv does; the command line's; LAZARET_GUARD_PYPI_URL instead of
  the settings), from their JSON pages or PEP 503 HTML ones: pages are
  rewritten to serve files by number, files younger than the cutoff are
  dropped from them, and a file is fetched, hash-checked against the page,
  scanned and spooled before it is served (403 when blocked). A project no
  relayed index has gets an empty page, not a 404, so uv never goes on to an
  index in its settings files by itself (0.1.7 set only `UV_DEFAULT_INDEX`,
  uv's last, so such an index came first and uv fetched from it unscanned).
  Since sdists are built during resolution, this is what keeps a malicious
  `setup.py` from running at all. The plan is scanned first so the report
  comes before any install: pip's `--dry-run --report`, uv pip's `--dry-run`
  (a planned package the index didn't serve blocks), uvx's requirements
  compiled through the index (`uv pip compile`). `uv run` in a project is
  guarded as `uv sync` is, then runs with `--frozen` through the index.

Registries that need credentials (0.1.8, `lazaret.registry.pmsettings`):
each tool's settings are read the way it reads them — npm's `config list`
(which leaves credentials out) over its .npmrc files and environment, pnpm's
and yarn 1's `config list --json`, yarn 2+'s `config get … --no-redacted`,
Bun's bunfig.toml and .npmrc; pip's `config list` and environment, uv's
environment and settings files, `UV_INDEX_<NAME>_USERNAME`, an index URL's
`user:password@`, `.netrc` — into `Credentials`, headers by host and path:
npm's keys cover their path and what is under it (the longest match wins, as
npm-registry-fetch walks a URL's path up), a Python index's its whole host.
The fetcher adds a request's own header as an unredirected one, so urllib
does not carry it over a redirect, and gives the redirected request the
header of where it leads, if any; nothing goes over plain http to another
machine; URLs are shown without their `user:password@`, and a 401 or 403
says whether credentials were missing or withheld. The tool itself talks to
127.0.0.1 without any.

Age: npm, pnpm, yarn 2+ and Bun are given the cutoff themselves
(`npm_config_before`, `npm_config_minimum_release_age`,
`YARN_NPM_MINIMAL_AGE_GATE`, `--minimum-release-age`) so they resolve to older
releases instead of failing. npm always gets a `before` — the run's start time
when there is no cutoff — which closes the window between the check and the
install. What a lockfile already pins is aged by the guard: the tarball's
`Last-Modified` (a registry sets it when the version is published), confirmed
against the packument's `time` only when it looks recent; uv.lock's
`upload-time`, else PyPI's JSON API. An index whose HTML pages give no upload
times can't be held back (the report says so).

Failure is closed: a package that can't be fetched, verified or scanned
blocks (a scan crash is a `ScanError`, never a verdict); only a file over the
200 MiB download cap is INCOMPLETE. The cache (`VerdictCache`) keys verdicts by
ecosystem, name, version and digest and is discarded when `ENGINE_VERSION`
changes. Scans run in `spawn` worker processes (`--jobs`), downloads in
threads; a stuck worker is terminated at exit.

---

## 6. How to add or change a rule — the loop

This is the working method. Follow it; it is why the tool has stayed trustworthy.

1. **Research first.** Understand the real attack/incident and how real code
   uses the same syntax benignly. The second half decides the false-positive
   risk.
2. **Write an inert fixture** that reproduces the miss (hosts `.invalid`,
   nothing executed) and **confirm the current engine misses it.** A test that
   never failed on the old code proves nothing.
3. **Implement it in the native engine** (`rust/`: its code, or the rule
   pack `rules/lazaret-rules.json`, the source of the rules). Keep it
   needle-gated and bounded. The npm package runs the same engine, so it
   follows; where the npm package still has a JavaScript twin of what
   changed (the taint, SQL and flow passes, the manifest and settings
   checks), twin it there too and mark it (`Twin of lazaret.scanner.core…`).
   Where the Python package still does the work in Python (project mode's
   passes, the manifest and workflow checks), change it there.
4. **Review its difference in the recorded outputs**: record the affected
   sets before and after (`scripts/snapshot.py record <set> --out …`), read
   every case that moved (`scripts/snapshot.py diff`), and record the new
   outputs (`LAZARET_SNAPSHOT_UPDATE=1`) in the same commit; bump the
   registry's `ENGINE_VERSION` (and the pack's `rule_set`) when what a
   verdict records changes.
5. **Verify:**
   - the behavioral suites (both packages; `cd js && npm run build` first);
   - **the recorded outputs** — `test_snapshot_*` with the native library
     built, `test_wasm_parity*` with the WebAssembly build
     (`docs/RUST_ENGINE.md` §5), and `test_js_parity*` (the two CLIs and
     the remaining twins); a Python-only feature goes in `_python_only`;
   - **the false-positive sweep** against the real corpora (§7): the bar is 0
     new findings;
   - **the benchmark** against the recorded baseline (attribution, and the
     holdout's aggregates only);
   - **bounded work** on an adversarial ~100 KB–1 MB input.
6. **Update docs** (`README.md` capabilities, `STRUCTURE.md`/this doc if the
   architecture moved, `CHANGELOG.md`).
7. **Commit** (see §9) and deliver.

If a check can't be made green honestly, the change isn't ready. Don't loosen a
parity or FP test to pass, or record outputs you have not read — that
discards the property it protects.

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
    shapes actually appear; and since 0.1.8's rework, the benchmark's 429
    popular packages (35,758 files read as `--deps` groups them, and each
    release as the registry reads it): no finding.
  These sweeps run the detector directly over file lists / package trees (see
  the scratch tooling used during development; reconstruct equivalents against
  whatever real `site-packages` / `node_modules` are available). Treat any new
  hit as a candidate FP to explain, not a win.
- **The malware benchmark, in-sample and held out.** The 516 malicious
  releases and 429 popular packages of the benchmark were read while the
  detectors were written, so their numbers are in-sample. 0.1.8 added a
  holdout: 747 other malicious releases of the same dataset, sampled with
  another seed, each marked when one of its code files is byte-identical to a
  benchmark sample's (a campaign sibling). Only its aggregate numbers are
  looked at — never a sample's files or the list of its misses — so it
  measures what carries over to releases no detector was written from.
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

Time is a bound too: the registry and the guard scan every file of a release.
0.1.8's readings are gated so a bundle doesn't pay for them twice — a decoded
view counts only when something was decoded (literals joined alone are no
second reading: a bundle joins them everywhere), the second reading stops at
1 MB (§5c), the row joiner skips rows that can open nothing, the
download-to-file tests look for sources only around a write, and the
follower's parse searches from quote to quote and reads a local only when a
return reaches it. Measure a change on the benchmark's heaviest packages
(litellm, playwright-core, next) against the previous release, not on a
fixture.

---

## 9. Versioning, release and delivery

- **One version, kept in sync:** `__version__` in
  `python/src/lazaret/__init__.py`, `"version"` in `js/package.json`, and the
  native engine's workspace version in `rust/Cargo.toml` (with its two
  `rust/Cargo.lock` entries). `scripts/check-versions.sh` fails if they
  disagree (and, at a tag, if they don't match the tag). Pre-1.0; the 0.x API
  may still change.
- **Release** (`docs/RELEASING.md`): bump the versions in one commit, get it
  onto `main`, `scripts/tag-release.sh vX.Y.Z` (it refuses uncommitted changes,
  a HEAD not on `origin/main`, mismatched versions, or an existing tag), then
  push the tag. The GitHub Actions workflow runs the suite, then publishes to
  PyPI and npm via **trusted publishing (OIDC)** — no long-lived tokens. The
  PyPI release has an sdist (with the engine's sources) and five platform
  wheels with the engine, built, checked and installed on their platforms
  by `wheels.yml` (no pure wheel: pip compiles the sdist elsewhere);
  the npm package carries the same engine as WebAssembly, built by
  `release.yml` with the same pinned compiler.
  Published versions are immutable; a mistake means releasing the next patch,
  not re-tagging.
- **CHANGELOG.md** started at 0.1.6 (Keep a Changelog). Date each entry at
  release.
- **What ships** is narrow: the wheel/sdist contain only `src/lazaret/` and
  their license files, `LICENSE` and `LICENSE-UNICODE` (the Unicode 13.0
  table and the dashboard's codec table are Unicode data: `Apache-2.0 AND
  Unicode-3.0`); a platform wheel adds the native library and two more,
  `rust/LICENSE-PYTHON` and `rust/NOTICE` (part of the engine is a Rust
  translation of CPython code: `Apache-2.0 AND Python-2.0.1 AND
  Unicode-3.0`); the npm package only `bin/`, `src/`, the engine
  (`native/lazaret.wasm` and its `native/NOTICE`, `rust/NOTICE`) and its
  license files (`LICENSE-PYTHON` and `NOTICE` for the engine's translations
  of CPython code, `LICENSE-UNICODE`: `Apache-2.0 AND Python-2.0.1 AND
  Unicode-3.0`).
  `tests/architecture/test_notices.py` and `test_rust_notices.py` hold the
  notices to the code. `scripts/make_bundle.py` builds a reproducible
  source tarball from tracked files only and refuses credential files.
- **Delivery in this project's history** used git-format-patch mailboxes
  (`git am`) applied onto a release branch; a direct contributor just commits to
  a branch and opens a PR. Either way, one logical change per commit, the
  engines together.

---

## 10. Key files, quick reference

| Path | What |
|---|---|
| `python/src/lazaret/scanner/core.py` | The engine: rules, taint, `scan_project`, `--deps`, received-code detector, cross-file follower |
| `python/src/lazaret/scanner/flow.py` | Interprocedural cross-file taint: hands the engine's passes the files and the configured model, builds their findings (Python's own AST pass until phase 3) |
| `rust/crates/lazaret-engine/src/jsparse/`, `jsflow/` | The JavaScript / TypeScript reader and the JS cross-file pass (the `js_parse` and `js_flow` calls, both packages'; jsparse.py, jsflow.py and their npm twins until phase 3) |
| `rust/crates/lazaret-engine/src/pyparse/`, `pyflow/` | The Python reader (Python 3.13's trees) and the Python cross-file pass (the `py_parse` and `py_flow` calls, both packages'; flow.py's own pass until phase 3) |
| `python/src/lazaret/scanner/autorun.py`, `ghworkflow.py` | Editor and AI-agent settings that run commands (SC-AUTORUN) and the workflows the Shai-Hulud worms planted (SC-WORKFLOW-*); twins `js/src/lib/autorun.js`, `ghworkflow.js` |
| `python/src/lazaret/scanner/frameworks.py` | Which route handler parameters Flask / FastAPI / Django fill from the request (shared by both taint passes; twinned in `js/src/scanner/taint.js`) |
| `python/src/lazaret/scanner/sca_feeds.py` | CVE bundle build (OSV/KEV/EPSS) |
| `python/src/lazaret/{registry,mcp,pg,safexml}/` | Registry auditor, MCP server, Postgres client, safe XML |
| `python/src/lazaret/registry/guard.py`, `python/src/lazaret/_cli.py` | The install guard (`lazaret guard`) and the `lazaret` command's dispatch |
| `python/src/lazaret/registry/pmsettings.py` | The package managers' own settings as the guard reads them: registries, indexes, credentials by host |
| `js/src/lib/native.js`, `js/scripts/build-wasm.js` | The npm package's native engine (WebAssembly: the loader, one call, the pack's values) and its build (`npm run build`) |
| `js/src/lib/supplychain.js`, `js/src/deps.js`, `js/src/scanner/flow.js`, `js/src/index.js`, `js/src/pool.js` | Install-hook checks, `--deps`, flow twin, npm CLI, its worker threads |
| `python/tests/architecture/test_js_parity*.py` | The package-parity guards (need `npm run build`) |
| `rust/crates/lazaret-engine`, `lazaret-ffi` | The native engine (supply-chain tests, `scan_file`, the cross-file follower, sre port, the rule pack: **the source of the rules**), its C ABI and its WebAssembly exports (`docs/RUST_ENGINE.md`) |
| `python/src/lazaret/scanner/engine.py`, `_native.py` | The engine's calls: batching and threads, the work budget, an unanswered file SC-TRUNCATED; the ctypes loader |
| `python/tests/architecture/test_snapshot_*.py`, `snapshots/`, `_snapshots.py`, `scripts/snapshot.py`, `test_wasm_parity*.py`, `hooks_corpus.py`, `scanfile_corpus.py`, `crossfile_corpus.py` | The engine's recorded outputs (and the tool that records and compares them), the WebAssembly build's parity, and their corpora |
| `scripts/make_rust_tables.py`, `check_rust_deps.py` | The rule pack's canonical form and checks (`--check`); no crate from outside the workspace |
| `scripts/check-versions.sh`, `tag-release.sh` | Version and release tooling |

To orient in `core.py`, search for the banner comments (e.g. "Code that runs
what it receives over the network", "Cross-file received code", "Download to
a file, then run the file").

---

## 11. Gotchas and hard-won lessons

- **Parity is sacred where twins remain.** The npm package's JavaScript
  twins (the taint, SQL and flow passes, the manifest and settings checks)
  and the dashboard must change with the Python package: run the parity
  suites before you believe a flow change is done.
- **Read every recorded difference.** A snapshot test fails on any change to
  what the engine answers; re-recording without reading the cases it moved
  (`scripts/snapshot.py diff`) throws away the only check left that the
  change does what it says.
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

## 12. Current state (0.1.8) and backlog

**In 0.1.8, its last round: detection and data flow.** What the behaviour
pass (below) left at WARN or did not connect, read further (§5d, "The
detection round"): the data flow's shapes and sources, scoped names, a
wallet swap as a behaviour, literals written in escapes and reused proxy
names in the decoded view, code built around a string array as a sign of
its own, the cross-file follower's known misses (relays, 16 hops, `getattr`
names a file builds, a distribution's top-level modules), a web app's static
assets out of `--deps`'s import-time test, and PyPI's owners for
SC-NEW-DEPENDENCY. On the benchmark (in-sample) 86% of the 516 malicious
releases are SUSPICIOUS (83% before the round), 85% on a behaviour or a
technique (82%); on the holdout 84% (78%), 83% on such evidence (77%), 98.6%
of its SUSPICIOUS verdicts. 41 of the 56 holdout verdicts the behaviour pass
lost are back — the 38 `_0x` ones on the string-array technique, 3 on a
host name the flow now follows to its send — and 13 of the benchmark's 19;
none was lost. On the holdout's 499 releases that share no code with the
benchmark, 77% (0.1.7 74%), 76% on behaviour or a technique (55%). The same 3
of 429 popular packages; no benign answer of the received-code test changed
on about 32,600 files, and the string-array technique is in none of the
~60,000 files of popular packages read for it.

**Before that in 0.1.8: behaviour, not names.** An audit of every strong
detector — does it name what code does, or recognize the samples it was
written from? — found 94 of the benchmark's 448 catches resting only on a
hook's tokens, lists of services, javascript-obfuscator's `_0x` names or
rules fitted to one campaign. Four readings replaced them (§5d, "Read as
behaviour"): a hook's command read as a program, exfiltration read as a data
flow, the decoded view of string arrays, proxy objects and character-code
decoders, and what a script starts followed whatever the runtime; and a
program written in a string literal stopped counting as received code
(xmlhttprequest and xmlhttprequest-ssl were SUSPICIOUS, so the guard
blocked socket.io's client). On the benchmark (in-sample) 83% of the 516
malicious releases are SUSPICIOUS (87% before the round), 82% on evidence of
a behaviour or a generic technique (69%). On the holdout (§7: 747 releases
no detector was written from), 78% (85% before), 77% on such evidence (66%):
98.5% of its SUSPICIOUS verdicts now say what the code does, against 78%.
The verdicts it lost rested on `_0x` names (38 of the 56), lists (11) or a
hook's tokens (4), and 6 on a host name near a network call that the data
flow does not connect. 0.1.7 catches 70% of the holdout; on its 499
releases that share no code with the benchmark, 0.1.7 74%, 0.1.8 72% (79%
before the round): 0.1.8's gain there is on campaign siblings of the
benchmark's samples, and on new campaigns it trades strict verdicts that
rested on names for verdicts that say what the code does (70% of the 499 on
behaviour, against 55%). The same 3 of 429 popular packages.

**Earlier in 0.1.8:** the native engine scans each dependency file itself
(registry, guard and `--deps` scans: the benchmark's 945 registry scans in
306 s, against 853 s when it answered only the install-script and
import-time tests); the exfiltration shapes the rounds below still missed —
a DNS name built from values outside a template, in code and in the name a
lookup command resolves, and the machine's name sent to an address fetched
at run time (a dead drop) — with the host name read through `require('os')`
or `from socket import gethostname` counting as reading it; the cross-file
follower through event emitters; the guard for yarn (1 and 2+), Bun,
`uvx`, `uv tool` and `uv run`, and for private registries and indexes, each
credential kept to its host (and uv no longer fetches around the guard from
an index in its settings); and the notices the npm package's shlex port
(PSF) and the Unicode data tables need. On the benchmark one more malicious
release was SUSPICIOUS (87% of 516), no popular package's verdict changed,
and no benign file's answer changed on every source file of the 945
releases and 29,629 installed files.

**Before that in 0.1.8** (from the 0.1.7 benchmark's misses, backlog items 1-11):
SC-SELF-PUBLISH (code that renames its package and publishes it: the registry
floods); install scripts that publish, collect npm tokens or run a DLL;
SC-OFFSCREEN-CODE (code after 150+ blanks on a line); SC-USE-RISK (the strong
import-time shapes in the files a package runs when used; registry, 3 s per
archive); SC-NEW-DEPENDENCY (a release that adds a dependency published days
before it, from another account; registry, live data); names and code in
strings a file decodes as it runs (a second reading of the install-script and
import-time tests) and SC-EVAL-DECODER; `Function.constructor`, statements
over several rows, environment variables, members read by name and runners
handed to a call in the received-code detector; a script downloaded or
decoded, written and run with an interpreter; scripts a script starts with
node or python, followed; and the cross-file follower — several hops, class
members and object literals, callbacks, caches, dynamic imports, environment
variables between files, another file's runner — in both engines and in
registry and guard scans, after an adversarial pass. On the same benchmark:
80% of 516 malicious releases SUSPICIOUS (66% in 0.1.7, 76% after items 1-4),
84% with the dependency history, and the same 3 of 429 popular packages, no
verdict changed. Then, from the releases GuardDog caught and Lazaret didn't:
a chat bot or webhook whose secret is in the code, credential files sent to
an IP address, a sweep of credential folders, the host name hidden in base64
or sent in a DNS name, the public IP address sent to a capture service, a
copy of the environment serialized, a reverse shell as an argument list, a
miner, curl or wget downloads run with Python, and at install time a raw
socket to a hard-coded address and rewritten browser shortcuts. On the
re-prepared benchmark (each PyPI sample read from its release's own files):
86% SUSPICIOUS (82% before this round, 68% in 0.1.7; GuardDog 71%), 89% with
the dependency history, the same 3 popular packages. Then the backlog's last
four items: programs set to start at login or boot, in install scripts; code
run from what a file reads back asynchronously; a file's own XOR decoder, in
the decoded view; and SC-TYPOSQUAT, a release's name or a dependency's one
change from one of the 5,000 most-downloaded packages of its registry. 87%
SUSPICIOUS, 90% with the dependency history, every release GuardDog catches,
and the same 3 popular packages. And the native engine (Rust, no crates,
`docs/RUST_ENGINE.md`) answers the supply-chain tests where it is installed,
with the Python engine's answers (and, since the Rust-first refactor, in
its place).

**Shipped in 0.1.7** (the September 2026 audit's P0s, and more): config and
data files checked for credentials; taint through f-strings and template
literals, Flask / Django / FastAPI / Express route models, containers and
allowlists; the JavaScript and TypeScript cross-file pass on a real parser;
PyPI install-script blind spots closed and strong import-time signals made
SUSPICIOUS; SC-AUTORUN and SC-WORKFLOW-* for the persistence the 2025-26 npm
worms used; uv.lock, pylock.toml and bun.lock in SCA; budgeted feed
decompression and MCP roots by default; and `lazaret guard`. On the audit's
benchmark: 66% of 516 real malicious releases SUSPICIOUS (was 45%) with the
same 0.7% of 429 popular packages; 95% of planted secrets (was 19%);
OWASP BenchmarkPython +0.22 (was +0.10); SCA 100% on eight lockfile formats.

**Shipped through 0.1.6:** the full received-code arc — the three sink families
(deserialization/CWE-502, dynamic import, download-to-file) plus aliases and
indirect eval; the shared spec for data *and* patterns; the cross-file follower
(Python + npm packages, Python engine, honest gate); and the hardening pass
(docstring/comment masking, class-method exports, dedicated bounds). 0 FP on the
real corpora throughout; full cross-subsystem suite green.

**Backlog** (candidates, not commitments — the detector is already
comprehensive, so weigh marginal value against FP risk):

- *Detection, from the 0.1.7 benchmark's misses* (all built in 0.1.8,
  above); what is left:
  - **What the exfiltration shapes don't read** (the benchmark's remaining
    misses, after the DNS names built from values and the dead drops):
    a load-testing flood (poppo213) and a wheel with no code at all
    (lightgboost). (@fnos/app's runner is read since the character-code
    decoder: decoded, it sends the machine's host name over the network.)
  - **Members read through constants**: react-zutils 1.0.1's stealer, once
    its XOR strings are decoded, calls everything through names its comma
    declarations give strings (`R='copyFile'` … `p[R](a, l)`, `U[f](l)` for
    `new sqlite3.Database(l)`), and the same short names hold other strings
    in other functions; the flow cannot follow what it reads. It and
    cycalculator-ye51 (an oastify.com address) rested on a list of services,
    now a label: WARN since the behaviour pass. Read a constant member by the
    declaration that last gave its name a string before it (as proxy objects
    are), then let the flow follow.
  - **Padding past the window**: in a text over `_LD_LONG` the flow
    follows a name only `_LD_NEAR` characters from where it was given data,
    and reads only `_DD_MAX_ASSIGNS` assignments, so a script padded past
    either parts its read from its send. Following a name the text gives a
    value in one place only was tried in the detection round and left out:
    the quote-pairing reader misreads a nested template literal (`${ …
    `inner` … }`), and in tailwindcss's bundle the words of 1.1 MB of
    strings then carried data across the file. The engine's lexer and
    scope resolution, under way, replace both the window and the reader.
- *What the holdout shows* (0.1.8's behaviour pass and detection round; read
  its aggregates only, §7): 15 of the 56 verdicts the behaviour pass lost are
  still WARN (10) or OK (5): 3 rested on a host name read near a network call
  that the flow still does not connect, 12 on a list of services or a hook's
  tokens. Look for such shapes on the benchmark's own files, never on the
  holdout's samples.
- *What the cross-file follower doesn't follow* (the adversarial pass's known
  misses, kept as tests; the event emitter, relays, 16 hops, `getattr` names
  a file builds and a distribution's modules were built in 0.1.8): a name
  built at run time from data (`getattr(m, name)` with `name` read or
  computed), and top-level modules of site-packages no RECORD lists together
  (they may be two distributions; a registry scan reads a release's as one).
- *Engine:* the native engine answers the supply-chain tests (0.1.8,
  `docs/RUST_ENGINE.md`), the dependency-mode scan of each file, the rules
  part of the project-mode scan and the cross-file follower in both
  packages; release CI builds it into five platform wheels, and the npm
  package runs it as WebAssembly (its JavaScript twins of those retired) on
  worker threads for a large scan. Next: the project-mode passes that
  follow the rules (SQL, taint, function metrics) in the engine, the rest
  of the npm package's twins (the manifest, workflow and settings checks),
  and `core.py` loading the rule pack so it has one source.
- *Quality:* a durable home for this backlog (a `BACKLOG.md` or issues).
- *Guard* (credentials, yarn, Bun, `uv run` and `uvx` were built in 0.1.8):
  `npx` / `npm exec`, `pnpm dlx`, `yarn dlx` and `bunx`, which run a package
  as `uvx` does; a registry that needs a client certificate (npm's
  `certfile` / `keyfile`) or credentials from a keyring (pip's and uv's
  keyring providers); an `extra-index-url` in pip's own configuration files,
  which pip still reads itself beside the guard's index (a file it takes from
  there blocks the install, so it fails closed); and the scan of a very large
  tarball (`next`, 42 MB), which dominates a first install.
- *From the audit (P1/P2):* a GitHub Action and pre-commit hook, a public
  nightly benchmark, per-rule docs, a coverage gate and parser fuzzing in CI,
  optional live secret verification, splitting `core.py`, generating the
  dashboard's script from `js/src`.

Prefer doing detection extensions **reactively** — when a real-world dropper
uses the pattern — over speculatively. The bar that made this tool good is the
false-positive bar; keep it.
