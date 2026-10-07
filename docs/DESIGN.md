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
  with `re`'s answers, for every pattern) and its patterns and finding texts
  in a rule pack
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
- **Bounded, linear work.** No catastrophic backtracking, ever. Every pattern
  of the engine runs on linre, in time linear in the text whatever it holds,
  and one linre would not run fails the tests (`docs/RUST_ENGINE.md` §14);
  the npm package's own remaining JavaScript patterns are written so V8's
  engine keeps a bounded number of backtrack entries (it overflows its stack
  on millions). Values are followed for
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
lazaret.registry   npm / PyPI / Go / crates.io package auditing  (lazaret-registry)
lazaret.registry.guard  pre-install guard for npm/pnpm/yarn/bun/pip/uv/go/cargo   (lazaret guard, lazaret-guard)
lazaret.registry.editorguard  the guard for VS Code's and its forks' --install-extension (lazaret guard code …)
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

**Go and Rust (0.1.9, S-4).** A project's `.go` and `.rs` files are source
(`core.EXTS`, `fs.js` `EXTS`): their comments and literals come from the
engine's Go and Rust lexers, and they get the rules whose `langs` list them
(S-SECRET, S-TOKEN, S-BIDI, Q-TODO) and the families every text gets. No
taint, function metric or supply-chain detector reads them yet. Two limits
are deliberate until the Go and Rust detectors exist: a package's Go and
Rust files (registry and guard scans) and a dependency tree's (`--deps`)
are not read (`core.DEP_LANGS`, `dep_source_lang`): reading them for
secrets alone would add findings a consumer cannot act on and say nothing
about what their build scripts and initializers run; and their lines are
left out of the duplication measure (`core.DUP_LANGS`), whose 10% gate was
set on Python and JavaScript (Go's standard library measures 2 to 13% with
its six-line windows, popular crates 4 to 54%), while they count in the
lines of code the maintainability rating divides by.

**CI files' hardening (0.1.9, S-4).** `scan_config_file` runs
`ghworkflow.hardening` on a workflow and `gitlabci.hardening` on a GitLab CI
file (both twins), each kind's rule from `hardening_rule`. These are
practices, not the worms' shapes: `build_result` counts one against the
supply-chain condition only when it is CRITICAL (`core.HARDENING_RULES`,
`rules.js` `HARDENING_RULES`), so a repository is not failed for running
`actions/checkout@v4`. Like every SC- finding they take no suppression
marker: a hardening check a team accepts stays a hotspot in the report.

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
  credentials or a credential store to an exfiltration service; (rule set
  2.17) the whole environment or a credential store sent anywhere, what
  local commands print about the machine (`_SH_LISTINGS`: `ps`, `netstat`,
  `ifconfig` …; not what Node's `os` module answers) sent anywhere, and a
  raw socket's hard-coded public address counted as a public IP address
  (`signs::raw_public_ip`: not this machine's, a private network's, a
  link-local or a carrier-grade NAT address); a request
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
  one). A Python text is read on its tree (0.1.9, N-19: the supply-chain
  model's `K_OWN`, given where those reads start): what it reads back is
  followed through its scopes and calls to what each call runs, so a
  function's parameter is not the module's variable of that name, a program
  given it as arguments runs that program, and a usage text's parser
  (`argparse`, `optparse`, `docopt`) gives the command line; the text
  follower answers for a text the tree can't read, and for JavaScript.

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
manages services is normal. A shell's startup file (0.1.9,
`shell_rc_written`) counts only when the command written there downloads
or runs code (`_SVC_SHELL_RC_RUN_RE` in the write call's arguments, or in
the text a name among them is first given, or before the `>>` of the
shell's spelling), or when the script names the file only in strings it
decodes as it runs (alinet): installers append PATH lines, and CLIs their
completion scripts (@asyncapi/cli's `postinstall`). The self-read
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
checks. Since 0.1.9 it also takes `go:` and `crates:` specs: their registry
modules (`registry/ecosystems`; the readers are RUST_ENGINE.md §21, §22) resolve,
download and check them through `repo.module_transport` (`_fetch` with the
module's own URL rule), and `scan_package` scans them as the guard does; the
errors and `Resolution` are the modules' classes, re-exported (X-2's first
step). `lazaret-sca --update-bundle` builds a CVE bundle from public feeds
(OSV, CISA KEV, EPSS) parsed with `lazaret.safexml`; Lazaret ships no
vulnerability database of its own. The registry always redacts what it stores.

Python-only registry checks (0.1.8): SC-USE-RISK runs the import-time test on
the files no entry point loads (`_ArtifactScan._use_time_code`) and keeps only
its CRITICAL shapes — skipping tests, examples, docs, demos, benchmarks and a
web app's static assets (USE_RISK_SKIP_DIRS), not reading once the archive is
SUSPICIOUS, smallest files first within USE_RISK_CHARS characters per archive
(a bound by work, so every machine reads the same files; until 0.1.9 it was 3
seconds). What it doesn't reach is not SC-TRUNCATED: the file rules read every
file. The artifact's `useTime` (files and characters read, of how many, and the
bound) says how much it read, and `print_scan` says so when it left code unread.
The cross-file follower reads the same files as one package (`_cross_file_code`,
§5c; its SC-IMPORT-RISK names the file), and scripts that install scripts and
import-time code start with node or python are followed to the package file each
runs (`_started_scripts`, `core.spawned_scripts`) and tested like the one that
started them. SC-NEW-DEPENDENCY
(`new_dependency_issues`, called by `scan_package`) compares a release's
dependencies with the release published before it and looks up the added
ones' first publication: live registry data, best effort, no request for a
release without dependencies; one the package's own people publish does not
count (npm's maintainers; PyPI's owners, maintainers and organization, from
the JSON API's `ownership`). The guard scans each package with
`_scan_artifact`, so it gets SC-USE-RISK and the follower but not the dependency history (it
already scans the new dependency itself, and holds back a release younger
than --min-age). SC-UNUSED-DEPENDENCY (`_ArtifactScan._unused_dependencies`,
npm only, INFO) lists the runtime dependencies no text of the release names
and that are neither among npm's 5,000 most-downloaded packages nor in its
own scope, when every text member was read whole; `_scan_artifact` returns
their registry names (`unusedDependencies`), and `scan_package` makes a new
one among them CRITICAL. The comparison itself, `registry/unused_deps.py`,
takes declared names, used names and an ecosystem's normalizer, so a crate's
or a Go module's dependencies go through the same function.

SCA for Go and Rust (0.1.9): the inventory reads `go.mod` (its `replace`
lines applied), `go.sum` only for a module whose `go` directive is before
1.17 (a later `go.mod` lists what the build needs), `vendor/modules.txt`,
`Cargo.lock` and the root `Cargo.toml`, and the bundle carries OSV's `Go` and
`crates.io` exports. Names are the registries' own identities, matched
exactly: a Go module path as written (case-sensitive; `.`, `-` and `_` are not
alike in it), a crate folded as crates.io folds it (case, and `_` to `-`).
Versions are ordered as SemVer only, Go's `v` prefix and pseudo-versions
included. A `replace` by another module keeps the original in with an
unknown version, so its advisories report unknown rather than nothing; a
`replace` by a directory, a path dependency and a workspace member are the
project's own code and are dropped; a Cargo git or other source has no
version. The standard library and the toolchain are not matched (`go.mod`
names a minimum Go version, not the toolchain that builds). The source gate is
fail-closed and per ecosystem: a bundle without `osv:go` or `osv:crates`
fails a project that has Go or Rust dependencies, and only such a project.
`scanner/gomod.py` is the one `go.mod` reader, `modfile`'s rules, shared by
the inventory and the Go module auditor (the scanner never imports the
registry, so it lives in `scanner/`); `scripts/gooracle` compares it with
Go's own.

The indexed bundle (`sca_index.py`, `--bundle-format index`) is the same
advisories in a file a scan reads only where it asks: a header with the
parts' places and CRC-32s, a key table sorted by a digest of each name's
key, and one zlib record per advisory and per name. A lookup bisects the
table, reads the name's record and its advisories, and sorts the pairs by
their place in the whole bundle, so `advisories_for` answers what the JSON
bundle's does, in the same order. Nothing is read twice in two ways: the
writer runs the document through `normalize_advisory` and `bundle_header`,
`CveBundle`'s own reading, and reads the whole file back and checks it
before it replaces the old bundle. Every way a file can be wrong is
`BundleDamaged` (a `ValueError`: exit 4), at open or at the record that is
read, and a record is inflated within a bound, so a bomb is refused unread.

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

**What is not read is said (N-1, 0.1.9).** Code in a language the engine
has no reader for is counted (`UNREAD_CODE`, `_unread_code`: not its test
code) and gets one SC-UNREAD-CODE finding, which `decide_verdict` counts with
the truncation rules: INCOMPLETE, never OK. A guard that said OK for a crate
whose `build.rs` it never read would say more than it knows (the readiness
review's finding 2). A Go module's `.go` files and a crate's `.rs` files were
such code until Part C; `UNREAD_CODE` has no entry now.

**A module's and a crate's code (Part C, 0.1.9).** `_ArtifactScan` reads a
`gomod` artifact's `.go` files and a `crate`'s `.rs` files as source
(`PACKAGE_CODE`): each gets the file rules in dependency mode, as a
package's JavaScript and Python do, and `_package_code` hands them all to
the engine's reader of the language (`engine.go_package` with the cgo
packages' `.c` and `.h` files and the root `go.mod`'s module path;
`engine.rs_crate` with the build script, the library's root and whether it
is a procedural macro, from `Cargo.toml` as cargo reads it:
`ecosystems/crates.py`'s `layout`). What the readers find is a finding of
the test the same moment gets in JavaScript and Python: what Go's init code
reaches and a Rust `#[ctor]` are SC-IMPORT-RISK (`import_time_severity`); a
build script and a procedural-macro crate are SC-INSTALL-HOOK, CRITICAL; the
strong reasons of the rest are SC-USE-RISK, read within `USE_RISK_CHARS` as
`_use_time_code` reads (its counts join `useTime`). `//go:generate` lines are
listed (SC-GO-GENERATE, INFO). A file no build of a dependent compiles (Go's
`*_test.go`, `testdata/`, `vendor/`, a name with `_` or `.` first; a crate's
`tests/`, `benches/`, `examples/`: `_never_built`) gets neither the reader
nor the file rules. A package over `PACKAGE_CODE_CHARS` (300 million
characters) is not read (SC-TRUNCATED): the reader holds all of it at once,
and aws-sdk-go v1's 207 million characters of Go peak at 2.4 GB.

**Go and Cargo (0.1.9).** go can be pointed at a proxy, so the Go guard is a
proxy (`LocalGoProxy`, 127.0.0.1, for the one command) that relays the
proxies `GOPROXY` lists by go's rules (a comma goes on after a 404 or 410
only, a bar after any error) and scans each zip before go has it; go still
checks the zip against `go.sum` and the database, so what go accepts is what
was scanned. The proxy is go's alone (`LocalGate`): it answers a path with
the run's secret segment and its own `Host` only, and of the checksum
database only the paths go asks for, so another process on the machine, or
a page that rebinds a name to 127.0.0.1, cannot use it or the proxy
credentials it holds (the same gate is on the pip and uv index). A zip is
fetched once, to the spool, hashed as it comes, and those bytes are go's:
the size a header claims decides nothing, and a second fetch would hand go
bytes nothing scanned. It never fetches from version control: `direct` is
not honoured. go still takes modules without the proxy, from its module
cache and from repositories (`GONOPROXY`), so the guard lists what a
command uses (`go mod download -json`, which runs no module's code) and
scans those zips where go keeps them (`check_cached`): before a command
that builds a program, so that a hostile module in the cache stops it
before anything is built or run, and after one that resolves; the listing's
changes to `go.sum` are put back, so the command finds the files as they
were. A vendored build fetches nothing and is said to be unchecked.
`--min-age` works at the proxy (a young version left out of the list, its
`.info` and zip refused), so `go get` falls back the way it does when a
version is missing; a cached module's time is the `.info` go kept beside
it. cargo has no such hook: a registry's index and download URL are
configuration, and a replaced source is the user's. So the Cargo guard
resolves first (`cargo update --workspace`, or the lock as it is with
`--locked`), reads `Cargo.lock`, fetches and checks every crates.io crate
the lock names against its checksum (one cargo has unpacked already too: a
verdict cached for its checksum is not scanned again), from where cargo
would (cargo's configuration as cargo merges it: `[source]` replacement,
`[registries]`, `include`, `--config`; the registry's `dl`), and only then
lets cargo run, with `--locked`. `cargo install` resolves in a scratch
project that is a workspace of its own, with the features asked for, run
from the user's folder (so its configuration and toolchain are the ones
`cargo install` reads), and installs `name@=version`. A crate that cannot be
checked is blocked; one from somewhere the guard does not read (git, a
vendor folder, a git index, a registry that answers 401 or 403) is
INCOMPLETE, and anything cargo unpacked that the guard did not check is
named. Every name and version that reaches a URL or a path is checked first
(`cargosrc.crate_ok`), so a hostile lockfile can name nothing but a crate to
fetch. The manifests and lockfiles of both are snapshotted and put back when
anything is blocked.

**VS Code's extensions (0.1.9, E-1).** An editor has no hook either: its
gallery is its `product.json`, and nothing on its command line or in its
environment points it elsewhere. So `editorguard.py` does what the editor's
`--install-extension` does up to the download, and then has the editor
install the files it checked (`--install-extension FILE.vsix`): what is
installed is what was scanned, whatever the registry serves next. Which
version is VS Code's choice, written again in `editorcompat.py` (its
extension management and its validator, MIT): an installed extension is
left alone unless `--force` or a version is given; else the newest release
(`--pre-release`: the newest version) whose file is for the editor's target
platform (its build's architecture, from `--version`; Alpine from
`/etc/os-release`) and whose `engines.vscode` takes the editor's VS Code
version (`--version`'s, or a fork's `vscodeVersion` from its `product.json`;
a fork that reports only its own version is not checked against engines,
and the editor checks each file it installs). The registry modules list what
the editor chooses among (`candidates`, in rounds: the Marketplace's
latest-only query and then every version, as VS Code asks; Open VSX's query
API page by page, or one version's files) and give one candidate's file and
its manifest (`artifact`, `manifest`). What an extension brings is VS Code's
walk too (`getAllDepsAndPackExtensions`): its dependencies that are not
installed, built-in extensions counted as installed (they are not in
`--list-extensions`, so they are read from the app's `extensions/`), and its
pack's members that the installed version did not list, each at the version
the editor would take for it, and what those bring in turn, an installed
member's newest version read from its manifest alone (the editor reads it
too, and installs what it brings that is missing). The editor applies a list
of malicious extensions (`controlUrl`) to what it downloads, not to a file it
is given, so the guard applies it. From VS Code 1.98 the CLI takes
`--do-not-include-pack-dependencies`, and the guard installs every file in
one command with it, so the editor fetches nothing; before 1.98 it installs
wave by wave, each extension after what it brings, so that the editor finds
them installed and fetches none, and a cycle stops the run. The editor's
list of installed extensions afterwards is compared with what was checked.
An extension installed from a file is pinned by the editor (as one installed
with `@version` is), which keeps it at the version checked.

**The guard's own folders and programs (0.1.9).** cargo, rustup, yarn, npm
and go read settings from every folder above where they run (a workspace, a
toolchain file, a `.yarnrc`'s `yarn-path`, `go.work`), and `/tmp` is a folder
every user can write to. A resolution the guard makes outside the project is
made in `private_scratch()`: `LAZARET_GUARD_SCRATCH` as given, else the
user's cache folder, else the temporary folder, each of these two only if no
folder above it is one another user can write to (`_shared_above`), and an
error otherwise. A
program is found by `scanner/programs.py`, in `PATH`'s absolute folders
only: `shutil.which` and `CreateProcess` look in the current folder first on
Windows, where the project is.

**Scan workers (0.1.9).** Every scan runs in a worker (`scanpool.py`),
`--jobs 1` included, never in the process that downloads, holds the
archives and talks to the package manager: that process peaked at 2 GB
scanning in place, and a worker that died used to leave the pool scanning in
it. The archive goes to the worker as a file (0700 directory, 0600 file,
named by its digest), and the worker hashes it again: other bytes are
`ArchiveChanged`, never a verdict. Limits follow the work: an address-space
limit per worker (`--worker-memory`, Linux), the cores shared out among the
archives running at that moment (`engine.THREADS`, which only the pool
writes), and a CPU-time limit above the scan's deadline as a backstop. A
lost worker's archives run again, each alone in a pool of its own; one that
kills its worker again is `Died`, a scan that failed, which the guard blocks
as not checked, as it blocks any scan error. A pool that cannot start at
all (`Unavailable`: no `spawn`, a limit too small to import Python) is told
apart from one that lost a worker, and only then does the guard scan in its
own process, once said. Isolation buys memory and robustness, not speed: the
wall time is the same.

`--from-plan` (pip, opt-in): after pip's plan (`--dry-run --report`) is
scanned, pip installs the scanned wheels from a folder (`--no-index
--find-links`) with the user's own arguments, so pip's rules still apply;
each file is hashed again just before pip runs. A plan with an sdist (its
build requirements come from the index), a file too large to scan or no
files at all goes through the index as before. `--keepalive` (opt-in)
replaces urllib's one connection per request with a pool of `http.client`
connections; redirects, credentials and hosts stay the fetcher's
(`_open_kept` applies `_opener`'s rules), and a connection goes back to the
pool only when its body was read to the end.

### g. Sources: a repository at a commit (`sources.py`, `sourcescan.py`, 0.1.9)

`lazaret scan github:owner/repo[@ref]` and `gitlab:group/project[@ref]` scan
a commit, not a branch: the ref is resolved to a SHA first, and the SHA is
what the archive is fetched by and what the report names, so a branch that
moves while the scan runs cannot change what was read. The rules are the
registry module's, applied to these hosts: HTTPS only, to fixed hosts
(`api.github.com`, `codeload.github.com`, `raw.githubusercontent.com`; for
GitLab the one host of `LAZARET_GITLAB_URL`), never a host taken from a spec,
a redirect or what was scanned; a token only to the API host, checked for
characters that could split a header, in no message, report or exception;
the archive read by `repo.iter_archive` with its byte, file and time budgets,
links resolved inside it rather than created; nothing run. `sourcescan`
then runs the ordinary scan (`core.main`, every option) on the directory.

What an archive cannot show is looked for. `git archive` leaves out every
path marked `export-ignore`, so a payload can sit in the commit and out of
its tarball. The commit's tree is listed (one call on GitHub, pages on
GitLab) and every path the archive lacks is fetched on its own and written
only when it is the blob the tree names (git's blob id, SHA-1 or SHA-256),
within a request, time and byte budget; a rate limit stops the asking.
Whatever is still missing, a tree too large to list, or an archive that hit
a budget makes the checkout incomplete: said after the report, the
result's `incomplete` and `incompleteReason` set (as an MCP scan that stopped
early sets them), and `--ci` fails on it unless `--accept-incomplete`. The
scan is told what it is a scan of (`core.main(argv, source=…)`,
`set_source`): `project` is the spec at its commit, not the temporary
directory, and `source` says what was read and what was not; SARIF's
`versionControlProvenance` maps `%SRCROOT%` to the repository at that commit.

`registry/actions.py` asks GitHub about a workflow's `uses:` under the same
rules: an impostor commit (a pin in no branch and at no tag tip: GitHub
serves a fork's commit under the parent's name), a version tag that moved
since the pin book first saw it, a tag off the branches, a pin comment that
names another commit, and the action's own `action.yml` (an image without a
digest, a composite action's unpinned steps, two levels deep). What it could
not ask (the rate limit, its call budget, an expression in a ref, a private
repository) is `incomplete`, and an action not checked is not cleared. A
project scan does not call it: it needs the network, and the offline checks
(`ghworkflow.hardening`) are the scan's.

Since N-4 it also reads each action's own code at the commit it resolves
to: the archive the runner fetches (GitHub's archive of the commit, from
`codeload.github.com`, or through the API with a token; `export-ignore` paths
are not in it for the runner either), checked against the commit its pax
header names, and scanned by `repo.scan_action` as an artifact of its own
kind ("action": the sdist's paths, without the top directory). Its
`action.yml` (`registry/actionmeta.py`, on the workflow reader's outline)
says what runs, and the scan reads that as it reads a package's entry points
and install hooks: a JavaScript action's `pre`, `main` and `post` (each
`node <the action's directory>/<path>`) are entry points, read with what they
load by the import-time test; a composite action's `run:` steps are install
hooks' commands (a PowerShell one as `pwsh -Command`, a Python one by the
install-script test in Python), and the files of the action they run are
followed: only a path built from `github.action_path` (GITHUB_ACTION_PATH)
names one, since a step runs in the job's workspace; a Docker action's
Dockerfile gives its base images and, through its COPY and ADD lines, the
file of the build context its entrypoint runs. The rest of the repository
gets the use-time test. npm's scripts, a `binding.gyp` and the names of
`package.json` are not the action's: the runner installs and builds
nothing. What counts is judged for CI code (`actionmeta.judge`): what CI code
does as its job (a named variable or token sent, a file uploaded, another
program started, a package published, a loopback address) is not counted; a
script fetched and run as it arrives is MAJOR, as SC-WORKFLOW-PIPE-SHELL rates
it in a workflow; the import-time test's strong shapes and the whole
environment sent are CRITICAL; an AI agent launched in an autonomous mode is
MAJOR (an action may exist to run one). Each counted issue is a `code`
finding with the scan's own rule; a Dockerfile's unpinned base image is
`docker-unpinned`; a scan that did not read the code whole leaves the action
`incomplete`. One archive per repository and commit is fetched, at most 60
and 1 GiB in a run; the engine's answers are shared between scans.

### h. Go and Rust in the engine (0.1.9)

The lexers (`lex/go.rs`, `lex/rs.rs`) are what a project scan reads `.go` and
`.rs` files with today (`Lang::Go`, `Lang::Rs`; comments and literals for the
rules that read them). The parsers come next, for the detectors (G-1, R-1):

- **The Go parser** (`goparse/`) is `go/parser`'s, not a new reading of Go:
  the point is that code the compiler builds is code the scan reads the same
  way. It accepts exactly the files `go/parser` accepts and builds the same
  tree (`go/ast`'s kinds and spans); `scripts/goparse/diff.py` holds it to Go
  on the Go distribution and on mutants of it. The one difference is depth:
  `MAX_DEPTH` 256 against Go's 100,000, since the engine reads untrusted files
  on a small stack. Comments are not in the tree, so the cgo preamble and the
  `//go:` directives come from the lexer. What Go leaves to its type checker
  (a `.(type)` outside a switch, `type T[] int`, `[...]int` with no literal,
  `select { case 1: }`, a label with no statement) is accepted, as
  `go/parser` accepts it.
- **The Rust item reader** (`rsparse/`) is the compiler's reading of items,
  not a new one: a crate that builds must be a crate the scan reads the same
  way. It reads the groups in an item's head and in field lists for items,
  because the compiler's parser sees an item there, and
  `scripts/rsparse/diff.py` holds it to `rustc`.
- **The hooks** (`goparse/hooks.rs`, `rsparse/hooks.rs`) list the code that
  runs without being called: `init` functions, package-variable
  initializers, cgo preambles, `//go:linkname`, `//go:generate`; procedural
  macros, `#[ctor]` and `#[dtor]`, load-time sections, a crate's entry point,
  a build script's `main`. Until detectors read them, a Go module or a crate
  with code is INCOMPLETE (N-1, §5f), never OK.

---

### i. VS Code extensions (`extensions.py`, 0.1.9, E-1)

An extension runs in the editor's extension host: Node, with all of the
user's access, no sandbox and no prompt, started with the editor (`*`,
`onStartupFinished`) or on an event, and updated by the editor. It is read
as the registry reads an npm package, artifact kind `vsix`, with the
editor's rules for what runs and when instead of npm's:

- what VS Code installs is what is under `extension/` in the `.vsix`
  (`canonical_member_path`); the package's own files (`[Content_Types].xml`,
  `extension.vsixmanifest`, a signature) are not the extension's;
- `main` and `browser` are the entries (an extension with neither runs no
  code: there is no `index.js` default), and they and what they load get
  the import-time test, whose finding says when the editor starts them at
  every start; the rest of the code gets the use-time test;
- `vscode:uninstall` is the one script VS Code runs: `node` and a file,
  split on single spaces (`vsix_hook_runs`, VS Code's `parseScript`), once
  the extension has been uninstalled, at the editor's next start. It gets
  the install-hook test and its findings speak of the editor; any other
  command, which VS Code logs and skips, is inventory (INFO). npm's
  lifecycle scripts, a bundled package's and a `binding.gyp` never run;
- `extensionDependencies` and `extensionPack` are what it brings (lowercase
  `publisher.name`, the first 500 of each). npm's look-alike test does not
  apply to an extension's names; the extensions' own does (below).

An installed extension is a folder (`<home>/.vscode/extensions/
publisher.name-version[-platform]`, and the same under each fork's data
folder). `repo.iter_folder` yields its files as `iter_archive` yields an
archive's members, under the same limits, in a fixed order, and
`repo.scan_members` scans either, so a folder and its `.vsix` give the same
findings. Nothing is followed out of the folder: a link to a file inside it
is read as that file; a link to a folder, out of the folder or to nothing
is not followed, and the scan is INCOMPLETE, since Node would follow it to
code no scan read; a FIFO, a socket or a device is never opened; and a
folder of more names than `MAX_FILES` is not listed whole (INCOMPLETE).
`extensions.py` finds the folders (`EDITORS`, code-server's, the folder
`VSCODE_EXTENSIONS` names), scans each and prints it as `lazaret-registry`
prints a package. `_cli.py` hands it a command line with `--extensions` or
a word that names a `.vsix` file.

**Open VSX (`ecosystems/openvsx.py`, E-1's second part).**
`lazaret-registry scan openvsx:namespace.name[@version]` resolves through
the registry's API (`https://open-vsx.org/api/<namespace>/<name>[/<version>]`):
its `downloads` map gives a `.vsix` per target platform, and every one the
editor installs (VS Code's TargetPlatform values) is scanned, the worst
deciding, as a PyPI release's wheels are; a platform the editor does not
know is listed in `skippedArtifacts`, not scanned. Each file is checked
against the SHA-256 Open VSX publishes beside it (`<file>.sha256`, from the
platform's own document) before anything is read, and a file URL from an
answer is held to the module's two hosts (`open-vsx.org`, and the content
host `openvsx.eclipsecontent.org` its file URLs redirect to). The result's
`registryInfo` says whether the namespace is verified, who published the
version, a pre-release, deprecated; `extensionDependencies` and
`startupEvent` come from the files' `package.json`. Requests to the API are
paced (0.5 s), as Open VSX asks of anonymous clients.

**The Visual Studio Marketplace (`ecosystems/vsmarketplace.py`, E-1's second
part, decision 11).** `lazaret-registry scan vscode:publisher.name[@version]`
resolves through the gallery query VS Code sends (a POST to
`https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery`:
the extension by name among VS Code's, unpublished ones and versions that
failed validation left out, with its versions' files, properties and asset
URIs and its statistics; with no version asked for, the latest release and
pre-release only, of which VS Code installs the release). A version is one
entry per target platform; each entry's `VSIXPackage` file, on its
publisher's CDN host (`<publisher>.gallerycdn.vsassets.io`, else the
fallback `<publisher>.gallery.vsassets.io` with the platform asked for), is
scanned as Open VSX's are, the worst deciding. The module's hosts hold
`*.` entries for those: `base.host_allowed` takes exactly one DNS label
before the domain, on port 443, for a request and every redirect, and
`base.Fetch.post_json` sends the query (the transport's `data`, a POST's
only). The Marketplace publishes no digest (it signs each package, a
`.sigzip` VS Code checks with vsce-sign; not checked here), so a download
is scanned unverified: `verify` gives None, and `registryInfo.digest` is None
and `print_scan` says so, beside the publisher's verified domain and the
install count; `extensionDependencies` and `extensionPack` are the
version's properties. Its terms of use tie its extensions to Microsoft's
products; scanning it is the project's decision 11. The sandbox cannot reach
it, so the tests build the gallery's answers in the shape VS Code's gallery
service reads.

**Names and new extensions (E-1's third part).** An extension is named
`publisher.name`, compared without case, and anyone can create a publisher.
`lookalike.vscode_lookalike` compares an extension's own identifier (its
`package.json`'s publisher and name) and the ones it brings with the targets
of `popular_names.json`'s `vscode`, in two tests: the identifier one change
from a target's, or its separators changed, in another publisher (npm's
test with the publisher as its scope: only a target's publisher can publish
in it; `juanbIanco.solidity`); and the publisher one change from a target's
publisher, its separators aside, whatever the name (`juan-bianco.solidity-vlang`),
for publishers of six letters and digits or more (`MIN_PUBLISHER`) that
neither a target nor a known name has and that `known_publishers` does not
list. Another publisher's extension of the same name is not compared: Open
VSX carries forks and builds under their builders' namespaces (several of
its 1,000 most downloaded are). The targets are Open VSX's 1,000 most
downloaded, read through a fetcher on Oct 6 (the sandbox cannot reach the
registry; each page was read twice and the readings compared);
`scripts/fetch-top-extensions.py` saves the Marketplace's ranking by
installs and Open VSX's by downloads, and `update-popular-names.py
--vscode` takes the first 1,000 of each in turn, the pages' other
identifiers one change from a target as known names, and their publishers
that look like a target's as known publishers. A registry scan also
compares the release with the version its registry published before it
(`repo.extension_new_dependencies`): the module's `history` (Open VSX's
query API, `/api/-/query?extensionId=…&includeAllVersions=true`, a page of
1,000 entries, at most 5,000; the Marketplace's gallery query with every
version) gives each version's time, what it brings and whether it is a
pre-release; the previous version is the one published last before this one
(a release against releases only). An extension it brings that the previous
did not, of another publisher, is looked up (`first_published`: Open VSX's
oldest version, the last page first and every page only when that one is
recent, since any version is no older than the first; the Marketplace's
`publishedDate`) and is SC-NEW-DEPENDENCY under 30 days, CRITICAL under 7,
unless on Open VSX the account that published the release published it.

### j. The network: Lazaret's own HTTPS client (`nativenet.py`, `lazaret-net`, 0.1.9, NET-1)

tiny_https, an HTTPS client written on Rust's standard library alone (TLS
1.3, X.509, HTTP/1.1 with a keep-alive pool, HTTP/2 and HTTP/3; and pure
verifiers: the Go checksum database, Sigstore bundles, CMS), is in the
repository as it was handed over (`rust/crates/tiny_https`;
`scripts/sync_tiny_https.py` takes a drop and `--verify` checks the copy
against `vendored.sha256`, so a local edit cannot slip in). Lazaret takes it
in as two crates, the split its consumer asked of it: `lazaret-verify`, its
pure part (`default-features = false`: no I/O, no `unsafe`, WebAssembly),
which the engine may use, and `lazaret-net`, which only the native library
links (`lazaret-ffi`, not for wasm32). `check_rust_deps.py` holds that line.

`lazaret-net` makes one shared client per process (a forked child makes its
own and leaves the parent's connections alone) and a clone per request with
the caller's rule: `HostRules` with `one_label_wildcards` and
`default_port_only` (the registry modules' `host_allowed`, applied by the
client to the first URL and to every redirect before it connects),
`UrlLimits::strict` (https, no credentials, printable ASCII, 2,048 bytes),
the timeouts, the redirect limit and the byte budget (a declared length over
it fails at once). The C ABI (`lazaret_net_request`, `_open`/`_read`/`_close`
for a body read in pieces, `_configure` for trust anchors) takes the request
as JSON and gives the head as JSON and the body as bytes. Python's side is
`scanner/nativenet.py`: `repo._fetch_bytes` and `repo.module_transport` send
through it, with REGISTRY_HOSTS or the module's `Fetch.hosts` as the rule
(a rule given only as a function goes through urllib, which can apply it
hop by hop), and turn its failures into the FetchError texts urllib's path
gives.

The protocol was measured on Lazaret's own traffic against the real
registries (fresh processes, cold connections): a burst of 200 npm documents
from 16 threads took 0.61–0.68 s over HTTP/2, 0.64–0.91 s over HTTP/1.1 and
8.3 s over urllib; 100 npm tarballs from 8 threads 0.43, 0.40 and 2.85 s; one
47 MB wheel a median 0.55 s over HTTP/2 and 0.35 s over HTTP/1.1; six wheels
at once (58 MB) 0.69 and 0.26 s. One HTTP/2 connection, read and decrypted by
one thread, is slower for bulk than HTTP/1.1's parallel connections, and the
gain over urllib is reuse whichever protocol is used. So a document (a
budget of at most 32 MiB) is offered h2 and a download goes over HTTP/1.1
(`LAZARET_HTTP` overrides); both keep their connections.

What falls back to urllib: no native library, or one without the network
layer; `LAZARET_NETWORK=python`; a server that offers no TLS 1.3 (tiny_https
speaks 1.3 only; OpenSSL then negotiates with its downgrade protection, and
the host goes to urllib for the rest of the process); a proxy reached over
TLS. Trust anchors: `SSL_CERT_FILE`, the system bundle, or what Python's
`ssl` loads (Windows' store); `SSL_CERT_DIR` alone is not read. The library
has not had an independent review, which Lazaret had asked for before
relying on its TLS; decision 12 (John, Oct 6) made it the default anyway,
with urllib one variable away.

The other callers (NET-1's second part): the guard's `Fetcher.open` (and so
`fetch`, `fetch_to_file`, the Go relay and the pip index's relay) sends an
https request through it, with the fetcher's hosts (and the URL's own,
already checked) as the rule, or no host rule for a redirect where
`https_redirects` lets one go to any https host; `_NativeResponse` reads like
urllib's response (`headers.get`, `read`, TooLarge over the budget).
`sources._http` sends the `github:` and `gitlab:` sources' requests,
`sca_feeds.fetch` a feed's download (no host rule: a feed may move, https
only). What stays on urllib: plain http (a registry served on this machine),
and secret verification, which sends the secret it checks (its transport is
V-1's, which waits on decision 4). `keepalive.py` (`--keepalive`) pools
urllib's connections and is moot for the native transport, which pools its
own.

Credentials (decision 14, John, Oct 6: they go over tiny_https in 0.1.9).
Until this drop they stayed on urllib, for two reasons: a redirect hop must
get its own host's credentials and no other's, which only urllib's redirect
hook gave (tiny_https dropped `Authorization`, `Cookie` and
`Proxy-Authorization` on a change of origin, and nothing more: a
`PRIVATE-TOKEN` the caller set went on, and nothing could add the next host's),
and secrets are what an unreviewed TLS stack would cost most. tiny_https's
drop of Oct 6 (b) added the hook (`Client::hop_headers`: called for the
request and for every redirect after the host rule and the URL limits allow
it and before anything is sent there; what it returns goes with that hop
alone; no response cache, a pool keyed by scheme, host, port and proxy, no
HTTP/2 coalescing across hosts, and the hook's header names never indexed in
HPACK or QPACK). `lazaret-net` takes a request's credentials as data
(`Credential`: a host written as a Host header is, a path prefix, a header,
and `first_only` for the request itself) and its hook gives each hop, over
https, the credential of the hop's host with the longest path prefix of the
hop's directory for each header name, a `first_only` one first on the
request, as `pmsettings.Credentials.header` chooses for a URL. A request that
sets `Authorization`, `Cookie`, `PRIVATE-TOKEN`, `JOB-TOKEN`, `Deploy-Token`
or `Proxy-Authorization` as a header is refused, so none can ride a redirect.
The guard gives the request's own `Authorization` (its URL's
`user:password@`, or the settings' for its URL) as `first_only` and the
settings' for every host and path as the rest, which is what urllib's path
sends: its own with the request, the settings' of each redirect's URL with
the redirect. `sources._http` gives the token to the API host (GitHub's API,
or the GitLab instance's host and port). A credential the native client
cannot send (a value or path outside printable ASCII, a host it would not
write that way) sends the request through urllib as before. The pip index's
relay of a file too large to scan now goes through `Fetcher.open` as the
scan's download does, with the file URL's credentials; it had made a request
of its own without them.

The Go checksum database (NET-1's third part). `golang.verify_lookup`
checks a `/lookup/<module>@<version>` answer as the go command's client does
(`golang.org/x/mod/sumdb`), through the native library's `verify.go_sumdb`
(lazaret-ffi's `verify` module, over `lazaret-verify`'s `gosum`: tiny_https's
`sumdb::Check` and `tlog`). The tree head the lookup carries must have the
signature of the key Go pins (`SUMDB_KEY`, `cmd/go/internal/modfetch`'s
`knownGOSUMDB`); it is checked against the newest head this process has
accepted before (a prefix proof, either way round), so the database cannot
show one run two histories; and the record is proved in that tree. The call
is made twice: first it names the tiles the proofs read (at most 64; their
paths and sizes are checked before any is fetched), then, given them, it
checks. Tiles come from `sum.golang.org` through the module's `Fetch` (its
host rule and budgets); a partial tile the database no longer serves is read
from the full one, whose first hashes are the same, as Go does. Tiles that
passed are kept for the process (1,024 at most) and are checked again each
time they are used: their bytes never change, and a kept tile proves nothing
by being kept. The hashes `parse_lookup` read must be lines of the record the
check vouched for, and its number the same. Anything that does not hold is a
FetchError and the module is not resolved (fail closed, as `go` fails with a
security error). `info["sumdb"]` is "verified"; it says "tls" only where the
native library is missing or is one from before the check. What the go
command does and this does not: keep the newest head between runs (its
`$GOPATH/pkg/sumdb`), so each run starts from the lookup's own head; and
honour `GOSUMDB`, `GONOSUMDB` and `GOPRIVATE` (the registry resolves public
modules through `proxy.golang.org` and checks them against `sum.golang.org`
only). The guard's Go relay is not affected: there the go command checks
the database itself. Tested on tiny_https's capture of the real database
(`golang.org/x/mod` v0.17.0's lookup, a head served a little before it and
the seven tiles Go's client reads): `tests/registry/test_golang_sumdb.py`,
lazaret-ffi's and lazaret-verify's own tests, and the `go-sumdb-check` fuzz
target (that answer changed: whatever the bytes, an answer that passes says
what the database signed).

Provenance (NET-1's fifth item; `registry/provenance.py`). npm lists a
version's attestations in `dist.attestations` (npm's own publish
attestation, signed with the registry's key, and SLSA provenance, signed
through Sigstore by the CI that built the tarball), and PyPI's Simple API
names each file's PEP 740 provenance. After a file's digest check,
`scan_package` hands its digest (npm: the tarball's SHA-512; PyPI: the
file's SHA-256) to `provenance.check_release`, which fetches the
attestations and has the native library check them (`verify.sigstore`,
lazaret-verify's `provenance` over tiny_https's `sigstore`): the signature
by the certificate or key, the chain to Sigstore's CA at a time a
transparency log or time-stamp authority vouches for, the log entries, and
a subject with the file's digest. The outcome is one of three, and the line
between the last two is the point: verified (with the signer: issuer,
repository URI and the numeric repository and owner IDs GitHub puts in the
certificate, workflow, ref, commit, runner); invalid, only when no subject
has the file's digest or the signature is not by the signer's key, which
no age of the trust explains (SC-PROVENANCE-INVALID, CRITICAL); unchecked,
for everything else, a log, authority or key the shipped trust does not
know among them (SC-PROVENANCE-UNCHECKED, INFO). The release before it
(npm: the highest lower SemVer version in the abbreviated packument, a
pre-release only for a pre-release; PyPI: the release uploaded last before
it, skipping releases whose every file is yanked) is compared: it had
provenance and this one has none, SC-PROVENANCE-DROPPED; both verified,
from repositories with different IDs (or URIs, without IDs) of different
owners, SC-PROVENANCE-REPO-CHANGED (both MAJOR; decision 13 asks whether
DROPPED should be CRITICAL). A repository of the same owner is INFO: on the
popular set's 1,205 releases the two changes of repository were both
within their owner (scikit-learn 1.9.1 from its release repository,
@rolldown/pluginutils 1.0.1 from a new plugins repository), and the one
drop was why-is-node-running 3.2.2, after two releases with provenance;
259 npm and 171 PyPI releases verified, none invalid or unchecked. The
trust is package data (`registry/sigstore/`: Sigstore's production
trusted root as sigstore-python 4.5.0 embeds it, npm's key list), checked
against recorded hashes by a test; a root only gains keys and authorities,
so an older copy can only fail to know something new, which is unchecked,
never invalid. Lazaret does no TUF: `LAZARET_SIGSTORE_ROOT` and
`LAZARET_NPM_KEYS` name copies fetched by something that does. Best effort
like SC-NEW-DEPENDENCY's history: a registry that does not answer flags
nothing, and the result's `provenance` says what was not checked. The
guard does not run it (its installs would wait on the requests).

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
are read for a fixed character span; brackets are matched in one pass; every
pattern runs in linear time (linre); a minified row is read once. When you add
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

A release's files share the engine's answers (0.1.9, P-2a:
`registry/contentcache.py`, one `Memo` per `scan_package` run): the
registry asks once about a file's first pass, the import-time test, the
scripts a script starts and the cross-file follower for content several of
the release's files hold. What is kept is the engine's raw answer, keyed by
the call, its arguments and the text (the engine reads no path; the
cross-file key is the files in order), never a verdict, and never an answer
the engine could not finish. So a hit changes the time and nothing else:
`test_content_memo.py`, and the benchmark scanned with the memo on and off,
hold that. A store that outlives the run is the next step (P-2b).

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
  Unicode-3.0`); a platform wheel adds the native library and the
  engine's notice, `rust/NOTICE` (the engine is Lazaret's own since P-16,
  with Unicode data); the npm package only `bin/`, `src/`, the engine
  (`native/lazaret.wasm` and its `native/NOTICE`, `rust/NOTICE`) and its
  license files (`NOTICE`, `LICENSE-UNICODE`). Every package is
  `Apache-2.0 AND Unicode-3.0`: the codec names the npm package and the
  dashboard list are facts about Python, not CPython's code.
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
| `python/src/lazaret/scanner/autorun.py`, `ghworkflow.py`, `gitlabci.py` | Editor and AI-agent settings that run commands (SC-AUTORUN), the workflows the Shai-Hulud worms planted (SC-WORKFLOW-SECRETS, -BACKDOOR) and the CI files' hardening checks (the other SC-WORKFLOW-* ids, SC-GITLAB-*); twins `js/src/lib/autorun.js`, `ghworkflow.js`, `gitlabci.js` |
| `python/src/lazaret/scanner/frameworks.py` | Which route handler parameters Flask / FastAPI / Django fill from the request (shared by both taint passes; twinned in `js/src/scanner/taint.js`) |
| `python/src/lazaret/scanner/sca_feeds.py`, `sca_index.py`, `gomod.py` | CVE bundle build (OSV/KEV/EPSS), the indexed bundle, the `go.mod` reader |
| `python/src/lazaret/{registry,mcp,pg,safexml}/` | Registry auditor, MCP server, Postgres client, safe XML |
| `python/src/lazaret/registry/guard.py`, `python/src/lazaret/_cli.py` | The install guard (`lazaret guard`) and the `lazaret` command's dispatch |
| `python/src/lazaret/registry/pmsettings.py` | The package managers' own settings as the guard reads them: registries, indexes, credentials by host |
| `python/src/lazaret/registry/goproxy.py`, `cargosrc.py`, `scanpool.py`, `ecosystems/` | The Go guard's proxy protocol, the Cargo guard's sources and lockfile, the guard's scan workers, the crates.io, Go module and Open VSX auditors |
| `python/src/lazaret/registry/sources.py`, `sourcescan.py`, `actions.py` | A repository at a commit (`lazaret scan github:…`), its scan and report `source`; a workflow's actions asked of GitHub |
| `python/src/lazaret/registry/extensions.py` | VS Code extensions: `lazaret FILE.vsix` and `lazaret --extensions` (the editors' installed extensions), read with the editor's rules for what runs |
| `rust/crates/lazaret-engine/src/lex/`, `goparse/`, `rsparse/` | The lexers (JavaScript, Python, Go, Rust), the Go parser and the Rust item reader, with their hooks (not used by a scan yet) |
| `js/src/lib/native.js`, `js/scripts/build-wasm.js` | The npm package's native engine (WebAssembly: the loader, one call, the pack's values) and its build (`npm run build`) |
| `js/src/lib/supplychain.js`, `js/src/deps.js`, `js/src/scanner/flow.js`, `js/src/index.js`, `js/src/pool.js` | Install-hook checks, `--deps`, flow twin, npm CLI, its worker threads |
| `python/tests/architecture/test_js_parity*.py` | The package-parity guards (need `npm run build`) |
| `rust/crates/lazaret-engine`, `lazaret-ffi` | The native engine (supply-chain tests, `scan_file`, the cross-file follower, linre, the rule pack: **the source of the rules**), its C ABI and its WebAssembly exports (`docs/RUST_ENGINE.md`) |
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

**After 0.1.8: popular packages' false positives.** A sweep of the latest
releases of 1,204 popular npm and PyPI packages found nine SUSPICIOUS
(vite, vitest, monaco-editor, future, sympy, ipython, kubernetes, coverage,
numba), each on a reading that took a library's ordinary code for a
dropper's. The data flow now reads an address as the script's own only
when it is text the script writes, local data or a global another file
defines, and no caller gives it (an object is no address), a server's events (not
the server) as what it receives, a Node module's objects as Node's
(`createHash(…).update` is no script's `update()`), `createRequire()` as a
require, a class made in several places as one container per instance, a
loop or an object that selects environment variables by name as that
selection, and a list's reversal as no decoder; SC-PTH-EXEC judges what a
`.pth` line's code does (an `exec` of a plain literal by the literal's
code; the network or another program at every interpreter start is
CRITICAL), `__doc__=` is no read of a docstring, and the cross-file
follower seeds a file only with the variables another file writes. None of
the 1,204 is SUSPICIOUS now.

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
  - **Members read through constants** (built in 0.1.9): a member named by
    a name bound once to a string (`x[N]`, a comma expression's last value
    included) and `require()` of such a name are read by that name, and the
    `request` client is a client; react-zutils 1.0.1 is SUSPICIOUS.
    cycalculator-ye51 posts one variable (`FLAG`, a CTF's) to an
    oastify.com address, which an SDK does with its key: WARN, by design.
- *What the in-sample misses show* (0.1.9, all 67 releases the benchmark
  doesn't call SUSPICIOUS read; 3 found since): another package's code
  rewritten at import time (@dinzid04/libsignal-node replaces a file of
  `@whiskeysockets/baileys`), a `.env` read under base64 twice and sent by
  a second file whose function a computed destructuring key imports
  (main-util-validation, at use time), JS-Confuser's string concealing
  (panel-keylogger-sim), a package manager install run at import time
  (crypto-hash-sdk), a `require()` of a package the manifest doesn't
  declare (dotenv-express), and a file written from a request callback's
  data, then run. The rest put their payload outside the release, are
  proofs of concept, CTFs or empty samples, or ship a compiled binary.
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
- *Instances in the data flow* (after the false-positive fixes above): a
  class made in several places keeps one container per instance, so a value
  given to one method from outside and run by another method of the same
  instance (`r.setCode(t); r.run()` where `run` evals `this.c`) is not
  followed, while a class made once still is. Reading `this` as a parameter
  of each method (sinks reached through it, what its methods store in it)
  would follow both without merging instances.
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
- *From the audit (P1/P2):* a public nightly benchmark, per-rule docs, a
  coverage gate and parser fuzzing in CI, optional live secret verification,
  splitting `core.py`, generating the dashboard's script from `js/src` (the
  GitHub Action was built in 0.1.8, and the pre-commit hook, `lazaret hook`,
  in 0.1.9; the npm package has no `hook` command yet).

Prefer doing detection extensions **reactively** — when a real-world dropper
uses the pattern — over speculatively. The bar that made this tool good is the
false-positive bar; keep it.
