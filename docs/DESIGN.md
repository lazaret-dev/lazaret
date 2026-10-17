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
JavaScript and SQL projects, plus a registry auditor for npm and PyPI packages,
Go modules, crates and VS Code extensions, and an install guard. It
ships as **two independently-installable packages that must behave identically**:

- **PyPI `lazaret`** — the Python package. Standard library only (its
  scanning engine is the native library every wheel carries). Console
  scripts: `lazaret` (project scan; `lazaret guard`, `lazaret hook`),
  `lazaret-registry` (package audit), `lazaret-mcp` (MCP server),
  `lazaret-sca` (CVE bundle + SCA), `lazaret-guard` (the install guard).
- **npm `lazaret`** — the Node engine. Zero runtime dependencies, ES modules.
  It is the **project scanner** (`lazaret <dir>`) and the commit-time gate
  (`lazaret hook`); registry auditing, the install guard, custom taint specs,
  SCA and the MCP server are Python-only.

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
   versions. A scan of the same bytes gives the same answer everywhere. The one
   exception is asked for by name: `--verify-secrets` (§5k) asks providers
   about the secrets a scan found, after the scan, and says so before it does.
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
what the native engine does not answer yet (the comment
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
- **The browser dashboard** (`python/src/lazaret/web/lazaret.html`) runs the
  npm package's scan on the engine it carries (BR-7 step 5, 0.1.9):
  `scripts/make_dashboard.py` builds it from `js/dashboard/`, the package's
  modules it imports (which therefore use nothing of Node's: the build
  refuses a `node:` import) and a build of the engine as WebAssembly, and
  pins the script by SHA-256 in its CSP. It is held to the CLI's results
  (`test_review_dashboard_parity.py`); after changing a module it imports,
  rebuild it, and after changing the engine, build the engine and rebuild
  it with `--engine` (`test_dashboard.py` fails until then).
- **The native engine** (`rust/crates/lazaret-engine`, 0.1.8) runs core's
  supply-chain tests — the install-script and import-time tests and
  everything they read — `scan_file` in dependency mode and in project mode
  (the passes after the rules too since 0.1.9's Q-1: the SQL statements
  without WHERE, the intra-file taint, the SQL sinks, the function metrics,
  the markers and the cap), findings included, and the cross-file follower
  (`cross_file`), with Python `re` semantics (linre, a linear-time engine
  with `re`'s answers, for every pattern) and its patterns and finding texts
  in a rule pack
  (`rust/crates/lazaret-engine/rules/lazaret-rules.json`, the source of the
  rules). It was ported from core function for function and held to it by
  differential tests on every field (zero differences) until the Rust-first
  refactor retired the Python engine; now it is the only engine. The Python
  package sends all of them through it (`lazaret.scanner.engine`), and the
  npm package (0.1.8) runs it as WebAssembly (`js/native/lazaret.wasm`,
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
  directly in scan logic. An archive member's name is compared as file systems
  that ignore case compare it by the engine's fold (`engine.case_fold`: NFD or
  NFC, then `str.casefold()`, on the same 13.0 data; BR-2), not the host's.
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
  report, the baseline fingerprinter, or the registry store. There is one
  redactor, the engine's (`redact.rs`, `findings.rs`; since BR-7's step 3 c),
  for the findings it makes and the ones the packages build (`mk_issue`,
  `redact_result`, `redact_file_issues`, and their npm callers).
  `--no-redact-secrets` keeps credential lines in a project scan's reports
  (registry results are always redacted); `--show-secrets` prints each
  finding's flagged line as read on a terminal, kept apart from the result
  (`core.flagged_lines`), so nothing written ever holds it.
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
   size caps, binary/pyc/symlink/encoding checks), each source file decoded as
   its interpreter reads it by the engine, for both packages since BR-7's step
   4 (b) (`rust/crates/lazaret-engine/src/decode/`, the `decode_source` call:
   the BOM and NUL sniff, PEP 263 cookies, every text codec Python has);
2. **scans each file** (`scan_file`) — rules, intra-file taint, SQL sinks,
   obfuscation/secret detection, per its language — and each config or data
   file (`scan_config_file`: `.env`, JSON, YAML, TOML, INI, shell, keys,
   Dockerfiles) for credentials, read by the engine for both packages since
   BR-7's step 3 (`rust/crates/lazaret-engine/src/config.rs`, the `scan_config`
   call: S-TOKEN and S-SECRET's config form, the suppression markers, the cap
   and the snippets, redacted by the engine's one redactor; which files are
   config files is still each package's, `configsecrets.is_config_file` and
   `js/src/lib/configsecrets.js`); config files are not code and count in no code metric. Two
   kinds get more (0.1.7): an editor's or AI agent's settings that run commands
   on their own (SC-AUTORUN: a JSON-with-comments reader that keeps lines, and
   what each file makes its tool run; the commands are followed into the files
   of the tree they run and judged by the install-script test; the engine's for
   both packages since BR-7's step 2, `rust/crates/lazaret-engine/src/autorun.rs`,
   the `autorun_*` calls: it names the files of the tree it follows a command
   into, and the package reads them with `tree_reader` and asks again), and CI
   files: GitHub Actions workflows (SC-WORKFLOW-*) and GitLab CI files
   (SC-GITLAB-*), read by the engine for both packages since BR-7
   (`rust/crates/lazaret-engine/src/ci/`, the `ci_*` calls: an outline reader
   of the YAML a pipeline needs, not a YAML parser; `core.ci_issues` and
   `scan.js` `ciIssues` shape what it answers into issues);
3. **scans manifests** (`package.json`'s install hooks and dependencies from
   an insecure source, `binding.gyp`'s actions and command expansions), read
   by the engine for both packages since BR-7's step 3 (b)
   (`rust/crates/lazaret-engine/src/manifest/`, the `scan_manifest` and
   `scan_gyp` calls: a package.json as `json.loads` reads it, a .gyp file as
   JSON or else as the Python literal gyp reads, `ast.literal_eval` on the
   engine's Python parser); `core.load_manifest` keeps the data the
   registry's and `--deps`' decisions read (the npm package asks the engine,
   `manifest_data`);
4. **runs `--deps` checks** (`dependency_checks`) — what dependencies run at
   install and import time (install hooks followed to the files they run,
   import-time received-code, and the cross-file follower); the decisions are
   the engine's (`deps.rs`, BR-7 step 3 e), which asks for what it needs to
   know of the tree and is answered (`_DependencyTree`);
5. **runs the interprocedural flow engine** (`lazaret_flow.analyze`), guarded so
   a failure degrades to the intra-file engine with a visible warning;
6. **adds coverage notes** (skipped trees, symlinks, unreadable/truncated);
7. **computes metrics, ratings and the quality gate**, then
8. **sweeps everything for secrets** and returns `build_result(...)`.

`build_result` returns the dict the CLI and MCP serialize: `project`,
`metrics`, `counts`, `ratings`, `supplyChain`, `crossFile`, `perFile`,
`issues`, `warnings`, and (when a stop budget fired) `incomplete`. Since
BR-7's step 4 (a) its grading is the engine's (`result.rs`: the `result`,
`regrade` and `project_metrics` calls), for both packages: the findings'
order, the counts, the three ratings, the gate's conditions, the
supply-chain indicators and cross-file flows, the findings by file and the
duplication across the files. A package hands it each finding's rule, type,
severity, file, line and a Q-CAPPED note's count, and each file's line
metrics, and keeps the project's path and the time.

---

## 5. The detection engines, in layers

### a. Intra-file rules and taint

Per-file pattern rules (SQL sinks, obfuscation, secrets, look-alike identifiers,
hidden Unicode, packed/hex-escape building, `.pth` execution, UTF-7/escape
codecs, binary artifacts) plus intra-file taint that follows request-shaped
input (`request.*`, `req.*`, `argv`, decoders) through assignments, f-string
and template-literal fields and multi-line statements into sinks (SQL,
command, code, path traversal, SSRF, open redirect, XSS — Flask/Django
responses and a Flask view's return value —, SSTI; since 0.1.9, Q-2, the
session's keys and values, LDAP searches in a file that imports an LDAP
client, XPath expressions). Only a sink's injectable arguments are read (a
row's seventh field names them where the category's default does not fit:
an XPath call's expression and not its variables, the rest of a
`session[k] = v` statement); path guards that leave clear path traversal; a
taint is scoped to the function body (by indentation) it was made in, and a
reassignment in the same block replaces it. A Python `for` statement binds
its targets as an assignment of what it iterates over would (0.1.9).
Containers (`d["k"] = q`, `xs.append(q)`, Python's `conf.set("s", "k", q)`)
take the taint of what is written into them, by literal key, read back by
subscript or by `get()` of the same literals; allowlist checks clear a value
where it passed. A check of a parsed URL's host against a collection (0.1.9,
Q-5: `urlparse(u).netloc in ALLOWED`, `p.netloc` for `p = urlparse(u)`, `h`
for `h = urlparse(u).netloc`, `.hostname`, `urlsplit`) clears the URL for the
redirect alone: in the `if`'s block when the whole test needs it (an `and`
of it, no `or`), after a block that leaves when a `not in` is an `or` of the
test, alone; read while the URL and the parsed result are the ones assigned,
in one function. A substring test of the raw URL or of the host
(`'example.com' in u`, `startswith`, `… in 'example.com'`) clears nothing.
After the taint pass, Python's cookie pass (0.1.9, Q-2,
S-COOKIE) reads each `set_cookie` call's arguments for its Secure flag. Framework models (0.1.7):
the parameters a route handler gets from the request are sources — a Flask
view's URL variables, a FastAPI path operation's parameters (not injected
dependencies, not types that validate to no free text), a Django view's URL
parameters. The decisions over a parameter's name, annotation and default
live in the engine's `pyflow/frameworks.rs`, which both taint passes read:
the intra-file pass takes a handler's signature from text (`taint.rs`), the
cross-file pass from the tree; `test_pyflow_frameworks.py` holds both to the
decisions recorded from `lazaret.scanner.frameworks` when it was retired
(0.1.9, Q-1), so both passes agree on what a handler receives. Comments
are **lexed, not guessed** — block-comment/string/template state is tracked
across lines, and a line counts as a comment only if all of it is, and only if
both readings of ambiguous text agree.

**Go and Rust (0.1.9, S-4).** A project's `.go` and `.rs` files are source
(`core.EXTS`, `collect.js` `EXTS`): their comments and literals come from the
engine's Go and Rust lexers, and they get the rules whose `langs` list them
(S-SECRET, S-TOKEN, S-BIDI, Q-TODO) and the families every text gets. No
taint, function metric or supply-chain detector reads them yet. Two limits
are deliberate until the Go and Rust detectors exist: a package's Go and
Rust files (registry and guard scans) and a dependency tree's (`--deps`)
are not read (`core.DEP_LANGS`, `dep_source_lang`): reading them for
secrets alone would add findings a consumer cannot act on and say nothing
about what their build scripts and initializers run; and their lines are
left out of the duplication measure (the engine's `metrics::measured_lang`), whose 10% gate was
set on Python and JavaScript (Go's standard library measures 2 to 13% with
its six-line windows, popular crates 4 to 54%), while they count in the
lines of code the maintainability rating divides by.

**CI files' hardening (0.1.9, S-4).** `scan_config_file` asks the engine for
a CI file's issues (`ci_issues`: on a workflow its findings, then its
hardening checks; on a GitLab CI file its checks), each with its rule from
the rule pack (the engine's since BR-7; until then `ghworkflow.py` and
`gitlabci.py` and their npm twins). These are
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
one package, the engine's `deps_files`), and a release's
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
s1ngularity/Nx attack). A shell script is read without its comments (0.1.9,
SH-COMMENT-FP: a `#` that starts a word outside quotes, here-documents and
arithmetic, to the end of its line), unless it reads its own file (`$0` or
`$BASH_SOURCE` given to a program that reads it), whose comments may be what it
runs, or does not read to its end. A package with a
`binding.gyp` and no install script gets the implicit `node-gyp rebuild` hook
(MAJOR). Also: look-alike identifiers (SC-HOMOGLYPH), hidden-Unicode carriers
(SC-HIDDEN-UNICODE), decode-then-execute (SC-EVAL-DECODE, incl. indirect eval).
Every other JavaScript and Python file of a dependency gets the import-time
test, but (the detection round) not a web app's static assets: a JavaScript
file in a `_next`, `static` or `public` directory of its package that none of
its npm package's entry points reach — main, module, bin and exports, then
what they require, import or start with node (the engine's `deps_files`) — is
left out of it and of the follower (litellm's proxy UI).

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

Agent configuration (0.1.9, RA-2; `autorun.rs`, for both packages). The
settings files were read for the commands they run; three more questions
are asked of them. Where a file sends data (SC-AGENT-ENDPOINT): a remote
MCP server (a server with no `command` and a `url`, Windsurf's `serverUrl`
or Gemini CLI's `httpUrl`), an HTTP hook (`type: "http"`, which posts each
event's input), an MCP bundle a plugin downloads, and a model provider's base
URL set in `env` to a host that is not the provider's or this machine
(`_AGENT_BASE_URL_ENVS`, `_AGENT_PROVIDER_HOST_RE`), MAJOR; the others INFO,
MAJOR at a tunnel or data-capture service (`_AGENT_TUNNEL_HOST_RE`), a raw IP
address, or plain http or ws to another machine (`url_risk`; a name with no
dot or a .local, .internal, .lan or .home.arpa one is the local network's,
and a URL whose host the tool fills in is not judged). What it lets the agent
do (SC-AGENT-CONFIG, in HARDENING_RULES: reported, and counted against the
gate only when CRITICAL): `permissions.defaultMode: bypassPermissions`, allow
rules that reach the network or run anything (`_AGENT_WIDE_ALLOW_RE`),
`enableAllProjectMcpServers`, VS Code's `chat.tools.autoApprove`, and a
hook whose command or file prints an approval (`_AGENT_APPROVE_RE`), MAJOR;
plugin marketplaces and plugins a project adds, INFO (MAJOR from an insecure
URL). An approving hook is MAJOR, not CRITICAL: on the popular repositories'
agent files one (pure-rand's npm-to-pnpm.sh) approves every Bash call it does
not rewrite, which is the bypass the other settings are, not a payload.
Claude Code's plugins are settings files too (`claude-plugin`,
`claude-marketplace`, `claude-hooks`, `claude-monitors`, `claude-lsp`): a
manifest's hooks (an event map with no wrapper, or an array of them and
paths), MCP and language servers, monitors and subagent status line, and the
files its paths name, read from the tree (`plugin_refs`, `referenced_entries`:
each command at the line of its path); their folder is the plugin's root
(`owner_dir`), which `${CLAUDE_PLUGIN_ROOT}` names. Of a command: a hook's
exec form is read with its `args`; a hidden file outside the repository that
it runs (`hidden_outside`: a home, temporary or absolute path with a dotted
component, a toolchain's folder aside) is MAJOR, since the scan cannot read
what runs; and one that writes the agent's permissions
(`signs::writes_agent_permissions`: an agent's settings file written with a
permission key, `_AGENT_PERMISSION_KEY_RE`) is CRITICAL, unlike a copy of the
settings a worktree hook makes.

Agent skill and instruction files (0.1.9, RA-3; the engine's `agentdoc.rs`,
for both packages): an AI agent reads a `SKILL.md`, `AGENTS.md`, `CLAUDE.md`,
`CLAUDE.local.md`, `GEMINI.md`, `.github/copilot-instructions.md`,
`.github/instructions/**/*.instructions.md`, `.claude/commands/**/*.md`,
`.claude/agents/**/*.md`, `.cursorrules`, `.cursor/rules/**/*.md|*.mdc` (and a
`.cursor/rules` file), `.windsurfrules`, `.windsurf/rules/**/*.md` or
`.clinerules` (a file, or a folder of `.md`/`.mdc`/`.txt` files) as
instructions and does what it says (`agentdoc::is_agent_doc`), so a dependency
that ships one turns the agent into its installer past a code-only scanner (the
clawdhub campaign's `SKILL.md`, Snyk Feb 2026, lured the agent to a glot.io
snippet that ran `base64 -d | sh` and fetched a second stage from a raw IP,
with a password-protected GitHub-release archive to hide the payload).

Where they are read. A project scan routes them to the config bucket
(`collect.rs`, by name before a `#!` line can make one a script), as workflows
are, but not to the config credential pass — a `CLAUDE.md` example is no
S-TOKEN. A dependency's are routed too, with `--deps` (a `node_modules`,
`site-packages` or vendor tree's file; the bucket's entry says `dep`), while a
dependency's other config files stay unread. The registry and the guard read
the members of the packages they scan (npm, PyPI wheels and sdists, crates, VS
Code extensions: `_ArtifactScan._agent_docs`, a phase of the second pass). The
MCP server's `scan_files` reads one by its name.

The reading. The reader pulls the file's candidates: fenced blocks whose info
string names a shell, PowerShell (`powershell`, `pwsh`, `ps1`) or cmd
(`cmd`, `bat`), or none or `text` — read whole whatever their lines look like
—, indented code blocks, inline code spans, and the text of HTML comments
(hidden from a human reader); each is read with the hook-command test
(`shell::hook_command_risk`), one longer than HOOK_MAX_CHARS in pieces cut at
line ends (a line longer than that in pieces of its own), and a block too long
for a message is reported at the line that reads hostile on its own. Fenced
`python` and `js`/`ts` blocks get the install-script test in their language. A
command that runs a script of the skill's own folder (`_AGENTDOC_LOCAL_SCRIPT_RE`:
after an interpreter and its flags — `bash -e`, `python3 -u`, `uv run`,
`npx tsx`, `pwsh -File`, `.`, `source` —, as `./x`, or a bare `scripts/x.sh`
at a command's place; resolved under the file's directory after the relative
`cd`s before it, `_AGENTDOC_CD_RE`) is followed through the tree and read with
the install-script test in its language (Python, JavaScript for .js and .ts,
text for a shell, PowerShell, Ruby or Perl script); a dependency's script the
walk did not keep (a `.sh` in `node_modules`) is read from the disk, through no
link (`core._disk_reader`, `deps.js` `diskReader`). The whole text is also read
for a password-protected archive (a download and a stated password — `the
password is`, `password:`, `pass:`, `pw:`, `with password X`, `unzip -P`, `7z
-p` — in one paragraph, `_AGENTDOC_ARCHIVE_RE`/`_AGENTDOC_PASSWORD_RE`), a
paste or snippet host (`_AGENTDOC_PASTE_RE`), a public raw IP as an install
source (a loopback, private, link-local or unspecified address is none, and
neither is a reason of the hook-command test that only contacts one), text
hidden from a human reader (invisible carrier characters,
`scanfile::hidden_unicode_run`; a run of three or more zero-width characters;
bidirectional overrides and isolates), and an order to send the conversation,
the environment or credentials out (`_AGENTDOC_EXFIL_RE`, dotted names such as
`.env` and `~/.ssh/id_rsa` included; an order negated in its sentence — "do not
send", "never upload", "don't share", `_AGENTDOC_NEGATION_RE` — is none). An
order is a hostile shape when its paragraph names an address (a capture or
exfiltration service, a public raw IP, a URL that is not this machine's or a
private network's), a weaker indicator without one.

What it counts for. One SC-AGENT-SKILL finding per file, at the first chosen
reason's line. A dependency's file is CRITICAL when any reason is a hostile
shape (a command or code block the tests flag, a followed hostile script, a
password-protected archive, an exfiltration order with an address) and MAJOR
for a weaker indicator alone (a paste host, a raw IP, hidden text, an order with
no address); it fails the gate, and a registry package with it is SUSPICIOUS.
The commands keep the hook-command test's semantics: a dependency's skill that
pipes a download into a shell is CRITICAL from an official installer's host
too, as its install hook would be. The project's own file is INFO, with what
was found in its message ("the project's own: listed, not counted") and a fix
text of its own: the gate (`--ci`, `lazaret hook`, the result's "No
supply-chain indicators") reads SC-* findings above INFO only, and a project's
`CLAUDE.md` that installs rustup, uv or Homebrew is its developers' own. A
clean skill file is no finding.

Workflows that send secrets out (0.1.9, RA-1; the engine's `ci/exfil.rs`,
for both packages: `ghworkflow.exfil` asks it): GhostAction's workflows named the
secrets they sent, or sent what `grep` found in the checkout and `git log -p`,
so SC-WORKFLOW-SECRETS (`toJSON(secrets)`) read neither. Each step's script is
read as the shell reads it, as far as the question needs: logical lines split
into pipelines at `;`, `&&`, `||`, `&` and `|` outside quotes and `$( … )`;
words with their quotes taken off and redirections apart (`<`, `<<` with its
here-document, `<<<`, `>`, `>>`); each `${{ … }}` replaced by a mark first,
since the runner pastes it in before the shell reads the line. What a word
holds is a set of secret names and, when it carries one, a credential search's
output: its expressions' `secrets.X` (and `env.Y`), the variables it reads
(the script's own assignments, then the step's, job's and workflow's `env:`),
and the output of what it substitutes, read to `_WFX_DEPTH` (4) levels. A
command's output carries its input and what its words hold (a send's output
is the answer, and carries nothing); a dump of the environment (`env`,
`printenv`, `set`, `gci env:`) carries every secret of it; a search for
credentials (`grep`, `rg`, `git grep` with a credential pattern, `git log -p`)
its own text. Files a job's steps write keep what was written to them. A send
(curl, wget, nc, socat, a redirection to `/dev/tcp`, `Invoke-WebRequest`,
`Invoke-RestMethod`; `xargs` handing its input on) gathers what it sends —
its body, its query, a header that is not a credential's, a file it uploads,
its input — and reads it once its address is known: a header or a query
parameter whose name is a credential's is not counted, and neither is a
body's field that is (`client_secret=`, `"password":`) when the address is
https to a named host; an address that comes from a secret is the
repository's own service (nothing counted), the runner's own (localhost, a
private address, a name without a dot: a service container) too, and a secret
whose name names an https host (`DOCKERHUB_TOKEN` and hub.docker.com) is for
it. The rule rates what is left: CRITICAL to plain HTTP (or a
raw socket), a raw IP address or a data-capture service (`capture_service`),
or two secrets or more in one request, MAJOR otherwise; a search's output
sent, CRITICAL. A logical line over `_WFX_LINE_MAX` (100,000 code points) is
not read. Not read: scripts in other languages (`python -c`, an inline
`actions/github-script`), a variable handed between steps through
`$GITHUB_ENV`, a composite action's steps.

Bulk secrets use positive clearance (WF-SECRETS-SCOPE, rule set 2.89.0).
`ci/exfil/scope.rs` tracks `Content.all` and its originating finding lines.
Each source stays CRITICAL when it reaches a send, or any reachable send-capable
step is not fully understood. `_WF_NETWORK_RE` is restored as the starting set;
opaque inline interpreters, shell evaluation and sending CLIs extend it.
Unsupported network options and unresolvable paths cannot establish clearance.
`secrets-sent` and `secrets-uncleared` are internal signals, folded by source line
into the original finding, with different messages for proof and uncertainty.
The reader follows static or dynamic GITHUB_ENV names, step GITHUB_OUTPUT values,
`${{ env.X }}`, and job outputs in needs order. Workflow/job/step overrides remove
the replaced taint. A job's files never leak into another job. Proven exposure
wins over an uncertainty reason; loopback sends of the complete object count too.
Named-secret service exemptions remain unchanged and cannot hide bulk exposure.

Upload matching normalizes dot components and workspace references without merging
absolute paths with workspace-relative paths. A glob matches its literal prefix;
`.`/`./`/`./**`/`*`/`**` and a missing path cover the workspace. Flow-form `with`
is read. Unknown variables and home expansion remain unresolved. `!` exclusions
are intentionally ignored, so they cannot prove clearance. Unmodeled file copies,
archives, working directories and control-flow retain uncertainty.

The held-value case, unrelated GETs, unrelated uploads, uploads before a write,
and a literal jq-selected key used as an Authorization credential stay MAJOR.
Download-only requests are cleared when they do not carry the complete object.
`github-script`'s script input is executable and conservatively uncleared;
ordinary action inputs remain outside this rule. Repository scripts and test
runners (`python x.py`, `npm test`, `make`) are not opaque senders: their code is
scanned separately. This is a residual risk: the workflow reader does not model
arbitrary code inside those programs or arbitrary action implementations.
The synthetic suite establishes these semantics; the 23,202-file real-world
measurement and malware benchmark/holdout runs are owed (John).

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

The install-script test gained two more reasons in 0.1.9 (RA-12, RA-11).
*TLS certificate verification turned off* (`_CERT_OFF_RE`, matched in code —
the lexers blank a JavaScript or Python text's comments, and Python's
docstrings, before the pattern reads it, so a mention in a comment is not a
reason — case-sensitively over every language and the shell: Python
`verify=False` / `ssl._create_unverified_context` / `CERT_NONE` /
`check_hostname=False`, Node `rejectUnauthorized: false` /
`NODE_TLS_REJECT_UNAUTHORIZED=0` / `strictSSL: false`, Go `InsecureSkipVerify:
true`, Rust `danger_accept_invalid_certs(true)` /
`danger_accept_invalid_hostnames(true)`, and `GIT_SSL_NO_VERIFY`,
`http.sslVerify=false` (git reads its config keys in any case, so this key —
and a URL's `http.<url>.sslVerify` — is matched in any case, the only part of
the pattern that is; and the `git config … false` space form),
`npm config set strict-ssl false`, `wget --no-check-certificate`, `curl
--insecure`, and a `curl` short-option cluster ending in `k` whose gap to the
option stops at a shell separator) — before 0.1.9 only a project-mode SAST rule
for a project's own Python saw it, so a dependency's build script that disabled
it went unremarked. A script's comments are blanked in the lexer of its real
language (`signs::comment_lexer`): its `#!` line's when it has one (node and
the other JavaScript runtimes, Python; a shell's comments are blanked by the
shell reader before the test reads the script, and any other program's are not
blanked), else the language `deps::script_lang` gives its file by extension
(`_SCRIPT_LANG_EXTS`: `.js` `.mjs` `.cjs` `.jsx` `.ts` `.mts` `.cts` `.tsx`
JavaScript, `.py` `.pyw` Python, `.sh` `.bash` `.zsh` `.ksh` `.dash` `.ash` a
shell, `.cmd` `.bat` a batch file — read without its `REM` and `::` lines,
`signs::bat_without_comments` — and `.ps1` `.pl` `.rb` `.vbs` … another
language, not blanked), a file with none of those extensions by its `#!` line,
else as JavaScript (what node runs). So a shell script's or a batch file's
`https://…` is not taken for a JavaScript comment. It is a **weaker** reason:
it is read only at install and build time (never at import time, where a
library's `verify=False` option is not an indicator), and a finding whose only
reason is it is MAJOR, not CRITICAL — a package to review, not an exfil on its
own. `signs::install_script_severity` (`core.install_script_severity`)
decides that for every finding the install-script test makes — an install
hook and the scripts it runs, an sdist's `setup.py`, a build script or
procedural macro, a start-up module, a `.pth` line, what an editor's or
agent's settings run, an agent doc — returning CRITICAL when any reason is
strong, MAJOR when every reason is a weaker one (`_WEAK_INSTALL_REASONS`), and
None for no reasons (the finding's own severity stands). A weaker reason never
hides a strong one: what an editor's or agent's settings run (`autorun.rs`)
is followed past a command's or a file's weaker reason to the files it runs
and the scripts they start, and the first strong reason stands (else the first
weaker one); an install hook followed to the files it runs (`--deps` and a
project's own hooks, `deps.rs`; the registry's `_follow_hooks`) names a file's
weaker reason in its MAJOR finding (`Install hook runs setup.js, which turns
off TLS certificate verification.`) and is CRITICAL for a strong one in any
file it runs, whichever comes first; an agent doc, a build script, a `.pth`
line and a start-up module read every reason before their severity is
decided. *A Windows Script Host launcher* (`signs::runs_wsh`, mirroring
`runs_dll`): `wscript`, `cscript` or `mshta` (`_WSH_LAUNCHER_RE`, in any case,
a drive, a path or `%SystemRoot%\` before it; not a file named after one,
`check-wscript.js` or `wscript.js`) launching a script, a *strong* (CRITICAL)
reason of the install-script test only. It is a launch only where the
launcher runs (`wsh_launch_at`). In shell text — a hook's command, a shell
script, a batch file, or the text of a string — the launcher is at a command's
start: a line's or the string's, after `;` `&` `|` (so `&&`, `||`) `(` `)` a
backtick or `$(`, or after a wrapper that runs the command it is given
(`_WSH_WRAPPERS`: `cmd /c`, `start ""`, `call`, `powershell -c`,
`Start-Process -FilePath`, `sh -c`, `exec`, `then` …: the command's first word
a wrapper and the last before the launcher a wrapper, its option or a quoted
title), and a string so placed stands where a command line does — as a
shell's command (`sh -c '…'`), or where code puts one (an argument, a list
element, a value assigned, joined or returned; not a word's argument such as
`echo '…'`). In code the launcher is also the program of an exec call in argv
form, a list's first element or an exec call's first argument
(`_WSH_EXEC_RE`: `spawn`, `execFile`, `subprocess.run`, `Popen`,
`Command::new` …). Its options (`//nologo`, `//B`, `//E:jscript`, `/e:…`,
`-ArgumentList`) are skipped, and its first other argument, on the same line
(an argv's elements may be on lines of their own), must be a script file with
a stem (`.vbs` / `.vbe` / `.js` / `.jse` / `.wsf` / `.wsh` / `.hta`:
`_WSH_SCRIPT_RE`), or any file once `//E:` names the engine, or not a literal:
a variable or a call (`subprocess.run(['wscript', p])`), a template's `${…}`
(`` `cscript ${f}` ``), an f-string's `{…}`, `%f%`, `$f`, or what is joined to
the string after it (`cp.exec('cscript ' + path.join(__dirname, 'x.vbs'))`).
A launcher named in prose (`run cscript setup.vbs to finish`, `echo please run
cscript setup.vbs`, `Usage: cscript tool.vbs`), in a comment, in a LOLBin list
(`['mshta.exe', 'wscript.exe']`), or followed by its script on the next line is
not one. The reason shows the launch alone, on one line — the launcher, its
options and that argument (`runs a script with the Windows Script Host
(cscript + path.join(__dirname, 'x.vbs'))`). The text is lexed only when it, or
its string pieces joined (`'wsc'+'ript x.v'+'bs'`), name a launcher, and the
pieces are joined once for this and the DLL launcher. Both are the single techniques of the proc-macro1 /
arrayref build-script shape (a build script that fetches a stage over a
connection with certificate checks off, drops it and runs it), each pinned by
an inert test in `rsread/tests.rs`.

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
   a reason found there names a line of the file. Since 0.1.9 (D-11) it also
   reads JS-Confuser 2's string concealing (Rust `jcstr.rs`): each
   `F(start, length)` is its slice of the file's one long string, decoded
   with base91 over the alphabet its decoder shuffled, written where it
   decodes to UTF-8; as a string array is, code built around it is a sign
   of its own (`concealed_strings_line`, `_JC_TECHNIQUE_REASON`: CRITICAL at
   install, a strong import-time reason; rule set 2.78.0).
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
than --min-age). SC-NEW-INDICATOR (0.1.9, `registry/prior.py`, called by
`scan_package` through `_release_findings`; John, Oct 14: "if the latest
release has findings then we review the prior release vs it"): a release
whose files have weaker indicators only is compared with its established
predecessor, the newest release published at least `prior.GAP` (7 days)
before it, a pre-release only for a pre-release (npm: the packument's
times; PyPI: the Simple API's upload times, and the predecessor's file of
the same name with the version changed, else the first of the kind;
crates: the index's publish times, a yanked release none), scanned as the
release's files were (`_scan_artifact`, the run's memo shared, so the
files the two have alike are answered once); each weaker indicator's rule
the predecessor has no finding of, but those of what a release may well
ship anew (`NOT_COMPARED`: SC-BINARY, SC-OPAQUE-BLOB, SC-NESTED-ARCHIVE, and
SC-NESTED-CODE, which generated code can be: JS-NEST), is CRITICAL. Nor is an install hook the install-script test reads clean
(NEW-HOOK-FP, rule set 2.86.0; John, Oct 15: it stays MAJOR): the registry
scan marks a MAJOR SC-INSTALL-HOOK `readClean`
(`_ArtifactScan._hooks_read_clean`, after the phases) when its command runs
files of the package and nothing else (the engine's `hook_runs_only_files`:
each command a file run with node, a JavaScript runtime, a shell or Python,
or by its path; `cd`, a wrapper such as `env` and `_HOOK_INERT`'s builtins
aside), names no download or evaluation tool (`_hook_is_suspicious`), the
walk is complete, each file is one the package holds and was read, and none
of them, nor the modules they load (`_reach_of`), has a supply-chain
finding of its own; `prior.candidates` passes it over, and the guard keeps
it so in a verdict's rules (`guard.rules_of`: read clean only when each of
the rule's findings is). A new hook with an indicator of its own is still
compared. Best effort: a history over `MAX_HISTORY_BYTES` (16 MB), a
registry that does not answer, a predecessor's file whose digest is not
the registry's or whose scan was not complete, is no finding, and the
result's `priorRelease` says what was compared (`notCompared` and why).
`LAZARET_NO_PRIOR_RELEASE=1` turns it off, as `LAZARET_NO_DEPENDENCY_HISTORY=1`
does; the tests turn it off (`tests/__init__.py`) but its own. The popular
set's 42 WARN releases (Oct 15): 33 have only rules not compared, 7 had a
finding of each rule in their predecessor, pnpm 12.8.1's new postinstall
(against 11.27.1) was the one SC-NEW-INDICATOR, and vite's packument (39 MB)
is over the budget; since NEW-HOOK-FP (Oct 16) pnpm's hooks are read clean
and the release WARN, and the 41 others compare as they did. `bench.py prior`
measures it on a run's WARN releases, which `run` (the files alone) does
not. The guard runs it (`guard.with_prior`, `prior.compare` over its
fetcher and scanner) on a WARN release from npm's or PyPI's public
registry in the provenance window (`PROVENANCE_DAYS`), from the lockfile
and through the pip index, and since RA-8 (0.1.9) on a WARN crate from
crates.io's own index too (`check_crate`, gated on `registry.default` and
not under `cargo --offline`, which asks the network nothing; crates have
no provenance, so only `with_prior` runs — `prior.ECOSYSTEMS` already held
crates, and the Cargo guard was the one caller that never asked; the
index is read by `prior._crates` over the crates module's own fetch, as
`lazaret-registry` reads it, and the predecessor's `.crate` is checked by
the module's own digest, `repo._module_digest` against the index's
`cksum` — `verify_digest` reads npm's and PyPI's fields only — and its
verdict kept under that SHA-256, as `check_crate` keys a crate's; a file
that does not match its digest, in any of the three, is a DigestError:
not compared, `notCompared`, the release keeps its verdict, and neither
the file's verdict nor the comparison is cached): the scan's answer keeps its findings' rules
(`rules_of`: the first finding of each, in short), the verdict cache keeps
them and the comparison once made (`_prior_kept`; one the registry did not
answer is made again, from the cached rules), and the predecessor's file
is fetched, checked against the registry's digest and scanned like any
other, its verdict cached under its own key. SC-NEW-COMPILED-CODE (RA-13,
0.1.9; John, Oct 15) is a narrower comparison over the same machinery,
asked of a release that is not SUSPICIOUS (`prior.strong`), OK ones
included: `_ArtifactScan.compiled` (`repo._compiled_code`: a binary member
whose first bytes are an ELF, Mach-O or PE program — not a WebAssembly or
DEX module, nor a Java class — or one named `COMPILED_CODE_EXTS`, .so,
.pyd, .dylib, .dll, .node, .exe, whose bytes are not text) is a file's
`compiledCode` (`MAX_COMPILED_LISTED`, 50) and its `artifacts` entry's; a
release whose files list some (`prior.compiled_files`) is compared kind by
kind, like with like (`_compiled_plan`): the predecessor's files of the
kind, and a wheel of them whose tags are not pure Python's
(`compiled_by_name`: an ABI tag other than `none`, or a platform other
than `any`) ships compiled code by its name, nothing of it downloaded;
else the counterparts of the release's compiled files (the same name with
the version changed, else the first of the kind, `MAX_FILES`) are scanned
with the files the weaker indicators asked for, once, and the release's
compiled code is new when none of them lists any (`_new_compiled`). It is
MAJOR, CRITICAL beside an SC-NEW-INDICATOR, and names `COMPILED_NAMED` (3)
of the files; `priorRelease` gains `newCompiledCode` when it was asked.
Shai-Hulud's PyPI wave (June 2026: `ensmallen_*.abi3.so` beside a .pth
loader, in pure-Python packages) and GlassWorm v2 (April 2026: six of 73
Open VSX extensions activated by updates that brought .node binaries)
are its shape. `scan_file` answers (rules, compiled code) now; a set
alone is the rules with the compiled code not known. Open VSX and the
Marketplace are `prior.ECOSYSTEMS` (RA-13): `prior._extension` reads the
module's `history` (each version's earliest time across its platforms, a
pre-release flag) over `History.module_fetch`, shared with
SC-NEW-DEPENDENCY's (`new_dependency_issues` passes the History's fetch;
`_OnceFetch` keeps a POSTed query too, so the Marketplace's one query
serves the history and the predecessor's resolution), and the
predecessor's files are `module.resolve`'s (each Open VSX file with its
SHA-256; the Marketplace's unverified, as the release's). The guard:
`_scan_one` keeps `compiled` (`compiled_of`, `COMPILED_KEPT` 5, [] for
none) and the verdict cache stores it; `prior_due` takes an OK or WARN
verdict whose file ships compiled code as well as a WARN with rules;
`prior_scanned` (shared by `_prior_scan` and the editor guard) scans a
cached predecessor again when its verdict has no `compiled` (cached before
RA-13: its absence is not none); `with_release_issues` makes a CRITICAL
SUSPICIOUS and a MAJOR an OK verdict WARN. `lazaret guard <editor>`
(`editorguard.Run._take`) compares an extension from its gallery in the
window (`prior_due(hit, published, True)`) over its own fetch
(`prior.History(fetch)`, `Run._prior_scan`: the file checked by the
module's `verify`, its verdict cached by its SHA-256 as an extension's
is), for an install or an update alike. Cost: the history document and at
most `MAX_FILES` of the predecessor's files for a release with compiled
code (none when the predecessor's wheels are platform wheels); not measured
on the popular set yet. SC-YANK-TO-PUSH (RA-10, 0.1.9,
`registry/yanks.py`, MAJOR): a crate release whose publisher (its publish
action's user, else `published_by`; one account by id, else login) yanked
`YANK_COUNT` (2) or more of the crate's stable versions before it by
SemVer, within `YANK_WINDOW` (a day) of its publication, either side,
each yanked still (its last yank or unyank a yank), read from crates.io's
version records (`/api/v1/crates/{name}/versions`, `audit_actions`). One
yank is not it: a maintainer yanks the broken release its fix replaces.
It is a release-level finding (file `(release)`) that `_release_findings`
adds before the comparison, and the comparison asks about it as a weaker
indicator: `prior.compare`'s `own` is {rule: test(predecessor)} for such
findings (`yanks.own`: `reason` of the predecessor, from the same
records), nothing of the predecessor downloaded for them; a finding of
the release's own without a test is not compared. So it is SC-NEW-INDICATOR
(CRITICAL) when the predecessor's publication came with no such yanks.
The records are asked only when the index (`earlier_yanked`, the records
History already holds) lists `YANK_COUNT` earlier stable versions as
yanked, through the History's crates fetch (read once; `own` reads them
from there), paced by the module's `rate`; a failure or an answer of
another shape is no finding. The Cargo guard (`with_yanks`, before
`with_prior` in `check_crate`): a crate from crates.io's own index
(`registry.default`), not offline, in `PROVENANCE_DAYS`, not SUSPICIOUS;
the index text is kept from the publish-time read (`crate_index_text`,
`keep`) or read once (its `pubtime` the publish time when nothing else
gave one), the records asked under `_api_lock` and `CRATES_API_INTERVAL`
(`yanks.MAX_VERSIONS_BYTES`, 16 MB); a finding is added to the verdict's
rules (WARN at least, the comparison made again) and `own` handed to
`with_prior`; `yanks` (cached) settles it once read a day or more after
publication. PyPI's yanks (PEP 592) carry no time in the JSON or Simple
API, so they are not read. SC-VERSION-INFLATION (RA-7,
0.1.9, `registry/version_anomaly.py` with `repo.version_inflation_issues`,
MAJOR) reads the public tell of dependency confusion: a release with an
inflated version — a non-zero PyPI epoch (which outranks every version
without one), or a major of `INFLATED_MAJOR` (99) or more that is not a
calendar version (`calendar_like`: a year from `CALENDAR_FIRST_YEAR`, 1990,
to the year after the version was published, as YYYY, YYYYMM or YYYYMMDD, so
2024.x and 20240101 are not it and 2099.x, 999912.x, 100001.x and
99991231.x are) — that is new to the package. That is judged on the versions
published at or before the release only (`timeline`: a crate's index lines
without `pubtime` first, in the index's order, as they predate it), so the
verdict does not change when later versions appear: the origin of the
release's inflated line is the latest inflated version up to it that is the
package's first published version, or a jump — its major at least `JUMP`
(50) above the highest published before it, or an epoch above every epoch
before it. A squat's 99.0.0 and 99.0.1 are both flagged; chromedriver's
97 -> 98 -> 99 is a climb, not flagged; a climb past 99 that later jumps
(130 -> 9999) is flagged from the jump. Judging it against the package's
own versions (not an absolute floor alone) is the "internal version" check
John asked for: the jump within the package's own sequence. The same read
reports a flood — more than `FLOOD_COUNT` (5) releases within a
`FLOOD_WINDOW` (24 hours) that contains the release's publish time,
pre-releases (a SemVer `-…`, a PEP 440 a/b/rc/dev) and versions without a
time not counted. It uses the version history `prior.version_times` reads
(npm's packument times, PyPI's Simple API upload times, the crates index's
`pubtime`), for every release (John, Oct 17: "Unconditional RA-7", after a
pre-gated version shipped first) that is not SUSPICIOUS already (its MAJOR
would add nothing), so a publish-flood on normally-versioned releases is
caught too. A release scan reads each of the package's registry documents
once (`prior.History`, made in `_release_findings` and dropped with it):
npm's packument (up to `MAX_HISTORY_BYTES`, 16 MB) is shared by
SC-NEW-DEPENDENCY, the predecessor comparison and SC-VERSION-INFLATION,
PyPI's Simple API document by the last two (SC-NEW-DEPENDENCY reads PyPI's
JSON API), a crate's index file (up to 64 MB) by all three and the
predecessor's resolution; so the history costs a request per release only
where neither of the others read it. The guard's comparison of a crate reads
its index once the same way. The history switches turn it off, the same ones
as the predecessor comparison (`LAZARET_NO_PRIOR_RELEASE`,
`LAZARET_NO_DEPENDENCY_HISTORY`).
TYPO-ESTABLISHED (0.1.9, `registry/lookalike_history.py`, no rule-set
change): an npm, PyPI or crates dependency's SC-TYPOSQUAT finding names the
dependency (`lookalike.DEPENDENCY_KEY`; not one like a Node built-in, nor the
release's own name), and `_release_findings`, before `prior.release_issues`,
reads that dependency's history with one request — npm's packument, PyPI's
Simple API (JSON), the crates index file over the crates module's fetch —
for the first `MAX_LOOKUPS` (5) of a release, each once a run (`RUN`, a lock
per name, `CACHE_SECONDS` for a long-lived process). Established (all of):
first published more than `MIN_AGE` (a year) before the release (a crate's
index line's `pubtime`, a PyPI file's first upload; now for npm, whose
version manifest has no time), at least `MIN_VERSIONS` (3) versions, and on
npm no new publisher (an account that published the newest version, its
`_npmUser` else its `maintainers`, published an earlier one; npm not saying
who is a new one). PyPI's documents and the crates index name no publisher
per version (crates.io's owners are a second request, to its API, not made),
so there age and versions decide; a crates line without `pubtime` predates
the field and counts as old. An established one's finding is INFO, its
message saying why ("…; it is an established package: first published 2015,
13 versions."), and each file that had one is given the verdict its scan
gives without it (`decide_verdict` over its findings, as `scan_members`
decided it); INFO is no indicator for the verdict, for `prior.candidates` or
`prior.rules_found`. A new one, a new publisher, a history that fails or is
over `MAX_HISTORY_BYTES` (16 MB) is MAJOR, as before: it fails closed and is
never an error of the scan. The guard: `_scan_one` keeps the scan's look-alike
findings in short (`guard_kept`: each with its indicator line and dependency,
and the weaker-indicator count) beside the verdict, and `with_lookalikes`
(first in `with_history`, and in `check_crate` before the comparison) settles
a fresh scan's of a release from the public registry over the guard's fetcher
(a crate's over the crates module's fetch, and never `--offline`): the lines
left out, `rules` kept by a finding that stays, a WARN that rested on them
OK; the short findings are never cached, so a cached verdict is the one so
made. Off with `LAZARET_NO_DEPENDENCY_HISTORY` or
`LAZARET_NO_LOOKALIKE_HISTORY` (the tests' default). `bench.py lookalikes`
reads a run's WARN releases with SC-TYPOSQUAT this way, which `run` (the
files alone) does not; the popular sets' measurement is owed (John).
SC-PUBLISHER-LOOKALIKE (RA-9, 0.1.9, `lookalike.owner_lookalike` with
`repo.publisher_lookalike_issues`, in `_release_findings` after
SC-NEW-DEPENDENCY, CRITICAL) is a look-alike name from a look-alike
account: arrayref's `proc-macro1`, one change from `proc-macro2`,
published by `dtolney`, one change from `dtolnay`. For npm, PyPI and crates,
when the release's own name is `lookalike()`'s look-alike of a target whose
owners `popular_names.json`'s "owners" keeps (`owner_target`), the
release's owners (`repo.release_owners`: npm's version document —
`maintainers`, and `_npmUser` when it is an account name, not a workflow's
"GitHub Actions"; PyPI's JSON `ownership`, roles' users and organization,
which `resolve_pypi` now keeps on the Resolution; crates.io's owners,
`repo.crate_owners`, the API's answer kept on the Resolution so
SC-NEW-DEPENDENCY's and this check read one request, none with
`LAZARET_NO_DEPENDENCY_HISTORY`) are compared with the target's
(`owner_change`: one change, or the separators changed, or one change with
the separators aside — `_publisher_change`'s rules, on names of
`MIN_OWNER` (5) letters and digits or more). An owner the target has
suppresses the finding (the maintainer's sibling package), an owner of any
target is never a look-alike (two real maintainers with like names:
`tibo-openai` and `tino-openai` own npm targets), and no owners named is no
finding. The guard (`guard.with_publisher`) compares the owners of the
documents it reads anyway — npm's packument, fetched for a release that may
be younger than `--min-age`; PyPI's JSON document, fetched when a lockfile
gives no upload time — and makes the verdict SUSPICIOUS; it adds no request,
so it reads no crate's owners and none for a file its local PyPI index
relays. The owners are account names only, lower-cased and sorted, one line
a package (`"proc-macro2": "dtolnay"`), at most 64 a package, of all
5,000 targets of each registry (`scripts/fetch-target-owners.py`, resumable,
crates.io one request a second; `update-popular-names.py --owners`). SC-UNUSED-DEPENDENCY (`_ArtifactScan._unused_dependencies`,
INFO) lists an npm release's runtime dependencies no text of it names
and that are neither among npm's 5,000 most-downloaded packages nor in its
own scope, when every text member was read whole; `_scan_artifact` returns
their registry names (`unusedDependencies`), and `scan_package` makes a new
one among them CRITICAL. The comparison itself, `registry/unused_deps.py`,
takes declared names, used names and an ecosystem's normalizer, so a crate's
or a Go module's dependencies go through the same function. Since 0.1.9 (D-5)
a wheel's or an sdist's requirements too (`_pypi_unused`; not an extra's):
a distribution's name is not its import name, so a requirement is used when
an import answers for one of the names it is commonly imported as
(`pypi_import_keys`: its own, without `python-`/`py-`, a `-python`-like
suffix or a `py` prefix; a dotted import for each of its chains) or another
text quotes it (setup.py and the other declaring files are not read for that);
PyPI's most-downloaded distributions are left out. That is a guess, so it is
INFO; the scan returns the modules the code imports (`importedModules`), and
`new_dependency_issues` reads a brand-new requirement exactly
(`pypi_unused_new`: its latest release's smallest wheel, else sdist, listed by
the archive reader, the modules it makes importable against those imports),
CRITICAL when the release imports none of them.
SC-UNPARSED-CODE (0.1.9, JS-PARSE-STRICT; INFO) lists the JavaScript members
the parser refused where a test that reads the syntax tree read them (the
import-time test, SC-USE-RISK's, the install-script test's, D-13's loads),
with each one's line and reason: there the text followers answered alone.
The import-time test gives the refusal when it is asked for
(`import_time_risk`'s `refused`, which `_import_risks` asks for), from the
supply model's cache, so the file is parsed once; an install script is
parsed once more (`js_refusal`, the parse alone:
`_unparsed_install_scripts`); a TypeScript declaration is left out. JS-NEST
(0.1.9) raised the parser's `MAX_DEPTH` by half (256 to 384; no file of the
popular set or the benchmark reached the old bound) and split off the one
shape V8 compiles that the parser still refuses, where the code runs: each
refusal is kept by the pass that read the file (`_note_unparsed`; the scan's
`unparsed` maps a file to {pass: (line, reason) or None}, the passes of
`_UNPARSED_PASSES`: the install-script test, the import-time test,
SC-USE-RISK's, D-13's loads), and a file refused *only* for nesting past the bound (its reason is "nesting too
deep") by the install-script or the import-time test (`_UNPARSED_RUNS`: code
that runs when the package is installed or loaded) is SC-NESTED-CODE (MAJOR,
so it counts as an indicator), apart from the INFO SC-UNPARSED-CODE
inventory. A nesting refusal where the code may never run (SC-USE-RISK's
files, D-13's) stays in the inventory with its reason: generated code nests
that deep too (a minifier's if-return chain of 378 ternaries, a deep data
literal). A file several passes refused is judged by the strongest
(`_unparsed_code_issues`); the install-script pass reads a hook's file even
when D-13's read refused it already.
TS-STRIP (0.1.9, rule set 2.93.0): a TypeScript member is read, and
refused, in its own dialect. The registry handed the engine a `.ts`, `.tsx`,
`.mts` or `.cts` member's text alone, as JavaScript, and the supply model read
it as JavaScript (JSX, Flow) first, then as TypeScript without JSX: a `.tsx`
file with TypeScript's syntax was refused by both (Vite's `main.tsx`), and a
`.ts` file's `post<object>(url, process.env)` was two comparisons, no call and
no refusal, so the tests found nothing. Each pass now gives the engine the
member's dialect from its name (`engine.dialect_args`: the import-time and
use-time passes' `_import_risks`, whose memo key holds it; the install
scripts' `install_script_risk` and `js_refusal`; `scan_calls`' `scan_file`;
`dep_file_issues`), and the engine reads a TypeScript file as tsc does, in
that dialect alone; a JavaScript file, and a text whose file is not known, as
before. SC-UNPARSED-CODE and SC-NESTED-CODE say TypeScript when each listed
file is TypeScript, JavaScript or TypeScript when some are, and give tsc's
check (`tsc --noEmit --jsx preserve FILE`, a syntax error a TS1xxx code)
where `node --check` would mislead (Node runs no `.tsx` file).

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
200 MiB download cap is INCOMPLETE. So is a scan that could not read what a
package can be made to hide (T-1, decision 9): the archive's result says why
it is INCOMPLETE (`incomplete`, of `repo.INCOMPLETE_KINDS`: its deadline
passed; the engine could not finish a file or a step; code that runs, or a
source file, a manifest or a reader's code, not read whole, bytecode that
runs included; the archive not read whole), each something a package controls, as a payload padded past the
size limit inside its file does (the Go/Rust review's GO-1), and an npm tarball that npm's tar reader and the
registry's read differently (BR-4: `registry/npmtar.py` follows node-tar's reading beside tarfile's; an entry npm writes
that tarfile read at another place, under another name or not at all, or a header node-tar finds invalid, makes the
archive corrupt, where npm 11 (node-tar 7.5) or npm 10 (node-tar 6.2, F-14) writes it), and an sdist whose members pip places otherwise than the registry reads them (BR-4, F-11: pip takes
the top folder off only when every member has the same one, `repo._pip_sdist_disagreement`). A wheel's or an sdist's
member whose path goes through `..` and stays in the folder is read where pip writes it (`x/../setup.py` is setup.py),
with an SC-ARCHIVE-PATH of its own, CRITICAL whatever the file holds since rule set 2.71.0 (no tool writes one, and it
hides the file from a listing); node-tar, cargo, Go and VS Code refuse one. `Context.apply`
blocks those unless `--allow-incomplete`; a program too large to read (a
native library a package names) is none of them, and goes through as
before. A time-out is scanned once more (`Scanner.scan`), since a machine
busy for a moment makes one, and never cached; the others are cached with
their kind, so a hit blocks too. Measured on 0.1.8's sweep (Oct 3): the
slowest of 1,206 popular releases took 15 s of the 120 s deadline on the
2-vCPU sandbox, and one release was INCOMPLETE, for a 16 MB library. The
cache (`VerdictCache`) keys verdicts by
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
verdict cached for its checksum is not scanned again; a file in cargo's
cache of that registry with other bytes blocks, since cargo builds a cached
file without checking it: `cargosrc.cache_mismatch`), from where cargo
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
gallery is its `product.json` (VSCodium's also a `product.json` in its folder
of user data and `VSCODE_GALLERY_SERVICE_URL`, field by field over it, as
VSCodium's patches read them), and nothing on its command line points it
elsewhere. So `editorguard.py` does what the editor's
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
is given, so the guard applies it. The same list says which extensions the
editor installs another in place of (`migrateToPreRelease`, a `deprecated`
entry with `autoMigrate`, and the product's `defaultChatAgent`, VS Code's
Copilot): an install, a brought extension and an update take the
replacement, at its newest version, as VS Code's
`checkAndGetCompatibleVersion` does (EG-7), except one the list says is
malicious, which that function refuses first (EG-11); a `deprecated` entry
is written over `migrateToPreRelease`'s for its id, as
`getExtensionsControlManifest` builds the map, and one with no replacement
leaves none (EG-12); one Item for an id, however many bring it or are
replaced by it (EG-13); the list is read once, when first needed, as the
editor reads it only when it fetches. The guard stands in for the editor's
gallery only where it reads it (EG-8): an editor whose gallery is another
(a company's, which serves its own extensions under names a public registry
may give to others) or none is refused unless `--gallery` says which
registry to read for the extensions the command names, so no private name
is sent to a public registry and no public extension of the same name is
installed in its place unasked; with no `product.json` found beside the
command, the editor's own default gallery is taken as its. From VS Code 1.98 the CLI takes
`--do-not-include-pack-dependencies`, and the guard installs every file in
one command with it, so the editor fetches nothing; before 1.98 it installs
wave by wave, each extension after what it brings, so that the editor finds
them installed and fetches none, and a cycle stops the run. The editor's
list of installed extensions afterwards is compared with what was checked.
An extension installed from a file is pinned by the editor (as one installed
with `@version` is), which keeps it at the version checked.

`--update-extensions` is VS Code's `updateExtensions`: the user's
extensions that have a gallery identifier, each asked of the gallery by that
identifier, to the newest version compatible with the editor (a pre-release
when the extension follows them), when it is newer. The identifier and the
pre-release choice are what the editor recorded when it installed the
extension, in the profile's `extensions.json` (`metadata.id`, else
`identifier.uuid`; `metadata.preRelease`): the default profile's is in the
extensions folder, a named profile's in `<user data>/User/profiles/<its
folder>`, which the editor's `User/globalStorage/storage.json` names
(`userDataProfiles`), and a named profile also lists the default's
application-scoped extensions. The registry modules are asked by name, so
`gallery_id` reads the identifier the gallery gives that name (the
Marketplace's query; Open VSX's VS Code gallery, `/vscode/gallery`, which
VSCodium's `product.json` names), and an update goes ahead only when it is
the one the editor recorded. The guard updates only when it reads the
editor's own gallery (EG-8: every extension installed is asked for by name,
private ones too), so the identifiers are always the same gallery's. An
extension the editor keeps in every profile (`isApplicationScoped`, or
`isBuiltin`) is installed without `--profile`, in the default profile, as
VS Code's own update installs it there (EG-16), and one that follows
pre-releases with `--pre-release` (EG-15: the editor records the flag only
if its command line waits for the lookup it starts after installing a file,
which as a rule it does not). An extension installed from a file has no
identifier as a rule: the editor's command line starts the gallery lookup
that would add one without waiting for it, and exits, and the window adds
it when it next opens, matching by name. The guard matches such an
extension by name, as the window does, so that what it installed is updated
by it; one installed from a location (`source: resource`) is matched by
neither. Under `--min-age` the newest version old enough is taken, a younger
one held back and said: an update is "whatever is newest", as an index
filtered for pip is, where an install names what it wants and is blocked.

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
rules: an impostor commit, a version tag that moved since the pin book first
saw it, a pin comment that names another commit, and the action's own
`action.yml` (an image without a digest, a composite action's unpinned steps,
two levels deep). What it could not ask (the rate limit, its call budget, an
expression in a ref, a private repository) is `incomplete`, and an action not
checked is not cleared. A project scan does not call it: it needs the
network, and the offline checks (the engine's `ci_workflow`) are the scan's.

An impostor commit (RA-4, `registry/actionrefs.py`, the one helper every
`uses:` the scan resolves goes through, a workflow's and a composite step's,
pinned or tagged) is a commit none of the repository's branches holds. GitHub
serves each commit of a fork network under the parent's name, and a tag of the
parent can be moved onto one: in May 2026 every tag of
actions-cool/issues-helper, and 15 of actions-cool/maintain-one-comment, were
moved to a commit put in through an attacker's fork, while workflows pinned to
a SHA of the real history were unaffected. So neither a tag nor a tag's tip
vouches for a commit (before RA-4 a pin at a tag's tip did, and a tag off the
branches was SC-ACTION-OFF-BRANCH, MAJOR, now folded into SC-ACTION-IMPOSTOR);
only a branch does. `Branches.check(owner, repo, sha)` asks the compare API
(`GET /repos/{o}/{r}/compare/{branch}...{sha}`: `behind` or `identical`
holds it): the default branch first, after the repository's record (two calls
for most pins), then one page of the branches (100; a branch whose head is the
commit needs no compare), release branches and version names first, then
`main` and `master`, then the rest by name, at most `MAX_COMPARES` (9)
compares a commit. In none of them, every branch compared, and the commit
itself found (one more call: a commit GitHub does not have is a note) is
SC-ACTION-IMPOSTOR, CRITICAL. A check that could not finish (branches left
past the budget, more than a page of branches, a branch name that cannot go
in a URL, the rate limit, the run's call budget, an API error) is never the
finding: the use is `incomplete`, as any other unanswered question of this
scan is (exit 3: the scan's own way, kept apart from the registry's
`INCOMPLETE_KINDS`, which are a package scan's and the guard's), and the
action's code is still read. The answers, errors included, are kept per
(repository, commit) for the run. `LAZARET_NO_ACTION_BRANCHES=1` turns the
check off (the test suite's default, as the provenance and predecessor checks
are off there), and the report says it was not made. The cost of a release
process that tags a commit no branch holds (built files committed on a
detached head and only the tag pushed) is that its tags read as impostors:
such a release cannot be told from a moved tag by GitHub's answers alone.

A version tag's commit is recorded the first time it is seen, in the pin book
(a JSON file in the user's cache) or, with `--db DSN`, in the registry's
database beside its scans (`StoreBook`; the table `action_tags`, keyed by the
repository and the tag, with the first commit, the times, and where the tag
was seen since). A tag seen at another commit is SC-ACTION-TAG-MOVED: MAJOR
(a maintainer may retag a release), CRITICAL when the commit it moved to is in
none of the branches; the record keeps its first commit until
`--accept-moved`. A floating tag (`v4`) moves by design and is not recorded;
moved onto a fork's commit, the branch check finds it. A record that cannot be
read or written leaves the use `incomplete`.

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

- what VS Code installs is every member of the `.vsix` whose name begins
  with `extension`, those letters taken off whether a `/` follows them or
  not (its extractor matches `^extension`: `extensionout/a.js` is
  `out/a.js`, and `extension.vsixmanifest` is the folder's `.vsixmanifest`),
  each by the name VS Code's zip reader, yauzl, gives it (an Info-ZIP
  Unicode Path field's, when one applies: `zip_entry_names`); the rest
  (`[Content_Types].xml`, a signature) is not the extension's. A name that
  begins with `extension` and no `/` (the manifest aside), and an entry with
  two names, are SC-ARCHIVE-PATH (MAJOR), and the guard refuses a file with
  more than one entry written as `package.json` (the editor checks the
  first and the extension runs with the last). The review of Oct 7 found
  both: such a file used to be OK, its code never read;
- `main` and `browser` are the entries (an extension with neither runs no
  code: there is no `index.js` default), and they and what they load get
  the import-time test, whose finding says when the editor starts them at
  every start; the rest of the code gets the use-time test. What they load
  is what Node loads: a relative require, and since 0.1.9 (EG-6) a bare one
  into the extension's own `node_modules` (the nearest folder's, as Node
  walks up from the requiring file; `_js_deps`, `_resolve_bare`), where vsce
  packs the packages it ships: a built-in module and `vscode` are no
  folder's. An npm package's bundleDependencies, packed in its tarball's
  `node_modules`, are followed the same way. VS Code runs an
  entry that leaves the extension's folder too (`../other.ext-1.0.0/x.js`,
  with only a warning), so such an entry is SC-UNREAD-CODE and the
  extension INCOMPLETE (EG-3): what it runs is not in the package;
- the code an extension's `contributes` names runs without `main`, so it is
  an entry point too, and its finding says when (EG-5; VS Code's and
  TypeScript's code read for each): a TypeScript server plugin
  (`typescriptServerPlugins`: the TypeScript server loads
  `node_modules/<name>` from every installed extension's folder whenever a
  JavaScript or TypeScript file is open, the extension activated or not), a
  debug adapter's `program` and a `./` `runtime` (`debuggers`, each
  platform's block too, started with a debug session; one outside the
  folder is EG-3's finding), a notebook renderer's `entrypoint` and a
  Markdown preview script (run in webviews);
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
paced (0.5 s), as Open VSX asks of anonymous clients. With no version asked
for, the newest release is scanned, as the editors install it
(OVSX-LATEST): what the API calls latest is the newest version of either
kind (redhat.vscode-yaml's nightly pre-release, on Oct 9), so when it is a
pre-release the query API is read, newest first, in pages of 50 files, for
the first page that holds a release, and the newest release there by SemVer
is taken. At most 500 files are read: rust-lang.rust-analyzer's newest
release, 0.3.2053, comes after some 1,500 pre-release versions, each
published for several platforms (13,140 files in all on Oct 9), and each
file of the query's answer carries up to a hundred of the versions' URLs
(about 9 KB). With no
release found, the pre-release is scanned and `registryInfo.preReleaseReason`
says why (no release at all, or none among the files read); the
Marketplace's module says the first the same way.

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
its 1,000 most downloaded are). The targets are the Marketplace's 1,000
most installed and Open VSX's 1,000 most downloaded (1,568 extensions, the
rankings of Oct 6): `scripts/fetch-top-extensions.py` saves the
Marketplace's ranking by installs and Open VSX's by downloads, and
`update-popular-names.py --vscode` takes the first 1,000 of each in turn, the pages' other
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

pratique (github.com/lazaret-dev/pratique; tiny_https until October 2026),
an HTTPS client written on Rust's standard library alone (TLS 1.3, X.509,
HTTP/1.1 with a keep-alive pool, HTTP/2 and HTTP/3; and pure verifiers:
the Go checksum database, Sigstore bundles, CMS), is in the repository as
it is upstream (`rust/crates/pratique`: `scripts/sync_pratique.py` takes
a commit of its repository and records which, and `--verify` checks the
copy against `vendored.sha256`, so a local edit cannot slip in). Lazaret takes it
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

A document comes compressed (John, Oct 7: gzip for registry documents, "Add
after Q-1"). A request with a budget of at most 64 MiB (`GZIP_BUDGET`: every
document's, the guard's too, whose npm packuments run to 39 MB) asks for
`gzip, deflate`, and lazaret-net decodes the body with pratique's own
inflate (its B-37), held to the request's budget once decoded as on the wire
(over it: too large) and to 200 times its compressed size once past 1 MiB
(`MAX_DECODE_RATIO`: JSON comes 5 to 13 times smaller, a bomb near 1,032
to 1); a compressed body cut short, corrupt or followed by anything is the
server's error. A download asks for the bytes as they are (`identity`) and
gets them so, compressed or not, since its digest is checked against the
bytes as published. Fourteen large documents (eight npm packuments, four
PyPI documents, two crates.io index files: 124 MB) come as 15.9 MB (npm 5 to
13 times smaller, PyPI 4.5 to 5.7, crates.io's index uncompressed either
way). Fetched from a data center, where npm's edge sent 39 MB in 0.27 s, the
set took longer compressed (2.9 to 4.6 s one at a time against 1.1 to 1.6 s
whole; 1.3 to 1.8 against 0.35 to 0.7 s from 8 threads; three rounds, both
protocols): Cloudflare compresses a full packument as it sends it, about
35 MB a second (vite's took 1.26 s compressed and 0.27 s whole, both from its
cache), while PyPI's documents took the same time either way. Through a link
capped at 100 Mbit/s (a local relay; its pacing makes one stream slower than
the cap) the set took 3.6 s compressed against 17.4 s whole one at a time,
and 1.5 against 10.5 s from 8 threads; capped at 300 Mbit/s, 3.2 against
9.8 s and 1.25 against 4.2 s. Lazaret runs mostly on developers' machines,
behind links of the second kind, so documents ask for compression;
`LAZARET_GZIP=0` asks for none (a runner with a fast link to npm). The
guard's documents (64 MiB) stay on HTTP/1.1: compressed, they came as fast
or faster over it than over h2 in every round.

What falls back to urllib: no native library, or one without the network
layer; `LAZARET_NETWORK=python`; a proxy reached over TLS. TLS 1.2 is the
floor on both transports (John, Oct 7: "Realistically we should avoid any
tls < 1.2 as that would be horrible security stance by a provider"): a
server that speaks neither TLS 1.3 nor TLS 1.2 is refused, not handed to
urllib, and urllib's connections take `nativenet.tls_context()`, urllib's
default context with the floor stated, so a process that lowered Python's
default does not lower Lazaret's (`test_tls_floor.py` holds every opener,
connection and context under `python/src` to it). pratique speaks TLS 1.2 only to a server that speaks
nothing newer (its drop of the evening of Oct 7, B-36, because npm's edge
answered only 1.2 to John's network): ECDHE with AEAD suites only, the
extended master secret required, RFC 8446's downgrade check, no
renegotiation or resumption, the certificate checks of 1.3; every reply
says which version it came over. Trust anchors: `SSL_CERT_FILE`, the system bundle, or what Python's
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
only). What stays on urllib: plain http (a registry served on this machine).
Secret verification's call goes over it too since V-1's stage 2 (§5k), its
credential given to the provider's host and the request alone; urllib's
transport makes it where the native client does not. `keepalive.py` (`--keepalive`) pools
urllib's connections and is moot for the native transport, which pools its
own.

Credentials (decision 14, John, Oct 6: they go over pratique in 0.1.9).
Until this drop they stayed on urllib, for two reasons: a redirect hop must
get its own host's credentials and no other's, which only urllib's redirect
hook gave (pratique dropped `Authorization`, `Cookie` and
`Proxy-Authorization` on a change of origin, and nothing more: a
`PRIVATE-TOKEN` the caller set went on, and nothing could add the next host's),
and secrets are what an unreviewed TLS stack would cost most. pratique's
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

A review of these credentials by a fresh reader (Oct 7) found no way for one
to reach another host, and the following, now fixed; a second review of the
fixes found more, fixed too. A path is read as npm and uv send it
(`pmsettings.normal_path`, the WHATWG URL standard's reading: "." and ".."
segments resolved, their "%2e" spellings too, a backslash a slash; an empty
segment stays). The guard sends a request's URL, and urllib's redirects,
with the path so read. pratique sends a redirect's path as its Location
gives it, and it is a drop that Lazaret does not edit, so a credential goes
with a path only when the path's directory is under the credential's path
read three ways (`pmsettings.covers`, and lazaret-net's `granted`): as it is
sent, as npm resolves it, and as a server that decodes it before it routes
it may (`server_path`: nginx decodes "%XX", merges slashes and resolves dot
segments; Tomcat drops a segment's ";parameters"): "/team/../x" is under
/team/ to a server that reads it as it is and /x to one that resolves it,
as "/team/..%2fx" and "/team//../x" are to nginx. A redirect from another
origin gets a credential of the whole host only: npm sends none on a
redirect to another host, and pip a `.netrc` login for it; any host the
guard fetches from can redirect. The choice is the longest key that covers
the path, as npm's walk up a path finds it, made over the host's few keys:
the old walk never ended on a path that starts with "//", and was quadratic
in a long one. A fetcher takes a host only when urllib, pratique and its
host rule read it alike (`guard.usable_netloc`): one entry the host rule
could not read failed every native request of its fetcher, and a "*." entry
is a wildcard to it. A lockfile URL with a backslash before its query (a
slash to npm's parser, so possibly another host) or such a host blocks its
package; a host that is not ASCII is to be written in its xn-- form. A
redirect to a server below TLS 1.2 is refused by that server's name, not the
first URL's (lazaret-net's `TlsVersion` names the hop's host). lazaret-net refuses a request header outside `PLAIN_HEADERS` (Accept,
Content-Type, User-Agent, X-GitHub-Api-Version, and live secret verification's
anthropic-version and x-amz-date), since a token in a header
of another name would follow a redirect, and its `Debug` shows no password
of a URL or a proxy. A GitLab under a path prefix gets its token on that
prefix alone. A request goes through urllib when urllib and pratique would
read the proxy settings differently: HTTPS_PROXY and https_proxy (or
NO_PROXY and no_proxy) that differ (urllib reads the lower-case name first,
pratique the upper-case one), a proxy whose port pratique would not take
(it takes 8080 when a path, even "/", follows the port, or none is given),
or a NO_PROXY that names the request's host to one and not the other ("*"
in a list, an entry with a port). What pratique's next drop is asked for:
dot segments resolved in a Location's path whatever its form, a backslash
refused or read as a slash, a port of digits only ("+443" is taken today), a
proxy's port read wherever the URL has a path, NO_PROXY read as urllib reads
it, and no password in the `Debug` of a URL, a proxy or a pool's key.

The Go checksum database (NET-1's third part). `golang.verify_lookup`
checks a `/lookup/<module>@<version>` answer as the go command's client does
(`golang.org/x/mod/sumdb`), through the native library's `verify.go_sumdb`
(lazaret-ffi's `verify` module, over `lazaret-verify`'s `gosum`: pratique's
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
the database itself. Tested on pratique's capture of the real database
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
lazaret-verify's `provenance` over pratique's `sigstore`): the signature
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
provenance and this one has none (a release's, on PyPI: any of its files
listed with provenance, as for the release before, whichever file is
scanned: EG-17), SC-PROVENANCE-DROPPED; both verified,
from repositories with different IDs (or URIs, without IDs) of different
owners, SC-PROVENANCE-REPO-CHANGED (both MAJOR; the guard blocks a
DROPPED release in its window, `Context.provenance_block`, as pnpm's
`trustPolicy: no-downgrade` fails an install, with `--trust` the way out,
and the verdict stays WARN: decision 13, John, Oct 7). The same
source-repository URL with a different immutable repository ID and a
different immutable owner ID (both known) is not a move but a takeover — a
name a repository gave up, taken by another account (npm's SlugFest, Oct
2026: Trusted Publishing matched repository names, not IDs); only another
account can take a name — SC-PROVENANCE-REPO-TAKEOVER (CRITICAL, and so
SUSPICIOUS and blocked, in the registry scan and the guard alike: RA-5).
The same URL with a new repository ID and the same owner ID (the owner
deleted and recreated its repository), or without both owner IDs, is the
same-owner case. A repository of
the same owner is INFO: on the popular set's 1,205 releases the two
changes of repository were both within their owner (scikit-learn 1.9.1 from its release repository,
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
guard runs it (0.1.9) on a release from npm's or PyPI's public registry
that it scans fresh (not from its verdict cache) and that was published
less than `guard.PROVENANCE_DAYS` (30) ago, or whose publish time is not
known: its installs wait on the requests, and the release before is read
from the package's whole history (npm's abbreviated document is megabytes
for an active package), so the check is kept to where a hijacked release
is live, as a rule (ultralytics' were found in hours). Measured on three
npm projects (773 packages) and three Python sets (179 releases) resolved
on Oct 7, 2026: 127 and 57 releases fall in the window, 311 requests and
67 MB for npm, 122 and 47 MB for PyPI (instead of 1,140 and 136 MB, 313 and
80 MB), and the two releases the whole check flagged, both benign and
older, are outside it. `provenance.guard_npm` reads the abbreviated
document once for the version's own `dist.attestations` and the release
before it; `guard.with_provenance` merges the findings into the scan's
verdict (CRITICAL: SUSPICIOUS; MAJOR: WARN at least) before the verdict is
cached, with whether the check ran to the end (`provenance.complete`: every
answer it needed read; an attestation read and not checkable here counts as
read). A cached verdict without it, for a release in the window, is scanned
and checked again (`guard.provenance_owed`, EG-10): one cached while the
registry could not be read, or with the check off, would otherwise pass
unchecked until the rule set changes. The pip and uv index runs the check
after the file's bytes have left the scanner's byte budget. A package of a
private registry is never named to the public one.

### k. Live secret verification (`--verify-secrets`, 0.1.9, V-1)

A secret the provider still accepts is the finding someone acts on first.
`lazaret scan --verify-secrets` asks (John's decision 4, Oct 7: "Let's
follow trufflehog behavior. Verify is an explicit flag -- detection of
secret is default without verification it is live"): off by default, any
target when asked (`github:` and `gitlab:` repositories too), never in the
guard, the registry auditor, the MCP server or the pre-commit hook.

One copy of the logic, in the engine (decision 7): the provider table is
the pack's `_VERIFY_PROVIDERS` (ten: GitHub, Slack, Stripe and npm tokens,
OpenAI and Anthropic API keys, AWS key pairs, and OpenAI's, the Console's
and Claude Enterprise's admin keys), checked when it
is read and by `make_rust_tables.py --check` (a host is a lower-case DNS
name; a credential goes in a header, never in the path or the query; a
signed request sends no secret). `secrets.rs` answers three questions,
with no clock and no network: which credentials a file's flagged lines
hold (`secrets.find`: a word that is all of a provider's format; an AWS
key id and a secret key of the same file, paired nearest first, eight
pairs at most), the request that asks about one (`secrets.request`: a call
that only authenticates; AWS's signed with Signature Version 4 over
lazaret-verify's SHA-256, the time given by the caller; the fields that
carry the credential named), and what an answer says (`secrets.judge`: the
first of the provider's rules that holds, live, rejected or unknown; a
body cut at 64 KiB read by its status alone; the account's name printable,
80 characters at most, any part of the credential in it `[redacted]`).

A key is asked about only where the call is documented for it, and is
rejected only on its provider's own word. OpenAI's pattern takes user,
project and service account keys (`sk-`, `sk-proj-`, `sk-svcacct-`), and
Anthropic's its API keys (`sk-ant-api03-`, and the Console's personal ones,
`sk-ant-usr-`): `/v1/models` is documented for them, not for an admin key,
which a live admin key turned away there must not read as rejected. The
admin keys have entries of their own (V-3, 0.1.9), each asked at its admin
API's own call: OpenAI's (`sk-admin-`) `GET /v1/organization/projects`, the
Administration API's list, which its reference calls with the admin key;
the Console's (`sk-ant-admin01-`) `GET /v1/organizations/me`, the Admin
API's organization of the key, whose name is the answer's owner; Claude
Enterprise's Compliance Access Keys (`sk-ant-api01-`) `GET
/v1/compliance/organizations`, read by the Compliance API's error catalogue:
401 `authentication_error` is a key that does not authenticate (invalid,
deactivated, expired), 403 `permission_error` a valid key without the
scope, a 400 that says the Compliance API is not enabled a valid key too,
and the bare 404 a credential it does not take, unknown. (A Compliance API
call is one of the organization's audited activities: its admins see it in
their Activity Feed, as any provider logs the call.) A 401 is rejected only
with OpenAI's `error.code` `invalid_api_key` or Anthropic's `error.type`
`authentication_error`; any other 401 (a gateway's, a proxy's, another
reason) is unknown, and Anthropic's 403 `permission_error` is a key it
knows, live, as Stripe's is. Anthropic's OAuth tokens (`sk-ant-oat01-`) are
not asked about: Anthropic documents neither the prefix nor a call for
them, and the Admin API's OAuth tokens are those with the `org:admin`
scope, so a live token of another scope could be turned away there. What
the table does not ask about is detected as before.

Each package keeps what is about a run and makes the call. Python
(`verifyscan.py`, `secretverify.py`, `secretverify_http.py`): the secret
findings' lines read again from their files, as the scan numbered them, in
memory only; one call per credential (a cache for the run, keyed by
provider, endpoint and the credential's SHA-256; 120 seconds and 500 calls
at most; two calls at once to one provider); the call over lazaret-net, the
provider's host the only host, no redirect (a 3xx with a Location is
`redirect`, unknown), nothing compressed, one deadline, the credential as a
`Credential` for that host and the request alone, and urllib's transport
where the native client does not send it. A failed call is unknown, never
rejected. A finding gets the result of the credentials on its line that
says most (live, then unknown, then rejected): live makes it a BLOCKER
vulnerability, and the result is graded again (`core.regrade`).

The npm package's runner (`js/src/verify.js`) is the twin of the three
Python modules, on the same engine calls: a finding's line read from the text
the scan read; the same cache, budgets and two calls at once to a provider;
the call over `node:https`, the provider's host alone on port 443, TLS 1.2 at
least (`minVersion`), no redirect followed, the body read to 64 KiB, one
deadline, `HTTPS_PROXY` through an http:// proxy's CONNECT tunnel (an
https:// proxy is refused) and `NO_PROXY` read as urllib reads it. Its
`run()` returns a promise of the exit code when the flag is given.

Tested against a stub provider over TLS on 127.0.0.1, on both transports:
each credential reaches its own provider's host and no other, AWS's
signature holds over the request as the stub received it, and a verifying
scan's every output (the terminal, stderr, the JSON, SARIF and HTML
reports) holds none of the values; the npm runner against its own stub
(`js/test/verify-secrets.test.js`: a server that speaks only TLS 1.1 refused,
as a client without the floor would reach it), and both CLIs against the same
stub with the same results (`test_js_parity_verify`). `scripts/verifylive` is the manual check
against the real services, run before a release.

### l. New GitHub repositories (`ghdiscover.py`, GH-NEW-REPOS)

`lazaret-registry discover --ecosystem github --resume [--scan]` lists every
new public repository and keeps the likely-hostile ones (John's scope, Oct
14; specs/lazaret-github-new-repos-plan-2026-10-14.md). GitHub's
`/repositories` is the complete source: every public repository in creation
order, 100 a page, paged by the last ID alone; the cursor is that ID
(`discovery_cursors`, `github`), stored after each page, so a stopped run
repeats at most one page. The first run finds the newest repository by a
search on `since` (doubling, then halving) and starts there. The filters read
the listing alone: a look-alike by Go's owner rules (`lookalike.
github_lookalike`, on `popular_names.json`'s "github" targets and the "go"
targets on github.com), a copy with the original's description, a campaign
marker (`campaign_markers.json`, compared whole with case and separators
folded: a repository that publishes stolen credentials is reported and never
downloaded) and the user's patterns. A candidate (`github_candidates`, in
SQLite and Postgres) waits for content: `GET /repos/{owner}/{repo}` at 1, 6,
24 and 72 hours after it was listed; dropped when still empty, gone or made
private. A scan is `sources.checkout` and `core.scan_project`, stored with
eco `github` and the commit as its version, profile `project`; its verdict
is `decide_verdict` over the findings with a CI file's hardening check below
CRITICAL left out (`core.HARDENING_RULES`, as the gate leaves it out), and a
checkout not read whole is a truncated part (INCOMPLETE at best). The run's
calls (`--max-calls`) go to what is due first (checks, then scans), then to
the listing; GitHub's rate limit (`X-RateLimit-Remaining` at `RATE_FLOOR`, a
403 or 429 that says so) stops the run with its cursor and candidates kept.
`sources.Client.get` hands the answer's headers back (`reply_headers`) for
that. A token is required; nothing runs; secrets are never verified.

GH Archive and every new repository (`ghevents.py`, GH-SCAN-ALL, 0.1.9:
the plan's phase 2). `--github-archive` reads GH Archive's hourly files of
public events (`data.gharchive.org/YYYY-MM-DD-H.json.gz`, the Events API's
events, some 70 MB gzipped, published a while after the hour), in order from
the cursor `gharchive`, at most `ARCHIVE_HOURS` a run, an hour that answers
404 waited for (`ARCHIVE_GIVE_UP` hours after it ended, passed over as a gap
of GH Archive's, and said so); the file goes to that host alone, with no credential, and is
read within bounds (the file, what it unpacks to, a line; an event's ID and
name checked as the listing's are). Read of it: `PushEvent` and a branch or
tag's `CreateEvent` (the repository has code), a repository's `CreateEvent`
(its description) and `PublicEvent` (made public: a repository created
private keeps its old ID, so the listing never shows it). A push makes a
waiting candidate ready; its content checks still run, since GH Archive can
miss an event. A repository made public goes through the filters by name.
`--github-scan-all` turns it on, with `--scan`: a repository newer than the
listing's cursor when scan-all first ran (`github-scan-all`), seen to get
code, is queued (state `queued`) when the listing has reached it, `pending`
until then (its verdict the listing's: reported, excluded or queued), and
judged by GH Archive's name and description where the listing cannot (a
repository made public). Campaign repositories stay reported and are never
downloaded; your excludes make a repository `excluded`. The scans
(`--max-scans`, `SCAN_ALL_MAX_SCANS` by default) take the filters' ready
candidates first, oldest first, then the queue, newest first; the queue keeps
`QUEUE_MAX` and a pending repository waits `PENDING_HOURS`, the rest skipped
and counted, so each run says what share of the stream it covered (some ten
thousand new repositories an hour against a token's 5,000 requests, three a
scan). A queued repository's failed scan drops it; a repository is scanned
once. No schema change: the states are new values of `github_candidates`'s
`state`, and the two cursors rows of `discovery_cursors`. GH Archive has
missed most events since 2025, so the files' source is a setting
(`--github-events-url`, `LAZARET_GITHUB_EVENTS_URL`; `ghevents.source`: an
https host and a folder, the default port, no credential, query or
fragment): OpenDigger's mirror (`ghevents.MIRROR`) serves the same files,
and a run whose hour holds under `THIN_HOUR` events says so. A scan GitHub
answers 404 or 409 (gone, made private, empty) drops its candidate and is
counted (`gone`), not an error of the run. The CLI prints an OK scan in one
line and the others in full, and `progress` lines on stderr (an hour being
read, every `LISTING_PROGRESS_EVERY` pages, each scan).

### m. crates.io discovery (`ecosystems/crates.py`, CRATES-DISCOVER)

crates.io has no change feed to read forward, as npm's replication feed and
PyPI's changelog are. Its API lists crates by their last update, newest
first (`/api/v1/crates?sort=recent-updates`, 100 a page, each next page as
the answer's own `next_page` names it: a seek key), and its crawler policy
asks for one request a second, which the crates module's fetch keeps for
its API host. `Crates.recent_updates` walks that list back to a position
(microseconds since 1970, `micros`: exact, no float), within a page budget,
and checks each answer: a page of the same list (a `next_page` of plain
characters that still sorts by update), a crate name the module accepts, a
time, each crate once. `repo.discover_crates` reads a `--since` window from
it, `repo.discover_crates_since` everything after the stored cursor
(`discovery_cursors`, `crates`: the newest update the previous run read).
Because the list runs newest first, a `--resume` run cannot stop part way
and continue later: a list longer than `CRATES_DISCOVER_PAGES` (200 pages,
about two and a half days) is listed as far as it was read, the part before
is named as not checked, and the cursor moves to the newest; a page that
fails keeps the cursor, so the next run reads back to it again; `--limit`
lists the oldest first and moves the cursor to the last listed. The first
`--resume` run reads the last hour unless `--since` is given
(`CRATES_FIRST_RUN`), and a walk of more than five pages says how far it has
read on stderr every 25 pages (`_crates_progress`). The version
listed is the one the crate published last (`newest_version`, which the API
marks deprecated; else `default_version`; else none, and the scan takes the
latest). A crate's `updated_at` moves for more than a publish (a yank, an
edit of its metadata), so the list holds every crate published since and
some that were not; a version already scanned is skipped.

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

Within one scan a file's text crosses into the engine once (0.1.9, FE-1:
`engine.Texts`, the engine's `texts.rs`): the scan puts each distinct text
in the engine's store the first time a step asks about it (`texts.put`, the
raw UTF-8, no JSON), every step after names it by id, and the scan drops its
texts when it ends, in a `finally`. The memo's keys hash each text once
(`contentcache.Digests`). The steps that went one file at a time (the agent
check, the scripts a file starts) go a batch at a time, and Node's names for
a path are asked once per path. A store that refuses a put (its 1 GiB bound)
leaves the texts to go with their calls, which gives the same answers:
`test_engine_texts.py` holds both.

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
  PyPI release has an sdist (with the engine's sources) and eight platform
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
  table is Unicode data, and so is the engine the dashboard carries, with its
  notices: `Apache-2.0 AND Unicode-3.0`); a platform wheel adds the native library and the
  engine's notice, `rust/NOTICE` (the engine is Lazaret's own since P-16,
  with Unicode data); the npm package only `bin/`, `src/`, the engine
  (`native/lazaret.wasm` and its `native/NOTICE`, `rust/NOTICE`) and its
  license files (`NOTICE`, `LICENSE-UNICODE`). Every package is
  `Apache-2.0 AND Unicode-3.0`: the codec names the engine lists are facts
  about Python, not CPython's code.
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
| `python/src/lazaret/scanner/core.py` | The scanner around the engine: `scan_project`, `--deps`, the taint configuration (`apply_taint_config`, `taint_args`), config files, manifests, the report |
| `python/src/lazaret/scanner/flow.py` | Interprocedural cross-file taint: hands the engine's passes the files and the configured model, builds their findings (Python's own AST pass until phase 3) |
| `rust/crates/lazaret-engine/src/jsparse/`, `jsflow/` | The JavaScript / TypeScript reader and the JS cross-file pass (the `js_parse` and `js_flow` calls, both packages'; jsparse.py, jsflow.py and their npm twins until phase 3) |
| `rust/crates/lazaret-engine/src/pyparse/`, `pyflow/` | The Python reader (Python 3.13's trees) and the Python cross-file pass (the `py_parse` and `py_flow` calls, both packages'; flow.py's own pass until phase 3) |
| `rust/crates/lazaret-engine/src/config.rs` | A config or data file's scan (the `scan_config` call, both packages'; since BR-7's step 3): S-TOKEN and S-SECRET's config form, the autorun and CI issues, the suppression markers, the cap and the redacted snippets; `scanner/configsecrets.py` says which files are config files and keeps the reader's checks for the tests (`config_check`) |
| `rust/crates/lazaret-engine/src/autorun.rs` | Editor and AI-agent settings that run commands (SC-AUTORUN; the `autorun_*` calls, both packages'; since BR-7's step 2): the JSON-with-comments reader, the commands each file makes its tool run, the issues; `scanner/autorun.py` keeps the names the package calls, over the engine |
| `rust/crates/lazaret-engine/src/agentdoc.rs` | Agent skill and instruction files (SC-AGENT-SKILL; the `agentdoc_kind` and `agentdoc_issues` calls and the config scan, both packages', and the registry's members; RA-3, 0.1.9): the commands and code a SKILL.md/AGENTS.md/CLAUDE.md/.cursor/rules tells the agent to run (the hook-command and install-script tests), a script of its folder they run, a password-protected archive, a paste host or public raw IP, hidden text, an order to send data out; a dependency's CRITICAL/MAJOR, the project's own INFO; `core.agentdoc_kind`/`agentdoc_issues` keep the names the package calls, over the engine |
| `rust/crates/lazaret-engine/src/ci/` | CI files (the `ci_*` calls, both packages'; since BR-7): the workflows the Shai-Hulud worms planted (SC-WORKFLOW-SECRETS, -BACKDOOR) and the CI files' hardening checks (the other SC-WORKFLOW-* ids, SC-GITLAB-*); `scanner/ghworkflow.py` and `gitlabci.py` keep the names the package calls, over the engine |
| `python/src/lazaret/scanner/sca_feeds.py`, `sca_index.py`, `gomod.py` | CVE bundle build (OSV/KEV/EPSS), the indexed bundle, the `go.mod` reader |
| `python/src/lazaret/{registry,mcp,pg,safexml}/` | Registry auditor, MCP server, Postgres client, safe XML |
| `python/src/lazaret/registry/guard.py`, `python/src/lazaret/_cli.py` | The install guard (`lazaret guard`) and the `lazaret` command's dispatch |
| `python/src/lazaret/registry/pmsettings.py` | The package managers' own settings as the guard reads them: registries, indexes, credentials by host |
| `python/src/lazaret/registry/goproxy.py`, `cargosrc.py`, `scanpool.py`, `ecosystems/` | The Go guard's proxy protocol, the Cargo guard's sources and lockfile, the guard's scan workers, the crates.io, Go module and Open VSX auditors |
| `python/src/lazaret/registry/sources.py`, `sourcescan.py`, `actions.py` | A repository at a commit (`lazaret scan github:…`), its scan and report `source`; a workflow's actions asked of GitHub |
| `python/src/lazaret/registry/extensions.py` | VS Code extensions: `lazaret FILE.vsix` and `lazaret --extensions` (the editors' installed extensions), read with the editor's rules for what runs |
| `rust/crates/lazaret-engine/src/lex/`, `goparse/`, `rsparse/` | The lexers (JavaScript, Python, Go, Rust), the Go parser and the Rust item reader, with their hooks (not used by a scan yet) |
| `js/src/lib/native.js`, `js/scripts/build-wasm.js` | The npm package's native engine (WebAssembly: the loader, one call, the pack's values) and its build (`npm run build`) |
| `rust/crates/lazaret-engine/src/manifest/` | Manifests (the `scan_manifest`, `scan_gyp`, `manifest_data` and `manifest_check` calls, both packages'; since BR-7's step 3 (b)): SC-INSTALL-HOOK, SC-DEP-URL, SC-MANIFEST-DEPTH and -UNPARSEABLE; `pyjson.rs` (json.loads), `pylit.rs` (ast.literal_eval), `pyval.rs` (Python's values, their str() and repr()), `gyp.rs` |
| `js/src/lib/supplychain.js`, `js/src/deps.js`, `js/src/scanner/flow.js`, `js/src/index.js`, `js/src/pool.js` | The manifests' calls, `--deps` (the tree read for the engine's decisions, the vendored readers), flow twin, npm CLI, its worker threads |
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
  must change with the Python package, and the dashboard, which runs them,
  be rebuilt: run the parity suites before you believe a flow change is
  done.
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
  (crypto-hash-sdk: SUSPICIOUS since D-12, an install at import time of a
  package the manifest doesn't name), a `require()` of a package the
  manifest doesn't declare (dotenv-express), and a file written from a
  request callback's data, then run. The rest put their payload outside
  the release, are proofs of concept, CTFs or empty samples, or ship a
  compiled binary.
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
  class made in several places keeps one container per instance, and since
  0.1.9 (B-3) a method of such a class reads `this` as a parameter, the
  value it is called on: a value given to one method from outside and run
  by another method of the same instance (`r.setCode(t); r.run()` where
  `run` evals `this.c`) is followed, for that instance and no other. Since
  D-3c (0.1.9) every class's methods read `this` so, and what a method is
  given and puts into a container that is a member of `this` (a recorder's
  `this._events.push(…)`) is the instance's it is called on: a call on a
  name puts it into that name (and its member's container), which another
  method's `this`, a method that returns the member, the member and the
  instance read back; never into every instance's member, which joined
  every caller's flows (monaco-editor's loader).
- *What the cross-file follower doesn't follow* (the adversarial pass's known
  misses, kept as tests; the event emitter, relays, 16 hops, `getattr` names
  a file builds and a distribution's modules were built in 0.1.8): a name
  built at run time from data (`getattr(m, name)` with `name` read or
  computed), and top-level modules of site-packages no RECORD lists together
  (they may be two distributions; a registry scan reads a release's as one).
- *Engine:* the native engine answers the supply-chain tests (0.1.8,
  `docs/RUST_ENGINE.md`), the dependency-mode scan of each file, the rules
  part of the project-mode scan and the cross-file follower in both
  packages; release CI builds it into eight platform wheels, and the npm
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
  splitting `core.py` (the GitHub Action was built in 0.1.8, and the
  pre-commit hook, `lazaret hook`, in 0.1.9, in both packages; since 0.1.9
  the dashboard's script is built from `js/src`).

Prefer doing detection extensions **reactively** — when a real-world dropper
uses the pattern — over speculatively. The bar that made this tool good is the
false-positive bar; keep it.
