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

A platform wheel of the PyPI package also carries a **native engine** written
in Rust (`rust/`, no crates), which answers the supply-chain tests faster; the
Python engine stays the reference it is held to (§2, `docs/RUST_ENGINE.md`).

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
- **The native engine** (`rust/crates/lazaret-engine`, 0.1.8) is a port of
  core's supply-chain tests — the install-script and import-time tests and
  everything they read — with Python `re` semantics (its own port of sre) and
  the patterns extracted from `core.py` into a rule pack. The Python package
  sends those tests through it where it is installed
  (`lazaret.scanner.engine`; `--engine rust|python`), and core answers any
  call it can't (a spent work budget, an error), so it never loses a finding.
  `test_rust_parity_{regex,hooks,signs}.py` compare it with core on every
  pack pattern and the 36,900-case hooks corpus: zero differences allowed.
  A change to those tests is made in core, ported to Rust and the pack
  regenerated (`scripts/make_rust_tables.py`; `--check` in CI), in the same
  commit.

### The documented Python-only exception

One capability runs only in the Python engine, by deliberate design, and the
parity test excludes it (`_python_only` in `test_js_parity.py`):

- **The AST half of the interprocedural flow engine** — `flow.py`'s Python
  analysis is AST-based and has no JS twin; its `X-*` findings and `Q-FLOW-*`
  coverage notes on Python files are Python-only. The JavaScript half of the
  flow engine *is* twinned (`js/src/scanner/flow.js` and `jsflow.js`, on the
  reader `js/src/lib/jsparse.js`).

(The cross-file received-code follower was the second exception until 0.1.8;
`js/src/lib/crossfile.js` is its twin now — §5c.)

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
lazaret.registry.guard  pre-install guard for npm/pnpm/pip/uv    (lazaret guard, lazaret-guard)
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
  Python interpreter; and (0.1.8) a chat bot or webhook whose secret is
  written in the code (a Telegram bot token, a Discord or Slack webhook) in
  a file that makes network calls, credential files sent to a raw public IP
  address, three or more credential folders named in one place (a sweep of
  the home folder), the host name sent to a base64-hidden address or in a
  DNS name the code builds, the public IP address sent to a data-capture
  service (an ngrok tunnel's own address counts as one), a reverse shell as
  an argument list or to an ngrok TCP address, and a miner (a Monero wallet
  address with a mining pool's arguments). An install script that does any
  of it → CRITICAL
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
statements), members read by name (`getattr(m, 'x')`, `m['x']` as `m.x`), a
call through a comma expression (`(0, ns.fn)(…)`) as the call, and a code
runner handed to a call as its last argument (`p.then(eval)`,
`res.on('data', eval)`) as the call it makes, `(_v)=>eval(_v)`. Each rewrite
keeps the row count (lines map back through `firsts`). A longer text (a
bundle) is read once: the second reading doubled the benign bundles' time and
found nothing there, and a minified payload is the first reading's long-row
pass.

**The shared spec.** The detector's data (name sets, character sets, limits) and
**all its patterns** (36 plain regexes + 6 alternation groups: 48 compiled
patterns) are authored once in
`python/src/lazaret/scanner/received_spec.json` and compiled by both engines.
`scripts/sync-received-spec.py` copies it to `js/src/lib/received-spec.json`
(run `--check` in CI); `tests/architecture/test_received_spec.py` fails if the
copies drift or if core stops matching the spec. `test_js_parity_hooks.py`
compares every compiled pattern of `hooks.js` and `received.js` with core's
(126 patterns / 30 sets / 4 maps) and runs a 30k+ case agreement corpus plus a
reach test. **Edit the spec, not the inline patterns; then sync.** The npm
engine loads the spec with `readFileSync` at import — the build backend ships
`.json` from the package so it lands in the wheel.

**The cross-file follower (both engines since 0.1.8).**
`core._cross_file_received_issues` and its twin `crossFileReceivedIssues`
(`js/src/lib/crossfile.js`) catch a value received in one file of a package and
run in another — source and sink split across modules — in Python and npm
packages: a dependency's under `--deps` (both engines), and a release's in the
registry and the guard (`_ArtifactScan._cross_file_code`: one distribution is
one package; the files SC-USE-RISK reads; not once the package is SUSPICIOUS).
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
   `_XF_ROUNDS` (4) hops — or when its body receives one and hands it to a
   callback: a parameter it calls, or a Promise's resolve. **A function runs
   its parameter** (a runner) when the single-file detector, reading its body
   with the parameters seeded, finds it run as code.
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

Export detection is deliberately *liberal* (an HTTP library's functions fetch
and return data); the sink side keeps it precise. Bounds: `_XF_WINDOW` (25 rows
of a body), `_XF_MAX_FILES` (3,000 per package), `_XF_MAX_SYMBOLS` (5,000),
`_XF_MAX_SEEDS` (64 per file), `_XF_OBJECT_ROWS` (400), `_XF_MAX_RUNNERS` (200
bodies tested), a file over `_XF_MAX_CHARS` (2,000,000) not read for what it
defines; litellm's 2,471 modules (34 MB) take 3.6 s. Both engines give the same
answer: `tests/architecture/test_js_parity_crossfile.py` holds the twins'
patterns and limits to core's and compares the follower's own cases and a
generated stream of 700 packages finding for finding. What it doesn't follow:
§12.

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

Persistence targets (0.1.7): the install-script test also fails on what makes
an AI agent, an editor or GitHub Actions run something later — writing an
agent's or editor's auto-run settings, a workflow, an editor extension, a
self-hosted runner — and on the Bun loader of the 2025-26 worms
(`core.persistence_reasons`, applied to a hook's own command too); at import
time only a workflow that dumps every secret counts. In the tree, SC-AUTORUN and
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
release without dependencies. The guard scans each package with
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

- **Lock, check, install** (npm, pnpm, uv projects). The tool resolves to a
  lockfile without installing (`--package-lock-only`, `--lockfile-only`,
  `uv add --no-sync`, `uv lock`; scripts off). What the lockfile adds on this
  machine — minus what is installed (npm's and pnpm's hidden lockfiles, the
  venv's `.dist-info`), minus other platforms (npm-install-checks' os/cpu/libc
  rules, as `node` reports the machine) — is fetched from the URL the tool will
  use (the `resolved` URL after npm's replace-registry-host rule, a scoped
  registry from `<tool> config list --json`) and **verified against the
  lockfile's digest**: the tool accepts only those bytes, so a verdict on them
  is a verdict on what gets installed, and a cached verdict can be reused
  without a download. Blocked: the files the resolution touched are restored
  from a snapshot (also on Ctrl-C or a crash). Not blocked: the user's command
  runs unchanged (for `uv sync` minus `--upgrade`, already in the lockfile),
  then the installed set is diffed against what was checked or noted, and
  anything else fails the run.
- **A local index** (pip, uv pip). There is no lockfile to read first, so the
  tool is pointed (`PIP_INDEX_URL`, `UV_DEFAULT_INDEX`) at an HTTP server on
  127.0.0.1 that relays PyPI's JSON simple API: pages are rewritten to serve
  files by number, files younger than the cutoff are dropped from them, and a
  file is fetched, hash-checked against the page, scanned and spooled before it
  is served (403 when blocked). Since sdists are built during resolution, this
  is what keeps a malicious `setup.py` from running at all. The dry run (pip's
  `--report`, uv's `--dry-run` plan) is scanned first so the report comes
  before any install.

Age: npm and pnpm are given the cutoff themselves (`npm_config_before`,
`npm_config_minimum_release_age`) so they resolve to older releases instead of
failing. npm always gets a `before` — the run's start time when there is no
cutoff — which closes the window between the check and the install. What a
lockfile already pins is aged by the guard: the tarball's `Last-Modified`
(a registry sets it when the version is published), confirmed against the
packument's `time` only when it looks recent; uv.lock's `upload-time`, else
PyPI's JSON API.

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
3. **Implement in the Python engine.** Keep it needle-gated and bounded.
4. **Twin it in the JS engine with exact parity**, in the same commit. Mark the
   twin (`Twin of lazaret.scanner.core…`). For received-code patterns, edit the
   **shared spec** and sync instead of hand-writing both. A change to the
   install-script or import-time test (or anything they read) is also ported
   to the native engine, with the rule pack regenerated
   (`python3 scripts/make_rust_tables.py`); a pattern core builds at run time
   is built from named module-level pieces, so the extractor sees them.
5. **Verify:**
   - the behavioral suites (both engines);
   - **engine parity** — `test_js_parity*` (the differential corpus + the
     pattern twins); a Python-only feature goes in `_python_only`; and
     `test_rust_parity_*` with the native library built
     (`docs/RUST_ENGINE.md` §5);
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
    shapes actually appear; and since 0.1.8's rework, the benchmark's 429
    popular packages (35,758 files read as `--deps` groups them, and each
    release as the registry reads it): no finding.
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
  PyPI release has a pure wheel and five platform wheels with the native
  engine, built, checked and installed on their platforms by `wheels.yml`.
  Published versions are immutable; a mistake means releasing the next patch,
  not re-tagging.
- **CHANGELOG.md** started at 0.1.6 (Keep a Changelog). Date each entry at
  release.
- **What ships** is narrow: the wheel/sdist contain only `src/lazaret/` (a
  platform wheel adds the native library and its two license files,
  `rust/LICENSE-PYTHON` and `rust/NOTICE`: part of the engine is a Rust
  translation of CPython code), the npm package only `bin/` and `src/`. `scripts/make_bundle.py` builds a reproducible
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
| `python/src/lazaret/scanner/autorun.py`, `ghworkflow.py` | Editor and AI-agent settings that run commands (SC-AUTORUN) and the workflows the Shai-Hulud worms planted (SC-WORKFLOW-*); twins `js/src/lib/autorun.js`, `ghworkflow.js` |
| `python/src/lazaret/scanner/frameworks.py` | Which route handler parameters Flask / FastAPI / Django fill from the request (shared by both taint passes; twinned in `js/src/scanner/taint.js`) |
| `python/src/lazaret/scanner/received_spec.json` | **Source of truth** for the received-code detector's data + patterns |
| `python/src/lazaret/scanner/sca_feeds.py` | CVE bundle build (OSV/KEV/EPSS) |
| `python/src/lazaret/{registry,mcp,pg,safexml}/` | Registry auditor, MCP server, Postgres client, safe XML |
| `python/src/lazaret/registry/guard.py`, `python/src/lazaret/_cli.py` | The install guard (`lazaret guard`) and the `lazaret` command's dispatch |
| `js/src/lib/received.js` | Twin of the received-code detector |
| `js/src/lib/received-spec.json` | Synced copy of the spec (do not edit by hand) |
| `js/src/lib/hooks.js`, `js/src/scanner/flow.js`, `js/src/index.js` | Install-hook checks, flow twin, npm CLI |
| `python/tests/architecture/test_js_parity*.py` | The engine-parity guards |
| `rust/crates/lazaret-engine`, `lazaret-ffi` | The native engine (supply-chain tests, sre port, rule pack) and its C ABI (`docs/RUST_ENGINE.md`) |
| `python/src/lazaret/scanner/engine.py`, `_native.py` | Which engine answers (`--engine`, `LAZARET_ENGINE`), batching and threads, the Python fallback; the ctypes loader |
| `python/tests/architecture/test_rust_parity_*.py`, `hooks_corpus.py` | The native engine's parity guards and the corpus they share with `test_js_parity_hooks.py` |
| `scripts/make_rust_tables.py`, `check_rust_deps.py` | The rule pack from `core.py` (`--check`); no crate from outside the workspace |
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

## 12. Current state (0.1.8) and backlog

**In 0.1.8** (from the 0.1.7 benchmark's misses, backlog items 1-11):
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
with the Python engine's answers.

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
  - **PyPI owners** for SC-NEW-DEPENDENCY: its JSON API has none, so a new
    requirement from the project's own account counts too.
  - **What the exfiltration shapes don't read** (the benchmark's remaining
    misses): an address built from variables for a DNS name
    (@fnos/app's telemetry runner), a destination fetched at run time with
    nothing else to show (data-pipeline-check was caught by its credential
    sweep, not its webhooks), a load-testing flood (poppo213), and a wheel
    with no code at all (lightgboost).
- *`--deps` and browser code:* `--deps` gives every file of a dependency the
  import-time test, where the registry reads what runs at install, at import
  and when used (skipping tests, docs and a web app's static files). So a
  Python package's browser bundle can be a CRITICAL hit: litellm's proxy UI
  ships a Next.js chunk of guardrail test prompts (one shows `curl … | sh`)
  that the test reads as code. Tell browser code from code that runs (a
  `_next/static` or `static/` file no entry point reaches) without letting a
  `main` pointed into `static/` hide; the deep sweep's wider reading lists
  such hits.
- *What the cross-file follower doesn't follow* (the adversarial pass's known
  misses, kept as tests): a value handed between files through an event
  emitter (`bus.emit('code', c)` / `bus.on('code', eval)`), and two top-level
  modules of site-packages in a `--deps` scan (they may be two distributions;
  a registry scan reads a release's as one). Nor a name built at run time
  (`getattr(m, name)`), a runner behind another function (one that hands its
  parameter to another file's runner), or more than four hops.
- *Engine:* the native engine answers the supply-chain tests (0.1.8,
  `docs/RUST_ENGINE.md`), and release CI builds it into five platform
  wheels; next, WebAssembly for the npm package (then the JavaScript twin can
  go, and the npm package carries `rust/NOTICE` and `rust/LICENSE-PYTHON`),
  the per-file rules (`scan_file`), and `core.py` loading the rule pack so it
  has one source.
- *Notices outside the native engine* (smaller, for a later release): the
  npm package's shell tokenizer (`js/src/lib/hooks.js`) reimplements the
  state machine of CPython's `shlex.read_token`, so give it the PSF notice
  as the Rust one has; and the character and codec tables generated from
  Python's `unicodedata` and `codecs` (`_unicode13.py` and its JS twins,
  `codecs.js`, `unicode13.rs`) are Unicode Character Database data, which
  the Unicode License asks to be credited where it is copied.
- *Quality:* a durable home for this backlog (a `BACKLOG.md` or issues).
- *Guard:* registries that need credentials (read them from the tool's own
  settings, for that host only), yarn and Bun, `uv run` / `uvx`; the scan of a
  very large tarball (`next`, 42 MB) dominates a first install.
- *From the audit (P1/P2):* a GitHub Action and pre-commit hook, a public
  nightly benchmark, per-rule docs, a coverage gate and parser fuzzing in CI,
  optional live secret verification, splitting `core.py`, generating the
  dashboard's script from `js/src`.

Prefer doing detection extensions **reactively** — when a real-world dropper
uses the pattern — over speculatively. The bar that made this tool good is the
false-positive bar; keep it.
